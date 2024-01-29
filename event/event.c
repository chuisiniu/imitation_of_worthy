#include <stdio.h>
#include <time.h>
#include <string.h>
#include <assert.h>

#include "log.h"
#include "event.h"
#ifdef EVENT_MULTIPATH_EPOLL
#include "epoll_scheduler.h"
#endif
#ifdef EVENT_MULTIPATH_SELECT
#include "select_scheduler.h"
#endif

#define MICRO_SEC_PER_SEC 1000000L

#define DEFAULT_TIMER_INTERVAL 10000L

struct event_mp_ops {
	struct event_scheduler *(* create_scheduler)();
	void (* set_write)(struct event *e);
	void (* set_read)(struct event *e);
	void (* cancel_write)(struct event *e);
	void (* cancel_read)(struct event *e);
	int (* poll)(struct event_scheduler *s, struct timeval *tv);
} event_multipath_ops = {
#ifdef EVENT_MULTIPATH_EPOLL
	.create_scheduler = epoll_create_scheduler,
	.set_write = epoll_set_write,
	.set_read = epoll_set_read,
	.cancel_write = epoll_cancel_write,
	.cancel_read = epoll_cancel_read,
	.poll = epoll_poll,
#endif
#ifdef EVENT_MULTIPATH_SELECT
		.create_scheduler = select_create_scheduler,
		.set_write = select_set_write,
		.set_read = select_set_read,
		.cancel_write = select_cancel_write,
		.cancel_read = select_cancel_read,
		.poll = select_poll,
#endif
};

static inline int event_tv_less(const struct timeval *a, const struct timeval *b)
{
	if (a->tv_sec < b->tv_sec
	    || (a->tv_sec == b->tv_sec
	        && a->tv_usec < b->tv_usec))
		return 1;

	return 0;
}

static int event_fd_less(struct rb_node *a, const struct rb_node *b)
{
	struct event *ea;
	struct event *eb;

	ea = rb_entry_safe(a, struct event, rb_node);
	eb = rb_entry_safe(b, struct event, rb_node);

	assert(ea->type == EVENT_READ || ea->type == EVENT_WRITE);
	assert(eb->type == EVENT_READ || eb->type == EVENT_WRITE);

	if (ea->fd < eb->fd)
		return 1;

	return 0;
}

static int event_timer_less(struct rb_node *a, const struct rb_node *b)
{
	struct event *ea;
	struct event *eb;

	ea = rb_entry_safe(a, struct event, rb_node);
	eb = rb_entry_safe(b, struct event, rb_node);

	assert(ea->type == EVENT_TIMER);
	assert(eb->type == EVENT_TIMER);

	return event_tv_less(&ea->tv, &eb->tv);
}

static int event_fd_cmp(const void *key, const struct rb_node *node)
{
	struct event *e;

	e = rb_entry_safe(node, struct event, rb_node);

	return *(const int *)key - e->fd;
}

static inline struct event_mp_ops *event_get_mp_ops()
{
	return &event_multipath_ops;
}

static int event_get_timeval(struct timeval *tv)
{
	int ret;
	struct timespec tp;

	ret = clock_gettime(CLOCK_MONOTONIC, &tp);
	if (0 == ret) {
		tv->tv_sec = tp.tv_sec;
		tv->tv_usec = (typeof(tv->tv_usec))tp.tv_nsec / 1000;
	}

	return ret;
}

struct event_scheduler *event_create_scheduler()
{
	struct event_scheduler *result;

	result = event_get_mp_ops()->create_scheduler();

	result->nr_alloced = 0;

	result->timer = RB_ROOT_CACHED;

	result->read = RB_ROOT_CACHED;
	result->write = RB_ROOT_CACHED;

	INIT_LIST_HEAD(&result->ready);

	INIT_LIST_HEAD(&result->free);

	return result;
}

struct event *event_get_free_event(
	struct event_scheduler *s,
	enum event_event_type type,
	int (*handler)(struct event *),
	void *arg,
	const char *name)
{
	struct event *e;

	if (list_empty(&s->free)) {
		e = mem_alloc(sizeof(*e));
		if (NULL == e) {
			log_error("fail to alloc event");

			return NULL;
		}
		s->nr_alloced += 1;
	} else {
		e = list_first_entry(
			&s->free, struct event, l_node);
		list_del(&e->l_node);
	}

	e->type = type;
	e->scheduler = s;
	e->handler = handler;
	e->arg = arg;
	e->ready = 0;
	snprintf(e->name, sizeof(e->name), "%s", name);

	return e;
}

struct event *event_add_io_with_name(
	struct event_scheduler *scheduler,
	int (*handler)(struct event *),
	void *arg, int fd,
	enum event_event_type t,
	void (* set_fn)(struct event *e),
	struct rb_root_cached *tree,
	char *name)
{
	struct event *e;

	e = event_get_free_event(scheduler, t, handler, arg, name);
	if (NULL == e) {
		log_error("fail to get free event when add io event, "
			  "name: %s, fd %d", name, fd);

		return NULL;
	}

	e->type = t;
	e->fd = fd;

	set_fn(e);
	rb_add_cached(&e->rb_node, tree, event_fd_less);

	log_debug("add %s on %d", name, fd);

	return e;
}

struct event *event_add_read_with_name(
	struct event_scheduler *scheduler,
	int (*handler)(struct event *),
	void *arg, int fd, char *name)
{
	return event_add_io_with_name(
		scheduler, handler,arg, fd, EVENT_READ,
		event_get_mp_ops()->set_read, &scheduler->read, name);
}

struct event *event_add_write_with_name(
	struct event_scheduler *scheduler,
	int (*handler)(struct event *),
	void *arg, int fd, char *name)
{
	return event_add_io_with_name(
		scheduler, handler, arg, fd, EVENT_WRITE,
		event_get_mp_ops()->set_write, &scheduler->write, name);
}

struct event *event_add_timer_with_name(
	struct event_scheduler *scheduler,
	int (*handler)(struct event *),
	void *arg, int sec, char *name)
{
	struct event *e;

	e = event_get_free_event(scheduler, EVENT_TIMER, handler, arg, name);
	if (NULL == e) {
		log_error("fail to get free event when add timer event, "
		          "name: %s, sec %d", name, sec);

		return NULL;
	}

	event_get_timeval(&e->tv);
	e->tv.tv_sec += sec;

	rb_add_cached(&e->rb_node, &scheduler->timer, event_timer_less);

	log_debug("add %s after %d seconds", name, sec);

	return e;
}

void event_cancel_event(struct event *e)
{
	struct rb_root_cached *root;

	root = NULL;
	switch (e->type) {
	case EVENT_WRITE:
		log_debug("cancel write evnet, name: %s, fd: %d",
		          e->name, e->fd);

		event_get_mp_ops()->cancel_write(e);

		if (!e->ready)
			root = &e->scheduler->write;

		break;
	case EVENT_READ:
		log_debug("cancel read evnet, name: %s, fd: %d",
		          e->name, e->fd);

		event_get_mp_ops()->cancel_read(e);

		if (!e->ready)
			root = &e->scheduler->read;

		break;
	case EVENT_TIMER:
		log_debug("cancel timer, name: %s", e->name);

		if (!e->ready)
			root = &e->scheduler->timer;

		break;
	default:
		log_error("cancel invalid event type %d", e->type);;

		break;
	}

	if (root)
		rb_erase_cached(&e->rb_node, root);
	else
		list_del(&e->l_node);

	list_add(&e->l_node, &e->scheduler->free);
}

void event_get_first_timeout(struct event_scheduler *scheduler,
                             struct timeval *tv)
{
	struct timeval now;
	struct event *first;

	first = rb_entry_safe(rb_first_cached(&scheduler->timer),
			      struct event, rb_node);
	event_get_timeval(&now);
	if (NULL == first) {
		tv->tv_usec = DEFAULT_TIMER_INTERVAL;
		tv->tv_sec = 0;

		return;
	}

	tv->tv_usec = first->tv.tv_usec - now.tv_usec;
	tv->tv_sec = first->tv.tv_sec - now.tv_sec;

	while (tv->tv_usec >= MICRO_SEC_PER_SEC) {
		tv->tv_usec -= MICRO_SEC_PER_SEC;
		tv->tv_sec += 1;
	}

	while (tv->tv_usec < 0) {
		tv->tv_usec += MICRO_SEC_PER_SEC;
		tv->tv_sec -= 1;
	}

	if (tv->tv_sec < 0) {
		tv->tv_sec = 1;
		tv->tv_usec = 0;
	}
}

int event_process_timer(struct event_scheduler *scheduler)
{
	struct timeval now;
	struct event *e;
	int cnt;

	event_get_timeval(&now);

	e = rb_entry_safe(rb_first_cached(&scheduler->timer),
			  struct event, rb_node);
	cnt = 0;
	while (e && (event_tv_less(&e->tv, &now)
	             || (e->tv.tv_sec == now.tv_sec
	                 && e->tv.tv_usec == now.tv_usec))) {
		rb_erase_cached(&e->rb_node, &scheduler->timer);

		log_debug("timer %s is ready", e->name);

		e->ready = 1;
		list_add_tail(&e->l_node, &scheduler->ready);

		e = rb_entry_safe(rb_first_cached(&scheduler->timer),
		                  struct event, rb_node);
		cnt += 1;
	}

	return cnt;
}

struct event *event_get_next(
	struct event_scheduler *scheduler,
	struct event *next)
{
	struct event *e;
	struct timeval tv;
	int nr_timer;

	while (1) {
		if (!list_empty(&scheduler->ready)) {
			e = list_first_entry(&scheduler->ready,
					     struct event, l_node);

			*next = *e;

			list_del(&e->l_node);
			list_add(&e->l_node, &scheduler->free);

			log_debug("get event, type %d, name %s",
				  next->type, next->name);

			return next;
		}

		nr_timer = event_process_timer(scheduler);

		if (0 == nr_timer)
			event_get_first_timeout(scheduler, &tv);
		else
			bzero(&tv, sizeof(tv));

		event_get_mp_ops()->poll(scheduler, &tv);
	}
}

void event_handle_event(struct event *e)
{
	e->handler(e);
}

struct event *event_find_event_of_fd(struct rb_root *tree, int fd)
{
	struct rb_node *n;

	n = rb_find(&fd, tree, event_fd_cmp);
	if (NULL == n)
		return NULL;

	return rb_entry_safe(n ,struct event, rb_node);
}

struct event *event_find_read_of_fd(struct event_scheduler *scheduler, int fd)
{
	return event_find_event_of_fd(&scheduler->read.rb_root, fd);
}

struct event *event_find_write_of_fd(struct event_scheduler *scheduler, int fd)
{
	return event_find_event_of_fd(&scheduler->write.rb_root, fd);
}
