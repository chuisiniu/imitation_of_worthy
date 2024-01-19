#include <stdio.h>
#include <time.h>
#include <string.h>
#include <assert.h>

#include "event.h"
#include "select_scheduler.h"

#define MICRO_SEC_PER_SEC 1000000L

struct event_mp_ops {
	struct event_scheduler *(* create_scheduler)();
	void (* set_write)(struct event_scheduler *s, struct event *e);
	void (* set_read)(struct event_scheduler *s, struct event *e);
	void (* cancel_write)(struct event *e);
	void (* cancel_read)(struct event *e);
	int (* poll)(struct event_scheduler *s, struct timeval *tv);
} event_multipath_ops[EVENT_MULTIPATH_MAX] = {
	[EVENT_MULTIPATH_SELECT] = {
		.create_scheduler = select_create_scheduler,
		.set_write = select_set_write,
		.set_read = select_set_read,
		.cancel_write = select_cancel_write,
		.cancel_read = select_cancel_read,
		.poll = select_poll,
	}
};

static inline int event_tv_less(const struct timeval *a, const struct timeval *b)
{
	if (a->tv_sec < b->tv_sec
	    || (a->tv_sec == b->tv_sec
	        && a->tv_usec < b->tv_usec))
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

static inline struct event_mp_ops *event_get_mp_ops(enum event_multipath_type t)
{
	return &event_multipath_ops[t];
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

struct event_scheduler *event_create_scheduler(
	enum event_multipath_type type)
{
	struct event_scheduler *result;

	result = event_get_mp_ops(type)->create_scheduler();

	result->type = type;
	result->nr_alloced = 0;

	result->timer = RB_ROOT_CACHED;

	INIT_LIST_HEAD(&result->read);
	INIT_LIST_HEAD(&result->write);

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
	void (* set_fn)(struct event_scheduler *s, struct event *e),
	struct list_head *head,
	char *name)
{
	struct event *e;

	e = event_get_free_event(scheduler, t, handler, arg, name);
	if (NULL == e)
		return NULL;

	e->type = t;
	e->fd = fd;

	set_fn(scheduler, e);
	list_add(&e->l_node, head);

	return e;
}

struct event *event_add_read_with_name(
	struct event_scheduler *scheduler,
	int (*handler)(struct event *),
	void *arg, int fd, char *name)
{
	return event_add_io_with_name(
		scheduler, handler,arg, fd, EVENT_READ,
		select_set_read, &scheduler->read, name);
}

struct event *event_add_write_with_name(
	struct event_scheduler *scheduler,
	int (*handler)(struct event *),
	void *arg, int fd, char *name)
{
	return event_add_io_with_name(
		scheduler, handler, arg, fd, EVENT_WRITE,
		select_set_write, &scheduler->write, name);
}

struct event *event_add_timer_with_name(
	struct event_scheduler *scheduler,
	int (*handler)(struct event *),
	void *arg, int sec, char *name)
{
	struct event *e;

	e = event_get_free_event(scheduler, EVENT_TIMER, handler, arg, name);
	if (NULL == e)
		return NULL;

	event_get_timeval(&e->tv);
	e->tv.tv_sec += sec;

	rb_add_cached(&e->rb_node, &scheduler->timer, event_timer_less);

	return e;
}

void event_cancel_event(struct event *e)
{
	switch (e->type) {
	case EVENT_WRITE:
		event_get_mp_ops(e->scheduler->type)->cancel_write(e);

		break;
	case EVENT_READ:
		event_get_mp_ops(e->scheduler->type)->cancel_read(e);

		break;
	case EVENT_TIMER:
		if (e->ready)
			list_del(&e->l_node);
		else
			rb_erase_cached(&e->rb_node, &e->scheduler->timer);
		list_add(&e->scheduler->free, &e->l_node);

		break;
	default:
		break;
	}

	if (e->type != EVENT_TIMER) {
		list_del(&e->l_node);
		list_add(&e->scheduler->free, &e->l_node);
	}
}

void event_get_first_timeout(struct event_scheduler *scheduler,
                             struct timeval *tv)
{
	struct timeval now;
	struct event *first;

	first = rb_entry_safe(rb_first_cached(&scheduler->timer),
			      struct event, rb_node);
	event_get_timeval(&now);

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

		list_add_tail(&e->l_node, &scheduler->ready);
		e->ready = 1;

		e = rb_entry_safe(rb_first_cached(&scheduler->timer),
		                  struct event, rb_node);
		cnt += 1;
	}

	return cnt;
}

struct event *event_get_next(struct event_scheduler *scheduler, struct event *next)
{
	struct event *e;
	struct timeval tv;
	int nr_timer;

	while (1) {
		if (!list_empty(&scheduler->ready)) {
			e = list_first_entry(&scheduler->ready, struct event, l_node);

			*next = *e;

			list_del(&e->l_node);
			list_add(&e->l_node, &scheduler->free);

			return next;
		}

		nr_timer = event_process_timer(scheduler);

		if (0 == nr_timer)
			event_get_first_timeout(scheduler, &tv);
		else
			bzero(&tv, sizeof(tv));

		event_get_mp_ops(scheduler->type)->poll(scheduler, &tv);
	}
}

void event_handle_event(struct event *e)
{
	e->handler(e);
}
