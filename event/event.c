#include <stdio.h>

#include "event.h"
#include "select_scheduler.h"

struct event_mp_ops {
	struct event_scheduler *(* create_scheduler)();
	void (* set_write)(struct event_scheduler *s, struct event *e);
	void (* set_read)(struct event_scheduler *s, struct event *e);
	int (* poll)(struct event_scheduler *s, struct timeval *tv);
} event_multipath_ops[EVENT_MULTIPATH_MAX] = {
	[EVENT_MULTIPATH_SELECT] = {
		.create_scheduler = select_create_scheduler,
		.set_write = select_set_write,
		.set_read = select_set_read,
		.poll = select_poll,
	}
};

struct event_mp_ops *event_get_mp_ops(enum event_multipath_type t)
{
	return &event_multipath_ops[t];
}

struct event_scheduler *event_create_scheduler(
	enum event_multipath_type type)
{
	struct event_scheduler *result;

	result = event_get_mp_ops(type)->create_scheduler();

	result->type = type;
	result->nr_alloced = 0;

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
			&s->free, struct event, node);
		list_del(&e->node);
	}

	e->type = type;
	e->scheduler = s;
	e->handler = handler;
	e->arg = arg;
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
	list_add(&e->node, head);

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

struct event *event_get_next(struct event_scheduler *scheduler, struct event *next)
{
	struct event *e;
	struct timeval tv;

	tv.tv_sec = 1;
	tv.tv_usec = 0;

	while (1) {
		if (!list_empty(&scheduler->ready)) {
			e = list_first_entry(&scheduler->ready, struct event, node);

			*next = *e;

			list_del(&e->node);
			list_add(&e->node, &scheduler->free);

			return next;
		}

		event_get_mp_ops(scheduler->type)->poll(scheduler, &tv);
	}
}

void event_handle_event(struct event *e)
{
	e->handler(e);
}
