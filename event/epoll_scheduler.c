#include <sys/epoll.h>
#include <stdio.h>

#include "epoll_scheduler.h"

#define EPOLL_MAX_SIZE 4096
#define EPOLL_MAX_EVENT 128

struct event_scheduler *epoll_create_scheduler()
{
	struct epoll_scheduler *es;

	es = mem_alloc(sizeof(*es));

	es->epoll = epoll_create(EPOLL_MAX_EVENT);

	return &es->scheduler;
}

static void epoll_process(
	struct epoll_scheduler *es,
	struct event *e,
	int op,
	int events)
{
	struct epoll_event ee;

	ee.events = events;
	ee.data.ptr = e;

	if (-1 == epoll_ctl(es->epoll, op, e->fd, &ee))
		perror("epoll_ctl");
}

void epoll_set_read(struct event *e)
{
	struct epoll_scheduler *es;
	int op;
	int flags;

	es = container_of(e->scheduler, struct epoll_scheduler, scheduler);

	if (event_find_write_of_fd(e->scheduler, e->fd)) {
		op = EPOLL_CTL_MOD;
		flags = EPOLLIN | EPOLLOUT;
	} else {
		op = EPOLL_CTL_ADD;
		flags = EPOLLIN;
	}

	epoll_process(es, e, op, flags);
}

void epoll_set_write(struct event *e)
{
	struct epoll_scheduler *es;
	int op;
	int flags;

	es = container_of(e->scheduler, struct epoll_scheduler, scheduler);

	if (event_find_read_of_fd(e->scheduler, e->fd)) {
		op = EPOLL_CTL_MOD;
		flags = EPOLLIN | EPOLLOUT;
	} else {
		op = EPOLL_CTL_ADD;
		flags = EPOLLOUT;
	}

	epoll_process(es, e, op, flags);
}

void epoll_cancel_read(struct event *e)
{
	struct epoll_scheduler *es;
	int op;
	int flags;

	es = container_of(e->scheduler, struct epoll_scheduler, scheduler);

	if (event_find_write_of_fd(e->scheduler, e->fd)) {
		op = EPOLL_CTL_MOD;
		flags = EPOLLOUT;
	} else {
		op = EPOLL_CTL_DEL;
		flags = EPOLLIN;
	}

	epoll_process(es, e, op, flags);
}

void epoll_cancel_write(struct event *e)
{
	struct epoll_scheduler *es;
	int op;
	int flags;

	es = container_of(e->scheduler, struct epoll_scheduler, scheduler);

	if (event_find_read_of_fd(e->scheduler, e->fd)) {
		op = EPOLL_CTL_MOD;
		flags = EPOLLIN;
	} else {
		op = EPOLL_CTL_DEL;
		flags = EPOLLOUT;
	}

	epoll_process(es, e, op, flags);
}

int epoll_poll(struct event_scheduler *s, struct timeval *tv)
{
	struct epoll_scheduler *es;
	struct epoll_event ee[EPOLL_MAX_EVENT];
	int nr;
	int i;
	struct event *e;

	es = container_of(s, struct epoll_scheduler, scheduler);

	nr = epoll_wait(es->epoll, ee, EPOLL_MAX_EVENT,
			tv->tv_sec * 1000000 + tv->tv_usec / 1000);
	if (nr < 0) {
		perror("epoll_wait");

		return -1;
	}

	for (i = 0; i < nr; i++) {
		e = ee[i].data.ptr;

		if (EVENT_READ == e->type) {
			rb_erase_cached(&e->rb_node, &s->read);
			if (event_find_write_of_fd(s, e->fd))
				epoll_process(es, e, EPOLL_CTL_MOD, EPOLLOUT);
			else
				epoll_process(es, e, EPOLL_CTL_DEL, EPOLLIN);
		} else {
			rb_erase_cached(&e->rb_node, &s->write);
			if (event_find_read_of_fd(s, e->fd))
				epoll_process(es, e, EPOLL_CTL_MOD, EPOLLIN);
			else
				epoll_process(es, e, EPOLL_CTL_DEL, EPOLLOUT);
		}

		e->ready = 1;
		list_add_tail(&e->l_node, &s->ready);
	}

	return nr;
}
