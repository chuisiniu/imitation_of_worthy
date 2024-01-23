#include <stdio.h>
#include <sys/select.h>

#include "select_scheduler.h"

struct event_scheduler *select_create_scheduler()
{
	struct select_scheduler *ss;

	ss = mem_alloc(sizeof(*ss));

	FD_ZERO(&ss->read);
	FD_ZERO(&ss->write);
	FD_ZERO(&ss->except);

	return &ss->scheduler;
}

void select_set_fd(fd_set *set, int fd, char *name)
{
	if (FD_ISSET(fd, set)) {
		printf("fd %d of %s is already set", fd, name);

		return;
	}

	FD_SET(fd, set);
}

void select_set_read(struct event *e)
{
	struct select_scheduler *ss;

	ss = container_of(e->scheduler, struct select_scheduler, scheduler);

	select_set_fd(&ss->read, e->fd, e->name);
}

void select_set_write(struct event *e)
{
	struct select_scheduler *ss;

	ss = container_of(e->scheduler, struct select_scheduler, scheduler);

	select_set_fd(&ss->write, e->fd, e->name);
}

void select_cancel_read(struct event *e)
{
	struct select_scheduler *ss;

	ss = container_of(e->scheduler, struct select_scheduler, scheduler);

	FD_CLR(e->fd, &ss->read);
}

void select_cancel_write(struct event *e)
{
	struct select_scheduler *ss;

	ss = container_of(e->scheduler, struct select_scheduler, scheduler);

	FD_CLR(e->fd, &ss->read);
}

int select_process_fd(struct rb_root_cached *l, fd_set *fdset, fd_set *poll_fdset)
{
	struct rb_node *cur;
	struct rb_node *next;
	struct event *e;
	int n;

	n = 0;
	cur = rb_first_cached(l);
	while (cur) {
		next = rb_next(cur);
		e = rb_entry_safe(cur, struct event, rb_node);
		if (FD_ISSET(e->fd, fdset)) {
			FD_CLR(e->fd, poll_fdset);

			rb_erase_cached(cur, l);
			list_add_tail(&e->l_node, &e->scheduler->ready);

			e->ready = 1;
			n += 1;
		}

		cur = next;
	}

	return n;
}

int select_poll(struct event_scheduler *s, struct timeval *tv)
{
	struct select_scheduler *ss;
	fd_set readfd;
	fd_set writefd;
	fd_set exceptfd;
	int n;
	int res;

	ss = container_of(s, struct select_scheduler, scheduler);
	readfd = ss->read;
	writefd = ss->write;
	exceptfd = ss->except;

	n = select(FD_SETSIZE, &readfd, &writefd, &exceptfd, tv);
	if (n < 0) {
		return -1;
	}

	res = 0;
	if (n > 0) {
		res += select_process_fd(&s->read, &readfd, &ss->read);
		res += select_process_fd(&s->write, &writefd, &ss->write);
	}

	return res;
}
