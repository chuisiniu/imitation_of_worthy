#include <sys/epoll.h>
#include <stdio.h>
#include <assert.h>

#include "memhook.h"
#include "epoll_scheduler.h"

#define EPOLL_MAX_SIZE 4096
#define EPOLL_MAX_EVENT 128

struct epoll_node {
	struct rb_node node;

	int fd;

	struct event *read;
	struct event *write;
};

static int epoll_event_fd_less(struct rb_node *a, const struct rb_node *b)
{
	struct epoll_node *ena;
	struct epoll_node *enb;

	ena = rb_entry_safe(a, struct epoll_node, node);
	enb = rb_entry_safe(b, struct epoll_node, node);

	if (ena->fd < enb->fd)
		return 1;

	return 0;
}

static int epoll_event_fd_cmp(const void *key, const struct rb_node *node)
{
	struct epoll_node *en;

	en = rb_entry_safe(node, struct epoll_node, node);

	return *(const int *)key - en->fd;
}

static struct epoll_node *epoll_event_find_fd(struct rb_root *root, int fd)
{
	struct rb_node *n;

	n = rb_find(&fd, root, epoll_event_fd_cmp);
	if (NULL == n)
		return NULL;

	return rb_entry_safe(n, struct epoll_node, node);
}

struct event_scheduler *epoll_create_scheduler()
{
	struct epoll_scheduler *es;

	es = mem_alloc(sizeof(*es));

	es->epoll = epoll_create(EPOLL_MAX_EVENT);
	es->tree = RB_ROOT;

	return &es->scheduler;
}

static void epoll_process(
	struct epoll_scheduler *es,
	struct epoll_node *en,
	int op,
	int events)
{
	struct epoll_event ee;

	ee.events = events;
	ee.data.ptr = en;

	if (-1 == epoll_ctl(es->epoll, op, en->fd, &ee))
		perror("epoll_ctl");
}

int epoll_set_read(struct event *e)
{
	struct epoll_scheduler *es;
	struct epoll_node *en;
	int op;
	int flags;

	es = container_of(e->scheduler, struct epoll_scheduler, scheduler);
	en = epoll_event_find_fd(&es->tree, e->fd);

	if (en) {
		assert(NULL == en->read);

		op = EPOLL_CTL_MOD;
		flags = EPOLLIN | EPOLLOUT;
	} else {
		en = mem_alloc(sizeof(*en));
		if (NULL == en)
			return -1;
		en->fd = e->fd;
		en->write = NULL;

		op = EPOLL_CTL_ADD;
		flags = EPOLLIN;

		rb_add(&en->node, &es->tree, epoll_event_fd_less);
	}
	en->read = e;

	epoll_process(es, en, op, flags);

	return 0;
}

int epoll_set_write(struct event *e)
{
	struct epoll_scheduler *es;
	struct epoll_node *en;
	int op;
	int flags;

	es = container_of(e->scheduler, struct epoll_scheduler, scheduler);
	en = epoll_event_find_fd(&es->tree, e->fd);

	if (en) {
		assert(NULL == en->write);

		op = EPOLL_CTL_MOD;
		flags = EPOLLIN | EPOLLOUT;
	} else {
		en = mem_alloc(sizeof(*en));
		if (NULL == en)
			return -1;

		en->fd = e->fd;
		en->read = NULL;
		op = EPOLL_CTL_ADD;
		flags = EPOLLOUT;

		rb_add(&en->node, &es->tree, epoll_event_fd_less);
	}
	en->write = e;

	epoll_process(es, en, op, flags);

	return 0;
}

void epoll_cancel_read(struct event *e)
{
	struct epoll_scheduler *es;
	struct epoll_node *en;
	int op;
	int flags;

	es = container_of(e->scheduler, struct epoll_scheduler, scheduler);
	en = epoll_event_find_fd(&es->tree, e->fd);

	if (en && en->write) {
		op = EPOLL_CTL_MOD;
		flags = EPOLLOUT;
		en->read = NULL;
	} else if (en) {
		op = EPOLL_CTL_DEL;
		flags = EPOLLIN;

		rb_erase(&en->node, &es->tree);
	} else {
		assert(0);

		return;
	}

	epoll_process(es, en, op, flags);

	if (EPOLL_CTL_DEL == op)
		mem_free(en);
}

void epoll_cancel_write(struct event *e)
{
	struct epoll_scheduler *es;
	struct epoll_node *en;
	int op;
	int flags;

	es = container_of(e->scheduler, struct epoll_scheduler, scheduler);
	en = epoll_event_find_fd(&es->tree, e->fd);

	if (en && en->read) {
		op = EPOLL_CTL_MOD;
		flags = EPOLLIN;
		en->write = NULL;
	} else if (en) {
		op = EPOLL_CTL_DEL;
		flags = EPOLLOUT;

		rb_erase(&en->node, &es->tree);
	} else {
		assert(0);

		return;
	}

	epoll_process(es, en, op, flags);

	if (EPOLL_CTL_DEL == op)
		mem_free(en);
}

int epoll_poll(struct event_scheduler *s, struct timeval *tv)
{
	struct epoll_scheduler *es;
	struct epoll_event ee[EPOLL_MAX_EVENT];
	int nr;
	int i;
	struct epoll_node *en;

	es = container_of(s, struct epoll_scheduler, scheduler);

	nr = epoll_wait(es->epoll, ee, EPOLL_MAX_EVENT,
			tv->tv_sec * 1000 + tv->tv_usec / 1000);
	if (nr < 0) {
		perror("epoll_wait");

		return -1;
	}

	for (i = 0; i < nr; i++) {
		en = ee[i].data.ptr;

		if (ee[i].events & EPOLLIN) {
			list_del(&en->read->l_node);
			list_add_tail(&en->read->l_node, &s->ready);
			en->read->ready = 1;
			en->read = NULL;
		}
		if (ee[i].events & EPOLLOUT) {
			list_del(&en->write->l_node);
			list_add_tail(&en->write->l_node, &s->ready);
			en->write->ready = 1;
			en->write = NULL;
		}
		assert(en->read == NULL || en->write == NULL);
		if (en->read) {
			epoll_process(es, en, EPOLL_CTL_MOD, EPOLLIN);
		} else if (en->write) {
			epoll_process(es, en, EPOLL_CTL_MOD, EPOLLOUT);
		} else {
			epoll_process(es, en, EPOLL_CTL_DEL, 0);

			rb_erase(&en->node, &es->tree);
		}
	}

	return nr;
}
