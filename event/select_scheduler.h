#ifndef __SELECT_SCHEDULER__
#define __SELECT_SCHEDULER__
#include "event.h"

struct select_scheduler {
	struct event_scheduler scheduler;

	fd_set read;
	fd_set write;
	fd_set except;
};

struct event_scheduler *select_create_scheduler();

int select_set_read(struct event *e);

int select_set_write(struct event *e);

int select_poll(struct event_scheduler *s, struct timeval *tv);

void select_cancel_read(struct event *e);

void select_cancel_write(struct event *e);

#endif
