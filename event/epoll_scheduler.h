#ifndef IMITATION_OF_WORTHY_EPOLL_SCHEDULER_H
#define IMITATION_OF_WORTHY_EPOLL_SCHEDULER_H
#include "event.h"

struct epoll_scheduler {
	struct event_scheduler scheduler;

	int epoll;
};

struct event_scheduler *epoll_create_scheduler();

void epoll_set_read(struct event *e);

void epoll_set_write(struct event *e);

int epoll_poll(struct event_scheduler *s, struct timeval *tv);

void epoll_cancel_read(struct event *e);

void epoll_cancel_write(struct event *e);
#endif //IMITATION_OF_WORTHY_EPOLL_SCHEDULER_H
