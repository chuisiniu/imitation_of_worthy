#ifndef __EVENT_H__
#define __EVENT_H__
#include "linux/list.h"
#include "linux/rbtree_augmented.h"

#include "memhook.h"

enum event_multipath_type {
	EVENT_MULTIPATH_SELECT,
	EVENT_MULTIPATH_POLL,
	EVENT_MULTIPATH_EPOLL,
	EVENT_MULTIPATH_KQUEUE,

	EVENT_MULTIPATH_MAX,
};

enum event_event_type {
	EVENT_READ,
	EVENT_WRITE,
	EVENT_TIMER,
};

struct event_scheduler {
	enum event_multipath_type type;

	int nr_alloced;

	struct rb_root_cached timer;

	struct list_head read;
	struct list_head write;

	struct list_head ready;

	struct list_head free;
};

#define EVENT_NAME_LEN 32

struct event {
	enum event_event_type type;

	union {
		struct list_head l_node;
		struct rb_node rb_node;
	};

	int ready;

	struct event_scheduler *scheduler;

	int (*handler)(struct event *);
	void *arg;

	char name[EVENT_NAME_LEN];

	union {
		int fd;
		struct timeval tv;
	};
};

struct event *event_add_read_with_name(
	struct event_scheduler *scheduler,
	int (*handler)(struct event *),
	void *arg, int fd, char *name);

struct event *event_add_write_with_name(
	struct event_scheduler *scheduler,
	int (*handler)(struct event *),
	void *arg, int fd, char *name);

struct event *event_add_timer_with_name(
	struct event_scheduler *scheduler,
	int (*handler)(struct event *),
	void *arg, int sec, char *name);

#define event_add_read(_scheduler_, _handler_, _arg_, _fd_) \
	event_add_read_with_name( \
		_scheduler_, _handler_, _arg_, _fd_, \
		#_handler_" on "#_fd_)

#define event_add_write(_scheduler_, _handler_, _arg_, _fd_) \
	event_add_write_with_name( \
		_scheduler_, _handler_, _arg_, _fd_, \
		#_handler_" on "#_fd_)

#define event_add_timer(_scheduler_, _handler_, _arg_, _sec_) \
	event_add_timer_with_name( \
		_scheduler_, _handler_, _arg_, _sec_, \
		#_handler_" after "#_sec_" seconds")

struct event_scheduler *event_create_scheduler(
	enum event_multipath_type type);

struct event *event_get_next(struct event_scheduler *scheduler, struct event *);

void event_handle_event(struct event *e);

void event_cancel_event(struct event *e);

#endif
