#include <unistd.h>
#include <stdlib.h>
#include <stdio.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <fcntl.h>
#include <strings.h>
#include <errno.h>

#include "event.h"
#include "echo_server.h"

#define MAX_CLIENTS 256

#define REPORT_INTERVAL 60

static int
get_none_block_tcp_listen_socket(struct sockaddr *addr, socklen_t len)
{
	int fd;

	switch (addr->sa_family) {
	case AF_INET:
		fd = socket(PF_INET, SOCK_STREAM, 0);

		break;
	case AF_INET6:
		fd = socket(PF_INET6, SOCK_STREAM, 0);

		break;
	case AF_UNIX:
		fd = socket(PF_UNIX, SOCK_STREAM, 0);

		break;
	default:
		return -1;
	}

	if (fcntl(fd, F_SETFL, O_NONBLOCK) < 0) {
		perror("fcntl");

		return -1;
	}

	if (bind(fd, addr, len) < 0) {
		perror("bind");

		return -1;
	}

	if (listen(fd, MAX_CLIENTS) < 0) {
		perror("listern error");

		return -1;
	}

	return fd;
}

int read_handler(struct event *e)
{
	char buf[1024];
	ssize_t rlen;
	ssize_t wlen;

	rlen = read(e->fd, buf, sizeof(buf));
	if (0 == rlen) {
		printf("close when read\n");

		close(e->fd);

		return 0;
	} else if (rlen < 0) {
		perror("read");

		close(e->fd);

		return -1;
	}

	event_add_read(e->scheduler, read_handler, NULL, e->fd);

	wlen = write(e->fd, buf, rlen);
	if (0 == wlen) {
		printf("close when write\n");

		close(e->fd);

		return 0;
	} else if (wlen < 0) {
		perror("write");

		close(e->fd);

		return -1;
	}

	return 0;
}

int listen_handler(struct event *e)
{
	struct sockaddr addr;
	socklen_t len;
	int fd;

	fd = accept(e->fd, &addr, &len);
	if (fd < 0) {
		perror("accept");

		return -1;
	}

	event_add_read(e->scheduler, read_handler, NULL, fd);
	event_add_read(e->scheduler, listen_handler, NULL, e->fd);

	return 0;
}

int report_timer(struct event *e)
{
	static int counter = 0;

	counter++;
	printf("server running %d\n", counter);

	event_add_timer(e->scheduler, report_timer, NULL, REPORT_INTERVAL);

	return 0;
}

int main(int argc, char **argv)
{
	struct event_scheduler *scheduler;
	int listen_fd;
	struct sockaddr_in saddr;
	struct event e;

	scheduler = event_create_scheduler(EVENT_MULTIPATH_SELECT);
	if (NULL == scheduler) {
		perror("event_create_scheduler");

		exit(-1);
	}

	saddr.sin_family = AF_INET;
	saddr.sin_port = htons(LISTEN_TCP_PORT);
	saddr.sin_addr.s_addr = inet_addr("127.0.0.1");

	listen_fd = get_none_block_tcp_listen_socket(
		(struct sockaddr *) &saddr, sizeof(saddr));

	event_add_read(scheduler, listen_handler, NULL, listen_fd);

	event_add_timer(scheduler, report_timer, NULL, REPORT_INTERVAL);

	while (event_get_next(scheduler, &e)) {
		event_handle_event(&e);
		sync();
	}

	exit(0);
}
