#include <unistd.h>
#include <stdlib.h>
#include <stdio.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <strings.h>

#include "log.h"
#include "network_funcs.h"
#include "event.h"
#include "echo_server.h"

#define MAX_CLIENTS 256

#define REPORT_INTERVAL 60

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

	len = sizeof(addr);
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

	log_init(stdout, LOG_LV_DEBUG);

	scheduler = event_create_scheduler();
	if (NULL == scheduler) {
		perror("event_create_scheduler");

		exit(-1);
	}

	saddr.sin_family = AF_INET;
	saddr.sin_port = htons(LISTEN_TCP_PORT);
	saddr.sin_addr.s_addr = inet_addr("127.0.0.1");

	listen_fd = get_none_block_tcp_listen_socket(
		(struct sockaddr *) &saddr, sizeof(saddr), MAX_CLIENTS);
	if (listen_fd < 0) {
		perror("get_none_block_tcp_listen_socket");

		exit(-1);
	}

	event_add_read(scheduler, listen_handler, NULL, listen_fd);

	event_add_timer(scheduler, report_timer, NULL, REPORT_INTERVAL);

	while (event_get_next(scheduler, &e)) {
		event_handle_event(&e);
		sync();
	}

	exit(0);
}
