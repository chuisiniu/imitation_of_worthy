#include <stdlib.h>
#include <stdio.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <time.h>

#include "log.h"
#include "network_funcs.h"
#include "event.h"

#include "proxy_ssl.h"

#define LISTEN_TCP_PORT 9999
#define BACKLOG 5

struct event_scheduler *g_proxy_event_scheduler = NULL;

time_t g_proxy_time;

struct event_scheduler *proxy_get_event_scheduler()
{
	return g_proxy_event_scheduler;
}

int proxy_refresh_time(struct event *e)
{
	event_add_timer(e->scheduler, proxy_refresh_time, NULL, 2);

	g_proxy_time = time(NULL);

	return 0;
}

int main(int argc, char **argv)
{
	int listen_fd;
	struct sockaddr_in saddr;
	struct event e;

	log_init(stdout ? stdout : stderr, LOG_LV_DEBUG);

	g_proxy_event_scheduler = event_create_scheduler();
	if (NULL == g_proxy_event_scheduler) {
		log_fatal("fail to create event scheduler");

		exit(-1);
	}

	saddr.sin_family = AF_INET;
	saddr.sin_port = htons(LISTEN_TCP_PORT);
	saddr.sin_addr.s_addr = inet_addr("0.0.0.0");

	listen_fd = get_none_block_tcp_listen_socket(
		(struct sockaddr *) &saddr, sizeof(saddr), BACKLOG);
	if (listen_fd < 0) {
		log_fatal("fail to create listen socket");

		exit(-1);
	}

	proxy_init_ssl(g_proxy_event_scheduler, listen_fd);

	event_add_timer(g_proxy_event_scheduler, proxy_refresh_time, NULL, 0);

	while (event_get_next(g_proxy_event_scheduler, &e)) {
		event_handle_event(&e);
	}

	exit(0);
}
