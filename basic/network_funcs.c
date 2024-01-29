#include <sys/socket.h>
#include <netinet/tcp.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>

#include "network_funcs.h"

int
get_none_block_tcp_listen_socket(
	struct sockaddr *addr,
	socklen_t len,
	int backlog)
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

	if (listen(fd, backlog) < 0) {
		perror("listern error");

		return -1;
	}

	return fd;
}

int get_none_block_tcp_connect_socket(int af)
{
	int fd;
	int flag;

	switch (af) {
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
	setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, (char*)&flag, sizeof(int));

	return fd;
}

void sockaddr_in_to_string(struct sockaddr_in *addr, char *buf, int len)
{
	unsigned char *p = (unsigned char *)&addr->sin_addr;

	snprintf(buf, len, "%d.%d.%d.%d:%d", p[0], p[1], p[2], p[3],
	         ntohs(addr->sin_port));
}

void sockaddr_in6_to_string(struct sockaddr_in6 *addr, char *buf, int len)
{
	char addr_str[sizeof("ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff")];

	inet_ntop(AF_INET6, &addr->sin6_addr, addr_str, sizeof(addr_str));
	snprintf(buf, len, "[%s]:%d", addr_str, ntohs(addr->sin6_port));
}

#define sockaddr_xx_stringn_func_body(_tp_, n...) \
const char *sockaddr_##_tp_##_string##n(struct sockaddr_##_tp_ *addr)  \
{                                             \
	static __thread char buf[sizeof("[ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff]:65535")];\
	sockaddr_##_tp_##_to_string(addr, buf, sizeof(buf));\
	return buf;                                  \
}

sockaddr_xx_stringn_func_body(in)
sockaddr_xx_stringn_func_body(in, 1)
sockaddr_xx_stringn_func_body(in, 2)
sockaddr_xx_stringn_func_body(in, 3)

sockaddr_xx_stringn_func_body(in6)
sockaddr_xx_stringn_func_body(in6, 1)
sockaddr_xx_stringn_func_body(in6, 2)
sockaddr_xx_stringn_func_body(in6, 3)

#define sockaddr_stringn_func_body(n...) \
const char *sockaddr_string##n(struct sockaddr *addr) \
{ \
	if (addr->sa_family == AF_INET) \
		return sockaddr_in_string##n((struct sockaddr_in *)addr); \
	else if (addr->sa_family == AF_INET6) \
		return sockaddr_in6_string##n((struct sockaddr_in6 *)addr); \
	return "";\
}

sockaddr_stringn_func_body()
sockaddr_stringn_func_body(1)
sockaddr_stringn_func_body(2)
sockaddr_stringn_func_body(3)

int str_to_port(char *str, be16 *port)
{
	char *end;
	long result;

	result = strtol(str, &end, 10);
	if (result < 0 || result > 65535 || end == str)
		return -1;

	*port = result;

	return 0;
}
