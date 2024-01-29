#ifndef IMITATION_OF_WORTHY_NETWORK_FUNCS_H
#define IMITATION_OF_WORTHY_NETWORK_FUNCS_H
#include <sys/socket.h>
#include <arpa/inet.h>

typedef unsigned short be16;

int get_none_block_tcp_listen_socket(
	struct sockaddr *addr,
	socklen_t len,
	int backlog);

int get_none_block_tcp_connect_socket(int af);

const char *sockaddr_in_string(struct sockaddr_in *addr);
const char *sockaddr_in6_string(struct sockaddr_in6 *addr);
const char *sockaddr_string(struct sockaddr *addr);

const char *sockaddr_in_string1(struct sockaddr_in *addr);
const char *sockaddr_in6_string1(struct sockaddr_in6 *addr);
const char *sockaddr_string1(struct sockaddr *addr);

const char *sockaddr_in_string2(struct sockaddr_in *addr);
const char *sockaddr_in6_string2(struct sockaddr_in6 *addr);
const char *sockaddr_string2(struct sockaddr *addr);

const char *sockaddr_in_string3(struct sockaddr_in *addr);
const char *sockaddr_in6_string3(struct sockaddr_in6 *addr);
const char *sockaddr_string3(struct sockaddr *addr);

void sockaddr_in_to_string(struct sockaddr_in *addr, char *buf, int len);
void sockaddr_in6_to_string(struct sockaddr_in6 *addr, char *buf, int len);

int str_to_port(char *str, be16 *port);

#endif //IMITATION_OF_WORTHY_NETWORK_FUNCS_H
