#include <unistd.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "echo_server.h"

#define BUF_SIZE 2048

int main(int argc, char **argv)
{
	int fd;
	char buf[BUF_SIZE];
	int len;
	struct sockaddr_in daddr;

	fd = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
	if (fd < 0) {
		perror("socket error");

		exit(-1);
	}

	daddr.sin_family = AF_INET;
	daddr.sin_port = htons(LISTEN_TCP_PORT);
	daddr.sin_addr.s_addr = inet_addr("127.0.0.1");

	if (connect(fd, (struct sockaddr *)&daddr, sizeof(daddr)) < 0) {
		perror("connect error");

		exit(-1);
	}

	while (1) {
		len = scanf("%s", buf);

		if (write(fd, buf, strlen(buf)) < 0) {
			printf("server close\n");

			close(fd);

			exit(0);
		}

		len = read(fd, buf, sizeof(buf));
		if (len <= 0) {
			printf("server close\n");

			close(fd);

			exit(0);
		}

		buf[len] = '\0';
		printf("%s\n", buf);
	}
}
