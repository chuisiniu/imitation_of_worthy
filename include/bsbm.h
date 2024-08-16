#ifndef BSBM_H
#define BSBM_H

#include <string.h>
#include <stdint.h>
#include <netinet/in.h>

#include "data_type.h"
#include "bm.h"

enum bsbm_type_e {
	BSBM_TYPE_PORT,
	BSBM_TYPE_IPV4,
	BSBM_TYPE_IPV6,
};

static inline
int bsbm_cmp_ipv4(const void *a, const void *b)
{
	return memcmp(a, b, 4);
}

static inline
int bsbm_cmp_ipv6(const void *a, const void *b)
{
	return memcmp(a, b, 16);
}

static inline
int bsbm_cmp_port(const void *a, const void *b)
{
	return memcmp(a, b, 2);
}

static inline
void bsbm_inc_port(void *port)
{
	*(be16 *)port = htons(ntohs(*(be16 *)port) + 1);
}

static inline
void bsbm_inc_ipv4(void *ipv4)
{
	*(be32 *)ipv4 = htonl(ntohl(*(be32 *)ipv4) + 1);
}

static inline
void bsbm_inc_ipv6(void *ipv6)
{
	int i;
	int inc;
	struct in6_addr *ip6;

	ip6 = (struct in6_addr *)ipv6;
	inc = 1;
	for (i = 15; i >= 0; i--) {
		ip6->s6_addr[i] += inc;
		if (ip6->s6_addr[i] != 0)
			inc = 0;

		if (0 == inc)
			break;
	}
}

static inline
int bsbm_is_max_port(void *port)
{
	return *(be16 *)port == 0xFFFF;
}

static inline
int bsbm_is_max_ipv4(void *ipv4)
{
	return *(be32 *)ipv4 == 0xFFFFFFFF;
}

static inline
int bsbm_is_max_ipv6(void *ipv6)
{
	static const struct in6_addr max = {
		.__u6_addr = {
			.__u6_addr8 = {
				0xFF, 0xFF, 0xFF, 0xFF,
				0xFF, 0xFF, 0xFF, 0xFF,
				0xFF, 0xFF, 0xFF, 0xFF,
				0xFF, 0xFF, 0xFF, 0xFF,
			}
		}
	};

	return 0 == memcmp(ipv6, &max, sizeof(max));
}

struct bsbm *bsbm_create(int max_node,
			 int max_bit,
			 enum bsbm_type_e type,
			 struct mem_func_set *mem_f);

void bsbm_destroy(struct bsbm *b);

int bsbm_insert(struct bsbm *b, void *s, void *e, int bit);

void bsbm_remove_by_bit(struct bsbm *b, int bit);

void bsbm_match(struct bsbm *b, void *data,
		struct bm *bitmap,
		enum bm_op_type bm_op);

int bsbm_str(const struct bsbm *b, char *str, int str_len);

void bsbm_print(struct bsbm *b);

int bsbm_get_data_size(enum bsbm_type_e type);
int (* bsbm_get_cmp_fn(enum bsbm_type_e type))(const void *d1, const void *d2);
void (* bsbm_get_inc_fn(enum bsbm_type_e type))(void *d);

#endif // BSBM_H
