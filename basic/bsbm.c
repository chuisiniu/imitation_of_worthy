/*
 * binary search + bitmap
 * */
#include <stdio.h>
#include <arpa//inet.h>

#include "linux/list.h"

#include "bm.h"
#include "bs.h"
#include "bsbm.h"

union bsbm_data {
	be16 port;
	be32 ipv4;
	struct in6_addr ipv6;
};

struct bsbm_item {
	// 一定要是第一个
	union bsbm_data data;

	struct bm *bitmap;

	struct list_head item;
};

struct bsbm {
	struct bs *bs;

	struct mem_func_set *mem_fn;

	int max;
	int max_bit;

	enum bsbm_type_e type;

	struct list_head items;
};

static struct mem_func_set bsbm_default_mem_fn = {
	.alloc = malloc,
	.realloc = realloc,
	.free = free
};

const char *bsbm_type_e2s(enum bsbm_type_e type)
{
	switch (type) {
	case BSBM_TYPE_PORT:
		return "port";
	case BSBM_TYPE_IPV4:
		return "ipv4";
	case BSBM_TYPE_IPV6:
		return "ipv6";
	default:
		return "invalid";
	}
}

int (* bsbm_get_cmp_fn(enum bsbm_type_e type))(const void *d1, const void *d2)
{
	switch (type) {
	case BSBM_TYPE_PORT:
		return bsbm_cmp_port;
	case BSBM_TYPE_IPV4:
		return bsbm_cmp_ipv4;
	case BSBM_TYPE_IPV6:
		return bsbm_cmp_ipv6;
	}

	return NULL;
}

void (* bsbm_get_inc_fn(enum bsbm_type_e type))(void *d)
{
	switch (type) {
	case BSBM_TYPE_PORT:
		return bsbm_inc_port;
	case BSBM_TYPE_IPV4:
		return bsbm_inc_ipv4;
	case BSBM_TYPE_IPV6:
		return bsbm_inc_ipv6;
	}

	return NULL;
}

int (* bsbm_get_is_max_fn(enum bsbm_type_e type))(void *d)
{
	switch (type) {
	case BSBM_TYPE_PORT:
		return bsbm_is_max_port;
	case BSBM_TYPE_IPV4:
		return bsbm_is_max_ipv4;
	case BSBM_TYPE_IPV6:
		return bsbm_is_max_ipv6;
	}

	return NULL;
}

int bsbm_get_data_size(enum bsbm_type_e type)
{
	switch (type) {
	case BSBM_TYPE_PORT:
		return 2;
	case BSBM_TYPE_IPV4:
		return 4;
	case BSBM_TYPE_IPV6:
		return 16;
	}

	return 0;
}

int bsbm_port_item_to_str(const void *data, char *str, int str_len)
{
	const struct bsbm_item *item;
	char *p;
	char bm_buf[128];

	item = data;
	p = str;

	bm_str(item->bitmap, bm_buf, sizeof(bm_buf));
	return snprintf(p, str_len, "data: %d, bitmap: %s",
			ntohs(item->data.port), bm_buf);
}

int bsbm_ipv4_item_to_str(const void *data, char *str, int str_len)
{
	const struct bsbm_item *item;
	char *p;
	char bm_buf[128];
	unsigned char *ch;

	item = data;
	p = str;
	ch = (unsigned char *)&item->data.ipv4;

	bm_str(item->bitmap, bm_buf, sizeof(bm_buf));

	return snprintf(p, str_len, "data: %d.%d.%d.%d, bitmap: %s",
			ch[0], ch[1], ch[2], ch[3], bm_buf);
}

int bsbm_ipv6_item_to_str(const void *data, char *str, int str_len)
{
	const struct bsbm_item *item;
	char *p;
	char bm_buf[128];
	char ip6_s[sizeof("ffff:ffff:ffff:ffff:ffff:ffff:255.255.255.255") + 1];

	item = data;
	p = str;
	inet_ntop(AF_INET6, &item->data.ipv6, ip6_s, sizeof(ip6_s));

	bm_str(item->bitmap, bm_buf, sizeof(bm_buf));
	return snprintf(p, str_len, "data: %s, bitmap: %s",
			ip6_s, bm_buf);
}

int (* bsbm_get_to_str_fn(enum bsbm_type_e type))(const void *data,
						  char *str,
						  int str_len)
{
	switch (type) {
	case BSBM_TYPE_PORT:
		return bsbm_port_item_to_str;
	case BSBM_TYPE_IPV4:
		return bsbm_ipv4_item_to_str;
	case BSBM_TYPE_IPV6:
		return bsbm_ipv6_item_to_str;
	}

	return NULL;
}


struct bsbm *bsbm_create(int max_node,
			 int max_bit,
			 enum bsbm_type_e type,
			 struct mem_func_set *mem_f)
{
	struct bsbm *b;
	struct mem_func_set *mem_fn;

	mem_fn = mem_f ? mem_f : &bsbm_default_mem_fn;

	b = mem_fn->alloc(sizeof(*b));
	if (NULL == b)
		return NULL;

	b->bs = bs_create(max_node, bsbm_get_cmp_fn(type),
			  bsbm_get_to_str_fn(type), mem_fn);
	if (NULL == b->bs) {
		mem_fn->free(b);

		return NULL;
	}

	b->mem_fn = mem_fn;
	b->max = max_node;
	b->max_bit = max_bit;
	b->type = type;
	INIT_LIST_HEAD(&b->items);

	return b;
}

struct bsbm_item *bsbm_create_item(struct bsbm *b, void *data)
{
	struct bsbm_item *result;

	result = b->mem_fn->alloc(sizeof(*result));
	if (NULL == result)
		return NULL;

	result->bitmap = bm_create(b->max_bit,
				   b->mem_fn);
	if (NULL == result->bitmap) {
		b->mem_fn->free(result);

		return NULL;
	}

	memcpy(&result->data, data, bsbm_get_data_size(b->type));
	INIT_LIST_HEAD(&result->item);

	return result;
}

static
void bsbm_destroy_item(struct bsbm *b, struct bsbm_item *item)
{
	bm_destroy(item->bitmap);

	b->mem_fn->free(item);
}

void bsbm_destroy(struct bsbm *b)
{
	struct bsbm_item *item;
	struct bsbm_item *temp;

	bs_destroy(b->bs);

	list_for_each_entry_safe(item, temp, &b->items, item) {
		list_del(&item->item);

		bsbm_destroy_item(b, item);
	}

	b->mem_fn->free(b);
}

static
int bsbm_insert_data_to_bs(struct bsbm *b, void *data, int *pre, int *found)
{
	int idx;
	struct bsbm_item *item;

	idx = bs_find(b->bs, data, pre);
	if (-1 == idx) {
		*found = 0;
		item = bsbm_create_item(b, data);
		if (NULL == item)
			return -1;

		idx = bs_insert(b->bs, item);

		list_add_tail(&b->items, &item->item);
	} else {
		*found = 1;
	}

	return idx;
}

int bsbm_insert(struct bsbm *b, void *s, void *e, int bit)
{
	int (* cmp_fn)(const void *d1, const void *d2);
	int (* is_max_fn)(void *data);
	void (* inc_fn)(void *data);
	int cmp_res;
	int pre_s;
	int pre_e;
	int idx_s;
	int idx_e;
	int idx;
	int nr_node;
	int found_s = 0;
	int found_e = 0;
	struct bsbm_item *item_s = NULL;
	struct bsbm_item *item_e = NULL;
	struct bsbm_item *item_pre_s;
	struct bsbm_item *item_pre_e;
	struct bsbm_item *item;
	union bsbm_data e_inc = {0};

	cmp_fn = bsbm_get_cmp_fn(b->type);
	is_max_fn = bsbm_get_is_max_fn(b->type);
	inc_fn = bsbm_get_inc_fn(b->type);
	if (NULL == cmp_fn || NULL == is_max_fn || NULL == inc_fn)
		return -1;

	cmp_res = cmp_fn(s, e);
	if (cmp_res > 0)
		return -1;

	nr_node = is_max_fn(e) ? 1 : 2;
	if ((bs_get_capacity(b->bs) - bs_get_nr(b->bs)) < nr_node)
		return -1;

	idx_s = bsbm_insert_data_to_bs(b, s, &pre_s, &found_s);
	if (-1 == idx_s)
		goto ERR;
	item_s = bs_get(b->bs, idx_s);

	if (nr_node == 1) {
		idx_e = bs_get_nr(b->bs);
		pre_e = idx_e - 1;
		item_e = NULL;
	} else {
		memcpy(&e_inc, e, bsbm_get_data_size(b->type));
		inc_fn(&e_inc);
		idx_e = bsbm_insert_data_to_bs(b, &e_inc, &pre_e, &found_e);
		if (-1 == idx_e) {
			if (!found_s)
				bs_remove_by_idx(b->bs, idx_s);

			goto ERR;
		}
		item_e = bs_get(b->bs, idx_e);
	}

	if (!found_s) {
		bm_zero(item_s->bitmap);
		if (-1 != pre_s) {
			item_pre_s = bs_get(b->bs, pre_s);
			bm_or(item_s->bitmap, item_pre_s->bitmap);
		}
	}

	if (nr_node == 2 && !found_e) {
		bm_zero(item_e->bitmap);
		if (-1 != pre_e) {
			item_pre_e = bs_get(b->bs, pre_e);
			bm_or(item_e->bitmap, item_pre_e->bitmap);
		}
	}

	for (idx = idx_s; idx < idx_e; idx++) {
		item = bs_get(b->bs, idx);
		bm_set(item->bitmap, bit);
	}

	return 0;
ERR:
	if (!found_s && item_s)
		b->mem_fn->free(item_s);
	if (!found_e && item_e)
		b->mem_fn->free(item_e);

	return -1;
}

void bsbm_remove_by_bit(struct bsbm *b, int bit)
{
	int nr_item;
	int i;
	struct bsbm_item *item;
	struct bsbm_item *pre;

	nr_item = bs_get_nr(b->bs);
	pre = NULL;
	i = 0;
	while (i < nr_item) {
		item = bs_get(b->bs, i);
		if (bm_test(item->bitmap, bit))
			bm_unset(item->bitmap, bit);

		if (i > 0) {
			pre = bs_get(b->bs, i - 1);
			if (bm_same(pre->bitmap, item->bitmap)) {
				bs_remove_by_idx(b->bs, i);
				nr_item = bs_get_nr(b->bs);

				list_del(&item->item);
				bsbm_destroy_item(b, item);
			} else {
				i++;
			}
		} else {
			if (bm_is_empty(item->bitmap)) {
				bs_remove_by_idx(b->bs, i);
				nr_item = bs_get_nr(b->bs);

				list_del(&item->item);
				bsbm_destroy_item(b, item);
			} else {
				i++;
			}
		}
	}
}

void bsbm_match(struct bsbm *b, void *data,
		struct bm *bitmap,
		enum bm_op_type bm_op)
{
	int idx;
	int pre;
	struct bsbm_item *found;

	if (NULL == bitmap)
		return;

	if (NULL == b || NULL == data)
		return;

	idx = bs_find(b->bs, data, &pre);
	if (-1 == idx) {
		if (-1 == pre) {
			if (bm_op == BM_OP_AND)
				bm_zero(bitmap);

			return;
		}

		found = bs_get(b->bs, pre);
	} else {
		found = bs_get(b->bs, idx);
	}

	if (BM_OP_AND == bm_op)
		bm_and(bitmap, found->bitmap);
	else
		bm_or(bitmap, found->bitmap);
}

int bsbm_str(const struct bsbm *b, char *str, int str_len)
{
	char *p;
	int write_len;

	p = str;
	write_len = snprintf(p, str_len, "type: %s, max_node: %d, max_bit: %d\n",
			     bsbm_type_e2s(b->type), b->max, b->max_bit);
	p += write_len;
	str_len -= write_len;

	write_len = bs_str(b->bs, p, str_len);

	return (int)(p - str) + write_len;
}

/*
 * 之所以使用这个全局变量是因为在kylin系统上gdb attach之后调用bsbm_print
 * 在控制台看不到输出，所以可以在调用之后 p bsbm_print_buf 查看
 * */
char bsbm_print_buf[1024];

void bsbm_print(struct bsbm *b)
{
	bsbm_str(b, bsbm_print_buf, sizeof(bsbm_print_buf));

	printf("%s\n", bsbm_print_buf);
}
