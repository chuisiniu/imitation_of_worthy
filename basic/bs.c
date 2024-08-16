/*
 * 二分查找实现
 * */
#include <stdio.h>

#include "memhook.h"
#include "bs.h"

struct bs {
	int max; // arr 的长度
	int nr; // 已经保存的数据的个数

	int (*cmp)(const void *d1, const void *d2); // 比较函数
	int (*to_str)(const void *data, char *str, int str_len);

	struct mem_func_set *mem_fn;

	void **arr; // 保存所有数据的数组
};

static struct mem_func_set bs_default_mem_fn = {
	.alloc = malloc,
	.realloc = realloc,
	.free = free
};

struct bs *bs_create(int max,
		     int (*cmp_f)(const void *d1, const void *d2),
		     int (*to_str_f)(const void *data, char *str, int str_len),
		     struct mem_func_set *mem_f)
{
	size_t sz;
	struct bs *bs;
	struct mem_func_set *mem_fn;

	mem_fn = mem_f ? mem_f : &bs_default_mem_fn;

	bs = mem_fn->alloc(sizeof(*bs));
	if (NULL == bs)
		return NULL;

	sz = max * sizeof(void *);
	bs->arr = mem_fn->alloc(sz);
	if (NULL == bs->arr) {
		mem_fn->free(bs);

		return NULL;
	}

	bs->max = max;
	bs->cmp = cmp_f;
	bs->to_str = to_str_f;
	bs->mem_fn = mem_fn;
	bs->nr = 0;

	return bs;
}

int bs_find(struct bs *b, void *data, int *pre)
{
	int s;
	int e;
	int mid;
	int res;

	if (0 == b->nr) {
		*pre = -1;

		return -1;
	}

	s = 0;
	e = b->nr - 1;
	*pre = -1;
	while (s <= e) {
		mid = (s + e) / 2;
		res = b->cmp(b->arr[mid], data);
		if (res < 0) {
			s = mid + 1;

			*pre = mid;
		} else if (0 == res) {
			*pre = mid - 1;

			return mid;
		} else {
			e = mid - 1;
		}
	}

	return -1;
}

int bs_insert(struct bs *b, void *data)
{
	int pos;
	int pre;
	int i;

	if (b->nr >= b->max)
		return -1;

	pos = bs_find(b, data, &pre);
	if (pos >= 0)
		return pos;

	for (i = b->nr - 1; i > pre; i--)
		b->arr[i + 1] = b->arr[i];

	b->arr[pre + 1] = data;
	b->nr += 1;

	return pre + 1;
}

void *bs_remove_by_idx(struct bs *b, int idx)
{
	int i;
	void *result;

	if (idx < 0 || idx >= b->nr)
		return NULL;

	result = b->arr[idx];
	for (i = idx; i < b->nr - 1; i++)
		b->arr[i] = b->arr[i + 1];

	b->arr[b->nr - 1] = NULL;
	b->nr -= 1;

	return result;
}

void *bs_remove_by_data(struct bs *b, void *data)
{
	int pos;
	int pre;

	if (b->nr == 0)
		return NULL;

	pos = bs_find(b, data, &pre);
	if (pos < 0)
		return NULL;

	return bs_remove_by_idx(b, pos);
}

void *bs_get(struct bs *b, int i)
{
	if (i >= b->nr)
		return NULL;

	return b->arr[i];
}

void bs_iter(struct bs *b,
	     void (*fn)(int idx, const void *d, void *args),
	     void *args)
{
	int i;

	for (i = 0; i < b->nr; i++)
		fn(i, b->arr[i], args);
}

void bs_destroy(struct bs *b)
{
	void (* free_fn)(void *ptr);

	if (NULL == b)
		return;

	free_fn = b->mem_fn->free;
	if (b->arr)
		free_fn(b->arr);

	free_fn(b);
}

int bs_is_empty(struct bs *b)
{
	return 0 == b->nr;
}

int bs_get_nr(struct bs *b)
{
	return b->nr;
}

int bs_get_capacity(struct bs *b)
{
	return b->max;
}

int bs_str(const struct bs *b, char *str, int str_len)
{
	int i;
	int write_len;
	char *p;

	p = str;
	for (i = 0; i < b->nr; i++) {
		if (NULL == b->to_str)
			continue;

		write_len = snprintf(p, str_len, "item %d:", i);
		p += write_len;
		str_len -= write_len;
		if (str_len <= 0)
			break;

		write_len = b->to_str(b->arr[i], p, str_len);
		p += write_len;
		str_len -= write_len;
		if (str_len <= 0)
			break;

		*(p++) = '\n';
		str_len -= 1;
		if (str_len <= 0)
			break;
	}

	*p = '\0';

	return (int)(p - str);
}

char bs_print_buf[1024];

void bs_print(struct bs *b)
{
	bs_str(b, bs_print_buf, sizeof(bs_print_buf));

	printf("%s\n", bs_print_buf);
}
