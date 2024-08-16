#ifndef BS_H
#define BS_H
#include "memhook.h"

struct bs;

struct bs *bs_create(int max,
		     int (*cmp_f)(const void *d1, const void *d2),
		     int (*to_str_f)(const void *data, char *str, int str_len),
		     struct mem_func_set *mem_f);

int bs_find(struct bs *b, void *data, int *pre);

int bs_insert(struct bs *b, void *data);

void *bs_remove_by_data(struct bs *b, void *data);

void *bs_remove_by_idx(struct bs *b, int idx);

void bs_destroy(struct bs *b);

void *bs_get(struct bs *b, int i);

int bs_get_nr(struct bs *b);

void bs_iter(struct bs *b,
	     void (*fn)(int idx, const void *d, void *args),
	     void *args);

int bs_is_empty(struct bs *b);

int bs_get_capacity(struct bs *b);

int bs_str(const struct bs *b, char *str, int str_len);

void bs_print(struct bs *b);

#endif // BS_H
