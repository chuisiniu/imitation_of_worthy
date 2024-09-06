#ifndef IMITATION_OF_WORTHY_BM_H
#define IMITATION_OF_WORTHY_BM_H
#include <stdint.h>
#include <stdlib.h>

#include "memhook.h"

/** 一个 char 可以保存多少位 */
#define BM_NR_BIT_PER_CHAR 8

typedef uint64_t bm_item_t;

enum bm_op_type {
	BM_OP_AND,
	BM_OP_OR,

	BM_OP_MAX,
};

enum bm_type {
	BM_TYPE_ARRAY,
	BM_TYPE_FIX_ARRAY,
};

struct bm;
struct bm_interface {
	struct bm *(*create)(int max_bit, struct mem_func_set *mem_fn);
	void (*destroy)(struct bm *b);
	void (*unset)(struct bm *b, uint32_t n);
	void (*clear)(struct bm *b);
	int (*test)(const struct bm *b, uint32_t n);
	int (*set)(struct bm *b, uint32_t n);
	int (*is_empty)(const struct bm *b);
	struct bm *(*dup)(const struct bm *b);
	int (*and)(struct bm *b1, const struct bm *b2);
	int (*or)(struct bm *b1, const struct bm *b2);
	int (*nr_set)(const struct bm *b);
	int (*next)(const struct bm *b, int i);
	int (*has_common)(const struct bm *b1, const struct bm *b2);
	uint32_t (*bit_capacity)(const struct bm *b);
	int (*str)(const struct bm *b, char *str, int str_len);
	int (*str_hex)(const struct bm *b, int nr_item, char *str, int str_len);
	int (*same)(const struct bm *bm1, const struct bm *bm2);
};

struct bm {
	enum bm_type type;
	const struct bm_interface *interface;
};

struct bm *bm_get_bm(
	enum bm_type type,
	int max_bit,
	struct mem_func_set *mem_fn);

static inline
struct bm *bm_create(int max_bit, struct mem_func_set *mem_fn)
{
	return bm_get_bm(BM_TYPE_ARRAY, max_bit, mem_fn);
}

static inline
struct bm *bm_create_fix(int max_bit, struct mem_func_set *mem_fn)
{
	return bm_get_bm(BM_TYPE_FIX_ARRAY, max_bit, mem_fn);
}

static inline
void bm_destroy(struct bm *b)
{
	b->interface->destroy(b);
}

static inline
void bm_unset(struct bm *b, uint32_t n)
{
	b->interface->unset(b, n);
}

static inline
void bm_zero(struct bm *b)
{
	b->interface->clear(b);
}

static inline
int bm_test(const struct bm *b, uint32_t n)
{
	return b->interface->test(b, n);
}

static inline
int bm_set(struct bm *b, uint32_t n)
{
	return b->interface->set(b, n);
}

static inline
int bm_is_empty(const struct bm *b)
{
	return b->interface->is_empty(b);
}

static inline
struct bm *bm_dup(const struct bm *b)
{
	return b->interface->dup(b);
}

static inline
int bm_and(struct bm *b1, const struct bm *b2)
{
	return b1->interface->and(b1, b2);
}

static inline
int bm_has_common(struct bm *b1, struct bm *b2)
{
	return b1->interface->has_common(b1, b2);
}

static inline
int bm_or(struct bm *b1, const struct bm *b2)
{
	return b1->interface->or(b1, b2);
}

static inline
uint32_t bm_bit_capacity(const struct bm *b)
{
	return b->interface->bit_capacity(b);
}

static inline
uint32_t bm_nr_set(const struct bm *b)
{
	return b->interface->nr_set(b);
}

static inline
int bm_str_hex(struct bm *b, int nr_item, char *str, int str_len)
{
	return b->interface->str_hex(b, nr_item, str, str_len);
}

static inline
int bm_str(struct bm *b, char *str, int str_len)
{
	return b->interface->str(b, str, str_len);
}

static inline
int bm_same(const struct bm *bm1, const struct bm *bm2)
{
	return bm1->interface->same(bm1, bm2);
}

static inline
int bm_next(const struct bm *b, int i)
{
	return b->interface->next(b, i);
}

char *bm_to_string(struct bm *b);

void bm_print(struct bm *b);

int bm_and_slow(struct bm *b1, const struct bm *b2);
int bm_or_slow(struct bm *b1, const struct bm *b2);
int bm_same_slow(const struct bm *b1, const struct bm *b2);
int bm_has_common_slow(const struct bm *b1, const struct bm *b2);

static inline
uint32_t bm_count_set_in_u64(uint64_t n)
{
	n = (n & 0x5555555555555555)
	    + ((n >> 1) & 0x5555555555555555); //相邻两位相加,保存为int2
	n = (n & 0x3333333333333333)
	    + ((n >> 2) & 0x3333333333333333); //相邻int2相加,保存为int4
	n = (n & 0x0f0f0f0f0f0f0f0f)
	    + ((n >> 4) & 0x0f0f0f0f0f0f0f0f); //相邻int4相加,保存为int8
	n = (n & 0x00ff00ff00ff00ff)
	    + ((n >> 8) & 0x00ff00ff00ff00ff); //相邻int8相加,保存为int16
	n = (n & 0x0000ffff0000ffff)
	    + ((n >> 16) & 0x0000ffff0000ffff); //相邻int16相加,保存为int32
	n = (n & 0x00000000ffffffff)
	    + ((n >> 32) & 0x00000000ffffffff); //相邻int32相加,保存为int64

	return (uint32_t )n;
}

static inline
int bm_is_fix(struct bm *b)
{
	return b->type == BM_TYPE_FIX_ARRAY;
}

#endif //IMITATION_OF_WORTHY_BM_H
