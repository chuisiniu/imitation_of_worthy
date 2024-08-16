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

struct bm;

struct bm *bm_create(int max_bit, struct mem_func_set *mem_fn);
struct bm *bm_create_fix(int max_bit, struct mem_func_set *mem_f);
void bm_destroy(struct bm *b);
void bm_unset(struct bm *b, uint32_t n);
void bm_zero(struct bm *b);

int bm_test(struct bm *b, uint32_t n);
int bm_set(struct bm *b, uint32_t n);
int bm_is_empty(const struct bm *b);
struct bm *bm_dup(struct bm *b);
int bm_and(struct bm *b1, struct bm *b2);
int bm_intersect(struct bm *b1, struct bm *b2);
int bm_or(struct bm *b1, struct bm *b2);
uint32_t bm_bit_capacity(struct bm *b);
int bm_is_fix(struct bm *b);
uint32_t bm_count_set(struct bm *b);
int bm_copy(struct bm *dst, struct bm *src);
int bm_str_16(struct bm *b, int nr_item, char *str, int str_len);
int bm_str(struct bm *b, char *str, int str_len);
int bm_same(const struct bm *bm1, const struct bm *bm2);
int bm_next(struct bm *b, int i);
char *bm_to_string(struct bm *b);

void bm_print(struct bm *b);

#endif //IMITATION_OF_WORTHY_BM_H
