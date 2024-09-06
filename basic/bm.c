#include <stdio.h>

#include "bm.h"
#include "abm.h"

struct bm *bm_get_bm(
	enum bm_type type,
	int max_bit,
	struct mem_func_set *mem_fn)
{
	switch (type) {
	case BM_TYPE_ARRAY:
		return abm_create(max_bit, mem_fn);
	case BM_TYPE_FIX_ARRAY:
		return abm_create_fix(max_bit, mem_fn);
	default:
		return NULL;
	}
}

int bm_and_slow(struct bm *b1, const struct bm *b2)
{
	int next_b1;

	next_b1 = bm_next(b1, -1);
	while (next_b1 != -1) {
		if (!bm_test(b2, next_b1))
			bm_unset(b1, next_b1);

		next_b1 = bm_next(b1, next_b1);
	}

	return 0;
}

int bm_or_slow(struct bm *b1, const struct bm *b2)
{
	int next_b2;

	next_b2 = bm_next(b2, -1);
	while (next_b2 != -1) {
		if (0 != bm_set(b1, next_b2))
			return -1;
		next_b2 = bm_next(b2, next_b2);
	}

	return 0;
}

int bm_has_common_slow(const struct bm *b1, const struct bm *b2)
{
	int next_b1;
	int next_b2;

	next_b1 = bm_next(b1, -1);
	next_b2 = bm_next(b2, -1);
	do {
		if (next_b1 < next_b2)
			next_b1 = bm_next(b1, next_b1);
		else if (next_b1 == next_b2)
			return 1;
		else
			next_b2 = bm_next(b2, next_b2);
	} while (next_b1 != -1 && next_b2 != -1);

	return 0;
}

int bm_same_slow(const struct bm *b1, const struct bm *b2)
{
	int next_b1;
	int next_b2;

	next_b1 = -1;
	next_b2 = -1;
	while (next_b1 == next_b2) {
		next_b1 = bm_next(b1, next_b1);
		next_b2 = bm_next(b2, next_b2);
	}

	return next_b1 == next_b2;
}

char *bm_to_string(struct bm *b)
{
	static __thread char strbuf[256];

	bm_str(b, strbuf, sizeof(strbuf));

	return strbuf;
}

char bm_print_buf[256];

void bm_print(struct bm *b)
{
	bm_str(b, bm_print_buf, sizeof(bm_print_buf));

	printf("%s\n", bm_print_buf);
}
