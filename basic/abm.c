/*
 * 实现基于数组的位图
 * */
#include <strings.h>
#include <stdio.h>

#include "bm.h"

#define BM_MAX_LEN 0xFF

/*
 * 基于数组的位图，
 * */
struct abm {
	struct bm bm;

	uint8_t len; /** arr 数组的长度 */
	uint8_t bottom; /** arr 中已经被置位的最小 item 的下标，如果没置过则为 0 */
	uint8_t top; /** arr 中已经被置位的最大 item 的下标，如果没置过则为 0 */
	uint8_t fix; /** arr 长度是否固定 */
	uint32_t max_bit; /** 位图中最大可以置的位 */

	struct mem_func_set *mem_fn; /** 内存分配函数 */

	bm_item_t *arr; /** 位图数组 */
};

/** arr 数组中每项占用多少 byte */
#define BM_ARR_ITEM_SZ (sizeof(((struct abm *)0)->arr[0]))

/** arr 数组中每项可以记录多少个位 */
#define BM_NR_BIT_PER_ITEM (BM_NR_BIT_PER_CHAR * BM_ARR_ITEM_SZ)

/** arr 的长度为 _len 时， arr 数组占用多少 byte */
#define BM_ARR_SIZE(_len) (BM_ARR_ITEM_SZ * (_len))

/** arr 的长度为 _len 时， arr 数组可以记录的最高位，从 0 开始记 */
#define BM_ARR_MAX_BIT_OF_LEN(_len) (BM_NR_BIT_PER_ITEM * (_len) - 1)

/** 支持的最高位 */
#define BM_MAX_BIT BM_ARR_MAX_BIT_OF_LEN(BM_MAX_LEN)

/** 位图中第 bit 位在 _arr 数组中的下标 */
#define BM_BIT_IDX(_bit) ((_bit) / BM_NR_BIT_PER_ITEM)

/** 位图中第 bit 位在对应的 bm_item_t 上的位 */
#define BM_BIT_OFF(_bit) ((_bit) % BM_NR_BIT_PER_ITEM)

#define bm_is_fix_array(b) (BM_TYPE_FIX_ARRAY == (b)->type)
#define bm_is_array(b) (BM_TYPE_ARRAY == (b)->type)
#define bm_use_array(b) (bm_is_array(b) || bm_is_fix_array(b))

static struct mem_func_set bm_default_mem_fn = {
	.alloc = malloc,
	.realloc = realloc,
	.free = free
};

void abm_unset(struct bm *b, uint32_t n);
int abm_set(struct bm *b, uint32_t n);
void abm_clear(struct bm *b);
int abm_test(const struct bm *b, uint32_t n);
int abm_is_empty(const struct bm *b);
struct bm *abm_dup(const struct bm *b);
int abm_and(struct bm *b1, const struct bm *b2);
int abm_or(struct bm *b1, const struct bm *b2);
int abm_nr_set(const struct bm *b);
int abm_next(const struct bm *b, int i);
int abm_has_common(const struct bm *b1, const struct bm *b2);
uint32_t abm_bit_capacity(const struct bm *b);
int abm_str(const struct bm *b, char *str, int str_len);
int abm_str_hex(const struct bm *b, int nr_16, char *str, int str_len);
int abm_same(const struct bm *b1, const struct bm *b2);
struct bm *abm_create(int max_bit, struct mem_func_set *mem_f);
struct bm *abm_create_fix(int max_bit, struct mem_func_set *mem_f);
void abm_destroy(struct bm *b);

static const struct bm_interface abm_interface = {
	.create = abm_create,
	.destroy = abm_destroy,
	.unset = abm_unset,
	.clear = abm_clear,
	.test = abm_test,
	.set = abm_set,
	.is_empty = abm_is_empty,
	.dup = abm_dup,
	.and = abm_and,
	.or = abm_or,
	.nr_set = abm_nr_set,
	.next = abm_next,
	.has_common = abm_has_common,
	.bit_capacity = abm_bit_capacity,
	.str = abm_str,
	.str_hex = abm_str_hex,
	.same = abm_same,
};

static const struct bm_interface abm_fix_interface = {
	.create = abm_create_fix,
	.destroy = abm_destroy,
	.unset = abm_unset,
	.clear = abm_clear,
	.test = abm_test,
	.set = abm_set,
	.is_empty = abm_is_empty,
	.dup = abm_dup,
	.and = abm_and,
	.or = abm_or,
	.nr_set = abm_nr_set,
	.next = abm_next,
	.has_common = abm_has_common,
	.bit_capacity = abm_bit_capacity,
	.str = abm_str,
	.str_hex = abm_str_hex,
	.same = abm_same,
};

/*
 * @brief 创建一个空的位图
 *
 * @param fix 是否为定长，当 fix 为 1 的时候 arr 不会因为 arr 长度不够重新分配，所以创建
 * 的时候需要指定 init_len 为需要的最大长度，当 fix 为 0 时，如果 arr 不够时，会重新分配
 * @param init_len arr 数组的初始长度
 * @param mem_f 内存分配函数
 * */
static
struct abm *abm_create_real(
	uint8_t fix,
	uint8_t init_len,
	struct mem_func_set *mem_f)
{
	size_t sz;
	struct abm *ab;
	struct mem_func_set *mem_fn;

	mem_fn = mem_f ? mem_f : &bm_default_mem_fn;

	ab = mem_fn->alloc(sizeof(*ab));
	if (NULL == ab)
		return NULL;

	sz = BM_ARR_SIZE(init_len);
	ab->arr = mem_fn->alloc(sz);
	if (NULL == ab->arr) {
		mem_fn->free(ab);

		return NULL;
	}

	ab->len = init_len;
	ab->top = 0;
	ab->bottom = 0;
	ab->arr[0] = 0;
	ab->fix = fix;
	ab->max_bit = BM_ARR_MAX_BIT_OF_LEN(ab->len);
	ab->mem_fn = mem_fn;

	return ab;
}

static inline
size_t abm_calc_len(unsigned int max_bit)
{
	if (0 == max_bit % BM_NR_BIT_PER_ITEM)
		return max_bit / BM_NR_BIT_PER_ITEM;
	else
		return max_bit / BM_NR_BIT_PER_ITEM + 1;
}

/*
 * @brief 创建一个初始长度为 len 的变长位图
 * @param max_bit 最多多少位
 * @param mem_f 内存分配释放函数，如果为空则使用malloc
 * */
struct bm *abm_create(int max_bit, struct mem_func_set *mem_f)
{
	struct abm *ab;

	ab = abm_create_real(0, abm_calc_len(max_bit), mem_f);

	ab->bm.type = BM_TYPE_ARRAY;
	ab->bm.interface = &abm_interface;

	return &ab->bm;
}

/*
 * @brief 创建一个初始长度为 len 的定长位图
 * @param max_bit 最多多少位
 * @param mem_f 内存分配释放函数，如果为空则使用malloc
 * */
struct bm *abm_create_fix(int max_bit, struct mem_func_set *mem_f)
{
	struct abm *ab;

	ab = abm_create_real(1, abm_calc_len(max_bit), mem_f);

	ab->bm.type = BM_TYPE_FIX_ARRAY;
	ab->bm.interface = &abm_fix_interface;

	return &ab->bm;
}

/*
 * @brief 释放位图
 * @param b 位图
 * */
void abm_destroy(struct bm *b)
{
	void (* free_fn)(void *ptr);
	struct abm *ab;

	if (NULL == b)
		return;

	ab = (struct abm*)b;
	free_fn = ab->mem_fn->free;
	if (ab->arr)
		free_fn(ab->arr);

	free_fn(ab);
}

static
int abm_realloc(struct abm *ab, uint8_t len)
{
	bm_item_t *new_arr;

	if (ab->len == len)
		return 0;

	if (ab->fix)
		return -1;

	new_arr = ab->mem_fn->realloc(ab->arr, BM_ARR_SIZE(len));
	if (NULL == new_arr)
		return -1;

	ab->arr = new_arr;
	ab->len = len;
	ab->max_bit = BM_ARR_MAX_BIT_OF_LEN(ab->len);

	// len < b->len 时可能会出现
	if (ab->bottom >= len) {
		ab->bottom = 0;
		ab->top = 0;
		ab->arr[0] = 0;
	}

	if (ab->top >= len)
		ab->top = len - 1;

	return 0;
}

static
void abm_reset_bottom_top(struct abm *ab)
{
	size_t realloc_len;

	if (ab->top >= ab->len) {
		ab->top = ab->len - 1;

		return;
	}

	while (ab->top > ab->bottom && ab->arr[ab->top] == 0)
		ab->top--;

	while (ab->bottom < ab->top && ab->arr[ab->bottom] == 0)
		ab->bottom++;

	if (ab->bottom > 0 && ab->bottom == ab->top && ab->arr[ab->top] == 0) {
		ab->bottom = 0;
		ab->top = 0;
		ab->arr[0] = 0;
	}

	if (ab->fix || ab->len <= 2)
		return;

	if (ab->top >= ab->len / 2)
		return;

	realloc_len = ab->len - (ab->len - ab->top) / 2;
	if (realloc_len >= ab->len)
		return;

	abm_realloc(ab, realloc_len);
}

/*
 * @brief 从位图上清掉第 n 位
 * @param b 位图
 * @param n 第几位
 * */
void abm_unset(struct bm *b, uint32_t n)
{
	uint32_t i;
	struct abm *ab;

	ab = (struct abm *)b;
	if (n > ab->max_bit)
		return;

	i = BM_BIT_IDX(n);
	if (i > ab->top)
		return;
	ab->arr[i] &= (~((bm_item_t)1 << (BM_BIT_OFF(n))));

	if (i == ab->top || i == ab->bottom)
		abm_reset_bottom_top(ab);
}

/*
 * @brief 清掉位图
 * @param b 位图
 * */
void abm_clear(struct bm *b)
{
	struct abm *ab;

	ab = (struct abm *)b;

	ab->bottom = 0;
	ab->top = 0;
	ab->arr[0] = 0;

	abm_reset_bottom_top(ab);
}

/*
 * @brief 检测位图第 n 位是否置 1 了
 * @param b 位图
 * @param n 第几位
 * */
int abm_test(const struct bm *b, uint32_t n)
{
	uint32_t i;
	const struct abm *ab;

	ab = (const struct abm *)b;
	if (ab->top >= ab->len)
		return 0;

	i = BM_BIT_IDX(n);
	if (i > ab->top || i < ab->bottom)
		return 0;

	return (ab->arr[i] & ((bm_item_t)1 << BM_BIT_OFF(n))) != 0;
}

/*
 * @brief 把位图 b 的第 n 位置 1
 * @param b 位图
 * @param n 第几位
 * */
int abm_set(struct bm *b, uint32_t n)
{
	uint32_t i;
	uint32_t j;
	struct abm *ab;

	ab = (struct abm *)b;
	if (ab->top >= ab->len || n > BM_MAX_BIT)
		return -1;

	if (ab->max_bit < n && ab->fix)
		return -1;

	i = BM_BIT_IDX(n);
	if (i >= ab->len) {
		if (0 != abm_realloc(ab, i + 1)) {
			return -1;
		}
	}

	if (abm_is_empty(b)) {
		ab->top = i;
		ab->bottom = i;
		ab->arr[i] = 0;
	} else if (i > ab->top) {
		for (j = ab->top + 1; j <= i; j++)
			ab->arr[j] = 0;
		ab->top = i;
	}

	if (i < ab->bottom) {
		for (j = i; j < ab->bottom; j++)
			ab->arr[j] = 0;
		ab->bottom = i;
	}

	ab->arr[i] |= ((bm_item_t)1 << BM_BIT_OFF(n));

	return 0;
}

int abm_is_empty(const struct bm *b)
{
	const struct abm *ab;

	ab = (const struct abm *)b;
	if (ab->bottom >= ab->len || ab->top >= ab->len)
		return 1;

	return ab->bottom == ab->top && 0 == ab->arr[ab->bottom];
}

struct bm *abm_dup(const struct bm *b)
{
	int new_len;
	const struct abm *ab;
	struct abm *new_ab;

	ab = (const struct abm *)b;
	new_len = ab->fix ? ab->len : ab->top + 1;
	new_ab = abm_create_real(ab->fix, new_len, ab->mem_fn);
	if (NULL == new_ab)
		return NULL;

	for (new_ab->top = ab->bottom; new_ab->top < ab->top; new_ab->top++)
		new_ab->arr[new_ab->top] = ab->arr[new_ab->top];
	new_ab->arr[new_ab->top] = ab->arr[new_ab->top];
	new_ab->bottom = ab->bottom;

	return &new_ab->bm;
}

/*
 * @brief b1 and b2，结果输出到 b1
 * @param b1
 * @param b2
 * @return 0 成功 -1 失败
 * */
int abm_and(struct bm *b1, const struct bm *b2)
{
	int i;
	int top_min;
	int bottom_max;
	struct abm *ab1;
	const struct abm *ab2;

	ab1 = (struct abm *)b1;
	ab2 = (const struct abm *)b2;

	if (abm_is_empty(b1))
		return 0;

	if (!bm_use_array(b2))
		return bm_and_slow(b1, b2);

	if (abm_is_empty(b2)) {
		abm_clear(b1);
	} else {
		top_min = ab1->top < ab2->top ? ab1->top : ab2->top;
		bottom_max = ab1->bottom > ab2->bottom ? ab1->bottom : ab2->bottom;
		if (top_min < bottom_max) {
			ab1->bottom = 0;
			ab1->top = 0;
			ab1->arr[0] = 0;
		} else {
			for (i = bottom_max; i <= top_min; i++)
				ab1->arr[i] &= ab2->arr[i];

			ab1->bottom = bottom_max;
			ab1->top = top_min;
		}
	}

	// 有可能需要重新分配内存
	abm_reset_bottom_top(ab1);

	return 0;
}


int abm_has_common(const struct bm *b1, const struct bm *b2)
{
	int i;
	int top_min;
	int bottom_max;
	struct abm *ab1;
	const struct abm *ab2;

	if (abm_is_empty(b1) || bm_is_empty(b2))
		return 0;

	if (!bm_use_array(b2))
		return bm_has_common_slow(b1, b2);

	ab1 = (struct abm *)b1;
	ab2 = (const struct abm *)b2;
	top_min = ab1->top < ab2->top ? ab1->top : ab2->top;
	bottom_max = ab1->bottom > ab2->bottom ? ab1->bottom : ab2->bottom;
	if (top_min >= bottom_max) {
		for (i = bottom_max; i <= top_min; i++) {
			if (ab1->arr[i] & ab2->arr[i]) {
				return 1;
			}
		}
	}

	return 0;
}

/*
 * @brief b1 or b2，结果输出到 b1
 * @param b1
 * @param b2
 * @return 0 成功 -1 失败
 * */
int abm_or(struct bm *b1, const struct bm *b2)
{
	int i;
	int bottom_min;
	int top_max;
	struct abm *ab1;
	const struct abm *ab2;

	if (!bm_use_array(b2))
		return bm_or_slow(b1, b2);

	ab1 = (struct abm *)b1;
	ab2 = (const struct abm *)b2;
	if (ab1->len <= ab2->top) {
		if (0 != abm_realloc(ab1, ab2->top + 1))
			return  -1;
	}

	if (abm_is_empty(b2))
		return 0;

	if (abm_is_empty(b1)) {
		ab1->bottom = ab2->bottom;
		ab1->top = ab1->bottom;
		ab1->arr[ab1->bottom] = 0;
	}

	bottom_min = ab1->bottom < ab2->bottom ? ab1->bottom : ab2->bottom;
	top_max = ab1->top > ab2->top ? ab1->top : ab2->top;

	for (i = bottom_min; i <= top_max; i++) {
		if (i < ab1->bottom || i > ab1->top)
			ab1->arr[i] = 0;

		if (ab2->bottom <= i && i <= ab2->top)
			ab1->arr[i] |= ab2->arr[i];
	}

	ab1->bottom = bottom_min;
	ab1->top = top_max;

	return 0;
}

uint32_t abm_bit_capacity(const struct bm *b)
{
	return ((const struct abm *)b)->max_bit + 1;
}

int abm_is_fix(const struct bm *b)
{
	return ((const struct abm *)b)->fix != 0;
}

/*
 * @brief 计算位图中被置位的个数
 * @param b 位图
 * */
int abm_nr_set(const struct bm *b)
{
	uint32_t total;
	int i;
	const struct abm *ab;

	ab = (const struct abm *)b;
	if (ab->top >= ab->len)
		return 0;

	total = 0;
	for (i = ab->bottom; i <= ab->top; i++)
		total += bm_count_set_in_u64(ab->arr[i]);

	return total;
}

int abm_same(const struct bm *b1, const struct bm *b2)
{
	int i;
	const struct abm *ab1;
	const struct abm *ab2;

	if (!bm_use_array(b2))
		return bm_same_slow(b1, b2);

	ab1 = (const struct abm *) b1;
	ab2 = (const struct abm *) b2;
	if (abm_is_empty(b1) && abm_is_empty(b2))
		return 1;

	if (ab1->bottom != ab2->bottom || ab1->top != ab2->top)
		return 0;

	for (i = ab1->bottom; i <= ab1->top; i++) {
		if (ab1->arr[i] != ab2->arr[i])
			return 0;
	}

	return 1;
}

/*
 * @brief b 输出到 str 上，输出字符串长度为 16 * nr_16 + 2
 * */
int abm_str_hex(const struct bm *b, int nr_16, char *str, int str_len)
{
	int i;
	char *s;
	uint64_t  output;
	int nr_item;
	int nr_bits;
	const struct abm *ab;

	if (str_len < 19)
		return -1;

	ab = (const struct abm *)b;
	if (0 == nr_16) {
		nr_bits = (ab->top + 1) * (int)BM_NR_BIT_PER_ITEM;
	} else {
		nr_bits = 64 * nr_16;
	}

	// 每个 uint64_t 16个字符，加前导的 0x 和最后的 '\0'
	if (nr_16 * 16 + 3 > str_len)
		return -1;

	nr_item = nr_bits / (int)BM_NR_BIT_PER_ITEM - 1;
	str[0] = '0';
	str[1] = 'x';
	s = str + 2;
	for (i = nr_item; i >= 0; i--) {
		output = i > ab->top ? 0 : (i < ab->bottom ? 0 : ab->arr[i]);
		sprintf(s, "%0*llX", (int)BM_NR_BIT_PER_ITEM / 4, output);
		s += (int)BM_NR_BIT_PER_ITEM / 4;
	}

	return 0;
}


int abm_str(const struct bm *b, char *str, int str_len)
{
	int i;
	int max;
	int write_len;
	char *p;
	const struct abm *ab;

	ab = (const struct abm *)b;
	max = BM_NR_BIT_PER_ITEM * (ab->top + 1);
	p = str;
	for (i = 0; i < max; i++) {
		if (abm_test(b, i)) {
			write_len = snprintf(p, str_len, "%d,", i);
			p += write_len;
			str_len -= write_len;

			if (str_len <= 0)
				break;
		}
	}

	if (p != str)
		*(p - 1) = '\0';
	else
		*p = '\0';

	return 0;
}

char *abm_to_string(struct bm *b)
{
	static __thread char strbuf[256];

	abm_str(b, strbuf, sizeof(strbuf));

	return strbuf;
}


char abm_print_buf[256];

void abm_print(struct bm *b)
{
	abm_str(b, abm_print_buf, sizeof(abm_print_buf));

	printf("%s\n", abm_print_buf);
}

int abm_next(const struct bm *b, int i)
{
	int pos;
	int bit;
	const struct abm *ab;

	ab = (const struct abm *)b;
	pos = i < 0 ? ab->bottom : (i / (int)BM_NR_BIT_PER_ITEM);
	bit = i < 0 ? 0 : (i % (int)BM_NR_BIT_PER_ITEM + 1);
	if (BM_NR_BIT_PER_ITEM == bit) {
		pos += 1;
		bit = 0;
	}
	if (pos > ab->top)
		return -1;

	while (pos <= ab->top) {
		if (ab->arr[pos] & ((uint64_t)1 << bit))
			return (pos * (int)BM_NR_BIT_PER_ITEM + bit);

		bit++;
		if (BM_NR_BIT_PER_ITEM == bit) {
			pos += 1;
			bit = 0;
		}
	}

	return -1;
}
