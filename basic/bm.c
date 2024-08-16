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
struct bm {
	uint8_t len; /** arr 数组的长度 */
	uint8_t bottom; /** arr 中已经被置位的最小 item 的下标，如果没置过则为 0 */
	uint8_t top; /** arr 中已经被置位的最大 item 的下标，如果没置过则为 0 */
	uint8_t fix; /** arr 长度是否固定 */
	uint32_t max_bit; /** 位图中最大可以置的位 */

	struct mem_func_set *mem_fn; /** 内存分配函数 */

	bm_item_t *arr; /** 位图数组 */
};

/** arr 数组中每项占用多少 byte */
#define BM_ARR_ITEM_SZ (sizeof(((struct bm *)0)->arr[0]))

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

static struct mem_func_set bm_default_mem_fn = {
	.alloc = malloc,
	.realloc = realloc,
	.free = free
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
struct bm *bm_create_real(uint8_t fix,
                          uint8_t init_len,
                          struct mem_func_set *mem_f)
{
	size_t sz;
	struct bm *bm;
	struct mem_func_set *mem_fn;

	mem_fn = mem_f ? mem_f : &bm_default_mem_fn;

	bm = mem_fn->alloc(sizeof(*bm));
	if (NULL == bm)
		return NULL;

	sz = BM_ARR_SIZE(init_len);
	bm->arr = mem_fn->alloc(sz);
	if (NULL == bm->arr) {
		mem_fn->free(bm);

		return NULL;
	}

	bm->len = init_len;
	bm->top = 0;
	bm->bottom = 0;
	bm->arr[0] = 0;
	bm->fix = fix;
	bm->max_bit = BM_ARR_MAX_BIT_OF_LEN(bm->len);
	bm->mem_fn = mem_fn;

	return bm;
}

static inline
size_t bm_calc_len(unsigned int max_bit)
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
struct bm *bm_create(int max_bit, struct mem_func_set *mem_f)
{
	return bm_create_real(0, bm_calc_len(max_bit), mem_f);
}

/*
 * @brief 创建一个初始长度为 len 的定长位图
 * @param max_bit 最多多少位
 * @param mem_f 内存分配释放函数，如果为空则使用malloc
 * */
struct bm *bm_create_fix(int max_bit, struct mem_func_set *mem_f)
{
	return bm_create_real(1, bm_calc_len(max_bit), mem_f);
}

/*
 * @brief 释放位图
 * @param b 位图
 * */
void bm_destroy(struct bm *b)
{
	void (* free_fn)(void *ptr);

	if (NULL == b)
		return;

	free_fn = b->mem_fn->free;
	if (b->arr)
		free_fn(b->arr);

	free_fn(b);
}

static
int bm_realloc(struct bm *b, uint8_t len)
{
	bm_item_t *new_arr;

	if (b->len == len)
		return 0;

	if (b->fix)
		return -1;

	new_arr = b->mem_fn->realloc(b->arr, BM_ARR_SIZE(len));
	if (NULL == new_arr)
		return -1;

	b->arr = new_arr;
	b->len = len;
	b->max_bit = BM_ARR_MAX_BIT_OF_LEN(b->len);

	// len < b->len 时可能会出现
	if (b->bottom >= len) {
		b->bottom = 0;
		b->top = 0;
		b->arr[0] = 0;
	}

	if (b->top >= len)
		b->top = len - 1;

	return 0;
}

static
void bm_reset_bottom_top(struct bm *b)
{
	size_t realloc_len;

	if (b->top >= b->len) {
		b->top = b->len - 1;

		return;
	}

	while (b->top > b->bottom && b->arr[b->top] == 0)
		b->top--;

	while (b->bottom < b->top && b->arr[b->bottom] == 0)
		b->bottom++;

	if (b->bottom > 0 && b->bottom == b->top && b->arr[b->top] == 0) {
		b->bottom = 0;
		b->top = 0;
		b->arr[0] = 0;
	}

	if (b->fix || b->len <= 2)
		return;

	if (b->top >= b->len / 2)
		return;

	realloc_len = b->len - (b->len - b->top) / 2;
	if (realloc_len >= b->len)
		return;

	bm_realloc(b, realloc_len);
}

/*
 * @brief 从位图上清掉第 n 位
 * @param b 位图
 * @param n 第几位
 * */
void bm_unset(struct bm *b, uint32_t n)
{
	uint32_t i;

	if (n > b->max_bit)
		return;

	i = BM_BIT_IDX(n);
	if (i > b->top)
		return;
	b->arr[i] &= (~((bm_item_t)1 << (BM_BIT_OFF(n))));

	if (i == b->top || i == b->bottom)
		bm_reset_bottom_top(b);
}

/*
 * @brief 清掉位图
 * @param b 位图
 * */
void bm_zero(struct bm *b)
{
	b->bottom = 0;
	b->top = 0;
	b->arr[0] = 0;

	bm_reset_bottom_top(b);
}

/*
 * @brief 检测位图第 n 位是否置 1 了
 * @param b 位图
 * @param n 第几位
 * */
int bm_test(struct bm *b, uint32_t n)
{
	uint32_t i;

	if (b->top >= b->len)
		return 0;

	i = BM_BIT_IDX(n);
	if (i > b->top || i < b->bottom)
		return 0;

	return (b->arr[i] & ((bm_item_t)1 << BM_BIT_OFF(n))) != 0;
}

/*
 * @brief 把位图 b 的第 n 位置 1
 * @param b 位图
 * @param n 第几位
 * */
int bm_set(struct bm *b, uint32_t n)
{
	uint32_t i;
	uint32_t j;
	struct bm *bm;

	bm = b;
	if (bm->top >= bm->len || n > BM_MAX_BIT)
		return -1;

	if (bm->max_bit < n && bm->fix)
		return -1;

	i = BM_BIT_IDX(n);
	if (i >= bm->len) {
		if (0 != bm_realloc(b, i + 1)) {
			return -1;
		}
	}

	if (bm_is_empty(b)) {
		bm->top = i;
		bm->bottom = i;
		bm->arr[i] = 0;
	} else if (i > bm->top) {
		for (j = bm->top + 1; j <= i; j++)
			bm->arr[j] = 0;
		bm->top = i;
	}

	if (i < bm->bottom) {
		for (j = i; j < bm->bottom; j++)
			bm->arr[j] = 0;
		bm->bottom = i;
	}

	bm->arr[i] |= ((bm_item_t)1 << BM_BIT_OFF(n));

	return 0;
}

int bm_is_empty(const struct bm *b)
{
	if (b->bottom >= b->len || b->top >= b->len)
		return 1;

	return b->bottom == b->top && 0 == b->arr[b->bottom];
}

struct bm *bm_dup(struct bm *b)
{
	int new_len;
	struct bm *new_b;

	new_len = b->fix ? b->len : b->top + 1;
	new_b = bm_create_real(b->fix, new_len, b->mem_fn);
	if (NULL == new_b)
		return NULL;

	for (new_b->top = b->bottom; new_b->top < b->top; new_b->top++)
		new_b->arr[new_b->top] = b->arr[new_b->top];
	new_b->arr[new_b->top] = b->arr[new_b->top];
	new_b->bottom = b->bottom;

	return new_b;
}

/*
 * @brief b1 and b2，结果输出到 b1
 * @param b1
 * @param b2
 * @return 0 成功 -1 失败
 * */
int bm_and(struct bm *b1, struct bm *b2)
{
	int i;
	int top_min;
	int bottom_max;

	if (bm_is_empty(b1))
		return 0;

	if (bm_is_empty(b2)) {
		bm_zero(b1);
	} else {
		top_min = b1->top < b2->top ? b1->top : b2->top;
		bottom_max = b1->bottom > b2->bottom ? b1->bottom : b2->bottom;
		if (top_min < bottom_max) {
			b1->bottom = 0;
			b1->top = 0;
			b1->arr[0] = 0;
		} else {
			for (i = bottom_max; i <= top_min; i++)
				b1->arr[i] &= b2->arr[i];

			b1->bottom = bottom_max;
			b1->top = top_min;
		}
	}

	// 有可能需要重新分配内存
	bm_reset_bottom_top(b1);

	return 0;
}


int bm_intersect(struct bm *b1, struct bm *b2)
{
	int i;
	int top_min;
	int bottom_max;

	if (bm_is_empty(b1) || bm_is_empty(b2))
		return 0;

	top_min = b1->top < b2->top ? b1->top : b2->top;
	bottom_max = b1->bottom > b2->bottom ? b1->bottom : b2->bottom;
	if (top_min >= bottom_max) {
		for (i = bottom_max; i <= top_min; i++) {
			if (b1->arr[i] & b2->arr[i]) {
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
int bm_or(struct bm *b1, struct bm *b2)
{
	int i;
	int bottom_min;
	int top_max;

	if (b1->len <= b2->top) {
		if (0 != bm_realloc(b1, b2->top + 1))
			return  -1;
	}

	if (bm_is_empty(b2))
		return 0;

	if (bm_is_empty(b1)) {
		b1->bottom = b2->bottom;
		b1->top = b1->bottom;
		b1->arr[b1->bottom] = 0;
	}

	bottom_min = b1->bottom < b2->bottom ? b1->bottom : b2->bottom;
	top_max = b1->top > b2->top ? b1->top : b2->top;

	for (i = bottom_min; i <= top_max; i++) {
		if (i < b1->bottom || i > b1->top)
			b1->arr[i] = 0;

		if (b2->bottom <= i && i <= b2->top)
			b1->arr[i] |= b2->arr[i];
	}

	b1->bottom = bottom_min;
	b1->top = top_max;

	return 0;
}

uint32_t bm_bit_capacity(struct bm *b)
{
	return b->max_bit + 1;
}

int bm_is_fix(struct bm *b)
{
	return b->fix != 0;
}

static
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

/*
 * @brief 计算位图中被置位的个数
 * @param b 位图
 * */
uint32_t bm_count_set(struct bm *b)
{
	uint32_t total;
	int i;
	if (b->top >= b->len)
		return 0;

	total = 0;
	for (i = b->bottom; i <= b->top; i++)
		total += bm_count_set_in_u64(b->arr[i]);

	return total;
}

int bm_copy(struct bm *dst, struct bm *src)
{
	int i;

	if (dst->len <= src->top) {
		if (0 != bm_realloc(dst, src->top + 1))
			return -1;
	}

	for (i = src->bottom; i <= src->top; i++)
		dst->arr[i] = src->arr[i];

	dst->bottom = src->bottom;
	dst->top = src->top;

	return 0;
}

int bm_same(const struct bm *bm1, const struct bm *bm2)
{
	int i;

	if (bm_is_empty(bm1) && bm_is_empty(bm2))
		return 1;

	if (bm1->bottom != bm2->bottom || bm1->top != bm2->top)
		return 0;

	for (i = bm1->bottom; i <= bm1->top; i++) {
		if (bm1->arr[i] != bm2->arr[i])
			return 0;
	}

	return 1;
}

/*
 * @brief b 输出到 str 上，输出字符串长度为 16 * nr_16 + 2
 * */
int bm_str_16(struct bm *b, int nr_16, char *str, int str_len)
{
	int i;
	char *s;
	uint64_t  output;
	int nr_item;
	int nr_bits;

	if (str_len < 19)
		return -1;

	if (0 == nr_16) {
		nr_bits = (b->top + 1) * (int)BM_NR_BIT_PER_ITEM;
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
		output = i > b->top ? 0 : (i < b->bottom ? 0 : b->arr[i]);
		sprintf(s, "%0*llX", (int)BM_NR_BIT_PER_ITEM / 4, output);
		s += (int)BM_NR_BIT_PER_ITEM / 4;
	}

	return 0;
}

/*
 * @brief 把 b 中的最低的 nr_item 个 uint64_t 输出到 str 上，如果 nr_item 为 0，则
 *        输出最低的 b->top，如果 b->top < nr_item，则补 0，输出的时候，低位在右
 * */

int bm_str(struct bm *b, char *str, int str_len)
{
	int i;
	int max;
	int write_len;
	char *p;

	max = BM_NR_BIT_PER_ITEM * (b->top + 1);
	p = str;
	for (i = 0; i < max; i++) {
		if (bm_test(b, i)) {
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

int bm_next(struct bm *b, int i)
{
	int pos;
	int bit;

	pos = i < 0 ? b->bottom : (i / (int)BM_NR_BIT_PER_ITEM);
	bit = i < 0 ? 0 : (i % (int)BM_NR_BIT_PER_ITEM + 1);
	if (BM_NR_BIT_PER_ITEM == bit) {
		pos += 1;
		bit = 0;
	}
	if (pos > b->top)
		return -1;

	while (pos <= b->top) {
		if (b->arr[pos] & ((uint64_t)1 << bit))
			return (pos * (int)BM_NR_BIT_PER_ITEM + bit);

		bit++;
		if (BM_NR_BIT_PER_ITEM == bit) {
			pos += 1;
			bit = 0;
		}
	}

	return -1;
}
