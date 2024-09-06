#include <CUnit/CUnit.h>
#include "time.h"
#include "bm.h"

static int suite_init(void)
{
	srand(time(NULL));

	return 0;
}

static int suite_clean(void)
{
	return 0;
}

static int nr_alloc = 0;
static int nr_realloc = 0;
static int nr_free = 0;

static inline void *malloc_hook(size_t sz)
{
	void *ptr;
	nr_alloc += 1;
	ptr = malloc(sz);

	memset(ptr, 0xFF, sz);

	return ptr;
}

static inline void *realloc_hook(void *ptr, size_t sz)
{
	nr_realloc += 1;
	ptr = realloc(ptr, sz);

	// cout<<"realloc"<<ptr<<endl;

	return ptr;
}

static inline void free_hook(void *ptr)
{
	nr_free += 1;

	// cout<<"free"<<ptr<<endl;

	free(ptr);
}

static struct mem_func_set mem_hook = {
	malloc_hook,
	realloc_hook,
	free_hook,
};

static void test_bm_create_destroy()
{
	struct bm *b;

	nr_alloc = 0;
	nr_free = 0;
	nr_realloc = 0;
	b = bm_create(64, NULL);

	CU_ASSERT_EQUAL(bm_bit_capacity(b), 64);
	CU_ASSERT_TRUE(b != NULL);
	CU_ASSERT_FALSE(bm_is_fix(b));

	bm_destroy(b);

	b = bm_create_fix(128, NULL);

	CU_ASSERT_TRUE(b != NULL);
	CU_ASSERT_EQUAL(bm_bit_capacity(b), 128);
	CU_ASSERT_TRUE(bm_is_fix(b));

	bm_destroy(b);

	b = bm_create(64, &mem_hook);

	CU_ASSERT_EQUAL(bm_bit_capacity(b), 64);
	CU_ASSERT_TRUE(b != NULL);
	CU_ASSERT_FALSE(bm_is_fix(b));
	CU_ASSERT_EQUAL(nr_alloc, 2);

	CU_ASSERT_EQUAL(bm_set(b, 500), 0);
	CU_ASSERT_TRUE(bm_test(b, 500));
	CU_ASSERT_EQUAL(bm_bit_capacity(b), 512);

	bm_destroy(b);
	CU_ASSERT_EQUAL(nr_free, 2);

	b = bm_create_fix(128, &mem_hook);

	CU_ASSERT_TRUE(b != NULL);
	CU_ASSERT_EQUAL(bm_bit_capacity(b), 128);
	CU_ASSERT_TRUE(bm_is_fix(b));
	CU_ASSERT_EQUAL(nr_alloc, 4);

	bm_destroy(b);
	CU_ASSERT_EQUAL(nr_free, 4);
}

static void test_bm_set_unset_zero()
{
	struct bm *b1;
	struct bm *b2;
	int i;

	b1 = bm_create(64, NULL);

	CU_ASSERT_TRUE(b1 != NULL);
	for (i = 0; i < 64; i++) {
		bm_set(b1, i);
		CU_ASSERT_TRUE(bm_test(b1, i));
	}
	CU_ASSERT_EQUAL(64, bm_nr_set(b1));

	for (i = 0; i < 128; i++) {
		bm_set(b1, i);
		CU_ASSERT_TRUE(bm_test(b1, i));
	}
	CU_ASSERT_EQUAL(bm_bit_capacity(b1), 128);

	for (i = 64; i < 128; i++) {
		bm_unset(b1, i);
		CU_ASSERT_FALSE(bm_test(b1, i));
	}
	for (i = 0; i < 64; i++) {
		CU_ASSERT_TRUE(bm_test(b1, i));
	}
	for (i = 192; i < 256; i++) {
		bm_set(b1, i);
		CU_ASSERT_TRUE(bm_test(b1, i));
	}
	CU_ASSERT_EQUAL(bm_bit_capacity(b1), 256);
	for (i = 64; i < 256; i++) {
		bm_unset(b1, i);
		CU_ASSERT_FALSE(bm_test(b1, i));
	}
	CU_ASSERT_TRUE(bm_bit_capacity(b1) > 64);

	bm_zero(b1);
	for (i = 0; i < 256; i++) {
		CU_ASSERT_FALSE(bm_test(b1, i));
	}

	CU_ASSERT_TRUE(bm_is_empty(b1));

	bm_destroy(b1);

	b1 = bm_create(64, NULL);

	bm_set(b1, 1024);
	CU_ASSERT_TRUE(bm_test(b1, 1024));
	bm_unset(b1, 1024);
	CU_ASSERT_TRUE(bm_is_empty(b1));

	bm_destroy(b1);

	b1 = bm_create(128, &mem_hook);
	bm_set(b1, 180);
	bm_set(b1, 1);

	for (i = 0; i < 256; i++) {
		if (1 == i || 180 == i) {
			CU_ASSERT_TRUE(bm_test(b1, i));
		} else {
			CU_ASSERT_FALSE(bm_test(b1, i));
		}
	}

	bm_destroy(b1);

	b1 = bm_create(128, &mem_hook);
	b2 = bm_create(128, &mem_hook);
	bm_set(b1, 180);
	CU_ASSERT_TRUE(bm_test(b1, 180));
	bm_set(b2, 78);
	//bm_zero(b2);
	bm_or(b1, b2);
	for (i = 0; i < 256; i++) {
		if (180 == i || 78 == i) {
			CU_ASSERT_TRUE(bm_test(b1, i));
		} else {
			CU_ASSERT_FALSE(bm_test(b1, i));
		}
	}
	bm_zero(b1);
	CU_ASSERT_TRUE(bm_is_empty(b1));
	bm_destroy(b1);
	bm_destroy(b2);
}

static void test_bm_fix_set_unset_zero()
{
	struct bm *b;

	b = bm_create_fix(128, NULL);

	CU_ASSERT_TRUE(b != NULL);
	for (int i = 0; i < 64; i++) {
		bm_set(b, i);
		CU_ASSERT_TRUE(bm_test(b, i));
	}

	for (int i = 0; i < 128; i++) {
		CU_ASSERT_EQUAL(bm_set(b, i), 0);
		CU_ASSERT_TRUE(bm_test(b, i));
	}
	CU_ASSERT_EQUAL(bm_bit_capacity(b), 128);

	for (int i = 64; i < 128; i++) {
		bm_unset(b, i);
		CU_ASSERT_FALSE(bm_test(b, i));
	}
	for (int i = 0; i < 64; i++) {
		CU_ASSERT_TRUE(bm_test(b, i));
	}
	for (int i = 129; i < 256; i++) {
		CU_ASSERT_NOT_EQUAL(bm_set(b, i), 0);
		CU_ASSERT_FALSE(bm_test(b, i));
	}
	CU_ASSERT_EQUAL(bm_bit_capacity(b), 128);
	for (int i = 64; i < 256; i++) {
		bm_unset(b, i);
		CU_ASSERT_FALSE(bm_test(b, i));
	}
	CU_ASSERT_TRUE(bm_bit_capacity(b) > 63);

	bm_zero(b);
	for (int i = 0; i < 256; i++) {
		CU_ASSERT_FALSE(bm_test(b, i));
	}

	CU_ASSERT_TRUE(bm_is_empty(b));

	bm_destroy(b);
}

static void test_bm_and()
{
	struct bm *b1;
	struct bm *b2;

	b1 = bm_create(128, NULL);
	b2 = bm_create(128, NULL);

	for (int i = 0; i < 64; i++)
		bm_set(b1, i);
	for (int i = 64; i < 128; i++)
		bm_set(b2, i);

	CU_ASSERT_FALSE(bm_same(b1, b2));
	CU_ASSERT_EQUAL(bm_and(b1, b2), 0);
	CU_ASSERT_TRUE(bm_is_empty(b1));
	for (int i = 64; i < 128; i++)
		CU_ASSERT_TRUE(bm_test(b2, i));

	for (int i = 32; i < 96; i++)
		bm_set(b1, i);
	CU_ASSERT_EQUAL(bm_and(b1, b2), 0);
	for (int i = 0; i < 64; i++)
		CU_ASSERT_FALSE(bm_test(b1, i));
	for (int i = 64; i < 96; i++)
		CU_ASSERT_TRUE(bm_test(b1, i));

	bm_destroy(b1);
	bm_destroy(b2);

	b1 = bm_create(128, NULL);
	b2 = bm_create(256, NULL);
	for (int i = 0; i < 32; i++)
		bm_set(b1, i);

	for (int i = 224; i < 256; i++)
		bm_set(b2, i);

	CU_ASSERT_EQUAL(bm_and(b1, b2), 0);
	CU_ASSERT_TRUE(bm_is_empty(b1));
	CU_ASSERT_FALSE(bm_is_empty(b2));
	CU_ASSERT_EQUAL(bm_bit_capacity(b1), 128);

	bm_destroy(b1);
	bm_destroy(b2);
}

static void test_bm_or()
{
	int i;
	struct bm *b1;
	struct bm *b2;

	b1 = bm_create(128, NULL);
	b2 = bm_create(128, NULL);

	for (i = 0; i < 64; i++)
		bm_set(b1, i);
	for (i = 64; i < 128; i++)
		bm_set(b2, i);

	CU_ASSERT_EQUAL(0, bm_or(b1, b2));

	for (i = 0; i < 64; i++)
		CU_ASSERT_TRUE(bm_test(b1, i));
	for (i = 64; i < 128; i++)
		CU_ASSERT_TRUE(bm_test(b1, i));

	bm_destroy(b1);
	bm_destroy(b2);

	b1 = bm_create(64, NULL);
	b2 = bm_create(256, NULL);

	bm_set(b1, 127);
	bm_zero(b1);
	bm_set(b1, 1);
	bm_set(b2, 100);
	bm_or(b1, b2);

	CU_ASSERT_TRUE(bm_test(b1, 1));
	CU_ASSERT_TRUE(bm_test(b1, 100));
	CU_ASSERT_FALSE(bm_test(b1, 127));

	bm_destroy(b1);
	bm_destroy(b2);

	b1 = bm_create(64, NULL);
	b2 = bm_create(256, NULL);

	for (i = 0; i < 32; i++)
		bm_set(b1, i);
	for (i = 224; i < 256; i++)
		bm_set(b2, i);

	CU_ASSERT_EQUAL(0, bm_or(b1, b2));

	for (i = 0; i < 32; i++)
		CU_ASSERT_TRUE(bm_test(b1, i));
	for (i = 32; i < 224; i++)
		CU_ASSERT_FALSE(bm_test(b1, i));
	for (i = 224; i < 256; i++)
		CU_ASSERT_TRUE(bm_test(b1, i));
	CU_ASSERT_FALSE(bm_test(b1, 257));

	bm_destroy(b1);
	bm_destroy(b2);

	b1 = bm_create(256, NULL);
	b2 = bm_create(256, NULL);

	for (i = 0; i < 32; i++)
		bm_set(b1, i);
	bm_set(b2, 127);

	bm_zero(b2);

	bm_or(b1, b2);

	for (i = 0; i < 32; i++)
		CU_ASSERT_TRUE(bm_test(b1, i));
	CU_ASSERT_FALSE(bm_test(b1, 40));

	bm_destroy(b1);
	bm_destroy(b2);

	b1 = bm_create(1000, NULL);
	b2 = bm_create(1000, NULL);
	bm_set(b1, 513);
	bm_zero(b2);
	bm_or(b2, b1);
	CU_ASSERT_TRUE(bm_test(b2, 513));
	bm_set(b2, 1);
	CU_ASSERT_TRUE(bm_test(b2, 1));
	bm_and(b1, b2);
	CU_ASSERT_TRUE(bm_test(b1, 513));
	CU_ASSERT_FALSE(bm_test(b1, 1));
	CU_ASSERT_TRUE(bm_test(b2, 1));


	bm_destroy(b1);
	bm_destroy(b2);

}

static void test_bm_random()
{
#define BM_TEST_MAX 1000
	int i;
	int j;
	int bit;
	int set1[BM_TEST_MAX] = {0};
	int set2[BM_TEST_MAX] = {0};
	int fix_test;
	struct bm *b1;
	struct bm *b2;
	struct bm *b3;

	b1 = bm_create(BM_TEST_MAX, NULL);
	b2 = bm_create(BM_TEST_MAX, NULL);
	b3 = bm_create(BM_TEST_MAX, NULL);
	fix_test = 0;
	goto TEST_START;
TEST_FIX:
	bm_destroy(b3);
	b3 = bm_create_fix(BM_TEST_MAX, NULL);
	bm_zero(b1);
	bm_zero(b2);
	fix_test = 1;
TEST_START:
	for (i = 0; i < BM_TEST_MAX; i++) {
		CU_ASSERT_FALSE(bm_test(b1, i));
		CU_ASSERT_FALSE(bm_test(b2, i));
		bm_set(b1, i);
		bm_or(b3, b1);
		CU_ASSERT_TRUE(bm_test(b3, i));
		CU_ASSERT_TRUE(bm_same(b1, b3));
		bm_and(b3, b2);
		CU_ASSERT_FALSE(bm_test(b3, i));
		CU_ASSERT_TRUE(bm_test(b1, i));
	}
	for (i = 0; i < 100; i++) {
		bzero(set1, sizeof(set1));
		bzero(set2, sizeof(set2));
		bm_zero(b1);
		bm_zero(b2);
		for (j = 0; j < BM_TEST_MAX; j++) {
			bm_zero(b3);
			bit = rand() % BM_TEST_MAX;
			bm_set(b1, bit);
			CU_ASSERT_TRUE(bm_test(b1, bit));
			bm_or(b3, b1);
			CU_ASSERT_TRUE(bm_test(b3, bit));
			CU_ASSERT_TRUE(bm_same(b1, b3));
			set1[bit] = 1;

			bit = rand() % BM_TEST_MAX;
			bm_set(b2, bit);
			CU_ASSERT_TRUE(bm_test(b2, bit));
			bm_and(b3, b2);
			set2[bit] = 1;
			if (set1[bit] && set2[bit]) {
				CU_ASSERT_TRUE(bm_test(b3, bit));
			} else {
				CU_ASSERT_FALSE(bm_test(b3, bit));
			}
		}
		for (j = 0; j < BM_TEST_MAX; j++) {
			if (set1[j]) {
				CU_ASSERT_TRUE(bm_test(b1, j));
			} else {
				CU_ASSERT_FALSE(bm_test(b1, j));
			}
			if (set1[j] && set2[j]) {
				CU_ASSERT_TRUE(bm_test(b3, j));
			} else {
				CU_ASSERT_FALSE(bm_test(b3, j));
			}
		}
		CU_ASSERT_TRUE(bm_has_common(b1, b3) || bm_is_empty(b3));
		CU_ASSERT_TRUE(bm_has_common(b2, b3) || bm_is_empty(b3));
		CU_ASSERT_FALSE(bm_has_common(b1, b3) && bm_is_empty(b3));
		CU_ASSERT_FALSE(bm_has_common(b2, b3) && bm_is_empty(b3));
		j = -1;
		while (-1 != (j = bm_next(b3, j))) {
			CU_ASSERT_TRUE(set1[j]);
			CU_ASSERT_TRUE(set2[j]);
		}
		j = -1;
		while (-1 != (j = bm_next(b1, j))) {
			CU_ASSERT_TRUE(set1[j]);
		}
		j = -1;
		while (-1 != (j = bm_next(b2, j))) {
			CU_ASSERT_TRUE(set2[j]);
			bm_unset(b1, j);
			set1[j] = 0;
		}
		CU_ASSERT_FALSE(bm_has_common(b1, b2));
		while (-1 != (j = bm_next(b1, j))) {
			bm_unset(b1, j);
			set1[j] = 0;
			CU_ASSERT_FALSE(bm_test(b1, j));
		}
		CU_ASSERT_TRUE(bm_is_empty(b1));
		for (j = 0; j < BM_TEST_MAX; j++) {
			bm_set(b1, j);
			set1[j] = 1;
			CU_ASSERT_TRUE(bm_test(b1, j));
		}
		CU_ASSERT_EQUAL(bm_nr_set(b1), BM_TEST_MAX);
	}

	if (!fix_test)
		goto TEST_FIX;

	bm_destroy(b1);
	bm_destroy(b2);
	bm_destroy(b3);
}

static CU_TestInfo tests_bm[] = {
	{"test_bm_create_destroy", test_bm_create_destroy},
	{"test_bm_set_unset_zero", test_bm_set_unset_zero},
	{"test_bm_fix_set_unset_zero", test_bm_fix_set_unset_zero},
	{"test_bm_and", test_bm_and},
	{"test_bm_or", test_bm_or},
	{"test_bm_random", test_bm_random},
	CU_TEST_INFO_NULL,
};

static CU_SuiteInfo suites[] = {
	{"test_bm", suite_init, suite_clean, NULL, NULL, tests_bm},
	CU_SUITE_INFO_NULL,
};

int register_bm_test()
{
	/* Register suites. */
	if (CUE_SUCCESS != CU_register_suites(suites)) {
		CU_cleanup_registry();
		return CU_get_error();
	}

	return 0;
}
