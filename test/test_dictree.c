#include <CUnit/CUnit.h>
#include <CUnit/Basic.h>
#include "dictree.h"

static int suite_init(void)
{
	return 0;
}

static int suite_clean(void)
{
	return 0;
}

struct dictree_test {
	const unsigned char *str;
	int len;
	int data;
};

static void test_dictree_insert_rm()
{
	struct dictree_test arr[] = {
		{(unsigned char *)"abc", 3, 100},
		{(unsigned char *)"ab", 2, 200},
		{(unsigned char *)"z", 1, 250},
		{(unsigned char *)"abcd", 4, 300},
		{(unsigned char *)"bbccdd", 6, 400},
		{(unsigned char *)"ddccbb", 6, 500},
		{(unsigned char *)"xbasdfsadf", 10, 600}
	};
	int i;
	int j;
	int prefix_len;

	struct dict_tree tree = DICT_TREE('a', 'z');
	void *tmp;

	tmp = dt_find(&tree, arr[0].str, arr[0].len, &prefix_len);
	CU_ASSERT_EQUAL(NULL, tmp);
	CU_ASSERT_EQUAL(prefix_len, 0);

	for (i = 0; i < sizeof(arr) / sizeof(arr[0]); i++) {
		tmp = dt_find_insert(&tree, arr[i].str, arr[i].len,
				     &arr[i].data);
		CU_ASSERT_EQUAL(tmp, &arr[i].data);

		tmp = dt_find(&tree, arr[i].str, arr[i].len, &prefix_len);
		CU_ASSERT_EQUAL(prefix_len, arr[i].len);
		CU_ASSERT_EQUAL(tmp, &arr[i].data);

		tmp = dt_find(&tree, (unsigned char *)"does not exists",
			      15, &prefix_len);
		CU_ASSERT_EQUAL(NULL, tmp);
		CU_ASSERT_EQUAL(0, prefix_len);

		tmp = dt_rm(&tree, arr[i].str, arr[i].len);
		CU_ASSERT_EQUAL(tmp, &arr[i].data);

		tmp = dt_find(&tree, arr[i].str, arr[i].len, &arr[i].data);
		CU_ASSERT_EQUAL(tmp, NULL);
	}

	for (i = 0; i < sizeof(arr) / sizeof(arr[0]); i++) {
		tmp = dt_find_insert(&tree, arr[i].str, arr[i].len,
				     &arr[i].data);
		CU_ASSERT_EQUAL(tmp, &arr[i].data);
	}

	for (i = 0; i < sizeof(arr) / sizeof(arr[0]); i++) {
		tmp = dt_find(&tree, arr[i].str, arr[i].len, &prefix_len);
		CU_ASSERT_EQUAL(prefix_len, arr[i].len);
		CU_ASSERT_EQUAL(tmp, &arr[i].data);
	}
	tmp = dt_find(&tree, (unsigned char *)"does not exists",
			      15, &prefix_len);
		CU_ASSERT_EQUAL(NULL, tmp);
		CU_ASSERT_EQUAL(0, prefix_len);

	for (i = 0; i < sizeof(arr) / sizeof(arr[0]); i++) {
		tmp = dt_rm(&tree, arr[i].str, arr[i].len);
		CU_ASSERT_EQUAL(tmp, &arr[i].data);

		tmp = dt_find(&tree, arr[i].str, arr[i].len, &arr[i].data);
		CU_ASSERT_EQUAL(tmp, NULL);

		for (j = i + 1; j < sizeof(arr) / sizeof(arr[0]); j++) {
			tmp = dt_find(&tree, arr[j].str, arr[j].len, &prefix_len);
			CU_ASSERT_EQUAL(prefix_len, arr[j].len);
			CU_ASSERT_EQUAL(tmp, &arr[j].data);
		}
	}

	CU_ASSERT_TRUE(dt_is_empty(&tree));

	for (i = 0; i < sizeof(arr) / sizeof(arr[0]); i++) {
		tmp = dt_find_insert(&tree, arr[i].str, arr[i].len,
		                     &arr[i].data);
		CU_ASSERT_EQUAL(tmp, &arr[i].data);

		tmp = dt_find(&tree, arr[i].str, arr[i].len, &arr[i].data);
		CU_ASSERT_EQUAL(tmp, &arr[i].data);
	}

	dt_rm_all(&tree, NULL);
	CU_ASSERT_TRUE(dt_is_empty(&tree));
}

static void test_dictree_partial() {
	struct dictree_test arr[] = {
		{(unsigned char *)"abc", 3, 100},
		{(unsigned char *)"ab", 2, 200},
		{(unsigned char *)"z", 1, 250},
		{(unsigned char *)"abcd", 4, 300},
		{(unsigned char *)"bbccdd", 6, 400},
		{(unsigned char *)"ddccbb", 6, 500},
		{(unsigned char *)"xbasdfsadf", 10, 600}
	};
	int i;
	int j;
	int prefix_len;

	struct dict_tree tree = DICT_TREE('a', 'z');
	void *tmp;
	char partial[64];

	for (i = 0; i < sizeof(arr) / sizeof(arr[0]); i++) {
		tmp = dt_find_insert(&tree, arr[i].str, arr[i].len,
		                     &arr[i].data);
		CU_ASSERT_EQUAL(tmp, &arr[i].data);

		tmp = dt_find(&tree, arr[i].str, arr[i].len, &prefix_len);
		CU_ASSERT_EQUAL(prefix_len, arr[i].len);
		CU_ASSERT_EQUAL(tmp, &arr[i].data);

		strcpy(partial, (const char *)arr[i].str);
		partial[arr[i].len - 1] -= 'a' - 'A';

		tmp = dt_find(&tree, (const unsigned char *)partial,
			      arr[i].len, &prefix_len);
		CU_ASSERT_EQUAL(tmp, NULL);
		CU_ASSERT_EQUAL(prefix_len, arr[i].len - 1);
	}

	for (i = 0; i < sizeof(arr) / sizeof(arr[0]); i++) {
		tmp = dt_rm(&tree, arr[i].str, arr[i].len);
		CU_ASSERT_EQUAL(tmp, &arr[i].data);

		tmp = dt_find(&tree, arr[i].str, arr[i].len, &arr[i].data);
		CU_ASSERT_EQUAL(tmp, NULL);

		for (j = i + 1; j < sizeof(arr) / sizeof(arr[0]); j++) {
			tmp = dt_find(&tree, arr[j].str, arr[j].len, &prefix_len);
			CU_ASSERT_EQUAL(prefix_len, arr[j].len);
			CU_ASSERT_EQUAL(tmp, &arr[j].data);
		}
	}
}

static CU_TestInfo tests_dictree[] = {
	{"test_dictree_insert_rm", test_dictree_insert_rm},
	{"test_dictree_partial", test_dictree_partial},
	CU_TEST_INFO_NULL,
};

static CU_SuiteInfo suites[] = {
	{"test_dictree", suite_init, suite_clean, NULL, NULL, tests_dictree},
	CU_SUITE_INFO_NULL,
};

int register_dictree_test()
{
	/* Register suites. */
	if (CUE_SUCCESS != CU_register_suites(suites)) {
		CU_cleanup_registry();
		return CU_get_error();
	}

	return 0;
}
