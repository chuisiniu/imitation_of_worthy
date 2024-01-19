#include <CUnit/CUnit.h>
#include <CUnit/Basic.h>
#include "linux/rbtree_augmented.h"

static int suite_init(void)
{
	return 0;
}

static int suite_clean(void)
{
	return 0;
}

struct rb_tree_test {
	struct rb_node node;
	int i;
};

int less(struct rb_node *a, const struct rb_node *b)
{
	struct rb_tree_test *ta;
	const struct rb_tree_test *tb;

	ta = container_of(a, struct rb_tree_test, node);
	tb = container_of_const(b, struct rb_tree_test, node);

	if (ta->i < tb->i)
		return 1;

	return 0;
}

static void test_rb_add()
{
	struct rb_tree_test data[] = {
		{.i = 5},
		{.i = 3},
		{.i = 1},
		{.i = -1},
		{.i = -3},
		{.i = -5},
		{.i = -4},
		{.i = -2},
		{.i = 0},
		{.i = 2},
		{.i = 4}
	};
	int i;
	int pre = -100000;
	struct rb_root root = RB_ROOT;
	struct rb_tree_test *item;
	struct rb_node *iter;

	for (i = 0; i < sizeof(data) / sizeof(data[0]); i++)
		rb_add(&data[i].node, &root, less);

	for (iter = rb_first(&root); iter; iter = rb_next(iter)) {
		item = container_of(iter, struct rb_tree_test, node);
		if (pre == -100000) {
			pre = item->i;

			continue;
		}
		CU_ASSERT_TRUE(pre < item->i);
		pre = item->i;
	}
}

static void test_rb_erase()
{
	struct rb_tree_test data[] = {
		{.i = 5},
		{.i = 3},
		{.i = 1},
		{.i = -1},
		{.i = -3},
		{.i = -5},
		{.i = -4},
		{.i = -2},
		{.i = 0},
		{.i = 2},
		{.i = 4}
	};
	int i;
	int pre;
	struct rb_root root = RB_ROOT;
	struct rb_tree_test *item;
	struct rb_node *iter;

	for (i = 0; i < sizeof(data) / sizeof(data[0]); i++)
		rb_add(&data[i].node, &root, less);

	for (i = sizeof(data) / sizeof(data[0]) - 1; i >= 0; i--) {
		rb_erase(&data[i].node, &root);
		pre = -100000;
		for (iter = rb_first(&root); iter; iter = rb_next(iter)) {
			item = container_of(iter, struct rb_tree_test, node);
			if (pre == -100000) {
				pre = item->i;

				continue;
			}
			CU_ASSERT_TRUE(pre < item->i);
			CU_ASSERT_TRUE(item->i != data[i].i)
			pre = item->i;
		}
	}
}

static CU_TestInfo tests_rbtree[] = {
	{"test_rb_add", test_rb_add},
	{"test_rb_erase", test_rb_erase},
	CU_TEST_INFO_NULL,
};

static void test_rb_add_cached()
{
	struct rb_tree_test data[] = {
		{.i = 5},
		{.i = 3},
		{.i = 1},
		{.i = -1},
		{.i = -3},
		{.i = -5},
		{.i = -4},
		{.i = -2},
		{.i = 0},
		{.i = 2},
		{.i = 4}
	};
	int i;
	int pre = -100000;
	struct rb_root_cached root = RB_ROOT_CACHED;
	struct rb_tree_test *item;
	struct rb_node *iter;

	for (i = 0; i < sizeof(data) / sizeof(data[0]); i++)
		rb_add_cached(&data[i].node, &root, less);

	for (iter = rb_first_cached(&root); iter; iter = rb_next(iter)) {
		item = container_of(iter, struct rb_tree_test, node);
		if (pre == -100000) {
			pre = item->i;

			continue;
		}
		CU_ASSERT_TRUE(pre < item->i);
		pre = item->i;
	}
}

static CU_TestInfo tests_rbtree_cached[] = {
	{"test_rb_add_cached", test_rb_add_cached},
	CU_TEST_INFO_NULL,
};

static CU_SuiteInfo suites[] = {
	{"test_rbtree", suite_init, suite_clean, NULL, NULL, tests_rbtree},
	{"test_rbtree_cached", suite_init, suite_clean, NULL, NULL, tests_rbtree_cached},
	CU_SUITE_INFO_NULL,
};

int main()
{
	/* initialize the CUnit test registry */
	if (CUE_SUCCESS != CU_initialize_registry()) {
		return CU_get_error();
	}

	/* Register suites. */
	if (CUE_SUCCESS != CU_register_suites(suites)) {
		CU_cleanup_registry();
		return CU_get_error();
	}

	/* Run all tests using the CUnit Basic interface */
	CU_basic_set_mode(CU_BRM_VERBOSE);
	CU_basic_run_tests();

	/* Clean up registry and return */
	CU_cleanup_registry();
	return CU_get_error();
}
