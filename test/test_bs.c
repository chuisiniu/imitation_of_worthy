#include <CUnit/CUnit.h>
#include "time.h"
#include "bs.h"

static int suite_init(void)
{
	srand(time(NULL));

	return 0;
}

static int suite_clean(void)
{
	return 0;
}

static int port_compare(const void *d1, const void *d2)
{
	return memcmp(d1, d2, 2);
}

typedef short be;

struct bs_test {
	be port;
	short pos;
	int flag;
};

int be_test_to_str(const void *data, char *str, int str_len)
{
	struct bs_test *d;

	d = (struct bs_test *)data;

	return snprintf(str, str_len, "{%d, %d}", d->port, d->pos);
}


static void test_bs_random()
{
#define BS_PORT_MAX 65535
#define BS_TEST_MAX 20020
	struct bs *b;
	struct bs_test arr[BS_PORT_MAX + 1];
	struct bs_test *ptr;
	struct bs_test *last_inserted;
	int arr_end;
	int pre;
	int found;
	int ins_pos;
	int i;
	int j;
	int k;
	int nr_port;

	for (arr_end = 0; arr_end <= BS_PORT_MAX; arr_end++) {
		arr[arr_end].port = ntohs((short)arr_end);
		arr[arr_end].pos = arr_end;
		arr[arr_end].flag = 0;
	}

	b = bs_create(BS_TEST_MAX, port_compare, be_test_to_str, NULL);
	for (i = 0; i < BS_TEST_MAX; i++) {
		found = bs_find(b, &arr[i], &pre);
		CU_ASSERT_EQUAL(found, -1);
		CU_ASSERT_EQUAL(pre, i - 1);

		ins_pos = bs_insert(b, &arr[i]);
		CU_ASSERT_EQUAL(ins_pos, i);
		arr[i].flag = 1;

		found = bs_find(b, &arr[i], &pre);
		CU_ASSERT_EQUAL(found, i);
		CU_ASSERT_EQUAL(pre, i - 1);

		ptr = bs_get(b, found);
		CU_ASSERT_EQUAL(ptr->pos, arr[i].pos);
		CU_ASSERT_EQUAL(ptr->port, arr[i].port);
		CU_ASSERT_EQUAL(ptr->flag, 1);
	}
	for (i = 0; i < BS_TEST_MAX; i++) {
		ptr = bs_remove_by_idx(b, 0);
		CU_ASSERT_EQUAL(ptr->pos, i);
		ptr->flag = 0;
	}
	for (i = 0; i < BS_TEST_MAX; i++) {
		CU_ASSERT_EQUAL(arr[i].flag, 0);
		found = bs_find(b, &arr[i], &pre);
		CU_ASSERT_EQUAL(found, -1);
		CU_ASSERT_EQUAL(pre, -1);
	}
	bs_destroy(b);

	for (i = 0; i < 100; i++) {
		nr_port = (rand() % (BS_TEST_MAX - 1)) + 1;
		b = bs_create(BS_TEST_MAX, port_compare, be_test_to_str, NULL);
		last_inserted = NULL;
		for (j = 0; j < nr_port; j++) {
			k = rand() % BS_PORT_MAX;
			if (arr[k].flag == 0)
				bs_insert(b, &arr[k]);
			arr[k].flag = 1;
		}

		for (j = 0; j < BS_PORT_MAX; j++) {
			if (arr[j].flag)
				last_inserted = &arr[j];

			found = bs_find(b, &arr[j], &pre);
			if (last_inserted) {
				ptr = found > -1 ? bs_get(b, found)
				                 : bs_get(b, pre);
				CU_ASSERT_EQUAL(last_inserted->pos, ptr->pos);
				if (found == -1) {
					CU_ASSERT_NOT_EQUAL(last_inserted->pos,
					                    arr[j].pos);
					CU_ASSERT_TRUE(last_inserted->pos < j);
				}
			} else {
				CU_ASSERT_EQUAL(found, -1);
				CU_ASSERT_EQUAL(pre, -1);
			}
		}
		bs_destroy(b);

		for (j = 0; j < BS_PORT_MAX; j++) {
			arr[j].flag = 0;
		}
	}
}

static CU_TestInfo tests_bs[] = {
	{"test_bs_random", test_bs_random},
	CU_TEST_INFO_NULL,
};

static CU_SuiteInfo suites[] = {
	{"test_bs", suite_init, suite_clean, NULL, NULL, tests_bs},
	CU_SUITE_INFO_NULL,
};

int register_bs_test()
{
	/* Register suites. */
	if (CUE_SUCCESS != CU_register_suites(suites)) {
		CU_cleanup_registry();
		return CU_get_error();
	}

	return 0;
}
