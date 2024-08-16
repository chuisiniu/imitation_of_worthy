#include <CUnit/CUnit.h>
#include <CUnit/Basic.h>

extern int register_rb_tree_test();
extern int register_dictree_test();
extern int register_bm_test();
extern int register_bs_test();

int main()
{
	int nr_failure;

	/* initialize the CUnit test registry */
	if (CUE_SUCCESS != CU_initialize_registry()) {
		return CU_get_error();
	}

	register_rb_tree_test();
	register_dictree_test();
	register_bm_test();
	register_bs_test();

	/* Run all tests using the CUnit Basic interface */
	CU_basic_set_mode(CU_BRM_VERBOSE);
	CU_basic_run_tests();
	nr_failure = CU_get_number_of_failures();

	/* Clean up registry and return */
	CU_cleanup_registry();

	return nr_failure ? -1 : 0;
}
