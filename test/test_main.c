#include <CUnit/CUnit.h>
#include <CUnit/Basic.h>

extern int register_rb_tree_test();
extern int register_dictree_test();

int main()
{
	/* initialize the CUnit test registry */
	if (CUE_SUCCESS != CU_initialize_registry()) {
		return CU_get_error();
	}

	register_rb_tree_test();
	register_dictree_test();

	/* Run all tests using the CUnit Basic interface */
	CU_basic_set_mode(CU_BRM_VERBOSE);
	CU_basic_run_tests();

	/* Clean up registry and return */
	CU_cleanup_registry();
	return CU_get_error();
}
