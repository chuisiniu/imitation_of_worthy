#include <CUnit/CUnit.h>
#include "time.h"
#include "bsbm.h"

union test_data {
	be16 port;
	be32 ipv4;
	struct in6_addr ipv6;
};

struct test_data_range {
	union test_data begin;
	union test_data end;
};

#define MAX_RANGE_PER_POLICY 10
struct test_data_range_set {
	enum bsbm_type_e type;
	int nr;
	struct test_data_range range[MAX_RANGE_PER_POLICY];
};

enum test_field {
	TEST_FIELD_SPORT,
	TEST_FIELD_DPORT,
	TEST_FIELD_SIP,
	TEST_FIELD_DIP,

	TEST_FIELD_MAX
};

struct test_policy {
	int id;
	struct test_data_range_set rs[TEST_FIELD_MAX];
};

#define MAX_BSBM_TEST_ID 1000

struct test_policy_manager {
	struct bsbm *matcher[TEST_FIELD_MAX];

	int nr;
	struct test_policy policies[MAX_BSBM_TEST_ID + 1];
};

static int suite_init(void)
{
	srand(time(NULL));

	return 0;
}

static int suite_clean(void)
{
	return 0;
}

void generate_range(enum bsbm_type_e type, struct test_data_range *r)
{
	unsigned char *begin;
	unsigned char *end;
	int size;
	int i;

	size = bsbm_get_data_size(type);
	end = (unsigned char *)&r->end;
	for (i = 0; i < size; i++)
		end[i] = rand() % 256;

	if (rand() % 3 == 0) {
		memcpy(&r->begin, &r->end, size);

		return;
	}

	begin = (unsigned char *)&r->begin;
	for (i = 0; i < size; i++) {
		if (i < size / 2) {
			begin[i] = end[i];
		} else {
			if (end[i] > 1)
				begin[i] = rand() % (end[i] - 1) + 1;
			else
				begin[i] = end[i];
		}
		CU_ASSERT_TRUE(begin[i] <= end[i]);
	}
}

void generage_range_set(enum bsbm_type_e type, struct test_data_range_set *s)
{
	int i;

	s->type = type;
	if (s->nr <= 0 || s->nr >= MAX_RANGE_PER_POLICY)
		s->nr = rand() % (MAX_RANGE_PER_POLICY - 1) + 1;

	for (i = 0; i < s->nr; i++)
		generate_range(type, &s->range[i]);
}

void generate_policy(int id, int test6, struct test_policy *p)
{
	int i;
	enum bsbm_type_e types[TEST_FIELD_MAX];

	types[TEST_FIELD_SPORT] = BSBM_TYPE_PORT;
	types[TEST_FIELD_DPORT] = BSBM_TYPE_PORT;
	if (test6) {
		types[TEST_FIELD_SIP] = BSBM_TYPE_IPV6;
		types[TEST_FIELD_DIP] = BSBM_TYPE_IPV6;
	} else {
		types[TEST_FIELD_SIP] = BSBM_TYPE_IPV4;
		types[TEST_FIELD_DIP] = BSBM_TYPE_IPV4;
	}

	p->id = id;
	for (i = 0; i < TEST_FIELD_MAX; i++)
		generage_range_set(types[i], &p->rs[i]);
}

void load_range(struct bsbm *matcher, struct test_data_range *r, int id)
{
	int ret;
	static struct bm *b = NULL;

	ret = bsbm_insert(matcher, &r->begin, &r->end, id);
	CU_ASSERT_EQUAL(ret, 0);

	if (NULL == b)
		b = bm_create_fix(MAX_BSBM_TEST_ID + 1, NULL);

	bm_zero(b);
	bsbm_match(matcher, &r->begin, b, BM_OP_OR);
	CU_ASSERT_TRUE(bm_test(b, id));

	bsbm_match(matcher, &r->begin, b, BM_OP_AND);
	CU_ASSERT_TRUE(bm_test(b, id));
}

void load_range_set(struct bsbm *matcher, struct test_data_range_set *s, int id)
{
	int i;

	for (i = 0; i < s->nr; i++)
		load_range(matcher, &s->range[i], id);
}

void load_policy(struct test_policy_manager *tpm, struct test_policy *p)
{
	int i;

	for (i = 0; i < TEST_FIELD_MAX; i++)
		load_range_set(tpm->matcher[i], &p->rs[i], p->id);
}

void generate_policy_manager(struct test_policy_manager *tpm, int test6)
{
	int i;
	enum bsbm_type_e types[TEST_FIELD_MAX];

	types[TEST_FIELD_SPORT] = BSBM_TYPE_PORT;
	types[TEST_FIELD_DPORT] = BSBM_TYPE_PORT;
	if (test6) {
		types[TEST_FIELD_SIP] = BSBM_TYPE_IPV6;
		types[TEST_FIELD_DIP] = BSBM_TYPE_IPV6;
	} else {
		types[TEST_FIELD_SIP] = BSBM_TYPE_IPV4;
		types[TEST_FIELD_DIP] = BSBM_TYPE_IPV4;
	}

	for (i = 0; i < TEST_FIELD_MAX; i++) {
		tpm->matcher[i] = bsbm_create(
			MAX_RANGE_PER_POLICY * 2 * (MAX_BSBM_TEST_ID + 1),
			MAX_BSBM_TEST_ID , types[i], NULL);
		CU_ASSERT_PTR_NOT_NULL(tpm->matcher[i]);
	}

	if (0 <= tpm->nr || tpm->nr >= MAX_BSBM_TEST_ID + 1) {
		tpm->nr = rand() % (MAX_BSBM_TEST_ID - 1) + 1;
	}

	for (i = 0; i < tpm->nr; i++) {
		generate_policy(i, test6, &tpm->policies[i]);
		load_policy(tpm, &tpm->policies[i]);
	}
}

struct test_flow {
	be16 sport;
	be16 dport;
	union {
		be32 sip4;
		struct in6_addr sip6;
	} sip;
	union {
		be32 dip4;
		struct in6_addr dip6;
	} dip;

	int id;
};

void generate_ip4_edge_flow(
	struct test_policy_manager *tpm,
	struct test_flow *flow)
{
	struct test_policy *p;
	struct test_data_range *r;

	flow->id = rand() % tpm->nr;
	p = &tpm->policies[flow->id];

	r = &p->rs[0].range[rand() % p->rs[0].nr];
	if (rand() % 2 == 0)
		memcpy(&flow->sport, &r->begin, sizeof(flow->sport));
	else
		memcpy(&flow->sport, &r->end, sizeof(flow->sport));

	r = &p->rs[1].range[rand() % p->rs[1].nr];
	if (rand() % 2 == 0)
		memcpy(&flow->dport, &r->begin, sizeof(flow->dport));
	else
		memcpy(&flow->dport, &r->end, sizeof(flow->dport));

	r = &p->rs[2].range[rand() % p->rs[2].nr];
	if (rand() % 2 == 0)
		memcpy(&flow->sip, &r->begin, sizeof(flow->sip));
	else
		memcpy(&flow->sip, &r->end, sizeof(flow->sip));

	r = &p->rs[3].range[rand() % p->rs[3].nr];
	if (rand() % 2 == 0)
		memcpy(&flow->dip, &r->begin, sizeof(flow->dip));
	else
		memcpy(&flow->dip, &r->end, sizeof(flow->dip));
}

void generate_ip4_random_flow(
	struct test_policy_manager *tpm,
	struct test_flow *flow)
{
	struct test_policy *p;
	struct test_data_range *r;
	unsigned char *c;
	unsigned char *cb;
	unsigned char *ce;
	int div;

	flow->id = rand() % tpm->nr;
	p = &tpm->policies[flow->id];

	r = &p->rs[0].range[rand() % p->rs[0].nr];
	div = rand() % 10;
	c = (unsigned char *)&flow->sport;
	cb = (unsigned char *)&r->begin;
	ce = (unsigned char *)&r->end;
	c[0] = (ce[0] - cb[0]) / div + cb[0];
	c[1] = (ce[1] - cb[1]) / div + cb[1];

	r = &p->rs[1].range[rand() % p->rs[1].nr];
	div = rand() % 10;
	c = (unsigned char *)&flow->dport;
	cb = (unsigned char *)&r->begin;
	ce = (unsigned char *)&r->end;
	c[0] = (ce[0] - cb[0]) / div + cb[0];
	c[1] = (ce[1] - cb[1]) / div + cb[1];

	r = &p->rs[2].range[rand() % p->rs[2].nr];
	div = rand() % 10;
	c = (unsigned char *)&flow->sip;
	cb = (unsigned char *)&r->begin;
	ce = (unsigned char *)&r->end;
	c[0] = (ce[0] - cb[0]) / div + cb[0];
	c[1] = (ce[1] - cb[1]) / div + cb[1];
	c[2] = (ce[2] - cb[2]) / div + cb[2];
	c[3] = (ce[3] - cb[3]) / div + cb[3];

	r = &p->rs[3].range[rand() % p->rs[3].nr];
	div = rand() % 10;
	c = (unsigned char *)&flow->dip;
	cb = (unsigned char *)&r->begin;
	ce = (unsigned char *)&r->end;
	c[0] = (ce[0] - cb[0]) / div + cb[0];
	c[1] = (ce[1] - cb[1]) / div + cb[1];
	c[2] = (ce[2] - cb[2]) / div + cb[2];
	c[3] = (ce[3] - cb[3]) / div + cb[3];
}

static void test_bsbm_random()
{
#define MAX_FLOW 1000000
	int i;
	struct test_policy_manager tpm = {0};
	struct test_flow flow;
	struct bm *b;

	b = bm_create_fix(MAX_BSBM_TEST_ID + 1, NULL);

	generate_policy_manager(&tpm, 0);

	for (i = 0; i < MAX_FLOW; i++) {
		generate_ip4_edge_flow(&tpm, &flow);
		bm_zero(b);
		bsbm_match(tpm.matcher[0], &flow.sport, b, BM_OP_OR);
		bsbm_match(tpm.matcher[1], &flow.dport, b, BM_OP_AND);
		bsbm_match(tpm.matcher[2], &flow.sip, b, BM_OP_AND);
		bsbm_match(tpm.matcher[3], &flow.dip, b, BM_OP_AND);

		CU_ASSERT_TRUE(bm_test(b, flow.id));

		generate_ip4_random_flow(&tpm, &flow);
		bm_zero(b);
		bsbm_match(tpm.matcher[0], &flow.sport, b, BM_OP_OR);
		bsbm_match(tpm.matcher[1], &flow.dport, b, BM_OP_AND);
		bsbm_match(tpm.matcher[2], &flow.sip, b, BM_OP_AND);
		bsbm_match(tpm.matcher[3], &flow.dip, b, BM_OP_AND);

		CU_ASSERT_TRUE(bm_test(b, flow.id));
	}

	for (i = 0; i < TEST_FIELD_MAX; i++)
		bsbm_destroy(tpm.matcher[i]);

	bzero(&tpm, sizeof(tpm));
	generate_policy_manager(&tpm, 1);

	bm_destroy(b);

	for (i = 0; i < TEST_FIELD_MAX; i++)
		bsbm_destroy(tpm.matcher[i]);
}

static CU_TestInfo tests_bsbm[] = {
	{"test_bsbm_random", test_bsbm_random},
	CU_TEST_INFO_NULL,
};

static CU_SuiteInfo suites[] = {
	{"test_bsbm", suite_init, suite_clean, NULL, NULL, tests_bsbm},
	CU_SUITE_INFO_NULL,
};

int register_bsbm_test()
{
	/* Register suites. */
	if (CUE_SUCCESS != CU_register_suites(suites)) {
		CU_cleanup_registry();
		return CU_get_error();
	}

	return 0;
}
