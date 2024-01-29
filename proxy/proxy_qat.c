#include <openssl/engine.h>

#include "log.h"
#include "event.h"

#include "proxy_qat.h"

ENGINE *g_qat_engine = NULL;

volatile struct event *g_qat_poll_timer = NULL;

#define GET_NUM_ASYM_REQUESTS_IN_FLIGHT             1
#define GET_NUM_KDF_REQUESTS_IN_FLIGHT              2
#define GET_NUM_CIPHER_PIPELINE_REQUESTS_IN_FLIGHT  3
#define GET_NUM_ASYM_NUM_ITEMS_IN_QUEUE             4
#define GET_NUM_KDF_NUM_ITEMS_IN_QUEUE              5
#define GET_NUM_SYM_NUM_ITEMS_IN_QUEUE              6

#define QAT_POLL_THRESHOLD 16

static int *nr_asym_requests_in_flight = NULL;
static int *nr_kdf_requests_in_flight = NULL;
static int *nr_cipher_requests_in_flight = NULL;
static int *nr_asym_mb_items_in_queue = NULL;
static int *nr_kdf_mb_items_in_queue = NULL;
static int *nr_sym_mb_items_in_queue = NULL;
static int nr_heuristic_poll = 0;

extern volatile int nr_ssl_connection;

static inline void
proxy_poll_qat_hw()
{
	int poll_status = 0;

	if (!ENGINE_ctrl_cmd(g_qat_engine, "POLL", 0, &poll_status, NULL, 0))
		perror("QAT Engine failed: POLL");
}

static int proxy_poll_timer(struct event *e)
{
	g_qat_poll_timer = NULL;

	if (*nr_asym_requests_in_flight + *nr_kdf_requests_in_flight
	    + *nr_cipher_requests_in_flight + *nr_asym_mb_items_in_queue
	    + *nr_kdf_mb_items_in_queue + *nr_sym_mb_items_in_queue > 0) {
		if (nr_heuristic_poll == 0) {
			proxy_poll_qat_hw();
		}
	}

	if (*nr_asym_requests_in_flight + *nr_kdf_requests_in_flight
	    + *nr_cipher_requests_in_flight + *nr_asym_mb_items_in_queue
	    + *nr_kdf_mb_items_in_queue + *nr_sym_mb_items_in_queue > 0) {
		nr_heuristic_poll = 0;
		g_qat_poll_timer = event_add_timer(
			e->scheduler, proxy_poll_timer, NULL, 1);
	}

	return 0;
}

void proxy_poll_qat(struct event_scheduler *es)
{
	int polled_flag = 0;

	if (*nr_asym_requests_in_flight + *nr_kdf_requests_in_flight
	    + *nr_cipher_requests_in_flight +  *nr_asym_mb_items_in_queue
	    + *nr_kdf_mb_items_in_queue + *nr_sym_mb_items_in_queue <= 0)
		return;

	/* one-time try to retrieve QAT responses */
	if (*nr_asym_requests_in_flight + *nr_kdf_requests_in_flight
	    + *nr_cipher_requests_in_flight +  *nr_asym_mb_items_in_queue
	    + *nr_kdf_mb_items_in_queue + *nr_sym_mb_items_in_queue
	    >= nr_ssl_connection) {
		proxy_poll_qat_hw();
		nr_heuristic_poll++;
		polled_flag = 1;
	}

	if (!polled_flag) {
		if (*nr_asym_requests_in_flight + *nr_kdf_requests_in_flight
		    + *nr_cipher_requests_in_flight + *nr_asym_mb_items_in_queue
		    + *nr_kdf_mb_items_in_queue + *nr_sym_mb_items_in_queue
		    >= QAT_POLL_THRESHOLD) {
			proxy_poll_qat_hw();
			nr_heuristic_poll ++;
		}
	}

	if (*nr_asym_requests_in_flight + *nr_kdf_requests_in_flight
	    + *nr_cipher_requests_in_flight+ *nr_asym_mb_items_in_queue
	    + *nr_kdf_mb_items_in_queue + *nr_sym_mb_items_in_queue > 0
	    && NULL == g_qat_poll_timer) {
		nr_heuristic_poll = 0;
		g_qat_poll_timer = event_add_timer(
			es, proxy_poll_timer, NULL, 1);
	}
}

static int proxy_get_counter_ptr()
{
	if (!ENGINE_ctrl_cmd(g_qat_engine, "GET_NUM_REQUESTS_IN_FLIGHT",
	                     GET_NUM_ASYM_REQUESTS_IN_FLIGHT,
	                     &nr_asym_requests_in_flight, NULL, 0)) {
		perror("QAT Engine failed: GET_NUM_REQUESTS_IN_FLIGHT");

		return -1;
	}

	if (!ENGINE_ctrl_cmd(g_qat_engine, "GET_NUM_REQUESTS_IN_FLIGHT",
	                     GET_NUM_KDF_REQUESTS_IN_FLIGHT,
	                     &nr_kdf_requests_in_flight, NULL, 0)) {
		perror("QAT Engine failed: GET_NUM_REQUESTS_IN_FLIGHT");

		return -1;
	}

	if (!ENGINE_ctrl_cmd(g_qat_engine, "GET_NUM_REQUESTS_IN_FLIGHT",
	                     GET_NUM_CIPHER_PIPELINE_REQUESTS_IN_FLIGHT,
	                     &nr_cipher_requests_in_flight, NULL, 0)) {
		perror("QAT Engine failed: GET_NUM_REQUESTS_IN_FLIGHT");

		return -1;
	}
	if (!ENGINE_ctrl_cmd(g_qat_engine, "GET_NUM_REQUESTS_IN_FLIGHT",
	                     GET_NUM_ASYM_NUM_ITEMS_IN_QUEUE,
	                     &nr_asym_mb_items_in_queue, NULL, 0)) {
		perror("QAT Engine failed: GET_NUM_REQUESTS_IN_FLIGHT");

		return -1;
	}
	if (!ENGINE_ctrl_cmd(g_qat_engine, "GET_NUM_REQUESTS_IN_FLIGHT",
	                     GET_NUM_KDF_NUM_ITEMS_IN_QUEUE,
	                     &nr_kdf_mb_items_in_queue, NULL, 0)) {
		perror("QAT Engine failed: GET_NUM_REQUESTS_IN_FLIGHT");

		return -1;
	}
	if (!ENGINE_ctrl_cmd(g_qat_engine, "GET_NUM_REQUESTS_IN_FLIGHT",
	                     GET_NUM_SYM_NUM_ITEMS_IN_QUEUE,
	                     &nr_sym_mb_items_in_queue, NULL, 0)) {
		perror("QAT Engine failed: GET_NUM_REQUESTS_IN_FLIGHT");

		return -1;
	}

	return 0;
}

void proxy_init_qat(struct event_scheduler* scheduler)
{
	g_qat_engine = ENGINE_by_id("qatengine");
	if (NULL == g_qat_engine) {
		log_info("no qatengine");

		return;
	}

	if (!ENGINE_init(g_qat_engine)) {
		log_info("fail to init qat engine");

		goto ERROR;
	}

	if (!ENGINE_set_default(g_qat_engine, ENGINE_METHOD_ALL)) {
		log_info("ENGINE_set_default error");

		goto ERROR;
	}

	proxy_get_counter_ptr();

	if (!ENGINE_ctrl_cmd(g_qat_engine, "ENABLE_EVENT_DRIVEN_POLLING_MODE",
			     0, NULL, NULL, 0)) {
		log_error("QAT Engine failed: ENABLE_EVENT_DRIVEN_POLLING_MODE");

		goto ERROR;
	}

	if (!ENGINE_ctrl_cmd(g_qat_engine, "ENABLE_HEURISTIC_POLLING",
			     0, NULL, NULL, 0)) {
		log_error("QAT Engine failed: ENABLE_HEURISTIC_POLLING");

		goto ERROR;
	}

	g_qat_poll_timer = event_add_timer(
		scheduler,  proxy_poll_timer, NULL, 1);

	log_info("QAT Engine init ok");

	return;
ERROR:
	if (g_qat_engine) {
		ENGINE_finish(g_qat_engine);
		ENGINE_free(g_qat_engine);
	}
	g_qat_engine = NULL;
}
