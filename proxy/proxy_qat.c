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
/*
	if (*nr_asym_requests_in_flight + *nr_kdf_requests_in_flight
	    + *nr_cipher_requests_in_flight + *nr_asym_mb_items_in_queue
	    + *nr_kdf_mb_items_in_queue + *nr_sym_mb_items_in_queue > 0) {
		if (nr_heuristic_poll == 0) {
			proxy_poll_qat_hw();
		}
	}
*/
	g_qat_poll_timer = event_add_timer_millisec(
		e->scheduler, proxy_poll_timer, NULL, 10);
	proxy_poll_qat_hw();
/*
	if (*nr_asym_requests_in_flight + *nr_kdf_requests_in_flight
	    + *nr_cipher_requests_in_flight + *nr_asym_mb_items_in_queue
	    + *nr_kdf_mb_items_in_queue + *nr_sym_mb_items_in_queue > 0) {
		nr_heuristic_poll = 0;
		g_qat_poll_timer = event_add_timer(
			e->scheduler, proxy_poll_timer, NULL, 1);
	}
*/
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

/*
 * 获取到qatengine中记录硬件正在处理的请求的个数，用于启发式POLL硬件，启发式POLL硬件
 * 会在发现硬件完成了异步操作的时候POLL硬件，nr_ssl_connection 记录当前我们下发过的异步
 * 操作的个数，当下面获取到的这几个记数器的和小于nr_ssl_connection时，就说明有异步请求
 * 处理完了，需要POLL硬件了。
 * */
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

/*
 * OpenSSL关于ENGINE的文档可以看
 * https://www.openssl.org/docs/man1.0.2/man3/engine.html
 *
 * 初始化qatengine
 * - 使用ENGINE_by_id获取到qatengine的structural reference
 * - 通过ENGINE_ctrl_cmd配置硬件
 * - 使用ENGINE_set_default让openssl把qatengine作为默认engine
 * - 调用ENGINE_init获取到qatengine的functional reference
 * - 添加poll硬件的定时器
 * */
int proxy_init_qat(struct event_scheduler *scheduler)
{
	g_qat_engine = ENGINE_by_id("qatengine");
	if (NULL == g_qat_engine) {
		log_info("no qatengine");

		return -1;
	}

	proxy_get_counter_ptr();

	if (!ENGINE_ctrl_cmd(g_qat_engine, "ENABLE_SW_FALLBACK",
			     0, NULL, NULL, 0)) {
		log_error("QAT Engine failed: ENABLE_SW_FALLBACK");

		goto ERROR;
	}

	if (!ENGINE_ctrl_cmd(g_qat_engine, "ENABLE_EXTERNAL_POLLING",
	                     0, NULL, NULL, 0)) {
		log_error("QAT Engine: ENABLE_EXTERNAL_POLLING, %s",
		          ERR_error_string(ERR_get_error(), NULL));

		goto ERROR;
	}
	if (!ENGINE_ctrl_cmd(g_qat_engine, "ENABLE_HEURISTIC_POLLING",
	                     0, NULL, NULL, 0)) {
		log_error("QAT Engine: ENABLE_HEURISTIC_POLLING, %s",
		          ERR_error_string(ERR_get_error(), NULL));

		goto ERROR;
	}

	if (!ENGINE_set_default(g_qat_engine,
				ENGINE_METHOD_ALL)) {
		log_info("ENGINE_set_default error");

		goto ERROR;
	}

	if (!ENGINE_init(g_qat_engine)) {
		log_info("fail to init qat engine");

		goto ERROR;
	}

	g_qat_poll_timer = event_add_timer(
		scheduler,  proxy_poll_timer, NULL, 1);

	log_info("QAT Engine init ok");

	return 0;
ERROR:
	if (g_qat_engine) {
		ENGINE_finish(g_qat_engine);
		ENGINE_free(g_qat_engine);
	}
	g_qat_engine = NULL;

	return -1;
}
