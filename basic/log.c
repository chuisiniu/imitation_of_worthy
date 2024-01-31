#include <stdio.h>
#include <signal.h>
#include <stdarg.h>
#include <time.h>

#include "log.h"

#undef LOG_LV_CHOOSE
#define LOG_LV_CHOOSE(lv, str) str

#define LOG_BUF_LEN 4096
#define LOG_LV_STR_MAX_LEN 6

#define LOG_TIME_FMT "[%04d-%02d-%02d %02d:%02d:%02d]"

#define LOG_DEBUG_FMT LOG_TIME_FMT" \033[32m[%*s]\033[0m %s\n"
#define LOG_INFO_FMT LOG_TIME_FMT" \033[34m[%*s]\033[0m %s\n"
#define LOG_ERROR_FMT LOG_TIME_FMT" \033[33m[%*s]\033[0m %s\n"
#define LOG_FATAL_FMT LOG_TIME_FMT" \033[41m[%*s]\033[0m %s\n"

const char *log_lv_e2s(enum log_lv lv)
{
	static const char *m_log_lv_str_array[] = {
		LOG_LV_ARRAY
	};

	if (lv > LOG_LV_FATAL) {
		return "";
	}

	return m_log_lv_str_array[lv];
}

struct logger {
	FILE *fp;
	enum log_lv lv;
};

static struct logger m_logger;

void log_open(FILE *fp, enum log_lv lv)
{
	m_logger.fp = fp;
	m_logger.lv = lv;
}

void log_printf(enum log_lv lv, const char *fmt, ...)
{
	va_list args;
	char buf[LOG_BUF_LEN];
	time_t now;
	struct tm tm;
	struct logger *logger = &m_logger;
	const char *fmts[] = {
		LOG_DEBUG_FMT,
		LOG_INFO_FMT,
		LOG_ERROR_FMT,
		LOG_FATAL_FMT
	};

	if (lv < logger->lv)
		return;

	va_start(args, fmt);
	vsnprintf(buf, sizeof(buf), fmt, args);
	va_end(args);

	time(&now);
	gmtime_r(&now, &tm);


	fprintf(logger->fp, fmts[lv],
	        tm.tm_year + 1900, tm.tm_mon + 1, tm.tm_mday,
	        tm.tm_hour, tm.tm_min, tm.tm_sec, LOG_LV_STR_MAX_LEN,
	        log_lv_e2s(lv), buf);

	if (lv ==LOG_LV_FATAL)
		raise(SIGTERM);
}

void log_init(FILE *fp, enum log_lv lv)
{
	log_open(fp, lv);
}
