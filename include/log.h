#ifndef IMITATION_OF_WORTHY_LOG_H
#define IMITATION_OF_WORTHY_LOG_H

#define LOG_LV_ARRAY                  \
LOG_LV_CHOOSE(LOG_LV_DEBUG, "DEBUG"), \
LOG_LV_CHOOSE(LOG_LV_INFO,  "INFO"),  \
LOG_LV_CHOOSE(LOG_LV_ERROR, "ERROR"), \
LOG_LV_CHOOSE(LOG_LV_FATAL, "FATAL")

#define LOG_LV_CHOOSE(lv, str) lv

enum log_lv {
	LOG_LV_ARRAY
};

void log_printf(enum log_lv lv, const char *fmt, ...);

#define log_debug(fmt, arg...) \
log_printf(LOG_LV_DEBUG, fmt, ##arg)

#define log_info(fmt, arg...) \
log_printf(LOG_LV_INFO, fmt, ##arg)

#define log_error(fmt, arg...) \
log_printf(LOG_LV_ERROR, fmt, ##arg)

#define log_fatal(fmt, arg...) \
log_printf(LOG_LV_FATAL, fmt, ##arg)

void log_init(FILE *fp, enum log_lv lv);

#endif //IMITATION_OF_WORTHY_LOG_H
