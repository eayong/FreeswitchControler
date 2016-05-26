#ifndef __CTRL_LOG_H__
#define __CTRL_LOG_H__

#include <stdio.h>

#include "ctrl_conf.h"

typedef enum
{
    CTRL_LOG_CONSOLE    = 0,
    CTRL_LOG_EMERG      = 1,
    CTRL_LOG_ALERT      = 2,
    CTRL_LOG_ERROR      = 3,
    CTRL_LOG_WARN       = 4,
    CTRL_LOG_NOTICE     = 5,
    CTRL_LOG_INFO       = 6,
	CTRL_LOG_DEBUG      = 7,
	CTRL_LOG_NULL       = 8,
}ctrl_log_level;

#define CTRL_LOG_PARAM  __FILE__, __FUNCTION__, __LINE__


typedef struct ctrl_log_s
{
    ctrl_log_level     level;
    FILE               *fp;
}ctrl_log_t;

void ctrl_log_print(const ctrl_log_t *log, ctrl_log_level level, const char *format, ...);

ctrl_log_t * init_ctrl_log(ctrl_log_t *init_log, const ctrl_conf_t *conf);

void fini_ctrl_log(ctrl_log_t *log);

#endif /* __CTRL_LOG_H__ */
