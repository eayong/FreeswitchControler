#include <time.h>
#include <stdarg.h>
#include <stdio.h>
#include <errno.h>
#include <string.h>

#include "ctrl_log.h"

#define LOG_BUFFER_LEN 4096
typedef struct level_str_s
{
    int         index;
    const char  *str;
}level_str_t;

static level_str_t s_level_str[] = {
    { CTRL_LOG_CONSOLE, "CONSOLE" },
    { CTRL_LOG_EMERG, "EMERG" },
    { CTRL_LOG_ALERT, "ALERT" },
    { CTRL_LOG_ERROR, "ERROR" },
    { CTRL_LOG_WARN, "WARN" },
    { CTRL_LOG_NOTICE, "NOTICE" },
    { CTRL_LOG_INFO, "INFO" },
    { CTRL_LOG_DEBUG, "DEBUG" },
    { CTRL_LOG_NULL, "NULL" }
};

void ctrl_log_print(const ctrl_log_t * log, ctrl_log_level level, const char *format, ...)
{
    if (log == NULL || log->fp == NULL)
        return;

    if (level > log->level || log->level > CTRL_LOG_NULL)
    {
        return;
    }

    int len = 0;
    struct tm tmv;
    time_t timev = time(NULL);
    localtime_r(&timev, &tmv);

    char date[32] = {0};
    snprintf(date, sizeof(date), "%04d-%02d-%02d %02d:%02d:%02d",
        tmv.tm_year + 1900, tmv.tm_mon + 1, tmv.tm_mday, tmv.tm_hour, tmv.tm_min, tmv.tm_sec);
    fprintf(log->fp, "[%s][%s]", date, s_level_str[log->level].str);
    
    va_list ap;
    va_start(ap, format);
    
    char buffer[LOG_BUFFER_LEN] = {0};
    len = vsnprintf(buffer, sizeof(buffer), format, ap);
    buffer[len] = 0;
    
    fprintf(log->fp, "%s", buffer);
    va_end(ap);
    fflush(log->fp);
}

ctrl_log_t *init_ctrl_log(ctrl_log_t *init_log, const ctrl_conf_t *conf)
{
    if (init_log == NULL || conf == NULL)
        return NULL;
    
    ctrl_log_t *log = NULL;
    if (conf->log_file != NULL)
    {
        init_log->fp = fopen(conf->log_file, "w+");
        if (init_log->fp == NULL)
        {
            fprintf(stderr, "fopen %s error. %s\n", conf->log_file, strerror(errno));
            return NULL;
        }
        log = init_log;
        log->level = conf->log_level;
    }

    ctrl_log_print(log, CTRL_LOG_INFO, "main:listen = %d, main:worker_count = %d, main:epoll_size = %d\n",
        conf->listen, conf->worker, conf->epoll_size);
    ctrl_log_print(log, CTRL_LOG_INFO, "log:level = %d, log:log_file = %s\n",
        conf->log_level, conf->log_file);
    ctrl_log_print(log, CTRL_LOG_INFO, "ssl:use = %d, ssl:cert_file = %s, ssl:key_file = %s, ssl:protocols = %x\n",
        conf->use_ssl, conf->cert_file, conf->key_file, conf->protocols);
    
    return log;
}

void fini_ctrl_log(ctrl_log_t *log)
{
    if (log->fp != NULL)
    {
        fclose(log->fp);
        log->fp = NULL;
    }
}


