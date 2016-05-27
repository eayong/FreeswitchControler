#ifndef __CTRL_CONF_H_
#define __CTRL_CONF_H_

#include "ctrl_def.h"

struct ctrl_conf_s
{
    int     listen;
    int     worker;
    int     connects;
    int     events;
    int     timer;
    int     process;
    int     log_level;
    int     use_ssl;
    int     protocols;
    char    *log_file;
    char    *cert_file;
    char    *key_file;
};


int init_ctrl_conf(ctrl_conf_t *conf, const char *conf_file);

int fini_ctrl_conf(ctrl_conf_t *conf);

#endif /* __CTRL_CONF_H_ */

