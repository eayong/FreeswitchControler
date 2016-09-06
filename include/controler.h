#ifndef __CTRL_CONTROLER_H__
#define __CTRL_CONTROLER_H__

#include <stdio.h>
#include <error.h>
#include <errno.h>

#include "ctrl_def.h"
#include "ctrl_log.h"
#include "ctrl_conf.h"
#include "ssl_context.h"
#include "sock_server.h"
#include "ctrl_event.h"
#include "ctrl_connect.h"

struct controler_s
{
    int                 ep_fd;
    int                 nfree_conn;
    const ctrl_log_t    *log;
    const ctrl_conf_t   *conf;
    ctrl_connection_t   *connections;
    ctrl_connection_t   *free_conn;
    ctrl_event_t        *readev;
    ctrl_event_t        *writeev;
    server_socket_t     ctrl_listen;
    
#ifdef HAS_OPENSSL
    const ssl_context_t *ssl_ctx;
#endif
};


int init_controler(controler_t *ctrl, const ctrl_conf_t *conf, ctrl_log_t *log);

void fini_controler(controler_t *ctrl);

#endif /* __CTRL_CONTROLER_H__ */
