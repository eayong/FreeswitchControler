#ifndef __CTRL_CONTROLER_H__
#define __CTRL_CONTROLER_H__

#include <stdio.h>
#include <error.h>
#include <errno.h>
#include <sys/epoll.h>

#include "ctrl_log.h"
#include "ctrl_conf.h"
#include "ssl_context.h"
#include "sock_server.h"

typedef struct listening_s
{
    server_socket_t     sock;
    struct epoll_event  rev;
}listening_t;

typedef struct controler_s
{
    int                 ep_fd;
    const ctrl_log_t    *log;
    const ctrl_conf_t   *conf;
    listening_t         listen;
    
#ifdef HAS_OPENSSL
    const ssl_context_t *ssl_ctx;
#endif
}controler_t;

extern volatile controler_t *g_ctrl;

int init_controler(controler_t *ctrl, const ctrl_conf_t *conf, ctrl_log_t *log);

#endif /* __CTRL_CONTROLER_H__ */
