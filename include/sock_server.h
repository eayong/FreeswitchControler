#ifndef __SOCK_SERVER_H__
#define __SOCK_SERVER_H__

#include "ctrl_def.h"
#include "sock_base.h"

struct server_socket_s
{
    ctrl_socket_t   sock;
    int             port;
#ifdef HAS_OPENSSL
    SSL_CTX         *ssl_ctx;
#endif /* HAS_OPENSSL */
};

int init_tcp_server(server_socket_t *serv, int port, const ctrl_log_t *log);

int init_ssl_server(server_socket_t *serv, int port, const ctrl_log_t *log, void *ssl_ctx);

int fini_server_socket(server_socket_t *serv, const ctrl_log_t *log);

int accept_socket(server_socket_t *serv, ctrl_socket_t *sock, const ctrl_log_t *log);


#endif /* __SOCK_SERVER_H__ */

