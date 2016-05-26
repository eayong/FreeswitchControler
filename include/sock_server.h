#ifndef __SOCK_SERVER_H__
#define __SOCK_SERVER_H__

#include "sock_base.h"

typedef struct server_socket_s
{
    int         fd;
    int         port;
#ifdef HAS_OPENSSL
    SSL_CTX     *ssl_ctx;
#endif /* HAS_OPENSSL */
}server_socket_t;

int init_server_socket(server_socket_t *serv, int port, const ctrl_log_t *log
#ifdef HAS_OPENSSL
    , SSL_CTX *ssl_ctx
#endif /* HAS_OPENSSL */
    );

int fini_server_socket(server_socket_t *serv, const ctrl_log_t *log);

int accept_socket(const server_socket_t *serv, ctrl_socket_t *sock, const ctrl_log_t *log);


#endif /* __SOCK_SERVER_H__ */

