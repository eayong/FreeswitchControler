#ifndef __SOCK_CLIENT_H__
#define __SOCK_CLIENT_H__

#include "sock_base.h"

#define DEFAULT_HOST_LEN    32


typedef struct client_socket_s
{
    char        host[DEFAULT_HOST_LEN];
    int         port;
    ctrl_socket_t    sock;
#ifdef HAS_OPENSSL
    SSL_CTX     *ssl_ctx;
#endif /* HAS_OPENSSL */

}client_socket_t;

int init_client_socket(client_socket_t *client, const char *host, int port, const ctrl_log_t *log
#ifdef HAS_OPENSSL
    , SSL_CTX *ssl_ctx
#endif /* HAS_OPENSSL */
    );

int fini_client_socket(client_socket_t *client, const ctrl_log_t *log);


#endif // __SOCK_CLIENT_H__
