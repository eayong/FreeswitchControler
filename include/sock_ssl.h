#ifndef __PROXY_SOCK_SSL_H__
#define __PROXY_SOCK_SSL_H__

#include "sock_base.h"
#include "ssl_context.h"

int ssl_init_socket(ctrl_socket_t *sock, int fd, socket_type_t type, const ctrl_log_t *log, SSL_CTX *ssl_ctx);

void ssl_fini_socket(ctrl_socket_t *sock, const ctrl_log_t *log);


#endif // __PROXY_SOCK_SSL_H__

