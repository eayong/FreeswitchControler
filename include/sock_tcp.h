#ifndef __PROXY_SOCK_TCP_H__
#define __PROXY_SOCK_TCP_H__

#include "sock_base.h"

int tcp_init_socket(ctrl_socket_t *sock, int fd, socket_type_t type, const ctrl_log_t *log);

void tcp_fini_socket(ctrl_socket_t *sock, const ctrl_log_t *log);


#endif // __PROXY_SOCK_TCP_H__

