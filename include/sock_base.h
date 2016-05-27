#ifndef __SOCK_BASE_H__
#define __SOCK_BASE_H__

#ifdef HAS_OPENSSL
#include "ssl_context.h"
#endif // HAS_OPENSSL

#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <errno.h>
#include <unistd.h>
#include <stdint.h>
#include <fcntl.h>

#include "ctrl_def.h"
#include "ctrl_log.h"

#define SOCKET_ERR_NONE     0
#define SOCKET_ERR_FAIL     -1
#define SOCKET_ERR_BLOCK    -2
#define SOCKET_ERR_CLOSE    -3
#define SOCKET_ERR_SSL      -4

typedef enum
{
    SOCKET_INVALID,
    SOCKET_HANDSHARE,
    SOCKET_HANDSHARE_SSL,
    SOCKET_CONNECTED,
    SOCKET_ACCEPTED,
}socket_status_t;

typedef enum
{
    SOCKET_TCP_CLIENT,
    SOCKET_TCP_SERVER,
    SOCKET_SSL_CLIENT,
    SOCKET_SSL_SERVER,
    SOCKET_TCP_ACCEPT,
    SOCKET_SSL_ACCEPT,
    SOCKET_UNKONW_TYPE,
}socket_type_t;

struct ctrl_socket_s
{
    int                 fd;
    socket_type_t       type;
    socket_status_t     status;
    struct sockaddr_in  local_addr;
    struct sockaddr_in  remote_addr;
    
#ifdef HAS_OPENSSL
    SSL     *ssl;
#endif // HAS_OPENSSL

    int (*send) (const ctrl_socket_t *sock, const char *data, uint32_t len, const ctrl_log_t *log);
    int (*recv) (const ctrl_socket_t *sock, char *data, uint32_t len, const ctrl_log_t *log);
    int (*handshake) (ctrl_socket_t *sock, const ctrl_log_t *log);
    void (*close) (ctrl_socket_t *sock, const ctrl_log_t *log);
};

void reset_ctrl_socket(ctrl_socket_t *sock);

int set_nonblocking(int fd, int blocking, const ctrl_log_t *log);

int set_recv_timeout(int fd, int msec, const ctrl_log_t *log);

int set_send_timeout(int fd, int msec, const ctrl_log_t *log);

int init_addr(ctrl_socket_t *sock, const ctrl_log_t *log);

#endif // __SOCK_BASE_H__

