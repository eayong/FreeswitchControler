#include "sock_base.h"

#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <error.h>
#include <assert.h>

int set_nonblocking(int fd, int blocking, const ctrl_log_t *log)
{
    
    int flags, ret;
    if ((flags = fcntl(fd, F_GETFL, 0)) == -1)
    {
        flags = 0;
    }
    if (blocking)
    {
        flags |= O_NONBLOCK;
    }
    else
    {
        flags &= ~O_NONBLOCK;
    }
    ret = fcntl(fd, F_SETFL, flags);
    if (ret < 0)
    {
        ctrl_log_print(log, CTRL_LOG_INFO, "socket %d set %s failed.\n", fd, blocking ? "nonblocking" : "blocking");
        return SOCKET_ERR_FAIL;
    }
    
    ctrl_log_print(log, CTRL_LOG_DEBUG, "socket %d set %s success.\n", fd, blocking ? "nonblocking" : "blocking");
    return SOCKET_ERR_NONE;
}

int set_recv_timeout(int fd, int msec, const ctrl_log_t *log)
{
    struct timeval tv;
    tv.tv_sec = msec / 1000;
    tv.tv_usec = msec % 1000 * 1000;
    
    int ret = setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, (const char*)&tv, sizeof(tv));
    if (ret != 0)
    {
        ctrl_log_print(log, CTRL_LOG_INFO, "socket %d set_recv_timeout %d failed.\n", fd, msec);
        return SOCKET_ERR_FAIL;
    }
    
    ctrl_log_print(log, CTRL_LOG_DEBUG, "socket %d set_recv_timeout %d success.\n", fd, msec);
    return SOCKET_ERR_NONE;
}

int set_send_timeout(int fd, int msec, const ctrl_log_t *log)
{
    struct timeval tv;
    tv.tv_sec = msec / 1000;
    tv.tv_usec = msec % 1000 * 1000;

    int ret = setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, (const char*)&tv, sizeof(tv));
    if (ret != 0)
    {
        ctrl_log_print(log, CTRL_LOG_INFO, "socket %d set_send_timeout %d failed.\n", fd, msec);
        return SOCKET_ERR_FAIL;
    }
    
    ctrl_log_print(log, CTRL_LOG_DEBUG, "socket %d set_send_timeout %d success.\n", fd, msec);
    return SOCKET_ERR_NONE;
}

int init_addr(ctrl_socket_t *sock, const ctrl_log_t *log)
{
    if (sock == NULL)
        return SOCKET_ERR_FAIL;
    
    socklen_t  len = sizeof(struct sockaddr_in);
    if (getsockname(sock->fd, (struct sockaddr*)&sock->local_addr, &len ) < 0)
    {
        ctrl_log_print(log, CTRL_LOG_INFO, "getsockname %d failed.", sock->fd);
        return SOCKET_ERR_FAIL;
    }
    if (getpeername(sock->fd, (struct sockaddr*)&sock->remote_addr, &len ) < 0)
    {
        ctrl_log_print(log, CTRL_LOG_INFO, "getpeername %d failed.", sock->fd);
        return SOCKET_ERR_FAIL;
    }
    
    ctrl_log_print(log, CTRL_LOG_DEBUG, "socket %d info: location[%s:%d], remote: %s.\n",
        sock->fd, inet_ntoa(sock->local_addr.sin_addr), ntohs(sock->local_addr.sin_port),
        inet_ntoa(sock->remote_addr.sin_addr), ntohs(sock->remote_addr.sin_port));
    return SOCKET_ERR_NONE;
}


