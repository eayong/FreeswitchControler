#include "sock_tcp.h"

static int tcp_send(const ctrl_socket_t *sock, const char *data, uint32_t len, const ctrl_log_t *log);

static int tcp_recv(const ctrl_socket_t *sock, char *data, uint32_t len, const ctrl_log_t *log);

static int tcp_handshake(ctrl_socket_t *sock, const ctrl_log_t *log);

static void tcp_close(ctrl_socket_t *sock, const ctrl_log_t *log);


int tcp_init_socket(ctrl_socket_t *sock, int fd, socket_type_t type, const ctrl_log_t *log)
{
    if (sock == NULL)
        return SOCKET_ERR_FAIL;

    sock->fd = fd;
    sock->type = type;
    sock->status = SOCKET_CONNECTED;
    sock->send = tcp_send;
    sock->recv = tcp_recv;
    sock->handshake = tcp_handshake;
    sock->close = tcp_close;
    init_addr(sock, log);
    
    ctrl_log_print(log, CTRL_LOG_DEBUG, "tcp_init_socket %d success...", sock->fd);

    return SOCKET_ERR_NONE;
}

void tcp_fini_socket(ctrl_socket_t *sock, const ctrl_log_t *log)
{
    if (sock == NULL)
        return;

    sock->close(sock, log);
    ctrl_log_print(log, CTRL_LOG_DEBUG, "tcp_fini_socket %d success...", sock->fd);
}

static int tcp_send(const ctrl_socket_t *sock, const char *data, uint32_t len, const ctrl_log_t *log)
{
    if (sock == NULL)
        return SOCKET_ERR_FAIL;
    
    int nwrite = 0;
    int nleft = len;
    const char *ptr = data;
    while (nleft > 0)
    {
        nwrite = write(sock->fd, (void *)ptr, nleft);
        if (nwrite <= 0)
        {
            if (errno == EINPROGRESS || errno == EINTR)
            {
                continue;
            }
            else if (errno == EWOULDBLOCK)
            {
                break;
            }
            else
            {
                return SOCKET_ERR_FAIL;
            }
        }
        nleft -= nwrite;
        ptr += nwrite;
    }
    return len - nleft;
}

static int tcp_recv(const ctrl_socket_t *sock, char *data, uint32_t len, const ctrl_log_t *log)
{
    if (sock == NULL)
        return SOCKET_ERR_FAIL;
    
    int nleft = len;
    int nread = 0;
    char *ptr = data;
    while (nleft > 0)
    {
        nread = read(sock->fd, (void *)ptr, nleft);
        if (nread < 0)
        {
            if (errno == EINTR)
            {
                nread = 0;
            }
            else if (errno == EWOULDBLOCK)
            {
                break;
            }
            else
            {
                return SOCKET_ERR_FAIL;
            }
        }
        else if (nread == 0)
        {
            break;
        }
        nleft -= nread;
        ptr += nread;
    }
    return (len - nleft);

}

static int tcp_handshake(ctrl_socket_t *sock, const ctrl_log_t *log)
{
    return SOCKET_ERR_NONE;
}

static void tcp_close(ctrl_socket_t *sock, const ctrl_log_t *log)
{
    if (sock == NULL)
        return;

    if (sock->status == SOCKET_INVALID)
    {
        close(sock->fd);
        sock->status = SOCKET_INVALID;
    }
    ctrl_log_print(log, CTRL_LOG_DEBUG, "socket %d close.\n", sock->fd);
}



