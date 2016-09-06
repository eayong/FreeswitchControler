#include <sys/ioctl.h>
#include <sys/select.h>
#include <sys/time.h>
#include <string.h>

#include "sock_client.h"
#include "sock_tcp.h"

#ifdef HAS_OPENSSL
#include "sock_ssl.h"
#endif

#define TIME_OUT_TIME 5


int init_client_socket(client_socket_t *client, const char *host, int port, const ctrl_log_t *log
#ifdef HAS_OPENSSL
    , SSL_CTX *ssl_ctx
#endif /* HAS_OPENSSL */
    )
{
#ifdef HAS_OPENSSL
        client->ssl_ctx = (SSL_CTX *) ssl_ctx;
#endif /* HAS_OPENSSL */

    int fd = socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0)
    {
        ctrl_log_print(log, CTRL_LOG_ERROR, "initialize socket failed. error: %s", strerror(errno));
        return SOCKET_ERR_FAIL;
    }
    
    struct sockaddr_in sa;
    memset (&sa, 0, sizeof(sa));
    sa.sin_family      = AF_INET;
    sa.sin_addr.s_addr = inet_addr(host);   /* Server IP */
    sa.sin_port        = htons(port);          /* Server Port number */

    int error = -1;
    int len = sizeof(int);
    
    set_nonblocking(fd, 1, log);

    int ret = 0;
    if (connect(fd, (struct sockaddr*)&sa, sizeof(sa)) == -1)
    {
        struct timeval tm;
        fd_set set;
        tm.tv_sec = TIME_OUT_TIME;
        tm.tv_usec = 0;
        FD_ZERO(&set);
        FD_SET(fd, &set);
        if (select(fd+1, NULL, &set, NULL, &tm) > 0)
        {
            getsockopt(fd, SOL_SOCKET, SO_ERROR, &error, (socklen_t *)&len);
            if (error == 0)
                ret = 1;
            else
                ret = 0;
        } 
        else
            ret = 0;
    }
    else
        ret = 1;
    
    set_nonblocking(fd, 0, log);

    if (!ret) 
    {
        close(fd);
        ctrl_log_print(log, CTRL_LOG_ERROR, "connect socket %s:%d failed. error: %s",
            host, port, strerror(errno));
        return -1;
    }
    
#ifdef HAS_OPENSSL
    if (client->ssl_ctx != NULL)
    {
        if (ssl_init_socket(&client->sock, fd, SOCKET_SSL_CLIENT, log, client->ssl_ctx) != SOCKET_ERR_NONE)
        {
            ctrl_log_print(log, CTRL_LOG_ERROR, "ssl_init_socket %d failed. error: %s", fd, strerror(errno));
            close(fd);
            return SOCKET_ERR_FAIL;
        }
    }
    else
    {
        if (tcp_init_socket(&client->sock, fd, SOCKET_TCP_CLIENT, log) != SOCKET_ERR_NONE)
        {
            ctrl_log_print(log, CTRL_LOG_ERROR, "tcp_init_socket %d failed. error: %s", fd, strerror(errno));
            close(fd);
            return SOCKET_ERR_FAIL;
        }
    }
#else
    if (tcp_init_socket(&client->sock, fd, SOCKET_TCP_CLIENT, log) != SOCKET_ERR_NONE)
    {
        ctrl_log_print(log, CTRL_LOG_ERROR, "tcp_init_socket %d failed. error: %s", fd, strerror(errno));
        close(fd);
        return SOCKET_ERR_FAIL;
    }
#endif // HAS_OPENSSL

    return SOCKET_ERR_NONE;

}

int fini_client_socket(client_socket_t *client, const ctrl_log_t *log)
{
    if (client == NULL)
        return SOCKET_ERR_FAIL;

    if (client->sock.fd > 0)
    {
        close(client->sock.fd);
        client->sock.fd = -1;
    }

    ctrl_log_print(log, CTRL_LOG_DEBUG, "fini_client_socket %d success.", client->sock.fd);
    return SOCKET_ERR_NONE;

}

