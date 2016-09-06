#include <string.h>
#include "sock_server.h"
#include "sock_tcp.h"

#ifdef HAS_OPENSSL
#include "sock_ssl.h"
#endif


static int init_server_socket(server_socket_t *serv, int port, const ctrl_log_t *log
#ifdef HAS_OPENSSL
    , SSL_CTX *ssl_ctx
#endif /* HAS_OPENSSL */
    )
{
#ifdef HAS_OPENSSL
    serv->ssl_ctx = ssl_ctx;
#endif /* HAS_OPENSSL */


    int fd = socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0)
    {
        ctrl_log_print(log, CTRL_LOG_ERROR, "initialize socket failed. error: %s", strerror(errno));
        return SOCKET_ERR_FAIL;
    }
    
    int yes = 1;
    setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &yes, sizeof(int));
    
    struct sockaddr_in sa_serv;
    memset(&sa_serv, 0, sizeof(sa_serv));
    sa_serv.sin_family      = AF_INET;
    sa_serv.sin_addr.s_addr = INADDR_ANY;
    sa_serv.sin_port        = htons(port);   /* Server Port number */

    int ret = bind(fd, (struct sockaddr*)&sa_serv, sizeof(sa_serv));
    if (ret < 0)
    {
        ctrl_log_print(log, CTRL_LOG_ERROR, "bind socket failed. error: %s", strerror(errno));
        return SOCKET_ERR_FAIL;
    }

    ret = listen(fd, 5);
    if (ret < 0)
    {
        ctrl_log_print(log, CTRL_LOG_ERROR, "listen socket failed. error: %s", strerror(errno));
        return SOCKET_ERR_FAIL;
    }
    
#ifdef HAS_OPENSSL
    if (serv->ssl_ctx != NULL)
    {
        if (ssl_init_socket(&serv->sock, fd, SOCKET_SSL_ACCEPT, log, serv->ssl_ctx) != SOCKET_ERR_NONE)
        {
            ctrl_log_print(log, CTRL_LOG_ERROR, "ssl_init_socket %d failed. error: %s", fd, strerror(errno));
            close(fd);
            return SOCKET_ERR_FAIL;
        }
    }
    else
    {
        if (tcp_init_socket(&serv->sock, fd, SOCKET_TCP_ACCEPT, log) != SOCKET_ERR_NONE)
        {
            ctrl_log_print(log, CTRL_LOG_ERROR, "tcp_init_socket %d failed. error: %s", fd, strerror(errno));
            close(fd);
            return SOCKET_ERR_FAIL;
        }
    }
#else
    if (tcp_init_socket(&serv->sock, fd, SOCKET_TCP_ACCEPT, log) != SOCKET_ERR_NONE)
    {
        ctrl_log_print(log, CTRL_LOG_ERROR, "tcp_init_socket %d failed. error: %s", fd, strerror(errno));
        close(fd);
        return SOCKET_ERR_FAIL;
    }
#endif // HAS_OPENSSL

    serv->port = port;
    
    return SOCKET_ERR_NONE;
}

int init_ssl_server(server_socket_t *serv, int port, const ctrl_log_t *log, void *ssl_ctx)
{
#ifdef HAS_OPENSSL
    return init_server_socket(serv, port, log, (SSL_CTX*)ssl_ctx);
#else
    return init_server_socket(serv, port, log);
#endif
}

int init_tcp_server(server_socket_t *serv, int port, const ctrl_log_t *log)
{
#ifdef HAS_OPENSSL
    return init_server_socket(serv, port, log, NULL);
#else
    return init_server_socket(serv, port, log);
#endif
}

int accept_socket(server_socket_t *serv, ctrl_socket_t *sock, const ctrl_log_t *log)
{
    if (serv == NULL)
        return SOCKET_ERR_FAIL;
    
    struct sockaddr_in sa_cli;
    size_t serv_len;
    int fd = accept(serv->sock.fd, (struct sockaddr*)&sa_cli, (socklen_t*)&serv_len);
    if (fd < 0)
    {
        ctrl_log_print(log, CTRL_LOG_ERROR, "accept socket failed. error: %s", strerror(errno));
        return SOCKET_ERR_FAIL;
    }

    ctrl_log_print(log, CTRL_LOG_DEBUG, "accept serv fd %d[%s:%d]", fd, inet_ntoa(sa_cli.sin_addr), ntohs(sa_cli.sin_port));

#ifdef HAS_OPENSSL
    if (serv->ssl_ctx != NULL)
    {
        if (ssl_init_socket(sock, fd, SOCKET_SSL_SERVER, log, serv->ssl_ctx) != SOCKET_ERR_NONE)
        {
            ctrl_log_print(log, CTRL_LOG_ERROR, "ssl_init_socket %d failed. error: %s", fd, strerror(errno));
            close(fd);
            return SOCKET_ERR_FAIL;
        }
    }
    else
    {
        if (tcp_init_socket(sock, fd, SOCKET_TCP_SERVER, log) != SOCKET_ERR_NONE)
        {
            ctrl_log_print(log, CTRL_LOG_ERROR, "tcp_init_socket %d failed. error: %s", fd, strerror(errno));
            close(fd);
            return SOCKET_ERR_FAIL;
        }
    }
#else
    if (tcp_init_socket(sock, fd, SOCKET_TCP_SERVER, log) != SOCKET_ERR_NONE)
    {
        ctrl_log_print(log, CTRL_LOG_ERROR, "tcp_init_socket %d failed. error: %s", fd, strerror(errno));
        close(fd);
        return SOCKET_ERR_FAIL;
    }
#endif /* HAS_OPENSSL */

    return SOCKET_ERR_NONE;
}

int fini_server_socket(server_socket_t *serv, const ctrl_log_t *log)
{
    if (serv == NULL)
        return SOCKET_ERR_FAIL;

    if (serv->sock.status != SOCKET_INVALID)
    {
        close(serv->sock.fd);
        serv->sock.fd = -1;
        serv->sock.status = SOCKET_INVALID;
    }

    ctrl_log_print(log, CTRL_LOG_DEBUG, "fini_server_socket %d success.", serv->sock.fd);
    return SOCKET_ERR_NONE;
}

