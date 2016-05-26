#include "sock_ssl.h"


static int ssl_send(const ctrl_socket_t *sock, const char *data, uint32_t len, const ctrl_log_t *log);

static int ssl_recv(const ctrl_socket_t *sock, char *data, uint32_t len, const ctrl_log_t *log);

static int ssl_handshake(ctrl_socket_t *sock, const ctrl_log_t *log);

static void ssl_close(ctrl_socket_t *sock, const ctrl_log_t *log);

static void show_certificate(const ctrl_socket_t *sock, const ctrl_log_t *log);


int ssl_init_socket(ctrl_socket_t *sock, int fd, socket_type_t type, const ctrl_log_t *log, SSL_CTX *ssl_ctx)
{
    if (sock == NULL || ssl_ctx == NULL)
        return SOCKET_ERR_FAIL;
    
    sock->ssl = SSL_new(ssl_ctx);

    if(NULL == sock->ssl)
    {
        ctrl_log_print(log, CTRL_LOG_ERROR, "SSL_new(%d) failed [%s]\n", fd, ERR_error_string(ERR_get_error(), NULL));
        return SOCKET_ERR_FAIL;
    }
    
    if(SSL_set_fd(sock->ssl, fd) != 1)
    {        
        ctrl_log_print(log, CTRL_LOG_ERROR, "SSL_set_fd(%d) failed [%s]\n", fd, ERR_error_string(ERR_get_error(), NULL));
        return SOCKET_ERR_FAIL;
    }

    sock->fd = fd;
    sock->type = type;
    sock->status = SOCKET_CONNECTED;
    sock->send = ssl_send;
    sock->recv = ssl_recv;
    sock->handshake = ssl_handshake;
    sock->close = ssl_close;
    init_addr(sock, log);
    
    ctrl_log_print(log, CTRL_LOG_DEBUG, "ssl_init_socket %d success...", sock->fd);

    return SOCKET_ERR_NONE;
}

void ssl_fini_socket(ctrl_socket_t *sock, const ctrl_log_t *log)
{
    if (sock == NULL)
        return;
    
    if(sock->ssl)
    {
        SSL_shutdown(sock->ssl);
        SSL_free(sock->ssl);
        sock->ssl = NULL;
    }

    sock->close(sock, log);
    ctrl_log_print(log, CTRL_LOG_DEBUG, "ssl_fini_socket %d success...", sock->fd);
}

static int ssl_send(const ctrl_socket_t *sock, const char *data, uint32_t len, const ctrl_log_t *log)
{
    if (sock == NULL || data == NULL)
        return SOCKET_ERR_FAIL;
    
    int n = 0;
    int ret = SOCKET_ERR_FAIL;

    for (;;)
    {
        /* should do a select for the write */
        ret = SSL_write(sock->ssl, data + n, len);
        switch (SSL_get_error(sock->ssl, ret))
        {
        case SSL_ERROR_NONE:
            break;
            
        case SSL_ERROR_WANT_WRITE:
        case SSL_ERROR_WANT_READ:
        case SSL_ERROR_WANT_X509_LOOKUP:
            ctrl_log_print(log, CTRL_LOG_DEBUG, "SSL_write %d BLOCK\n", sock->fd);
            return SOCKET_ERR_BLOCK;
            
        case SSL_ERROR_SYSCALL:
        case SSL_ERROR_SSL:
            ctrl_log_print(log, CTRL_LOG_INFO, "SSL_write %d ERROR, %s\n", sock->fd, ERR_error_string(ERR_get_error(), NULL));
            return SOCKET_ERR_FAIL;
            
        case SSL_ERROR_ZERO_RETURN:
            ctrl_log_print(log, CTRL_LOG_INFO, "SSL_write %d return zore, socket close\n", sock->fd);
            return SOCKET_ERR_CLOSE;
            
        default:
            ctrl_log_print(log, CTRL_LOG_INFO, "SSL_write %d unkonw error, msg: %s\n", sock->fd, ERR_error_string(ERR_get_error(), NULL));
            return SOCKET_ERR_FAIL;
        }
        
        if (ret > 0)
        {
            n += ret;
            len -= ret;
        }
        if (len <= 0)
            break;
    }

    return n;
}

static int ssl_recv(const ctrl_socket_t *sock, char *data, uint32_t len, const ctrl_log_t *log)
{
    if (sock == NULL || data == NULL)
        return SOCKET_ERR_FAIL;
    
    int ret = SOCKET_ERR_FAIL;
    uint32_t nread = 0;
    uint32_t nleft = len;

    /* SSL handshake has completed? */
    if (!SSL_is_init_finished(sock->ssl))
    {
        char* buffer[1024];
        if ((ret = SSL_read(sock->ssl, buffer, sizeof(buffer))) <= 0)
        {
            ret = SSL_get_error(sock->ssl, ret);
            if (ret == SSL_ERROR_WANT_WRITE || ret == SSL_ERROR_WANT_READ)
            {
                ctrl_log_print(log, CTRL_LOG_INFO, "SSL_read %s block, %s\n", sock->fd, ERR_error_string(ERR_get_error(), NULL));
                ret = SOCKET_ERR_BLOCK;
            }
            else
            {
                ctrl_log_print(log, CTRL_LOG_INFO, "SSL_read %d failed, %s\n", sock->fd, ERR_error_string(ERR_get_error(), NULL));
                return SOCKET_ERR_FAIL;
            }
        }
        else
        {
            ret = SOCKET_ERR_NONE;
        }
        return ret;
    }

    while (nleft > 0)
    {
        if (nread + nleft > len)
        {
            ctrl_log_print(log, CTRL_LOG_INFO, "SSL_read %d Warnning too many data to read, bufsize: %d, to readsize: %d\n",
                sock->fd, len, nread + nleft);
            break;
        }

        ret = SSL_read(sock->ssl, (((uint8_t*)data) + nread), nleft);
        switch (SSL_get_error(sock->ssl, ret))
        {
        case SSL_ERROR_NONE:
            break;
            
        case SSL_ERROR_WANT_WRITE:
        case SSL_ERROR_WANT_READ:
        case SSL_ERROR_WANT_X509_LOOKUP:
            ctrl_log_print(log, CTRL_LOG_DEBUG, "SSL_read %d BLOCK.\n", sock->fd);
            return nread;
            
        case SSL_ERROR_SYSCALL:
        case SSL_ERROR_SSL:
            ctrl_log_print(log, CTRL_LOG_INFO, "SSL_read %d ERROR, msg: %s\n", sock->fd, ERR_error_string(ERR_get_error(), NULL));
            return SOCKET_ERR_FAIL;
            
        case SSL_ERROR_ZERO_RETURN:
            ctrl_log_print(log, CTRL_LOG_INFO, "SSL_read %d return zore, socket close\n", sock->fd);
            return SOCKET_ERR_CLOSE;
        default:
            ctrl_log_print(log, CTRL_LOG_INFO, "SSL_read %d unkonw error, msg: %s\n", sock->fd, ERR_error_string(ERR_get_error(), NULL));
            return SOCKET_ERR_FAIL;
        }
        
        nread += (uint32_t)ret;

        if ((ret = SSL_pending(sock->ssl)) > 0)
        {
            nleft = ret;
        }
        else
        {
            nleft = 0;
        }
    }

    return nread;
}

static int ssl_handshake(ctrl_socket_t *sock, const ctrl_log_t *log)
{
    if (sock == NULL)
        return SOCKET_ERR_FAIL;
    
    if (sock->ssl == NULL)
    {
        return SOCKET_ERR_SSL;
    }

    if (sock->type == SOCKET_SSL_CLIENT)
    {
        SSL_set_connect_state(sock->ssl);
    }
    else if (sock->type == SOCKET_SSL_SERVER)
    {
        SSL_set_accept_state(sock->ssl);
    }
    else
    {
        return SOCKET_ERR_SSL;
    }
    
    int ret = SSL_do_handshake(sock->ssl);
    switch (SSL_get_error(sock->ssl, ret))
    {
    case SSL_ERROR_NONE:
        show_certificate(sock, log);
        ctrl_log_print(log, CTRL_LOG_DEBUG, "ssl_handshake %d success...", sock->fd);
        return SOCKET_ERR_NONE;
        
    case SSL_ERROR_WANT_CONNECT:
    case SSL_ERROR_WANT_ACCEPT:
    case SSL_ERROR_WANT_WRITE:
    case SSL_ERROR_WANT_READ:
    case SSL_ERROR_WANT_X509_LOOKUP:
        ctrl_log_print(log, CTRL_LOG_DEBUG, "Socket %d blocking when SSL_do_handshake.\n", sock->fd);
        return SOCKET_ERR_BLOCK;
        
    case SSL_ERROR_ZERO_RETURN:
        ctrl_log_print(log, CTRL_LOG_INFO, "Socket %d was close when SSL_do_handshake.\n", sock->fd);
        return SOCKET_ERR_CLOSE;
        
    case SSL_ERROR_SYSCALL:
    case SSL_ERROR_SSL:
        ctrl_log_print(log, CTRL_LOG_INFO, "SSL_do_handshake  %d failed, msg: %s\n", sock->fd, ERR_error_string(ERR_get_error(), NULL));
        return SOCKET_ERR_SSL;
        
    default:
        ctrl_log_print(log, CTRL_LOG_INFO, "SSL_do_handshake %d unkonw error, msg: %s\n", sock->fd, ERR_error_string(ERR_get_error(), NULL));
        return SOCKET_ERR_FAIL;
    }
    return SOCKET_ERR_FAIL;
}

static void ssl_close(ctrl_socket_t *sock, const ctrl_log_t *log)
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

static void show_certificate(const ctrl_socket_t *sock, const ctrl_log_t *log)
{
    if (sock == NULL || sock->ssl == NULL)
        return;
    
    X509 *cert = SSL_get_peer_certificate(sock->ssl);
    if (cert != NULL)
    {
        ctrl_log_print(log, CTRL_LOG_DEBUG, "%s certificate %d:\n", sock->type == SOCKET_SSL_SERVER ? "local" : "remote", sock->fd);
        
        char *str = X509_NAME_oneline(X509_get_subject_name(cert), 0, 0);
        if (str == NULL)
            return;
        ctrl_log_print(log, CTRL_LOG_DEBUG, "\t subject: %s\n", str);
        OPENSSL_free(str);
        
        str = X509_NAME_oneline(X509_get_issuer_name(cert), 0, 0);
        if (str == NULL)
            return;
        ctrl_log_print(log, CTRL_LOG_DEBUG, "\t issuer: %s\n", str);
        OPENSSL_free(str);
        
        /* We could do all sorts of certificate verification stuff here before
           deallocating the certificate. */
        
        X509_free(cert);
    }
    else
    {
        ctrl_log_print(log, CTRL_LOG_DEBUG, "%s has not certificate %d:\n", sock->type == SOCKET_SSL_SERVER ? "local" : "remote", sock->fd);
    }
}



