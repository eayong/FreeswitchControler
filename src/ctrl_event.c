#include "ctrl_event.h"
#include "ctrl_connect.h"
#include "controler.h"

int init_accept_event(controler_t *ctrl)
{
    ctrl_connection_t *conn;
    int ret;
    
    if (ctrl_init_event(ctrl, ctrl->conf->timer) == CTRL_ERROR)
    {
        return CTRL_ERROR;
    }
    
#ifdef HAS_OPENSSL
    ret = init_server_socket(&ctrl->listen, ctrl->conf->listen, ctrl->log, ctrl->ssl_ctx->serv_ctx);
#else
    ret = init_server_socket(&ctrl->listen, ctrl->conf->listen, ctrl->log);
#endif
    if (ret != SOCKET_ERR_NONE)
    {
        ctrl_log_print(ctrl->log, CTRL_LOG_ERROR, "init_server_socket error.");
        return CTRL_ERROR;
    }

    conn = ctrl_get_connection(&ctrl->listen.sock, ctrl->log);

    if (conn == NULL)
    {
        fini_server_socket(&ctrl->listen, ctrl->log);
        return CTRL_ERROR;
    }

    if (ctrl_add_connection(conn) == CTRL_ERROR)
    {
        fini_server_socket(&ctrl->listen, ctrl->log);
        ctrl_free_connection(conn);
        return CTRL_ERROR;
    }
    
    return CTRL_OK;
}

void ctrl_event_handler(ctrl_event_t *event)
{
    ctrl_connection_t   *conn = (ctrl_connection_t*) event->data;
    ctrl_socket_t       *sock = &conn->sock;

    if (sock->fd == g_ctrl->listen.sock.fd)
    {
        
    }
    if (event->type == CTRL_READ_EVENT)
    {
    }
    else
    {
        
    }
}

