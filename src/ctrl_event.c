#include "ctrl_event.h"
#include "ctrl_connect.h"
#include "controler.h"

int ctrl_event_handler(ctrl_event_t *event);
int ctrl_accept_handler(ctrl_event_t *event);
int ctrl_handshake_handler(ctrl_event_t *event);


int init_accept_event(controler_t *ctrl)
{
    ctrl_connection_t *conn;
    int ret;
    
    if (ctrl_init_event(ctrl, ctrl->conf->timer) == CTRL_ERROR)
    {
        return CTRL_ERROR;
    }

    ret = init_tcp_server(&ctrl->ctrl_listen, ctrl->conf->ctrl_listen, ctrl->log);

    if (ret != SOCKET_ERR_NONE)
    {
        ctrl_log_print(ctrl->log, CTRL_LOG_ERROR, "init_server_socket error.");
        return CTRL_ERROR;
    }

    conn = ctrl_get_connection(&ctrl->ctrl_listen.sock, ctrl->log);

    if (conn == NULL)
    {
        fini_server_socket(&ctrl->ctrl_listen, ctrl->log);
        return CTRL_ERROR;
    }
    
    conn->readev->handler = ctrl_accept_handler;
    conn->writeev->handler = ctrl_accept_handler;
    if (ctrl_add_connection(conn) == CTRL_ERROR)
    {
        fini_server_socket(&ctrl->ctrl_listen, ctrl->log);
        ctrl_free_connection(conn);
        return CTRL_ERROR;
    }
    
    return CTRL_OK;
}

int ctrl_event_handler(ctrl_event_t *event)
{
    ctrl_connection_t   *conn = (ctrl_connection_t*) event->data;
    ctrl_socket_t       *sock = &conn->sock;
    char buffer[1024] = {0};
    if (event->type == CTRL_READ_EVENT)
    {
        sock->recv(sock, buffer, sizeof(buffer)-1, conn->log);
    }
    else
    {
        
    }
    return CTRL_OK;
}

int ctrl_accept_handler(ctrl_event_t *event)
{
    ctrl_socket_t sock;
    if (accept_socket(&g_ctrl->ctrl_listen, &sock, g_ctrl->log) != SOCKET_ERR_NONE)
    {
        ctrl_log_print(g_ctrl->log, CTRL_LOG_ERROR, "accept socket failed.");
        return CTRL_ERROR;
    }

    sock.status = SOCKET_HANDSHARE;
    set_nonblocking(sock.fd, 1, g_ctrl->log);
    ctrl_connection_t *conn = NULL;
    conn = ctrl_get_connection(&sock, conn->log);
    if (conn == NULL)
    {
        sock.close(&sock, conn->log);
        return CTRL_ERROR;
    }
    return ctrl_handshake_handler(event);
}

int ctrl_handshake_handler(ctrl_event_t *event)
{
    ctrl_connection_t *conn = (ctrl_connection_t *) event->data;
    int ret = conn->sock.handshake(&conn->sock, conn->log);
    switch (ret)
    {
    case SOCKET_ERR_NONE:
        conn->readev->handler = ctrl_event_handler;
        conn->writeev->handler = ctrl_event_handler;
        return CTRL_OK;
        
    case SOCKET_ERR_BLOCK:
        conn->readev->handler = ctrl_handshake_handler;
        conn->writeev->handler = ctrl_handshake_handler;
        if ((ctrl_add_event(conn->readev, CTRL_READ_EVENT, 0) != CTRL_OK) ||
            (ctrl_add_event(conn->writeev, CTRL_WRITE_EVENT, 0) != CTRL_OK))
        {
            break;
        }
        return CTRL_OK;
        
    default:
        break;
    }
    
    conn->sock.close(&conn->sock, conn->log);
    return CTRL_ERROR;
}

int els_accept_handler(ctrl_event_t *event)
{
    ctrl_socket_t sock;
    if (accept_socket(&g_ctrl->ctrl_listen, &sock, g_ctrl->log) != SOCKET_ERR_NONE)
    {
        ctrl_log_print(g_ctrl->log, CTRL_LOG_ERROR, "accept socket failed.");
        return CTRL_ERROR;
    }
    return CTRL_OK;
}

