#include "ctrl_connect.h"
#include "controler.h"

ctrl_connection_t *ctrl_get_connection(const ctrl_socket_t *sock, const ctrl_log_t *log)
{
    ctrl_event_t        *rev, *wev;
    ctrl_connection_t   *conn;

    conn = g_ctrl->free_conn;
    if (conn == NULL)
    {
        return NULL;
    }

    g_ctrl->free_conn = conn->next;
    g_ctrl->nfree_conn--;

    rev = conn->readev;
    wev = conn->writeev;


    memset(rev, 0, sizeof(ctrl_event_t));
    memset(wev, 0, sizeof(ctrl_event_t));
    memset(conn, 0, sizeof(ctrl_connection_t));
    
    conn->readev = rev;
    conn->writeev = wev;

    rev->data = conn;
    wev->data = conn;

    memcpy(&conn->sock, sock, sizeof(ctrl_socket_t));
    
    return conn;
}

void ctrl_free_connection(ctrl_connection_t *conn)
{
    conn->sock.close(&conn->sock, g_ctrl->log);
    reset_ctrl_socket(&conn->sock);
    conn->next = g_ctrl->free_conn;
    g_ctrl->free_conn = conn;
    g_ctrl->nfree_conn++;
}

