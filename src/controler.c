#include <stdlib.h>

#include "controler.h"


controler_t *g_ctrl = NULL;


int init_controler(controler_t *ctrl, const ctrl_conf_t *conf, ctrl_log_t *log)
{
    if (ctrl == NULL || conf == NULL)
    {
        return CTRL_ERROR;
    }
    
    int i;
    ctrl_connection_t *conn, *next = NULL;
    ctrl->conf = conf;
    ctrl->log = log;

    ctrl->connections = calloc(sizeof(ctrl_connection_t), conf->connects);
    if (ctrl->connections == NULL)
    {
        ctrl_log_print(log, CTRL_LOG_ERROR, "calloc connections error.");
        return CTRL_ERROR;
    }
    ctrl->readev = calloc(sizeof(ctrl_event_t), conf->connects);
    if (ctrl->readev == NULL)
    {
        ctrl_log_print(log, CTRL_LOG_ERROR, "calloc read event error.");
        return CTRL_ERROR;
    }
    ctrl->writeev = calloc(sizeof(ctrl_event_t), conf->connects);
    if (ctrl->writeev == NULL)
    {
        ctrl_log_print(log, CTRL_LOG_ERROR, "calloc write event error.");
        return CTRL_ERROR;
    }
    
    conn = ctrl->connections;
    for (i = conf->connects; i >= 0; i--)
    {
        conn[i].next = next;
        conn[i].readev = &ctrl->readev[i];
        conn[i].writeev = &ctrl->writeev[i];
        conn[i].index = i;
        conn[i].log = ctrl->log;
        reset_ctrl_socket(&conn[i].sock);
        next = &conn[i];
    }
    
    ctrl->free_conn = next;
    ctrl->nfree_conn = conf->connects;
    
    g_ctrl = ctrl;
    
    if (init_accept_event(ctrl) != CTRL_OK)
    {
        ctrl_log_print(log, CTRL_LOG_ERROR, "init accept event error.");
        return CTRL_ERROR;
    }
    
    return CTRL_OK;
}

void fini_controler(controler_t *ctrl)
{
    if (ctrl == NULL)
        return;

    int i;
    
    if (ctrl->ep_fd > 0)
    {
        close(ctrl->ep_fd);
        ctrl->ep_fd = -1;
    }

    if (ctrl->ctrl_listen.sock.status != SOCKET_INVALID)
    {
        fini_server_socket(&ctrl->ctrl_listen, ctrl->log);
    }

    if (ctrl->connections)
    {
        for (i = 0; i < ctrl->conf->connects; i++)
        {
            ctrl->connections[i].sock.close(&ctrl->connections[i].sock, ctrl->log);
        }
        free(ctrl->connections);
        ctrl->connections = NULL;
    }

    if (ctrl->writeev)
    {
        free(ctrl->writeev);
        ctrl->writeev = NULL;
    }
    
    if (ctrl->readev)
    {
        free(ctrl->readev);
        ctrl->readev = NULL;
    }
}


