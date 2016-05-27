#ifndef __CTRL_CONNECT_H__
#define __CTRL_CONNECT_H__

#include "ctrl_def.h"
#include "sock_base.h"
#include "ctrl_event.h"
#include "ctrl_log.h"
#include "sock_server.h"

struct ctrl_connection_s
{
    int                 index;
    ctrl_socket_t       sock;
    ctrl_event_t        *readev;
    ctrl_event_t        *writeev;
    const ctrl_log_t    *log;
    void                *next;
};

ctrl_connection_t *ctrl_get_connection(const ctrl_socket_t *sock, const ctrl_log_t *log);

void ctrl_free_connection(ctrl_connection_t *conn);

#endif /* __CTRL_CONNECT_H__ */
