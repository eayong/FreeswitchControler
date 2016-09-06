#ifndef __CTRL_EVENT_H__
#define __CTRL_EVENT_H__

#include <inttypes.h>

#include "ctrl_def.h"

#ifdef HAS_EPOLL_EVENT
#include <sys/epoll.h>
#define CTRL_READ_EVENT     EPOLLIN
#define CTRL_WRITE_EVENT    EPOLLOUT
#endif

struct ctrl_event_s
{
    int                 active;
    int                 events;
    int                 type;
    void                *data;
    const ctrl_log_t    *log;
    
    int (*handler) (ctrl_event_t *event);
};

struct event_actions_s
{
    int (*add) (ctrl_event_t *ev, int event, uint32_t flags);
    int (*del) (ctrl_event_t *ev, int event, uint32_t flags);
    int (*add_conn) (ctrl_connection_t *conn);
    int (*del_conn) (ctrl_connection_t *conn, uint32_t flags);
    int (*process) (controler_t *ctrl, int msec);
    int (*init) (controler_t *ctrl, int msec);
    int (*fini) (controler_t *ctrl);
};

extern event_actions_t ctrl_event_actions;

#define ctrl_add_event      ctrl_event_actions.add
#define ctrl_del_event      ctrl_event_actions.del
#define ctrl_add_connection ctrl_event_actions.add_conn
#define ctrl_del_connection ctrl_event_actions.del_conn
#define ctrl_process_events ctrl_event_actions.process
#define ctrl_init_event     ctrl_event_actions.init
#define ctrl_fini_event     ctrl_event_actions.fini

int init_accept_event(controler_t *ctrl);


#endif /* __CTRL_EVENT_H__ */

