#include <sys/epoll.h>
#include <errno.h>
#include <string.h>

#include "ctrl_event.h"
#include "controler.h"

static int                  ep = -1;
static struct epoll_event   *event_list = NULL;
static int                  nevents = 0;


static int ctrl_epoll_init(controler_t *ctrl, int msec);
static int ctrl_epoll_fini(controler_t *ctrl);
static int ctrl_epoll_add_event(ctrl_event_t *ev, int event, uint32_t flags);
static int ctrl_epoll_del_event(ctrl_event_t *ev, int event, uint32_t flags);
static int ctrl_epoll_add_connection(ctrl_connection_t *conn);
static int ctrl_epoll_del_connection(ctrl_connection_t *conn, uint32_t flags);
static int ctrl_epoll_process_events(controler_t *ctrl, int msec);

event_actions_t ctrl_event_actions = {
    .init = ctrl_epoll_init,
    .fini = ctrl_epoll_fini,
    .add = ctrl_epoll_add_event,
    .del = ctrl_epoll_del_event,
    .add_conn = ctrl_epoll_add_connection,
    .del_conn = ctrl_epoll_del_connection,
    .process = ctrl_epoll_process_events
};


static int ctrl_epoll_init(controler_t *ctrl, int msec)
{
    if (ep == -1)
    {
        ep = epoll_create(ctrl->conf->connects / 2);
        if (ep == -1)
        {
            ctrl_log_print(ctrl->log, CTRL_LOG_ERROR, "epoll_create() error.");
            return CTRL_ERROR;
        }
    }
    if (nevents < ctrl->conf->events)
    {
        if (event_list)
        {
            free(event_list);
        }

        event_list = calloc(sizeof(ctrl_event_t), ctrl->conf->events);
        if (event_list == NULL)
        {
            ctrl_log_print(ctrl->log, CTRL_LOG_ERROR, "calloc event list error.");
            return CTRL_ERROR;
        }
    }

    nevents = ctrl->conf->events;

    return CTRL_OK;
}

static int ctrl_epoll_fini(controler_t *ctrl)
{
    if (ep > 0 && close(ep) == -1)
    {
        ctrl_log_print(ctrl->log, CTRL_LOG_ERROR, "close epoll error.");
        return CTRL_ERROR;
    }
    ep = -1;

    if (event_list)
        free(event_list);

    event_list = NULL;
    nevents = 0;
    return CTRL_OK;
}


static int ctrl_epoll_add_event(ctrl_event_t *ev, int event, uint32_t flags)
{
    int                 op;
    uint32_t            events, prev;
    struct epoll_event  ee;
    ctrl_event_t        *e;
    ctrl_connection_t   *conn;

    events = (uint32_t) event;
    
    conn = (ctrl_connection_t *) ev->data;
    if (event == CTRL_READ_EVENT)
    {
        e = conn->writeev;
        prev = EPOLLOUT;
        events = EPOLLIN|EPOLLRDHUP;
    }
    else
    {
        e = conn->readev;
        prev = EPOLLIN|EPOLLRDHUP;
        events = EPOLLOUT;
    }

    if (e->active)
    {
        op = EPOLL_CTL_MOD;
        events |= prev;
    }
    else
    {
        op = EPOLL_CTL_ADD;
    }

    ee.events = events | flags;
    ee.data.ptr = (void *) conn;

    ctrl_log_print(ev->log, CTRL_LOG_ERROR, "epoll add event: fd:%d op:%d, ev:%08XD",
        conn->sock.fd, op, ee.events);

    if (epoll_ctl(ep, op, conn->sock.fd, &ee) == -1)
    {
        ctrl_log_print(ev->log, CTRL_LOG_ERROR, "epoll_ctl(op:%d, fd:%d) failed", op, conn->sock.fd);
        return CTRL_ERROR;
    }

    ev->active = 1;
    
    return CTRL_OK;
}

static int ctrl_epoll_del_event(ctrl_event_t *ev, int event, uint32_t flags)
{
    int                  op;
    uint32_t             prev;
    ctrl_event_t         *e;
    ctrl_connection_t    *conn;
    struct epoll_event   ee;

    conn = (ctrl_connection_t *) ev->data;

    if (event == CTRL_READ_EVENT) {
        e = conn->writeev;
        prev = EPOLLOUT;

    } else {
        e = conn->readev;
        prev = EPOLLIN|EPOLLRDHUP;
    }

    if (e->active) {
        op = EPOLL_CTL_MOD;
        ee.events = prev | flags;
        ee.data.ptr = (void *) conn;

    } else {
        op = EPOLL_CTL_DEL;
        ee.events = 0;
        ee.data.ptr = NULL;
    }

    ctrl_log_print(ev->log, CTRL_LOG_ERROR, "epoll del event: fd:%d op:%d, ev:%08XD",
        conn->sock.fd, op, ee.events);

    if (epoll_ctl(ep, op, conn->sock.fd, &ee) == -1)
    {
        ctrl_log_print(ev->log, CTRL_LOG_ERROR, "epoll_ctl(op:%d, fd:%d) failed", op, conn->sock.fd);
        return CTRL_ERROR;
    }

    ev->active = 0;
    
    return CTRL_OK;
}

static int ctrl_epoll_add_connection(ctrl_connection_t *conn)
{
    struct epoll_event  ee;

    ee.events = EPOLLIN|EPOLLOUT|EPOLLET|EPOLLRDHUP;
    ee.data.ptr = (void *) conn;

    
    ctrl_log_print(conn->log, CTRL_LOG_ERROR, "epoll add connection: fd:%d, ev:%08XD",
           conn->sock.fd, ee.events);
    

    if (epoll_ctl(ep, EPOLL_CTL_ADD, conn->sock.fd, &ee) == -1)
    {
        ctrl_log_print(conn->log, CTRL_LOG_ERROR, "epoll_ctl(EPOLL_CTL_ADD, fd:%d) failed", conn->sock.fd);
        return CTRL_ERROR;
    }

    conn->readev->active = 1;
    conn->writeev->active = 1;

    return CTRL_OK;
}


static int ctrl_epoll_del_connection(ctrl_connection_t *conn, uint32_t flags)
{
    struct epoll_event  ee;

    ctrl_log_print(conn->log, CTRL_LOG_ERROR, "epoll del connection: fd:%d, ev:%08XD",
           conn->sock.fd, ee.events);

    ee.events = 0;
    ee.data.ptr = NULL;

    if (epoll_ctl(ep, EPOLL_CTL_DEL, conn->sock.fd, &ee) == -1)
    {
        ctrl_log_print(conn->log, CTRL_LOG_ERROR, "epoll_ctl(EPOLL_CTL_DEL, fd:%d) failed", conn->sock.fd);
        return CTRL_ERROR;
    }

    conn->readev->active = 0;
    conn->writeev->active = 0;

    return CTRL_OK;
}

static int ctrl_epoll_process_events(controler_t *ctrl, int msec)
{
    int                 events, revents;
    int                 i;
    ctrl_connection_t   *conn;
    ctrl_event_t        *rev, *wev;
    
    ctrl_log_print(ctrl->log, CTRL_LOG_DEBUG, "epoll wait timer %d", msec);

    events = epoll_wait(ep, event_list, nevents, msec);

    if (events < 0)
    {
        if (errno == EINTR)
            return CTRL_OK;
        
        ctrl_log_print(ctrl->log, CTRL_LOG_ALERT, "epoll_wait failed. %s", strerror(errno));
        return CTRL_ERROR;
    }
    else if (events == 0)
    {
        if (msec != -1)
        {
            return CTRL_OK;
        }
        ctrl_log_print(ctrl->log, CTRL_LOG_ALERT, "epoll_wait() returned no events without timeout. %s",
            strerror(errno));
        return CTRL_ERROR;
    }

    for (i = 0; i < events; i++)
    {
        conn = (ctrl_connection_t *) event_list[i].data.ptr;
        revents = event_list[i].events;
        rev = conn->readev;
        wev = conn->writeev;

        if (revents & (EPOLLERR|EPOLLHUP))
        {
            ctrl_log_print(ctrl->log, CTRL_LOG_ALERT, "epoll_wait() error on fd:%d ev:%04XD",
                conn->sock.fd, revents);
            ctrl_free_connection(conn);
            return CTRL_ERROR;
        }
        
        if (revents & EPOLLIN && rev->active)
        {
            rev->type = CTRL_READ_EVENT;
            rev->handler(rev);
        }
        
        if (revents & EPOLLOUT && wev->active)
        {
            wev->type = CTRL_WRITE_EVENT;
            wev->handler(rev);
        }
    }
    
    return CTRL_OK;
}

