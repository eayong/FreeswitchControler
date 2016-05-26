#ifndef __CTRL_PROCESS_H__
#define __CTRL_PROCESS_H__

#include <inttypes.h>

#include "controler.h"

typedef void (*process_func) (const controler_t *ctrl, void *data);

typedef struct ctrl_process_s
{
    pid_t           pid;
    int             status;
    int             channel[2];

    process_func    proc;
    void            *data;
    const char      *name;
    int             exited;
}ctrl_process_t;


extern uint32_t ctrl_process;

int init_signals(const ctrl_log_t *log);

void start_worker_processes(const controler_t *ctrl, int type);

void dispacth_process_singal(const controler_t *ctrl);

void dispacth_process_master(const controler_t *ctrl);

#endif /* __CTRL_PROCESS_H__ */
