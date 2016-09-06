#include <assert.h>
#include <unistd.h>
#include <signal.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <error.h>
#include <errno.h>

#include "ctrl_process.h"
#include "ctrl_conf.h"
#include "sock_base.h"
#include "BugReport.h"

ctrl_process_t worker_processes[MAX_PROCESS_COUNT];
uint32_t    last_worker_process = 0;

pid_t       worker_pid;
uint32_t    worker_slot;

uint32_t    ctrl_process = CTRL_PROCESS_MASTER;
uint32_t    ctrl_worker;
uint32_t    ctrl_exiting;
pid_t       ctrl_new_binary;
pid_t       ctrl_pid;
int         ctrl_channel;

sig_atomic_t    ctrl_reap;
sig_atomic_t    ctrl_sigio;
sig_atomic_t    ctrl_sigalrm;
sig_atomic_t    ctrl_terminate;
sig_atomic_t    ctrl_quit;
sig_atomic_t    ctrl_debug_quit;
sig_atomic_t    ctrl_reconfigure;
sig_atomic_t    ctrl_reopen;
sig_atomic_t    ctrl_noaccept;
sig_atomic_t    ctrl_change_binary;

extern int     ctrl_daemonized;

typedef struct ctrl_signal_s
{
    int         signo;
    const char  *signame;
    const char  *name;
    void        (*handler)(int signo);
}ctrl_signal_t;


static int spawn_process(const controler_t *ctrl, process_func proc, void *data,
    const char *name, int type);
static void worker_process(const controler_t *ctrl, void *data);
static void init_process();
static void process_get_status();
static void worker_process_exit(const controler_t *ctrl);
static void process_event(const controler_t *ctrl);

static int init_channel(int *channel, const char *name, const ctrl_log_t *log);
static void close_channel(int *channel, const char *name, const ctrl_log_t *log);
static void signal_handler(int signo);

ctrl_signal_t signals[] = {
    { SIGHUP, "SIGHUP", "reload", signal_handler },

    { SIGUSR1, "SIGUSE1", "reopen", signal_handler },

    { SIGWINCH, "SIGWINCH", "", signal_handler },

    { SIGTERM, "SIGTERM", "stop", signal_handler },

    { SIGQUIT, "SIGQUIT", "quit", signal_handler },

    { SIGUSR2, "SIGUSR2", "", signal_handler },

    { SIGALRM, "SIGALRM", "", signal_handler },

    { SIGINT, "SIGINT", "", signal_handler },

    { SIGIO, "SIGIO", "", signal_handler },

    { SIGCHLD, "SIGCHLD", "", signal_handler },

    { SIGSYS, "SIGSYS, SIG_IGN", "", SIG_IGN },

    { SIGPIPE, "SIGPIPE, SIG_IGN", "", SIG_IGN },

    { 0, NULL, "", NULL }
};


static void signal_handler(int signo)
{
    const char      *action = "";
    int             ignore = 0;
    int             err = errno;
    ctrl_signal_t   *sig = NULL;

    for (sig = signals; sig->signo != 0; sig++)
    {
        if (sig->signo == signo)
        {
            break;
        }
    }

    switch (ctrl_process)
    {
    case CTRL_PROCESS_MASTER:
    case CTRL_PROCESS_SINGLE:
        switch (signo)
        {
        case SIGQUIT:
            ctrl_quit = 1;
            action = ", shutting down";
            break;

        case SIGTERM:
        case SIGINT:
            ctrl_terminate = 1;
            action = ", exiting";
            break;

        case SIGWINCH:
            if (ctrl_daemonized) {
                ctrl_noaccept = 1;
                action = ", stop accepting connections";
            }
            break;

        case SIGHUP:
            ctrl_reconfigure = 1;
            action = ", reconfiguring";
            break;

        case SIGUSR1:
            ctrl_reopen = 1;
            action = ", reopening logs";
            break;

        case SIGUSR2:
            if (getppid() > 1 || ctrl_new_binary > 0) {

                /*
                 * Ignore the signal in the new binary if its parent is
                 * not the init process, i.e. the old binary's process
                 * is still running.  Or ignore the signal in the old binary's
                 * process if the new binary's process is already running.
                 */

                action = ", ignoring";
                ignore = 1;
                break;
            }

            ctrl_change_binary = 1;
            action = ", changing binary";
            break;

        case SIGALRM:
            ctrl_sigalrm = 1;
            break;

        case SIGIO:
            ctrl_sigio = 1;
            break;

        case SIGCHLD:
            ctrl_reap = 1;
            break;
        }

        break;
    case CTRL_PROCESS_WORKER:
        switch (signo)
        {
        case SIGWINCH:
            if (!ctrl_daemonized) {
                break;
            }
            ctrl_debug_quit = 1;
        case SIGQUIT:
            ctrl_quit = 1;
            action = ", shutting down";
            break;

        case SIGTERM:
        case SIGINT:
            ctrl_terminate = 1;
            action = ", exiting";
            break;

        case SIGUSR1:
            ctrl_reopen = 1;
            action = ", reopening logs";
            break;

        case SIGUSR2:
        case SIGHUP:
        case SIGIO:
            action = ", ignoring";
            break;
        }

        break;
    }

    ctrl_log_print(g_ctrl->log, CTRL_LOG_NOTICE, "signal %d (%s) received%s",
        signo, sig->signame, action);

    if (signo == SIGCHLD)
    {
        process_get_status();
    }
    
    errno = err;
}

static void process_get_status()
{
    int         status;
    const char  *process;
    pid_t       pid;
    int         one = 0;
    uint32_t    i;
    for (;;)
    {
        pid = waitpid(-1, &status, WNOHANG);
        if (pid == 0)
        {
            return;
        }

        if (pid == -1)
        {
            if (errno == EINTR)
            {
                continue;
            }
            else if (errno == ECHILD && one)
            {
                return;
            }
            if (errno == ECHILD)
            {
                ctrl_log_print(g_ctrl->log, CTRL_LOG_INFO, "waitpid() failed. %s", strerror(errno));
                return;
            }
            
            ctrl_log_print(g_ctrl->log, CTRL_LOG_ALERT, "waitpid() failed. %s", strerror(errno));
            return;
        }

        one = 1;
        for (i = 0; i < last_worker_process; i++)
        {
            if (worker_processes[i].pid == pid)
            {
                worker_processes[i].status = status;
                worker_processes[i].exited = 1;
                process = worker_processes[i].name;
                break;
            }
        }

        if (WTERMSIG(status))
        {
            ctrl_log_print(g_ctrl->log, CTRL_LOG_ALERT, "%s %P exited on signal %d",
                process, pid, WTERMSIG(status));
        }
        else
        {
            ctrl_log_print(g_ctrl->log, CTRL_LOG_ALERT, "%s %P exited with code %d",
                process, pid, WEXITSTATUS(status));
        }
    }
}

int init_signals(const ctrl_log_t *log)
{
    ctrl_signal_t      *sig;
    struct sigaction   sa;
    
    for (sig = signals; sig->signo != 0; sig++)
    {
        bzero(&sa, sizeof(struct sigaction));
        sa.sa_handler = sig->handler;
        sigemptyset(&sa.sa_mask);
        if (sigaction(sig->signo, &sa, NULL) == -1)
        {
            ctrl_log_print(log, CTRL_LOG_ALERT, "sigaction(%s) failed", sig->signame);
        }
    }
    return CTRL_OK;
}


static void init_process()
{
    int i;
    for (i = 0; i < MAX_PROCESS_COUNT; i++)
    {
        worker_processes[i].pid = -1;
        worker_processes[i].status = 0;
        worker_processes[i].channel[0] = -1;
        worker_processes[i].channel[1] = -1;
        worker_processes[i].proc = NULL;
        worker_processes[i].data = NULL;
        worker_processes[i].name = NULL;
    }
}

void start_worker_processes(const controler_t *ctrl, int type)
{
    init_process();
    int i = 0;
    const ctrl_conf_t *conf = ctrl->conf;
    for (; i < conf->worker; i++)
    {
        spawn_process(ctrl, worker_process, (void *)&i, "worker process", type);
    }
}

static int spawn_process(const controler_t *ctrl, process_func proc, void *data,
    const char *name, int type)
{
    assert(ctrl && data && name);
    
    uint32_t slot;
    for (slot = 0; slot < last_worker_process; slot++)
    {
        if (worker_processes[slot].pid == -1)
            break;
    }

    if (init_channel(worker_processes[slot].channel, name, ctrl->log) != CTRL_OK)
    {
        ctrl_log_print(ctrl->log, CTRL_LOG_ERROR, "%s init_channel() failed", name);
        return CTRL_ERROR;
    }
    
    ctrl_channel = worker_processes[slot].channel[1];
    worker_slot = slot;
    
    int pid = fork();
    if (pid == 0)
    {
        ctrl_pid = getpid();
        char str_pid[16] = {0};
        snprintf(str_pid, sizeof(str_pid), "controler_%d", ctrl_pid);
        BugReportRegister(str_pid, "./", NULL, NULL);
        proc(ctrl, data);
    }
    else if (pid == -1)
    {
        close_channel(worker_processes[slot].channel, name, ctrl->log);
        ctrl_log_print(ctrl->log, CTRL_LOG_ERROR, "%s fork() failed", name, strerror(errno));
        return CTRL_ERROR;
    }

    worker_processes[slot].pid = pid;
    worker_processes[slot].proc = proc;
    worker_processes[slot].name = name;
    worker_processes[slot].data = data;

    if (last_worker_process == slot)
        last_worker_process++;
    
    return pid;
}

static void worker_process(const controler_t *ctrl, void *data)
{
    ctrl_process = CTRL_PROCESS_WORKER;
    ctrl_log_print(ctrl->log, CTRL_LOG_INFO, "worker process pid %d", ctrl_pid);

    for (;;)
    {
        if (ctrl_exiting)
        {
            worker_process_exit(ctrl);
        }

        process_event(ctrl);
    }
}

static void worker_process_exit(const controler_t *ctrl)
{
    if (ctrl_exiting)
    {
    }
    
    exit(0);
}

static void process_event(const controler_t *ctrl)
{
    
}


static int init_channel(int *channel, const char *name, const ctrl_log_t *log)
{
    assert(channel && name);
    
    if (socketpair(AF_UNIX, SOCK_STREAM, 0, channel) == -1)
    {
        ctrl_log_print(log, CTRL_LOG_ERROR, "%s socketpair() failed", name);
        return CTRL_ERROR;
    }

    ctrl_log_print(log, CTRL_LOG_DEBUG, "%s channel %d:%d", name, channel[0], channel[1]);

    if (set_nonblocking(channel[0], 1, log) != SOCKET_ERR_NONE)
    {
        ctrl_log_print(log, CTRL_LOG_ERROR, "%s channel %d set nonblocking failed.", name, channel[0]);
        return CTRL_ERROR;
    }
    if (set_nonblocking(channel[1], 1, log) != SOCKET_ERR_NONE)
    {
        ctrl_log_print(log, CTRL_LOG_ERROR, "%s channel %d set nonblocking failed.", name, channel[1]);
        return CTRL_ERROR;
    }
    
    return CTRL_OK;
}

static void close_channel(int *channel, const char *name, const ctrl_log_t *log)
{
    if (close(channel[0]) == -1)
        ctrl_log_print(log, CTRL_LOG_ERROR, "%s close channel %d failed.", name, channel[0]);
    
    if (close(channel[1]) == -1)
        ctrl_log_print(log, CTRL_LOG_ERROR, "%s close channel %d failed.", name, channel[1]);
}

void dispacth_process_singal(const controler_t *ctrl)
{
}

void dispacth_process_master(const controler_t *ctrl)
{
    sigset_t           set;
    sigemptyset(&set);
    sigaddset(&set, SIGCHLD);
    sigaddset(&set, SIGALRM);
    sigaddset(&set, SIGIO);
    sigaddset(&set, SIGINT);
    sigaddset(&set, SIGHUP);
    sigaddset(&set, SIGWINCH);
    sigaddset(&set, SIGTERM);
    sigaddset(&set, SIGQUIT);
    sigaddset(&set, SIGUSR1);

    if (sigprocmask(SIG_BLOCK, &set, NULL) == -1)
    {
        ctrl_log_print(ctrl->log, CTRL_LOG_ERROR, "sigprocmask() failed. %s", strerror(errno));
    }

    sigemptyset(&set);

    ctrl_new_binary = 0;

    start_worker_processes(ctrl, 0);
    
    for (;;)
    {
        sigsuspend(&set);

        if (ctrl_terminate)
        {
            exit(0);
        }

        if (ctrl_quit)
        {
            exit(0);
        }
        
    }
}

