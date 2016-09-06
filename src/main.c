#include <getopt.h>
#include <stdio.h>

#include "units.h"
#include "BugReport.h"
#include "ctrl_conf.h"
#include "controler.h"
#include "ctrl_process.h"


int         ctrl_daemonized     = 0;
int         listen_port         = -1;
const char  *ctrl_conf_file     = NULL;

static void usage()
{
    printf("usage:\n");
    printf("\t-h --hellp    : show help\n");
    printf("\t-p --port     : server listen port.\n");
    printf("\t-c --conf     : server listen port.\n");
    printf("\t-d --daemon   : run as daemon.\n");
}

static void set_option(int argc, char **argv)
{
    const char* short_options = "p:c:hd";
    struct option long_options[] = {
        { "port",   1,  NULL,   'p' },
        { "conf",   1,  NULL,   'c' },
        { "daemon", 0,  NULL,   'd' },
        { "single", 0,  NULL,   's' },
        { "help",   0,  NULL,   'h' },
        { 0, 0, 0, 0},
    };
    
    int c;
    while((c = getopt_long(argc, argv, short_options, long_options, NULL)) != -1)
    {
        switch (c)
        {
        case 'p':
            listen_port = strtoul(optarg, NULL, 0);
            if (listen_port < 0)
            {
                printf("listen port %d invalid.\n", listen_port);
                return;
            }
            break;
        case 'c':
            ctrl_conf_file = optarg;
            break;
        case 'd':
            ctrl_daemonized = 1;
            break;
        case 's':
            ctrl_process = CTRL_PROCESS_SINGLE;
            break;
        case 'h':
            usage();
            exit(0);
        default:
            printf("unkown type %c\n", c);
            usage();
            exit(1);
        }
    }
}



int main(int argc, char **argv)
{
    controler_t ctrl;
    ctrl_conf_t conf;
    ctrl_log_t *log = NULL, init_log;

    set_option(argc, argv);

    if (ctrl_daemonized && init_daemon() < 0)
    {
        perror("init_deamon failed.\n");
        return -1;
    }

    BugReportRegister(argv[0], "./", NULL, NULL);


    if (init_ctrl_conf(&conf, ctrl_conf_file) != 0)
    {
        perror("init_ctrl_conf failed.\n");
        return -1;
    }

    /* begin replace config with command */
    if (listen_port != -1)
        conf.ctrl_listen = listen_port;
    
    conf.process = ctrl_process;
    /* end replace config with command */
    
    log = init_ctrl_log(&init_log, &conf);
    
    init_signals(log);
    
#ifdef HAS_OPENSSL
    ssl_context_t ssl_ctx;
    if (conf.use_ssl)
    {
        if (init_ssl_context(&ssl_ctx, conf.protocols, log, conf.cert_file, conf.key_file) == 0)
        {
            ctrl.ssl_ctx = &ssl_ctx;
        }
        else
        {
            ctrl_log_print(log, CTRL_LOG_ERROR, "init_ssl_context error.");
            return -1;
        }
    }
    else
    {
        ctrl.ssl_ctx = NULL;
    }
#endif

    if (init_controler(&ctrl, &conf, log) != 0)
    {
        perror("init_controler failed.\n");
        return -1;
    }

    if (ctrl_process == CTRL_PROCESS_SINGLE)
    {
        dispacth_process_singal(&ctrl);
    }
    else
    {
        dispacth_process_master(&ctrl);
    }

    /* finish controler resource */
    fini_controler(&ctrl);
    
#ifdef HAS_OPENSSL
    fini_ssl_context(&ssl_ctx, log);
#endif

    fini_ctrl_conf(&conf);
    fini_ctrl_log(log);
    
    return 0;
}

