#ifndef __CTRL_DEFINE_H__
#define __CTRL_DEFINE_H__


#define CTRL_PROCESS_SINGLE 1
#define CTRL_PROCESS_MASTER 2
#define CTRL_PROCESS_WORKER 3

#define MAX_PROCESS_COUNT 128

#define CTRL_OK     0
#define CTRL_ERROR  -1

typedef struct controler_s          controler_t;
typedef struct ctrl_log_s           ctrl_log_t;
typedef struct ctrl_conf_s          ctrl_conf_t;
typedef struct ctrl_event_s         ctrl_event_t;
typedef struct event_actions_s      event_actions_t;
typedef struct ctrl_connection_s    ctrl_connection_t;
typedef struct ssl_context_s        ssl_context_t;
typedef struct ctrl_socket_s        ctrl_socket_t;
typedef struct client_socket_s      client_socket_t;
typedef struct server_socket_s      server_socket_t;


extern controler_t *g_ctrl;

#endif /* __CTRL_DEFINE_H__ */

