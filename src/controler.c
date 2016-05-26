#include "controler.h"


volatile controler_t *g_ctrl = NULL;


int init_controler(controler_t *ctrl, const ctrl_conf_t *conf, ctrl_log_t *log)
{
    if (ctrl == NULL || conf == NULL)
    {
        return CTRL_ERROR;
    }
    ctrl->conf = conf;
    ctrl->log = log;
    
    ctrl->ep_fd = epoll_create(conf->epoll_size);
    if (ctrl->ep_fd < 0)
    {
        ctrl_log_print(log, CTRL_LOG_ERROR, "epoll_create error. %s\n", strerror(errno));
        return CTRL_ERROR;
    }
    
    int ret = 0;
#ifdef HAS_OPENSSL
    ret = init_server_socket(&ctrl->listen.sock, conf->listen, log, ctrl->ssl_ctx->serv_ctx);
#else
    ret = init_server_socket(&ctrl->listen.sock, conf->listen, log);
#endif
    if (ret != SOCKET_ERR_NONE)
    {
        ctrl_log_print(log, CTRL_LOG_ERROR, "init_server_socket error.");
        return CTRL_ERROR;
    }
    struct epoll_event *rev = &ctrl->listen.rev;
    
    epoll_ctl(ctrl->ep_fd, EPOLL_CTL_ADD, ctrl->listen.sock.fd, rev);
    g_ctrl = ctrl;
    return CTRL_OK;
}

