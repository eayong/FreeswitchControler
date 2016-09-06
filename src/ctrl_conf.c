#include "ctrl_conf.h"
#include "ctrl_log.h"
#include "iniparser.h"
#include "ssl_context.h"

#define DEFAULT_CONFIG_FILE     "/etc/controler.conf"
#define DEFAULT_LOG_FILE        "./controler.log"
#define DEFAULT_CERT_FILE       "./cert.pem"

#define DEFAULT_LISTEN_PORT             8080
#define DEFAULT_WORKER_COUNT            2
#define DEFAUL_MAX_CONNECTION_SIZE      10000
#define DEFAUL_MAX_EVENT_SIZE           512
#define DEFAUL_EVENT_TIMER              1000


int init_ctrl_conf(ctrl_conf_t *conf, const char *conf_file)
{
    if (conf == NULL)
        return CTRL_ERROR;

    const char *file = DEFAULT_CONFIG_FILE;
    if (conf_file != NULL)
    {
        file = conf_file;
    }

    dictionary *ini = iniparser_load(file);
    if (ini == NULL)
    {
        fprintf(stderr, "iniparser_load %s error.\n", file);
        return CTRL_ERROR;
    }
    conf->ctrl_listen = iniparser_getint(ini, "main:listen", DEFAULT_LISTEN_PORT);
    conf->worker = iniparser_getint(ini, "main:worker_count", DEFAULT_WORKER_COUNT);
    conf->connects = iniparser_getint(ini, "main:connects", DEFAUL_MAX_CONNECTION_SIZE);
    conf->events = iniparser_getint(ini, "event:events", DEFAUL_MAX_EVENT_SIZE);
    conf->timer = iniparser_getint(ini, "event:timer", DEFAUL_EVENT_TIMER);
    conf->log_level = iniparser_getint(ini, "log:level", CTRL_LOG_INFO);
    conf->log_file = strdup(iniparser_getstring(ini, "log:log_file", DEFAULT_LOG_FILE));
    
#ifdef HAS_OPENSSL
    conf->use_ssl = iniparser_getboolean(ini, "ssl:use", 0);
    conf->cert_file = strdup(iniparser_getstring(ini, "ssl:cert_file", DEFAULT_CERT_FILE));
    conf->key_file = strdup(iniparser_getstring(ini, "ssl:key_file", DEFAULT_CERT_FILE));
    const char *str_protocols = iniparser_getstring(ini, "ssl:protocols", "tlsv1:tlsv1_1:tlsv1_2");
    conf->protocols = 0;
    if (strstr(str_protocols, "sslv2") != NULL)
        conf->protocols |= CTRL_SSL_SSLv2;
    if (strstr(str_protocols, "sslv3") != NULL)
        conf->protocols |= CTRL_SSL_SSLv3;
    if (strstr(str_protocols, "tlsv1") != NULL)
        conf->protocols |= CTRL_SSL_TLSv1;
    if (strstr(str_protocols, "tlsv1_1") != NULL)
        conf->protocols |= CTRL_SSL_TLSv1_1;
    if (strstr(str_protocols, "tlsv1_2") != NULL)
        conf->protocols |= CTRL_SSL_TLSv1_2;
#endif

    iniparser_freedict(ini);

    
    return CTRL_OK;
}

int fini_ctrl_conf(ctrl_conf_t *conf)
{
    if (conf == NULL)
        return CTRL_ERROR;

    if (conf->log_file != NULL)
    {
        free(conf->log_file);
        conf->log_file = NULL;
    }
#ifdef HAS_OPENSSL
    if (conf->cert_file != NULL)
    {
        free(conf->cert_file);
        conf->cert_file = NULL;
    }
    if (conf->key_file != NULL)
    {
        free(conf->key_file);
        conf->key_file = NULL;
    }
#endif
    return CTRL_OK;
}


