#ifndef __PROXY_SSL_CONTEXT_H__
#define __PROXY_SSL_CONTEXT_H__

#include <openssl/crypto.h>
#include <openssl/x509.h>
#include <openssl/pem.h>
#include <openssl/ssl.h>
#include <openssl/err.h>

#define CTRL_SSL_SSLv2    0x0002
#define CTRL_SSL_SSLv3    0x0004
#define CTRL_SSL_TLSv1    0x0008
#define CTRL_SSL_TLSv1_1  0x0010
#define CTRL_SSL_TLSv1_2  0x0020

#include "ctrl_def.h"
#include "ctrl_log.h"

struct ssl_context_s
{
    SSL_CTX     *cli_ctx;
    SSL_CTX     *serv_ctx;
    int         protocols;
};

int init_ssl_context(ssl_context_t *ssl_ctx, int protocols, const ctrl_log_t *log,
    const char *cert_file, const char *key_file);

void fini_ssl_context(ssl_context_t *ssl_ctx, const ctrl_log_t *log);

#endif // __PROXY_SSL_CONTEXT_H__
