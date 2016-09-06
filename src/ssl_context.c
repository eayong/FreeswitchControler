#include "ssl_context.h"

static int init_client_ctx(ssl_context_t * ssl_ctx, const ctrl_log_t *log);
static int init_server_ctx(ssl_context_t * ssl_ctx, const ctrl_log_t *log,
    const char *cert_file, const char *key_file);


int init_ssl_context(ssl_context_t * ssl_ctx, int protocols, const ctrl_log_t *log,
    const char *cert_file, const char *key_file)
{
#if OPENSSL_VERSION_NUMBER >= 0x10100003L

    OPENSSL_init_ssl(OPENSSL_INIT_LOAD_CONFIG, NULL);

#else


    SSL_library_init();
    SSL_load_error_strings();

    OpenSSL_add_all_algorithms();

#endif

#if OPENSSL_VERSION_NUMBER >= 0x0090800fL
#ifndef SSL_OP_NO_COMPRESSION
    {
    /*
     * Disable gzip compression in OpenSSL prior to 1.0.0 version,
     * this saves about 522K per connection.
     */
    int                  n;
    STACK_OF(SSL_COMP)  *ssl_comp_methods;

    ssl_comp_methods = SSL_COMP_get_compression_methods();
    n = sk_SSL_COMP_num(ssl_comp_methods);

    while (n--) {
        (void) sk_SSL_COMP_pop(ssl_comp_methods);
    }
    }
#endif
#endif
    ssl_ctx->protocols = protocols;

    if (init_client_ctx(ssl_ctx, log) < 0)
    {
        ctrl_log_print(log, CTRL_LOG_ERROR, "init_client_ctx error.");
        return -1;
    }

    if (init_server_ctx(ssl_ctx, log, cert_file, key_file) < 0)
    {
        ctrl_log_print(log, CTRL_LOG_ERROR, "init_server_ctx error.");
        return -1;
    }
    
    ctrl_log_print(log, CTRL_LOG_DEBUG, "init_ssl_context success...");
    return 0;
}

void fini_ssl_context(ssl_context_t * ssl_ctx, const ctrl_log_t *log)
{
    if (ssl_ctx->cli_ctx != NULL)
    {
        SSL_CTX_free(ssl_ctx->cli_ctx);
        ssl_ctx->cli_ctx = NULL;
    }
    
    if (ssl_ctx->serv_ctx != NULL)
    {
        SSL_CTX_free(ssl_ctx->serv_ctx);
        ssl_ctx->serv_ctx = NULL;
    }
    ctrl_log_print(log, CTRL_LOG_DEBUG, "fini_ssl_context success...");
}


static int init_client_ctx(ssl_context_t * ssl_ctx, const ctrl_log_t *log)
{
    if (ssl_ctx == NULL)
    {
        return -1;
    }
    ssl_ctx->cli_ctx = SSL_CTX_new(SSLv23_method());
    if (ssl_ctx->cli_ctx == NULL)
    {
        ctrl_log_print(log, CTRL_LOG_ERROR, "init_client_ctx SSL_CTX_new(SSLv23_method()) failed. %s",
            ERR_error_string(ERR_get_error(), NULL));
        return -1;
    }

    if (!(ssl_ctx->protocols & CTRL_SSL_SSLv2)) {
        SSL_CTX_set_options(ssl_ctx->cli_ctx, SSL_OP_NO_SSLv2);
    }
    if (!(ssl_ctx->protocols & CTRL_SSL_SSLv3)) {
        SSL_CTX_set_options(ssl_ctx->cli_ctx, SSL_OP_NO_SSLv3);
    }
    if (!(ssl_ctx->protocols & CTRL_SSL_TLSv1)) {
        SSL_CTX_set_options(ssl_ctx->cli_ctx, SSL_OP_NO_TLSv1);
    }
#ifdef SSL_OP_NO_TLSv1_1
    SSL_CTX_clear_options(ssl_ctx->cli_ctx, SSL_OP_NO_TLSv1_1);
    if (!(ssl_ctx->protocols & CTRL_SSL_TLSv1_1)) {
        SSL_CTX_set_options(ssl_ctx->cli_ctx, SSL_OP_NO_TLSv1_1);
    }
#endif
#ifdef SSL_OP_NO_TLSv1_2
    SSL_CTX_clear_options(ssl_ctx->cli_ctx, SSL_OP_NO_TLSv1_2);
    if (!(ssl_ctx->protocols & CTRL_SSL_TLSv1_2)) {
        SSL_CTX_set_options(ssl_ctx->cli_ctx, SSL_OP_NO_TLSv1_2);
    }
#endif

    return 0;
}

static int init_server_ctx(ssl_context_t * ssl_ctx, const ctrl_log_t *log,
    const char *cert_file, const char *key_file)
{
    if (ssl_ctx == NULL || cert_file == NULL || key_file == NULL)
    {
        fprintf(stderr, "InitServer param error.");
        return -1;
    }
    
    ssl_ctx->serv_ctx = SSL_CTX_new(SSLv23_method());
    if (ssl_ctx->serv_ctx == NULL)
    {
        ctrl_log_print(log, CTRL_LOG_ERROR, "init_server_ctx SSL_CTX_new(SSLv23_method()) failed. %s",
            ERR_error_string(ERR_get_error(), NULL));
        return -1;
    }

    if (!(ssl_ctx->protocols & CTRL_SSL_SSLv2)) {
        SSL_CTX_set_options(ssl_ctx->serv_ctx, SSL_OP_NO_SSLv2);
    }
    if (!(ssl_ctx->protocols & CTRL_SSL_SSLv3)) {
        SSL_CTX_set_options(ssl_ctx->serv_ctx, SSL_OP_NO_SSLv3);
    }
    if (!(ssl_ctx->protocols & CTRL_SSL_TLSv1)) {
        SSL_CTX_set_options(ssl_ctx->serv_ctx, SSL_OP_NO_TLSv1);
    }
#ifdef SSL_OP_NO_TLSv1_1
    SSL_CTX_clear_options(ssl_ctx->serv_ctx, SSL_OP_NO_TLSv1_1);
    if (!(ssl_ctx->protocols & CTRL_SSL_TLSv1_1)) {
        SSL_CTX_set_options(ssl_ctx->serv_ctx, SSL_OP_NO_TLSv1_1);
    }
#endif
#ifdef SSL_OP_NO_TLSv1_2
    SSL_CTX_clear_options(ssl_ctx->serv_ctx, SSL_OP_NO_TLSv1_2);
    if (!(ssl_ctx->protocols & CTRL_SSL_TLSv1_2)) {
        SSL_CTX_set_options(ssl_ctx->serv_ctx, SSL_OP_NO_TLSv1_2);
    }
#endif
    
    if (SSL_CTX_use_certificate_file(ssl_ctx->serv_ctx, cert_file,  SSL_FILETYPE_PEM) <= 0)
    {
        ctrl_log_print(log, CTRL_LOG_ERROR, "SSL_CTX_use_certificate_file %s error. %s", cert_file, ERR_error_string(ERR_get_error(), NULL));
        return -1;
    }
    
    if (SSL_CTX_use_PrivateKey_file(ssl_ctx->serv_ctx, key_file, SSL_FILETYPE_PEM) <= 0)
    {
        ctrl_log_print(log, CTRL_LOG_ERROR, "SSL_CTX_use_PrivateKey_file %s error. %s", key_file, ERR_error_string(ERR_get_error(), NULL));
        return -1;
    }

    if (!SSL_CTX_check_private_key(ssl_ctx->serv_ctx))
    {
        ctrl_log_print(log, CTRL_LOG_ERROR, "Private key does not match the certificate public key");
        return -1;
    }

    return 0;
}


