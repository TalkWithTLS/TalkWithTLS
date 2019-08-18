#include "test_openssl_ssl_mode.h"

int ssl_ctx_mode_config(TC_CONF *conf, SSL_CTX *ssl_ctx)
{
    /* If arg is 1 then set release buf mode at context */
    if (conf->ssl_mode.release_buf == 1) {
        SSL_CTX_set_mode(ssl_ctx, SSL_MODE_RELEASE_BUFFERS);
    }
    return 0;
}

int ssl_mode_config(TC_CONF *conf, SSL *ssl)
{
    /* If arg is non zero and other than 1 then set release buf mode at SSL */
    if (conf->ssl_mode.release_buf > 1) {
        SSL_set_mode(ssl, SSL_MODE_RELEASE_BUFFERS);
    }
    return 0;
}
