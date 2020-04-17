#ifndef _OPENSSL_SSL_MODE_H_
#define _OPENSSL_SSL_MODE_H_

#ifdef __cplusplus
extern "C" {
#endif

#include "openssl_common.h"

int ssl_ctx_mode_config(TC_CONF *conf, SSL_CTX *ssl_ctx);

int ssl_mode_config(TC_CONF *conf, SSL *ssl);

#ifdef __cplusplus
}
#endif

#endif
