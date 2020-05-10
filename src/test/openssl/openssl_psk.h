#ifndef _OPENSSL_PSK_H_
#define _OPENSSL_PSK_H_

#ifdef __cplusplus
extern "C" {
#endif

#include "openssl_common.h"

int ssl_ctx_psk_config(TC_CONF *conf, SSL_CTX *ctx);

#ifdef __cplusplus
}
#endif

#endif
