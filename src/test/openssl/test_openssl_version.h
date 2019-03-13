#ifndef _TEST_OPENSSL_VERSION_H_
#define _TEST_OPENSSL_VERSION_H_

#ifdef __cplusplus
extern "C" {
#endif

#include "test_openssl_common.h"

int ssl_ctx_version_conf(TC_CONF *conf, SSL_CTX *ctx);

int do_negotiated_version_validation(TC_CONF *conf, SSL *ssl);

#ifdef __cplusplus
}
#endif

#endif
