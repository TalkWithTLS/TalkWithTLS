#ifndef _TEST_OPENSSL_ARG_H_
#define _TEST_OPENSSL_ARG_H_

#ifdef __cplusplus
extern "C" {
#endif

#include "test_openssl_common.h"

int initialize_resumption_params(TC_CONF *conf, SSL_CTX *ctx);

#ifdef __cplusplus
}
#endif

#endif
