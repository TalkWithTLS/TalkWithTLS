#ifndef _TEST_OPENSSL_VALIDATION_H_
#define _TEST_OPENSSL_VALIDATION_H_

#ifdef __cplusplus
extern "C" {
#endif

#include "test_openssl_common.h"

int do_after_handshake_validation(TC_CONF *conf, SSL *ssl);

#ifdef __cplusplus
}
#endif

#endif
