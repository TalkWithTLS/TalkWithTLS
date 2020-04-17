#ifndef _OPENSSL_VALIDATION_H_
#define _OPENSSL_VALIDATION_H_

#ifdef __cplusplus
extern "C" {
#endif

#include "openssl_common.h"

int do_after_handshake_validation(TC_CONF *conf, SSL *ssl);

#ifdef __cplusplus
}
#endif

#endif
