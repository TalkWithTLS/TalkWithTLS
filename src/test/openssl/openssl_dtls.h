#ifndef _OPENSSL_DTLS_H_
#define _OPENSSL_DTLS_H_

#ifdef __cplusplus
extern "C" {
#endif

#include "openssl_common.h"

int ssl_config_dtls_bio(TC_CONF *conf, SSL *ssl);

#ifdef __cplusplus
}
#endif

#endif
