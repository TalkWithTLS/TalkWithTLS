#ifndef _OPENSSL_CIPHER_H_
#define _OPENSSL_CIPHER_H_

#ifdef __cplusplus
extern "C" {
#endif

#include "openssl_common.h"

int ssl_ciph_config(TC_CONF *conf, SSL *ssl);

int do_negotiated_ciphersuite_validation(TC_CONF *conf, SSL *ssl);

#ifdef __cplusplus
}
#endif

#endif
