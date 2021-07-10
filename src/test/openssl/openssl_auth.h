#ifndef _OPENSSL_AUTH_H_
#define _OPENSSL_AUTH_H_

#ifdef __cplusplus
extern "C" {
#endif

#include "openssl_common.h"

int ssl_ctx_auth_conf(TC_CONF *conf, SSL_CTX *ctx);

int tc_conf_auth(TC_CONF *conf);

int do_print_peer_cert(TC_CONF *conf, SSL *ssl);

#ifdef __cplusplus
}
#endif

#endif /* _OPENSSL_AUTH_H_ */
