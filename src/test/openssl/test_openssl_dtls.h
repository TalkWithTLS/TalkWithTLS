#ifndef _TEST_OPENSSL_DTLS_H_
#define _TEST_OPENSSL_DTLS_H_

#ifdef __cplusplus
extern "C" {
#endif

#include "test_openssl_common.h"

int ssl_config_dtls_bio(TC_CONF *conf, SSL *ssl, const char *server_ip, uint16_t serv_port);

#ifdef __cplusplus
}
#endif

#endif
