#ifndef _OPENSSL_COMMON_H_
#define _OPENSSL_COMMON_H_

#ifdef __cplusplus
extern "C" {
#endif

#include "test_common.h"

#include "test_conf.h"

#include "openssl/crypto.h"
#include "openssl/rand.h"
#include "openssl/ssl.h"

int init_tc_conf_for_openssl(TC_CONF *conf);

int do_test_openssl(TC_CONF *conf);

int do_handshake(TC_CONF *conf, SSL *ssl);

int do_data_transfer(TC_CONF *conf, SSL *ssl);

#ifdef __cplusplus
}
#endif

#endif
