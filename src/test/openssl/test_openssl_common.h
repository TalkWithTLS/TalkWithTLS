#ifndef _TEST_OPENSSL_COMMON_H_
#define _TEST_OPENSSL_COMMON_H_

#ifdef __cplusplus
extern "C" {
#endif

#include "test_common.h"
#include "test_openssl_conf.h"

#include "openssl/crypto.h"
#include "openssl/rand.h"
#include "openssl/ssl.h"

int init_tc_conf(TC_CONF *conf);

void fini_tc_conf(TC_CONF *conf);

int init_psk_params(TC_CONF *conf, const char *psk_id, const char *psk_key);

int do_test_openssl(TC_CONF *conf);

int do_handshake(TC_CONF *conf, SSL *ssl);

int do_data_transfer(TC_CONF *conf, SSL *ssl);

#ifdef __cplusplus
}
#endif

#endif
