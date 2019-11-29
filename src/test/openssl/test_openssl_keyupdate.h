#ifndef _TEST_OPENSSL_KEYUPDATE_H_
#define _TEST_OPENSSL_KEYUPDATE_H_

#ifdef __cplusplus
extern "C" {
#endif

#include "test_openssl_common.h"

int do_key_update_test(TC_CONF *conf, SSL *ssl);

#ifdef __cplusplus
}
#endif

#endif
