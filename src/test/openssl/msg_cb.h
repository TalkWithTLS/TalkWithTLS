#ifndef _MSG_CB_H_
#define _MSG_CB_H_

#ifdef __cplusplus
extern "C" {
#endif

#include "test_openssl_common.h"

void ssl_msg_cb(int write_p, int version, int content_type, const void *buf, size_t len,
                                                                SSL *ssl, void *arg);
#ifdef __cplusplus
}
#endif

#endif
