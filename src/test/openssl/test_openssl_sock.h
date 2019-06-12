#ifndef _TEST_OPENSSL_SOCK_H_
#define _TEST_OPENSSL_SOCK_H_

#ifdef __cplusplus
extern "C" {
#endif

int create_listen_sock(TC_CONF *conf);

int create_sock_connection(TC_CONF *conf);

#ifdef __cplusplus
}
#endif

#endif
