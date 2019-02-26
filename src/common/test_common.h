#ifndef _TEST_COMMON_H_
#define _TEST_COMMON_H_

#ifdef __cplusplus
extern "C" {
#endif

#include <stdio.h>
#include <stdint.h>
#include <string.h>

#define MAX_BUF_SIZE    1024

#define MSG_FOR_OPENSSL_CLNT    "Hi, This is OpenSSL client"
#define MSG_FOR_OPENSSL_SERV    "Hello, This is OpenSSL server"
#define MSG_FOR_WOLFSSL_CLNT    "Hi, This is wolfSSL client"
#define MSG_FOR_WOLFSSL_SERV    "Hello, This is wolfSSL server"

#define EC256_CAFILE1 "./certs/ECC_Prime256_Certs/rootcert.pem"
#define SERVER_IP "127.0.0.1"
#define SERVER_PORT 7788

#define TCP_CON_RETRY_COUNT 20
#define TCP_CON_RETRY_WAIT_TIME_MS 200

#define TLS_SOCK_TIMEOUT_MS 2000

int do_tcp_connection(const char *server_ip, uint16_t port);

int do_tcp_listen(const char *server_ip, uint16_t port);

int do_tcp_accept(int lfd);

#ifdef __cplusplus
}
#endif

#endif

