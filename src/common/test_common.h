#ifndef _TEST_COMMON_H_
#define _TEST_COMMON_H_

#ifdef __cplusplus
extern "C" {
#endif

#include <stdio.h>
#include <stdint.h>

#define MAX_BUF_SIZE    1024

#define MSG_FOR_SERV    "Hi TLS server"
#define MSG_FOR_CLNT    "Hello TLS client"

#define EC256_CAFILE1 "./certs/ECC_Prime256_Certs/rootcert.pem"
#define SERVER_IP "127.0.0.1"
#define SERVER_PORT 7788

int do_tcp_connection(const char *server_ip, uint16_t port);

int do_tcp_listen(const char *server_ip, uint16_t port);

int do_tcp_accept(int lfd);

#ifdef __cplusplus
}
#endif

#endif

