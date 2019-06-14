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
#define EARLY_DATA_MSG_FOR_OPENSSL_CLNT "Hi, This is an early data from OpenSSL Client"
#define MSG_FOR_WOLFSSL_CLNT    "Hi, This is wolfSSL client"
#define MSG_FOR_WOLFSSL_SERV    "Hello, This is wolfSSL server"

#define MAX_EARLY_DATA_MSG  4098

#define RSA2048_SERVER_CERT_FILE "./certs/RSA_Certs/serv_cert.pem"
#define RSA2048_SERVER_KEY_FILE "./certs/RSA_Certs/serv_key.der"
#define RSA2048_CAFILE1 "./certs/RSA_Certs/rootcert.pem"

#define RAS2048_PSS_PSS_SERV_CERT "./certs/RSA_PSS_PSS_Certs/serv_cert.pem"
#define RAS2048_PSS_PSS_SERV_KEY "./certs/RSA_PSS_PSS_Certs/serv_key.pem"
#define RAS2048_PSS_PSS_CAFILE1 "./certs/RSA_PSS_PSS_Certs/rootcert.pem"

#define EC256_SERVER_CERT_FILE "./certs/ECC_Prime256_Certs/serv_cert.pem"
#define EC256_SERVER_KEY_FILE "./certs/ECC_Prime256_Certs/serv_key.der"
#define EC256_CLIENT_CERT_FILE "./certs/ECC_Prime256_Certs/client_cert.pem"
#define EC256_CLIENT_KEY_FILE "./certs/ECC_Prime256_Certs/client_key.der"
#define EC256_CAFILE1 "./certs/ECC_Prime256_Certs/rootcert.pem"

#define EC256_CURVE_NAME NID_X9_62_prime256v1

#define SERVER_IP "127.0.0.1"
#define SERVER_PORT 4433

#define TCP_CON_RETRY_COUNT 20
#define TCP_CON_RETRY_WAIT_TIME_MS 200

#define TLS_SOCK_TIMEOUT_MS 8000

#define DTLS_MTU 1400

int create_udp_sock();

int create_udp_serv_sock(const char *server_ip, uint16_t port);

int do_tcp_connection(const char *server_ip, uint16_t port);

int do_tcp_listen(const char *server_ip, uint16_t port);

int do_tcp_accept(int lfd);

void check_and_close(int *fd);

#ifdef __cplusplus
}
#endif

#endif

