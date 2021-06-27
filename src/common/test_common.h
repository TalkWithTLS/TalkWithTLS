#ifndef _TEST_COMMON_H_
#define _TEST_COMMON_H_

#ifdef __cplusplus
extern "C" {
#endif

#include <stdio.h>
#include <stdint.h>
#include <string.h>

#define RED_COLOUR    "\x1B[31m"
#define RESET_COLOUR  "\x1B[0m"

#define LOG(colour_start, colour_end, fmt, loglevel, ...) \
    do { \
        char *token, *filename = __FILE__; \
        char *rest_orig, *rest; \
        rest_orig = rest = strdup(filename); \
        if (rest != NULL) { \
            while ((token = strtok_r(rest, "/", &rest)) != NULL) { \
                filename = token; \
            } \
        } \
        printf("%s[%s][%s:%d]"fmt"%s", colour_start, loglevel, filename, \
                __LINE__, ##__VA_ARGS__, colour_end); \
        fflush(stdout); \
        if (rest_orig != NULL) free(rest_orig); \
    } while (0)

#define DBG(fmt, ...) \
    LOG("", "", fmt, "DBG", ##__VA_ARGS__)

#define ERR(fmt, ...) \
    LOG(RED_COLOUR, RESET_COLOUR, fmt, "ERR", ##__VA_ARGS__)

#define PRINT(fmt, ...) \
    do { \
        printf(fmt, ##__VA_ARGS__); \
        fflush(stdout); \
    } while (0)

#define MAX_BUF_SIZE    1024

#define MSG1_REQ "GET /index.html HTTP/1.1\r\nHOST: twt.com\r\n\r\n"
#define MSG1_RES "<html>" \
                 "<title>TWT Perf</title>" \
                 "<body><H1>TalkWithTLS<H1>This is index.html</body>" \
                 "</html>"
#define MSG2_REQ "GET /main.html HTTP/1.1\r\nHOST: twt.com\r\n\r\n"
#define MSG2_RES "<html>" \
                 "<title>TWT Perf</title>" \
                 "<body><H1>TalkWithTLS<H1>This is main.html</body>" \
                 "</html>"

#define EARLY_DATA_MSG_FOR_OPENSSL_CLNT "Hi, This is an early data from OpenSSL Client"

#define MAX_EARLY_DATA_MSG  4098

#define RSA2048_SERVER_CERT_FILE "./certs/RSA2048_Certs/serv_cert.pem"
#define RSA2048_SERVER_KEY_FILE "./certs/RSA2048_Certs/serv_key.der"
#define RSA2048_CAFILE1 "./certs/RSA2048_Certs/rootcert.pem"

#define RAS2048_PSS_PSS_SERV_CERT "./certs/RSA2048_PSS_PSS_Certs/serv_cert.pem"
#define RAS2048_PSS_PSS_SERV_KEY "./certs/RSA2048_PSS_PSS_Certs/serv_key.pem"
#define RAS2048_PSS_PSS_CAFILE1 "./certs/RSA2048_PSS_PSS_Certs/rootcert.pem"

#define EC256_SERVER_CERT_FILE "./certs/ECC_Prime256_Certs/serv_cert.pem"
#define EC256_SERVER_KEY_FILE "./certs/ECC_Prime256_Certs/serv_key.der"
#define EC256_CLIENT_CERT_FILE "./certs/ECC_Prime256_Certs/client_cert.pem"
#define EC256_CLIENT_KEY_FILE "./certs/ECC_Prime256_Certs/client_key.der"
#define EC256_CAFILE1 "./certs/ECC_Prime256_Certs/rootcert.pem"

#define EC256_CURVE_NAME NID_X9_62_prime256v1

#define ED25519_SERVER_CERT_FILE "./certs/ED25519/serv_cert.pem"
#define ED25519_SERVER_KEY_FILE "./certs/ED25519/serv_key.pem"
#define ED25519_CAFILE1 "./certs/ED25519/rootcert.pem"

#define SERVER_IP "127.0.0.1"
#define SERVER_PORT 4433

#define TCP_CON_RETRY_COUNT 20
#define TCP_CON_RETRY_WAIT_TIME_MS 2

#define TLS_SOCK_TIMEOUT_MS 8000

#define DTLS_MTU 1400

int create_udp_sock();

int create_udp_serv_sock(const char *server_ip, uint16_t port);

int do_tcp_connection(const char *server_ip, uint16_t port);

int do_tcp_listen(const char *server_ip, uint16_t port);

int do_tcp_accept(int lfd);

int set_receive_to(int fd, int secs);

void check_and_close(int *fd);

#ifdef __cplusplus
}
#endif

#endif

