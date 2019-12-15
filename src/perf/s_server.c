#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <getopt.h>
#include <errno.h>

#include "openssl/crypto.h"
#include "openssl/ssl.h"
#include "openssl/err.h"

#define SERVER_IP "127.0.0.1"
#define SERVER_PORT 4433
#define TCP_CON_RETRY_COUNT 20
#define TCP_CON_RETRY_WAIT_TIME_MS 200
#define TLS_SOCK_TIMEOUT_MS 8000

#define MAX_BUF_SIZE    1024
#define MSG_FOR_S_SERV    "<html><title>TWT Perf</title><body>TalkWithTLS</body></html>"

#define SERVER_CERT_FILE "./certs/ECC_Prime256_Certs/serv_cert.pem"
#define SERVER_KEY_FILE "./certs/ECC_Prime256_Certs/serv_key.der"

int g_kexch_groups[] = {
    NID_X9_62_prime256v1,   /* secp256r1 */
    NID_secp384r1,          /* secp384r1 */
    NID_secp521r1,          /* secp521r1 */
    NID_X25519,             /* x25519 */
    NID_X448                /* x448 */
};

int do_tcp_listen(const char *server_ip, uint16_t port)
{
    struct sockaddr_in addr;
    int optval = 1;
    int lfd;
    int ret;

    lfd = socket(AF_INET, SOCK_STREAM, 0);
    if (lfd < 0) {
        printf("Socket creation failed\n");
        return -1;
    }

    addr.sin_family = AF_INET;
    if (inet_aton(server_ip, &addr.sin_addr) == 0) {
        printf("inet_aton failed\n");
        goto err_handler;
    }
    addr.sin_port = htons(port);

    if (setsockopt(lfd, SOL_SOCKET, SO_REUSEADDR, &optval, sizeof(optval))) {
        printf("set sock reuseaddr failed\n");
    }
    ret = bind(lfd, (struct sockaddr *)&addr, sizeof(addr));
    if (ret) {
        printf("bind failed %s:%d\n", server_ip, port);
        goto err_handler;
    }

    printf("TCP listening on %s:%d...\n", server_ip, port);
    ret = listen(lfd, 5);
    if (ret) {
        printf("listen failed\n");
        goto err_handler;
    }
    printf("TCP listen fd=%d\n", lfd);
    return lfd;
err_handler:
    close(lfd);
    return -1;
}

int do_tcp_accept(int lfd)
{
    struct sockaddr_in peeraddr;
    socklen_t peerlen = sizeof(peeraddr);
    int cfd;

    printf("Waiting for TCP connection from client...\n");
    cfd = accept(lfd, (struct sockaddr *)&peeraddr, &peerlen);
    if (cfd < 0) {
        printf("accept failed, errno=%d\n", errno);
        return -1;
    }

    printf("TCP connection accepted fd=%d\n", cfd);
    return cfd;
}

void check_and_close(int *fd)
{
    if (*fd < 0) {
        return;
    }
    if (*fd == 0 || *fd == 1 || *fd == 2) {
        printf("Trying to close fd=%d, skipping it !!!\n", *fd);
    }
    printf("Closing fd=%d\n", *fd);
    close(*fd);
}
SSL_CTX *create_context()
{
    SSL_CTX *ctx;

    ctx = SSL_CTX_new(TLS_server_method());
    if (!ctx) {
        printf("SSL ctx new failed\n");
        return NULL;
    }

    printf("SSL context created\n");

    if (SSL_CTX_use_certificate_file(ctx, SERVER_CERT_FILE, SSL_FILETYPE_PEM) != 1) {
        printf("Load Server cert %s failed\n", SERVER_CERT_FILE);
        goto err_handler;
    }

    printf("Loaded server cert %s on context\n", SERVER_CERT_FILE);

    if (SSL_CTX_use_PrivateKey_file(ctx, SERVER_KEY_FILE, SSL_FILETYPE_ASN1) != 1) {
        printf("Load Server key %s failed\n", SERVER_KEY_FILE);
        goto err_handler;
    }

    printf("Loaded server key %s on context\n", SERVER_KEY_FILE);

    printf("SSL context configurations completed\n");

    return ctx;
err_handler:
    SSL_CTX_free(ctx);
    return NULL;
}

SSL *create_ssl_object(SSL_CTX *ctx, int lfd)
{
    SSL *ssl;
    int fd;

    fd = do_tcp_accept(lfd);
    if (fd < 0) {
        printf("TCP connection establishment failed\n");
        return NULL;
    }

    ssl = SSL_new(ctx);
    if (!ssl) {
        printf("SSL object creation failed\n");
        return NULL;
    }

    SSL_set_fd(ssl, fd);

    if (SSL_set1_groups(ssl, g_kexch_groups, sizeof(g_kexch_groups)/sizeof(g_kexch_groups[0])) != 1) {
        printf("Set Groups failed\n");
        goto err_handler;
    }

    printf("SSL object creation finished\n");

    return ssl;
err_handler:
    SSL_free(ssl);
    return NULL;
}

int do_data_transfer(SSL *ssl)
{
    const char *msg = MSG_FOR_S_SERV;
    char buf[MAX_BUF_SIZE] = {0};
    int ret;

    ret = SSL_read(ssl, buf, sizeof(buf) - 1);
    if (ret <= 0) {
        printf("SSL_read failed ret=%d\n", ret);
        return -1;
    }
    printf("SSL_read[%d] %s\n", ret, buf);
    ret = SSL_write(ssl, msg, strlen(msg));
    if (ret <= 0) {
        printf("SSL_write failed ret=%d\n", ret);
        return -1;
    }
    printf("SSL_write[%d] sent %s\n", ret, msg);
    return 0;
}

void do_cleanup(SSL_CTX *ctx, SSL *ssl)
{
    int fd;
    if (ssl) {
        fd = SSL_get_fd(ssl);
        SSL_free(ssl);
        close(fd);
    }
    if (ctx) {
        SSL_CTX_free(ctx);
    }
}

void get_error()
{
    unsigned long error;
    const char *file = NULL;
    int line= 0;
    error = ERR_get_error_line(&file, &line);
    printf("Error reason=%d on [%s:%d]\n", ERR_GET_REASON(error), file, line);
}

int do_tls_server(SSL_CTX *ctx, int lfd)
{
    SSL *ssl = NULL;
    int ret_val = -1;
    int ret;

    ssl = create_ssl_object(ctx, lfd);
    if (!ssl) {
        goto err_handler;
    }

    ret = SSL_accept(ssl); 
    if (ret != 1) {
        printf("SSL accept failed%d\n", ret);
        if (SSL_get_error(ssl, ret) == SSL_ERROR_SSL) {
            get_error();
        }
        goto err_handler;
    }

    printf("SSL accept succeeded\n");
    printf("Negotiated Cipher suite:%s\n", SSL_CIPHER_get_name(SSL_get_current_cipher(ssl)));

    if (do_data_transfer(ssl)) {
        printf("Data transfer over TLS failed\n");
        goto err_handler;
    }
    printf("Data transfer over TLS succeeded\n");
    SSL_shutdown(ssl);
    ret_val = 0;
err_handler:
    do_cleanup(NULL, ssl);
    return ret_val;
}

typedef struct perf_conf_st {
    uint32_t with_out_tls:1;
}PERF_CONF;

int init_conf(PERF_CONF *conf)
{
    return 0;
}

int parse_arg(int argc, char *argv[], PERF_CONF *conf)
{
    return 0;
}

int do_tls_server_perf(PERF_CONF *conf)
{
    SSL_CTX *ctx;
    int ret_val = -1;
    int lfd;

    ctx = create_context();
    if (!ctx) {
        return -1;
    }

    if ((lfd = do_tcp_listen(SERVER_IP, SERVER_PORT)) < 0) {
        goto err;
    }
    do {
        if (do_tls_server(ctx, lfd) != 0) {
            printf("TLS server connection failed\n");
            goto err;
        }
    } while (1);
    ret_val = 0;
err:
    check_and_close(&lfd);
    do_cleanup(ctx, NULL);
    return ret_val;
}

int main(int argc, char *argv[])
{
    PERF_CONF conf = {0};
    printf("OpenSSL version: %s, %s\n", OpenSSL_version(OPENSSL_VERSION),
            OpenSSL_version(OPENSSL_BUILT_ON));
    if (init_conf(&conf) || parse_arg(argc, argv, &conf) != 0) {
        return -1;
    }
    if (do_tls_server_perf(&conf) != 0) {
        return -1;
    }
    return 0;
}
