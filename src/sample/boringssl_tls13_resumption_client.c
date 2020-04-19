#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <errno.h>

#include "openssl/crypto.h"
#include "openssl/ssl.h"

#include "test_common.h"

#define CAFILE1 "./certs/ECC_Prime256_Certs/rootcert.pem"

SSL_CTX *create_context()
{
    SSL_CTX *ctx;

    ctx = SSL_CTX_new(TLS_client_method());
    if (!ctx) {
        printf("SSL ctx new failed\n");
        return NULL;
    }

    printf("SSL context created\n");

    if (SSL_CTX_load_verify_locations(ctx, CAFILE1, NULL) != 1) {
        printf("Load CA cert failed\n");
        goto err_handler;
    }

    printf("Loaded cert %s on context\n", CAFILE1);

    SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER, NULL);
    SSL_CTX_set_verify_depth(ctx, 5);

    printf("SSL context configurations completed\n");

    return ctx;
err_handler:
    SSL_CTX_free(ctx);
    return NULL;
}

SSL *create_ssl_object(SSL_CTX *ctx)
{
    SSL *ssl;
    int fd;

    fd = do_tcp_connection(SERVER_IP, SERVER_PORT);
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
    printf("SSL object creation finished\n");
    return ssl;
}

int do_data_transfer(SSL *ssl)
{
    const char *msg_req[] = {MSG1_REQ, MSG2_REQ};
    const char *req;
    char buf[MAX_BUF_SIZE] = {0};
    int ret, i;
    for (i = 0; i < sizeof(msg_req)/sizeof(msg_req[0]); i++) {
        req = msg_req[i];
        ret = SSL_write(ssl, req, strlen(req));
        if (ret <= 0) {
            printf("SSL_write failed ret=%d\n", ret);
            return -1;
        }
        printf("SSL_write[%d] sent %s\n", ret, req);

        ret = SSL_read(ssl, buf, sizeof(buf) - 1);
        if (ret <= 0) {
            printf("SSL_read failed ret=%d\n", ret);
            return -1;
        }
        printf("SSL_read[%d] %s\n", ret, buf);
    }
    return 0;
}

int validate_sess_resumption(SSL *ssl, int *check_sess_reused)
{
    if (*check_sess_reused) {
        if (SSL_session_reused(ssl) != 1) {
            printf("SSL session not reused\n");
            return -1;
        }
        printf("SSL session resumption succeeded\n");
        *check_sess_reused = 0;
    }
    return 0;
}

int tls13_client(int con_count)
{
    SSL_CTX *ctx;
    SSL *ssl = NULL;
    SSL_SESSION *prev_sess = NULL;
    int check_sess_reused = 0;
    int ret_val = -1;
    int fd;
    int ret;
    int i;

    ctx = create_context();
    if (!ctx) {
        return -1;
    }

    for (i = 0; i < con_count; i++) {
        ssl = create_ssl_object(ctx);
        if (!ssl) {
            goto err_handler;
        }

        fd = SSL_get_fd(ssl);

        if (prev_sess != NULL) {
            SSL_set_session(ssl, prev_sess);
            SSL_SESSION_free(prev_sess);
            prev_sess = NULL;
            check_sess_reused = 1;
        }

        ret = SSL_connect(ssl);
        if (ret != 1) {
            printf("SSL connect failed%d\n", ret);
            goto err_handler;
        }
        printf("SSL connect succeeded\n");

        if (validate_sess_resumption(ssl, &check_sess_reused)) {
            goto err_handler;
        }

        if (do_data_transfer(ssl)) {
            printf("Data transfer over TLS failed\n");
            goto err_handler;
        }
        printf("Data transfer over TLS succeeded\n\n");

        prev_sess = SSL_get1_session(ssl);
        if (!prev_sess) {
            printf("SSL session is NULL\n");
            goto err_handler;
        }
        printf("SSL session backed up\n");

        SSL_shutdown(ssl);
        SSL_free(ssl);
        ssl = NULL;
        close(fd);
        fd = -1;
    }

    ret_val = 0;
err_handler:
    SSL_free(ssl);
    SSL_SESSION_free(prev_sess);
    SSL_CTX_free(ctx);
    close(fd);
    return ret_val;
}

int main(int argc, char *argv[])
{
    printf("OpenSSL version: %s, %s\n", OpenSSL_version(OPENSSL_VERSION), OpenSSL_version(OPENSSL_BUILT_ON));
    if (tls13_client(2)) {
        printf("TLS13 client connection failed\n");
        return -1;
    }
    return 0;
}
