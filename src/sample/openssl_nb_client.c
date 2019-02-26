#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <errno.h>
#include <fcntl.h>

#include "openssl/crypto.h"
#include "openssl/ssl.h"

#include "test_common.h"

SSL_CTX *create_context()
{
    SSL_CTX *ctx;

    ctx = SSL_CTX_new(TLS_client_method());
    if (!ctx) {
        printf("SSL ctx new failed\n");
        return NULL;
    }

    printf("SSL context created\n");

    if (SSL_CTX_load_verify_locations(ctx, EC256_CAFILE1, NULL) != 1) {
        printf("Load CA cert failed\n");
        goto err_handler;
    }

    printf("Loaded cert %s on context\n", EC256_CAFILE1);

    SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER, NULL);
    SSL_CTX_set_verify_depth(ctx, 5);
    SSL_CTX_set_options(ctx, SSL_OP_NO_TLSv1_3);

    printf("SSL context configurations completed\n");

    return ctx;
err_handler:
    SSL_CTX_free(ctx);
    return NULL;
}

int enable_nonblock(int fd)
{
    int flags;
    flags = fcntl(fd, F_GETFL, 0);
    if (flags == -1) {
        printf("Get flag failed for fcntl");
        return -1;
    }
    flags |= O_NONBLOCK;
    if (fcntl(fd, F_SETFL, flags) != 0) {
        printf("Set nonblock flags on fcntl failed\n");
        return -1;
    }
    return 0;
}

SSL *create_ssl_object(SSL_CTX *ctx)
{
    SSL *ssl;
    int fd = -1;

    fd = do_tcp_connection(SERVER_IP, SERVER_PORT);
    if (fd < 0) {
        printf("TCP connection establishment failed\n");
        return NULL;
    }

    /* Enable nonblocking on socket fd */
    if (enable_nonblock(fd)) {
        printf("Enabling non block failed\n");
        goto err;
    }

    ssl = SSL_new(ctx);
    if (!ssl) {
        printf("SSL object creation failed\n");
        goto err;
    }

    SSL_set_fd(ssl, fd);

    printf("SSL object creation finished\n");

    return ssl;
err:
    close(fd);
    return NULL;
}

int wait_for_sock_failure(SSL *ssl, int ret)
{
    fd_set readfds, writefds;
    struct timeval timeout;
    int err;
    int fd;

    fd = SSL_get_fd(ssl);
    FD_ZERO(&readfds);
    FD_ZERO(&writefds);

    err = SSL_get_error(ssl, ret); 
    switch (err) {
        case SSL_ERROR_WANT_READ:
            printf("SSL want read occured\n");
            FD_SET(fd, &readfds);
            break;
        case SSL_ERROR_WANT_WRITE:
            printf("SSL want write occured\n");
            FD_SET(fd, &writefds);
            break;
        default:
            printf("SSL connect failed with err%d\n", err);
            return -1;
    }
    timeout.tv_sec = TLS_SOCK_TIMEOUT_MS / 1000;
    timeout.tv_usec = (TLS_SOCK_TIMEOUT_MS % 1000) * 1000;
    if (select(fd + 1, &readfds, &writefds, NULL, &timeout) < 1) {
        printf("select timed out, ret=%d\n", ret);
        return -1;
    }
    return 0;
}

int do_ssl_connect(SSL *ssl)
{
    int ret;

    do {
        ret = SSL_connect(ssl);
        if (ret == 1) {
            printf("SSL connect succeeded\n");
            break;
        }
        printf("Check and going to wait for sock failure in SSL_connect\n");
        if (wait_for_sock_failure(ssl, ret)) {
            printf("SSL connect failed\n");
            return -1;
        }
        printf("Continue SSL connection\n");
    } while (1);
    return 0;
}

int do_data_transfer(SSL *ssl)
{
    const char *msg = MSG_FOR_OPENSSL_CLNT;
    char buf[MAX_BUF_SIZE] = {0};
    int ret;

    do {
        ret = SSL_write(ssl, msg, strlen(msg));
        if (ret == strlen(msg)) {
            break;
        }
        printf("Check and going to wait for sock failure in SSL_write\n");
        if (wait_for_sock_failure(ssl, ret)) {
            printf("SSL write failed\n");
            return -1;
        }
    } while (1);
    printf("SSL_write[%d] sent %s\n", ret, msg);

    do {
        ret = SSL_read(ssl, buf, sizeof(buf) - 1);
        if (ret > 0) {
            break;
        }
        printf("Check and going to wait for sock failure in SSL_read\n");
        if (wait_for_sock_failure(ssl, ret)) {
            printf("SSL read failed\n");
            return -1;
        }
    } while (1);
    printf("SSL_read[%d] %s\n", ret, buf);
    return 0;
}

void do_cleanup(SSL_CTX *ctx, SSL *ssl)
{
    int fd;
    if (ssl) {
        fd = SSL_get_fd(ssl);
        close(fd);
        SSL_free(ssl);
    }
    if (ctx) {
        SSL_CTX_free(ctx);
    }
}

int tls12_client()
{
    SSL_CTX *ctx;
    SSL *ssl = NULL;
    int ret_val = -1;

    ctx = create_context();
    if (!ctx) {
        return -1;
    }

    ssl = create_ssl_object(ctx);
    if (!ssl) {
        goto err_handler;
    }

    if (do_ssl_connect(ssl)) {
        printf("SSL connect failed\n");
        goto err_handler;
    }

    if (do_data_transfer(ssl)) {
        printf("Data transfer over TLS failed\n");
        goto err_handler;
    }
    printf("Data transfer over TLS succeeded\n");
    SSL_shutdown(ssl);
    ret_val = 0;
err_handler:
    do_cleanup(ctx, ssl);
    return ret_val;
}

int main()
{
    printf("OpenSSL version: %s, %s\n", OpenSSL_version(OPENSSL_VERSION), OpenSSL_version(OPENSSL_BUILT_ON));
    if (tls12_client()) {
        printf("TLS12 client connection failed\n");
        return -1;
    }
    return 0;
}
