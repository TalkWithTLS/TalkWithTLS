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

    ctx = SSL_CTX_new(DTLS_client_method());
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

int update_dtls_client_bio(SSL *ssl, const char *serv_ip, uint16_t serv_port)
{
    struct timeval recv_to;
    struct in_addr ipv4;
    BIO_ADDR *peer_addr;
    BIO *bio = NULL;
    int ret_val = -1;
    int fd;

    fd = create_udp_sock();
    if (fd < 0) {
        printf("UDP socket creation failed\n");
        return -1;
    }

    if (enable_nonblock(fd)) {
        printf("enable nb on sockfd failed\n");
        close(fd);
        return -1;
    }

    if (inet_aton(serv_ip, &ipv4) != 1) {
        printf("Invalid server ip %s\n", serv_ip);
        return -1;
    }

    peer_addr = BIO_ADDR_new();
    if (!peer_addr) {
        printf("BIO ADDR new failed\n");
        return -1;
    }

    if (BIO_ADDR_rawmake(peer_addr, AF_INET, &ipv4, sizeof(ipv4), htons(serv_port)) != 1) {
        printf("BIO ADDR rawmake failed\n");
        goto err;
    }

    bio = BIO_new_dgram(fd, BIO_NOCLOSE);
    if (!bio) {
        printf("BIO new failed\n");
        goto err;
    }

    if (BIO_dgram_set_peer(bio, peer_addr) != 1) {
        printf("BIO dgram set peer failed\n");
        goto err;
    }

    recv_to.tv_sec = TLS_SOCK_TIMEOUT_MS / 1000;
    recv_to.tv_usec = (TLS_SOCK_TIMEOUT_MS % 1000) * 1000;
    
    if (BIO_ctrl(bio, BIO_CTRL_DGRAM_SET_RECV_TIMEOUT, 0, &recv_to) != 1) {
        printf("BIO set recv timeout failed\n");
        goto err;
    }

    SSL_set_bio(ssl, bio, bio);
    bio = NULL;

    printf("BIO DGRAM configured for DTLS\n");
    ret_val = 0;
err:
    BIO_ADDR_free(peer_addr);
    if (bio) {
        BIO_free(bio);
    }
    return ret_val;
}

SSL *create_ssl_object(SSL_CTX *ctx)
{
    SSL *ssl;

    ssl = SSL_new(ctx);
    if (!ssl) {
        printf("SSL object creation failed\n");
        return NULL; 
    }

    if (update_dtls_client_bio(ssl, SERVER_IP, SERVER_PORT)) {
        printf("Updating BIO for DTLS failed\n");
        goto err;
    }

    printf("SSL object creation finished\n");

    return ssl;
err:
    SSL_free(ssl);
    return NULL;
}

int handle_handshake_failure(SSL *ssl, int ret)
{
    fd_set readfds, writefds;
    struct timeval timeout = {0};
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
    do {
        if (DTLSv1_get_timeout(ssl, &timeout) != 1) {
            printf("DTLS get timeout failed\n");
            return -1;
        }
        printf("DTLS handshake timeout is %ld sec, and %ld usec\n", timeout.tv_sec, timeout.tv_usec);
        if (select(fd + 1, &readfds, &writefds, NULL, &timeout) > 0) {
            printf("Select succeeds, time spent is %ld sec, and %ld usec\n", timeout.tv_sec, timeout.tv_usec);
            return 0;
        }
        printf("Calling DTLS handle timeout as select timed out, ret=%d\n", ret);
        if (DTLSv1_handle_timeout(ssl) != 1) {
            printf("DTLS handle timeout failed\n");
            return -1;
        }
    } while (1);
    return 0;
}

int do_dtls_connect(SSL *ssl)
{
    int ret;
    do {
        ret = SSL_connect(ssl); 
        if (ret == 1) {
            printf("DTLS connect succeeded\n");
            return 0;
        }
        printf("Check and going to wait for sock failure in DTLS connect\n");
        if (handle_handshake_failure(ssl, ret)) {
            printf("SSL connect failed\n");
            return -1;
        }
        printf("Continue DTLS connection\n");
    } while (1);
    printf("DTLS connect succeeded\n");
}

int handle_data_transfer_failure(SSL *ssl, int ret)
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
        printf("Check and going to wait for sock failure in DTLS write\n");
        if (handle_data_transfer_failure(ssl, ret)) {
            printf("DTLS write failed\n");
            return -1;
        }
    } while (1);
    printf("SSL_write[%d] sent %s\n", ret, msg);

    do {
        ret = SSL_read(ssl, buf, sizeof(buf) - 1);
        if (ret > 1) {
            break;
        }
        printf("Check and going to wait for sock failure in DTLS read\n");
        if (handle_data_transfer_failure(ssl, ret)) {
            printf("DTLS read failed\n");
            return -1;
        }
    } while(1);
    printf("SSL_read[%d] %s\n", ret, buf);
    return 0;
}

int dtls12_client()
{
    SSL_CTX *ctx;
    SSL *ssl = NULL;
    int fd;

    ctx = create_context();
    if (!ctx) {
        return -1;
    }

    ssl = create_ssl_object(ctx);
    if (!ssl) {
        goto err_handler;
    }

    fd = SSL_get_fd(ssl);

    if (do_dtls_connect(ssl)) {
        printf("DTLS connect failed\n");
        goto err_handler;
    }

    if (do_data_transfer(ssl)) {
        printf("Data transfer over DTLS failed\n");
        goto err_handler;
    }
    printf("Data transfer over DTLS succeeded\n");
    SSL_shutdown(ssl);
    SSL_free(ssl);
    SSL_CTX_free(ctx);
    close(fd);

    return 0;
err_handler:
    if (ssl) {
        SSL_free(ssl);
    }
    SSL_CTX_free(ctx);
    close(fd);
    return -1;
}

int main()
{
    printf("OpenSSL version: %s, %s\n", OpenSSL_version(OPENSSL_VERSION), OpenSSL_version(OPENSSL_BUILT_ON));
    if (dtls12_client()) {
        printf("DTLS12 client connection failed\n");
        return -1;
    }
    return 0;
}
