#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <errno.h>

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

    if (BIO_ctrl(bio, BIO_CTRL_DGRAM_SET_MTU, DTLS_MTU, NULL) != DTLS_MTU) {
        printf("BIO set mtu failed\n");
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

    if (SSL_set_mtu(ssl, DTLS_MTU) != DTLS_MTU) {
        printf("Setting MTU failed\n");
        goto err;
    }
    SSL_set_options(ssl, SSL_OP_NO_QUERY_MTU);
    printf("SSL object creation finished\n");

    return ssl;
err:
    SSL_free(ssl);
    return NULL;
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

int dtls12_client()
{
    SSL_CTX *ctx;
    SSL *ssl = NULL;
    int ret_val = -1;
    int ret;

    ctx = create_context();
    if (!ctx) {
        return -1;
    }

    ssl = create_ssl_object(ctx);
    if (!ssl) {
        goto err_handler;
    }

    ret = SSL_connect(ssl); 
    if (ret != 1) {
        printf("SSL connect failed%d\n", ret);
        goto err_handler;
    }
    printf("SSL connect succeeded\n");

    if (do_data_transfer(ssl)) {
        printf("Data transfer over DTLS failed\n");
        goto err_handler;
    }
    printf("Data transfer over DTLS succeeded\n");
    SSL_shutdown(ssl);
    ret_val = 0;
err_handler:
    do_cleanup(ctx, ssl);
    return ret_val;
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
