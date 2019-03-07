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
#include "openssl/rand.h"
#include "openssl/ssl.h"

#include "test_common.h"

#define SERVER_CERT_FILE "./certs/ECC_Prime256_Certs/serv_cert.pem"
#define SERVER_KEY_FILE "./certs/ECC_Prime256_Certs/serv_key.der"
#define EC_CURVE_NAME NID_X9_62_prime256v1

/*
 * Cookie key is needed to generate strongly and regenerate periodically.
 * For example regenerate every 8 hours
 */
#define DTLS_COOKIE_KEY_SIZE 16
uint8_t g_cookie_key[DTLS_COOKIE_KEY_SIZE] =  {0};
int g_cookie_key_len = 0;

#define MAX_DTLS_COOKIE_LEN 256

int generate_cookie_key()
{
    if (RAND_bytes(g_cookie_key, sizeof(g_cookie_key)) <= 0) {
        printf("RAND bytes failed for cookie key gen\n");
        return -1;
    }
    return 0;
}

/*
 * Generate cookie by below step
 * 1) Generate hmac of peer info (Here peer sock addr is used, any more
 * information also can be added).
 * 2) Need to periodically regenerate the cookie key
 */
int dtls_cookie_generate(SSL *ssl, unsigned char *cookie, unsigned int *cookie_len)
{
    BIO_ADDR *peer_addr = NULL;
    int ret_val = -1;
    BIO *bio;

    peer_addr = BIO_ADDR_new();
    if (peer_addr == NULL) {
        printf("BIO ADDR new failed\n");
        goto err;
    }
    bio = SSL_get_rbio(ssl);
    if (bio == NULL) {
        printf("Get bio failed\n");
        goto err;
    }
    if (BIO_ctrl(bio, BIO_CTRL_DGRAM_GET_PEER, sizeof(struct sockaddr_in), peer_addr)
            != sizeof(struct sockaddr_in)) {
        printf("BIO get peer failed\n");
        goto err;
    }

    if (!HMAC(EVP_sha256(), g_cookie_key, sizeof(g_cookie_key),
                (unsigned char *)peer_addr, sizeof(struct sockaddr_in),
                cookie, cookie_len))
    {
        printf("HMAC for cookie gen failed\n");
        goto err;
    }
    ret_val = 0;
err:
    if (peer_addr) {
        BIO_ADDR_free(peer_addr);
    }
    return ret_val;
}

int dtls_cookie_generate_cb(SSL *ssl, unsigned char *cookie, unsigned int *cookie_len)
{
    if (dtls_cookie_generate(ssl, cookie, cookie_len)) {
        printf("Generate cookie failed\n");
        return 0;
    }
    printf("Generated cookie\n");
    return 1;
}

int dtls_cookie_verify_cb(SSL *ssl, const unsigned char *cookie, unsigned int cookie_len)
{
    uint8_t out[MAX_DTLS_COOKIE_LEN] = {0};
    uint32_t out_len = sizeof(out);
    if (dtls_cookie_generate(ssl, out, &out_len)) {
        printf("Generate cookie failed\n");
        return 0;
    }
    if ((cookie_len != out_len) || (memcmp(cookie, out, out_len))) {
        printf("Cookie not valid\n");
        return 0;
    }
    printf("Cookie is valid\n");
    return 1;
}

void do_cookie_conf_in_context(SSL_CTX *ctx)
{
    SSL_CTX_set_options(ctx, SSL_OP_COOKIE_EXCHANGE);
    SSL_CTX_set_cookie_generate_cb(ctx, dtls_cookie_generate_cb);
    SSL_CTX_set_cookie_verify_cb(ctx, dtls_cookie_verify_cb);
}

SSL_CTX *create_context()
{
    SSL_CTX *ctx;

    ctx = SSL_CTX_new(DTLS_server_method());
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


    do_cookie_conf_in_context(ctx);
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

int update_dtls_server_bio(SSL *ssl, const char *serv_ip, uint16_t serv_port)
{
    struct timeval recv_to;
    BIO *bio = NULL;
    int ret_val = -1;
    int fd;

    fd = create_udp_serv_sock(serv_ip, serv_port);
    if (fd < 0) {
        printf("TCP connection establishment failed\n");
        return -1;
    }

    if (enable_nonblock(fd)) {
        printf("enable nb on sockfd failed\n");
        close(fd);
        return -1;
    }

    bio = BIO_new_dgram(fd, BIO_NOCLOSE);
    if (!bio) {
        printf("BIO new failed\n");
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
    if (bio) {
        BIO_free(bio);
    }
    return ret_val;
}

SSL *create_ssl_object(SSL_CTX *ctx, const char *serv_ip, uint16_t serv_port)
{
    SSL *ssl;
    EC_KEY *ecdh;

    ssl = SSL_new(ctx);
    if (!ssl) {
        printf("SSL object creation failed\n");
        return NULL;
    }


    if (update_dtls_server_bio(ssl, SERVER_IP, SERVER_PORT)) {
        printf("Updating BIO for DTLS failed\n");
        goto err_handler;
    }

    ecdh = EC_KEY_new_by_curve_name(EC_CURVE_NAME);
    if (!ecdh) {
        printf("ECDH generation failed\n");
        goto err_handler;
    }

    SSL_set_tmp_ecdh(ssl, ecdh);
    EC_KEY_free(ecdh);
    ecdh = NULL;

    if (SSL_set_mtu(ssl, DTLS_MTU) != DTLS_MTU) {
        printf("Setting MTU failed\n");
        goto err_handler;
    }
    SSL_set_options(ssl, SSL_OP_NO_QUERY_MTU);
    printf("SSL object creation finished\n");

    return ssl;
err_handler:
    SSL_free(ssl);
    return NULL;
}

int update_fds_for_ssl_failure(SSL *ssl, int ret, int fd, fd_set *readfds, fd_set *writefds)
{
    int err;
    err = SSL_get_error(ssl, ret);
    switch (err) {
        case SSL_ERROR_WANT_READ:
            printf("SSL want read occured\n");
            FD_SET(fd, readfds);
            break;
        case SSL_ERROR_WANT_WRITE:
            printf("SSL want write occured\n");
            FD_SET(fd, writefds);
            break;
        default:
            printf("SSL operation failed with err=%d\n", err);
            return -1;
    }
    return 0;
}

int handle_data_transfer_failure(SSL *ssl, int ret)
{
    fd_set readfds, writefds;
    struct timeval timeout;
    int fd;

    fd = SSL_get_fd(ssl);
    FD_ZERO(&readfds);
    FD_ZERO(&writefds);

    if (update_fds_for_ssl_failure(ssl, ret, fd, &readfds, &writefds)) {
        printf("No need to wait on select for data transfer failure\n");
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
    const char *msg = MSG_FOR_OPENSSL_SERV;
    char buf[MAX_BUF_SIZE] = {0};
    int ret;
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
    return 0;
}

int handle_handshake_failure(SSL *ssl, int ret)
{
    fd_set readfds, writefds;
    struct timeval timeout = {0};
    int fd;

    fd = SSL_get_fd(ssl);
    FD_ZERO(&readfds);
    FD_ZERO(&writefds);

    if (update_fds_for_ssl_failure(ssl, ret, fd, &readfds, &writefds)) {
        printf("No need to wait on select for handshake failure\n");
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

int handle_listen_failure(SSL *ssl, int ret)
{
    fd_set readfds, writefds;
    int fd;

    fd = SSL_get_fd(ssl);
    FD_ZERO(&readfds);
    FD_ZERO(&writefds);

    /* SSL_get_error should not be called on DTLSv1_listen */
    /* Instead retry should be done for return value of 0 */
    if (ret != 0) {
        return -1;
    }
    FD_SET(fd, &readfds);

    /* Wait for some max timeout or wait indefinitely */
    if (select(fd + 1, &readfds, &writefds, NULL, NULL) > 0) {
        printf("Select succeeds\n");
        return 0;
    }
    printf("select failed\n");
    return -1;
}

int do_dtls_accept(SSL *ssl)
{
    BIO_ADDR *peer_addr;
    int ret;

    peer_addr = BIO_ADDR_new();
    if (!peer_addr) {
        printf("BIO ADDR new failed\n");
        return -1;
    }

    do {
        ret = DTLSv1_listen(ssl, peer_addr);
        if (ret != 1) {
            printf("Going to wait for incoming msg for doing DTLS listen\n");
            if (handle_listen_failure(ssl, ret)) {
                printf("DTLS listen failed\n");
                BIO_ADDR_free(peer_addr);
                return -1;
            }
        }
    } while (ret != 1);
    printf("DTLS listen finished\n");
    BIO_ADDR_free(peer_addr);
    do {
        ret = SSL_accept(ssl);
        if (ret == 1) {
            printf("DTLS accept succeeded\n");
            break;
        }
        printf("Check and going to wait for sock failure in DTLS accept\n");
        if (handle_handshake_failure(ssl, ret)) {
            printf("DTLS accept failed\n");
            return -1;
        }
        printf("Continue DTLS connection\n");
    } while (1);
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

int dtls12_server()
{
    SSL_CTX *ctx;
    SSL *ssl = NULL;
    int ret_val = -1;

    if (generate_cookie_key()) {
        printf("generate cookie key failed\n");
        return -1;
    }

    ctx = create_context();
    if (!ctx) {
        return -1;
    }

    ssl = create_ssl_object(ctx, SERVER_IP, SERVER_PORT);
    if (!ssl) {
        goto err_handler;
    }

    if (do_dtls_accept(ssl)) {
        printf("SSL accept failed\n");
        goto err_handler;
    }

    printf("SSL accept succeeded\n");

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
    if (dtls12_server()) {
        printf("DTLS12 server connection failed\n");
        return -1;
    }
    return 0;
}

