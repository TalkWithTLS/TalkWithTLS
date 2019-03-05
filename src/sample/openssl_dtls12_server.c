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

#define SERVER_CERT_FILE "./certs/ECC_Prime256_Certs/serv_cert.pem"
#define SERVER_KEY_FILE "./certs/ECC_Prime256_Certs/serv_key.der"
#define EC_CURVE_NAME NID_X9_62_prime256v1

/* 
 * Cookie key is needed to generate strongly and regenerate periodically.
 * For example regenerate every 8 hours
 */
char g_cookie_key[] = "1111222233334444";

/*
 * Generate cookie by below step
 * 1) Generate hash of peer info (Here peer sock addr is used, any more 
 * information also can be added).
 * 2) Encrypt with a cookie key.
 * 3) Need to periodically regenerate the cookie key
 */
int dtls_cookie_generate_cb(SSL *ssl, unsigned char *cookie, unsigned int *cookie_len)
{
    BIO_ADDR *peer_addr = NULL;
    int ret_val = 0;
    BIO *bio;
    uint8_t digest[SHA256_DIGEST_LENGTH] = {0};
    uint32_t digest_len = sizeof(digest);

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
    if (!EVP_Digest(peer_addr, sizeof(struct sockaddr_in), digest, &digest_len, EVP_sha256(), NULL)) {
        printf("Digest gen failed\n");
        goto err;
    }
    memcpy(cookie, "abcd", strlen("abcd"));
    *cookie_len = strlen("abcd");
    printf("Generated cookie\n");
    ret_val = 1;
err:
    if (peer_addr) {
        BIO_ADDR_free(peer_addr);
    }
    return ret_val;
}

int dtls_cookie_verify_cb(SSL *ssl, const unsigned char *cookie, unsigned int cookie_len)
{
    if (memcmp(cookie, "abcd", strlen("abcd"))) {
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

    printf("SSL object creation finished\n");

    return ssl;
err_handler:
    SSL_free(ssl);
    return NULL;
}

int do_data_transfer(SSL *ssl)
{
    const char *msg = MSG_FOR_OPENSSL_SERV;
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
        close(fd);
        SSL_free(ssl);
    }
    if (ctx) {
        SSL_CTX_free(ctx);
    }
}

int tls12_server()
{
    SSL_CTX *ctx;
    SSL *ssl = NULL;
    int ret_val = -1;
    int ret;

    ctx = create_context();
    if (!ctx) {
        return -1;
    }

    ssl = create_ssl_object(ctx, SERVER_IP, SERVER_PORT);
    if (!ssl) {
        goto err_handler;
    }

    ret = SSL_accept(ssl); 
    if (ret != 1) {
        printf("SSL accept failed%d\n", ret);
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
    if (tls12_server()) {
        printf("TLS12 server connection failed\n");
        return -1;
    }
    return 0;
}

