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
#include "openssl/err.h"

#include "test_common.h"

#define CAFILE1 EC256_CAFILE1
#define CAFILE2 RAS2048_PSS_PSS_CAFILE1

int load_ca_cert(SSL_CTX *ctx, const char *ca_file)
{
    if (SSL_CTX_load_verify_locations(ctx, ca_file, NULL) != 1) {
        printf("Load CA cert %s failed\n", ca_file);
        return -1;
    }

    printf("Loaded cert %s on context\n", ca_file);
    return 0;
}

int g_kexch_groups[] = {
    NID_X9_62_prime256v1,   /* secp256r1 */
    NID_secp384r1,          /* secp384r1 */
    NID_secp521r1,          /* secp521r1 */
    NID_X25519,             /* x25519 */
    NID_X448                /* x448 */
};

SSL_CTX *create_context()
{
    SSL_CTX *ctx;

    ctx = SSL_CTX_new(TLS_client_method());
    if (!ctx) {
        printf("SSL ctx new failed\n");
        return NULL;
    }

    printf("SSL context created\n");

    if (load_ca_cert(ctx, CAFILE1) || load_ca_cert(ctx, CAFILE2)) {
        goto err_handler;
    }

    if (SSL_CTX_set_ciphersuites(ctx, TLS1_3_RFC_CHACHA20_POLY1305_SHA256) != 1) {
        printf("Setting TLS1.3 cipher suite failed\n");
        goto err_handler;
    }
    printf("Setting TLS1.3 cipher suite succeeded\n");

    if (SSL_CTX_set_cipher_list(ctx, TLS1_TXT_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256) != 1) {
        printf("Setting TLS1.2 cipher suite failed\n");
        goto err_handler;
    }
    printf("Setting TLS1.2 cipher suite succeeded\n");

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

int tls13_client()
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
        if (SSL_get_error(ssl, ret) == SSL_ERROR_SSL) {
            get_error();
        }
        goto err_handler;
    }
    printf("SSL connect succeeded\n");

    printf("Negotiated Cipher suite:%s\n", SSL_CIPHER_get_name(SSL_get_current_cipher(ssl)));
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
    if (tls13_client()) {
        printf("TLS12 client connection failed\n");
        fflush(stdout);
        return -1;
    }
    return 0;
}
