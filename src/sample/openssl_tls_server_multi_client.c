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

int g_kexch_groups[] = {
    NID_X9_62_prime256v1,   /* secp256r1 */
    NID_secp384r1,          /* secp384r1 */
    NID_secp521r1,          /* secp521r1 */
    NID_X25519,             /* x25519 */
    NID_X448                /* x448 */
};

int load_cert_and_key(SSL_CTX *ctx, const char *serv_cert_pem_file, const char *serv_key_der_file)
{
    if (SSL_CTX_use_certificate_file(ctx, serv_cert_pem_file, SSL_FILETYPE_PEM) != 1) {
        printf("Load Server cert %s failed\n", serv_cert_pem_file);
        return -1;
    }

    printf("Loaded server cert %s on context\n", serv_cert_pem_file);

    if (SSL_CTX_use_PrivateKey_file(ctx, serv_key_der_file, SSL_FILETYPE_ASN1) != 1) {
        printf("Load Server key %s failed\n", serv_key_der_file);
        return -1;
    }

    printf("Loaded server key %s on context\n", serv_key_der_file);

    return 0;
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

    if (load_cert_and_key(ctx, EC256_SERVER_CERT_FILE, EC256_SERVER_KEY_FILE)) {
        goto err_handler;
    }

    if (load_cert_and_key(ctx, RSA2048_SERVER_CERT_FILE, RSA2048_SERVER_KEY_FILE)) {
        goto err_handler;
    }

    printf("SSL context configurations completed\n");

    return ctx;
err_handler:
    SSL_CTX_free(ctx);
    return NULL;
}

SSL *create_ssl_object(SSL_CTX *ctx, int lfd)
{
    SSL *ssl;
    EC_KEY *ecdh;
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

    /*if (SSL_set1_groups(ssl, g_kexch_groups, sizeof(g_kexch_groups)/sizeof(g_kexch_groups[0])) != 1) {
        printf("Set Groups failed\n");
        goto err;
    }*/

    if (SSL_set_dh_auto(ssl, 1) != 1) {
        printf("Set DH Auto failed\n");
        goto err;
    }

    ecdh = EC_KEY_new_by_curve_name(EC256_CURVE_NAME);
    if (!ecdh) {
        printf("ECDH generation failed\n");
        goto err;
    }

    SSL_set_tmp_ecdh(ssl, ecdh);
    EC_KEY_free(ecdh);
    ecdh = NULL;

    printf("SSL object creation finished\n");

    return ssl;
err:
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
        SSL_free(ssl);
        close(fd);
    }
    if (ctx) {
        SSL_CTX_free(ctx);
    }
}

void print_ssl_err()
{
    char err_buf[512] = {0};
    unsigned long error;
    const char *file;
    int line_num = 0;
    error = ERR_peek_error_line(&file, &line_num);
    ERR_error_string_n(error, err_buf, sizeof(err_buf));
    printf("SSL error[%lu][%s] on [%s:%d]\n", error, err_buf, file, line_num);
}

int tls13_server()
{
    SSL_CTX *ctx;
    SSL *ssl = NULL;
    int ret_val = -1;
    int lfd;
    int ret;

    ctx = create_context();
    if (!ctx) {
        return -1;
    }

    lfd = do_tcp_listen(SERVER_IP, SERVER_PORT);
    if (lfd < 0) {
        goto err_handler;
    }

    do {
        ssl = create_ssl_object(ctx, lfd);
        if (!ssl) {
            goto err_handler;
        }

        ret = SSL_accept(ssl); 
        if (ret != 1) {
            print_ssl_err();
            printf("SSL accept failed%d\n", ret);
            continue;
        }

        printf("SSL accept succeeded\n");

        if (do_data_transfer(ssl)) {
            printf("Data transfer over TLS failed\n");
            continue;
        }
        printf("Data transfer over TLS succeeded\n\n");
        SSL_shutdown(ssl);
        do_cleanup(NULL, ssl);
    } while (1);

    ret_val = 0;
err_handler:
    do_cleanup(ctx, ssl);
    close(lfd);
    return ret_val;
}

int main()
{
    printf("OpenSSL version: %s, %s\n", OpenSSL_version(OPENSSL_VERSION), OpenSSL_version(OPENSSL_BUILT_ON));
    if (tls13_server()) {
        printf("TLS12 server connection failed\n");
        return -1;
    }
    return 0;
}

