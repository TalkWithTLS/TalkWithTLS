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

int g_conf_tlsver;

int g_kexch_groups[] = {
    //NID_X9_62_prime256v1,   /* secp256r1 */
    //NID_secp384r1,          /* secp384r1 */
    NID_secp521r1,          /* secp521r1 */
    //NID_X25519,             /* x25519 */
    NID_X448                /* x448 */
};

void update_ver(SSL_CTX *ctx)
{
    switch(g_conf_tlsver) {
        case 13:
            printf("Enabled TLS1.3\n");
            /* By default TLS1.3 is enabled */
            break;
        case 12:
            printf("Enabled TLS1.2\n");
            SSL_CTX_set_options(ctx, SSL_OP_NO_TLSv1_3);
            break;
    }
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

    update_ver(ctx);

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

int tls13_server(int con_count)
{
    SSL_CTX *ctx;
    SSL *ssl = NULL;
    int lfd = -1, fd = -1;
    int ret;
    int i;

    ctx = create_context();
    if (!ctx) {
        return -1;
    }

    lfd = do_tcp_listen(SERVER_IP, SERVER_PORT);
    if (lfd < 0) {
        goto err_handler;
    }

    for (i = 0; i < con_count; i++) {
        ssl = create_ssl_object(ctx, lfd);
        if (!ssl) {
            goto err_handler;
        }

        fd = SSL_get_fd(ssl);

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
        printf("Data transfer over TLS succeeded\n\n");
        SSL_shutdown(ssl);
        SSL_free(ssl);
        ssl = NULL;
        close(fd);
        fd = -1;
    }

    close(lfd);
    SSL_CTX_free(ctx);
    return 0;
err_handler:
    if (ssl) {
        SSL_free(ssl);
    }
    SSL_CTX_free(ctx);
    close(fd);
    close(lfd);
    return -1;
}

int main(int argc, char *argv[])
{
    if (argc > 1) {
        g_conf_tlsver = atoi(argv[1]);
    }
    printf("OpenSSL version: %s, %s\n", OpenSSL_version(OPENSSL_VERSION), OpenSSL_version(OPENSSL_BUILT_ON));
    if (tls13_server(2)) {
        printf("TLS12 server connection failed\n");
        return -1;
    }
    return 0;
}

