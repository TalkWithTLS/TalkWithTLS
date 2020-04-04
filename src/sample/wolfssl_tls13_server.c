#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <errno.h>

#include "wolfssl/options.h"
#include "wolfssl/wolfcrypt/settings.h"
#include "wolfssl/ssl.h"

#include "test_common.h"

#define SERVER_CERT_FILE "./certs/ECC_Prime256_Certs/serv_cert.pem"
#define SERVER_KEY_FILE "./certs/ECC_Prime256_Certs/serv_key.der"

int g_kexch_groups[] = {
    WOLFSSL_FFDHE_2048,
    WOLFSSL_ECC_SECP256R1
};

void ssl_init()
{
    printf("wolfSSL Version: %s\n", LIBWOLFSSL_VERSION_STRING);
    wolfSSL_Init();
}

void ssl_fini()
{
    wolfSSL_Cleanup();
}

void *create_ssl_context()
{
    WOLFSSL_CTX *ctx;

    ctx = wolfSSL_CTX_new(wolfTLSv1_3_server_method_ex(NULL));
    if (!ctx) {
        printf("wolfSSL ctx new failed\n");
        return NULL;
    }

    printf("wolfSSL context created\n");

    if (wolfSSL_CTX_use_certificate_file(ctx, SERVER_CERT_FILE, WOLFSSL_FILETYPE_PEM) != 1) {
        printf("Load Server cert %s failed\n", SERVER_CERT_FILE);
        goto err_handler;
    }

    printf("Loaded server cert %s on context\n", SERVER_CERT_FILE);

    if (wolfSSL_CTX_use_PrivateKey_file(ctx, SERVER_KEY_FILE, SSL_FILETYPE_ASN1) != 1) {
        printf("Load Server key %s failed\n", SERVER_KEY_FILE);
        goto err_handler;
    }

    printf("Loaded server key %s on context\n", SERVER_KEY_FILE);

    printf("wolfSSL context configurations completed\n");

    return ctx;
err_handler:
    wolfSSL_CTX_free(ctx);
    return NULL;
}

void *create_ssl_object(void *ctx_in, int lfd)
{
    WOLFSSL_CTX *ctx = (WOLFSSL_CTX *)ctx_in;
    WOLFSSL *ssl;
    int fd;
    int i;

    fd = do_tcp_accept(lfd);
    if (fd < 0) {
        printf("TCP connection establishment failed\n");
        return NULL;
    }

    ssl = wolfSSL_new(ctx);
    if (!ssl) {
        printf("SSL object creation failed\n");
        return NULL;
    }

    wolfSSL_set_fd(ssl, fd);

    for (i = 0; i < (int)(sizeof(g_kexch_groups)/sizeof(g_kexch_groups[0])); i++) {
        if (wolfSSL_UseSupportedCurve(ssl, g_kexch_groups[i]) != 1) {
            printf("Set supported group %d failed\n", g_kexch_groups[i]);
            goto err_handler;
        }
        if (wolfSSL_UseKeyShare(ssl, g_kexch_groups[i]) != 1) {
            printf("Use key share for group %d failed\n", g_kexch_groups[i]);
            goto err_handler;
        }
    }

    printf("SSL object creation finished\n");

    return ssl;
err_handler:
    wolfSSL_free(ssl);
    return NULL;
}

int do_data_transfer(void *ssl_in)
{
    WOLFSSL *ssl = (WOLFSSL *)ssl_in;
    const char *msg_res[] = {MSG1_RES, MSG2_RES};
    const char *res;
    char buf[MAX_BUF_SIZE] = {0};
    int ret, i;
    for (i = 0; i < sizeof(msg_res)/sizeof(msg_res[0]); i++) {
        res = msg_res[i];
        ret = wolfSSL_read(ssl, buf, sizeof(buf) - 1);
        if (ret <= 0) {
            printf("wolfSSL_read failed ret=%d\n", ret);
            return -1;
        }
        printf("wolfSSL_read[%d] %s\n", ret, buf);

        ret = wolfSSL_write(ssl, res, strlen(res));
        if (ret <= 0) {
            printf("wolfSSL_write failed ret=%d\n", ret);
            return -1;
        }
        printf("wolfSSL_write[%d] sent %s\n", ret, res);
    }
    return 0;
}

void do_cleanup(void *ctx_in, void *ssl_in)
{
    WOLFSSL_CTX *ctx = (WOLFSSL_CTX *)ctx_in;
    WOLFSSL *ssl = (WOLFSSL *)ssl_in;
    int fd;
    if (ctx) {
        wolfSSL_CTX_free(ctx);
    }
    if (ssl) {
        fd = wolfSSL_get_fd(ssl);
        wolfSSL_free(ssl);
        close(fd);
    }
}

int tls13_server()
{
    void *ctx;
    void *ssl = NULL;
    int ret_val = -1;
    int lfd = -1;
    int ret;

    ssl_init();

    ctx = create_ssl_context();
    if (!ctx) {
        return -1;
    }

    lfd = do_tcp_listen(SERVER_IP, SERVER_PORT);
    if (lfd < 0) {
        goto err_handler;
    }

    ssl = create_ssl_object(ctx, lfd);
    check_and_close(&lfd);
    if (!ssl) {
        goto err_handler;
    }

    ret = wolfSSL_accept(ssl); 
    if (ret != 1) {
        printf("wolfSSL accept failed%d\n", ret);
        goto err_handler;
    }

    printf("wolfSSL accept succeeded\n");

    if (do_data_transfer(ssl)) {
        printf("Data transfer over TLS failed\n");
        goto err_handler;
    }
    printf("Data transfer over TLS succeeded\n");
    wolfSSL_shutdown(ssl);

    ret_val = 0;
err_handler:
    do_cleanup(ctx, ssl);
    ssl_fini();
    return ret_val;
}

int main()
{
    if (tls13_server()) {
        printf("TLS13 server connection failed\n");
        fflush(stdout);
        return -1;
    }
    return 0;
}

