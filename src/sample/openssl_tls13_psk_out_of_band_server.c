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

SSL_CTX *create_context()
{
    SSL_CTX *ctx;

    ctx = SSL_CTX_new(TLS_server_method());
    if (!ctx) {
        printf("SSL ctx new failed\n");
        return NULL;
    }

    printf("SSL context created\n");
    return ctx;
}

#define PSK_ID "Client1"
#define PSK_KEY "1234567890ABCDEF"

unsigned int tls13_psk_out_of_bound_serv_cb(SSL *ssl, const char *id,
                                            unsigned char *psk,
                                            unsigned int max_psk_len)
{
    if (strcmp(PSK_ID, id) != 0) {
        printf("Unknown Client's PSK ID\n");
        goto err;
    }
    if (strlen(PSK_KEY) > max_psk_len) {
        printf("Insufficient buffer size to copy PSK_KEY\n");
        goto err;
    }
    memcpy(psk, PSK_KEY, strlen(PSK_KEY));
    return strlen(PSK_KEY);
err:
    return 0;
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
    SSL_set_psk_server_callback(ssl, tls13_psk_out_of_bound_serv_cb);
    printf("SSL object creation finished\n");
    return ssl;
}

int do_data_transfer(SSL *ssl)
{
    const char *msg_res[] = {MSG1_RES, MSG2_RES};
    const char *res;
    char buf[MAX_BUF_SIZE] = {0};
    int ret, i;
    for (i = 0; i < sizeof(msg_res)/sizeof(msg_res[0]); i++) {
        res = msg_res[i];
        ret = SSL_read(ssl, buf, sizeof(buf) - 1);
        if (ret <= 0) {
            printf("SSL_read failed ret=%d\n", ret);
            return -1;
        }
        printf("SSL_read[%d] %s\n", ret, buf);

        ret = SSL_write(ssl, res, strlen(res));
        if (ret <= 0) {
            printf("SSL_write failed ret=%d\n", ret);
            return -1;
        }
        printf("SSL_write[%d] sent %s\n", ret, res);
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
    const char *file = NULL, *func = "";
    int line= 0;
#ifdef WITH_OSSL_111
    error = ERR_get_error_line(&file, &line);
#elif defined WITH_OSSL_300
    error = ERR_get_error_all(&file, &line, &func, NULL, NULL);
#endif
    printf("Error reason=%d on [%s:%d:%s]\n", ERR_GET_REASON(error),
           file, line, func);
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

    ssl = create_ssl_object(ctx, lfd);
    check_and_close(&lfd);
    if (!ssl) {
        goto err_handler;
    }

    ret = SSL_accept(ssl); 
    if (ret != 1) {
        printf("SSL accept failed%d\n", ret);
        if (SSL_get_error(ssl, ret) == SSL_ERROR_SSL) {
            get_error();
        }
        goto err_handler;
    }

    printf("SSL accept succeeded\n");
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
    if (tls13_server()) {
        printf("TLS12 server connection failed\n");
        fflush(stdout);
        return -1;
    }
    return 0;
}

