#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
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

#define CAFILE1 "./certs/ECC_Prime256_Certs/rootcert.pem"

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

SSL_CTX *create_context()
{
    SSL_CTX *ctx;

    ctx = SSL_CTX_new(TLS_client_method());
    if (!ctx) {
        printf("SSL ctx new failed\n");
        return NULL;
    }

    printf("SSL context created\n");

    if (SSL_CTX_load_verify_locations(ctx, CAFILE1, NULL) != 1) {
        printf("Load CA cert failed\n");
        goto err_handler;
    }

    printf("Loaded cert %s on context\n", CAFILE1);

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
    printf("SSL object creation finished\n");
    return ssl;
}

int do_early_data_transfer(SSL *ssl)
{
    char *msg_req = "Hello, I am client early data!";
    char buf[MAX_BUF_SIZE] = {0};
    size_t written;
    int ret;

    ret = SSL_write_early_data(ssl, msg_req, strlen(msg_req), &written);
    if (ret <= 0) {
    	printf("SSL_write_early_data failed ret=%d\n", ret);
	return -1;
    }
    printf("Early data write sucessed\n");

    ret = SSL_read(ssl, buf, sizeof(buf) - 1);
    if (ret <= 0) {
        printf("SSL_read read early data failed ret=%d\n", ret);
	return -1;
    }
    printf("Early data read '%s'\n", buf);

    return 0;
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

int tls13_client(int con_count)
{
    SSL_CTX *ctx;
    SSL *ssl = NULL;
    SSL_SESSION *prev_sess = NULL;
    int ret_val = -1;
    int fd;
    int ret;
    int i;

    for (i = 0; i < con_count; i++) {
        ctx = create_context();
        if (!ctx) {
	    return -1;
        }

	if (i < 1) {
	    ret = SSL_CTX_set_max_early_data(ctx, SSL3_RT_MAX_PLAIN_LENGTH);
	    if (ret != 1) {
	    	printf("CTX set max early data failed\n");
		goto err_handler;
	    }
	}

        ssl = create_ssl_object(ctx);
        if (!ssl) {
	    goto err_handler;
        }

        fd = SSL_get_fd(ssl);

        if (prev_sess != NULL) {
            SSL_set_session(ssl, prev_sess);
            SSL_SESSION_free(prev_sess);
            prev_sess = NULL;
        }

	if (i >= 1) {
	    if (do_early_data_transfer(ssl)) {
	        printf("Early data transfer over TLS failed\n");
	        goto err_handler;
	    }
	    printf("Early data transfer over TLS suceeded\n");
        }

        ret = SSL_connect(ssl);
        if (ret != 1) {
            printf("SSL connect failed%d\n", ret);
	    get_error();
            goto err_handler;
        }
        printf("SSL connect succeeded\n");

        if (do_data_transfer(ssl)) {
            printf("Data transfer over TLS failed\n");
            goto err_handler;
        }
        printf("Data transfer over TLS succeeded\n\n");

        prev_sess = SSL_get1_session(ssl);
        if (!prev_sess) {
            printf("SSL session is NULL\n");
            goto err_handler;
        }
        printf("SSL session backed up\n");

        SSL_shutdown(ssl);
        SSL_free(ssl);
        ssl = NULL;
	SSL_CTX_free(ctx);
	ctx = NULL;
        close(fd);
        fd = -1;
    }

    ret_val = 0;
err_handler:
    SSL_free(ssl);
    SSL_SESSION_free(prev_sess);
    SSL_CTX_free(ctx);
    close(fd);
    return ret_val;
}

int main(int argc, char *argv[])
{
    printf("OpenSSL version: %s, %s\n", OpenSSL_version(OPENSSL_VERSION), OpenSSL_version(OPENSSL_BUILT_ON));
    if (tls13_client(2)) {
        printf("TLS13 client connection failed\n");
        return -1;
    }
    return 0;
}
