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

#include "test_common.h"

#define CAFILE1 "./certs/ECC_Prime256_Certs/rootcert.pem"
#define SERVER_IP "127.0.0.1"
#define SERVER_PORT 7788

int g_kexch_groups[] = {
    NID_X9_62_prime256v1,   /* secp256r1 */
    NID_secp384r1,          /* secp384r1 */
    NID_secp521r1,          /* secp521r1 */
    NID_X25519,             /* x25519 */
    NID_X448                /* x448 */
};

SSL_SESSION *g_prev_sess = NULL;
uint8_t g_ssl_sess_id[SSL_MAX_SSL_SESSION_ID_LENGTH];

int g_conf_tlsver;

int tls13_use_sess_cb(SSL *ssl, const EVP_MD *md, const unsigned char **id, size_t *idlen,
                                                                        SSL_SESSION **sess)
{
    const unsigned char *sess_id;
    uint32_t sess_id_len = 0;
    printf("Use Sess CB called\n");
    if (g_prev_sess) {
        sess_id = SSL_SESSION_get_id(g_prev_sess, &sess_id_len);
        if ((!sess_id) || (!sess_id_len)
            || (sess_id_len > SSL_MAX_SSL_SESSION_ID_LENGTH)) {
            printf("Invalid Sess ID=%p, len=%d\n", sess_id, sess_id_len);
            return 0;
        }
        memcpy(g_ssl_sess_id, sess_id, sess_id_len);
        *id = g_ssl_sess_id;
        *idlen = sess_id_len;
        SSL_SESSION_up_ref(g_prev_sess);
        *sess = g_prev_sess;
        printf("Providing PSK statless ticket for resumption\n");
        return 1;
    }
    return 0;
}

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

    ctx = SSL_CTX_new(TLS_client_method());
    if (!ctx) {
        printf("SSL ctx new failed\n");
        return NULL;
    }

    printf("SSL context created\n");

    update_ver(ctx);

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
    const char *msg = MSG_FOR_OPENSSL_CLNT;
    char buf[MAX_BUF_SIZE] = {0};
    int ret;
    ret = SSL_write(ssl, msg, strlen(msg));
    if (ret <= 0) {
        printf("SSL_write failed ret=%d\n", ret);
        return -1;
    }
    printf("SSL_write[%d] sent %s\n", ret, msg);

    ret = SSL_read(ssl, buf, sizeof(buf) - 1);
    if (ret <= 0) {
        printf("SSL_read failed ret=%d\n", ret);
        return -1;
    }
    printf("SSL_read[%d] %s\n", ret, buf);
    return 0;
}

int update_for_sess_resumption(SSL *ssl, SSL_SESSION *prev_sess)
{
    if (SSL_SESSION_get_protocol_version(prev_sess) < TLS1_3_VERSION) {
        if (SSL_set_session(ssl, prev_sess)) {
            printf("SSL session set succeeded\n");
            SSL_SESSION_free(prev_sess);
        } else {
            printf("SSL session set failed\n");
            SSL_SESSION_free(prev_sess);
            return -1;
        }
    } else {
        if (g_prev_sess) {
            SSL_SESSION_free(g_prev_sess);
        }
        g_prev_sess = prev_sess;
        SSL_set_psk_use_session_callback(ssl, tls13_use_sess_cb);
    }
    return 0;
}

int validate_sess_resumption(SSL *ssl, int *check_sess_reused)
{
    if (*check_sess_reused) {
        if (SSL_session_reused(ssl) != 1) {
            printf("SSL session not reused\n");
            return -1;
        }
        *check_sess_reused = 0;
    }
    return 0;
}

int tls13_client(int con_count)
{
    SSL_CTX *ctx;
    SSL *ssl = NULL;
    SSL_SESSION *prev_sess = NULL;
    int check_sess_reused = 0;
    int ret_val = -1;
    int fd;
    int ret;
    int i;

    ctx = create_context();
    if (!ctx) {
        return -1;
    }

    for (i = 0; i < con_count; i++) {
        ssl = create_ssl_object(ctx);
        if (!ssl) {
            goto err_handler;
        }

        fd = SSL_get_fd(ssl);

        if (prev_sess) {
            if (update_for_sess_resumption(ssl, prev_sess)) {
                goto err_handler;
            }
            prev_sess = NULL;
            check_sess_reused = 1;
        }

        ret = SSL_connect(ssl);
        if (ret != 1) {
            printf("SSL connect failed%d\n", ret);
            goto err_handler;
        }
        printf("SSL connect succeeded\n");

        if (validate_sess_resumption(ssl, &check_sess_reused)) {
            goto err_handler;
        }

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
        close(fd);
        fd = -1;
    }

    ret_val = 0;
err_handler:
    if (ssl) {
        SSL_free(ssl);
    }
    if (g_prev_sess) {
        SSL_SESSION_free(g_prev_sess);
    }
    if (prev_sess) {
        SSL_SESSION_free(prev_sess);
    }
    SSL_CTX_free(ctx);
    close(fd);
    return ret_val;
}

int main(int argc, char *argv[])
{
    if (argc > 1) {
        g_conf_tlsver = atoi(argv[1]);
    }
    printf("OpenSSL version: %s, %s\n", OpenSSL_version(OPENSSL_VERSION), OpenSSL_version(OPENSSL_BUILT_ON));
    if (tls13_client(2)) {
        printf("TLS12 client connection failed\n");
    }
}
