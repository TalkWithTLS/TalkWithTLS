#include "test_openssl_common.h"

#include "openssl/crypto.h"
#include "openssl/ssl.h"

int do_openssl_init(TC_CONF *conf)
{
    (void)conf;
    printf("OpenSSL version: %s, %s\n", OpenSSL_version(OPENSSL_VERSION), OpenSSL_version(OPENSSL_BUILT_ON));
    return 0;
}

void do_openssl_fini(TC_CONF *conf)
{
    return;
}

void init_tc_conf(TC_CONF *conf)
{
    memset(conf, 0, sizeof(TC_CONF));
    conf->tcp_listen_fd = conf->fd = -1;
}

SSL_CTX *create_context_openssl(TC_CONF *conf)
{
    const SSL_METHOD *meth;
    SSL_CTX *ctx;
    int i;

    meth = conf->server ? TLS_server_method() : TLS_client_method();

    ctx = SSL_CTX_new(meth);
    if (!ctx) {
        printf("SSL ctx new failed\n");
        return NULL;
    }

    printf("SSL context created\n");

    if (conf->cafiles_count) {
        for (i = 0; i < conf->cafiles_count; i++) {
            if (SSL_CTX_load_verify_locations(ctx, conf->cafiles[i], NULL) != 1) {
                printf("Load CA cert [%s] failed\n", conf->cafiles[i]);
                goto err_handler;
            }
            printf("Loaded cert %s on context\n", conf->cafiles[i]);
        }
    }
    if (conf->cert) {
        if (SSL_CTX_use_certificate_file(ctx, conf->cert, conf->cert_type) != 1) {
            printf("Load Server cert %s failed\n", conf->cert);
            goto err_handler;
        }

        printf("Loaded server cert %s on context\n", conf->cert);
    }

    if (conf->priv_key) {
        if (SSL_CTX_use_PrivateKey_file(ctx, conf->priv_key, conf->priv_key_type) != 1) {
            printf("Load Server key %s failed\n", conf->priv_key);
            goto err_handler;
        }

        printf("Loaded server key %s on context\n", conf->priv_key);
    }

    SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER, NULL);
    SSL_CTX_set_verify_depth(ctx, 5);

    printf("SSL context configurations completed\n");

    return ctx;
err_handler:
    SSL_CTX_free(ctx);
    return NULL;
}

SSL *create_ssl_object_openssl(TC_CONF *conf, SSL_CTX *ctx)
{
    SSL *ssl;

    if (conf->server) {
        conf->tcp_listen_fd = do_tcp_listen(SERVER_IP, SERVER_PORT);
        if (conf->tcp_listen_fd < 0) {
            return NULL;
        }

        conf->fd = do_tcp_accept(conf->tcp_listen_fd);
        if (conf->fd < 0) {
            printf("TCP connection establishment failed\n");
            return NULL;
        }
    } else {
        conf->fd = do_tcp_connection(SERVER_IP, SERVER_PORT);
        if (conf->fd < 0) {
            printf("TCP connection establishment failed\n");
            return NULL;
        }
    }

    ssl = SSL_new(ctx);
    if (!ssl) {
        printf("SSL object creation failed\n");
        return NULL; 
    }

    SSL_set_fd(ssl, conf->fd);

    if (conf->kexch_groups && conf->kexch_groups_count) {
        if (SSL_set1_groups(ssl, conf->kexch_groups, conf->kexch_groups_count) != 1) {
            printf("Set Groups failed\n");
            goto err_handler;
        }
    }

    printf("SSL object creation finished\n");

    return ssl;
err_handler:
    SSL_free(ssl);
    return NULL;
}

int do_ssl_accept(TC_CONF *conf, SSL *ssl)
{
    int ret;
    ret = SSL_accept(ssl); 
    if (ret != 1) {
        printf("SSL accept failed%d\n", ret);
        return -1;
    }
    printf("SSL accept succeeded\n");
    return 0;
}

int do_ssl_connect(TC_CONF *conf, SSL *ssl)
{
    int ret;
    ret = SSL_connect(ssl);
    if (ret != 1) {
        printf("SSL connect failed%d\n", ret);
        return -1;
    }
    printf("SSL connect succeeded\n");
    return 0;
}

int do_ssl_handshake(TC_CONF *conf, SSL *ssl)
{
    if (conf->server) {
        return do_ssl_accept(conf, ssl);
    } else {
        return do_ssl_connect(conf, ssl);
    }
}

int do_data_transfer_client(TC_CONF *conf, SSL *ssl)
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

int do_data_transfer_server(TC_CONF *conf, SSL *ssl)
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

int do_data_transfer(TC_CONF *conf, SSL *ssl)
{
    if (conf->server) {
        return do_data_transfer_server(conf, ssl);
    } else {
        return do_data_transfer_client(conf, ssl);
    }
}

void do_cleanup_openssl(TC_CONF *conf, SSL_CTX *ctx, SSL *ssl)
{
    if (ssl) {
        SSL_free(ssl);
    }
    check_and_close(&conf->fd);
    if (conf->server) {
        check_and_close(&conf->tcp_listen_fd);
    }
    if (ctx) {
        SSL_CTX_free(ctx);
    }
}

int do_test_openssl(TC_CONF *conf)
{
    SSL_CTX *ctx;
    SSL *ssl = NULL;
    int ret_val = -1;

    if (do_openssl_init(conf)) {
        printf("Openssl init failed\n");
        return -1;
    }

    ctx = create_context_openssl(conf);
    if (!ctx) {
        printf("SSl context creation failed\n");
        return -1;
    }

    ssl = create_ssl_object_openssl(conf, ctx);
    if (!ssl) {
        printf("SSl context object failed\n");
        goto err_handler;
    }

    if (do_ssl_handshake(conf, ssl)) {
        printf("SSL handshake failed\n");
        goto err_handler;
    }

    if (do_data_transfer(conf, ssl)) {
        printf("Data transfer over TLS failed\n");
        goto err_handler;
    }
    printf("Data transfer over TLS succeeded\n");
    SSL_shutdown(ssl);
    ret_val = 0;
err_handler:
    do_cleanup_openssl(conf, ctx, ssl);
    do_openssl_fini(conf);
    return ret_val;
}
