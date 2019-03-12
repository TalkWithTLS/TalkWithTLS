#include "test_openssl_common.h"
#include "test_openssl_resumption.h"

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

    if (conf->server == 0) {
        SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER, NULL);
    }
    SSL_CTX_set_verify_depth(ctx, 5);
    /*if (SSL_CTX_set_session_id_context(ctx, SSL_SESS_ID_CTX, strlen(SSL_SESS_ID_CTX)) != 1) {
        printf("Set sess id ctx failed\n");
        goto err_handler;
    }*/

    if ((conf->resumption) && (initialize_resumption_params(conf, ctx) != 0)) {
        printf("Initializing resumption params failed\n");
        goto err_handler;
    }
    printf("SSL context configurations completed\n");

    return ctx;
err_handler:
    SSL_CTX_free(ctx);
    return NULL;
}

void ssl_info_cb(const SSL *ssl, int type, int val)
{
    printf("SSL Info cb: type=%d, val=%d\n", type, val);
}

const char *get_handshake_msg_type(const void *buf, size_t len)
{
    if (len < 1) {
        return "Handshake zero len";
    }
    switch (*((uint8_t *)buf)) {
        case SSL3_MT_HELLO_REQUEST:
            return "Hello Request";
        case SSL3_MT_CLIENT_HELLO:
            return "Client Hello";
        case SSL3_MT_SERVER_HELLO:
            return "Server Hello";
        case SSL3_MT_NEWSESSION_TICKET:
            return "New session ticket";
        case SSL3_MT_END_OF_EARLY_DATA:
            return "End of Ealy Data";
        case SSL3_MT_ENCRYPTED_EXTENSIONS:
            return "Encrypted extensions";
        case SSL3_MT_CERTIFICATE:
            return "Certificate";
        case SSL3_MT_SERVER_KEY_EXCHANGE:
            return "Server key exchange";
        case SSL3_MT_CERTIFICATE_REQUEST:
            return "Certificate Request";
        case SSL3_MT_SERVER_DONE:
            return "Server Done";
        case SSL3_MT_CERTIFICATE_VERIFY:
            return "Certificate Verify";
        case SSL3_MT_CLIENT_KEY_EXCHANGE:
            return "Client Key exchange";
        case SSL3_MT_FINISHED:
            return "Finished";
        case SSL3_MT_CERTIFICATE_URL:
            return "Certificate URL";
        case SSL3_MT_CERTIFICATE_STATUS:
            return "Certificate Status";
        case SSL3_MT_SUPPLEMENTAL_DATA:
            return "Supplemental Data";
        case SSL3_MT_NEXT_PROTO:
            return "Next Protocol";
        case SSL3_MT_MESSAGE_HASH:
            return "Message hash";
        case DTLS1_MT_HELLO_VERIFY_REQUEST:
            return "DTLS Hello Verify Request";
    }
    return "Unknown Handshake";
}

void print_content_type(int write_p, int version, int content_type, const void *buf,
                                                    size_t len, const char *prefix_str)
{
    const char *op = (write_p ? "Sent" : "Received");
    const char *cont_type = "Unknown msg";
    switch(content_type) {
        case SSL3_RT_CHANGE_CIPHER_SPEC:
            cont_type = "Change Cipher Spec";
            break;
        case SSL3_RT_ALERT:
            cont_type = "Alert";
            break;
        case SSL3_RT_HANDSHAKE:
            cont_type = get_handshake_msg_type(buf, len);
            break;
        case SSL3_RT_APPLICATION_DATA:
            cont_type = "Application";
            break;
        case SSL3_RT_HEADER:
            cont_type = "Header";
            break;
        case SSL3_RT_INNER_CONTENT_TYPE:
            cont_type = "Inner Content";
            break;
    }
    printf("%s[ver=%04X]%s %s msg[%zu]", prefix_str, version, op, cont_type, len);
}

#define MSG_CB_PREFIX "[MSG_CB]"
void ssl_msg_cb(int write_p, int version, int content_type, const void *buf, size_t len,
                                                                SSL *ssl, void *arg)
{
    int i;
    print_content_type(write_p, version, content_type, buf, len, MSG_CB_PREFIX);
    if (arg != NULL) {
        printf(":");
        for (i = 0; i < len; i++) {
            printf(" %02X", *(((uint8_t *)buf) + i));
        }
    }
    printf("\n");
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

    if (conf->cb.info_cb) {
        SSL_set_info_callback(ssl, ssl_info_cb);
    }
    if (conf->cb.msg_cb) {
        SSL_set_msg_callback(ssl, ssl_msg_cb);
        if (conf->cb.msg_cb_detailed) {
            SSL_set_msg_callback_arg(ssl, ssl_msg_cb);
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
    if (conf->resumption) { //TODO Need to improve this check for TLS1.2 resumption also
        if (SSL_session_reused(ssl)) {
            printf("SSL session reused\n");
        } else {
            printf("SSL session not reused\n");
            return -1;
        }
    }
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
