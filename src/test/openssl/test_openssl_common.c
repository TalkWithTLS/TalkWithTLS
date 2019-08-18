#include "test_openssl_common.h"
#include "test_openssl_sock.h"
#include "test_openssl_resumption.h"
#include "test_openssl_validation.h"
#include "test_openssl_kexch.h"
#include "test_openssl_version.h"
#include "test_openssl_crypto_mem.h"

#include "openssl/crypto.h"
#include "openssl/ssl.h"
#include "openssl/err.h"

#include <fcntl.h>

int do_openssl_init(TC_CONF *conf)
{
    (void)conf;
    printf("OpenSSL version: %s, %s\n", OpenSSL_version(OPENSSL_VERSION),
            OpenSSL_version(OPENSSL_BUILT_ON));
    if (conf->cb.crypto_mem_cb != 0) {
        CRYPTO_set_mem_functions(TWT_malloc, TWT_realloc, TWT_free);
    }
    return 0;
}

void do_openssl_fini(TC_CONF *conf)
{
    return;
}

int init_psk_params(TC_CONF *conf, const char *psk_id, const char *psk_key)
{
    if ((strlen(psk_id) >= sizeof(conf->res.psk_id))
            || (strlen(psk_key) >= sizeof(conf->res.psk_key))) {
        printf("Insufficient space in TC_CONF for storing PSK\n");
        return -1;
    }
    strcpy(conf->res.psk_id, psk_id);
    conf->res.psk_id_len = strlen(psk_id);
    strcpy(conf->res.psk_key, psk_key);
    conf->res.psk_key_len = strlen(psk_key);
    return 0;
}

int init_tc_conf(TC_CONF *conf)
{
    memset(conf, 0, sizeof(TC_CONF));
    conf->tcp_listen_fd = conf->fd = -1;
    if (init_psk_params(conf, DEFAULT_PSK_ID, DEFAULT_PSK_KEY)) {
        printf("Initializing psk params failed\n");
        return -1;
    }
    return 0;
}

void fini_tc_conf(TC_CONF *conf)
{
    if (conf->server) {
        check_and_close(&conf->tcp_listen_fd);
    }
    if (conf->res.sess) {
        SSL_SESSION_free(conf->res.sess);
        conf->res.sess = NULL;
    }
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

    if (ssl_ctx_version_conf(conf, ctx)) {
        printf("Version conf failed\n");
        goto err;
    }

    if (conf->cafiles_count) {
        for (i = 0; i < conf->cafiles_count; i++) {
            if (SSL_CTX_load_verify_locations(ctx, conf->cafiles[i], NULL) != 1) {
                printf("Load CA cert [%s] failed\n", conf->cafiles[i]);
                goto err;
            }
            printf("Loaded cert %s on context\n", conf->cafiles[i]);
        }
    }
    if (conf->cert) {
        if (SSL_CTX_use_certificate_file(ctx, conf->cert, conf->cert_type) != 1) {
            printf("Load Server cert %s failed\n", conf->cert);
            goto err;
        }

        printf("Loaded server cert %s on context\n", conf->cert);
    }

    if (conf->priv_key) {
        if (SSL_CTX_use_PrivateKey_file(ctx, conf->priv_key, conf->priv_key_type) != 1) {
            printf("Load Server key %s failed\n", conf->priv_key);
            goto err;
        }

        printf("Loaded server key %s on context\n", conf->priv_key);
    }

    if ((conf->server == 0) || (conf->auth & TC_CONF_CLIENT_CERT_AUTH)) {
        SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER|SSL_VERIFY_FAIL_IF_NO_PEER_CERT, NULL);
        printf("Configured Verify Peer\n");
    }
    SSL_CTX_set_verify_depth(ctx, 5);
    /*if (SSL_CTX_set_session_id_context(ctx, SSL_SESS_ID_CTX, strlen(SSL_SESS_ID_CTX)) != 1) {
        printf("Set sess id ctx failed\n");
        goto err;
    }*/

    if ((conf->res.psk) && (initialize_resumption_params(conf, ctx) != 0)) {
        printf("Initializing resumption params failed\n");
        goto err;
    }
    if ((conf->res.early_data) && (conf->server)) {
        SSL_CTX_set_max_early_data(ctx, MAX_EARLY_DATA_MSG);
    }
    printf("SSL context configurations completed\n");

    return ctx;
err:
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
        case SSL3_MT_KEY_UPDATE:
            return "Key Update";
        case SSL3_MT_NEXT_PROTO:
            return "Next Protocol";
        case SSL3_MT_MESSAGE_HASH:
            return "Message hash";
        case DTLS1_MT_HELLO_VERIFY_REQUEST:
            return "DTLS Hello Verify Request";
    }
    return NULL;
}

void print_content_type(int write_p, int version, int content_type, const void *buf,
                                                    size_t len, const char *prefix_str)
{
    const char *op = (write_p ? "Sent" : "Received");
    const char *cont_type = "Unknown msg";
    const char *handshake_type;
    int first_byte_val = -1;
    if (len >= 1) {
        first_byte_val = *((char*)buf);
    }
    switch(content_type) {
        case SSL3_RT_CHANGE_CIPHER_SPEC:
            cont_type = "Change Cipher Spec";
            break;
        case SSL3_RT_ALERT:
            cont_type = "Alert";
            break;
        case SSL3_RT_HANDSHAKE:
            handshake_type = get_handshake_msg_type(buf, len);
            cont_type = handshake_type ? handshake_type : "Unknown Handshake";
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
    printf("%s[ver=%04X]%s %s msg[len=%zu]", prefix_str, version, op, cont_type, len);
    if (content_type == SSL3_RT_HEADER) {
        printf(" rec_type=%d", first_byte_val);
    } else if (content_type == SSL3_RT_INNER_CONTENT_TYPE) {
        printf(" val=%d", first_byte_val);
    } else if (handshake_type == NULL) {
        printf(" type_val=%d", first_byte_val);
    }
}

#define MSG_CB_PREFIX "[MSG_CB]"
void ssl_msg_cb(int write_p, int version, int content_type, const void *buf, size_t len,
                                                                SSL *ssl, void *arg)
{
    TC_CONF *conf = SSL_get_ex_data(ssl, SSL_EX_DATA_TC_CONF);
    int i;
    print_content_type(write_p, version, content_type, buf, len, MSG_CB_PREFIX);
    if (conf->cb.msg_cb_detailed) {
        printf(":");
        for (i = 0; i < len; i++) {
            printf(" %02X", *(((uint8_t *)buf) + i));
        }
    }
    printf("\n");
}

int enable_nonblock(TC_CONF *conf)
{
    int fd = conf->fd;
    int flags;
    if (conf->nb_sock) {
        flags = fcntl(fd, F_GETFL, 0);
        if (flags == -1) {
            printf("Get flag failed for fcntl");
            return -1;
        }
        flags |= O_NONBLOCK;
        if (fcntl(fd, F_SETFL, flags) != 0) {
            printf("Set nonblock flags on fcntl failed\n");
            return -1;
        }
    }
    return 0;
}

SSL *create_ssl_object_openssl(TC_CONF *conf, SSL_CTX *ctx)
{
    SSL *ssl;

    if (create_sock_connection(conf)) {
        return NULL;
    }

    ssl = SSL_new(ctx);
    if (!ssl) {
        printf("SSL object creation failed\n");
        return NULL; 
    }
    SSL_set_ex_data(ssl, SSL_EX_DATA_TC_CONF, conf);
    SSL_set_fd(ssl, conf->fd);

    if (ssl_kexch_config(conf, ssl)) {
        printf("SSL kexch conf failed\n");
        goto err;
    }

    if (enable_nonblock(conf)) {
        printf("Enable non block failed");
        goto err;
    }
    if (conf->cb.info_cb) {
        SSL_set_info_callback(ssl, ssl_info_cb);
    }
    if (conf->cb.msg_cb) {
        SSL_set_msg_callback(ssl, ssl_msg_cb);
    }
    printf("SSL object creation finished\n");

    return ssl;
err:
    SSL_free(ssl);
    return NULL;
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

int wait_for_sock_io(SSL *ssl, int ret, const char *op)
{
    fd_set readfds, writefds;
    struct timeval timeout;
    int err;
    int fd;

    fd = SSL_get_fd(ssl);
    FD_ZERO(&readfds);
    FD_ZERO(&writefds);

    err = SSL_get_error(ssl, ret);
    switch (err) {
        case SSL_ERROR_WANT_READ:
            printf("SSL want read occured for %s\n", op);
            FD_SET(fd, &readfds);
            break;
        case SSL_ERROR_WANT_WRITE:
            printf("SSL want write occured for %s\n", op);
            FD_SET(fd, &writefds);
            break;
        default:
            printf("%s failed with err=%d\n", op, err);
            if (err == SSL_ERROR_SSL) {
                print_ssl_err();
            }
            return -1;
    }
    timeout.tv_sec = TLS_SOCK_TIMEOUT_MS / 1000;
    timeout.tv_usec = (TLS_SOCK_TIMEOUT_MS % 1000) * 1000;
    if (select(fd + 1, &readfds, &writefds, NULL, &timeout) < 1) {
        printf("select timed out, ret=%d\n", ret);
        return -1;
    }
    printf("Time spent on select %ldsecs and %ldusecs\n", timeout.tv_sec, timeout.tv_usec);
    return 0;
}

int do_ssl_accept(TC_CONF *conf, SSL *ssl)
{
    int ret;
    do {
        ret = SSL_accept(ssl);
        if (ret == 1) {
            printf("SSL accept succeeded\n");
            break;
        }
        if (wait_for_sock_io(ssl, ret, "SSL_accept")) {
            printf("SSL accept failed\n");
            return -1;
        }
        printf("Continue SSL accept\n");
    } while (1);
    if (conf->res.resumption) { //TODO Need to improve this check for TLS1.2 resumption also
        if (SSL_session_reused(ssl)) {
            printf("SSL session reused\n");
        } else {
            printf("SSL session not reused\n");
            return -1;
        }
    }
    return 0;
}

int do_ssl_write_early_data(TC_CONF *conf, SSL *ssl)
{
    const char *msg = EARLY_DATA_MSG_FOR_OPENSSL_CLNT;
    size_t sent = 0;
    int ret = 0;
    if ((conf->res.early_data != 1) && (conf->res.early_data_sent == 0)) {
        ret = SSL_write_early_data(ssl, msg, strlen(msg), &sent);
        printf("write early data ret=%d\n", ret);
    }
    return ret > 0 ? 0 : -1;
}

int do_ssl_connect(TC_CONF *conf, SSL *ssl)
{
    int ret;

    do {
        ret = SSL_connect(ssl);
        if (ret == 1) {
            printf("SSL connect succeeded\n");
            break;
        }
        if (wait_for_sock_io(ssl, ret, "SSL_connect")) {
            printf("SSL connect failed\n");
            return -1;
        }
        printf("Continue SSL connection\n");
    } while (1);
    return 0;
}

int do_handshake(TC_CONF *conf, SSL *ssl)
{
    int ret;
    do {
        ret = SSL_do_handshake(ssl);
        if (ret == 1) {
            printf("SSL handshake succeeded\n");
            break;
        }
        if (wait_for_sock_io(ssl, ret, "SSL_do_handshake")) {
            printf("SSL handshake failed\n");
            return -1;
        }
        printf("Continue SSL_handshake\n");
    } while (1);
    return 0;
}

int do_ssl_handshake(TC_CONF *conf, SSL *ssl)
{
    printf("###Doing SSL handshake\n");
    int ret;
    if (conf->server) {
        ret = do_ssl_accept(conf, ssl);
    } else {
        ret = do_ssl_connect(conf, ssl);
    }
    if (ret) return ret;
    return do_after_handshake_validation(conf, ssl);
}

int do_ssl_read(TC_CONF *conf, SSL *ssl)
{
    char buf[MAX_BUF_SIZE] = {0};
    const char *msg_for_cmp;
    int ret;

    msg_for_cmp = conf->server ? MSG_FOR_OPENSSL_CLNT : MSG_FOR_OPENSSL_SERV;
    do {
        ret = SSL_read(ssl, buf, sizeof(buf) - 1);
        if (ret > 0) {
            break;
        }
        if (wait_for_sock_io(ssl, ret, "SSL_read")) {
            printf("SSL read failed\n");
            return -1;
        }
    } while (1);
    printf("SSL_read[%d] %s\n", ret, buf);
    if (memcmp(buf, msg_for_cmp, strlen(msg_for_cmp))) {
        printf("Invalid msg received\n");
    }
    return 0;
}

int do_ssl_write(TC_CONF *conf, SSL *ssl)
{
    const char *msg;
    int ret;

    msg = conf->server ? MSG_FOR_OPENSSL_SERV : MSG_FOR_OPENSSL_CLNT;
    do {
        ret = SSL_write(ssl, msg, strlen(msg));
        if (ret == strlen(msg)) {
            break;
        }
        if (wait_for_sock_io(ssl, ret, "SSL_write")) {
            printf("SSL write failed\n");
            return -1;
        }
    } while (1);
    printf("SSL_write[%d] sent %s\n", ret, msg);
    return 0;
}

int do_data_transfer_client(TC_CONF *conf, SSL *ssl)
{
    if ((do_ssl_write(conf, ssl) != 0)
            || (do_ssl_read(conf, ssl) != 0)) {
        printf("Data transfer failed\n");
        return -1;
    }
    return 0;
}

int do_data_transfer_server(TC_CONF *conf, SSL *ssl)
{
    if ((do_ssl_read(conf, ssl) != 0)
            || (do_ssl_write(conf, ssl) != 0)) {
        printf("Data transfer failed\n");
        return -1;
    }
    return 0;
}

int do_data_transfer(TC_CONF *conf, SSL *ssl)
{
    printf("### Doing Data transfer\n");
    if (conf->server) {
        return do_data_transfer_server(conf, ssl);
    } else {
        return do_data_transfer_client(conf, ssl);
    }
}

int do_key_update(TC_CONF *conf, SSL *ssl, int type)
{
    printf("### Doing Key update\n");
    if (SSL_version(ssl) != TLS1_3_VERSION) {
        printf("Key update for non TLS13 version=%#x\n", SSL_version(ssl));
        return -1;
    }
    if (SSL_key_update(ssl, type) != 1) {
        printf("Key update failed\n");
        return -1;
    }
    if (do_handshake(conf, ssl)) {
        printf("Do handshake after key update failed\n");
        return -1;
    }
    printf("Do handshake after key update succeeded\n");
    printf("Key update Request (type=%d) done\n", type);
    return 0;
}

int check_and_do_key_update(TC_CONF *conf, SSL *ssl)
{
    int key_update = 0;
    int key_update_type = -1;
    if (((conf->ku.key_update_test == TC_CONF_KEY_UPDATE_REQ_ON_SERVER) && (conf->server == 1))
            || ((conf->ku.key_update_test == TC_CONF_KEY_UPDATE_REQ_ON_CLIENT) && (conf->server == 0))
            || ((conf->ku.key_update_test == TC_CONF_KEY_UPDATE_NREQ_ON_SERVER) && (conf->server == 1))
            || ((conf->ku.key_update_test == TC_CONF_KEY_UPDATE_NREQ_ON_CLIENT) && (conf->server == 0))) {
        key_update = 1;
    }
    switch (conf->ku.key_update_test) {
        case TC_CONF_KEY_UPDATE_REQ_ON_SERVER:
        case TC_CONF_KEY_UPDATE_REQ_ON_CLIENT:
            key_update_type = SSL_KEY_UPDATE_REQUESTED;
            break;
        case TC_CONF_KEY_UPDATE_NREQ_ON_SERVER:
        case TC_CONF_KEY_UPDATE_NREQ_ON_CLIENT:
            key_update_type = SSL_KEY_UPDATE_NOT_REQUESTED;
            break;
    }
    if (key_update) {
        if (do_key_update(conf, ssl, key_update_type)) {
            printf("Keyupdate failed\n");
            return -1;
        }
    }
    return 0;
}

int do_key_update_test(TC_CONF *conf, SSL *ssl)
{
    if (conf->ku.key_update_test == 0) {
        /* Key update testing is not configured */
        return 0;
    }
    if (check_and_do_key_update(conf, ssl)) {
        printf("Checking and doing key update failed\n");
        return -1;
    }
    if (do_data_transfer(conf, ssl)) {
        printf("Data transfer failed\n");
        return -1;
    }
    return 0;
}

void do_cleanup_openssl(TC_CONF *conf, SSL_CTX *ctx, SSL *ssl)
{
    if (ssl) {
        SSL_free(ssl);
    }
    check_and_close(&conf->fd);
    if (ctx) {
        SSL_CTX_free(ctx);
    }
}

int do_test_tls_connection(TC_CONF *conf)
{
    SSL_CTX *ctx;
    SSL *ssl = NULL;
    int ret_val = -1;

    conf->con_count++;
    ctx = create_context_openssl(conf);
    if (!ctx) {
        printf("SSl context creation failed\n");
        return -1;
    }

    ssl = create_ssl_object_openssl(conf, ctx);
    if (!ssl) {
        printf("SSl context object failed\n");
        goto err;
    }

    if (do_ssl_handshake(conf, ssl)) {
        printf("SSL handshake failed\n");
        goto err;
    }

    if (do_data_transfer(conf, ssl)) {
        printf("Data transfer over TLS failed\n");
        goto err;
    }
    printf("Data transfer over TLS succeeded\n");
    if (do_key_update_test(conf, ssl)) {
        printf("Key update testing failed\n");
        goto err;
    }
    if (conf->server == 0) {
        /* Store SSL session for resumption */
        conf->res.sess = SSL_get1_session(ssl);
    }
    SSL_shutdown(ssl);
    ret_val = 0;
err:
    do_cleanup_openssl(conf, ctx, ssl);
    return ret_val;
}

int do_test_early_data(TC_CONF *conf)
{
    SSL_CTX *ctx;
    SSL *ssl = NULL;
    int ret_val = -1;

    if (conf->res.early_data == 0) {
        return 0;
    }

    conf->con_count++;
    ctx = create_context_openssl(conf);
    if (!ctx) {
        printf("SSl context creation failed\n");
        return -1;
    }

    ssl = create_ssl_object_openssl(conf, ctx);
    if (!ssl) {
        printf("SSl context object failed\n");
        goto err;
    }

    if (conf->server == 0) {
        if (conf->res.sess == NULL) {
            printf("Sess is not available for doing early data\n");
            goto err;
        }
        SSL_set_session(ssl, conf->res.sess);
        /* On client send early data during handshake */
        /*if (do_ssl_write_early_data(conf, ssl)) {
            printf("Write early data failed\n");
            goto err;
        }*/
        if (do_ssl_handshake(conf, ssl)) {
            printf("SSL handshake failed\n");
            goto err;
        }
    } else {
        /* On server do normal handshake */
        if (do_ssl_handshake(conf, ssl)) {
            printf("SSL handshake failed\n");
            goto err;
        }
    }
    if (do_data_transfer(conf, ssl)) {
        printf("Data transfer over TLS failed\n");
        goto err;
    }
    printf("Data transfer over TLS succeeded\n");
    ret_val = 0;
err:
    do_cleanup_openssl(conf, ctx, ssl);
    return ret_val;
}

int do_test_openssl(TC_CONF *conf)
{
    int ret_val = -1;

    if (create_listen_sock(conf)) {
        return -1;
    }
    if (do_openssl_init(conf)) {
        printf("Openssl init failed\n");
        return -1;
    }
    if (do_test_tls_connection(conf)) {
        goto err;
    }
    if (do_test_early_data(conf)) {
        goto err;
    }
    ret_val = 0;
err:
    do_openssl_fini(conf);
    return ret_val;
}
