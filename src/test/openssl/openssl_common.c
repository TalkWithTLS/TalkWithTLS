#include "openssl_common.h"
#include "test_init.h"
#include "openssl_resumption.h"
#include "openssl_validation.h"
#include "openssl_kexch.h"
#include "openssl_version.h"
#include "openssl_crypto_mem.h"
#include "openssl_ssl_mode.h"
#include "openssl_keyupdate.h"
#include "openssl_dtls.h"
#include "openssl_msg_cb.h"

#include "openssl/crypto.h"
#include "openssl/ssl.h"
#include "openssl/err.h"

#include <fcntl.h>

int do_openssl_init(TC_CONF *conf)
{
    (void)conf;
    DBG("OpenSSL version: %s, %s\n", OpenSSL_version(OPENSSL_VERSION),
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

void fini_tc_conf_for_openssl(TC_CONF *conf)
{
    if (conf->res.sess) {
        SSL_SESSION_free(conf->res.sess);
        conf->res.sess = NULL;
    }
}

int init_tc_conf_for_openssl(TC_CONF *conf)
{
    conf->fini = fini_tc_conf_for_openssl;
    return 0;
}

SSL_CTX *create_context_openssl(TC_CONF *conf)
{
    const SSL_METHOD *meth;
    SSL_CTX *ctx;
    int i;

    meth = conf->server ? \
           (conf->dtls ? DTLS_server_method() : TLS_server_method()) \
           : (conf->dtls ? DTLS_client_method() : TLS_client_method());

    ctx = SSL_CTX_new(meth);
    if (!ctx) {
        ERR("SSL ctx new failed\n");
        return NULL;
    }

    DBG("SSL context created\n");

    if (ssl_ctx_version_conf(conf, ctx)) {
        ERR("Version conf failed\n");
        goto err;
    }

    if (conf->cafiles_count) {
        for (i = 0; i < conf->cafiles_count; i++) {
#ifdef WITH_OSSL_111
            if (SSL_CTX_load_verify_locations(ctx, conf->cafiles[i], NULL) != 1) {
#else
            if (SSL_CTX_load_verify_file(ctx, conf->cafiles[i]) != 1) {
#endif
                ERR("Load CA cert [%s] failed\n", conf->cafiles[i]);
                goto err;
            }
            DBG("Loaded cert %s on context\n", conf->cafiles[i]);
        }
    }
    if (conf->cert) {
        if (SSL_CTX_use_certificate_file(ctx, conf->cert, conf->cert_type) != 1) {
            ERR("Load Server cert %s failed\n", conf->cert);
            goto err;
        }

        DBG("Loaded server cert %s on context\n", conf->cert);
    }

    if (conf->priv_key) {
        if (SSL_CTX_use_PrivateKey_file(ctx, conf->priv_key, conf->priv_key_type) != 1) {
            ERR("Load Server key %s failed\n", conf->priv_key);
            goto err;
        }

        DBG("Loaded server key %s on context\n", conf->priv_key);
    }

    if ((conf->server == 0) || (conf->auth & TC_CONF_CLIENT_CERT_AUTH)) {
        SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER|SSL_VERIFY_FAIL_IF_NO_PEER_CERT, NULL);
        DBG("Configured Verify Peer\n");
    }
    SSL_CTX_set_verify_depth(ctx, 5);
    /*if (SSL_CTX_set_session_id_context(ctx, SSL_SESS_ID_CTX, strlen(SSL_SESS_ID_CTX)) != 1) {
        ERR("Set sess id ctx failed\n");
        goto err;
    }*/

    if ((conf->res.psk) && (initialize_resumption_params(conf, ctx) != 0)) {
        ERR("Initializing resumption params failed\n");
        goto err;
    }
    if ((conf->res.early_data) && (conf->server)) {
        SSL_CTX_set_max_early_data(ctx, MAX_EARLY_DATA_MSG);
    }
    if (ssl_ctx_mode_config(conf, ctx) != 0) {
        goto err;
    }
    DBG("SSL context configurations completed\n");

    return ctx;
err:
    SSL_CTX_free(ctx);
    return NULL;
}

void ssl_info_cb(const SSL *ssl, int type, int val)
{
    DBG("SSL Info cb: type=%d, val=%d\n", type, val);
}

int enable_nonblock(TC_CONF *conf)
{
    int fd = conf->test_con_fd.con_fd;
    int flags;
    if (conf->nb_sock) {
        flags = fcntl(fd, F_GETFL, 0);
        if (flags == -1) {
            ERR("Get flag failed for fcntl");
            return -1;
        }
        flags |= O_NONBLOCK;
        if (fcntl(fd, F_SETFL, flags) != 0) {
            ERR("Set nonblock flags on fcntl failed\n");
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
        ERR("SSL object creation failed\n");
        return NULL; 
    }
    SSL_set_ex_data(ssl, SSL_EX_DATA_TC_CONF, conf);

    if (conf->dtls == 0) {
        if (SSL_set_fd(ssl, conf->test_con_fd.con_fd) != 1) {
            goto err;
        }
    } else {
        if (ssl_config_dtls_bio(conf, ssl) != 0) {
            goto err;
        }
    }

    if (ssl_kexch_config(conf, ssl)) {
        ERR("SSL kexch conf failed\n");
        goto err;
    }

    if (enable_nonblock(conf)) {
        ERR("Enable non block failed");
        goto err;
    }
    if (conf->cb.info_cb) {
        SSL_set_info_callback(ssl, ssl_info_cb);
    }
    if (conf->cb.msg_cb) {
        SSL_set_msg_callback(ssl, ssl_msg_cb);
    }
    if (ssl_mode_config(conf, ssl) != 0) {
        goto err;
    }
    DBG("SSL object creation finished\n");

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
    ERR("SSL error[%lu][%s] on [%s:%d]\n", error, err_buf, file, line_num);
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
            DBG("SSL want read occured for %s\n", op);
            FD_SET(fd, &readfds);
            break;
        case SSL_ERROR_WANT_WRITE:
            DBG("SSL want write occured for %s\n", op);
            FD_SET(fd, &writefds);
            break;
        default:
            DBG("%s failed with err=%d\n", op, err);
            if (err == SSL_ERROR_SSL) {
                print_ssl_err();
            }
            return -1;
    }
    timeout.tv_sec = TLS_SOCK_TIMEOUT_MS / 1000;
    timeout.tv_usec = (TLS_SOCK_TIMEOUT_MS % 1000) * 1000;
    if (select(fd + 1, &readfds, &writefds, NULL, &timeout) < 1) {
        ERR("select timed out, ret=%d\n", ret);
        return -1;
    }
    DBG("Time spent on select %ldsecs and %ldusecs\n", timeout.tv_sec, timeout.tv_usec);
    return 0;
}

int do_ssl_accept(TC_CONF *conf, SSL *ssl)
{
    int ret;
    do {
        ret = SSL_accept(ssl);
        if (ret == 1) {
            DBG("SSL accept succeeded\n");
            break;
        }
        if (wait_for_sock_io(ssl, ret, "SSL_accept")) {
            ERR("SSL accept failed\n");
            return -1;
        }
        DBG("Continue SSL accept\n");
    } while (1);
    if (conf->res.resumption) { //TODO Need to improve this check for TLS1.2 resumption also
        if (SSL_session_reused(ssl)) {
            DBG("SSL session reused\n");
        } else {
            DBG("SSL session not reused\n");
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
        DBG("write early data ret=%d\n", ret);
    }
    return ret > 0 ? 0 : -1;
}

int do_ssl_connect(TC_CONF *conf, SSL *ssl)
{
    int ret;

    do {
        ret = SSL_connect(ssl);
        if (ret == 1) {
            DBG("SSL connect succeeded\n");
            break;
        }
        if (wait_for_sock_io(ssl, ret, "SSL_connect")) {
            ERR("SSL connect failed\n");
            return -1;
        }
        DBG("Continue SSL connection\n");
    } while (1);
    return 0;
}

int do_handshake(TC_CONF *conf, SSL *ssl)
{
    int ret;
    do {
        ret = SSL_do_handshake(ssl);
        if (ret == 1) {
            DBG("SSL handshake succeeded\n");
            break;
        }
        if (wait_for_sock_io(ssl, ret, "SSL_do_handshake")) {
            ERR("SSL handshake failed\n");
            return -1;
        }
        DBG("Continue SSL_handshake\n");
    } while (1);
    return 0;
}

int do_ssl_handshake(TC_CONF *conf, SSL *ssl)
{
    DBG("###Doing SSL handshake\n");
    int ret;
    if (conf->server) {
        ret = do_ssl_accept(conf, ssl);
    } else {
        ret = do_ssl_connect(conf, ssl);
    }
    if (ret) return ret;
    return do_after_handshake_validation(conf, ssl);
}

int do_ssl_read(TC_CONF *conf, SSL *ssl, const char *req, const char *res)
{
    char buf[MAX_BUF_SIZE] = {0};
    const char *msg_for_cmp;
    int ret;

    msg_for_cmp = conf->server ? req : res;
    do {
        ret = SSL_read(ssl, buf, sizeof(buf) - 1);
        if (ret > 0) {
            break;
        }
        if (wait_for_sock_io(ssl, ret, "SSL_read")) {
            ERR("SSL read failed\n");
            return -1;
        }
    } while (1);
    DBG("SSL_read[%d] %s\n", ret, buf);
    if (memcmp(buf, msg_for_cmp, strlen(msg_for_cmp))) {
        ERR("Invalid msg received\n");
    }
    return 0;
}

int do_ssl_write(TC_CONF *conf, SSL *ssl, const char* req, const char *res)
{
    const char *msg;
    int ret;

    msg = conf->server ? res : req;
    do {
        ret = SSL_write(ssl, msg, strlen(msg));
        if (ret == strlen(msg)) {
            break;
        }
        if (wait_for_sock_io(ssl, ret, "SSL_write")) {
            ERR("SSL write failed\n");
            return -1;
        }
    } while (1);
    DBG("SSL_write[%d] sent %s\n", ret, msg);
    return 0;
}

int do_data_transfer_client(TC_CONF *conf, SSL *ssl)
{
    const char *msg_req[] = {MSG1_REQ, MSG2_REQ};
    const char *msg_res[] = {MSG1_RES, MSG2_RES};
    int i;
    for (i = 0; i < sizeof(msg_req)/sizeof(msg_req[0]); i++) {
        if ((do_ssl_write(conf, ssl, msg_req[i], msg_res[i]) != 0)
                || (do_ssl_read(conf, ssl, msg_req[i], msg_res[i]) != 0)) {
            ERR("Data transfer failed\n");
            return -1;
        }
    }
    return 0;
}

int do_data_transfer_server(TC_CONF *conf, SSL *ssl)
{
    const char *msg_req[] = {MSG1_REQ, MSG2_REQ};
    const char *msg_res[] = {MSG1_RES, MSG2_RES};
    int i;
    for (i = 0; i < sizeof(msg_req)/sizeof(msg_req[0]); i++) {
        if ((do_ssl_read(conf, ssl, msg_req[i], msg_res[i]) != 0)
                || (do_ssl_write(conf, ssl, msg_req[i], msg_res[i]) != 0)) {
            ERR("Data transfer failed\n");
            return -1;
        }
    }
    return 0;
}

int do_data_transfer(TC_CONF *conf, SSL *ssl)
{
    DBG("### Doing Data transfer\n");
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
    close_sock_connection(&conf->test_con_fd);
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
        ERR("SSl context creation failed\n");
        return -1;
    }

    ssl = create_ssl_object_openssl(conf, ctx);
    if (!ssl) {
        ERR("SSl context object failed\n");
        goto err;
    }

    if (do_ssl_handshake(conf, ssl)) {
        ERR("SSL handshake failed\n");
        goto err;
    }

    if (do_data_transfer(conf, ssl)) {
        ERR("Data transfer over TLS failed\n");
        goto err;
    }
    DBG("Data transfer over TLS succeeded\n");
    if (do_key_update_test(conf, ssl)) {
        ERR("Key update testing failed\n");
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
        ERR("SSl context creation failed\n");
        return -1;
    }

    ssl = create_ssl_object_openssl(conf, ctx);
    if (!ssl) {
        ERR("SSl context object failed\n");
        goto err;
    }

    if (conf->server == 0) {
        if (conf->res.sess == NULL) {
            ERR("Sess is not available for doing early data\n");
            goto err;
        }
        SSL_set_session(ssl, conf->res.sess);
        /* On client send early data during handshake */
        /*if (do_ssl_write_early_data(conf, ssl)) {
            ERR("Write early data failed\n");
            goto err;
        }*/
        if (do_ssl_handshake(conf, ssl)) {
            ERR("SSL handshake failed\n");
            goto err;
        }
    } else {
        /* On server do normal handshake */
        if (do_ssl_handshake(conf, ssl)) {
            ERR("SSL handshake failed\n");
            goto err;
        }
    }
    if (do_data_transfer(conf, ssl)) {
        ERR("Data transfer over TLS failed\n");
        goto err;
    }
    DBG("Data transfer over TLS succeeded\n");
    ret_val = 0;
err:
    do_cleanup_openssl(conf, ctx, ssl);
    return ret_val;
}

int do_test_openssl(TC_CONF *conf)
{
    int ret_val = -1;

    DBG("Staring Test OpenSSL\n");
    if (do_openssl_init(conf)) {
        ERR("Openssl init failed\n");
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
