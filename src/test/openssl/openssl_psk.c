#include "openssl_psk.h"

const SSL_CIPHER *get_cipher_for_tls13_psk(SSL *s)
{
    TC_CONF *conf = SSL_get_ex_data(s, SSL_EX_DATA_TC_CONF);
    unsigned char aes128gcmsha256_id[] = {0x13, 0x02};
    const SSL_CIPHER *cipher;
    const char *ch;
    int i;

    if (strlen(conf->ch.ciph) > 0) {
        for (i = 0; i < sizeof(g_cipher_info)/sizeof(g_cipher_info[0]); i++) {
            ch = g_cipher_info[i].ciph_rfc;
            if (strncmp(conf->ch.ciph, ch, strlen(ch)) == 0
                    && (cipher = SSL_CIPHER_find(s, g_cipher_info[i].ciph_val))
                        != NULL) {
                DBG("PSK out of band with cipher [%s]\n", ch);
                return cipher;
            }
        }
    }
    DBG("PSK out of band with default ciphersuite TLS_AES_256_GCM_SHA384\n");
    return SSL_CIPHER_find(s, aes128gcmsha256_id);
}

int tls13_psk_use_session_cb(SSL *s, const EVP_MD *md,
                              const unsigned char **id, size_t *idlen,
                              SSL_SESSION **sess)
{
    TC_CONF *conf = SSL_get_ex_data(s, SSL_EX_DATA_TC_CONF);
    SSL_SESSION *usesess = NULL;
    const SSL_CIPHER *cipher = NULL;
    long key_len;
    unsigned char *key = NULL;
    
    DBG("Called PSK use sess cb\n");
    if ((key = OPENSSL_hexstr2buf(conf->res.psk_key, &key_len)) == NULL) {
        ERR("hexstr2buf failed\n");
        return 0;
    }

    if ((cipher = get_cipher_for_tls13_psk(s)) == NULL) {
        ERR("TLS1.3 PSK Cipher find failed\n");
        goto err;
    }

    if (md != NULL && SSL_CIPHER_get_handshake_digest(cipher) != md) {
        /* PSK not usable, ignore it */
        return 1;
    }

    usesess = SSL_SESSION_new();
    if (usesess == NULL
            || !SSL_SESSION_set1_master_key(usesess, key, key_len)
            || !SSL_SESSION_set_cipher(usesess, cipher)
            || !SSL_SESSION_set_protocol_version(usesess, TLS1_3_VERSION)) {
        goto err;
    }
    OPENSSL_free(key);
    key = NULL;

    if ((conf->res.early_data)
            && (SSL_SESSION_set_max_early_data(usesess,
                                               MAX_EARLY_DATA_MSG) != 1)) {
        ERR("Use sess cb: Enabled early data\n");
        goto err;
    }
    DBG("Set Max early data [%d] to SSL_SESS in psk use cb\n",
        MAX_EARLY_DATA_MSG);

    *sess = usesess;
    *id = (unsigned char *)conf->res.psk_id;
    *idlen = strlen(conf->res.psk_id);
    return 1;
 err:
    SSL_SESSION_free(usesess);
    OPENSSL_free(key);
    return 0;
}

int tls13_psk_find_session_cb(SSL *ssl, const unsigned char *id,
                               size_t id_len, SSL_SESSION **sess)
{
    TC_CONF *conf = SSL_get_ex_data(ssl, SSL_EX_DATA_TC_CONF);
    SSL_SESSION *tmpsess = NULL;
    unsigned char *key = NULL;
    long key_len;
    const SSL_CIPHER *cipher = NULL;

    DBG("Called PSK find sess cb\n");
    if ((id_len != strlen(conf->res.psk_id))
            || (memcmp(id, conf->res.psk_id, id_len) != 0)) {
        *sess = NULL;
        return 1;
    }

    if ((key = OPENSSL_hexstr2buf(conf->res.psk_key, &key_len)) == NULL) {
        ERR("hexstr2buf conversion failed\n");
        return 0;
    }

    if ((cipher = get_cipher_for_tls13_psk(ssl)) == NULL) {
        ERR("TLS1.3 PSK Cipher find failed\n");
        goto err;
    }

    tmpsess = SSL_SESSION_new();
    if (tmpsess == NULL
            || !SSL_SESSION_set1_master_key(tmpsess, key, key_len)
            || !SSL_SESSION_set_cipher(tmpsess, cipher)
            || !SSL_SESSION_set_protocol_version(tmpsess, SSL_version(ssl))) {
        goto err;
    }
    OPENSSL_free(key);
    key = NULL;

    if ((conf->res.early_data)
            && (SSL_SESSION_set_max_early_data(tmpsess,
                                               MAX_EARLY_DATA_MSG) != 1)) {
        ERR("Use sess cb: Enabled early data\n");
        goto err;
    }
    DBG("Set Max early data [%d] to SSL_SESS in psk find cb\n",
        MAX_EARLY_DATA_MSG);

    *sess = tmpsess;
    return 1;
err:
    SSL_SESSION_free(tmpsess);
    OPENSSL_free(key);
    return 0;
}

unsigned int tls_psk_client_cb(SSL *ssl, const char *hint,
                                       char *identity,
                                       unsigned int max_identity_len,
                                       unsigned char *psk,
                                       unsigned int max_psk_len)
{
    TC_CONF *conf = SSL_get_ex_data(ssl, SSL_EX_DATA_TC_CONF);
    unsigned char *key;
    long key_len;

    DBG("Called PSK client cb\n");
    if ((key = OPENSSL_hexstr2buf(conf->res.psk_key, &key_len)) == NULL) {
        ERR("hexstr2buf failed\n");
        return 0;
    }
    if ((strlen(conf->res.psk_id) + 1 > max_identity_len)
            || (key_len > max_psk_len)) {
        ERR("PSK ID or Key buffer is not sufficient\n");
        goto err;
    }
    strcpy(identity, conf->res.psk_id);
    memcpy(psk, key, key_len);
    OPENSSL_free(key);
    return (unsigned int)key_len;
err:
    OPENSSL_free(key);
    return 0;
}

unsigned int tls_psk_server_cb(SSL *ssl, const char *id,
                                            unsigned char *psk,
                                            unsigned int max_psk_len)
{
    TC_CONF *conf = SSL_get_ex_data(ssl, SSL_EX_DATA_TC_CONF);
    unsigned char *key;
    long key_len;

    DBG("Called PSK server cb\n");
    if ((key = OPENSSL_hexstr2buf(conf->res.psk_key, &key_len)) == NULL) {
        ERR("hexstr2buf failed\n");
        return 0;
    }
    if (strcmp(conf->res.psk_id, id) != 0) {
        ERR("Unknown Client's PSK ID\n");
        goto err;
    }
    if (key_len > max_psk_len) {
        ERR("Insufficient buffer size to copy conf->res.psk_key\n");
        goto err;
    }
    memcpy(psk, key, key_len);
    OPENSSL_free(key);
    return (unsigned int)key_len;
err:
    OPENSSL_free(key);
    return 0;
}

int ssl_ctx_psk_cb_config(TC_CONF *conf, SSL_CTX *ctx)
{
    if (conf->server == 1) {
        SSL_CTX_set_psk_server_callback(ctx, tls_psk_server_cb);
    } else {
        SSL_CTX_set_psk_client_callback(ctx, tls_psk_client_cb);
    }
    return TWT_SUCCESS;
}

int ssl_ctx_psk_sess_cb_config(TC_CONF *conf, SSL_CTX *ctx)
{
    if (conf->server == 1) {
        SSL_CTX_set_psk_find_session_callback(ctx, tls13_psk_find_session_cb);
        DBG("Registered TLS1.3 PSK find sess cb\n");
    } else {
        SSL_CTX_set_psk_use_session_callback(ctx, tls13_psk_use_session_cb);
        DBG("Registered TLS1.3 PSK use sess cb\n");
    }
    return TWT_SUCCESS;
}

int ssl_ctx_psk_config(TC_CONF *conf, SSL_CTX *ctx)
{
    switch (conf->res.psk) {
        case PSK_ID_AND_KEY:
            return ssl_ctx_psk_cb_config(conf, ctx);
        case PSK_ID_KEY_AND_CIPHERSUITE:
            return ssl_ctx_psk_sess_cb_config(conf, ctx);
        default:
            return TWT_FAILURE;
    }
}
