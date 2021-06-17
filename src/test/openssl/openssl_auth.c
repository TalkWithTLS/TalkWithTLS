#include "openssl_auth.h"

int ssl_ctx_trusted_certs_conf(TC_CONF *conf, SSL_CTX *ctx)
{
    int i;
    if (conf->cafiles_count) {
        for (i = 0; i < conf->cafiles_count; i++) {
#ifdef WITH_OSSL_111
            if (SSL_CTX_load_verify_locations(ctx, conf->cafiles[i], NULL) != 1) {
#else
            if (SSL_CTX_load_verify_file(ctx, conf->cafiles[i]) != 1) {
#endif
                ERR("Load CA cert [%s] failed\n", conf->cafiles[i]);
                return TWT_FAILURE;
            }
            DBG("Loaded cert %s on context\n", conf->cafiles[i]);
        }
    }
    return TWT_SUCCESS;
}

int ssl_ctx_end_entity_certs_key_conf(TC_CONF *conf, SSL_CTX *ctx)
{
    if (conf->cert) {
        if (SSL_CTX_use_certificate_file(ctx, conf->cert, conf->cert_type) != 1) {
            ERR("Load Server cert %s failed\n", conf->cert);
            return TWT_FAILURE;
        }

        DBG("Loaded server cert %s on context\n", conf->cert);
    }

    if (conf->priv_key) {
        if (SSL_CTX_use_PrivateKey_file(ctx, conf->priv_key, conf->priv_key_type) != 1) {
            ERR("Load Server key %s failed\n", conf->priv_key);
            return TWT_FAILURE;
        }

        DBG("Loaded server key %s on context\n", conf->priv_key);
    }
    return TWT_SUCCESS;
}

int ssl_ctx_peer_verify_conf(TC_CONF *conf, SSL_CTX *ctx)
{
    if ((conf->server == 0) || (conf->auth & TC_CONF_CLIENT_CERT_AUTH)) {
        SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER|SSL_VERIFY_FAIL_IF_NO_PEER_CERT, NULL);
        DBG("Configured Verify Peer\n");
    }
    SSL_CTX_set_verify_depth(ctx, 5);

    return TWT_SUCCESS;
}

int ssl_ctx_auth_conf(TC_CONF *conf, SSL_CTX *ctx)
{
    if ((ssl_ctx_trusted_certs_conf(conf, ctx) != TWT_SUCCESS)
            || (ssl_ctx_end_entity_certs_key_conf(conf, ctx) != TWT_SUCCESS)
            || (ssl_ctx_peer_verify_conf(conf, ctx) != TWT_SUCCESS)) {
        return TWT_FAILURE;
    }

    return TWT_SUCCESS;
}

int tc_conf_auth(TC_CONF *conf)
{
    if (conf->server) {
        conf->cert = EC256_SERVER_CERT_FILE;
        conf->cert_type = SSL_FILETYPE_PEM;
        conf->priv_key = EC256_SERVER_KEY_FILE;
        conf->priv_key_type = SSL_FILETYPE_ASN1;
        if ((conf->auth & TC_CONF_CLIENT_CERT_AUTH) != 0) {
            conf->cafiles[0] = EC256_CAFILE1;
            conf->cafiles_count = 1;
        }
    } else {
        if ((conf->auth & TC_CONF_CLIENT_CERT_AUTH) != 0) {
            conf->cert = EC256_CLIENT_CERT_FILE;
            conf->cert_type = SSL_FILETYPE_PEM;
            conf->priv_key = EC256_CLIENT_KEY_FILE;
            conf->priv_key_type = SSL_FILETYPE_ASN1;
        }
        conf->cafiles[0] = EC256_CAFILE1;
        conf->cafiles_count = 1;
    }
    return 0;
}

