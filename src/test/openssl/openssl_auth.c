#include "test_cli_arg.h"
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
    if (strlen(conf->cert) > 0) {
        if (SSL_CTX_use_certificate_file(ctx, conf->cert, conf->cert_type) != 1) {
            ERR("Load Server cert %s failed\n", conf->cert);
            return TWT_FAILURE;
        }

        DBG("Loaded server cert %s on context\n", conf->cert);
    }

    if (strlen(conf->priv_key) > 0) {
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

void tc_conf_default_certs(TC_CONF *conf)
{
    if (conf->server) {
        if (strlen(conf->cert) == 0) {
            strcpy(conf->cert, EC256_SERVER_CERT_FILE);
            conf->cert_type = SSL_FILETYPE_PEM;
        }
        if (strlen(conf->priv_key) == 0) {
            strcpy(conf->priv_key, EC256_SERVER_KEY_FILE);
            conf->priv_key_type = SSL_FILETYPE_ASN1;
        }
        if ((conf->auth & TC_CONF_CLIENT_CERT_AUTH) != 0) {
            if (strlen(conf->cafiles[0]) == 0) {
                strcpy(conf->cafiles[0], EC256_CAFILE1);
                conf->cafiles_count = 1;
            }
        }
    } else {
        if ((conf->auth & TC_CONF_CLIENT_CERT_AUTH) != 0) {
            if (strlen(conf->cert) == 0) {
                strcpy(conf->cert, EC256_CLIENT_CERT_FILE);
                conf->cert_type = SSL_FILETYPE_PEM;
            }
            if (strlen(conf->priv_key) == 0) {
                strcpy(conf->priv_key, EC256_CLIENT_KEY_FILE);
                conf->priv_key_type = SSL_FILETYPE_ASN1;
            }
        }
        if (strlen(conf->cafiles[0]) == 0) {
            strcpy(conf->cafiles[0], EC256_CAFILE1);
            conf->cafiles_count = 1;
        }
    }
}

int convert_cert_type_str_to_ossl_value(int *out_type, const char *type_str) {

    if (strcmp(type_str, TWT_CLI_CERT_TYPE_PEM) == 0) {
        *out_type = SSL_FILETYPE_PEM;
    } else if (strcmp(type_str, TWT_CLI_CERT_TYPE_ASN) == 0) {
        *out_type = SSL_FILETYPE_ASN1;
    } else if (strlen(type_str) > 0) {
        return TWT_FAILURE;
    }
    return TWT_SUCCESS;
}

/* CLI arg passed for cert/priv_key types are 'pem' or 'asn' that has been
 * updated to openssl param */
int tc_conf_update_cert_types(TC_CONF *conf)
{
    if (convert_cert_type_str_to_ossl_value(&conf->cert_type,
                                    conf->cert_type_str) == TWT_FAILURE) {
        ERR("Invalid cert type str [%s]\n", conf->cert_type_str);
        return TWT_FAILURE;
    }
    if (convert_cert_type_str_to_ossl_value(&conf->priv_key_type,
                                    conf->priv_key_type_str) == TWT_FAILURE) {
        ERR("Invalid priv key type str [%s]\n", conf->priv_key_type_str);
        return TWT_FAILURE;
    }
    return TWT_SUCCESS;
}

int tc_conf_auth(TC_CONF *conf)
{
    tc_conf_default_certs(conf);
    return tc_conf_update_cert_types(conf);
}
