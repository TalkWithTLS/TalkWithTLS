#include "openssl_version.h"

int ssl_ctx_version_conf(TC_CONF *conf, SSL_CTX *ctx)
{
    if (conf->max_version) {
        switch (conf->max_version) {
            case TC_CONF_TLS_1_0_VERSION:
                SSL_CTX_set_max_proto_version(ctx, TLS1_VERSION);
                conf->ver_should_negotiate = TLS1_VERSION;
                break;
            case TC_CONF_TLS_1_1_VERSION:
                SSL_CTX_set_max_proto_version(ctx, TLS1_1_VERSION);
                conf->ver_should_negotiate = TLS1_1_VERSION;
                break;
            case TC_CONF_TLS_1_2_VERSION:
                SSL_CTX_set_max_proto_version(ctx, TLS1_2_VERSION);
                conf->ver_should_negotiate = TLS1_2_VERSION;
                break;
            case TC_CONF_TLS_1_3_VERSION:
                SSL_CTX_set_max_proto_version(ctx, TLS1_3_VERSION);
                conf->ver_should_negotiate = TLS1_3_VERSION;
                break;
            case TC_CONF_DTLS_1_0_VERSION:
                SSL_CTX_set_max_proto_version(ctx, DTLS1_VERSION);
                conf->ver_should_negotiate = DTLS1_VERSION;
                break;
            case TC_CONF_DTLS_1_2_VERSION:
                SSL_CTX_set_max_proto_version(ctx, DTLS1_2_VERSION);
                conf->ver_should_negotiate = DTLS1_2_VERSION;
                break;
            /*TODO for DTLS version */
            case TC_CONF_SERV_T13_CLNT_T12_VERSION:
                if (conf->server) {
                    SSL_CTX_set_max_proto_version(ctx, TLS1_3_VERSION);
                } else {
                    SSL_CTX_set_max_proto_version(ctx, TLS1_2_VERSION);
                }
                conf->ver_should_negotiate = TLS1_2_VERSION;
                break;
            case TC_CONF_SERV_T12_CLNT_T13_VERSION:
                if (conf->server) {
                    SSL_CTX_set_max_proto_version(ctx, TLS1_2_VERSION);
                } else {
                    SSL_CTX_set_max_proto_version(ctx, TLS1_3_VERSION);
                }
                conf->ver_should_negotiate = TLS1_2_VERSION;
                break;
            default:
                return -1;
        }
    }
    return 0;
}


int do_negotiated_version_validation(TC_CONF *conf, SSL *ssl)
{
    int ver_should_negotiate;
    ver_should_negotiate = conf->ver_should_negotiate ?
                                conf->ver_should_negotiate : TLS1_3_VERSION;
    if (SSL_version(ssl) != ver_should_negotiate) {
        ERR("Negotiated version=%#x, expected=%#x\n", SSL_version(ssl), ver_should_negotiate);
        return -1;
    }
    DBG("Negotiated [D]TLS version=%#x\n", SSL_version(ssl));
    return 0;
}
