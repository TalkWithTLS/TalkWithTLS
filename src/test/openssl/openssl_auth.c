#include "openssl_auth.h"

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

