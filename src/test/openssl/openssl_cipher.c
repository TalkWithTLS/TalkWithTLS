#include "openssl_cipher.h"

int ssl_ciph_config(TC_CONF *conf, SSL *ssl)
{
    if (strlen(conf->ch.ciph) > 0) {
        if (SSL_set_ciphersuites(ssl, conf->ch.ciph) != 1) {
            ERR("Configuring TLS1.3 ciphersuite [%s] failed\n", conf->ch.ciph);
            return TWT_FAILURE;
        }
        DBG("Configured ciphersuite [%s]\n", conf->ch.ciph);
        if (conf->ch.negotiated_ciph == NULL) {
            conf->ch.negotiated_ciph = conf->ch.ciph;
        }
    }
    return TWT_SUCCESS;
}

int do_negotiated_ciphersuite_validation(TC_CONF *conf, SSL *ssl)
{
    const char *negotiated_cipher;
    negotiated_cipher = SSL_CIPHER_get_name(SSL_get_current_cipher(ssl));
    DBG("Negotiated cipher[%s]\n", negotiated_cipher);
    if (conf->ch.negotiated_ciph != NULL) {
        if ((negotiated_cipher == NULL) ||
                (strcmp(negotiated_cipher, conf->ch.negotiated_ciph) != 0)) {
            ERR("Negotiated cipher[%s] is not expected [%s]\n",
                    negotiated_cipher, conf->ch.negotiated_ciph);
            return TWT_FAILURE;
        }
    }
    return TWT_SUCCESS;
}
