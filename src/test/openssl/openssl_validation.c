#include "openssl_cipher.h"
#include "openssl_validation.h"
#include "openssl_kexch.h"
#include "openssl_version.h"
#include "openssl_auth.h"

int do_after_handshake_validation(TC_CONF *conf, SSL *ssl)
{
    if (do_negotiated_ciphersuite_validation(conf, ssl) != TWT_SUCCESS) {
        ERR("Negotiated ciphersuite validation failed\n");
        return TWT_FAILURE;
    }
    if (do_negotiated_kexch_validation(conf, ssl) != TWT_SUCCESS) {
        ERR("Negotiated kexch validation failed\n");
        return TWT_FAILURE;
    }
    if (do_negotiated_version_validation(conf, ssl) != TWT_SUCCESS) {
        ERR("Negotiated version validation failed\n");
        return TWT_FAILURE;
    }
    if (do_print_peer_cert(conf, ssl) != TWT_SUCCESS) {
        ERR("Printing peer cert failed\n");
        return TWT_FAILURE;
    }
    return TWT_SUCCESS;
}
