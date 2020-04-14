#include "openssl_validation.h"
#include "openssl_kexch.h"
#include "openssl_version.h"

int do_after_handshake_validation(TC_CONF *conf, SSL *ssl)
{
    if (do_negotiated_kexch_validation(conf, ssl)) {
        ERR("Negotiated kexch validation failed\n");
        return -1;
    }
    if (do_negotiated_version_validation(conf, ssl)) {
        ERR("Negotiated version validation failed\n");
        return -1;
    }
    return 0;
}
