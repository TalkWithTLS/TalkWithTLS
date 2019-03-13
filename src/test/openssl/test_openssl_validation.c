#include "test_openssl_validation.h"
#include "test_openssl_kexch.h"

int do_after_handshake_validation(TC_CONF *conf, SSL *ssl)
{
    if (do_negotiated_kexch_validation(conf, ssl)) {
        printf("Negotiated kexch validation failed\n");
        return -1;
    }
    return 0;
}
