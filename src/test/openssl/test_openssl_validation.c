#include "test_openssl_validation.h"

int do_after_handshake_validation(TC_CONF *conf, SSL *ssl)
{
    int kexch_group;
    if (conf->server) {
        kexch_group = SSL_get_shared_group(ssl, 0);
        printf("Kexch group=%x\n", kexch_group);
        if (kexch_group != conf->kexch.kexch_should_neg) {
            printf("Expected kexch group is %x\n", conf->kexch.kexch_should_neg);
            return -1;
        }
    }
    return 0;
}
