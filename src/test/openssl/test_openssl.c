#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>

#include "openssl/crypto.h"
#include "openssl/ssl.h"

#include "test_common.h"
#include "test_openssl_common.h"

int g_dhe_kexch_groups[] = {
    NID_ffdhe2048,
    NID_ffdhe3072,
    NID_ffdhe4096,
    NID_ffdhe6144,
    NID_ffdhe8192
};

int g_ec_kexch_groups[] = {
    NID_X9_62_prime256v1,   /* secp256r1 */
    NID_secp384r1,          /* secp384r1 */
    NID_secp521r1,          /* secp521r1 */
    NID_X25519,             /* x25519 */
    NID_X448                /* x448 */
};

int tls13_client()
{
    TC_CONF conf = {0};

    init_tc_conf(&conf);
    conf.cafiles[0] = EC256_CAFILE1;
    conf.cafiles_count = 1;
    conf.tcp_listen_fd = conf.fd = -1;

    return do_test_openssl(&conf);
}

int tls13_server()
{
    TC_CONF conf = {0};

    init_tc_conf(&conf);
    conf.server = 1;
    conf.cert = EC256_SERVER_CERT_FILE;
    conf.cert_type = SSL_FILETYPE_PEM;
    conf.priv_key = EC256_SERVER_KEY_FILE;
    conf.priv_key_type = SSL_FILETYPE_ASN1;

    return do_test_openssl(&conf);
}

int main(int argc, char *argv[])
{
    int server = 0;
    if (argc > 1) {
        server = atoi(argv[1]);
    }

    if (server) {
        return tls13_server();
    } else {
        return tls13_client();
    }
}
