#include <unistd.h>
#include "test_openssl_common.h"
#include "test_openssl_arg.h"

void update_certs(TC_CONF *conf)
{
    if (conf->server) {
        conf->server = 1;
        conf->cert = EC256_SERVER_CERT_FILE;
        conf->cert_type = SSL_FILETYPE_PEM;
        conf->priv_key = EC256_SERVER_KEY_FILE;
        conf->priv_key_type = SSL_FILETYPE_ASN1;
    } else {
        conf->cafiles[0] = EC256_CAFILE1;
        conf->cafiles_count = 1;
    }
}

int parse_arg(int argc, char *argv[], TC_CONF *conf)
{
    int opt;

    init_tc_conf(conf);

    while((opt = getopt(argc, argv, "Sa:p:")) != -1) {
        switch (opt) {
            case 'S':
                conf->server = 1;
        }
    }

    update_certs(conf);
    return 0;
}
