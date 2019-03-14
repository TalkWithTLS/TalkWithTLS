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

void usage()
{
    printf("-h      - Help\n");
    printf("-k      - Key Exchange group for TLS1.3\n");
    printf("          1 - All ECDHE\n");
    printf("          2 - All FFDHE\n");
    printf("-K      - Key update\n");
    printf("          1 - Sever initiating Key update request\n");
    printf("-V      - [D]TLS Max Version\n");
    printf("          10 - TLS1.0\n");
    printf("          11 - TLS1.1\n");
    printf("          12 - TLS1.2\n");
    printf("          13 - TLS1.3\n");
    printf("          1312 - Server TLS1.3 and Client TLS1.2\n");
    printf("          1213 - Server TLS1.2 and Client TLS1.3\n");
    printf("-S      - [D]TLS server\n");
}

int parse_arg(int argc, char *argv[], TC_CONF *conf)
{
    int opt;

    while((opt = getopt(argc, argv, "hSRPEimMnK:k:V:a:p:")) != -1) {
        switch (opt) {
            case 'h':
                usage();
                return 1;
            case 'S':
                conf->server = 1;
                break;
            case 'R':
                conf->res.resumption = 1;
                break;
            case 'P':
                conf->res.psk = 1;
                break;
            case 'E':
                conf->res.early_data = 1;
                break;
            case 'i':
                conf->cb.info_cb = 1;
                break;
            case 'm':
                conf->cb.msg_cb = 1;
                break;
            case 'M':
                conf->cb.msg_cb = 1;
                conf->cb.msg_cb_detailed = 1;
                break;
            case 'n':
                conf->nb_sock = 1;
                break;
            case 'K':
                conf->ku.key_update_test = atoi(optarg);
                break;
            case 'k':
                conf->kexch.kexch_conf = atoi(optarg);
                break;
            case 'V':
                conf->max_version = atoi(optarg);
                break;
        }
    }

    update_certs(conf);
    return 0;
}
