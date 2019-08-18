#include <unistd.h>
#include "test_openssl_common.h"
#include "test_openssl_arg.h"

void usage()
{
    printf("-h      - Help\n");
    printf("-S      - Run as [D]TLS server\n");
    printf("-s      - Run as [D]TLS server, fork a server process and send all args.\n");
    printf("          This is used in test automation with pytest.\n");
    printf("-k      - Key Exchange group for TLS1.3\n");
    printf("          1 - All ECDHE\n");
    printf("          2 - All FFDHE\n");
    printf("          3 - All ECDHE set using str API (SSL_set1_group_list)\n");
    printf("-K      - Key update\n");
    printf("          1 - Server initiating Key update request\n");
    printf("-V      - [D]TLS Max Version\n");
    printf("          10 - TLS1.0\n");
    printf("          11 - TLS1.1\n");
    printf("          12 - TLS1.2\n");
    printf("          13 - TLS1.3\n");
    printf("          1312 - Server TLS1.3 and Client TLS1.2\n");
    printf("          1213 - Server TLS1.2 and Client TLS1.3\n");
    printf("-c      - Client Cert Authentication\n");
    printf("-C      - Crypto mem Callback\n");
    printf("-i      - TLS Info Callback\n");
    printf("-m      - TLS msg Callback\n");
    printf("-M      - TLS detailed msg Callback\n");
    printf("-b      - Release TLS buffer\n");
    printf("          1 - Enable at SSL context\n");
    printf("          other than 1 - Enable at SSL\n");
}

int parse_arg(int argc, char *argv[], TC_CONF *conf)
{
    int opt;

    while((opt = getopt(argc, argv, "hSRPEimMnK:k:V:a:p:cCb:")) != -1) {
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
            case 'c':
                conf->auth |= TC_CONF_CLIENT_CERT_AUTH;
                break;
            case 'C':
                conf->cb.crypto_mem_cb = 1;
                break;
            case 'b':
                if (optarg == NULL) {
                    conf->ssl_mode.release_buf = 2;
                } else {
                    conf->ssl_mode.release_buf = (uint8_t)atoi(optarg);
                }
                break;
        }
    }

    return 0;
}
