#include <unistd.h>
#include <getopt.h>
#include "test_openssl_common.h"
#include "test_openssl_arg.h"

void usage()
{
    printf("-h or --help\n");
    printf("    - Help\n");
    printf("-s or --serv\n");
    printf("    - Run as [D]TLS server\n");
    printf("-c or --cauth\n");
    printf("    - Client Cert Authentication\n");
    printf("-k or --kex\n");
    printf("    - Key Exchange group for TLS1.3\n");
    printf("    1 - All ECDHE\n");
    printf("    2 - All FFDHE\n");
    printf("    3 - All ECDHE set using str API (SSL_set1_group_list)\n");
    printf("-n or --nbsock\n");
    printf("    - Enable non blocking socket\n");
    printf("-r or --res\n");
    printf("    - Perform resumption\n");
    printf("-p or --psk\n");
    printf("    - Enable PSK\n");
    printf("-v or --ver\n");
    printf("    - [D]TLS Max Version\n");
    printf("    10 - TLS1.0\n");
    printf("    11 - TLS1.1\n");
    printf("    12 - TLS1.2\n");
    printf("    13 - TLS1.3\n");
    printf("    1312 - Server TLS1.3 and Client TLS1.2\n");
    printf("    1213 - Server TLS1.2 and Client TLS1.3\n");
    printf("    910 - DTLS1.0\n");
    printf("    912 - DTLS1.2\n");
    printf("    11 - TLS1.1\n");
    printf("--kupda\n");
    printf("    - Key update\n");
    printf("          1 - Server initiating Key update request\n");
    printf("--infocb\n");
    printf("    - TLS Info Callback\n");
    printf("--msgcb\n");
    printf("    - TLS msg Callback\n");
    printf("--memcb\n");
    printf("    - Crypto mem Callback\n");
    printf("--relbuf\n");
    printf("    - Release TLS buffer\n");
    printf("    1 - Enable at SSL context\n");
    printf("    other than 1 - Enable at SSL\n");
}

struct option lopts[] = {
    {"cauth", optional_argument, NULL, 'c'},
    {"earlydata", optional_argument, NULL, 'e'},
    {"help", no_argument, NULL, 'h'},
    {"kex", required_argument, NULL, 'k'},
    {"nbsock", optional_argument, NULL, 'n'},
    {"res", optional_argument, NULL, 'r'},
    {"psk", optional_argument, NULL, 'p'},
    {"serv", optional_argument, NULL, 's'},
    {"ver", required_argument, NULL, 'v'},
    {"kupda", required_argument, NULL, 255},
    {"infocb", no_argument, NULL, 256},
    {"msgcb", optional_argument, NULL, 257},
    {"memcb", optional_argument, NULL, 258},
    {"relbuf", optional_argument, NULL, 259},
};

int parse_arg(int argc, char *argv[], TC_CONF *conf)
{
    int opt;
    int count = 0;

    while ((opt = getopt_long_only(argc, argv, "", lopts, NULL)) != -1) {
        count++;
        switch (opt) {
            case 'c':
                conf->auth |= TC_CONF_CLIENT_CERT_AUTH;
                break;
            case 'e':
                conf->res.early_data = 1;
                break;
            case 'h':
                usage();
                return 1;
            case 'k':
                conf->kexch.kexch_conf = atoi(optarg);
                break;
            case 'n':
                conf->nb_sock = 1;
                break;
            case 'p':
                conf->res.psk = 1;
                break;
            case 'r':
                conf->res.resumption = 1;
                break;
            case 's':
                conf->server = 1;
                break;
            case 'v':
                conf->max_version = atoi(optarg);
                break;
            case 255:
                conf->ku.key_update_test = atoi(optarg);
                break;
            case 256:
                conf->cb.info_cb = 1;
                break;
            case 257:
                conf->cb.msg_cb = 1;
                if (optarg != NULL)
                    conf->cb.msg_cb_detailed = 1;
                break;
            case 258:
                conf->cb.crypto_mem_cb = 1;
                break;
            case 259:
                if (optarg == NULL) {
                    conf->ssl_mode.release_buf = 2;
                } else {
                    conf->ssl_mode.release_buf = (uint8_t)atoi(optarg);
                }
                break;
        }
    }

    printf("Processed %d arguments successfully\n", count);
    return 0;
}
