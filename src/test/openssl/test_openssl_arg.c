#include <unistd.h>
#include <getopt.h>
#include "test_openssl_common.h"
#include "test_openssl_arg.h"

void usage()
{
    printf("-help\n");
    printf("    - Help\n");
    printf("-serv\n");
    printf("    - Run as [D]TLS server\n");
    printf("-cauth\n");
    printf("    - Performs Client Cert Authentication\n");
    printf("-kex <arg>\n");
    printf("    - Key Exchange group for TLS1.3\n");
    printf("    1 - All ECDHE\n");
    printf("    2 - All FFDHE\n");
    printf("    3 - All ECDHE set using str API (SSL_set1_group_list)\n");
    printf("-nbsock\n");
    printf("    - Enables non blocking on socket\n");
    printf("-res\n");
    printf("    - Performs resumption\n");
    printf("-psk\n");
    printf("    - Enables PSK\n");
    printf("-ver <arg> \n");
    printf("    - [D]TLS Max Version on Server and Client\n");
    printf("    10 - TLS1.0\n");
    printf("    11 - TLS1.1\n");
    printf("    12 - TLS1.2\n");
    printf("    13 - TLS1.3\n");
    printf("    1312 - Server TLS1.3 and Client TLS1.2\n");
    printf("    1213 - Server TLS1.2 and Client TLS1.3\n");
    printf("    910 - DTLS1.0\n");
    printf("    912 - DTLS1.2\n");
    printf("    11 - TLS1.1\n");
    printf("-kupda <arg>\n");
    printf("    - Performs TLSv1.3 Key update\n");
    printf("    - 1 - Server initiating Key update request\n");
    printf("-earlydata\n");
    printf("    - Performs TLSv1.3 early data transfer\n");
    printf("-infocb\n");
    printf("    - Enables TLS Info Callback\n");
    printf("-msgcb [<arg>] \n");
    printf("    - Enables TLS msg Callback, argument is optional\n");
    printf("    - 1 - Enable detailed print on msg callback\n");
    printf("-memcb\n");
    printf("    - Enables Crypto mem Callback\n");
    printf("-relbuf <arg>\n");
    printf("    - Enables Release TLS buffer\n");
    printf("    1 - Enable at SSL context\n");
    printf("    2 - Enable at SSL\n");
}

struct option lopts[] = {
    {"help", no_argument, NULL, 1},
    {"serv", optional_argument, NULL, 2},
    {"cauth", optional_argument, NULL, 3},
    {"kex", required_argument, NULL, 4},
    {"nbsock", optional_argument, NULL, 5},
    {"res", optional_argument, NULL, 6},
    {"psk", optional_argument, NULL, 7},
    {"ver", required_argument, NULL, 8},
    {"kupda", required_argument, NULL, 9},
    {"earlydata", optional_argument, NULL, 10},
    {"infocb", no_argument, NULL, 11},
    {"msgcb", optional_argument, NULL, 12},
    {"memcb", optional_argument, NULL, 13},
    {"relbuf", required_argument, NULL, 14},
};

int parse_arg(int argc, char *argv[], TC_CONF *conf)
{
    int opt;
    int count = 0;

    while ((opt = getopt_long_only(argc, argv, "", lopts, NULL)) != -1) {
        count++;
        switch (opt) {
            case 1:
                usage();
                return 1;
            case 2:
                conf->server = 1;
                break;
            case 3:
                conf->auth |= TC_CONF_CLIENT_CERT_AUTH;
                break;
            case 4:
                conf->kexch.kexch_conf = atoi(optarg);
                break;
            case 5:
                conf->nb_sock = 1;
                break;
            case 6:
                conf->res.resumption = 1;
                break;
            case 7:
                conf->res.psk = 1;
                break;
            case 8:
                conf->max_version = atoi(optarg);
                break;
            case 9:
                conf->ku.key_update_test = atoi(optarg);
                break;
            case 10:
                conf->res.early_data = 1;
                break;
            case 11:
                conf->cb.info_cb = 1;
                break;
            case 12:
                conf->cb.msg_cb = 1;
                if (optarg != NULL)
                    conf->cb.msg_cb_detailed = 1;
                break;
            case 13:
                conf->cb.crypto_mem_cb = 1;
                break;
            case 14:
                conf->ssl_mode.release_buf = (uint8_t)atoi(optarg);
                break;
        }
    }

    printf("Processed %d arguments successfully\n", count);
    return 0;
}
