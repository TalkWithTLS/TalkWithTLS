#include <unistd.h>
#include <getopt.h>
#include "test_openssl_common.h"
#include "test_openssl_arg.h"

void usage()
{
    printf("-help\n");
    printf("    - Help\n");
    printf("-tc-automation[=<arg>]\n");
    printf("    - Listens for test command on a TCP socket on a default address [0.0.0.0:25100]\n");
    printf("    - arg is optional, requires if bind port should be changed\n");
    printf("    - arg should be an integer which is added to default port 25100 for binding\n");
    printf("    - If -tc-automation is used, then all other option gets ignored and "\
                  "directly listens on Test TCP socket\n");
    printf("-serv\n");
    printf("    - Run as [D]TLS server\n");
    printf("-clnt\n");
    printf("    - Run as [D]TLS clnt\n");
    printf("    - Using either -serv or -clnt will be sufficient\n");
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

enum cmd_opt_id {
    OPT_HELP = 1,
    OPT_TC_AUTOMATION,
    OPT_SERV,
    OPT_CLNT,
    OPT_CAUTH,
    OPT_KEX,
    OPT_NBSOCK,
    OPT_RES,
    OPT_PSK,
    OPT_VER,
    OPT_KUPDA,
    OPT_EARLYDATA,
    OPT_INFOCB,
    OPT_MSGCB,
    OPT_MEMCB,
    OPT_RELBUF,
};

struct option lopts[] = {
    {"help", no_argument, NULL, OPT_HELP},
    {"tc-automation", optional_argument, NULL, OPT_TC_AUTOMATION},
    {"serv", no_argument, NULL, OPT_SERV},
    {"clnt", no_argument, NULL, OPT_CLNT},
    /*TODO Need to take cauth arg to use type of certs */
    {"cauth", optional_argument, NULL, OPT_CAUTH},
    {"kex", required_argument, NULL, OPT_KEX},
    {"nbsock", optional_argument, NULL, OPT_NBSOCK},
    {"res", optional_argument, NULL, OPT_RES},
    {"psk", optional_argument, NULL, OPT_PSK},
    {"ver", required_argument, NULL, OPT_VER},
    {"kupda", required_argument, NULL, OPT_KUPDA},
    {"earlydata", optional_argument, NULL, OPT_EARLYDATA},
    {"infocb", no_argument, NULL, OPT_INFOCB},
    {"msgcb", optional_argument, NULL, OPT_MSGCB},
    {"memcb", optional_argument, NULL, OPT_MEMCB},
    {"relbuf", required_argument, NULL, OPT_RELBUF},
};

/* Parses CLI argument and updates values to TC_CONF
 * return : Returns 0 in case of successfully parsing or else -1
 *          Special value of 1 is returned for test automation
 *          And 2 is returned for help */
int parse_arg(int argc, char **argv, TC_CONF *conf)
{
    int opt;
    int count = 0;

    /* optind should be resetted to 1 for repeatitive calls to getoptxxx with
     * different argv list */
    optind = 1;
    while ((opt = getopt_long_only(argc, argv, "", lopts, NULL)) != -1) {
        count++;
        switch (opt) {
            case OPT_HELP:
                usage();
                return TWT_CLI_HELP;
            case OPT_TC_AUTOMATION:
                conf->test_automation = 1;
                if (optarg != NULL) {
                    conf->bind_addr.port += atoi(optarg);
                }
                return TWT_START_AUTOMATION;
            /* TODO Need to do OPT_BIND_ADDR */
            case OPT_SERV:
                conf->server = 1;
                break;
            case OPT_CLNT:
                conf->server = 0;
                break;
            case OPT_CAUTH:
                conf->auth |= TC_CONF_CLIENT_CERT_AUTH;
                break;
            case OPT_KEX:
                conf->kexch.kexch_conf = atoi(optarg);
                break;
            case OPT_NBSOCK:
                conf->nb_sock = 1;
                break;
            case OPT_RES:
                conf->res.resumption = 1;
                break;
            case OPT_PSK:
                conf->res.psk = 1;
                break;
            case OPT_VER:
                conf->max_version = atoi(optarg);
                break;
            case OPT_KUPDA:
                conf->ku.key_update_test = atoi(optarg);
                break;
            case OPT_EARLYDATA:
                conf->res.early_data = 1;
                break;
            case OPT_INFOCB:
                conf->cb.info_cb = 1;
                break;
            case OPT_MSGCB:
                conf->cb.msg_cb = 1;
                if (optarg != NULL)
                    conf->cb.msg_cb_detailed = 1;
                break;
            case OPT_MEMCB:
                conf->cb.crypto_mem_cb = 1;
                break;
            case OPT_RELBUF:
                conf->ssl_mode.release_buf = (uint8_t)atoi(optarg);
                break;
            default:
                ERR("Unknown options [%d]\n", opt);
                break;
        }
    }

    DBG("Processed %d arguments successfully\n", count);
    return 0;
}
