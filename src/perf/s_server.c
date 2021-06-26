#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <getopt.h>
#include <errno.h>
#include <signal.h>

#include "openssl/crypto.h"
#include "openssl/ssl.h"
#include "openssl/err.h"

#define SERVER_IP "127.0.0.1"
#define SERVER_PORT 4433
#define TCP_MAX_LISTEN_COUNT 200
#define TCP_CON_RETRY_COUNT 20
#define TCP_CON_RETRY_WAIT_TIME_MS 200
#define TLS_SOCK_TIMEOUT_MS 8000

#define MAX_BUF_SIZE    1024
#define MSG_FOR_S_SERV    "<html><title>TWT Perf</title><body>TalkWithTLS</body></html>"

#define CAFILE1 "./certs/ECC_Prime256_Certs/rootcert.pem"
#define CAFILE2 "./certs/RSA2048_PSS_PSS_Certs/rootcert.pem"

#define SERVER_CERT_FILE "./certs/ECC_Prime256_Certs/serv_cert.pem"
#define SERVER_KEY_FILE "./certs/ECC_Prime256_Certs/serv_key.der"

#define MAX_IP_ADDR 32
typedef struct perf_conf_st {
    char ip[MAX_IP_ADDR];
    uint16_t port;
    int sess_ticket_count;
    int proto_version;
    uint32_t with_out_tls:1;
    uint32_t with_client_auth:1;
}PERF_CONF;

enum opt_enum {
    CLI_HELP = 1,
    CLI_IP,
    CLI_PORT,
    CLI_SESS_TICKET_COUNT,
    CLI_CLIENT_AUTH,
    CLI_TLS1_0,
    CLI_TLS1_1,
    CLI_TLS1_2,
    CLI_TLS1_3
};

struct option lopts[] = {
    {"help", no_argument, NULL, CLI_HELP},
    {"ip", required_argument, NULL, CLI_IP},
    {"port", required_argument, NULL, CLI_PORT},
    {"sess-tkt-count", required_argument, NULL, CLI_SESS_TICKET_COUNT},
    {"client-auth", no_argument, NULL, CLI_CLIENT_AUTH},
    {"tls1_0", no_argument, NULL, CLI_TLS1_0},
    {"tls1_1", no_argument, NULL, CLI_TLS1_1},
    {"tls1_2", no_argument, NULL, CLI_TLS1_2},
    {"tls1_3", no_argument, NULL, CLI_TLS1_3},
};

int do_tcp_listen(const char *server_ip, uint16_t port)
{
    struct sockaddr_in addr;
    int optval = 1;
    int lfd;
    int ret;

    lfd = socket(AF_INET, SOCK_STREAM, 0);
    if (lfd < 0) {
        printf("Socket creation failed\n");
        return -1;
    }

    addr.sin_family = AF_INET;
    if (inet_aton(server_ip, &addr.sin_addr) == 0) {
        printf("inet_aton failed\n");
        goto err_handler;
    }
    addr.sin_port = htons(port);

    if (setsockopt(lfd, SOL_SOCKET, SO_REUSEADDR, &optval, sizeof(optval))) {
        printf("set sock reuseaddr failed\n");
    }
    ret = bind(lfd, (struct sockaddr *)&addr, sizeof(addr));
    if (ret) {
        printf("bind failed %s:%d\n", server_ip, port);
        goto err_handler;
    }

    printf("TCP listening on %s:%d...\n", server_ip, port);
    ret = listen(lfd, TCP_MAX_LISTEN_COUNT);
    if (ret) {
        printf("listen failed\n");
        goto err_handler;
    }
    printf("TCP listen fd=%d\n", lfd);
    return lfd;
err_handler:
    close(lfd);
    return -1;
}

int do_tcp_accept(int lfd)
{
    struct sockaddr_in peeraddr;
    socklen_t peerlen = sizeof(peeraddr);
    int cfd;

    printf("\n\n###Waiting for TCP connection from client...\n");
    cfd = accept(lfd, (struct sockaddr *)&peeraddr, &peerlen);
    if (cfd < 0) {
        printf("accept failed, errno=%d\n", errno);
        return -1;
    }

    printf("TCP connection accepted fd=%d\n", cfd);
    return cfd;
}

void check_and_close(int *fd)
{
    if (*fd < 0) {
        return;
    }
    if (*fd == 0 || *fd == 1 || *fd == 2) {
        printf("Trying to close fd=%d, skipping it !!!\n", *fd);
    }
    printf("Closing fd=%d\n", *fd);
    close(*fd);
    *fd = -1;
}

int load_ca_cert(SSL_CTX *ctx, const char *ca_file)
{
#ifdef WITH_OSSL_111
    if (SSL_CTX_load_verify_locations(ctx, ca_file, NULL) != 1) {
#else
    if (SSL_CTX_load_verify_file(ctx, ca_file) != 1) {
#endif
        printf("Load CA cert %s failed\n", ca_file);
        return -1;
    }

    return 0;
}

SSL_CTX *create_context(PERF_CONF *conf)
{
    SSL_CTX *ctx;

    ctx = SSL_CTX_new(TLS_server_method());
    if (!ctx) {
        printf("SSL ctx new failed\n");
        return NULL;
    }

    printf("SSL context created\n");

    if (SSL_CTX_use_certificate_file(ctx, SERVER_CERT_FILE, SSL_FILETYPE_PEM) != 1) {
        printf("Load Server cert %s failed\n", SERVER_CERT_FILE);
        goto err_handler;
    }
    printf("Loaded server cert %s on context\n", SERVER_CERT_FILE);
    if (SSL_CTX_use_PrivateKey_file(ctx, SERVER_KEY_FILE, SSL_FILETYPE_ASN1) != 1) {
        printf("Load Server key %s failed\n", SERVER_KEY_FILE);
        goto err_handler;
    }
    printf("Loaded server key %s on context\n", SERVER_KEY_FILE);

    if (conf->with_client_auth == 1) {
        if (load_ca_cert(ctx, CAFILE1) != 0) {
            goto err_handler;
        }

        SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER | SSL_VERIFY_FAIL_IF_NO_PEER_CERT, NULL);
    }
    if (conf->proto_version != 0) {
        SSL_CTX_set_min_proto_version(ctx, conf->proto_version);
        SSL_CTX_set_max_proto_version(ctx, conf->proto_version);
    }

    if (conf->sess_ticket_count >= 0) {
        SSL_CTX_set_num_tickets(ctx, (size_t)conf->sess_ticket_count);
    }

    printf("SSL context configurations completed\n");

    return ctx;
err_handler:
    SSL_CTX_free(ctx);
    return NULL;
}

SSL *create_ssl_object(SSL_CTX *ctx, int lfd, PERF_CONF *conf)
{
    SSL *ssl;
    int fd;

    fd = do_tcp_accept(lfd);
    if (fd < 0) {
        printf("TCP connection establishment failed\n");
        return NULL;
    }

    ssl = SSL_new(ctx);
    if (!ssl) {
        printf("SSL object creation failed\n");
        return NULL;
    }

    SSL_set_fd(ssl, fd);

    return ssl;
}

int do_data_transfer(SSL *ssl)
{
    const char *msg = MSG_FOR_S_SERV;
    char buf[MAX_BUF_SIZE] = {0};
    int ret;

    ret = SSL_read(ssl, buf, sizeof(buf) - 1);
    if (ret <= 0) {
        printf("SSL_read failed ret=%d\n", ret);
        return -1;
    }
    printf("SSL_read[%d] %s\n", ret, buf);
    ret = SSL_write(ssl, msg, strlen(msg));
    if (ret <= 0) {
        printf("SSL_write failed ret=%d\n", ret);
        return -1;
    }
    printf("SSL_write[%d] sent %s\n", ret, msg);
    return 0;
}

void do_cleanup(SSL_CTX *ctx, SSL *ssl)
{
    int fd;
    if (ssl) {
        fd = SSL_get_fd(ssl);
        SSL_free(ssl);
        close(fd);
    }
    if (ctx) {
        SSL_CTX_free(ctx);
    }
}

void get_error()
{
    unsigned long error;
    const char *file = NULL, *func = "";
    int line= 0;
#ifdef WITH_OSSL_111
    error = ERR_get_error_line(&file, &line);
#elif defined WITH_OSSL_300
    error = ERR_get_error_all(&file, &line, &func, NULL, NULL);
#endif
    printf("Error reason=%d on [%s:%d:%s]\n", ERR_GET_REASON(error),
           file, line, func);
}

int do_tls_server(SSL_CTX *ctx, int lfd, PERF_CONF *conf)
{
    SSL *ssl = NULL;
    int ret_val = -1;
    int ret;

    ssl = create_ssl_object(ctx, lfd, conf);
    if (!ssl) {
        goto err_handler;
    }

    ret = SSL_accept(ssl);
    if (ret != 1) {
        printf("SSL accept failed%d\n", ret);
        if (SSL_get_error(ssl, ret) == SSL_ERROR_SSL) {
            get_error();
        }
        goto err_handler;
    }

    printf("SSL accept succeeded\n");
    printf("Negotiated\n");
    printf("    - Version: %s\n", SSL_get_version(ssl));
    printf("    - Ciphersuite: %s\n", SSL_CIPHER_get_name(SSL_get_current_cipher(ssl)));
    printf("    - KeyExch Group: %s\n",
#ifdef WITH_OSSL_111
            OBJ_nid2sn(SSL_get_shared_group(ssl, 0))
#elif defined WITH_OSSL_300
            OBJ_nid2sn(SSL_get_negotiated_group(ssl))
#endif
    );
    if (SSL_get_peer_certificate(ssl) != NULL) {
        printf("    - Performed client cert auth\n");
    }

    if (do_data_transfer(ssl)) {
        printf("Data transfer over TLS failed\n");
        goto err_handler;
    }
    SSL_shutdown(ssl);
    ret_val = 0;
err_handler:
    do_cleanup(NULL, ssl);
    return ret_val;
}

#define DEFAULT_SESS_TKT_COUNT -1
int init_conf(PERF_CONF *conf)
{
    memset(conf, 0, sizeof(PERF_CONF));
    if (sizeof(conf->ip) <= strlen(SERVER_IP)) {
        printf("Size of conf->ip is small [%zu]\n", sizeof(conf->ip));
        return -1;
    }
    strcpy(conf->ip, SERVER_IP);
    conf->port = SERVER_PORT;
    conf->sess_ticket_count = DEFAULT_SESS_TKT_COUNT;
    return 0;
}

void usage()
{
    printf("-help               Help\n");
    printf("-ip                 IP address to bind\n");
    printf("-port               Port number to bind\n");
    printf("-sess-tkt-count     Number of sess ticket server should issue after handshake\n");
    printf("-client-auth        To perform client authentication\n");
    printf("-tls1_0             TLS connection with TLSv1.0\n");
    printf("-tls1_1             TLS connection with TLSv1.1\n");
    printf("-tls1_2             TLS connection with TLSv1.2\n");
    printf("-tls1_3             TLS connection with TLSv1.3\n");
    return;
};

int parse_cli_args(int argc, char *argv[], PERF_CONF *conf) {
    int opt;

    while ((opt = getopt_long_only(argc, argv, "", lopts, NULL)) != -1) {
        switch (opt) {
            case CLI_HELP:
                usage();
                return 1;
            case CLI_IP:
                if (sizeof(conf->ip) <= strlen(optarg)) {
                    printf("Size of IP passed [%zu] is much bigger\n", strlen(optarg));
                    return -1;
                }
                strcpy(conf->ip, optarg);
                break;
            case CLI_PORT:
                conf->port = (uint16_t)atoi(optarg);
                break;
            case CLI_SESS_TICKET_COUNT:
                if (atoi(optarg) < 0) {
                    printf("Invalid sess ticket count [%s]\n", optarg);
                    goto err;
                }
                conf->sess_ticket_count = (uint32_t)atoi(optarg);
                printf("Session ticket num %d\n", conf->sess_ticket_count);
                break;
            case CLI_CLIENT_AUTH:
                conf->with_client_auth = 1;
                break;
            case CLI_TLS1_0:
                conf->proto_version = TLS1_VERSION;
                break;
            case CLI_TLS1_1:
                conf->proto_version = TLS1_1_VERSION;
                break;
            case CLI_TLS1_2:
                conf->proto_version = TLS1_2_VERSION;
                break;
            case CLI_TLS1_3:
                conf->proto_version = TLS1_3_VERSION;
                break;
        }
    }
    return 0;
err:
    return -1;
}

int do_tls_server_perf(PERF_CONF *conf)
{
    SSL_CTX *ctx;
    int ret_val = -1;
    int lfd;

    ctx = create_context(conf);
    if (!ctx) {
        return -1;
    }

    if ((lfd = do_tcp_listen(conf->ip, conf->port)) < 0) {
        goto err;
    }
    do {
        if (do_tls_server(ctx, lfd, conf) != 0) {
            printf("TLS server connection failed\n");
            goto err;
        }
    } while (1);
    ret_val = 0;
err:
    check_and_close(&lfd);
    do_cleanup(ctx, NULL);
    return ret_val;
}

void sig_handler(int signum)
{
    printf("Received signal [%d]\n", signum);
    exit(0);
}

int main(int argc, char *argv[])
{
    PERF_CONF conf;
    int ret;

    signal(SIGTERM, sig_handler);
    signal(SIGINT, sig_handler);
    signal(SIGABRT, sig_handler);
    if (init_conf(&conf) != 0 || (ret = parse_cli_args(argc, argv, &conf)) < 0) {
        return -1;
    } else if (ret == 1) { /* Print only help */
        return 0;
    }
    printf("OpenSSL version: %s, %s\n", OpenSSL_version(OPENSSL_VERSION),
            OpenSSL_version(OPENSSL_BUILT_ON));
    if (do_tls_server_perf(&conf) != 0) {
        return -1;
    }
    return 0;
}
