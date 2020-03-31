#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <errno.h>
#include <getopt.h>

#include "openssl/crypto.h"
#include "openssl/ssl.h"
#include "openssl/err.h"

#define SERVER_IP "127.0.0.1"
#define SERVER_PORT 4433
#define TCP_CON_RETRY_COUNT 20
#define TCP_CON_RETRY_WAIT_TIME_MS 200
#define TLS_SOCK_TIMEOUT_MS 8000

#define MAX_BUF_SIZE    1024
#define MSG_FOR_S_TIME "GET /index.html HTTP/1.1\r\nHOST: twt.com\r\n\r\n"

#define CAFILE1 "./certs/ECC_Prime256_Certs/rootcert.pem"
#define CAFILE2 "./certs/RSA_PSS_PSS_Certs/rootcert.pem"

#define CLIENT_CERT_FILE "./certs/ECC_Prime256_Certs/client_cert.der"
#define CLIENT_CERT_TYPE  SSL_FILETYPE_ASN1
#define CLIENT_PRIV_KEY_FILE "./certs/ECC_Prime256_Certs/client_key.der"
#define CLIENT_PRIV_KEY_TYPE SSL_FILETYPE_ASN1

#define MAX_IP_ADDR 32
typedef struct perf_conf_st {
    char ip[MAX_IP_ADDR];
    uint16_t port;
    uint32_t time_sec;
    int proto_version;
    uint32_t with_client_auth:1;
}PERF_CONF;

enum opt_enum {
    CLI_HELP = 1,
    CLI_IP,
    CLI_PORT,
    CLI_TIME,
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
    {"time", required_argument, NULL, CLI_TIME},
    {"client-auth", no_argument, NULL, CLI_CLIENT_AUTH},
    {"tls1_0", no_argument, NULL, CLI_TLS1_0},
    {"tls1_1", no_argument, NULL, CLI_TLS1_1},
    {"tls1_2", no_argument, NULL, CLI_TLS1_2},
    {"tls1_3", no_argument, NULL, CLI_TLS1_3},
};

int do_tcp_connection(const char *server_ip, uint16_t port)
{
    struct sockaddr_in serv_addr;
    int count = 0;
    int fd;
    int ret;

    fd = socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0) {
        printf("Socket creation failed\n");
        return -1;
    }

    serv_addr.sin_family = AF_INET;
    if (inet_aton(server_ip, &serv_addr.sin_addr) == 0) {
        printf("inet_aton failed\n");
        goto err_handler;
    }
    serv_addr.sin_port = htons(port);

    do {
        ret = connect(fd, (struct sockaddr *)&serv_addr, sizeof(serv_addr));
        if (ret) {
            printf("Connect failed, errno=%d\n", errno);
            goto err_handler;
        } else {
            break;
        }
        count++;
        usleep(TCP_CON_RETRY_WAIT_TIME_MS);
    } while (count < TCP_CON_RETRY_COUNT);

    return fd;
err_handler:
    close(fd);
    return -1;
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

    ctx = SSL_CTX_new(TLS_client_method());
    if (!ctx) {
        printf("SSL ctx new failed\n");
        return NULL;
    }

    if (load_ca_cert(ctx, CAFILE1) != 0) {
        goto err_handler;
    }

    SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER, NULL);
    SSL_CTX_set_verify_depth(ctx, 5);

    if (conf->with_client_auth == 1) {
        if (SSL_CTX_use_certificate_file(ctx, CLIENT_CERT_FILE, CLIENT_CERT_TYPE) != 1) {
            printf("Load client cert %s failed\n", CLIENT_CERT_FILE);
            goto err_handler;
        }
        printf("Loaded client cert %s\n", CLIENT_CERT_FILE);
        if (SSL_CTX_use_PrivateKey_file(ctx, CLIENT_PRIV_KEY_FILE, CLIENT_PRIV_KEY_TYPE) != 1) {
            printf("Load client key %s failed\n", CLIENT_PRIV_KEY_FILE);
            goto err_handler;
        }
        printf("Loaded client key %s\n", CLIENT_PRIV_KEY_FILE);
    }
    if (conf->proto_version != 0) {
        SSL_CTX_set_min_proto_version(ctx, conf->proto_version);
        SSL_CTX_set_max_proto_version(ctx, conf->proto_version);
    }

    return ctx;
err_handler:
    SSL_CTX_free(ctx);
    return NULL;
}

SSL *create_ssl_object(SSL_CTX *ctx, PERF_CONF *conf)
{
    SSL *ssl;
    int fd;

    fd = do_tcp_connection(conf->ip, conf->port);
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
    const char *msg = MSG_FOR_S_TIME;
    char buf[MAX_BUF_SIZE] = {0};
    int ret;

    ret = SSL_write(ssl, msg, strlen(msg));
    if (ret <= 0) {
        printf("SSL_write failed ret=%d\n", ret);
        return -1;
    }
    ret = SSL_read(ssl, buf, sizeof(buf) - 1);
    if (ret <= 0) {
        printf("SSL_read failed ret=%d\n", ret);
        return -1;
    }
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
    const char *file = NULL;
    int line= 0;
    error = ERR_get_error_line(&file, &line);
    printf("Error reason=%d on [%s:%d]\n", ERR_GET_REASON(error), file, line);
}

int do_tls_client(SSL_CTX *ctx, PERF_CONF *conf)
{
    SSL *ssl = NULL;
    int ret_val = -1;
    int ret;

    ssl = create_ssl_object(ctx, conf);
    if (!ssl) {
        goto err_handler;
    }

    ret = SSL_connect(ssl); 
    if (ret != 1) {
        printf("SSL connect failed%d\n", ret);
        if (SSL_get_error(ssl, ret) == SSL_ERROR_SSL) {
            get_error();
        }
        goto err_handler;
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

#define DEFAULT_TIME_SEC 30
int init_conf(PERF_CONF *conf)
{
    if (sizeof(conf->ip) <= strlen(SERVER_IP)) {
        printf("Size of conf->ip is small [%zu]\n", sizeof(conf->ip));
        return -1;
    }
    strcpy(conf->ip, SERVER_IP);
    conf->port = SERVER_PORT;
    conf->time_sec = DEFAULT_TIME_SEC;
    return 0;
}

void usage()
{
    printf("-help           Help\n");
    printf("-ip             IP address to connect\n");
    printf("-port           Port number to connect\n");
    printf("-time           Time to run (in second), default is 30 secs\n");
    printf("-client-auth    To perform client authentication\n");
    printf("-tls1_0         TLS connection with TLSv1.0\n");
    printf("-tls1_1         TLS connection with TLSv1.1\n");
    printf("-tls1_2         TLS connection with TLSv1.2\n");
    printf("-tls1_3         TLS connection with TLSv1.3\n");
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
            case CLI_TIME:
                if (atoi(optarg) <= 0) {
                    printf("Invalid time [%s]\n", optarg);
                    goto err;
                }
                conf->time_sec = (uint32_t)atoi(optarg);
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

int do_tls_client_perf(PERF_CONF *conf)
{
    SSL_CTX *ctx;
    time_t finish_time;
    uint32_t count = 0;
    int ret_val = -1;

    ctx = create_context(conf);
    if (!ctx) {
        return -1;
    }
    printf("Performing TLS connections for %d secs...\n", conf->time_sec);
    finish_time = conf->time_sec + time(NULL);
    do {
        if (finish_time <= time(NULL)) {
            break;
        }
        if (do_tls_client(ctx, conf) != 0) {
            printf("TLS client connection failed\n");
            fflush(stdout);
            goto err;
        }
        count++;
    } while (1);
    printf("%u TLS connections in %u secs\n", count, conf->time_sec);
    printf("%u connections/sec\n", count / conf->time_sec); 
    ret_val = 0;
err:
    do_cleanup(ctx, NULL);
    return ret_val;
}

int main(int argc, char *argv[])
{
    PERF_CONF conf;
    int ret;

    if (init_conf(&conf) != 0 || (ret = parse_cli_args(argc, argv, &conf)) < 0) {
        return -1;
    } else if (ret == 1) { /* Print only help */
        return 0;
    }
    printf("OpenSSL version: %s, %s\n", OpenSSL_version(OPENSSL_VERSION),
                                        OpenSSL_version(OPENSSL_BUILT_ON));
    if (do_tls_client_perf(&conf) != 0) {
        return -1;
    }
    return 0;
}
