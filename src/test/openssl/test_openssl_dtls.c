#include <netinet/in.h>
#include <arpa/inet.h>
#include "test_openssl_dtls.h"

int ssl_config_dtls_bio(TC_CONF *conf, SSL *ssl, const char *serv_ip, uint16_t serv_port)
{
    struct timeval recv_to;
    struct in_addr ipv4;
    BIO_ADDR *peer_addr = NULL;
    BIO *bio = NULL;
    int ret_val = -1;

    if (conf->fd < 0) {
        printf("Invalid UDP socket\n");
        return -1;
    }

    bio = BIO_new_dgram(conf->fd, BIO_NOCLOSE);
    if (!bio) {
        printf("BIO new failed\n");
        goto err;
    }

    if (conf->server == 0) {
        if (inet_aton(serv_ip, &ipv4) != 1) {
            printf("Invalid server ip %s\n", serv_ip);
            return -1;
        }

        peer_addr = BIO_ADDR_new();
        if (!peer_addr) {
            printf("BIO ADDR new failed\n");
            return -1;
        }

        if (BIO_ADDR_rawmake(peer_addr, AF_INET, &ipv4, sizeof(ipv4), htons(serv_port)) != 1) {
            printf("BIO ADDR rawmake failed\n");
            goto err;
        }

        if (BIO_dgram_set_peer(bio, peer_addr) != 1) {
            printf("BIO dgram set peer failed\n");
            goto err;
        }
    }

    recv_to.tv_sec = TLS_SOCK_TIMEOUT_MS / 1000;
    recv_to.tv_usec = (TLS_SOCK_TIMEOUT_MS % 1000) * 1000;
    
    if (BIO_ctrl(bio, BIO_CTRL_DGRAM_SET_RECV_TIMEOUT, 0, &recv_to) != 1) {
        printf("BIO set recv timeout failed\n");
        goto err;
    }

    if (BIO_ctrl(bio, BIO_CTRL_DGRAM_SET_MTU, DTLS_MTU, NULL) != DTLS_MTU) {
        printf("BIO set mtu failed\n");
        goto err;
    }

    SSL_set_bio(ssl, bio, bio);
    bio = NULL;

    printf("BIO DGRAM configured for DTLS\n");
    ret_val = 0;
err:
    BIO_ADDR_free(peer_addr);
    if (bio) {
        BIO_free(bio);
    }
    return ret_val;
}
