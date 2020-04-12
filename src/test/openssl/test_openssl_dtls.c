#include <netinet/in.h>
#include <arpa/inet.h>
#include "test_openssl_dtls.h"

int ssl_config_dtls_bio(TC_CONF *conf, SSL *ssl)
{
    struct timeval recv_to;
    struct in_addr ipv4;
    BIO_ADDR *peer_addr = NULL;
    BIO *bio = NULL;
    int ret_val = -1;

    if (conf->test_con_fd.con_fd < 0) {
        ERR("Invalid UDP socket\n");
        return -1;
    }

    bio = BIO_new_dgram(conf->test_con_fd.con_fd, BIO_NOCLOSE);
    if (!bio) {
        ERR("BIO new failed\n");
        goto err;
    }

    if (conf->server == 0) {
        if (inet_aton(conf->taddr->peer_addr_to_con.ip, &ipv4) != 1) {
            ERR("Invalid server ip %s\n", conf->taddr->peer_addr_to_con.ip);
            return -1;
        }

        peer_addr = BIO_ADDR_new();
        if (!peer_addr) {
            ERR("BIO ADDR new failed\n");
            return -1;
        }

        if (BIO_ADDR_rawmake(peer_addr, AF_INET, &ipv4, sizeof(ipv4),
                             htons(conf->taddr->peer_addr_to_con.port)) != 1) {
            ERR("BIO ADDR rawmake failed\n");
            goto err;
        }

        if (BIO_dgram_set_peer(bio, peer_addr) != 1) {
            ERR("BIO dgram set peer failed\n");
            goto err;
        }
    }

    recv_to.tv_sec = TLS_SOCK_TIMEOUT_MS / 1000;
    recv_to.tv_usec = (TLS_SOCK_TIMEOUT_MS % 1000) * 1000;
    
    if (BIO_ctrl(bio, BIO_CTRL_DGRAM_SET_RECV_TIMEOUT, 0, &recv_to) != 1) {
        ERR("BIO set recv timeout failed\n");
        goto err;
    }

    if (BIO_ctrl(bio, BIO_CTRL_DGRAM_SET_MTU, DTLS_MTU, NULL) != DTLS_MTU) {
        ERR("BIO set mtu failed\n");
        goto err;
    }

    SSL_set_bio(ssl, bio, bio);
    bio = NULL;

    DBG("BIO DGRAM configured for DTLS\n");
    ret_val = 0;
err:
    BIO_ADDR_free(peer_addr);
    if (bio) {
        BIO_free(bio);
    }
    return ret_val;
}
