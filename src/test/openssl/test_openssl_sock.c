#include "test_openssl_common.h"

int create_listen_sock(TC_CONF *conf)
{
    if (conf->server == 1) {
        if (conf->dtls == 0) {
            if ((conf->tcp_listen_fd == -1)
                    && ((conf->tcp_listen_fd = do_tcp_listen(SERVER_IP, SERVER_PORT)) < 0)) {
                return -1;
            }
        } else {
            if ((conf->fd == -1)
                    && ((conf->fd = create_udp_serv_sock(SERVER_IP, SERVER_PORT)) < 0)) {
                return -1;
            }
        }
    }
    return 0;
}

void close_listen_sock(TC_CONF *conf)
{
    check_and_close(&conf->tcp_listen_fd);
}

int create_sock_connection(TC_CONF *conf)
{
    if (conf->server) {
        if (conf->dtls == 0) {
            /* tcp_listen_fd would have already created */
            conf->fd = do_tcp_accept(conf->tcp_listen_fd);
            close_listen_sock(conf);
        }
        /* No need to create any fd at this place for DTLS
         * As already created in above function */
        if (conf->fd < 0) {
            printf("TCP/UDP connection establishment failed\n");
            return -1;
        }
    } else {
        if (conf->dtls == 0) {
            conf->fd = do_tcp_connection(SERVER_IP, SERVER_PORT);
        } else {
            conf->fd = create_udp_sock();
        }
        if (conf->fd < 0) {
            printf("TCP/UDP connection establishment failed\n");
            return -1;
        }
    }
    return 0;
}

