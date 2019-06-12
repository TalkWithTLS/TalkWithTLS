#include "test_openssl_common.h"

int create_listen_sock(TC_CONF *conf)
{
    if (conf->server) {
        if (conf->tcp_listen_fd == -1) {
            conf->tcp_listen_fd = do_tcp_listen(SERVER_IP, SERVER_PORT);
            if (conf->tcp_listen_fd < 0) {
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
        /* tcp_listen_fd would have already created */
        conf->fd = do_tcp_accept(conf->tcp_listen_fd);
        if (conf->fd < 0) {
            printf("TCP connection establishment failed\n");
            return -1;
        }
        close_listen_sock(conf);
    } else {
        conf->fd = do_tcp_connection(SERVER_IP, SERVER_PORT);
        if (conf->fd < 0) {
            printf("TCP connection establishment failed\n");
            return -1;
        }
    }
    return 0;
}

