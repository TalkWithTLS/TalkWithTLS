#include "test_conf.h"
#include "test_init.h"

#include <unistd.h>

#define TC_CMD_RECV_TIMEOUT_SEC 5

int init_psk_params(TC_CONF *conf, const char *psk_id, const char *psk_key)
{
    if ((strlen(psk_id) >= sizeof(conf->res.psk_id))
            || (strlen(psk_key) >= sizeof(conf->res.psk_key))) {
        ERR("Insufficient space in TC_CONF for storing PSK\n");
        return -1;
    }
    strcpy(conf->res.psk_id, psk_id);
    conf->res.psk_id_len = strlen(psk_id);
    strcpy(conf->res.psk_key, psk_key);
    conf->res.psk_key_len = strlen(psk_key);
    return 0;
}

/* init_tc_conf gets called before parsing CLI args */
int init_tc_conf(TC_CONF *conf)
{
    memset(conf, 0, sizeof(TC_CONF));
    conf->test_con_fd.con_fd = -1;
    if (init_psk_params(conf, DEFAULT_PSK_ID, DEFAULT_PSK_KEY) != 0) {
        ERR("Initializing psk params failed\n");
        return -1;
    }
    return 0;
}

int init_test_sock_addr(TEST_SERV_FD *test_serv_fd, const char *ip, uint16_t port)
{
    if (strlen(ip) >= sizeof(test_serv_fd->test_addr.ip)) {
        ERR("Insufficient space in TC_CONF for storing test addr IP\n");
        return -1;
    }
    strcpy(test_serv_fd->test_addr.ip, ip);
    test_serv_fd->test_addr.port = port;
    return 0;
}

int init_test_serv_fd(TEST_SERV_FD *test_serv_fd)
{
    memset(test_serv_fd, 0, sizeof(TEST_SERV_FD));
    /* PORT gets added later by instance ID */
    if (init_test_sock_addr(test_serv_fd, SERVER_IP, SERVER_PORT) != 0) {
        return TWT_FAILURE;
    }
    test_serv_fd->tcp_listen_fd = test_serv_fd->udp_serv_fd = -1;
    return TWT_SUCCESS;
}

void fini_test_serv_fd(TEST_SERV_FD *test_serv_fd)
{
    check_and_close(&test_serv_fd->tcp_listen_fd);
    check_and_close(&test_serv_fd->udp_serv_fd);
}

int create_tls_test_serv_sock(TEST_SERV_FD *tsfd)
{
    if ((tsfd->tcp_listen_fd == -1)
            && ((tsfd->tcp_listen_fd = do_tcp_listen(tsfd->test_addr.ip,
                                            tsfd->test_addr.port)) < 0)) {
        return TWT_FAILURE;
    }
    return TWT_SUCCESS;
}

int create_dtls_test_serv_sock(TEST_SERV_FD *tsfd)
{
    if ((tsfd->udp_serv_fd == -1)
            && ((tsfd->udp_serv_fd = create_udp_serv_sock(tsfd->test_addr.ip,
                                            tsfd->test_addr.port)) < 0)) {
        return TWT_FAILURE;
    }
    return TWT_SUCCESS;
}

int create_test_serv_sock(TC_CONF *conf)
{
    if (conf->server == 1) {
        if (conf->dtls == 0) {
            return create_tls_test_serv_sock(conf->test_serv_fd);
        } else {
            return create_dtls_test_serv_sock(conf->test_serv_fd);
        }
    }
    return TWT_SUCCESS;
}

int create_sock_connection(TC_CONF *conf)
{
    TEST_CON_FD *test_con_fd = &conf->test_con_fd;
    if (conf->server) {
        if (conf->dtls == 0) {
            /* tcp_listen_fd would have already created */
            test_con_fd->con_fd = do_tcp_accept(conf->test_serv_fd->tcp_listen_fd);
        } else {
            /* TODO Need to create con_fd and connect to peer fd */
            test_con_fd->con_fd = dup(conf->test_serv_fd->udp_serv_fd);
        }
        if (test_con_fd->con_fd < 0) {
            ERR("TCP/UDP fd connection establishment failed\n");
            return -1;
        }
    } else {
        if (conf->dtls == 0) {
            test_con_fd->con_fd = do_tcp_connection(conf->test_serv_fd->test_addr.ip,
                                                       conf->test_serv_fd->test_addr.port);
        } else {
            test_con_fd->con_fd = create_udp_sock();
        }
        if (test_con_fd->con_fd < 0) {
            ERR("TCP/UDP connection establishment failed\n");
            return -1;
        }
    }
    return 0;
}

void close_sock_connection(TEST_CON_FD *test_con_fd)
{
    check_and_close(&test_con_fd->con_fd);
}

void fini_tc_conf(TC_CONF *conf)
{
    close_sock_connection(&conf->test_con_fd);
    if (conf->fini) {
        conf->fini(conf);
    }
}

int init_tc_automation_sock_addr(TC_AUTOMATION *ta, const char *ip, uint16_t port)
{
    if (strlen(ip) >= sizeof(ta->bind_addr.ip)) {
        ERR("Insufficient space in TC_CONF for storing bind addr IP\n");
        return -1;
    }
    strcpy(ta->bind_addr.ip, ip);
    ta->bind_addr.port = port;
    return 0;
}

int init_tc_automation(TC_AUTOMATION *ta, const char *argv1)
{
    ta->test_lfd = ta->test_fd = -1;
    ta->argv1 = strdup(argv1);
    /* PORT gets added later by instance ID */
    if (init_tc_automation_sock_addr(ta, DEFAULT_TEST_IP, DEFAULT_TEST_PORT) != 0) {
        return -1;
    }
    return TWT_SUCCESS;
}

int create_tc_automation_sock(TC_AUTOMATION *ta)
{
    if ((ta->test_lfd = do_tcp_listen(ta->bind_addr.ip, ta->bind_addr.port)) < 0) {
        ERR("Initializing Test FD failed\n");
        return TWT_FAILURE;
    }
    return TWT_SUCCESS;
}

int accept_tc_automation_con(TC_AUTOMATION *ta)
{
    if (((ta->test_fd = do_tcp_accept(ta->test_lfd)) < 0)
            || (set_receive_to(ta->test_fd, TC_CMD_RECV_TIMEOUT_SEC) != 0)) {
        ERR("TCP accept or set timeout failed\n");
        return TWT_FAILURE;
    }
    DBG("Test con created, fd=%d\n", ta->test_fd);
    return TWT_SUCCESS;
}

void close_tc_automation_con(TC_AUTOMATION *ta)
{
    check_and_close(&ta->test_fd);
}

void fini_tc_automation(TC_AUTOMATION *ta)
{
    check_and_close(&ta->test_fd);
    check_and_close(&ta->test_lfd);
    free(ta->argv1);
}
