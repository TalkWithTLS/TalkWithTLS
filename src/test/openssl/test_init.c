#include "test_conf.h"
#include "test_init.h"

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

int init_test_sock_addr(TC_CONF *conf, const char *ip, uint16_t port)
{
    if (strlen(ip) >= sizeof(conf->bind_addr.ip)) {
        ERR("Insufficient space in TC_CONF for storing bind addr IP\n");
        return -1;
    }
    strcpy(conf->bind_addr.ip, ip);
    conf->bind_addr.port = port;
    return 0;
}

/* init_tc_conf gets called before parsing CLI args */
int init_tc_conf(TC_CONF *conf)
{
    memset(conf, 0, sizeof(TC_CONF));
    conf->test_con_state.tcp_listen_fd = conf->test_con_state.con_fd = -1;
    if (init_test_sock_addr(conf, DEFAULT_TEST_IP, DEFAULT_TEST_PORT) != 0) {
        return -1;
    }
    if (init_psk_params(conf, DEFAULT_PSK_ID, DEFAULT_PSK_KEY) != 0) {
        ERR("Initializing psk params failed\n");
        return -1;
    }
    return 0;
}

int create_listen_sock(TC_CONF *conf)
{
    TEST_CON_STATE *test_con_state = &conf->test_con_state;
    if (conf->server == 1) {
        if (conf->dtls == 0) {
            if ((test_con_state->tcp_listen_fd == -1)
                    && ((test_con_state->tcp_listen_fd = do_tcp_listen(SERVER_IP, SERVER_PORT)) < 0)) {
                return -1;
            }
        } else {
            if ((test_con_state->con_fd == -1)
                    && ((test_con_state->con_fd = create_udp_serv_sock(SERVER_IP, SERVER_PORT)) < 0)) {
                return -1;
            }
        }
    }
    return 0;
}

int create_sock_connection(TC_CONF *conf)
{
    TEST_CON_STATE *test_con_state = &conf->test_con_state;
    if (conf->server) {
        if (conf->dtls == 0) {
            /* tcp_listen_fd would have already created */
            test_con_state->con_fd = do_tcp_accept(test_con_state->tcp_listen_fd);
        }
        /* No need to create any fd at this place for DTLS
         * As already created in above function */
        if (test_con_state->con_fd < 0) {
            ERR("TCP/UDP connection establishment failed\n");
            return -1;
        }
    } else {
        if (conf->dtls == 0) {
            test_con_state->con_fd = do_tcp_connection(SERVER_IP, SERVER_PORT);
        } else {
            test_con_state->con_fd = create_udp_sock();
        }
        if (test_con_state->con_fd < 0) {
            ERR("TCP/UDP connection establishment failed\n");
            return -1;
        }
    }
    return 0;
}

void close_sock_connection(TEST_CON_STATE *test_con_state)
{
    check_and_close(&test_con_state->con_fd);
}

void close_listen_sock(TEST_CON_STATE *con_state)
{
    check_and_close(&con_state->tcp_listen_fd);
}

void fini_tc_conf(TC_CONF *conf)
{
    if (conf->server) {
        close_listen_sock(&conf->test_con_state);
    }
    if (conf->fini) {
        conf->fini(conf);
    }
}

int init_tc_automation(TC_AUTOMATION *ta, const char *argv1)
{
    ta->test_lfd = ta->test_fd = -1;
    ta->argv1 = strdup(argv1);
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
