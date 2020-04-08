#include "test_conf.h"
#include "test_init.h"

int init_psk_params(TC_CONF *conf, const char *psk_id, const char *psk_key)
{
    if ((strlen(psk_id) >= sizeof(conf->res.psk_id))
            || (strlen(psk_key) >= sizeof(conf->res.psk_key))) {
        printf("Insufficient space in TC_CONF for storing PSK\n");
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
        printf("Insufficient space in TC_CONF for storing bind addr IP\n");
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
    conf->tcp_listen_fd = conf->fd = -1;
    if (init_test_sock_addr(conf, DEFAULT_TEST_IP, DEFAULT_TEST_PORT) != 0) {
        return -1;
    }
    if (init_psk_params(conf, DEFAULT_PSK_ID, DEFAULT_PSK_KEY) != 0) {
        printf("Initializing psk params failed\n");
        return -1;
    }
    return 0;
}

void fini_tc_conf(TC_CONF *conf)
{
    if (conf->server) {
        check_and_close(&conf->tcp_listen_fd);
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
        printf("Initializing Test FD failed\n");
        return TWT_FAILURE;
    }
    return TWT_SUCCESS;
}

int accept_tc_automation_con(TC_AUTOMATION *ta)
{
    if ((ta->test_fd = do_tcp_accept(ta->test_lfd)) < 0) {
        printf("TCP accept failed\n");
        return TWT_FAILURE;
    }
    printf("Test con created, fd=%d\n", ta->test_fd);
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
