#include "test_conf.h"
#include "test_init.h"

#include <unistd.h>

#define TC_CMD_RECV_TIMEOUT_SEC 5

int test_sock_addr_ip(SOCK_ADDR *addr, const char *ip)
{
    if (strlen(ip) >= sizeof(addr->ip)) {
        ERR("Insufficient space for storing bind addr IP\n");
        return TWT_FAILURE;
    }
    strcpy(addr->ip, ip);
    return TWT_SUCCESS;
}

int init_test_sock_addr(TEST_SOCK_ADDR *taddr)
{
    memset(taddr, 0, sizeof(TEST_SOCK_ADDR));
    test_sock_addr_ip(&taddr->tc_automation_addr, TC_AUTOMATION_IP);
    taddr->tc_automation_addr.port = TC_AUTOMATION_PORT;
    test_sock_addr_ip(&taddr->test_addr, SERVER_IP);
    taddr->test_addr.port = SERVER_PORT;
    test_sock_addr_ip(&taddr->peer_addr_to_con, SERVER_IP);
    taddr->peer_addr_to_con.port = SERVER_PORT;
    DBG("Initialized Test sock address\n");
    return TWT_SUCCESS;
}

int test_sock_addr_port_off(TEST_SOCK_ADDR *taddr, uint16_t port_off)
{
    taddr->port_off = port_off;
    taddr->tc_automation_addr.port += port_off;
    taddr->test_addr.port += port_off;
    taddr->peer_addr_to_con.port += port_off;
    return TWT_SUCCESS;
}

int test_sock_addr_port_to_connect(TEST_SOCK_ADDR *taddr, const char *ip_port)
{
    char *ip_port_str, *token, *rest;
    int ret_val = TWT_FAILURE, count = 1;
    if ((ip_port_str = strdup(ip_port)) == NULL) {
        ERR("IP Port string dup failed\n");
        return TWT_FAILURE;
    }
    rest = ip_port_str;
    while (((token = strtok_r(rest, ":", &rest)) != NULL) && (count <= 2)) {
        switch (count) {
            case 1:
                if (strlen(token) >= sizeof(taddr->peer_addr_to_con.ip)) {
                    ERR("Unsupported length IP address %s\n", token);
                    goto err;
                }
                strcpy(taddr->peer_addr_to_con.ip, token);
                break;
            case 2:
                if (atoi(token) <= 0) {
                    ERR("Invalid port %s\n", token);
                    goto err;
                }
                taddr->peer_addr_to_con.port = atoi(token) + taddr->port_off;
                break;
        }
        count++;
    }
    DBG("Updated socket address to connect as [%s]\n", ip_port);
    ret_val = TWT_SUCCESS;
err:
    free(ip_port_str);
    return ret_val;
}

int test_sock_addr_tc_automation(TEST_SOCK_ADDR *taddr, const char *str)
{
    char *data, *token, *rest;
    int idx = 0;

    DBG("TC automation address details [%s]\n", str);
    if ((data = (char *)malloc(strlen(str) + 1)) == NULL) {
        ERR("Malloc failed\n");
        return TWT_FAILURE;
    }
    strcpy(data, str);

    rest = data;
    while ((token = strtok_r(rest, ",", &rest)) != NULL) {
        switch (idx) {
            case 0:
                taddr->tc_automation_addr.port = atoi(token);
                break;
            case 1:
                taddr->test_addr.port = atoi(token);
                break;
            case 2:
                test_sock_addr_port_off(taddr, atoi(token));
                break;
        }
        idx++;
    }
    free(data);
    return TWT_SUCCESS;
}

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

int init_test_serv_fd(TEST_SERV_FD *test_serv_fd)
{
    memset(test_serv_fd, 0, sizeof(TEST_SERV_FD));
    test_serv_fd->tcp_listen_fd = test_serv_fd->udp_serv_fd = -1;
    return TWT_SUCCESS;
}

void fini_test_serv_fd(TEST_SERV_FD *test_serv_fd)
{
    check_and_close(&test_serv_fd->tcp_listen_fd);
    check_and_close(&test_serv_fd->udp_serv_fd);
}

int create_tls_test_serv_sock(TEST_SERV_FD *tsfd, TEST_SOCK_ADDR *taddr)
{
    if ((tsfd->tcp_listen_fd == -1)
            && ((tsfd->tcp_listen_fd = do_tcp_listen(taddr->test_addr.ip,
                                            taddr->test_addr.port)) < 0)) {
        return TWT_FAILURE;
    }
    return TWT_SUCCESS;
}

int create_dtls_test_serv_sock(TEST_SERV_FD *tsfd, TEST_SOCK_ADDR *taddr)
{
    if ((tsfd->udp_serv_fd == -1)
            && ((tsfd->udp_serv_fd = create_udp_serv_sock(taddr->test_addr.ip,
                                            taddr->test_addr.port)) < 0)) {
        return TWT_FAILURE;
    }
    return TWT_SUCCESS;
}

int create_test_serv_sock(TC_CONF *conf)
{
    if (conf->server == 1) {
        if (conf->dtls == 0) {
            return create_tls_test_serv_sock(conf->test_serv_fd, conf->taddr);
        } else {
            return create_dtls_test_serv_sock(conf->test_serv_fd, conf->taddr);
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
            test_con_fd->con_fd = do_tcp_connection(conf->taddr->peer_addr_to_con.ip,
                                                    conf->taddr->peer_addr_to_con.port);
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

int init_tc_automation(TC_AUTOMATION *ta, const char *argv1)
{
    memset(ta, 0, sizeof(TC_AUTOMATION));
    ta->test_lfd = ta->test_fd = -1;
    ta->argv1 = strdup(argv1);
    return TWT_SUCCESS;
}

int create_tc_automation_sock(TC_AUTOMATION *ta, TEST_SOCK_ADDR *taddr)
{
    if ((ta->test_lfd = do_tcp_listen(taddr->tc_automation_addr.ip,
                                      taddr->tc_automation_addr.port)) < 0) {
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
