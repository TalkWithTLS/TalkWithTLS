#ifndef _TEST_INIT_H_
#define _TEST_INIT_H_

#ifdef __cplusplus
extern "C" {
#endif

#include "test_conf.h"

int init_test_sock_addr(TEST_SOCK_ADDR *taddr);

int test_sock_addr_port_to_connect(TEST_SOCK_ADDR *taddr, const char *ip_port);

int test_sock_addr_tc_automation(TEST_SOCK_ADDR *taddr, const char *str);

int init_tc_conf(TC_CONF *conf);

void fini_tc_conf(TC_CONF *conf);

int init_psk_params(TC_CONF *conf, const char *psk_id, const char *psk_key);

int init_test_serv_fd(TEST_SERV_FD *test_serv_fd);

void fini_test_serv_fd(TEST_SERV_FD *test_serv_fd);

int create_tls_test_serv_sock(TEST_SERV_FD *tsfd, TEST_SOCK_ADDR *taddr);

int create_dtls_test_serv_sock(TEST_SERV_FD *tsfd, TEST_SOCK_ADDR *taddr);

int create_test_serv_sock(TC_CONF *conf);

int create_sock_connection(TC_CONF *conf);

void close_sock_connection(TEST_CON_FD *test_con_fd);

/* TC Automation init fini functions */
int init_tc_automation(TC_AUTOMATION *ta, const char *argv1);

int create_tc_automation_sock(TC_AUTOMATION *ta, TEST_SOCK_ADDR *taddr);

int accept_tc_automation_con(TC_AUTOMATION *ta);

void close_tc_automation_con(TC_AUTOMATION *ta);

void fini_tc_automation(TC_AUTOMATION *ta);

#ifdef __cplusplus
}
#endif

#endif
