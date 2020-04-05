#ifndef _TEST_INIT_H_
#define _TEST_INIT_H_

#ifdef __cplusplus
extern "C" {
#endif

#include "test_conf.h"

int init_tc_conf(TC_CONF *conf);

void fini_tc_conf(TC_CONF *conf);

int init_tc_automation(TC_AUTOMATION *ta);

int init_psk_params(TC_CONF *conf, const char *psk_id, const char *psk_key);

int init_tc_automation(TC_AUTOMATION *ta);

int create_tc_automation_sock(TC_AUTOMATION *ta);

int accept_tc_automation_con(TC_AUTOMATION *ta);

void close_tc_automation_con(TC_AUTOMATION *ta);

void fini_tc_automation(TC_AUTOMATION *ta);

#ifdef __cplusplus
}
#endif

#endif
