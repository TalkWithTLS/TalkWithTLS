#ifndef _TEST_INIT_H_
#define _TEST_INIT_H_

#ifdef __cplusplus
extern "C" {
#endif

#include "test_conf.h"

/* TC Config init fini functions */
int init_tc_conf(TC_CONF *conf);

void fini_tc_conf(TC_CONF *conf);

int init_psk_params(TC_CONF *conf, const char *psk_id, const char *psk_key);

/* TC Automation init fini functions */
int init_tc_automation(TC_AUTOMATION *ta, const char *argv1);

int create_tc_automation_sock(TC_AUTOMATION *ta);

int accept_tc_automation_con(TC_AUTOMATION *ta);

void close_tc_automation_con(TC_AUTOMATION *ta);

void fini_tc_automation(TC_AUTOMATION *ta);

#ifdef __cplusplus
}
#endif

#endif
