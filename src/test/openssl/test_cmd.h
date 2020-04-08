#ifndef _TEST_CMD_H_
#define _TEST_CMD_H_

#ifdef __cplusplus
extern "C" {
#endif

#include "test_conf.h"

int receive_tc(TC_AUTOMATION *ta, char *buf, size_t buf_size);

int send_tc_result(TC_AUTOMATION *ta, int result);

#ifdef __cplusplus
}
#endif

#endif
