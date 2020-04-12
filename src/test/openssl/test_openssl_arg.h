#ifndef _TEST_OPENSSL_ARG_H_
#define _TEST_OPENSSL_ARG_H_

#ifdef __cplusplus
extern "C" {
#endif

#include "test_openssl_common.h"

int parse_args(int argc, char **argv, TC_CONF *conf);

#ifdef __cplusplus
}
#endif

#endif
