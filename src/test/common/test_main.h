#ifndef _TEST_MAIN_H_
#define _TEST_MAIN_H_

#ifdef __cplusplus
extern "C" {
#endif

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>

#include "test_conf.h"
#include "test_init.h"
#include "test_cmd.h"
#include "test_cli_arg.h"

typedef struct sut_st {
    int (*do_test_sut_func)(TC_CONF *conf);
}SUT;

int test_main(int argc, char **argv, SUT *sut);

#ifdef __cplusplus
}
#endif

#endif
