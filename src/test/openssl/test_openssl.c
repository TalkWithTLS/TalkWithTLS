#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>

#include "openssl/crypto.h"
#include "openssl/ssl.h"

#include "test_common.h"
#include "test_openssl_common.h"
#include "test_openssl_arg.h"
#include "test_openssl_kexch.h"
#include "test_openssl_auth.h"

int tc_conf_update(TC_CONF *conf)
{
    if (tc_conf_kexch(conf)) {
        printf("TC conf for kexch failed\n");
        return -1;
    }
    if (tc_conf_auth(conf)) {
        printf("TC conf for authentication failed\n");
        return -1;
    }
    return 0;
}

int main(int argc, char *argv[])
{
    TC_CONF conf;
    int ret_val = -1;
    int ret;

    if (init_tc_conf(&conf)) {
        printf("TC conf failed\n");
        return -1;
    }

    ret = parse_arg(argc, argv, &conf);
    if (ret == -1) {
        printf("Parsing arg failed\n");
        return -1;
    }
    if (ret == 1) {
        /* Printed only help */
        ret_val =  0;
        goto err;
    }

    if (tc_conf_update(&conf)) {
        return -1;
    }

    ret_val = do_test_openssl(&conf);
err:
    fini_tc_conf(&conf);
    fflush(stdout);
    return ret_val;
}
