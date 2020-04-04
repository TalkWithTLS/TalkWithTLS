#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>

#include "openssl/crypto.h"
#include "openssl/ssl.h"

#include "test_conf.h"
#include "test_init.h"
#include "test_openssl_common.h"
#include "test_openssl_arg.h"
#include "test_openssl_kexch.h"
#include "test_openssl_auth.h"

void tc_conf_dtls(TC_CONF *conf)
{
    if ((conf->max_version == TC_CONF_DTLS_1_0_VERSION) ||
            (conf->max_version == TC_CONF_DTLS_1_2_VERSION)) {
        conf->dtls = 1;
    }
}

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
    tc_conf_dtls(conf);
    return 0;
}

int start_test_case(int argc, char *argv[], TC_AUTOMATION *ta)
{
    TC_CONF conf = {0};
    int ret_val = -1;
    int ret;

    if (init_tc_conf(&conf) != 0
            || init_tc_conf_for_openssl(&conf) != 0) {
        printf("TC conf failed\n");
        goto end;
    }

    if (((ret = parse_arg(argc, argv, &conf)) == TWT_START_AUTOMATION) && (ta != NULL)) {
        ta->bind_addr = conf.bind_addr;
        fini_tc_conf(&conf);
        ret_val = TWT_START_AUTOMATION;
        goto end;
    } else if (ret == TWT_CLI_HELP) {
        /* Printed only help */
        ret_val = 0;
        goto end;
    } else if (ret == TWT_FAILURE) {
        printf("Parsing arg failed\n");
        goto end;
    }

    /* Else continue executing one TC */

    /* Based on CLI arguments does some internal initialization which will be used in further
     * test scripts */
    if (tc_conf_update(&conf) != 0) {
        return -1;
    }

    ret_val = do_test_openssl(&conf);
end:
    fini_tc_conf(&conf);
    fflush(stdout);
    return ret_val;
}

#define MAX_TC_MSG 1024
int start_test_automation(TC_AUTOMATION *ta)
{
    //uint8_t buf[MAX_TC_MSG];
    int ret_val = TWT_FAILURE;
    if (create_tc_automation_sock(ta) != 0
            || accept_tc_automation_con(ta) != 0) {
        printf("TC socket creation failed\n");
        goto err;
    }
    /* TODO Accept has to be done for every TC */
    /* TODO Need to implement receive msg and call start_test_case */
    /*do {
        memset(buf, 0, sizeof(buf));
        if (receive_testcase(ta, buf, sizeof(buf)) != 0) {
            printf("Receive testcase failed\n");
            goto err;
        }
    } while (1);*/
err:
    return ret_val;
}

int main(int argc, char *argv[])
{
    TC_AUTOMATION ta = {0};
    int ret;

    if (init_tc_automation(&ta) != 0) {
        return TWT_FAILURE;
    }
    if ((ret = start_test_case(argc, argv, &ta)) == TWT_START_AUTOMATION) {
        ret = start_test_automation(&ta);
        fini_tc_automation(&ta);
    }
    return ret;
}
