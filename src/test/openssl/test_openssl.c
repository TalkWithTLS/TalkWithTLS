#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <errno.h>

#include "openssl/crypto.h"
#include "openssl/ssl.h"

#include "test_conf.h"
#include "test_init.h"
#include "test_cmd.h"
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

int start_test_case(int argc, char **argv, TC_AUTOMATION *ta)
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

#define ARGV_BUCKET_FACTOR 4
int update_args(int *argc_out, char ***argv_out, char *token)
{
    char *token_dup;
    char **argv;
    int i;
    if ((*argc_out % ARGV_BUCKET_FACTOR) == 0) {
        if ((argv = (char **)malloc(sizeof(char *) * (*argc_out + ARGV_BUCKET_FACTOR))) == NULL) {
            printf("Expanding argv failed for len=%d\n", *argc_out + ARGV_BUCKET_FACTOR);
            return TWT_FAILURE;
        }
        memset(argv, 0, sizeof(char *) * (*argc_out + ARGV_BUCKET_FACTOR));
        for (i = 0; i < *argc_out; i++) {
            argv[i] = *((*argv_out) + i);
        }
        free(*argv_out);
        *argv_out = argv;
    }
    if (token != NULL) {
        if ((token_dup = strdup(token)) == NULL) {
            return TWT_FAILURE;
        }
        *((*argv_out) + *argc_out) = token_dup;
    }
    *argc_out += 1;
    return TWT_SUCCESS;
}

void free_args(int argc, char ***argv)
{
    int i;
    for (i = 0; i < argc; i++) {
        free(*((*argv) + i));
    }
    free(*argv);
    *argv = NULL;
}

void print_args(int argc, char **argv)
{
    int i;
    printf("argv list -\n");
    for (i = 0; i < argc; i++) {
        printf("%s\n", argv[i]);
    }
}

int split_args(TC_AUTOMATION *ta, char *buf, int *argc_out, char ***argv_out)
{
    char *token;
    char *rest = buf;
    /* Keep exe name as 1st entry in argv */
    update_args(argc_out, argv_out, ta->argv1);
    while ((token = strtok_r(rest, " ", &rest)) != NULL) {
        if (update_args(argc_out, argv_out, token) == TWT_FAILURE) {
            return TWT_FAILURE;
        }
    }
    update_args(argc_out, argv_out, NULL);
    *argc_out -= 1; /* Dont count NULL pointer at last */
    return TWT_SUCCESS;
}

int do_test(TC_AUTOMATION *ta, char *tc_cmd)
{
    int argc = 0, ret_val = TWT_FAILURE;
    char **argv = NULL;
    if (split_args(ta, tc_cmd, &argc, &argv) == TWT_FAILURE) {
        goto finish;
    }
    print_args(argc, argv);
    ret_val = start_test_case(argc, argv, NULL);
finish:
    free_args(argc, &argv);
    return ret_val;
}

#define MAX_TC_MSG 1024
int do_test_automation(TC_AUTOMATION *ta)
{
    int ret_val = TWT_FAILURE;
    int tc_result, ret;
    char buf[MAX_TC_MSG] = {0};

    if (accept_tc_automation_con(ta) != TWT_SUCCESS) {
        goto finish;
    }
    /* 1. Receive TC start msg */
    if ((ret = receive_tc(ta, buf, sizeof(buf))) != TWT_SUCCESS) {
        if (ret == TWT_STOP_AUTOMATION) {
            ret_val = TWT_STOP_AUTOMATION;
            printf("Stopping TC Automation...\n");
        }
        goto finish;
    }
    printf("TC [%s]\n", buf);
    /* 2. Receive TC args */
    memset(buf, 0, sizeof(buf));
    if ((ret = receive_tc(ta, buf, sizeof(buf))) != TWT_SUCCESS) {
        goto finish;
    }
    printf("received tc [%s]\n", buf);
    tc_result = do_test(ta, buf);
    /* 3. Send TC result */
    if (send_tc_result(ta, tc_result) != TWT_SUCCESS) {
        goto finish;
    }
    ret_val = TWT_SUCCESS;
finish:
    close_tc_automation_con(ta);
    return ret_val;
}

int start_test_automation(TC_AUTOMATION *ta)
{
    if (create_tc_automation_sock(ta) != TWT_SUCCESS) {
        printf("TC socket creation failed, errno=%d\n", errno);
        goto err;
    }
    do {
        if (do_test_automation(ta) == TWT_STOP_AUTOMATION) {
            printf("Received Stop Automation msg");
            break;
        }
    } while (1);
    return TWT_SUCCESS;
err:
    return TWT_FAILURE;
}

int main(int argc, char **argv)
{
    TC_AUTOMATION ta = {0};
    int ret;

    if (init_tc_automation(&ta, argv[0]) != 0) {
        return TWT_FAILURE;
    }
    if ((ret = start_test_case(argc, argv, &ta)) == TWT_START_AUTOMATION) {
        ret = start_test_automation(&ta);
    }
    fini_tc_automation(&ta);
    return ret;
}
