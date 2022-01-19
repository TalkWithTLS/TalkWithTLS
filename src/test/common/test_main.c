#include "test_main.h"

#include <errno.h>

int create_test_serv_fd(TC_CONF *conf, SUT *sut)
{
    if (conf->server == 1) {
        if (conf->dtls == 0) {
            return sut->create_tls_test_serv_fd(conf->test_serv_fd, conf->taddr);
        } else {
            return sut->create_dtls_test_serv_fd(conf->test_serv_fd, conf->taddr);
        }
    }
    return TWT_SUCCESS;
}

int start_test_case(int argc, char **argv, SUT *sut, TEST_SOCK_ADDR *taddr,
                                                        TEST_SERV_FD *tsfd)
{
    TEST_SERV_FD test_serv_fd;
    TC_CONF conf;
    int ret_val = TWT_FAILURE;
    int ret;

    if (init_tc_conf(&conf) != TWT_SUCCESS) {
        ERR("TC conf failed\n");
        goto end;
    }
    conf.taddr = taddr;
    /* Note: tsfd will be Not NULL incase of TC automation */
    if ((conf.test_serv_fd = tsfd) == NULL) {
        if (sut->init_test_serv_fd(&test_serv_fd) != TWT_SUCCESS) {
            ERR("Init test serv fd failed before starting test case\n");
            goto end;
        }
        /* Manual test execution case so port offset not needed to add here */
        conf.test_serv_fd = &test_serv_fd;
    }

    if ((ret = parse_args(argc, argv, &conf)) == TWT_START_AUTOMATION) {
        if (tsfd == NULL) { /* If it is called from main for TC automation */
            ret_val = TWT_START_AUTOMATION;
        } else {
            ERR("For Test case execution invalid option -tc-automation is passed\n");
            ret_val = TWT_FAILURE;
        }
        goto end;
    } else if (ret == TWT_CLI_HELP) {
        /* Printed only help */
        ret_val = TWT_SUCCESS;
        goto end;
    } else if (ret == TWT_FAILURE) {
        ERR("Parsing arg failed\n");
        goto end;
    }

    /* Else continue executing one TC */

    if (tsfd == NULL) {
        DBG("Creating Test serv socket fd\n");
        /* This case is only for independent test execution not for TC
         * automation. Here serv fd gets created only for [D]TLS server */
        if (create_test_serv_fd(&conf, sut) != TWT_SUCCESS) {
            ERR("Create test serv listen fd failed before starting test case\n");
            goto end;
        }
    }
    ret_val = sut->do_test_sut_func(&conf);
end:
    fini_tc_conf(&conf);
    if (tsfd == NULL) {
        sut->fini_test_serv_fd(&test_serv_fd);
    }
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
            ERR("Expanding argv failed for len=%d\n", *argc_out + ARGV_BUCKET_FACTOR);
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
    DBG("argv list -\n");
    for (i = 0; i < argc; i++) {
        DBG("%s\n", argv[i]);
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

int do_test(SUT *sut, TC_AUTOMATION *ta, TEST_SOCK_ADDR *taddr,
                            TEST_SERV_FD *tsfd, char *tc_cmd)
{
    int argc = 0, ret_val = TWT_FAILURE;
    char **argv = NULL;
    if (split_args(ta, tc_cmd, &argc, &argv) == TWT_FAILURE) {
        goto finish;
    }
    print_args(argc, argv);
    ret_val = start_test_case(argc, argv, sut, taddr, tsfd);
finish:
    free_args(argc, &argv);
    return ret_val;
}

#define MAX_TC_MSG 1024
int do_test_automation(SUT *sut, TC_AUTOMATION *ta, TEST_SOCK_ADDR *taddr,
                                                        TEST_SERV_FD *tsfd)
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
            DBG("Stopping TC Automation...\n");
        }
        goto finish;
    }
    DBG("TC [%s]\n", buf);
    /* 2. Receive TC args */
    memset(buf, 0, sizeof(buf));
    if ((ret = receive_tc(ta, buf, sizeof(buf))) != TWT_SUCCESS) {
        goto finish;
    }
    DBG("received tc [%s]\n", buf);
    tc_result = do_test(sut, ta, taddr, tsfd, buf);
    /* 3. Send TC result */
    if (send_tc_result(ta, tc_result) != TWT_SUCCESS) {
        goto finish;
    }
    ret_val = TWT_SUCCESS;
finish:
    close_tc_automation_con(ta);
    return ret_val;
}

int start_test_automation(SUT *sut, TC_AUTOMATION *ta, TEST_SOCK_ADDR *taddr)
{
    TEST_SERV_FD tsfd;
    int ret_val = TWT_FAILURE;

    if (sut->init_test_serv_fd(&tsfd) != TWT_SUCCESS) {
        ERR("TEST_SERV_FD initialization for test automation failed\n");
        goto err;
    }
    DBG("Creating Test serv socket fds\n");
    if ((sut->create_tls_test_serv_fd(&tsfd, taddr) != TWT_SUCCESS)
            || (sut->create_dtls_test_serv_fd(&tsfd, taddr) != TWT_SUCCESS)) {
        ERR("Create test serv listen fd failed for TC Automation\n");
    }
    DBG("Creating TC Automation socket fd\n");
    if (create_tc_automation_sock(ta, taddr) != TWT_SUCCESS) {
        ERR("TC socket creation failed, errno=%d\n", errno);
        goto err;
    }
    do {
        if (do_test_automation(sut, ta, taddr, &tsfd) == TWT_STOP_AUTOMATION) {
            break;
        }
    } while (1);
    ret_val = TWT_SUCCESS;
err:
    sut->fini_test_serv_fd(&tsfd);
    return ret_val;
}

int test_main(int argc, char **argv, SUT *sut)
{
    TEST_SOCK_ADDR taddr;
    TC_AUTOMATION ta;
    int ret = TWT_FAILURE;

    if ((init_tc_automation(&ta, argv[0]) != 0)
            || (init_test_sock_addr(&taddr) != 0)) {
        goto end;
    }
    if ((ret = start_test_case(argc, argv, sut, &taddr, NULL))
                                    == TWT_START_AUTOMATION) {
        ret = start_test_automation(sut, &ta, &taddr);
    }
    fini_tc_automation(&ta);

end:
    if (ret == TWT_SUCCESS) {
        DBG("SUCCESS !!\n");
    } else {
        DBG("FAILURE !!\n");
    }
    return ret;
}
