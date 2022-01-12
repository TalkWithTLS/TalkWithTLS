#include "test_main.h"

#include "openssl_common.h"
#include "openssl_kexch.h"
#include "openssl_auth.h"

void tc_conf_dtls(TC_CONF *conf)
{
    if ((conf->max_version == TC_CONF_DTLS_1_0_VERSION) ||
            (conf->max_version == TC_CONF_DTLS_1_2_VERSION)) {
        conf->dtls = 1;
    }
}

/* tc_conf_update
 * - Based on CLI arguments it does some internal initialization which will be
 *   used in further test scripts */
int tc_conf_update(TC_CONF *conf)
{
    if (init_tc_conf_for_openssl(conf) != 0) {
        ERR("TC conf init failed for openssl\n");
        return TWT_FAILURE;
    }
    if (tc_conf_kexch(conf)) {
        ERR("TC conf for kexch failed\n");
        return TWT_FAILURE;
    }
    if (tc_conf_auth(conf)) {
        ERR("TC conf for authentication failed\n");
        return TWT_FAILURE;
    }
    tc_conf_dtls(conf);
    return 0;
}

int test_openssl(TC_CONF *conf)
{
    /* Based on CLI arguments do some internal initialization which will be
     * used in further test scripts */
    if (tc_conf_update(conf) != 0) {
        goto end;
    }

    return do_test_openssl(conf);
end:
    return TWT_FAILURE;
}

int main(int argc, char **argv)
{
    SUT sut = {0};
    sut.do_test_sut_func = test_openssl;
    return test_main(argc, argv, &sut);
}
