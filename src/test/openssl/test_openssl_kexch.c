#include "test_openssl_kexch.h"

int ssl_kexch_config(TC_CONF *conf, SSL *ssl)
{
    if (conf->kexch.kexch_groups_count) {
        if (SSL_set1_groups(ssl, conf->kexch.kexch_groups, conf->kexch.kexch_groups_count) != 1) {
            printf("Set Groups failed\n");
            return -1;
        }
        printf("Configured kexchange groups of count=%d\n", conf->kexch.kexch_groups_count);
    }

    if (strlen(conf->kexch.kexch_groups_str)) {
        if (SSL_set1_groups_list(ssl, conf->kexch.kexch_groups_str) != 1) {
            printf("Set groups list failed\n");
            return -1;
        }
        printf("Configured kexchange groups str=%s\n", conf->kexch.kexch_groups_str);
    }

    return 0;
}

int do_negotiated_kexch_validation(TC_CONF *conf, SSL *ssl)
{
    int kexch_group;
    if (conf->server) {
        kexch_group = SSL_get_shared_group(ssl, 0);
        printf("Kexch group=%x\n", kexch_group);
        if (kexch_group != conf->kexch.kexch_should_neg) {
            printf("Expected kexch group is %x\n", conf->kexch.kexch_should_neg);
            return -1;
        }
    }
    return 0;
}

int tc_conf_all_ffdhe_kexch_group(TC_CONF *conf)
{
    int dhe_kexch_groups[] = {
        NID_ffdhe2048,
        NID_ffdhe3072,
        NID_ffdhe4096,
        NID_ffdhe6144,
        NID_ffdhe8192
    };
    conf->kexch.kexch_groups_count = sizeof(dhe_kexch_groups)/sizeof(dhe_kexch_groups[0]);
    memcpy(conf->kexch.kexch_groups, dhe_kexch_groups, sizeof(dhe_kexch_groups));
    conf->kexch.kexch_should_neg = dhe_kexch_groups[0];
    printf("Use all FFDHE supported groups\n");
    return 0;
}

int tc_conf_all_ecc_kexch_group(TC_CONF *conf)
{
    int ec_kexch_groups[] = {
        NID_X9_62_prime256v1,   /* secp256r1 */
        NID_secp384r1,          /* secp384r1 */
        NID_secp521r1,          /* secp521r1 */
        NID_X25519,             /* x25519 */
        NID_X448                /* x448 */
    };

    conf->kexch.kexch_groups_count = sizeof(ec_kexch_groups)/sizeof(ec_kexch_groups[0]);
    memcpy(conf->kexch.kexch_groups, ec_kexch_groups, sizeof(ec_kexch_groups));
    conf->kexch.kexch_should_neg = ec_kexch_groups[0];
    printf("Use all ECDHE supported groups\n");
    return 0;
}

int tc_conf_all_ecc_kexch_group_str(TC_CONF *conf)
{
    const char *all_ec_kexch_str = "P-256:P-384:P-521";
    strcpy(conf->kexch.kexch_groups_str, all_ec_kexch_str);
    conf->kexch.kexch_should_neg = NID_X9_62_prime256v1;
    return 0;
}

int tc_conf_kexch(TC_CONF *conf)
{
    switch(conf->kexch.kexch_conf) {
        case 0:
            /* Leave it to default */
            break;
        case TC_CONF_KEXCH_GROUP_ALL_ECC:
            return tc_conf_all_ecc_kexch_group(conf);
        case TC_CONF_KEXCH_GROUP_ALL_FFDHE:
            return tc_conf_all_ffdhe_kexch_group(conf);
        case TC_CONF_KEXCH_GROUP_ALL_ECC_STR:
            return tc_conf_all_ecc_kexch_group_str(conf);
        default:
            /* Any other non zero received on CLI is failure */
            return -1;
    }

    /* X25519 is the first as per OpenSSL default */
    /* After handshake this is validated in Server */
    conf->kexch.kexch_should_neg = NID_X25519;
    return 0;
}
