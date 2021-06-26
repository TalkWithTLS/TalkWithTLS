#include "openssl_kexch.h"

int ssl_kexch_config(TC_CONF *conf, SSL *ssl)
{
    if (conf->kexch.kexch_groups_count) {
        if (SSL_set1_groups(ssl, conf->kexch.kexch_groups, conf->kexch.kexch_groups_count) != 1) {
            ERR("Set Groups failed\n");
            return TWT_FAILURE;
        }
        DBG("Configured kexchange groups of count=%d\n", conf->kexch.kexch_groups_count);
    }

    if (strlen(conf->kexch.kexch_groups_str)) {
        if (SSL_set1_groups_list(ssl, conf->kexch.kexch_groups_str) != 1) {
            ERR("Set groups list failed\n");
            return TWT_FAILURE;
        }
        DBG("Configured kexchange groups str=%s\n", conf->kexch.kexch_groups_str);
    }

    return TWT_SUCCESS;
}

/* TLSv1.2 RSA based ciphersuite doesn't uses [EC]DHE algorithm */
int is_kexch_not_required(TC_CONF *conf, SSL *ssl) {
    const char *ciph_nego;
    if ((ciph_nego = SSL_CIPHER_get_name(SSL_get_current_cipher(ssl)))
                                                            != NULL) {
        if (strcmp(ciph_nego, "AES128-GCM-SHA256") == 0) {
            return 1;
        } else if (strcmp(ciph_nego, "AES256-GCM-SHA384") == 0) {
            return 1;
        }
    }
    return 0;
}

const char *convert_ossl_group_id_to_str(int group) {
    switch (group) {
        case NID_ffdhe2048:
            return "FFDHE2048";
        case NID_ffdhe3072:
            return "FFDHE3072";
        case NID_ffdhe4096:
            return "FFDHE4096";
        case NID_ffdhe6144:
            return "FFDHE6144";
        case NID_ffdhe8192:
            return "FFDHE8192";
        case NID_X9_62_prime256v1:
            return "SECP-256R1";
        case NID_secp384r1:
            return "SECP-384R1";
        case NID_secp521r1:
            return "SECP-521R1";
        case NID_X25519:
            return "X25519";
        case NID_X448:
            return "X448";
        default:
            return "Unknowns-Kexch-alg";
    }
}
int do_negotiated_kexch_validation(TC_CONF *conf, SSL *ssl)
{
    int kexch_group;
    /* OpenSSL client does not have API to provide negotiated group */
    if (conf->server) {
        if (is_kexch_not_required(conf, ssl) == 1) {
            DBG("Negotiated keyexchange alg not required to check\n");
            return TWT_SUCCESS;
        }
        kexch_group = SSL_get_shared_group(ssl, 0);
        DBG("Negotiated Kexch group [%s]\n", convert_ossl_group_id_to_str(kexch_group));
        if (kexch_group != conf->kexch.kexch_should_neg) {
            ERR("Expected kexch group is %s\n",
                    convert_ossl_group_id_to_str(conf->kexch.kexch_should_neg));
            return TWT_FAILURE;
        }
    }
    return TWT_SUCCESS;
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
    DBG("Use all FFDHE supported groups\n");
    return TWT_SUCCESS;
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
    DBG("Use all ECDHE supported groups\n");
    return TWT_SUCCESS;
}

int tc_conf_all_ecc_kexch_group_str(TC_CONF *conf)
{
    const char *all_ec_kexch_str = "P-256:P-384:P-521:X25519:X448";
    strcpy(conf->kexch.kexch_groups_str, all_ec_kexch_str);
    conf->kexch.kexch_should_neg = NID_X9_62_prime256v1;
    return TWT_SUCCESS;
}

int tc_conf_all_ffdhe_kexch_group_str(TC_CONF *conf)
{
    const char *all_ec_kexch_str = "ffdhe2048:ffdhe3072:ffdhe4096:ffdhe6144:ffdhe8192";
    strcpy(conf->kexch.kexch_groups_str, all_ec_kexch_str);
    conf->kexch.kexch_should_neg = NID_ffdhe2048;
    return TWT_SUCCESS;
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
        case TC_CONF_KEXCH_GROUP_ALL_FFDHE_STR:
            return tc_conf_all_ffdhe_kexch_group_str(conf);
        default:
            /* Any other non zero received on CLI is failure */
            return TWT_FAILURE;
    }

    /* X25519 is the first as per OpenSSL default */
    /* After handshake this is validated in Server */
    conf->kexch.kexch_should_neg = NID_X25519;
    return TWT_SUCCESS;
}
