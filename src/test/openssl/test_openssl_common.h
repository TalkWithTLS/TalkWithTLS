#ifndef _TEST_OPENSSL_COMMON_H_
#define _TEST_OPENSSL_COMMON_H_

#ifdef __cplusplus
extern "C" {
#endif

#include "test_common.h"

#include "openssl/crypto.h"
#include "openssl/rand.h"
#include "openssl/ssl.h"

/* Flags for auth in TC_CONF */
#define TC_CONF_AUTH_ECDSA      0x01
#define TC_CONF_AUTH_RSA        0x02

#if 0
#define MAX_TLS13_KEXCH_GROUPS      9
/* Flags for kexch_sup_groups */
#define TC_CONF_KEXCH_GROUP_SECP256R1         0x00000001U
#define TC_CONF_KEXCH_GROUP_SECP384R1         0x00000002U
#define TC_CONF_KEXCH_GROUP_SECP521R1         0x00000004U
#define TC_CONF_KEXCH_GROUP_X25519            0x00000008U
#define TC_CONF_KEXCH_GROUP_X448              0x00000010U
#define TC_CONF_KEXCH_GROUP_FFDHE2048         0x00000020U
#define TC_CONF_KEXCH_GROUP_FFDHE3072         0x00000040U
#define TC_CONF_KEXCH_GROUP_FFDHE4096         0x00000080U
#define TC_CONF_KEXCH_GROUP_FFDHE6144         0x00000100U
#define TC_CONF_KEXCH_GROUP_FFDHE8192         0x00000200U

#define TC_CONF_KEXCH_GROUP_ALL_ECC           0x0000001FU
#define TC_CONF_KEXCH_GROUP_ALL_FFDHE         0x000003E0U
#endif

/* Flags for kexch_tmp_key in TC_CONF */
#define TC_CONF_KEXCH_TMP_ECDHE      0x01
#define TC_CONF_KEXCH_TMP_DHE        0x02

#define MAX_CA_FILE_LOAD    5

typedef struct test_case_conf_st {
    uint8_t server;
    int tcp_listen_fd;
    int fd;
    uint8_t auth;
    int *kexch_groups; /* Used for TLS1.3 connections */
    int kexch_groups_count;
    uint8_t kexch_tmp_key; /* Used for TLS1.2 and lower versions */
    const char *cafiles[MAX_CA_FILE_LOAD];
    uint8_t cafiles_count;
    const char *cert;
    int cert_type;
    const char *priv_key;
    int priv_key_type;
}TC_CONF;

void init_tc_conf(TC_CONF *conf);

int do_test_openssl(TC_CONF *conf);

#ifdef __cplusplus
}
#endif

#endif
