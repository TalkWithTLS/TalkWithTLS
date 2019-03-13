#ifndef _TEST_OPENSSL_COMMON_H_
#define _TEST_OPENSSL_COMMON_H_

#ifdef __cplusplus
extern "C" {
#endif

#include "test_common.h"

#include "openssl/crypto.h"
#include "openssl/rand.h"
#include "openssl/ssl.h"

#define SSL_SESS_ID_CTX "TalkWithTLS"

#define DEFAULT_PSK_ID "clientid1"
/* Hex string representation of 16 byte key */
#define DEFAULT_PSK_KEY "A1A2A3A4A5A6A7A8A9A0AAABACADAEAF"

#define SSL_EX_DATA_TC_CONF         1

/* Flags for auth in TC_CONF */
#define TC_CONF_AUTH_ECDSA      0x01
#define TC_CONF_AUTH_RSA        0x02

#define MAX_TLS13_KEXCH_GROUPS      9
#define TC_CONF_KEXCH_GROUP_ALL_ECC           1
#define TC_CONF_KEXCH_GROUP_ALL_FFDHE         2

/* Flags for kexch_tmp_key in TC_CONF */
#define TC_CONF_KEXCH_TMP_ECDHE      0x01
#define TC_CONF_KEXCH_TMP_DHE        0x02

#define MAX_CA_FILE_LOAD    5

typedef struct test_case_conf_cb_st {
    uint8_t info_cb;
    uint8_t msg_cb;
    uint8_t msg_cb_detailed;
}TC_CONF_CB;

#define TEST_MAX_PSK_ID     32
#define TEST_MAX_PSK_KEY    64

typedef struct test_case_conf_resumption_st {
    void *sess;
    uint8_t resumption;
    uint8_t psk;
    char psk_id[TEST_MAX_PSK_ID];
    uint16_t psk_id_len;
    char psk_key[TEST_MAX_PSK_KEY];
    uint16_t psk_key_len;
    uint8_t early_data;
    uint8_t early_data_sent;
}TC_CONF_RESUMPTION;

typedef struct test_case_kexch_st {
    int kexch_should_neg; /* Alg ID it should be negotiation in TLS1.3 supported groups ext */
    int kexch_groups[MAX_TLS13_KEXCH_GROUPS]; /* Used for TLS1.3 connections */
    int kexch_groups_count;
    uint32_t kexch_conf;
    uint8_t kexch_tmp_key; /* Used for TLS1.2 and lower versions */
}TC_CONF_KEXCH;

typedef struct test_case_conf_st {
    uint8_t server;
    int tcp_listen_fd;
    int fd;
    uint8_t nb_sock;
    uint8_t auth;
    const char *cafiles[MAX_CA_FILE_LOAD];
    uint8_t cafiles_count;
    const char *cert;
    int cert_type;
    const char *priv_key;
    int priv_key_type;
    uint16_t con_count;
    TC_CONF_KEXCH kexch;
    TC_CONF_RESUMPTION res;
    TC_CONF_CB cb;
}TC_CONF;

int init_tc_conf(TC_CONF *conf);

void fini_tc_conf(TC_CONF *conf);

int init_psk_params(TC_CONF *conf, const char *psk_id, const char *psk_key);

int do_test_openssl(TC_CONF *conf);

#ifdef __cplusplus
}
#endif

#endif
