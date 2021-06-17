#ifndef _TEST_CONF_H_
#define _TEST_CONF_H_

#ifdef __cplusplus
extern "C" {
#endif

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

#include "test_common.h"

/* Return values used in test scripts */

/* Success and Failure return value */
#define TWT_FAILURE     -1
#define TWT_SUCCESS     0

/* CLI arg parsed return values */
#define TWT_START_AUTOMATION    1
#define TWT_CLI_HELP            2

/* TC Automation break return value */
#define TWT_STOP_AUTOMATION     3

/* Strings */
#define SSL_SESS_ID_CTX "TalkWithTLS"

#define DEFAULT_PSK_ID "clientid1"
/* Hex string representation of 16 byte key */
#define DEFAULT_PSK_KEY "A1A2A3A4A5A6A7A8A9A0AAABACADAEAF"

#define SSL_EX_DATA_TC_CONF         1

/* Flags for auth in TC_CONF */
#define TC_CONF_AUTH_ECDSA          0x01
#define TC_CONF_AUTH_RSA            0x02
#define TC_CONF_CLIENT_CERT_AUTH    0x04

#define MAX_TLS13_KEXCH_GROUPS      10

/* Values of kexch_conf */
#define TC_CONF_KEXCH_GROUP_ALL_ECC           1
#define TC_CONF_KEXCH_GROUP_ALL_FFDHE         2
#define TC_CONF_KEXCH_GROUP_ALL_ECC_STR       3
#define TC_CONF_KEXCH_GROUP_ALL_FFDHE_STR     4

#define MAX_KEXCH_STR                         64

/* Flags for kexch_tmp_key in TC_CONF */
#define TC_CONF_KEXCH_TMP_ECDHE      0x01
#define TC_CONF_KEXCH_TMP_DHE        0x02

/* max_version and min_version values */
#define TC_CONF_TLS_1_0_VERSION                 10
#define TC_CONF_TLS_1_1_VERSION                 11
#define TC_CONF_TLS_1_2_VERSION                 12
#define TC_CONF_TLS_1_3_VERSION                 13
#define TC_CONF_DTLS_1_0_VERSION                910
#define TC_CONF_DTLS_1_2_VERSION                912
#define TC_CONF_SERV_T13_CLNT_T12_VERSION       1312
#define TC_CONF_SERV_T12_CLNT_T13_VERSION       1213

#define MAX_CA_FILE_LOAD    5

#define MAX_IP_ADDR_STR     64

#define MAX_CIPHER_STR_SIZE   32
#define MAX_CIPHER_STR_LIST_SIZE   256

/* Reason for listing on Any IP is to run pytest and SUT on different nodes */
#define TC_AUTOMATION_IP "0.0.0.0"
#define TC_AUTOMATION_PORT 25100

#if 0
typedef struct test_mem_debug_st {
    size_t allocated;
    size_t freed;
}TC_MEM_DEBUG;
#endif

#define CIPHER_RFC_MAX 64
#define CIPHER_OSSL_TXT 64
typedef struct tc_ciphersuite_info_st {
    char ciph_rfc[CIPHER_RFC_MAX];
    uint8_t ciph_val[2];
    char ciph_openssl_txt[CIPHER_OSSL_TXT];
}TC_CIPHERSUITE_INFO;

extern TC_CIPHERSUITE_INFO g_cipher_info[5];

typedef struct test_case_conf_cb_st {
    uint8_t info_cb;
    uint8_t msg_cb;
    uint8_t msg_cb_detailed;
    /* Enable mem cb using CRYPTO_set_mem_functions */
    uint8_t crypto_mem_cb;
}TC_CONF_CB;

#define TEST_MAX_PSK_ID     32
#define TEST_MAX_PSK_KEY    64

typedef enum tc_psk_test_type {
    PSK_ID_AND_KEY = 1,
    PSK_ID_KEY_AND_CIPHERSUITE,
}TC_PSK_TEST_TYPE;

typedef struct test_case_conf_resumption_st {
    void *sess;
    uint8_t resumption;
    TC_PSK_TEST_TYPE psk;
    char psk_id[TEST_MAX_PSK_ID];
    uint16_t psk_id_len;
    char psk_key[TEST_MAX_PSK_KEY];
    uint16_t psk_key_len;
    uint8_t early_data;
    uint8_t early_data_sent; //TODO Not needed
}TC_CONF_RESUMPTION;

typedef struct test_case_kexch_st {
    /* Alg ID it should be negotiation in TLS1.3 supported groups ext */
    int kexch_should_neg;
    int kexch_groups[MAX_TLS13_KEXCH_GROUPS]; /* Used for TLS1.3 connections */
    int kexch_groups_count;
    char kexch_groups_str[MAX_KEXCH_STR];
    uint32_t kexch_conf; /* CLI argument is stored here */
    uint8_t kexch_tmp_key; /* Used for TLS1.2 and lower versions */
}TC_CONF_KEXCH;

typedef struct test_case_ssl_mode_st {
    uint8_t release_buf;
}TC_CONF_SSL_MODE;

typedef struct test_case_config_cipher_st {
    /* Passed with '-ciph' option to configure for [D]TLS connection. */
    /* Stored as RFC defined cipher suite name delimited by ':'. */
    char ciph[MAX_CIPHER_STR_LIST_SIZE];
    /* Currently negotiated_ciph is set when only one ciph is configued using
     * '-ciph' option. */
    char negotiated_ciph[MAX_CIPHER_STR_SIZE];
}TC_CONF_CIPHER;

#define TC_CONF_KEY_UPDATE_REQ_ON_SERVER    1
#define TC_CONF_KEY_UPDATE_REQ_ON_CLIENT    2
#define TC_CONF_KEY_UPDATE_NREQ_ON_SERVER   3
#define TC_CONF_KEY_UPDATE_NREQ_ON_CLIENT   4

typedef struct test_key_update_st {
    uint8_t key_update_test;
}TC_CONF_KEY_UPDATE;

typedef struct test_case_conf_st TC_CONF;

typedef void (*fini_fp)(TC_CONF *conf);

typedef struct test_sockaddr_st {
    char ip[MAX_IP_ADDR_STR];
    uint16_t port;
}SOCK_ADDR;

typedef struct test_sock_addr_st {
    SOCK_ADDR tc_automation_addr;
    SOCK_ADDR test_addr;
    SOCK_ADDR peer_addr_to_con; /* Peer addr to connect */
    uint16_t port_off;
}TEST_SOCK_ADDR;

typedef struct test_serv_fd_st {
    int tcp_listen_fd;
    /* For DTLS server udp_serv_fd is created and assigned to con_fd */
    /* For DTLS client con_fd is created directly before starting DTLS
     * connection*/
    int udp_serv_fd;
}TEST_SERV_FD;

typedef struct test_con_fd_st {
    int con_fd;
}TEST_CON_FD;

struct test_case_conf_st {
    TEST_SOCK_ADDR *taddr;
    TEST_CON_FD test_con_fd;
    TEST_SERV_FD *test_serv_fd;
    /* Test automation keep listens on test_fd for Test cases */
    uint32_t test_automation:1;
    uint8_t server;
    uint32_t dtls:1;
    fini_fp fini; /* Specific fini function */
    /* TEST_CON_FD and TEST_SERV_FD are created for TEST TLS and DTLS
     * connections */
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
    int min_version; /*TODO Need to CLI arg for this */
    int max_version;
    int ver_should_negotiate;
    TC_CONF_CIPHER ch;
    TC_CONF_KEXCH kexch;
    TC_CONF_RESUMPTION res;
    TC_CONF_CB cb;
    TC_CONF_KEY_UPDATE ku;
    TC_CONF_SSL_MODE ssl_mode;
};

typedef struct test_automation_st {
    char *argv1; /* 1st entry in argv, that is exe name */
    int test_lfd; /* Test TCP FDs */
    int test_fd;
    /* This stores listen fd and gets copied to TC_CONF for every TC */
    TEST_SERV_FD test_serv_fd;
}TC_AUTOMATION;

#ifdef __cplusplus
}
#endif

#endif
