#include "test_openssl_keyupdate.h"

int do_key_update(TC_CONF *conf, SSL *ssl, int type)
{
    printf("### Doing Key update\n");
    if (SSL_version(ssl) != TLS1_3_VERSION) {
        printf("Key update for non TLS13 version=%#x\n", SSL_version(ssl));
        return -1;
    }
    if (SSL_key_update(ssl, type) != 1) {
        printf("Key update failed\n");
        return -1;
    }
    if (do_handshake(conf, ssl)) {
        printf("Do handshake after key update failed\n");
        return -1;
    }
    printf("Do handshake after key update succeeded\n");
    printf("Key update Request (type=%d) done\n", type);
    return 0;
}

int check_and_do_key_update(TC_CONF *conf, SSL *ssl)
{
    int key_update = 0;
    int key_update_type = -1;
    if (((conf->ku.key_update_test == TC_CONF_KEY_UPDATE_REQ_ON_SERVER) && (conf->server == 1))
            || ((conf->ku.key_update_test == TC_CONF_KEY_UPDATE_REQ_ON_CLIENT) && (conf->server == 0))
            || ((conf->ku.key_update_test == TC_CONF_KEY_UPDATE_NREQ_ON_SERVER) && (conf->server == 1))
            || ((conf->ku.key_update_test == TC_CONF_KEY_UPDATE_NREQ_ON_CLIENT) && (conf->server == 0))) {
        key_update = 1;
    }
    switch (conf->ku.key_update_test) {
        case TC_CONF_KEY_UPDATE_REQ_ON_SERVER:
        case TC_CONF_KEY_UPDATE_REQ_ON_CLIENT:
            key_update_type = SSL_KEY_UPDATE_REQUESTED;
            break;
        case TC_CONF_KEY_UPDATE_NREQ_ON_SERVER:
        case TC_CONF_KEY_UPDATE_NREQ_ON_CLIENT:
            key_update_type = SSL_KEY_UPDATE_NOT_REQUESTED;
            break;
    }
    if (key_update) {
        if (do_key_update(conf, ssl, key_update_type)) {
            printf("Keyupdate failed\n");
            return -1;
        }
    }
    return 0;
}

int do_key_update_test(TC_CONF *conf, SSL *ssl)
{
    if (conf->ku.key_update_test == 0) {
        /* Key update testing is not configured */
        return 0;
    }
    if (check_and_do_key_update(conf, ssl)) {
        printf("Checking and doing key update failed\n");
        return -1;
    }
    if (do_data_transfer(conf, ssl)) {
        printf("Data transfer failed\n");
        return -1;
    }
    return 0;
}

