#include "test_openssl_resumption.h"


const unsigned char g_tls13_aes128gcmsha256_id[] = { 0x13, 0x01 };
const unsigned char g_tls13_aes256gcmsha384_id[] = { 0x13, 0x02 };
const char *g_psk_identity = "clientid1";
/* Hex string representation of 16 byte key */
const char *g_psk_key = "A1A2A3A4A5A6A7A8A9A0AAABACADAEAF";

int tls13_psk_use_session_cb(SSL *s, const EVP_MD *md,
                              const unsigned char **id, size_t *idlen,
                              SSL_SESSION **sess)
{
    SSL_SESSION *usesess = NULL;
    const SSL_CIPHER *cipher = NULL;
    long key_len;
    unsigned char *key;
    
    printf("Called PSK use sess cb\n");
    key = OPENSSL_hexstr2buf(g_psk_key, &key_len);
    if (key == NULL) {
        printf("hexstr2buf failed\n");
        return 0;
    }

    /* We default to SHA-256 */
    cipher = SSL_CIPHER_find(s, g_tls13_aes256gcmsha384_id);
    if (cipher == NULL) {
        printf("Cipher fine failed\n");
        OPENSSL_free(key);
        return 0;
    }

    usesess = SSL_SESSION_new();
    if (usesess == NULL
            || !SSL_SESSION_set1_master_key(usesess, key, key_len)
            || !SSL_SESSION_set_cipher(usesess, cipher)
            || !SSL_SESSION_set_protocol_version(usesess, TLS1_3_VERSION)) {
        OPENSSL_free(key);
        goto err;
    }
    OPENSSL_free(key);

    if (md != NULL && SSL_CIPHER_get_handshake_digest(cipher) != md) {
        /* PSK not usable, ignore it */
        *id = NULL;
        *idlen = 0;
        *sess = NULL;
        SSL_SESSION_free(usesess);
    } else {
        *sess = usesess;
        *id = (unsigned char *)g_psk_identity;
        *idlen = strlen(g_psk_identity);
    }

    return 1;

 err:
    SSL_SESSION_free(usesess);
    return 0;
}

int tls13_psk_find_session_cb(SSL *ssl, const unsigned char *id,
                               size_t id_len, SSL_SESSION **sess)
{
    SSL_SESSION *tmpsess = NULL;
    unsigned char *key;
    long key_len;
    const SSL_CIPHER *cipher = NULL;

    printf("Called PSK find sess cb\n");
    if ((id_len != strlen(g_psk_identity))
            || (memcmp(id, g_psk_identity, id_len) != 0)) {
        *sess = NULL;
        return 1;
    }
    key = OPENSSL_hexstr2buf(g_psk_key, &key_len);
    if (key == NULL) {
        printf("hexstr2buf conversion failed\n");
        return 0;
    }

    /* We default to SHA256 */
    cipher = SSL_CIPHER_find(ssl, g_tls13_aes256gcmsha384_id);
    if (cipher == NULL) {
        printf("Find cipher failed\n");
        OPENSSL_free(key);
        return 0;
    }

    tmpsess = SSL_SESSION_new();
    if (tmpsess == NULL
            || !SSL_SESSION_set1_master_key(tmpsess, key, key_len)
            || !SSL_SESSION_set_cipher(tmpsess, cipher)
            || !SSL_SESSION_set_protocol_version(tmpsess, SSL_version(ssl))) {
        OPENSSL_free(key);
        return 0;
    }
    OPENSSL_free(key);
    *sess = tmpsess;

    return 1;
}

int initialize_resumption_params(TC_CONF *conf, SSL_CTX *ctx)
{
    if (conf->server) {
        SSL_CTX_set_psk_find_session_callback(ctx, tls13_psk_find_session_cb);
        printf("Registered TLS1.3 PSK find sess cb\n");
    } else {
        SSL_CTX_set_psk_use_session_callback(ctx, tls13_psk_use_session_cb);
        printf("Registered TLS1.3 PSK use sess cb\n");
    }
    return 0;
}
