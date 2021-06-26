#include "test_cli_arg.h"
#include "openssl_cipher.h"

/* TWT cli args receives ciphers delimited by ',' */
#define OPENSSL_CIPHER_DELIMITER ":"

int append_ciph_str(char **ciph_list, const char *ciph)
{
    char *ciph_list_new;
    int new_len;
    new_len = (*ciph_list != NULL ? strlen(*ciph_list) : 0) + strlen(ciph) + 2;
    if ((ciph_list_new = malloc(new_len)) == NULL) {
        ERR("Mem alloc failed for size [%d]\n", new_len);
        return TWT_FAILURE;
    }
    memset(ciph_list_new, 0, new_len);
    if (*ciph_list != NULL) {
        strcpy(ciph_list_new, *ciph_list);
        strcat(ciph_list_new, OPENSSL_CIPHER_DELIMITER);
    }
    strcat(ciph_list_new, ciph);
    if (*ciph_list != NULL)
        free(*ciph_list);
    *ciph_list = ciph_list_new;
    return TWT_SUCCESS;
}

const char *convert_ciph_to_ossl_format(const char* ciph, int *is_tls13_ciph)
{
    *is_tls13_ciph = 0;
    if (strcmp(ciph, TLS1_3_RFC_AES_128_GCM_SHA256) == 0) {
        *is_tls13_ciph = 1;
        return ciph;
    } else if (strcmp(ciph, TLS1_3_RFC_AES_256_GCM_SHA384) == 0) {
        *is_tls13_ciph = 1;
        return ciph;
    } else if (strcmp(ciph, TLS1_3_RFC_CHACHA20_POLY1305_SHA256) == 0) {
        *is_tls13_ciph = 1;
        return ciph;
    } else if (strcmp(ciph, TLS1_3_RFC_AES_128_CCM_SHA256) == 0) {
        *is_tls13_ciph = 1;
        return ciph;
    } else if (strcmp(ciph, TLS1_3_RFC_AES_128_CCM_8_SHA256) == 0) {
        *is_tls13_ciph = 1;
        return ciph;
    } else if (strcmp(ciph, "TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256") == 0) {
        return TLS1_TXT_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256;
    } else if (strcmp(ciph, "TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384") == 0) {
        return TLS1_TXT_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384;
    } else if (strcmp(ciph, "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256") == 0) {
        return TLS1_TXT_ECDHE_RSA_WITH_AES_128_GCM_SHA256;
    } else if (strcmp(ciph, "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384") == 0) {
        return TLS1_TXT_ECDHE_RSA_WITH_AES_256_GCM_SHA384;
    } else if (strcmp(ciph, "TLS_RSA_WITH_AES_128_GCM_SHA256") == 0) {
        return TLS1_TXT_RSA_WITH_AES_128_GCM_SHA256;
    } else if (strcmp(ciph, "TLS_RSA_WITH_AES_256_GCM_SHA384") == 0) {
        return TLS1_TXT_RSA_WITH_AES_256_GCM_SHA384;
    }
    ERR("Unknown cipher configured to TWT [%s]\n", ciph);
    return NULL;
}

/* - Convert RFC defined cipher name to OpenSSL defined name and splits and
 *   update to two different variable (tls13_ciph and tls12_ciph).
 * - For TLSv1.3 openssl API takes cipher name same as RFC, but for TLSv1.2
 *   it takes differently. */
int convert_ciph_list_to_ossl_format(TC_CONF *conf, char* ciph,
                                     char **tls13_ciph, char **tls12_ciph)
{
    int ciph_count = 0, is_tls13_ciph = 0;
    char *rest = ciph, *token;
    const char *ciph_str;
    while ((token = strtok_r(rest, TWT_CLI_ARG_VALUE_DELIMITER, &rest))
                                                                != NULL) {
        if ((ciph_str = convert_ciph_to_ossl_format(token, &is_tls13_ciph))
                                                                   == NULL) {
            return TWT_FAILURE;
        }
        if (is_tls13_ciph == 1) {
            append_ciph_str(tls13_ciph, ciph_str);
        } else {
            append_ciph_str(tls12_ciph, ciph_str);
        }
        ciph_count++;
    }
    DBG("Received %d ciphers to config\n", ciph_count);
    if (ciph_count == 1) {
        if (strlen(conf->ch.negotiated_ciph) == 0) {
            if (strlen(ciph_str) >= sizeof(conf->ch.negotiated_ciph)) {
                ERR("Negotiated cipher suite size is not sufficient to copy"
                        "cipher of len [%ld]\n", strlen(ciph_str));
                return TWT_FAILURE;
            }
            strcpy(conf->ch.negotiated_ciph, ciph_str);
        }
    }
    return TWT_SUCCESS;
}

int ssl_ciph_config(TC_CONF *conf, SSL *ssl)
{
    char *ciph_in, *tls13_ciph = NULL, *tls12_ciph = NULL;
    int ret_val = TWT_FAILURE;
    if ((ciph_in = strdup(conf->ch.ciph)) == NULL) {
        ERR("Duping configured cipher str failed\n");
        return TWT_FAILURE;
    }
    if (convert_ciph_list_to_ossl_format(conf, ciph_in, &tls13_ciph,
                                         &tls12_ciph) != TWT_SUCCESS) {
        ERR("Configured cipher parsing failed\n");
        goto err;
    }
    if (tls13_ciph != NULL) {
        DBG("TLSv1.3 cipher to configure [%s]\n", tls13_ciph);
        if (SSL_set_ciphersuites(ssl, tls13_ciph) != 1) {
            ERR("Configuring TLS1.3 ciphersuite [%s] failed\n", tls13_ciph);
            goto err;
        }
    }
    if (tls12_ciph != NULL) {
        DBG("TLSv1.2 cipher to configure [%s]\n", tls12_ciph);
        if (SSL_set_cipher_list(ssl, tls12_ciph) != 1) {
            ERR("Configuring TLS1.2 ciphersuire [%s] failed\n", tls12_ciph);
            goto err;
        }
    }
    ret_val = TWT_SUCCESS;
err:
    free(tls13_ciph);
    free(tls12_ciph);
    free(ciph_in);
    return ret_val;
}

int do_negotiated_ciphersuite_validation(TC_CONF *conf, SSL *ssl)
{
    const char *negotiated_cipher;
    negotiated_cipher = SSL_CIPHER_get_name(SSL_get_current_cipher(ssl));
    DBG("Negotiated cipher [%s]\n", negotiated_cipher);
    if (strlen(conf->ch.negotiated_ciph) != 0) {
        if ((negotiated_cipher == NULL) ||
                (strcmp(negotiated_cipher, conf->ch.negotiated_ciph) != 0)) {
            ERR("Negotiated cipher[%s] is not expected [%s]\n",
                    negotiated_cipher, conf->ch.negotiated_ciph);
            return TWT_FAILURE;
        }
    }
    return TWT_SUCCESS;
}
