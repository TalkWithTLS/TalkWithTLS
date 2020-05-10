#include "test_conf.h"

TC_CIPHERSUITE_INFO g_cipher_info[5] = {
    /* TLSv1.3 Ciphersuite */
    {"TLS_AES_128_GCM_SHA256", {0x13, 0x01}, ""},
    {"TLS_AES_256_GCM_SHA384", {0x13, 0x02}, ""},
    {"TLS_CHACHA20_POLY1305_SHA256", {0x13, 0x03}, ""},
    {"TLS_AES_128_CCM_SHA256", {0x13, 0x04}, ""},
    {"TLS_AES_128_CCM_8_SHA256", {0x13, 0x05}, ""},
};
