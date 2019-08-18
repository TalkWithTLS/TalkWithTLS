#ifndef _TEST_OPENSSL_CRYPTO_MEM_H_
#define _TEST_OPENSSL_CRYPTO_MEM_H_

#ifdef __cplusplus
extern "C" {
#endif

#include "test_openssl_common.h"

void *TWT_malloc(size_t size, const char *file, int line);

void *TWT_realloc(void *buf, size_t size, const char *file, int line);

void TWT_free(void *buf, const char *file, int line);

#ifdef __cplusplus
}
#endif

#endif
