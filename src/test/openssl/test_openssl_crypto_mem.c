#include "test_openssl_crypto_mem.h"

#define MEM_SIZE_LIMIT_TO_PRINT 1000

void *TWT_malloc(size_t size, const char *file, int line)
{
    if (size > MEM_SIZE_LIMIT_TO_PRINT) {
        DBG("[Mem][malloc][%s:%d] %zu\n", file, line, size);
    }
    return malloc(size);
}

void *TWT_realloc(void *buf, size_t size, const char *file, int line)
{
    //DBG("[Mem][realloc][%s:%d] %p %zu\n", file, line, buf, size);
    if (buf == NULL) {
        return malloc(size);
    }
    if (size == 0) {
        free(buf);
        return NULL;
    }
    return realloc(buf, size);
}

void TWT_free(void *buf, const char *file, int line)
{
    //DBG("[Mem][free][%s:%d]\n", file, line);
    if (buf != NULL) {
        free(buf);
    }
}
