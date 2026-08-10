/* См. tests/stub/mbedtls/sha256.h — заглушки для локальной проверки src/ext.
 * Здесь, в отличие от стендов, есть и ПРОТОТИПЫ: ext-syntax компилирует сами
 * reality.c/tls13.c, а не только структуры, и вызовы без объявлений — ошибка. */
#ifndef STEER_TESTSTUB_MBEDTLS_MD_H
#define STEER_TESTSTUB_MBEDTLS_MD_H
#include <stddef.h>

typedef enum {
    MBEDTLS_MD_NONE = 0,
    MBEDTLS_MD_SHA256,
    MBEDTLS_MD_SHA384,
    MBEDTLS_MD_SHA512,
} mbedtls_md_type_t;

typedef struct mbedtls_md_info_t mbedtls_md_info_t;

const mbedtls_md_info_t *mbedtls_md_info_from_type(mbedtls_md_type_t md_type);
int mbedtls_md_hmac(const mbedtls_md_info_t *md_info,
                    const unsigned char *key, size_t keylen,
                    const unsigned char *input, size_t ilen,
                    unsigned char *output);
#endif
