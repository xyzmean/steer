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
/* Нужны certverify.c: размер хеша по типу и разовый расчёт хеша. */
unsigned char mbedtls_md_get_size(const mbedtls_md_info_t *md_info);
int mbedtls_md(const mbedtls_md_info_t *md_info, const unsigned char *input, size_t ilen,
               unsigned char *output);
/* Нужны tls13.c (tls12_prf, TLS 1.2 у моста tgws): потоковый HMAC через контекст. Размер
 * контекста в заглушке произвольный — ext-syntax только компилирует, не компонует. */
typedef struct mbedtls_md_context_t { const mbedtls_md_info_t *md_info; void *md_ctx, *hmac_ctx; }
    mbedtls_md_context_t;
void mbedtls_md_init(mbedtls_md_context_t *ctx);
void mbedtls_md_free(mbedtls_md_context_t *ctx);
int mbedtls_md_setup(mbedtls_md_context_t *ctx, const mbedtls_md_info_t *md_info, int hmac);
int mbedtls_md_hmac_starts(mbedtls_md_context_t *ctx, const unsigned char *key, size_t keylen);
int mbedtls_md_hmac_update(mbedtls_md_context_t *ctx, const unsigned char *input, size_t ilen);
int mbedtls_md_hmac_finish(mbedtls_md_context_t *ctx, unsigned char *output);
int mbedtls_md_hmac_reset(mbedtls_md_context_t *ctx);
#endif
