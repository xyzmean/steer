/* Заглушка для стенда h2match: h2.c тянет tls13.h ради одной константы
 * TLS13_MAX_PLAIN, а tls13.h — заголовки mbedtls ради типов в структурах, которые
 * стенд не трогает. Ставить mbedtls ради этого значило бы, что модульный тест
 * транспорта требует криптобиблиотеку. Размеры полей здесь неважны: ни одно из них
 * не читается, важно лишь, чтобы структуры были полными типами. */
#ifndef STEER_TESTSTUB_MBEDTLS_SHA256_H
#define STEER_TESTSTUB_MBEDTLS_SHA256_H
#include <stddef.h>
#include <stdint.h>
typedef struct { unsigned char opaque[416]; } mbedtls_sha256_context;

void mbedtls_sha256_init(mbedtls_sha256_context *ctx);
void mbedtls_sha256_free(mbedtls_sha256_context *ctx);
void mbedtls_sha256_clone(mbedtls_sha256_context *dst, const mbedtls_sha256_context *src);
int mbedtls_sha256_starts(mbedtls_sha256_context *ctx, int is224);
int mbedtls_sha256_update(mbedtls_sha256_context *ctx, const unsigned char *input, size_t ilen);
int mbedtls_sha256_finish(mbedtls_sha256_context *ctx, unsigned char *output);
int mbedtls_sha256(const unsigned char *input, size_t ilen, unsigned char *output, int is224);
#endif
