/* См. tests/stub/mbedtls/sha256.h — заглушка для стенда h2match и ext-syntax. */
#ifndef STEER_TESTSTUB_MBEDTLS_SHA512_H
#define STEER_TESTSTUB_MBEDTLS_SHA512_H
#include <stddef.h>
typedef struct { unsigned char opaque[416]; } mbedtls_sha512_context;

void mbedtls_sha512_init(mbedtls_sha512_context *ctx);
void mbedtls_sha512_free(mbedtls_sha512_context *ctx);
void mbedtls_sha512_clone(mbedtls_sha512_context *dst, const mbedtls_sha512_context *src);
int mbedtls_sha512_starts(mbedtls_sha512_context *ctx, int is384);
int mbedtls_sha512_update(mbedtls_sha512_context *ctx, const unsigned char *input, size_t ilen);
int mbedtls_sha512_finish(mbedtls_sha512_context *ctx, unsigned char *output);
int mbedtls_sha512(const unsigned char *input, size_t ilen, unsigned char *output, int is384);
#endif
