/* См. tests/stub/mbedtls/sha256.h — заглушки для локальной проверки src/ext.
 * Отсюда certverify.c берёт проверку подписи CertificateVerify. */
#ifndef STEER_TESTSTUB_MBEDTLS_PK_H
#define STEER_TESTSTUB_MBEDTLS_PK_H
#include <stddef.h>
#include "mbedtls/md.h"

#define MBEDTLS_PK_RSASSA_PSS 1
#define MBEDTLS_RSA_SALT_LEN_ANY (-1)

typedef int mbedtls_pk_type_t;
/* Тело нужно: x509_crt держит ключ ПОЛЕМ, а не указателем, и неполный тип там
 * не соберётся. Содержимое стенду безразлично — его никто не читает. */
typedef struct mbedtls_pk_context { void *opaque; } mbedtls_pk_context;

typedef struct {
    mbedtls_md_type_t mgf1_hash_id;
    int expected_salt_len;
} mbedtls_pk_rsassa_pss_options;

int mbedtls_pk_verify(mbedtls_pk_context *ctx, mbedtls_md_type_t md_alg,
                      const unsigned char *hash, size_t hash_len,
                      const unsigned char *sig, size_t sig_len);
int mbedtls_pk_verify_ext(mbedtls_pk_type_t type, const void *options,
                          mbedtls_pk_context *ctx, mbedtls_md_type_t md_alg,
                          const unsigned char *hash, size_t hash_len,
                          const unsigned char *sig, size_t sig_len);
#endif
