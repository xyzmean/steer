/* См. tests/stub/mbedtls/md.h — заглушка для ext-syntax. Мост tgws шифрует гамму
 * AES-256-CTR напрямую (обфускация MTProto), поэтому кроме типа нужны и объявления. */
#ifndef STEER_TESTSTUB_MBEDTLS_AES_H
#define STEER_TESTSTUB_MBEDTLS_AES_H
#include <stddef.h>
typedef struct { unsigned char opaque[288]; } mbedtls_aes_context;
void mbedtls_aes_init(mbedtls_aes_context *);
void mbedtls_aes_free(mbedtls_aes_context *);
int mbedtls_aes_setkey_enc(mbedtls_aes_context *, const unsigned char *, unsigned int);
int mbedtls_aes_crypt_ctr(mbedtls_aes_context *, size_t, size_t *, unsigned char *,
                          unsigned char *, const unsigned char *, unsigned char *);
#endif
