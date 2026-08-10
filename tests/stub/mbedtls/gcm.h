/* См. tests/stub/mbedtls/sha256.h — заглушка для стенда h2match и ext-syntax.
 * Прототипы — для ext-syntax: он компилирует tls13.c/reality.c целиком, и вызовы
 * без объявлений — ошибка; h2match структурой и обходился. */
#ifndef STEER_TESTSTUB_MBEDTLS_GCM_H
#define STEER_TESTSTUB_MBEDTLS_GCM_H
#include <stddef.h>
typedef struct { unsigned char opaque[512]; } mbedtls_gcm_context;

#define MBEDTLS_GCM_ENCRYPT 1

typedef enum {
    MBEDTLS_CIPHER_ID_NONE = 0,
    MBEDTLS_CIPHER_ID_AES,
} mbedtls_cipher_id_t;

void mbedtls_gcm_init(mbedtls_gcm_context *ctx);
void mbedtls_gcm_free(mbedtls_gcm_context *ctx);
int mbedtls_gcm_setkey(mbedtls_gcm_context *ctx, mbedtls_cipher_id_t cipher,
                       const unsigned char *key, unsigned int keybits);
int mbedtls_gcm_crypt_and_tag(mbedtls_gcm_context *ctx, int mode, size_t length,
                              const unsigned char *iv, size_t iv_len,
                              const unsigned char *add, size_t add_len,
                              const unsigned char *input, unsigned char *output,
                              size_t tag_len, unsigned char *tag);
int mbedtls_gcm_auth_decrypt(mbedtls_gcm_context *ctx, size_t length,
                             const unsigned char *iv, size_t iv_len,
                             const unsigned char *add, size_t add_len,
                             const unsigned char *tag, size_t tag_len,
                             const unsigned char *input, unsigned char *output);
#endif
