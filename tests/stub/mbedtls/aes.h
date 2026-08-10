/* См. tests/stub/mbedtls/md.h — заглушка для ext-syntax. Функции AES наши
 * исходники не зовут (AES идёт через GCM), нужен только полный тип. */
#ifndef STEER_TESTSTUB_MBEDTLS_AES_H
#define STEER_TESTSTUB_MBEDTLS_AES_H
typedef struct { unsigned char opaque[288]; } mbedtls_aes_context;
#endif
