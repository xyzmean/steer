/* См. tests/stub/mbedtls/sha256.h — заглушки для локальной проверки src/ext.
 * Отсюда certverify.c берёт разбор и проверку цепочки сертификатов. */
#ifndef STEER_TESTSTUB_MBEDTLS_X509_CRT_H
#define STEER_TESTSTUB_MBEDTLS_X509_CRT_H
#include <stddef.h>
#include <stdint.h>
#include "mbedtls/pk.h"

/* Поля ровно те, которые читает certverify.c: разобранная версия (ноль означает «в
 * хранилище не оказалось ни одного корня») и открытый ключ листового сертификата. */
typedef struct mbedtls_x509_crt {
    int version;
    mbedtls_pk_context pk;
} mbedtls_x509_crt;

typedef struct mbedtls_x509_crl mbedtls_x509_crl;

void mbedtls_x509_crt_init(mbedtls_x509_crt *crt);
void mbedtls_x509_crt_free(mbedtls_x509_crt *crt);
int mbedtls_x509_crt_parse(mbedtls_x509_crt *chain, const unsigned char *buf, size_t buflen);
int mbedtls_x509_crt_parse_der(mbedtls_x509_crt *chain, const unsigned char *buf, size_t buflen);
int mbedtls_x509_crt_verify(mbedtls_x509_crt *crt, mbedtls_x509_crt *trust_ca,
                            mbedtls_x509_crl *ca_crl, const char *cn, uint32_t *flags,
                            int (*f_vrfy)(void *, mbedtls_x509_crt *, int, uint32_t *),
                            void *p_vrfy);
#endif
