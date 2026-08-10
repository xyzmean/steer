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
#endif
