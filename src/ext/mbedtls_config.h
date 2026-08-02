/* Урезанная конфигурация mbedtls: только то, что нужно клиенту VLESS/Reality.
 *
 * Полная сборка mbedtls — это ~700 КБ кода: серверная половина TLS, DTLS, RSA, десяток
 * шифров, работа с файлами сертификатов. Клиенту Reality из этого не нужно ничего, кроме
 * TLS 1.3 с X25519 и двумя AEAD, и разница в весе решает, влезет ли пакет на роутер.
 *
 * Отсюда правило для всего файла: включается ровно то, чем пользуется код, и каждое
 * исключение объяснено — иначе через полгода никто не рискнёт это тронуть.
 */
#ifndef STEER_MBEDTLS_CONFIG_H
#define STEER_MBEDTLS_CONFIG_H

/* ---- платформа ------------------------------------------------------------ */
/* Стандартная libc есть (musl), своих оболочек не нужно. */
#define MBEDTLS_PLATFORM_C
#define MBEDTLS_HAVE_TIME          /* TLS 1.3 нужен только для проверки срока — но
                                    * сертификат сервера мы не проверяем (см. ниже),
                                    * поэтому время используется лишь как источник
                                    * энтропии в сидировании. */

/* ---- TLS: только клиент, только 1.3 --------------------------------------- */
/* Серверной половины в бинарнике быть не должно: steer никогда не принимает TLS.
 * MBEDTLS_SSL_SRV_C не определён намеренно.
 *
 * TLS 1.2 тоже не нужен: Reality — это строго 1.3, и оставленный 1.2 добавил бы
 * не только вес, но и путь, по которому рукопожатие могло бы деградировать до версии,
 * в которой Reality не работает. */
#define MBEDTLS_SSL_TLS_C
#define MBEDTLS_SSL_CLI_C
#define MBEDTLS_SSL_PROTO_TLS1_3
#define MBEDTLS_SSL_TLS1_3_COMPATIBILITY_MODE   /* «middlebox compat»: пустой
                                                 * ChangeCipherSpec, который посылает
                                                 * каждый настоящий браузер. Без него
                                                 * наш ClientHello отличается от
                                                 * браузерного — а вся суть Reality в
                                                 * том, чтобы не отличаться. */
#define MBEDTLS_SSL_SESSION_TICKETS
#define MBEDTLS_SSL_SERVER_NAME_INDICATION      /* SNI обязателен: именно он несёт
                                                 * маскировочный домен (ads.x5.ru). */

/* Обмен ключами — только эфемерный ECDHE. PSK и RSA-варианты не нужны. */
#define MBEDTLS_KEY_EXCHANGE_ECDHE_ECDSA_ENABLED
#define MBEDTLS_KEY_EXCHANGE_ECDHE_RSA_ENABLED  /* Настоящие сайты, которыми
                                                 * прикрывается Reality, часто на
                                                 * RSA-сертификатах: без этого набора
                                                 * наш ClientHello сузился бы до
                                                 * нетипичного, что само по себе
                                                 * признак. */

/* ---- криптография --------------------------------------------------------- */
#define MBEDTLS_ECP_C
#define MBEDTLS_ECDH_C
#define MBEDTLS_ECDSA_C
#define MBEDTLS_ECP_DP_CURVE25519_ENABLED       /* X25519 — на нём Reality и держится. */
#define MBEDTLS_ECP_DP_SECP256R1_ENABLED        /* P-256 в списке групп, потому что он
                                                 * есть у браузеров. */
#define MBEDTLS_BIGNUM_C
#define MBEDTLS_ASN1_PARSE_C
#define MBEDTLS_ASN1_WRITE_C
#define MBEDTLS_OID_C
#define MBEDTLS_PK_C
#define MBEDTLS_PK_PARSE_C
#define MBEDTLS_RSA_C
#define MBEDTLS_PKCS1_V15
#define MBEDTLS_PKCS1_V21

#define MBEDTLS_AES_C
#define MBEDTLS_GCM_C                           /* AES-128-GCM: первый набор в списке
                                                 * у Chrome. */
#define MBEDTLS_CHACHA20_C
#define MBEDTLS_POLY1305_C
#define MBEDTLS_CHACHAPOLY_C                    /* На роутере без AES-NI ChaCha
                                                 * заметно быстрее AES, и сервера её
                                                 * обычно предлагают. */
#define MBEDTLS_SHA256_C
#define MBEDTLS_SHA384_C
#define MBEDTLS_SHA512_C
#define MBEDTLS_MD_C
#define MBEDTLS_HKDF_C                          /* Вывод ключей TLS 1.3 и
                                                 * аутентификатора Reality. */
#define MBEDTLS_CIPHER_C

/* ---- энтропия ------------------------------------------------------------- */
#define MBEDTLS_ENTROPY_C
#define MBEDTLS_CTR_DRBG_C
#define MBEDTLS_NO_PLATFORM_ENTROPY             /* Свой источник: см. ниже про
                                                 * getrandom. */
#define MBEDTLS_ENTROPY_HARDWARE_ALT

/* ---- сертификаты ---------------------------------------------------------- */
/* Разбор X.509 нужен: сервер присылает цепочку настоящего сайта, и её надо хотя бы
 * прочитать, чтобы рукопожатие завершилось.
 *
 * Но ПРОВЕРЯТЬ её нельзя и не имеет смысла: сертификат подлинный, чужой и к нашему
 * серверу отношения не имеет. Подлинность в Reality доказывается совсем иначе —
 * X25519-аутентификатором. Поэтому MBEDTLS_FS_IO не включён (корневых хранилищ на
 * роутере нет и не нужно), а режим проверки код выставляет в NONE явно, с
 * объяснением на месте. */
#define MBEDTLS_X509_USE_C
#define MBEDTLS_X509_CRT_PARSE_C

/* ---- чего нет и почему ----------------------------------------------------- */
/* MBEDTLS_SSL_SRV_C          — steer не сервер;
 * MBEDTLS_SSL_PROTO_DTLS     — UDP-TLS не используется;
 * MBEDTLS_FS_IO              — на роутере нечего читать с диска;
 * MBEDTLS_DES_C, CAMELLIA... — устаревшие шифры, которых нет у браузеров;
 * MBEDTLS_DHM_C              — классический DH: у TLS 1.3 его нет вовсе;
 * MBEDTLS_SELF_TEST          — тесты в бинарнике на роутере ни к чему;
 * MBEDTLS_ERROR_C            — текстовые описания ошибок это ~10 КБ строк; коды
 *                              печатаются числом, а расшифровка есть в документации. */

#include "mbedtls/check_config.h"
#endif
