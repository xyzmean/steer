/* Проверка сертификата сервера для security=tls.
 *
 * Отдельным файлом, а не внутри tls13.c, и это не вкусовщина: заголовок tls13.c обещает, что
 * mbedtls_x509_* и mbedtls_ssl_* там не вызываются НИ РАЗУ, и это обещание проверяется одной
 * командой (`grep -rho 'mbedtls_[a-z0-9_]*' src/`). Reality сертификат не проверяет по
 * построению — цепочка принадлежит чужому маскировочному сайту, — и путь записей обязан
 * оставаться свободным от X.509, чтобы сборка tgws и сборка без security=tls не тащили за
 * собой сотню килобайт разбора ASN.1. Здесь этот код собран в одном месте, и видно, кто его
 * зовёт.
 */
#ifndef STEER_CERTVERIFY_H
#define STEER_CERTVERIFY_H
#include <stddef.h>

#define CERTV_EPARSE   (-70)   /* сообщение Certificate или CertificateVerify не разобралось */
#define CERTV_ENOROOTS (-71)   /* хранилище корней не прочиталось: проверять нечем */
#define CERTV_ECHAIN   (-72)   /* цепочка не сошлась с корнями или имя не то */
#define CERTV_ESIG     (-73)   /* подпись CertificateVerify неверна */
#define CERTV_EALG     (-74)   /* сервер подписал алгоритмом, которого мы не предлагали */

/* Где лежат корни. Путь вынесен в шов, а не зашит: стенду нужен свой набор, а на роутере это
 * файл пакета ca-bundle. Пустая строка означает «взять умолчание». */
#define CERTV_DEFAULT_ROOTS "/etc/ssl/certs/ca-certificates.crt"

/* Проверить подлинность сервера по правилам TLS 1.3 (RFC 8446 §4.4.2 и §4.4.3).
 *
 * cert_body / cert_n     — ТЕЛО сообщения Certificate, без четырёх байт заголовка;
 * cv_body  / cv_n        — тело CertificateVerify;
 * transcript / thash_n   — Transcript-Hash по сообщениям ДО CertificateVerify включительно
 *                          с Certificate, то есть ровно то, что подписал сервер;
 * host                   — имя, которое обязано найтись в сертификате;
 * roots                  — путь к хранилищу корней или NULL/"" для умолчания.
 *
 * Возвращает 0, если сервер подлинный. Всё остальное — код выше, и каждый из них означает
 * РАЗНОЕ: «нечем проверить» это не то же самое, что «проверили и не сошлось», и человеку в
 * причине непригодности узла нужно видеть именно эту разницу.
 */
int cert_verify_server(const unsigned char *cert_body, size_t cert_n,
                       const unsigned char *cv_body, size_t cv_n,
                       const unsigned char *transcript, size_t thash_n,
                       const char *host, const char *roots);

/* Человеческое объяснение кода. Пустая строка для 0. */
const char *cert_verify_strerror(int rc);

#endif
