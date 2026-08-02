/* Проверка AES-GCM на размерах записи TLS.
 *
 * Появилась из-за конкретной поломки: расшифровка записи в 16401 байт (максимальной для
 * TLS 1.3) стабильно не сходилась по тегу, тогда как всё до 8203 байт работало
 * безупречно — на живом сервере, после десятков тысяч успешных записей. Такая граница не
 * может быть случайной, и проверить её надо было в отрыве от сети.
 *
 * Тест шифрует и расшифровывает НА МЕСТЕ, ровно как это делает tls13.c: тег лежит сразу
 * за шифротекстом в том же буфере. Если библиотека при этом задевает тег, тест это и
 * покажет — без роутера, без сервера и без криптоанализа.
 */
#include <stdio.h>
#include <string.h>
#include "mbedtls/gcm.h"

static int roundtrip(size_t plain_n, int inplace) {
    static unsigned char buf[20000];
    unsigned char key[32], iv[12], aad[5] = { 0x17, 0x03, 0x03, 0, 0 };
    memset(key, 0xA5, sizeof(key));
    memset(iv, 0x5A, sizeof(iv));
    for (size_t i = 0; i < plain_n; i++) buf[i] = (unsigned char)(i * 31 + 7);

    static unsigned char expect[20000];
    memcpy(expect, buf, plain_n);

    size_t total = plain_n + 16;
    aad[3] = (unsigned char)(total >> 8);
    aad[4] = (unsigned char)total;

    mbedtls_gcm_context g;
    mbedtls_gcm_init(&g);
    if (mbedtls_gcm_setkey(&g, MBEDTLS_CIPHER_ID_AES, key, 256) != 0) return -1;
    /* Шифруем на месте и кладём тег сразу за шифротекстом — как в записи TLS. */
    if (mbedtls_gcm_crypt_and_tag(&g, MBEDTLS_GCM_ENCRYPT, plain_n, iv, 12,
                                  aad, 5, buf, buf, 16, buf + plain_n) != 0) return -2;
    mbedtls_gcm_free(&g);

    unsigned char tag[16];
    memcpy(tag, buf + plain_n, 16);

    mbedtls_gcm_init(&g);
    if (mbedtls_gcm_setkey(&g, MBEDTLS_CIPHER_ID_AES, key, 256) != 0) return -3;
    int rc = mbedtls_gcm_auth_decrypt(&g, plain_n, iv, 12, aad, 5,
                                      inplace ? tag : buf + plain_n, 16,
                                      buf, buf);
    mbedtls_gcm_free(&g);
    if (rc != 0) return -4;
    if (memcmp(buf, expect, plain_n) != 0) return -5;
    return 0;
}

int main(void) {
    /* Размеры вокруг границы 2^14: именно там ломалось. */
    size_t sizes[] = { 1, 16, 17, 266, 1203, 8176, 8187, 8203,
                       16368, 16383, 16384, 16385, 16400, 16401, 16624 };
    int bad = 0;
    for (size_t i = 0; i < sizeof(sizes) / sizeof(sizes[0]); i++) {
        int a = roundtrip(sizes[i], 1);
        int b = roundtrip(sizes[i], 0);
        if (a != 0 || b != 0) {
            printf("FAIL %zu байт: копия тега rc=%d, тег в буфере rc=%d\n", sizes[i], a, b);
            bad++;
        }
    }
    printf("%s\n", bad ? "есть отказы" : "все размеры сошлись");
    return bad ? 1 : 0;
}
