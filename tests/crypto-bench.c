/* Сколько мегабайт в секунду даёт AEAD на этом железе.
 *
 * Нужен потому, что весь трафик туннеля проходит через расшифровку ровно один раз, и
 * потолок AEAD — это потолок туннеля. Гадать тут нельзя: на Cortex-A53 разница между
 * программным AES и инструкциями AES доходит до пяти раз, а GHASH в mbedtls 3.6 всегда
 * табличный (PMULL не используется), поэтому «включили аппаратный AES» может ничего не
 * дать — узкое место окажется в аутентификации.
 *
 * Меряется то, что происходит в реальности: расшифровка записи TLS размером 16 КБ вместе
 * с проверкой тега, на месте, с теми же вызовами, что в tls13.c.
 */
#include <stdio.h>
#include <string.h>
#include <time.h>
#include "mbedtls/gcm.h"
#include "mbedtls/chachapoly.h"

#define REC 16384
#define ROUNDS 400

static double now_s(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (double)ts.tv_sec + (double)ts.tv_nsec / 1e9;
}

static void bench_gcm(int bits) {
    static unsigned char buf[REC + 16];
    unsigned char key[32], iv[12], aad[5] = { 0x17, 3, 3, REC >> 8, REC & 255 }, tag[16];
    memset(key, 0x11, sizeof(key));
    memset(iv, 0x22, sizeof(iv));
    memset(buf, 0x33, sizeof(buf));

    mbedtls_gcm_context g;
    mbedtls_gcm_init(&g);
    if (mbedtls_gcm_setkey(&g, MBEDTLS_CIPHER_ID_AES, key, (unsigned)bits) != 0) {
        printf("AES-%d-GCM: ключ не принят\n", bits);
        return;
    }
    /* Один раз шифруем, чтобы получить настоящий тег, дальше меряем расшифровку. */
    mbedtls_gcm_crypt_and_tag(&g, MBEDTLS_GCM_ENCRYPT, REC, iv, 12, aad, 5, buf, buf, 16, tag);

    double t0 = now_s();
    for (int i = 0; i < ROUNDS; i++) {
        unsigned char t2[16];
        memcpy(t2, tag, 16);
        /* Расшифровка портит буфер, поэтому дальше тег не сойдётся — нас интересует
         * только время работы, и оно от результата не зависит. */
        mbedtls_gcm_auth_decrypt(&g, REC, iv, 12, aad, 5, t2, 16, buf, buf);
    }
    double dt = now_s() - t0;
    mbedtls_gcm_free(&g);
    printf("AES-%d-GCM:            %6.1f МБ/с  (%.0f Мбит/с)\n", bits,
           (double)REC * ROUNDS / dt / 1048576.0,
           (double)REC * ROUNDS * 8 / dt / 1000000.0);
}

static void bench_chacha(void) {
    static unsigned char buf[REC + 16];
    unsigned char key[32], iv[12], aad[5] = { 0x17, 3, 3, REC >> 8, REC & 255 }, tag[16];
    memset(key, 0x44, sizeof(key));
    memset(iv, 0x55, sizeof(iv));
    memset(buf, 0x66, sizeof(buf));

    mbedtls_chachapoly_context c;
    mbedtls_chachapoly_init(&c);
    if (mbedtls_chachapoly_setkey(&c, key) != 0) {
        printf("ChaCha20-Poly1305: ключ не принят\n");
        return;
    }
    mbedtls_chachapoly_encrypt_and_tag(&c, REC, iv, aad, 5, buf, buf, tag);

    double t0 = now_s();
    for (int i = 0; i < ROUNDS; i++)
        mbedtls_chachapoly_auth_decrypt(&c, REC, iv, aad, 5, tag, buf, buf);
    double dt = now_s() - t0;
    mbedtls_chachapoly_free(&c);
    printf("ChaCha20-Poly1305:    %6.1f МБ/с  (%.0f Мбит/с)\n",
           (double)REC * ROUNDS / dt / 1048576.0,
           (double)REC * ROUNDS * 8 / dt / 1000000.0);
}

int main(void) {
    printf("запись %d байт, %d проходов\n", REC, ROUNDS);
#if defined(MBEDTLS_AESCE_C)
    printf("сборка: инструкции AES включены (с проверкой на месте)\n");
#else
    printf("сборка: AES программный\n");
#endif
#if defined(MBEDTLS_GCM_LARGE_TABLE)
    printf("сборка: GHASH на больших таблицах\n");
#endif
    bench_gcm(128);
    bench_gcm(256);
    bench_chacha();
    return 0;
}
