/* Сколько мегабайт в секунду даёт AEAD на этом железе.
 *
 * Нужен потому, что весь трафик туннеля проходит через расшифровку ровно один раз, и
 * потолок AEAD — это потолок туннеля. Гадать тут нельзя: на Cortex-A53 разница между
 * программным AES и инструкциями AES доходит до пяти раз, а GHASH в mbedtls 3.6 всегда
 * табличный (PMULL не используется), поэтому «включили аппаратный AES» может ничего не
 * дать — узкое место окажется в аутентификации.
 *
 * Меряется то, что происходит в реальности: расшифровка записи TLS вместе с проверкой тега,
 * на месте, с теми же вызовами, что в tls13.c.
 *
 * ДВА замера на каждый шифр, и второй важнее первого. «Ключ развёрнут заранее» — это то,
 * что делает tls13.c сейчас. «Ключ на каждую запись» — это то, что он делал раньше:
 * init + setkey + free перед каждой записью, то есть выделение контекста в куче, разворот
 * расписания ключа и генерация таблицы GHASH как постоянная добавка к каждой записи.
 *
 * Первая версия этого файла ставила ключ ОДИН РАЗ вне измеряемого цикла — и потому измеряла
 * не тот код, который работал. Отсюда и брались «800 Мбит/с» при скорости туннеля в 45:
 * цифра была честная, но относилась к другой программе.
 *
 * Размер записи задаётся первым аргументом. Это не украшение: после перехода Vision на
 * прямое копирование записи становятся по 300 байт, и постоянная добавка на запись, которая
 * при 16 КБ невидима, при 300 байтах становится основной статьёй расхода.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include "mbedtls/gcm.h"
#include "mbedtls/chachapoly.h"

static size_t g_rec = 16384;
static long g_rounds = 400;
#define REC_MAX 16384

static double now_s(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (double)ts.tv_sec + (double)ts.tv_nsec / 1e9;
}

/* Замер: keyed == 1 — ключ развёрнут заранее (как сейчас), 0 — на каждую запись
 * (как было). Возвращает МБ/с. */
static double bench_gcm(int bits, int keyed) {
    static unsigned char buf[REC_MAX + 16];
    unsigned char key[32], iv[12], tag[16];
    unsigned char aad[5] = { 0x17, 3, 3, 0, 0 };
    aad[3] = (unsigned char)(g_rec >> 8); aad[4] = (unsigned char)g_rec;
    memset(key, 0x11, sizeof(key));
    memset(iv, 0x22, sizeof(iv));
    memset(buf, 0x33, sizeof(buf));

    mbedtls_gcm_context g;
    mbedtls_gcm_init(&g);
    if (mbedtls_gcm_setkey(&g, MBEDTLS_CIPHER_ID_AES, key, (unsigned)bits) != 0) {
        printf("AES-%d-GCM: ключ не принят\n", bits);
        return 0;
    }
    /* Один раз шифруем, чтобы получить настоящий тег, дальше меряем расшифровку. */
    mbedtls_gcm_crypt_and_tag(&g, MBEDTLS_GCM_ENCRYPT, g_rec, iv, 12, aad, 5, buf, buf, 16, tag);

    double t0 = now_s();
    for (long i = 0; i < g_rounds; i++) {
        unsigned char t2[16];
        memcpy(t2, tag, 16);
        /* Расшифровка портит буфер, поэтому дальше тег не сойдётся — нас интересует
         * только время работы, и оно от результата не зависит. */
        if (keyed) {
            mbedtls_gcm_auth_decrypt(&g, g_rec, iv, 12, aad, 5, t2, 16, buf, buf);
        } else {
            mbedtls_gcm_context t;
            mbedtls_gcm_init(&t);
            mbedtls_gcm_setkey(&t, MBEDTLS_CIPHER_ID_AES, key, (unsigned)bits);
            mbedtls_gcm_auth_decrypt(&t, g_rec, iv, 12, aad, 5, t2, 16, buf, buf);
            mbedtls_gcm_free(&t);
        }
    }
    double dt = now_s() - t0;
    mbedtls_gcm_free(&g);
    return (double)g_rec * (double)g_rounds / dt / 1048576.0;
}

static double bench_chacha(int keyed) {
    static unsigned char buf[REC_MAX + 16];
    unsigned char key[32], iv[12], tag[16];
    unsigned char aad[5] = { 0x17, 3, 3, 0, 0 };
    aad[3] = (unsigned char)(g_rec >> 8); aad[4] = (unsigned char)g_rec;
    memset(key, 0x44, sizeof(key));
    memset(iv, 0x55, sizeof(iv));
    memset(buf, 0x66, sizeof(buf));

    mbedtls_chachapoly_context c;
    mbedtls_chachapoly_init(&c);
    if (mbedtls_chachapoly_setkey(&c, key) != 0) {
        printf("ChaCha20-Poly1305: ключ не принят\n");
        return 0;
    }
    mbedtls_chachapoly_encrypt_and_tag(&c, g_rec, iv, aad, 5, buf, buf, tag);

    double t0 = now_s();
    for (long i = 0; i < g_rounds; i++) {
        if (keyed) {
            mbedtls_chachapoly_auth_decrypt(&c, g_rec, iv, aad, 5, tag, buf, buf);
        } else {
            mbedtls_chachapoly_context t;
            mbedtls_chachapoly_init(&t);
            mbedtls_chachapoly_setkey(&t, key);
            mbedtls_chachapoly_auth_decrypt(&t, g_rec, iv, aad, 5, tag, buf, buf);
            mbedtls_chachapoly_free(&t);
        }
    }
    double dt = now_s() - t0;
    mbedtls_chachapoly_free(&c);
    return (double)g_rec * (double)g_rounds / dt / 1048576.0;
}

static void report(const char *name, double keyed, double per_rec) {
    printf("  %-22s %7.1f МБ/с (%5.0f Мбит/с)   на запись: %7.1f МБ/с (%5.0f Мбит/с)"
           "   потеря %2.0f%%\n",
           name, keyed, keyed * 8 / 1.048576, per_rec, per_rec * 8 / 1.048576,
           keyed > 0 ? 100.0 * (keyed - per_rec) / keyed : 0.0);
}

int main(int argc, char **argv) {
#if defined(MBEDTLS_AESCE_C) || defined(MBEDTLS_AESNI_C)
    printf("сборка: инструкции AES включены (с проверкой на месте)\n");
#else
    printf("сборка: AES программный\n");
#endif
#if defined(MBEDTLS_GCM_LARGE_TABLE)
    printf("сборка: GHASH на больших таблицах\n");
#endif
    /* Размеры записи, а не один: постоянная добавка на запись видна только на мелких. */
    static const size_t sizes[] = { 16384, 4096, 300 };
    size_t only = argc > 1 ? (size_t)strtoul(argv[1], NULL, 10) : 0;

    for (size_t i = 0; i < sizeof(sizes) / sizeof(*sizes); i++) {
        if (only && sizes[i] != only) continue;
        g_rec = sizes[i];
        /* Проходов столько, чтобы каждый замер трогал одинаковый объём данных: иначе на
         * мелких записях измеряется в основном разброс часов. */
        g_rounds = (long)(64u * 1024 * 1024 / g_rec);
        printf("запись %zu байт, %ld проходов (%.0f МБ на замер)\n",
               g_rec, g_rounds, (double)g_rec * (double)g_rounds / 1048576.0);
        report("AES-128-GCM", bench_gcm(128, 1), bench_gcm(128, 0));
        report("AES-256-GCM", bench_gcm(256, 1), bench_gcm(256, 0));
        report("ChaCha20-Poly1305", bench_chacha(1), bench_chacha(0));
    }
    return 0;
}
