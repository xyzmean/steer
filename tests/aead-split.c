/* Из чего складывается потолок AEAD: ChaCha20 отдельно, Poly1305 отдельно, вместе.
 *
 * Зачем отдельно от crypto-bench.c. Тот отвечает на вопрос «какой шифр выбрать» и мерит
 * то, что происходит в tls13.c целиком. Этот отвечает на другой: «а внутри выбранного шифра
 * что дорого». Разница практическая — если потолок ставит Poly1305, ускорять поток шифра
 * бессмысленно, и наоборот; на MIPS без SIMD догадаться, что из двух дороже, нельзя.
 *
 * Считаем такты на байт, а не только мегабайты в секунду: такты сравнимы между машинами
 * разной частоты, а «сколько это в процентах от разумного» видно только по ним. Частота
 * берётся аргументом, потому что /proc/cpuinfo на MIPS её не печатает.
 *
 * Сборка — так же, как crypto-bench.c (см. build/bench.sh).
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include "mbedtls/chacha20.h"
#include "mbedtls/poly1305.h"
#include "mbedtls/chachapoly.h"

static double now_s(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (double)ts.tv_sec + (double)ts.tv_nsec / 1e9;
}

int main(int argc, char **argv) {
    size_t n = argc > 1 ? (size_t)strtoul(argv[1], NULL, 10) : 16384;
    double mhz = argc > 2 ? strtod(argv[2], NULL) : 0;
    /* Объём фиксирован, а не число проходов: иначе замеры разных размеров записи
     * несравнимы между собой по времени. */
    size_t total = 64u * 1024 * 1024;
    size_t passes = total / n;
    if (!passes) passes = 1;

    unsigned char *buf = malloc(n + 16);
    if (!buf) return 1;
    memset(buf, 0x5a, n + 16);
    unsigned char key[32], nonce[12], mac[16];
    memset(key, 0x11, sizeof(key));
    memset(nonce, 0x22, sizeof(nonce));

    printf("запись %zu байт, %zu проходов (%zu МБ на замер)\n",
           n, passes, total / (1024 * 1024));

    struct { const char *name; double s; } r[3];

    { /* ChaCha20: только поток шифра, на месте. */
        mbedtls_chacha20_context c;
        mbedtls_chacha20_init(&c);
        mbedtls_chacha20_setkey(&c, key);
        double t0 = now_s();
        for (size_t i = 0; i < passes; i++) {
            mbedtls_chacha20_starts(&c, nonce, 1);
            mbedtls_chacha20_update(&c, n, buf, buf);
        }
        r[0].name = "ChaCha20"; r[0].s = now_s() - t0;
        mbedtls_chacha20_free(&c);
    }

    { /* Poly1305: только аутентификация. */
        double t0 = now_s();
        for (size_t i = 0; i < passes; i++)
            mbedtls_poly1305_mac(key, buf, n, mac);
        r[1].name = "Poly1305"; r[1].s = now_s() - t0;
    }

    { /* Вместе — то, что и делает tls13.c. */
        mbedtls_chachapoly_context c;
        mbedtls_chachapoly_init(&c);
        mbedtls_chachapoly_setkey(&c, key);
        double t0 = now_s();
        for (size_t i = 0; i < passes; i++)
            mbedtls_chachapoly_encrypt_and_tag(&c, n, nonce, NULL, 0, buf, buf, mac);
        r[2].name = "ChaCha20-Poly1305"; r[2].s = now_s() - t0;
        mbedtls_chachapoly_free(&c);
    }

    for (int i = 0; i < 3; i++) {
        double mb = (double)total / (1024 * 1024) / r[i].s;
        printf("  %-20s %7.1f МБ/с (%5.0f Мбит/с)", r[i].name, mb, mb * 8);
        if (mhz > 0) printf("   %5.1f такта/байт", mhz * 1e6 / (mb * 1024 * 1024));
        printf("\n");
    }
    free(buf);
    return 0;
}
