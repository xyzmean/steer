/* Байтовая неизменность ClientHello: страховка для правок в reality.c.
 *
 * ЗАЧЕМ. В reality.c написано прямо: отпечаток Chrome — это то, по чему сервер Reality
 * отличает нас от постороннего, и любая правка там проверяется перехватом рядом с
 * браузерным эталоном. Перехват требует сети, сервера и глаз; этот стенд требует только
 * компилятора. Он не заменяет перехват — он ловит НЕПРЕДНАМЕРЕННОЕ изменение байтов,
 * то есть тот случай, когда правка «рядом» поехала в собранный Hello и никто не заметил.
 *
 * КАК ЭТО ВОЗМОЖНО. Hello целиком выводится из случайности, времени и порядка шифров.
 * Случайность здесь подменяется детерминированным генератором (getrandom заменяется
 * макросом ДО включения исходника, поэтому подменяются и ключевая пара, и перемешивание
 * расширений, и весь шум), время фиксируется, порядок шифров пинится через STEER_CIPHER —
 * он зависит от процессора, и без пиннинга «эталон» отличался бы от машины к машине.
 *
 * ПОЧЕМУ НЕ В make test. Нужен настоящий mbedtls: Hello здесь СОБИРАЕТСЯ. Разбор того же
 * Hello проверяет tests/chellomatch.c, который берёт байты из заморозки и потому библиотеки
 * не требует, — он в make test входит.
 *
 * Собрать и запустить (исходники mbedtls 3.6.2, как в build/Dockerfile):
 *     cc -O2 -w -Isrc -I<mbedtls>/include -o build/hellofreeze tests/hellofreeze.c \
 *        <mbedtls>/library/libmbedcrypto.a
 *     ./build/hellofreeze                # сверить с tests/chello-frozen.h
 *     ./build/hellofreeze --emit > tests/chello-frozen.h   # заново заморозить
 *
 * Заново замораживать можно ТОЛЬКО вместе с перехватом рядом с браузером: заморозка
 * фиксирует то, что есть, и молча узаконит любую поломку отпечатка. */
#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/random.h>
#include <time.h>

/* Детерминированная замена getrandom. Тот же генератор, что был при первой заморозке;
 * менять его — значит менять эталон, то есть заново замораживать. */
static uint64_t prng = 0x123456789ABCDEFull;
static ssize_t det_getrandom(void *buf, size_t n, unsigned int flags) {
    (void)flags;
    unsigned char *p = buf;
    for (size_t i = 0; i < n; i++) {
        prng = prng * 6364136223846793005ull + 1442695040888963407ull;
        p[i] = (unsigned char)(prng >> 33);
    }
    return (ssize_t)n;
}
static time_t det_time(time_t *p) { (void)p; return (time_t)1700000000; }

#define getrandom(b, n, f) det_getrandom((b), (n), (f))
#define time(p) det_time(p)
#include "../src/ext/reality.c"
#undef getrandom
#undef time

#include "chello-frozen.h"

static const struct reality_cfg CFG = {
    .sni = "www.example.com",
    .pbk = "xNlHRs0RY8mJhMhOVWRxg8ykpZmqHrjKQqm3-1lQF3E",
    .sid = "0123456789abcdef",
    .fp  = "chrome",
    .alpn = "h2",
};

static size_t build(const char *cipher, unsigned char *out, size_t cap) {
    setenv("STEER_CIPHER", cipher, 1);
    prng = 0x123456789ABCDEFull;
    struct reality_state st;
    size_t n = 0;
    if (reality_build_hello(&CFG, &st, out, cap, &n) != 0) return 0;
    return n;
}

static void emit(const char *name, const unsigned char *b, size_t n) {
    printf("static const char %s[] =\n    \"", name);
    for (size_t i = 0; i < n; i++) {
        printf("\\x%02x", b[i]);
        if ((i + 1) % 16 == 0 && i + 1 < n) printf("\"\n    \"");
    }
    printf("\";\n\n");
}

int main(int argc, char **argv) {
    unsigned char a[4096], c[4096];
    size_t an = build("aes", a, sizeof(a));
    size_t cn = build("chacha", c, sizeof(c));
    if (!an || !cn) { puts("сборка Hello отказала"); return 2; }

    if (argc > 1 && !strcmp(argv[1], "--emit")) {
        puts("/* Сгенерировано tests/hellofreeze.c --emit. Пояснения — в его шапке. */");
        puts("#ifndef STEER_CHELLO_FROZEN_H\n#define STEER_CHELLO_FROZEN_H\n");
        emit("FROZEN_AES", a, an);
        emit("FROZEN_CHACHA", c, cn);
        printf("#define FROZEN_N %zu\n\n#endif\n", an);
        return 0;
    }

    int fails = 0;
    if (an != FROZEN_N || memcmp(a, FROZEN_AES, an) != 0) {
        printf("ПРОВАЛ: Hello (aes) отличается от заморозки (%zu против %d байт)\n",
               an, FROZEN_N);
        for (size_t i = 0; i < an && i < FROZEN_N; i++)
            if (a[i] != (unsigned char)FROZEN_AES[i]) {
                printf("  первое расхождение на байте %zu: %02x против %02x\n",
                       i, a[i], (unsigned char)FROZEN_AES[i]);
                break;
            }
        fails++;
    } else {
        printf("%-62s ok\n", "Hello (aes): байт в байт как в заморозке");
    }
    if (cn != FROZEN_N || memcmp(c, FROZEN_CHACHA, cn) != 0) {
        printf("ПРОВАЛ: Hello (chacha) отличается от заморозки\n");
        fails++;
    } else {
        printf("%-62s ok\n", "Hello (chacha): байт в байт как в заморозке");
    }
    /* Порядок наборов ОБЯЗАН различаться: если он одинаков, значит cpu_has_aes перестал
     * влиять на Hello, и роутер на MIPS получит шифр в шесть раз медленнее. */
    if (memcmp(a, c, an) == 0) {
        printf("ПРОВАЛ: aes и chacha дали одинаковый Hello — порядок шифров не действует\n");
        fails++;
    } else {
        printf("%-62s ok\n", "порядок наборов шифров зависит от процессора");
    }
    printf("\n%s\n", fails ? "ЕСТЬ ПРОВАЛЫ" : "все проверки прошли");
    return fails ? 1 : 0;
}
