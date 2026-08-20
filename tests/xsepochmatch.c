/* Ратчет эпох против ВЕКТОРОВ ИЗ РЕАЛИЗАЦИИ НА GO.
 *
 * ЗАЧЕМ ИМЕННО ВЕКТОРЫ, А НЕ «сходится сам с собой». Номер эпохи на проводе не передаётся: обе
 * стороны выводят его из смещения и меняют ключи молча (см. xsepoch.h). Значит расхождение в
 * выводе НЕ ПРОЯВЛЯЕТСЯ ни на рукопожатии, ни в первую минуту работы — туннель исправно несёт
 * трафик и умирает ровно на 64-м мегабайте, а в журнале при этом «запись не расшифровалась».
 * Стенд, который сверяет ратчет с самим собой, такую ошибку пропускает целиком: обе половины
 * согласованно неверны.
 *
 * И это не гипотетическая беда. При переносе я перепутал местами соль и ikm во ВТОРОМ вызове
 * HKDF-Extract (в Go порядок аргументов обратный: hkdf.Extract(hash, secret, salt)). Корень
 * при этом выводится другим вызовом и совпадал, поэтому совпадали и первые эпохи «на глаз»;
 * поймал ошибку только живой стенд против Go-хаба, потратив на это гигабайт трафика. Векторы
 * ниже — из noise/epoch.go той же реализации, снятые после трёх шагов ратчета на известном
 * корне; теперь та же ошибка стоит одного прогона make.
 *
 * Нужен настоящий mbedtls (здесь считается криптография), поэтому в make test стенд не входит —
 * как tests/crypto.c и tests/xsloop.c:
 *
 *     cc -O2 -w -Isrc -I<mbedtls>/include -DMBEDTLS_CONFIG_FILE='"steer_mbedtls_config.h"' \
 *        -Isrc/ext -o build/xsepochmatch tests/xsepochmatch.c src/ext/xsepoch.c \
 *        src/ext/tls13.c src/ext/reality.c src/ext/h2.c <mbedtls>/library/libmbedcrypto.a
 */
#include <stdio.h>
#include <string.h>

#include "../src/ext/xsepoch.h"
#include "../src/ext/xswire.h"   /* XS_REC_HDR: AAD записи — её настоящий заголовок */

static int fails;

static void ok(const char *what, int good) {
    printf("%-62s %s\n", what, good ? "ok" : "ПРОВАЛ");
    if (!good) fails++;
}

static void hex(char *dst, const uint8_t *b, size_t n) {
    for (size_t i = 0; i < n; i++) sprintf(dst + i * 2, "%02x", b[i]);
}

static void check_hex(const char *what, const char *want, const uint8_t *b, size_t n) {
    char got[160];
    hex(got, b, n);
    printf("%-62s %s\n", what, strcmp(want, got) == 0 ? "ok" : "ПРОВАЛ");
    if (strcmp(want, got) != 0) {
        printf("     хочу: %s\n     есть:  %s\n", want, got);
        fails++;
    }
}

/* Те же самые числа, что в noise/epoch_test.go задаёт keysPair: ключ 1..32, iv 100..111,
 * корень 200..231. Совпадать они обязаны именно потому, что вектора ниже сняты с них. */
static void start_keys(struct tls13_keys *k, struct xs_epoch *e) {
    memset(k, 0, sizeof(*k));
    k->aead = TLS13_AEAD_AES128;
    k->key_n = 16;
    for (int i = 0; i < 32; i++) k->key[i] = (uint8_t)(i + 1);
    for (int i = 0; i < 12; i++) k->iv[i] = (uint8_t)(i + 100);
    if (tls13_keys_setup(k) != 0) { printf("разворот шифра не удался\n"); fails++; }
    uint8_t root[32];
    for (int i = 0; i < 32; i++) root[i] = (uint8_t)(i + 200);
    xs_epoch_start(e, root);
}

/* Шифрование и расшифровка одной записи через ратчет: возвращает 0, когда открытый текст
 * вернулся тем же. AAD — настоящий заголовок записи, как на проводе. */
static int roundtrip(struct xs_epoch *te, struct tls13_keys *tk,
                     struct xs_epoch *re, struct tls13_keys *rk, uint64_t off) {
    uint8_t aad[XS_REC_HDR] = { 0x17, 0x03, 0x03, 0x00, 0x18 };
    uint8_t buf[8 + 16];
    memset(buf, 0x5A, 8);
    if (xs_epoch_seal(te, tk, off, aad, sizeof(aad), buf, 8, buf + 8) != 0) return -1;
    if (xs_epoch_open(re, rk, off, aad, sizeof(aad), buf, 8 + 16) != 0) return -2;
    for (int i = 0; i < 8; i++)
        if (buf[i] != 0x5A) return -3;
    return 0;
}

int main(void) {
    /* ---- ВЕКТОРЫ: три шага ратчета от известного корня ------------------------- */
    {
        struct tls13_keys k;
        struct xs_epoch e;
        start_keys(&k, &e);
        static const char *roots[3] = {
            "0e1855ab26dbcd9db0ec2d2d0068595c5adf852bd07a0483aeb2b7e1bc67ec2d",
            "fde2a64d14ed0f6bc28136d69b8d38225bf1e2b3769d4e8659ae2ccceb92d5a7",
            "b6b5cf7926e8447a85ef5d53187bf93b7ee9b2430d17a55b0307c39c42ce83df",
        };
        static const char *ivs[3] = {
            "ecdaeab22a46269a2389e17c",
            "09500fcafcde89f01453efb0",
            "543f295011ea809ab112df9a",
        };
        uint8_t aad[XS_REC_HDR] = { 0x17, 0x03, 0x03, 0x00, 0x18 };
        uint8_t buf[8 + 16];
        for (int step = 1; step <= 3; step++) {
            char what[128];
            /* Запись с любым смещением внутри нужной эпохи заставляет ратчет дойти до неё:
             * номер эпохи и есть смещение, делённое на её длину. */
            memset(buf, 0, 8);
            ok("шаг ратчета прошёл",
               xs_epoch_seal(&e, &k, (uint64_t)step * XS_EPOCH_BYTES + 1, aad, sizeof(aad),
                             buf, 8, buf + 8) == 0);
            snprintf(what, sizeof(what), "корень эпохи %d — как в Go", step);
            check_hex(what, roots[step - 1], e.root, 32);
            snprintf(what, sizeof(what), "iv эпохи %d — как в Go", step);
            check_hex(what, ivs[step - 1], k.iv, 12);
            snprintf(what, sizeof(what), "номер эпохи %d", step);
            ok(what, xs_epoch_now(&e) == (uint64_t)step);
        }
        xs_epoch_stop(&e);
        tls13_keys_free(&k);
    }

    /* ---- ДВЕ СТОРОНЫ ПРИХОДЯТ К ОДНИМ КЛЮЧАМ, НЕ СГОВАРИВАЯСЬ -------------------
     * Это главное свойство: получатель считает номер эпохи сам, из смещения записи. */
    {
        struct tls13_keys tk, rk;
        struct xs_epoch te, re;
        start_keys(&tk, &te);
        start_keys(&rk, &re);
        ok("запись первой эпохи (смещение 1) ходит", roundtrip(&te, &tk, &re, &rk, 1) == 0);
        ok("на границе 64 МиБ обе стороны сменили ключи молча",
           roundtrip(&te, &tk, &re, &rk, XS_EPOCH_BYTES) == 0);
        ok("отправитель в эпохе 1", xs_epoch_now(&te) == 1);
        ok("получатель тоже в эпохе 1", xs_epoch_now(&re) == 1);
        ok("через десять эпох тоже сходятся",
           roundtrip(&te, &tk, &re, &rk, 11 * XS_EPOCH_BYTES + 777) == 0);
        ok("оба в эпохе 11", xs_epoch_now(&te) == 11 && xs_epoch_now(&re) == 11);

        /* Запись ПРОШЛОЙ эпохи, отставшая на границе, ещё расшифровывается — и состояние
         * получателя от неё не откатывается. Иначе одна такая запись стоила бы обрыва. */
        uint8_t aad[XS_REC_HDR] = { 0x17, 0x03, 0x03, 0x00, 0x18 };
        uint8_t buf[8 + 16];
        struct tls13_keys tk2;
        struct xs_epoch te2;
        start_keys(&tk2, &te2);
        memset(buf, 0x33, 8);
        /* Отправитель остаётся в эпохе 10, получатель уже в 11. */
        ok("запись эпохи 10 собрана",
           xs_epoch_seal(&te2, &tk2, 10 * XS_EPOCH_BYTES, aad, sizeof(aad), buf, 8, buf + 8) == 0);
        ok("отправитель в эпохе 10", xs_epoch_now(&te2) == 10);
        ok("получатель принял запись прошлой эпохи прошлыми ключами",
           xs_epoch_open(&re, &rk, 10 * XS_EPOCH_BYTES, aad, sizeof(aad), buf, 8 + 16) == 0);
        ok("и НЕ откатился назад", xs_epoch_now(&re) == 11);

        /* Позапрошлая эпоха — отказ: её ключи стёрты, и в этом весь смысл ратчета. */
        struct tls13_keys tk3;
        struct xs_epoch te3;
        start_keys(&tk3, &te3);
        memset(buf, 0x44, 8);
        xs_epoch_seal(&te3, &tk3, 9 * XS_EPOCH_BYTES, aad, sizeof(aad), buf, 8, buf + 8);
        ok("запись позапрошлой эпохи отвергнута",
           xs_epoch_open(&re, &rk, 9 * XS_EPOCH_BYTES, aad, sizeof(aad), buf, 8 + 16) != 0);

        /* Прыжок дальше предела — отказ, а не миллион HKDF на одну запись. */
        memset(buf, 0x55, 8);
        ok("прыжок за предел отвергнут",
           xs_epoch_open(&re, &rk, (11 + XS_EPOCH_JUMP_MAX + 1) * XS_EPOCH_BYTES,
                         aad, sizeof(aad), buf, 8 + 16) != 0);
        ok("состояние от отказа не сдвинулось", xs_epoch_now(&re) == 11);

        xs_epoch_stop(&te); xs_epoch_stop(&re);
        xs_epoch_stop(&te2); xs_epoch_stop(&te3);
        tls13_keys_free(&tk); tls13_keys_free(&rk);
        tls13_keys_free(&tk2); tls13_keys_free(&tk3);
    }

    /* ---- ВЫКЛЮЧЕННЫЙ РАТЧЕТ НЕ МЕНЯЕТ НИ ОДНОГО БАЙТА --------------------------
     * Половина поддельного TCP зовёт tls13_aead_seal напрямую и про эпохи не знает. Если
     * когда-нибудь она пойдёт через эту обёртку, шифротекст обязан остаться тем же — иначе
     * обновление одной стороны рассыпало бы совместимость. */
    {
        struct tls13_keys ka, kb;
        struct xs_epoch ea, eb;
        start_keys(&ka, &ea);
        start_keys(&kb, &eb);
        memset(&ea, 0, sizeof(ea));              /* ратчет выключен: on == 0 */
        uint8_t aad[XS_REC_HDR] = { 0x17, 0x03, 0x03, 0x00, 0x18 };
        uint8_t a[8 + 16], b[8 + 16];
        memset(a, 0x77, 8);
        memset(b, 0x77, 8);
        int r1 = xs_epoch_seal(&ea, &ka, 12345, aad, sizeof(aad), a, 8, a + 8);
        int r2 = tls13_aead_seal(&kb, 12345, aad, sizeof(aad), b, 8, b + 8);
        ok("оба шифрования прошли", r1 == 0 && r2 == 0);
        ok("с выключенным ратчетом шифротекст побайтово тот же",
           memcmp(a, b, sizeof(a)) == 0);
        xs_epoch_stop(&eb);
        tls13_keys_free(&ka); tls13_keys_free(&kb);
    }

    printf(fails ? "\nПРОВАЛОВ: %d\n" : "\nвсе проверки прошли\n", fails);
    return fails ? 1 : 0;
}
