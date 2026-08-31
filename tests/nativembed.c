/* Годится ли libmbedcrypto САМОГО УСТРОЙСТВА в качестве криптографии движка.
 *
 * ЗАЧЕМ ЭТОТ СТЕНД. Расширенную половину можно связать не со своей копией mbedtls, а с той
 * библиотекой, которая уже лежит на роутере (см. build/build-ext-native.sh и docs/xsteer.md):
 * бинарник худеет с 574 552 до 319 940 байт, а на шифре не теряет ничего заметного — около 1%.
 * Плата за это — зависимость от ЧУЖОЙ сборки: раскладка публичных структур mbedtls зависит от
 * макросов конфигурации (MBEDTLS_ECP_RESTARTABLE добавляет поля в mbedtls_ecp_group, любой *_ALT
 * меняет контекст целиком), а конфигурацию выбирает OpenWrt, не мы.
 *
 * Расхождение раскладки НЕ ПАДАЕТ на сборке и НЕ ЛОВИТСЯ линковщиком: оно портит память в работе.
 * В криптографии это худший вид отказа, потому что «тихо перестало защищать» снаружи неотличимо от
 * «работает». Отсюда правило: нативная сборка выкладывается только на тот выпуск OpenWrt, на
 * котором этот стенд отвечает «всё сошлось», и проверяется он на самом устройстве.
 *
 * Сверить версию заголовков с версией библиотеки нельзя: в сборке OpenWrt выключен
 * MBEDTLS_VERSION_C, и mbedtls_version_get_number в библиотеке роутера просто нет (проверено —
 * «symbol not found»).
 * Поэтому единственный настоящий оракул здесь — ОТВЕТЫ примитивов на известных векторах: если бы
 * раскладка не совпала, они бы не сошлись.
 *
 * Проверяется два разных вопроса:
 *
 *  1. РАЗМЕРЫ структур, которые трогает движок, — печатаются, чтобы человек видел, с чем имеет
 *     дело, и мог сравнить два выпуска между собой.
 *  2. ОТВЕТЫ примитивов: ChaCha20-Poly1305 из RFC 8439, AES-128-GCM (круг и отказ по тегу),
 *     SHA-256, HKDF из RFC 5869 и загрузка кривой X25519 — её OpenWrt мог и не включить, а без
 *     неё рукопожатия нет вовсе.
 *
 * КАК ЗАПУСКАТЬ (на устройстве, стоковыми заголовками той же версии, что библиотека, БЕЗ нашей
 * steer_mbedtls_config.h — именно так собран и сам нативный бинарник):
 *
 *     $CC -O2 -I<mbedtls-3.6.x>/include -o nativembed tests/nativembed.c -lmbedcrypto
 *     scp nativembed root@роутер:/tmp && ssh root@роутер /tmp/nativembed
 *
 * В `make test` его нет намеренно: на хосте сборки лежит наша конфигурация, и там стенд проверял
 * бы не ту библиотеку, ради которой существует. */
#include <stdio.h>
#include <string.h>
#include <mbedtls/gcm.h>
#include <mbedtls/chachapoly.h>
#include <mbedtls/sha256.h>
#include <mbedtls/sha512.h>
#include <mbedtls/ecp.h>
#include <mbedtls/bignum.h>
#include <mbedtls/hkdf.h>
#include <mbedtls/md.h>
#include <mbedtls/version.h>

/* ГПСЧ обязателен: mbedtls ослепляет скаляр и без него отвечает BAD_INPUT_DATA. Наш код передаёт
 * свой (reality.c, rng_cb), поэтому и проба обязана — иначе она проверяла бы не то. */
static int probe_rng(void *ctx, unsigned char *out, size_t n) {
    (void)ctx;
    static unsigned int st = 12345;
    for (size_t i = 0; i < n; i++) { st = st * 1103515245u + 12345u; out[i] = (unsigned char)(st >> 16); }
    return 0;
}

static int fails;
static void ok(const char *what, int good) {
    printf("%-46s %s\n", what, good ? "ok" : "ПРОВАЛ");
    if (!good) fails++;
}
static void hexdump(const char *tag, const unsigned char *p, size_t n) {
    printf("    %s: ", tag);
    for (size_t i = 0; i < n; i++) printf("%02x", p[i]);
    printf("\n");
}

int main(void) {
    /* mbedtls_version_get_string_full НЕ ЗОВЁМ: в сборке OpenWrt модуль версии выключен
     * (MBEDTLS_VERSION_C), и проба с ним не запускается вовсе — «symbol not found». Само это
     * находка: библиотека роутера урезана, и каждый нужный символ надо проверять, а не
     * предполагать. Все 51, которые зовёт движок, в ней есть — сверено отдельно. */
    printf("библиотека: та, что лежит на роутере\n\n");

    printf("размеры структур (сравнить с нашей конфигурацией):\n");
    printf("  mbedtls_gcm_context        %zu\n", sizeof(mbedtls_gcm_context));
    printf("  mbedtls_chachapoly_context %zu\n", sizeof(mbedtls_chachapoly_context));
    printf("  mbedtls_sha256_context     %zu\n", sizeof(mbedtls_sha256_context));
    printf("  mbedtls_sha512_context     %zu\n", sizeof(mbedtls_sha512_context));
    printf("  mbedtls_ecp_group          %zu\n", sizeof(mbedtls_ecp_group));
    printf("  mbedtls_ecp_point          %zu\n", sizeof(mbedtls_ecp_point));
    printf("  mbedtls_mpi                %zu\n", sizeof(mbedtls_mpi));
    printf("\nответы примитивов:\n");

    /* ChaCha20-Poly1305, вектор RFC 8439 §2.8.2. */
    {
        static const unsigned char key[32] = {
            0x80,0x81,0x82,0x83,0x84,0x85,0x86,0x87,0x88,0x89,0x8a,0x8b,0x8c,0x8d,0x8e,0x8f,
            0x90,0x91,0x92,0x93,0x94,0x95,0x96,0x97,0x98,0x99,0x9a,0x9b,0x9c,0x9d,0x9e,0x9f };
        static const unsigned char nonce[12] = {0x07,0x00,0x00,0x00,0x40,0x41,0x42,0x43,0x44,0x45,0x46,0x47};
        static const unsigned char aad[12] = {0x50,0x51,0x52,0x53,0xc0,0xc1,0xc2,0xc3,0xc4,0xc5,0xc6,0xc7};
        const char *pt = "Ladies and Gentlemen of the class of '99: If I could offer you only one tip for the future, sunscreen would be it.";
        static const unsigned char want_tag[16] = {
            0x1a,0xe1,0x0b,0x59,0x4f,0x09,0xe2,0x6a,0x7e,0x90,0x2e,0xcb,0xd0,0x60,0x06,0x91 };
        unsigned char ct[128], tag[16];
        mbedtls_chachapoly_context c;
        mbedtls_chachapoly_init(&c);
        int e = mbedtls_chachapoly_setkey(&c, key);
        e |= mbedtls_chachapoly_encrypt_and_tag(&c, strlen(pt), nonce, aad, sizeof(aad),
                                               (const unsigned char *)pt, ct, tag);
        ok("ChaCha20-Poly1305: вектор RFC 8439 сошёлся",
           e == 0 && memcmp(tag, want_tag, 16) == 0 && ct[0] == 0xd3);
        if (memcmp(tag, want_tag, 16) != 0) hexdump("тег", tag, 16);
        mbedtls_chachapoly_free(&c);
    }

    /* AES-128-GCM: свой шифротекст обязан расшифроваться, а испорченный тег — отвергнуться. */
    {
        unsigned char key[16], iv[12], buf[64], out[64], tag[16];
        memset(key, 0x2b, sizeof(key));
        memset(iv, 0x11, sizeof(iv));
        for (size_t i = 0; i < sizeof(buf); i++) buf[i] = (unsigned char)i;
        mbedtls_gcm_context g;
        mbedtls_gcm_init(&g);
        int e1 = mbedtls_gcm_setkey(&g, MBEDTLS_CIPHER_ID_AES, key, 128);
        int e2 = mbedtls_gcm_crypt_and_tag(&g, MBEDTLS_GCM_ENCRYPT, sizeof(buf), iv, sizeof(iv),
                                       NULL, 0, buf, out, 16, tag);
        int e = e1 | e2;
        if (e) printf("    setkey=%d crypt=%d\n", e1, e2);
        unsigned char back[64];
        int d = mbedtls_gcm_auth_decrypt(&g, sizeof(buf), iv, sizeof(iv), NULL, 0,
                                        tag, 16, out, back);
        if (d) printf("    decrypt=%d\n", d);
        /* Итог круга проверяется ДО порчи тега: mbedtls расшифровывает в выходной буфер и только
         * потом проваливает проверку тега, то есть неудачная расшифровка затирает то, что мы
         * собирались сравнивать. Первая версия пробы так и попалась. */
        int round_ok = (e == 0 && d == 0 && memcmp(back, buf, sizeof(buf)) == 0);
        tag[0] ^= 0x80;
        int bad = mbedtls_gcm_auth_decrypt(&g, sizeof(buf), iv, sizeof(iv), NULL, 0,
                                          tag, 16, out, back);
        ok("AES-128-GCM: круг сошёлся", round_ok);
        ok("AES-128-GCM: испорченный тег отвергнут", bad != 0);
        mbedtls_gcm_free(&g);
    }

    /* SHA-256 известного входа. */
    {
        unsigned char h[32];
        static const unsigned char want[32] = {
            0xba,0x78,0x16,0xbf,0x8f,0x01,0xcf,0xea,0x41,0x41,0x40,0xde,0x5d,0xae,0x22,0x23,
            0xb0,0x03,0x61,0xa3,0x96,0x17,0x7a,0x9c,0xb4,0x10,0xff,0x61,0xf2,0x00,0x15,0xad };
        int e = mbedtls_sha256((const unsigned char *)"abc", 3, h, 0);
        ok("SHA-256: вектор сошёлся", e == 0 && memcmp(h, want, 32) == 0);
    }

    /* HKDF: им выводятся все транспортные ключи. */
    {
        unsigned char out[42];
        unsigned char ikm[22], salt[13], info[10];
        memset(ikm, 0x0b, sizeof(ikm));
        for (size_t i = 0; i < sizeof(salt); i++) salt[i] = (unsigned char)i;
        for (size_t i = 0; i < sizeof(info); i++) info[i] = (unsigned char)(0xf0 + i);
        static const unsigned char want8[8] = {0x3c,0xb2,0x5f,0x25,0xfa,0xac,0xd5,0x7a};
        int e = mbedtls_hkdf(mbedtls_md_info_from_type(MBEDTLS_MD_SHA256),
                             salt, sizeof(salt), ikm, sizeof(ikm), info, sizeof(info),
                             out, sizeof(out));
        ok("HKDF-SHA256: вектор RFC 5869 сошёлся", e == 0 && memcmp(out, want8, 8) == 0);
    }

    /* X25519: кривую OpenWrt мог и не включить, а без неё рукопожатия нет вовсе. */
    {
        mbedtls_ecp_group grp;
        mbedtls_ecp_group_init(&grp);
        int e = mbedtls_ecp_group_load(&grp, MBEDTLS_ECP_DP_CURVE25519);
        ok("X25519: кривая в библиотеке есть", e == 0);
        if (e == 0) {
            /* Базовая точка на скаляре 9 — то же, что делает наш x25519_shared_ext. */
            mbedtls_mpi s;
            mbedtls_ecp_point P;
            mbedtls_mpi_init(&s);
            mbedtls_ecp_point_init(&P);
            /* Скаляр X25519 обязан быть ПРИВЕДЁН: младшие три бита сняты, старший снят,
             * предстарший установлен (RFC 7748 §5). Без этого mbedtls отвечает
             * MBEDTLS_ERR_ECP_INVALID_KEY (-0x4C80) — на этом первая версия пробы и споткнулась,
             * приняв свою ошибку за несовместимость библиотеки. */
            unsigned char sc[32];
            for (size_t i = 0; i < sizeof(sc); i++) sc[i] = (unsigned char)(i + 1);
            sc[0] &= 248;
            sc[31] &= 127;
            sc[31] |= 64;
            int r = mbedtls_mpi_read_binary_le(&s, sc, sizeof(sc));
            r |= mbedtls_ecp_mul(&grp, &P, &s, &grp.G, probe_rng, NULL);
            if (r) printf("    ecp_mul вернул %d\n", r);
            unsigned char x[32];
            r |= mbedtls_mpi_write_binary_le(&P.MBEDTLS_PRIVATE(X), x, sizeof(x));
            ok("X25519: умножение на базовой точке прошло", r == 0);
            mbedtls_mpi_free(&s);
            mbedtls_ecp_point_free(&P);
        }
        mbedtls_ecp_group_free(&grp);
    }

    printf(fails ? "\nПРОВАЛОВ: %d\n" : "\nвсё сошлось\n", fails);
    return fails ? 1 : 0;
}
