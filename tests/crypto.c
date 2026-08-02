/* Проверка криптографии Reality против известных векторов.
 *
 * Зачем отдельный тест, а не проверка «на живом сервере»: ошибка в X25519 не выглядит
 * как ошибка. Сервер Reality на неверный аутентификатор не отвечает отказом — он молча
 * проксирует на настоящий сайт, то есть соединение устанавливается, страница открывается,
 * и всё выглядит рабочим, пока не заметишь, что трафик идёт мимо туннеля. Единственный
 * способ поймать это до развёртывания — сверить примитивы с векторами RFC.
 *
 * Реально найденные этим тестом ошибки:
 *   1. mbedtls_ecp_mul с NULL вместо RNG -> -20352: он использует случайность для
 *      ослепления, без которого время операции выдаёт биты приватного ключа;
 *   2. неприжатый скаляр -> -19584 INVALID_KEY: X25519 требует снять три младших бита,
 *      снять старший и поставить второй по старшинству, иначе ключ вне подгруппы и
 *      секрет не совпадёт с серверным.
 */
#include <stdio.h>
#include <string.h>
#include "mbedtls/ecp.h"
#include "mbedtls/hkdf.h"
#include "mbedtls/md.h"

static int fails = 0;

static void check(const char *what, int ok) {
    printf("%-46s %s\n", what, ok ? "ok" : "ПРОВАЛ");
    if (!ok) fails++;
}

/* Детерминированный «RNG»: тест обязан давать один результат при каждом прогоне, иначе
 * его провал невозможно воспроизвести. Для ослепления этого достаточно — оно влияет на
 * время выполнения, а не на результат. */
static int rng(void *c, unsigned char *o, size_t n) {
    (void)c;
    for (size_t i = 0; i < n; i++) o[i] = (unsigned char)(i * 7 + 1);
    return 0;
}

static int x25519(const unsigned char priv[32], const unsigned char peer[32],
                  unsigned char out[32]) {
    mbedtls_ecp_group g;
    mbedtls_mpi d;
    mbedtls_ecp_point P;
    mbedtls_ecp_group_init(&g);
    mbedtls_mpi_init(&d);
    mbedtls_ecp_point_init(&P);
    int rc = -1;
    unsigned char cl[32], be[32];

    if (mbedtls_ecp_group_load(&g, MBEDTLS_ECP_DP_CURVE25519)) goto out;
    memcpy(cl, priv, 32);
    cl[0] &= 248; cl[31] &= 127; cl[31] |= 64;
    for (int i = 0; i < 32; i++) be[i] = cl[31 - i];
    if (mbedtls_mpi_read_binary(&d, be, 32)) goto out;
    if (mbedtls_mpi_read_binary_le(&P.MBEDTLS_PRIVATE(X), peer, 32)) goto out;
    if (mbedtls_mpi_lset(&P.MBEDTLS_PRIVATE(Z), 1)) goto out;
    if (mbedtls_ecp_mul(&g, &P, &d, &P, rng, NULL)) goto out;
    if (mbedtls_mpi_write_binary_le(&P.MBEDTLS_PRIVATE(X), out, 32)) goto out;
    rc = 0;
out:
    mbedtls_ecp_group_free(&g);
    mbedtls_mpi_free(&d);
    mbedtls_ecp_point_free(&P);
    return rc;
}

int main(void) {
    /* RFC 7748 §6.1 — обмен Alice/Bob. */
    static const unsigned char a_priv[32] = {
        0x77,0x07,0x6d,0x0a,0x73,0x18,0xa5,0x7d,0x3c,0x16,0xc1,0x72,0x51,0xb2,0x66,0x45,
        0xdf,0x4c,0x2f,0x87,0xeb,0xc0,0x99,0x2a,0xb1,0x77,0xfb,0xa5,0x1d,0xb9,0x2c,0x2a };
    static const unsigned char b_pub[32] = {
        0xde,0x9e,0xdb,0x7d,0x7b,0x7d,0xc1,0xb4,0xd3,0x5b,0x61,0xc2,0xec,0xe4,0x35,0x37,
        0x3f,0x83,0x43,0xc8,0x5b,0x78,0x67,0x4d,0xad,0xfc,0x7e,0x14,0x6f,0x88,0x2b,0x4f };
    static const unsigned char want[32] = {
        0x4a,0x5d,0x9d,0x5b,0xa4,0xce,0x2d,0xe1,0x72,0x8e,0x3b,0xf4,0x80,0x35,0x0f,0x25,
        0xe0,0x7e,0x21,0xc9,0x47,0xd1,0x9e,0x33,0x76,0xf0,0x9b,0x3c,0x1e,0x16,0x17,0x42 };

    unsigned char got[32];
    check("X25519 совпадает с вектором RFC 7748",
          x25519(a_priv, b_pub, got) == 0 && memcmp(got, want, 32) == 0);

    /* Тот же обмен с другой стороны обязан дать тот же секрет — иначе клиент и сервер
     * посчитают разное, а выглядеть это будет как «сервер отдаёт чужой сайт». */
    static const unsigned char b_priv[32] = {
        0x5d,0xab,0x08,0x7e,0x62,0x4a,0x8a,0x4b,0x79,0xe1,0x7f,0x8b,0x83,0x80,0x0e,0xe6,
        0x6f,0x3b,0xb1,0x29,0x26,0x18,0xb6,0xfd,0x1c,0x2f,0x8b,0x27,0xff,0x88,0xe0,0xeb };
    static const unsigned char a_pub[32] = {
        0x85,0x20,0xf0,0x09,0x89,0x30,0xa7,0x54,0x74,0x8b,0x7d,0xdc,0xb4,0x3e,0xf7,0x5a,
        0x0d,0xbf,0x3a,0x0d,0x26,0x38,0x1a,0xf4,0xeb,0xa4,0xa9,0x8e,0xaa,0x9b,0x4e,0x6a };
    unsigned char got2[32];
    check("обмен симметричен (та же пара с другой стороны)",
          x25519(b_priv, a_pub, got2) == 0 && memcmp(got2, want, 32) == 0);

    /* HKDF-SHA256, RFC 5869 §A.1: на нём выводится ключ аутентификатора. */
    {
        unsigned char ikm[22], salt[13], info[10], out[42];
        memset(ikm, 0x0b, sizeof(ikm));
        for (unsigned i = 0; i < sizeof(salt); i++) salt[i] = (unsigned char)i;
        for (unsigned i = 0; i < sizeof(info); i++) info[i] = (unsigned char)(0xf0 + i);
        static const unsigned char okm[42] = {
            0x3c,0xb2,0x5f,0x25,0xfa,0xac,0xd5,0x7a,0x90,0x43,0x4f,0x64,0xd0,0x36,0x2f,0x2a,
            0x2d,0x2d,0x0a,0x90,0xcf,0x1a,0x5a,0x4c,0x5d,0xb0,0x2d,0x56,0xec,0xc4,0xc5,0xbf,
            0x34,0x00,0x72,0x08,0xd5,0xb8,0x87,0x18,0x58,0x65 };
        const mbedtls_md_info_t *md = mbedtls_md_info_from_type(MBEDTLS_MD_SHA256);
        int rc = mbedtls_hkdf(md, salt, sizeof(salt), ikm, sizeof(ikm),
                              info, sizeof(info), out, sizeof(out));
        check("HKDF-SHA256 совпадает с вектором RFC 5869",
              rc == 0 && memcmp(out, okm, sizeof(okm)) == 0);
    }

    /* Прижатие скаляра обязательно: mbedtls отвергает неприжатый ключ, и без этого
     * первая версия падала с INVALID_KEY. Проверяем, что прижатие идемпотентно —
     * повторное применение не меняет ключ, то есть его можно делать где угодно. */
    {
        unsigned char k[32];
        for (int i = 0; i < 32; i++) k[i] = (unsigned char)(i * 11 + 3);
        unsigned char once[32], twice[32];
        memcpy(once, k, 32);
        once[0] &= 248; once[31] &= 127; once[31] |= 64;
        memcpy(twice, once, 32);
        twice[0] &= 248; twice[31] &= 127; twice[31] |= 64;
        check("прижатие скаляра идемпотентно", memcmp(once, twice, 32) == 0);
    }

    printf("\n%s\n", fails ? "ЕСТЬ ПРОВАЛЫ" : "все векторы совпали");
    return fails != 0;
}
