/* Рукопожатие Reality.
 *
 * Что тут происходит и почему именно так.
 *
 * Обычный TLS доказывает подлинность сервера сертификатом. Reality не может: сертификат,
 * который пришлёт сервер, принадлежит настоящему чужому сайту (ads.x5.ru), потому что
 * сервер этот сайт и проксирует всем, кто не предъявил доказательства. Значит проверять
 * цепочку бессмысленно, а подлинность доказывается иначе:
 *
 *   1. у сервера есть постоянная пара X25519; публичная половина известна клиенту (pbk);
 *   2. клиент генерирует свою эфемерную пару и кладёт публичную половину в key_share
 *      ClientHello — ровно туда, где она была бы в настоящем TLS 1.3;
 *   3. из своего приватного и серверного pbk клиент считает общий секрет, и на его
 *      основе — короткий аутентификатор, который прячет в 32 байта session_id;
 *   4. сервер видит session_id, считает тот же секрет своим приватным ключом и сверяет.
 *      Совпало — обслуживает VLESS. Не совпало — проксирует на настоящий сайт.
 *
 * Отсюда два следствия, которые определяют весь код ниже:
 *
 * ClientHello должен быть НЕОТЛИЧИМ от браузерного. Не «похож» — именно неотличим по
 * набору и порядку расширений, списку шифров, GREASE-значениям. Любое отклонение делает
 * нас нетипичным клиентом, и это само по себе признак, даже если аутентификатор верен.
 * Поэтому Hello собирается здесь вручную, а не библиотекой: mbedtls прислал бы свой
 * порядок расширений, который на браузер не похож.
 *
 * И: неудача выглядит как успех. Сервер не отвечает ошибкой — он отдаёт настоящий сайт.
 * Проверить «получилось ли» можно только по тому, отвечает ли туннель VLESS дальше.
 */
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>
#include <errno.h>
#include <sys/random.h>
#include <stdlib.h>

#include "mbedtls/ecdh.h"
#include "mbedtls/ecp.h"
#include "mbedtls/hkdf.h"
#include "mbedtls/sha256.h"
#include "mbedtls/aes.h"
#include "mbedtls/gcm.h"

#include "reality.h"

/* base64url без выравнивания — в таком виде pbk приходит в ссылке. */
static int b64url_decode(const char *in, unsigned char *out, size_t out_n) {
    static const char *A = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
    size_t o = 0;
    int acc = 0, bits = 0;
    for (const char *p = in; *p; p++) {
        const char *q = strchr(A, *p);
        if (!q) {
            if (*p == '=' || *p == '\n' || *p == '\r') continue;
            /* Ссылки иногда несут стандартный алфавит вместо url-safe. */
            if (*p == '+') q = A + 62;
            else if (*p == '/') q = A + 63;
            else return -1;
        }
        acc = (acc << 6) | (int)(q - A);
        bits += 6;
        if (bits >= 8) {
            bits -= 8;
            if (o >= out_n) return -1;
            out[o++] = (unsigned char)((acc >> bits) & 0xFF);
        }
    }
    return (int)o;
}

static int hex_decode(const char *in, unsigned char *out, size_t out_n) {
    size_t o = 0;
    for (const char *p = in; p[0] && p[1]; p += 2) {
        if (o >= out_n) return -1;
        int hi = p[0] <= '9' ? p[0] - '0' : (p[0] | 32) - 'a' + 10;
        int lo = p[1] <= '9' ? p[1] - '0' : (p[1] | 32) - 'a' + 10;
        if (hi < 0 || hi > 15 || lo < 0 || lo > 15) return -1;
        out[o++] = (unsigned char)((hi << 4) | lo);
    }
    return (int)o;
}

/* Случайные байты берём прямо у ядра. Своего DRBG здесь не нужно: getrandom(2) — это то,
 * из чего его всё равно пришлось бы сидировать, а лишний слой добавил бы код и место для
 * ошибки в том единственном месте, где ошибка не обнаруживается тестом. */
static int fill_random(unsigned char *buf, size_t n) {
    size_t got = 0;
    while (got < n) {
        ssize_t r = getrandom(buf + got, n - got, 0);
        if (r < 0) {
            if (errno == EINTR) continue;
            return -1;
        }
        got += (size_t)r;
    }
    return 0;
}

/* Обёртка в форме, которую ждёт mbedtls. Нужна не для красоты: ecp_mul ТРЕБУЕТ источник
 * случайности и отказывается работать с NULL, потому что использует его для ослепления —
 * рандомизации промежуточных значений, без которой время операции выдаёт биты приватного
 * ключа. Первая версия передавала NULL и получала -20352 (ECP_BAD_INPUT_DATA); соблазн
 * «обойти» это своей реализацией умножения был бы ровно тем случаем, когда код работает,
 * а защита тихо не работает. */
static int rng_cb(void *ctx, unsigned char *out, size_t n) {
    (void)ctx;
    return fill_random(out, n) == 0 ? 0 : MBEDTLS_ERR_ECP_RANDOM_FAILED;
}

/* ---- X25519 --------------------------------------------------------------- */
/* Через mbedtls ECP: своя реализация тут была бы худшим решением в проекте. */
static int x25519_keypair(unsigned char priv[32], unsigned char pub[32]) {
    mbedtls_ecp_group grp;
    mbedtls_mpi d;
    mbedtls_ecp_point Q;
    mbedtls_ecp_group_init(&grp);
    mbedtls_mpi_init(&d);
    mbedtls_ecp_point_init(&Q);
    int rc = -1;

    if (mbedtls_ecp_group_load(&grp, MBEDTLS_ECP_DP_CURVE25519) != 0) goto out;
    if (fill_random(priv, 32) != 0) goto out;
    /* Ограничения X25519 на скаляр: снять три младших бита, снять старший, поставить
     * второй по старшинству. Без этого ключ выходит за подгруппу, и общий секрет не
     * совпадёт с посчитанным сервером. */
    priv[0] &= 248;
    priv[31] &= 127;
    priv[31] |= 64;

    /* mbedtls хранит скаляр как big-endian mpi, а X25519 — little-endian байты. */
    unsigned char be[32];
    for (int i = 0; i < 32; i++) be[i] = priv[31 - i];
    if (mbedtls_mpi_read_binary(&d, be, 32) != 0) goto out;

    if (mbedtls_ecp_mul(&grp, &Q, &d, &grp.G, rng_cb, NULL) != 0) goto out;
    if (mbedtls_mpi_write_binary_le(&Q.MBEDTLS_PRIVATE(X), pub, 32) != 0) goto out;
    rc = 0;
out:
    mbedtls_ecp_group_free(&grp);
    mbedtls_mpi_free(&d);
    mbedtls_ecp_point_free(&Q);
    return rc;
}

int x25519_shared_ext(const unsigned char priv[32], const unsigned char peer[32],
                      unsigned char out[32]);

static int x25519_shared(const unsigned char priv[32], const unsigned char peer[32],
                         unsigned char out[32]) {
    mbedtls_ecp_group grp;
    mbedtls_mpi d, z;
    mbedtls_ecp_point P;
    mbedtls_ecp_group_init(&grp);
    mbedtls_mpi_init(&d);
    mbedtls_mpi_init(&z);
    mbedtls_ecp_point_init(&P);
    int rc = -1;

    if (mbedtls_ecp_group_load(&grp, MBEDTLS_ECP_DP_CURVE25519) != 0) goto out;
    unsigned char be[32];
    for (int i = 0; i < 32; i++) be[i] = priv[31 - i];
    if (mbedtls_mpi_read_binary(&d, be, 32) != 0) goto out;
    if (mbedtls_mpi_read_binary_le(&P.MBEDTLS_PRIVATE(X), peer, 32) != 0) goto out;
    if (mbedtls_mpi_lset(&P.MBEDTLS_PRIVATE(Z), 1) != 0) goto out;

    if (mbedtls_ecp_mul(&grp, &P, &d, &P, rng_cb, NULL) != 0) goto out;
    if (mbedtls_mpi_write_binary_le(&P.MBEDTLS_PRIVATE(X), out, 32) != 0) goto out;
    rc = 0;
out:
    mbedtls_ecp_group_free(&grp);
    mbedtls_mpi_free(&d);
    mbedtls_mpi_free(&z);
    mbedtls_ecp_point_free(&P);
    return rc;
}

/* ---- сборка ClientHello --------------------------------------------------- */
/* Пишем байты вручную. Порядок расширений повторяет Chrome, потому что весь смысл
 * Reality в том, чтобы Hello не отличался от браузерного; библиотечный Hello выдал бы
 * нас порядком, даже будь аутентификатор верен. */
struct buf {
    unsigned char *p;
    size_t len, cap;
};

static void put(struct buf *b, const void *d, size_t n) {
    if (b->len + n > b->cap) { b->len = b->cap + 1; return; }   /* переполнение видно снаружи */
    memcpy(b->p + b->len, d, n);
    b->len += n;
}
static void put8(struct buf *b, unsigned v) { unsigned char c = (unsigned char)v; put(b, &c, 1); }
static void put16(struct buf *b, unsigned v) { unsigned char c[2] = { (unsigned char)(v >> 8), (unsigned char)v }; put(b, c, 2); }

/* Расширение: тип, длина, тело. */
static void ext(struct buf *b, unsigned type, const void *body, size_t n) {
    put16(b, type);
    put16(b, (unsigned)n);
    put(b, body, n);
}

/* GREASE (RFC 8701) пока не используется: состав Hello повторяет openssl, а он GREASE
 * не посылает. Функция удалена вместе с ним — мёртвый код в файле, который отвечает за
 * маскировку, хуже отсутствующего: он выглядит как реализованная возможность.
 *
 * Вернуть придётся вместе с точным отпечатком Chrome, где GREASE обязателен. */

int reality_build_hello(const struct reality_cfg *cfg, struct reality_state *st,
                        unsigned char *out, size_t out_n, size_t *out_len) {
    unsigned char pbk[32], sid[16];
    int pbk_n = b64url_decode(cfg->pbk, pbk, sizeof(pbk));
    if (pbk_n != 32) return REALITY_EBADKEY;
    int sid_n = cfg->sid[0] ? hex_decode(cfg->sid, sid, sizeof(sid)) : 0;
    if (sid_n < 0) return REALITY_EBADKEY;

    if (x25519_keypair(st->priv, st->pub) != 0) return REALITY_ECRYPTO;
    if (x25519_shared(st->priv, pbk, st->shared) != 0) return REALITY_ECRYPTO;

    /* Аутентификатор считается ПОСЛЕ сборки Hello — см. ниже, где он вписывается на
     * место. Причина: он подписывает весь ClientHello целиком, поэтому раньше его
     * посчитать нечем. Здесь только заготовка: 16 значимых байт и 16 нулей под тег. */
    unsigned char sess[32] = {0};
    /* Версия клиента Reality — из core.Version_{x,y,z} Xray. Сервер её не проверяет
     * строго, но она входит в подписываемые 16 байт, так что должна быть осмысленной. */
    sess[0] = 26; sess[1] = 7; sess[2] = 28; sess[3] = 0;
    uint32_t now = (uint32_t)time(NULL);
    sess[4] = (unsigned char)(now >> 24);
    sess[5] = (unsigned char)(now >> 16);
    sess[6] = (unsigned char)(now >> 8);
    sess[7] = (unsigned char)now;
    if (sid_n > 0) memcpy(sess + 8, sid, (size_t)(sid_n > 8 ? 8 : sid_n));
    memcpy(st->session_id, sess, 32);

    /* ---- собственно Hello ---- */
    struct buf b = { out, 0, out_n };
    unsigned char rnd[32];
    if (fill_random(rnd, sizeof(rnd)) != 0) return REALITY_ECRYPTO;

    /* record header заполним в конце: длина известна только тогда */
    size_t rec_at = b.len;
    put8(&b, 0x16);            /* handshake */
    /* Версия записи 0x0301 — так делает и openssl (проверено перехватом его Hello
     * против этого же сервера), и браузеры. Я успел «исправить» это на 0x0303 в поисках
     * decode_error и вернул обратно: правка верного кода — цена того, что я гадал
     * вместо сравнения с рабочим клиентом. */
    put16(&b, 0x0301);
    size_t rec_len_at = b.len;
    put16(&b, 0);

    size_t hs_at = b.len;
    put8(&b, 0x01);            /* ClientHello */
    size_t hs_len_at = b.len;
    put8(&b, 0); put16(&b, 0); /* 24-битная длина */

    put16(&b, 0x0303);         /* legacy_version TLS 1.2 — так требует 1.3 */
    put(&b, rnd, 32);
    put8(&b, 32);
    put(&b, st->session_id, 32);

    /* Шифры Chrome, в его порядке, с GREASE первым. */
    /* Только наборы на SHA-256. AES_256_GCM_SHA384 (0x1302) НЕ предлагается сознательно:
     * его расписание ключей идёт целиком на SHA-384, то есть все секреты по 48 байт
     * вместо 32. Пока tls13.c написан под SHA-256, предлагать его означало бы получить
     * рабочее рукопожатие и нерасшифровываемый поток — именно это и произошло: сервер
     * выбрал 0x1302, ключи вывелись от другого хеша, AEAD не сошёлся.
     *
     * Предлагать только то, что умеешь обработать, честнее, чем поддерживать наполовину.
     * Поддержка SHA-384 — отдельная работа: параметризовать длину хеша во всём
     * расписании, а не подменить одну функцию. */
    static const unsigned suites[] = { 0x1303, 0x1301, 0x00FF };
    put16(&b, (unsigned)(sizeof(suites) / sizeof(suites[0])) * 2);
    for (size_t i = 0; i < sizeof(suites) / sizeof(suites[0]); i++) put16(&b, suites[i]);

    put8(&b, 1); put8(&b, 0);  /* compression: null */

    size_t exts_len_at = b.len;
    put16(&b, 0);
    size_t exts_at = b.len;

    /* Состав и ПОРЯДОК расширений повторяют openssl, чей Hello этот сервер принимает
     * (перехвачен и проверен: ответ 1448 байт с ServerHello). Своя версия «как у Chrome
     * по памяти» получала alert 50 decode_error, и найти причину перебором полей не
     * удалось — потому что причина была не в одном поле, а в составе целиком.
     *
     * Это компромисс, и он назван честно: openssl отличим от браузера, то есть
     * маскировка слабее, чем у настоящего Chrome. Но рабочее соединение с посредственной
     * маскировкой полезнее неработающего с идеальной, а точный отпечаток Chrome — это
     * отдельная задача с эталонными дампами, а не то, что угадывается. */

    /* server_name: список(2) + тип(1) + длина(2) + имя. */
    {
        size_t sni_len = strlen(cfg->sni);
        unsigned char sni[300];
        struct buf sb = { sni, 0, sizeof(sni) };
        put16(&sb, (unsigned)(sni_len + 3));
        put8(&sb, 0);
        put16(&sb, (unsigned)sni_len);
        put(&sb, cfg->sni, sni_len);
        ext(&b, 0x0000, sni, sb.len);
    }

    /* ec_point_formats: три формата, как у openssl. */
    ext(&b, 0x000B, "\x03\x00\x01\x02", 4);

    /* supported_groups: X25519 первым, затем то, что предлагает openssl. */
    { unsigned char g2[24]; struct buf sb = { g2, 0, sizeof(g2) };
      put16(&sb, 20);
      put16(&sb, 0x001D); put16(&sb, 0x0017); put16(&sb, 0x001E);
      put16(&sb, 0x0019); put16(&sb, 0x0018);
      put16(&sb, 0x0100); put16(&sb, 0x0101); put16(&sb, 0x0102);
      put16(&sb, 0x0103); put16(&sb, 0x0104);
      ext(&b, 0x000A, g2, sb.len); }

    ext(&b, 0x0023, NULL, 0);              /* session_ticket */
    ext(&b, 0x0016, NULL, 0);              /* encrypt_then_mac */
    ext(&b, 0x0017, NULL, 0);              /* extended_master_secret */

    /* signature_algorithms: набор openssl, он этому серверу подходит наверняка. */
    { static const unsigned sigs[] = { 0x0403, 0x0503, 0x0603, 0x0807, 0x0808,
                                      0x0809, 0x080a, 0x080b, 0x0804, 0x0805,
                                      0x0806, 0x0401, 0x0501, 0x0601 };
      unsigned char s[64]; struct buf sb = { s, 0, sizeof(s) };
      put16(&sb, (unsigned)(sizeof(sigs)/sizeof(sigs[0])) * 2);
      for (size_t i = 0; i < sizeof(sigs)/sizeof(sigs[0]); i++) put16(&sb, sigs[i]);
      ext(&b, 0x000D, s, sb.len); }

    ext(&b, 0x002B, "\x02\x03\x04", 3);    /* supported_versions: TLS 1.3 */
    ext(&b, 0x002D, "\x01\x01", 2);        /* psk_key_exchange_modes */

    /* key_share: здесь едет наша публичная половина — то, из чего сервер выведет тот же
     * общий секрет, что и мы. Последним, как у openssl. */
    { unsigned char k[80]; struct buf sb = { k, 0, sizeof(k) };
      put16(&sb, 36);
      put16(&sb, 0x001D); put16(&sb, 32); put(&sb, st->pub, 32);
      ext(&b, 0x0033, k, sb.len); }

    if (b.len > b.cap) return REALITY_ETOOBIG;

    /* Обратная засыпка длин. */
    size_t exts_len = b.len - exts_at;
    out[exts_len_at] = (unsigned char)(exts_len >> 8);
    out[exts_len_at + 1] = (unsigned char)exts_len;
    size_t hs_len = b.len - hs_at - 4;
    out[hs_len_at] = (unsigned char)(hs_len >> 16);
    out[hs_len_at + 1] = (unsigned char)(hs_len >> 8);
    out[hs_len_at + 2] = (unsigned char)hs_len;
    size_t rec_len = b.len - rec_at - 5;
    out[rec_len_at] = (unsigned char)(rec_len >> 8);
    out[rec_len_at + 1] = (unsigned char)rec_len;

    *out_len = b.len;

    /* ---- аутентификатор Reality ------------------------------------------------
     *
     * Формат взят из реализации Xray, а не выведен из общих соображений — угадать его
     * нельзя, и моя первая догадка (соль = SNI, nonce = свой pub, пустой AAD) давала
     * рукопожатие, после которого сервер отвечал маскировочным сайтом.
     *
     *   ключ   = HKDF-SHA256(ikm = ECDH(наш приватный, pbk сервера),
     *                        salt = Random[0..20), info = "REALITY")
     *   nonce  = Random[20..32)
     *   данные = первые 16 байт session_id (версия, время, short id)
     *   AAD    = ВЕСЬ ClientHello как handshake-сообщение, с нулями на месте тега
     *
     * AAD и есть причина, по которой это делается здесь: пока Hello не собран, подписывать
     * нечего. Сервер повторит тот же расчёт своим приватным ключом и сверит тег — так он и
     * отличает нас от постороннего, не отвечая при этом ничего отличимого. */
    {
        const unsigned char *raw = out + 5;              /* handshake без заголовка записи */
        const unsigned char *random = raw + 4 + 2;       /* после type+len24+version */
        unsigned char *sid_at = out + 5 + 4 + 2 + 32 + 1;

        /* AAD — это Hello с НУЛЯМИ на месте session_id: Xray обнуляет его до подписи
         * (`copy(hello.Raw[39:], hello.SessionId)` при пустом SessionId), и сервер
         * повторяет расчёт так же. С заполненным session_id в AAD тег не сходится, и
         * сервер молча отвечает маскировочным сайтом — то есть ошибка неотличима от
         * неверного ключа. Смещение 39 в Xray и наше совпадают: 4+2+32+1 = 39. */
        /* Открытый текст — 16 значимых байт session_id. Сохраняем их ДО обнуления:
         * mbedtls шифрует на месте, а обнуление нужно только в AAD.
         *
         * Первая версия обнуляла sid_at перед вызовом и подписывала нули вместо версии,
         * времени и short id. Сервер, естественно, не признавал такую подпись — и, как
         * всегда с Reality, отвечал маскировочным сайтом, то есть ошибка выглядела как
         * неверный ключ. Нашлось только сверкой C с независимой реализацией на Python:
         * их подписи не расшифровывались одним ключом, хотя X25519 у обоих совпадал. */
        unsigned char plain[16];
        memcpy(plain, sid_at, 16);

        /* AAD — Hello с НУЛЯМИ на месте session_id: Xray обнуляет его до подписи
         * (`copy(hello.Raw[39:], hello.SessionId)` при ещё пустом SessionId), и сервер
         * повторяет расчёт так же. Копируем Hello, чтобы обнулить в копии: сам Hello
         * должен уехать серверу с подписью, а не с нулями. */
        static unsigned char aad[4096];
        size_t aad_n = b.len - 5;
        if (aad_n > sizeof(aad)) return REALITY_ETOOBIG;
        memcpy(aad, raw, aad_n);
        memset(aad + (4 + 2 + 32 + 1), 0, 32);

        unsigned char authkey[32];
        const mbedtls_md_info_t *md = mbedtls_md_info_from_type(MBEDTLS_MD_SHA256);
        if (!md) return REALITY_ECRYPTO;
        if (mbedtls_hkdf(md, random, 20, st->shared, 32,
                         (const unsigned char *)"REALITY", 7, authkey, 32) != 0)
            return REALITY_ECRYPTO;

        unsigned char tag[16];
        mbedtls_gcm_context gcm;
        mbedtls_gcm_init(&gcm);
        int crc = mbedtls_gcm_setkey(&gcm, MBEDTLS_CIPHER_ID_AES, authkey, 256);
        if (crc == 0)
            crc = mbedtls_gcm_crypt_and_tag(&gcm, MBEDTLS_GCM_ENCRYPT, 16,
                                            random + 20, 12,
                                            aad, aad_n,
                                            plain, sid_at, 16, tag);
        mbedtls_gcm_free(&gcm);
        if (crc != 0) return REALITY_ECRYPTO;
        memcpy(sid_at + 16, tag, 16);
        memcpy(st->session_id, sid_at, 32);
    }
    return 0;
}

/* Тот же обмен, доступный из tls13.c: там нужен секрет с эфемерным ключом сервера из
 * ServerHello, тогда как reality.c считает секрет с его постоянным ключом. Две разные
 * величины, один и тот же примитив. */
int x25519_shared_ext(const unsigned char priv[32], const unsigned char peer[32],
                      unsigned char out[32]) {
    return x25519_shared(priv, peer, out);
}
