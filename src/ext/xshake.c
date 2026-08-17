/* xsteer: рукопожатие Noise IK внутри ClientHello. Раскладка полей и доводы — в xshake.h. */
#define _GNU_SOURCE
#include <stdio.h>
#include <string.h>
#include <time.h>

#include "mbedtls/hkdf.h"
#include "mbedtls/md.h"
#include "mbedtls/sha256.h"

#include "xshake.h"
#include "xswire.h"
#include "chello.h"
#include "reality.h"

/* Имя протокола Noise. Для ChaCha оно ровно 32 символа, то есть h инициализируется без
 * хеширования — приятная мелочь, обещанная спецификацией Noise. Для AES-GCM короче, и тогда
 * оно добивается нулями (тоже по спецификации). Имена РАЗНЫЕ у разных шифров нарочно: это
 * привязка транскрипта к согласованному AEAD, без которой посредник, переписавший порядок
 * наборов в Hello, остался бы незамеченным. */
#define NOISE_NAME_CHACHA "Noise_IK_25519_ChaChaPoly_SHA256"
#define NOISE_NAME_AES    "Noise_IK_25519_AESGCM_SHA256"
/* Пролог: версия формата. Разные версии не должны давать сходящиеся транскрипты — иначе
 * будущая правка формата выглядела бы как «ключи не те», а не как «другая версия». */
#define NOISE_PROLOGUE "xsteer/1"

/* Длины на проводе. Собраны здесь, потому что обе стороны обязаны считать одинаково, а
 * «посчитаю на месте» — это два места, где можно ошибиться по-разному. */
#define XS_ENC_STATIC   (32 + 16)   /* статический ключ пира под es */
#define XS_ENC_EMPTY    16          /* пустая нагрузка: только тег */
#define XS_ECH_USED     (XS_ENC_STATIC + XS_ENC_EMPTY)   /* 64 из 176 байт набивки */
#define XS_SID_PLAIN    16          /* открытая часть аутентификатора */
#define XS_FIN_PLAIN    37          /* транскрипт(32) + версия(1) + запас(4) */
#define XS_FIN_BODY     (XS_FIN_PLAIN + XS_TAG)          /* 53 */
#define XS_FIN_REC      (XS_REC_HDR + XS_FIN_BODY)       /* 58 — как у настоящего Finished */
/* Ответ хаба целиком обязан влезть в ОДИН сегмент: транспорт датаграммный, и разрезать
 * поток рукопожатия значило бы завести пересборку там, где её больше нигде нет. Отсюда и
 * скромный размер фальшивого «сертификата». */
#define XS_CERT_MIN     600
#define XS_CERT_MAX     1100

/* ---- Noise: транскрипт и цепочка ключей ------------------------------------ */

static void mix_hash(struct xs_hs *hs, const uint8_t *data, size_t n) {
    mbedtls_sha256_context c;
    mbedtls_sha256_init(&c);
    mbedtls_sha256_starts(&c, 0);
    mbedtls_sha256_update(&c, hs->h, 32);
    mbedtls_sha256_update(&c, data, n);
    mbedtls_sha256_finish(&c, hs->h);
    mbedtls_sha256_free(&c);
}

/* MixKey(ikm) = HKDF(ck, ikm, 2): ck' и k одним расширением на 64 байта.
 *
 * Совпадение с определением Noise точное, и именно поэтому здесь нет своего HMAC:
 * HKDF-Expand(prk, "", 64) даёт T1 || T2, где T1 = HMAC(prk, 0x01) и T2 = HMAC(prk, T1||0x02)
 * — буква в букву цепочка Noise. Стенд tests/xscrypto.c сверяет это с независимым
 * подсчётом, потому что «должно совпадать» и «совпадает» — разные утверждения. */
static int mix_key(struct xs_hs *hs, const uint8_t *ikm, size_t ikm_n) {
    const mbedtls_md_info_t *md = mbedtls_md_info_from_type(MBEDTLS_MD_SHA256);
    if (!md) return XS_ECRYPTO;
    uint8_t prk[32], out[64];
    if (mbedtls_hkdf_extract(md, hs->ck, 32, ikm, ikm_n, prk) != 0) return XS_ECRYPTO;
    if (mbedtls_hkdf_expand(md, prk, 32, NULL, 0, out, sizeof(out)) != 0) return XS_ECRYPTO;
    memcpy(hs->ck, out, 32);
    memcpy(hs->k, out + 32, 32);
    /* Контекст шифра разворачивается заново на каждый шаг: ключ сменился, а держать старый
     * означало бы шифровать не тем. Это единственное место, где setkey зовётся часто, — но
     * шагов в рукопожатии четыре, а не на каждый пакет (см. tls13.h про цену setkey). */
    tls13_keys_free(&hs->hk);
    memset(&hs->hk, 0, sizeof(hs->hk));
    hs->hk.aead = hs->aead;
    hs->hk.key_n = hs->aead == TLS13_AEAD_AES128 ? 16 : 32;
    memcpy(hs->hk.key, hs->k, hs->hk.key_n);
    /* iv нулевой: nonce в Noise — это счётчик шага, а он на каждом шаге начинается заново,
     * потому что ключ на каждом шаге новый. Ноль здесь не «забыли заполнить», а ровно то,
     * что предписывает Noise. */
    memset(hs->hk.iv, 0, sizeof(hs->hk.iv));
    return tls13_keys_setup(&hs->hk) == 0 ? 0 : XS_ECRYPTO;
}

/* Зашифровать и вобрать в транскрипт. AAD — текущий h, как требует Noise. */
static int encrypt_and_hash(struct xs_hs *hs, const uint8_t *plain, size_t n, uint8_t *out) {
    if (n) memcpy(out, plain, n);
    if (tls13_aead_seal(&hs->hk, 0, hs->h, 32, out, n, out + n) != 0) return XS_ECRYPTO;
    mix_hash(hs, out, n + XS_TAG);
    return 0;
}

/* Расшифровать и вобрать в транскрипт. Шифротекст копируется до расшифровки: она идёт на
 * месте, а в транскрипт входят именно ПРИСЛАННЫЕ байты — иначе стороны получат разные h и
 * разойдутся на следующем же шаге. */
static int decrypt_and_hash(struct xs_hs *hs, const uint8_t *ct, size_t ct_n, uint8_t *plain) {
    if (ct_n < XS_TAG) return XS_EFORMAT;
    size_t n = ct_n - XS_TAG;
    uint8_t tmp[256];
    if (ct_n > sizeof(tmp)) return XS_EFORMAT;
    memcpy(tmp, ct, ct_n);
    if (tls13_aead_open(&hs->hk, 0, hs->h, 32, tmp, ct_n) != 0) return XS_EAUTH;
    if (n && plain) memcpy(plain, tmp, n);
    mix_hash(hs, ct, ct_n);
    return 0;
}

/* Split: транспортные ключи. Восемьдесят восемь байт одним расширением — ключ и iv на
 * каждое направление. Направления названы от инициатора: i2r и r2i. */
static int split_keys(struct xs_hs *hs, struct tls13_keys *i2r, struct tls13_keys *r2i) {
    const mbedtls_md_info_t *md = mbedtls_md_info_from_type(MBEDTLS_MD_SHA256);
    if (!md) return XS_ECRYPTO;
    uint8_t prk[32], out[88];
    if (mbedtls_hkdf_extract(md, hs->ck, 32, (const uint8_t *)"", 0, prk) != 0) return XS_ECRYPTO;
    if (mbedtls_hkdf_expand(md, prk, 32, (const uint8_t *)"xsteer split", 12,
                            out, sizeof(out)) != 0) return XS_ECRYPTO;
    size_t kn = hs->aead == TLS13_AEAD_AES128 ? 16 : 32;
    memset(i2r, 0, sizeof(*i2r));
    memset(r2i, 0, sizeof(*r2i));
    i2r->aead = r2i->aead = hs->aead;
    i2r->key_n = r2i->key_n = kn;
    memcpy(i2r->key, out, kn);
    memcpy(i2r->iv, out + 32, 12);
    memcpy(r2i->key, out + 44, kn);
    memcpy(r2i->iv, out + 76, 12);
    if (tls13_keys_setup(i2r) != 0 || tls13_keys_setup(r2i) != 0) return XS_ECRYPTO;
    /* Ключ шага рукопожатия больше не нужен: Split — его последнее применение. Освобождаем
     * ЗДЕСЬ, а не оставляем вызывающему: контекст AES лежит в куче, а рукопожатий за час
     * работы хаба проходят тысячи, и «вызывающий не забудет» — не то свойство, на которое
     * стоит опираться. Санитайзер на стенде xsloop показал ровно эту утечку. */
    tls13_keys_free(&hs->hk);
    memset(&hs->hk, 0, sizeof(hs->hk));
    return 0;
}

static int hs_begin(struct xs_hs *hs, enum tls13_aead aead, const uint8_t rs[32]) {
    memset(hs, 0, sizeof(*hs));
    hs->aead = aead;
    memcpy(hs->rs, rs, 32);
    const char *name = aead == TLS13_AEAD_AES128 ? NOISE_NAME_AES : NOISE_NAME_CHACHA;
    size_t nl = strlen(name);
    if (nl == 32) memcpy(hs->h, name, 32);
    else {
        /* Короче 32 — добить нулями, как предписывает Noise; длиннее — хешировать. */
        memset(hs->h, 0, 32);
        memcpy(hs->h, name, nl < 32 ? nl : 32);
    }
    memcpy(hs->ck, hs->h, 32);
    mix_hash(hs, (const uint8_t *)NOISE_PROLOGUE, strlen(NOISE_PROLOGUE));
    /* IK: статический публичный ключ отвечающего известен инициатору заранее и входит в
     * транскрипт как предварительное сообщение. Именно это связывает рукопожатие с
     * КОНКРЕТНЫМ хабом: тот же Hello, отправленный другому, не сойдётся. */
    mix_hash(hs, hs->rs, 32);
    return 0;
}

void xs_hs_wipe(struct xs_hs *hs) {
    tls13_keys_free(&hs->hk);
    volatile uint8_t *p = (volatile uint8_t *)hs;
    for (size_t i = 0; i < sizeof(*hs); i++) p[i] = 0;
}

enum tls13_aead xs_aead_for_cpu(void) {
    return xc_cpu_has_aes() ? TLS13_AEAD_AES128 : TLS13_AEAD_CHACHA;
}

static enum tls13_aead aead_from_suite(uint16_t suite) {
    /* 0x1301 — AES-128-GCM, 0x1303 — ChaCha20-Poly1305. Остальные наборы TLS 1.3 нам не
     * нужны: AES-256 стоит дороже без выигрыша здесь, а CCM на роутере медленнее обоих. */
    if (suite == 0x1301) return TLS13_AEAD_AES128;
    return TLS13_AEAD_CHACHA;
}

/* ---- полезная нагрузка ------------------------------------------------------ */

static void payload_pack(const struct xs_payload *p, uint8_t out[XS_SID_PLAIN]) {
    out[0] = p->ver;
    out[1] = p->flags;
    out[2] = (uint8_t)(p->mtu >> 8);
    out[3] = (uint8_t)(p->mtu & 0xFF);
    for (int i = 0; i < 8; i++) out[4 + i] = (uint8_t)(p->stamp >> (8 * (7 - i)));
    /* Четыре байта запаса — случайные, а не нулевые: постоянные нули в подписанном блоке
     * дали бы наблюдателю известный открытый текст в фиксированном месте. */
    xc_random(out + 12, 4);
}

static void payload_unpack(const uint8_t in[XS_SID_PLAIN], struct xs_payload *p) {
    p->ver = in[0];
    p->flags = in[1];
    p->mtu = (uint16_t)((in[2] << 8) | in[3]);
    p->stamp = 0;
    for (int i = 0; i < 8; i++) p->stamp = (p->stamp << 8) | in[4 + i];
}

/* Ключ аутентификатора session_id: отдельный, выведенный из цепочки. Отдельный потому, что
 * этой же операцией шифруется полезная нагрузка Noise, и переиспользовать ключ с тем же
 * нулевым nonce означало бы повтор пары «ключ, nonce» — то есть полную потерю защиты. */
static int auth_key(const struct xs_hs *hs, struct tls13_keys *k) {
    const mbedtls_md_info_t *md = mbedtls_md_info_from_type(MBEDTLS_MD_SHA256);
    if (!md) return XS_ECRYPTO;
    uint8_t prk[32], out[44];
    if (mbedtls_hkdf_extract(md, hs->ck, 32, (const uint8_t *)"", 0, prk) != 0) return XS_ECRYPTO;
    if (mbedtls_hkdf_expand(md, prk, 32, (const uint8_t *)"xsteer auth", 11,
                            out, sizeof(out)) != 0) return XS_ECRYPTO;
    memset(k, 0, sizeof(*k));
    k->aead = hs->aead;
    k->key_n = hs->aead == TLS13_AEAD_AES128 ? 16 : 32;
    memcpy(k->key, out, k->key_n);
    memcpy(k->iv, out + 32, 12);
    return tls13_keys_setup(k) == 0 ? 0 : XS_ECRYPTO;
}

/* ---- пир: сборка ClientHello --------------------------------------------- */

/* Контекст для обратных вызовов носителя (см. reality.h). */
struct carry_ctx {
    struct xs_hs *hs;
    const uint8_t *our_static;      /* 32 байта: наш публичный статический */
    const uint8_t *our_priv;        /* 32 байта: наш приватный статический — для ss */
    struct xs_payload pay;
    int rc;
};

/* Первый обратный вызов: набивка ECH. Здесь делается ВСЯ работа msg1 по Noise, потому что
 * ровно здесь впервые есть общий секрет es и ещё не собран Hello. */
static int carry_ech(void *ctx, unsigned char *ech, size_t ech_n,
                     const unsigned char shared[32]) {
    struct carry_ctx *c = ctx;
    struct xs_hs *hs = c->hs;
    if (ech_n < XS_ECH_USED) { c->rc = XS_ESMALL; return -1; }

    mix_hash(hs, hs->e_pub, 32);                       /* e */
    if ((c->rc = mix_key(hs, shared, 32)) != 0) return -1;      /* es */
    if ((c->rc = encrypt_and_hash(hs, c->our_static, 32, ech)) != 0) return -1;   /* s */
    uint8_t ss[32];
    if (x25519_shared_ext(c->our_priv, hs->rs, ss) != 0) { c->rc = XS_ECRYPTO; return -1; }
    if ((c->rc = mix_key(hs, ss, 32)) != 0) return -1;          /* ss */
    memset(ss, 0, sizeof(ss));
    /* Пустая нагрузка: один тег. Всё содержательное (версия, MTU, время) едет в
     * аутентификаторе session_id — он и так подписывает весь Hello, значит второй экземпляр
     * тех же полей был бы лишними байтами. */
    if ((c->rc = encrypt_and_hash(hs, NULL, 0, ech + XS_ENC_STATIC)) != 0) return -1;
    /* Остаток набивки — случайный, как у браузера без настроенного ECH. Шифротекст от шума
     * неотличим, поэтому граница между нашими 64 байтами и шумом снаружи не видна. */
    if (xc_random(ech + XS_ECH_USED, ech_n - XS_ECH_USED) != 0) { c->rc = XS_ECRYPTO; return -1; }
    return 0;
}

/* Второй обратный вызов: аутентификатор в session_id, подписывающий ВЕСЬ Hello. */
static int carry_sid(void *ctx, unsigned char sid[32],
                     const unsigned char *hsmsg, size_t hsmsg_n,
                     const unsigned char shared[32]) {
    (void)shared;
    struct carry_ctx *c = ctx;
    struct tls13_keys ak;
    if ((c->rc = auth_key(c->hs, &ak)) != 0) return -1;
    uint8_t plain[XS_SID_PLAIN];
    payload_pack(&c->pay, plain);
    memcpy(sid, plain, XS_SID_PLAIN);
    int rc = tls13_aead_seal(&ak, 0, hsmsg, hsmsg_n, sid, XS_SID_PLAIN, sid + XS_SID_PLAIN);
    tls13_keys_free(&ak);
    if (rc != 0) { c->rc = XS_ECRYPTO; return -1; }
    return 0;
}

/* base64url публичного ключа: в таком виде reality.c ждёт постоянный ключ сервера. */
static void b64url(const uint8_t in[32], char out[44]) {
    static const char A[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
    int o = 0;
    for (int i = 0; i < 30; i += 3) {
        uint32_t v = ((uint32_t)in[i] << 16) | ((uint32_t)in[i + 1] << 8) | in[i + 2];
        out[o++] = A[(v >> 18) & 63];
        out[o++] = A[(v >> 12) & 63];
        out[o++] = A[(v >> 6) & 63];
        out[o++] = A[v & 63];
    }
    uint32_t v = ((uint32_t)in[30] << 16) | ((uint32_t)in[31] << 8);
    out[o++] = A[(v >> 18) & 63];
    out[o++] = A[(v >> 12) & 63];
    out[o++] = A[(v >> 6) & 63];
    out[o] = '\0';                                  /* без выравнивания '=' — как в ссылке */
}

static int xs_hs_client_hello_impl(struct xs_hs *hs, const struct xs_secrets *sec,
                       const uint8_t hub_pub[32], const char *sni, int mtu, int conn_id,
                       uint8_t *out, size_t cap, size_t *out_n) {
    enum tls13_aead aead = xs_aead_for_cpu();
    hs_begin(hs, aead, hub_pub);
    hs->role_init = 1;
    if (xc_x25519_keypair(hs->e_priv, hs->e_pub) != 0) return XS_ECRYPTO;

    /* Публичная половина нашего СТАТИЧЕСКОГО ключа выводится из приватного, а не хранится
     * рядом с ним: два значения, выведенных одно из другого, обязаны считаться. */
    uint8_t our_pub[32];
    if (xc_x25519_public(sec->priv, our_pub) != 0) return XS_ECRYPTO;
    memcpy(hs->s_priv, sec->priv, 32);

    struct carry_ctx cc;
    memset(&cc, 0, sizeof(cc));
    cc.hs = hs;
    cc.our_static = our_pub;
    cc.our_priv = sec->priv;
    cc.pay.ver = XS_PROTO_VER;
    cc.pay.flags = (uint8_t)(conn_id & 0x07);
    cc.pay.mtu = (uint16_t)mtu;
    cc.pay.stamp = (uint64_t)time(NULL);

    char pbk[44];
    b64url(hub_pub, pbk);
    struct reality_cfg cfg = { .sni = sni && sni[0] ? sni : "www.microsoft.com",
                               .pbk = pbk, .sid = "", .fp = "chrome", .alpn = "h2" };
    struct reality_carrier car = { .priv = hs->e_priv, .pub = hs->e_pub,
                                   .fill_ech = carry_ech, .fill_sid = carry_sid, .ctx = &cc };
    struct reality_state st;
    size_t n = 0;
    int rc = reality_build_hello_carry(&cfg, &st, &car, out, cap, &n);
    if (rc != 0) return cc.rc ? cc.rc : XS_ECRYPTO;

    /* Транскрипт вбирает ГОТОВОЕ сообщение рукопожатия — вместе с настоящим session_id и
     * вместе со всей формой Hello. Значит подмена любого байта конверта (порядка наборов
     * шифров, расширений, SNI) сломает подтверждение, а не пройдёт незамеченной. */
    struct chello_ref ref;
    if (chello_parse(out, n, &ref) != 0) return XS_EFORMAT;
    memcpy(hs->sid, out + ref.sid_off, 32);
    mix_hash(hs, out + ref.hs_off, ref.hs_n);
    *out_n = n;
    return 0;
}

/* ---- хаб: разбор ClientHello ------------------------------------------------ */

static int xs_hs_server_read_impl(struct xs_hs *hs, const struct xs_secrets *sec,
                      const uint8_t *rec, size_t n, uint8_t peer_static[32]) {
    struct chello_ref ref;
    if (chello_parse(rec, n, &ref) != 0) return XS_EFORMAT;
    if (!ref.ech_off || ref.ech_n < XS_ECH_USED) return XS_EFORMAT;
    if (!ref.suite) return XS_EFORMAT;

    uint8_t our_pub[32];
    if (xc_x25519_public(sec->priv, our_pub) != 0) return XS_ECRYPTO;
    hs_begin(hs, aead_from_suite(ref.suite), our_pub);
    memcpy(hs->s_priv, sec->priv, 32);
    hs->role_init = 0;
    memcpy(hs->e_pub, rec + ref.ks_off, 32);

    /* es считается НАШИМ статическим и ЕГО эфемерным — то же значение, что у него. */
    uint8_t es[32];
    if (x25519_shared_ext(sec->priv, hs->e_pub, es) != 0) return XS_ECRYPTO;

    mix_hash(hs, hs->e_pub, 32);
    int rc = mix_key(hs, es, 32);
    memset(es, 0, sizeof(es));
    if (rc != 0) return rc;

    /* Личность инициатора приезжает зашифрованной — расшифровываем и только потом ищем её в
     * таблице пиров. Явного индекса на проводе нет намеренно (см. xshake.h). */
    if ((rc = decrypt_and_hash(hs, rec + ref.ech_off, XS_ENC_STATIC, peer_static)) != 0)
        return rc;
    uint8_t ss[32];
    if (x25519_shared_ext(sec->priv, peer_static, ss) != 0) return XS_ECRYPTO;
    rc = mix_key(hs, ss, 32);
    memset(ss, 0, sizeof(ss));
    if (rc != 0) return rc;
    if ((rc = decrypt_and_hash(hs, rec + ref.ech_off + XS_ENC_STATIC, XS_ENC_EMPTY, NULL)) != 0)
        return rc;

    /* Аутентификатор session_id: по нему же читаются версия, MTU и метка времени. Считается
     * над сообщением рукопожатия с ОБНУЛЁННЫМ session_id — теми самыми байтами, что
     * подписывала пир. */
    static __thread uint8_t aad[4096];
    if (ref.hs_n > sizeof(aad)) return XS_EFORMAT;
    memcpy(aad, rec + ref.hs_off, ref.hs_n);
    memset(aad + (4 + 2 + 32 + 1), 0, 32);
    struct tls13_keys ak;
    if ((rc = auth_key(hs, &ak)) != 0) return rc;
    uint8_t sid[32];
    memcpy(sid, rec + ref.sid_off, 32);
    rc = tls13_aead_open(&ak, 0, aad, ref.hs_n, sid, 32);
    tls13_keys_free(&ak);
    if (rc != 0) return XS_EAUTH;
    payload_unpack(sid, &hs->peer);
    if (hs->peer.ver != XS_PROTO_VER) return XS_EVERSION;

    memcpy(hs->sid, rec + ref.sid_off, 32);
    mix_hash(hs, rec + ref.hs_off, ref.hs_n);
    /* Личность пира нужна ещё раз — на шаге se при сборке ответа. */
    memcpy(hs->peer_static, peer_static, 32);
    return 0;
}

/* ---- хаб: ответный поток ---------------------------------------------------- */

/* ServerHello с эхом session_id и нашим эфемерным ключом. Эхо — обязанность настоящего
 * сервера TLS 1.3, и оно бесплатно; отсутствие эха было бы отличием от всякого настоящего
 * сервера в первом же ответе. */
static size_t build_server_hello(const struct xs_hs *hs, uint16_t suite,
                                 const uint8_t sid[32], uint8_t *out) {
    size_t o = 0;
    out[o++] = 0x16; out[o++] = 0x03; out[o++] = 0x03;
    size_t rec_len_at = o; o += 2;
    size_t hs_at = o;
    out[o++] = 0x02;
    size_t hs_len_at = o; o += 3;
    out[o++] = 0x03; out[o++] = 0x03;
    xc_random(out + o, 32); o += 32;
    out[o++] = 32;
    memcpy(out + o, sid, 32); o += 32;
    out[o++] = (uint8_t)(suite >> 8); out[o++] = (uint8_t)(suite & 0xFF);
    out[o++] = 0x00;                                   /* без сжатия */
    size_t ext_len_at = o; o += 2;
    /* supported_versions: 1.3 */
    out[o++] = 0x00; out[o++] = 0x2B; out[o++] = 0x00; out[o++] = 0x02;
    out[o++] = 0x03; out[o++] = 0x04;
    /* key_share: x25519 и наш эфемерный ключ */
    out[o++] = 0x00; out[o++] = 0x33; out[o++] = 0x00; out[o++] = 0x24;
    out[o++] = 0x00; out[o++] = 0x1D; out[o++] = 0x00; out[o++] = 0x20;
    memcpy(out + o, hs->e_pub, 32); o += 32;
    size_t ext_n = o - ext_len_at - 2;
    out[ext_len_at] = (uint8_t)(ext_n >> 8);
    out[ext_len_at + 1] = (uint8_t)(ext_n & 0xFF);
    size_t hs_n = o - hs_at - 4;
    out[hs_len_at] = 0;
    out[hs_len_at + 1] = (uint8_t)(hs_n >> 8);
    out[hs_len_at + 2] = (uint8_t)(hs_n & 0xFF);
    size_t rec_n = o - rec_len_at - 2;
    out[rec_len_at] = (uint8_t)(rec_n >> 8);
    out[rec_len_at + 1] = (uint8_t)(rec_n & 0xFF);
    return o;
}

static int xs_hs_server_write_impl(struct xs_hs *hs, int mtu, uint8_t *out, size_t cap, size_t *out_n,
                       struct tls13_keys *tx, struct tls13_keys *rx) {
    if (cap < 2048) return XS_ESMALL;
    uint16_t suite = hs->aead == TLS13_AEAD_AES128 ? 0x1301 : 0x1303;
    /* ПОРЯДОК ЗДЕСЬ ВАЖЕН И НЕОЧЕВИДЕН. В hs->e_pub сейчас лежит эфемерный ключ ПИРЫ,
     * прочитанный из её Hello, и он нужен для ee. Своя пара генерируется только после того,
     * как чужой ключ сохранён: первая версия этого кода генерировала пару сразу и затирала
     * его, после чего ee у сторон не совпадал — то есть рукопожатие «проходило» и разъезжалось
     * на подтверждении. */
    uint8_t peer_e[32];
    memcpy(peer_e, hs->e_pub, 32);
    if (xc_x25519_keypair(hs->e_priv, hs->e_pub) != 0) return XS_ECRYPTO;

    size_t o = build_server_hello(hs, suite, hs->sid, out);
    /* Транскрипт вбирает ВСЁ сообщение ServerHello, а не только ключ: так подмена любого
     * поля ответа (набора шифров, версии) ломает подтверждение. */
    mix_hash(hs, out + 5, o - 5);

    uint8_t ee[32], se[32];
    if (x25519_shared_ext(hs->e_priv, peer_e, ee) != 0) return XS_ECRYPTO;
    int rc = mix_key(hs, ee, 32);
    memset(ee, 0, sizeof(ee));
    if (rc != 0) return rc;
    /* se: наш эфемерный и СТАТИЧЕСКИЙ инициатора. Именно этот шаг аутентифицирует пир —
     * без него любой, кто перехватил её Hello, мог бы выдать себя за неё. */
    if (x25519_shared_ext(hs->e_priv, hs->peer_static, se) != 0) return XS_ECRYPTO;
    rc = mix_key(hs, se, 32);
    memset(se, 0, sizeof(se));
    if (rc != 0) return rc;

    /* Фальшивый ChangeCipherSpec: настоящий TLS 1.3 его посылает ради посредников, и его
     * отсутствие было бы отличием. Шесть байт. */
    out[o++] = 0x14; out[o++] = 0x03; out[o++] = 0x03; out[o++] = 0x00; out[o++] = 0x01;
    out[o++] = 0x01;

    /* Запись формы «Certificate»: наша нагрузка плюс случайная набивка правдоподобной
     * длины. Длина СЛУЧАЙНАЯ, потому что постоянная сама стала бы отпечатком; и она
     * невелика, потому что весь ответ обязан влезть в один сегмент. Набивка входит в
     * транскрипт, поэтому её подмена ломает подтверждение, а не проходит молча. */
    uint8_t rnd[2];
    xc_random(rnd, 2);
    size_t pad = XS_CERT_MIN + (((size_t)rnd[0] << 8 | rnd[1]) % (XS_CERT_MAX - XS_CERT_MIN));
    size_t body = XS_SID_PLAIN + XS_TAG + pad;
    if (o + XS_REC_HDR + body + XS_FIN_REC > cap) return XS_ESMALL;
    out[o++] = 0x17; out[o++] = 0x03; out[o++] = 0x03;
    out[o++] = (uint8_t)(body >> 8); out[o++] = (uint8_t)(body & 0xFF);
    struct xs_payload mine = { XS_PROTO_VER, 0, (uint16_t)mtu, (uint64_t)time(NULL) };
    uint8_t plain[XS_SID_PLAIN];
    payload_pack(&mine, plain);
    if ((rc = encrypt_and_hash(hs, plain, XS_SID_PLAIN, out + o)) != 0) return rc;
    o += XS_SID_PLAIN + XS_TAG;
    if (xc_random(out + o, pad) != 0) return XS_ECRYPTO;
    mix_hash(hs, out + o, pad);
    o += pad;

    if ((rc = split_keys(hs, rx, tx)) != 0) return rc;   /* у хаба rx — от пира, tx — к ней */

    /* Подтверждение под транспортным ключом и НУЛЕВЫМ nonce. Ноль свободен по построению:
     * записи данных выводят nonce из смещения в потоке, а оно начинается с единицы. */
    uint8_t fin[XS_FIN_PLAIN];
    memcpy(fin, hs->h, 32);
    fin[32] = XS_PROTO_VER;
    memset(fin + 33, 0, 4);
    out[o++] = 0x17; out[o++] = 0x03; out[o++] = 0x03;
    out[o++] = (uint8_t)(XS_FIN_BODY >> 8); out[o++] = (uint8_t)(XS_FIN_BODY & 0xFF);
    memcpy(out + o, fin, XS_FIN_PLAIN);
    if (tls13_aead_seal(tx, 0, hs->h, 32, out + o, XS_FIN_PLAIN, out + o + XS_FIN_PLAIN) != 0)
        return XS_ECRYPTO;
    o += XS_FIN_BODY;
    *out_n = o;
    return 0;
}

/* ---- пир: разбор ответа --------------------------------------------------- */

static int xs_hs_client_finish_impl(struct xs_hs *hs, const uint8_t *in, size_t n,
                        struct tls13_keys *tx, struct tls13_keys *rx, size_t *consumed) {
    size_t i = 0;
    /* ServerHello */
    if (n < 5 || in[0] != 0x16) return XS_EFORMAT;
    size_t sh_len = ((size_t)in[3] << 8) | in[4];
    if (n < 5 + sh_len) return XS_EFORMAT;
    /* Разбираем ровно то, что нам нужно: эхо session_id и ключ обмена. Всё остальное в
     * ServerHello нам безразлично, но входит в транскрипт целиком. */
    const uint8_t *sh = in + 5;
    if (sh_len < 4 + 2 + 32 + 1 + 32 + 2 + 1 + 2) return XS_EFORMAT;
    if (sh[0] != 0x02) return XS_EFORMAT;
    if (sh[4 + 2 + 32] != 32) return XS_EFORMAT;
    if (memcmp(sh + 4 + 2 + 32 + 1, hs->sid, 32) != 0) return XS_EAUTH;
    uint16_t suite = (uint16_t)((sh[4 + 2 + 32 + 1 + 32] << 8) | sh[4 + 2 + 32 + 1 + 32 + 1]);
    if (aead_from_suite(suite) != hs->aead) return XS_EFORMAT;
    /* Ключ обмена ищем разбором расширений: их порядок задаёт сервер. */
    size_t p = 4 + 2 + 32 + 1 + 32 + 2 + 1;
    size_t ext_n = ((size_t)sh[p] << 8) | sh[p + 1];
    p += 2;
    if (p + ext_n > sh_len) return XS_EFORMAT;
    const uint8_t *peer_e = NULL;
    size_t e = p;
    while (e + 4 <= p + ext_n) {
        uint16_t t = (uint16_t)((sh[e] << 8) | sh[e + 1]);
        size_t l = ((size_t)sh[e + 2] << 8) | sh[e + 3];
        if (e + 4 + l > p + ext_n) return XS_EFORMAT;
        if (t == 0x0033 && l == 36 && sh[e + 4] == 0x00 && sh[e + 5] == 0x1D)
            peer_e = sh + e + 8;
        e += 4 + l;
    }
    if (!peer_e) return XS_EFORMAT;

    mix_hash(hs, sh, sh_len);
    uint8_t ee[32], se[32];
    if (x25519_shared_ext(hs->e_priv, peer_e, ee) != 0) return XS_ECRYPTO;
    int rc = mix_key(hs, ee, 32);
    memset(ee, 0, sizeof(ee));
    if (rc != 0) return rc;
    /* se со стороны пира: его СТАТИЧЕСКИЙ и эфемерный сервера. */
    if (x25519_shared_ext(hs->s_priv, peer_e, se) != 0) return XS_ECRYPTO;
    rc = mix_key(hs, se, 32);
    memset(se, 0, sizeof(se));
    if (rc != 0) return rc;
    i = 5 + sh_len;

    /* ChangeCipherSpec — пропускаем, он фальшивый у обеих сторон. */
    if (i + 6 <= n && in[i] == 0x14) i += 6;

    /* Запись формы «Certificate»: наша нагрузка в начале, дальше набивка. */
    if (i + XS_REC_HDR > n || in[i] != 0x17) return XS_EFORMAT;
    size_t clen = ((size_t)in[i + 3] << 8) | in[i + 4];
    if (i + XS_REC_HDR + clen > n) return XS_EFORMAT;
    if (clen < XS_SID_PLAIN + XS_TAG) return XS_EFORMAT;
    const uint8_t *cbody = in + i + XS_REC_HDR;
    uint8_t plain[XS_SID_PLAIN];
    if ((rc = decrypt_and_hash(hs, cbody, XS_SID_PLAIN + XS_TAG, plain)) != 0) return rc;
    payload_unpack(plain, &hs->peer);
    if (hs->peer.ver != XS_PROTO_VER) return XS_EVERSION;
    mix_hash(hs, cbody + XS_SID_PLAIN + XS_TAG, clen - XS_SID_PLAIN - XS_TAG);
    i += XS_REC_HDR + clen;

    if ((rc = split_keys(hs, tx, rx)) != 0) return rc;   /* у пира tx — к хабу */

    /* Подтверждение хаба. Проверяется не только тегом, но и равенством транскрипта: тег без
     * этого сказал бы «не сошлось», а равенство говорит «не сошлось ИМЕННО здесь». Тот же
     * урок, что стоит в tls13.c кодом TLS13_EFINISHED. */
    if (i + XS_FIN_REC > n || in[i] != 0x17) return XS_EFORMAT;
    size_t flen = ((size_t)in[i + 3] << 8) | in[i + 4];
    if (flen != XS_FIN_BODY || i + XS_REC_HDR + flen > n) return XS_EFORMAT;
    uint8_t fin[XS_FIN_BODY];
    memcpy(fin, in + i + XS_REC_HDR, flen);
    if (tls13_aead_open(rx, 0, hs->h, 32, fin, flen) != 0) return XS_EAUTH;
    if (memcmp(fin, hs->h, 32) != 0) return XS_EAUTH;
    i += XS_REC_HDR + flen;

    *consumed = i;
    return 0;
}

int xs_hs_client_confirm(struct xs_hs *hs, struct tls13_keys *tx,
                         uint8_t *out, size_t cap, size_t *out_n) {
    if (cap < XS_FIN_REC) return XS_ESMALL;
    out[0] = 0x17; out[1] = 0x03; out[2] = 0x03;
    out[3] = (uint8_t)(XS_FIN_BODY >> 8);
    out[4] = (uint8_t)(XS_FIN_BODY & 0xFF);
    memcpy(out + XS_REC_HDR, hs->h, 32);
    out[XS_REC_HDR + 32] = XS_PROTO_VER;
    memset(out + XS_REC_HDR + 33, 0, 4);
    if (tls13_aead_seal(tx, 0, hs->h, 32, out + XS_REC_HDR, XS_FIN_PLAIN,
                        out + XS_REC_HDR + XS_FIN_PLAIN) != 0)
        return XS_ECRYPTO;
    *out_n = XS_FIN_REC;
    return 0;
}

int xs_hs_server_confirm(struct xs_hs *hs, struct tls13_keys *rx,
                         const uint8_t *in, size_t n, size_t *consumed) {
    if (n < XS_FIN_REC || in[0] != 0x17) return XS_EFORMAT;
    size_t flen = ((size_t)in[3] << 8) | in[4];
    if (flen != XS_FIN_BODY || XS_REC_HDR + flen > n) return XS_EFORMAT;
    uint8_t fin[XS_FIN_BODY];
    memcpy(fin, in + XS_REC_HDR, flen);
    if (tls13_aead_open(rx, 0, hs->h, 32, fin, flen) != 0) return XS_EAUTH;
    if (memcmp(fin, hs->h, 32) != 0) return XS_EAUTH;
    *consumed = XS_REC_HDR + flen;
    return 0;
}

size_t xs_hs_alert(uint8_t *out, size_t cap) {
    /* fatal handshake_failure: 15 03 03 00 02 02 28. Так отвечает настоящий сервер TLS,
     * которому предложили то, чего он не может. От активного зондирования это не спасает
     * (см. docs/xsteer.md), но молчание было бы отличимо ещё сильнее. */
    static const uint8_t A[] = { 0x15, 0x03, 0x03, 0x00, 0x02, 0x02, 0x28 };
    if (cap < sizeof(A)) return 0;
    memcpy(out, A, sizeof(A));
    return sizeof(A);
}

/* ---- обёртки, прибирающие за отказом ---------------------------------------
 *
 * ЗАЧЕМ ОНИ ЕСТЬ. Каждый шаг Noise разворачивает контекст шифра, а контекст AES внутри GCM
 * лежит в КУЧЕ. Значит рукопожатие, прерванное на середине, оставляет выделенную память —
 * и это не мелочь: на публичном порту хаба живут сканеры, каждый их пакет доходит хотя бы
 * до первого шага, и «вызывающий не забудет освободить» означало бы рост памяти от чужого
 * трафика, то есть отказ в обслуживании одной строкой невнимательности.
 *
 * Санитайзер на стенде xsloop показал ровно эту утечку. Лечится не дисциплиной вызывающего,
 * а тем, что промахнуться нельзя: наружу выходят обёртки, и при любом ненулевом ответе
 * состояние уже чистое. Контракт для вызывающего простой — при отказе трогать состояние не
 * нужно, при успехе оно живёт до Split, а после Split ключ шага освобождает сам split_keys. */
static int hs_cleanup(struct xs_hs *hs, int rc) {
    if (rc != 0) {
        tls13_keys_free(&hs->hk);
        memset(&hs->hk, 0, sizeof(hs->hk));
    }
    return rc;
}

int xs_hs_client_hello(struct xs_hs *hs, const struct xs_secrets *sec,
                       const uint8_t hub_pub[32], const char *sni, int mtu, int conn_id,
                       uint8_t *out, size_t cap, size_t *out_n) {
    return hs_cleanup(hs, xs_hs_client_hello_impl(hs, sec, hub_pub, sni, mtu, conn_id,
                                                  out, cap, out_n));
}

int xs_hs_server_read(struct xs_hs *hs, const struct xs_secrets *sec,
                      const uint8_t *rec, size_t n, uint8_t peer_static[32]) {
    return hs_cleanup(hs, xs_hs_server_read_impl(hs, sec, rec, n, peer_static));
}

int xs_hs_server_write(struct xs_hs *hs, int mtu, uint8_t *out, size_t cap, size_t *out_n,
                       struct tls13_keys *tx, struct tls13_keys *rx) {
    return hs_cleanup(hs, xs_hs_server_write_impl(hs, mtu, out, cap, out_n, tx, rx));
}

int xs_hs_client_finish(struct xs_hs *hs, const uint8_t *in, size_t n,
                        struct tls13_keys *tx, struct tls13_keys *rx, size_t *consumed) {
    return hs_cleanup(hs, xs_hs_client_finish_impl(hs, in, n, tx, rx, consumed));
}
