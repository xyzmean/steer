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
#if defined(__aarch64__)
#include <sys/auxv.h>
#endif

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

/* Есть ли у процессора инструкции AES.
 *
 * От этого зависит порядок шифров в ClientHello, и оба варианта — браузерные: Chrome
 * задаёт тот же вопрос (EVP_has_aes_hardware) и так же меняет порядок. Так что здесь мы не
 * выбираем «что нам удобнее», а повторяем поведение браузера на этом железе.
 *
 * Спрашиваем ядро через AT_HWCAP, а не пробуем инструкцию: инструкция, которой нет, даёт
 * SIGILL, а ловить его в статическом бинарнике на роутере — худшая из идей. На MIPS
 * вопроса нет вовсе: там таких инструкций не бывает.
 *
 * STEER_CIPHER=aes|chacha переопределяет ответ. Нужно, чтобы «стало быстрее от смены
 * шифра» можно было перепроверить на месте, а не поверить на слово. */
static int cpu_has_aes(void) {
    const char *env = getenv("STEER_CIPHER");
    if (env && !strcmp(env, "aes")) return 1;
    if (env && !strcmp(env, "chacha")) return 0;
#if defined(__x86_64__) || defined(__i386__)
    unsigned a = 1, b = 0, c = 0, d = 0;
    __asm__ volatile("cpuid" : "=a"(a), "=b"(b), "=c"(c), "=d"(d) : "a"(1), "c"(0));
    return (c & (1u << 25)) != 0;                 /* AESNI */
#elif defined(__aarch64__)
    return (getauxval(AT_HWCAP) & (1ul << 3)) != 0;      /* HWCAP_AES */
#else
    /* Всё остальное — включая 32-битный ARM с расширениями криптографии. Вопрос здесь не
     * «есть ли инструкции у процессора», а «воспользуется ли ими НАША сборка»: путь
     * MBEDTLS_AESCE_C существует только для aarch64 (см. mbedtls_config.h). На armv7 с
     * crypto extensions AES у нас всё равно табличный, то есть медленный, и объявлять его
     * предпочтительным означало бы выбрать заведомо худший шифр. */
    return 0;
#endif
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

    /* Значения GREASE (RFC 8701) — по одному на каждое место, где Chrome их ставит, и
     * СВОИ на каждое соединение. Постоянные значения сами стали бы отпечатком: именно
     * непредсказуемость здесь и есть смысл GREASE.
     *
     * Значения — это 0x0a0a + n*0x1010, то есть шестнадцать вариантов от 0x0a0a до 0xfafa.
     * Два типа расширений обязаны отличаться друг от друга: одинаковые дали бы расширение,
     * повторённое дважды, чего в TLS быть не может. */
    unsigned char gr[5];
    if (fill_random(gr, sizeof(gr)) != 0) return REALITY_ECRYPTO;
    unsigned g_cipher  = 0x0A0Au + (unsigned)(gr[0] & 15) * 0x1010u;
    unsigned g_group   = 0x0A0Au + (unsigned)(gr[1] & 15) * 0x1010u;
    unsigned g_version = 0x0A0Au + (unsigned)(gr[2] & 15) * 0x1010u;
    unsigned g_ext_a   = 0x0A0Au + (unsigned)(gr[3] & 15) * 0x1010u;
    unsigned g_ext_b   = 0x0A0Au + (unsigned)((gr[4] & 15) ^ (((gr[4] & 15) == (gr[3] & 15)) ? 1 : 0)) * 0x1010u;

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

    /* Наборы шифров Chrome, в его порядке, с GREASE первым. Сверено с перехватом.
     *
     * 0x1302 (AES_256_GCM_SHA384) в списке есть, хотя tls13.c умеет только SHA-256. Это не
     * оплошность: список обязан совпадать с браузерным, иначе весь смысл Reality теряется, —
     * а выбирает набор сервер, и сервер здесь Go. crypto/tls перебирает СВОЙ порядок
     * предпочтений (AES_128_GCM_SHA256, CHACHA20, AES_256_GCM_SHA384) и берёт первый, который
     * предложил клиент, то есть 0x1301; без аппаратного AES — 0x1303. Оба мы умеем.
     *
     * Если сервер всё-таки выберет 0x1302, рукопожатие честно упадёт с TLS13_EBADSUITE, а не
     * даст нерасшифровываемый поток: раньше именно так и было, и выглядело это как рабочее
     * соединение без данных. Поддержка SHA-384 — отдельная работа: параметризовать длину
     * хеша во всём расписании ключей, а не подменить одну функцию. */
    static const unsigned suites_aes[] = {
        0x1301, 0x1302, 0x1303, 0xC02B, 0xC02F, 0xC02C, 0xC030,
        0xCCA9, 0xCCA8, 0xC013, 0xC014, 0x009C, 0x009D, 0x002F, 0x0035,
    };
    /* Тот же список в порядке BoringSSL для процессора БЕЗ инструкций AES: ChaCha20
     * поднята выше AES-GCM и в 1.3, и в 1.2. Ровно это делает Chrome (EVP_has_aes_hardware
     * в ssl_cipher.cc), поэтому отпечаток остаётся браузерным — меняется не состав, а
     * порядок, и меняется он так же, как у настоящего Chrome на таком же процессоре.
     *
     * Зачем: сервер Reality — это Go, а crypto/tls смотрит на НАШ порядок. Функция
     * aesgcmPreferred() спрашивает, стоит ли AES-GCM первым в списке клиента, и если нет,
     * берёт список предпочтений defaultCipherSuitesTLS13NoAES, то есть ChaCha20.
     *
     * Зачем это нужно, числами, на роутере с MIPS 24Kc: AES-128-GCM 1,7 МБ/с против
     * 11,6 МБ/с у ChaCha20-Poly1305 — в шесть раз. Туннель отдавал 1,2 МБ/с, проводя 91%
     * времени в расшифровке, то есть упирался ровно в этот потолок. Полоса канала при этом
     * была 48 Мбит/с. Ни один другой предел близко не стоял. */
    static const unsigned suites_chacha[] = {
        0x1303, 0x1301, 0x1302, 0xCCA9, 0xCCA8, 0xC02B, 0xC02F, 0xC02C, 0xC030,
        0xC013, 0xC014, 0x009C, 0x009D, 0x002F, 0x0035,
    };
    const unsigned *suites = cpu_has_aes() ? suites_aes : suites_chacha;
    size_t nsuites = sizeof(suites_aes) / sizeof(suites_aes[0]);
    put16(&b, (unsigned)(nsuites + 1) * 2);
    put16(&b, g_cipher);
    for (size_t i = 0; i < nsuites; i++) put16(&b, suites[i]);

    put8(&b, 1); put8(&b, 0);  /* compression: null */

    size_t exts_len_at = b.len;
    put16(&b, 0);
    size_t exts_at = b.len;

    /* Состав, содержимое и порядок расширений повторяют Chrome, сверенные с перехватом
     * его Hello до этого же сервера (tests/hello-diff.py).
     *
     * Почему это важно настолько. Аутентификатор Reality подписывает ClientHello ЦЕЛИКОМ,
     * а весь смысл Reality — быть неотличимым от браузера. Прежняя версия повторяла openssl:
     * 3 набора шифров вместо 16, 10 расширений вместо 18, ни одного GREASE, без ECH и ALPN,
     * зато с encrypt_then_mac, которого браузер не посылает. Работало это до тех пор, пока
     * сервер не стал разборчивее — а потом перестало на всех 26 узлах подписки сразу, при
     * рабочем sing-box на том же узле и тех же ключах (0 успехов из 10 против 7 из 10).
     *
     * Симптом при этом ничего не подсказывал: рукопожатие проходит целиком, серверный
     * Finished сходится, не приходит только ответ VLESS. У Reality нет отрицательного
     * ответа — непризнанного клиента он молча проксирует на маскировочный сайт.
     *
     * Отсюда правило для этого блока: любое изменение здесь проверяется перехватом рядом с
     * браузерным эталоном, а не рассуждением о том, что «должно подойти». */

    /* Расширения складываются в таблицу и лишь потом пишутся: Chrome начиная с 110-й версии
     * ПЕРЕМЕШИВАЕТ их порядок на каждом соединении, оставляя на месте первое и последнее.
     * Фиксированный порядок сам был бы отпечатком. */
    struct pend { unsigned type; const unsigned char *body; size_t n; };
    struct pend px[20];
    size_t pn = 0;

    unsigned char b_sni[300], b_alpn[16], b_cc[4], b_ech[220], b_alps[8], b_reneg[1];
    unsigned char b_ocsp[5], b_vers[8], b_sigs[20], b_ks[64], b_grp[12], b_pskm[2];
    unsigned char b_ecpf[2], b_last[1];

    /* Первым — GREASE, пустой. */
    px[pn].type = g_ext_a; px[pn].body = NULL; px[pn].n = 0; pn++;

    /* server_name: список(2) + тип(1) + длина(2) + имя. */
    {
        size_t sni_len = strlen(cfg->sni);
        struct buf sb = { b_sni, 0, sizeof(b_sni) };
        put16(&sb, (unsigned)(sni_len + 3));
        put8(&sb, 0);
        put16(&sb, (unsigned)sni_len);
        put(&sb, cfg->sni, sni_len);
        px[pn].type = 0x0000; px[pn].body = b_sni; px[pn].n = sb.len; pn++;
    }

    /* ALPN: ВСЕГДА h2 и http/1.1, как браузер, независимо от транспорта узла.
     *
     * Раньше ALPN ставился только для grpc и xhttp — и это само было отличием от браузера,
     * который присылает его всегда. Транспорту это не вредит: h2 стоит первым, поэтому
     * сервер, желающий h2, его и выберет, а признавший нас Reality не выбирает ничего
     * (NextProtos nil в Xray) и присылает пустые EncryptedExtensions. */
    {
        struct buf ab = { b_alpn, 0, sizeof(b_alpn) };
        put16(&ab, 12);
        put8(&ab, 2); put(&ab, "h2", 2);
        put8(&ab, 8); put(&ab, "http/1.1", 8);
        px[pn].type = 0x0010; px[pn].body = b_alpn; px[pn].n = ab.len; pn++;
    }

    /* compress_certificate: brotli (2). */
    { struct buf cb = { b_cc, 0, sizeof(b_cc) };
      put8(&cb, 2); put16(&cb, 0x0002);
      px[pn].type = 0x001B; px[pn].body = b_cc; px[pn].n = cb.len; pn++; }

    /* encrypted_client_hello — НАБИВКА, а не настоящий ECH.
     *
     * Chrome без конфигурации ECH посылает именно это: расширение правильной формы, набитое
     * случайными байтами (в utls — GREASE-ECH). Настоящий ECH нам не нужен и не с чем
     * согласовывать; нужна ровно та же форма и тот же размер, иначе Hello отличим по одному
     * отсутствующему расширению в 218 байт.
     *
     * Раскладка: тип(1)=0 внешний, kdf(2)=HKDF-SHA256, aead(2)=AES-128-GCM, номер
     * конфигурации(1), длина enc(2)=32 и сам enc, длина payload(2)=176 и payload.
     * Итого 1+2+2+1+2+32+2+176 = 218 байт — столько же, сколько у эталона. */
    {
        unsigned char noise[209];
        if (fill_random(noise, sizeof(noise)) != 0) return REALITY_ECRYPTO;
        struct buf eb = { b_ech, 0, sizeof(b_ech) };
        put8(&eb, 0x00);
        put16(&eb, 0x0001);
        put16(&eb, 0x0001);
        put8(&eb, noise[0]);
        put16(&eb, 32);
        put(&eb, noise + 1, 32);
        put16(&eb, 176);
        put(&eb, noise + 33, 176);
        px[pn].type = 0xFE0D; px[pn].body = b_ech; px[pn].n = eb.len; pn++;
    }

    /* application_settings (ALPS), новый номер 0x44cd: список из одного "h2". */
    { struct buf ab = { b_alps, 0, sizeof(b_alps) };
      put16(&ab, 3); put8(&ab, 2); put(&ab, "h2", 2);
      px[pn].type = 0x44CD; px[pn].body = b_alps; px[pn].n = ab.len; pn++; }

    b_reneg[0] = 0;
    px[pn].type = 0xFF01; px[pn].body = b_reneg; px[pn].n = 1; pn++;

    px[pn].type = 0x0017; px[pn].body = NULL; px[pn].n = 0; pn++;   /* extended_master_secret */
    px[pn].type = 0x0023; px[pn].body = NULL; px[pn].n = 0; pn++;   /* session_ticket */

    /* status_request: OCSP, пустые списки. */
    { struct buf ob = { b_ocsp, 0, sizeof(b_ocsp) };
      put8(&ob, 1); put16(&ob, 0); put16(&ob, 0);
      px[pn].type = 0x0005; px[pn].body = b_ocsp; px[pn].n = ob.len; pn++; }

    /* supported_versions: GREASE, 1.3, 1.2.
     *
     * TLS 1.2 в списке есть потому, что он есть у браузера. Обслужить его tls13.c не умеет,
     * но Reality — это строго 1.3, и сервер выберет 1.3; если вдруг нет, разбор ServerHello
     * не найдёт key_share и вернёт ENOKEYSHARE, то есть ошибку, а не молчание. */
    { struct buf vb = { b_vers, 0, sizeof(b_vers) };
      put8(&vb, 6); put16(&vb, g_version); put16(&vb, 0x0304); put16(&vb, 0x0303);
      px[pn].type = 0x002B; px[pn].body = b_vers; px[pn].n = vb.len; pn++; }

    px[pn].type = 0x0012; px[pn].body = NULL; px[pn].n = 0; pn++;   /* signed_cert_timestamp */

    /* signature_algorithms: восемь, в порядке Chrome. */
    { static const unsigned sigs[] = { 0x0403, 0x0804, 0x0401, 0x0503,
                                       0x0805, 0x0501, 0x0806, 0x0601 };
      struct buf sb = { b_sigs, 0, sizeof(b_sigs) };
      put16(&sb, (unsigned)(sizeof(sigs) / sizeof(sigs[0])) * 2);
      for (size_t i = 0; i < sizeof(sigs) / sizeof(sigs[0]); i++) put16(&sb, sigs[i]);
      px[pn].type = 0x000D; px[pn].body = b_sigs; px[pn].n = sb.len; pn++; }

    /* key_share: GREASE-группа с одним нулевым байтом, затем наша половина X25519.
     * Номер GREASE-группы тот же, что в supported_groups — так делает браузер. */
    { struct buf kb = { b_ks, 0, sizeof(b_ks) };
      put16(&kb, 41);
      put16(&kb, g_group); put16(&kb, 1); put8(&kb, 0);
      put16(&kb, 0x001D); put16(&kb, 32); put(&kb, st->pub, 32);
      px[pn].type = 0x0033; px[pn].body = b_ks; px[pn].n = kb.len; pn++; }

    /* supported_groups: GREASE, X25519, secp256r1, secp384r1 — ровно набор Chrome.
     * Прежние FFDHE 0x0100..0x0104 браузер не предлагает вовсе. */
    { struct buf gb = { b_grp, 0, sizeof(b_grp) };
      put16(&gb, 8); put16(&gb, g_group);
      put16(&gb, 0x001D); put16(&gb, 0x0017); put16(&gb, 0x0018);
      px[pn].type = 0x000A; px[pn].body = b_grp; px[pn].n = gb.len; pn++; }

    b_pskm[0] = 1; b_pskm[1] = 1;
    px[pn].type = 0x002D; px[pn].body = b_pskm; px[pn].n = 2; pn++;  /* psk_key_exchange_modes */

    b_ecpf[0] = 1; b_ecpf[1] = 0;
    px[pn].type = 0x000B; px[pn].body = b_ecpf; px[pn].n = 2; pn++;  /* ec_point_formats */

    /* Последним — второй GREASE, с одним нулевым байтом. */
    b_last[0] = 0;
    px[pn].type = g_ext_b; px[pn].body = b_last; px[pn].n = 1; pn++;

    /* Перемешиваем всё, кроме первого и последнего. Тасование Фишера — Йетса на случайных
     * байтах: без него порядок был бы постоянным, то есть отличимым. */
    if (pn > 3) {
        unsigned char sh[20];
        if (fill_random(sh, sizeof(sh)) != 0) return REALITY_ECRYPTO;
        for (size_t i = pn - 2; i > 1; i--) {
            size_t j = 1 + (size_t)sh[i] % i;
            struct pend t = px[i]; px[i] = px[j]; px[j] = t;
        }
    }
    for (size_t i = 0; i < pn; i++) ext(&b, px[i].type, px[i].body, px[i].n);

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
