/* Слой записей TLS 1.3 поверх готового рукопожатия Reality.
 *
 * Что здесь есть и чего сознательно нет.
 *
 * Reality — это настоящий TLS 1.3 с той единственной особенностью, что подлинность
 * сервера доказана аутентификатором в session_id, а не сертификатом. Всё остальное —
 * обычный обмен по RFC 8446: ServerHello приносит серверную половину key_share, из
 * общего секрета выводятся ключи трафика, дальше записи шифруются AEAD.
 *
 * Сертификат сервера мы НЕ проверяем, и это не небрежность: сертификат подлинный, но
 * принадлежит чужому сайту, которым сервер прикрывается. Проверять его бессмысленно —
 * подлинность уже доказана иначе. Именно поэтому здесь нет mbedtls_ssl_*: полный
 * TLS-стек библиотеки настаивал бы на проверке цепочки и тянул бы X.509 с корневым
 * хранилищем, которого на роутере нет.
 *
 * Реализована только та часть рукопожатия, которая нужна: разобрать ServerHello, вывести
 * ключи, проверить Finished. Возобновление сессий, client cert, HelloRetryRequest и
 * post-handshake сообщения не поддержаны — на них не приходит ни один узел подписки, а
 * каждое было бы кодом, который никогда не исполняется и потому не проверен.
 */
#define _GNU_SOURCE
#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <poll.h>

#include "mbedtls/sha256.h"
#include "mbedtls/sha512.h"
#include "mbedtls/hkdf.h"
#include "mbedtls/md.h"
#include "mbedtls/gcm.h"
#include "mbedtls/chachapoly.h"

#include "tls13.h"

/* Из reality.c: тот же X25519, но со вторым множителем из ServerHello. Общая функция, а
 * не копия, потому что копия крипто-кода — это два места, где может разойтись прижатие
 * скаляра или порядок байт. */
int x25519_shared_ext(const unsigned char priv[32], const unsigned char peer[32],
                      unsigned char out[32]);

/* ---- HKDF-Expand-Label из RFC 8446 §7.1 ------------------------------------ */
/* Своя обёртка, потому что метка склеивается по строгому формату: длина вывода,
 * "tls13 "+label, контекст. Ошибка в одном байте здесь даёт ключи, отличные от
 * серверных, и проявляется как «расшифровка не выходит» уже после рукопожатия. */
static int expand_label(const mbedtls_md_info_t *md,
                        const unsigned char *secret, size_t secret_n,
                        const char *label,
                        const unsigned char *ctx, size_t ctx_n,
                        unsigned char *out, size_t out_n) {
    unsigned char info[512];
    size_t i = 0;
    size_t llen = strlen(label);
    if (6 + llen > 255 || ctx_n > 255 || 4 + 6 + llen + ctx_n > sizeof(info)) return -1;
    info[i++] = (unsigned char)(out_n >> 8);
    info[i++] = (unsigned char)out_n;
    info[i++] = (unsigned char)(6 + llen);
    memcpy(info + i, "tls13 ", 6); i += 6;
    memcpy(info + i, label, llen); i += llen;
    info[i++] = (unsigned char)ctx_n;
    if (ctx_n) { memcpy(info + i, ctx, ctx_n); i += ctx_n; }
    return mbedtls_hkdf_expand(md, secret, secret_n, info, i, out, out_n);
}

static int derive_secret(const mbedtls_md_info_t *md, const unsigned char *secret,
                         const char *label, const unsigned char *thash, size_t hash_n,
                         unsigned char *out) {
    return expand_label(md, secret, hash_n, label, thash, hash_n, out, hash_n);
}

/* ---- транскрипт ------------------------------------------------------------ */
/* Хеш всех сообщений рукопожатия по порядку. Он входит в вывод каждого ключа, поэтому
 * любое расхождение с сервером (лишний байт, пропущенное сообщение) ломает не транскрипт,
 * а ключи — и обнаруживается как неверный Finished. */
static void tr_init(struct tls13 *t) {
    mbedtls_sha256_init(&t->tr);
    mbedtls_sha256_starts(&t->tr, 0);
}
static void tr_add(struct tls13 *t, const unsigned char *d, size_t n) {
    mbedtls_sha256_update(&t->tr, d, n);
}
static void tr_hash(const struct tls13 *t, unsigned char out[32]) {
    /* Копия: транскрипт продолжается после каждого вывода ключей. */
    mbedtls_sha256_context c;
    mbedtls_sha256_init(&c);
    mbedtls_sha256_clone(&c, &t->tr);
    mbedtls_sha256_finish(&c, out);
    mbedtls_sha256_free(&c);
}

/* ---- чтение записей -------------------------------------------------------- */
/* Чтение по дескриптору — только для рукопожатия: у него ещё нет struct tls13 с буфером,
 * и оно по своей природе синхронное. */
static int read_full(int fd, unsigned char *buf, size_t n) {
    size_t got = 0;
    while (got < n) {
        ssize_t r = read(fd, buf + got, n - got);
        if (r == 0) return TLS13_ECLOSED;
        if (r < 0) {
            if (errno == EINTR) continue;
            return TLS13_EIO;
        }
        got += (size_t)r;
    }
    return 0;
}

/* Одна TLS-запись, собранная из буфера соединения.
 *
 * Читаем у сокета КРУПНО и редко: один read() берёт всё, что накопилось (до 16 КБ), а
 * записи выдаются из буфера без новых вызовов. Прежняя версия спрашивала FIONREAD,
 * подглядывала заголовок и ждала дособирания записи на каждой итерации — это давало
 * 16 000 чтений в секунду по 600 байт и 80% времени цикла внутри чтения.
 *
 * may_wait разделяет два режима: рукопожатие ЖДЁТ (оно синхронное, продолжить с середины
 * некому), поток данных не ждёт — недособранную запись оставляем в буфере и уходим к
 * другим соединениям. */
static int rbuf_fill(struct tls13 *t, int may_wait) {
    /* Сдвигаем остаток к началу, чтобы место под чтение было непрерывным. */
    if (t->rbuf_off) {
        if (t->rbuf_n > t->rbuf_off)
            memmove(t->rbuf, t->rbuf + t->rbuf_off, t->rbuf_n - t->rbuf_off);
        t->rbuf_n -= t->rbuf_off;
        t->rbuf_off = 0;
    }
    if (t->rbuf_n >= sizeof(t->rbuf)) return TLS13_ETOOBIG;

    if (!may_wait) {
        struct pollfd p = { .fd = t->fd, .events = POLLIN };
        int pr = poll(&p, 1, 0);
        if (pr <= 0 || !(p.revents & POLLIN)) return TLS13_EAGAIN;
    }
    ssize_t r = read(t->fd, t->rbuf + t->rbuf_n, sizeof(t->rbuf) - t->rbuf_n);
    if (r == 0) return TLS13_ECLOSED;
    if (r < 0) {
        if (errno == EINTR) return 0;
        if (errno == EAGAIN || errno == EWOULDBLOCK) return TLS13_EAGAIN;
        return TLS13_EIO;
    }
    t->rbuf_n += (size_t)r;
    return 0;
}

/* Для рукопожатия: своего буфера у него ещё нет, а ждать он обязан. */
static int read_record_fd(int fd, unsigned char *type, unsigned char *body, size_t cap,
                          size_t *body_n) {
    unsigned char h[5];
    int rc = read_full(fd, h, 5);
    if (rc) return rc;
    size_t len = ((size_t)h[3] << 8) | h[4];
    if (len > cap) return TLS13_ETOOBIG;
    rc = read_full(fd, body, len);
    if (rc) return rc;
    *type = h[0];
    *body_n = len;
    return 0;
}

static int read_record(struct tls13 *t, unsigned char *type, unsigned char **body,
                       size_t *body_n, int may_wait) {
    for (int guard = 0; guard < 64; guard++) {
        size_t have = t->rbuf_n - t->rbuf_off;
        if (have >= 5) {
            const unsigned char *h = t->rbuf + t->rbuf_off;
            size_t len = ((size_t)h[3] << 8) | h[4];
            if (len > TLS13_MAX_REC) return TLS13_EBADREC;
            if (have >= 5 + len) {
                *type = h[0];
                *body = t->rbuf + t->rbuf_off + 5;
                *body_n = len;
                t->rbuf_off += 5 + len;
                return 0;
            }
        }
        int rc = rbuf_fill(t, may_wait);
        if (rc) return rc;
    }
    return TLS13_EAGAIN;
}

/* ---- AEAD ------------------------------------------------------------------ */
/* Nonce в TLS 1.3: iv XOR порядковый номер, выровненный вправо. Счётчик свой на каждое
 * направление и НЕ сбрасывается — сброс означал бы повтор nonce, то есть полную потерю
 * защиты AEAD. */
static void aead_nonce(const unsigned char iv[12], uint64_t seq, unsigned char out[12]) {
    memcpy(out, iv, 12);
    for (int i = 0; i < 8; i++)
        out[11 - i] ^= (unsigned char)(seq >> (8 * i));
}

/* Развернуть ключ в контекст шифра. Вызывается один раз на направление, когда ключи
 * трафика готовы; дальше каждая запись пользуется готовым контекстом. */
static int keys_setup(struct tls13_keys *k) {
    if (k->ctx_ready) return 0;
    if (k->aead == TLS13_AEAD_CHACHA) {
        mbedtls_chachapoly_init(&k->chacha);
        if (mbedtls_chachapoly_setkey(&k->chacha, k->key) != 0) return TLS13_ECRYPTO;
    } else {
        mbedtls_gcm_init(&k->gcm);
        if (mbedtls_gcm_setkey(&k->gcm, MBEDTLS_CIPHER_ID_AES, k->key,
                               (unsigned)k->key_n * 8) != 0)
            return TLS13_ECRYPTO;
    }
    k->ctx_ready = 1;
    return 0;
}

static void keys_free(struct tls13_keys *k) {
    if (!k->ctx_ready) return;
    if (k->aead == TLS13_AEAD_CHACHA) mbedtls_chachapoly_free(&k->chacha);
    else mbedtls_gcm_free(&k->gcm);
    k->ctx_ready = 0;
}

void tls13_free(struct tls13 *t) {
    keys_free(&t->rd);
    keys_free(&t->wr);
    mbedtls_sha256_free(&t->tr);
    t->ready = 0;
}

static int aead_open(struct tls13_keys *k, uint64_t seq,
                     const unsigned char *aad, size_t aad_n,
                     unsigned char *buf, size_t n) {
    if (n < 16) return TLS13_EBADREC;
    if (!k->ctx_ready) return TLS13_ESTATE;
    unsigned char nonce[12];
    aead_nonce(k->iv, seq, nonce);
    size_t ct = n - 16;
    /* Тег КОПИРУЕТСЯ, а не читается из того же буфера. Расшифровка идёт на месте, и тег
     * лежит сразу за шифротекстом — то есть в области, которую реализация вправе задеть,
     * дописывая последний неполный блок. Проверено отдельным тестом (tests/gcm-size.c),
     * что эта mbedtls так не делает ни на одном размере записи, — но зависеть от её
     * внутреннего устройства незачем, а копия в шестнадцать байт стоит ничего. */
    unsigned char tag[16];
    memcpy(tag, buf + ct, 16);
    int rc;
    if (k->aead == TLS13_AEAD_CHACHA)
        rc = mbedtls_chachapoly_auth_decrypt(&k->chacha, ct, nonce, aad, aad_n, tag, buf, buf);
    else
        rc = mbedtls_gcm_auth_decrypt(&k->gcm, ct, nonce, 12, aad, aad_n, tag, 16, buf, buf);
    return rc == 0 ? 0 : TLS13_EAUTH;
}

static int aead_seal(struct tls13_keys *k, uint64_t seq,
                     const unsigned char *aad, size_t aad_n,
                     unsigned char *buf, size_t n, unsigned char *tag) {
    if (!k->ctx_ready) return TLS13_ESTATE;
    unsigned char nonce[12];
    aead_nonce(k->iv, seq, nonce);
    int rc;
    if (k->aead == TLS13_AEAD_CHACHA)
        rc = mbedtls_chachapoly_encrypt_and_tag(&k->chacha, n, nonce, aad, aad_n, buf, buf, tag);
    else
        rc = mbedtls_gcm_crypt_and_tag(&k->gcm, MBEDTLS_GCM_ENCRYPT, n, nonce, 12,
                                       aad, aad_n, buf, buf, 16, tag);
    return rc == 0 ? 0 : TLS13_ECRYPTO;
}

/* Те же две операции, но с одноразовым контекстом — для РУКОПОЖАТИЯ.
 *
 * Оно проходит по три-четыре записи на соединение, поэтому цена разворота ключа здесь не
 * значит ничего, а взамен не приходится освобождать контексты на десятке путей выхода по
 * ошибке. Постоянные контексты стоят там, где идёт поток, — и только там. */
static int aead_open_once(const struct tls13_keys *src, uint64_t seq,
                          const unsigned char *aad, size_t aad_n,
                          unsigned char *buf, size_t n) {
    struct tls13_keys k = *src;
    k.ctx_ready = 0;
    int rc = keys_setup(&k);
    if (rc == 0) rc = aead_open(&k, seq, aad, aad_n, buf, n);
    keys_free(&k);
    return rc;
}

static int aead_seal_once(const struct tls13_keys *src, uint64_t seq,
                          const unsigned char *aad, size_t aad_n,
                          unsigned char *buf, size_t n, unsigned char *tag) {
    struct tls13_keys k = *src;
    k.ctx_ready = 0;
    int rc = keys_setup(&k);
    if (rc == 0) rc = aead_seal(&k, seq, aad, aad_n, buf, n, tag);
    keys_free(&k);
    return rc;
}

/* ---- рукопожатие ----------------------------------------------------------- */
/* Принимает уже отправленный ClientHello (для транскрипта) и общий секрет из Reality.
 * Возвращается с готовыми ключами трафика. */
int tls13_handshake(struct tls13 *t, int fd,
                    const unsigned char *client_hello, size_t hello_n,
                    const unsigned char *our_priv) {
    memset(t, 0, sizeof(*t));
    t->fd = fd;
    const mbedtls_md_info_t *md = mbedtls_md_info_from_type(MBEDTLS_MD_SHA256);
    if (!md) return TLS13_ECRYPTO;
    const size_t H = 32;

    tr_init(t);
    /* В транскрипт идёт handshake-сообщение без заголовка записи. */
    tr_add(t, client_hello + 5, hello_n - 5);

    unsigned char rec[TLS13_MAX_REC];
    unsigned char type;
    size_t n;

    /* ServerHello. */
    int rc = read_record_fd(fd, &type, rec, sizeof(rec), &n);
    if (rc) return rc;
    if (type != 0x16 || n < 44 || rec[0] != 0x02) return TLS13_EBADREC;
    tr_add(t, rec, n);

    /* Серверная половина key_share — в расширениях. Ищем по типу 0x33, а не по
     * смещению: длина session_id и набор расширений меняются от сервера к серверу.
     *
     * HS_HDR = 4: тип сообщения(1) + длина(3). Первая версия начинала разбор сразу с
     * версии, съедая заголовок как данные — session_id читался как 22 вместо 32, а
     * длина расширений выходила 14973 при записи в 122 байта. Проявлялось это как
     * «испорченная TLS-запись», то есть виноватым выглядел сервер. */
    const size_t HS_HDR = 4;
    unsigned char server_pub[32];
    int have_pub = 0;
    {
        size_t p = HS_HDR + 2 + 32;             /* заголовок + version + random */
        if (p >= n) return TLS13_EBADREC;
        size_t sid_n = rec[p++];
        p += sid_n;
        p += 2;                                 /* cipher_suite */
        p += 1;                                 /* compression */
        if (p + 2 > n) return TLS13_EBADREC;
        size_t exts_n = ((size_t)rec[p] << 8) | rec[p + 1];
        p += 2;
        size_t end = p + exts_n;
        if (end > n) return TLS13_EBADREC;
        while (p + 4 <= end) {
            unsigned etype = ((unsigned)rec[p] << 8) | rec[p + 1];
            size_t elen = ((size_t)rec[p + 2] << 8) | rec[p + 3];
            p += 4;
            if (p + elen > end) break;
            if (etype == 0x0033 && elen >= 4 + 32) {
                /* group(2) + length(2) + key */
                memcpy(server_pub, rec + p + 4, 32);
                have_pub = 1;
            }
            p += elen;
        }
    }
    if (!have_pub) return TLS13_ENOKEYSHARE;

    /* Выбранный шифр определяет AEAD. Берём из ServerHello, а не догадываемся. */
    {
        size_t p = HS_HDR + 2 + 32;
        size_t sid_n = rec[p++];
        p += sid_n;
        unsigned suite = ((unsigned)rec[p] << 8) | rec[p + 1];
        switch (suite) {
            case 0x1301: t->rd.aead = t->wr.aead = TLS13_AEAD_AES128; t->rd.key_n = t->wr.key_n = 16; break;
            case 0x1302: t->rd.aead = t->wr.aead = TLS13_AEAD_AES256; t->rd.key_n = t->wr.key_n = 32; break;
            case 0x1303: t->rd.aead = t->wr.aead = TLS13_AEAD_CHACHA; t->rd.key_n = t->wr.key_n = 32; break;
            default: return TLS13_EBADSUITE;
        }
    }

    /* Расписание ключей RFC 8446 §7.1. Каждый шаг обязателен и порядок его строг:
     * early -> handshake -> master, с derive-secret между ними. */
    unsigned char zeros[32] = {0};
    unsigned char early[32], derived[32], hs_secret[32], empty_hash[32];
    mbedtls_sha256(zeros, 0, empty_hash, 0);

    if (mbedtls_hkdf_extract(md, NULL, 0, zeros, H, early) != 0) return TLS13_ECRYPTO;
    if (expand_label(md, early, H, "derived", empty_hash, H, derived, H) != 0) return TLS13_ECRYPTO;

    /* ECDHE-вход расписания — секрет с ЭФЕМЕРНЫМ ключом сервера из ServerHello, а не
     * тот, что посчитан в reality.c.
     *
     * Это разные величины, и путать их — ровно та ошибка, из-за которой рукопожатие
     * доходило до конца, а AEAD не сходился:
     *
     *   Reality-секрет = наш эфемерный x постоянный ключ сервера (pbk из ссылки).
     *                    Он нужен ТОЛЬКО для аутентификатора в session_id;
     *   TLS-секрет     = наш эфемерный x эфемерный ключ сервера (key_share в ServerHello).
     *                    На нём стоит всё расписание ключей.
     *
     * Сервер, обслуживая нас как VLESS, всё равно проводит обычный TLS 1.3 со своим
     * эфемерным ключом — иначе поток не был бы неотличим от настоящего HTTPS. */
    unsigned char ecdhe[32];
    if (x25519_shared_ext(our_priv, server_pub, ecdhe) != 0) return TLS13_ECRYPTO;
    if (mbedtls_hkdf_extract(md, derived, H, ecdhe, 32, hs_secret) != 0)
        return TLS13_ECRYPTO;

    unsigned char th[32];
    tr_hash(t, th);
    unsigned char c_hs[32], s_hs[32];
    if (derive_secret(md, hs_secret, "c hs traffic", th, H, c_hs) != 0) return TLS13_ECRYPTO;
    if (derive_secret(md, hs_secret, "s hs traffic", th, H, s_hs) != 0) return TLS13_ECRYPTO;

    struct tls13_keys c_hk = t->wr, s_hk = t->rd;
    if (expand_label(md, c_hs, H, "key", NULL, 0, c_hk.key, c_hk.key_n) != 0) return TLS13_ECRYPTO;
    if (expand_label(md, c_hs, H, "iv", NULL, 0, c_hk.iv, 12) != 0) return TLS13_ECRYPTO;
    if (expand_label(md, s_hs, H, "key", NULL, 0, s_hk.key, s_hk.key_n) != 0) return TLS13_ECRYPTO;
    if (expand_label(md, s_hs, H, "iv", NULL, 0, s_hk.iv, 12) != 0) return TLS13_ECRYPTO;

    /* Дальше сервер шлёт зашифрованные сообщения. Читаем до Finished, попутно добавляя
     * их в транскрипт: Certificate и CertificateVerify нам не нужны по содержанию, но
     * нужны в хеше — иначе Finished не сойдётся. */
    uint64_t s_seq = 0;
    int got_finished = 0;
    unsigned char server_finished[32];
    for (int guard = 0; guard < 16 && !got_finished; guard++) {
        rc = read_record_fd(fd, &type, rec, sizeof(rec), &n);
        if (rc) return rc;
        if (type == 0x14) continue;             /* ChangeCipherSpec: игнор в 1.3 */
        if (type != 0x17) return TLS13_EBADREC;

        unsigned char aad[5] = { 0x17, 0x03, 0x03,
                                 (unsigned char)(n >> 8), (unsigned char)n };
        rc = aead_open_once(&s_hk, s_seq++, aad, 5, rec, n);
        if (rc) return rc;
        size_t pt = n - 16;
        /* Последний непустой байт — настоящий тип записи (RFC 8446 §5.4). */
        while (pt > 0 && rec[pt - 1] == 0) pt--;
        if (pt == 0) return TLS13_EBADREC;
        unsigned char inner = rec[--pt];
        if (inner != 0x16) continue;            /* не handshake — пропускаем */

        /* В одной записи может быть несколько сообщений. */
        size_t p = 0;
        while (p + 4 <= pt) {
            unsigned char msg = rec[p];
            size_t mlen = ((size_t)rec[p + 1] << 16) | ((size_t)rec[p + 2] << 8) | rec[p + 3];
            if (p + 4 + mlen > pt) break;
            if (msg == 0x08) {                  /* EncryptedExtensions */
                /* Достаём только ALPN. Разбирать остальные расширения нечем и незачем:
                 * ни одно из них на нас не влияет, а лишний разбор недоверенных байт —
                 * лишнее место для ошибки. Тело: длина списка(2), затем расширения
                 * тип(2)+длина(2)+тело, а внутри ALPN — длина списка(2), длина(1), имя. */
                const unsigned char *e = rec + p + 4;
                if (mlen >= 2) {
                    size_t total = ((size_t)e[0] << 8) | e[1];
                    if (total + 2 <= mlen) {
                        size_t q = 2;
                        while (q + 4 <= total + 2) {
                            unsigned etype = ((unsigned)e[q] << 8) | e[q + 1];
                            size_t ebody = ((size_t)e[q + 2] << 8) | e[q + 3];
                            if (q + 4 + ebody > total + 2) break;
                            if (etype == 0x0010 && ebody >= 4) {
                                size_t pl = e[q + 6];
                                if (pl && pl < sizeof(t->alpn) && 3 + pl <= ebody) {
                                    memcpy(t->alpn, e + q + 7, pl);
                                    t->alpn[pl] = '\0';
                                }
                            }
                            q += 4 + ebody;
                        }
                    }
                }
            }
            if (msg == 0x14) {                  /* Finished */
                /* Проверяем ДО добавления в транскрипт: сервер считал его от хеша
                 * предыдущих сообщений. */
                unsigned char fkey[32], hash[32], want[32];
                tr_hash(t, hash);
                if (expand_label(md, s_hs, H, "finished", NULL, 0, fkey, H) != 0)
                    return TLS13_ECRYPTO;
                if (mbedtls_md_hmac(md, fkey, H, hash, H, want) != 0) return TLS13_ECRYPTO;
                if (mlen != H || memcmp(rec + p + 4, want, H) != 0) return TLS13_EFINISHED;
                memcpy(server_finished, want, H);
                got_finished = 1;
            }
            tr_add(t, rec + p, 4 + mlen);
            p += 4 + mlen;
        }
    }
    if (!got_finished) return TLS13_EFINISHED;

    /* Свой Finished — от транскрипта, включающего серверный. */
    unsigned char th2[32], cfkey[32], chash[32], cfin[32];
    tr_hash(t, th2);
    if (expand_label(md, c_hs, H, "finished", NULL, 0, cfkey, H) != 0) return TLS13_ECRYPTO;
    memcpy(chash, th2, H);
    if (mbedtls_md_hmac(md, cfkey, H, chash, H, cfin) != 0) return TLS13_ECRYPTO;

    /* Отправляем: ChangeCipherSpec (совместимость с middlebox, как браузер) и
     * зашифрованный Finished. */
    {
        unsigned char ccs[6] = { 0x14, 0x03, 0x03, 0x00, 0x01, 0x01 };
        if (write(fd, ccs, 6) != 6) return TLS13_EIO;

        unsigned char pt[64];
        size_t pl = 0;
        pt[pl++] = 0x14;
        pt[pl++] = 0; pt[pl++] = 0; pt[pl++] = (unsigned char)H;
        memcpy(pt + pl, cfin, H); pl += H;
        pt[pl++] = 0x16;                        /* inner type */

        unsigned char out[128];
        size_t total = pl + 16;
        out[0] = 0x17; out[1] = 0x03; out[2] = 0x03;
        out[3] = (unsigned char)(total >> 8); out[4] = (unsigned char)total;
        memcpy(out + 5, pt, pl);
        if (aead_seal_once(&c_hk, 0, out, 5, out + 5, pl, out + 5 + pl) != 0) return TLS13_ECRYPTO;
        if (write(fd, out, 5 + total) != (ssize_t)(5 + total)) return TLS13_EIO;
    }

    /* Ключи трафика приложения — от master secret и полного транскрипта. */
    unsigned char master[32], c_ap[32], s_ap[32];
    if (expand_label(md, hs_secret, H, "derived", empty_hash, H, derived, H) != 0)
        return TLS13_ECRYPTO;
    if (mbedtls_hkdf_extract(md, derived, H, zeros, H, master) != 0) return TLS13_ECRYPTO;
    tr_hash(t, th2);
    if (derive_secret(md, master, "c ap traffic", th2, H, c_ap) != 0) return TLS13_ECRYPTO;
    if (derive_secret(md, master, "s ap traffic", th2, H, s_ap) != 0) return TLS13_ECRYPTO;

    if (expand_label(md, c_ap, H, "key", NULL, 0, t->wr.key, t->wr.key_n) != 0) return TLS13_ECRYPTO;
    if (expand_label(md, c_ap, H, "iv", NULL, 0, t->wr.iv, 12) != 0) return TLS13_ECRYPTO;
    if (expand_label(md, s_ap, H, "key", NULL, 0, t->rd.key, t->rd.key_n) != 0) return TLS13_ECRYPTO;
    if (expand_label(md, s_ap, H, "iv", NULL, 0, t->rd.iv, 12) != 0) return TLS13_ECRYPTO;
    /* Ключи трафика больше не меняются — разворачиваем их в контексты шифров здесь, и
     * дальше поток идёт без единого setkey. */
    if (keys_setup(&t->wr) != 0 || keys_setup(&t->rd) != 0) return TLS13_ECRYPTO;
    t->wr_seq = t->rd_seq = 0;
    t->ready = 1;
    return 0;
}

size_t tls13_take_pending(struct tls13 *t, unsigned char *out, size_t cap) {
    size_t have = t->rbuf_n - t->rbuf_off;
    if (!have) return 0;
    if (have > cap) have = cap;
    memcpy(out, t->rbuf + t->rbuf_off, have);
    t->rbuf_off += have;
    return have;
}

/* ---- обмен данными --------------------------------------------------------- */
int tls13_write(struct tls13 *t, const unsigned char *data, size_t n) {
    if (!t->ready) return TLS13_ESTATE;
    while (n) {
        size_t chunk = n > TLS13_MAX_PLAIN ? TLS13_MAX_PLAIN : n;
        unsigned char out[TLS13_MAX_REC + 5];
        size_t total = chunk + 1 + 16;          /* + inner type + tag */
        out[0] = 0x17; out[1] = 0x03; out[2] = 0x03;
        out[3] = (unsigned char)(total >> 8); out[4] = (unsigned char)total;
        memcpy(out + 5, data, chunk);
        out[5 + chunk] = 0x17;                  /* inner type: application_data */
        if (aead_seal(&t->wr, t->wr_seq++, out, 5, out + 5, chunk + 1,
                      out + 5 + chunk + 1) != 0)
            return TLS13_ECRYPTO;
        size_t want = 5 + total, sent = 0;
        while (sent < want) {
            ssize_t w = write(t->fd, out + sent, want - sent);
            if (w <= 0) {
                if (w < 0 && errno == EINTR) continue;
                return TLS13_EIO;
            }
            sent += (size_t)w;
        }
        data += chunk;
        n -= chunk;
    }
    return 0;
}

/* Прочитать РОВНО ОДНУ запись. Данных в ней может не оказаться — тогда ноль байт с
 * кодом 0, и это успех, а не отказ.
 *
 * «Ровно одну» здесь дороже, чем выглядит. Прежняя версия крутила цикл, пока не получит
 * данные, и на записи без данных немедленно бралась читать следующую. А записей без
 * данных в этом потоке хватает: ChangeCipherSpec, NewSessionTicket и пустые записи,
 * которыми пользуется Vision. Второе чтение упиралось в SO_RCVTIMEO, через восемь секунд
 * возвращало EAGAIN — и вызывающий получал ошибку ввода-вывода на полностью исправном
 * соединении.
 *
 * Наблюдалось как «выгрузка встаёт на 130–260 КБ и обрывается»: пустая запись приезжала
 * посреди передачи, соединение умирало, и место обрыва каждый раз было другим. На коротких
 * ответах не проявлялось никогда, потому что пустая запись просто не успевала прийти.
 *
 * Ждать, пока сокет станет читаемым, — дело вызывающего: у него есть poll, у нас его нет
 * и быть не должно. */
int tls13_read(struct tls13 *t, unsigned char *out, size_t cap, size_t *got) {
    if (!t->ready) return TLS13_ESTATE;
    *got = 0;

    /* Запись расшифровывается НА МЕСТЕ в буфере соединения: копировать её ещё раз значило
     * бы гонять по памяти лишние 16 КБ на каждую запись. */
    unsigned char *rec = NULL;
    unsigned char type;
    size_t n = 0;
    int rc = read_record(t, &type, &rec, &n, 0);
    /* Записи целиком нет — это «пока нечего», а не сбой: вызывающий просто придёт снова. */
    if (rc == TLS13_EAGAIN) return 0;
    if (rc) return rc;
    if (type == 0x14) return 0;                /* ChangeCipherSpec: в 1.3 смысла не несёт */
    if (type != 0x17) return TLS13_EBADREC;

    unsigned char aad[5] = { 0x17, 0x03, 0x03,
                             (unsigned char)(n >> 8), (unsigned char)n };
    rc = aead_open(&t->rd, t->rd_seq++, aad, 5, rec, n);
    if (rc) return rc;
    size_t pt = n - 16;
    while (pt > 0 && rec[pt - 1] == 0) pt--;
    if (pt == 0) return TLS13_EBADREC;
    unsigned char inner = rec[--pt];

    /* NewSessionTicket и прочие post-handshake сообщения приходят как handshake и нас не
     * интересуют: возобновление не поддержано. Пропускаем, а не считаем ошибкой — иначе
     * соединение падало бы через минуту после установки. */
    if (inner == 0x16) return 0;
    if (inner == 0x15) return TLS13_ECLOSED;   /* alert */
    if (inner != 0x17) return 0;
    if (pt == 0) return 0;                     /* пустая запись — законная набивка Vision */

    if (pt > cap) return TLS13_ETOOBIG;
    memcpy(out, rec, pt);
    *got = pt;
    return 0;
}
