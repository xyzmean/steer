/* Разбор ClientHello. Почему только разбор и почему это граница доверия — в chello.h. */
#include <string.h>
#include "chello.h"

/* Курсор с проверкой границ на каждом шаге. Заведён потому, что альтернатива — считать
 * длины вручную в двух десятках мест, и ровно там появляется чтение за буфером: Hello
 * приходит от кого угодно, и «длина, которой доверились» здесь означает удалённое чтение
 * чужой памяти. */
struct cur { const uint8_t *p; size_t n, i; };

static int need(struct cur *c, size_t k) { return c->i + k <= c->n; }
static int u8(struct cur *c, unsigned *v) {
    if (!need(c, 1)) return -1;
    *v = c->p[c->i++];
    return 0;
}
static int u16(struct cur *c, unsigned *v) {
    if (!need(c, 2)) return -1;
    *v = ((unsigned)c->p[c->i] << 8) | c->p[c->i + 1];
    c->i += 2;
    return 0;
}
static int u24(struct cur *c, unsigned *v) {
    if (!need(c, 3)) return -1;
    *v = ((unsigned)c->p[c->i] << 16) | ((unsigned)c->p[c->i + 1] << 8) | c->p[c->i + 2];
    c->i += 3;
    return 0;
}
static int skip(struct cur *c, size_t k) {
    if (!need(c, k)) return -1;
    c->i += k;
    return 0;
}

int chello_parse(const uint8_t *rec, size_t n, struct chello_ref *out) {
    memset(out, 0, sizeof(*out));
    struct cur c = { rec, n, 0 };
    unsigned v;

    /* Запись рукопожатия. Версию записи не проверяем строго: настоящие клиенты ставят и
     * 0x0301, и 0x0303, и это ничего не значит. */
    if (u8(&c, &v) != 0 || v != 0x16) return -1;
    if (skip(&c, 2) != 0) return -1;
    if (u16(&c, &v) != 0) return -1;
    /* Запись обязана быть ЦЕЛОЙ и ровно такой, как заявлено: Hello в этом протоколе
     * приходит одним сегментом (он всегда меньше 1460 байт — проверено на SNI до 195
     * байт), поэтому «не хватает конца» здесь означает не поток, а брак. */
    if (5 + (size_t)v != n) return -1;

    /* Сообщение рукопожатия: тип 01 и длина 24 бита. Отсюда и до конца — то, по чему
     * считается AAD аутентификатора, поэтому смещение и длина сохраняются. */
    out->hs_off = c.i;
    if (u8(&c, &v) != 0 || v != 0x01) return -1;
    if (u24(&c, &v) != 0) return -1;
    if (c.i + v != n) return -1;
    out->hs_n = 4 + (size_t)v;

    if (skip(&c, 2) != 0) return -1;               /* legacy_version */
    if (skip(&c, 32) != 0) return -1;              /* random */

    if (u8(&c, &v) != 0) return -1;                /* legacy_session_id */
    /* Ровно 32 байта: именно столько занимает аутентификатор, и именно столько кладёт
     * всякий современный клиент. Другая длина — не наш собеседник. */
    if (v != 32) return -1;
    out->sid_off = c.i;
    if (skip(&c, 32) != 0) return -1;

    if (u16(&c, &v) != 0) return -1;               /* cipher_suites */
    if (v == 0 || (v & 1) || !need(&c, v)) return -1;
    size_t suites_end = c.i + v;
    while (c.i < suites_end) {
        unsigned s;
        if (u16(&c, &s) != 0) return -1;
        if (out->suite) continue;                  /* уже нашли — но список надо пройти */
        if (chello_is_grease((uint16_t)s)) continue;
        /* Наборы TLS 1.3: 0x1301..0x1305. Всё остальное (в том числе наборы 1.2, которые
         * браузер тоже перечисляет) нас не касается — согласуется только AEAD. */
        if (s >= 0x1301 && s <= 0x1305) out->suite = (uint16_t)s;
    }

    if (u8(&c, &v) != 0) return -1;                /* legacy_compression_methods */
    if (skip(&c, v) != 0) return -1;

    if (u16(&c, &v) != 0) return -1;               /* extensions */
    if (!need(&c, v)) return -1;
    size_t ext_end = c.i + v;

    while (c.i < ext_end) {
        unsigned type, len;
        if (u16(&c, &type) != 0 || u16(&c, &len) != 0) return -1;
        if (!need(&c, len) || c.i + len > ext_end) return -1;
        size_t body = c.i;

        if (type == 0x0000 && len >= 5) {          /* server_name */
            struct cur e = { rec, body + len, body };
            unsigned list_len, nt, nlen;
            if (u16(&e, &list_len) == 0 && u8(&e, &nt) == 0 && nt == 0 &&
                u16(&e, &nlen) == 0 && nlen < sizeof(out->sni) && need(&e, nlen)) {
                memcpy(out->sni, rec + e.i, nlen);
                out->sni[nlen] = '\0';
            }
        } else if (type == 0x0033 && len >= 6) {   /* key_share */
            struct cur e = { rec, body + len, body };
            unsigned shares_len;
            if (u16(&e, &shares_len) != 0) return -1;
            size_t shares_end = e.i + shares_len;
            if (shares_end > body + len) return -1;
            while (e.i < shares_end) {
                unsigned grp, klen;
                if (u16(&e, &grp) != 0 || u16(&e, &klen) != 0) return -1;
                if (!need(&e, klen)) return -1;
                /* GREASE-группа лежит в key_share первой и несёт один случайный байт —
                 * взять её за ключ значило бы не найти настоящий вовсе. */
                if (grp == CHELLO_GROUP_X25519 && klen == 32 && !out->ks_off)
                    out->ks_off = e.i;
                e.i += klen;
            }
        } else if (type == CHELLO_EXT_ECH) {
            /* Раскладка фальшивого ECH ровно та, что собирает reality.c: тип(1), kdf(2),
             * aead(2), номер конфигурации(1), длина enc(2) и enc, длина payload(2) и
             * payload. Нам нужен payload — в нём едет запечатанный статический ключ. */
            struct cur e = { rec, body + len, body };
            unsigned enc_len, pay_len, tmp;
            if (u8(&e, &tmp) == 0 && u16(&e, &tmp) == 0 && u16(&e, &tmp) == 0 &&
                u8(&e, &tmp) == 0 && u16(&e, &enc_len) == 0 && skip(&e, enc_len) == 0 &&
                u16(&e, &pay_len) == 0 && need(&e, pay_len)) {
                out->ech_off = e.i;
                out->ech_n = pay_len;
            }
        }
        c.i = body + len;
    }
    if (c.i != ext_end) return -1;
    /* Без ключа обмена разговаривать не о чем: это либо не TLS 1.3, либо не наш клиент. */
    if (!out->ks_off) return -1;
    return 0;
}
