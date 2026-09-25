/* Построитель сообщений netlink в плоском буфере — общий для резолвера (nfnetlink: элементы
 * наборов, ctnetlink) и выхода kind=awg (rtnetlink и generic netlink AmneziaWG/WireGuard).
 *
 * ПОЧЕМУ ОБЩИЙ ФАЙЛ, а не вторая копия в awg.c. Разметка атрибута netlink — длина с
 * заголовком, тип, выравнивание на четыре байта, флаг вложенности — это ровно то место, где
 * копия расходится с оригиналом молча: ошибка на байт в выравнивании даёт сообщение, которое
 * ядро разбирает как ДРУГОЕ (следующий атрибут читается со сдвигом), и отвечает на него не
 * отказом, а чем-нибудь правдоподобным. Одна реализация проверяется двумя потребителями и
 * тремя стендами (dnsmatch, ctnl49, awgmatch) — копия проверялась бы одним.
 *
 * Функции static inline: заголовок включают несколько единиц трансляции, и каждой нужна
 * своя копия без внешних символов (движок собирается одним вызовом компилятора из списка
 * файлов, и стенды включают исходники целиком — внешнее имя здесь дало бы двойное
 * определение). Неиспользованная inline-функция предупреждения -Wunused не даёт.
 *
 * Семантика прежняя, из dnsd.c: переполнение буфера не пишет за край, а тихо не добавляет
 * атрибут — вызывающий обязан сверить итоговую длину с ожидаемой (так делает резолвер) или
 * проверить nlbuf_overflow (так делает awg.c, где сообщение собирается из файла человека и
 * размер заранее не известен). */
#ifndef STEER_NLBUF_H
#define STEER_NLBUF_H
#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <arpa/inet.h>
#include <linux/netlink.h>

/* NLA_F_NESTED, NLA_HDRLEN, NLA_ALIGN come from <linux/netlink.h>. */
struct nlbuf {
    uint8_t *base;    /* start of nlmsghdr */
    uint8_t *p;       /* next write position */
    uint8_t *end;     /* one past last writable byte */
    int overflow;     /* атрибут не влез — сообщение неполное, отправлять нельзя */
};

static inline void nlbuf_init(struct nlbuf *b, void *mem, size_t cap) {
    b->base = mem; b->p = mem; b->end = (uint8_t *)mem + cap; b->overflow = 0;
}

static inline struct nlattr *nlbuf_reserve(struct nlbuf *b, uint16_t type, size_t pay_len) {
    size_t aligned = (NLA_HDRLEN + pay_len + 3) & ~(size_t)3;
    /* Длина атрибута — 16 бит: полезная нагрузка больше 65531 байта не выражается вовсе, и
     * усечение дало бы атрибут, который ядро читает короче, а хвост — как следующие
     * атрибуты. Такой атрибут не пишется, как и не влезший в буфер. */
    if (NLA_HDRLEN + pay_len > 0xffff || (size_t)(b->end - b->p) < aligned) {
        b->overflow = 1;
        return NULL;
    }
    struct nlattr *a = (struct nlattr *)b->p;
    a->nla_len = (uint16_t)(NLA_HDRLEN + pay_len);
    a->nla_type = type;
    /* Хвост выравнивания — нулями: ядро его не читает, но в буфере мог остаться прежний
     * запрос, в том числе с ключом, и отдавать ядру чужие байты незачем. */
    if (aligned > NLA_HDRLEN + pay_len)
        memset(b->p + NLA_HDRLEN + pay_len, 0, aligned - NLA_HDRLEN - pay_len);
    b->p += aligned;
    return a; /* caller writes payload into (a+1) immediately */
}
/* Scalar nf_tables attributes are BIG-ENDIAN on the wire: the kernel parses
 * NFTA_SET_ELEM_TIMEOUT with nla_get_be64(). Writing host order on a
 * little-endian box turned a 60000ms timeout into an astronomically large value,
 * and nf_msecs_to_jiffies64() rejected it with -ERANGE — which is exactly why
 * inserts into the timeout-flagged VPN/direct sets failed while the map (which
 * carries no timeout) succeeded. Confirmed on the test router: ack error=-34 for
 * the set, error=0 for the map, same code path otherwise. */
static inline void nlbuf_put_be32(struct nlbuf *b, uint16_t type, uint32_t v) {
    struct nlattr *a = nlbuf_reserve(b, type, 4);
    if (!a) return;
    uint32_t be = htonl(v);
    memcpy(a + 1, &be, 4);
}

static inline void nlbuf_put_be64(struct nlbuf *b, uint16_t type, uint64_t v) {
    struct nlattr *a = nlbuf_reserve(b, type, 8);
    if (!a) return;
    uint8_t be[8];
    for (int i = 0; i < 8; i++) be[i] = (uint8_t)(v >> (56 - 8 * i));
    memcpy(a + 1, be, 8);
}
static inline void nlbuf_put_str(struct nlbuf *b, uint16_t type, const char *s) {
    size_t n = strlen(s) + 1;
    struct nlattr *a = nlbuf_reserve(b, type, n);
    if (a) memcpy(a + 1, s, n);
}
/* Fixed binary blob (e.g. a 4-byte IPv4 key). */
static inline void nlbuf_put_data(struct nlbuf *b, uint16_t type, const void *d, size_t n) {
    struct nlattr *a = nlbuf_reserve(b, type, n);
    if (a && n) memcpy(a + 1, d, n);
}
/* Целые В ПОРЯДКЕ ХОСТА — так их ждут rtnetlink и generic netlink (NLA_U8/U16/U32/U64 ядро
 * читает nla_get_u32 и соседями, без перестановки байт). Отдельные функции, а не put_data с
 * адресом переменной на месте вызова: ширина атрибута — часть его типа в политике ядра, и
 * u16, записанный четырьмя байтами, на ядрах со строгой проверкой отвергается, а на старых
 * читается по младшим байтам — то есть на одной машине работает, на другой нет. */
static inline void nlbuf_put_u8(struct nlbuf *b, uint16_t type, uint8_t v) {
    nlbuf_put_data(b, type, &v, 1);
}
static inline void nlbuf_put_u16(struct nlbuf *b, uint16_t type, uint16_t v) {
    nlbuf_put_data(b, type, &v, 2);
}
static inline void nlbuf_put_u32(struct nlbuf *b, uint16_t type, uint32_t v) {
    nlbuf_put_data(b, type, &v, 4);
}
static inline void nlbuf_put_u64(struct nlbuf *b, uint16_t type, uint64_t v) {
    nlbuf_put_data(b, type, &v, 8);
}
/* Атрибут-флаг (NLA_FLAG): одно присутствие, без полезной нагрузки. */
static inline void nlbuf_put_flag(struct nlbuf *b, uint16_t type) {
    (void)nlbuf_reserve(b, type, 0);
}
/* Begin a nested attribute; returns an opaque cookie (the nlattr*) to pass to
 * nlbuf_end_nested(), which backpatches nla_len with the filled size. */
static inline struct nlattr *nlbuf_begin_nested(struct nlbuf *b, uint16_t type) {
    struct nlattr *a = nlbuf_reserve(b, type | NLA_F_NESTED, 0);
    return a; /* nla_len currently == NLA_HDRLEN; end_nested fixes it */
}
static inline void nlbuf_end_nested(struct nlbuf *b, struct nlattr *outer) {
    if (!outer) return;   /* начало не влезло — nlbuf_overflow уже поднят */
    size_t len = (size_t)(b->p - (uint8_t *)outer);
    if (len > 0xffff) { b->overflow = 1; return; }
    outer->nla_len = (uint16_t)len;
}

#endif
