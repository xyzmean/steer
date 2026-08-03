/* Кольцо неподтверждённых байт. Зачем отдельным файлом — в rtx.h. */
#include <stdlib.h>
#include <string.h>

#include "rtx.h"

int rtx_init(struct rtx *r, uint32_t cap) {
    r->buf = malloc(cap);
    r->cap = cap;
    r->len = 0;
    r->head = 0;
    return r->buf ? 0 : -1;
}

void rtx_done(struct rtx *r) {
    free(r->buf);
    r->buf = NULL;
    r->cap = r->len = r->head = 0;
}

uint32_t rtx_room(const struct rtx *r) {
    return r->cap - r->len;
}

void rtx_push(struct rtx *r, const unsigned char *p, uint32_t n) {
    if (n > rtx_room(r)) return;            /* вызывающий проверил; молча не портим кольцо */
    uint32_t tail = r->head + r->len;
    if (tail >= r->cap) tail -= r->cap;     /* без % : cap не обязан быть степенью двойки,
                                             * а tail заведомо меньше двух cap */
    uint32_t first = r->cap - tail;
    if (first > n) first = n;
    memcpy(r->buf + tail, p, first);
    if (n > first) memcpy(r->buf, p + first, n - first);
    r->len += n;
}

uint32_t rtx_drop(struct rtx *r, uint32_t n) {
    if (n > r->len) n = r->len;
    r->head += n;
    if (r->head >= r->cap) r->head -= r->cap;
    r->len -= n;
    return n;
}

uint32_t rtx_peek(const struct rtx *r, uint32_t want, const unsigned char **p) {
    if (!r->len) { *p = NULL; return 0; }
    if (want > r->len) want = r->len;
    uint32_t contig = r->cap - r->head;
    if (want > contig) want = contig;
    *p = r->buf + r->head;
    return want;
}
