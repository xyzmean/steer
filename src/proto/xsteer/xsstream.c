/* Записи по настоящему потоку TCP: буфер чтения, досылка хвоста, смещения. Почему это
 * отдельный файл от xswire.c — потому что там нет ни одного системного вызова нарочно (его
 * стенд собирается без библиотек и без сети), а здесь сокет и есть предмет. */
#define _GNU_SOURCE
#include <errno.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/types.h>

#include "xsstream.h"

void xs_stream_init(struct xs_stream *st, int fd) {
    memset(st, 0, sizeof(*st));
    st->fd = fd;
    /* С единицы: нулевое смещение занято подтверждением рукопожатия. */
    st->tx_off = st->rx_off = 1;
}

/* ---- отправка --------------------------------------------------------------- */

/* Один write без разбора причин: сколько ушло, столько ушло. Разбирать причины — дело
 * вызывающего, потому что решение у него разное: «переполнилась очередь» это норма под
 * нагрузкой, а «обрыв» — конец соединения. */
static ssize_t st_write(struct xs_stream *st, const uint8_t *b, size_t n) {
    for (;;) {
        ssize_t r = send(st->fd, b, n, MSG_NOSIGNAL);
        if (r >= 0) return r;
        if (errno == EINTR) continue;
        if (errno == EAGAIN || errno == EWOULDBLOCK) return 0;
        st->dead = 1;
        return -1;
    }
}

int xs_stream_flush(struct xs_stream *st) {
    if (st->dead) return -1;
    while (st->wn > st->woff) {
        ssize_t r = st_write(st, st->wpend + st->woff, st->wn - st->woff);
        if (r < 0) return -1;
        if (r == 0) return 0;
        st->woff += (size_t)r;
    }
    st->wn = st->woff = 0;
    return 1;
}

int xs_stream_send(struct xs_stream *st, const uint8_t *rec, size_t n) {
    if (st->dead) return -1;
    if (!n || n > XS_STREAM_REC_MAX) return -1;
    int f = xs_stream_flush(st);
    if (f < 0) return -1;
    if (f == 0) return -2;                       /* прошлая запись ещё в дороге */
    ssize_t r = st_write(st, rec, n);
    if (r < 0) return -1;
    /* Смещение двигается на ВСЮ запись сразу, даже если ушла половина: запись уже отдана
     * потоку, её место в нём определено, а хвост уедет раньше любой следующей. Считать по
     * фактически отправленным байтам значило бы, что смещение зависит от размера очереди
     * сокета, — и стороны разъехались бы на первом же переполнении. */
    st->tx_off += n;
    if ((size_t)r < n) {
        memcpy(st->wpend, rec + r, n - (size_t)r);
        st->wn = n - (size_t)r;
        st->woff = 0;
    }
    return 0;
}

int xs_stream_write_raw(struct xs_stream *st, const uint8_t *b, size_t n) {
    if (st->dead) return -1;
    size_t off = 0;
    int spins = 0;
    while (off < n) {
        ssize_t r = st_write(st, b + off, n - off);
        if (r < 0) return -1;
        if (r == 0) {
            /* Очередь сокета переполнена на РУКОПОЖАТИИ. Это почти невозможно (записи
             * рукопожатия — два килобайта на пустом соединении), поэтому здесь не цикл с
             * poll, а предел попыток: висеть в надежде на место в очереди хуже, чем
             * признать соединение негодным и поднять его заново. */
            if (++spins > 64) { st->dead = 1; return -1; }
            continue;
        }
        spins = 0;
        off += (size_t)r;
    }
    st->tx_off += n;
    return 0;
}

/* ---- приём ------------------------------------------------------------------ */

/* Освободить место в конце буфера, сдвинув неразобранный остаток к началу.
 *
 * Условие сдвига — «в хвосте меньше места, чем одна запись целиком»: тогда любой peek на
 * запись гарантированно выполним, а сдвигать приходится редко (раз на 64 КБ потока) и
 * недорого (остаток меньше записи). */
static void st_compact(struct xs_stream *st) {
    if (st->roff == 0) return;
    size_t left = st->rn - st->roff;
    if (left) memmove(st->rbuf, st->rbuf + st->roff, left);
    st->rn = left;
    st->roff = 0;
}

/* Взять у сокета всё, что есть. 1 — что-то добавилось, 0 — пусто, -1 — обрыв. */
static int st_fill(struct xs_stream *st) {
    if (XS_STREAM_RBUF - st->rn < XS_STREAM_REC_MAX) st_compact(st);
    if (st->rn >= XS_STREAM_RBUF) return 0;
    for (;;) {
        ssize_t r = recv(st->fd, st->rbuf + st->rn, XS_STREAM_RBUF - st->rn, 0);
        if (r > 0) { st->rn += (size_t)r; return 1; }
        if (r == 0) { st->dead = 1; return -1; }      /* сторона закрыла соединение */
        if (errno == EINTR) continue;
        if (errno == EAGAIN || errno == EWOULDBLOCK) return 0;
        st->dead = 1;
        return -1;
    }
}

int xs_stream_peek(struct xs_stream *st, size_t n, const uint8_t **p) {
    if (st->dead) return -1;
    if (!n || n > XS_STREAM_REC_MAX) return -1;
    while (st->rn - st->roff < n) {
        int f = st_fill(st);
        if (f < 0) return -1;
        if (f == 0) return 0;
    }
    *p = st->rbuf + st->roff;
    return 1;
}

void xs_stream_drop(struct xs_stream *st, size_t n) {
    size_t left = st->rn - st->roff;
    if (n > left) n = left;
    st->roff += n;
    st->rx_off += n;
    if (st->roff == st->rn) st->rn = st->roff = 0;
}

int xs_stream_recv(struct xs_stream *st, const uint8_t **hdr, const uint8_t **body,
                   size_t *body_n, uint64_t *rel) {
    const uint8_t *h;
    int rc = xs_stream_peek(st, XS_REC_HDR, &h);
    if (rc <= 0) return rc;
    /* Проверка формы ДО длины: чужой или испорченный поток не должен даже заявить размер.
     * Разбор здесь свой, а не xs_rec_parse: тот требует, чтобы запись занимала сегмент
     * ровно (одна датаграмма — одна запись), а в потоке за записью сразу лежит следующая. */
    if (h[0] != XS_REC_TYPE || h[1] != XS_REC_V0 || h[2] != XS_REC_V1) return -2;
    size_t n = ((size_t)h[3] << 8) | h[4];
    /* Пустая запись (keepalive) это тег без нагрузки, то есть ровно XS_TAG. Меньше — не наша
     * запись; больше предела — тоже: восемь килобайт пишет в одну запись настоящий xhttp, и
     * принимать больше значило бы принимать то, чего сами не отправляем. */
    if (n < XS_TAG || n > XS_MAX_RECORD + XS_TAG) return -2;
    rc = xs_stream_peek(st, XS_REC_HDR + n, &h);
    if (rc <= 0) return rc;
    *rel = st->rx_off;
    *hdr = h;
    *body = h + XS_REC_HDR;
    *body_n = n;
    /* Байты забраны СРАЗУ, до расшифровки: указатели остаются годными до следующего чтения
     * (сдвиг буфера делает только st_fill), а «забрать после успеха» означало бы, что
     * неудачная расшифровка оставляет запись в буфере и следующий вызов читает её снова. */
    xs_stream_drop(st, XS_REC_HDR + n);
    return 1;
}
