/* xsteer: арифметика провода. Почему это отдельный файл без mbedtls — в xswire.h. */
#include "xswire.h"
#include <stdio.h>

/* Версия в заголовке записи — 0x0303, то есть «TLS 1.2», и это не ошибка. TLS 1.3 сам
 * ставит в записях именно её ради посредников, которые не понимают версию 1.3 и рвут
 * такие потоки; настоящая версия согласуется расширением внутри рукопожатия. Поставить
 * здесь 0x0304 значило бы отличаться от всякого настоящего TLS 1.3 на проводе первым же
 * байтом каждой записи. */
int xs_rec_build(uint8_t *hdr, size_t body_n) {
    /* Предел ФОРМАТА, а не предел ПОЛЯ: записей длиннее XS_MAX_RECORD мы не отправляем никогда, и
     * приёмники (xs_reasm_feed, xs_stream_read_record) проверяют ровно этим числом. Пока здесь
     * стояло 0xFFFF, переполнение набора кадров доезжало до провода и обрывало соединение у
     * получателя вместо того, чтобы отказать у отправителя. */
    if (body_n < XS_TAG || body_n > XS_MAX_RECORD) return -1;
    hdr[0] = XS_REC_TYPE;
    hdr[1] = XS_REC_V0;
    hdr[2] = XS_REC_V1;
    hdr[3] = (uint8_t)(body_n >> 8);
    hdr[4] = (uint8_t)(body_n & 0xFF);
    return 0;
}

int xs_rec_parse(const uint8_t *seg, size_t n, const uint8_t **body, size_t *body_n) {
    if (n < XS_REC_MIN) return -1;
    if (seg[0] != XS_REC_TYPE || seg[1] != XS_REC_V0 || seg[2] != XS_REC_V1) return -1;
    size_t len = ((size_t)seg[3] << 8) | seg[4];
    /* РОВНО остаток сегмента, а не «не больше». Одна датаграмма — одна запись, и запись,
     * заявившая меньше, чем лежит в сегменте, означала бы поток: там, где потока нет, это
     * либо чужой пакет, либо попытка спрятать за концом записи что-то ещё. */
    if (len != n - XS_REC_HDR) return -1;
    if (len < XS_TAG) return -1;
    *body = seg + XS_REC_HDR;
    *body_n = len;
    return 0;
}

int xs_win_check(const struct xs_win *w, uint32_t rel) {
    /* Нулевое смещение не бывает данными: начальный номер занят самим SYN, поэтому первая
     * запись начинается с единицы. Заодно это позволяет нулём обозначать «ещё ничего не
     * принято» и не держать отдельный признак. */
    if (!rel) return -1;
    /* Знаковая разность — то же понятие «позже», что в obfs_next_ack. Одно сравнение
     * закрывает подавляющую часть пакетов: они идут по порядку. */
    if ((int32_t)(rel - w->max) > 0) return 0;
    unsigned have = w->n;
    if (have == XS_WIN_RING) {
        /* Кольцо обернулось: старейшее помнимое лежит там, куда сейчас писать. Всё, что
         * старше него, отвергаем — не потому, что это точно повтор, а потому, что
         * проверить нечем, а пропустить непроверенное здесь нельзя. */
        if ((int32_t)(rel - w->ring[w->head]) < 0) return -1;
    }
    for (unsigned i = 0; i < have; i++)
        if (w->ring[i] == rel) return -1;
    return 0;
}

void xs_win_commit(struct xs_win *w, uint32_t rel) {
    w->ring[w->head] = rel;
    w->head = (uint16_t)((w->head + 1) % XS_WIN_RING);
    if (w->n < XS_WIN_RING) w->n++;
    if ((int32_t)(rel - w->max) > 0) w->max = rel;
}

/* ---- согласование MTU ------------------------------------------------------ */

int xs_mtu_next(int lo, int hi, int ceiling) {
    if (ceiling > XS_MTU_DEF) ceiling = XS_MTU_DEF;
    if (lo < XS_MTU_FLOOR) lo = XS_MTU_FLOOR;
    if (ceiling <= lo) return 0;                 /* потолок не выше низа — проверять нечего */
    if (hi <= 0) return ceiling;                 /* ещё не знаем верхней границы: пробуем потолок */
    if (hi > ceiling) hi = ceiling;
    if (hi - lo <= XS_MTU_GRAIN) return 0;       /* сошлось */
    return lo + (hi - lo) / 2;
}

int xs_probe_build(uint8_t *pt, size_t cap, int size) {
    if (size < 4 || (size_t)size > cap || size > XS_MTU_DEF) return -1;
    pt[0] = XS_CTL_PROBE;
    pt[1] = (uint8_t)(size >> 8);
    pt[2] = (uint8_t)(size & 0xFF);
    /* Набивка нулями, а не случайными байтами: проба всё равно уходит под AEAD, снаружи её
     * не отличить от данных, а нули не требуют источника случайности на каждый кадр. */
    memset(pt + 3, 0, (size_t)size - 3);
    return size;
}

int xs_probe_size(const uint8_t *pt, size_t n) {
    if (n < 3 || pt[0] != XS_CTL_PROBE) return -1;
    int size = (pt[1] << 8) | pt[2];
    /* Заявленный размер обязан совпасть с фактическим: иначе это не проба пути, а кадр,
     * который прикидывается ею — и эхо на него сообщило бы неправду о том, что путь несёт. */
    if ((size_t)size != n) return -1;
    return size;
}

size_t xs_pack_build(uint8_t *pt, size_t cap, int size) {
    if (cap < 3) return 0;
    pt[0] = XS_CTL_PACK;
    pt[1] = (uint8_t)(size >> 8);
    pt[2] = (uint8_t)(size & 0xFF);
    return 3;
}

int xs_pack_size(const uint8_t *pt, size_t n) {
    if (n < 3 || pt[0] != XS_CTL_PACK) return -1;
    return (pt[1] << 8) | pt[2];
}

size_t xs_mtu_build(uint8_t *pt, size_t cap, int mtu) {
    if (cap < 3) return 0;
    pt[0] = XS_CTL_MTU;
    pt[1] = (uint8_t)(mtu >> 8);
    pt[2] = (uint8_t)(mtu & 0xFF);
    return 3;
}

int xs_mtu_value(const uint8_t *pt, size_t n) {
    if (n < 3 || pt[0] != XS_CTL_MTU) return -1;
    return (pt[1] << 8) | pt[2];
}

/* ---- ограничитель частоты сообщений ---------------------------------------- */

int xs_ratelog(struct xs_ratelog *r, long long now, long long every_ms, unsigned long long *held) {
    if (r->last && now - r->last < every_ms) {
        r->held++;
        return 0;
    }
    *held = r->held;
    r->held = 0;
    /* Время печати запоминается, даже если печатать нечего было бы: иначе первая же пауза
     * длиннее окна открывала бы поток заново на каждый пакет. */
    r->last = now ? now : 1;
    return 1;
}

const char *xs_held_str(unsigned long long held, char *buf, size_t cap) {
    if (!held) return "";
    snprintf(buf, cap, " (и ещё %llu таких же за последние %d с)", held, XS_LOG_EVERY_MS / 1000);
    return buf;
}

/* ---- пачка кадров и сборка разрезанной записи -------------------------------
 * Зачем это всё нужно и чем оплачено — в xswire.h. */

size_t xs_batch_build(uint8_t *dst, size_t cap, const struct xs_frame *fr, size_t n) {
    if (n < 2) return 0;                       /* одиночный кадр едет без контейнера */
    size_t need = XS_BATCH_HDR;
    for (size_t i = 0; i < n; i++) need += 2 + fr[i].n;
    /* Предел ОТКРЫТОГО текста, а не ёмкости буфера: буфер держит XS_MAX_RECORD+XS_TAG и
     * пропустил бы пачку, которую приёмник отвергнет по длине тела. */
    if (need > cap || need > XS_MAX_PLAIN) return 0;
    dst[0] = XS_CTL_BATCH;
    size_t o = XS_BATCH_HDR;
    for (size_t i = 0; i < n; i++) {
        dst[o] = (uint8_t)(fr[i].n >> 8);
        dst[o + 1] = (uint8_t)(fr[i].n & 0xFF);
        memcpy(dst + o + 2, fr[i].p, fr[i].n);
        o += 2 + fr[i].n;
    }
    return o;
}

int xs_batch_iter(const uint8_t *pt, size_t n,
                  void (*fn)(void *ctx, const uint8_t *frame, size_t flen), void *ctx) {
    if (n < XS_BATCH_HDR || pt[0] != XS_CTL_BATCH) return -1;
    /* ПЕРВЫЙ проход — только проверка: пройти цепочку длин до конца и не вызвать ничего. Иначе
     * «отвергается целиком» из заголовка не выполняется: кадры до места порчи уже доставлены к
     * моменту, когда возвращается -1, а отменить доставленное вызывающему нечем — все четыре
     * потребителя на -1 умеют только увеличить счётчик (I-063). Контейнер целиком лежит в
     * памяти и не длиннее XS_MAX_RECORD, поэтому второй проход стоит одно сложение и одно
     * сравнение на кадр — ни аллокации, ни копии.
     *
     * Здесь же — предел на ЧИСЛО кадров. XS_BATCH_FRAMES_MAX до сих пор действовал только на
     * сборке, а на приёме контейнер на 8191 байт из однобайтовых кадров давал 2730 вызовов
     * обработчика. Законная пачка длиннее предела не бывает: и здесь, и в реализации на Go
     * набор кадров ограничен этой же константой (xsclient.c, xshub.c: batch_max никогда не
     * растёт выше неё), а сама константа равна восьми с первого дня формата — значит предел на
     * приёме не отвергнет ничего, собранного уже установленными версиями. */
    size_t frames = 0;
    for (size_t o = XS_BATCH_HDR; o < n; ) {
        if (o + 2 > n) return -1;
        size_t f = ((size_t)pt[o] << 8) | pt[o + 1];
        o += 2;
        if (!f || o + f > n) return -1;
        if (++frames > XS_BATCH_FRAMES_MAX) return -1;
        o += f;
    }
    /* ВТОРОЙ проход — доставка. Проверок здесь уже нет: цепочка длин пройдена целиком выше. */
    for (size_t o = XS_BATCH_HDR; o < n; ) {
        size_t f = ((size_t)pt[o] << 8) | pt[o + 1];
        o += 2;
        fn(ctx, pt + o, f);
        o += f;
    }
    return 0;
}

size_t xs_loss_build(uint8_t *pt, size_t cap, int n) {
    if (cap < 3) return 0;
    if (n > 0xFFFF) n = 0xFFFF;
    pt[0] = XS_CTL_RLOSS;
    pt[1] = (uint8_t)(n >> 8);
    pt[2] = (uint8_t)(n & 0xFF);
    return 3;
}

int xs_loss_value(const uint8_t *pt, size_t n) {
    if (n < 3 || pt[0] != XS_CTL_RLOSS) return -1;
    return (pt[1] << 8) | pt[2];
}

int xs_reasm_feed(struct xs_reasm *r, uint32_t seq, uint32_t isn_rx,
                  const uint8_t *pl, size_t n,
                  const uint8_t **body, size_t *body_n, const uint8_t **hdr, uint32_t *rel,
                  size_t *used) {
    if (used) *used = n;                        /* по умолчанию нагрузка съедена целиком */
    if (r->active && seq == r->next_seq) {
        /* Берём РОВНО недостающий хвост записи, а не всю нагрузку: за концом записи в той же
         * нагрузке может лежать следующая (склейка GRO) — её разберёт следующий круг цикла. */
        size_t want = XS_REC_HDR + r->need - r->len;
        if (want > n) {
            if (r->len + n > sizeof(r->buf)) {  /* больше заявленного — не наш поток */
                r->active = 0;
                r->dropped++;
                return 0;
            }
            memcpy(r->buf + r->len, pl, n);
            r->len += n;
            r->next_seq = seq + (uint32_t)n;
            return 0;
        }
        if (r->len + want > sizeof(r->buf)) {
            r->active = 0;
            r->dropped++;
            return 0;
        }
        memcpy(r->buf + r->len, pl, want);
        r->len += want;
        r->active = 0;
        if (used) *used = want;
        *body = r->buf + XS_REC_HDR;
        *body_n = r->need;
        *hdr = r->buf;
        *rel = r->rel0;
        return 1;
    }
    if (r->active) {
        /* Продолжение не пришло: сегмент потерялся или приехал не по порядку. Незаконченное
         * выбрасываем — держать его дольше значило бы склеить чужие байты с нашими. Повторов у нас
         * нет и не будет, поэтому это просто потерянный внутренний пакет. */
        r->active = 0;
        r->dropped++;
    }
    if (n < XS_REC_MIN) return 0;
    if (pl[0] != XS_REC_TYPE || pl[1] != XS_REC_V0 || pl[2] != XS_REC_V1) return 0;
    size_t want = ((size_t)pl[3] << 8) | pl[4];
    if (want < XS_TAG || want > XS_MAX_RECORD) return 0;
    if (XS_REC_HDR + want <= n) {              /* целая запись; за ней в склейке может быть ещё */
        if (used) *used = XS_REC_HDR + want;
        *body = pl + XS_REC_HDR;
        *body_n = want;
        *hdr = pl;
        *rel = xs_rel(seq, isn_rx);
        return 1;
    }
    /* Начало разрезанной записи. */
    if (n > sizeof(r->buf)) return 0;
    memcpy(r->buf, pl, n);
    r->len = n;
    r->need = want;
    r->rel0 = xs_rel(seq, isn_rx);
    r->next_seq = seq + (uint32_t)n;
    r->active = 1;
    return 0;
}
