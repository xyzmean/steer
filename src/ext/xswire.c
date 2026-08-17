/* xsteer: арифметика провода. Почему это отдельный файл без mbedtls — в xswire.h. */
#include "xswire.h"
#include <stdio.h>

/* Версия в заголовке записи — 0x0303, то есть «TLS 1.2», и это не ошибка. TLS 1.3 сам
 * ставит в записях именно её ради посредников, которые не понимают версию 1.3 и рвут
 * такие потоки; настоящая версия согласуется расширением внутри рукопожатия. Поставить
 * здесь 0x0304 значило бы отличаться от всякого настоящего TLS 1.3 на проводе первым же
 * байтом каждой записи. */
#define XS_REC_TYPE 0x17
#define XS_REC_V0   0x03
#define XS_REC_V1   0x03

int xs_rec_build(uint8_t *hdr, size_t body_n) {
    if (body_n < XS_TAG || body_n > 0xFFFF) return -1;
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
