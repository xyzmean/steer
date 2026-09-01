/* xsteer: поддельное TCP-соединение. Что здесь есть и чего нет — в xsconn.h. */
#define _GNU_SOURCE
#include <errno.h>
#include <string.h>
#include <time.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <ifaddrs.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/socket.h>

#include "xsconn.h"
#include "reality.h"     /* xc_random */

#define TH_FIN 0x01
#define TH_SYN 0x02
#define TH_RST 0x04
#define TH_PSH 0x08
#define TH_ACK 0x10
#define XSC_WIN 65535

/* Своя структура заголовка, а не системная: имена полей в <netinet/tcp.h> зависят от libc и
 * от feature-макросов, и один и тот же файл собирался бы по-разному под glibc и musl. Тот же
 * довод, что записан в obfs.c. */
struct xsc_tcp {
    uint16_t sport, dport;
    uint32_t seq, ack;
    uint8_t  off, flags;
    uint16_t win, sum, urp;
};

/* Монотонные часы, а не стенные: ntp на роутере прыгает при первой синхронизации после
 * загрузки, и «тишина три секунды» случилась бы на ровном месте. */
long long xs_now_ms(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (long long)ts.tv_sec * 1000 + ts.tv_nsec / 1000000;
}

/* MTU интерфейса, через который мы уходим к той стороне. Нужен, чтобы предел MTU туннеля считался
 * от настоящего канала, а не от предположения «1500».
 *
 * Зачем это отдельной функцией. Замер на живом роутере: канал PPPoE с MTU 1492, а проверка
 * движка сравнивала MTU туннеля с 1439 — пределом для канала 1500. Значит настройка 1431,
 * которая для PPPoE как раз верна, проходила без замечаний, а настройка 1439 (по нашему же
 * умолчанию) была бы уже велика — и большие пакеты пропадали бы молча.
 *
 * Ищем по адресу, который ядро выбрало источником для сокета к хабу: он принадлежит ровно
 * тому интерфейсу, через который мы уходим, и спрашивать таблицу маршрутизации не нужно. */
int xs_egress_mtu(uint32_t saddr, char *ifname, size_t ifn) {
    struct ifaddrs *list = NULL;
    if (getifaddrs(&list) != 0) return 0;
    int mtu = 0;
    for (struct ifaddrs *a = list; a; a = a->ifa_next) {
        if (!a->ifa_addr || a->ifa_addr->sa_family != AF_INET) continue;
        if (((struct sockaddr_in *)a->ifa_addr)->sin_addr.s_addr != saddr) continue;
        char path[128], buf[32];
        snprintf(path, sizeof(path), "/sys/class/net/%.32s/mtu", a->ifa_name);
        FILE *f = fopen(path, "r");
        if (f) {
            if (fgets(buf, sizeof(buf), f)) mtu = atoi(buf);
            fclose(f);
        }
        if (ifname) snprintf(ifname, ifn, "%s", a->ifa_name);
        break;
    }
    freeifaddrs(list);
    return mtu;
}

static uint32_t rnd32(void) {
    uint32_t v = 0;
    if (xc_random((unsigned char *)&v, sizeof(v)) != 0) v = (uint32_t)xs_now_ms();
    return v;
}

/* Следующее объявляемое окно. Блуждание, а не случайное число: у настоящего приёмника окно ползёт
 * вверх и вниз небольшими шагами, потому что приложение читает данные порциями. Прыжки по всему
 * диапазону выглядели бы так же неестественно, как постоянное значение, только иначе. */
static uint16_t next_win(struct xs_conn *c) {
    if (!c->win) {   /* сессия хаба заводится через memset, окно там ещё не выбрано */
        c->wrnd = (uint64_t)(c->isn_tx ^ c->dport) * 6364136223846793005ULL + 1442695040888963407ULL;
        c->win = (uint16_t)(XSC_WIN_FLOOR + (c->wrnd >> 33) % (XSC_WIN_CEIL - XSC_WIN_FLOOR));
    }
    /* Шевелится только у ПРИНИМАЮЩЕЙ стороны: у отдающей приложение ничего не вычитывает, и
     * значение стоит почти неподвижно. Ровно так ведут себя настоящие стороны загрузки. */
    if (!c->win_fresh) return c->win;
    c->win_fresh = 0;
    c->wrnd = c->wrnd * 6364136223846793005ULL + 1442695040888963407ULL;
    int step = (int)((c->wrnd >> 35) % 97) - 48;            /* ±48 */
    int v = (int)c->win + step;
    if (v > XSC_WIN_CEIL) v = XSC_WIN_CEIL - (v - XSC_WIN_CEIL);
    if (v < XSC_WIN_FLOOR) v = XSC_WIN_FLOOR + (XSC_WIN_FLOOR - v);
    c->win = (uint16_t)v;
    return c->win;
}

/* Флаги сегмента данных: ACK всегда, PSH по политике настоящего стека — он означает «конец записи
 * приложения» и при потоковой передаче приходится примерно на каждый шестой сегмент. Мы не знаем,
 * будет ли за этим пакетом следующий, поэтому считаем сегменты; отдельно PSH ставится после ПАУЗЫ,
 * где запись действительно закончилась. */
static uint8_t next_flags(struct xs_conn *c, long long now) {
    if (now - c->last_tx >= 5) {
        c->psh_run = 0;
        return TH_PSH | TH_ACK;
    }
    if (++c->psh_run >= 6) {
        c->psh_run = 0;
        return TH_PSH | TH_ACK;
    }
    return TH_ACK;
}

/* Частичная сумма для сегментов, собранных из двух кусков: заголовок отдельно, часть записи
 * отдельно. Нужна потому, что obfs_tcp_csum требует непрерывный буфер, а мы нарочно не копируем. */
static uint32_t sum_partial(const uint8_t *p, size_t n) {
    uint32_t s = 0;
    size_t i = 0;
    for (; i + 1 < n; i += 2) s += ((uint32_t)p[i] << 8) | p[i + 1];
    if (i < n) s += (uint32_t)p[i] << 8;
    return s;
}

static uint16_t fold(uint32_t s) {
    while (s >> 16) s = (s & 0xFFFF) + (s >> 16);
    return (uint16_t)(~s & 0xFFFF);
}

int xs_conn_split_mm(struct xs_conn *c, const uint8_t *rec, size_t rec_len, size_t max_seg,
                     uint8_t hdrs[][20], struct iovec *iov, struct mmsghdr *mm,
                     size_t cap, long long now) {
    if (!max_seg) return -1;
    size_t segs = (rec_len + max_seg - 1) / max_seg;
    if (!segs || segs > cap) return -1;
    uint32_t seq = c->seq;
    for (size_t i = 0; i < segs; i++) {
        size_t off = i * max_seg;
        size_t n = rec_len - off;
        if (n > max_seg) n = max_seg;
        uint8_t *h = hdrs[i];
        memset(h, 0, 20);
        h[0] = (uint8_t)(c->sport >> 8); h[1] = (uint8_t)c->sport;
        h[2] = (uint8_t)(c->dport >> 8); h[3] = (uint8_t)c->dport;
        uint32_t s32 = seq + (uint32_t)off;
        h[4] = (uint8_t)(s32 >> 24); h[5] = (uint8_t)(s32 >> 16);
        h[6] = (uint8_t)(s32 >> 8);  h[7] = (uint8_t)s32;
        h[8] = (uint8_t)(c->ack >> 24); h[9] = (uint8_t)(c->ack >> 16);
        h[10] = (uint8_t)(c->ack >> 8); h[11] = (uint8_t)c->ack;
        h[12] = (uint8_t)((20 / 4) << 4);
        h[13] = next_flags(c, now);
        uint16_t w = next_win(c);
        h[14] = (uint8_t)(w >> 8); h[15] = (uint8_t)w;
        /* Сумма: псевдозаголовок, свой заголовок и часть записи. */
        uint32_t sum = sum_partial((const uint8_t *)&c->saddr, 4) +
                       sum_partial((const uint8_t *)&c->daddr, 4) +
                       6 + (uint32_t)(20 + n) +
                       sum_partial(h, 20) + sum_partial(rec + off, n);
        uint16_t ck = fold(sum);
        h[16] = (uint8_t)(ck >> 8); h[17] = (uint8_t)ck;
        iov[2 * i].iov_base = h;
        iov[2 * i].iov_len = 20;
        iov[2 * i + 1].iov_base = (void *)(uintptr_t)(rec + off);
        iov[2 * i + 1].iov_len = n;
        memset(&mm[i].msg_hdr, 0, sizeof(mm[i].msg_hdr));
        mm[i].msg_hdr.msg_iov = &iov[2 * i];
        mm[i].msg_hdr.msg_iovlen = 2;
    }
    c->seq += (uint32_t)rec_len;
    c->last_tx = now;
    if (rec_len) c->last_data_tx = now;
    c->last_ack = now;
    c->unacked = 0;
    return (int)segs;
}

int xs_conn_open(struct xs_conn *c, uint32_t daddr, int dport, int shard) {
    memset(c, 0, sizeof(*c));
    c->fd = -1;
    c->daddr = daddr;
    c->dport = (uint16_t)dport;
    /* Порт из эфемерного диапазона и новый на каждое подключение: прежняя запись conntrack
     * по дороге может ещё жить, и повтор порта выглядел бы для неё продолжением уже
     * закрытого потока.
     *
     * Младшие биты задаются, когда пир открывает несколько соединений: по ним хаб решает,
     * какому воркеру достанется соединение. Случайный порт при этом остаётся случайным во всех
     * остальных разрядах — на проводе он выглядит так же, как обычный эфемерный. */
    c->sport = (uint16_t)(32768 + (rnd32() % 28000));
    if (shard >= 0) c->sport = (uint16_t)((c->sport & ~(uint16_t)(XS_CONNS_MAX - 1)) |
                                          (uint16_t)(shard & (XS_CONNS_MAX - 1)));
    c->isn_tx = rnd32();
    c->seq = c->isn_tx;
    c->wrnd = (uint64_t)c->isn_tx * 6364136223846793005ULL + 1442695040888963407ULL;
    c->win = (uint16_t)(XSC_WIN_FLOOR + (c->wrnd >> 33) % (XSC_WIN_CEIL - XSC_WIN_FLOOR));
    c->born = c->last_rx = c->last_tx = c->last_data_tx = xs_now_ms();

    c->fd = obfs_raw_open(daddr, &c->saddr);
    if (c->fd < 0) return -1;
    /* Фильтр ставится ДО первого SYN: между socket() и настройкой очередь успевает набрать
     * чужого, и на нагруженном роутере это тысячи пакетов. */
    obfs_filter_quad(c->fd, daddr, c->dport, c->sport);
    if (xs_conn_send(c, TH_SYN, NULL, 0, OBFS_OPT_SCALE) != 0) { xs_conn_close(c); return -1; }
    c->state = XSC_SYN_SENT;
    c->syn_tries = 1;
    return 0;
}

void xs_conn_close(struct xs_conn *c) {
    if (c->fd >= 0) close(c->fd);
    c->fd = -1;
    c->state = XSC_CLOSED;
}

int xs_conn_send(struct xs_conn *c, uint8_t flags, const void *payload, size_t plen,
                 int with_mss) {
    uint8_t buf[60 + XS_MTU_DEF + XS_TAG + XS_REC_HDR];
    if (plen > sizeof(buf) - 60) return -1;
    size_t n = obfs_build(buf, c->saddr, c->daddr, c->sport, c->dport,
                          c->seq, c->ack, flags, with_mss, payload, plen);
    /* Объявляемое окно у служебных сегментов и коротких нагрузок такое же блуждающее, как у
     * данных: постоянное значение в подтверждениях выдало бы нас ровно так же, как в данных.
     * obfs_build ставит своё, поэтому поле и сумма правятся здесь. */
    {
        uint16_t w = next_win(c);
        buf[14] = (uint8_t)(w >> 8);
        buf[15] = (uint8_t)(w & 0xFF);
        buf[16] = buf[17] = 0;
        uint16_t ck = htons(obfs_tcp_csum(c->saddr, c->daddr, buf, n));
        memcpy(buf + 16, &ck, 2);
    }
    ssize_t sent = send(c->fd, buf, n, MSG_NOSIGNAL);
    /* Номер двигается ДАЖЕ при неудачной отправке — см. инвариант в xsconn.h. Датаграмма
     * потеряна, номер потрачен; вернуть его назад значило бы однажды повторить nonce. */
    c->seq += (uint32_t)plen;
    if (flags & TH_SYN) c->seq += 1;              /* SYN занимает один номер */
    c->last_tx = xs_now_ms();
    /* Нагрузка — это разговор, голое подтверждение — нет. См. last_data_tx в xsconn.h. */
    if (plen) c->last_data_tx = c->last_tx;
    if (flags & TH_ACK) { c->unacked = 0; c->last_ack = c->last_tx; }
    return sent < 0 ? -1 : 0;
}

uint8_t *xs_conn_ahead(struct xs_conn *c, uint8_t *row, size_t plen, size_t *seglen,
                       long long now) {
    uint8_t *seg = row + XS_HDR_ROOM - XS_REC_HDR - sizeof(struct xsc_tcp);
    struct xsc_tcp *t = (struct xsc_tcp *)seg;
    memset(t, 0, sizeof(*t));
    t->sport = htons(c->sport);
    t->dport = htons(c->dport);
    t->seq = htonl(c->seq);
    t->ack = htonl(c->ack);
    t->off = (uint8_t)((sizeof(*t) / 4) << 4);
    t->flags = next_flags(c, now);
    /* Окно объявляем максимальное. Само поле — те же 65535, но в SYN согласован МАСШТАБ
     * (OBFS_OPT_SCALE), поэтому для conntrack по дороге это 8 МиБ, а не 64 КиБ. Без
     * масштаба он ограничивал бы нас 64 килобайтами в полёте — то есть 10 Мбит/с на круге
     * 50 мс, что и было измерено на живом роутере до этой правки (см. obfs.h). */
    t->win = htons(next_win(c));
    *seglen = sizeof(*t) + plen;
    t->sum = htons(obfs_tcp_csum(c->saddr, c->daddr, seg, *seglen));
    c->seq += (uint32_t)plen;
    /* Время приходит СНАРУЖИ, одно на пачку: на mipsel в ядрах OpenWrt нет vDSO для
     * clock_gettime, это настоящий системный вызов на 1-3 мкс, и на каждом пакете при девяти
     * тысячах пакетов в секунду это проценты единственного ядра за метку, которая всё равно
     * измеряется с гранулярностью тика. Тот же довод, что у build_ahead в obfs.c. */
    c->last_tx = now;
    if (plen) c->last_data_tx = now;
    c->last_ack = now;
    c->unacked = 0;
    return seg;
}

int xs_conn_on_seg(struct xs_conn *c, const struct obfs_seg *s, long long now) {
    c->last_rx = now;
    c->stall = 0;
    if (s->flags & TH_RST) return -1;
    if (c->state == XSC_SYN_SENT) {
        if ((s->flags & (TH_SYN | TH_ACK)) != (TH_SYN | TH_ACK)) return 0;
        c->isn_rx = s->seq;
        c->ack = s->seq + 1;
        c->state = XSC_EST;
        /* Подтверждаем рукопожатие сразу: без этого хаб не считает соединение
         * установившимся и будет повторять SYN-ACK. */
        xs_conn_send(c, TH_ACK, NULL, 0, 0);
        return 0;
    }
    if (c->state == XSC_SYN_RCVD && (s->flags & TH_ACK)) c->state = XSC_EST;
    if (!s->plen || c->state != XSC_EST) return 0;
    c->ack = obfs_next_ack(c->ack, s->seq, s->plen);
    c->unacked++;
    c->rx_since_ack++;
    /* Окно шевелим раз в восемь принятых сегментов: настоящий приёмник меняет его, когда
     * приложение вычитало порцию, а не на каждый пакет (см. xsconn.h). */
    if (++c->rx_total % 8 == 0) c->win_fresh = 1;
    /* ГОЛОЕ подтверждение отправляется ЗДЕСЬ, а не по таймеру. Таймер тикает раз в двадцать
     * миллисекунд, то есть даёт не больше пятидесяти подтверждений в секунду, а принимаем мы при
     * загрузке пятьдесят тысяч сегментов в секунду — по таймеру их выходило восемь штук на восемь
     * мегабайт, и признак «туннель, а не загрузка» оставался на месте. */
    if (c->rx_since_ack >= XSC_ACK_BARE) {
        struct timespec ts;
        clock_gettime(CLOCK_MONOTONIC, &ts);
        long long ns = (long long)ts.tv_sec * 1000000000LL + ts.tv_nsec;
        if (ns - c->last_bare_ns >= XSC_ACK_BARE_GAP_NS) {
            xs_conn_send(c, TH_ACK, NULL, 0, 0);
            c->rx_since_ack = 0;
            c->last_bare_ns = ns;
        }
    }
    return 1;
}

int xs_conn_tick(struct xs_conn *c, long long now, int sending) {
    /* Сколько времени за текущую тишину не работали МЫ. Считается здесь, потому что tick — это и
     * есть тот самый цикл: если его не вызывали, значит поток не исполнялся. */
    /* ДВА вида не нашей тишины, и оба обязаны вычитаться из порога.
     *
     * Первый — нас не исполняли: перерыв между вызовами больше XSC_STALL_GAP_MS означает, что
     * потоку не давали процессор. Ради него этот учёт и заводился.
     *
     * Второй — НАМ БЫЛО НЕЧЕГО СКАЗАТЬ (sending == 0). Пока мы молчим, путь не обязан отвечать
     * ничем, и это время такая же не наша тишина, как первая. Без этого вычета покой дольше
     * порога убивал соединение ПЕРВЫМ ЖЕ тиком после того, как отправлять снова стало что: вся
     * тишина уже была накоплена на покое, и хаб не получал на круг ни миллисекунды. На живой
     * связи роутер↔VPS это выглядело как переподъём каждые пятнадцать-двадцать пять секунд, и
     * тем чаще, чем МЕНЬШЕ шло трафика (пир говорит раз в двадцать пять секунд по
     * PersistentKeepalive, а хаб на покое молчит сам). В пространствах имён и в стенде такого
     * покоя не бывает — трафик там идёт непрерывно, — поэтому поймано это только вживую. */
    if (c->tick_at) {
        long long gap = now - c->tick_at;
        if (gap > XSC_STALL_GAP_MS || !sending) c->stall += gap;
    }
    c->tick_at = now;
    if (c->state == XSC_SYN_SENT) {
        if (now - c->last_tx >= XSC_SYN_RETRY_MS) {
            if (c->syn_tries >= XSC_SYN_RETRIES) return 1;
            /* Повтор ТОГО ЖЕ SYN: номер уже потрачен на первую попытку, поэтому откатываем
             * его на единицу перед отправкой — это единственное место, где номер идёт назад,
             * и оно безопасно, потому что нагрузки в SYN нет и nonce из него не выводится. */
            c->seq -= 1;
            xs_conn_send(c, TH_SYN, NULL, 0, OBFS_OPT_SCALE);
            c->syn_tries++;
        }
        return 0;
    }
    if (c->state != XSC_EST) return 0;
    /* Отложенное подтверждение: через XSC_ACK_SEGS принятых сегментов или по времени. */
    if (c->unacked && (c->unacked >= XSC_ACK_SEGS || now - c->last_ack >= XSC_ACK_MS))
        xs_conn_send(c, TH_ACK, NULL, 0, 0);
    /* Мёртвый путь считается ТОЛЬКО при активной отправке: молчание на покое — это покой, а
     * не поломка, и поднимать из-за него соединение заново значило бы дёргать туннель на
     * простое. */
    if (sending && now - c->last_rx - c->stall > XSC_DEAD_MS) return 1;
    return 0;
}
