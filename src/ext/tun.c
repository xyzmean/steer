/* TUN-устройство и пересылка пакетов через VLESS.
 *
 * Почему TUN, а не SOCKS. Выход steer описан как устройство (`kind: interface`), и весь
 * механизм — метки, таблицы маршрутизации, failover, каналы — уже умеет с устройствами
 * работать. TUN означает, что VLESS вписывается в модель без единого исключения: канал
 * ведёт в него так же, как в wireguard. SOCKS потребовал бы отдельного вида выхода,
 * прозрачного проксирования и правил REDIRECT — то есть второго способа делать то же.
 *
 * Что здесь происходит: из TUN приходят IP-пакеты целиком. Мы разбираем заголовок, для
 * каждого TCP-соединения открываем свой поток VLESS и дальше переносим байты между TUN и
 * потоком. Это и есть та часть, которую в готовых решениях называют «стеком»: ядро отдаёт
 * нам пакеты, а не соединения, и восстанавливать соединения приходится самим.
 *
 * Границы реализации названы честно:
 *   TCP  — работает: состояние соединения отслеживается, поток VLESS на соединение;
 *   UDP  — работает: поток VLESS на пару адрес-порт, датаграммы едут с двухбайтовой
 *          длиной (VLESS cmd=2). Этим же путём идут QUIC и WireGuard;
 *   ICMP — не пересылается: ping через прокси требует эмуляции, которая полезна только для
 *          диагностики, а вводит в заблуждение (успешный ping не означает рабочий путь).
 */
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <fcntl.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <linux/if.h>
#include <linux/if_tun.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <poll.h>
#include <sys/uio.h>

#include "tun.h"

/* Заголовок разгрузки virtio, тот самый, который принимает IFF_VNET_HDR.
 *
 * Объявлен здесь, а не взят из <linux/virtio_net.h>: тот тянет virtio_types и с musl
 * собирается не на всех версиях ядерных headers, а нам нужны ровно эти десять байт.
 *
 * Числа в ПОРЯДКЕ ХОСТА, а не в сетевом. Это не небрежность: tun согласовывает порядок
 * только через VIRTIO_F_VERSION_1, которого он не объявляет, поэтому ядро читает поля
 * как __virtio16 в legacy-режиме — то есть родным порядком. Среди целей сборки есть
 * mips_24kc, он big-endian; фиксированный little-endian сломал бы разгрузку именно на нём,
 * и выглядело бы это как «на одной архитектуре пакеты не доходят». */
struct vnet_hdr {
    uint8_t flags;
    uint8_t gso_type;
    uint16_t hdr_len;
    uint16_t gso_size;
    uint16_t csum_start;
    uint16_t csum_offset;
};
#define VNET_HDR_LEN 10
#define VNET_F_NEEDS_CSUM 1
#define VNET_GSO_NONE     0
#define VNET_GSO_TCPV4    1
/* Раскладка обязана совпасть с ядерной побайтово: лишний байт выравнивания сдвинул бы
 * всё, и ядро прочитало бы gso_size там, где лежит csum_start. */
typedef char vnet_hdr_size_check[sizeof(struct vnet_hdr) == VNET_HDR_LEN ? 1 : -1];

/* Одна попытка открыть очередь с заданным набором флагов.
 *
 * errno сохраняется в g_open_errno: перебор наборов флагов затирает его следующей попыткой,
 * а причина нужна именно от ПЕРВОЙ — она отвечает на вопрос «почему устройства нет вовсе»,
 * тогда как последняя расскажет лишь про отказ от последнего украшения. */
static int g_open_errno;
static int g_open_stage;      /* 1 — не открылся /dev/net/tun, 2 — отказал TUNSETIFF */

static int queue_open(const char *name, short flags) {
    int fd = open("/dev/net/tun", O_RDWR);
    if (fd < 0) {
        if (!g_open_errno) { g_open_errno = errno; g_open_stage = 1; }
        return -1;
    }
    struct ifreq ifr;
    memset(&ifr, 0, sizeof(ifr));
    snprintf(ifr.ifr_name, IFNAMSIZ, "%s", name);
    ifr.ifr_flags = flags;
    if (ioctl(fd, TUNSETIFF, &ifr) < 0) {
        if (!g_open_errno) { g_open_errno = errno; g_open_stage = 2; }
        close(fd);
        return -1;
    }
    return fd;
}

int tun_open(struct tun_dev *d, int max_queues, const char *name) {
    /* IFF_NO_PI: без 4-байтного префикса протокола. Он нужен только тому, кто хочет
     * различать семейства на одном устройстве, а у нас IPv4 и разбор всё равно по
     * заголовку пакета.
     *
     * IFF_VNET_HDR: разрешает писать в устройство сегмент больше MTU с пометкой «нарежь
     * по столько», а контрольную сумму TCP оставить недосчитанной.
     *
     * IFF_MULTI_QUEUE: несколько дескрипторов на одно устройство, по одному на поток.
     *
     * Порядок попыток — от лучшего к худшему, и каждая следующая отказывается ровно от
     * одного. Ядро без той или иной поддержки не должно ронять туннель: остаться без
     * УСКОРЕНИЯ можно, остаться без туннеля нельзя.
     *
     * TUNSETOFFLOAD мы НЕ вызываем, и это осознанно. Он описывает, что мы готовы принимать
     * ОТ ядра, то есть включил бы приход суперпакетов и в обратную сторону — а для них
     * пришлось бы всюду держать буферы по 64 КБ вместо 16. Отдача клиенту, где выигрыш и
     * лежит, от него не зависит: разгрузку на запись включает сам vnet_hdr. */
    short base = IFF_TUN | IFF_NO_PI;
    /* STEER_TUN_NOGSO отключает разгрузку принудительно. Нужно для замеров: «стало быстрее»
     * без возможности вернуться на прежний путь одной переменной — это утверждение, которое
     * нельзя перепроверить на том же железе и той же подписке. */
    int want_gso = getenv("STEER_TUN_NOGSO") == NULL;
    if (max_queues < 1) max_queues = 1;

    static const struct { int gso, multi; } order[] = {
        { 1, 1 }, { 1, 0 }, { 0, 1 }, { 0, 0 },
    };
    for (size_t i = 0; i < sizeof(order) / sizeof(*order); i++) {
        if (order[i].gso && !want_gso) continue;
        if (order[i].multi && max_queues < 2) continue;
        short flags = base;
        if (order[i].gso) flags |= IFF_VNET_HDR;
        if (order[i].multi) flags |= IFF_MULTI_QUEUE;

        int fd = queue_open(name, flags);
        if (fd < 0) continue;
        d[0].fd = fd;
        d[0].gso = order[i].gso;

        int n = 1;
        if (order[i].multi) {
            /* Остальные очереди — теми же флагами. Сколько дали, столько и берём: отказ на
             * пятой очереди не повод отказываться от четырёх уже открытых. */
            while (n < max_queues) {
                int extra = queue_open(name, flags);
                if (extra < 0) break;
                d[n].fd = extra;
                d[n].gso = order[i].gso;
                n++;
            }
        }
        return n;
    }
    /* Ни один набор флагов не подошёл. Молча вернуть код нельзя: он доходил до человека
     * только как код выхода процесса — и не как 40 или 41, а как 216 или 215, потому что
     * отрицательное возвращённое из main обрезается до байта. В журнале при этом не было
     * ни строки, и «туннель не поднялся» выглядело как «туннель просто не работает». */
    if (g_open_stage == 1 && (g_open_errno == ENOENT || g_open_errno == ENXIO ||
                              g_open_errno == ENODEV)) {
        fprintf(stderr, "steer[warn] tunnel: нет /dev/net/tun (%s) — не установлен kmod-tun\n",
                strerror(g_open_errno));
        return TUN_ENODEV;
    }
    fprintf(stderr, "steer[warn] tunnel: устройство %s не создалось: %s (%s)\n", name,
            strerror(g_open_errno ? g_open_errno : EINVAL),
            g_open_stage == 1 ? "не открылся /dev/net/tun" : "отказал TUNSETIFF");
    return TUN_ESETUP;
}

ssize_t tun_read_packet(const struct tun_dev *d, unsigned char *buf, size_t cap) {
    if (!d->gso) return read(d->fd, buf, cap);
    /* Заголовок разгрузки приезжает и на чтении — он нам не нужен (без TUNSETOFFLOAD ядро
     * отдаёт обычные пакеты), но снять его обязаны, иначе разбор поедет на десять байт. */
    struct vnet_hdr vh;
    struct iovec iov[2] = { { &vh, sizeof(vh) }, { buf, cap } };
    ssize_t r = readv(d->fd, iov, 2);
    if (r <= (ssize_t)sizeof(vh)) return r <= 0 ? r : 0;
    return r - (ssize_t)sizeof(vh);
}

/* ---- разбор IP-заголовка --------------------------------------------------- */
/* Только то, что нужно для маршрутизации соединения: адреса, порты, флаги TCP. Полного
 * разбора нет намеренно — чем меньше кода трогает недоверенные байты из сети, тем меньше
 * места для ошибки в нём. */
int ip_parse(const unsigned char *p, size_t n, struct flow_key *k, size_t *payload_off) {
    if (n < 20) return -1;
    if ((p[0] >> 4) != 4) return -1;                 /* IPv6 не поддержан */
    size_t ihl = (size_t)(p[0] & 0x0F) * 4;
    if (ihl < 20 || n < ihl) return -1;

    k->proto = p[9];
    memcpy(&k->src, p + 12, 4);
    memcpy(&k->dst, p + 16, 4);

    /* Фрагменты. Раньше эти два байта не читались вовсе, и для TCP это проходило
     * незамеченным: в продолжении фрагмента на месте заголовка лежат данные, из них
     * выходили случайные порты, соединение по ним не находилось, и пакет тихо пропадал —
     * то есть верный итог по неверной причине.
     *
     * Для UDP такой итог уже не годится: случайные порты — это НОВЫЙ поток, а новый поток
     * означает рукопожатие с узлом. Мусорный фрагмент открывал бы сессию к узлу.
     *
     * Продолжение фрагмента (смещение не ноль) разобрать нечем — заголовка в нём нет,
     * поэтому отказ. У первого фрагмента заголовок есть, но датаграмма неполна: он
     * размечается флагом, а решает вызывающий (см. handle_packet). */
    unsigned frag = (unsigned)((p[6] << 8) | p[7]);
    if (frag & 0x1FFF) return -1;                    /* не первый фрагмент — заголовка нет */
    k->frag = (frag & 0x2000) ? 1 : 0;               /* MF: продолжение будет */

    if (k->proto == 6) {                             /* TCP */
        if (n < ihl + 20) return -1;
        const unsigned char *t = p + ihl;
        k->sport = (uint16_t)((t[0] << 8) | t[1]);
        k->dport = (uint16_t)((t[2] << 8) | t[3]);
        size_t doff = (size_t)(t[12] >> 4) * 4;
        if (doff < 20 || n < ihl + doff) return -1;
        k->tcp_flags = t[13];
        k->window = (uint16_t)((t[14] << 8) | t[15]);
        /* Масштаб окна из опций SYN (kind 3, RFC 7323).
         *
         * Без него объявленное окно читается как 16 бит, то есть максимум 64 КБ, — а
         * современный клиент присылает 65535 со множителем и имеет в виду мегабайты.
         * Считать его буквально значит держать в пути не больше 64 КБ и упереться в это
         * задолго до полосы: при подтверждениях раз в 5 мс это 13 МБ/с потолка.
         *
         * Опции разбираются только в SYN: дальше их не бывает, а множитель постоянен на
         * всё соединение. */
        k->wscale = 0;
        if ((k->tcp_flags & TCP_SYN) && doff > 20) {
            size_t o = ihl + 20, end = ihl + doff;
            while (o < end && o < n) {
                unsigned char kind = p[o];
                if (kind == 0) break;                 /* конец списка опций */
                if (kind == 1) { o++; continue; }     /* заполнитель */
                if (o + 1 >= end) break;
                unsigned char olen = p[o + 1];
                if (olen < 2 || o + olen > end) break;
                if (kind == 3 && olen == 3) {
                    k->wscale = p[o + 2] > 14 ? 14 : p[o + 2];
                    break;
                }
                o += olen;
            }
        }
        k->seq = ((uint32_t)t[4] << 24) | ((uint32_t)t[5] << 16) |
                 ((uint32_t)t[6] << 8) | t[7];
        k->ack = ((uint32_t)t[8] << 24) | ((uint32_t)t[9] << 16) |
                 ((uint32_t)t[10] << 8) | t[11];
        if (payload_off) *payload_off = ihl + doff;
        return 0;
    }
    if (k->proto == 17) {                            /* UDP */
        if (n < ihl + 8) return -1;
        const unsigned char *u = p + ihl;
        k->sport = (uint16_t)((u[0] << 8) | u[1]);
        k->dport = (uint16_t)((u[2] << 8) | u[3]);
        if (payload_off) *payload_off = ihl + 8;
        return 0;
    }
    return -1;
}

/* ---- контрольные суммы ----------------------------------------------------- */
/* Считаются здесь, а не берутся у ядра: пакеты, которые мы синтезируем для клиента,
 * ядро не проверяет на выходе из TUN, но проверит стек клиента. Неверная сумма означает
 * молча отброшенный пакет — то есть соединение, которое «висит» без ошибки. */
static uint32_t csum_add(const unsigned char *d, size_t n, uint32_t acc) {
    /* Словами по четыре байта, а не байтовыми парами: memcpy сворачивается в
     * одну неупорядоченную загрузку, ntohl — в перестановку байтов (на BE — в
     * ничто), и на каждые 4 байта остаётся два сложения вместо четырёх
     * загрузок со сдвигами. Через эту функцию идёт каждый UDP-пакет к клиенту
     * и весь поток при выключенной разгрузке — на роутерном ядре это заметно.
     *
     * Сумма ТА ЖЕ САМАЯ, а не «эквивалентная по свёртке»: складываются те же
     * 16-битные слова, только парами за шаг, и переполнение uint32 недостижимо
     * (даже 64 КБ данных дают < 2^31), так что и сырое значение acc совпадает
     * с прежним побитово. */
    size_t i = 0;
    for (; i + 4 <= n; i += 4) {
        uint32_t w;
        memcpy(&w, d + i, 4);
        w = ntohl(w);
        acc += (w >> 16) + (w & 0xFFFF);
    }
    for (; i + 1 < n; i += 2)
        acc += ((uint32_t)d[i] << 8) | d[i + 1];
    if (n & 1) acc += (uint32_t)d[n - 1] << 8;
    return acc;
}
static uint16_t csum_fin(uint32_t acc) {
    while (acc >> 16) acc = (acc & 0xFFFF) + (acc >> 16);
    return (uint16_t)~acc;
}

/* Собрать TCP-пакет для отправки клиенту. Адреса и порты меняются местами: мы отвечаем
 * от имени того, к кому клиент обращался. */
/* Заголовок IP и TCP без опций, поля сумм оставлены нулями.
 *
 * Отдельно от tcp_build потому, что для потока данных сумму TCP считать может НЕ НАДО:
 * при разгрузке её досчитывает ядро, и это ровно та экономия, ради которой разгрузка и
 * включается. Смешивать «собрать заголовок» и «посчитать сумму по всем данным» в одной
 * функции значило бы платить за вторую там, где она не нужна. */
void tcp_hdr_build(unsigned char out[TUN_HDR_LEN],
                   uint32_t src, uint32_t dst, uint16_t sport, uint16_t dport,
                   uint32_t seq, uint32_t ack, unsigned char flags,
                   size_t data_n, uint16_t window) {
    size_t total = TUN_HDR_LEN + data_n;
    memset(out, 0, TUN_HDR_LEN);
    out[0] = 0x45;
    out[2] = (unsigned char)(total >> 8);
    out[3] = (unsigned char)total;
    out[8] = 64;
    out[9] = 6;
    memcpy(out + 12, &src, 4);
    memcpy(out + 16, &dst, 4);
    uint16_t ipsum = csum_fin(csum_add(out, 20, 0));
    out[10] = (unsigned char)(ipsum >> 8);
    out[11] = (unsigned char)ipsum;

    unsigned char *t = out + 20;
    t[0] = (unsigned char)(sport >> 8); t[1] = (unsigned char)sport;
    t[2] = (unsigned char)(dport >> 8); t[3] = (unsigned char)dport;
    t[4] = (unsigned char)(seq >> 24); t[5] = (unsigned char)(seq >> 16);
    t[6] = (unsigned char)(seq >> 8);  t[7] = (unsigned char)seq;
    t[8] = (unsigned char)(ack >> 24); t[9] = (unsigned char)(ack >> 16);
    t[10] = (unsigned char)(ack >> 8); t[11] = (unsigned char)ack;
    t[12] = 0x50;                                    /* data offset 5 слов, опций нет */
    t[13] = flags;
    t[14] = (unsigned char)(window >> 8); t[15] = (unsigned char)window;
}

/* Сумма псевдозаголовка TCP: адреса, протокол, длина. */
static uint32_t tcp_pseudo_sum(uint32_t src, uint32_t dst, size_t tcp_len) {
    unsigned char pseudo[12];
    memcpy(pseudo, &src, 4);
    memcpy(pseudo + 4, &dst, 4);
    pseudo[8] = 0; pseudo[9] = 6;
    pseudo[10] = (unsigned char)(tcp_len >> 8); pseudo[11] = (unsigned char)tcp_len;
    return csum_add(pseudo, 12, 0);
}

/* Дождаться, пока в очереди устройства освободится место, и повторить запись.
 *
 * Очередь заполняется на любом пике скорости, и write отвечает EAGAIN — устройство у нас
 * неблокирующее (иначе последнее чтение в цикле засыпало бы). Считать это отказом
 * соединения нельзя: очередь разгружается за микросекунды, а первая версия так и делала —
 * скачивание пропадало совсем.
 *
 * Ожидание миллисекунда, а не десять: замерено, что десять превращались в потолок скорости
 * (110 проходов цикла в секунду при простое poll в 0%). */
static int tun_writev(const struct tun_dev *d, struct iovec *iov, int n) {
    for (int attempts = 0;;) {
        if (writev(d->fd, iov, n) >= 0) return 0;
        if (errno == EINTR) continue;
        if ((errno != EAGAIN && errno != EWOULDBLOCK) || ++attempts > 200) return -1;
        struct pollfd wp = { .fd = d->fd, .events = POLLOUT };
        poll(&wp, 1, 1);
    }
}

int tun_write_data(const struct tun_dev *d, unsigned char hdr[TUN_HDR_LEN],
                   const unsigned char *data, size_t data_n) {
    struct iovec iov[3];
    int n = 0;
    struct vnet_hdr vh;
    size_t tcp_len = 20 + data_n;
    /* Адреса берём из уже собранного заголовка через memcpy, а не сдвигами: в flow_key они
     * лежат в СЕТЕВОМ порядке внутри uint32_t, и сборка сдвигами дала бы верный результат
     * только на little-endian — то есть mips_24kc считал бы сумму от перевёрнутых адресов. */
    uint32_t src, dst;
    memcpy(&src, hdr + 12, 4);
    memcpy(&dst, hdr + 16, 4);

    if (d->gso) {
        /* Сумму ставим НЕДОСЧИТАННОЙ: только псевдозаголовок, без прохода по данным.
         * Досчитает ядро — так же, как для любого сокета с CHECKSUM_PARTIAL.
         *
         * В поле check кладётся свёрнутая, но НЕ инвертированная сумма псевдозаголовка с
         * НАСТОЯЩЕЙ длиной всего сегмента. Это тот же вид, который ядро само себе готовит
         * в __tcp_v4_send_check: `th->check = ~tcp_v4_check(skb->len, saddr, daddr, 0)`.
         * Поправку на длину каждого куска при нарезке вносит tcp_gso_segment. Инвертировать
         * здесь ещё раз означало бы отдать сумму, которая не сойдётся ни у одного куска, —
         * а выглядело бы это как «пакеты уходят, клиент их не видит». */
        uint16_t partial = (uint16_t)~csum_fin(tcp_pseudo_sum(
                src, dst, tcp_len));
        hdr[20 + 16] = (unsigned char)(partial >> 8);
        hdr[20 + 17] = (unsigned char)partial;

        memset(&vh, 0, sizeof(vh));
        vh.flags = VNET_F_NEEDS_CSUM;
        vh.csum_start = 20;                          /* начало заголовка TCP */
        vh.csum_offset = 16;                         /* поле check внутри него */
        vh.hdr_len = TUN_HDR_LEN;
        /* Нарезку просим только когда резать есть что: пометка GSO на сегменте в один MSS
         * лишней работы ядру не добавляет, но и смысла не несёт. */
        if (data_n > TUN_MSS) {
            vh.gso_type = VNET_GSO_TCPV4;
            vh.gso_size = TUN_MSS;
        }
        iov[n].iov_base = &vh;
        iov[n].iov_len = sizeof(vh);
        n++;
    } else {
        /* Без разгрузки сумму приходится считать самим, и это проход по ВСЕМ данным. */
        uint32_t acc = tcp_pseudo_sum(src, dst, tcp_len);
        acc = csum_add(hdr + 20, 20, acc);
        acc = csum_add(data, data_n, acc);
        uint16_t tsum = csum_fin(acc);
        hdr[20 + 16] = (unsigned char)(tsum >> 8);
        hdr[20 + 17] = (unsigned char)tsum;
    }

    iov[n].iov_base = hdr;
    iov[n].iov_len = TUN_HDR_LEN;
    n++;
    if (data_n) {
        iov[n].iov_base = (void *)(uintptr_t)data;
        iov[n].iov_len = data_n;
        n++;
    }
    return tun_writev(d, iov, n);
}

void tun_write_ctl(const struct tun_dev *d, const unsigned char *pkt, size_t n) {
    struct iovec iov[2];
    int i = 0;
    struct vnet_hdr vh;
    if (d->gso) {
        /* Суммы в служебном пакете уже посчитаны, поэтому ядру сообщаем «ничего не надо». */
        memset(&vh, 0, sizeof(vh));
        vh.gso_type = VNET_GSO_NONE;
        iov[i].iov_base = &vh;
        iov[i].iov_len = sizeof(vh);
        i++;
    }
    iov[i].iov_base = (void *)(uintptr_t)pkt;
    iov[i].iov_len = n;
    i++;
    /* Без повторов и без проверки: потерянный SYN-ACK или ACK клиент пришлёт заново сам,
     * а вешать на это ожидание значило бы задержать весь цикл ради пакета без данных. */
    (void)!writev(d->fd, iov, i);
}

/* ICMP «порт недостижим» на пакет, который мы нести не умеем.
 *
 * Зачем это вообще есть. В туннель попадает всё, что совпало с адресным списком, — правило
 * метки протокол не различает и не должно: иначе UDP пошёл бы открытым путём, и сайт увидел
 * бы настоящий адрес ровно там, где его прятали. Но нести UDP мы не умеем, и прежде такой
 * пакет просто выбрасывался молча.
 *
 * Молча — это и была ошибка, ценой которой стало «speed.cloudflare.com не открывается
 * вообще». Браузер идёт к Cloudflare по QUIC, то есть UDP на 443. Тишина для него означает
 * не «нельзя», а «пока не ответили»: он ждёт, повторяет, и только потом пробует TCP. На
 * сайтах, которые предпочитают QUIC особенно настойчиво, это выглядит как мёртвая страница
 * при полностью живом туннеле — TCP до тех же адресов проходил за 250 мс, 7 попыток из 7.
 *
 * ICMP-ошибка превращает ожидание в мгновенный отказ: браузер бросает QUIC и берёт TCP,
 * который у нас работает. Источником ставится тот адрес, к которому клиент обращался, —
 * то же решение, что и в синтезированных RST выше: мы отвечаем от имени назначения, потому
 * что для клиента мы и есть путь к нему.
 *
 * Формат (RFC 792): заголовок ICMP 8 байт, дальше заголовок исходного пакета IP и первые
 * 8 байт его данных — по ним клиент и опознаёт, какое своё соединение отвергли. */
size_t icmp_unreach_build(unsigned char *out, size_t cap,
                          const unsigned char *orig, size_t orig_n) {
    if (orig_n < 20) return 0;
    size_t ihl = (size_t)(orig[0] & 0x0F) * 4;
    if (ihl < 20 || ihl > orig_n) return 0;
    size_t quote = ihl + 8 > orig_n ? orig_n : ihl + 8;   /* заголовок + 8 байт данных */
    size_t total = 20 + 8 + quote;
    if (cap < total) return 0;

    memset(out, 0, 28);
    out[0] = 0x45;                                  /* IPv4, заголовок 20 байт */
    out[2] = (unsigned char)(total >> 8);
    out[3] = (unsigned char)total;
    out[6] = 0x40;                                  /* не фрагментировать */
    out[8] = 64;                                    /* TTL */
    out[9] = 1;                                     /* ICMP */
    memcpy(out + 12, orig + 16, 4);                 /* от имени назначения */
    memcpy(out + 16, orig + 12, 4);                 /* клиенту */
    uint16_t ipc = csum_fin(csum_add(out, 20, 0));
    out[10] = (unsigned char)(ipc >> 8);
    out[11] = (unsigned char)ipc;

    out[20] = 3;                                    /* destination unreachable */
    out[21] = 3;                                    /* port unreachable */
    /* Следующие 4 байта — нули: для кода 3 они не используются. */
    memcpy(out + 28, orig, quote);
    uint16_t ic = csum_fin(csum_add(out + 20, 8 + quote, 0));
    out[22] = (unsigned char)(ic >> 8);
    out[23] = (unsigned char)ic;
    return total;
}

size_t tcp_build(unsigned char *out, size_t cap,
                 uint32_t src, uint32_t dst, uint16_t sport, uint16_t dport,
                 uint32_t seq, uint32_t ack, unsigned char flags,
                 const unsigned char *data, size_t data_n, uint16_t window,
                 unsigned mss, int wscale) {
    /* Опции: MSS занимает 4 байта, масштаб окна 3, и вместе они дают 7 — а длина
     * заголовка TCP измеряется в 32-битных словах. Дополняем NOP до восьми. */
    size_t opt_n = 0;
    if (mss) opt_n += 4;
    if (wscale >= 0) opt_n += 4;                     /* NOP + kind + len + shift */
    size_t total = 20 + 20 + opt_n + data_n;
    if (total > cap) return 0;
    memset(out, 0, 40 + opt_n);

    out[0] = 0x45;                                   /* IPv4, ihl=5 */
    out[2] = (unsigned char)(total >> 8);
    out[3] = (unsigned char)total;
    out[8] = 64;                                     /* TTL */
    out[9] = 6;                                      /* TCP */
    memcpy(out + 12, &src, 4);
    memcpy(out + 16, &dst, 4);
    out[10] = 0; out[11] = 0;
    uint16_t ipsum = csum_fin(csum_add(out, 20, 0));
    out[10] = (unsigned char)(ipsum >> 8);
    out[11] = (unsigned char)ipsum;

    unsigned char *t = out + 20;
    t[0] = (unsigned char)(sport >> 8); t[1] = (unsigned char)sport;
    t[2] = (unsigned char)(dport >> 8); t[3] = (unsigned char)dport;
    t[4] = (unsigned char)(seq >> 24); t[5] = (unsigned char)(seq >> 16);
    t[6] = (unsigned char)(seq >> 8);  t[7] = (unsigned char)seq;
    t[8] = (unsigned char)(ack >> 24); t[9] = (unsigned char)(ack >> 16);
    t[10] = (unsigned char)(ack >> 8); t[11] = (unsigned char)ack;
    t[12] = (unsigned char)(((20 + opt_n) / 4) << 4); /* data offset в 32-битных словах */
    t[13] = flags;
    t[14] = (unsigned char)(window >> 8); t[15] = (unsigned char)window;
    size_t o = 20;
    if (mss) {
        t[o++] = 2;                                  /* kind: MSS */
        t[o++] = 4;                                  /* длина опции */
        t[o++] = (unsigned char)(mss >> 8);
        t[o++] = (unsigned char)mss;
    }
    if (wscale >= 0) {
        t[o++] = 1;                                  /* NOP: выравнивание до слова */
        t[o++] = 3;                                  /* kind: масштаб окна */
        t[o++] = 3;                                  /* длина опции */
        t[o++] = (unsigned char)wscale;
    }
    if (data_n) memcpy(t + 20 + opt_n, data, data_n);

    uint32_t acc = tcp_pseudo_sum(src, dst, 20 + opt_n + data_n);
    acc = csum_add(t, 20 + opt_n + data_n, acc);
    uint16_t tsum = csum_fin(acc);
    t[16] = (unsigned char)(tsum >> 8);
    t[17] = (unsigned char)tsum;
    return total;
}

/* ---- UDP клиенту ----------------------------------------------------------- */
/* Сумма псевдозаголовка UDP: то же, что у TCP, но с номером протокола 17. */
static uint32_t udp_pseudo_sum(uint32_t src, uint32_t dst, size_t udp_len) {
    unsigned char pseudo[12];
    memcpy(pseudo, &src, 4);
    memcpy(pseudo + 4, &dst, 4);
    pseudo[8] = 0; pseudo[9] = 17;
    pseudo[10] = (unsigned char)(udp_len >> 8); pseudo[11] = (unsigned char)udp_len;
    return csum_add(pseudo, 12, 0);
}

/* Заголовок IPv4 с полями фрагментации. Отдельно от tcp_build не ради красоты: датаграмма
 * может не влезть в MTU, и тогда один и тот же заголовок печатается несколько раз с разным
 * смещением. */
static void ip4_hdr(unsigned char *out, size_t total, uint32_t src, uint32_t dst,
                    unsigned char proto, uint16_t id, unsigned frag_off, int more) {
    memset(out, 0, 20);
    out[0] = 0x45;
    out[2] = (unsigned char)(total >> 8);
    out[3] = (unsigned char)total;
    out[4] = (unsigned char)(id >> 8);
    out[5] = (unsigned char)id;
    unsigned flags = (frag_off / 8) | (more ? 0x2000u : 0u);
    out[6] = (unsigned char)(flags >> 8);
    out[7] = (unsigned char)flags;
    out[8] = 64;                                     /* TTL */
    out[9] = proto;
    memcpy(out + 12, &src, 4);
    memcpy(out + 16, &dst, 4);
    uint16_t ipsum = csum_fin(csum_add(out, 20, 0));
    out[10] = (unsigned char)(ipsum >> 8);
    out[11] = (unsigned char)ipsum;
}

/* Отдать клиенту датаграмму. Адреса и порты уже поменяны местами вызывающим: мы отвечаем
 * от имени того, к кому клиент обращался.
 *
 * Фрагментация здесь не про экзотику. Датаграмма приезжает от узла ЦЕЛОЙ — по пути к нему
 * её собрало ядро сервера, — и в MTU нашего устройства она может не влезть: классический
 * случай это ответ DNS с EDNS0, где клиент сам объявил буфер в 4096 байт. Без нарезки
 * такой ответ пришлось бы выбросить, то есть «UDP работает, а большие ответы теряются» —
 * поломка, которую ищут месяцами. Собирает фрагменты обратно стек клиента, это его
 * обычная работа.
 *
 * Смещение фрагмента считается в восьмибайтовых блоках, поэтому кусок обязан быть кратен
 * восьми — кроме последнего. Возвращает 0 или -1. */
int udp_write_to_client(const struct tun_dev *d, uint32_t src, uint32_t dst,
                        uint16_t sport, uint16_t dport,
                        const unsigned char *data, size_t n, uint16_t ip_id) {
    /* Заголовок UDP плюс сама датаграмма: сумма UDP считается по ВСЕЙ датаграмме, а не по
     * куску, поэтому собрать её надо целиком и только потом нарезать. Статический буфер, а
     * не стек: 64 КБ на стеке в цикле, который и без того держит буфер записи TLS. */
    static __thread unsigned char l4[8 + UDP_DGRAM_MAX];
    if (n > UDP_DGRAM_MAX) return -1;

    size_t udp_len = 8 + n;
    l4[0] = (unsigned char)(sport >> 8); l4[1] = (unsigned char)sport;
    l4[2] = (unsigned char)(dport >> 8); l4[3] = (unsigned char)dport;
    l4[4] = (unsigned char)(udp_len >> 8); l4[5] = (unsigned char)udp_len;
    l4[6] = 0; l4[7] = 0;
    memcpy(l4 + 8, data, n);
    uint32_t acc = udp_pseudo_sum(src, dst, udp_len);
    acc = csum_add(l4, udp_len, acc);
    uint16_t usum = csum_fin(acc);
    /* Ноль в поле суммы означает «сумма не считалась», поэтому по RFC 768 его заменяют на
     * 0xFFFF: обе величины дают один и тот же результат при проверке. */
    if (!usum) usum = 0xFFFF;
    l4[6] = (unsigned char)(usum >> 8);
    l4[7] = (unsigned char)usum;

    unsigned char pkt[20 + UDP_MTU_PAYLOAD];
    size_t off = 0;
    while (off < udp_len) {
        size_t chunk = udp_len - off;
        if (chunk > UDP_MTU_PAYLOAD) chunk = UDP_MTU_PAYLOAD & ~7u;
        int more = off + chunk < udp_len;
        ip4_hdr(pkt, 20 + chunk, src, dst, 17, ip_id, (unsigned)off, more);
        memcpy(pkt + 20, l4 + off, chunk);
        /* Через tun_writev, а НЕ через tun_write_ctl, и это не мелочь.
         *
         * tun_write_ctl не проверяет результат и не повторяет: он для служебных пакетов, где
         * потеря дёшева — SYN-ACK или ACK клиент пришлёт заново сам. Здесь же уходят ДАННЫЕ,
         * и при заполненной очереди устройства writev отвечает EAGAIN, то есть датаграмма
         * пропадает молча.
         *
         * Замерено на живом роутере: страница по HTTP/3 через туннель то скачивалась за
         * 840 мс, то вставала на четверти и добиралась до конца за двадцать секунд, то
         * обрывалась совсем — при том, что узел присылал всё. QUIC потерю переживает, но не
         * такую: очередь заполняется как раз на скачивании, то есть теряется не отдельная
         * датаграмма, а подряд идущая пачка.
         *
         * Дождаться места дешевле: очередь TUN опустошает ядро, отдавая пакеты в LAN, и
         * ожидание здесь измеряется миллисекундой. Ровно так же поступает путь TCP
         * (tun_write_data), и по той же причине.
         *
         * Заголовок vnet при включённой разгрузке обязателен ВСЕГДА, а не только при
         * нарезке: без него ядро прочитает первые десять байт нашего IP-заголовка как этот
         * заголовок. Нарезку не просим — суммы посчитаны, пакет уже размером в MTU. */
        struct iovec iov[2];
        int nio = 0;
        struct vnet_hdr vh;
        if (d->gso) {
            memset(&vh, 0, sizeof(vh));
            vh.gso_type = VNET_GSO_NONE;
            iov[nio].iov_base = &vh;
            iov[nio].iov_len = sizeof(vh);
            nio++;
        }
        iov[nio].iov_base = pkt;
        iov[nio].iov_len = 20 + chunk;
        nio++;
        if (tun_writev(d, iov, nio) != 0) return -1;
        off += chunk;
    }
    return 0;
}
