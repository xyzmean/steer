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
 *   UDP  — не поддержан (VLESS UDP требует отдельной обёртки; DNS всё равно перехватывает
 *          резолвер steer, а это основной UDP, который важен для маршрутизации);
 *   ICMP — не пересылается: ping через прокси требует эмуляции, которая полезна только для
 *          диагностики, а вводит в заблуждение (успешный ping не означает рабочий путь).
 */
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
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

#include "tun.h"

int tun_open(const char *name) {
    int fd = open("/dev/net/tun", O_RDWR);
    if (fd < 0) return TUN_ENODEV;

    struct ifreq ifr;
    memset(&ifr, 0, sizeof(ifr));
    /* IFF_NO_PI: без 4-байтного префикса протокола. Он нужен только тому, кто хочет
     * различать семейства на одном устройстве, а у нас IPv4 и разбор всё равно по
     * заголовку пакета. */
    ifr.ifr_flags = IFF_TUN | IFF_NO_PI;
    snprintf(ifr.ifr_name, IFNAMSIZ, "%s", name);
    if (ioctl(fd, TUNSETIFF, &ifr) < 0) {
        close(fd);
        return TUN_ESETUP;
    }
    return fd;
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

    if (k->proto == 6) {                             /* TCP */
        if (n < ihl + 20) return -1;
        const unsigned char *t = p + ihl;
        k->sport = (uint16_t)((t[0] << 8) | t[1]);
        k->dport = (uint16_t)((t[2] << 8) | t[3]);
        size_t doff = (size_t)(t[12] >> 4) * 4;
        if (doff < 20 || n < ihl + doff) return -1;
        k->tcp_flags = t[13];
        k->window = (uint16_t)((t[14] << 8) | t[15]);
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
    for (size_t i = 0; i + 1 < n; i += 2)
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
size_t tcp_build(unsigned char *out, size_t cap,
                 uint32_t src, uint32_t dst, uint16_t sport, uint16_t dport,
                 uint32_t seq, uint32_t ack, unsigned char flags,
                 const unsigned char *data, size_t data_n, uint16_t window,
                 unsigned mss) {
    size_t opt_n = mss ? 4 : 0;
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
    if (opt_n) {
        t[20] = 2;                                   /* kind: MSS */
        t[21] = 4;                                   /* длина опции */
        t[22] = (unsigned char)(mss >> 8);
        t[23] = (unsigned char)mss;
    }
    if (data_n) memcpy(t + 20 + opt_n, data, data_n);

    /* Псевдозаголовок TCP: адреса, протокол, длина — иначе сумма не сойдётся у клиента. */
    unsigned char pseudo[12];
    memcpy(pseudo, &src, 4);
    memcpy(pseudo + 4, &dst, 4);
    pseudo[8] = 0; pseudo[9] = 6;
    uint16_t tlen = (uint16_t)(20 + opt_n + data_n);
    pseudo[10] = (unsigned char)(tlen >> 8); pseudo[11] = (unsigned char)tlen;
    uint32_t acc = csum_add(pseudo, 12, 0);
    acc = csum_add(t, 20 + opt_n + data_n, acc);
    uint16_t tsum = csum_fin(acc);
    t[16] = (unsigned char)(tsum >> 8);
    t[17] = (unsigned char)tsum;
    return total;
}
