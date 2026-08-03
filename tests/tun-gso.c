/* Проверка разгрузки записи в TUN: доходят ли данные и сходятся ли контрольные суммы.
 *
 * Зачем нужен отдельный тест. При разгрузке мы кладём в поле check НЕДОСЧИТАННУЮ сумму —
 * только псевдозаголовок, — и рассчитываем, что ядро досчитает остальное при нарезке. Это
 * договорённость, а не наблюдаемое поведение: ошибись в ней на слагаемое длины, и пакеты
 * будут уходить, а приёмник — молча их отбрасывать. Отладка такого на роутере обходится
 * дороже всего, потому что «скорость не выросла» и «данные не доходят» выглядят одинаково.
 *
 * Проверить это локальной доставкой НЕЛЬЗЯ, и это главная тонкость: пакет с
 * CHECKSUM_PARTIAL, доставленный в сокет на той же машине, проверку суммы не проходит вовсе
 * (skb_csum_unnecessary считает такой пакет доверенным). Тест прошёл бы при любой сумме.
 *
 * Поэтому схема такая: пишем в одно устройство, а читаем из ДРУГОГО, заставив ядро
 * маршрутизировать пакет между ними. На выходе ядро обязано и нарезать сегмент, и досчитать
 * суммы — то есть мы читаем ровно то, что увидел бы клиент, и можем проверить суммы сами.
 *
 * Запускать в своём сетевом пространстве (см. tests/run-tun-gso.sh): тест поднимает
 * устройства, включает пересылку и выключает проверку обратного пути.
 */
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <arpa/inet.h>

#include "../src/ext/tun.h"

#define PAYLOAD_N 16000
#define QUEUES 4

static int sh(const char *cmd) {
    int rc = system(cmd);
    if (rc != 0) fprintf(stderr, "не удалось: %s\n", cmd);
    return rc;
}

/* Сумма по RFC 1071 — своя копия, чтобы тест не зависел от той, которую проверяет. */
static uint16_t csum(const unsigned char *d, size_t n, uint32_t acc) {
    for (size_t i = 0; i + 1 < n; i += 2) acc += ((uint32_t)d[i] << 8) | d[i + 1];
    if (n & 1) acc += (uint32_t)d[n - 1] << 8;
    while (acc >> 16) acc = (acc & 0xFFFF) + (acc >> 16);
    return (uint16_t)~acc;
}

int main(void) {
    struct tun_dev in, outq[QUEUES];
    if (tun_open(&in, 1, "tgin") < 0) { fprintf(stderr, "tgin не открылся\n"); return 2; }
    /* Приёмную сторону открываем НЕСКОЛЬКИМИ очередями: на них проверяется свойство, на
     * котором стоит вся многопоточность, — что ядро кладёт весь поток в одну очередь. */
    int nq = tun_open(outq, QUEUES, "tgout");
    if (nq < 0) { fprintf(stderr, "tgout не открылся\n"); return 2; }
    struct tun_dev out = outq[0];
    printf("разгрузка: tgin=%d tgout=%d; очередей tgout: %d из %d\n",
           in.gso, out.gso, nq, QUEUES);

    if (sh("ip addr add 10.77.0.1/24 dev tgin && ip link set tgin up") ||
        sh("ip addr add 10.88.0.1/24 dev tgout && ip link set tgout up") ||
        sh("sysctl -qw net.ipv4.ip_forward=1") ||
        sh("sysctl -qw net.ipv4.conf.all.rp_filter=0") ||
        sh("sysctl -qw net.ipv4.conf.tgin.rp_filter=0") ||
        /* Соседа для 10.88.0.2 нет и быть не может — устройство точка-точка, но ядро всё
         * равно ищет его. Прописываем вручную, иначе пакет уйдёт в ARP-ожидание. */
        sh("ip neigh replace 10.88.0.2 dev tgout lladdr 00:00:00:00:00:00 nud permanent"))
        return 2;

    /* Читаем всё, что ядро уже успело положить в tgout до нашей записи (объявления и
     * прочий шум): иначе оно попадёт в проверку и будет выглядеть как испорченный сегмент. */
    unsigned char junk[65536];
    for (int q = 0; q < nq; q++) {
        int fl = fcntl(outq[q].fd, F_GETFL, 0);
        fcntl(outq[q].fd, F_SETFL, fl | O_NONBLOCK);
        while (tun_read_packet(&outq[q], junk, sizeof(junk)) > 0) { }
    }

    static unsigned char payload[PAYLOAD_N];
    for (size_t i = 0; i < sizeof(payload); i++) payload[i] = (unsigned char)(i * 31 + 7);

    uint32_t src, dst;
    inet_pton(AF_INET, "10.77.0.2", &src);
    inet_pton(AF_INET, "10.88.0.2", &dst);

    /* Нарезка ровно та же, что в emit_to_client: с разгрузкой отдаём запись целиком, без
     * неё — по MSS. Отдать 16 КБ одним пакетом БЕЗ разгрузки нельзя, и это не мелочь: ядро
     * примет такой пакет и порежет его на фрагменты IP, а не на сегменты TCP. Проверено
     * этим же тестом: 11 фрагментов, из которых только первый несёт заголовок TCP. */
    size_t seg = in.gso ? (size_t)TUN_GSO_MAX : (size_t)TUN_MSS;
    for (size_t sent = 0; sent < sizeof(payload); ) {
        size_t chunk = sizeof(payload) - sent > seg ? seg : sizeof(payload) - sent;
        unsigned char hdr[TUN_HDR_LEN];
        tcp_hdr_build(hdr, src, dst, 12345, 9999, (uint32_t)(1000 + sent), 2000,
                      TCP_ACK | TCP_PSH, chunk, 65535);
        if (tun_write_data(&in, hdr, payload + sent, chunk) != 0) {
            fprintf(stderr, "запись не удалась: %s\n", strerror(errno));
            return 2;
        }
        sent += chunk;
    }

    /* Собираем то, что вышло с другой стороны. */
    size_t got = 0, segs = 0, bad_ip = 0, bad_tcp = 0, bad_data = 0;
    size_t per_queue[QUEUES] = {0};
    for (int idle = 0; idle < 200 && got < sizeof(payload); ) {
        unsigned char pkt[65536];
        ssize_t n = -1;
        int from = -1;
        for (int q = 0; q < nq; q++) {
            n = tun_read_packet(&outq[q], pkt, sizeof(pkt));
            if (n > 0) { from = q; break; }
        }
        if (n <= 0) {
            struct pollfd p[QUEUES];
            for (int q = 0; q < nq; q++) { p[q].fd = outq[q].fd; p[q].events = POLLIN; }
            poll(p, (unsigned)nq, 10);
            idle++;
            continue;
        }
        idle = 0;
        per_queue[from]++;
        if (n < 40 || (pkt[0] >> 4) != 4 || pkt[9] != 6) continue;
        size_t ihl = (size_t)(pkt[0] & 0x0F) * 4;
        size_t doff = (size_t)(pkt[ihl + 12] >> 4) * 4;
        size_t dn = (size_t)n - ihl - doff;

        if (csum(pkt, ihl, 0) != 0) bad_ip++;

        unsigned char pseudo[12];
        memcpy(pseudo, pkt + 12, 4);
        memcpy(pseudo + 4, pkt + 16, 4);
        pseudo[8] = 0; pseudo[9] = 6;
        uint16_t tlen = (uint16_t)(doff + dn);
        pseudo[10] = (unsigned char)(tlen >> 8); pseudo[11] = (unsigned char)tlen;
        uint32_t acc = 0;
        for (int i = 0; i < 12; i += 2) acc += ((uint32_t)pseudo[i] << 8) | pseudo[i + 1];
        if (csum(pkt + ihl, doff + dn, acc) != 0) bad_tcp++;

        /* Номер последовательности говорит, куда этот сегмент ложится. */
        uint32_t seq = ((uint32_t)pkt[ihl + 4] << 24) | ((uint32_t)pkt[ihl + 5] << 16) |
                       ((uint32_t)pkt[ihl + 6] << 8) | pkt[ihl + 7];
        size_t off = seq - 1000;
        if (off + dn > sizeof(payload) ||
            memcmp(pkt + ihl + doff, payload + off, dn) != 0) bad_data++;
        got += dn;
        segs++;
    }

    printf("сегментов %zu, байт %zu из %zu; суммы IP плохих %zu, TCP плохих %zu, данные "
           "разошлись %zu раз\n", segs, got, sizeof(payload), bad_ip, bad_tcp, bad_data);

    /* Весь поток обязан лежать в ОДНОЙ очереди. Разложись он по нескольким — и соединение
     * обслуживали бы разные потоки, у каждого своя таблица; получилось бы два независимых
     * состояния одного TCP, то есть тихая порча вместо ошибки. */
    int used = 0, spread = 0;
    for (int q = 0; q < nq; q++) {
        if (!per_queue[q]) continue;
        used++;
        printf("  очередь %d: %zu пакетов\n", q, per_queue[q]);
    }
    if (nq > 1 && used != 1) { printf("FAIL: поток разложился по %d очередям\n", used); spread = 1; }
    if (nq == 1) printf("  (ядро без IFF_MULTI_QUEUE — привязку проверить нечем)\n");

    int ok = got == sizeof(payload) && !bad_ip && !bad_tcp && !bad_data && !spread;
    printf("%s\n", ok ? "PASS" : "FAIL");
    return ok ? 0 : 1;
}
