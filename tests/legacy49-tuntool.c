/* Помощник стенда tests/legacy49.sh (ядро 4.9 в tools/vm49): «клиент за роутером» без второго
 * сетевого пространства. veth в статическом ip стенда нет, а пакет, записанный в TUN, входит
 * в ядро так же, как пришедший из LAN, — через PREROUTING, где и стоят правила nat.
 *   tuntool dns NAME                  — UDP 10.99.0.2:40000 -> 1.1.1.1:53, печатает адрес ответа
 *   tuntool syn A.B.C.D PORT [SPORT]  — TCP SYN 10.99.0.2:SPORT(40001) -> A:PORT, печатает
 *                                       «synack/rst от адрес:порт» или «none»
 * Устройство tn0 создаётся и получает 10.99.0.1/24 самим инструментом. */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <fcntl.h>
#include <unistd.h>
#include <poll.h>
#include <sys/ioctl.h>
#include <arpa/inet.h>
#include <linux/if.h>
#include <linux/if_tun.h>
static unsigned short csum(const void *b, int n, unsigned s0) {
    const unsigned char *p = b; unsigned s = s0;
    for (int i = 0; i + 1 < n; i += 2) s += (p[i] << 8) | p[i + 1];
    if (n & 1) s += p[n - 1] << 8;
    while (s >> 16) s = (s & 0xffff) + (s >> 16);
    return (unsigned short)~s;
}
static int mkpkt(unsigned char *p, int proto, unsigned src, unsigned dst, const unsigned char *l4, int l4n) {
    memset(p, 0, 20);
    p[0] = 0x45; int tot = 20 + l4n; p[2] = tot >> 8; p[3] = tot; p[8] = 64; p[9] = proto;
    memcpy(p + 12, &src, 4); memcpy(p + 16, &dst, 4);
    unsigned short c = csum(p, 20, 0); p[10] = c >> 8; p[11] = c;
    memcpy(p + 20, l4, l4n);
    /* псевдозаголовок */
    unsigned char ph[12]; memcpy(ph, &src, 4); memcpy(ph + 4, &dst, 4); ph[8] = 0; ph[9] = proto; ph[10] = l4n >> 8; ph[11] = l4n;
    unsigned s = 0; for (int i = 0; i < 12; i += 2) s += (ph[i] << 8) | ph[i + 1];
    int co = proto == 17 ? 6 : 16;
    p[20 + co] = p[20 + co + 1] = 0;
    c = csum(p + 20, l4n, s); p[20 + co] = c >> 8; p[20 + co + 1] = c;
    return tot;
}
int main(int argc, char **argv) {
    int fd = open("/dev/net/tun", O_RDWR);
    if (fd < 0) { perror("tun"); return 1; }
    struct ifreq ifr; memset(&ifr, 0, sizeof ifr);
    ifr.ifr_flags = IFF_TUN | IFF_NO_PI; strcpy(ifr.ifr_name, "tn0");
    if (ioctl(fd, TUNSETIFF, &ifr) < 0) { perror("TUNSETIFF"); return 1; }
    if (system("ip addr add 10.99.0.1/24 dev tn0 && ip link set tn0 up") != 0) return 1;
    usleep(200000);
    unsigned src, dst; inet_pton(AF_INET, "10.99.0.2", &src);
    unsigned char l4[512], pkt[600]; int n = 0, proto;
    if (argc == 3 && !strcmp(argv[1], "dns")) {
        inet_pton(AF_INET, "1.1.1.1", &dst); proto = 17;
        unsigned char *q = l4 + 8; int qn = 12; memset(q, 0, 12); q[0] = 0x42; q[1] = 0x43; q[2] = 1; q[5] = 1;
        char name[256]; snprintf(name, sizeof name, "%s", argv[2]);
        for (char *t = strtok(name, "."); t; t = strtok(NULL, ".")) { q[qn++] = strlen(t); memcpy(q + qn, t, strlen(t)); qn += strlen(t); }
        q[qn++] = 0; q[qn++] = 0; q[qn++] = 1; q[qn++] = 0; q[qn++] = 1;
        n = 8 + qn; l4[0] = 40000 >> 8; l4[1] = 40000 & 255; l4[2] = 0; l4[3] = 53; l4[4] = n >> 8; l4[5] = n;
    } else if ((argc == 4 || argc == 5) && !strcmp(argv[1], "syn")) {
        inet_pton(AF_INET, argv[2], &dst); proto = 6; int port = atoi(argv[3]);
        int sport = argc == 5 ? atoi(argv[4]) : 40001;
        memset(l4, 0, 20); l4[0] = sport >> 8; l4[1] = sport & 255; l4[2] = port >> 8; l4[3] = port;
        l4[7] = 1; l4[12] = 0x50; l4[13] = 0x02; l4[14] = 0xff; l4[15] = 0xff; n = 20;
    } else { fprintf(stderr, "usage\n"); return 2; }
    int tot = mkpkt(pkt, proto, src, dst, l4, n);
    if (write(fd, pkt, tot) != tot) { perror("write"); return 1; }
    for (;;) {
        struct pollfd pf = { fd, POLLIN, 0 };
        if (poll(&pf, 1, 3000) <= 0) { puts(proto == 17 ? "timeout" : "none"); return 0; }
        unsigned char r[2048]; int m = read(fd, r, sizeof r);
        if (m < 20 || (r[0] >> 4) != 4 || r[9] != proto) continue;
        int ihl = (r[0] & 15) * 4; char from[16]; inet_ntop(AF_INET, r + 12, from, sizeof from);
        if (proto == 17) {
            unsigned char *d = r + ihl + 8; int dn = m - ihl - 8;
            if (dn < 16) continue;
            if (d[3] & 15) { printf("rcode%d\n", d[3] & 15); return 0; }
            printf("%d.%d.%d.%d (от %s)\n", r[m-4], r[m-3], r[m-2], r[m-1], from); return 0;
        }
        unsigned char fl = r[ihl + 13];
        printf("%s от %s:%d\n", (fl & 0x12) == 0x12 ? "synack" : (fl & 4) ? "rst" : "other", from, (r[ihl] << 8) | r[ihl + 1]);
        return 0;
    }
}
