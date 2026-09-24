/* Помощник стенда tests/local49.sh: трафик, который устройство порождает САМО, и куда он уходит.
 *
 * Каналы на сам телефон (from: self / uid:N) метят пакеты на хуке output, а не prerouting, и
 * проверить их можно только соединением изнутри: процесс под нужным UID открывает TCP, а мы
 * читаем, через какое устройство и с каким адресом источника ушёл его SYN. Устройства — TUN:
 * всё, что ядро в них маршрутизирует, приходит на дескриптор, и ничего сверх этого не нужно.
 *
 *   local49-tool mk NAME A.B.C.D/NN      — постоянное TUN-устройство с адресом, поднятое
 *   local49-tool conn UID A.B.C.D PORT   — от имени UID начать TCP-соединение (SYN) и выйти
 *   local49-tool watch NAME MS           — MS миллисекунд читать NAME и печатать TCP SYN
 *                                          «syn SRC -> DST:PORT» и UDP (IPv4 и IPv6)
 *                                          «udp SRC -> DST:PORT»; ничего — «none»
 *   local49-tool dns UID SERVER NAME [MARK]
 *                                        — от имени UID спросить A у SERVER:53 (IPv4 или
 *                                          IPv6), напечатать первый адрес ответа или
 *                                          «timeout»; MARK — SO_MARK сокета, как fwmark,
 *                                          которым netd метит сокет DnsResolver
 *   local49-tool serve6 PORT ADDR6 A.B.C.D
 *                                        — DNS-сервер на [ADDR6]:PORT: на любой вопрос A
 *                                          отвечает A.B.C.D (dnstool стенда — только IPv4)
 *
 * Статически и без libc-зависимостей сверх POSIX: собирается и musl-gcc для стенда vm49, и
 * обычным cc для сетевого пространства на хосте. */
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <poll.h>
#include <time.h>
#include <sys/ioctl.h>
#include <sys/time.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <linux/if.h>
#include <linux/if_tun.h>

#ifndef TUN_DEV
#define TUN_DEV "/dev/net/tun"
#endif

static int tun_attach(const char *name) {
    int fd = open(TUN_DEV, O_RDWR);
    if (fd < 0) { perror("tun"); exit(1); }
    struct ifreq ifr;
    memset(&ifr, 0, sizeof ifr);
    ifr.ifr_flags = IFF_TUN | IFF_NO_PI;
    snprintf(ifr.ifr_name, IFNAMSIZ, "%s", name);
    if (ioctl(fd, TUNSETIFF, &ifr) < 0) { perror("TUNSETIFF"); exit(1); }
    return fd;
}

static long now_ms(void) {
    struct timespec t;
    clock_gettime(CLOCK_MONOTONIC, &t);
    return t.tv_sec * 1000L + t.tv_nsec / 1000000L;
}

int main(int argc, char **argv) {
    if (argc == 4 && !strcmp(argv[1], "mk")) {
        int fd = tun_attach(argv[2]);
        if (ioctl(fd, TUNSETPERSIST, 1) < 0) { perror("TUNSETPERSIST"); return 1; }
        close(fd);
        char cmd[256];
        snprintf(cmd, sizeof cmd, "ip addr add %s dev %s && ip link set %s up",
                 argv[3], argv[2], argv[2]);
        return system(cmd) == 0 ? 0 : 1;
    }
    if (argc == 5 && !strcmp(argv[1], "conn")) {
        unsigned uid = (unsigned)strtoul(argv[2], NULL, 10);
        if (uid && (setgid(uid) != 0 || setuid(uid) != 0)) { perror("setuid"); return 1; }
        int s = socket(AF_INET, SOCK_STREAM | SOCK_NONBLOCK, 0);
        struct sockaddr_in a;
        memset(&a, 0, sizeof a);
        a.sin_family = AF_INET;
        a.sin_port = htons((unsigned short)atoi(argv[4]));
        inet_pton(AF_INET, argv[3], &a.sin_addr);
        if (connect(s, (struct sockaddr *)&a, sizeof a) != 0 && errno != EINPROGRESS) {
            printf("connect: %s\n", strerror(errno));
            return 1;
        }
        usleep(400000);
        return 0;
    }
    if (argc == 4 && !strcmp(argv[1], "watch")) {
        int fd = tun_attach(argv[2]);
        long until = now_ms() + atol(argv[3]);
        int seen = 0;
        for (;;) {
            long left = until - now_ms();
            if (left <= 0) break;
            struct pollfd p = { fd, POLLIN, 0 };
            if (poll(&p, 1, (int)left) <= 0) continue;
            unsigned char b[2048];
            ssize_t n = read(fd, b, sizeof b);
            if (n >= 48 && (b[0] >> 4) == 6 && b[6] == 17) {        /* IPv6 + UDP */
                char src[64], dst[64];
                inet_ntop(AF_INET6, b + 8, src, sizeof src);
                inet_ntop(AF_INET6, b + 24, dst, sizeof dst);
                printf("udp %s -> [%s]:%d\n", src, dst, (b[42] << 8) | b[43]);
                fflush(stdout);
                seen++;
                continue;
            }
            if (n >= 28 && (b[0] >> 4) == 4 && b[9] == 17) {        /* IPv4 + UDP */
                int ihl = (b[0] & 15) * 4;
                char src[16], dst[16];
                inet_ntop(AF_INET, b + 12, src, sizeof src);
                inet_ntop(AF_INET, b + 16, dst, sizeof dst);
                printf("udp %s -> %s:%d\n", src, dst, (b[ihl + 2] << 8) | b[ihl + 3]);
                fflush(stdout);
                seen++;
                continue;
            }
            if (n < 40 || (b[0] >> 4) != 4 || b[9] != 6) continue;
            int ihl = (b[0] & 15) * 4;
            if (!(b[ihl + 13] & 0x02) || (b[ihl + 13] & 0x10)) continue;   /* только SYN */
            char src[16], dst[16];
            inet_ntop(AF_INET, b + 12, src, sizeof src);
            inet_ntop(AF_INET, b + 16, dst, sizeof dst);
            printf("syn %s -> %s:%d\n", src, dst, (b[ihl + 2] << 8) | b[ihl + 3]);
            fflush(stdout);
            seen++;
        }
        if (!seen) printf("none\n");
        return 0;
    }
    if ((argc == 5 || argc == 6) && !strcmp(argv[1], "dns")) {
        unsigned uid = (unsigned)strtoul(argv[2], NULL, 10);
        int v6 = strchr(argv[3], ':') != NULL;
        /* Сокет и метка — до смены UID: SO_MARK требует CAP_NET_ADMIN (у DnsResolver метку
         * ставит netd, у которого она есть). */
        int s = socket(v6 ? AF_INET6 : AF_INET, SOCK_DGRAM, 0);
        if (argc == 6) {
            unsigned mk = (unsigned)strtoul(argv[5], NULL, 0);
            if (setsockopt(s, SOL_SOCKET, SO_MARK, &mk, sizeof mk) != 0) {
                perror("SO_MARK"); return 1;
            }
        }
        if (uid && (setgid(uid) != 0 || setuid(uid) != 0)) { perror("setuid"); return 1; }
        unsigned char q[300], r[600];
        int n = 12;
        memset(q, 0, 12);
        q[0] = 0x12; q[1] = 0x34; q[2] = 1; q[5] = 1;
        char name[256];
        snprintf(name, sizeof name, "%s", argv[4]);
        for (char *t = strtok(name, "."); t; t = strtok(NULL, ".")) {
            q[n++] = (unsigned char)strlen(t); memcpy(q + n, t, strlen(t)); n += (int)strlen(t);
        }
        q[n++] = 0; q[n++] = 0; q[n++] = 1; q[n++] = 0; q[n++] = 1;
        struct timeval tv = { 2, 0 };
        setsockopt(s, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof tv);
        struct sockaddr_storage ss;
        socklen_t sl;
        memset(&ss, 0, sizeof ss);
        if (v6) {
            struct sockaddr_in6 *a6 = (struct sockaddr_in6 *)&ss;
            a6->sin6_family = AF_INET6;
            a6->sin6_port = htons(53);
            inet_pton(AF_INET6, argv[3], &a6->sin6_addr);
            sl = sizeof *a6;
        } else {
            struct sockaddr_in *a = (struct sockaddr_in *)&ss;
            a->sin_family = AF_INET;
            a->sin_port = htons(53);
            inet_pton(AF_INET, argv[3], &a->sin_addr);
            sl = sizeof *a;
        }
        /* connect, как DnsResolver: ответ с чужого адреса (например, с адреса Wi-Fi вместо
         * того, к которому шёл запрос, или с ::1 вместо сервера) ядро такому сокету не
         * отдаст — стенд увидит timeout. */
        if (connect(s, (struct sockaddr *)&ss, sl) != 0) { printf("connect\n"); return 0; }
        send(s, q, n, 0);
        int m = (int)recv(s, r, sizeof r, 0);
        if (m < n + 16 || !r[7]) { printf("timeout\n"); return 0; }
        /* Первый ответ: за вопросом — имя-указатель (2), тип, класс, TTL, длина, адрес. */
        int at = n + 2 + 2 + 2 + 4 + 2;
        char ip[16];
        inet_ntop(AF_INET, r + at, ip, sizeof ip);
        printf("%s\n", ip);
        return 0;
    }
    if (argc == 5 && !strcmp(argv[1], "serve6")) {
        int s = socket(AF_INET6, SOCK_DGRAM, 0);
        struct sockaddr_in6 a;
        memset(&a, 0, sizeof a);
        a.sin6_family = AF_INET6;
        a.sin6_port = htons((unsigned short)atoi(argv[2]));
        inet_pton(AF_INET6, argv[3], &a.sin6_addr);
        if (bind(s, (struct sockaddr *)&a, sizeof a) != 0) { perror("bind"); return 1; }
        struct in_addr ip;
        inet_pton(AF_INET, argv[4], &ip);
        for (;;) {
            unsigned char q[512], r[600];
            struct sockaddr_in6 f;
            socklen_t fl = sizeof f;
            int n = (int)recvfrom(s, q, sizeof q, 0, (struct sockaddr *)&f, &fl);
            if (n < 13) continue;
            int e = 12;
            while (e < n && q[e]) e += 1 + q[e];
            e += 5;
            if (e > n) continue;
            memcpy(r, q, e);
            r[2] = 0x81; r[3] = 0x80; r[6] = 0; r[7] = 1; r[8] = r[9] = r[10] = r[11] = 0;
            unsigned char ans[16] = { 0xc0, 0x0c, 0, 1, 0, 1, 0, 0, 0, 60, 0, 4 };
            memcpy(ans + 12, &ip, 4);
            memcpy(r + e, ans, 16);
            sendto(s, r, e + 16, 0, (struct sockaddr *)&f, fl);
        }
    }
    fprintf(stderr, "usage: mk NAME CIDR | conn UID ADDR PORT | watch NAME MS | "
                    "dns UID SERVER NAME [MARK] | serve6 PORT ADDR6 A.B.C.D\n");
    return 2;
}
