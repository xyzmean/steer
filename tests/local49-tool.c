/* Помощник стенда tests/local49.sh: трафик, который устройство порождает САМО, и куда он уходит.
 *
 * Каналы на сам телефон (from: self / uid:N) метят пакеты на хуке output, а не prerouting, и
 * проверить их можно только соединением изнутри: процесс под нужным UID открывает TCP, а мы
 * читаем, через какое устройство и с каким адресом источника ушёл его SYN. Устройства — TUN:
 * всё, что ядро в них маршрутизирует, приходит на дескриптор, и ничего сверх этого не нужно.
 *
 *   local49-tool mk NAME A.B.C.D/NN      — постоянное TUN-устройство с адресом, поднятое
 *   local49-tool conn UID A.B.C.D PORT   — от имени UID начать TCP-соединение (SYN) и выйти
 *   local49-tool watch NAME MS           — MS миллисекунд читать NAME и печатать TCP SYN:
 *                                          «syn SRC -> DST:PORT» или «none»
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
    fprintf(stderr, "usage: mk NAME CIDR | conn UID ADDR PORT | watch NAME MS\n");
    return 2;
}
