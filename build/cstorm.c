/* Измеритель установления TCP: сколько соединений к узлу открывается и за какое время.
 * Нужен, чтобы отделить «узел/сеть отбивает соединения» от «наш цикл не успевает».
 *   cstorm IP PORT N MODE   MODE = seq | par
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <fcntl.h>
#include <poll.h>
#include <time.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <arpa/inet.h>
#include <sys/socket.h>

#define MAXN 64
#define TMO_MS 9000

static long long ms(void) {
    struct timespec t; clock_gettime(CLOCK_MONOTONIC, &t);
    return (long long)t.tv_sec * 1000 + t.tv_nsec / 1000000;
}

static int start(struct sockaddr_in *a) {
    int fd = socket(AF_INET, SOCK_STREAM | SOCK_NONBLOCK, 0);
    if (fd < 0) return -1;
    int one = 1; setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, &one, sizeof one);
    if (connect(fd, (struct sockaddr *)a, sizeof *a) == 0) return fd;
    if (errno != EINPROGRESS) { fprintf(stderr, "connect: %s\n", strerror(errno)); close(fd); return -1; }
    return fd;
}

static int finish(int fd, int tmo) {   /* 0 ок, иначе errno */
    struct pollfd p = { .fd = fd, .events = POLLOUT };
    int r = poll(&p, 1, tmo);
    if (r == 0) return ETIMEDOUT;
    if (r < 0) return errno;
    int err = 0; socklen_t l = sizeof err;
    getsockopt(fd, SOL_SOCKET, SO_ERROR, &err, &l);
    return err;
}

int main(int argc, char **argv) {
    if (argc < 5) { fprintf(stderr, "cstorm IP PORT N seq|par\n"); return 2; }
    struct sockaddr_in a = { .sin_family = AF_INET, .sin_port = htons(atoi(argv[2])) };
    inet_pton(AF_INET, argv[1], &a.sin_addr);
    int n = atoi(argv[3]); if (n > MAXN) n = MAXN;
    int par = strcmp(argv[4], "par") == 0;
    int ok = 0, fail = 0;

    if (!par) {
        for (int i = 0; i < n; i++) {
            long long t0 = ms();
            int fd = start(&a);
            int e = fd < 0 ? EINVAL : finish(fd, TMO_MS);
            printf("%2d %-14s %5lldms\n", i + 1, e ? strerror(e) : "ok", ms() - t0);
            if (e) fail++; else ok++;
            if (fd >= 0) close(fd);
        }
    } else {
        int fd[MAXN]; long long t0[MAXN];
        long long base = ms();
        for (int i = 0; i < n; i++) { t0[i] = ms(); fd[i] = start(&a); }
        printf("все %d SYN отправлены за %lldms\n", n, ms() - base);
        for (int i = 0; i < n; i++) {
            int left = (int)(TMO_MS - (ms() - t0[i])); if (left < 0) left = 0;
            int e = fd[i] < 0 ? EINVAL : finish(fd[i], left);
            printf("%2d %-14s %5lldms\n", i + 1, e ? strerror(e) : "ok", ms() - t0[i]);
            if (e) fail++; else ok++;
            if (fd[i] >= 0) close(fd[i]);
        }
    }
    printf("итог: ok=%d fail=%d\n", ok, fail);
    return 0;
}
