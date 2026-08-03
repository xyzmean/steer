/* Замер туннеля с самого роутера: N параллельных HTTP-запросов через заданное устройство.
 * Меряет то, что чувствует человек, — время до первого байта каждого соединения и общую
 * скорость, а не «пинг до узла».
 *   hget УСТРОЙСТВО IP ХОСТ ПУТЬ N СЕКУНД      (УСТРОЙСТВО = "-" значит не привязывать)
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <poll.h>
#include <time.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <arpa/inet.h>
#include <sys/socket.h>

#define MAXC 32

static long long ms(void) {
    struct timespec t; clock_gettime(CLOCK_MONOTONIC, &t);
    return (long long)t.tv_sec * 1000 + t.tv_nsec / 1000000;
}

static void say_ms(char *out, size_t cap, long long v) {
    if (v < 0) snprintf(out, cap, "нет");
    else snprintf(out, cap, "%lldms", v);
}

int main(int argc, char **argv) {
    if (argc < 7) { fprintf(stderr, "hget DEV IP HOST PATH N SEC\n"); return 2; }
    const char *dev = argv[1], *ip = argv[2], *host = argv[3], *path = argv[4];
    int n = atoi(argv[5]); if (n > MAXC) n = MAXC; if (n < 1) n = 1;
    long long budget = atoll(argv[6]) * 1000;

    struct sockaddr_in a = { .sin_family = AF_INET, .sin_port = htons(80) };
    inet_pton(AF_INET, ip, &a.sin_addr);

    int fd[MAXC], st[MAXC];              /* st: 0 соединяется, 1 запрос ушёл, 2 закрыто */
    long long t0[MAXC], tc[MAXC], tf[MAXC], got[MAXC];
    long long start = ms();
    int one = 1;

    for (int i = 0; i < n; i++) {
        fd[i] = socket(AF_INET, SOCK_STREAM | SOCK_NONBLOCK, 0);
        if (dev[0] != '-') setsockopt(fd[i], SOL_SOCKET, SO_BINDTODEVICE, dev, strlen(dev));
        setsockopt(fd[i], IPPROTO_TCP, TCP_NODELAY, &one, sizeof one);
        t0[i] = ms(); tc[i] = tf[i] = -1; got[i] = 0; st[i] = 0;
        if (connect(fd[i], (struct sockaddr *)&a, sizeof a) != 0 && errno != EINPROGRESS) {
            printf("%2d connect: %s\n", i + 1, strerror(errno));
            close(fd[i]); fd[i] = -1; st[i] = 2;
        }
    }

    char req[512];
    int rl = snprintf(req, sizeof req,
                      "GET %s HTTP/1.1\r\nHost: %s\r\nUser-Agent: steer-hget\r\n"
                      "Connection: close\r\n\r\n", path, host);
    unsigned char buf[16384];

    while (ms() - start < budget) {
        struct pollfd pv[MAXC]; int map[MAXC], np = 0;
        for (int i = 0; i < n; i++) {
            if (st[i] == 2) continue;
            pv[np].fd = fd[i]; pv[np].events = st[i] == 0 ? POLLOUT : POLLIN; pv[np].revents = 0;
            map[np++] = i;
        }
        if (!np) break;
        int pr = poll(pv, np, 500);
        if (pr < 0) { if (errno == EINTR) continue; break; }
        for (int k = 0; k < np; k++) {
            int i = map[k];
            if (!pv[k].revents) continue;
            if (st[i] == 0) {
                int err = 0; socklen_t el = sizeof err;
                getsockopt(fd[i], SOL_SOCKET, SO_ERROR, &err, &el);
                if (err) {
                    printf("%2d соединение: %s (%lldms)\n", i + 1, strerror(err), ms() - t0[i]);
                    close(fd[i]); st[i] = 2; continue;
                }
                tc[i] = ms() - t0[i];
                if (write(fd[i], req, rl) != rl) { close(fd[i]); st[i] = 2; continue; }
                st[i] = 1;
                continue;
            }
            ssize_t r = read(fd[i], buf, sizeof buf);
            if (r > 0) { if (tf[i] < 0) tf[i] = ms() - t0[i]; got[i] += r; }
            else if (r == 0 || (errno != EAGAIN && errno != EINTR)) { close(fd[i]); st[i] = 2; }
        }
    }

    long long total = 0, elapsed = ms() - start;
    int ok = 0;
    for (int i = 0; i < n; i++) {
        if (st[i] != 2 && fd[i] >= 0) close(fd[i]);
        total += got[i];
        if (tf[i] >= 0) ok++;
        char c[24], f[24];
        say_ms(c, sizeof c, tc[i]);
        say_ms(f, sizeof f, tf[i]);
        printf("%2d соед=%-8s первый байт=%-8s байт=%lld\n", i + 1, c, f, got[i]);
    }
    printf("итог: с данными %d из %d, %lld КБ за %lldms = %.1f Мбит/с\n",
           ok, n, total / 1024, elapsed, elapsed ? total * 8.0 / elapsed / 1000.0 : 0.0);
    return 0;
}
