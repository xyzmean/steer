/* Приходит ли отказ на UDP, ушедший в туннель.
 *
 * Смысл проверки: браузер должен получить ОТКАЗ, а не тишину, — иначе он ждёт QUIC вместо
 * того, чтобы сразу взять TCP. Отказ виден как ECONNREFUSED на присоединённом сокете UDP:
 * ядро запоминает пришедший ICMP и отдаёт его следующей операцией.
 *   uprobe УСТРОЙСТВО IP ПОРТ
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <poll.h>
#include <time.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/socket.h>

static long long ms(void) {
    struct timespec t; clock_gettime(CLOCK_MONOTONIC, &t);
    return (long long)t.tv_sec * 1000 + t.tv_nsec / 1000000;
}

int main(int argc, char **argv) {
    if (argc < 4) { fprintf(stderr, "uprobe DEV IP PORT\n"); return 2; }
    struct sockaddr_in a = { .sin_family = AF_INET, .sin_port = htons(atoi(argv[3])) };
    inet_pton(AF_INET, argv[2], &a.sin_addr);

    int fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (argv[1][0] != '-') setsockopt(fd, SOL_SOCKET, SO_BINDTODEVICE, argv[1], strlen(argv[1]));
    if (connect(fd, (struct sockaddr *)&a, sizeof a) != 0) {
        printf("connect: %s\n", strerror(errno)); return 1;
    }
    /* Похоже на начало QUIC: длинный заголовок Initial. Содержимое не важно — важно, что
     * это UDP на 443 и что мы его не понесём. */
    unsigned char q[64];
    memset(q, 0, sizeof q);
    q[0] = 0xC0; q[1] = 0x00; q[2] = 0x00; q[3] = 0x00; q[4] = 0x01;
    long long t0 = ms();
    if (send(fd, q, sizeof q, 0) < 0) { printf("send: %s (%lldms)\n", strerror(errno), ms() - t0); return 0; }

    struct pollfd p = { .fd = fd, .events = POLLIN };
    int r = poll(&p, 1, 3000);
    if (r == 0) { printf("ТИШИНА за 3000мс — браузер будет ждать QUIC\n"); return 1; }
    char buf[64];
    ssize_t got = recv(fd, buf, sizeof buf, 0);
    if (got < 0) {
        printf("ОТКАЗ за %lldms: %s%s\n", ms() - t0, strerror(errno),
               errno == ECONNREFUSED ? "  <- то, что нужно: браузер сразу возьмёт TCP" : "");
        return 0;
    }
    printf("пришёл ответ %zd байт за %lldms — UDP работает?!\n", got, ms() - t0);
    return 0;
}
