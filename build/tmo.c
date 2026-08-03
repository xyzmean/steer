/* Проверка SO_SNDTIMEO на 32-битной цели: ставим 8 с, читаем обратно, делаем
 * блокирующий connect к живому узлу и смотрим, сколько он реально ждал. */
#include <stdio.h>
#include <stdlib.h>
#include <sys/time.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <time.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/socket.h>

static long long ms(void) {
    struct timespec t; clock_gettime(CLOCK_MONOTONIC, &t);
    return (long long)t.tv_sec * 1000 + t.tv_nsec / 1000000;
}

int main(int argc, char **argv) {
    printf("sizeof(struct timeval)=%u sizeof(time_t)=%u\n",
           (unsigned)sizeof(struct timeval), (unsigned)sizeof(time_t));
    struct sockaddr_in a = { .sin_family = AF_INET, .sin_port = htons(argc > 2 ? atoi(argv[2]) : 8443) };
    inet_pton(AF_INET, argc > 1 ? argv[1] : "212.127.91.190", &a.sin_addr);

    int fd = socket(AF_INET, SOCK_STREAM, 0);
    struct timeval tv = { .tv_sec = 8, .tv_usec = 0 };
    int r1 = setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof tv);
    int r2 = setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof tv);
    struct timeval back = { 0, 0 }; socklen_t bl = sizeof back;
    getsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &back, &bl);
    printf("setsockopt snd=%d rcv=%d, прочитано обратно: %lld.%06lld c (len=%u)\n",
           r1, r2, (long long)back.tv_sec, (long long)back.tv_usec, (unsigned)bl);

    long long t0 = ms();
    int rc = connect(fd, (struct sockaddr *)&a, sizeof a);
    printf("connect rc=%d errno=%s за %lldms\n", rc, rc ? strerror(errno) : "-", ms() - t0);
    close(fd);
    return 0;
}
