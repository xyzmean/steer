/* Что getaddrinfo отдаёт статически слинкованному musl-бинарю на этом роутере.
 * Тот же путь, которым идёт steer: hints.ai_family = AF_INET. */
#include <stdio.h>
#include <string.h>
#include <time.h>
#include <netdb.h>
#include <arpa/inet.h>
#include <netinet/in.h>

static long long ms(void) {
    struct timespec t; clock_gettime(CLOCK_MONOTONIC, &t);
    return (long long)t.tv_sec * 1000 + t.tv_nsec / 1000000;
}

int main(int argc, char **argv) {
    for (int i = 1; i < argc; i++) {
        struct addrinfo hints = { .ai_family = AF_INET, .ai_socktype = SOCK_STREAM };
        struct addrinfo *res = NULL;
        long long t0 = ms();
        int rc = getaddrinfo(argv[i], "8443", &hints, &res);
        long long dt = ms() - t0;
        if (rc != 0 || !res) { printf("%s: ОШИБКА %s (%lldms)\n", argv[i], gai_strerror(rc), dt); continue; }
        printf("%s (%lldms):", argv[i], dt);
        for (struct addrinfo *p = res; p; p = p->ai_next) {
            char b[64];
            inet_ntop(AF_INET, &((struct sockaddr_in *)p->ai_addr)->sin_addr, b, sizeof b);
            printf(" %s", b);
        }
        printf("   <- steer берёт ПЕРВЫЙ\n");
        freeaddrinfo(res);
    }
    return 0;
}
