/* Помощник стенда tests/legacy49.sh (ядро 4.9 в tools/vm49): поддельный вышестоящий DNS и
 * клиент к нему. Python в initramfs стенда нет, поэтому оба — одной статической программой.
 *   dnstool serve PORT A.B.C.D [BIND [TCPADDR]] — отвечает на любой A-запрос этим адресом
 *                                  (TTL 60); слушает BIND (по умолчанию 127.0.0.1) по UDP и по
 *                                  TCP (два байта длины, RFC 7766). По TCP отвечает TCPADDR,
 *                                  если он задан, — так стенд видит, каким протоколом резолвер
 *                                  движка спросил наверх
 *   dnstool ask SERVER PORT NAME  — печатает первый адрес ответа, «timeout» или «rcodeN»
 *   dnstool asktcp SERVER PORT NAME [NAME…] — то же по TCP, все вопросы одной записью в одном
 *                                  соединении (конвейер); по строке на имя в порядке имён */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <poll.h>
#include <unistd.h>
#include <netinet/in.h>
#include <arpa/inet.h>
/* Ответ на запрос q[0..n): вопрос как есть и одна запись A. 0 — не запрос. */
static int answer(const unsigned char *q, int n, struct in_addr ip, unsigned char *r) {
    if (n < 13) return 0;
    int e = 12; while (e < n && q[e]) e += 1 + q[e]; e += 5;
    if (e > n || e > 512) return 0;
    memcpy(r, q, e); r[2] = 0x81; r[3] = 0x80; r[6] = 0; r[7] = 1; r[8]=r[9]=r[10]=r[11]=0;
    unsigned char ans[16] = { 0xc0, 0x0c, 0, 1, 0, 1, 0, 0, 0, 60, 0, 4 };
    memcpy(ans + 12, &ip, 4); memcpy(r + e, ans, 16);
    return e + 16;
}

static int readn(int s, unsigned char *b, int k) {
    int got = 0;
    while (got < k) { int m = recv(s, b + got, k - got, 0); if (m <= 0) return -1; got += m; }
    return 0;
}

static void qname(unsigned char *q, int *n, const char *nm) {
    char name[256]; snprintf(name, sizeof name, "%s", nm);
    for (char *t = strtok(name, "."); t; t = strtok(NULL, ".")) { q[(*n)++] = strlen(t); memcpy(q + *n, t, strlen(t)); *n += strlen(t); }
    q[(*n)++] = 0; q[(*n)++] = 0; q[(*n)++] = 1; q[(*n)++] = 0; q[(*n)++] = 1;
}

int main(int argc, char **argv) {
    if (argc >= 4 && argc <= 6 && !strcmp(argv[1], "serve")) {
        int s = socket(AF_INET, SOCK_DGRAM, 0);
        int t = socket(AF_INET, SOCK_STREAM, 0), one = 1;
        setsockopt(t, SOL_SOCKET, SO_REUSEADDR, &one, sizeof one);
        struct sockaddr_in a = { .sin_family = AF_INET, .sin_port = htons(atoi(argv[2])) };
        a.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
        if (argc >= 5) inet_pton(AF_INET, argv[4], &a.sin_addr);
        if (bind(s, (void *)&a, sizeof a)) { perror("bind"); return 1; }
        if (bind(t, (void *)&a, sizeof a) || listen(t, 16)) { perror("bind tcp"); return 1; }
        struct in_addr ip; inet_pton(AF_INET, argv[3], &ip);
        struct in_addr tip = ip; if (argc == 6) inet_pton(AF_INET, argv[5], &tip);
        for (;;) {
            struct pollfd pf[2] = { { s, POLLIN, 0 }, { t, POLLIN, 0 } };
            if (poll(pf, 2, -1) <= 0) continue;
            unsigned char q[512], r[600];
            if (pf[0].revents & POLLIN) {
                struct sockaddr_in f; socklen_t fl = sizeof f;
                int n = recvfrom(s, q, sizeof q, 0, (void *)&f, &fl);
                int m = answer(q, n, ip, r);
                if (m) sendto(s, r, m, 0, (void *)&f, fl);
            }
            if (pf[1].revents & POLLIN) {
                /* Соединение обслуживается целиком, по запросу за раз, пока клиент не закроет:
                 * резолвер движка открывает соединение на вопрос, и больше не нужно. */
                int c = accept(t, NULL, NULL);
                if (c < 0) continue;
                struct timeval tv = { 3, 0 }; setsockopt(c, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof tv);
                unsigned char h[2], out[602];
                while (readn(c, h, 2) == 0) {
                    int n = h[0] << 8 | h[1];
                    if (n > (int)sizeof q || readn(c, q, n)) break;
                    int m = answer(q, n, tip, out + 2);
                    if (!m) break;
                    out[0] = m >> 8; out[1] = m & 255;
                    send(c, out, m + 2, 0);
                }
                close(c);
            }
        }
    }
    if (argc >= 5 && !strcmp(argv[1], "asktcp")) {
        int s = socket(AF_INET, SOCK_STREAM, 0);
        struct timeval tv = { 3, 0 }; setsockopt(s, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof tv);
        struct sockaddr_in a = { .sin_family = AF_INET, .sin_port = htons(atoi(argv[3])) };
        inet_pton(AF_INET, argv[2], &a.sin_addr);
        if (connect(s, (void *)&a, sizeof a)) { puts("connect"); return 0; }
        unsigned char all[4096]; int len = 0, k = argc - 4;
        for (int i = 0; i < k && i < 16; i++) {
            unsigned char *q = all + len + 2; int n = 12;
            memset(q, 0, 12); q[0] = 0x43; q[1] = i; q[2] = 1; q[5] = 1;
            qname(q, &n, argv[4 + i]);
            all[len] = n >> 8; all[len + 1] = n & 255; len += n + 2;
        }
        send(s, all, len, 0);                       /* все вопросы одной записью */
        char res[16][32] = { { 0 } };
        for (int i = 0; i < k && i < 16; i++) {
            unsigned char h[2], r[600];
            if (readn(s, h, 2)) break;
            int m = h[0] << 8 | h[1];
            if (m > (int)sizeof r || readn(s, r, m)) break;
            int id = r[1];
            if (r[0] != 0x43 || id >= k) continue;
            if (r[3] & 15) snprintf(res[id], 32, "rcode%d", r[3] & 15);
            else if (m < 4 || (r[6] == 0 && r[7] == 0)) snprintf(res[id], 32, "empty");
            else snprintf(res[id], 32, "%d.%d.%d.%d", r[m-4], r[m-3], r[m-2], r[m-1]);
        }
        for (int i = 0; i < k && i < 16; i++) puts(res[i][0] ? res[i] : "timeout");
        return 0;
    }
    if (argc == 5 && !strcmp(argv[1], "ask")) {
        unsigned char q[512]; int n = 12;
        memset(q, 0, 12); q[0] = 0x42; q[1] = 0x42; q[2] = 1; q[5] = 1;
        char name[256]; snprintf(name, sizeof name, "%s", argv[4]);
        for (char *t = strtok(name, "."); t; t = strtok(NULL, ".")) { q[n++] = strlen(t); memcpy(q + n, t, strlen(t)); n += strlen(t); }
        q[n++] = 0; q[n++] = 0; q[n++] = 1; q[n++] = 0; q[n++] = 1;
        int s = socket(AF_INET, SOCK_DGRAM, 0);
        struct timeval tv = { 3, 0 }; setsockopt(s, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof tv);
        struct sockaddr_in a = { .sin_family = AF_INET, .sin_port = htons(atoi(argv[3])) };
        inet_pton(AF_INET, argv[2], &a.sin_addr);
        sendto(s, q, n, 0, (void *)&a, sizeof a);
        unsigned char r[600]; int m = recv(s, r, sizeof r, 0);
        if (m < 0) { puts("timeout"); return 0; }
        if (r[3] & 15) { printf("rcode%d\n", r[3] & 15); return 0; }
        if (m < 4 || (r[6] == 0 && r[7] == 0)) { puts("empty"); return 0; }
        printf("%d.%d.%d.%d\n", r[m-4], r[m-3], r[m-2], r[m-1]);
        return 0;
    }
    fprintf(stderr, "usage\n"); return 2;
}
