/* Проба соединения БРАУЗЕРНЫМ рукопожатием.
 *
 * ЗАЧЕМ ОНА ЕСТЬ. Подбор стратегий мерил цели обычным curl, и это оказалось измерением не
 * того. DPI смотрит на ClientHello, а он у curl и у браузера разный: у curl три-четыре сотни
 * байт без GREASE и ALPN, у Chrome — под две тысячи. Стратегии же построены ровно на форме
 * этого пакета: `--dpi-desync-split-pos` и `seqovl` режут его в определённом месте, и с
 * коротким рукопожатием ведут себя иначе, чем с длинным.
 *
 * Итог на живом роутере: подбор выбирал стратегию, у которой ВСЕ цели Discord открывались
 * curl'ом, а приложение Discord не подключалось вовсе. Трафик при этом был помечен, в очередь
 * попадал, стратегия применялась — разницу между curl и приложением проба показать не могла.
 *
 * ЧТО ДЕЛАЕТ. Собирает Hello тем же кодом, что и клиент VLESS (reality.c, отпечаток Chrome),
 * отправляет и ждёт ответа. Успех — пришла запись TLS с ServerHello. Дальше рукопожатие не
 * доводится: судим, пережил ли ClientHello дорогу, а не сможем ли договориться о ключах.
 *
 * ПОЧЕМУ НЕ ПОЛНЫЙ TLS. Полное рукопожатие требует проверки сертификата и согласования с любым
 * сервером в интернете — это уже не проба, а второй клиент. Здесь судится ровно одно: дошёл ли
 * наш ClientHello и ответил ли сервер вместо обрыва. Именно это и ломает DPI. */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <time.h>
#include <netdb.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <arpa/inet.h>

#include "reality.h"

#define PROBE_TIMEOUT_S 6

static void pb64(const unsigned char *in, size_t n, char *out) {
    static const char A[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
    size_t i = 0, o = 0;
    for (; i + 2 < n; i += 3) {
        out[o++] = A[in[i] >> 2];
        out[o++] = A[((in[i] & 3) << 4) | (in[i + 1] >> 4)];
        out[o++] = A[((in[i + 1] & 15) << 2) | (in[i + 2] >> 6)];
        out[o++] = A[in[i + 2] & 63];
    }
    if (i < n) {
        out[o++] = A[in[i] >> 2];
        if (i + 1 < n) {
            out[o++] = A[((in[i] & 3) << 4) | (in[i + 1] >> 4)];
            out[o++] = A[(in[i + 1] & 15) << 2];
        } else {
            out[o++] = A[(in[i] & 3) << 4];
        }
    }
    out[o] = '\0';
}

/* session_id — случайные байты: аутентификатор Reality здесь не нужен, мы говорим с обычным
 * сервером, а не с сервером Reality (тот же приём, что в мосте tgws). */
static int psid(void *ctx, unsigned char sid[32], const unsigned char *hs, size_t hs_n,
                const unsigned char shared[32]) {
    (void)ctx; (void)hs; (void)hs_n; (void)shared;
    return xc_random(sid, 32);
}

/* Свой порт нужен, чтобы проба попадала в полосу, которую подбор изолирует своими правилами:
 * иначе её не отличить от обычного трафика роутера. */
static int bind_local(int fd, int port) {
    struct sockaddr_in a;
    int one = 1;
    if (port <= 0) return 0;
    memset(&a, 0, sizeof(a));
    a.sin_family = AF_INET;
    a.sin_port = htons((uint16_t)port);
    setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one));
    return bind(fd, (struct sockaddr *)&a, sizeof(a));
}

int cmd_tls_probe(const char *host, const char *addr, int port, int local_port, int quiet) {
    char portbuf[16];
    struct addrinfo hints, *res = NULL, *it;
    int fd = -1;

    snprintf(portbuf, sizeof(portbuf), "%d", port > 0 ? port : 443);
    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_INET;
    hints.ai_socktype = SOCK_STREAM;
    if (getaddrinfo(addr && *addr ? addr : host, portbuf, &hints, &res) != 0) {
        if (!quiet) printf("итог:       имя не разрешилось\n");
        return 2;
    }

    struct timeval tv = { .tv_sec = PROBE_TIMEOUT_S, .tv_usec = 0 };
    for (it = res; it; it = it->ai_next) {
        fd = socket(it->ai_family, it->ai_socktype, 0);
        if (fd < 0) continue;
        setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
        setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));
        if (bind_local(fd, local_port) != 0) { close(fd); fd = -1; continue; }
        if (connect(fd, it->ai_addr, it->ai_addrlen) == 0) break;
        close(fd);
        fd = -1;
    }
    freeaddrinfo(res);
    if (fd < 0) {
        if (!quiet) printf("итог:       соединение не установилось (%s)\n", strerror(errno));
        return 1;
    }
    { int one = 1; setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, &one, sizeof(one)); }

    unsigned char priv[32], pub[32], throwaway[32], fake_pbk[32], hello[4096];
    char pbk[64];
    size_t hello_n = 0;
    if (xc_x25519_keypair(throwaway, fake_pbk) != 0 || xc_x25519_keypair(priv, pub) != 0) {
        close(fd);
        if (!quiet) printf("итог:       ключи не сделались\n");
        return 2;
    }
    pb64(fake_pbk, sizeof(fake_pbk), pbk);

    struct reality_cfg cfg = { .sni = host, .pbk = pbk, .sid = "", .fp = "chrome",
                               .alpn = "h2" };
    struct reality_state st;
    struct reality_carrier car = { .priv = priv, .pub = pub, .fill_sid = psid };
    int hrc = reality_build_hello_carry(&cfg, &st, &car, hello, sizeof(hello), &hello_n);
    if (hrc != 0) {
        close(fd);
        if (!quiet) printf("итог:       Hello не собрался (%d)\n", hrc);
        return 2;
    }

    struct timespec t0, t1;
    clock_gettime(CLOCK_MONOTONIC, &t0);
    size_t off = 0;
    while (off < hello_n) {
        ssize_t w = send(fd, hello + off, hello_n - off, MSG_NOSIGNAL);
        if (w <= 0) {
            close(fd);
            if (!quiet) printf("итог:       Hello не ушёл (%s)\n", strerror(errno));
            return 1;
        }
        off += (size_t)w;
    }

    /* Пяти байт заголовка записи довольно, чтобы отличить ServerHello от обрыва: 0x16 —
     * рукопожатие, 0x15 — предупреждение (тоже ответ сервера, но не наш случай). */
    unsigned char head[5];
    size_t got = 0;
    while (got < sizeof(head)) {
        ssize_t r = recv(fd, head + got, sizeof(head) - got, 0);
        if (r <= 0) {
            close(fd);
            if (!quiet)
                printf("итог:       ответа нет (%s) — рукопожатие не дошло\n",
                       r == 0 ? "соединение закрыто" : strerror(errno));
            return 1;
        }
        got += (size_t)r;
    }
    clock_gettime(CLOCK_MONOTONIC, &t1);
    close(fd);

    long ms = (t1.tv_sec - t0.tv_sec) * 1000 + (t1.tv_nsec - t0.tv_nsec) / 1000000;
    if (head[0] != 0x16) {
        if (!quiet) printf("итог:       ответ не рукопожатие (0x%02x)\n", head[0]);
        return 1;
    }
    if (!quiet) printf("итог:       %s отвечает, %ld мс\n", host, ms);
    return 0;
}
