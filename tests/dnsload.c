/* Сколько запросов в секунду держит встроенный резолвер и чего это стоит процессору.
 *
 * Зачем отдельно от tests/dnsproxy.sh. Тот проверяет ПРАВИЛЬНОСТЬ пересылки: номера
 * транзакций, попадание ответа тому клиенту, который спрашивал. Скорости он не мерит вовсе,
 * и по нему не видно ни цены сопоставления имени со списками, ни того, как эта цена растёт
 * со числом доменов в спеке.
 *
 * А расти ей есть куда: резолвер стоит на пути КАЖДОГО запроса всех устройств сети, а
 * доменных списков в наборе `ru-bypass-ipsets` полторы тысячи строк. Если сопоставление
 * линейное, цена запроса линейно зависит от длины списка — и заметно это станет не на стенде
 * разработчика, а на роутере с включёнными категориями.
 *
 * Окно, а не «запрос-ответ». Последовательный обмен мерит круг до резолвера, а не его
 * пропускную способность: между отправкой и ответом процесс простаивает. Здесь в полёте
 * держится до `-w` запросов, поэтому упирается замер в резолвер, а не в задержку петли.
 *
 * Имена берутся ИЗ ФАЙЛА, по кругу. Одно и то же имя измеряло бы кэш ответов, а не разбор и
 * сопоставление, — а кэш в реальной сети греется далеко не всегда.
 *
 *   dnsload -p ПОРТ -f ФАЙЛ_ИМЁН [-n ЗАПРОСОВ] [-w ОКНО] [-t МС_ОЖИДАНИЯ]
 *
 * Второй режим — заглушка апстрима: `dnsload -S -p ПОРТ`. Она нужна тому же замеру и
 * поэтому живёт здесь, а не отдельным файлом. Резолвер спрашивает наверх даже в режиме
 * fakeip — настоящий адрес ему нужен для карты DNAT, — и без ответа сверху он не отвечает
 * вниз вовсе. Питона на роутере нет, поэтому заглушку из tests/dnsproxy.sh туда не
 * перенести: там она на питоне.
 */
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <time.h>
#include <poll.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <netinet/in.h>

#define MAX_NAMES 20000
#define NAME_MAX_LEN 256

static char *g_names[MAX_NAMES];
static int g_name_n;

static uint64_t now_ms(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (uint64_t)ts.tv_sec * 1000 + (uint64_t)ts.tv_nsec / 1000000;
}

/* Имя в формат DNS: «a.b» -> 1 'a' 1 'b' 0. Возвращает длину или 0 при браке. */
static size_t qname(const char *host, unsigned char *out, size_t cap) {
    size_t o = 0;
    const char *p = host;
    while (*p) {
        const char *dot = strchr(p, '.');
        size_t len = dot ? (size_t)(dot - p) : strlen(p);
        if (!len || len > 63 || o + 1 + len + 1 > cap) return 0;
        out[o++] = (unsigned char)len;
        memcpy(out + o, p, len);
        o += len;
        if (!dot) break;
        p = dot + 1;
    }
    if (o + 1 > cap) return 0;
    out[o++] = 0;
    return o;
}

static int load_names(const char *path) {
    FILE *f = fopen(path, "r");
    if (!f) { perror(path); return -1; }
    char line[NAME_MAX_LEN];
    while (g_name_n < MAX_NAMES && fgets(line, sizeof(line), f)) {
        char *s = line;
        while (*s == ' ' || *s == '\t') s++;
        if (*s == '#' || *s == '\n' || !*s) continue;
        char *e = s + strlen(s);
        while (e > s && (e[-1] == '\n' || e[-1] == '\r' || e[-1] == ' ')) e--;
        *e = 0;
        if (e == s) continue;
        /* Ведущая точка в списках означает «и поддомены» — для запроса она лишняя. */
        if (*s == '.') s++;
        if (!*s) continue;
        g_names[g_name_n] = strdup(s);
        if (!g_names[g_name_n]) break;
        g_name_n++;
    }
    fclose(f);
    return g_name_n ? 0 : -1;
}

/* Заглушка апстрима: на любой запрос отвечает одним адресом A.
 *
 * Отвечает КОПИЕЙ вопроса и своим ответом — так же, как поддельный апстрим в
 * tests/dnsproxy.sh, — потому что резолвер сверяет вопрос в ответе со своим. Работает до
 * убийства процесса. */
static int stub_upstream(int port) {
    int fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (fd < 0) { perror("socket"); return 1; }
    int one = 1;
    setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one));
    struct sockaddr_in sa = { .sin_family = AF_INET, .sin_port = htons((uint16_t)port),
                              .sin_addr = { .s_addr = htonl(INADDR_LOOPBACK) } };
    if (bind(fd, (struct sockaddr *)&sa, sizeof(sa)) < 0) { perror("bind"); return 1; }
    fprintf(stderr, "заглушка апстрима на 127.0.0.1:%d\n", port);
    unsigned char in[1500], out[1500];
    for (;;) {
        struct sockaddr_in from;
        socklen_t fl = sizeof(from);
        ssize_t n = recvfrom(fd, in, sizeof(in), 0, (struct sockaddr *)&from, &fl);
        if (n < 13) continue;
        /* Конец вопроса: метки до нулевой, потом тип и класс. */
        size_t qend = 12;
        while (qend < (size_t)n && in[qend]) qend += 1 + in[qend];
        qend += 5;
        if (qend > (size_t)n || qend + 16 > sizeof(out)) continue;
        size_t o = 0;
        out[o++] = in[0]; out[o++] = in[1];        /* тот же номер транзакции */
        out[o++] = 0x81; out[o++] = 0x80;          /* ответ, рекурсия доступна */
        out[o++] = 0; out[o++] = 1;                /* один вопрос */
        out[o++] = 0; out[o++] = 1;                /* один ответ */
        out[o++] = 0; out[o++] = 0;
        out[o++] = 0; out[o++] = 0;
        memcpy(out + o, in + 12, qend - 12); o += qend - 12;
        out[o++] = 0xc0; out[o++] = 0x0c;          /* указатель на имя вопроса */
        out[o++] = 0; out[o++] = 1;                /* тип A */
        out[o++] = 0; out[o++] = 1;                /* класс IN */
        out[o++] = 0; out[o++] = 0; out[o++] = 0; out[o++] = 60;   /* TTL */
        out[o++] = 0; out[o++] = 4;
        out[o++] = 93; out[o++] = 184; out[o++] = 216; out[o++] = 34;
        sendto(fd, out, o, 0, (struct sockaddr *)&from, fl);
    }
}

int main(int argc, char **argv) {
    int port = 53, total = 5000, window = 64, wait_ms = 2000, stub = 0;
    const char *file = NULL, *host = "127.0.0.1";
    for (int i = 1; i < argc; i++) {
        if (!strcmp(argv[i], "-S")) stub = 1;
        else if (!strcmp(argv[i], "-p") && i + 1 < argc) port = atoi(argv[++i]);
        else if (!strcmp(argv[i], "-f") && i + 1 < argc) file = argv[++i];
        else if (!strcmp(argv[i], "-n") && i + 1 < argc) total = atoi(argv[++i]);
        else if (!strcmp(argv[i], "-w") && i + 1 < argc) window = atoi(argv[++i]);
        else if (!strcmp(argv[i], "-t") && i + 1 < argc) wait_ms = atoi(argv[++i]);
        else if (!strcmp(argv[i], "-h") && i + 1 < argc) host = argv[++i];
        else { fprintf(stderr, "dnsload -p ПОРТ -f ФАЙЛ [-n N] [-w ОКНО] [-t МС] [-h АДРЕС]\n"
                               "dnsload -S -p ПОРТ   — заглушка апстрима\n"); return 2; }
    }
    if (stub) return stub_upstream(port);
    if (!file) { fprintf(stderr, "нужен -f ФАЙЛ со списком имён\n"); return 2; }
    if (load_names(file) != 0) { fprintf(stderr, "имён не нашлось в %s\n", file); return 2; }
    if (window < 1) window = 1;

    int fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (fd < 0) { perror("socket"); return 1; }
    struct sockaddr_in sa = { .sin_family = AF_INET, .sin_port = htons((uint16_t)port) };
    if (inet_pton(AF_INET, host, &sa.sin_addr) != 1) { fprintf(stderr, "плохой адрес\n"); return 2; }
    /* Приёмный буфер побольше: при окне в сотни запросов ответы приходят пачкой, и
     * умолчание ядра теряло бы их, а потеря выглядела бы как медленный резолвер. */
    int rcv = 1 << 20;
    setsockopt(fd, SOL_SOCKET, SO_RCVBUF, &rcv, sizeof(rcv));

    unsigned char q[512], r[1500];
    int sent = 0, got = 0, inflight = 0;
    uint64_t t0 = now_ms();

    while (got < total) {
        while (inflight < window && sent < total) {
            const char *name = g_names[sent % g_name_n];
            unsigned char qn[NAME_MAX_LEN + 2];
            size_t ql = qname(name, qn, sizeof(qn));
            if (!ql) { sent++; total--; continue; }
            uint16_t tid = (uint16_t)(0x1000 + (sent & 0x7fff));
            size_t o = 0;
            q[o++] = (unsigned char)(tid >> 8); q[o++] = (unsigned char)tid;
            q[o++] = 0x01; q[o++] = 0x00;          /* стандартный запрос, рекурсия */
            q[o++] = 0; q[o++] = 1;                /* один вопрос */
            q[o++] = 0; q[o++] = 0;
            q[o++] = 0; q[o++] = 0;
            q[o++] = 0; q[o++] = 0;
            memcpy(q + o, qn, ql); o += ql;
            q[o++] = 0; q[o++] = 1;                /* тип A */
            q[o++] = 0; q[o++] = 1;                /* класс IN */
            if (sendto(fd, q, o, 0, (struct sockaddr *)&sa, sizeof(sa)) < 0) {
                if (errno == EAGAIN || errno == ENOBUFS) break;
                perror("sendto"); return 1;
            }
            sent++; inflight++;
        }
        if (!inflight) break;
        struct pollfd p = { .fd = fd, .events = POLLIN };
        int pr = poll(&p, 1, wait_ms);
        if (pr <= 0) break;                        /* больше не отвечают — считаем остаток потерей */
        while (1) {
            ssize_t n = recv(fd, r, sizeof(r), MSG_DONTWAIT);
            if (n < 0) break;
            if (n >= 12) { got++; inflight--; }
            if (inflight <= 0) break;
        }
    }
    uint64_t ms = now_ms() - t0;
    if (!ms) ms = 1;

    printf("имён в списке: %d, окно %d\n", g_name_n, window);
    printf("отправлено %d, получено %d, потеряно %d\n", sent, got, sent - got);
    printf("время %llu мс, скорость %llu запросов/с\n",
           (unsigned long long)ms, (unsigned long long)((uint64_t)got * 1000 / ms));
    if (got) printf("на запрос: %llu мкс\n", (unsigned long long)((uint64_t)ms * 1000 / (uint64_t)got));
    return got == total ? 0 : 1;
}
