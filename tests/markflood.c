/* Поток помеченных датаграмм для стенда перепривязки (tests/rebindleak.sh).
 *
 * markflood МЕТКА АДРЕС ПОРТ СЕКУНД
 *
 * Шлёт UDP на АДРЕС:ПОРТ с меткой сокета МЕТКА так часто, как успевает, — СЕКУНД или до
 * SIGTERM, что раньше, — и печатает, сколько отправлено и сколько отказов. Нужен ровно для
 * одного: чтобы в каждое мгновение перепривязки таблицы выхода по ней шёл пакет — и если в
 * таблице или в правиле на миг образуется пустота, пакет попал бы в неё и ушёл по main, где
 * его и сосчитает стенд.
 *
 * СОКЕТ НЕ СОЕДИНЁН, и это главное. У соединённого UDP ядро запоминает маршрут в сокете и
 * ищет его заново только при смене поколения таблиц — то есть мог бы «проскочить» окно, не
 * заглянув в правила. sendto на несоединённом сокете ищет маршрут для каждой датаграммы: ровно
 * так ведёт себя пересылаемый трафик клиентов и первые пакеты новых соединений.
 *
 * Отказы (EINVAL от blackhole, ENETUNREACH, ENOBUFS) не останавливают поток: запрет в таблице
 * — законное состояние, считается лишь то, что вышло в сеть. Статически собирается musl для
 * стенда tools/vm49 так же, как прочие помощники стендов. */
#define _GNU_SOURCE
#include <arpa/inet.h>
#include <errno.h>
#include <netinet/in.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>
#include <sys/socket.h>
#include <time.h>
#include <unistd.h>

static volatile sig_atomic_t g_stop;
static void on_term(int s) { (void)s; g_stop = 1; }

int main(int argc, char **argv) {
    if (argc != 5) {
        fprintf(stderr, "usage: markflood MARK ADDR PORT SECONDS\n");
        return 2;
    }
    unsigned mark = (unsigned)strtoul(argv[1], NULL, 0);
    struct sockaddr_in sa;
    memset(&sa, 0, sizeof sa);
    sa.sin_family = AF_INET;
    sa.sin_port = htons((unsigned short)atoi(argv[3]));
    if (inet_pton(AF_INET, argv[2], &sa.sin_addr) != 1) { fprintf(stderr, "bad addr\n"); return 2; }
    int secs = atoi(argv[4]);
    int fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (fd < 0) { perror("socket"); return 1; }
    if (setsockopt(fd, SOL_SOCKET, SO_MARK, &mark, sizeof mark) != 0) { perror("SO_MARK"); return 1; }
    signal(SIGTERM, on_term);
    signal(SIGINT, on_term);
    char buf[32] = "steer-rebind";
    struct timespec t0, t;
    clock_gettime(CLOCK_MONOTONIC, &t0);
    unsigned long sent = 0, errs = 0, n = 0;
    while (!g_stop) {
        if ((++n & 1023) == 0) {
            clock_gettime(CLOCK_MONOTONIC, &t);
            if (t.tv_sec - t0.tv_sec >= secs) break;
        }
        if (sendto(fd, buf, sizeof buf, MSG_DONTWAIT, (struct sockaddr *)&sa, sizeof sa) >= 0) sent++;
        else errs++;
    }
    printf("sent %lu errors %lu\n", sent, errs);
    return 0;
}
