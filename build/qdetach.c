/* Проверка одного утверждения: закрывает ли close() очередь multi-queue TUN так, что ядро
 * перестаёт в неё раскладывать потоки.
 *
 * От ответа зависит, есть ли в steer дефект «мёртвая очередь». Если ядро после close
 * перераспределяет потоки по живым очередям, то поток, вышедший по ошибке epoll, никакого
 * трафика не теряет. Если нет — четверть соединений уходит в никуда.
 *
 * Опыт: открыть две очереди, закрыть вторую, пустить много разных потоков и посмотреть,
 * все ли пакеты читаются из первой. Хэш у ядра по потоку, значит без перераспределения
 * примерно половина не дойдёт.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <poll.h>
#include <sys/ioctl.h>
#include <net/if.h>
#include <linux/if_tun.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <netinet/in.h>

static int qopen(const char *name, short flags) {
    int fd = open("/dev/net/tun", O_RDWR);
    if (fd < 0) { perror("open /dev/net/tun"); return -1; }
    struct ifreq ifr;
    memset(&ifr, 0, sizeof ifr);
    ifr.ifr_flags = flags;
    snprintf(ifr.ifr_name, IFNAMSIZ, "%s", name);
    if (ioctl(fd, TUNSETIFF, &ifr) < 0) { perror("TUNSETIFF"); close(fd); return -1; }
    return fd;
}

int main(void) {
    const char *dev = "qtest0";
    short flags = IFF_TUN | IFF_NO_PI | IFF_MULTI_QUEUE;

    int q0 = qopen(dev, flags);
    if (q0 < 0) return 2;
    int q1 = qopen(dev, flags);
    if (q1 < 0) { fprintf(stderr, "вторая очередь не открылась — ядро без MULTI_QUEUE\n"); return 2; }
    printf("две очереди открыты\n");

    /* Поднять устройство и маршрут в него. */
    char cmd[256];
    snprintf(cmd, sizeof cmd, "ip addr add 198.51.100.1/24 dev %s 2>/dev/null; ip link set %s up", dev, dev);
    if (system(cmd)) { fprintf(stderr, "не удалось поднять %s\n", dev); return 2; }

    /* Закрываем ВТОРУЮ очередь: именно это делает worker_loop на выходе по ошибке. */
    close(q1);
    printf("вторая очередь закрыта\n");

    /* Пускаем 40 разных потоков (разные адреса назначения => разный хэш) и считаем,
     * сколько пакетов пришло в первую очередь. Без перераспределения половина осядет
     * в закрытой. */
    const int FLOWS = 40;
    for (int i = 0; i < FLOWS; i++) {
        int s = socket(AF_INET, SOCK_DGRAM, 0);
        if (s < 0) continue;
        struct sockaddr_in a = { .sin_family = AF_INET, .sin_port = htons(9000 + i) };
        a.sin_addr.s_addr = htonl(0xC6336402u + i);   /* 198.51.100.2 + i */
        char buf[16] = "steer-qtest";
        sendto(s, buf, sizeof buf, 0, (struct sockaddr *)&a, sizeof a);
        close(s);
    }

    int got = 0;
    unsigned char pkt[2048];
    for (;;) {
        struct pollfd p = { .fd = q0, .events = POLLIN };
        if (poll(&p, 1, 700) <= 0) break;
        ssize_t n = read(q0, pkt, sizeof pkt);
        if (n <= 0) break;
        got++;
    }
    printf("отправлено потоков %d, прочитано пакетов из первой очереди %d\n", FLOWS, got);

    /* Вывод: цифры сравнивает человек, но крайние случаи назовём сами. */
    if (got >= FLOWS)
        printf("ВЫВОД: close() отсоединяет очередь, ядро перераспределяет потоки — "
               "мёртвой очереди не остаётся\n");
    else if (got == 0)
        printf("ВЫВОД: в первую очередь не пришло ничего — опыт не удался, "
               "проверять нечего\n");
    else
        printf("ВЫВОД: пришло %d из %d — часть потоков осела в закрытой очереди, "
               "дефект настоящий\n", got, FLOWS);

    close(q0);
    snprintf(cmd, sizeof cmd, "ip link del %s 2>/dev/null", dev);
    system(cmd);
    return 0;
}
