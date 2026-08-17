/* Чем платит транспорт: сырой сокет против TUN. Стенд отвечает на один вопрос — «а с TUN было
 * бы быстрее?» — и отвечает числами, потому что рассуждением он не решается.
 *
 * ЧТО ЗДЕСЬ СРАВНИВАЕТСЯ. Два способа отдать и принять поддельный сегмент TCP:
 *   - сырой сокет (то, что делает xsteer): sendmmsg пачкой на отправку, recvmmsg с фильтром
 *     cBPF на приём;
 *   - TUN с перенаправлением (то, что делает phantun): write на пакет, а на приёме правило
 *     DNAT заворачивает поток в устройство, откуда мы его читаем.
 * Работа у сторон одинаковая: пакет обязан РЕАЛЬНО уйти соседу по veth (проверяется счётчиком
 * на его интерфейсе) или реально дойти до нас.
 *
 * ЧТО СТЕНД РЕШАЕТ. Отправку: пачка против вызова на пакет — разница устойчиво измерима.
 * ЧТО НЕ РЕШАЕТ: приём. Отправитель здесь сам себя притормаживает, когда буфер полон, и его
 * собственная цена входит в общий счёт процессора, поэтому разницу меньше примерно трети на
 * приёме этот стенд не различает. Числа по приёму надо брать из профиля живого прогона
 * (perf record во время tests/run-xsteer.sh), там видны и клон skb на каждый сокет воркера, и
 * RST, который ядро порождает на каждый принятый сегмент.
 *
 * ОДНО НАБЛЮДЕНИЕ ЦЕНОЙ ОТДЕЛЬНОГО ЧАСА. Вариант с TUN работает только если сумма TCP в наших
 * поддельных сегментах верна: иначе conntrack объявляет поток недействительным, правило DNAT к
 * нему не применяется, и пакеты уходят не туда — молча. У сырого сокета такой зависимости нет
 * вовсе: ядро отбрасывает свою копию, а наша приходит. Это не довод «за» или «против», это
 * условие, которое надо знать, если вариант с TUN когда-нибудь захотят попробовать.
 *
 * Запускать:  sudo sh tests/transportcost.sh
 */
/* Приём: сырой сокет с фильтром против TUN с перенаправлением. Три режима.
 *
 *   transportcost tx   <адрес>            — сравнить ОТПРАВКУ (пачки 1/4/16 против TUN)
 *   transportcost send <адрес> <сколько>  — залить пакетами на порт 443 (для приёмных режимов)
 *   transportcost raw  <сколько> <сокетов> — принимать сырым сокетом (как сейчас в xsteer)
 *   transportcost tun  <сколько>           — принимать из TUN с DNAT (как phantun)
 *   transportcost pkt  <сколько> <сокетов> — принимать AF_PACKET с раскладкой PACKET_FANOUT
 *
 * Число сокетов у приёмника важно: ядро клонирует skb для КАЖДОГО сырого сокета, и именно это
 * ограничивает многопоточность хаба. Внимание: все сокеты здесь слушают ОДИН порт без
 * раскладки, поэтому каждый получает копию каждого пакета — сравнивать их пропускную
 * способность между собой нельзя, годится только счёт процессора.
 */
#define _GNU_SOURCE
#include <fcntl.h>
#include <linux/filter.h>
#include <linux/if.h>
#include <linux/if_tun.h>
#include <linux/if_ether.h>
#include <linux/if_packet.h>
#include <net/ethernet.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <poll.h>
#include <time.h>
#include <unistd.h>

#define PKT 1439
#define N   300000        /* пакетов на один прогон отправки */
#define BATCH 16

static long long now_ns(void) {
    struct timespec t;
    clock_gettime(CLOCK_MONOTONIC, &t);
    return (long long)t.tv_sec * 1000000000LL + t.tv_nsec;
}

/* Сумма для заголовка IP: считается по полю суммы, обнулённому заранее. */
static unsigned short csum16(const unsigned char *p, size_t n) {
    unsigned long s = 0;
    for (size_t i = 0; i + 1 < n; i += 2) s += (unsigned long)((p[i] << 8) | p[i + 1]);
    if (n & 1) s += (unsigned long)p[n - 1] << 8;
    while (s >> 16) s = (s & 0xFFFF) + (s >> 16);
    return (unsigned short)(~s & 0xFFFF);
}

static void filter_port(int fd, unsigned short port) {
    struct sock_filter code[] = {
        { BPF_LDX | BPF_B | BPF_MSH, 0, 0, 0 },
        { BPF_LD | BPF_H | BPF_IND, 0, 0, 2 },
        { BPF_JMP | BPF_JEQ | BPF_K, 0, 1, port },
        { BPF_RET | BPF_K, 0, 0, 0xFFFFFFFF },   /* совпало — берём */
        { BPF_RET | BPF_K, 0, 0, 0 },            /* нет — мимо */
    };
    struct sock_fprog p = { 5, code };
    setsockopt(fd, SOL_SOCKET, SO_ATTACH_FILTER, &p, sizeof(p));
}

static int tx_compare(const char *dst) {
        static unsigned char pkt[PKT];
    memset(pkt, 0x41, sizeof(pkt));
    /* Заголовок IP для пути TUN: источник из подсети устройства, получатель — сосед. */
    memset(pkt, 0, 40);                 /* заголовки обнуляем: сумма считается по нулевому полю */
    pkt[0] = 0x45; pkt[2] = (PKT >> 8); pkt[3] = PKT & 0xFF;
    pkt[8] = 64; pkt[9] = 6;
    unsigned s4 = inet_addr("10.91.0.2"), d4 = inet_addr(dst);
    memcpy(pkt + 12, &s4, 4); memcpy(pkt + 16, &d4, 4);
    unsigned short c = csum16(pkt, 20);
    pkt[10] = c >> 8; pkt[11] = c & 0xFF;
    /* Заголовок TCP, чтобы пакет был правдоподобным. */
    unsigned short sp = htons(40000), dp = htons(443);
    memcpy(pkt + 20, &sp, 2); memcpy(pkt + 22, &dp, 2);
    pkt[32] = 0x50; pkt[33] = 0x10; pkt[34] = 0xFF; pkt[35] = 0xFF;

    printf("пакет %d байт, по %d штук, получатель %s\n", PKT, N, dst);

    /* ---- сырой сокет ---- */
    int rf = socket(AF_INET, SOCK_RAW, IPPROTO_TCP);
    if (rf < 0) { perror("raw"); return 1; }
    struct sockaddr_in to;
    memset(&to, 0, sizeof(to));
    to.sin_family = AF_INET;
    to.sin_addr.s_addr = d4;
    if (connect(rf, (struct sockaddr *)&to, sizeof(to)) != 0) { perror("connect"); return 1; }
    int one = 1;
    setsockopt(rf, SOL_SOCKET, SO_SNDBUF, &(int){1 << 21}, sizeof(int));
    (void)one;
    for (int batch = 1; batch <= 16; batch *= 4) {
        struct mmsghdr *mm = calloc((size_t)batch, sizeof(*mm));
        struct iovec *iov = calloc((size_t)batch, sizeof(*iov));
        for (int i = 0; i < batch; i++) {
            iov[i].iov_base = pkt + 20;          /* заголовок IP ставит ядро */
            iov[i].iov_len = PKT - 20;
            mm[i].msg_hdr.msg_iov = &iov[i];
            mm[i].msg_hdr.msg_iovlen = 1;
        }
        long long t0 = now_ns();
        long sent = 0;
        for (int i = 0; i < N / batch; i++) {
            int r = sendmmsg(rf, mm, (unsigned)batch, 0);
            if (r > 0) sent += r;
        }
        long long t1 = now_ns();
        printf("  сырой сокет, пачка %2d:   %7.0f нс/пакет  (ушло %ld)\n",
               batch, (double)(t1 - t0) / (double)(N / batch * batch), sent);
        free(mm); free(iov);
    }
    close(rf);

    /* ---- TUN ---- */
    int tf = open("/dev/net/tun", O_RDWR);
    if (tf < 0) { perror("tun"); return 1; }
    struct ifreq ifr;
    memset(&ifr, 0, sizeof(ifr));
    ifr.ifr_flags = IFF_TUN | IFF_NO_PI;
    strcpy(ifr.ifr_name, "sct0");
    if (ioctl(tf, TUNSETIFF, &ifr) < 0) { perror("TUNSETIFF"); return 1; }
    if (system("ip addr add 10.91.0.1/24 dev sct0 >/dev/null 2>&1;"
               "ip link set sct0 up >/dev/null 2>&1;"
               "sysctl -qw net.ipv4.ip_forward=1")) { }
    long long t0 = now_ns();
    long w = 0;
    for (int i = 0; i < N; i++) if (write(tf, pkt, PKT) == PKT) w++;
    long long t1 = now_ns();
    printf("  TUN, write на пакет:     %7.0f нс/пакет  (ушло %ld)\n",
           (double)(t1 - t0) / (double)N, w);
    return 0;
}

int main(int argc, char **argv) {
    if (argc < 2) return 2;
    const char *mode = argv[1];

    if (!strcmp(mode, "tx")) {
        /* Отправка: сырой сокет пачками 1/4/16 против write в TUN. Получатель — сосед по veth,
         * пакеты обязаны реально уйти (стендовый скрипт сверяет счётчик на его интерфейсе). */
        const char *dst = argc > 2 ? argv[2] : "10.90.0.2";
        return tx_compare(dst);
    }

    if (!strcmp(mode, "send")) {
        long n = atol(argv[3]);
        int fd = socket(AF_INET, SOCK_RAW, IPPROTO_TCP);
        struct sockaddr_in to;
        memset(&to, 0, sizeof(to));
        to.sin_family = AF_INET;
        to.sin_addr.s_addr = inet_addr(argv[2]);
        if (connect(fd, (struct sockaddr *)&to, sizeof(to)) != 0) { perror("connect"); return 1; }
        setsockopt(fd, SOL_SOCKET, SO_SNDBUF, &(int){1 << 21}, sizeof(int));
        static unsigned char body[PKT];
        memset(body, 0, 40);
        memset(body + 40, 0x42, sizeof(body) - 40);
        unsigned short sp = htons(40000), dp = htons(443);
        memcpy(body, &sp, 2); memcpy(body + 2, &dp, 2);
        body[12] = 0x50; body[13] = 0x10; body[14] = 0xFF; body[15] = 0xFF;
        /* Сумма TCP ОБЯЗАТЕЛЬНА, и это не формальность: без неё conntrack объявляет поток
         * недействительным, правило DNAT к нему не применяется, и пакет уходит не туда, куда
         * задумано. В самом xsteer сумма считается всегда (obfs_tcp_csum). */
        {
            unsigned long sum = 0;
            unsigned src = inet_addr("10.90.0.2"), dst2 = to.sin_addr.s_addr;
            const unsigned char *a = (const unsigned char *)&src, *b = (const unsigned char *)&dst2;
            sum += (unsigned)((a[0] << 8) | a[1]) + (unsigned)((a[2] << 8) | a[3]);
            sum += (unsigned)((b[0] << 8) | b[1]) + (unsigned)((b[2] << 8) | b[3]);
            sum += 6;
            sum += (unsigned)(PKT - 20);
            for (int i = 0; i + 1 < PKT - 20; i += 2)
                sum += (unsigned)((body[i] << 8) | body[i + 1]);
            if ((PKT - 20) & 1) sum += (unsigned)body[PKT - 21] << 8;
            while (sum >> 16) sum = (sum & 0xFFFF) + (sum >> 16);
            unsigned short ck = (unsigned short)(~sum & 0xFFFF);
            body[16] = (unsigned char)(ck >> 8);
            body[17] = (unsigned char)(ck & 0xFF);
        }
        struct mmsghdr mm[BATCH];
        struct iovec iov[BATCH];
        for (int i = 0; i < BATCH; i++) {
            iov[i].iov_base = body;
            iov[i].iov_len = PKT - 20;
            memset(&mm[i].msg_hdr, 0, sizeof(mm[i].msg_hdr));
            mm[i].msg_hdr.msg_iov = &iov[i];
            mm[i].msg_hdr.msg_iovlen = 1;
        }
        long sent = 0;
        while (sent < n) {
            int r = sendmmsg(fd, mm, BATCH, 0);
            if (r > 0) sent += r; else usleep(200);
        }
        printf("отправлено %ld\n", sent);
        return 0;
    }

    if (!strcmp(mode, "pkt")) {
        /* AF_PACKET: пакет достаётся приложению ДО netfilter, поэтому ядру можно прямо
         * запретить видеть этот порт — тогда оно не порождает RST на каждый наш сегмент.
         * SOCK_DGRAM снимает канальный заголовок, то есть разбор остаётся тем же, что у
         * сырого сокета. PACKET_FANOUT раскладывает пакеты по сокетам группы хэшем потока:
         * пакет достаётся РОВНО ОДНОМУ, то есть клон не умножается на число воркеров. */
        long want2 = atol(argv[2]);
        int nw = argc > 3 ? atoi(argv[3]) : 1;
        if (nw < 1) nw = 1;
        if (system("nft add table ip pktdrop;"
                   "nft add chain ip pktdrop in '{ type filter hook input priority -300; }';"
                   "nft add rule ip pktdrop in tcp dport 443 drop")) { }
        int fds[8];
        struct pollfd pf[8];
        for (int i = 0; i < nw; i++) {
            fds[i] = socket(AF_PACKET, SOCK_DGRAM, htons(ETH_P_IP));
            if (fds[i] < 0) { perror("AF_PACKET"); return 1; }
            filter_port(fds[i], 443);
            setsockopt(fds[i], SOL_SOCKET, SO_RCVBUF, &(int){1 << 22}, sizeof(int));
            int fl = fcntl(fds[i], F_GETFL, 0);
            fcntl(fds[i], F_SETFL, fl | O_NONBLOCK);
            /* Группа одна на всех: хэш считает ядро, и одно соединение всегда достаётся
             * одному и тому же сокету. */
            int fanout = (1234 & 0xFFFF) | (PACKET_FANOUT_HASH << 16);
            if (nw > 1 && setsockopt(fds[i], SOL_PACKET, PACKET_FANOUT,
                                     &fanout, sizeof(fanout)) != 0)
                perror("PACKET_FANOUT");
            pf[i].fd = fds[i];
            pf[i].events = POLLIN;
        }
        static unsigned char buf[BATCH][2048];
        struct mmsghdr mm[BATCH];
        struct iovec iov[BATCH];
        for (int i = 0; i < BATCH; i++) {
            iov[i].iov_base = buf[i];
            iov[i].iov_len = sizeof(buf[i]);
            memset(&mm[i].msg_hdr, 0, sizeof(mm[i].msg_hdr));
            mm[i].msg_hdr.msg_iov = &iov[i];
            mm[i].msg_hdr.msg_iovlen = 1;
        }
        long long p0 = 0;
        long pgot = 0;
        while (pgot < want2) {
            int pr = poll(pf, (nfds_t)nw, 3000);
            if (pr <= 0) { if (p0) break; else continue; }
            for (int i = 0; i < nw; i++) {
                if (!(pf[i].revents & POLLIN)) continue;
                for (;;) {
                    int r = recvmmsg(fds[i], mm, BATCH, MSG_DONTWAIT, NULL);
                    if (r <= 0) break;
                    if (!p0) p0 = now_ns();
                    pgot += r;
                    if (r < BATCH) break;
                }
            }
        }
        long long p1 = now_ns();
        if (system("nft delete table ip pktdrop 2>/dev/null")) { }
        if (!p0) { printf("не принято ничего\n"); return 1; }
        printf("принято %ld за %.2f мс = %.0f нс/пакет, %.0f тыс. пак/с\n",
               pgot, (double)(p1 - p0) / 1e6, (double)(p1 - p0) / (double)pgot,
               (double)pgot / ((double)(p1 - p0) / 1e9) / 1000.0);
        return 0;
    }

    long want = atol(argv[2]);
    long long t0 = 0, t1;
    long got = 0;

    if (!strcmp(mode, "raw")) {
        int nw = argc > 3 ? atoi(argv[3]) : 1;
        if (nw < 1) nw = 1;
        int fds[8];
        for (int i = 0; i < nw; i++) {
            fds[i] = socket(AF_INET, SOCK_RAW, IPPROTO_TCP);
            int fl = fcntl(fds[i], F_GETFL, 0);
            fcntl(fds[i], F_SETFL, fl | O_NONBLOCK);
            setsockopt(fds[i], SOL_SOCKET, SO_RCVBUF, &(int){1 << 22}, sizeof(int));
            filter_port(fds[i], 443);
        }
        static unsigned char buf[BATCH][2048];
        struct mmsghdr mm[BATCH];
        struct iovec iov[BATCH];
        for (int i = 0; i < BATCH; i++) {
            iov[i].iov_base = buf[i];
            iov[i].iov_len = sizeof(buf[i]);
            memset(&mm[i].msg_hdr, 0, sizeof(mm[i].msg_hdr));
            mm[i].msg_hdr.msg_iov = &iov[i];
            mm[i].msg_hdr.msg_iovlen = 1;
        }
        /* Ждём через poll, а не крутим цикл: холостой спин измерял бы сам себя. */
        struct pollfd pf[8];
        for (int i = 0; i < nw; i++) { pf[i].fd = fds[i]; pf[i].events = POLLIN; }
        while (got < want) {
            int pr = poll(pf, (nfds_t)nw, 3000);
            if (pr <= 0) { if (t0) break; else continue; }
            for (int i = 0; i < nw; i++) {
                if (!(pf[i].revents & POLLIN)) continue;
                for (;;) {
                    int r = recvmmsg(fds[i], mm, BATCH, MSG_DONTWAIT, NULL);
                    if (r <= 0) break;
                    if (!t0) t0 = now_ns();
                    got += r;
                    if (r < BATCH) break;
                }
            }
        }
    } else {
        int tf = open("/dev/net/tun", O_RDWR);
        struct ifreq ifr;
        memset(&ifr, 0, sizeof(ifr));
        ifr.ifr_flags = IFF_TUN | IFF_NO_PI;
        strcpy(ifr.ifr_name, "rxt0");
        if (ioctl(tf, TUNSETIFF, &ifr) < 0) { perror("TUNSETIFF"); return 1; }
        if (system("ip addr add 10.91.0.1/24 dev rxt0 >/dev/null 2>&1;"
                   "ip link set rxt0 up >/dev/null 2>&1;"
                   "sysctl -qw net.ipv4.ip_forward=1;"
                   "nft add table ip rxt;"
                   "nft add chain ip rxt pre '{ type nat hook prerouting priority dstnat; }';"
                   "nft add rule ip rxt pre tcp dport 443 dnat to 10.91.0.2;"
                   "ip route replace 10.91.0.2/32 dev rxt0")) { }
        static unsigned char buf[2048];
        int fl = fcntl(tf, F_GETFL, 0);
        fcntl(tf, F_SETFL, fl | O_NONBLOCK);
        struct pollfd pf = { tf, POLLIN, 0 };
        while (got < want) {
            int pr = poll(&pf, 1, 3000);
            if (pr <= 0) { if (t0) break; else continue; }
            for (;;) {
                ssize_t r = read(tf, buf, sizeof(buf));
                if (r <= 0) break;
                if (!t0) t0 = now_ns();
                got++;
            }
        }
    }
    t1 = now_ns();
    if (!t0) { printf("не принято ничего\n"); return 1; }
    printf("принято %ld за %.2f мс = %.0f нс/пакет, %.0f тыс. пак/с\n",
           got, (double)(t1 - t0) / 1e6, (double)(t1 - t0) / (double)(got ? got : 1),
           (double)got / ((double)(t1 - t0) / 1e9) / 1000.0);
    return 0;
}
