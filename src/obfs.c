/* WireGuard поверх поддельного TCP: обфускация UDP-транспорта выхода.
 *
 * ЗАЧЕМ. Выход kind=interface — это WireGuard, а WireGuard это UDP целиком. Там, где
 * UDP режут, деприоритизируют или пропускают по белому списку протоколов, выход мёртв
 * при полностью исправной маршрутизации: устройство поднято, метки стоят, таблица
 * ведёт куда надо, и ни один пакет не доходит. Лечится это переносом датаграмм в поток,
 * который выглядит как обычный TCP.
 *
 * ПОЧЕМУ ПОДДЕЛЬНЫЙ, А НЕ НАСТОЯЩИЙ TCP. Датаграммы поверх настоящего TCP — это
 * TCP-over-TCP: внешний слой начинает переспрашивать потерянное, внутренний тоже, и
 * одна потеря превращается в лавину повторов. Поэтому здесь то же решение, что у
 * phantun: TCP-заголовок настоящий (рукопожатие, номера, флаги — всё, на что смотрят
 * межсетевые экраны и NAT), а семантика остаётся датаграммной: ни повторов, ни окна,
 * ни контроля потока. Одна датаграмма = один сегмент. Накладные — 12 байт против UDP
 * (20 байт заголовка TCP вместо 8 байт UDP).
 *
 * ФОРМАТ СОВМЕСТИМ С phantun: с той стороны может стоять как `steer obfs-server`, так и
 * апстримовый phantun_server, и наоборот. Всё, что делается сверх него (случайный ISN,
 * MSS в SYN, регулярные ACK), — поля, которые вторая сторона игнорирует.
 *
 * ПОЧЕМУ СЫРОЙ СОКЕТ, А НЕ TUN. Апстрим пишет пакеты в свой TUN, а наружу их выпускает
 * маршрутизацией с masquerade — ему нужен ip_forward, правило NAT и, на OpenWrt, ещё и
 * зона fw4 для этого интерфейса. Зона, которой нет, — самый частый тихий отказ в этом
 * проекте (см. fw_check и выход kind=interface без зоны). Сырой сокет не требует ни
 * интерфейса, ни NAT, ни форвардинга: пакет уходит с настоящего адреса роутера.
 *
 * ЦЕНА СЫРОГО СОКЕТА — ОДНО ПРАВИЛО. Ядро не имеет сокета на наш порт и на входящий
 * сегмент отвечает RST, обрывая нашу же сессию. Поэтому процесс ставит себе правило,
 * гасящее ИСХОДЯЩИЙ RST в сторону сервера обфускации, и снимает его при выходе. Правило
 * живёт в отдельной таблице `steer_obfs`, а не в `inet steer`: последнюю `apply`
 * пересобирает целиком, и правило исчезало бы при каждом сохранении настроек.
 *
 * ЧЕГО ЗДЕСЬ НЕТ И ПОЧЕМУ. Шифрования нет: его делает WireGuard, второй слой добавил бы
 * только вес. Повторов нет — см. про лавину. Фрагментации нет, но, в отличие от
 * апстрима, DF мы и не ставим: при ошибке в MTU ядро фрагментирует, и настройка
 * деградирует, а не отваливается молча на больших пакетах — худший класс отказов.
 */
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <poll.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>
#include <sys/socket.h>
#include <sys/types.h>
#include "obfs.h"

#define LOG_W "steer[warn] obfs: "
#define LOG_I "steer[info] obfs: "

/* Живёт в failover.c: запуск внешней команды без оболочки (argv массивом, не строкой). */
int run_quiet(const char *const argv[]);

/* ---- заголовки на проводе -------------------------------------------------
 *
 * Свои структуры, а не <netinet/ip.h> и <netinet/tcp.h>: имена полей там зависят от
 * libc и от feature-макросов, и один и тот же файл собирается по-разному под glibc и
 * musl. Здесь важен байтовый порядок полей, а не удобство. */
struct ip4_hdr {
    uint8_t  vhl, tos;
    uint16_t len, id, off;
    uint8_t  ttl, proto;
    uint16_t sum;
    uint32_t src, dst;
};

struct tcp_hdr {
    uint16_t sport, dport;
    uint32_t seq, ack;
    uint8_t  off;               /* верхние 4 бита — длина заголовка в 32-битных словах */
    uint8_t  flags;
    uint16_t win, sum, urp;
};

#define TH_FIN 0x01
#define TH_SYN 0x02
#define TH_RST 0x04
#define TH_PSH 0x08
#define TH_ACK 0x10

/* Окно объявляем максимальное без масштабирования. Меньшее не даёт ничего: потока мы
 * не контролируем, а маленькое окно заставило бы conntrack по дороге считать наши же
 * сегменты вышедшими за его пределы и метить их invalid. */
#define OBFS_WIN 65535

/* Больше одной датаграммы WireGuard в сегмент не кладём, поэтому предел — самая
 * большая датаграмма, которую туннель может породить, с запасом на служебные пакеты. */
#define OBFS_MAX_PAYLOAD 1600
#define OBFS_PKT_MAX ((int)sizeof(struct ip4_hdr) + 60 + OBFS_MAX_PAYLOAD)

enum { ST_CLOSED, ST_SYN_SENT, ST_SYN_RCVD, ST_EST };

struct fconn {
    uint32_t saddr, daddr;      /* сетевой порядок */
    uint16_t sport, dport;      /* хостовый порядок */
    uint32_t seq, ack;          /* хостовый порядок */
    int state;
    int syn_tries;
    long long last_rx, last_tx, last_ack;   /* монотонные миллисекунды */
    int unacked;                /* принято сегментов с прошлого нашего ACK */
};

/* Монотонные часы, а не time(): секундной гранулярности не хватает отложенному ACK,
 * а стенным часам нельзя доверять таймауты — ntp на роутере прыгает при первой
 * синхронизации после загрузки, и «тишина 60 секунд» случилась бы на ровном месте. */
static long long now_ms(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (long long)ts.tv_sec * 1000 + ts.tv_nsec / 1000000;
}

/* ---- контрольные суммы ----------------------------------------------------- */
static uint32_t csum_add(const void *data, size_t len, uint32_t acc) {
    const uint8_t *p = data;
    while (len > 1) { acc += (uint32_t)((p[0] << 8) | p[1]); p += 2; len -= 2; }
    if (len) acc += (uint32_t)(p[0] << 8);
    return acc;
}

static uint16_t csum_fin(uint32_t acc) {
    while (acc >> 16) acc = (acc & 0xFFFF) + (acc >> 16);
    return (uint16_t)(~acc & 0xFFFF);
}

/* Псевдозаголовок TCP: адреса, протокол и длина. Ядро сырому сокету сумму не считает —
 * сегмент с неверной суммой уйдёт, и стек той стороны отбросит его молча, поэтому
 * считаем сами; на входе по той же причине проверяем. */
uint16_t obfs_tcp_csum(uint32_t saddr, uint32_t daddr, const void *seg, size_t len) {
    uint8_t ph[12];
    memcpy(ph, &saddr, 4);
    memcpy(ph + 4, &daddr, 4);
    ph[8] = 0;
    ph[9] = 6;                                  /* IPPROTO_TCP */
    ph[10] = (uint8_t)(len >> 8);
    ph[11] = (uint8_t)(len & 0xFF);
    uint32_t acc = csum_add(ph, sizeof(ph), 0);
    acc = csum_add(seg, len, acc);
    return csum_fin(acc);
}

/* ---- случайность ----------------------------------------------------------
 *
 * Начальный номер последовательности и исходный порт — случайные, а не с нуля, как в
 * апстриме: поток, у которого seq всегда начинается с нуля, отличается от настоящего
 * TCP одним признаком, а вся затея — про то, чтобы не отличаться. */
static uint32_t rnd32(void) {
    static int seeded;
    static uint32_t s;
    if (!seeded) {
        seeded = 1;
        int fd = open("/dev/urandom", O_RDONLY);
        if (fd >= 0) {
            if (read(fd, &s, sizeof(s)) != (ssize_t)sizeof(s)) s = 0;
            close(fd);
        }
        if (!s) s = (uint32_t)time(NULL) ^ ((uint32_t)getpid() << 16);
    }
    /* xorshift32: нужен разброс, а не криптостойкость — секретов эти числа не несут. */
    s ^= s << 13; s ^= s >> 17; s ^= s << 5;
    return s;
}

/* ---- сборка и разбор сегмента ---------------------------------------------- */
/* Возвращает длину сегмента в buf. buf должен вмещать 60 + OBFS_MAX_PAYLOAD. */
size_t obfs_build(uint8_t *buf, uint32_t saddr, uint32_t daddr,
                  uint16_t sport, uint16_t dport, uint32_t seq, uint32_t ack,
                  uint8_t flags, int with_mss, const void *payload, size_t plen) {
    struct tcp_hdr *t = (struct tcp_hdr *)buf;
    size_t hlen = sizeof(*t);

    memset(t, 0, sizeof(*t));
    t->sport = htons(sport);
    t->dport = htons(dport);
    t->seq = htonl(seq);
    t->ack = htonl(ack);
    t->flags = flags;
    t->win = htons(OBFS_WIN);

    /* MSS в SYN — не оптимизация, а правдоподобие: SYN вообще без опций встречается так
     * редко, что сам по себе служит признаком. Заодно честно называет размер сегмента
     * промежуточным узлам. Апстрим опции не читает: полезную нагрузку он берёт по длине
     * заголовка, и лишние четыре байта её не сдвигают. */
    if (with_mss) {
        buf[hlen++] = 2; buf[hlen++] = 4;
        buf[hlen++] = (uint8_t)((1500 - 40) >> 8);
        buf[hlen++] = (uint8_t)((1500 - 40) & 0xFF);
    }
    t->off = (uint8_t)((hlen / 4) << 4);

    if (plen) memcpy(buf + hlen, payload, plen);
    size_t total = hlen + plen;
    t->sum = htons(obfs_tcp_csum(saddr, daddr, buf, total));
    return total;
}

/* Сырой сокет отдаёт пакет целиком, начиная с IP-заголовка; фрагменты ядро собирает до
 * выдачи, поэтому здесь всегда целый сегмент. Возврат -1 — «не наше или битое»:
 * вызывающий просто продолжает цикл, потому что на сыром сокете чужие пакеты — норма. */
int obfs_parse(const uint8_t *pkt, size_t n, struct obfs_seg *s) {
    if (n < sizeof(struct ip4_hdr)) return -1;
    const struct ip4_hdr *ip = (const struct ip4_hdr *)pkt;
    if ((ip->vhl >> 4) != 4) return -1;
    size_t ihl = (size_t)(ip->vhl & 0x0F) * 4;
    if (ihl < sizeof(struct ip4_hdr) || n < ihl + sizeof(struct tcp_hdr)) return -1;
    if (ip->proto != 6) return -1;

    const struct tcp_hdr *t = (const struct tcp_hdr *)(pkt + ihl);
    size_t thl = (size_t)(t->off >> 4) * 4;
    if (thl < sizeof(struct tcp_hdr) || ihl + thl > n) return -1;

    size_t seglen = n - ihl;
    if (obfs_tcp_csum(ip->src, ip->dst, pkt + ihl, seglen) != 0) return -1;

    s->saddr = ip->src;
    s->daddr = ip->dst;
    s->sport = ntohs(t->sport);
    s->dport = ntohs(t->dport);
    s->seq = ntohl(t->seq);
    s->ack = ntohl(t->ack);
    s->flags = t->flags;
    s->payload = pkt + ihl + thl;
    s->plen = seglen - thl;
    return 0;
}

/* Обновление ack по принятому сегменту: двигаем только вперёд и без требования
 * строгого порядка — повторов у нас нет, и требовать их семантику значило бы врать
 * самому себе. Сравнение через знаковую разность, иначе переполнение uint32 на
 * четырёх гигабайтах трафика откатило бы ack к началу и conntrack по дороге счёл бы
 * весь поток недействительным. */
uint32_t obfs_next_ack(uint32_t have, uint32_t seq, size_t plen) {
    uint32_t want = seq + (uint32_t)plen;
    return ((int32_t)(want - have) > 0) ? want : have;
}

/* ---- отбор пакетов в ядре --------------------------------------------------
 *
 * Сырой сокет получает КОПИЮ каждого TCP-пакета, доставляемого локально, — и это не
 * мелочь, а главная цена конструкции. На сервере обфускации локально доставляется в том
 * числе всё, что несёт сам туннель: пакет приходит к нам поддельным TCP, мы отдаём его
 * WireGuard, тот расшифровывает — и расшифрованный TCP снова доставляется локально,
 * снова попадая в очередь нашего сокета. Чем быстрее идёт туннель, тем больше мусора мы
 * копируем в userspace, тем чаще переполняется очередь, тем больше НАСТОЯЩИХ сегментов
 * теряется. Обратная связь с положительным знаком: скорость падала на глазах, а
 * /proc/net/raw показывал сотни тысяч drops на сокете, из которого никто не читает.
 *
 * Отбор поэтому делает ядро. Фильтр классический (cBPF), потому что он нужен на сокете
 * и должен работать на musl-роутере без libbpf и без прав на bpf(2).
 *
 * Смещения: у сырого сокета AF_INET данные начинаются с IP-заголовка, поэтому 12 — это
 * адрес источника, а длина заголовка берётся из младшего полубайта нулевого байта
 * (идиома `ldxb 4*([0]&0xf)`), после чего порты лежат по X+0 и X+2. Проверено не по
 * документации, а стендом: при неверном смещении не приходит вообще ничего.
 */
#include <linux/filter.h>

static void raw_filter(int fd, struct sock_filter *code, unsigned short n) {
    struct sock_fprog p;
    p.len = n;
    p.filter = code;
    /* Отказ не смертелен: без фильтра всё работает, просто дороже. Ругаться здесь
     * значило бы пугать там, где деградация измерима и не фатальна. */
    setsockopt(fd, SOL_SOCKET, SO_ATTACH_FILTER, &p, sizeof(p));
}

/* Клиент: только наша четвёрка. */
static void filter_client(int fd, uint32_t server_be, uint16_t sport, uint16_t dport) {
    struct sock_filter code[] = {
        BPF_STMT(BPF_LD  | BPF_W   | BPF_ABS, 12),                  /* ip saddr */
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, ntohl(server_be), 0, 5),
        BPF_STMT(BPF_LDX | BPF_B   | BPF_MSH, 0),                   /* X = ihl */
        BPF_STMT(BPF_LD  | BPF_H   | BPF_IND, 0),                   /* tcp sport */
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, sport, 0, 3),
        BPF_STMT(BPF_LD  | BPF_H   | BPF_IND, 2),                   /* tcp dport */
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, dport, 0, 1),
        BPF_STMT(BPF_RET | BPF_K, 0xFFFFFFFF),
        BPF_STMT(BPF_RET | BPF_K, 0),
    };
    raw_filter(fd, code, sizeof(code) / sizeof(code[0]));
}

/* Сервер: всё, что адресовано порту обфускации. Клиенты заранее неизвестны, поэтому
 * четвёрку здесь не проверить — но порт отсекает ровно тот мусор, ради которого фильтр
 * и заводится. */
static void filter_server(int fd, uint16_t port) {
    struct sock_filter code[] = {
        BPF_STMT(BPF_LDX | BPF_B   | BPF_MSH, 0),
        BPF_STMT(BPF_LD  | BPF_H   | BPF_IND, 2),                   /* tcp dport */
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, port, 0, 1),
        BPF_STMT(BPF_RET | BPF_K, 0xFFFFFFFF),
        BPF_STMT(BPF_RET | BPF_K, 0),
    };
    raw_filter(fd, code, sizeof(code) / sizeof(code[0]));
}

/* Сокеты, которые только отправляют: не принимать ничего. Без этого connect()'нутый
 * сокет сессии копил очередь на мегабайт и складывал туда весь встречный поток —
 * именно он и дал 146 тысяч drops на первом же замере под нагрузкой. */
static void filter_none(int fd) {
    struct sock_filter code[] = { BPF_STMT(BPF_RET | BPF_K, 0) };
    raw_filter(fd, code, 1);
}

/* ---- сырой сокет ----------------------------------------------------------- */
/* connect() на сыром сокете ничего не шлёт: он фиксирует получателя и заставляет ядро
 * выбрать маршрут, а с ним и адрес источника — тот самый, который нужен контрольной
 * сумме. Спрашивать адрес у интерфейса нельзя: их несколько, и правильный знает только
 * таблица маршрутизации. */
static int raw_open(uint32_t daddr, uint32_t *saddr_out) {
    int fd = socket(AF_INET, SOCK_RAW, IPPROTO_TCP);
    if (fd < 0) return -1;

    /* Не ставим DF: путь с меньшим MTU при ошибке в настройке даст фрагментацию, а не
     * тихую пропажу больших пакетов. */
    int mtu_mode = IP_PMTUDISC_DONT;
    setsockopt(fd, IPPROTO_IP, IP_MTU_DISCOVER, &mtu_mode, sizeof(mtu_mode));
    int buf = 1 << 20;
    setsockopt(fd, SOL_SOCKET, SO_RCVBUF, &buf, sizeof(buf));
    setsockopt(fd, SOL_SOCKET, SO_SNDBUF, &buf, sizeof(buf));

    struct sockaddr_in to;
    memset(&to, 0, sizeof(to));
    to.sin_family = AF_INET;
    to.sin_addr.s_addr = daddr;
    if (connect(fd, (struct sockaddr *)&to, sizeof(to)) != 0) { close(fd); return -1; }

    struct sockaddr_in me;
    socklen_t ml = sizeof(me);
    if (getsockname(fd, (struct sockaddr *)&me, &ml) != 0) { close(fd); return -1; }
    if (saddr_out) *saddr_out = me.sin_addr.s_addr;

    int fl = fcntl(fd, F_GETFL, 0);
    fcntl(fd, F_SETFL, fl | O_NONBLOCK);
    return fd;
}

static int conn_send(int fd, struct fconn *c, uint8_t flags,
                     const void *payload, size_t plen, int with_mss) {
    uint8_t buf[60 + OBFS_MAX_PAYLOAD];
    if (plen > OBFS_MAX_PAYLOAD) return -1;
    size_t n = obfs_build(buf, c->saddr, c->daddr, c->sport, c->dport,
                          c->seq, c->ack, flags, with_mss, payload, plen);
    if (send(fd, buf, n, MSG_NOSIGNAL) < 0) return -1;
    c->seq += (uint32_t)plen;
    if (flags & TH_SYN) c->seq += 1;            /* SYN занимает один номер */
    c->last_tx = now_ms();
    if (flags & TH_ACK) { c->unacked = 0; c->last_ack = c->last_tx; }
    return 0;
}

/* ---- правило против RST ядра ----------------------------------------------
 *
 * Ядро видит входящие сегменты (сырой сокет получает КОПИЮ, а не перехватывает их) и,
 * не найдя своего сокета, отвечает RST — то есть рвёт нашу же сессию. Гасим ровно
 * исходящий RST этого потока и только его.
 *
 * Своя таблица, а не `inet steer`: ту `apply` удаляет и создаёт заново при каждом
 * сохранении настроек, и правило исчезало бы вместе с ней. Цепочка на выход — чтобы
 * два выхода не гасили правила друг друга при остановке. */
static char g_chain[64];
static int g_chain_up;

static void chain_name(const char *out, char *dst, size_t n) {
    size_t k = 0;
    dst[k++] = 'o'; dst[k++] = '_';
    for (size_t i = 0; out[i] && k + 1 < n; i++) {
        char c = out[i];
        int ok = (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') ||
                 (c >= '0' && c <= '9') || c == '_';
        dst[k++] = ok ? c : '_';
    }
    dst[k] = '\0';
}

static void guard_down(void) {
    if (!g_chain_up) return;
    const char *del[] = { "nft", "delete", "chain", "inet", "steer_obfs", g_chain, NULL };
    run_quiet(del);
    g_chain_up = 0;
}

static void guard_sig(int sig) {
    guard_down();
    _exit(128 + sig);
}

/* Возвращает 0, если правило встало. Отказ не смертелен на сервере, где порт может быть
 * закрыт политикой firewall (тогда RST не порождается вовсе), но на клиенте означает,
 * что первую же сессию оборвёт собственное ядро — поэтому вызывающий говорит об этом
 * громко, а не молча продолжает. */
static int guard_up(const char *label, const char *peer_addr, int port, int is_server) {
    /* Имя цепочки обязано быть РАЗНЫМ у разных экземпляров, и это не аккуратность.
     * Серверные экземпляры звались одинаково («server»), поэтому второй сервер,
     * поднятый на другом порту, при выходе снимал цепочку первого — и тот оставался
     * работать без правила против RST. Снаружи это выглядело как «туннель отвалился
     * сам по себе»: ядро начинало отвечать RST на каждое рукопожатие, клиент рвал
     * сессию, пробовал с нового порта и так по кругу. Проверено на живом сервере,
     * ценой упавшего туннеля. Порт в имени делает экземпляры независимыми. */
    char label_buf[64];
    if (is_server) snprintf(label_buf, sizeof(label_buf), "srv%d", port);
    else snprintf(label_buf, sizeof(label_buf), "%.40s", label);
    chain_name(label_buf, g_chain, sizeof(g_chain));
    char portbuf[16];
    snprintf(portbuf, sizeof(portbuf), "%d", port);

    const char *tab[] = { "nft", "add", "table", "inet", "steer_obfs", NULL };
    if (run_quiet(tab) != 0) return -1;
    /* Снять хвост от прошлого падения: процесс мог уйти по SIGKILL, и тогда цепочка
     * осталась, а `add` поверх неё правило задвоил бы. */
    const char *delc[] = { "nft", "delete", "chain", "inet", "steer_obfs", g_chain, NULL };
    run_quiet(delc);
    const char *addc[] = { "nft", "add", "chain", "inet", "steer_obfs", g_chain,
                           "{ type filter hook output priority filter - 10; policy accept; }",
                           NULL };
    if (run_quiet(addc) != 0) return -1;

    /* Клиент: RST, адресованный серверу обфускации. Сервер: RST, уходящий с нашего
     * порта кому угодно — клиентов много и заранее они неизвестны.
     *
     * Маска `& rst == rst` вместо голого `flags rst` — потому что ядро отвечает на SYN
     * закрытого порта не чистым RST, а RST+ACK, и запись без маски в части версий nft
     * читается как сравнение поля флагов ЦЕЛИКОМ. Тогда правило ловит RST на данные и
     * пропускает ровно тот, который рвёт рукопожатие. Здешний nft вёл себя правильно и
     * без маски, но зависеть от версии в правиле, от которого зависит связь, незачем.
     *
     * `tcp window 0` отделяет RST ЯДРА от НАШЕГО. Ядро шлёт RST на несуществующее
     * соединение всегда с нулевым окном, а мы объявляем 65535 — и нам этот RST нужен:
     * им сервер сообщает клиенту, что сессии больше нет (например, после перезапуска).
     * Без такого различения клиент узнавал бы об этом только по тишине, то есть через
     * минуту, и перезапуск сервера стоил бы минуты простоя туннеля. */
    const char *rule_c[] = { "nft", "add", "rule", "inet", "steer_obfs", g_chain,
                             "ip", "daddr", peer_addr, "tcp", "dport", portbuf,
                             "tcp", "flags", "&", "rst", "==", "rst",
                             "tcp", "window", "0", "counter", "drop", NULL };
    const char *rule_s[] = { "nft", "add", "rule", "inet", "steer_obfs", g_chain,
                             "tcp", "sport", portbuf,
                             "tcp", "flags", "&", "rst", "==", "rst",
                             "tcp", "window", "0", "counter", "drop", NULL };
    if (run_quiet(is_server ? rule_s : rule_c) != 0) return -1;

    g_chain_up = 1;
    atexit(guard_down);
    signal(SIGTERM, guard_sig);
    signal(SIGINT, guard_sig);
    return 0;
}

/* ---- общие постоянные цикла ------------------------------------------------ */
#define TICK_MS     20          /* шаг цикла: чаще незачем, реже — заметно для ACK */
#define SYN_RETRY_MS 1000
#define SYN_RETRIES  6
#define ACK_SEGS     8          /* через сколько принятых сегментов слать голый ACK */
#define ACK_MS       40         /* и не реже, чем раз во столько миллисекунд */
#define DEAD_MS      60000      /* тишина при активной отправке — путь считается мёртвым */

/* ---- клиент ---------------------------------------------------------------- */
static void client_reset(struct fconn *c, uint32_t daddr, int dport) {
    memset(c, 0, sizeof(*c));
    c->daddr = daddr;
    c->dport = (uint16_t)dport;
    /* Порт из эфемерного диапазона и новый на каждое подключение: прежняя запись
     * conntrack по дороге может ещё жить, и повтор порта выглядел бы для неё
     * продолжением уже закрытого потока. */
    c->sport = (uint16_t)(32768 + (rnd32() % 28000));
    c->seq = rnd32();
    c->state = ST_CLOSED;
}

static int client_connect(struct fconn *c, int *raw_fd, uint32_t daddr, int dport) {
    if (*raw_fd >= 0) close(*raw_fd);
    client_reset(c, daddr, dport);
    *raw_fd = raw_open(daddr, &c->saddr);
    if (*raw_fd < 0) {
        fprintf(stderr, LOG_W "сырой сокет недоступен: %s\n", strerror(errno));
        return -1;
    }
    /* Фильтр ставится ДО первого SYN: между socket() и настройкой очередь успевает
     * набрать чужого, и на нагруженном роутере это тысячи пакетов. */
    filter_client(*raw_fd, daddr, c->dport, c->sport);
    if (conn_send(*raw_fd, c, TH_SYN, NULL, 0, 1) != 0) return -1;
    c->state = ST_SYN_SENT;
    c->syn_tries = 1;
    c->last_rx = now_ms();
    return 0;
}

int obfs_client(const char *out_name, const char *server, int server_port,
                const char *listen_addr, int listen_port) {
    struct in_addr sa;
    if (inet_pton(AF_INET, server, &sa) != 1) {
        fprintf(stderr, LOG_W "%s: сервер обфускации задаётся адресом, а не именем: %s\n",
                out_name, server);
        return 2;
    }

    int udp = socket(AF_INET, SOCK_DGRAM, 0);
    if (udp < 0) { perror("steer: udp"); return 1; }
    struct sockaddr_in la;
    memset(&la, 0, sizeof(la));
    la.sin_family = AF_INET;
    la.sin_port = htons((uint16_t)listen_port);
    if (inet_pton(AF_INET, listen_addr, &la.sin_addr) != 1)
        la.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    if (bind(udp, (struct sockaddr *)&la, sizeof(la)) != 0) {
        fprintf(stderr, LOG_W "%s: не занять %s:%d — %s\n", out_name, listen_addr,
                listen_port, strerror(errno));
        return 1;
    }
    int fl = fcntl(udp, F_GETFL, 0);
    fcntl(udp, F_SETFL, fl | O_NONBLOCK);

    if (guard_up(out_name, server, server_port, 0) != 0)
        fprintf(stderr, LOG_W "%s: правило против RST не встало — сессию может оборвать "
                              "собственное ядро (нет nft?)\n", out_name);

    struct fconn c;
    int raw = -1;
    /* Уходим с ошибкой, а не крутимся в цикле: подъём заново — дело procd, и его пауза
     * respawn заодно не даёт молотить сеть, которой ещё нет. */
    if (client_connect(&c, &raw, sa.s_addr, server_port) != 0) return 1;
    fprintf(stderr, LOG_I "%s: %s:%d ← udp %s:%d, порт %u\n",
            out_name, server, server_port, listen_addr, listen_port, c.sport);

    /* Откуда пришла последняя датаграмма WireGuard. Заранее неизвестно: исходный порт
     * ядро выбирает само, а `Endpoint` пира указывает только на нас. */
    struct sockaddr_in peer;
    socklen_t peer_len = 0;
    memset(&peer, 0, sizeof(peer));

    uint8_t pkt[OBFS_PKT_MAX];
    unsigned long long up_pkts = 0, down_pkts = 0, dropped = 0;

    for (;;) {
        struct pollfd fds[2];
        fds[0].fd = udp;  fds[0].events = POLLIN; fds[0].revents = 0;
        fds[1].fd = raw;  fds[1].events = POLLIN; fds[1].revents = 0;
        int n = poll(fds, 2, TICK_MS);
        if (n < 0 && errno != EINTR) break;

        /* Наружу: датаграмма WireGuard → один сегмент. */
        if (n > 0 && (fds[0].revents & POLLIN)) {
            for (;;) {
                struct sockaddr_in from;
                socklen_t fl2 = sizeof(from);
                ssize_t r = recvfrom(udp, pkt, OBFS_MAX_PAYLOAD, 0,
                                     (struct sockaddr *)&from, &fl2);
                if (r <= 0) break;
                peer = from;
                peer_len = fl2;
                if (c.state != ST_EST) { dropped++; continue; }
                if (conn_send(raw, &c, TH_PSH | TH_ACK, pkt, (size_t)r, 0) != 0) {
                    /* Переполненная очередь устройства — потеря одной датаграммы, а не
                     * повод рвать сессию: наверху WireGuard, он переспросит сам. */
                    if (errno == ENOBUFS || errno == EAGAIN || errno == EWOULDBLOCK) {
                        dropped++;
                        continue;
                    }
                    fprintf(stderr, LOG_W "%s: отправка не удалась: %s\n",
                            out_name, strerror(errno));
                    c.state = ST_CLOSED;
                    break;
                }
                up_pkts++;
            }
        }

        /* Обратно: сегмент → датаграмма тому, кто прислал последнюю. */
        if (n > 0 && (fds[1].revents & POLLIN)) {
            for (;;) {
                ssize_t r = recv(raw, pkt, sizeof(pkt), 0);
                if (r <= 0) break;
                struct obfs_seg s;
                if (obfs_parse(pkt, (size_t)r, &s) != 0) continue;
                /* Сырой сокет слышит весь TCP, доставляемый локально: чужое отсеиваем
                 * по четвёрке. Фильтр BPF в ядре сюда просится, но локально
                 * доставляемого TCP на роутере — только его собственное управление,
                 * единицы пакетов в секунду; лишняя хрупкость дороже выигрыша. */
                if (s.saddr != c.daddr || s.sport != c.dport ||
                    s.daddr != c.saddr || s.dport != c.sport) continue;

                c.last_rx = now_ms();

                if (s.flags & TH_RST) {
                    fprintf(stderr, LOG_W "%s: сервер оборвал сессию (RST)\n", out_name);
                    c.state = ST_CLOSED;
                    break;
                }
                if (c.state == ST_SYN_SENT && (s.flags & TH_SYN) && (s.flags & TH_ACK)) {
                    c.ack = s.seq + 1;
                    c.state = ST_EST;
                    conn_send(raw, &c, TH_ACK, NULL, 0, 0);
                    fprintf(stderr, LOG_I "%s: сессия установлена\n", out_name);
                    continue;
                }
                if (s.plen && c.state == ST_EST) {
                    c.ack = obfs_next_ack(c.ack, s.seq, s.plen);
                    c.unacked++;
                    /* Датаграмма отдаётся наверх в любом случае, даже вне порядка: за
                     * порядок и подлинность отвечает WireGuard, а не мы. */
                    if (peer_len)
                        sendto(udp, s.payload, s.plen, 0,
                               (struct sockaddr *)&peer, peer_len);
                    down_pkts++;
                }
            }
        }

        /* Часы: повтор рукопожатия, отложенный ACK, обнаружение мёртвого пути. */
        long long t = now_ms();
        if (c.state == ST_SYN_SENT && t - c.last_tx >= SYN_RETRY_MS) {
            if (c.syn_tries >= SYN_RETRIES) {
                fprintf(stderr, LOG_W "%s: сервер не отвечает (%d попыток)\n",
                        out_name, c.syn_tries);
                c.state = ST_CLOSED;
            } else {
                c.seq -= 1;                     /* повтор SYN — тот же сегмент, тот же номер */
                conn_send(raw, &c, TH_SYN, NULL, 0, 1);
                c.syn_tries++;
            }
        }
        /* Регулярный ACK — не вежливость. Апстрим подтверждает раз в 128 МиБ, и
         * отслеживающий окно conntrack по дороге считает всё сверх объявленного окна
         * недействительным. Подтверждая часто, мы держим поток в окне и заодно
         * выглядим как настоящий TCP. */
        if (c.state == ST_EST && c.unacked &&
            (c.unacked >= ACK_SEGS || t - c.last_ack >= ACK_MS))
            conn_send(raw, &c, TH_ACK, NULL, 0, 0);

        /* Мёртвый путь: мы шлём, ответа нет. Смена адреса WAN попадает сюда же —
         * пересоздание сокета заново спрашивает маршрут, а с ним и адрес источника. */
        if (c.state == ST_EST && up_pkts && t - c.last_rx > DEAD_MS) {
            fprintf(stderr, LOG_W "%s: %d с тишины при активной отправке — пересоздаю сессию\n",
                    out_name, DEAD_MS / 1000);
            c.state = ST_CLOSED;
        }
        if (c.state == ST_CLOSED) {
            fprintf(stderr, LOG_I "%s: наружу %llu, обратно %llu, потеряно до сессии %llu\n",
                    out_name, up_pkts, down_pkts, dropped);
            if (client_connect(&c, &raw, sa.s_addr, server_port) != 0) return 1;
        }
    }
    guard_down();
    return 1;
}

/* ---- сервер ----------------------------------------------------------------
 *
 * Сессий несколько: за одним сервером обфускации живёт целый набор клиентов. Ключ —
 * четвёрка, как в апстриме. Своего сокета UDP на сессию достаточно, чтобы ответы от
 * WireGuard возвращались тому, чьи они: connect() к цели фиксирует получателя, а ядро
 * само разводит ответы по сокетам. */
#define MAX_SESS 64
#define SESS_IDLE_MS 180000

struct sess {
    struct fconn c;
    int udp;                    /* к локальному WireGuard */
    int tx;                     /* сырой сокет к этому клиенту */
    int used;
};

static struct sess g_sess[MAX_SESS];

static struct sess *sess_find(uint32_t caddr, uint16_t cport) {
    for (int i = 0; i < MAX_SESS; i++)
        if (g_sess[i].used && g_sess[i].c.daddr == caddr && g_sess[i].c.dport == cport)
            return &g_sess[i];
    return NULL;
}

static void sess_free(struct sess *s) {
    if (s->udp >= 0) close(s->udp);
    if (s->tx >= 0) close(s->tx);
    s->udp = s->tx = -1;
    s->used = 0;
}

static struct sess *sess_alloc(uint32_t caddr, uint16_t cport, uint16_t our_port,
                               uint32_t fwd_addr, int fwd_port) {
    struct sess *slot = NULL, *oldest = NULL;
    for (int i = 0; i < MAX_SESS; i++) {
        if (!g_sess[i].used) { slot = &g_sess[i]; break; }
        if (!oldest || g_sess[i].c.last_rx < oldest->c.last_rx) oldest = &g_sess[i];
    }
    /* Таблица полна — вытесняем самую старую. Отказать новому клиенту ради записи,
     * которая молчит дольше всех, хуже: та либо жива и придёт снова, либо мертва. */
    if (!slot) { sess_free(oldest); slot = oldest; }

    memset(slot, 0, sizeof(*slot));
    slot->udp = slot->tx = -1;

    slot->tx = raw_open(caddr, &slot->c.saddr);
    if (slot->tx < 0) return NULL;
    filter_none(slot->tx);

    slot->udp = socket(AF_INET, SOCK_DGRAM, 0);
    if (slot->udp < 0) { sess_free(slot); return NULL; }
    struct sockaddr_in to;
    memset(&to, 0, sizeof(to));
    to.sin_family = AF_INET;
    to.sin_addr.s_addr = fwd_addr;
    to.sin_port = htons((uint16_t)fwd_port);
    if (connect(slot->udp, (struct sockaddr *)&to, sizeof(to)) != 0) {
        sess_free(slot);
        return NULL;
    }
    int fl = fcntl(slot->udp, F_GETFL, 0);
    fcntl(slot->udp, F_SETFL, fl | O_NONBLOCK);

    slot->used = 1;
    slot->c.daddr = caddr;
    slot->c.dport = cport;
    slot->c.sport = our_port;
    slot->c.seq = rnd32();
    slot->c.last_rx = now_ms();
    return slot;
}

int obfs_server(int listen_port, const char *forward, int forward_port) {
    struct in_addr fa;
    if (inet_pton(AF_INET, forward, &fa) != 1) {
        fprintf(stderr, LOG_W "адрес назначения задаётся адресом: %s\n", forward);
        return 2;
    }
    for (int i = 0; i < MAX_SESS; i++) { g_sess[i].udp = -1; g_sess[i].tx = -1; }

    /* Приём — один сырой сокет без connect: клиентов много и заранее они неизвестны.
     * Отвечает каждому свой сокет сессии, привязанный к её адресу. */
    int rx = socket(AF_INET, SOCK_RAW, IPPROTO_TCP);
    if (rx < 0) { perror("steer: raw"); return 1; }
    int fl = fcntl(rx, F_GETFL, 0);
    fcntl(rx, F_SETFL, fl | O_NONBLOCK);
    int rcvbuf = 1 << 20;
    setsockopt(rx, SOL_SOCKET, SO_RCVBUF, &rcvbuf, sizeof(rcvbuf));
    filter_server(rx, (uint16_t)listen_port);

    /* Отдельный сокет без connect: им отвечают тем, чьей сессии нет. Заводится один
     * раз, а не на каждый такой пакет, иначе поток чужих сегментов означал бы поток
     * системных вызовов socket/close. Принимать ему нечего. */
    int tx0 = socket(AF_INET, SOCK_RAW, IPPROTO_TCP);
    if (tx0 >= 0) {
        int md = IP_PMTUDISC_DONT;
        setsockopt(tx0, IPPROTO_IP, IP_MTU_DISCOVER, &md, sizeof(md));
        filter_none(tx0);
    }

    if (guard_up("server", NULL, listen_port, 1) != 0)
        fprintf(stderr, LOG_W "правило против RST не встало: если порт %d не закрыт "
                              "политикой firewall, ядро будет рвать сессии\n", listen_port);

    fprintf(stderr, LOG_I "сервер: поддельный TCP :%d → udp %s:%d\n",
            listen_port, forward, forward_port);

    uint8_t pkt[OBFS_PKT_MAX];
    for (;;) {
        struct pollfd fds[1 + MAX_SESS];
        struct sess *map[1 + MAX_SESS];
        int nf = 0;
        fds[nf].fd = rx; fds[nf].events = POLLIN; fds[nf].revents = 0; map[nf] = NULL; nf++;
        for (int i = 0; i < MAX_SESS; i++)
            if (g_sess[i].used && g_sess[i].udp >= 0) {
                fds[nf].fd = g_sess[i].udp; fds[nf].events = POLLIN; fds[nf].revents = 0;
                map[nf] = &g_sess[i];
                nf++;
            }

        int n = poll(fds, (nfds_t)nf, TICK_MS * 5);
        if (n < 0 && errno != EINTR) break;

        if (n > 0 && (fds[0].revents & POLLIN)) {
            for (;;) {
                ssize_t r = recv(rx, pkt, sizeof(pkt), 0);
                if (r <= 0) break;
                struct obfs_seg s;
                if (obfs_parse(pkt, (size_t)r, &s) != 0) continue;
                if (s.dport != (uint16_t)listen_port) continue;

                struct sess *ss = sess_find(s.saddr, s.sport);

                if ((s.flags & TH_SYN) && !(s.flags & TH_ACK)) {
                    /* Повторный SYN по живой сессии — клиент, потерявший наш ответ:
                     * отвечаем заново по той же записи, а не заводим вторую. */
                    if (!ss) {
                        ss = sess_alloc(s.saddr, s.sport, (uint16_t)listen_port,
                                        fa.s_addr, forward_port);
                        if (!ss) continue;
                    } else {
                        ss->c.seq -= 1;         /* повтор того же SYN-ACK */
                    }
                    ss->c.ack = s.seq + 1;
                    ss->c.state = ST_SYN_RCVD;
                    ss->c.last_rx = now_ms();
                    conn_send(ss->tx, &ss->c, TH_SYN | TH_ACK, NULL, 0, 1);
                    continue;
                }
                if (!ss) {
                    /* Данные по сессии, которой у нас нет: клиент пережил наш
                     * перезапуск и продолжает слать в пустоту. Молчание здесь стоит
                     * дорого — он узнает о беде только по тишине, то есть через минуту
                     * (DEAD_MS), и всё это время туннель стоит. RST говорит об этом
                     * сразу, и клиент переподключается за миллисекунды.
                     *
                     * Окно 65535, а не ноль: именно этим наш RST отличается от RST ядра,
                     * который гасит наше же правило (см. guard_up). */
                    if (tx0 >= 0 && !(s.flags & TH_RST)) {
                        uint8_t rst[60];
                        size_t rn = obfs_build(rst, s.daddr, s.saddr,
                                               (uint16_t)listen_port, s.sport,
                                               s.ack, s.seq + (uint32_t)s.plen,
                                               TH_RST | TH_ACK, 0, NULL, 0);
                        struct sockaddr_in to;
                        memset(&to, 0, sizeof(to));
                        to.sin_family = AF_INET;
                        to.sin_addr.s_addr = s.saddr;
                        sendto(tx0, rst, rn, 0, (struct sockaddr *)&to, sizeof(to));
                    }
                    continue;
                }
                ss->c.last_rx = now_ms();
                if (s.flags & TH_RST) { sess_free(ss); continue; }
                if (ss->c.state == ST_SYN_RCVD && (s.flags & TH_ACK)) ss->c.state = ST_EST;
                if (s.plen && ss->c.state == ST_EST) {
                    ss->c.ack = obfs_next_ack(ss->c.ack, s.seq, s.plen);
                    ss->c.unacked++;
                    send(ss->udp, s.payload, s.plen, MSG_NOSIGNAL);
                }
            }
        }

        for (int i = 1; i < nf; i++) {
            if (!(fds[i].revents & POLLIN)) continue;
            struct sess *ss = map[i];
            for (;;) {
                ssize_t r = recv(ss->udp, pkt, OBFS_MAX_PAYLOAD, 0);
                if (r <= 0) break;
                if (conn_send(ss->tx, &ss->c, TH_PSH | TH_ACK, pkt, (size_t)r, 0) != 0 &&
                    errno != ENOBUFS && errno != EAGAIN && errno != EWOULDBLOCK)
                    break;
            }
        }

        long long t = now_ms();
        for (int i = 0; i < MAX_SESS; i++) {
            if (!g_sess[i].used) continue;
            if (t - g_sess[i].c.last_rx > SESS_IDLE_MS) { sess_free(&g_sess[i]); continue; }
            if (g_sess[i].c.state == ST_EST && g_sess[i].c.unacked &&
                (g_sess[i].c.unacked >= ACK_SEGS || t - g_sess[i].c.last_ack >= ACK_MS))
                conn_send(g_sess[i].tx, &g_sess[i].c, TH_ACK, NULL, 0, 0);
        }
    }
    guard_down();
    return 1;
}
