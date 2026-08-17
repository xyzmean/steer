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
 * И ЦЕНА ЭТА НЕ ТОЛЬКО В ПРАВИЛЕ, а в том, что RST ядро всё равно СОБИРАЕТ на каждый
 * принятый сегмент — правило гасит его уже готовым. Плюс на приёме ядро клонирует skb для
 * КАЖДОГО сырого сокета, и только потом фильтр отбрасывает лишние копии: значит цена растёт
 * с числом воркеров.
 *
 * СКОЛЬКО ЭТО СТОИТ И ЧТО БЫЛО БЫ С TUN — измерено, стенд tests/transportcost.sh. На отправке
 * разницы нет: сырой сокет пачкой sendmmsg по 16 даёт 3,1 мкс на пакет, TUN с вызовом на
 * пакет — 3,2 (сама пачка стоит 22%: по одному пакету — 4,0). На приёме, наоборот, TUN
 * дешевле сырого сокета (10,2 против 11,5 мкс процессора системы на пакет), и вся разница
 * именно в том RST, которого при перенаправлении в TUN не возникает вовсе.
 *
 * НО ВЫВОД ИЗ ЭТОГО НЕ «НАДО TUN». Тот же выигрыш даёт приём через AF_PACKET: он получает
 * пакет ДО netfilter, значит нашему порту можно прямо запретить доходить до стека ядра — и
 * RST не собирается; а PACKET_FANOUT отдаёт пакет ровно одному сокету группы, значит клон не
 * умножается на воркеров. Измерено там же: 10,5 мкс одним сокетом и 8,6 четырьмя против 11,5
 * у сырого сокета. При этом не нужны ни ip_forward, ни NAT, ни зона firewall, и не нужно,
 * чтобы conntrack признал наш поддельный поток действительным (у варианта с TUN правило DNAT
 * к недействительному потоку не применяется, и пакеты молча уходят не туда — это первое, на
 * чём стенд и споткнулся). Отправка при любом раскладе остаётся на сыром сокете: у AF_PACKET
 * пришлось бы самим собирать канальный заголовок, а на PPPoE это не Ethernet.
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

/* ---- контрольные суммы -----------------------------------------------------
 *
 * Сумма считается по КАЖДОМУ пакету и проходит по всей нагрузке, то есть на гигабите
 * это гигабайт чтений в секунду — здесь стоит считать словами, а не байтами. Складываем
 * 32-битными кусками в 64-битный накопитель: переносы копятся внутри и сворачиваются
 * один раз в конце, а не на каждом шаге.
 *
 * Порядок байтов не трогаем нарочно. Сумма в интернете симметрична относительно
 * перестановки байтов в паре: посчитать её в «неправильном» порядке и один раз
 * переставить байты результата — то же самое, что считать в правильном. Поэтому
 * промежуточные слова читаются как есть, а разворот делается единожды в csum_fin. */
/* Слагаемые читаются 32-битными словами В ПОРЯДКЕ МАШИНЫ, а не парами байт.
 *
 * Прежний код собирал пары вручную (`p[0] << 8 | p[1]`) и объяснял это тем, что выигрыш
 * от слов «пара процентов», а невыровненное чтение на MIPS стоит ловушки ядра. Обе
 * половины довода не действуют:
 *
 *   * «Пара процентов» верна для -O2 и неверна для -Os, а базовый пакет (вместе с этим
 *     файлом) собирается именно с -Os — там компилятор цикл пар не разворачивает и не
 *     векторизует. Замер на нагрузке 1400 байт: 428 нс парами против 110 нс словами.
 *   * Ловушки нет: memcpy четырёх байт выравнивания не требует, компилятор на MIPS
 *     выпускает lwl/lwr. Этот же приём уже едет в пакете на тех же целях —
 *     src/ext/tun.c читает словами через memcpy ровно так.
 *
 * Порядок байтов не трогается ни разу за проход, и это ключ к скорости. Сумма в
 * интернете симметрична относительно перестановки байтов в паре: сложив единицы В
 * ПОРЯДКЕ МАШИНЫ и один раз переставив байты результата, получаем то же число.
 * Перестановку делает htons в csum_fin — на big-endian он ничего не делает, там сумма
 * уже в нужном порядке, а на little-endian меняет байты местами. Никаких #if.
 *
 * Хвост дописывается нулём в двухбайтовый буфер и читается ТАК ЖЕ, как остальные
 * единицы, — иначе последний байт пришлось бы класть в разную половину на разных
 * машинах, и именно там такая правка обычно и ломается.
 *
 * Проверять эквивалентность обязательно: ошибка в сумме не проявляется явно — пакет
 * молча отбрасывается стеком той стороны. См. стенд obfsmatch: он сверяет эту функцию с
 * независимой построчной реализацией на всех длинах и смещениях. */
static uint32_t csum_add(const void *data, size_t len, uint32_t acc) {
    const uint8_t *p = data;
    uint64_t s = acc;
    while (len >= 16) {
        uint32_t w0, w1, w2, w3;
        memcpy(&w0, p, 4); memcpy(&w1, p + 4, 4);
        memcpy(&w2, p + 8, 4); memcpy(&w3, p + 12, 4);
        s += (uint64_t)w0 + w1 + w2 + w3;
        p += 16; len -= 16;
    }
    while (len >= 4) {
        uint32_t w;
        memcpy(&w, p, 4);
        s += w;
        p += 4; len -= 4;
    }
    if (len >= 2) {
        uint16_t h;
        memcpy(&h, p, 2);
        s += h;
        p += 2; len -= 2;
    }
    if (len) {
        uint8_t tail[2] = { p[0], 0 };
        uint16_t h;
        memcpy(&h, tail, 2);
        s += h;
    }
    while (s >> 32) s = (s & 0xFFFFFFFF) + (s >> 32);
    return (uint32_t)s;
}

static uint16_t csum_fin(uint32_t acc) {
    while (acc >> 16) acc = (acc & 0xFFFF) + (acc >> 16);
    /* htons здесь — не «положить на провод», а перестановка байтов суммы из порядка
     * машины в порядок сети, тот единственный раз за пакет, ради которого весь проход
     * выше идёт без перестановок. На big-endian это тождество. */
    return (uint16_t)(~htons((uint16_t)acc) & 0xFFFF);
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
    /* Масштаб окна — только по просьбе (OBFS_OPT_SCALE) и только в SYN. Зачем он нужен и
     * что без него измерено на живом роутере — в obfs.h. Раскладка: NOP, затем опция 3
     * длиной 3 со множителем; NOP впереди выравнивает опции на четыре байта, как это делают
     * настоящие стеки. */
    if (with_mss >= OBFS_OPT_SCALE) {
        buf[hlen++] = 1;                       /* NOP */
        buf[hlen++] = 3; buf[hlen++] = 3;
        buf[hlen++] = OBFS_WSCALE;
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
void obfs_filter_quad(int fd, uint32_t server_be, uint16_t sport, uint16_t dport) {
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
void obfs_filter_port(int fd, uint16_t port) {
    struct sock_filter code[] = {
        BPF_STMT(BPF_LDX | BPF_B   | BPF_MSH, 0),
        BPF_STMT(BPF_LD  | BPF_H   | BPF_IND, 2),                   /* tcp dport */
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, port, 0, 1),
        BPF_STMT(BPF_RET | BPF_K, 0xFFFFFFFF),
        BPF_STMT(BPF_RET | BPF_K, 0),
    };
    raw_filter(fd, code, sizeof(code) / sizeof(code[0]));
}

/* То же, но с раскладкой по воркерам: сокету достаются только сегменты, у которых младшие
 * биты ПОРТА ИСТОЧНИКА равны id. Так каждый поток получает свою долю соединений, и ни одно
 * соединение не приходит двум потокам — а значит окно приёма, ключи и счётчик nonce остаются
 * личной собственностью потока и не требуют ни одного замка на горячем пути (тот же довод, что
 * записан про очереди TUN в tun.h).
 *
 * Раскладка ИМЕННО по порту источника, а не по адресу: за одним NAT может сидеть вся звезда,
 * и по адресу все соединения достались бы одному потоку. Маска обязана быть степенью двойки
 * минус один: у cBPF нет деления, а «и» с маской — одна инструкция.
 *
 * Порядок проверок — сначала порт назначения (он отбивает основную массу чужого), потом
 * раскладка: ядро исполняет фильтр на каждый локально доставляемый TCP-сегмент, и лишняя
 * работа здесь платится на всём трафике машины, а не только на нашем. */
void obfs_filter_port_shard(int fd, uint16_t port, uint16_t mask, uint16_t id) {
    struct sock_filter code[] = {
        BPF_STMT(BPF_LDX | BPF_B   | BPF_MSH, 0),
        BPF_STMT(BPF_LD  | BPF_H   | BPF_IND, 2),                   /* tcp dport */
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, port, 0, 4),
        BPF_STMT(BPF_LD  | BPF_H   | BPF_IND, 0),                   /* tcp sport */
        BPF_STMT(BPF_ALU | BPF_AND | BPF_K, mask),
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, id, 0, 1),
        BPF_STMT(BPF_RET | BPF_K, 0xFFFFFFFF),
        BPF_STMT(BPF_RET | BPF_K, 0),
    };
    raw_filter(fd, code, sizeof(code) / sizeof(code[0]));
}

/* Сокеты, которые только отправляют: не принимать ничего. Без этого connect()'нутый
 * сокет сессии копил очередь на мегабайт и складывал туда весь встречный поток —
 * именно он и дал 146 тысяч drops на первом же замере под нагрузкой. */
void obfs_filter_none(int fd) {
    struct sock_filter code[] = { BPF_STMT(BPF_RET | BPF_K, 0) };
    raw_filter(fd, code, 1);
}

/* ---- сырой сокет ----------------------------------------------------------- */
/* connect() на сыром сокете ничего не шлёт: он фиксирует получателя и заставляет ядро
 * выбрать маршрут, а с ним и адрес источника — тот самый, который нужен контрольной
 * сумме. Спрашивать адрес у интерфейса нельзя: их несколько, и правильный знает только
 * таблица маршрутизации. */
int obfs_raw_open(uint32_t daddr, uint32_t *saddr_out) {
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

/* ---- пакеты пачками --------------------------------------------------------
 *
 * На пакет приходилось по два системных вызова в каждую сторону плюс копирование
 * нагрузки в буфер сегмента. При 1400 байтах на пакет это на порядок больше работы,
 * чем сам разбор заголовка, и упирается всё именно в них, а не в арифметику.
 *
 * Две меры разом. Первая: recvmmsg/sendmmsg — до BATCH пакетов за вызов, то есть
 * системных вызовов в BATCH раз меньше. Вторая: заголовок пишется ПЕРЕД нагрузкой в
 * том же буфере, для чего при чтении резервируется место, — датаграмма не копируется
 * вовсе, а отправляется с того места, куда её положило ядро.
 *
 * BATCH = 16, а не 64: пачка больше упирается уже не в вызовы, а в задержку — пакеты
 * ждут, пока наберётся группа. Шестнадцати хватает, чтобы вызовов стало на порядок
 * меньше, и они набираются за микросекунды на любой скорости, где это вообще важно. */
#define BATCH 16
#define HDR_ROOM 24                 /* с запасом на 20 байт заголовка */

/* Статические, а не на стеке: 16 × 1.6 КБ на два направления — это 52 КБ, которые на
 * стеке процесса с малым лимитом были бы риском, а в bss просто есть. */
static uint8_t g_bat_rx[BATCH][OBFS_PKT_MAX];
static uint8_t g_bat_tx[BATCH][HDR_ROOM + OBFS_MAX_PAYLOAD];
static struct mmsghdr g_mm[BATCH];
static struct iovec g_iov[BATCH];
static struct sockaddr_in g_from[BATCH];

/* Записать заголовок ВПЕРЁД нагрузки, лежащей по base + HDR_ROOM, и вернуть указатель
 * на начало сегмента. Двигает seq так же, как это делает conn_send. */
static uint8_t *build_ahead(struct fconn *c, uint8_t *base, size_t plen, size_t *seglen,
                            long long now) {
    uint8_t *seg = base + HDR_ROOM - sizeof(struct tcp_hdr);
    struct tcp_hdr *t = (struct tcp_hdr *)seg;
    memset(t, 0, sizeof(*t));
    t->sport = htons(c->sport);
    t->dport = htons(c->dport);
    t->seq = htonl(c->seq);
    t->ack = htonl(c->ack);
    t->off = (uint8_t)((sizeof(*t) / 4) << 4);
    t->flags = TH_PSH | TH_ACK;
    t->win = htons(OBFS_WIN);
    *seglen = sizeof(*t) + plen;
    t->sum = htons(obfs_tcp_csum(c->saddr, c->daddr, seg, *seglen));
    c->seq += (uint32_t)plen;
    /* Время приходит СНАРУЖИ, одно на пачку, а не снимается на каждый пакет.
     *
     * На mipsel в ядрах OpenWrt нет vDSO для clock_gettime — это не дешёвое чтение
     * страницы, а настоящий системный вызов с переключением режима, 1-3 мкс. На каждом
     * пакете при девяти тысячах пакетов в секунду это 1-3% единственного ядра, отданные
     * за метку, которая всё равно измеряется с гранулярностью TICK_MS = 20.
     *
     * Ровно это решение уже принято в туннеле, по той же причине и с тем же объяснением:
     * см. g_now_ns в src/ext/tunnel.c. */
    c->last_tx = now;
    c->last_ack = now;
    c->unacked = 0;
    return seg;
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

/* Вид в имени цепочки ('o' — обфускатор, 'x' — xsteer): у них одна таблица, но свои
 * цепочки, иначе выход из одного процесса снимал бы правило другого. Таблица общая
 * НАРОЧНО — вторая означала бы вторую строку уборки в init-скрипте, вторую запись в
 * контракте и второй способ забыть одну из них. Имя таблицы историческое: «steer_obfs»
 * теперь про поддельный TCP вообще, а не только про обфускацию WireGuard. */
static void chain_name(char kind, const char *out, char *dst, size_t n) {
    size_t k = 0;
    dst[k++] = kind; dst[k++] = '_';
    for (size_t i = 0; out[i] && k + 1 < n; i++) {
        char c = out[i];
        int ok = (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') ||
                 (c >= '0' && c <= '9') || c == '_';
        dst[k++] = ok ? c : '_';
    }
    dst[k] = '\0';
}

void obfs_guard_down(void) {
    if (!g_chain_up) return;
    const char *del[] = { "nft", "delete", "chain", "inet", "steer_obfs", g_chain, NULL };
    run_quiet(del);
    g_chain_up = 0;
}

static void guard_sig(int sig) {
    obfs_guard_down();
    _exit(128 + sig);
}

/* Возвращает 0, если правило встало. Отказ не смертелен на сервере, где порт может быть
 * закрыт политикой firewall (тогда RST не порождается вовсе), но на клиенте означает,
 * что первую же сессию оборвёт собственное ядро — поэтому вызывающий говорит об этом
 * громко, а не молча продолжает. */
int obfs_guard_up(char kind, const char *label, const char *peer_addr, int port,
                  int is_server) {
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
    chain_name(kind, label_buf, g_chain, sizeof(g_chain));
    char portbuf[16];
    snprintf(portbuf, sizeof(portbuf), "%d", port);

    const char *tab[] = { "nft", "add", "table", "inet", "steer_obfs", NULL };
    if (run_quiet(tab) != 0) return -1;
    /* Снять хвост от прошлого падения: процесс мог уйти по SIGKILL, и тогда цепочка
     * осталась, а `add` поверх неё правило задвоил бы. */
    const char *delc[] = { "nft", "delete", "chain", "inet", "steer_obfs", g_chain, NULL };
    run_quiet(delc);
    /* Приоритет raw, а не filter, и это разница между «работает» и «не работает».
     *
     * conntrack смотрит исходящий пакет на приоритете -200, то есть РАНЬШЕ цепочки
     * filter. Пока правило стояло там, RST ядра успевал перевести запись conntrack в
     * состояние CLOSE и лишь потом отбрасывался — а дальше каждый наш сегмент был для
     * conntrack недействительным, и штатное правило fw4 «Prevent NAT leakage»
     * (oifname wan ct state invalid drop) выбрасывало его, возвращая нам EPERM.
     * Симптом был из самых злых: туннель то работает, то теряет большинство пакетов,
     * и виновата якобы обфускация, а не одно число в приоритете цепочки.
     *
     * raw (-300) выполняется раньше conntrack, поэтому RST ядра не доживает даже до
     * учёта: запись остаётся ESTABLISHED, и наши пакеты никого не смущают. */
    const char *addc[] = { "nft", "add", "chain", "inet", "steer_obfs", g_chain,
                           "{ type filter hook output priority raw; policy accept; }",
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
    atexit(obfs_guard_down);
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

/* Масштаб окна в SYN появился здесь ПОЗЖЕ обфускатора, и вот почему он важен и ему.
 *
 * Замер на живом роутере (канал 176 Мбит вверх, задержка 50 мс): туннель через обфускатор
 * отдавал 2,15 Мбит/с и на восьмисекундном тесте растягивался на сорок секунд. Тот же путь,
 * то же железо, но с масштабом окна — 63 Мбит/с. Причина не в шифре и не в процессоре:
 * conntrack по дороге верит объявленному окну 65535 и метит недействительным всё, что
 * выходит за 64 КиБ в полёте, а правило fw4 против утечек NAT такие пакеты отбрасывает.
 *
 * С phantun на другой стороне выигрыша не будет: масштаб действует, только если его прислали
 * ОБА, а он опций не посылает. Но и вреда нет — опцию он игнорирует, как и раньше. */
static int client_connect(struct fconn *c, int *raw_fd, uint32_t daddr, int dport) {
    if (*raw_fd >= 0) close(*raw_fd);
    client_reset(c, daddr, dport);
    *raw_fd = obfs_raw_open(daddr, &c->saddr);
    if (*raw_fd < 0) {
        fprintf(stderr, LOG_W "сырой сокет недоступен: %s\n", strerror(errno));
        return -1;
    }
    /* Фильтр ставится ДО первого SYN: между socket() и настройкой очередь успевает
     * набрать чужого, и на нагруженном роутере это тысячи пакетов. */
    obfs_filter_quad(*raw_fd, daddr, c->dport, c->sport);
    if (conn_send(*raw_fd, c, TH_SYN, NULL, 0, OBFS_OPT_SCALE) != 0) return -1;
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

    if (obfs_guard_up('o', out_name, server, server_port, 0) != 0)
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

    unsigned long long up_pkts = 0, down_pkts = 0, dropped = 0;
    long long last_send_warn = 0;

    for (;;) {
        struct pollfd fds[2];
        fds[0].fd = udp;  fds[0].events = POLLIN; fds[0].revents = 0;
        fds[1].fd = raw;  fds[1].events = POLLIN; fds[1].revents = 0;
        int n = poll(fds, 2, TICK_MS);
        if (n < 0 && errno != EINTR) break;

        /* Наружу: пачка датаграмм WireGuard → пачка сегментов, без копирования. */
        if (n > 0 && (fds[0].revents & POLLIN)) {
            for (;;) {
                for (int i = 0; i < BATCH; i++) {
                    g_iov[i].iov_base = g_bat_tx[i] + HDR_ROOM;
                    g_iov[i].iov_len = OBFS_MAX_PAYLOAD;
                    memset(&g_mm[i].msg_hdr, 0, sizeof(g_mm[i].msg_hdr));
                    g_mm[i].msg_hdr.msg_iov = &g_iov[i];
                    g_mm[i].msg_hdr.msg_iovlen = 1;
                    g_mm[i].msg_hdr.msg_name = &g_from[i];
                    g_mm[i].msg_hdr.msg_namelen = sizeof(g_from[i]);
                }
                int got = recvmmsg(udp, g_mm, BATCH, MSG_DONTWAIT, NULL);
                if (got <= 0) break;
                /* Отвечать надо тому, кто прислал последним: WireGuard может сменить
                 * исходный порт, и запомненный адрес обязан быть свежим. */
                peer = g_from[got - 1];
                peer_len = sizeof(struct sockaddr_in);
                if (c.state != ST_EST) { dropped += (unsigned)got; continue; }

                int k = 0;
                long long tx_now = now_ms();     /* одно на пачку — см. build_ahead */
                for (int i = 0; i < got; i++) {
                    size_t seglen;
                    uint8_t *seg = build_ahead(&c, g_bat_tx[i], g_mm[i].msg_len, &seglen, tx_now);
                    g_iov[k].iov_base = seg;
                    g_iov[k].iov_len = seglen;
                    memset(&g_mm[k].msg_hdr, 0, sizeof(g_mm[k].msg_hdr));
                    g_mm[k].msg_hdr.msg_iov = &g_iov[k];
                    g_mm[k].msg_hdr.msg_iovlen = 1;
                    k++;
                }
                int sent = sendmmsg(raw, g_mm, (unsigned)k, 0);
                if (sent < 0) {
                    /* Неудачная отправка — это потеря датаграммы, а НЕ повод рвать
                     * сессию, каким бы ни был код ошибки.
                     *
                     * Стоило это дорого и выяснилось только на живом канале: ядро
                     * возвращает EPERM, когда исходящий пакет отбросил netfilter, и
                     * прежний код считал такой отказ смертельным. Сессия пересоздавалась,
                     * следующая пачка получала тот же EPERM, и туннель уходил в вечный
                     * цикл переподключений — 68 тысяч датаграмм, потерянных «до сессии»,
                     * против 13 тысяч отправленных. Признак живости у нас ровно один и он
                     * ниже: тишина в ответ дольше DEAD_MS. Отправка о жизни пути не судит.
                     *
                     * Жалуемся не чаще раза в пять секунд: на такой ошибке журнал
                     * заполняется быстрее, чем читается. */
                    dropped += (unsigned)k;
                    long long tnow = now_ms();
                    if (tnow - last_send_warn > 5000) {
                        last_send_warn = tnow;
                        fprintf(stderr, LOG_W "%s: пачку не принял стек (%s), потеряно %llu\n",
                                out_name, strerror(errno), dropped);
                    }
                } else {
                    up_pkts += (unsigned)sent;
                    if (sent < k) dropped += (unsigned)(k - sent);
                }
                if (got < BATCH) break;             /* очередь исчерпана */
            }
        }

        /* Обратно: пачка сегментов → пачка датаграмм, тоже без копирования: iovec
         * указывает прямо в нагрузку принятого пакета. */
        if (n > 0 && (fds[1].revents & POLLIN)) {
            for (;;) {
                for (int i = 0; i < BATCH; i++) {
                    g_iov[i].iov_base = g_bat_rx[i];
                    g_iov[i].iov_len = OBFS_PKT_MAX;
                    memset(&g_mm[i].msg_hdr, 0, sizeof(g_mm[i].msg_hdr));
                    g_mm[i].msg_hdr.msg_iov = &g_iov[i];
                    g_mm[i].msg_hdr.msg_iovlen = 1;
                }
                int got = recvmmsg(raw, g_mm, BATCH, MSG_DONTWAIT, NULL);
                if (got <= 0) break;

                int k = 0, closed = 0;
                for (int i = 0; i < got; i++) {
                    struct obfs_seg s;
                    if (obfs_parse(g_bat_rx[i], g_mm[i].msg_len, &s) != 0) continue;
                    /* Чужое отсеивает фильтр в ядре, но четвёрку проверяем и здесь:
                     * фильтр мог не встать (старое ядро, отказ setsockopt), и тогда
                     * без этой проверки в WireGuard уехал бы чужой байт. */
                    if (s.saddr != c.daddr || s.sport != c.dport ||
                        s.daddr != c.saddr || s.dport != c.sport) continue;

                    c.last_rx = now_ms();

                    if (s.flags & TH_RST) {
                        fprintf(stderr, LOG_W "%s: сервер оборвал сессию (RST)\n", out_name);
                        c.state = ST_CLOSED;
                        closed = 1;
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
                        /* Датаграмма отдаётся наверх в любом случае, даже вне порядка:
                         * за порядок и подлинность отвечает WireGuard, а не мы. */
                        g_iov[k].iov_base = (void *)(uintptr_t)s.payload;
                        g_iov[k].iov_len = s.plen;
                        memset(&g_mm[k].msg_hdr, 0, sizeof(g_mm[k].msg_hdr));
                        g_mm[k].msg_hdr.msg_iov = &g_iov[k];
                        g_mm[k].msg_hdr.msg_iovlen = 1;
                        g_mm[k].msg_hdr.msg_name = &peer;
                        g_mm[k].msg_hdr.msg_namelen = peer_len;
                        k++;
                    }
                }
                if (k && peer_len) {
                    int sent = sendmmsg(udp, g_mm, (unsigned)k, 0);
                    if (sent > 0) down_pkts += (unsigned)sent;
                }
                if (closed || got < BATCH) break;
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
    obfs_guard_down();
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

    slot->tx = obfs_raw_open(caddr, &slot->c.saddr);
    if (slot->tx < 0) return NULL;
    obfs_filter_none(slot->tx);

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
    obfs_filter_port(rx, (uint16_t)listen_port);

    /* Отдельный сокет без connect: им отвечают тем, чьей сессии нет. Заводится один
     * раз, а не на каждый такой пакет, иначе поток чужих сегментов означал бы поток
     * системных вызовов socket/close. Принимать ему нечего. */
    int tx0 = socket(AF_INET, SOCK_RAW, IPPROTO_TCP);
    if (tx0 >= 0) {
        int md = IP_PMTUDISC_DONT;
        setsockopt(tx0, IPPROTO_IP, IP_MTU_DISCOVER, &md, sizeof(md));
        obfs_filter_none(tx0);
    }

    if (obfs_guard_up('o', "server", NULL, listen_port, 1) != 0)
        fprintf(stderr, LOG_W "правило против RST не встало: если порт %d не закрыт "
                              "политикой firewall, ядро будет рвать сессии\n", listen_port);

    fprintf(stderr, LOG_I "сервер: поддельный TCP :%d → udp %s:%d\n",
            listen_port, forward, forward_port);

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
            for (int i = 0; i < BATCH; i++) {
                g_iov[i].iov_base = g_bat_rx[i];
                g_iov[i].iov_len = OBFS_PKT_MAX;
                memset(&g_mm[i].msg_hdr, 0, sizeof(g_mm[i].msg_hdr));
                g_mm[i].msg_hdr.msg_iov = &g_iov[i];
                g_mm[i].msg_hdr.msg_iovlen = 1;
            }
            int got = recvmmsg(rx, g_mm, BATCH, MSG_DONTWAIT, NULL);
            if (got <= 0) break;
            for (int bi = 0; bi < got; bi++) {
                struct obfs_seg s;
                if (obfs_parse(g_bat_rx[bi], g_mm[bi].msg_len, &s) != 0) continue;
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
                    conn_send(ss->tx, &ss->c, TH_SYN | TH_ACK, NULL, 0, OBFS_OPT_SCALE);
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
            if (got < BATCH) break;
          }
        }

        for (int i = 1; i < nf; i++) {
            if (!(fds[i].revents & POLLIN)) continue;
            struct sess *ss = map[i];
            for (;;) {
                /* Место под заголовок резервируется при чтении, поэтому датаграмма
                 * уходит клиенту с того места, куда её положило ядро, — без копии. */
                for (int b = 0; b < BATCH; b++) {
                    g_iov[b].iov_base = g_bat_tx[b] + HDR_ROOM;
                    g_iov[b].iov_len = OBFS_MAX_PAYLOAD;
                    memset(&g_mm[b].msg_hdr, 0, sizeof(g_mm[b].msg_hdr));
                    g_mm[b].msg_hdr.msg_iov = &g_iov[b];
                    g_mm[b].msg_hdr.msg_iovlen = 1;
                }
                int got = recvmmsg(ss->udp, g_mm, BATCH, MSG_DONTWAIT, NULL);
                if (got <= 0) break;
                long long tx_now = now_ms();     /* одно на пачку — см. build_ahead */
                for (int b = 0; b < got; b++) {
                    size_t seglen;
                    uint8_t *seg = build_ahead(&ss->c, g_bat_tx[b], g_mm[b].msg_len, &seglen,
                                               tx_now);
                    g_iov[b].iov_base = seg;
                    g_iov[b].iov_len = seglen;
                    memset(&g_mm[b].msg_hdr, 0, sizeof(g_mm[b].msg_hdr));
                    g_mm[b].msg_hdr.msg_iov = &g_iov[b];
                    g_mm[b].msg_hdr.msg_iovlen = 1;
                }
                if (sendmmsg(ss->tx, g_mm, (unsigned)got, 0) < 0 &&
                    errno != ENOBUFS && errno != EAGAIN && errno != EWOULDBLOCK)
                    break;
                if (got < BATCH) break;
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
    obfs_guard_down();
    return 1;
}
