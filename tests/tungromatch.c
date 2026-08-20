/* Склейка соседних сегментов в одну запись в устройство: что склеивается, что нет и какими
 * байтами это уезжает.
 *
 * ЗАЧЕМ ОТДЕЛЬНЫМ СТЕНДОМ. Ошибка здесь не выглядит ошибкой. Склеим лишнее — клиент получит
 * поток, в котором переставлены или задвоены байты, и увидеть это можно только дампом; не
 * склеим ничего — всё работает, просто вдвое медленнее, и заметить нечем. Ровно второе тут и
 * случилось при первом живом прогоне: условие требовало TCP БЕЗ ОПЦИЙ, а Linux по умолчанию
 * включает метки времени, поэтому склеивался ноль пакетов из ста. Счётчики показали 100%
 * отказов разбора; стенд ниже ловит это первым же случаем с опциями.
 *
 * Обстановка — socketpair датаграммами, а не настоящее устройство: один writev даёт ровно
 * одну датаграмму, поэтому видно и СКОЛЬКО было записей, и какими именно байтами. Настоящий
 * TUN потребовал бы прав root и не дал бы прочитать то, что мы написали.
 *
 * Ни mbedtls, ни сети: tun.c не касается ни того, ни другого, поэтому стенд подключает
 * исходник напрямую и входит в обычный make test — как xswirematch и xsstreammatch.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

#include "../src/ext/tun.c"

static int fails;

static void check(const char *what, long want, long got) {
    printf("%-62s %s\n", what, want == got ? "ok" : "ПРОВАЛ");
    if (want != got) {
        printf("     хочу: %ld\n     есть:  %ld\n", want, got);
        fails++;
    }
}

static void ok(const char *what, int good) {
    printf("%-62s %s\n", what, good ? "ok" : "ПРОВАЛ");
    if (!good) fails++;
}

/* ---- обстановка ------------------------------------------------------------- */

static int g_pair[2];
static struct tun_dev g_dev;
static struct tun_gro g_gro;

static void setup(int gso) {
    if (g_pair[0] > 0) { close(g_pair[0]); close(g_pair[1]); }
    if (socketpair(AF_UNIX, SOCK_DGRAM, 0, g_pair) != 0) { perror("socketpair"); exit(2); }
    int big = 1 << 20;
    setsockopt(g_pair[0], SOL_SOCKET, SO_SNDBUF, &big, sizeof(big));
    setsockopt(g_pair[1], SOL_SOCKET, SO_RCVBUF, &big, sizeof(big));
    memset(&g_dev, 0, sizeof(g_dev));
    g_dev.fd = g_pair[0];
    g_dev.gso = gso;
    g_dev.gro = gso;
    memset(&g_gro, 0, sizeof(g_gro));
}

/* Сколько датаграмм пришло на ту сторону и какая была первой. */
static int drain(unsigned char *first, size_t cap, size_t *first_n) {
    int cnt = 0;
    for (;;) {
        unsigned char buf[65536];
        ssize_t r = recv(g_pair[1], buf, sizeof(buf), MSG_DONTWAIT);
        if (r <= 0) break;
        if (cnt == 0 && first) {
            *first_n = (size_t)r > cap ? cap : (size_t)r;
            memcpy(first, buf, *first_n);
        }
        cnt++;
    }
    return cnt;
}

/* ---- сборка пакетов --------------------------------------------------------- */

#define OPT_TS 12       /* метка времени: то, что Linux ставит в каждый сегмент */

/* Собрать IPv4+TCP с нагрузкой. opt_n — байты опций TCP (0 или 12), fill — чем набить
 * нагрузку, чтобы её потом узнать. Суммы не считаются: склейка их пересчитывает сама, а
 * несклеенный пакет уезжает как есть — стенд проверяет не суммы пакета, а поведение склейки. */
static size_t mk(unsigned char *p, uint16_t sport, uint32_t seq, uint32_t ack,
                 uint16_t win, size_t pay_n, unsigned char flags, size_t opt_n,
                 unsigned char fill, unsigned char ts) {
    size_t hdr = 20 + 20 + opt_n;
    size_t tot = hdr + pay_n;
    memset(p, 0, tot);
    p[0] = 0x45;
    p[2] = (unsigned char)(tot >> 8);
    p[3] = (unsigned char)(tot & 0xFF);
    p[6] = 0x40;                              /* DF — как у любого сегмента Linux */
    p[8] = 64;                                /* ttl */
    p[9] = 6;                                 /* TCP */
    p[12] = 10; p[13] = 0; p[14] = 0; p[15] = 1;      /* 10.0.0.1 */
    p[16] = 10; p[17] = 0; p[18] = 0; p[19] = 2;      /* 10.0.0.2 */
    p[20] = (unsigned char)(sport >> 8); p[21] = (unsigned char)sport;
    p[22] = 0x1F; p[23] = 0x90;               /* порт 8080 */
    p[24] = (unsigned char)(seq >> 24); p[25] = (unsigned char)(seq >> 16);
    p[26] = (unsigned char)(seq >> 8);  p[27] = (unsigned char)seq;
    p[28] = (unsigned char)(ack >> 24); p[29] = (unsigned char)(ack >> 16);
    p[30] = (unsigned char)(ack >> 8);  p[31] = (unsigned char)ack;
    p[32] = (unsigned char)(((20 + opt_n) / 4) << 4);
    p[33] = flags;
    p[34] = (unsigned char)(win >> 8); p[35] = (unsigned char)win;
    if (opt_n == OPT_TS) {
        p[40] = 1; p[41] = 1;                 /* NOP NOP */
        p[42] = 8; p[43] = 10;                /* timestamp, длина 10 */
        p[44] = ts;                           /* TSval: им и различаем «те же опции» */
    }
    memset(p + hdr, fill, pay_n);
    return tot;
}

/* Поля заголовка разгрузки из первой датаграммы. */
struct vh_read { unsigned char flags, gso_type; uint16_t hdr_len, gso_size, cs_start, cs_off; };
static void vh_of(const unsigned char *d, struct vh_read *v) {
    struct vnet_hdr h;
    memcpy(&h, d, sizeof(h));
    v->flags = h.flags; v->gso_type = h.gso_type;
    v->hdr_len = h.hdr_len; v->gso_size = h.gso_size;
    v->cs_start = h.csum_start; v->cs_off = h.csum_offset;
}

int main(void) {
    unsigned char a[2048], b[2048], c[2048];
    unsigned char got[65536];
    size_t got_n = 0;
    const size_t SEG = 1400;

    /* ---- ДВА СОСЕДНИХ СЕГМЕНТА БЕЗ ОПЦИЙ: одна запись --------------------------- */
    setup(1);
    size_t na = mk(a, 1234, 1000, 77, 501, SEG, 0x10, 0, 0xA0, 0);
    size_t nb = mk(b, 1234, 1000 + SEG, 77, 501, SEG, 0x10, 0, 0xB0, 0);
    tun_gro_push(&g_dev, &g_gro, a, na);
    tun_gro_push(&g_dev, &g_gro, b, nb);
    tun_gro_flush(&g_dev, &g_gro);
    check("два сегмента уехали ОДНОЙ записью", 1, drain(got, sizeof(got), &got_n));
    check("длина записи: заголовок разгрузки, заголовок пакета и две нагрузки",
          (long)(VNET_HDR_LEN + 40 + 2 * SEG), (long)got_n);
    {
        struct vh_read v;
        vh_of(got, &v);
        check("пометка «нарежь сам»", VNET_GSO_TCPV4, v.gso_type);
        check("размер куска — нагрузка первого пакета", (long)SEG, v.gso_size);
        check("длина заголовка", 40, v.hdr_len);
        check("сумму считает ядро", VNET_F_NEEDS_CSUM, v.flags);
        check("смещение суммы: начало TCP", 20, v.cs_start);
        check("смещение поля суммы внутри TCP", 16, v.cs_off);
        const unsigned char *ip = got + VNET_HDR_LEN;
        check("длина IP переписана на весь склеенный кусок",
              (long)(40 + 2 * SEG), (long)(((size_t)ip[2] << 8) | ip[3]));
        ok("сумма IP пересчитана и сходится", csum_fin(csum_add(ip, 20, 0)) == 0);
        ok("нагрузки лежат в порядке отправки",
           ip[40] == 0xA0 && ip[40 + SEG - 1] == 0xA0 &&
           ip[40 + SEG] == 0xB0 && ip[40 + 2 * SEG - 1] == 0xB0);
        /* Сумма TCP обязана быть НЕДОСЧИТАННОЙ: только псевдозаголовок с длиной ВСЕГО
         * склеенного. Инвертированная лишний раз не сойдётся ни у одного куска — и это тот
         * отказ, который выглядит как «пакеты уходят, клиент их не видит». */
        uint32_t src, dst;
        memcpy(&src, ip + 12, 4);
        memcpy(&dst, ip + 16, 4);
        uint16_t want = (uint16_t)~csum_fin(tcp_pseudo_sum(src, dst, 20 + 2 * SEG));
        check("сумма TCP — псевдозаголовок с полной длиной",
              want, (long)(((uint16_t)ip[36] << 8) | ip[37]));
    }

    /* ---- С ОПЦИЯМИ (метки времени): тоже склеивается ----------------------------
     * Тот самый случай, на котором склейка не работала вовсе: у обычного сегмента Linux
     * заголовок TCP 32 байта, а не 20. */
    setup(1);
    na = mk(a, 1234, 2000, 77, 501, SEG, 0x10, OPT_TS, 0xA1, 9);
    nb = mk(b, 1234, 2000 + SEG, 77, 501, SEG, 0x10, OPT_TS, 0xB1, 9);
    tun_gro_push(&g_dev, &g_gro, a, na);
    tun_gro_push(&g_dev, &g_gro, b, nb);
    tun_gro_flush(&g_dev, &g_gro);
    check("сегменты с метками времени склеились", 1, drain(got, sizeof(got), &got_n));
    {
        struct vh_read v;
        vh_of(got, &v);
        check("длина заголовка учла опции", 52, v.hdr_len);
        check("длина записи считает опции один раз",
              (long)(VNET_HDR_LEN + 52 + 2 * SEG), (long)got_n);
    }

    /* Разные байты опций — не склеиваем: ядро скопирует опции ПЕРВОГО во все куски. */
    setup(1);
    na = mk(a, 1234, 3000, 77, 501, SEG, 0x10, OPT_TS, 0xA2, 1);
    nb = mk(b, 1234, 3000 + SEG, 77, 501, SEG, 0x10, OPT_TS, 0xB2, 2);
    tun_gro_push(&g_dev, &g_gro, a, na);
    tun_gro_push(&g_dev, &g_gro, b, nb);
    tun_gro_flush(&g_dev, &g_gro);
    check("разные метки времени — две записи", 2, drain(NULL, 0, NULL));

    /* ---- что склеивать НЕЛЬЗЯ --------------------------------------------------- */
    setup(1);
    na = mk(a, 1234, 4000, 77, 501, SEG, 0x10, 0, 0xA3, 0);
    nb = mk(b, 1234, 4000 + SEG + 1, 77, 501, SEG, 0x10, 0, 0xB3, 0);   /* дырка в номерах */
    tun_gro_push(&g_dev, &g_gro, a, na);
    tun_gro_push(&g_dev, &g_gro, b, nb);
    tun_gro_flush(&g_dev, &g_gro);
    check("разрыв в номерах — две записи", 2, drain(NULL, 0, NULL));

    setup(1);
    na = mk(a, 1234, 5000, 77, 501, SEG, 0x10, 0, 0xA4, 0);
    nb = mk(b, 4321, 5000 + SEG, 77, 501, SEG, 0x10, 0, 0xB4, 0);       /* другой порт */
    tun_gro_push(&g_dev, &g_gro, a, na);
    tun_gro_push(&g_dev, &g_gro, b, nb);
    tun_gro_flush(&g_dev, &g_gro);
    check("другой поток — две записи", 2, drain(NULL, 0, NULL));

    setup(1);
    na = mk(a, 1234, 6000, 77, 501, SEG, 0x10, 0, 0xA5, 0);
    nb = mk(b, 1234, 6000 + SEG, 77, 999, SEG, 0x10, 0, 0xB5, 0);       /* другое окно */
    tun_gro_push(&g_dev, &g_gro, a, na);
    tun_gro_push(&g_dev, &g_gro, b, nb);
    tun_gro_flush(&g_dev, &g_gro);
    check("изменилось окно — две записи", 2, drain(NULL, 0, NULL));

    setup(1);
    na = mk(a, 1234, 7000, 77, 501, SEG, 0x10, 0, 0xA6, 0);
    nb = mk(b, 1234, 7000 + SEG, 88, 501, SEG, 0x10, 0, 0xB6, 0);       /* другое подтверждение */
    tun_gro_push(&g_dev, &g_gro, a, na);
    tun_gro_push(&g_dev, &g_gro, b, nb);
    tun_gro_flush(&g_dev, &g_gro);
    check("изменилось подтверждение — две записи", 2, drain(NULL, 0, NULL));

    setup(1);
    na = mk(a, 1234, 8000, 77, 501, SEG, 0x02, 0, 0xA7, 0);             /* SYN */
    tun_gro_push(&g_dev, &g_gro, a, na);
    tun_gro_flush(&g_dev, &g_gro);
    check("SYN уезжает сам по себе", 1, drain(got, sizeof(got), &got_n));
    {
        struct vh_read v;
        vh_of(got, &v);
        check("и БЕЗ пометки нарезки", VNET_GSO_NONE, v.gso_type);
        check("и без просьбы считать сумму", 0, v.flags);
    }

    setup(1);
    na = mk(a, 1234, 9000, 77, 501, 0, 0x10, 0, 0xA8, 0);               /* голое подтверждение */
    tun_gro_push(&g_dev, &g_gro, a, na);
    tun_gro_flush(&g_dev, &g_gro);
    check("голое подтверждение — отдельная запись", 1, drain(NULL, 0, NULL));

    setup(1);
    na = mk(a, 1234, 9500, 77, 501, 100, 0x10, 0, 0xA9, 0);
    a[9] = 17;                                                          /* UDP */
    tun_gro_push(&g_dev, &g_gro, a, na);
    tun_gro_flush(&g_dev, &g_gro);
    check("не TCP — отдельная запись", 1, drain(NULL, 0, NULL));

    /* ---- PSH и короткий кусок закрывают набор ----------------------------------- */
    setup(1);
    na = mk(a, 1234, 10000, 77, 501, SEG, 0x10, 0, 0xAA, 0);
    nb = mk(b, 1234, 10000 + SEG, 77, 501, SEG, 0x18, 0, 0xBA, 0);      /* ACK|PSH */
    size_t nc = mk(c, 1234, 10000 + 2 * SEG, 77, 501, SEG, 0x10, 0, 0xCA, 0);
    tun_gro_push(&g_dev, &g_gro, a, na);
    tun_gro_push(&g_dev, &g_gro, b, nb);
    tun_gro_push(&g_dev, &g_gro, c, nc);
    tun_gro_flush(&g_dev, &g_gro);
    check("PSH закрыл набор: две записи, а не одна", 2, drain(got, sizeof(got), &got_n));
    check("в первой — оба сегмента до PSH включительно",
          (long)(VNET_HDR_LEN + 40 + 2 * SEG), (long)got_n);

    setup(1);
    na = mk(a, 1234, 11000, 77, 501, SEG, 0x10, 0, 0xAB, 0);
    nb = mk(b, 1234, 11000 + SEG, 77, 501, 200, 0x10, 0, 0xBB, 0);      /* короткий */
    nc = mk(c, 1234, 11000 + SEG + 200, 77, 501, SEG, 0x10, 0, 0xCB, 0);
    tun_gro_push(&g_dev, &g_gro, a, na);
    tun_gro_push(&g_dev, &g_gro, b, nb);
    tun_gro_push(&g_dev, &g_gro, c, nc);
    tun_gro_flush(&g_dev, &g_gro);
    check("короткий кусок закрыл набор", 2, drain(got, sizeof(got), &got_n));
    check("в первой записи — полный и короткий",
          (long)(VNET_HDR_LEN + 40 + SEG + 200), (long)got_n);

    /* Кусок ДЛИННЕЕ первого склеивать нельзя: нарезка вернула бы не то. */
    setup(1);
    na = mk(a, 1234, 12000, 77, 501, 500, 0x10, 0, 0xAC, 0);
    nb = mk(b, 1234, 12000 + 500, 77, 501, SEG, 0x10, 0, 0xBC, 0);
    tun_gro_push(&g_dev, &g_gro, a, na);
    tun_gro_push(&g_dev, &g_gro, b, nb);
    tun_gro_flush(&g_dev, &g_gro);
    check("кусок длиннее первого — две записи", 2, drain(NULL, 0, NULL));

    /* ---- предел числа кадров ----------------------------------------------------
     * Векторов ровно столько, сколько кадров кладёт в запись отправитель; девятый обязан
     * начать новый набор, а не потеряться. */
    setup(1);
    {
        static unsigned char many[TUN_GRO_FRAMES + 2][2048];
        int total = TUN_GRO_FRAMES + 1;
        uint32_t seq = 20000;
        for (int i = 0; i < total; i++) {
            size_t nn = mk(many[i], 1234, seq, 77, 501, SEG, 0x10, 0,
                           (unsigned char)(0x50 + i), 0);
            seq += (uint32_t)SEG;
            tun_gro_push(&g_dev, &g_gro, many[i], nn);
        }
        tun_gro_flush(&g_dev, &g_gro);
        check("девятый кадр начал новый набор, а не пропал", 2,
              drain(got, sizeof(got), &got_n));
        check("в первой записи ровно восемь кадров",
              (long)(VNET_HDR_LEN + 40 + TUN_GRO_FRAMES * SEG), (long)got_n);
    }

    /* ---- без разгрузки склейки нет вовсе ---------------------------------------- */
    setup(0);
    na = mk(a, 1234, 30000, 77, 501, SEG, 0x10, 0, 0xAD, 0);
    nb = mk(b, 1234, 30000 + SEG, 77, 501, SEG, 0x10, 0, 0xBD, 0);
    tun_gro_push(&g_dev, &g_gro, a, na);
    tun_gro_push(&g_dev, &g_gro, b, nb);
    tun_gro_flush(&g_dev, &g_gro);
    check("устройство без разгрузки: по записи на пакет", 2,
          drain(got, sizeof(got), &got_n));
    check("и без заголовка разгрузки в них", (long)(40 + SEG), (long)got_n);

    printf(fails ? "\nПРОВАЛОВ: %d\n" : "\nвсе проверки прошли\n", fails);
    return fails ? 1 : 0;
}
