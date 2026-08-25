/* Стенд хаба xsteer: размеры, из которых складывается запись, и их согласие друг с другом.
 *
 * ЗАЧЕМ ИМЕННО ТАКОЙ СТЕНД. Цикл хаба (worker_loop) целиком построен на I/O: сырой сокет,
 * очередь TUN, потоки. Проверить его целиком в памяти нельзя, не переписав. Но самая дорогая
 * ошибка в нём — не в логике ветвлений, а в АРИФМЕТИКЕ РАЗМЕРОВ: набор кадров в пачку
 * ограничен одним правилом, строка под запись объявлена другим числом, и разойтись они могут
 * молча. Ровно это и вышло (I-070): строку посчитали с местом под ОДИН заголовок вместо трёх,
 * и на предельной пачке тег AEAD ложился на четыре байта за границу поля — внутрь соседнего
 * поля той же структуры, где его не видит ни компилятор, ни AddressSanitizer (у ASan нет
 * красной зоны между полями структуры). Получатель при этом получал запись с испорченным
 * тегом и отбрасывал её целиком, то есть терял до шести пакетов разом — молча.
 *
 * Стенд включает сам xshub.c: правило набора и объявление строки живут внутри него, и смотреть
 * на них надо на настоящих, а не пересказанных числах. Ни сети, ни root, ни потоков он не
 * трогает — только считает и один раз вызывает настоящий xs_conn_split_mm.
 *
 * Отсюда же растёт стенд для самого цикла, когда до него дойдёт очередь: включение .c уже
 * даёт доступ к struct worker, g_sess и статическим функциям.
 *
 *     cc -O2 -w -Isrc -I<mbedtls>/include -o build/hubmatch tests/hubmatch.c \
 *        src/ext/xsconn.c src/ext/xswire.c src/ext/xsepoch.c src/ext/xsroute.c \
 *        src/ext/xsconf.c src/ext/xsstream.c src/ext/xshake.c src/ext/chello.c \
 *        src/ext/reality.c src/ext/tls13.c src/ext/h2.c src/ext/tun.c src/obfs.c \
 *        src/spec.c <mbedtls>/library/libmbedcrypto.a -lpthread
 */
#define _GNU_SOURCE
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>

/* Хабу run_quiet нужен для `ip link` (hub_retune_mtu, hub_dev_up, cmd_xsteer_hub); в
 * src/steer.c его настоящая реализация, а здесь — ЗАПИСЬ вместо запуска: подъём устройства
 * (hub_dev_up) проверяется именно по тому, какие команды он отдал и что сказал о неудавшихся.
 * По умолчанию все проходят; отказать умеет ровно та, чью подстроку назвал стенд (тот же
 * приём, что в tests/failovermatch.c). */
static char g_cmd[64][256];
static int  g_cmd_n;
static const char *g_fail_on = "";

int run_quiet(const char *const argv[]) {
    if (!argv || !argv[0]) return -1;
    char joined[256];
    size_t jn = 0;
    for (int i = 0; argv[i] && jn < sizeof(joined) - 2; i++)
        jn += (size_t)snprintf(joined + jn, sizeof(joined) - jn, i ? " %s" : "%s", argv[i]);
    if (g_cmd_n < (int)(sizeof(g_cmd) / sizeof(*g_cmd)))
        snprintf(g_cmd[g_cmd_n++], sizeof(g_cmd[0]), "%s", joined);
    if (g_fail_on[0] && strstr(joined, g_fail_on)) return 2;
    return 0;
}

static int cmd_seen(const char *needle) {
    for (int i = 0; i < g_cmd_n; i++)
        if (strstr(g_cmd[i], needle)) return 1;
    return 0;
}

/* ---- перехват журнала --------------------------------------------------------
 *
 * У подъёма устройства нет ни возвращаемого значения, ни следующей команды, по которой можно
 * судить со стороны: единственное его наблюдаемое следствие при отказе — строка в журнале.
 * Поэтому stderr на время вызова уводится в файл. Уровень строки проверяется отдельно:
 * `steer[warn]` против `steer[info]` — это контракт с интерфейсом, а не оформление. */
static char g_logpath[] = "/tmp/hubmatch-log.XXXXXX";
static int  g_logfd = -1, g_saved_err = -1;
static char g_log[8192];

static void log_begin(void) {
    if (g_logfd < 0) {
        g_logfd = mkstemp(g_logpath);
        unlink(g_logpath);
        g_saved_err = dup(2);
    }
    fflush(stderr);
    /* Обнуляются И длина, И смещение: запись идёт по смещению дескриптора, и без lseek
     * следующий перехват начинался бы дырой из нулевых байтов, то есть пустой строкой при
     * непустом файле. */
    if (ftruncate(g_logfd, 0) != 0) { /* пусто и так */ }
    lseek(g_logfd, 0, SEEK_SET);
    dup2(g_logfd, 2);
}

static const char *log_end(void) {
    fflush(stderr);
    dup2(g_saved_err, 2);
    ssize_t n = pread(g_logfd, g_log, sizeof(g_log) - 1, 0);
    g_log[n > 0 ? n : 0] = '\0';
    return g_log;
}

static int log_lines_with(const char *log, const char *level) {
    int n = 0;
    for (const char *p = log; (p = strstr(p, level)); p += strlen(level)) n++;
    return n;
}

#include "../src/ext/xshub.c"
#include "chello-frozen.h"

static int fails;

static void check(const char *what, long want, long got) {
    printf("%-64s %s\n", what, want == got ? "ok" : "ПРОВАЛ");
    if (want != got) {
        printf("     хочу: %ld\n     есть: %ld\n", want, got);
        fails++;
    }
}

/* ---- наблюдатель за поддельным соединением -----------------------------------
 *
 * xs_conn_send собирает сегмент TCP и отправляет его send() по своему сокету. Стенду сырой
 * сокет не нужен (и прав на него нет): подставляем сокет UDP, соединённый с петлёй, — тогда
 * «что именно ушло прибору» становится читаемой датаграммой, а не рассуждением о том, куда
 * пошло исполнение. Флаги лежат в 13-м байте сегмента, нагрузка — за заголовком. */
static int obs_fd = -1, obs_port;

static int wire_open(void) {
    if (obs_fd < 0) {
        struct sockaddr_in a;
        socklen_t al = sizeof(a);
        obs_fd = socket(AF_INET, SOCK_DGRAM, 0);
        memset(&a, 0, sizeof(a));
        a.sin_family = AF_INET;
        a.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
        bind(obs_fd, (struct sockaddr *)&a, sizeof(a));
        getsockname(obs_fd, (struct sockaddr *)&a, &al);
        obs_port = ntohs(a.sin_port);
        int fl = fcntl(obs_fd, F_GETFL, 0);
        fcntl(obs_fd, F_SETFL, fl | O_NONBLOCK);
    }
    int fd = socket(AF_INET, SOCK_DGRAM, 0);
    struct sockaddr_in to;
    memset(&to, 0, sizeof(to));
    to.sin_family = AF_INET;
    to.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    to.sin_port = htons((uint16_t)obs_port);
    connect(fd, (struct sockaddr *)&to, sizeof(to));
    return fd;
}

/* Взять следующий ушедший сегмент. -1 — не ушло ничего. */
static uint8_t wire_buf[2048];
static int wire_take(uint8_t **pay, size_t *pn) {
    ssize_t n = recv(obs_fd, wire_buf, sizeof(wire_buf), MSG_DONTWAIT);
    if (n < 20) return -1;
    size_t hl = (size_t)(wire_buf[12] >> 4) * 4;
    if (hl > (size_t)n) return -1;
    if (pay) *pay = wire_buf + hl;
    if (pn) *pn = (size_t)n - hl;
    return wire_buf[13];
}

static void wire_drain(void) {
    while (wire_take(NULL, NULL) >= 0) {}
}

/* ---- минимальный SYN с опцией MSS -------------------------------------------
 *
 * Собирается руками, а не берётся из захвата: подрезка смотрит ровно на четыре поля (версия,
 * протокол, флаг SYN, опция 2 длиной 4), и пакет из 44 байт содержит их все и ничего сверх. */
static size_t syn_build(uint8_t *ip, uint32_t src, uint32_t dst, int mss) {
    size_t n = 44;                                 /* 20 IP + 24 TCP (20 + опция MSS) */
    memset(ip, 0, n);
    ip[0] = 0x45;
    ip[2] = (uint8_t)(n >> 8);
    ip[3] = (uint8_t)(n & 0xFF);
    ip[8] = 64;                                    /* TTL: хабу его ещё уменьшать */
    ip[9] = 6;                                     /* TCP */
    uint32_t sn = htonl(src), dn = htonl(dst);
    memcpy(ip + 12, &sn, 4);
    memcpy(ip + 16, &dn, 4);
    uint8_t *tcp = ip + 20;
    tcp[12] = 6 << 4;                              /* смещение данных — 6 слов */
    tcp[13] = 0x02;                                /* SYN */
    tcp[20] = 2;                                   /* kind = MSS */
    tcp[21] = 4;                                   /* длина опции */
    tcp[22] = (uint8_t)(mss >> 8);
    tcp[23] = (uint8_t)(mss & 0xFF);
    return n;
}

static int syn_mss(const uint8_t *ip) {
    const uint8_t *tcp = ip + 20;
    return (tcp[22] << 8) | tcp[23];
}

int main(void) {
    printf("== хаб: арифметика записи ==\n");

    /* ПРАВИЛО НАБОРА, дословно как в worker_loop: перед чтением очередного кадра цикл требует
     * off + 2 + XS_MTU_DEF + XS_TAG <= XS_MAX_RECORD, а прочитанный кадр может быть полным.
     * Значит предельная нагрузка записи — вот эта. */
    size_t off_max = XS_MAX_RECORD - 2 - XS_MTU_DEF - XS_TAG;
    size_t pn_max = off_max + 2 + XS_MTU_DEF;
    check("предельная нагрузка записи по правилу набора",
          (long)(XS_MAX_RECORD - XS_TAG), (long)pn_max);
    check("она же равна XSH_PN_MAX, на который смотрит статическая проверка",
          (long)XSH_PN_MAX, (long)pn_max);

    /* ДОСТИЖИМОСТЬ. Проверка выше — про предел правила; эта — про то, что предел берётся
     * настоящими кадрами обычных размеров, а не только на бумаге. Набираем так же, как цикл:
     * полные кадры, пока следующий полный ещё оставляет off не выше границы правила; один
     * подогнанный, чтобы off встал ровно на границу; и ещё один полный — тот самый, который
     * правило пропускает, а строка уже не держала. */
    size_t off = XS_BATCH_HDR;
    int frames = 0;
    while (off + 2 + (size_t)XS_MTU_DEF <= off_max) { off += 2 + XS_MTU_DEF; frames++; }
    size_t pad = off_max - off - 2;
    off = off_max; frames++;
    off += 2 + XS_MTU_DEF; frames++;
    printf("     %d кадров: %d полных, один %zu байт и последний полный\n",
           frames, frames - 2, pad);
    check("подогнанный кадр — обычный пакет, а не выдумка", 1,
          pad > 20 && pad <= (size_t)XS_MTU_DEF);
    check("кадров нужно не больше, чем несёт пачка", 1, frames <= XS_BATCH_FRAMES_MAX);
    check("и набранная нагрузка равна предельной", (long)pn_max, (long)off);

    /* СТРОКА ВОРКЕРА. Нагрузка лежит по row + XS_HDR_ROOM (там же, где оказывается
     * расшифрованный пакет при пересылке пир↔пир), тег — сразу за нагрузкой. */
    size_t row = sizeof(((struct worker *)0)->row);
    check("строка воркера вмещает предельную запись с заголовками и тегом",
          1, row >= XS_HDR_ROOM + pn_max + XS_TAG);
    printf("     строка %zu, нужно %zu (заголовки %d + нагрузка %zu + тег %d)\n",
           row, XS_HDR_ROOM + pn_max + XS_TAG, XS_HDR_ROOM, pn_max, XS_TAG);

    /* ОДИНОЧНЫЙ КАДР. Он едет без контейнера, и hub_send_frames переносит его на место
     * нагрузки записи (memmove внутри строки) — предел тот же, что у сегмента. */
    check("одиночный кадр в строку влезает", 1,
          XS_HDR_ROOM + (size_t)XS_MTU_DEF + XS_TAG <= row);

    /* СЕГМЕНТОВ У ПРЕДЕЛЬНОЙ ЗАПИСИ НЕ БОЛЬШЕ, ЧЕМ ВЕКТОРОВ ПОД sendmmsg. Иначе
     * xs_conn_split_mm вернёт -1 и запись не уйдёт вовсе — то же молчаливое исчезновение
     * пакетов, только по другой причине. Проверяем настоящим split_mm на обоих концах
     * диапазона MTU: договорённом по умолчанию и наименьшем, до которого доходит пробой пути. */
    size_t cap = sizeof(((struct worker *)0)->hdrs) / 20;
    uint8_t rec[XS_REC_HDR + XSH_PN_MAX + XS_TAG];
    uint8_t hdrs[XS_BATCH_FRAMES_MAX + 8][20];
    struct iovec iov[2 * (XS_BATCH_FRAMES_MAX + 8)];
    struct mmsghdr mm[XS_BATCH_FRAMES_MAX + 8];
    memset(rec, 0x5A, sizeof(rec));
    int mtus[2] = { XS_MTU_DEF, XS_MTU_FLOOR };
    for (int i = 0; i < 2; i++) {
        struct xs_conn c;
        memset(&c, 0, sizeof(c));
        c.fd = -1;
        c.sport = 443;
        c.dport = 40000;
        size_t max_seg = (size_t)mtus[i] + XS_OVERHEAD - 40;
        int segs = xs_conn_split_mm(&c, rec, sizeof(rec), max_seg, hdrs, iov, mm, cap, 1000);
        printf("     MTU %d: сегментов %d, векторов %zu\n", mtus[i], segs, cap);
        check("предельная запись режется и влезает в векторы", 1, segs > 0);
    }

    /* ---- SYN в живую сессию (I-071) -----------------------------------------
     *
     * Поддельный SYN не несёт ни байта аутентификации, а ветка SYN приёмного цикла правила
     * по нему isn_rx — базу, из которой выводится nonce расшифровки. Одно постороннее
     * сообщение останавливало входящий поток целиком, и сессия при этом не умирала по
     * XSH_IDLE_MS, потому что last_rx обновляется каждым принятым сегментом.
     *
     * Про seq проверка ниже стоит не потому, что он уезжал: откат на единицу сходится сам,
     * SYN-ACK занимает этот номер обратно. Она стоит потому, что откат шёл БЕЗ g_tx_lock, а
     * записи данных в ту же сессию пишет другой воркер под этим замком — и номер между
     * откатом и SYN-ACK мог достаться настоящей записи. Такую гонку стендом не поймать;
     * поймать можно только то, что теперь по этому пути номер не меняется вовсе.
     *
     * Проверяется ровно граница: до подтверждённого рукопожатия SYN принимается (иначе
     * потерянный SYN-ACK нельзя было бы переспросить), после — не трогает ничего. Дотянуться
     * до этого удаётся потому, что ветка вынесена в sess_on_syn: внутри worker_loop её
     * окружают poll и сырой сокет. */
    printf("\n== хаб: SYN в живую сессию ==\n");
    {
        static struct worker w;
        struct sess *s = &g_sess[0];
        const uint32_t ISN_RX = 0x11111111u, SEQ = 0x22222222u, ACK = 0x33333333u;
        const uint32_t SYN_SEQ = 0x99999999u;

        int phases[2] = { PH_EST, PH_HS };
        const char *names[2] = { "работающая сессия", "сессия в рукопожатии" };
        for (int i = 0; i < 2; i++) {
            memset(&w, 0, sizeof(w));
            w.listen_port = 443; w.rx = -1; w.tx0 = -1; w.cap = 1;
            memset(s, 0, sizeof(*s));
            s->phase = phases[i];
            s->conn.fd = -1; s->conn.sport = 443; s->conn.dport = 40000;
            s->conn.isn_rx = ISN_RX; s->conn.seq = SEQ; s->conn.ack = ACK;

            struct obfs_seg seg;
            memset(&seg, 0, sizeof(seg));
            seg.flags = 0x02;                   /* SYN без ACK */
            seg.seq = SYN_SEQ;
            seg.sport = 40000;
            seg.saddr = htonl(0x0A000001);
            struct sess *r = sess_on_syn(&w, s, &seg, 1000);

            printf("  %s:\n", names[i]);
            check("  SYN отброшен, сессия не возвращена", 1, r == NULL);
            check("  isn_rx не подменён (nonce расшифровки цел)", (long)ISN_RX,
                  (long)s->conn.isn_rx);
            check("  seq не тронут вовсе (гонке с записью данных нечего забрать)", (long)SEQ,
                  (long)s->conn.seq);
            check("  ack не тронут", (long)ACK, (long)s->conn.ack);
            check("  отброшенный сосчитан", 1, (long)w.d_syn_est);
            check("  SYN-ACK не отправлялся", 0, (long)w.d_syn);
        }

        /* Обратная сторона границы: в фазе PH_SYN повторный SYN обязан приниматься —
         * иначе потерянный SYN-ACK означал бы, что пир не поднимется вовсе. */
        memset(&w, 0, sizeof(w));
        w.listen_port = 443; w.rx = -1; w.tx0 = -1; w.cap = 1;
        memset(s, 0, sizeof(*s));
        s->phase = PH_SYN;
        s->conn.fd = -1; s->conn.sport = 443; s->conn.dport = 40000;
        s->conn.isn_rx = ISN_RX; s->conn.seq = SEQ; s->conn.ack = ACK;
        struct obfs_seg seg2;
        memset(&seg2, 0, sizeof(seg2));
        seg2.flags = 0x02;
        seg2.seq = SYN_SEQ;
        seg2.sport = 40000;
        seg2.saddr = htonl(0x0A000001);
        struct sess *r2 = sess_on_syn(&w, s, &seg2, 1000);
        printf("  повтор в фазе рукопожатия:\n");
        check("  SYN принят", 1, r2 == s);
        check("  isn_rx взят из этого SYN", (long)SYN_SEQ, (long)s->conn.isn_rx);
        check("  ack встал за ним", (long)(SYN_SEQ + 1), (long)s->conn.ack);
        check("  SYN-ACK сосчитан", 1, (long)w.d_syn);
        check("  в живые сессии не записан", 0, (long)w.d_syn_est);
    }

    /* ---- ограничители разных событий не общие (I-064) ------------------------
     *
     * У воркера три ограничителя частоты, и каждый заведён под СВОЁ событие. Сообщение о
     * несобранных записях пользовалось ограничителем предупреждения о повторе метки времени:
     * тогда два разных события глушат друг друга в течение XS_LOG_EVERY_MS, а хвост «и ещё N
     * таких же» называет число, которое к напечатанной строке не относится. Ограничитель
     * заведён ровно для того, чтобы это число было верным.
     *
     * Проверяется наблюдаемое состояние ЧУЖОГО ограничителя: после двух кадров о потерях
     * сборки ограничитель метки времени обязан остаться нетронутым. */
    printf("\n== хаб: ограничитель на событие, а не на всех ==\n");
    {
        static struct worker w;
        struct sess *s = &g_sess[0];
        memset(&w, 0, sizeof(w));
        w.listen_port = 443; w.rx = -1; w.tx0 = -1; w.cap = 1;
        memset(s, 0, sizeof(*s));
        s->phase = PH_EST; s->peer = 0; s->batch_max = 8;
        s->conn.fd = -1; s->conn.sport = 443; s->conn.dport = 40000;

        uint8_t loss[8];
        size_t ln = xs_loss_build(loss, sizeof(loss), 3);
        check("кадр обратной связи по сборке собран", 1, ln > 0);
        hub_frame(&w, s, loss, ln, 1000);          /* печатается, ограничитель заряжен */
        hub_frame(&w, s, loss, ln, 1100);          /* в том же окне — подавлено */
        check("пачка схлопнута до одного кадра", 1, (long)s->batch_max);
        check("ограничитель метки времени не тронут", 0, (long)w.rl_stamp.last);
        check("подавленное не сосчитано ограничителем метки времени", 0,
              (long)w.rl_stamp.held);
        check("оно сосчитано своим ограничителем", 1, (long)w.rl_reasm.held);
    }

    /* ---- кадр IPv6 и нижняя граница MTU (I-073, I-075) -----------------------
     *
     * Оба про одно: недоверенное значение, которое дальше разбирается не тем, чем оно
     * является. hub_frame пропускал XS_IPV6 в route_packet, где кадр разбирается
     * ИСКЛЮЧИТЕЛЬНО как IPv4: адрес источника читается по смещению 12, а у пакета IPv6 там
     * лежат байты 4-7 его адреса источника. Обычно такой кадр отбрасывает проверка права на
     * адрес — то есть «не поддерживается» выводилось из случайного отказа, — но пира,
     * описанная в конфигурации, может подобрать эти байты так, чтобы они попали в её
     * разрешённый диапазон, и тогда кадр IPv6 уезжает в устройство как пакет IPv4.
     *
     * Второе: MTU, названный пиром в XS_CTL_MTU, принимался по единственному условию mv > 0.
     * Ниже ~492 запись перестаёт резаться (xs_conn_split_mm отказывает: сегментов больше, чем
     * векторов), и к этой пире не уходит НИ ОДНОГО пакета — ни данных, ни keepalive, ни
     * обратной связи, — причём молча. Пол у протокола есть: XS_MTU_FLOOR.
     *
     * Устройство подменено концом трубы: тогда «уехало в ядро» — наблюдаемый факт, а не
     * рассуждение о том, куда пошло исполнение. */
    printf("\n== хаб: кадр IPv6 и пол MTU ==\n");
    {
        static struct worker w;
        struct sess *s = &g_sess[0];
        int pf[2];
        if (pipe(pf) != 0) { printf("нет трубы — проверка невозможна\n"); return 1; }
        int fl = fcntl(pf[0], F_GETFL, 0);
        fcntl(pf[0], F_SETFL, fl | O_NONBLOCK);

        memset(&w, 0, sizeof(w));
        w.listen_port = 443; w.rx = -1; w.tx0 = -1; w.cap = 1;
        w.tun.fd = pf[1];
        xs_sidx_reset(&w.idx);
        memset(s, 0, sizeof(*s));
        s->phase = PH_EST; s->peer = 0; s->batch_max = 1;
        s->conn.fd = -1; s->conn.sport = 443; s->conn.dport = 40000;

        /* Пир имеет право на 10.7.0.0/24 — ровно те байты, которые разбор IPv4 прочитает у
         * кадра IPv6 как адрес источника. */
        memset(&g_conf, 0, sizeof(g_conf));
        g_conf.listen_port = 443;
        g_conf.peer_n = 1;
        g_conf.peer[0].allowed_n = 1;
        g_conf.peer[0].allowed[0].net = 0x0A070000u;
        g_conf.peer[0].allowed[0].mask = 0xFFFFFF00u;
        g_conf.peer[0].allowed[0].plen = 24;
        xs_router_build(&g_router, g_conf.peer, g_conf.peer_n);

        uint8_t *pt = w.row + XS_HDR_ROOM;
        memset(pt, 0, 40);
        pt[0] = 0x60;                                  /* версия 6 */
        pt[7] = 64;                                    /* hop limit */
        pt[12] = 0x0A; pt[13] = 0x07; pt[14] = 0x00; pt[15] = 0x02;  /* середина src */
        check("кадр опознан как IPv6", (long)XS_IPV6, (long)xs_frame_kind(pt, 40));
        check("а разбор IPv4 прочёл бы эти байты как разрешённый адрес источника", 1,
              xs_src_ok(&g_conf.peer[0], 0x0A070002u));
        hub_frame(&w, s, pt, 40, 1000);
        uint8_t sink[64];
        ssize_t got = read(pf[0], sink, sizeof(sink));
        check("кадр IPv6 в устройство не уехал", -1, (long)got);
        check("он сосчитан своим счётчиком", 1, (long)w.d_ipv6);
        hub_frame(&w, s, pt, 40, 1010);
        check("вторая такая же строка подавлена своим ограничителем", 1,
              (long)w.rl_ipv6.held);

        /* Пол MTU. Значение ниже пола не принимается вовсе: прежнее остаётся в силе. */
        uint8_t mf[8];
        s->mtu = 1400;
        size_t mn = xs_mtu_build(mf, sizeof(mf), 400);
        check("кадр XS_CTL_MTU собран", 1, mn > 0);
        hub_frame(&w, s, mf, mn, 1020);
        check("MTU ниже пола не принят", 1400, (long)s->mtu);
        mn = xs_mtu_build(mf, sizeof(mf), XS_MTU_FLOOR - 1);
        hub_frame(&w, s, mf, mn, 1030);
        check("на байт ниже пола — тоже не принят", 1400, (long)s->mtu);
        mn = xs_mtu_build(mf, sizeof(mf), XS_MTU_FLOOR);
        hub_frame(&w, s, mf, mn, 1040);
        check("ровно пол — принят", (long)XS_MTU_FLOOR, (long)s->mtu);

        /* ПОТОЛОК MTU — того же класса, что пол, и его не было вовсе.
         *
         * Значение из провода зажималось ТОЛЬКО числом из конфигурации, а конфигурация
         * принимает MTU до XS_LINK_MAX (xsconf.c: «576..1500»). Хаб, настроенный по MTU
         * КАНАЛА вместо MTU туннеля — обычная описка, ведь оба числа называются «MTU», — плюс
         * пир, назвавший столько же, дают max_seg = 1521 и пакет на проводе 1561 байт. Дальше
         * одно из двух, и оба плохи: либо ядро фрагментирует его (фрагментация сама по себе
         * признак протокола, и такие пакеты режут по пути), либо sendmmsg отвечает EMSGSIZE и
         * к этому пиру не уходит НИ ОДНОГО крупного кадра. Снаружи это «мелкие пакеты ходят,
         * крупные молча пропадают» — тот же худший класс отказов, что у пола.
         *
         * Проверяется не только само число, но и то, ради чего потолок существует: пакет с
         * согласованным сегментом обязан влезать в кадр канала. Иначе потолок можно было бы
         * «починить» любой константой, которая ни с чем не связана. */
        g_conf.mtu = XS_LINK_MAX;
        int over[4] = { XS_MTU_DEF + 1, 1480, XS_LINK_MAX, 9000 };
        for (int i = 0; i < 4; i++) {
            s->mtu = 1400;
            mn = xs_mtu_build(mf, sizeof(mf), over[i]);
            hub_frame(&w, s, mf, mn, 1050 + i * 10);
            char what[80];
            snprintf(what, sizeof(what), "MTU %d из провода зажат потолком", over[i]);
            check(what, (long)XS_MTU_DEF, (long)s->mtu);
            size_t seg = (size_t)s->mtu + XS_OVERHEAD - 40;
            printf("     MTU %d: сегмент %zu, на проводе %zu\n", over[i], seg,
                   XS_IP_HDR + XS_TCP_HDR + seg);
            check("пакет с таким сегментом влезает в кадр канала", 1,
                  XS_IP_HDR + XS_TCP_HDR + seg <= XS_LINK_MAX);
        }
        g_conf.mtu = 0;
        close(pf[0]);
        close(pf[1]);
    }

    /* ---- ответ неопознанному: четыре режима (I-076, R-062) -------------------
     *
     * Активное зондирование — это прибор, который сам присылает ClientHello (или «GET /
     * HTTP/1.1», или просто мусор) и смотрит НА ОТВЕТ. До появления режимов ответ был один —
     * семь байт фатального оповещения TLS, — и он отличим от настоящего сервера с сертификатом
     * одной командой openssl s_client. Здесь проверяется, что каждый режим отвечает ровно тем,
     * что обещает, и что дорожка проксирования делает три вещи, которые в реализации на Go
     * нашлись только стендом: отдаёт прикрытию присланное БЕЗ ПРАВОК, режет ответ на сегменты и
     * закрывает НАШУ сессию, когда прикрытие закрыло своё.
     *
     * Прикрытие здесь настоящее: слушающий сокет на петле. Ни root, ни сети наружу это не
     * требует, а проверяет ровно то, что происходит в бою, — включая неблокирующий connect. */
    printf("\n== хаб: ответ неопознанному ==\n");
    {
        static struct worker w;
        struct sess *s = &g_sess[0];
        const char *probe = "GET / HTTP/1.1\r\nHost: example.com\r\n\r\n";
        size_t probe_n = strlen(probe);

        /* Слушающий сокет прикрытия. */
        int srv = socket(AF_INET, SOCK_STREAM, 0);
        struct sockaddr_in sa;
        socklen_t sl = sizeof(sa);
        memset(&sa, 0, sizeof(sa));
        sa.sin_family = AF_INET;
        sa.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
        if (srv < 0 || bind(srv, (struct sockaddr *)&sa, sizeof(sa)) != 0 ||
            listen(srv, 4) != 0 || getsockname(srv, (struct sockaddr *)&sa, &sl) != 0) {
            printf("нет петлевого сокета — проверка невозможна\n");
            return 1;
        }
        int decoy_port = ntohs(sa.sin_port);

        memset(&g_conf, 0, sizeof(g_conf));
        g_conf.listen_port = 443;
        g_conf.peer_n = 0;

        /* Каждый случай начинается с чистой сессии в фазе рукопожатия и настоящего сегмента с
         * мусором вместо TLS: ровно то, что присылает прибор первым делом. */
        struct { int mode; const char *name; } modes[3] = {
            { XS_DECOY_ALERT,  "alert" },
            { XS_DECOY_SILENT, "silent" },
            { XS_DECOY_RESET,  "reset" },
        };
        for (int m = 0; m < 3; m++) {
            memset(&w, 0, sizeof(w));
            w.listen_port = 443; w.rx = -1; w.tx0 = -1; w.base = 0; w.cap = 1;
            xs_sidx_reset(&w.idx);
            memset(s, 0, sizeof(*s));
            s->phase = PH_SYN; s->peer = -1; s->conn_id = -1; s->up_fd = -1;
            s->conn.fd = wire_open(); s->conn.sport = 443; s->conn.dport = 40000;
            s->conn.daddr = htonl(0x0A000001u);
            g_conf.decoy = modes[m].mode;
            wire_drain();

            struct obfs_seg seg;
            memset(&seg, 0, sizeof(seg));
            seg.flags = 0x18;
            seg.sport = 40000;
            seg.saddr = htonl(0x0A000001u);
            seg.payload = (const uint8_t *)probe;
            seg.plen = probe_n;
            hs_step(&w, s, &seg, 443, 1000);

            uint8_t *pay = NULL;
            size_t pn = 0;
            int flags = wire_take(&pay, &pn);
            printf("  режим %s:\n", modes[m].name);
            check("  сессия закрыта", (long)PH_FREE, (long)s->phase);
            if (modes[m].mode == XS_DECOY_ALERT) {
                check("  ушло фатальное оповещение TLS", 0x18, flags);
                check("  ровно семь байт", 7, (long)pn);
                check("  и это запись типа alert", 0x15, pay ? pay[0] : 0);
                check("  fatal handshake_failure", 0x0228,
                      pay && pn == 7 ? (pay[5] << 8) | pay[6] : 0);
            } else if (modes[m].mode == XS_DECOY_SILENT) {
                check("  не ушло ничего", -1, flags);
            } else {
                check("  ушёл RST", 0x14, flags);
                check("  без нагрузки", 0, (long)pn);
            }
        }

        /* ---- proxy: настоящее соединение к прикрытию ------------------------- */
        printf("  режим proxy:\n");
        memset(&w, 0, sizeof(w));
        w.listen_port = 443; w.rx = -1; w.tx0 = -1; w.base = 0; w.cap = 1;
        xs_sidx_reset(&w.idx);
        memset(s, 0, sizeof(*s));
        s->phase = PH_SYN; s->peer = -1; s->conn_id = -1; s->up_fd = -1;
        s->conn.fd = wire_open(); s->conn.sport = 443; s->conn.dport = 40000;
        s->conn.daddr = htonl(0x0A000001u);
        g_conf.decoy = XS_DECOY_PROXY;
        snprintf(g_conf.decoy_dest, sizeof(g_conf.decoy_dest), "127.0.0.1");
        g_conf.decoy_port = decoy_port;
        g_decoy_live = 0;
        wire_drain();
        {
            struct obfs_seg seg;
            memset(&seg, 0, sizeof(seg));
            seg.flags = 0x18;
            seg.sport = 40000;
            seg.saddr = htonl(0x0A000001u);
            seg.payload = (const uint8_t *)probe;
            seg.plen = probe_n;
            hs_step(&w, s, &seg, 443, 1000);
        }
        check("  сессия жива и переведена на дорожку прикрытия", (long)PH_PROXY, (long)s->phase);
        check("  соединение к прикрытию открыто", 1, s->up_fd >= 0);
        check("  прибору пока не ушло ни байта отказа", -1, wire_take(NULL, NULL));
        check("  занято одно место из предела", 1, (long)g_decoy_live);
        check("  сосчитано", 1, (long)w.d_decoy);

        int up = accept(srv, NULL, NULL);
        check("  прикрытие приняло соединение", 1, up >= 0);
        decoy_event(&w, s, POLLOUT, 1010);
        check("  присланное отдано прикрытию целиком", 1, (long)s->up_ready);
        {
            uint8_t got[256];
            ssize_t gn = recv(up, got, sizeof(got), 0);
            check("  прикрытию ушло столько же байт, сколько прислал прибор",
                  (long)probe_n, (long)gn);
            check("  и ровно те же байты, без единой правки", 0,
                  gn == (ssize_t)probe_n ? memcmp(got, probe, probe_n) : 1);
        }

        /* Ответ прикрытия режется на сегменты: у нас датаграммная семантика, и сегмент больше
         * MSS просто не дойдёт. */
        {
            uint8_t big[1500];
            for (size_t i = 0; i < sizeof(big); i++) big[i] = (uint8_t)(i & 0xFF);
            check("  прикрытие ответило", (long)sizeof(big),
                  (long)send(up, big, sizeof(big), 0));
            decoy_event(&w, s, POLLIN, 1020);
            uint8_t *pay = NULL;
            size_t pn = 0, total = 0;
            int segs = 0, ok_bytes = 1;
            int flags;
            while ((flags = wire_take(&pay, &pn)) >= 0) {
                if (flags != 0x18) ok_bytes = 0;
                if (pn > XSH_DECOY_CHUNK) ok_bytes = 0;
                if (memcmp(pay, big + total, pn) != 0) ok_bytes = 0;
                total += pn;
                segs++;
            }
            check("  ответ прикрытия дошёл прибору целиком", (long)sizeof(big), (long)total);
            check("  разрезанный на сегменты не больше куска", 2, segs);
            check("  байты те же и флаги как у данных", 1, ok_bytes);
        }

        /* Продолжение прибора уходит прикрытию как есть. */
        {
            const char *more = "второй запрос";
            struct obfs_seg seg;
            memset(&seg, 0, sizeof(seg));
            seg.flags = 0x18;
            seg.sport = 40000;
            seg.saddr = htonl(0x0A000001u);
            seg.payload = (const uint8_t *)more;
            seg.plen = strlen(more);
            decoy_up(&w, s, &seg, 1030);
            uint8_t got[64];
            ssize_t gn = recv(up, got, sizeof(got), 0);
            check("  продолжение прибора ушло прикрытию", (long)strlen(more), (long)gn);
            check("  и тоже без правок", 0,
                  gn > 0 ? memcmp(got, more, (size_t)gn) : 1);
        }

        /* ЗАКРЫТИЕ ПРИКРЫТИЯ ЗАКРЫВАЕТ И НАС. Без этого прибор, приславший запрос HTTP, не
         * получал ничего: прикрытие закрывалось, а поддельное соединение висело — снаружи это
         * ровно тот признак, ради устранения которого дорожка и заведена. */
        close(up);
        wire_drain();
        decoy_event(&w, s, POLLIN, 1040);
        {
            uint8_t *pay = NULL;
            size_t pn = 0;
            int flags = wire_take(&pay, &pn);
            check("  прикрытие закрылось — ушёл FIN", 0x11, flags);
            check("  и наша сессия закрыта", (long)PH_FREE, (long)s->phase);
            check("  место в пределе освобождено", 0, (long)g_decoy_live);
        }

        /* ПРЕДЕЛ ОДНОВРЕМЕННО ПРОКСИРУЕМЫХ. Без него поток зондирования превращается в нашу же
         * атаку на прикрытие и на собственные дескрипторы. Сверх предела отвечаем как прежде. */
        g_decoy_live = XSH_DECOY_MAX;
        memset(s, 0, sizeof(*s));
        s->phase = PH_SYN; s->peer = -1; s->conn_id = -1; s->up_fd = -1;
        s->conn.fd = wire_open(); s->conn.sport = 443; s->conn.dport = 40000;
        s->conn.daddr = htonl(0x0A000001u);
        wire_drain();
        {
            struct obfs_seg seg;
            memset(&seg, 0, sizeof(seg));
            seg.flags = 0x18;
            seg.sport = 40000;
            seg.saddr = htonl(0x0A000001u);
            seg.payload = (const uint8_t *)probe;
            seg.plen = probe_n;
            hs_step(&w, s, &seg, 443, 1050);
            uint8_t *pay = NULL;
            size_t pn = 0;
            int flags = wire_take(&pay, &pn);
            printf("  сверх предела:\n");
            check("  соединения к прикрытию нет", 1, s->up_fd < 0);
            check("  предел не превышен", (long)XSH_DECOY_MAX, (long)g_decoy_live);
            check("  ответ прежний — оповещение", 0x18, flags);
            check("  и оно те же семь байт", 7, (long)pn);
            check("  сессия закрыта", (long)PH_FREE, (long)s->phase);
        }
        g_decoy_live = 0;
        close(srv);
    }

    /* ---- MSS пир↔пир: узкое место — минимум ДВУХ тоннелей (I-077) ------------
     *
     * MSS в SYN объявляет то, что отправитель готов ПРИНИМАТЬ, то есть ограничивает сегменты,
     * которые вторая сторона пошлёт ОБРАТНО, — а обратный путь идёт через тоннель отправителя.
     * Подрезка только по MTU получателя оставляла обратному потоку предел шире, чем держит
     * тоннель отправителя: при отправителе 1380 и получателе 1420 SYN уходил с MSS 1380, и
     * полноразмерные ответы получателя в тоннель 1380 не влезали. Снаружи это «мелкое ходит,
     * большое пропадает» между двумя пирами с разными MTU, причём молча: ICMP «нужна
     * фрагментация» внутри тоннеля не рождается, а посчитать минимум кроме хаба некому — пиры
     * друг о друге ничего не знают.
     *
     * Обе стороны проверяются нарочно: при получателе уже отправителя прежний код давал верное
     * число, и односторонняя проверка прошла бы на баге.
     *
     * Сессия получателя оставлена НЕ в PH_EST намеренно: send_to отказывает на первой же
     * проверке фазы под своим замком, то есть до шифрования в той же строке, и подрезанный
     * пакет остаётся читаемым. Проверяется ровно то число, которое хаб подставил в подрезку. */
    printf("\n== хаб: MSS пир↔пир по минимуму тоннелей ==\n");
    {
        static struct worker w;
        struct sess *from = &g_sess[0], *d = &g_sess[1];

        memset(&g_conf, 0, sizeof(g_conf));
        g_conf.listen_port = 443;
        g_conf.peer_n = 2;
        g_conf.peer[0].allowed_n = 1;
        g_conf.peer[0].allowed[0].net = 0x0A070000u;
        g_conf.peer[0].allowed[0].mask = 0xFFFFFF00u;
        g_conf.peer[0].allowed[0].plen = 24;
        g_conf.peer[1].allowed_n = 1;
        g_conf.peer[1].allowed[0].net = 0x0A080000u;
        g_conf.peer[1].allowed[0].mask = 0xFFFFFF00u;
        g_conf.peer[1].allowed[0].plen = 24;
        xs_router_build(&g_router, g_conf.peer, g_conf.peer_n);

        /* Таблица пир→сессия у стенда нулевая, а ноль — это индекс живой сессии: без сброса
         * peer_pick вернул бы сессию отправителя. */
        for (int i = 0; i < XS_PEERS_MAX; i++)
            for (int c = 0; c < XS_CONNS_MAX; c++) g_peer_sess[i][c] = -1;
        g_peer_sess[1][0] = (int16_t)(d - g_sess);

        struct { int from_mtu, d_mtu, want; const char *name; } cs[5] = {
            { 1380, 1420, 1340, "тоннель отправителя уже: 1380 против 1420" },
            { 1420, 1380, 1340, "тоннель получателя уже: 1420 против 1380" },
            { 1300, 1300, 1260, "узкое место сам хаб — оба по 1300" },
            {    0, 1420, 1380, "отправитель размера не назвал — по получателю" },
            { 1420,    0, 1380, "получатель не назвал — по отправителю" },
        };
        for (int i = 0; i < 5; i++) {
            memset(&w, 0, sizeof(w));
            w.listen_port = 443; w.rx = -1; w.tx0 = -1; w.cap = 1;
            w.tun.fd = -1;
            xs_sidx_reset(&w.idx);
            memset(from, 0, sizeof(*from));
            memset(d, 0, sizeof(*d));
            from->phase = PH_EST; from->peer = 0; from->conn_id = 0;
            from->mtu = cs[i].from_mtu; from->conn.fd = -1;
            d->phase = PH_SYN; d->peer = 1; d->conn_id = 0;
            d->mtu = cs[i].d_mtu; d->conn.fd = -1;

            uint8_t *pt = w.row + XS_HDR_ROOM;
            size_t pn = syn_build(pt, 0x0A070002u, 0x0A080002u, 1460);
            route_packet(&w, from, pt, pn, 1000);
            printf("  %s:\n", cs[i].name);
            check("  MSS по узкому месту пути, а не по одному концу",
                  (long)cs[i].want, (long)syn_mss(pt));
        }

        /* Ни один MTU не согласован — подрезать не по чему, опция остаётся как пришла. */
        memset(&w, 0, sizeof(w));
        w.listen_port = 443; w.rx = -1; w.tx0 = -1; w.cap = 1;
        w.tun.fd = -1;
        xs_sidx_reset(&w.idx);
        memset(from, 0, sizeof(*from));
        memset(d, 0, sizeof(*d));
        from->phase = PH_EST; from->peer = 0; from->conn.fd = -1;
        d->phase = PH_SYN; d->peer = 1; d->conn.fd = -1;
        {
            uint8_t *pt = w.row + XS_HDR_ROOM;
            size_t pn = syn_build(pt, 0x0A070002u, 0x0A080002u, 1460);
            route_packet(&w, from, pt, pn, 1000);
            printf("  размера не назвал никто:\n");
            check("  MSS не тронут", 1460, (long)syn_mss(pt));
        }
    }

    /* ---- прикрытие по имени из SNI (R-070) -----------------------------------
     *
     * Одно постоянное прикрытие даёт подлинный сертификат только тому, кто спросил имя ЭТОГО
     * прикрытия; всякий другой прибор видит «просил A — получил сертификат B», то есть ровно
     * тот признак, ради устранения которого дорожка proxy и заведена. Имена разрешаются в
     * адреса один раз при подъёме, а здесь проверяется выбор по таблице — и, главное, его
     * поведение на недоверенных байтах: разбор SNI происходит ДО всякой аутентификации, на
     * публичном порту, куда пишет кто угодно.
     *
     * Hello берётся НАСТОЯЩИЙ (замороженные байты reality.c, SNI www.example.com), а не
     * выдуманный: разбор придирчив к длине записи, к session_id и к key_share, и стенд на
     * самодельном Hello проверял бы не то, что приходит в бою. */
    printf("\n== хаб: прикрытие по имени из SNI ==\n");
    {
        const uint8_t *hello = (const uint8_t *)FROZEN_AES;
        const uint32_t A_COM = inet_addr("198.51.100.7");
        const uint32_t A_NET = inet_addr("198.51.100.8");
        const uint32_t A_FIX = inet_addr("203.0.113.9");

        memset(&g_conf, 0, sizeof(g_conf));
        g_conf.listen_port = 443;
        g_conf.decoy = XS_DECOY_PROXY;
        snprintf(g_conf.decoy_dest, sizeof(g_conf.decoy_dest), "203.0.113.9");
        g_conf.decoy_port = 443;

        /* Таблица — та, что заполняет hub_decoy_resolve при подъёме. Имена в ней уже
         * нормализованы разбором конфигурации: нижний регистр, без завершающей точки. */
        memset(g_decoy_map, 0, sizeof(g_decoy_map));
        snprintf(g_decoy_map[0].name, XS_DECOY_SNI_LEN, "www.example.com");
        g_decoy_map[0].addr = A_COM;
        snprintf(g_decoy_map[1].name, XS_DECOY_SNI_LEN, "cdn.example.net");
        g_decoy_map[1].addr = A_NET;
        g_decoy_map_n = 2;

        check("имя из SNI ведёт к своему прикрытию, а не к постоянному",
              (long)A_COM, (long)decoy_dest_for(hello, FROZEN_N));

        /* Имя ВНЕ таблицы — прежнее поведение, а не отказ. Отказывай мы по незнакомому имени,
         * порт отвечал бы по-разному на разные имена, и сама эта разница рассказывала бы
         * прибору, какие имена мы обслуживаем. Подменяем имя той же длины, чтобы ни одно поле
         * длины в Hello не поехало. */
        uint8_t buf[FROZEN_N];
        size_t sni_off = 0;
        for (size_t i = 0; i + 15 <= FROZEN_N; i++)
            if (memcmp(hello + i, "www.example.com", 15) == 0) { sni_off = i; break; }
        check("имя нашлось в замороженном Hello", 1, sni_off != 0);

        memcpy(buf, hello, FROZEN_N);
        memcpy(buf + sni_off, "www.example.ORG", 15);
        check("незнакомое имя — постоянное прикрытие, а не отказ",
              (long)A_FIX, (long)decoy_dest_for(buf, FROZEN_N));

        /* Регистр имени выбирает прибор, а не мы: DNS его не различает, и «WWW.» от того же
         * прибора не должно означать другое прикрытие. */
        memcpy(buf, hello, FROZEN_N);
        memcpy(buf + sni_off, "WWW.Example.COM", 15);
        check("регистр имени не важен", (long)A_COM, (long)decoy_dest_for(buf, FROZEN_N));

        /* Посторонний символ в имени — прежнее поведение. Сравнивать такое имя не с чем, а
         * отвечать иначе, чем прочим неопознанным, нельзя. */
        memcpy(buf, hello, FROZEN_N);
        memcpy(buf + sni_off, "www.examp/e.com", 15);
        check("имя с посторонним символом — постоянное прикрытие",
              (long)A_FIX, (long)decoy_dest_for(buf, FROZEN_N));

        /* Не TLS вовсе и полуприсланное — тоже прежнее поведение. */
        check("мусор вместо Hello — постоянное прикрытие", (long)A_FIX,
              (long)decoy_dest_for((const uint8_t *)"GET / HTTP/1.1\r\n\r\n", 18));
        check("Hello дочитан наполовину — постоянное прикрытие", (long)A_FIX,
              (long)decoy_dest_for(hello, FROZEN_N / 2));
        check("нечего разбирать вовсе — постоянное прикрытие", (long)A_FIX,
              (long)decoy_dest_for(hello, 0));

        /* Таблица пуста — ведём себя ровно как до появления ключа. */
        g_decoy_map_n = 0;
        check("без таблицы имён — прежнее поведение", (long)A_FIX,
              (long)decoy_dest_for(hello, FROZEN_N));
        g_decoy_map_n = 2;

        /* ГРАНИЦЫ. Разбор смотрит на присланные байты до всякой аутентификации, поэтому
         * проверяется не «разобралось ли», а что НИ ОДНА обрезка и ни одна порча байта не
         * уводит исполнение за буфер и не даёт адреса, которого нет в таблице. Под
         * -fsanitize=address,undefined это и есть проверка границ; без него — проверка того,
         * что ответ всегда один из трёх известных. */
        int bad = 0;
        for (size_t n = 0; n <= FROZEN_N; n++) {
            uint32_t got = decoy_dest_for(hello, n);
            if (got != A_FIX && got != A_COM) bad++;
        }
        check("любая обрезка Hello даёт известный адрес и не выходит за буфер", 0, bad);
        bad = 0;
        for (size_t i = 0; i < FROZEN_N; i++) {
            memcpy(buf, hello, FROZEN_N);
            buf[i] ^= 0xFF;
            uint32_t got = decoy_dest_for(buf, FROZEN_N);
            if (got != A_FIX && got != A_COM && got != A_NET) bad++;
        }
        check("порча любого байта Hello не уводит к чужому адресу", 0, bad);
    }

    /* ---- то же на НАСТОЯЩЕМ соединении: прибор назвал имя — туда и позвонили --- */
    printf("\n== хаб: соединение к прикрытию, выбранному именем ==\n");
    {
        static struct worker w;
        struct sess *s = &g_sess[0];

        int srv = socket(AF_INET, SOCK_STREAM, 0);
        struct sockaddr_in sa;
        socklen_t sl = sizeof(sa);
        memset(&sa, 0, sizeof(sa));
        sa.sin_family = AF_INET;
        sa.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
        if (srv < 0 || bind(srv, (struct sockaddr *)&sa, sizeof(sa)) != 0 ||
            listen(srv, 4) != 0 || getsockname(srv, (struct sockaddr *)&sa, &sl) != 0) {
            printf("нет петлевого сокета — проверка невозможна\n");
            return 1;
        }
        int port = ntohs(sa.sin_port);
        /* Слушающий сокет НЕБЛОКИРУЮЩИЙ, и ждём мы его через poll с пределом: если выбор по
         * имени не сработает, дорожка уйдёт к постоянному прикрытию, сюда не позвонит никто, и
         * блокирующий accept подвесил бы весь стенд навсегда вместо того, чтобы показать
         * провалившуюся проверку. */
        {
            int sfl = fcntl(srv, F_GETFL, 0);
            fcntl(srv, F_SETFL, sfl | O_NONBLOCK);
        }

        memset(&g_conf, 0, sizeof(g_conf));
        g_conf.listen_port = 443;
        g_conf.decoy = XS_DECOY_PROXY;
        /* Постоянное прикрытие ведёт ТУДА, ГДЕ НИКТО НЕ СЛУШАЕТ: если выбор по имени не
         * сработает, дорожка пойдёт к нему, и это будет видно, а не спрячется за успехом. */
        snprintf(g_conf.decoy_dest, sizeof(g_conf.decoy_dest), "127.0.0.2");
        g_conf.decoy_port = port;
        memset(g_decoy_map, 0, sizeof(g_decoy_map));
        snprintf(g_decoy_map[0].name, XS_DECOY_SNI_LEN, "www.example.com");
        g_decoy_map[0].addr = inet_addr("127.0.0.1");
        g_decoy_map_n = 1;

        memset(&w, 0, sizeof(w));
        w.listen_port = 443; w.rx = -1; w.tx0 = -1; w.base = 0; w.cap = 1;
        xs_sidx_reset(&w.idx);
        memset(s, 0, sizeof(*s));
        s->phase = PH_SYN; s->peer = -1; s->conn_id = -1; s->up_fd = -1;
        s->conn.fd = wire_open(); s->conn.sport = 443; s->conn.dport = 40000;
        s->conn.daddr = htonl(0x0A000001u);
        g_decoy_live = 0;
        wire_drain();

        /* Настоящий ClientHello с настоящим SNI. Рукопожатие на нём не сойдётся (ключи в
         * заморозке чужие), значит хаб пойдёт по дорожке неопознанного — ровно как в бою. */
        struct obfs_seg seg;
        memset(&seg, 0, sizeof(seg));
        seg.flags = 0x18;
        seg.sport = 40000;
        seg.saddr = htonl(0x0A000001u);
        seg.payload = (const uint8_t *)FROZEN_AES;
        seg.plen = FROZEN_N;
        hs_step(&w, s, &seg, 443, 1000);

        check("сессия на дорожке прикрытия", (long)PH_PROXY, (long)s->phase);
        check("позвонили по имени из SNI, а не в DecoyDest",
              (long)inet_addr("127.0.0.1"), (long)s->up_addr);
        struct pollfd wait_fd = { srv, POLLIN, 0 };
        poll(&wait_fd, 1, 2000);
        int up = accept(srv, NULL, NULL);
        check("прикрытие, названное именем, приняло соединение", 1, up >= 0);
        decoy_event(&w, s, POLLOUT, 1010);
        check("присланное отдано ему целиком", 1, (long)s->up_ready);
        {
            uint8_t got[FROZEN_N + 16];
            ssize_t gn = up >= 0 ? recv(up, got, sizeof(got), 0) : -1;
            check("и ровно те же байты, без единой правки", (long)FROZEN_N, (long)gn);
            check("байт в байт", 0, gn == (ssize_t)FROZEN_N ? memcmp(got, FROZEN_AES, FROZEN_N) : 1);
        }
        if (up >= 0) close(up);
        sess_free(&w, s);
        close(srv);
        g_decoy_map_n = 0;
        g_decoy_live = 0;
    }

    /* ---- «не наш» опознан ПОЗЖЕ разбора: накопленное всё равно доезжает (I-124) ----
     *
     * Развилок «не наш» в hs_step три, и до сих пор присланное доходило до прикрытия только
     * на первой — «рукопожатие не разобралось». Две другие лежат ЗА успешным
     * xs_hs_server_read: «нет такого пира» и «повтор msg1». Накопленное очищалось сразу за
     * разбором, то есть до них, и прикрытие на этих двух развилках получало ПУСТОТУ: имя из
     * SNI не разбиралось (звонок уходил в постоянный DecoyDest вместо названного прибором), а
     * сам ClientHello не уходил вовсе — открытое соединение, в котором никто ничего не сказал,
     * и прибор, ждущий ответа, которого не будет.
     *
     * Кому это видно: тому, у кого есть наш ОТКРЫТЫЙ ключ, — своей паре ключей хватает, чтобы
     * дойти до «нет такого пира». То есть разница в ответе достаётся ровно тому, кто уже
     * подозревает, что здесь не сайт. Ту же правку в реализации на Go сделал H-098.
     *
     * Hello здесь собирается на месте настоящим клиентским рукопожатием, а не берётся из
     * заморозки: обе развилки лежат за успешным разбором, а заморозку с чужими ключами разбор
     * не проходит. */
    printf("\n== хаб: неопознанный, опознанный за успешным разбором ==\n");
    {
        static struct worker w;
        struct sess *s = &g_sess[0];
        static uint8_t hello[4096];
        size_t hn = 0;
        struct xs_secrets peer_sec;
        struct xs_hs chs;
        uint8_t hub_pub[32], peer_pub[32];

        /* Ключи постоянные, чтобы стенд не зависел от источника случайности; эфемерный ключ
         * рукопожатия всё равно свежий на каждом вызове. Подрезка обязательна: скалярное
         * умножение на кривой 25519 принимает только скаляр нужной формы, и без неё вывод
         * публичной половины отказывает, а не даёт другой ключ. */
        memset(&g_sec, 0, sizeof(g_sec));
        memset(&peer_sec, 0, sizeof(peer_sec));
        for (int i = 0; i < 32; i++) {
            g_sec.priv[i]   = (uint8_t)(0x11 + i);
            peer_sec.priv[i] = (uint8_t)(0x71 + i);
        }
        g_sec.priv[0] &= 248;    g_sec.priv[31] &= 127;    g_sec.priv[31] |= 64;
        peer_sec.priv[0] &= 248; peer_sec.priv[31] &= 127; peer_sec.priv[31] |= 64;
        g_sec.has_priv = peer_sec.has_priv = 1;
        check("статические ключи стенда выведены", 0,
              xc_x25519_public(g_sec.priv, hub_pub) |
              xc_x25519_public(peer_sec.priv, peer_pub));
        memset(&chs, 0, sizeof(chs));
        check("настоящий msg1 собран", 0,
              xs_hs_client_hello(&chs, &peer_sec, hub_pub, "www.example.com", 1420, 0,
                                 hello, sizeof(hello), &hn));
        check("и он не влезает в один сегмент — придёт частями", 1, hn > 1200);
        /* Состояние клиентского рукопожатия дальше не нужно — только собранные байты. Затираем
         * сразу: в нём живёт контекст шифра, и без этого стенд течёт под ASan. */
        xs_hs_wipe(&chs);

        struct { const char *name; size_t peers; } forks[2] = {
            { "нет такого пира", 0 },
            { "повтор msg1",     1 },
        };
        for (int f = 0; f < 2; f++) {
            printf("  развилка «%s»:\n", forks[f].name);

            int srv = socket(AF_INET, SOCK_STREAM, 0);
            struct sockaddr_in sa;
            socklen_t sl = sizeof(sa);
            memset(&sa, 0, sizeof(sa));
            sa.sin_family = AF_INET;
            sa.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
            if (srv < 0 || bind(srv, (struct sockaddr *)&sa, sizeof(sa)) != 0 ||
                listen(srv, 4) != 0 || getsockname(srv, (struct sockaddr *)&sa, &sl) != 0) {
                printf("нет петлевого сокета — проверка невозможна\n");
                return 1;
            }
            {
                int sfl = fcntl(srv, F_GETFL, 0);
                fcntl(srv, F_SETFL, sfl | O_NONBLOCK);
            }

            memset(&g_conf, 0, sizeof(g_conf));
            g_conf.listen_port = 443;
            g_conf.decoy = XS_DECOY_PROXY;
            /* Постоянное прикрытие ведёт ТУДА, ГДЕ НИКТО НЕ СЛУШАЕТ: выбор по имени работает
             * только по разобранному Hello, и на пустом буфере дорожка ушла бы сюда — это
             * будет видно провалом, а не спрячется за успехом. */
            snprintf(g_conf.decoy_dest, sizeof(g_conf.decoy_dest), "127.0.0.2");
            g_conf.decoy_port = ntohs(sa.sin_port);
            memset(g_decoy_map, 0, sizeof(g_decoy_map));
            snprintf(g_decoy_map[0].name, XS_DECOY_SNI_LEN, "www.example.com");
            g_decoy_map[0].addr = inet_addr("127.0.0.1");
            g_decoy_map_n = 1;

            /* Развилка выбирается таблицей пиров: пустая даёт «нет такого пира», а таблица с
             * этим самым ключом и уже виденной меткой времени — «повтор msg1». */
            g_conf.peer_n = forks[f].peers;
            memset(g_last_stamp, 0, sizeof(g_last_stamp));
            if (forks[f].peers) {
                memcpy(g_conf.peer[0].pub, peer_pub, 32);
                g_last_stamp[0] = (uint64_t)1 << 62;   /* заведомо новее присланной */
            }

            memset(&w, 0, sizeof(w));
            w.listen_port = 443; w.rx = -1; w.tx0 = -1; w.base = 0; w.cap = 1;
            xs_sidx_reset(&w.idx);
            memset(s, 0, sizeof(*s));
            s->phase = PH_SYN; s->peer = -1; s->conn_id = -1; s->up_fd = -1;
            s->conn.fd = wire_open(); s->conn.sport = 443; s->conn.dport = 40000;
            s->conn.daddr = htonl(0x0A000001u);
            g_decoy_live = 0;
            wire_drain();

            /* Hello приходит ДВУМЯ сегментами — как в бою. Половина, оставленная в буфере
             * прежним порядком очистки, была бы именно этим вторым сегментом. */
            struct obfs_seg seg;
            memset(&seg, 0, sizeof(seg));
            seg.flags = 0x18;
            seg.sport = 40000;
            seg.saddr = htonl(0x0A000001u);
            seg.payload = hello;
            seg.plen = hn / 2;
            hs_step(&w, s, &seg, 443, 1000);
            check("  на первой половине хаб ещё молчит и ждёт продолжения",
                  (long)PH_SYN, (long)s->phase);
            seg.payload = hello + hn / 2;
            seg.plen = hn - hn / 2;
            hs_step(&w, s, &seg, 443, 1000);

            check("  сессия на дорожке прикрытия", (long)PH_PROXY, (long)s->phase);
            check("  прибору не ушло ни байта отказа", -1, wire_take(NULL, NULL));
            check("  позвонили по имени из SNI, а не в DecoyDest",
                  (long)inet_addr("127.0.0.1"), (long)s->up_addr);

            struct pollfd wait_fd = { srv, POLLIN, 0 };
            poll(&wait_fd, 1, 2000);
            int up = accept(srv, NULL, NULL);
            check("  прикрытие, названное именем, приняло соединение", 1, up >= 0);
            decoy_event(&w, s, POLLOUT, 1010);
            check("  присланное отдано прикрытию целиком", 1, (long)s->up_ready);
            {
                static uint8_t got[4096];
                size_t gn = 0;
                while (up >= 0 && gn < hn) {
                    struct pollfd pf = { up, POLLIN, 0 };
                    if (poll(&pf, 1, 1000) <= 0) break;
                    ssize_t r = recv(up, got + gn, sizeof(got) - gn, 0);
                    if (r <= 0) break;
                    gn += (size_t)r;
                }
                check("  прикрытию ушёл ВЕСЬ Hello, а не последний его сегмент",
                      (long)hn, (long)gn);
                check("  байт в байт", 0, gn == hn ? memcmp(got, hello, hn) : 1);
            }
            if (up >= 0) close(up);
            sess_free(&w, s);
            close(srv);
            g_decoy_map_n = 0;
            g_decoy_live = 0;
        }
        memset(&g_sec, 0, sizeof(g_sec));
        memset(&peer_sec, 0, sizeof(peer_sec));
    }

    /* ---- вытеснение сессий: живую забираем, только если она почти мертва (R-067, I-082) ----
     *
     * Комментарий в sess_alloc обещал, что подтверждённую сессию может забрать только другая
     * подтверждённая, а код при полной таблице отдавал самую давно молчавшую ЖИВУЮ по
     * неаутентифицированному SYN. То есть посторонний с одного хоста, посылая SYN с меняющихся
     * портов, забирал рукопожавшийся туннель — молча, потому что отказа никто не печатал.
     *
     * Проверяется политика, а не сокеты: sess_alloc открывает сырой сокет (нужны права root и
     * настоящая сеть), а решает всё sess_evict_pick — две структуры в памяти. */
    printf("\n== хаб: вытеснение только почти мёртвой сессии ==\n");
    {
        static struct worker w;
        struct sess *live = &g_sess[0], *raw = &g_sess[1];
        const long long NOW = 10000000;

        /* Срок обязан лежать МЕЖДУ двумя уже существующими: за границей, по которой пир сама
         * считает путь мёртвым, и заметно раньше уборки по простою. Иначе правило либо
         * забирает работающий туннель, либо не меняет ничего — место освободилось бы и без
         * него. Это же число стоит в реализации на Go. */
        check("порог — шесть периодов keepalive хаба", 60000, (long)XSH_EVICT_QUIET_MS);
        check("он за границей мёртвого пути (пир уже пересоединяется)", 1,
              XSH_EVICT_QUIET_MS > XSC_DEAD_MS);
        check("и заметно раньше уборки по простою — правило не повторяет её", 1,
              XSH_EVICT_QUIET_MS * 2 < XSH_IDLE_MS);

        /* Приоритет неподтверждённых не тронут: он и есть защита от потока SYN. */
        memset(&w, 0, sizeof(w));
        memset(live, 0, sizeof(*live));
        memset(raw, 0, sizeof(*raw));
        live->phase = PH_EST;  live->conn.last_rx = NOW - 1;
        raw->phase = PH_SYN;   raw->conn.last_rx = NOW - 100;
        check("неподтверждённая уходит первой, даже будучи моложе живой", 1,
              sess_evict_pick(&w, raw, live, NOW) == raw);
        check("отказа при этом не было", 0, (long)w.d_full);

        /* Живая и молодая НЕ ВЫТЕСНЯЕТСЯ: в приёме отказано. */
        memset(&w, 0, sizeof(w));
        live->conn.last_rx = NOW - 1000;
        check("живая и молодая остаётся на месте", 1,
              sess_evict_pick(&w, NULL, live, NOW) == NULL);
        check("отказ сосчитан", 1, (long)w.d_full);
        check("и о нём сказано в журнале — молчаливого отказа быть не должно", 1,
              w.rl_full.last != 0);
        check("вторая такая же строка подавлена своим ограничителем", 1,
              (sess_evict_pick(&w, NULL, live, NOW + 10) == NULL) && w.rl_full.held == 1);
        check("чужие ограничители не тронуты", 0,
              (long)(w.rl_synest.last | w.rl_decoy.last | w.rl_unknown.last));

        /* Ровно на пороге — ещё не вытесняется: сравнение строгое, как и в Go. */
        memset(&w, 0, sizeof(w));
        live->conn.last_rx = NOW - XSH_EVICT_QUIET_MS;
        check("ровно на пороге молчания — ещё не вытесняется", 1,
              sess_evict_pick(&w, NULL, live, NOW) == NULL);

        /* На миллисекунду дольше — уже почти мертва, место отдаётся. */
        memset(&w, 0, sizeof(w));
        live->conn.last_rx = NOW - XSH_EVICT_QUIET_MS - 1;
        check("молчит дольше порога — место отдаётся новому пиру", 1,
              sess_evict_pick(&w, NULL, live, NOW) == live);
        check("это не отказ, и он не сосчитан", 0, (long)w.d_full);

        /* Таблица пуста в смысле кандидатов — отказ без падения. */
        memset(&w, 0, sizeof(w));
        check("кандидатов нет вовсе — отказ, а не разыменование нуля", 1,
              sess_evict_pick(&w, NULL, NULL, NOW) == NULL);
    }

    /* ---- подъём устройства хаба: каждый отказ `ip` назван (I-114) ----------------
     *
     * Симптом всех трёх отказов снаружи один и тот же — «хаб слушает, трафика нет», — и до
     * этой правки ни один из них не оставлял в журнале ни строки: три команды шли через
     * run_quiet, и ни у одной не смотрели код возврата. Регресс не виден ни в одной другой
     * проверке: процесс работает, рукопожатия идут, ошибок нет.
     *
     * Ни сети, ни прав здесь не нужно: hub_dev_up только считает строки и зовёт run_quiet,
     * который на стенде записывает команды вместо их запуска. Имя устройства НЕ содержит
     * подстроки "up" — ею стенд отличает `ip link set ... up` от остальных команд. */
    printf("\n== хаб: подъём устройства называет свои отказы ==\n");
    {
        memset(&g_conf, 0, sizeof(g_conf));
        g_conf.addr = (10u << 24) | (77u << 16) | 1u;   /* 10.77.0.1 */
        g_conf.addr_plen = 24;
        g_conf.mtu = 1380;
        g_conf.peer_n = 2;
        g_conf.peer[0].allowed_n = 2;
        g_conf.peer[0].allowed[0].net = (10u << 24) | (77u << 16) | (2u << 8); /* 10.77.2.0/24 */
        g_conf.peer[0].allowed[0].plen = 24;
        g_conf.peer[0].allowed[1].net = 0;              /* 0.0.0.0/0 — не наш маршрут */
        g_conf.peer[0].allowed[1].plen = 0;
        g_conf.peer[1].allowed_n = 1;
        g_conf.peer[1].allowed[0].net = (192u << 24) | (168u << 16) | (9u << 8);
        g_conf.peer[1].allowed[0].plen = 24;
        const char *DEV = "xshub-tst0";

        /* Успешный подъём: порядок команд тот же, что был, и журнал молчит. Вторая половина
         * этой проверки — страховка от перестарания: предупреждение на исправном подъёме
         * учило бы не смотреть в журнал. */
        g_cmd_n = 0; g_fail_on = "";
        log_begin();
        hub_dev_up(DEV);
        const char *log = log_end();
        check("команд четыре: адрес, mtu+up и два маршрута к сетям пиров", 4, g_cmd_n);
        check("адрес хаба ставится из конфигурации", 1,
              cmd_seen("ip addr replace 10.77.0.1/24 dev xshub-tst0"));
        check("MTU и подъём — одной командой", 1,
              cmd_seen("ip link set dev xshub-tst0 mtu 1380 up"));
        check("маршрут к сети первого пира", 1,
              cmd_seen("ip route replace 10.77.2.0/24 dev xshub-tst0"));
        check("маршрут к сети второго пира", 1,
              cmd_seen("ip route replace 192.168.9.0/24 dev xshub-tst0"));
        check("0.0.0.0/0 маршрутом не заводится", 0, cmd_seen("route replace 0.0.0.0/0"));
        check("на успешном подъёме журнал молчит", 0, log_lines_with(log, "steer["));

        g_cmd_n = 0; g_fail_on = "addr replace";
        log_begin();
        hub_dev_up(DEV);
        log = log_end();
        check("отказ адреса назван предупреждением", 1, log_lines_with(log, "steer[warn]") > 0);
        check("и в нём сам адрес — видно, что именно не встало", 1,
              strstr(log, "10.77.0.1/24") != NULL);
        check("остальные команды всё равно отданы", 4, g_cmd_n);

        g_cmd_n = 0; g_fail_on = " up";
        log_begin();
        hub_dev_up(DEV);
        log = log_end();
        check("отказ подъёма назван предупреждением", 1, log_lines_with(log, "steer[warn]") > 0);
        check("названы обе настройки той команды — MTU тоже", 1,
              strstr(log, "1380") != NULL);

        /* Главный из трёх: отказ маршрута к сети пира — это работа В ОДНУ СТОРОНУ, и в
         * строке обязана стоять СЕТЬ. Пиров бывает тридцать две; «маршрут не встал» без
         * адреса не говорит, у кого именно связь окажется односторонней. */
        g_cmd_n = 0; g_fail_on = "route replace 192.168.9.0/24";
        log_begin();
        hub_dev_up(DEV);
        log = log_end();
        check("отказ маршрута к сети пира назван", 1, log_lines_with(log, "steer[warn]") > 0);
        check("и названа именно та сеть, что не встала", 1,
              strstr(log, "192.168.9.0/24") != NULL);
        check("а сеть, маршрут к которой встал, в журнале не поминается", 0,
              strstr(log, "10.77.2.0/24") != NULL);
        check("ровно одна строка — по одному отказу, не по всем пирам", 1,
              log_lines_with(log, "steer[warn]"));
    }

    printf(fails ? "\nПРОВАЛОВ: %d\n" : "\nвсе проверки прошли\n", fails);
    return fails ? 1 : 0;
}
