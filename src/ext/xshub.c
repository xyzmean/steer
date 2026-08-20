/* xsteer: хаб полной звезды. Живёт на VPS, спека ему не нужна.
 *
 * ЧТО ОН ДЕЛАЕТ. Слушает один порт поддельного TCP, держит по сессии на пир и разводит
 * трафик между ними по AllowedIPs. Пир видит пир ЧЕРЕЗ хаб: пакет расшифровывается,
 * проверяется на право отправлять с этого адреса, и, если адресат — другая пир,
 * зашифровывается для неё В ТОЙ ЖЕ СТРОКЕ БУФЕРА и уходит. Ни ip_forward, ни NAT, ни поиска
 * маршрута в ядре, ни единой копии.
 *
 * ПОЧЕМУ TUN ВСЁ РАВНО ЕСТЬ. Он нужен не для трафика между пирами, а для выхода в интернет:
 * AllowedIPs со 0.0.0.0/0 означает, что пакет должен покинуть хаб наружу, а это уже ядро,
 * masquerade оператора и его же правила — ровно модель wireguard. Цена называется вслух:
 * без net.ipv4.ip_forward=1 выход в интернет не работает, и правило masquerade оператор
 * ставит сам.
 *
 * ЧТО ЭТО ЗНАЧИТ ДЛЯ FIREWALL. Трафик пир↔пир через firewall хаба НЕ ПРОХОДИТ: он
 * разворачивается в пользовательском пространстве. Это плата за отсутствие копий, и её надо
 * знать заранее, а не обнаружить, пытаясь отфильтровать такой трафик правилами.
 *
 * МНОГОПОТОЧНОСТЬ: ПО СОЕДИНЕНИЯМ, А НЕ ПО ПАКЕТАМ. Одно ядро хаба несёт около 0,6 Гбит/с
 * (замерено tests/run-xsteer.sh: и хаб, и пир съедали ровно по ядру), и на пяти пирах это
 * потолок ВСЕЙ звезды, а не одной. Поэтому воркеров столько, сколько ядер: каждый со своим
 * сырым сокетом, своей очередью TUN, своим индексом сессий и своим отрезком таблицы.
 *
 * Раскладку делает ЯДРО, а не мы: фильтр cBPF на сокете каждого воркера пропускает только
 * сегменты, у которых младшие биты порта источника равны его номеру (obfs_filter_port_shard).
 * Отсюда главное: поддельное соединение TCP принадлежит РОВНО ОДНОМУ воркеру навсегда, и
 * окно приёма, ключи расшифровки и счётчик nonce — его личная собственность без замков.
 *
 * Замок нужен ровно в одном месте — на ОТПРАВКУ в сессию. Причина: пакет пир→пир
 * приходит одному воркеру, а уходит в сессию, которой владеет другой; так же и пакет из TUN,
 * потому что очередь TUN ядро выбирает по хэшу потока, а не по нашей раскладке. Отправка
 * двигает номер последовательности и счётчик nonce, а повтор nonce — это полная потеря AEAD,
 * поэтому здесь замок обязателен. Он берётся на пакет, не на поток, и на непротиворечивом
 * пути стоит десятки наносекунд против ~17 микросекунд полного прохода пакета.
 *
 * ПОИСК: РАЗНЫЙ ПО ЧАСТОТЕ ВЫЗОВА. Пир по статическому ключу — линейный обход (раз на
 * рукопожатие). Сессия по четвёрке — хеш-индекс (на каждый пакет). Пир по адресу — линейный
 * обход с кэшем на одну запись. Обоснование каждого — в xsroute.h.
 */
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <pthread.h>

#include "xsconn.h"
#include "xsconf.h"
#include "xshake.h"
#include "xsroute.h"
#include "tun.h"
#include "reality.h"

#define LOG_W "steer[warn] hub: "
#define LOG_I "steer[info] hub: "

#define XSH_BATCH 16
/* Сессий вчетверо больше, чем пиров: запас на переподключение пира без разрыва И на
 * неравномерность раскладки по воркерам (порты хэшируются, и одному воркеру может достаться
 * вдвое больше пиров, чем в среднем). */
#define XSH_MAX_SESS (XS_PEERS_MAX * 4)
/* Предел числа воркеров — ЧЕТЫРЕ, и это не «на всякий случай», а результат замера.
 *
 * Цена воркера лежит в ядре: приём идёт сырым сокетом, и ядро на каждый локально доставляемый
 * TCP-пакет КЛОНИРУЕТ skb для КАЖДОГО такого сокета, а фильтр отбрасывает лишние уже потом.
 * То есть при восьми воркерах каждый наш же туннельный пакет клонируется восемь раз, семь
 * клонов выбрасывается, и эта работа растёт линейно, тогда как выигрыш от ядер насыщается.
 * Замер (tests/run-xsteer.sh, два пира, сумма): 1 воркер — 0,67 Гбит/с, 2 — 1,20, 4 — 1,11,
 * 8 — 0,97.
 *
 * ЧТО НУЖНО, ЧТОБЫ РАСТИ ДАЛЬШЕ. Убрать умножение клонов, а для этого — приём не сырым
 * сокетом, а AF_PACKET с PACKET_FANOUT: там ядро отдаёт пакет РОВНО ОДНОМУ сокету группы,
 * выбирая его хэшем потока, то есть сессия по-прежнему принадлежит одному воркеру, но клон
 * один. Это отдельная работа: у AF_PACKET другой приёмный путь (нужно отсекать исходящие
 * пакеты по PKTTYPE и учитывать, что он видит трафик до firewall). */
#define XSH_WORKERS_MAX 4
#define XSH_IDLE_MS  180000
/* Хаб присылает пустую запись, если получал данные, но сам давно ничего не отправлял.
 *
 * Обязательно, а не «полезно»: пир считает путь мёртвым по тишине при активной отправке, и
 * без этого односторонний трафик (она отправляет, отвечать нечем) выглядел бы для неё
 * обрывом. Ровно это и показал живой стенд. Так же устроен WireGuard: keepalive посылает
 * ПРИНИМАЮЩАЯ сторона, и по той же причине. Десять секунд — его же интервал. */
#define XSH_KEEPALIVE_MS 10000
/* Обратная связь по сборке разрезанных записей — те же числа, что у пира, и по тем же причинам. */
#define XSH_REASM_COOL_MS   10000
#define XSH_REASM_REPORT_MS 2000
#define XSH_REASM_GROW_MS   3000

int run_quiet(const char *const argv[]);

enum sess_phase { PH_FREE, PH_SYN, PH_HS, PH_EST };

struct sess {
    struct xs_conn conn;
    struct xs_hs hs;
    struct tls13_keys tx, rx;
    struct xs_win win;
    int      phase;
    /* Накопленные байты ClientHello: он приходит НЕСКОЛЬКИМИ сегментами, потому что браузерный
     * Hello больше сегмента (около 1760 байт из-за постквантового ключа), и наш такой же. Предел
     * обязателен: сюда пишет кто угодно из интернета, и «копим, пока не разберётся» без предела —
     * это способ съесть память хаба чужими байтами. */
    uint8_t  hs_buf[4096];
    size_t   hs_len;
    /* Сборка разрезанных записей и обратная связь по ней (см. xswire.h). */
    struct xs_reasm reasm;
    unsigned long long last_drops;
    int      batch_max;
    long long cool_until, last_report, last_grow, keep_next;
    int16_t  peer;                 /* индекс пира или -1, пока не опознан */
    int8_t   conn_id;              /* номер соединения этой пира (0..XS_CONNS_MAX-1) */
    /* MTU, о котором договорились с этой пиром. Ноль — ещё не договорились. Хранится на
     * СЕССИЮ, а не на хаб: у разных пиров разные пути, и общее значение означало бы, что
     * худший путь ограничивает всех. */
    int      mtu;
    long long handshake_at;
    unsigned long long up_pkts, down_pkts;
};

static struct sess g_sess[XSH_MAX_SESS];
static struct xs_router g_router;
static struct xs_conf g_conf;
static struct xs_secrets g_sec;
/* Имя устройства TUN. Умолчание xshub0, но конфигурация может задать своё через Device —
 * тогда на одной машине уживаются два хаба, не столкнувшись за имя устройства. Разрешается
 * один раз при старте (cmd_xsteer_hub) и дальше только читается. */
static char g_dev[32] = "xshub0";
/* Последняя метка времени от каждого пира: защита от воспроизведения записанного msg1.
 * Держится в памяти, а не на диске: перезапуск хаба и так требует нового рукопожатия. */
static uint64_t g_last_stamp[XS_PEERS_MAX];
/* Сессии пира: по одной на каждое его соединение (пир открывает по соединению на воркер).
 * Номер соединения пир называет в аутентификаторе рукопожатия, поэтому место в наборе
 * определено ею, а не порядком прихода — переподключение одного соединения не задевает
 * остальные. -1 означает «этого соединения нет». */
static int16_t g_peer_sess[XS_PEERS_MAX][XS_CONNS_MAX];

/* Замок на ОТПРАВКУ в сессию. Держится ОТДЕЛЬНО от struct sess, а не полем в ней, и это не
 * вкус: sess_free обнуляет структуру целиком (memset), а обнулить мьютекс, который в этот миг
 * кто-то держит, — это порча замка, то есть зависание или порча памяти под нагрузкой, ловимая
 * только в бою. Отдельный массив живёт всё время работы процесса и не обнуляется никогда. */
static pthread_mutex_t g_tx_lock[XSH_MAX_SESS];
/* Один замок на всё, что делается РАЗ НА РУКОПОЖАТИЕ: таблица пиров, метки времени, привязка
 * пир→сессия, пересчёт MTU устройства. Частота этих действий — доли раза в секунду на всю
 * звезду, поэтому дробить их на отдельные замки значило бы усложнять без выигрыша. На горячем
 * пути этот замок не берётся ни разу. */
static pthread_mutex_t g_ctl = PTHREAD_MUTEX_INITIALIZER;

/* Воркер: всё, что принадлежит одному потоку. Ни одного общего изменяемого поля здесь нет —
 * именно поэтому приём не требует замков. */
struct worker {
    int id, n;                       /* номер и общее число воркеров */
    uint16_t mask;                   /* n-1: младшие биты порта источника */
    int rx;                          /* свой сырой сокет с фильтром-раскладкой */
    int tx0;                         /* сокет для RST тем, чьей сессии нет */
    struct tun_dev tun;              /* своя очередь TUN */
    struct xs_sidx idx;              /* свой индекс сессий: чужих он не увидит по построению */
    int base, cap;                   /* свой отрезок g_sess */
    int listen_port;
    int debug;
    uint8_t rx_buf[XSH_BATCH][XS_ROW];
    struct mmsghdr mm[XSH_BATCH];
    struct iovec iov[XSH_BATCH];
    /* Строка под ОДНУ запись целиком: с пачкой она больше сегмента по построению. Нагрузка лежит
     * по XS_HDR_ROOM — там же, где оказывается расшифрованный пакет, поэтому пересылка пир↔пир
     * обходится без копий, — значит место впереди мерится XS_HDR_ROOM, а не одним заголовком
     * (I-070: было 20 + XS_REC_HDR, то есть на 20 байт меньше нужного). Согласие с правилом
     * набора кадров проверяется ниже при компиляции. */
    uint8_t row[XS_HDR_ROOM + XS_MAX_RECORD + XS_TAG];
    /* Заголовки сегментов и векторы для sendmmsg: сегмент собирается из двух кусков — своего
     * заголовка и части записи, — поэтому нагрузка не копируется вовсе. */
    uint8_t hdrs[XS_BATCH_FRAMES_MAX + 8][20];
    struct iovec siov[2 * (XS_BATCH_FRAMES_MAX + 8)];
    struct mmsghdr smm[XS_BATCH_FRAMES_MAX + 8];
    /* Отдельный буфер под ответ рукопожатия. Строка пакета для него мала: ответ — это
     * ServerHello, фальшивый ChangeCipherSpec, запись формы «сертификат» со случайной набивкой
     * и подтверждение, то есть до ~1300 байт, и он обязан влезть в ОДИН сегмент (см. xshake.c).
     * Первая версия передавала сюда строку пакета и получала отказ XS_ESMALL — «ответ на
     * рукопожатие не ушёл», без указания, что не так с размером. */
    uint8_t hs[2048];
    /* Ограничители на строки, которые вызывает чужой пакет: до них добирается кто угодно из
     * интернета, и без ограничителя одна такая строка — способ залить журнал VPS. Свои у
     * каждого воркера: общие потребовали бы замка на пути, который и так под потоком. */
    struct xs_ratelog rl_unknown, rl_stamp, rl_synest;
    unsigned long long d_seg, d_bad, d_syn, d_hs, d_data, d_alien, d_syn_est;
};

/* Строка ОБЯЗАНА вмещать самую большую запись, какую собирает цикл TUN, вместе с местом под
 * заголовки впереди и тегом позади: нагрузка лежит по row + XS_HDR_ROOM, а тег — сразу за ней.
 * Предел записи задаёт ПРАВИЛО САМОГО ЦИКЛА (см. набор кадров в worker_loop): он читает
 * следующий кадр, пока off + 2 + XS_MTU_DEF + XS_TAG <= XS_MAX_RECORD, и дочитанный кадр доводит
 * нагрузку ровно до XS_MAX_RECORD - XS_TAG. Два числа обязаны спорить при компиляции, а не в бою:
 * здесь они разошлись на 20 байт (I-070) — строка была посчитана с местом под ОДИН заголовок
 * вместо трёх, — и обнаружилось это чтением, потому что заметить четыре байта, ушедшие за
 * границу поля внутри структуры, не может ни компилятор, ни AddressSanitizer. */
#define XSH_PN_MAX (XS_MAX_RECORD - XS_TAG)
XS_STATIC_ASSERT(sizeof(((struct worker *)0)->row) >= XS_HDR_ROOM + XSH_PN_MAX + XS_TAG,
                 hub_row_fits_batch);

static struct worker g_w[XSH_WORKERS_MAX];
static int g_workers = 1;
/* Аварийный выключатель нового формата: см. пояснение у batch_max в hs_confirm. Читается один раз
 * при старте, а не на каждом пакете. */
static int g_compat;

static struct sess *sess_find(struct worker *w, uint32_t addr, uint16_t port) {
    int i = xs_sidx_find(&w->idx, addr, port);
    return i < 0 ? NULL : &g_sess[i];
}

static void sess_free(struct worker *w, struct sess *s) {
    if (s->phase == PH_FREE) return;
    uint32_t addr = ntohl(s->conn.daddr);
    /* Замок берётся ДО обнуления: в этот самый миг другой воркер может быть внутри отправки в
     * эту сессию (пир↔пир или пакет из TUN), и обнулить ключи у него под руками значило бы
     * шифровать мусором или упасть. Проверку «сессия ещё жива» отправка делает уже под этим же
     * замком, поэтому после освобождения она просто ничего не отправит. */
    pthread_mutex_lock(&g_tx_lock[s - g_sess]);
    xs_sidx_remove(&w->idx, addr, s->conn.dport);
    if (s->peer >= 0) {
        pthread_mutex_lock(&g_ctl);
        for (int c = 0; c < XS_CONNS_MAX; c++)
            if (g_peer_sess[s->peer][c] == (int16_t)(s - g_sess)) g_peer_sess[s->peer][c] = -1;
        pthread_mutex_unlock(&g_ctl);
    }
    tls13_keys_free(&s->tx);
    tls13_keys_free(&s->rx);
    xs_hs_wipe(&s->hs);
    xs_conn_close(&s->conn);
    memset(s, 0, sizeof(*s));
    s->peer = -1;
    s->conn_id = -1;
    s->conn.fd = -1;
    pthread_mutex_unlock(&g_tx_lock[s - g_sess]);
}

static struct sess *sess_alloc(struct worker *w, const struct obfs_seg *seg, int listen_port) {
    struct sess *free_slot = NULL, *oldest = NULL, *oldest_raw = NULL;
    /* Только СВОЙ отрезок таблицы: сессия, созданная здесь, будет и приниматься здесь —
     * фильтр на сокете это гарантирует, — а лазить в чужой отрезок значило бы делить таблицу
     * между потоками и брать замок на каждый пакет. */
    for (int i = w->base; i < w->base + w->cap; i++) {
        if (g_sess[i].phase == PH_FREE) { free_slot = &g_sess[i]; break; }
        if (!oldest || g_sess[i].conn.last_rx < oldest->conn.last_rx) oldest = &g_sess[i];
        /* Отдельно — самая давняя из НЕ дошедших до подтверждения. */
        if (g_sess[i].phase != PH_EST &&
            (!oldest_raw || g_sess[i].conn.last_rx < oldest_raw->conn.last_rx))
            oldest_raw = &g_sess[i];
    }
    /* Свободного нет — вытесняем. Отказать вместо вытеснения значило бы, что одна забытая
     * сессия навсегда закрывает вход новой пиру.
     *
     * НО: неподтверждённая вытесняется ПЕРВОЙ, и это не тонкость. Сессия создаётся на первом
     * же поддельном SYN, то есть кем угодно и без всякой проверки; вытесняй мы просто «самую
     * давно молчавшую», поток SYN с меняющихся портов выбил бы из таблицы живые
     * рукопожавшиеся туннели — отказ в обслуживании ценой в один цикл на постороннем хосте.
     * Подтверждённую сессию у нас может забрать только другая подтверждённая. */
    if (!free_slot) {
        struct sess *victim = oldest_raw ? oldest_raw : oldest;
        if (!victim) return NULL;
        sess_free(w, victim);
        free_slot = victim;
    }
    struct sess *s = free_slot;
    memset(s, 0, sizeof(*s));
    s->peer = -1;
    s->conn_id = -1;
    /* Свой сырой сокет на сессию, подключённый к её адресу: тогда ядро само демультиплексирует
     * отправку, и адрес не приходится указывать на каждый пакет. Тот же приём, что в obfs.c. */
    s->conn.fd = obfs_raw_open(seg->saddr, &s->conn.saddr);
    if (s->conn.fd < 0) { s->phase = PH_FREE; return NULL; }
    obfs_filter_none(s->conn.fd);       /* принимать этому сокету нечего */
    s->conn.daddr = seg->saddr;
    s->conn.sport = (uint16_t)listen_port;
    s->conn.dport = seg->sport;
    s->conn.isn_tx = seg->ack ? seg->ack : (uint32_t)xs_now_ms();
    s->conn.seq = s->conn.isn_tx;
    s->conn.isn_rx = seg->seq;
    s->conn.ack = seg->seq + 1;
    s->conn.born = s->conn.last_rx = s->conn.last_tx = xs_now_ms();
    s->conn.state = XSC_SYN_RCVD;
    s->phase = PH_SYN;
    if (xs_sidx_insert(&w->idx, ntohl(seg->saddr), seg->sport, (int)(s - g_sess)) != 0) {
        sess_free(w, s);
        return NULL;
    }
    return s;
}

/* Вызывается редко (раз на пробой пира) и из ЛЮБОГО воркера, поэтому целиком под общим
 * замком: он же защищает `applied`, иначе два воркера могли бы одновременно решить, что
 * значение сменилось, и дважды дёрнуть `ip link`. */
static void hub_retune_mtu(void) {
    pthread_mutex_lock(&g_ctl);
    int best = 0;
    for (int i = 0; i < XSH_MAX_SESS; i++)
        if (g_sess[i].phase == PH_EST && g_sess[i].mtu > 0)
            if (!best || g_sess[i].mtu < best) best = g_sess[i].mtu;
    static int applied;
    if (!best || applied == best) { pthread_mutex_unlock(&g_ctl); return; }
    char val[8];
    snprintf(val, sizeof(val), "%d", best);
    const char *a[] = { "ip", "link", "set", "dev", g_dev, "mtu", val, NULL };
    if (run_quiet(a) == 0) {
        fprintf(stderr, LOG_I "MTU устройства: %d (минимум среди пиров)\n", best);
        applied = best;
    }
    pthread_mutex_unlock(&g_ctl);
}

/* Зашифровать пакет для сессии и отправить. Открытый текст лежит по row + XS_HDR_ROOM —
 * ровно там, где он оказался после расшифровки входящего, поэтому пересылка пир↔пир
 * обходится без единой копии.
 *
 * ПОД ЗАМКОМ ЦЕЛИКОМ, и это несущая конструкция, а не осторожность. Отправлять в одну сессию
 * может любой воркер: пакет пир↔пир пришёл одному, а уходит в сессию другого; пакет из TUN
 * попал в ту очередь, которую выбрало ядро по хэшу потока. Отправка выдаёт следующий
 * относительный номер — он же nonce AEAD, — и два потока, взявшие один номер, повторили бы
 * nonce. Повтор nonce означает не «пакет потерялся», а полную потерю стойкости шифра на этой
 * сессии, причём молча. Поэтому номер, шифрование и сама отправка — одна неделимая операция.
 *
 * Проверка phase == PH_EST стоит ПОСЛЕ взятия замка: пока мы ждали, владелец мог освободить
 * сессию (sess_free берёт тот же замок), и тогда отправлять уже некуда. */
static int send_to(struct worker *w, struct sess *d, uint8_t *row, size_t plen, long long now) {
    pthread_mutex_t *lk = &g_tx_lock[d - g_sess];
    pthread_mutex_lock(lk);
    if (d->phase != PH_EST) { pthread_mutex_unlock(lk); return -1; }
    uint32_t rel = xs_conn_rel_next(&d->conn);
    if (xs_retire_due(rel, now - d->conn.born)) { pthread_mutex_unlock(lk); return -1; }
    uint8_t *rec = row + XS_HDR_ROOM - XS_REC_HDR;
    int rc = -1;
    if (xs_rec_build(rec, plen + XS_TAG) == 0 &&
        tls13_aead_seal(&d->tx, rel, rec, XS_REC_HDR, row + XS_HDR_ROOM, plen,
                        row + XS_HDR_ROOM + plen) == 0) {
        /* Запись режется на сегменты по MTU ЭТОЙ сессии: у пиров он свой у каждого, и превышать
         * согласованный пробами размер нельзя. Пачка больше сегмента по построению, поэтому путь
         * через xs_conn_split_mm теперь общий и для одиночных записей — при одном сегменте он
         * ровно эквивалентен прежнему xs_conn_ahead. */
        int mtu = d->mtu > 0 ? d->mtu : XS_MTU_DEF;
        size_t max_seg = (size_t)mtu + XS_OVERHEAD - 40;
        int segs = xs_conn_split_mm(&d->conn, rec, XS_REC_HDR + plen + XS_TAG, max_seg,
                                    w->hdrs, w->siov, w->smm,
                                    sizeof(w->hdrs) / sizeof(w->hdrs[0]), now);
        if (segs > 0) {
            int off = 0, stuck = 0;
            while (off < segs) {
                int sent = sendmmsg(d->conn.fd, &w->smm[off], (unsigned)(segs - off), 0);
                if (sent > 0) { off += sent; stuck = 0; continue; }
                if (++stuck >= 3) break;
                if (errno != EAGAIN && errno != ENOBUFS && errno != EINTR) break;
            }
            if (off == segs) {
                d->down_pkts++;
                rc = 0;
            }
        }
    }
    pthread_mutex_unlock(lk);
    return rc;
}

/* Обслуживание сессии (подтверждения, keepalive) — тоже под замком отправки: xs_conn_tick сам
 * отправляет голые подтверждения, а они двигают тот же номер последовательности. */
static void sess_tick_locked(struct sess *s, long long now) {
    pthread_mutex_t *lk = &g_tx_lock[s - g_sess];
    pthread_mutex_lock(lk);
    xs_conn_tick(&s->conn, now, 0);
    pthread_mutex_unlock(lk);
}

/* Разобрать рукопожатие пира и ответить. */
static void hs_step(struct worker *w, struct sess *s, const struct obfs_seg *seg,
                    int listen_port, long long now) {
    (void)listen_port;
    uint8_t peer_static[32];
    /* СОБИРАЕМ HELLO ИЗ СЕГМЕНТОВ. Браузерный ClientHello больше одного сегмента (около 1760 байт
     * из-за постквантового ключа), и наш такой же — иначе размер Hello сам по себе признак.
     * Значит первый сегмент почти всегда неполон, и разбирать его сразу нельзя. */
    if (s->hs_len + seg->plen > sizeof(s->hs_buf)) {
        uint8_t alert[16];
        size_t an = xs_hs_alert(alert, sizeof(alert));
        if (an) xs_conn_send(&s->conn, 0x18, alert, an, 0);
        sess_free(w, s);
        return;
    }
    memcpy(s->hs_buf + s->hs_len, seg->payload, seg->plen);
    s->hs_len += seg->plen;
    /* НЕ ПОХОЖЕ НА РУКОПОЖАТИЕ TLS ВООБЩЕ — отвечаем сразу, не дожидаясь продолжения.
     *
     * Это про зондирование, а не про аккуратность: прибор первым делом присылает не только
     * настоящий ClientHello, но и «GET / HTTP/1.1», и просто мусор. Копить такие байты до предела
     * значит молчать в ответ на запрос HTTP — чего настоящий сервер не делает никогда, и что
     * отличимо не хуже молчания на Hello. */
    if (s->hs_len >= 2 && (s->hs_buf[0] != 0x16 || s->hs_buf[1] != 0x03)) {
        uint8_t alert[16];
        size_t an = xs_hs_alert(alert, sizeof(alert));
        if (an) xs_conn_send(&s->conn, 0x18, alert, an, 0);
        sess_free(w, s);
        return;
    }
    if (s->hs_len < 5) return;
    {
        size_t want = 5 + ((size_t)s->hs_buf[3] << 8) + s->hs_buf[4];
        if (s->hs_len < want) return;
    }
    int rc = xs_hs_server_read(&s->hs, &g_sec, s->hs_buf, s->hs_len, peer_static);
    s->hs_len = 0;
    if (rc != 0) {
        /* Отказ имеет форму настоящего фатального оповещения TLS. Молчание было бы отличимо
         * ещё сильнее — но от целенаправленного зондирования это всё равно не спасает, о чём
         * сказано в docs/xsteer.md прямо. */
        uint8_t alert[16];
        size_t an = xs_hs_alert(alert, sizeof(alert));
        if (an) xs_conn_send(&s->conn, 0x18, alert, an, 0);
        sess_free(w, s);
        return;
    }
    /* Личность известна — ищем пира. Линейный обход: раз на рукопожатие. */
    int found = -1;
    for (size_t i = 0; i < g_conf.peer_n; i++)
        if (memcmp(g_conf.peer[i].pub, peer_static, 32) == 0) { found = (int)i; break; }
    if (found < 0) {
        /* Сюда попадает ЛЮБОЙ, кто сделал себе пару ключей: статический ключ инициатора
         * подтверждается общим секретом с нашим, а он считается из нашего ОТКРЫТОГО ключа.
         * То есть частоту этой строки выбирает посторонний — отсюда ограничитель. */
        unsigned long long held = 0;
        if (xs_ratelog(&w->rl_unknown, now, XS_LOG_EVERY_MS, &held)) {
            char fp[12], tail[64];
            xs_key_fp(peer_static, fp);
            fprintf(stderr, LOG_W "пир %s не описан в конфигурации — отказ%s\n",
                    fp, xs_held_str(held, tail, sizeof(tail)));
        }
        sess_free(w, s);
        return;
    }
    /* Воспроизведение записанного msg1: метка времени обязана быть новее прошлой от этого
     * пира. Само по себе это не даёт атакующему сессию (подтверждение он не подделает), но
     * даёт хабу три зря потраченных X25519 на каждый повтор.
     *
     * Метки времени общие для всех воркеров: один и тот же пир приходит с разных портов, то
     * есть к разным воркерам, и защита от повтора обязана быть общей. Читаем под замком и
     * решаем уже без него — иначе освобождение сессии происходило бы с занятым замком. */
    pthread_mutex_lock(&g_ctl);
    uint64_t seen_stamp = g_last_stamp[found];
    pthread_mutex_unlock(&g_ctl);
    if (s->hs.peer.stamp && s->hs.peer.stamp < seen_stamp) {
        unsigned long long held = 0;
        if (xs_ratelog(&w->rl_stamp, now, XS_LOG_EVERY_MS, &held)) {
            char tail[64];
            fprintf(stderr, LOG_W "пир %zu: метка времени старее прошлой — похоже на повтор%s\n",
                    (size_t)found + 1, xs_held_str(held, tail, sizeof(tail)));
        }
        sess_free(w, s);
        return;
    }
    s->peer = (int16_t)found;

    size_t on = 0;
    /* Хаб называет свой предел так же, как пир: MTU настоящего канала минус накладные, но
     * не больше заданного в конфигурации. Из этих двух чисел стороны берут минимум. */
    int own_limit = XS_MTU_DEF;
    {
        char ifn[32] = "";
        int link = xs_egress_mtu(s->conn.saddr, ifn, sizeof(ifn));
        if (link > 0) own_limit = xs_mtu(link);
    }
    if (g_conf.mtu && g_conf.mtu < own_limit) own_limit = g_conf.mtu;
    rc = xs_hs_server_write(&s->hs, own_limit, w->hs, sizeof(w->hs), &on, &s->tx, &s->rx);
    if (rc != 0 || xs_conn_send(&s->conn, 0x18, w->hs, on, 0) != 0) {
        fprintf(stderr, LOG_W "ответ на рукопожатие не ушёл: %d\n", rc);
        sess_free(w, s);
        return;
    }
    s->phase = PH_HS;
    s->conn.last_rx = now;
}

/* Подтверждение пира: после него сессия несёт данные. */
static void hs_confirm(struct worker *w, struct sess *s, const struct obfs_seg *seg,
                       long long now) {
    size_t used = 0;
    if (xs_hs_server_confirm(&s->hs, &s->rx, seg->payload, seg->plen, &used) != 0) {
        fprintf(stderr, LOG_W "подтверждение пира не сошлось\n");
        sess_free(w, s);
        return;
    }
    int peer_mtu = s->hs.peer.mtu;
    /* Метку времени снимаем ДО очистки состояния рукопожатия: xs_hs_wipe затирает его целиком,
     * и первая версия этой правки читала уже занулённое поле — защита от повтора превратилась
     * бы в «последняя метка всегда ноль», то есть в её отсутствие. */
    uint64_t peer_stamp = s->hs.peer.stamp;
    /* Номер соединения пира: он лежит в подписанной части рукопожатия, поэтому ему можно
     * верить. Маска обязательна — иначе значение из будущей версии протокола вышло бы за
     * пределы массива. */
    int conn_id = s->hs.peer.flags & 0x07;
    if (conn_id >= XS_CONNS_MAX) conn_id = 0;
    s->conn_id = (int8_t)conn_id;
    xs_hs_wipe(&s->hs);
    xs_win_reset(&s->win);
    xs_reasm_reset(&s->reasm);
    /* Пачка начинается с двух кадров и растёт по чистой обратной связи: начинать с восьми значило
     * бы платить на рваном пути с первой же секунды.
     *
     * STEER_XS_COMPAT=1 оставляет один кадр навсегда: это аварийный выключатель нового формата на
     * время обновления, когда к хабу ещё приходят пиры предыдущей версии. Сборку Hello из
     * сегментов выключать не нужно — короткий Hello старого пира она разбирает сразу. */
    s->batch_max = g_compat ? 1 : 2;
    s->cool_until = 0;
    s->last_drops = s->reasm.dropped;
    s->phase = PH_EST;
    s->handshake_at = now;
    /* Одна сессия на пира: новая заменяет прежнюю. Это и есть переподключение пира — он
     * приходит с НОВОГО ПОРТА, а значит, возможно, и к другому воркеру.
     *
     * Прежнюю сессию мы здесь НЕ освобождаем, хотя раньше освобождали. Причина в раскладке:
     * старая сессия может принадлежать другому воркеру, и её запись лежит в ЕГО индексе —
     * вычистить её отсюда значило бы либо трогать чужую таблицу под замком на горячем пути,
     * либо оставить в чужом индексе ссылку на переиспользованную ячейку, то есть отдавать
     * чужие пакеты не той сессии. Вместо этого прежняя сессия остаётся «смещённой» и её
     * убирает СВОЙ владелец в своём же обслуживании (см. цикл обслуживания ниже): признак —
     * привязка пир→сессия указывает не на неё. Трафика она не несёт с этой секунды, потому
     * что пир в неё больше не отправляет. */
    pthread_mutex_lock(&g_ctl);
    g_last_stamp[s->peer] = peer_stamp;
    g_peer_sess[s->peer][conn_id] = (int16_t)(s - g_sess);
    pthread_mutex_unlock(&g_ctl);
    char fp[12];
    xs_key_fp(g_conf.peer[s->peer].pub, fp);
    struct in_addr in;
    in.s_addr = s->conn.daddr;
    fprintf(stderr, LOG_I "пир %s поднялся с %s:%u, MTU %d, шифр %s\n", fp,
            inet_ntoa(in), s->conn.dport, peer_mtu,
            s->tx.aead == TLS13_AEAD_AES128 ? "AES-128-GCM" : "ChaCha20-Poly1305");
    if (peer_mtu && g_conf.mtu && peer_mtu != g_conf.mtu)
        fprintf(stderr, LOG_W "пир %s: MTU %d против нашего %d — большие пакеты будут "
                              "пропадать\n", fp, peer_mtu, g_conf.mtu);
}

/* Выбрать соединение пира для этого пакета. Соединений у пира может быть несколько (по одному
 * на её воркер), и выбор ОБЯЗАН быть постоянным для потока: раскидай мы пакеты одного
 * соединения TCP по разным путям — получатель увидит переставленные пакеты, а это для него
 * неотличимо от потерь и рушит скорость сильнее, чем помогает второе ядро.
 *
 * Хеш берётся от внутренних адресов и портов, слот — по кругу от него до первого живого.
 * Изменение числа живых соединений переставит потоки один раз, и это допустимо: событие
 * редкое (переподключение), а альтернатива — таблица закреплений, которую надо чистить. */
static int16_t peer_pick(int peer, const uint8_t *pt, size_t pn) {
    if (peer < 0) return -1;
    uint32_t h = xs_flow_hash(pt, pn);
    int start = (int)(h % XS_CONNS_MAX);
    for (int k = 0; k < XS_CONNS_MAX; k++) {
        int16_t idx = g_peer_sess[peer][(start + k) % XS_CONNS_MAX];
        if (idx >= 0) return idx;
    }
    return -1;
}

/* Расшифрованный пакет: проверить право на адрес источника и развести. */
static void route_packet(struct worker *w, struct sess *from, uint8_t *pt, size_t pn, long long now) {
    if (pn < 20) return;
    uint32_t src, dst;
    memcpy(&src, pt + 12, 4);
    memcpy(&dst, pt + 16, 4);
    src = ntohl(src);
    dst = ntohl(dst);
    /* ОБЯЗАТЕЛЬНАЯ проверка: без неё одна скомпрометированная пир подделывает трафик любой
     * другой. Право на адрес даёт конфигурация, а не сам пакет. */
    if (from->peer < 0 || !xs_src_ok(&g_conf.peer[from->peer], src)) return;
    int to = xs_route(&g_router, dst);
    /* Привязка пир→сессия читается один раз в локальную переменную: между чтением и отправкой
     * владелец сессии может её сменить, и «прочитать дважды» означало бы отправку по индексу,
     * который уже другой. Что сессия к моменту отправки ещё жива, проверяет сама send_to под
     * своим замком — здесь достаточно, чтобы индекс был осмысленным. */
    int16_t di = to >= 0 ? peer_pick(to, pt, pn) : -1;
    if (to >= 0 && to != from->peer && di >= 0) {
        /* Пир↔пир: уменьшаем TTL (иначе петля живёт вечно) и шифруем В ТОЙ ЖЕ строке. */
        if (xs_ttl_dec(pt, pn) != 0) return;
        struct sess *d = &g_sess[di];
        /* Подрезка по MTU ПОЛУЧАТЕЛЯ: у пиров он свой у каждой (у одной 1431, у другой 1387),
         * и путь между ними — узкое место из двух. Кроме хаба это посчитать некому: пира
         * друг о друге ничего не знают. */
        if (d->mtu > 0) xs_mss_clamp(pt, pn, d->mtu);
        send_to(w, d, w->row, pn, now);
        return;
    }
    /* Свой адрес или выход наружу — отдаём ядру, в СВОЮ очередь устройства: писать можно в
     * любую, и своя не требует ни выбора, ни согласования с другими потоками. */
    tun_write_ctl(&w->tun, pt, pn);
}

/* Увезти набранные кадры ОДНОЙ записью: один кадр — как есть, несколько — в контейнере.
 *
 * pay указывает на нагрузку записи, off — сколько в ней занято вместе с местом под тип
 * контейнера. Одиночный кадр едет БЕЗ контейнера: он дешевле на три байта, и таких записей
 * большинство. */
static void hub_send_frames(struct worker *w, struct sess *d, uint8_t *pay, size_t off,
                            int frames) {
    size_t pn;
    if (frames == 1) {
        pn = off - XS_BATCH_HDR - 2;
        memmove(pay, pay + XS_BATCH_HDR + 2, pn);
    } else {
        pay[0] = XS_CTL_BATCH;
        pn = off;
    }
    send_to(w, d, w->row, pn, xs_now_ms());
}

/* ---- один кадр открытого текста от пира ------------------------------------
 *
 * Вынесено в функцию, потому что кадр приходит двумя путями: одиночной записью и внутри пачки,
 * которую разбор отдаёт по одному через обратный вызов. Две копии этой обработки означали бы два
 * места, где можно по-разному ошибиться в том, что делать с чужим пакетом. */
static void hub_frame(struct worker *w, struct sess *s, const uint8_t *pt, size_t pn,
                      long long now) {
    s->up_pkts++;
    enum xs_kind kind = xs_frame_kind(pt, pn);
    if (kind == XS_CTL) {
        /* Проба пути: отвечаем эхом с ДОШЕДШИМ размером. Эхо крохотное (три байта), поэтому оно
         * проходит всегда — иначе пир не смог бы отличить «большой кадр не дошёл» от «не дошёл
         * ответ». */
        int psz = xs_probe_size(pt, pn);
        if (psz > 0) {
            uint8_t ack[8];
            size_t an2 = xs_pack_build(ack, sizeof(ack), psz);
            if (an2) {
                memcpy(w->row + XS_HDR_ROOM, ack, an2);
                send_to(w, s, w->row, an2, now);
            }
            return;
        }
        /* Пир не собирает наши записи: путь рвёт сегменты. Схлопываем пачку немедленно — на
         * рваном пути она делает хуже, а не лучше. */
        int lost = xs_loss_value(pt, pn);
        if (lost > 0) {
            s->batch_max = 1;
            s->cool_until = now + XSH_REASM_COOL_MS;
            unsigned long long held = 0;
            if (xs_ratelog(&w->rl_stamp, now, XS_LOG_EVERY_MS, &held)) {
                char tail[64];
                fprintf(stderr, LOG_I "пир не собрал %d записей — везу по одному кадру%s\n",
                        lost, xs_held_str(held, tail, sizeof(tail)));
            }
            return;
        }
        /* Итог согласования: пир проверил путь и называет рабочий размер. Берём минимум со своим
         * пределом — больше него мы всё равно не отправим. */
        int mv = xs_mtu_value(pt, pn);
        if (mv > 0) {
            int own = g_conf.mtu ? g_conf.mtu : XS_MTU_DEF;
            int was = s->mtu;
            s->mtu = mv < own ? mv : own;
            /* Печатаем только ИЗМЕНЕНИЕ: кадр приходит после каждого пробоя пира, то есть раз в
             * две минуты на каждого, и строка «согласован тот же MTU» через год работы звезды из
             * тридцати пиров — это четверть миллиона строк ни о чём. */
            if (s->mtu != was) {
                char fp2[12];
                xs_key_fp(g_conf.peer[s->peer >= 0 ? s->peer : 0].pub, fp2);
                fprintf(stderr, LOG_I "пир %s: согласован MTU %d\n", fp2, s->mtu);
            }
            hub_retune_mtu();
        }
        return;
    }
    if (kind != XS_IPV4 && kind != XS_IPV6) return;
    /* Пакет поедет дальше из строки с местом под заголовки впереди, а пришёл он либо в приёмном
     * буфере, либо в буфере сборки — переносим, если он не там. */
    if (pt != w->row + XS_HDR_ROOM) {
        if (pn > XS_MTU_DEF) return;
        memmove(w->row + XS_HDR_ROOM, pt, pn);
    }
    route_packet(w, s, w->row + XS_HDR_ROOM, pn, now);
}

struct hub_fctx { struct worker *w; struct sess *s; long long now; };

static void hub_frame_cb(void *ctx, const uint8_t *f, size_t n) {
    struct hub_fctx *c = ctx;
    hub_frame(c->w, c->s, f, n, c->now);
}

/* Цикл одного воркера. Всё, что он трогает, — либо его личное (буферы, индекс, свой отрезок
 * таблицы), либо взято под замок отправки. */
/* Ветка SYN приёмного цикла. Возвращает сессию, которой сегмент принадлежит, или NULL,
 * если он отброшен.
 *
 * Отдельной функцией, а не строками внутри worker_loop, ради стенда: до неё нужно дотянуться
 * из tests/hubmatch.c, а внутри цикла её окружают poll и сырой сокет.
 *
 * СЕССИЮ В РАБОТЕ SYN НЕ ТРОГАЕТ — это главное свойство, и оно новое. Поддельный SYN не
 * несёт ни байта аутентификации: такой сегмент собирает кто угодно, кто знает адрес хаба и
 * порт пира. Раньше эта ветка по нему правила isn_rx — базу, из которой xs_reasm_feed
 * считает смещение принятой записи, а из смещения выводится nonce расшифровки. Одно
 * постороннее сообщение останавливало входящий поток целиком, и сессия при этом даже не
 * умирала по XSH_IDLE_MS: last_rx обновляется каждым принятым сегментом, включая
 * нерасшифрованные (I-071).
 *
 * Второе следствие тоньше и живёт в замках. Откат `seq -= 1` сам по себе сходится: SYN-ACK
 * тут же занимает этот номер обратно (xs_conn_send прибавляет единицу за флаг SYN). Но
 * происходит он БЕЗ g_tx_lock, а записи данных в ту же сессию пишет другой воркер именно
 * под этим замком — то есть между откатом и SYN-ACK номер может достаться настоящей записи.
 * Номер и есть смещение, из которого выводится nonce отправки, а повтор nonce — это полная
 * потеря AEAD, о чём шапка xsconn.h говорит прямо.
 *
 * У WireGuard граница проведена там же: состояние живой сессии меняет только УЖЕ
 * ПРОВЕРЕННЫЙ пакет. Инициация рукопожатия несёт mac1 на статическом ключе получателя (а под
 * нагрузкой ещё и cookie), проверяется до всякой дорогой арифметики — и даже пройдя
 * проверку, не трогает текущую пару ключей: та сменяется только после ЗАВЕРШЁННОГО
 * рукопожатия, а прежняя ещё живёт на расшифровку. Наш аутентификатор едет в session_id
 * ClientHello, то есть в сегменте ПОСЛЕ SYN, поэтому на сам SYN опираться нечем, и
 * единственный честный ответ — не менять по нему ничего.
 *
 * Цена отказа мала: пир выбирает порт источника случайно из 28000 (xsconn.c), поэтому SYN в
 * ту же четвёрку от своего же пира после перезапуска — один случай на семь тысяч, и он
 * разрешается сам: сессия уходит по XSH_IDLE_MS, пир соединяется с нового порта. Полный
 * ответ на этот случай — SYN-cookie на неопознанный SYN и подмена сессии только после
 * сошедшегося аутентификатора, как у WireGuard; это отдельная работа, R-059. */
static struct sess *sess_on_syn(struct worker *w, struct sess *s, const struct obfs_seg *seg,
                                long long now) {
    if (s && s->phase != PH_SYN) {
        w->d_syn_est++;
        /* Строку вызывает пришедший из сети пакет, значит её частоту выбирает не хозяин
         * хаба — отсюда ограничитель, как у неопознанного пира выше. */
        unsigned long long held = 0;
        if (xs_ratelog(&w->rl_synest, now, XS_LOG_EVERY_MS, &held)) {
            struct in_addr in;
            char tail[64];
            in.s_addr = seg->saddr;
            fprintf(stderr, LOG_W "SYN в сессию, которая уже работает (%s:%u) — отброшен%s\n",
                    inet_ntoa(in), seg->sport, xs_held_str(held, tail, sizeof(tail)));
        }
        return NULL;
    }
    if (!s) s = sess_alloc(w, seg, g_conf.listen_port);
    else s->conn.seq -= 1;          /* повтор того же SYN-ACK */
    if (!s) return NULL;
    s->conn.ack = seg->seq + 1;
    s->conn.isn_rx = seg->seq;
    s->conn.state = XSC_SYN_RCVD;
    s->conn.last_rx = now;
    w->d_syn++;
    xs_conn_send(&s->conn, 0x12 /* SYN|ACK */, NULL, 0, OBFS_OPT_SCALE);
    return s;
}

static void *worker_loop(void *arg) {
    struct worker *w = arg;
    long long d_last = xs_now_ms();
    for (;;) {
        struct pollfd fds[2 + XSH_MAX_SESS];
        int nf = 0;
        fds[nf].fd = w->rx; fds[nf].events = POLLIN; fds[nf].revents = 0; nf++;
        fds[nf].fd = w->tun.fd; fds[nf].events = POLLIN; fds[nf].revents = 0; nf++;
        int n = poll(fds, (nfds_t)nf, XSC_TICK_MS * 5);
        long long now = xs_now_ms();
        if (n < 0 && errno != EINTR) break;

        /* ---- со пиров -------------------------------------------------------- */
        if (n > 0 && (fds[0].revents & POLLIN)) {
          for (;;) {
            for (int i = 0; i < XSH_BATCH; i++) {
                w->iov[i].iov_base = w->rx_buf[i];
                w->iov[i].iov_len = XS_ROW;
                memset(&w->mm[i].msg_hdr, 0, sizeof(w->mm[i].msg_hdr));
                w->mm[i].msg_hdr.msg_iov = &w->iov[i];
                w->mm[i].msg_hdr.msg_iovlen = 1;
            }
            int got = recvmmsg(w->rx, w->mm, XSH_BATCH, MSG_DONTWAIT, NULL);
            if (got <= 0) break;
            for (int i = 0; i < got; i++) {
                struct obfs_seg seg;
                w->d_seg++;
                if (obfs_parse(w->rx_buf[i], w->mm[i].msg_len, &seg) != 0) { w->d_bad++; continue; }
                if (seg.dport != (uint16_t)w->listen_port) { w->d_alien++; continue; }
                struct sess *s = sess_find(w, ntohl(seg.saddr), seg.sport);

                if ((seg.flags & 0x02) && !(seg.flags & 0x10)) {         /* SYN */
                    sess_on_syn(w, s, &seg, now);
                    continue;
                }
                if (!s) {
                    /* Данные по сессии, которой нет: пир пережила наш перезапуск. RST
                     * говорит ей об этом сразу — иначе она узнает по тишине, то есть через
                     * XSC_DEAD_MS, и всё это время туннель стоит. Окно 65535, а не ноль:
                     * именно этим наш RST отличается от RST ядра, который гасит правило. */
                    if (w->tx0 >= 0 && !(seg.flags & 0x04)) {
                        uint8_t rst[60];
                        size_t rn = obfs_build(rst, seg.daddr, seg.saddr,
                                               (uint16_t)w->listen_port, seg.sport,
                                               seg.ack, seg.seq + (uint32_t)seg.plen,
                                               0x14 /* RST|ACK */, 0, NULL, 0);
                        struct sockaddr_in to;
                        memset(&to, 0, sizeof(to));
                        to.sin_family = AF_INET;
                        to.sin_addr.s_addr = seg.saddr;
                        sendto(w->tx0, rst, rn, 0, (struct sockaddr *)&to, sizeof(to));
                    }
                    continue;
                }
                /* Замок берётся вокруг УЧЁТА принятого, потому что он теперь может отправить:
                 * голое подтверждение уходит прямо из xs_conn_on_seg (по таймеру их выходило
                 * пятьдесят в секунду там, где нужно тысячи). Отправка двигает номер, а в эту же
                 * сессию может писать другой воркер — пакет пир→пир или пакет из TUN. */
                pthread_mutex_lock(&g_tx_lock[s - g_sess]);
                int what = xs_conn_on_seg(&s->conn, &seg, now);
                pthread_mutex_unlock(&g_tx_lock[s - g_sess]);
                if (what < 0) { sess_free(w, s); continue; }
                if (what != 1) continue;

                if (s->phase == PH_SYN) { w->d_hs++; hs_step(w, s, &seg, g_conf.listen_port, now); continue; }
                if (s->phase == PH_HS) { w->d_hs++; hs_confirm(w, s, &seg, now); continue; }
                w->d_data++;

                /* Сборка записи, которая могла быть разрезана между сегментами. Она же
                 * предфильтр: сегмент, не начинающийся с заголовка записи и не продолжающий
                 * начатую, отбрасывается до всякой криптографии. */
                const uint8_t *body, *hdr;
                size_t body_n;
                uint32_t rel;
                if (!xs_reasm_feed(&s->reasm, seg.seq, s->conn.isn_rx, seg.payload, seg.plen,
                                   &body, &body_n, &hdr, &rel))
                    continue;
                if (xs_win_check(&s->win, rel) != 0) continue;
                /* Расшифровка НА МЕСТЕ: у целой записи — прямо в приёмной строке, у собранной —
                 * в буфере сборки. Пересылку другому пиру это не удорожает: копия туда всё равно
                 * нужна, и делается она ниже одним memmove на кадр. */
                uint8_t *ct = (uint8_t *)(uintptr_t)body;
                if (tls13_aead_open(&s->rx, rel, hdr, XS_REC_HDR, ct, body_n) != 0)
                    continue;
                xs_win_commit(&s->win, rel);
                size_t pn = body_n - XS_TAG;
                struct hub_fctx fc = { w, s, now };
                if (pn && ct[0] == XS_CTL_BATCH) {
                    if (xs_batch_iter(ct, pn, hub_frame_cb, &fc) != 0) w->d_bad++;
                } else {
                    hub_frame(w, s, ct, pn, now);
                }
            }
            if (got < XSH_BATCH) break;
          }
        }

        /* ---- из ядра (интернет и локальные ответы) --------------------------
         *
         * Это ГЛАВНОЕ направление загрузки, и именно здесь пачка окупается: подряд идущие пакеты
         * одному и тому же пиру уезжают одной записью, которая больше сегмента и потому режется
         * между ними — ровно так ведёт себя настоящий TLS (см. xswire.h). Ждать ради пачки нечего:
         * берётся только то, что уже прочитано.
         *
         * Пачка собирается на ОДНОГО получателя: у каждой сессии свои ключи и свой номер
         * последовательности, и «одна запись двум пирам» бессмысленна. */
        if (n > 0 && (fds[1].revents & POLLIN)) {
            struct sess *dst = NULL;
            uint8_t *pay = w->row + XS_HDR_ROOM;
            size_t off = XS_BATCH_HDR;
            int frames = 0;
            for (int i = 0; i < XSH_BATCH * XS_BATCH_FRAMES_MAX; i++) {
                int max = dst ? dst->batch_max : XS_BATCH_FRAMES_MAX;
                if (dst && now < dst->cool_until) max = 1;
                if (frames >= max) break;
                if (frames > 0 && off + 2 + XS_MTU_DEF + XS_TAG > XS_MAX_RECORD) break;
                ssize_t r = tun_read_packet(&w->tun, pay + off + 2, XS_MTU_DEF);
                if (r <= 20) break;
                uint32_t dip;
                memcpy(&dip, pay + off + 2 + 16, 4);
                int to = xs_route(&g_router, ntohl(dip));
                int16_t di = to >= 0 ? peer_pick(to, pay + off + 2, (size_t)r) : -1;
                if (di < 0) continue;                          /* нет пира — отбросить */
                struct sess *d = &g_sess[di];
                if (d->mtu > 0) xs_mss_clamp(pay + off + 2, (size_t)r, d->mtu);
                if (dst && d != dst) {
                    /* Пакет другому пиру закрывает набор. Его самого переносим в начало и делаем
                     * первым кадром следующей записи: откладывать его до следующего круга значило
                     * бы менять порядок пакетов в потоке. */
                    hub_send_frames(w, dst, pay, off, frames);
                    memmove(pay + XS_BATCH_HDR + 2, pay + off + 2, (size_t)r);
                    off = XS_BATCH_HDR;
                    frames = 0;
                }
                dst = d;
                pay[off] = (uint8_t)((size_t)r >> 8);
                pay[off + 1] = (uint8_t)((size_t)r & 0xFF);
                off += 2 + (size_t)r;
                frames++;
            }
            if (frames > 0 && dst) hub_send_frames(w, dst, pay, off, frames);
        }

        if (w->debug && now - d_last >= 1000) {
            fprintf(stderr, LOG_I "воркер %d: сегментов %llu, битых %llu, чужих %llu, SYN %llu, "
                                  "рукопожатий %llu, данных %llu, SYN в живую сессию %llu\n",
                    w->id, w->d_seg, w->d_bad, w->d_alien, w->d_syn, w->d_hs, w->d_data,
                    w->d_syn_est);
            d_last = now;
        }

        /* ---- обслуживание СВОИХ сессий -------------------------------------- */
        for (int i = w->base; i < w->base + w->cap; i++) {
            struct sess *s = &g_sess[i];
            if (s->phase == PH_FREE) continue;
            if (now - s->conn.last_rx > XSH_IDLE_MS) { sess_free(w, s); continue; }
            /* Смещённая сессия: пир пересоединился с другого порта, привязка пир→сессия
             * указывает уже не на нас. Убирает её именно ВЛАДЕЛЕЦ — тот, в чьём индексе лежит
             * её запись; сделать это из чужого потока значило бы править чужую таблицу. */
            if (s->phase == PH_EST && s->peer >= 0 && s->conn_id >= 0) {
                int16_t cur = g_peer_sess[s->peer][s->conn_id];
                if (cur >= 0 && cur != (int16_t)i) { sess_free(w, s); continue; }
            }
            /* Обратная связь по сборке: если у НАС не собираются записи пира, сказать об этом
             * обязаны мы — уменьшить пачку может только он. */
            if (s->phase == PH_EST && s->reasm.dropped > s->last_drops &&
                now - s->last_report >= XSH_REASM_REPORT_MS) {
                size_t ln = xs_loss_build(w->row + XS_HDR_ROOM, 8,
                                          (int)(s->reasm.dropped - s->last_drops));
                if (ln && send_to(w, s, w->row, ln, now) == 0) {
                    s->last_drops = s->reasm.dropped;
                    s->last_report = now;
                }
            }
            /* Рост пачки на чистом пути: медленно вверх, мгновенно вниз (см. hub_frame). */
            if (!g_compat && s->phase == PH_EST && now >= s->cool_until &&
                now - s->last_grow >= XSH_REASM_GROW_MS && s->batch_max < XS_BATCH_FRAMES_MAX) {
                s->batch_max *= 2;
                if (s->batch_max > XS_BATCH_FRAMES_MAX) s->batch_max = XS_BATCH_FRAMES_MAX;
                s->last_grow = now;
            }
            /* Пустая запись и есть keepalive: длина нагрузки ноль, тип кадра пир опознаёт по
             * пустоте (xs_frame_kind). Отдельного вида кадра для этого не нужно.
             *
             * ИНТЕРВАЛ С РАЗБРОСОМ, а не ровный: пакет одного размера ровно каждые десять секунд не
             * встречается ни в одном браузерном соединении и находится подсчётом пауз между мелкими
             * пакетами. Разброс ±20% не стоит ничего. */
            if (s->phase == PH_EST && !s->keep_next) s->keep_next = XSH_KEEPALIVE_MS;
            if (s->phase == PH_EST && s->conn.last_rx > s->conn.last_tx &&
                now - s->conn.last_tx >= s->keep_next) {
                send_to(w, s, w->row, 0, now);
                uint32_t j = 0;
                xc_random((unsigned char *)&j, sizeof(j));
                s->keep_next = XSH_KEEPALIVE_MS * 8 / 10 +
                               (long long)(j % (uint32_t)(XSH_KEEPALIVE_MS * 4 / 10 + 1));
            }
            sess_tick_locked(s, now);
        }
    }
    return NULL;
}

int cmd_xsteer_hub(const char *conf_path) {
    const char *path = conf_path ? conf_path : "/etc/steer/xsteer/hub.conf";
    char err[256];
    if (xs_conf_load(path, XS_ROLE_HUB, &g_conf, &g_sec, err, sizeof(err)) != 0) {
        fprintf(stderr, LOG_W "%s\n", err);
        return 2;
    }
    if (g_conf.device[0])
        snprintf(g_dev, sizeof(g_dev), "%s", g_conf.device);
    for (int i = 0; i < XS_PEERS_MAX; i++)
        for (int c = 0; c < XS_CONNS_MAX; c++) g_peer_sess[i][c] = -1;
    for (int i = 0; i < XSH_MAX_SESS; i++) {
        g_sess[i].conn.fd = -1;
        g_sess[i].peer = -1;
        g_sess[i].conn_id = -1;
    }
    xs_router_build(&g_router, g_conf.peer, g_conf.peer_n);

    int debug = getenv("STEER_XS_DEBUG") != NULL;
    g_compat = getenv("STEER_XS_COMPAT") != NULL;
    if (g_compat)
        fprintf(stderr, LOG_I "STEER_XS_COMPAT: везу по одному кадру в записи — формат предыдущей "
                              "версии, для пиров, которые ещё не обновлены\n");

    /* ---- воркеры ---------------------------------------------------------- */
    /* СКОЛЬКО ПОТОКОВ, и почему не «по числу ядер».
     *
     * Степень двойки обязательна: раскладка делается маской по младшим битам порта источника, а
     * у cBPF нет деления. Округляем ВНИЗ.
     *
     * Верхний предел — не только ядра, но и число ВОЗМОЖНЫХ СЕССИЙ, и это выяснилось замером.
     * Каждый воркер держит свой сырой сокет, а ядро на КАЖДЫЙ локально доставляемый TCP-пакет
     * клонирует skb для каждого такого сокета — и только потом фильтр отбрасывает лишние. То
     * есть лишний воркер платится на всём трафике машины, а приносит пользу только если ему
     * достанется своя сессия. Сессий не больше, чем пиров, умноженных на число соединений,
     * которое пир может открыть.
     *
     * Числа с tests/run-xsteer.sh (два пира по одному соединению, сумма; та же машина):
     *     1 воркер — 0,67 Гбит/с;  2 — 1,20;  4 — 1,11;  8 — 0,97.
     * Видно и пользу, и цену: второй воркер почти удваивает, восьмой уже отнимает.
     *
     * Переменная окружения нужна для замеров: утверждение «многопоток дал столько-то» без
     * возможности вернуться к одному потоку на том же железе проверить нельзя (та же причина,
     * что у STEER_TUN_NOGSO). */
    long cores = sysconf(_SC_NPROCESSORS_ONLN);
    int want = cores > 0 ? (int)cores : 1;
    if (want > (int)g_conf.peer_n * XS_CONNS_MAX) want = (int)g_conf.peer_n * XS_CONNS_MAX;
    const char *env = getenv("STEER_XS_WORKERS");
    if (env) { long v = strtol(env, NULL, 10); if (v >= 1) want = (int)v; }
    if (want > XSH_WORKERS_MAX) want = XSH_WORKERS_MAX;
    if (want < 1) want = 1;
    int n = 1;
    while (n * 2 <= want) n *= 2;
    g_workers = n;

    /* Очереди TUN: по одной на воркера. Ядро само раскладывает пакеты по очередям, хэшируя
     * поток, — и хэш у него симметричный, поэтому обе половины одного соединения попадают в
     * одну очередь. Меньше очередей, чем воркеров, не беда: лишние воркеры возьмут очередь по
     * кругу, просто будут делить её с соседом. */
    struct tun_dev tq[XSH_WORKERS_MAX];
    const char *dev = g_dev;
    int nq = tun_open(tq, n, dev);
    if (nq < 0) {
        fprintf(stderr, LOG_W "нет /dev/net/tun (на LXC и OpenVZ его часто нет вовсе) — "
                              "хаб не может отдавать трафик наружу\n");
        return 1;
    }
    if (nq < n)
        fprintf(stderr, LOG_I "очередей TUN дали %d на %d воркеров — часть будет делить очередь\n",
                nq, n);

    /* TUN переводится в НЕБЛОКИРУЮЩИЙ режим, и это не тонкая настройка, а условие
     * работоспособности. Пакеты читаются пачкой, до XS*_BATCH за одно событие poll: на
     * блокирующем дескрипторе второе чтение, когда пакетов больше нет, останавливает весь
     * цикл НАВСЕГДА. Именно так и вышло при первом живом прогоне — хаб печатал «слушаю» и
     * замолкал, не отвечая на SYN, и снаружи это выглядело как «сеть не доходит». */
    {
        /* Неблокирующими делаются ВСЕ очереди: воркер, у которого очередь блокирующая, встанет
         * на втором чтении так же, как вставал единственный поток до появления очередей. */
        for (int q = 0; q < nq; q++) {
            int tfl = fcntl(tq[q].fd, F_GETFL, 0);
            fcntl(tq[q].fd, F_SETFL, tfl | O_NONBLOCK);
        }
        char addr[24], mtu[8];
        struct in_addr in;
        in.s_addr = htonl(g_conf.addr);
        snprintf(addr, sizeof(addr), "%s/%d", inet_ntoa(in), g_conf.addr_plen);
        snprintf(mtu, sizeof(mtu), "%d", g_conf.mtu ? g_conf.mtu : XS_MTU_DEF);
        const char *a1[] = { "ip", "addr", "replace", addr, "dev", dev, NULL };
        const char *a2[] = { "ip", "link", "set", "dev", dev, "mtu", mtu, "up", NULL };
        run_quiet(a1);
        run_quiet(a2);
        /* Маршруты к сетям пиров: без них ядро не знает, что ответы им идут через это
         * устройство, и выход в интернет работал бы только в одну сторону. */
        for (size_t i = 0; i < g_conf.peer_n; i++)
            for (size_t a = 0; a < g_conf.peer[i].allowed_n; a++) {
                if (!g_conf.peer[i].allowed[a].plen) continue;   /* 0.0.0.0/0 — не наш маршрут */
                char pfx[24];
                in.s_addr = htonl(g_conf.peer[i].allowed[a].net);
                snprintf(pfx, sizeof(pfx), "%s/%d", inet_ntoa(in),
                         g_conf.peer[i].allowed[a].plen);
                const char *r[] = { "ip", "route", "replace", pfx, "dev", dev, NULL };
                run_quiet(r);
            }
    }


    for (int i = 0; i < XSH_MAX_SESS; i++) pthread_mutex_init(&g_tx_lock[i], NULL);

    int per = XSH_MAX_SESS / n;
    for (int i = 0; i < n; i++) {
        struct worker *w = &g_w[i];
        w->id = i;
        w->n = n;
        w->mask = (uint16_t)(n - 1);
        w->base = i * per;
        w->cap = per;
        w->listen_port = g_conf.listen_port;
        w->debug = debug;
        w->tun = tq[i % nq];
        xs_sidx_reset(&w->idx);
        /* Свой сырой сокет с раскладкой. Приём — БЕЗ connect: пиров много и заранее они
         * неизвестны; отвечает каждой свой сокет сессии. */
        w->rx = socket(AF_INET, SOCK_RAW, IPPROTO_TCP);
        if (w->rx < 0) { perror("steer: raw"); return 1; }
        int fl = fcntl(w->rx, F_GETFL, 0);
        fcntl(w->rx, F_SETFL, fl | O_NONBLOCK);
        int rcvbuf = 1 << 20;
        setsockopt(w->rx, SOL_SOCKET, SO_RCVBUF, &rcvbuf, sizeof(rcvbuf));
        if (n == 1) obfs_filter_port(w->rx, (uint16_t)g_conf.listen_port);
        else obfs_filter_port_shard(w->rx, (uint16_t)g_conf.listen_port, w->mask, (uint16_t)i);
        /* Сокет для тех, чьей сессии нет: им отвечают RST, чтобы пир узнала о перезапуске
         * хаба сразу, а не по тишине через XSC_DEAD_MS. */
        w->tx0 = socket(AF_INET, SOCK_RAW, IPPROTO_TCP);
        if (w->tx0 >= 0) obfs_filter_none(w->tx0);
    }

    if (obfs_guard_up('x', "hub", NULL, g_conf.listen_port, 1) != 0)
        fprintf(stderr, LOG_W "правило против RST не встало: если порт %d не закрыт политикой "
                              "firewall, ядро будет рвать сессии\n", g_conf.listen_port);

    fprintf(stderr, LOG_I "слушаю поддельный TCP :%d, пиров %zu, устройство %s, воркеров %d "
                          "(по %d сессий)\n",
            g_conf.listen_port, g_conf.peer_n, dev, n, per);

    /* Воркер 0 работает в этом же потоке: при n == 1 процесс ведёт себя ровно так, как до
     * появления потоков вовсе, и отладка одного потока остаётся возможной. */
    pthread_t th[XSH_WORKERS_MAX];
    for (int i = 1; i < n; i++)
        if (pthread_create(&th[i], NULL, worker_loop, &g_w[i]) != 0) {
            fprintf(stderr, LOG_W "поток %d не создался: работаем меньшим числом\n", i);
            g_w[i].rx = -1;
        }
    worker_loop(&g_w[0]);
    obfs_guard_down();
    xs_conf_wipe(&g_sec);
    return 1;
}
