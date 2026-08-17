/* xsteer: цикл пира. TUN с одной стороны, поддельный TCP до хаба с другой.
 *
 * УСТРОЙСТВО ЦИКЛА. Один поток, один poll на два дескриптора, ни одного блокирующего вызова.
 * Наружу: чтение TUN → шифрование НА МЕСТЕ → заголовки записи и TCP ПЕРЕД нагрузкой в том же
 * буфере → отправка. Обратно: recvmmsg пачкой → разбор сегмента → окно приёма → расшифровка
 * на месте → запись в TUN. Копий нагрузки нет ни одной в обе стороны.
 *
 * ПОЧЕМУ ОДИН ПОТОК В ЭТОЙ ВЕРСИИ. Замер (tests/xsbench.c) показал, что 95% стоимости пакета
 * — это AEAD, а всё остальное вместе 4,6%. Значит второй поток даёт почти ровно второе ядро,
 * и на роутере с одним ядром давать нечего. Многопоточность здесь выражается не потоками
 * внутри одного соединения (там общий номер последовательности, то есть общее изменяемое
 * состояние), а НЕСКОЛЬКИМИ СОЕДИНЕНИЯМИ — по одному на поток, каждое со своими ключами и
 * своим смещением. Это следующий шаг, и он не потребует ломать ничего здесь: цикл уже
 * оперирует одним соединением как единицей владения.
 *
 * ЧЕГО В ЭТОЙ ВЕРСИИ НЕТ, СКАЗАНО ПРЯМО. Смены ключей «поднять новое, потом отпустить
 * старое» (make-before-break) ещё нет: при достижении порога соединение поднимается заново, и
 * туннель молчит один круг обмена. Порог — гигабайт или двадцать минут, то есть на обычной
 * скорости это раз в двадцать минут; но назвать это надо, а не оставить читателю.
 */
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>
#include <pthread.h>
#include <arpa/inet.h>
#include <sys/socket.h>

#include "../spec.h"
#include "xsconn.h"
#include "xsconf.h"
#include "xshake.h"
#include "xsroute.h"
#include "tun.h"
#include "reality.h"

/* Живёт в failover.c: запуск внешней команды без оболочки (argv массивом, не строкой). */
int run_quiet(const char *const argv[]);

#define LOG_W "steer[warn] xsteer: "
#define LOG_I "steer[info] xsteer: "

/* Пачка на приёме: до XSC_BATCH сегментов за один системный вызов. Шестнадцать, как в
 * obfs.c, и по той же причине — пачка больше упирается уже не в вызовы, а в задержку. */
#define XSC_BATCH 16

/* Буферы приёма и отправки лежат В СТРУКТУРЕ ВОРКЕРА, а не рядом с файлом: соединений у пира
 * несколько, каждое обслуживает свой поток, и общий буфер означал бы, что два потока пишут в
 * одну строку. Цена — около 50 КБ на воркера; на роутере с 128 МБ это ничто по сравнению с
 * тем, что общий буфер сломался бы только под нагрузкой и только иногда. */
/* Исходящая пачка. Отдельные строки, а не одна: пока пачка не отправлена, каждый сегмент
 * должен лежать целиком — sendmmsg читает их все за один вызов.
 *
 * Зачем пачка. Первый живой замер дал 0,64 Гбит/с при том, что один проход AEAD на этом
 * железе стоит вчетверо меньше: время уходило не в шифр, а в системные вызовы — по send() на
 * каждый пакет. Приём пачкой был с самого начала, отправка — нет, и перекос был виден именно
 * по замеру, а не по коду. */


/* ТЕКУЩИЙ MTU туннеля — общий на все воркеры, потому что устройство одно. Ставит его воркер 0
 * (он же ведёт пробой пути), остальные ЧИТАЮТ: им это нужно для подрезки MSS и для предела
 * чтения из TUN. Тип int и одно слово: чтение и запись целого слова на всех наших
 * архитектурах неделимы, а согласовывать больше нечего — значение меняется раз в минуты. */
static volatile int g_mtu_now;
/* И отдельно — ПОДТВЕРЖДЁННОЕ пробоем значение. Разница нужна: g_mtu_now в начале равен
 * безопасному низу, и остальные соединения, назвав его хабу, заставляли бы хаб опускать MTU
 * устройства на низ, пока пробой не закончится. Хабу называется только подтверждённое. */
static volatile int g_mtu_pub;

/* Название `spoke` в коде оставлено НАРОЧНО, хотя в текстах, журнале и настройках эта сторона
 * называется ПИРОМ. Причина простая: `xs_peer` в xsconf.h — уже занято, там это пир ИЗ
 * КОНФИГУРАЦИИ, и два разных `peer` в одном файле читались бы хуже, чем одно историческое имя.
 * Здесь `spoke` — состояние НАШЕЙ стороны (соединение, ключи, буферы одного воркера). */
struct spoke {
    /* Конфигурация и секреты — ОДНИ на все воркеры, по указателю. Копия у каждого означала бы
     * четыре копии приватного ключа в памяти вместо одной. */
    const struct xs_conf *conf;
    struct xs_secrets *sec;
    struct tun_dev tun;
    struct xs_conn conn;
    struct tls13_keys tx, rx;
    struct xs_win win;
    int up;                       /* рукопожатие прошло, данные можно нести */
    /* Номер этого соединения у пира. Пока соединение одно, он равен нулю; хаб по нему
     * различает соединения одной и той же пира и не вытесняет соседнее (см. xshake.h). */
    int conn_id;
    int mtu;
    uint8_t hub_pub[32];
    uint32_t hub_addr;
    int hub_port;
    long long handshake_at;
    unsigned long long up_pkts, down_pkts, up_bytes, down_bytes, dropped;
    long long last_drop_warn;
    /* ---- согласование MTU (см. xswire.h) --------------------------------------
     * mtu_cap — предел, заданный человеком в конфигурации: его не превышаем никогда.
     * mtu_limit — наш предел по каналу; agreed — минимум с пределом хаба.
     * confirmed — размер, ПОДТВЕРЖДЁННЫЙ пробой; до подтверждения несём безопасный низ. */
    int mtu_cap, mtu_limit, mtu_agreed, mtu_confirmed;
    /* Границы поиска: lo заведомо проходит, hi заведомо нет (0 — пока неизвестно), cur —
     * размер, который проверяется сейчас. p_verify — стадия «проверяю прежнее значение»
     * повторного пробоя (см. probe_start). */
    int p_lo, p_hi, p_cur, p_tries, p_steps, p_verify;
    long long probe_sent, probe_next;
    int probing;
    char link_if[32];
    char state_path[320];
    const char *out_name;
    const char *dev;
    int managed;
    /* Приём и отправка: свои у каждого воркера (см. выше). */
    uint8_t rx_buf[XSC_BATCH][XS_ROW];
    struct mmsghdr mm[XSC_BATCH];
    struct iovec iov[XSC_BATCH];
    uint8_t txb[XS_ROW];
    uint8_t tb[XSC_BATCH][XS_ROW];
    struct mmsghdr tmm[XSC_BATCH];
    struct iovec tiov[XSC_BATCH];
    /* Какой MTU этот воркер уже назвал хабу: своя сессия у каждого соединения, и хаб должен
     * знать размер по каждой — иначе подрезка MSS на обратном пути её пропустит. */
    int mtu_told;
};

/* Воркеры пира. Статические, а не на стеке: в каждом по 50 КБ буферов. */
static struct spoke g_sp[XS_CONNS_MAX];
static int g_conns = 1;
/* Конфигурация и секреты — по одному экземпляру на процесс. */
static struct xs_conf g_cf;
static struct xs_secrets g_sc;

/* Состояние на диск: его читают сторож (жив ли туннель) и status. Отдельным файлом, а не
 * через опрос процесса, потому что проверка процесса — это запуск процесса, а status
 * опрашивают раз в пять секунд. */
static void state_write(struct spoke *s) {
    char tmp[336];
    snprintf(tmp, sizeof(tmp), "%s.tmp", s->state_path);
    FILE *f = fopen(tmp, "w");
    if (!f) return;
    char fp[12];
    xs_key_fp(s->hub_pub, fp);
    /* Счётчики СУММИРУЮТСЯ по всем соединениям: наружу пир одна, и «отдано байт» должно
     * означать отданное туннелем, а не одним из его соединений. Читаем без замка: значения
     * только растут, и расхождение на несколько пакетов в файле состояния безвредно, а замок
     * на пути, который ведёт счёт на каждый пакет, — нет.
     *
     * `up` считается по ЛЮБОМУ живому соединению: туннель работает, пока работает хотя бы
     * одно, и сторож обязан видеть именно это. */
    unsigned long long tp = 0, tb2 = 0, rp = 0, rb = 0, dr = 0;
    int any_up = 0;
    long long hs_at = 0;
    for (int i = 0; i < g_conns; i++) {
        tp += g_sp[i].up_pkts;   tb2 += g_sp[i].up_bytes;
        rp += g_sp[i].down_pkts; rb  += g_sp[i].down_bytes;
        dr += g_sp[i].dropped;
        if (g_sp[i].up) any_up = 1;
        if (g_sp[i].handshake_at > hs_at) hs_at = g_sp[i].handshake_at;
    }
    fprintf(f, "{\"schema\":1,\"out\":\"%s\",\"up\":%s,\"mtu\":%d,\"conns\":%d"
               ",\"hub\":\"%s:%d\""
               ",\"hub_key\":\"%s\",\"handshake_age\":%lld"
               ",\"tx_packets\":%llu,\"tx_bytes\":%llu"
               ",\"rx_packets\":%llu,\"rx_bytes\":%llu,\"dropped\":%llu}\n",
            s->out_name, any_up ? "true" : "false", s->mtu, g_conns,
            s->conf->peer[0].endpoint, s->conf->peer[0].endpoint_port, fp,
            hs_at ? (xs_now_ms() - hs_at) / 1000 : -1,
            tp, tb2, rp, rb, dr);
    fclose(f);
    /* Переименование, а не запись на месте: читатель не должен увидеть половину файла.
     * Секретов в файле нет — печатает его тот же код, что xs_conf_json, и приватного ключа
     * он не видит по построению. */
    rename(tmp, s->state_path);
}

/* Поднять TUN. Два режима, и разница между ними — В ТОМ, КТО ВЛАДЕЕТ УСТРОЙСТВОМ.
 *
 * managed == 0 (выход спеки): устройство создаём и настраиваем мы — адрес из конфигурации,
 * MTU из накладных, — как это делает клиент VLESS.
 *
 * managed == 1 (режим netifd; обработчик протокола и страница LuCI едут в пакете
 * luci-app-splify2, потому что это часть интерфейса, а не движка): устройство уже создано,
 * адрес, MTU и
 * зону firewall ему даёт netifd. Мы его только ОТКРЫВАЕМ и ничего не трогаем: две стороны,
 * настраивающие одно устройство, — это гонка, в которой проигрывает та, что настроила первой,
 * и заметно это будет как «MTU иногда не тот». Но MTU мы ПРОВЕРЯЕМ: если netifd дал больше,
 * чем влезает в конверт, большие пакеты будут пропадать молча — худший класс отказов. */
static int tun_up_queues(struct spoke *s, struct tun_dev *q, int want, const char *dev,
                         int managed) {
    int n = tun_open(q, want, dev);
    if (n < 0) {
        fprintf(stderr, LOG_W "нет /dev/net/tun — установите kmod-tun\n");
        return -1;
    }
    s->tun = q[0];
    /* TUN переводится в НЕБЛОКИРУЮЩИЙ режим, и это не тонкая настройка, а условие
     * работоспособности. Пакеты читаются пачкой, до XS*_BATCH за одно событие poll: на
     * блокирующем дескрипторе второе чтение, когда пакетов больше нет, останавливает весь
     * цикл НАВСЕГДА. Именно так и вышло при первом живом прогоне — хаб печатал «слушаю» и
     * замолкал, не отвечая на SYN, и снаружи это выглядело как «сеть не доходит». */
    for (int i = 0; i < n; i++) {
        int fl = fcntl(q[i].fd, F_GETFL, 0);
        fcntl(q[i].fd, F_SETFL, fl | O_NONBLOCK);
    }

    if (managed) {
        char path[128], buf[32];
        snprintf(path, sizeof(path), "/sys/class/net/%.32s/mtu", dev);
        FILE *mf = fopen(path, "r");
        int dev_mtu = 0;
        if (mf) {
            if (fgets(buf, sizeof(buf), mf)) dev_mtu = atoi(buf);
            fclose(mf);
        }
        if (dev_mtu > 0) s->mtu = dev_mtu;
        fprintf(stderr, LOG_I "%s: устройством владеет netifd, MTU %d (накладные %d)\n",
                dev, s->mtu, XS_OVERHEAD);
        if (dev_mtu > XS_MTU_DEF)
            fprintf(stderr, LOG_W "%s: MTU %d больше предела %d для канала 1500 — большие "
                                  "пакеты будут пропадать; поставьте mtu %d в настройках "
                                  "интерфейса\n", dev, dev_mtu, XS_MTU_DEF, XS_MTU_DEF);
        return n;
    }

    char addr[24], mtu[8];
    struct in_addr in;
    in.s_addr = htonl(s->conf->addr);
    snprintf(addr, sizeof(addr), "%s/%d", inet_ntoa(in), s->conf->addr_plen);
    snprintf(mtu, sizeof(mtu), "%d", s->mtu);
    const char *a1[] = { "ip", "addr", "replace", addr, "dev", dev, NULL };
    const char *a2[] = { "ip", "link", "set", "dev", dev, "mtu", mtu, "up", NULL };
    if (run_quiet(a1) != 0 || run_quiet(a2) != 0) {
        fprintf(stderr, LOG_W "не удалось настроить %s\n", dev);
        return -1;
    }
    fprintf(stderr, LOG_I "%s: адрес %s, MTU %d (накладные %d)\n", dev, addr, s->mtu,
            XS_OVERHEAD);
    return n;
}

/* Одно рукопожатие целиком. Блокирующее по существу: до его конца нести нечего, а
 * усложнять цикл ради параллельности с самим собой незачем. Ждём с таймаутом, потому что
 * молчащий хаб не должен подвесить процесс — procd поднимет заново. */
static int do_handshake(struct spoke *s) {
    struct xs_hs hs;
    size_t hn = 0;
    /* В рукопожатие уходит НАШ ПРЕДЕЛ, а не текущий MTU устройства: согласовывать надо
     * возможности сторон, а не то, что случайно стоит на интерфейсе прямо сейчас. */
    int rc = xs_hs_client_hello(&hs, s->sec, s->hub_pub, s->conf->sni,
                               s->mtu_limit ? s->mtu_limit : s->mtu, s->conn_id,
                               s->txb, sizeof(s->txb), &hn);
    if (rc != 0) { fprintf(stderr, LOG_W "рукопожатие не собралось: %d\n", rc); return rc; }
    if (xs_conn_send(&s->conn, 0x18 /* PSH|ACK */, s->txb, hn, 0) != 0) return -1;

    long long deadline = xs_now_ms() + 5000;
    uint8_t in[XS_ROW * 2];
    size_t got = 0;
    for (;;) {
        long long left = deadline - xs_now_ms();
        if (left <= 0) {
            fprintf(stderr, LOG_W "хаб %s:%d не ответил на рукопожатие\n",
                    s->conf->peer[0].endpoint, s->hub_port);
            xs_hs_wipe(&hs);
            return -1;
        }
        struct pollfd p = { s->conn.fd, POLLIN, 0 };
        if (poll(&p, 1, (int)left) <= 0) continue;
        uint8_t pkt[XS_ROW];
        ssize_t r = recv(s->conn.fd, pkt, sizeof(pkt), 0);
        if (r <= 0) continue;
        struct obfs_seg seg;
        if (obfs_parse(pkt, (size_t)r, &seg) != 0) continue;
        if (seg.sport != s->conn.dport || seg.dport != s->conn.sport) continue;
        if (xs_conn_on_seg(&s->conn, &seg, xs_now_ms()) != 1) continue;
        /* Ответ хаба приходит одним сегментом: он собран так, чтобы влезть (см. xshake.c).
         * Но склеить два сегмента мы всё равно умеем — дешевле, чем однажды не понять почему
         * рукопожатие не проходит на канале с меньшим MSS. */
        if (got + seg.plen > sizeof(in)) { xs_hs_wipe(&hs); return -1; }
        memcpy(in + got, seg.payload, seg.plen);
        got += seg.plen;
        size_t used = 0;
        rc = xs_hs_client_finish(&hs, in, got, &s->tx, &s->rx, &used);
        if (rc == XS_EFORMAT && got < sizeof(in)) continue;    /* ждём остаток */
        if (rc != 0) {
            fprintf(stderr, LOG_W "хаб не признал нас или ответил не тем: %d\n", rc);
            xs_hs_wipe(&hs);
            return rc;
        }
        break;
    }
    size_t fn = 0;
    rc = xs_hs_client_confirm(&hs, &s->tx, s->txb, sizeof(s->txb), &fn);
    if (rc == 0) rc = xs_conn_send(&s->conn, 0x18, s->txb, fn, 0);
    int peer_mtu = hs.peer.mtu;
    xs_hs_wipe(&hs);
    if (rc != 0) return rc;

    /* СОГЛАСОВАНИЕ MTU, ступень первая: минимум из пределов сторон — «максимальное для обоих
     * устройств». Ступень вторая (проверка самого пути пробами) начинается ниже, потому что
     * канал у обоих может быть шире, чем путь между ними. */
    s->mtu_agreed = s->mtu_limit ? s->mtu_limit : XS_MTU_DEF;
    if (peer_mtu > 0 && peer_mtu < s->mtu_agreed) s->mtu_agreed = peer_mtu;
    if (s->mtu_cap > 0 && s->mtu_cap < s->mtu_agreed) s->mtu_agreed = s->mtu_cap;
    fprintf(stderr, LOG_I "предел согласован: %d (наш канал %s даёт %d, хаб называет %d%s)\n",
            s->mtu_agreed, s->link_if[0] ? s->link_if : "?",
            s->mtu_limit ? s->mtu_limit : XS_MTU_DEF, peer_mtu,
            s->mtu_cap ? ", в настройках задан предел" : "");
    xs_win_reset(&s->win);
    s->up = 1;
    s->handshake_at = xs_now_ms();
    fprintf(stderr, LOG_I "рукопожатие с %s:%d прошло, порт %u, шифр %s\n",
            s->conf->peer[0].endpoint, s->hub_port, s->conn.sport,
            s->tx.aead == TLS13_AEAD_AES128 ? "AES-128-GCM" : "ChaCha20-Poly1305");
    return 0;
}

/* Отправить один кадр открытого текста как запись. Служебные кадры (проба, эхо, итог) уходят
 * тем же путём, что данные: у них нет своего канала, и это нарочно — иначе появился бы второй
 * путь на проводе, который DPI различал бы по размеру и ритму. */
static int send_frame(struct spoke *s, const uint8_t *pt, size_t pn, long long now) {
    if (!s->up || pn > (size_t)XS_MTU_DEF) return -1;
    uint32_t rel = xs_conn_rel_next(&s->conn);
    uint8_t *rec = s->txb + XS_HDR_ROOM - XS_REC_HDR;
    memcpy(s->txb + XS_HDR_ROOM, pt, pn);
    if (xs_rec_build(rec, pn + XS_TAG) != 0) return -1;
    if (tls13_aead_seal(&s->tx, rel, rec, XS_REC_HDR, s->txb + XS_HDR_ROOM, pn,
                        s->txb + XS_HDR_ROOM + pn) != 0) return -1;
    size_t seglen = 0;
    uint8_t *seg = xs_conn_ahead(&s->conn, s->txb, XS_REC_HDR + pn + XS_TAG, &seglen, now);
    return send(s->conn.fd, seg, seglen, MSG_NOSIGNAL) < 0 ? -1 : 0;
}

/* Поставить устройству новый MTU. Делает это САМ движок в обоих режимах — и в режиме netifd
 * тоже, потому что согласование по определению узнаёт правильное значение позже, чем netifd
 * поднял интерфейс. Значение, заданное человеком в конфигурации, при этом никогда не
 * превышается: если он написал 1380, мы не поставим 1431, даже если путь его несёт. */
static void mtu_apply(struct spoke *s, const char *dev, int mtu, const char *why) {
    if (mtu == s->mtu) return;
    /* Устройство одно на все соединения, поэтому МЕНЯЕТ его только воркер 0 — тот же, что ведёт
     * пробой пути. Иначе несколько потоков дёргали бы `ip link` с разными числами, и на
     * устройстве оставалось бы то, чей вызов пришёл последним. */
    if (s->conn_id) return;
    char val[8];
    snprintf(val, sizeof(val), "%d", mtu);
    const char *a[] = { "ip", "link", "set", "dev", dev, "mtu", val, NULL };
    if (run_quiet(a) != 0) {
        fprintf(stderr, LOG_W "%s: не удалось поставить MTU %d\n", dev, mtu);
        return;
    }
    fprintf(stderr, LOG_I "%s: MTU %d → %d (%s)\n", dev, s->mtu, mtu, why);
    s->mtu = mtu;
    /* Публикуем остальным воркерам: им это нужно для подрезки MSS и для предела чтения из TUN.
     * Читать чужое поле s->mtu они не могут — своё у каждого. */
    g_mtu_now = mtu;
}

/* Начать проверку пути.
 *
 * ПОЧЕМУ ПОВТОРНЫЙ ПРОБОЙ НАЧИНАЕТСЯ С ПРОВЕРКИ УЖЕ НАЙДЕННОГО, А НЕ С ПОПЫТКИ ПОДНЯТЬ.
 * Путь меняется под живой сессией — оператор переключил канал, сменился маршрут, добавился
 * ещё один туннель по дороге, — и меняется он в обе стороны. Поиск, который умеет только
 * поднимать предел, при сузившемся пути оставит нас на прежнем значении: мелкие пакеты
 * ходят, большие пропадают целиком и молча. Поэтому сначала стадия «прежний размер ещё
 * проходит?» (для неизменившегося пути это одна проба и почти нулевая цена), и лишь потом
 * попытка вырасти; не прошла проверка — предел немедленно опускается на безопасный низ, и
 * поиск идёт ВНИЗ от прежнего значения. */
static void probe_start(struct spoke *s, long long now) {
    /* Путь у всех соединений один — тот же канал, тот же хаб, — поэтому проверяет его ОДИН
     * воркер. Четыре независимых пробоя дали бы вчетверо больше служебных кадров и четыре
     * мнения об одном и том же числе. */
    if (s->conn_id) { s->probing = 0; return; }
    s->p_tries = 0;
    s->p_steps = 0;
    s->probe_sent = 0;
    if (s->mtu_confirmed > XS_MTU_FLOOR) {
        s->p_verify = 1;
        s->p_cur = s->mtu_confirmed;
        s->p_lo = XS_MTU_FLOOR;
        s->p_hi = 0;
        s->probing = 1;
    } else {
        s->p_verify = 0;
        s->p_lo = XS_MTU_FLOOR;
        s->p_hi = 0;
        s->p_cur = xs_mtu_next(s->p_lo, s->p_hi, s->mtu_agreed);
        s->probing = s->p_cur > 0;
    }
    (void)now;
}

/* Как часто перепроверять путь. Переменной окружения хватает ровно для стенда: живая звезда
 * меняет путь раз в дни, а стенду нужно увидеть сужение за секунды, и ждать в нём две минуты
 * значило бы, что проверку сужения выключат первой. В настройки это не выносится: числу неоткуда
 * взяться у человека, а неверное сделает пробои заметной долей трафика. */
static long long probe_every(void) {
    const char *e = getenv("STEER_XS_PROBE_MS");
    if (!e) return XS_PROBE_EVERY_MS;
    long v = strtol(e, NULL, 10);
    return v >= 1000 ? (long long)v : 1000;
}

/* Проверка закончена: применить найденное и сообщить хабу. */
static void probe_done(struct spoke *s, const char *dev, long long now) {
    s->probing = 0;
    s->p_verify = 0;
    s->probe_next = now + probe_every();
    if (s->p_lo <= XS_MTU_FLOOR) {
        /* Не подтвердился ни один размер выше низа. Остаёмся на нём — и ГОВОРИМ об этом:
         * молча работать вдвое медленнее возможного это ровно тот отказ, который никто не
         * заметит. Пробы не доходят вовсе либо путь действительно такой узкий. */
        fprintf(stderr, LOG_W "путь не подтвердил ни один размер выше %d — остаюсь на нём. "
                              "Похоже, пробы не доходят вовсе\n", XS_MTU_FLOOR);
        mtu_apply(s, dev, XS_MTU_FLOOR, "путь не подтвердил ничего выше низа");
        s->mtu_confirmed = 0;
        return;
    }
    /* Сравнение — с тем, что СТОИТ НА УСТРОЙСТВЕ, а не с прошлым подтверждённым значением.
     * Разница стоила живого туннеля: после переподключения устройство сидело на безопасном
     * низу, подтверждённое значение осталось прежним, проверка «ничего не изменилось»
     * срабатывала — и туннель оставался на 1200 при пути, несущем 1387, до перезапуска. Ни
     * одной строки в журнале при этом не появлялось. */
    int grew = s->p_lo > s->mtu;
    s->mtu_confirmed = s->p_lo;
    g_mtu_pub = s->p_lo;
    mtu_apply(s, dev, s->p_lo, grew ? "путь подтвердил пробой" : "путь сузился");
    uint8_t fin[8];
    size_t fn2 = xs_mtu_build(fin, sizeof(fin), s->p_lo);
    if (fn2) send_frame(s, fin, fn2, now);
}

static void session_down(struct spoke *s) {
    if (s->up) {
        tls13_keys_free(&s->tx);
        tls13_keys_free(&s->rx);
        memset(&s->tx, 0, sizeof(s->tx));
        memset(&s->rx, 0, sizeof(s->rx));
    }
    s->up = 0;
    xs_conn_close(&s->conn);
}

/* Общий цикл обеих ролей вынесен, чтобы «поднять для выхода спеки» и «поднять на готовом
 * устройстве» отличались ровно тем, чем отличаются: владением устройством и маршрутизацией.
 * Скопировать цикл во второй раз значило бы два места для одной ошибки в пути данных. */
static int spoke_run(struct spoke *s, const char *dev, const char *chain_label, int managed,
                     struct output *o);
static int cmd_xsteer_spec(const char *spec_path, const char *out_name, const char *conf_path);

int cmd_xsteer(const char *spec_path, const char *out_name, const char *conf_path,
               const char *device) {
    static struct spoke sd;
    /* Без имени выхода спека не читается ВОВСЕ: на маршрутизаторе, где туннелем владеет
     * netifd, выходов и каналов может не быть, а требовать спеку ради того, чтобы её не
     * использовать, значило бы требовать настройку, которая ни на что не влияет. */
    if (!out_name || !out_name[0]) {
        if (!conf_path || !device) {
            fprintf(stderr, "steer: без имени выхода нужны --config и --device "
                            "(подсказка: steer xsteer --help)\n");
            return 2;
        }
        char err2[256];
        if (xs_conf_load(conf_path, XS_ROLE_SPOKE, &g_cf, &g_sc, err2, sizeof(err2)) != 0) {
            fprintf(stderr, LOG_W "%s\n", err2);
            return 2;
        }
        sd.conf = &g_cf;
        sd.sec = &g_sc;
        sd.out_name = device;
        snprintf(sd.state_path, sizeof(sd.state_path), "%s/xsteer-%.40s.json",
                 g_state_dir, device);
        return spoke_run(&sd, device, device, 1, NULL);
    }
    return cmd_xsteer_spec(spec_path, out_name, conf_path);
}

static int cmd_xsteer_spec(const char *spec_path, const char *out_name, const char *conf_path) {
    load_spec(spec_path);
    struct output *o = out_by_name(out_name);
    if (!o) die("нет такого выхода: %s", out_name);
    if (o->kind != OUT_XSTEER) die("выход %s не kind=xsteer", out_name);
    /* Реестр нужен ДО подъёма: из него берутся метка и номер таблицы выхода, а их привязка к
     * устройству — работа этого процесса (см. bind_device ниже). Вызов идемпотентен и с apply
     * не спорит: тот же файл, те же номера. Без него метка была бы нулевой, и правило
     * `ip rule fwmark 0x0` поймало бы весь трафик роутера. */
    registry_assign();

    static struct spoke s;
    s.out_name = o->name;
    char err[256];
    const char *path = conf_path ? conf_path : o->xs_conf;
    if (xs_conf_load(path, XS_ROLE_SPOKE, &g_cf, &g_sc, err, sizeof(err)) != 0) {
        fprintf(stderr, LOG_W "%s\n", err);
        return 2;
    }
    s.conf = &g_cf;
    s.sec = &g_sc;
    /* Публичный ключ хаба берётся из конфигурации как есть — он там и лежит публичной
     * половиной, в отличие от нашего собственного. */
    memcpy(s.hub_pub, g_cf.peer[0].pub, 32);
    s.hub_port = g_cf.peer[0].endpoint_port;
    struct in_addr hin;
    if (inet_pton(AF_INET, g_cf.peer[0].endpoint, &hin) != 1) {
        fprintf(stderr, LOG_W "адрес хаба не разобран: %s\n", g_cf.peer[0].endpoint);
        return 2;
    }
    s.hub_addr = hin.s_addr;
    s.mtu = g_cf.mtu ? g_cf.mtu : XS_MTU_DEF;
    snprintf(s.state_path, sizeof(s.state_path), "%s/xsteer-%.40s.json",
             g_state_dir, o->name);

    /* Таблицу к устройству привязывает САМ процесс: apply прошёл раньше, дождаться
     * устройства снаружи нельзя, и момент готовности знает только тот, кто его создал. Тот
     * же довод и тот же приём, что у клиента VLESS. В режиме netifd этого не делается вовсе:
     * маршрутизацией там владеет он, а выход описывается в спеке как обычный interface. */
    return spoke_run(&s, o->device, o->name, 0, o);
}

/* Сколько соединений открывать. По одному на ядро, но не больше XS_CONNS_MAX.
 *
 * ЗАЧЕМ ИХ НЕСКОЛЬКО. Одно поддельное соединение обслуживается одним потоком целиком — так
 * счётчик nonce остаётся его личным, без атомиков и замков в самом опасном месте протокола, —
 * и потому упирается ровно в одно ядро (замерено: около 0,6 Гбит/с на этой машине). Второе
 * соединение — второе ядро.
 *
 * И ВТОРАЯ, НЕ МЕНЕЕ ВАЖНАЯ ПРИЧИНА: хаб раскладывает соединения по своим воркерам по младшим
 * битам порта источника, а порт случайный. При одном соединении на пир два пира с
 * вероятностью 1/2 попадают в один воркер хаба, и его многопоточность не работает вовсе —
 * именно это и показал стенд (0,57 Гбит/с вместо 1,18 на том же коде). Соединения с РАЗНЫМИ
 * младшими битами закрывают это: каждый пир занимает все воркеры хаба поровну. */
static int spoke_conns(void) {
    long cores = sysconf(_SC_NPROCESSORS_ONLN);
    int n = cores > 0 ? (int)cores : 1;
    const char *e = getenv("STEER_XS_CONNS");
    if (e) { long v = strtol(e, NULL, 10); if (v >= 1) n = (int)v; }
    if (n > XS_CONNS_MAX) n = XS_CONNS_MAX;
    if (n < 1) n = 1;
    return n;
}

static void *worker_main(void *arg);

/* Что делать соединению, которое не поднялось.
 *
 * Воркер 0 УХОДИТ, и процесс с ним: подъём заново — дело procd, и его пауза respawn заодно не
 * даёт молотить сеть, которой ещё нет. Это поведение было единственным, пока соединение было
 * одно, и менять его нельзя — на нём стоит и сторож, и respawn.
 *
 * Остальные ЖДУТ и пробуют снова: уронить процесс из-за второго соединения значило бы, что
 * лишний поток сделал туннель ХУЖЕ, чем без него — работающее соединение 0 умерло бы вместе с
 * ним. Пауза та же, что у respawn у procd, чтобы ритм попыток был одинаковым. */
static int worker_give_up(struct spoke *s) {
    if (!s->conn_id) return 1;
    struct timespec ts = { 5, 0 };
    nanosleep(&ts, NULL);
    return 0;
}

/* Установка: одно устройство, одно правило nft, одна привязка таблицы — и N воркеров. */
static int spoke_run(struct spoke *s, const char *dev, const char *chain_label, int managed,
                     struct output *o) {
    if (!s->hub_port) {
        /* Режим netifd: подготовка проще, но те же три величины обязаны быть посчитаны. */
        memcpy(s->hub_pub, s->conf->peer[0].pub, 32);
        s->hub_port = s->conf->peer[0].endpoint_port;
        struct in_addr h2;
        if (inet_pton(AF_INET, s->conf->peer[0].endpoint, &h2) != 1) {
            fprintf(stderr, LOG_W "адрес хаба не разобран: %s\n", s->conf->peer[0].endpoint);
            return 2;
        }
        s->hub_addr = h2.s_addr;
        s->mtu = s->conf->mtu ? s->conf->mtu : XS_MTU_DEF;
    }
    g_conns = spoke_conns();
    /* Очереди TUN: по одной на воркера. Ядро раскладывает пакеты по очередям симметричным
     * хэшем потока, поэтому обе половины одного соединения всегда достаются одному воркеру. */
    struct tun_dev tq[XS_CONNS_MAX];
    int nq = tun_up_queues(s, tq, g_conns, dev, managed);
    if (nq < 0) return 1;
    /* MTU, заданный человеком, — это ПРЕДЕЛ, а не значение: согласование никогда не поднимет
     * выше него. Если он не задан, предел ставит только канал и путь. */
    s->mtu_cap = s->conf->mtu;
    g_mtu_now = s->mtu;
    /* Правило против RST собственного ядра: без него стек роутера сам рвёт нашу сессию.
     * Цепочка своя (вид 'x'), таблица общая с обфускатором — имя её историческое. Правило одно
     * на все соединения: оно описано портом ХАБА, а не нашим. */
    if (obfs_guard_up('x', chain_label, s->conf->peer[0].endpoint, s->hub_port, 0) != 0)
        fprintf(stderr, LOG_W "%s: правило против RST не встало — сессию может оборвать "
                              "собственное ядро (нет nft?)\n", chain_label);
    if (o) bind_device(o, dev);

    /* Воркер 0 — этот же поток: при одном соединении процесс ведёт себя ровно так, как до
     * появления потоков, и отладка одного потока остаётся возможной. */
    for (int i = 0; i < g_conns; i++) {
        if (i) {
            g_sp[i] = *s;                       /* общие величины: конфигурация по указателю */
            memset(&g_sp[i].conn, 0, sizeof(g_sp[i].conn));
            g_sp[i].up = 0;
            g_sp[i].up_pkts = g_sp[i].down_pkts = g_sp[i].up_bytes = g_sp[i].down_bytes = 0;
            g_sp[i].dropped = 0;
            g_sp[i].probing = 0;
            g_sp[i].probe_next = 0;
            g_sp[i].mtu_confirmed = 0;
        } else {
            g_sp[0] = *s;
        }
        g_sp[i].conn_id = i;
        g_sp[i].tun = tq[i % nq];
        g_sp[i].dev = dev;
        g_sp[i].managed = managed;
    }
    if (g_conns > 1)
        fprintf(stderr, LOG_I "%s: соединений к хабу %d (по одному на ядро), очередей TUN %d\n",
                dev, g_conns, nq);
    pthread_t th[XS_CONNS_MAX];
    for (int i = 1; i < g_conns; i++)
        if (pthread_create(&th[i], NULL, worker_main, &g_sp[i]) != 0) {
            fprintf(stderr, LOG_W "поток соединения %d не создался: работаем меньшим числом\n", i);
            g_sp[i].conn_id = -1;
        }
    return (int)(intptr_t)worker_main(&g_sp[0]);
}

/* Цикл одного соединения. */
static void *worker_main(void *arg) {
    struct spoke *s = arg;
    const char *dev = s->dev;
    long long last_state = 0, last_keep = 0;
    int keepalive_ms = s->conf->peer[0].keepalive * 1000;

    for (;;) {
        if (!s->up) {
            if (s->conn.state == XSC_CLOSED &&
                xs_conn_open(&s->conn, s->hub_addr, s->hub_port, s->conn_id) != 0) {
                fprintf(stderr, LOG_W "сырой сокет недоступен: %s\n", strerror(errno));
                if (worker_give_up(s)) return (void *)1;
                continue;
            }
            /* Печатается ВСЕГДА и до ожидания. Первая версия молчала до конца рукопожатия,
             * и «пир ничего не делает» было не отличить от «SYN не уходит»: ровно на это
             * ушёл первый прогон живого стенда. Знать надо до замеров, а не после. */
            fprintf(stderr, LOG_I "подключаюсь к %s:%d с порта %u\n",
                    s->conf->peer[0].endpoint, s->hub_port, s->conn.sport);
            /* Ждём установления поддельного TCP, потом здороваемся. */
            long long deadline = xs_now_ms() + XSC_SYN_RETRY_MS * XSC_SYN_RETRIES;
            while (s->conn.state != XSC_EST && xs_now_ms() < deadline) {
                struct pollfd p = { s->conn.fd, POLLIN, 0 };
                poll(&p, 1, XSC_TICK_MS);
                if (p.revents & POLLIN) {
                    uint8_t pkt[XS_ROW];
                    ssize_t r = recv(s->conn.fd, pkt, sizeof(pkt), 0);
                    struct obfs_seg seg;
                    if (r > 0 && obfs_parse(pkt, (size_t)r, &seg) == 0 &&
                        seg.sport == s->conn.dport && seg.dport == s->conn.sport) {
                        if (xs_conn_on_seg(&s->conn, &seg, xs_now_ms()) < 0) {
                            /* RST на поддельный SYN — это ОТВЕТ, и он говорит больше, чем
                             * тишина: на порту либо нет нашего хаба, либо у него не встало
                             * правило против RST, и его же ядро рвёт нам сессию. Сказать это
                             * надо здесь: иначе видно только «не отвечает». */
                            fprintf(stderr, LOG_W "%s:%d ответил RST — на этом порту не наш "
                                                  "хаб, либо у него не встало правило против "
                                                  "RST собственного ядра\n",
                                    s->conf->peer[0].endpoint, s->hub_port);
                            break;
                        }
                    }
                }
                xs_conn_tick(&s->conn, xs_now_ms(), 0);
            }
            if (s->conn.state == XSC_EST) {
    /* Предел по каналу считается от НАСТОЯЩЕГО интерфейса, через который мы уходим, а не от
     * предположения «1500»: на PPPoE это 1492, и разница в 8 байт — ровно тот случай, когда
     * большие пакеты пропадают молча. */
    s->mtu_limit = 0;
    {
        char ifn[32] = "";
        int link = xs_egress_mtu(s->conn.saddr, ifn, sizeof(ifn));
        if (link > 0) {
            s->mtu_limit = xs_mtu(link);
            snprintf(s->link_if, sizeof(s->link_if), "%s", ifn);
        }
    }
            }
            if (s->conn.state != XSC_EST) {
                /* Молчаливого выхода здесь быть не должно. Первая версия просто возвращала 1,
                 * и на живом роутере это выглядело так: «подключаюсь…» — и всё, процесса нет,
                 * причины нет. А причина типовая: на той стороне никто не слушает, либо её
                 * ядро отвечает RST (у хаба не встало правило против RST), либо путь режут. */
                fprintf(stderr, LOG_W "%s:%d не отвечает на поддельный SYN (%d попыток): "
                                      "хаб не запущен, порт закрыт, или у хаба не встало "
                                      "правило против RST собственного ядра\n",
                        s->conf->peer[0].endpoint, s->hub_port, XSC_SYN_RETRIES);
                session_down(s);
                if (!s->conn_id) state_write(s);
                if (worker_give_up(s)) return (void *)1;
                continue;
            }
            if (do_handshake(s) != 0) {
                session_down(s);
                if (!s->conn_id) state_write(s);
                if (worker_give_up(s)) return (void *)1;
                continue;
            }
            /* НАЧИНАЕМ С БЕЗОПАСНОГО НИЗА, и это главный урок, взятый у veil (engine/pmtu.go):
             * пока проба не подтвердила размер, каждый полноразмерный пакет рискует уйти в ту
             * самую чёрную дыру, которую мы ищем. Низ несёт любой реальный путь, поэтому
             * туннель работает сразу, просто пока не на полную.
             *
             * НО ТОЛЬКО НА ПЕРВОМ рукопожатии. Переподключение к тому же хабу по тому же
             * каналу происходит по причинам, к пути не относящимся (тишина, смена ключей,
             * перезапуск хаба), и путь при этом тот самый, который мы уже измерили. Ронять
             * MTU на низ при каждом переподключении значило бы платить провалом скорости за
             * событие, которое к MTU отношения не имеет; проверку прежнего значения делает
             * первая же проба и стоит она 300 мс. Риск назван прямо: если путь всё-таки
             * сузился ИМЕННО в этот момент, полноразмерные пакеты пропадают эти 300 мс. */
            if (!s->mtu_confirmed && s->mtu_agreed > XS_MTU_FLOOR && s->mtu > XS_MTU_FLOOR)
                mtu_apply(s, dev, XS_MTU_FLOOR, "начинаю с безопасного низа, проверяю путь");
            probe_start(s, xs_now_ms());
            state_write(s);
        }

        struct pollfd fds[2] = { { s->tun.fd, POLLIN, 0 }, { s->conn.fd, POLLIN, 0 } };
        int n = poll(fds, 2, XSC_TICK_MS);
        long long now = xs_now_ms();
        if (n < 0 && errno != EINTR) break;

        /* ---- наружу: TUN → поддельный TCP ---------------------------------- */
        if (n > 0 && (fds[0].revents & POLLIN)) {
            int k = 0;
            unsigned long long payload = 0;
            for (int i = 0; i < XSC_BATCH; i++) {
                /* Чтение TUN пачкой возможно только по одному вызову на пакет: это
                 * символьное устройство, recvmmsg к нему не применим. Зато отправка —
                 * одна на всю пачку. */
                ssize_t r = tun_read_packet(&s->tun, s->tb[k] + XS_HDR_ROOM, (size_t)s->mtu);
                if (r <= 0) break;
                /* Подрезка MSS в ОБОИХ направлениях, и это не перестраховка: сюда приходят
                 * SYN от узлов локальной сети, а из туннеля — SYN-ACK от узлов интернета,
                 * которые объявляют MSS по СВОЕМУ каналу и ничего не знают про наш. Не
                 * подрезав встречный, мы получили бы ровно тот отказ, от которого защищаемся:
                 * рукопожатие проходит, а первая же полная страница данных пропадает. */
                xs_mss_clamp(s->tb[k] + XS_HDR_ROOM, (size_t)r, s->mtu);
                uint32_t rel = xs_conn_rel_next(&s->conn);
                uint8_t *rec = s->tb[k] + XS_HDR_ROOM - XS_REC_HDR;
                if (xs_rec_build(rec, (size_t)r + XS_TAG) != 0) { s->dropped++; continue; }
                if (tls13_aead_seal(&s->tx, rel, rec, XS_REC_HDR, s->tb[k] + XS_HDR_ROOM,
                                    (size_t)r, s->tb[k] + XS_HDR_ROOM + r) != 0) {
                    s->dropped++;
                    continue;
                }
                size_t seglen = 0;
                uint8_t *seg = xs_conn_ahead(&s->conn, s->tb[k], XS_REC_HDR + (size_t)r + XS_TAG,
                                             &seglen, now);
                s->tiov[k].iov_base = seg;
                s->tiov[k].iov_len = seglen;
                memset(&s->tmm[k].msg_hdr, 0, sizeof(s->tmm[k].msg_hdr));
                s->tmm[k].msg_hdr.msg_iov = &s->tiov[k];
                s->tmm[k].msg_hdr.msg_iovlen = 1;
                payload += (unsigned long long)r;
                k++;
                /* Ретайр: смещение подошло к пределу или соединение старое. Замолчать
                 * ОБЯЗАНЫ — иначе повтор nonce. */
                if (xs_retire_due(xs_conn_rel_next(&s->conn), now - s->conn.born)) break;
            }
            if (k > 0) {
                /* ЧАСТИЧНАЯ ОТПРАВКА ДОСЫЛАЕТСЯ, А НЕ СЧИТАЕТСЯ ПОТЕРЕЙ.
                 *
                 * sendmmsg отправляет СКОЛЬКО СМОГ и возвращает это число: очередь сокета
                 * заполняется, и на скорости это происходит постоянно. Первая версия молча
                 * записывала остаток в потери — и вот что это стоило на живом роутере: канал
                 * 200 Мбит, процессор занят на 10%, а iperf показывал 0,25 Мбит/с при сотнях
                 * потерь за шесть секунд. Потому что у нас нет повторной передачи: каждая
                 * недосланная датаграмма — это дырка во внутреннем TCP, а одна дырка на
                 * шестнадцать пакетов обрушивает окно до нуля.
                 *
                 * Поэтому досылаем хвост, а «нет прогресса дважды подряд» считаем настоящей
                 * потерей — иначе один неотправляемый пакет (например, слишком большой)
                 * заклинил бы цикл навсегда. */
                int off = 0, stuck = 0;
                while (off < k) {
                    int sent = sendmmsg(s->conn.fd, &s->tmm[off], (unsigned)(k - off), 0);
                    if (sent > 0) { off += sent; stuck = 0; continue; }
                    if (++stuck >= 3) break;
                    if (errno != EAGAIN && errno != ENOBUFS && errno != EINTR) break;
                }
                s->up_pkts += (unsigned long long)off;
                s->up_bytes += payload;
                if (off < k) {
                    s->dropped += (unsigned long long)(k - off);
                    /* Причину называем, но не чаще раза в секунду: поток сообщений об одной
                     * и той же беде не помогает, а мешает — тот же приём, что у обфускатора. */
                    if (now - s->last_drop_warn >= 1000) {
                        fprintf(stderr, LOG_W "отправка не прошла (%s): потеряно %d из %d "
                                              "пакетов пачки\n", strerror(errno), k - off, k);
                        s->last_drop_warn = now;
                    }
                }
            }
            if (s->up && xs_retire_due(xs_conn_rel_next(&s->conn), now - s->conn.born)) {
                fprintf(stderr, LOG_I "смена ключей: поднимаю соединение заново\n");
                session_down(s);
            }
        }

        /* ---- обратно: поддельный TCP → TUN --------------------------------- */
        if (s->up && n > 0 && (fds[1].revents & POLLIN)) {
            for (;;) {
                for (int i = 0; i < XSC_BATCH; i++) {
                    s->iov[i].iov_base = s->rx_buf[i];
                    s->iov[i].iov_len = XS_ROW;
                    memset(&s->mm[i].msg_hdr, 0, sizeof(s->mm[i].msg_hdr));
                    s->mm[i].msg_hdr.msg_iov = &s->iov[i];
                    s->mm[i].msg_hdr.msg_iovlen = 1;
                }
                int got = recvmmsg(s->conn.fd, s->mm, XSC_BATCH, MSG_DONTWAIT, NULL);
                if (got <= 0) break;
                for (int i = 0; i < got; i++) {
                    struct obfs_seg seg;
                    if (obfs_parse(s->rx_buf[i], s->mm[i].msg_len, &seg) != 0) continue;
                    if (seg.sport != s->conn.dport || seg.dport != s->conn.sport) continue;
                    int what = xs_conn_on_seg(&s->conn, &seg, now);
                    if (what < 0) { session_down(s); break; }
                    if (what != 1) continue;
                    /* Предфильтр до всякой криптографии: три сравнения отбивают чужое. */
                    const uint8_t *body;
                    size_t body_n;
                    if (xs_rec_parse(seg.payload, seg.plen, &body, &body_n) != 0) continue;
                    uint32_t rel = xs_conn_rel_of(&s->conn, seg.seq);
                    if (xs_win_check(&s->win, rel) != 0) continue;
                    uint8_t *ct = (uint8_t *)(uintptr_t)body;
                    if (tls13_aead_open(&s->rx, rel, seg.payload, XS_REC_HDR, ct, body_n) != 0)
                        continue;
                    /* Коммит окна ТОЛЬКО после сошедшегося тега: иначе подделанный пакет с
                     * далёким смещением выбил бы из окна весь честный поток. */
                    xs_win_commit(&s->win, rel);
                    size_t pn = body_n - XS_TAG;
                    enum xs_kind kind = xs_frame_kind(ct, pn);
                    if (kind == XS_IPV4 || kind == XS_IPV6) {
                        xs_mss_clamp(ct, pn, s->mtu);
                        tun_write_ctl(&s->tun, ct, pn);
                        s->down_pkts++;
                        s->down_bytes += pn;
                    } else if (kind == XS_CTL) {
                        int acked = xs_pack_size(ct, pn);
                        if (acked > 0 && s->probing && acked == s->p_cur) {
                            /* Размер вернулся эхом — путь его несёт. Двигаем нижнюю границу и
                             * спрашиваем, есть ли смысл проверять дальше. */
                            s->p_lo = acked;
                            s->p_tries = 0;
                            s->p_verify = 0;      /* прежнее значение подтверждено — растём */
                            s->p_cur = xs_mtu_next(s->p_lo, s->p_hi, s->mtu_agreed);
                            if (!s->p_cur || ++s->p_steps > XS_MTU_TRIES_MAX)
                                probe_done(s, dev, now);
                            else
                                s->probe_sent = 0;
                        }
                    }
                    /* keepalive молча учтён: он уже обновил last_rx. */
                }
                if (got < XSC_BATCH) break;
            }
        }

        if (!s->up) continue;

        /* ---- согласование MTU: проверка пути пробами ------------------------
         *
         * Пока проба не подтвердила размер, на устройстве стоит безопасный низ: до этого
         * момента любой полноразмерный пакет рискует уйти в чёрную дыру, которую мы и ищем.
         * Порядок «сначала опустить, потом поднимать» взят у veil (engine/pmtu.go) — там это
         * уже проходили, и обратный порядок стоил им как раз тех потерь. */
        if (s->probing) {
            if (!s->probe_sent || now - s->probe_sent >= XS_PROBE_WAIT_MS) {
                if (s->probe_sent && ++s->p_tries >= XS_PROBE_TRIES) {
                    /* Не подтвердился после повторов — считаем размер непроходящим. Повторы
                     * обязательны: у пробы нет повторной передачи, и одна случайная потеря не
                     * должна означать «путь этого не несёт». */
                    s->p_hi = s->p_cur;
                    s->p_tries = 0;
                    if (s->p_verify) {
                        /* Прежнее значение больше не проходит. Опускаемся НЕМЕДЛЕННО, не
                         * дожидаясь конца поиска: пока он идёт, каждый полный пакет пропадал
                         * бы. Дальше поиск сам поднимет до нового настоящего предела. */
                        s->p_verify = 0;
                        fprintf(stderr, LOG_W "путь больше не несёт %d — опускаюсь на %d и "
                                              "ищу новый предел\n", s->p_cur, XS_MTU_FLOOR);
                        mtu_apply(s, dev, XS_MTU_FLOOR, "путь сузился, ищу новый предел");
                    }
                    s->p_cur = xs_mtu_next(s->p_lo, s->p_hi, s->mtu_agreed);
                    if (!s->p_cur || ++s->p_steps > XS_MTU_TRIES_MAX) {
                        probe_done(s, dev, now);
                        continue;
                    }
                }
                static uint8_t probe[XS_ROW];
                if (xs_probe_build(probe, sizeof(probe), s->p_cur) == s->p_cur)
                    send_frame(s, probe, (size_t)s->p_cur, now);
                s->probe_sent = now;
            }
        } else if (s->probe_next && now >= s->probe_next) {
            /* Повторная проверка под живой сессией: путь меняется (смена маршрута у
             * провайдера, переход между точками WiFi), и без этого суженный путь глотал бы
             * полноразмерные кадры до конца сессии. */
            probe_start(s, now);
        }
        /* Соединения кроме нулевого: подхватываем согласованный MTU и НАЗЫВАЕМ его хабу.
         * Назвать обязательно: у каждого соединения на хабе своя сессия, и подрезку MSS для
         * обратного трафика хаб делает по MTU ТОЙ сессии, в которую отправляет. Не сказав, мы
         * получили бы «через одно соединение большие пакеты ходят, через другое нет». */
        if (s->conn_id) {
            if (g_mtu_now > 0 && s->mtu != g_mtu_now) s->mtu = g_mtu_now;
            if (g_mtu_pub > 0 && s->mtu_told != g_mtu_pub) {
                uint8_t fin[8];
                size_t fn = xs_mtu_build(fin, sizeof(fin), g_mtu_pub);
                if (fn && send_frame(s, fin, fn, now) == 0) s->mtu_told = g_mtu_pub;
            }
        }
        /* «Активная отправка» — это «мы отправили ПОСЛЕ того, как получили», а не «мы вообще
         * когда-нибудь отправляли». Разница принципиальна: со вторым условием туннель на
         * покое, однажды отправивший пакет, считался бы мёртвым навсегда. */
        if (xs_conn_tick(&s->conn, now, s->conn.last_tx > s->conn.last_rx)) {
            fprintf(stderr, LOG_W "путь молчит %d мс при активной отправке — поднимаю "
                                  "соединение заново\n", XSC_DEAD_MS);
            session_down(s);
            continue;
        }
        /* Keepalive: пустая запись. Пир за NAT обязана поддерживать отображение живым,
         * потому что дозвониться до неё хаб не может. */
        if (keepalive_ms && now - s->conn.last_tx >= keepalive_ms) {
            uint32_t rel = xs_conn_rel_next(&s->conn);
            uint8_t *rec = s->txb + XS_HDR_ROOM - XS_REC_HDR;
            if (xs_rec_build(rec, XS_TAG) == 0 &&
                tls13_aead_seal(&s->tx, rel, rec, XS_REC_HDR, s->txb + XS_HDR_ROOM, 0,
                                s->txb + XS_HDR_ROOM) == 0) {
                size_t seglen = 0;
                uint8_t *seg = xs_conn_ahead(&s->conn, s->txb, XS_REC_HDR + XS_TAG, &seglen, now);
                (void)!send(s->conn.fd, seg, seglen, MSG_NOSIGNAL);
            }
        }
        if (!s->conn_id && now - last_state >= 2000) { state_write(s); last_state = now; }
        (void)last_keep;
    }
    session_down(s);
    if (!s->conn_id) xs_conf_wipe(s->sec);
    return (void *)1;
}

/* ---- пиры и ключи ----------------------------------------------------------- */

int cmd_xsteer_peers(const char *spec_path, const char *out_name, const char *conf_path) {
    load_spec(spec_path);
    struct output *o = out_by_name(out_name);
    if (!o) die("нет такого выхода: %s", out_name);
    if (o->kind != OUT_XSTEER) die("выход %s не kind=xsteer", out_name);
    struct xs_conf c;
    struct xs_secrets sec;
    char err[256];
    const char *path = conf_path ? conf_path : o->xs_conf;
    if (xs_conf_load(path, XS_ROLE_SPOKE, &c, &sec, err, sizeof(err)) != 0) {
        fprintf(stderr, LOG_W "%s\n", err);
        return 2;
    }
    /* Секреты не нужны для печати и потому затираются СРАЗУ, до вывода: так «в выводе нет
     * приватного ключа» становится свойством порядка операций, а не обещанием. */
    xs_conf_wipe(&sec);
    xs_conf_json(stdout, &c);
    printf("\n");
    /* Живое состояние лежит рядом, в файле, который пишет сам процесс. Печатаем его как есть
     * — разбирать нечего, а склеивать два JSON в один значило бы завести формат, который
     * придётся согласовывать с интерфейсом отдельно. */
    char sp[320];
    snprintf(sp, sizeof(sp), "%s/xsteer-%.40s.json", g_state_dir, o->name);
    FILE *f = fopen(sp, "r");
    if (!f) return 1;              /* состояния нет: рукопожатий не было */
    char line[1024];
    if (fgets(line, sizeof(line), f)) fputs(line, stdout);
    fclose(f);
    return 0;
}
