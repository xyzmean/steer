/* Цикл туннеля: пакеты из TUN — в потоки VLESS и обратно.
 *
 * Ядро отдаёт нам IP-пакеты, а сервер VLESS принимает соединения. Разрыв между этими двумя
 * представлениями и есть содержание этого файла: на каждое TCP-соединение из TUN мы
 * открываем свой поток VLESS и дальше переносим байты, подтверждая клиенту приём так, как
 * это сделал бы настоящий стек.
 *
 * Почему это НЕ полный стек TCP и почему так можно. Мы не реализуем повторную передачу,
 * управление окном и алгоритмы перегрузки — их делает клиент на своей стороне и сервер на
 * своей. Наша задача уже: подтвердить SYN, принимать данные по порядку, отдавать полученное
 * и закрыть соединение. Всё, что требует памяти о неподтверждённых байтах, живёт в ядре
 * клиента, а не здесь — поэтому на роутере с 15 МБ это остаётся дешёвым.
 *
 * Плата за это названа прямо: пакет, пришедший не по порядку, отбрасывается вместо
 * буферизации. В локальной сети до роутера потери редки, а буфер переупорядочивания на
 * каждое соединение — это как раз та память, которой на слабой коробке нет.
 */
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <time.h>
#include <arpa/inet.h>

#include "vless.h"
#include "client.h"
#include "vless_proto.h"
#include "vision.h"
#include "tls13.h"
#include "tun.h"
#include "tunnel.h"
#include "../spec.h"

/* Сколько соединений держим одновременно. Каждое — это сокет к серверу плюс TLS-состояние,
 * то есть около 3 КБ; 64 соединения это ~200 КБ, что для роутера с 15 МБ приемлемо, а для
 * домашней сети более чем достаточно. Упираться в предел лучше заметно (новые соединения
 * получают отказ), чем незаметно съесть память и быть убитым OOM. */
#define MAX_CONNS 64

struct conn {
    int used;
    struct flow_key key;
    struct vless_conn v;
    struct vision vis;
    unsigned char uuid[16];
    /* Порядковые номера с точки зрения КЛИЕНТА: what we ack, what we send. */
    uint32_t client_seq;      /* следующий ожидаемый от клиента */
    uint32_t our_seq;         /* следующий, который отправим клиенту */
    int header_sent;          /* заголовок VLESS уже ушёл серверу */
    int established;
    /* Сколько из отправленного клиент подтвердил и сколько он готов принять. Нужно потому,
     * что повторной передачи у нас нет: сегмент, потерянный из-за переполнения очереди
     * устройства, не будет отправлен заново никогда, и соединение повиснет навсегда —
     * клиент будет подтверждать старое, а мы отдавать новое. */
    uint32_t client_ack;
    uint16_t client_win;
    uint8_t client_wscale;    /* множитель из опций SYN: окно = client_win << wscale */
    time_t last;
};

/* Сколько неподтверждённых байт разрешаем себе держать в пути.
 *
 * Не «сколько объявил клиент», а МИНИМУМ из его окна и этого числа. Предел нужен потому,
 * что повторной передачи у нас нет: очередь устройства TUN — около пятисот пакетов, и
 * обогнав её, мы теряем сегмент навсегда.
 *
 * Почему именно столько. Скорость здесь равна «окно, поделённое на задержку
 * подтверждения»: при подтверждениях раз в пять миллисекунд 32 КБ дают 6 МБ/с и ни байтом
 * больше — сколько бы ни держала полоса. 256 КБ при той же задержке дают ~50 МБ/с, а в
 * очередь устройства укладываются с запасом (180 пакетов из 500).
 *
 * Замерено, почему предел вообще нужен и почему одного его мало: без него передача на
 * роутере вставала на втором мегабайте; с ним, но без вычерпывания сокета — 3 Мбит/с;
 * с вычерпыванием и 32 КБ — 42 Мбит/с. Порядок важен: увеличивать окно, не научившись
 * вычерпывать, бессмысленно, и первая попытка это подтвердила — стало хуже. */
#define CLIENT_INFLIGHT_CAP (256 * 1024)

/* Сколько клиент готов принять СЕЙЧАС, с учётом множителя окна и нашего предела. Одна
 * функция вместо трёх копий одного вычисления: разойдясь, они дали бы либо остановку на
 * пустом месте, либо обгон клиента с потерей сегмента. */
static uint32_t client_room(const struct conn *c) {
    uint32_t win = (uint32_t)c->client_win << c->client_wscale;
    return win < CLIENT_INFLIGHT_CAP ? win : CLIENT_INFLIGHT_CAP;
}

/* Сколько записей подряд читаем у одного соединения за проход цикла.
 *
 * Не «сколько влезет»: цикл один на все соединения, и одно активное скачивание не должно
 * замораживать остальные. Восемь записей — это до 128 КБ за проход, чего хватает, чтобы
 * окно сервера не закрывалось, и мало, чтобы соседи ждали дольше миллисекунд. */
#define DRAIN_MAX_RECORDS 8

static struct conn g_conns[MAX_CONNS];

/* Диагностика включается переменной окружения: в обычной работе поток пакетов заливает
 * лог, а при разборе «почему соединение не встаёт» видеть каждый шаг необходимо. */
static int g_trace;
#define TR(...) do { if (g_trace) fprintf(stderr, "tun: " __VA_ARGS__); } while (0)

static struct conn *conn_find(const struct flow_key *k) {
    for (int i = 0; i < MAX_CONNS; i++) {
        struct conn *c = &g_conns[i];
        if (!c->used) continue;
        if (c->key.src == k->src && c->key.dst == k->dst &&
            c->key.sport == k->sport && c->key.dport == k->dport)
            return c;
    }
    return NULL;
}

static struct conn *conn_new(void) {
    for (int i = 0; i < MAX_CONNS; i++)
        if (!g_conns[i].used) return &g_conns[i];
    return NULL;
}

static void conn_drop(struct conn *c) {
    TR("закрываю conn#%ld fd=%d\n", (long)(c - g_conns), c->v.fd);
    if (c->used) vless_close(&c->v);
    memset(c, 0, sizeof(*c));
}

/* Отправить серверу данные в правильной форме: с заголовком VLESS на первом кадре и в
 * обёртке Vision, если узел её требует.
 *
 * Три исхода, а не два: «ушло», «сейчас нельзя, повторите» и «всё сломалось». Средний
 * появился вместе с HTTP/2, где закрытое окно — нормальное состояние, а не сбой, и
 * путать его с отказом значит разрывать рабочее соединение. */
#define SEND_OK    0
#define SEND_AGAIN 1
#define SEND_FATAL (-1)

static int upstream_send(struct conn *c, const struct vless_node *node,
                         const unsigned char *data, size_t n) {
    static unsigned char out[TUNNEL_BUF];
    size_t len = 0;

    if (!c->header_sent) {
        /* Адрес назначения берём из пакета: имени у нас нет, клиент уже разрешил его сам
         * (или через наш резолвер, который вернул fake-IP и подменит адрес в DNAT). */
        unsigned char ip4[4];
        memcpy(ip4, &c->key.dst, 4);
        /* dport уже в хостовом порядке — см. комментарий в tun.h. */
        len = vless_build_request(c->uuid, VLESS_CMD_TCP, NULL, ip4,
                                  c->key.dport, node->flow, out, sizeof(out));
        if (!len) return SEND_FATAL;
    }

    if (node->flow[0]) {
        static unsigned char framed[TUNNEL_BUF];
        size_t fn = vision_wrap(&c->vis, data, n, framed, sizeof(framed));
        if (!fn) return SEND_FATAL;
        if (len + fn > sizeof(out)) return SEND_FATAL;
        memcpy(out + len, framed, fn);
        len += fn;
    } else {
        if (len + n > sizeof(out)) return SEND_FATAL;
        memcpy(out + len, data, n);
        len += n;
    }

    /* Через vless_send: упаковку транспорта знает клиент, а не туннель. */
    int rc = vless_send(&c->v, out, len);
    if (rc == H2_EWINDOW) {
        /* Окно HTTP/2 закрыто: сервер не успевает принимать. Это НЕ отказ — это то, для
         * чего управление потоком и существует. Ничего не ушло (h2_write либо отправляет
         * всё, либо ничего), поэтому достаточно не подтверждать пакет: клиент повторит
         * его сам, как при потере, и повторит уже тогда, когда окно откроется.
         *
         * Первая версия считала это ошибкой и разрывала соединение. Выглядело как
         * «выгрузка обрывается на случайном месте» — месте, где сервер впервые не успел. */
        return SEND_AGAIN;
    }
    if (rc) return SEND_FATAL;
    /* Заголовок отмечаем отправленным только теперь: пометить раньше значило бы, что
     * повторная попытка уйдёт без него, и сервер не поймёт, куда соединять. */
    c->header_sent = 1;
    return SEND_OK;
}

/* Прочитать у сервера и отдать клиенту как TCP-пакет. */
static int downstream_pump(struct conn *c, const struct vless_node *node, int tun_fd) {
    /* Статический, а не на стеке: буфер размером с запись TLS — это шестнадцать килобайт
     * стека на каждый вызов, а поток обработки здесь один. */
    static unsigned char buf[TUNNEL_BUF];
    size_t got = 0;
    /* Через vless_recv, а не tls13_read напрямую: у grpc и xhttp между TLS и VLESS лежит
     * HTTP/2, и чтение мимо него отдавало бы кадры вместо данных. Прямой вызов работал,
     * пока транспорт был единственный, и это ровно тот случай, когда «работает» и
     * «правильно» разошлись молча. */
    TR("чтение conn#%ld fd=%d\n", (long)(c - g_conns), c->v.fd);
    int rc = vless_recv(&c->v, buf, sizeof(buf), &got);
    if (rc) { TR("чтение от сервера: rc=%d\n", rc); return rc; }
    /* Ноль байт — законно: приехал служебный кадр HTTP/2, данных пока нет. Принять это за
     * конец потока значило бы разрывать соединение на первом же SETTINGS. */
    if (!got) { TR("служебный кадр, данных нет\n"); return 0; }
    TR("от сервера %zu байт\n", got);

    /* Порядок разбора: сначала заголовок ОТВЕТА VLESS, потом кадры Vision.
     *
     * Сервер отвечает так: [версия|длина_доп|доп] и только ДАЛЬШЕ поток в кадрах Vision.
     * Заголовок ответа обёрткой не покрыт, и первая версия пыталась развернуть его как
     * кадр: получала «00 00 96 67 ad» (версия 0, длина 0, начало данных), длины кадра
     * выходили бессмысленные, unwrap возвращал EAGAIN, и ответ терялся целиком.
     *
     * Это зеркало ошибки на отправке: там заголовок ЗАПРОСА тоже идёт до кадра, а не
     * внутри него. Один и тот же принцип, который я дважды прочитал наоборот. */
    const unsigned char *cur = buf;
    size_t left = got;

    if (!c->established) {
        size_t skip = 0;
        if (vless_parse_response(cur, left, &skip) != 0) {
            TR("ответ VLESS не разобран (%zu байт)\n", left);
            return -1;
        }
        cur += skip;
        left -= skip;
        c->established = 1;
        TR("заголовок ответа снят (%zu байт), осталось %zu\n", skip, left);
    }

    unsigned char payload[TUNNEL_BUF];
    size_t total = 0;

    while (left) {
        const unsigned char *p = cur;
        size_t pn = left;

        if (node->flow[0]) {
            size_t used = 0;
            const unsigned char *pl = NULL;
            size_t pl_n = 0;
            int ur = vision_unwrap(&c->vis, cur, left, &used, &pl, &pl_n);
            if (ur != 0 || !used) {
                /* Разбор больше не может «не хватить данных»: он потоковый и переносит
                 * состояние между вызовами. Сюда попадаем только на настоящей ошибке —
                 * недопустимой команде в кадре. */
                TR("кадр не разобран: ur=%d осталось %zu\n", ur, left);
                break;
            }
            p = pl;
            pn = pl_n;
            cur += used;
            left -= used;

        } else {
            cur += left;
            left = 0;
        }

        if (pn) {
            if (total + pn > sizeof(payload)) break;
            memcpy(payload + total, p, pn);
            total += pn;
        }
    }

    /* Сервер объявил прямое копирование — сообщаем об этом соединению, чтобы следующее
     * чтение шло мимо расшифровки. Ставится ЗДЕСЬ, потому что команда живёт в кадрах
     * Vision, а про них знает только этот код. */
    if (c->vis.recv_direct && !c->v.rx_direct) {
        c->v.rx_direct = 1;
        TR("сервер перешёл на прямое копирование — читаем сокет как есть\n");
    }

    if (!total) { TR("после разбора данных нет\n"); return 0; }

    /* Нарезаем на сегменты по MSS. Обязательно: за один раз от сервера приезжает до целой
     * записи TLS — шестнадцать килобайт, — а MTU устройства 1500. Пакет больше MTU ядро в
     * TUN не принимает, write возвращает ошибку, и данные пропадают.
     *
     * Именно так и ломалось: короткие ответы проходили, а длинная передача встаёт, как
     * только сервер переходит на записи полного размера. Локально спотыкалось на 34 МБ, на
     * роутере на 16 — то есть «работает, но не до конца», причём место обрыва каждый раз
     * другое. Отдавать клиенту гигантский сегмент нельзя ещё и по существу: мы синтезируем
     * TCP, и MSS для него не рекомендация. */
    static unsigned char pkt[TUNNEL_BUF];
    size_t sent = 0;
    while (sent < total) {
        size_t chunk = total - sent > TUN_MSS ? (size_t)TUN_MSS : total - sent;
        /* Отвечаем от имени сервера: адреса и порты наоборот. */
        size_t len = tcp_build(pkt, sizeof(pkt), c->key.dst, c->key.src,
                               c->key.dport, c->key.sport,
                               c->our_seq, c->client_seq, TCP_ACK | TCP_PSH,
                               payload + sent, chunk, 65535, 0);
        if (!len) return -1;
        if (write(tun_fd, pkt, len) < 0) {
            TR("запись в TUN не удалась (%zu байт): %s\n", len, strerror(errno));
            return -1;
        }
        c->our_seq += (uint32_t)chunk;
        sent += chunk;
    }
    TR("клиенту %zu байт (%zu сегментов, seq до %u)\n",
       total, (total + TUN_MSS - 1) / TUN_MSS, c->our_seq);
    return 0;
}

/* Один пакет из TUN. */
static void handle_packet(int tun_fd, const struct vless_node *node,
                          const unsigned char *pkt, size_t n) {
    struct flow_key k;
    size_t off = 0;
    if (ip_parse(pkt, n, &k, &off) != 0) { TR("пакет не разобран (%zu байт)\n", n); return; }
    TR("%u.%u.%u.%u:%u -> %u.%u.%u.%u:%u proto=%u flags=0x%02x len=%zu\n",
       k.src&255,(k.src>>8)&255,(k.src>>16)&255,(k.src>>24)&255, k.sport,
       k.dst&255,(k.dst>>8)&255,(k.dst>>16)&255,(k.dst>>24)&255, k.dport,
       k.proto, k.tcp_flags, n - off);

    /* UDP и прочее не пересылаем: VLESS UDP требует отдельной обёртки, а основной UDP,
     * который важен для маршрутизации, — это DNS, и его перехватывает резолвер steer. */
    if (k.proto != 6) { TR("не TCP, пропуск\n"); return; }

    struct conn *c = conn_find(&k);

    if (k.tcp_flags & TCP_SYN) {
        if (c) return;                              /* повтор SYN — уже открываем */
        c = conn_new();
        if (!c) return;                             /* предел: клиент повторит SYN */
        memset(c, 0, sizeof(*c));
        c->used = 1;
        c->key = k;
        c->client_seq = k.seq + 1;                  /* SYN занимает один номер */
        c->our_seq = 1;                             /* свой поток начинаем с 1 */
        c->client_ack = 1;                          /* столько он уже подтвердил (SYN-ACK) */
        c->client_win = k.window ? k.window : 8192;
        c->client_wscale = k.wscale;
        c->last = time(NULL);
        if (vless_uuid_parse(node->uuid, c->uuid) != 0) { conn_drop(c); return; }
        vision_init(&c->vis, c->uuid);

        TR("SYN: открываю поток к серверу\n");
        if (vless_connect(node, &c->v, 8) != 0) {
            TR("поток не открылся, отвечаю RST\n");
            /* Сервер недоступен — отвечаем RST, а не молчим: клиент иначе будет ждать
             * до таймаута, и «сайт не открывается» вместо «отказано в соединении». */
            unsigned char rst[64];
            size_t rl = tcp_build(rst, sizeof(rst), k.dst, k.src, k.dport, k.sport,
                                  0, c->client_seq, TCP_RST | TCP_ACK, NULL, 0, 0, 0);
            if (rl) write(tun_fd, rst, rl);
            conn_drop(c);
            return;
        }
        /* SYN-ACK: подтверждаем соединение клиенту. */
        unsigned char sa[64];
        size_t sl = tcp_build(sa, sizeof(sa), k.dst, k.src, k.dport, k.sport,
                              c->our_seq++, c->client_seq, TCP_SYN | TCP_ACK,
                              NULL, 0, 65535, TUN_MSS);
        if (sl) write(tun_fd, sa, sl);
        TR("SYN-ACK отправлен (seq=%u ack=%u)\n", c->our_seq - 1, c->client_seq);
        return;
    }

    if (!c) return;                                 /* данные без соединения — игнор */
    c->last = time(NULL);

    /* Учитываем подтверждения и окно клиента с ЛЮБОГО его пакета, включая чистые ACK: без
     * этого мы не знаем, сколько он принял, и продолжаем лить в устройство. Именно чистые
     * ACK и приходят во время скачивания — данных от клиента там нет вовсе. */
    if (k.tcp_flags & TCP_ACK) {
        /* Сравнение с учётом переполнения счётчика: разность как знаковая. */
        if ((int32_t)(k.ack - c->client_ack) > 0) c->client_ack = k.ack;
        c->client_win = k.window;
    }

    if (k.tcp_flags & (TCP_RST | TCP_FIN)) {
        if (k.tcp_flags & TCP_FIN) {
            /* Подтверждаем FIN и закрываем: половинчатое закрытие не поддержано, потому
             * что требует хранить, какая сторона ещё пишет. */
            unsigned char fa[64];
            size_t fl = tcp_build(fa, sizeof(fa), k.dst, k.src, k.dport, k.sport,
                                  c->our_seq, k.seq + 1, TCP_ACK | TCP_FIN, NULL, 0, 0, 0);
            if (fl) write(tun_fd, fa, fl);
        }
        conn_drop(c);
        return;
    }

    size_t data_n = n - off;
    if (!data_n) return;                            /* чистый ACK */

    /* Не по порядку — отбрасываем. Буфер переупорядочивания на каждое соединение это как
     * раз та память, которой на слабой коробке нет; клиент повторит. */
    if (k.seq != c->client_seq) return;

    TR("данные клиента %zu байт -> серверу\n", data_n);
    int sr = upstream_send(c, node, pkt + off, data_n);
    if (sr == SEND_AGAIN) {
        /* Окно закрыто. Прежде чем перекладывать задержку на клиента, разберём то, что уже
         * лежит в сокете: WINDOW_UPDATE приходит именно оттуда и обычно УЖЕ там — сервер
         * присылает его, как только освободил буфер.
         *
         * Без этой попытки каждое закрытие окна стоило бы таймаута повторной передачи у
         * клиента, то есть двухсот миллисекунд на каждые 64 КБ. Замер: выгрузка через
         * grpc шла 200 КБ/с вместо мегабайта.
         *
         * Читаем через downstream_pump, а не сами: только он умеет отдать пришедшие данные
         * клиенту. Читать «на выброс» здесь означало бы потерять ответ сервера. */
        /* Пять миллисекунд ожидания, а не ноль. Кадр WINDOW_UPDATE обычно уже в сокете, но
         * иногда отстаёт на доли круга — и тогда нулевое ожидание отдаёт задержку клиенту,
         * у которого таймаут повторной передачи двести миллисекунд. Пять против двухсот.
         *
         * Больше нельзя: цикл здесь один на все соединения, и каждая миллисекунда ожидания
         * — это миллисекунда, на которую стоят остальные. */
        struct pollfd sp = { .fd = c->v.fd, .events = POLLIN };
        if (poll(&sp, 1, 5) > 0 && (sp.revents & POLLIN)) {
            if (downstream_pump(c, node, tun_fd) != 0) { conn_drop(c); return; }
            sr = upstream_send(c, node, pkt + off, data_n);
        }
    }
    if (sr == SEND_AGAIN) {
        /* Всё ещё нельзя: не подтверждаем и не двигаем счётчик — пакет для нас как бы не
         * приходил. Клиент повторит его сам, и это единственный способ придержать поток,
         * не храня недоотправленное у себя. */
        TR("окно закрыто, пакет не подтверждён — клиент повторит\n");
        return;
    }
    if (sr != SEND_OK) {
        TR("отправка серверу не удалась\n");
        conn_drop(c);
        return;
    }
    c->client_seq += (uint32_t)data_n;

    /* Подтверждаем приём: без ACK клиент будет повторять пакет, считая его потерянным. */
    unsigned char ackp[64];
    size_t al = tcp_build(ackp, sizeof(ackp), k.dst, k.src, k.dport, k.sport,
                          c->our_seq, c->client_seq, TCP_ACK, NULL, 0, 65535, 0);
    if (al) write(tun_fd, ackp, al);
}

int run_quiet(const char *const argv[]);   /* из steer.c */

/* Поднять устройство и дать ему адрес.
 *
 * Делает это движок, а не управляющий слой, потому что устройство создаёт тоже движок:
 * между «TUN появился» и «TUN готов нести трафик» нет никого, кому это можно было бы
 * поручить. Без этого apply не находит рабочего устройства, ставит blackhole (при
 * on_fail=drop) и трафик стоит — притом что процесс запущен, узел выбран и в логе всё
 * выглядит успешным. Ровно тот случай, когда «настроено» и «работает» расходятся молча.
 *
 * Адрес нужен не нам: наш клиент читает из TUN пакеты и открывает по ним потоки, source
 * в них не участвует вовсе. Нужен он ядру и фаерволу — маршрут на устройство без адреса
 * ядро считает непригодным для локально порождённых пакетов.
 *
 * 198.51.100.0/24 — это TEST-NET-2 из RFC 5737: диапазон, отведённый под документацию и
 * НЕ маршрутизируемый в интернете. Поэтому он не может столкнуться ни с чужим сервисом,
 * ни с локальной сетью, которую кто-то себе выбрал. Пул fake-IP (198.18.0.0/15) здесь
 * брать нельзя — он занят под другую задачу, и пересечение перепутало бы одно с другим.
 *
 * Номер адреса берётся из таблицы маршрутизации выхода: она уже уникальна и уже лежит в
 * реестре, то есть переживает перезагрузку. Выдумывать для этого второй счётчик значило
 * бы завести второе место, где номера могут разъехаться. */
static void tun_bring_up(const char *dev, int table) {
    char addr[40];
    snprintf(addr, sizeof(addr), "198.51.100.%d/32", 1 + (table % 200));
    const char *a[] = { "ip", "addr", "replace", addr, "dev", dev, NULL };
    run_quiet(a);
    const char *u[] = { "ip", "link", "set", "dev", dev, "up", NULL };
    run_quiet(u);
}

int tunnel_run(struct output *o, const struct vless_node *node) {
    const char *dev = o->device;
    int tun_fd = tun_open(dev);
    if (tun_fd < 0) return tun_fd;
    tun_bring_up(dev, o->table);

    /* Привязываем таблицу выхода к устройству ЗДЕСЬ, а не в apply.
     *
     * Apply уже прошёл к этому моменту и, не найдя устройства, поставил запрет — иначе и
     * нельзя: пока туннеля нет, пускать в него трафик некуда. Дождаться устройства снаружи
     * невозможно: procd запускает этот процесс только после того, как init-скрипт вернул
     * управление, то есть уже после apply. Значит привязать может только тот, кто знает
     * момент готовности, — а это мы. */
    bind_device(o, dev);
    fprintf(stderr, "steer tunnel: %s привязан к таблице %d\n", dev, o->table);
    fprintf(stderr, "steer tunnel: %s -> %s (%s:%u %s%s)\n", dev, node->name,
            node->host, node->port, node->type, node->flow[0] ? " +vision" : "");

    g_trace = getenv("STEER_TUN_TRACE") != NULL;
    memset(g_conns, 0, sizeof(g_conns));
    unsigned char pkt[TUNNEL_BUF];

    for (;;) {
        struct pollfd pf[1 + MAX_CONNS];
        struct conn *map[MAX_CONNS];
        int nf = 0;
        pf[nf].fd = tun_fd;
        pf[nf].events = POLLIN;
        nf++;
        for (int i = 0; i < MAX_CONNS; i++) {
            if (!g_conns[i].used) continue;
            /* Не спрашиваем сервер о новых данных, пока клиент не разгрёб прежние.
             *
             * Это и есть управление потоком, которого у нас иначе нет: прочитав, мы обязаны
             * сразу записать в устройство, а очередь устройства не бесконечна. Переполнив
             * её, мы теряем сегмент — и без повторной передачи соединение подвисает
             * навсегда: клиент подтверждает старое, мы отдаём новое, и никто не сходится.
             *
             * Замер: на роутере без этой проверки передача вставала на втором мегабайте. */
            if (g_conns[i].our_seq - g_conns[i].client_ack >= client_room(&g_conns[i]))
                continue;
            pf[nf].fd = g_conns[i].v.fd;
            pf[nf].events = POLLIN;
            map[nf - 1] = &g_conns[i];
            nf++;
        }

        int r = poll(pf, (unsigned)nf, 1000);
        if (r < 0) {
            if (errno == EINTR) continue;
            break;
        }

        if (pf[0].revents & POLLIN) {
            ssize_t rn = read(tun_fd, pkt, sizeof(pkt));
            if (rn > 0) handle_packet(tun_fd, node, pkt, (size_t)rn);
        }
        for (int i = 1; i < nf; i++) {
            if (!(pf[i].revents & (POLLIN | POLLHUP | POLLERR))) continue;
            struct conn *c = map[i - 1];
            if (!c->used) continue;

            /* ВЫЧЕРПЫВАЕМ сокет, а не читаем по одной записи за проход цикла.
             *
             * Разница принципиальная. Пока мы не читаем, у сервера закрывается окно, и
             * заново открыть его стоит круга до сервера — десятки миллисекунд. Читая по
             * одной записи на итерацию, мы получаем скорость «запись за круг», то есть
             * задержку вместо полосы: замерено 3 Мбит/с там, где криптография держит 800.
             *
             * Предел здесь двойной: окно клиента (иначе потеряем сегмент, а повторной
             * передачи нет) и число записей за проход — чтобы одно активное соединение не
             * заморозило остальные. */
            int drained = 0;
            for (;;) {
                if (downstream_pump(c, node, tun_fd) != 0) {
                    /* Сервер закрыл — сообщаем клиенту FIN, иначе он будет ждать данных,
                     * которых больше не будет. */
                    unsigned char fin[64];
                    size_t fl = tcp_build(fin, sizeof(fin), c->key.dst, c->key.src,
                                          c->key.dport, c->key.sport,
                                          c->our_seq, c->client_seq, TCP_FIN | TCP_ACK,
                                          NULL, 0, 0, 0);
                    if (fl) write(tun_fd, fin, fl);
                    conn_drop(c);
                    break;
                }
                if (++drained >= DRAIN_MAX_RECORDS) break;
                if (c->our_seq - c->client_ack >= client_room(c)) break;
                /* Есть ли ещё что читать. Без этой проверки следующее чтение заблокируется
                 * на таймауте сокета и остановит весь цикл на секунды. */
                struct pollfd sp = { .fd = c->v.fd, .events = POLLIN };
                if (poll(&sp, 1, 0) <= 0 || !(sp.revents & POLLIN)) break;
            }
        }

        /* Уборка задержавшихся: без неё таблица заполняется соединениями, которые клиент
         * бросил без FIN, и новые перестают открываться. */
        time_t now = time(NULL);
        for (int i = 0; i < MAX_CONNS; i++)
            if (g_conns[i].used && now - g_conns[i].last > 120) conn_drop(&g_conns[i]);
    }
    close(tun_fd);
    return 0;
}

/* ---- подкоманда steer vless -------------------------------------------------
 *
 * Поднимает TUN для выхода kind=vless из спеки. Отдельный процесс, а не поток внутри
 * apply: apply должен завершаться, а туннель — жить. Init-скрипт держит по экземпляру
 * procd на каждый такой выход, поэтому падение одного не уносит остальные.
 */
#define MAX_NODES 128
static struct vless_node g_nodes[MAX_NODES];

/* Найти выход и разобрать его подписку. Одно место на все три команды: иначе «как
 * читается подписка» разошлось бы между подъёмом, списком и проверкой — а расхождение
 * здесь означало бы, что человек выбирает в интерфейсе не тот узел, который поднимется. */
static int load_nodes(const char *spec_path, const char *out_name, struct output **out,
                      size_t *cnt, size_t *skipped, size_t *foreign) {
    load_spec(spec_path);
    struct output *o = out_by_name(out_name);
    if (!o) { fprintf(stderr, "steer: выхода %s нет в спеке\n", out_name); return 2; }
    if (o->kind != OUT_VLESS) {
        fprintf(stderr, "steer: выход %s не vless (kind другой)\n", out_name);
        return 2;
    }
    *out = o;

    /* Подписка читается с диска: скачивание — дело управляющего слоя. */
    FILE *f = fopen(o->sub_file, "r");
    if (!f) { fprintf(stderr, "steer: %s не читается\n", o->sub_file); return 2; }
    static char raw[262144], dec[262144];
    size_t n = fread(raw, 1, sizeof(raw) - 1, f);
    raw[n] = '\0';
    fclose(f);
    const char *text = raw;
    if (!strstr(raw, "://")) { b64_decode(raw, n, dec, sizeof(dec)); text = dec; }

    *cnt = vless_parse_sub(text, g_nodes, MAX_NODES, skipped, foreign);
    return 0;
}

/* Строка JSON с экранированием. Имена узлов приходят из подписки и содержат что угодно —
 * кавычки в них ломали бы весь ответ, а не только своё поле. */
static void json_str(const char *s) {
    putchar('"');
    for (const unsigned char *p = (const unsigned char *)s; *p; p++) {
        if (*p == '"' || *p == '\\') { putchar('\\'); putchar(*p); }
        else if (*p < 0x20) printf("\\u%04x", *p);
        else putchar(*p);
    }
    putchar('"');
}

static void node_json(const struct vless_node *n, int index) {
    printf("{\"index\":%d,", index);
    printf("\"name\":"); json_str(n->name);
    printf(",\"host\":"); json_str(n->host);
    printf(",\"port\":%u,\"type\":", n->port);
    json_str(n->type);
    printf(",\"security\":"); json_str(n->security);
    printf(",\"vision\":%s", n->flow[0] ? "true" : "false");
    if (n->mode[0]) { printf(",\"mode\":"); json_str(n->mode); }
    printf("}");
}

/* Перечислить узлы подписки.
 *
 * Индекс здесь — это индекс среди ПРИГОДНЫХ узлов, и он же понимается движком в поле
 * `node` спеки. Одно значение слова «номер узла» на весь проект: если бы список включал
 * непригодные, человек выбрал бы номер 5, а поднялся бы другой узел — и понять это было
 * бы невозможно, потому что оба списка выглядят правдоподобно. Непригодные считаются
 * отдельно и объясняются причиной, но номеров не занимают. */
int cmd_vless_nodes(const char *spec_path, const char *out_name) {
    struct output *o = NULL;
    size_t cnt = 0, skipped = 0, foreign = 0;
    int rc = load_nodes(spec_path, out_name, &o, &cnt, &skipped, &foreign);
    if (rc) return rc;

    printf("{\"output\":");
    json_str(out_name);
    printf(",\"sub_file\":");
    json_str(o->sub_file);
    printf(",\"node\":%d,\"usable\":%zu,\"skipped\":%zu,\"foreign\":%zu,\"nodes\":[",
           o->node_index, cnt, skipped, foreign);
    for (size_t i = 0; i < cnt; i++) {
        if (i) putchar(',');
        node_json(&g_nodes[i], (int)i);
    }
    printf("]}\n");
    return 0;
}

/* Проверить узел и измерить задержку.
 *
 * node >= 0 — только этот узел. node < 0 — по порядку до первого рабочего, то есть ровно
 * то, что сделает движок при подъёме выхода.
 *
 * По одному узлу за вызов не случайно: проверка узла упирается в таймаут, и «проверить
 * все» на подписке из двадцати шести узлов заняло бы минуты — дольше, чем живёт вызов
 * ubus. Интерфейс спрашивает по одному и заполняет таблицу постепенно. */
int cmd_vless_probe(const char *spec_path, const char *out_name, int node, int timeout_s) {
    struct output *o = NULL;
    size_t cnt = 0, skipped = 0, foreign = 0;
    int rc = load_nodes(spec_path, out_name, &o, &cnt, &skipped, &foreign);
    if (rc) return rc;
    if (!cnt) {
        printf("{\"ok\":false,\"error\":\"в подписке нет пригодных узлов\","
               "\"skipped\":%zu,\"foreign\":%zu}\n", skipped, foreign);
        return 1;
    }
    if (node >= (int)cnt) {
        printf("{\"ok\":false,\"error\":\"узла %d нет, всего %zu\"}\n", node, cnt);
        return 1;
    }

    size_t from = node >= 0 ? (size_t)node : 0;
    size_t to = node >= 0 ? (size_t)node + 1 : cnt;
    int found = -1;
    printf("{\"output\":");
    json_str(out_name);
    printf(",\"results\":[");
    for (size_t i = from; i < to; i++) {
        char why[256] = "";
        int hs = -1, ttfb = -1;
        int pr = vless_probe_timed(&g_nodes[i], timeout_s, why, sizeof(why), &hs, &ttfb);
        if (i > from) putchar(',');
        printf("{\"index\":%zu,\"name\":", i);
        json_str(g_nodes[i].name);
        printf(",\"type\":");
        json_str(g_nodes[i].type);
        printf(",\"ok\":%s,\"handshake_ms\":%d,\"ttfb_ms\":%d,\"why\":",
               pr == 0 ? "true" : "false", hs, ttfb);
        json_str(why);
        printf("}");
        if (pr == 0) { found = (int)i; if (node < 0) break; }
    }
    printf("],\"working\":%d}\n", found);
    return found >= 0 ? 0 : 1;
}

int cmd_vless(const char *spec_path, const char *out_name) {
    struct output *o = NULL;
    size_t cnt = 0, skipped = 0, foreign = 0;
    int rc = load_nodes(spec_path, out_name, &o, &cnt, &skipped, &foreign);
    if (rc) return rc;
    struct vless_node *nodes = g_nodes;
    if (!cnt) {
        fprintf(stderr, "steer: в подписке нет пригодных узлов "
                        "(пропущено %zu, чужих протоколов %zu)\n", skipped, foreign);
        return 1;
    }
    fprintf(stderr, "steer: узлов %zu (пропущено %zu, чужих %zu)\n", cnt, skipped, foreign);

    /* Выбор узла. node=-1 означает «первый рабочий», и это умолчание не из лени: номер
     * узла в подписке меняется при её обновлении, а проверка находит живой сама. */
    int chosen = -1;
    if (o->node_index >= 0) {
        if ((size_t)o->node_index >= cnt) {
            fprintf(stderr, "steer: узла %d нет (всего %zu)\n", o->node_index, cnt);
            return 1;
        }
        chosen = o->node_index;
    } else {
        for (size_t i = 0; i < cnt; i++) {
            char why[256];
            if (vless_probe(&nodes[i], 8, why, sizeof(why)) == 0) {
                fprintf(stderr, "steer: выбран %s (%s)\n", nodes[i].name, why);
                chosen = (int)i;
                break;
            }
            fprintf(stderr, "steer: %s — %s\n", nodes[i].name, why);
        }
    }
    if (chosen < 0) {
        fprintf(stderr, "steer: ни один узел подписки не отвечает\n");
        return 1;
    }

    /* Реестр — чтобы узнать таблицу выхода: из неё берётся адрес устройства. Вызов
     * идемпотентен и с apply не спорит: тот же файл, те же номера. */
    registry_assign();
    return tunnel_run(o, &nodes[chosen]);
}
