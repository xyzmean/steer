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
    time_t last;
};

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
    if (c->used) vless_close(&c->v);
    memset(c, 0, sizeof(*c));
}

/* Отправить серверу данные в правильной форме: с заголовком VLESS на первом кадре и в
 * обёртке Vision, если узел её требует. */
static int upstream_send(struct conn *c, const struct vless_node *node,
                         const unsigned char *data, size_t n) {
    unsigned char out[TUNNEL_BUF];
    size_t len = 0;

    if (!c->header_sent) {
        /* Адрес назначения берём из пакета: имени у нас нет, клиент уже разрешил его сам
         * (или через наш резолвер, который вернул fake-IP и подменит адрес в DNAT). */
        unsigned char ip4[4];
        memcpy(ip4, &c->key.dst, 4);
        /* dport уже в хостовом порядке — см. комментарий в tun.h. */
        len = vless_build_request(c->uuid, VLESS_CMD_TCP, NULL, ip4,
                                  c->key.dport, node->flow, out, sizeof(out));
        if (!len) return -1;
        c->header_sent = 1;
    }

    if (node->flow[0]) {
        unsigned char framed[TUNNEL_BUF];
        size_t fn = vision_wrap(&c->vis, data, n, framed, sizeof(framed));
        if (!fn) return -1;
        if (len + fn > sizeof(out)) return -1;
        memcpy(out + len, framed, fn);
        len += fn;
    } else {
        if (len + n > sizeof(out)) return -1;
        memcpy(out + len, data, n);
        len += n;
    }
    return tls13_write(&c->v.tls, out, len);
}

/* Прочитать у сервера и отдать клиенту как TCP-пакет. */
static int downstream_pump(struct conn *c, const struct vless_node *node, int tun_fd) {
    unsigned char buf[TUNNEL_BUF];
    size_t got = 0;
    int rc = tls13_read(&c->v.tls, buf, sizeof(buf), &got);
    if (rc) { TR("чтение от сервера: rc=%d\n", rc); return rc; }
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
                /* Кадр пришёл не целиком. Остаток бросаем: собирать его между чтениями
                 * значило бы держать буфер на каждое соединение, а TLS-записи и так
                 * приходят целиком — этот случай возможен только при кадре больше записи. */
                TR("кадр не целиком: ur=%d осталось %zu\n", ur, left);
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

    if (!total) { TR("после разбора данных нет\n"); return 0; }

    unsigned char pkt[TUNNEL_BUF];
    /* Отвечаем от имени сервера: адреса и порты наоборот. */
    size_t len = tcp_build(pkt, sizeof(pkt), c->key.dst, c->key.src,
                           c->key.dport, c->key.sport,
                           c->our_seq, c->client_seq, TCP_ACK | TCP_PSH,
                           payload, total, 65535);
    if (!len) return -1;
    c->our_seq += (uint32_t)total;
    TR("клиенту %zu байт (seq=%u)\n", total, c->our_seq - (uint32_t)total);
    if (write(tun_fd, pkt, len) < 0) return -1;
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
                                  0, c->client_seq, TCP_RST | TCP_ACK, NULL, 0, 0);
            if (rl) write(tun_fd, rst, rl);
            conn_drop(c);
            return;
        }
        /* SYN-ACK: подтверждаем соединение клиенту. */
        unsigned char sa[64];
        size_t sl = tcp_build(sa, sizeof(sa), k.dst, k.src, k.dport, k.sport,
                              c->our_seq++, c->client_seq, TCP_SYN | TCP_ACK, NULL, 0, 65535);
        if (sl) write(tun_fd, sa, sl);
        TR("SYN-ACK отправлен (seq=%u ack=%u)\n", c->our_seq - 1, c->client_seq);
        return;
    }

    if (!c) return;                                 /* данные без соединения — игнор */
    c->last = time(NULL);

    if (k.tcp_flags & (TCP_RST | TCP_FIN)) {
        if (k.tcp_flags & TCP_FIN) {
            /* Подтверждаем FIN и закрываем: половинчатое закрытие не поддержано, потому
             * что требует хранить, какая сторона ещё пишет. */
            unsigned char fa[64];
            size_t fl = tcp_build(fa, sizeof(fa), k.dst, k.src, k.dport, k.sport,
                                  c->our_seq, k.seq + 1, TCP_ACK | TCP_FIN, NULL, 0, 0);
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
    if (upstream_send(c, node, pkt + off, data_n) != 0) {
        TR("отправка серверу не удалась\n");
        conn_drop(c);
        return;
    }
    c->client_seq += (uint32_t)data_n;

    /* Подтверждаем приём: без ACK клиент будет повторять пакет, считая его потерянным. */
    unsigned char ackp[64];
    size_t al = tcp_build(ackp, sizeof(ackp), k.dst, k.src, k.dport, k.sport,
                          c->our_seq, c->client_seq, TCP_ACK, NULL, 0, 65535);
    if (al) write(tun_fd, ackp, al);
}

int tunnel_run(const char *dev, const struct vless_node *node) {
    int tun_fd = tun_open(dev);
    if (tun_fd < 0) return tun_fd;
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
            if (downstream_pump(c, node, tun_fd) != 0) {
                /* Сервер закрыл — сообщаем клиенту FIN, иначе он будет ждать данных,
                 * которых больше не будет. */
                unsigned char fin[64];
                size_t fl = tcp_build(fin, sizeof(fin), c->key.dst, c->key.src,
                                      c->key.dport, c->key.sport,
                                      c->our_seq, c->client_seq, TCP_FIN | TCP_ACK,
                                      NULL, 0, 0);
                if (fl) write(tun_fd, fin, fl);
                conn_drop(c);
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
int cmd_vless(const char *spec_path, const char *out_name) {
    load_spec(spec_path);
    struct output *o = out_by_name(out_name);
    if (!o) { fprintf(stderr, "steer: выхода %s нет в спеке\n", out_name); return 2; }
    if (o->kind != OUT_VLESS) {
        fprintf(stderr, "steer: выход %s не vless (kind другой)\n", out_name);
        return 2;
    }

    /* Подписка читается с диска: скачивание — дело управляющего слоя. */
    FILE *f = fopen(o->sub_file, "r");
    if (!f) { fprintf(stderr, "steer: %s не читается\n", o->sub_file); return 2; }
    static char raw[262144], dec[262144];
    size_t n = fread(raw, 1, sizeof(raw) - 1, f);
    raw[n] = '\0';
    fclose(f);
    const char *text = raw;
    if (!strstr(raw, "://")) { b64_decode(raw, n, dec, sizeof(dec)); text = dec; }

    static struct vless_node nodes[128];
    size_t skipped = 0, foreign = 0;
    size_t cnt = vless_parse_sub(text, nodes, 128, &skipped, &foreign);
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

    return tunnel_run(o->device, &nodes[chosen]);
}
