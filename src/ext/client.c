/* Соединение с узлом VLESS/Reality: от TCP до проверки «нас признали».
 *
 * Ключевая мысль этого файла: у Reality нет отрицательного ответа. Сервер, не узнавший
 * клиента, не отвечает отказом — он проксирует соединение на настоящий сайт, которым
 * прикрывается. Значит рукопожатие может пройти полностью, ключи сойтись, TLS
 * установиться, и всё равно это будет чужой сайт, а не туннель.
 *
 * Отличить одно от другого можно только по первому байту ответа VLESS: сервер отвечает
 * версией 0, а настоящий сайт пришлёт что угодно другое — HTTP, HTML, редирект. Поэтому
 * vless_probe() ниже и есть единственная честная проверка узла, и именно её использует
 * сторож вместо пинга.
 */
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <netdb.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <poll.h>
#include <fcntl.h>
#include <arpa/inet.h>
#include <sys/random.h>
#include <time.h>

#include "vless.h"
#include "reality.h"
#include "tls13.h"
#include "vless_proto.h"
#include "vision.h"
#include "client.h"

/* ---- транспорты поверх HTTP/2 ------------------------------------------------
 *
 * grpc и xhttp — это HTTP/2, а не «другой формат кадров». Разница между ними меньше, чем
 * кажется: оба открывают один поток запросом POST и гоняют байты в его теле. Отличаются
 * ровно двумя вещами — путём и тем, обёрнуты ли данные в сообщения gRPC.
 *
 * Формат сообщения gRPC (RFC на gRPC over HTTP/2 плюс schema Xray из stream.proto):
 *
 *   признак сжатия  1 байт  (0 — не сжато; сжатие мы не предлагаем и не принимаем)
 *   длина           4 байта big-endian
 *   тело            protobuf-сообщение Hunk { bytes data = 1 } — то есть 0x0A, длина, байты
 *
 * MultiHunk (mode=multi) отличается только тем, что поле 1 может повторяться. На отправку
 * это неотличимо от Hunk — одно поле и есть законный MultiHunk, — а на приём разбор
 * повторов получается сам, потому что мы читаем поля до конца сообщения.
 *
 * xhttp в режиме stream-one не оборачивает ничего: тело запроса — это поток наверх, тело
 * ответа — поток вниз. Зато он требует набивки: сервер проверяет длину x_padding в
 * Referer и без неё отвечает 400 (см. hub.go в Xray). Это не украшение — это условие.
 */
static enum vless_transport transport_of(const struct vless_node *n) {
    if (!strcmp(n->type, "grpc")) return VT_GRPC;
    if (!strcmp(n->type, "xhttp")) return VT_XHTTP;
    return VT_RAW;
}

static int io_write(void *ctx, const unsigned char *d, size_t n) {
    struct vless_conn *c = ctx;
    if (c->plain) {
        size_t sent = 0;
        while (sent < n) {
            ssize_t w = write(c->fd, d + sent, n - sent);
            if (w <= 0) {
                if (w < 0 && errno == EINTR) continue;
                return VLESS_CONN_EIO;
            }
            sent += (size_t)w;
        }
        return 0;
    }
    return tls13_write(&c->tls, d, n);
}

static int io_read(void *ctx, unsigned char *d, size_t cap, size_t *got) {
    struct vless_conn *c = ctx;
    /* Прямое копирование: сервер перестал шифровать в нашу сторону, и расшифровывать
     * теперь нечего — в сокете лежит поток целевого соединения. Читаем как есть.
     *
     * Но СНАЧАЛА отдаём то, что уже прочитано у сокета в буфер записей: переход в прямой
     * режим случается посреди потока, и начало сырых данных к этому моменту обычно уже у
     * нас. Прочитать сокет, не отдав их, значит выбросить кусок и разъехаться с сервером —
     * узлы с Vision отдавали ровно ноль байт. */
    if (c->rx_direct && !c->plain) {
        size_t pending = tls13_take_pending(&c->tls, d, cap);
        if (pending) { *got = pending; return 0; }
    }
    if (c->plain || c->rx_direct) {
        ssize_t r = read(c->fd, d, cap);
        if (r <= 0) return r == 0 ? VLESS_CONN_ECLOSED : VLESS_CONN_EIO;
        *got = (size_t)r;
        return 0;
    }
    return tls13_read(&c->tls, d, cap, got);
}

/* Путь запроса для gRPC.
 *
 * Обычная форма: serviceName без ведущего слэша, тогда путь — /<service>/Tun. Новая форма
 * из Xray: serviceName начинается со слэша и УЖЕ содержит имя метода целиком, тогда путь
 * это он сам. Различать обязательно: перепутав, мы попадём в несуществующий метод, и
 * сервер ответит 404 — то есть узел будет выглядеть неисправным. */
static void grpc_path(const struct vless_node *n, char *out, size_t cap) {
    int multi = !strcmp(n->mode, "multi");
    if (n->service[0] == '/') {
        /* Форма «/a/b/MyTun» или «/a/b/MyTun|MyTunMulti»: берём нужную половину. */
        const char *bar = strchr(n->service, '|');
        size_t len = bar ? (size_t)(bar - n->service) : strlen(n->service);
        if (multi && bar) {
            const char *slash = strrchr(n->service, '/');
            size_t head = slash ? (size_t)(slash - n->service) : 0;
            snprintf(out, cap, "%.*s/%s", (int)head, n->service, bar + 1);
            return;
        }
        snprintf(out, cap, "%.*s", (int)len, n->service);
        return;
    }
    snprintf(out, cap, "/%s/%s", n->service, multi ? "TunMulti" : "Tun");
}

/* Путь xhttp: с ведущим и завершающим слэшем.
 *
 * Завершающий слэш — не косметика. Сервер вычисляет идентификатор сессии как остаток
 * пути после своего, и режим stream-one опознаётся именно по ПУСТОМУ остатку. Путь без
 * завершающего слэша даёт непустой остаток, сервер уходит в режим packet-up и отвечает
 * 400 — а выглядит это как «узел не работает». */
static void xhttp_path(const struct vless_node *n, char *out, size_t cap) {
    const char *p = n->path[0] ? n->path : "/";
    size_t len = strlen(p);
    snprintf(out, cap, "%s%s%s", p[0] == '/' ? "" : "/", p,
             len && p[len - 1] == '/' ? "" : "/");
}

static int h2_open(struct vless_conn *c, const struct vless_node *n) {
    struct h2_io io = { .ctx = c, .write = io_write, .read = io_read };
    /* Имя хоста в :authority — маскировочный домен, как и в SNI: сервер прикрывается им,
     * и запрос к другому имени выдал бы нас сразу. */
    const char *authority = n->sni[0] ? n->sni : n->host;
    char path[320];

    if (c->tr == VT_GRPC) {
        grpc_path(n, path, sizeof(path));
        memset(&c->de, 0, sizeof(c->de));
        return h2_start(&c->h2, &io, authority, path, "application/grpc", NULL);
    }

    xhttp_path(n, path, sizeof(path));
    /* Набивка: сервер требует от 100 до 1000 символов x_padding. Длина случайная — иначе
     * постоянная длина запроса сама становится признаком, ради устранения которого эта
     * набивка и придумана. */
    /* __thread: буфер живёт между вызовами, но потоков теперь несколько, и один общий
     * массив они переписывали бы друг под другом. Своя копия на поток — 1,4 КБ. */
    static __thread char ref[1400];
    unsigned char r = 0;
    if (getrandom(&r, 1, 0) != 1) r = 128;
    size_t pad = 150 + (size_t)r * 2;               /* 150…660 */
    int k = snprintf(ref, sizeof(ref), "https://%s%s?x_padding=", authority, path);
    if (k < 0 || (size_t)k + pad + 1 > sizeof(ref)) return H2_ETOOBIG;
    memset(ref + k, 'X', pad);
    ref[k + pad] = '\0';
    /* Content-Type: application/grpc и здесь — так делает Xray, и посредники по нему
     * не пытаются буферизовать поток. */
    return h2_start(&c->h2, &io, authority, path, "application/grpc", ref);
}

/* Обернуть данные в сообщение gRPC. */
static size_t grpc_wrap(const unsigned char *d, size_t n, unsigned char *out, size_t cap) {
    unsigned char pb[8];
    size_t pb_n = 0;
    pb[pb_n++] = 0x0A;                    /* поле 1, wire type 2 (bytes) */
    size_t v = n;
    while (v >= 128) { pb[pb_n++] = (unsigned char)((v & 0x7F) | 0x80); v >>= 7; }
    pb[pb_n++] = (unsigned char)v;

    size_t msg = pb_n + n;
    if (5 + msg > cap) return 0;
    out[0] = 0;                            /* не сжато */
    out[1] = (unsigned char)(msg >> 24); out[2] = (unsigned char)(msg >> 16);
    out[3] = (unsigned char)(msg >> 8);    out[4] = (unsigned char)msg;
    memcpy(out + 5, pb, pb_n);
    memcpy(out + 5 + pb_n, d, n);
    return 5 + msg;
}

/* Вынуть данные из потока сообщений gRPC. Работает по кускам любого размера: состояние
 * живёт в struct grpc_de, потому что границы сообщения и записи не совпадают. */
static int grpc_unwrap(struct grpc_de *de, const unsigned char *in, size_t n,
                       unsigned char *out, size_t cap, size_t *out_n) {
    *out_n = 0;
    size_t i = 0;
    while (i < n) {
        if (de->msg_left == 0) {
            /* Заголовок сообщения: признак сжатия и длина. */
            while (de->hdr_n < 5 && i < n) de->hdr[de->hdr_n++] = in[i++];
            if (de->hdr_n < 5) break;
            if (de->hdr[0] != 0) return VLESS_CONN_EGRPC;   /* сжатие не предлагали */
            de->msg_left = ((uint32_t)de->hdr[1] << 24) | ((uint32_t)de->hdr[2] << 16) |
                           ((uint32_t)de->hdr[3] << 8) | de->hdr[4];
            de->hdr_n = 0;
            de->pb_n = 0;
            de->field_left = 0;
            /* Пустое сообщение — законно: сервер так проверяет живость потока. */
            continue;
        }
        if (de->field_left == 0) {
            /* Тег и длина поля protobuf внутри сообщения. Собираем побайтно: тег и varint
             * могут разъехаться по записям так же, как всё остальное. */
            int complete = 0;
            while (i < n && de->msg_left > 0) {
                unsigned char b = in[i++];
                de->msg_left--;
                if (de->pb_n >= sizeof(de->pb)) return VLESS_CONN_EGRPC;  /* varint длиннее пяти байт не бывает */
                if (de->pb_n == 0 && b != 0x0A) return VLESS_CONN_EGRPC;  /* ждём только поле 1 */
                de->pb[de->pb_n++] = b;
                if (de->pb_n > 1 && !(b & 0x80)) { complete = 1; break; }
            }
            if (!complete) break;                  /* дочитаем в следующий раз */
            uint32_t v = 0;
            unsigned shift = 0;
            for (unsigned k = 1; k < de->pb_n; k++) {
                v |= (uint32_t)(de->pb[k] & 0x7F) << shift;
                shift += 7;
            }
            de->field_left = v;
            de->pb_n = 0;
            /* Пустое поле — законно, просто нечего отдавать. */
            if (de->field_left == 0) continue;
        }
        size_t take = de->field_left;
        if (take > n - i) take = n - i;
        if (take > de->msg_left) take = de->msg_left;
        if (*out_n + take > cap) return H2_ETOOBIG;
        memcpy(out + *out_n, in + i, take);
        *out_n += take;
        i += take;
        de->field_left -= (uint32_t)take;
        de->msg_left -= (uint32_t)take;
    }
    return 0;
}

/* ---- установление TCP: ВСЕ адреса узла, а не первый ---------------------------
 *
 * Одно имя узла — это, как правило, не один адрес. Живой пример, на котором это нашлось:
 * pl.riotvpn.eu отдаёт ПЯТНАДЦАТЬ записей A, и шесть из них — чёрные дыры: SYN уходит, в
 * ответ тишина. DNS перемешивает список при каждом запросе, поэтому «первый адрес» каждый
 * раз другой, и в сорока процентах случаев он мёртвый.
 *
 * Прежний код брал res->ai_next == первый и на этом останавливался. Последствия оказались
 * куда хуже, чем «иногда не соединяется»:
 *
 *   - блокирующий connect к чёрной дыре ждёт SO_SNDTIMEO целиком — восемь секунд, — и
 *     всё это время событийный цикл СТОИТ. Не тормозит, а стоит: ни один другой поток не
 *     двигается. На роутере это выглядело как «сайты еле открываются» при простое
 *     процессора 80% и нулевых счётчиках ошибок;
 *   - Linux сообщает об этом таймауте кодом EINPROGRESS (см. __inet_stream_connect:
 *     истёк timeo — err остаётся -EINPROGRESS), а не ETIMEDOUT. То есть в логе стояло
 *     «Operation in progress» у блокирующего вызова — вид сообщения, за которым не видно
 *     ни таймаута, ни мёртвого адреса;
 *   - сторож считал узел живым или мёртвым по одной пробе, то есть по жребию.
 *
 * Поэтому здесь: неблокирующий connect, свой таймаут вместо SO_SNDTIMEO, несколько
 * попыток одновременно с задержкой между запусками, и адрес-победитель запоминается,
 * чтобы следующее соединение начиналось с него. */

#define ADDR_MAX      16   /* сколько адресов имени вообще рассматриваем */
#define ATTEMPT_MAX    4   /* сколько держим в воздухе одновременно */
#define STAGGER_MS   150   /* пауза перед запуском следующей попытки */

/* Победивший адрес на имя. Живёт по потоку: работники независимы, блокировка не нужна, а
 * «каждый узнал сам» стоит одного лишнего перебора на работника при старте. */
#define GOOD_MAX 8
static __thread struct { char host[96]; struct in_addr ip; uint16_t port; } g_good[GOOD_MAX];
static __thread unsigned g_good_n;

static struct in_addr *good_get(const char *host, uint16_t port) {
    for (unsigned i = 0; i < g_good_n; i++)
        if (g_good[i].port == port && strcmp(g_good[i].host, host) == 0) return &g_good[i].ip;
    return NULL;
}

static void good_put(const char *host, uint16_t port, struct in_addr ip) {
    struct in_addr *p = good_get(host, port);
    if (p) { *p = ip; return; }
    unsigned i = g_good_n < GOOD_MAX ? g_good_n++ : GOOD_MAX - 1;
    snprintf(g_good[i].host, sizeof(g_good[i].host), "%s", host);
    g_good[i].port = port;
    g_good[i].ip = ip;
}

static int64_t now_ms(void) {
    struct timespec t;
    clock_gettime(CLOCK_MONOTONIC, &t);
    return (int64_t)t.tv_sec * 1000 + t.tv_nsec / 1000000;
}

/* Готовит установленный сокет к работе остального кода: снимает O_NONBLOCK (чтение и
 * запись дальше блокирующие, с таймаутом через SO_*TIMEO) и ставит опции. */
static void sock_ready(int fd, int timeout_s) {
    int fl = fcntl(fd, F_GETFL, 0);
    if (fl >= 0) fcntl(fd, F_SETFL, fl & ~O_NONBLOCK);
    /* Таймаут на чтение и запись. Без него мёртвый узел вешает проверку до таймаута
     * ядра — минуты, за которые сторож не успеет обойти остальных кандидатов. */
    struct timeval tv = { .tv_sec = timeout_s, .tv_usec = 0 };
    setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
    setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));
    int one = 1;
    setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, &one, sizeof(one));
    /* SO_RCVBUF здесь НЕ ставится, и это отказ от прежней «оптимизации», а не упущение.
     *
     * Любой вызов setsockopt(SO_RCVBUF) ОТКЛЮЧАЕТ автоподстройку приёмного окна в Linux и
     * прибивает его к заданному размеру. А скорость приёма равна «окно, поделённое на круг
     * до сервера»: при круге 60 мс полмегабайта — это потолок 68 Мбит/с, сколько бы ни
     * давал канал. Автоподстройка дошла бы до нескольких мегабайт сама.
     *
     * То есть «поставил буфер побольше» на деле означало «запретил ядру увеличивать его
     * дальше». Пределы живут в net.ipv4.tcp_rmem и настраиваются системой, а не нами. */
}

/* Запускает неблокирующий connect. Возвращает fd (соединение уже установлено или в
 * процессе) либо -1. */
static int attempt_start(struct in_addr ip, uint16_t port, int *done) {
    int fd = socket(AF_INET, SOCK_STREAM | SOCK_NONBLOCK, 0);
    if (fd < 0) return -1;
    struct sockaddr_in sa = { .sin_family = AF_INET, .sin_port = htons(port), .sin_addr = ip };
    *done = 0;
    if (connect(fd, (struct sockaddr *)&sa, sizeof(sa)) == 0) { *done = 1; return fd; }
    if (errno != EINPROGRESS) { close(fd); return -1; }
    return fd;
}

static int tcp_connect(const char *host, uint16_t port, int timeout_s) {
    char portstr[8];
    snprintf(portstr, sizeof(portstr), "%u", port);
    struct addrinfo hints = { .ai_family = AF_INET, .ai_socktype = SOCK_STREAM };
    struct addrinfo *res = NULL;
    if (getaddrinfo(host, portstr, &hints, &res) != 0 || !res) return VLESS_CONN_EDNS;

    struct in_addr addr[ADDR_MAX];
    unsigned an = 0;
    for (struct addrinfo *p = res; p && an < ADDR_MAX; p = p->ai_next)
        if (p->ai_family == AF_INET)
            addr[an++] = ((struct sockaddr_in *)p->ai_addr)->sin_addr;
    freeaddrinfo(res);
    if (an == 0) return VLESS_CONN_EDNS;

    /* Прошлый победитель — вперёд. В устойчивом состоянии это означает одно соединение за
     * один круг до сервера вместо перебора мёртвых адресов заново каждый раз. */
    struct in_addr *g = good_get(host, port);
    if (g) for (unsigned i = 1; i < an; i++)
        if (addr[i].s_addr == g->s_addr) { struct in_addr t = addr[0]; addr[0] = addr[i]; addr[i] = t; break; }

    int fd[ATTEMPT_MAX];
    struct in_addr fa[ATTEMPT_MAX];
    unsigned nf = 0;     /* попыток в воздухе */
    unsigned next = 0;   /* следующий адрес к запуску */
    unsigned dead = 0;   /* сколько адресов отвалилось */
    int64_t deadline = now_ms() + (long long)timeout_s * 1000;
    int64_t stagger_at = 0;
    int win = -1;

    while (win < 0) {
        int64_t t = now_ms();
        if (t >= deadline) break;

        /* Запуск новых попыток: первая сразу, дальше через STAGGER_MS. Пауза нужна, чтобы
         * при живом первом адресе (обычный случай) второй сокет вообще не открывался. */
        while (nf < ATTEMPT_MAX && next < an && t >= stagger_at) {
            int d = 0;
            struct in_addr ip = addr[next++];
            int s = attempt_start(ip, port, &d);
            if (s < 0) { dead++; continue; }
            if (d) {   /* соединилось сразу: обычно это адрес в той же сети */
                for (unsigned j = 0; j < nf; j++) close(fd[j]);
                nf = 0;
                good_put(host, port, ip);
                win = s;
                break;
            }
            fd[nf] = s; fa[nf] = ip;
            nf++;
            stagger_at = t + STAGGER_MS;
        }
        if (win >= 0) break;
        if (nf == 0) break;   /* адреса кончились, и ни одна попытка не жива */

        struct pollfd pv[ATTEMPT_MAX];
        for (unsigned i = 0; i < nf; i++) { pv[i].fd = fd[i]; pv[i].events = POLLOUT; pv[i].revents = 0; }

        /* Ждём до ближайшего из двух событий: пора запускать следующую попытку или вышел
         * общий срок. Ограничение «только если есть куда запускать» — не мелочь: без него
         * при четырёх попытках в воздухе и непустом остатке адресов poll получал таймаут 0
         * и цикл крутился на месте, съедая ядро. */
        int64_t wait = deadline - t;
        if (next < an && nf < ATTEMPT_MAX) {
            int64_t till = stagger_at > t ? stagger_at - t : 0;
            if (till < wait) wait = till;
        }
        if (wait < 0) wait = 0;
        int pr = poll(pv, nf, (int)wait);
        if (pr < 0) { if (errno == EINTR) continue; break; }

        for (unsigned i = 0; i < nf; ) {
            if (!pv[i].revents) { i++; continue; }
            int err = 0; socklen_t el = sizeof(err);
            getsockopt(fd[i], SOL_SOCKET, SO_ERROR, &err, &el);
            if (err == 0 && !(pv[i].revents & (POLLERR | POLLHUP))) {
                win = fd[i];
                good_put(host, port, fa[i]);
                for (unsigned j = 0; j < nf; j++) if (j != i) close(fd[j]);
                nf = 0;
                break;
            }
            /* Этот адрес отпал — освобождаем место и сразу пробуем следующий. */
            close(fd[i]); dead++;
            nf--; fd[i] = fd[nf]; fa[i] = fa[nf]; pv[i] = pv[nf];
            stagger_at = 0;
        }
    }

    if (win < 0) {
        for (unsigned i = 0; i < nf; i++) close(fd[i]);
        /* Сообщение называет масштаб: «ни один из N адресов» — это про имя узла, а не
         * про сеть, и лечится сменой узла, а не настройкой роутера. */
        fprintf(stderr, "steer vless: %s:%u — ни один адрес не ответил (адресов %u, отпало %u)\n",
                host, port, an, dead);
        return VLESS_CONN_ECONNECT;
    }
    if (dead)
        fprintf(stderr, "steer vless: %s:%u — соединился, пропущено мёртвых адресов: %u из %u\n",
                host, port, dead, an);
    sock_ready(win, timeout_s);
    return win;
}

/* Полное установление: TCP + Reality + TLS 1.3. Возвращает 0 и заполняет conn. */
int vless_connect(const struct vless_node *node, struct vless_conn *conn, int timeout_s) {
    memset(conn, 0, sizeof(*conn));
    conn->fd = -1;
    int rc_h2;

    int fd = tcp_connect(node->host, node->port, timeout_s);
    if (fd < 0) return fd;
    conn->fd = fd;

    /* security=none — голый VLESS, без TLS вообще. Полезен в доверенной сети, и именно
     * поэтому он не «частный случай reality», а отдельная ветка: ставить TLS там, где
     * его нет, значило бы просто не соединиться. */
    conn->tr = transport_of(node);

    if (strcmp(node->security, "none") == 0) {
        conn->plain = 1;
        /* Без TLS согласовывать ALPN нечем, поэтому HTTP/2 начинаем сразу: голый h2 по
         * TCP («h2c») сервер либо примет, либо ответит мусором, и это увидит проверка. */
        if (conn->tr == VT_RAW) return 0;
        rc_h2 = h2_open(conn, node);
        /* Единственная ветка отказа в этой функции, которая дескриптор НЕ закрывала —
         * все соседние закрывают. Узел security=none с транспортом grpc/xhttp, который
         * не отвечает по h2, за сутки опроса упирал процесс в RLIMIT_NOFILE. */
        if (rc_h2) { close(fd); conn->fd = -1; }
        return rc_h2;
    }

    struct reality_cfg cfg = {
        .sni = node->sni, .pbk = node->pbk, .sid = node->sid, .fp = node->fp,
        /* ALPN просим ровно тогда, когда он нужен. Для tcp его нет — и Hello остаётся
         * тем самым, который проверен на живых узлах. */
        .alpn = conn->tr == VT_RAW ? NULL : "h2",
    };
    unsigned char hello[2048];
    size_t hello_n = 0;
    int rc = reality_build_hello(&cfg, &conn->rst, hello, sizeof(hello), &hello_n);
    if (rc) { close(fd); conn->fd = -1; return rc; }

    size_t sent = 0;
    while (sent < hello_n) {
        ssize_t w = write(fd, hello + sent, hello_n - sent);
        if (w <= 0) {
            if (w < 0 && errno == EINTR) continue;
            close(fd); conn->fd = -1;
            return VLESS_CONN_EIO;
        }
        sent += (size_t)w;
    }

    /* Передаётся наш ПРИВАТНЫЙ ключ, а не готовый секрет: TLS-расписание строится на
     * обмене с эфемерным ключом сервера, который приедет только в ServerHello. */
    rc = tls13_handshake(&conn->tls, fd, hello, hello_n, conn->rst.priv);
    if (rc) { close(fd); conn->fd = -1; return rc; }

    if (conn->tr != VT_RAW) {
        /* ALPN здесь НЕ обязателен, и это важно понять правильно.
         *
         * Сервер Reality, признавший клиента, обслуживает соединение сам — с
         * `NextProtos: nil` (так и написано в config.go Xray), то есть ALPN не выбирает
         * вовсе и присылает пустые EncryptedExtensions. Признаком «h2 согласован» служит
         * не ответ, а сама конфигурация узла: Xray для reality решает версию HTTP тем же
         * способом — decideHTTPVersion возвращает «2» при reality, ни на что не глядя.
         *
         * Проверено на живом узле: openssl с -alpn h2 получает «h2», потому что его
         * НЕ признали и проксировали на настоящий сайт. Наше соединение ALPN не получает
         * именно потому, что признали. Требование ALPN отвергало бы ровно те узлы,
         * которые работают, — и первая версия этой проверки так и делала.
         *
         * Поэтому ошибка остаётся только на противоречие: сервер назвал протокол, и это
         * не h2. Тогда мы точно знаем, что говорить по HTTP/2 бессмысленно. */
        /* Отказы ПОСЛЕ удавшегося рукопожатия закрываются через vless_close, а не одним
         * close(fd), и это не стилистика. К этому месту ключи уже развёрнуты, и контексты
         * AES/GCM живут в КУЧЕ (tls13.c: mbedtls_gcm_setkey → mbedtls_cipher_setup →
         * calloc). Дескриптор их не держит, вызывающие тоже не убирают: проверка узла
         * возвращается сразу, пул запасных сессий лишь помечает слот пустым.
         *
         * Стреляет это на узле grpc/xhttp с security=reality, которого Reality не
         * признал: маскировочный сайт выбирает ALPN http/1.1, ENOH2 приходит на КАЖДОЙ
         * попытке, а пул пополняется на каждый SYN. Процесс живёт неделями — RSS растёт
         * до OOM-killer, и в журнале при этом только «поток к узлу не открылся». */
        if (conn->tls.alpn[0] && strcmp(conn->tls.alpn, "h2") != 0) {
            vless_close(conn);
            return VLESS_CONN_ENOH2;
        }
        rc = h2_open(conn, node);
        if (rc) { vless_close(conn); return rc; }
    }
    return 0;
}

/* Отдать данные в той упаковке, которую требует транспорт узла. Единственная точка, где
 * это решается: знание о транспорте, размазанное по туннелю и проверке, означало бы
 * забытое место и поток, уехавший не в той форме. */
int vless_send(struct vless_conn *c, const unsigned char *d, size_t n) {
    switch (c->tr) {
        case VT_XHTTP:
            return h2_write(&c->h2, d, n);
        case VT_GRPC: {
            static __thread unsigned char msg[H2_MIN_READ_CAP + 16];
            size_t mn = grpc_wrap(d, n, msg, sizeof(msg));
            if (!mn) return H2_ETOOBIG;
            return h2_write(&c->h2, msg, mn);
        }
        default:
            return io_write(c, d, n);
    }
}

int vless_recv(struct vless_conn *c, unsigned char *d, size_t cap, size_t *got) {
    *got = 0;
    switch (c->tr) {
        case VT_XHTTP:
            return h2_read(&c->h2, d, cap, got);
        case VT_GRPC: {
            /* Один буфер на ПОТОК, а не на соединение: по 16 КБ на каждое соединение
             * это мегабайт на коробке с пятнадцатью, а потоков всего несколько. Общим он
             * был, пока поток был один; теперь общий массив потоки переписывали бы друг под
             * другом — и это не «иногда мусор», а перепутанные куски чужого соединения. */
            static __thread unsigned char raw[H2_MIN_READ_CAP];
            size_t rn = 0;
            int rc = h2_read(&c->h2, raw, sizeof(raw), &rn);
            if (rc) return rc;
            if (!rn) return 0;
            return grpc_unwrap(&c->de, raw, rn, d, cap, got);
        }
        default:
            return io_read(c, d, cap, got);
    }
}

/* Проверка узла: единственный способ узнать, признал ли нас Reality.
 *
 * Просим у сервера соединение с заведомо живым адресом и смотрим на ПЕРВЫЙ БАЙТ ответа.
 * Версия 0 — это ответ VLESS, то есть сервер наш. Что угодно другое означает, что нас не
 * признали и мы разговариваем с настоящим сайтом: соединение при этом рабочее, страница
 * откроется, и без этой проверки узел выглядел бы полностью здоровым.
 *
 * Обращаемся к 1.1.1.1:80 и ждём хоть какой-то ответ: цель не проверить интернет, а
 * получить от СЕРВЕРА подтверждение, что он понял запрос VLESS. Побочно это и есть
 * измерение задержки — тот же путь, по которому пойдёт настоящий трафик. */
int vless_probe(const struct vless_node *node, int timeout_s, char *why, size_t why_n) {
    return vless_probe_timed(node, timeout_s, why, why_n, NULL, NULL);
}

int vless_probe_timed(const struct vless_node *node, int timeout_s, char *why, size_t why_n,
                      int *handshake_ms, int *ttfb_ms) {
    if (handshake_ms) *handshake_ms = -1;
    if (ttfb_ms) *ttfb_ms = -1;

    struct vless_conn c;
    int64_t t0 = now_ms();
    int rc = vless_connect(node, &c, timeout_s);
    if (rc) {
        snprintf(why, why_n, "%s", vless_strerror(rc));
        return rc;
    }
    if (handshake_ms) *handshake_ms = (int)(now_ms() - t0);

    unsigned char uuid[16];
    if (vless_uuid_parse(node->uuid, uuid) != 0) {
        vless_close(&c);
        snprintf(why, why_n, "UUID неразборчив");
        return VLESS_CONN_EBADUUID;
    }

    unsigned char req[512];
    unsigned char probe_ip[4] = { 1, 1, 1, 1 };
    size_t req_n = vless_build_request(uuid, VLESS_CMD_TCP, NULL, probe_ip, 80,
                                       node->flow, req, sizeof(req));
    if (!req_n) { vless_close(&c); snprintf(why, why_n, "заголовок не собрался"); return VLESS_CONN_EIO; }

    /* Минимальный HTTP-запрос вместе с заголовком: сервер не отвечает, пока не получит
     * данные для пересылки, и без них проверка ждала бы до таймаута. */
    static const char http[] = "GET / HTTP/1.1\r\nHost: 1.1.1.1\r\nConnection: close\r\n\r\n";
    if (req_n + sizeof(http) - 1 <= sizeof(req)) {
        memcpy(req + req_n, http, sizeof(http) - 1);
        req_n += sizeof(http) - 1;
    }

    /* Заголовок VLESS и данные с Vision — РАЗНЫЕ вещи, и порядок здесь не произволен.
     *
     * Заголовок уходит сырым, сразу за ним первый кадр Vision с данными. В Xray это видно
     * по XtlsPadding: обёртка применяется к буферам ДАННЫХ, а комментарий «we do a long
     * padding to hide vless header» означает, что заголовок прячет набивка СЛЕДУЮЩЕГО
     * кадра, попадая с ним в одну TLS-запись — а не что заголовок лежит внутри кадра.
     *
     * Первая версия заворачивала заголовок внутрь кадра. Сервер тогда читал UUID (он
     * совпадал), брал следующие 5 байт как команду и длины — а там была версия VLESS и
     * начало UUID из заголовка. Длины выходили бессмысленные, и сервер закрывал
     * соединение: read возвращал -11, то есть выглядело как отказ по ключу. */
    if (node->flow[0]) {
        struct vision vis;
        vless_uuid_parse(node->uuid, uuid);
        vision_init(&vis, uuid);
        static __thread unsigned char framed[8192];
        /* Заголовок VLESS занимает первые header_n байт req — остальное это HTTP-данные. */
        size_t header_n = req_n - (sizeof(http) - 1);
        size_t fn = vision_wrap(&vis, req + header_n, req_n - header_n,
                                framed, sizeof(framed));
        if (!fn) { vless_close(&c); snprintf(why, why_n, "кадр Vision не собрался"); return VLESS_CONN_EIO; }
        /* Одной записью: заголовок и кадр должны уехать вместе, иначе их разделение по
         * записям само становится признаком. */
        static __thread unsigned char together[8704];
        if (header_n + fn > sizeof(together)) { vless_close(&c); snprintf(why, why_n, "не влезло"); return VLESS_CONN_EIO; }
        memcpy(together, req, header_n);
        memcpy(together + header_n, framed, fn);
        rc = vless_send(&c, together, header_n + fn);
    } else {
        rc = vless_send(&c, req, req_n);
    }
    if (rc) { vless_close(&c); snprintf(why, why_n, "запрос не ушёл: %s", vless_strerror(rc)); return rc; }
    int64_t t_sent = now_ms();

    /* Буфер по мерке транспорта, а не «с запасом»: поверх HTTP/2 за один раз приезжает до
     * целой записи TLS, и меньший буфер дал бы ошибку на совершенно законном кадре. */
    static __thread unsigned char buf[VLESS_MIN_RECV_CAP];
    size_t got = 0;
    /* Ждём данных ПО ЧАСАМ, а не заданным числом попыток.
     *
     * Ноль байт от vless_recv означает «пока нечего», и причин тому две: служебный кадр
     * HTTP/2 (SETTINGS, WINDOW_UPDATE) или запись, которая ещё не приехала целиком. Чтение
     * записей неблокирующее — оно обязано таким быть, потому что в туннеле один цикл на все
     * соединения, — поэтому восемь попыток подряд проходили за микросекунды, ещё до того
     * как ответ вообще успевал прийти по сети.
     *
     * Стоило это дорого: проба объявляла «сервер не прислал данных» на полностью рабочем
     * узле. Туннель при этом работал, потому что при заданном номере узла он пробу не
     * вызывает вовсе, — и расхождение между «узел не проходит проверку» и «через узел идёт
     * трафик» выглядело как что угодно, кроме ошибки в самой проверке. Проверено на своём
     * Reality-сервере (tests/run-reality.sh): сервер отвечал, в его логе видно и разбор
     * нашего кадра Vision, и отправленный нам ответ.
     *
     * Ждём на сокете, а не в холостом цикле: иначе это те же микросекунды, только дороже. */
    int64_t rx_deadline = now_ms() + (int64_t)(timeout_s > 0 ? timeout_s : 8) * 1000;
    for (;;) {
        rc = vless_recv(&c, buf, sizeof(buf), &got);
        if (rc) { vless_close(&c); snprintf(why, why_n, "ответа нет: %s", vless_strerror(rc)); return rc; }
        if (got) break;
        if (now_ms() >= rx_deadline) break;
        struct pollfd pw = { .fd = c.fd, .events = POLLIN, .revents = 0 };
        poll(&pw, 1, 200);
    }
    if (!got) { vless_close(&c); snprintf(why, why_n, "сервер не прислал данных"); return VLESS_CONN_EIO; }
    /* Первый байт пришёл. Замер сделан ДО разбора ответа: разбор ничего не ждёт, а
     * включать его в задержку значило бы мерить свою же работу. */
    if (ttfb_ms) *ttfb_ms = (int)(now_ms() - t_sent);

    /* Ответ Vision тоже в кадрах, и первым в них идёт заголовок VLESS. Разворачиваем
     * до разбора: иначе version-байт читался бы из поля команды кадра. */
    const unsigned char *body = buf;
    size_t body_n = got;
    if (node->flow[0]) {
        struct vision rv;
        memset(&rv, 0, sizeof(rv));
        size_t used = 0;
        const unsigned char *pl = NULL;
        size_t pl_n = 0;
        if (vision_unwrap(&rv, buf, got, &used, &pl, &pl_n) == 0 && pl) {
            body = pl;
            body_n = pl_n;
        }
    }

    size_t skip = 0;
    int pr = vless_parse_response(body, body_n, &skip);
    vless_close(&c);

    if (pr == VLESS_EPROTO) {
        /* Вот он, тихий отказ Reality. Говорим прямо, потому что иначе это неотличимо
         * от рабочего узла: TLS установлен, ответ пришёл, но он от чужого сайта. */
        snprintf(why, why_n,
                 "сервер не признал ключ — отвечает маскировочный сайт, а не туннель "
                 "(проверьте pbk, sid и sni)");
        return VLESS_CONN_EREJECTED;
    }
    if (pr == VLESS_EAGAIN) {
        snprintf(why, why_n, "ответ слишком короткий (%zu байт)", got);
        return VLESS_CONN_EIO;
    }
    snprintf(why, why_n, "ok, ответ VLESS (%zu байт)", got);
    return 0;
}

int vless_recv_zc(struct vless_conn *c, unsigned char *buf, size_t cap,
                  const unsigned char **data, size_t *got) {
    *got = 0;
    *data = buf;
    /* Без копии — только на голом транспорте: у grpc и xhttp между TLS и данными лежит
     * HTTP/2, и он всё равно перекладывает тело кадра в свой буфер. Тянуть указатель ещё и
     * через него значило бы усложнить разбор ради случая, который на этих транспортах не
     * встречается. Прямое копирование (rx_direct) и security=none читают сокет сами. */
    if (c->tr == VT_RAW && !c->plain && !c->rx_direct)
        return tls13_read_ref(&c->tls, data, got);
    return vless_recv(c, buf, cap, got);
}

/* Есть ли у нас непрочитанное, о чём ядро не расскажет.
 *
 * Спрашивает туннель, прежде чем уйти ждать событий: данные, уже вынутые из сокета в буфер
 * записей, для epoll не существуют. Зачем это важно — в tls13.h у tls13_has_record.
 *
 * Три режима, а не один. Без TLS буфера нет вовсе. В прямом копировании нет и границ
 * записей — значимо просто «есть байты». В обычном режиме — только ЦЕЛАЯ запись: по части
 * записи мы всё равно ничего не сможем отдать, и считать её готовностью значило бы крутить
 * цикл впустую до прихода остатка. */
int vless_has_data(const struct vless_conn *c) {
    if (c->plain) return 0;
    if (c->rx_direct) return tls13_buffered(&c->tls) > 0;
    return tls13_has_record(&c->tls);
}

void vless_close(struct vless_conn *c) {
    if (c->fd >= 0) close(c->fd);
    c->fd = -1;
    /* Контексты шифров живут в куче: без освобождения туннель за час работы утекает на
     * тысячах соединений. */
    if (!c->plain) tls13_free(&c->tls);
    c->tls.ready = 0;
}

const char *vless_strerror(int rc) {
    switch (rc) {
        case 0: return "ok";
        case VLESS_CONN_EDNS: return "имя не разрешилось";
        case VLESS_CONN_ESOCK: return "нет сокета";
        case VLESS_CONN_ECONNECT: return "TCP не соединился";
        case VLESS_CONN_EIO: return "обрыв ввода-вывода";
        case VLESS_CONN_ECLOSED: return "сервер закрыл соединение";
        case VLESS_CONN_EBADUUID: return "UUID неразборчив";
        case VLESS_CONN_EREJECTED: return "сервер не признал ключ";
        case VLESS_CONN_ENOH2: return "сервер не согласился на HTTP/2 (нужен для grpc и xhttp)";
        case VLESS_CONN_EGRPC: return "поток gRPC в неожиданной форме";
        case H2_EIO: case H2_EPROTO: case H2_ESTATUS:
        case H2_ERESET: case H2_ETOOBIG: case H2_EWINDOW: return h2_strerror(rc);
        case REALITY_EBADKEY: return "pbk или sid не разобрались";
        case REALITY_ECRYPTO: return "сбой криптографии";
        case REALITY_ETOOBIG: return "ClientHello не влез";
        case TLS13_EAUTH: return "AEAD не сошёлся (ключи разъехались)";
        case TLS13_EFINISHED: return "Finished не совпал";
        case TLS13_ENOKEYSHARE: return "ServerHello без key_share";
        case TLS13_EBADSUITE: return "сервер выбрал неподдержанный шифр";
        case TLS13_EBADREC: return "испорченная TLS-запись";
        case TLS13_ECLOSED: return "TLS закрыт сервером";
        case TLS13_EIO: return "ошибка чтения TLS";
        default: return "неизвестная ошибка";
    }
}
