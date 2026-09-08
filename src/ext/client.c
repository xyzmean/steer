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

/* Режим xhttp узла. Пусто и «auto» — stream-one: его же выбирает Xray при reality, и он
 * дешевле всех. Всё остальное названо в ссылке явно, и разбор подписки уже отсеял то, чего
 * мы не умеем (sub.c), так что сюда доходят только эти три. */
static enum xhttp_mode xhttp_mode_of(const struct vless_node *n) {
    if (!strcmp(n->mode, "packet-up")) return XH_PACKET_UP;
    if (!strcmp(n->mode, "stream-up")) return XH_STREAM_UP;
    return XH_STREAM_ONE;
}

/* Идентификатор сессии. Ровно им сервер связывает запрос выгрузки с запросом загрузки, и
 * поэтому он обязан быть непредсказуемым: угадав его, посторонний влил бы свои байты в чужую
 * сессию. Форма — как у Xray по умолчанию, строка UUID: она же встречается в путях обычных
 * приложений и ничем не выделяется. */
static void session_id(char *out, size_t cap) {
    unsigned char r[16];
    if (getrandom(r, sizeof r, 0) != (ssize_t)sizeof r) {
        /* Источник случайности отказал. Нули здесь были бы ХУЖЕ отказа: сессия стала бы
         * предсказуемой, оставаясь на вид рабочей. Пусть будет заведомо негодная строка —
         * сервер её примет, но такой узел не поднимется, и это заметят. */
        snprintf(out, cap, "00000000-0000-0000-0000-000000000000");
        return;
    }
    r[6] = (unsigned char)((r[6] & 0x0F) | 0x40);   /* версия 4 */
    r[8] = (unsigned char)((r[8] & 0x3F) | 0x80);   /* вариант   */
    snprintf(out, cap,
             "%02x%02x%02x%02x-%02x%02x-%02x%02x-%02x%02x-%02x%02x%02x%02x%02x%02x",
             r[0], r[1], r[2], r[3], r[4], r[5], r[6], r[7],
             r[8], r[9], r[10], r[11], r[12], r[13], r[14], r[15]);
}

/* Referer с набивкой для одного запроса.
 *
 * Своя длина у КАЖДОГО запроса, а не одна на соединение: у packet-up запросов череда, и
 * одинаковая длина набивки во всех превратила бы саму набивку в признак — то есть в ровно
 * то, против чего она заведена. Диапазон 100..1000 знаков задан сервером Xray
 * (GetNormalizedXPaddingBytes), и выйти за него значит получить отказ. */
static int xhttp_referer_r(char *out, size_t cap, const char *authority, const char *path,
                           uint16_t pf, uint16_t pt);

static int xhttp_referer(char *out, size_t cap, const char *authority, const char *path,
                         const struct vless_node *n) {
    return xhttp_referer_r(out, cap, authority, path, n ? n->pad_from : 0, n ? n->pad_to : 0);
}

static int xhttp_referer_r(char *out, size_t cap, const char *authority, const char *path,
                           uint16_t pf, uint16_t pt) {
    /* ДЛИНУ ЗАДАЁТ СЕРВЕР, А НЕ МЫ. Она приезжает в ссылке полем `xPaddingBytes` (см.
     * pad_range в sub.c), и сервер её ПРОВЕРЯЕТ: не попал в диапазон — 400 и всё.
     *
     * Прежде здесь стояло жёсткое 150…660. Оно укладывается в умолчание Xray (100…1000) и
     * потому работало почти везде — а на подписке, где продавец объявил «50-150», отвечали
     * отказом ВСЕ его узлы xhttp. Выглядело это как «узлы мёртвые»: TLS проходит, Reality
     * признаёт, и только потом 400.
     *
     * Пусто — умолчание Xray 100…1000 (GetNormalizedXPaddingBytes), а не прежние 150…660:
     * повторяем upstream, чтобы у нас и у него совпадали не только границы, но и середина. */
    size_t lo = pt ? pf : 100;
    size_t hi = pt ? pt : 1000;
    unsigned char r = 0;
    if (getrandom(&r, 1, 0) != 1) r = 128;
    size_t pad = lo + (size_t)r * (hi - lo + 1) / 256;
    if (pad < lo) pad = lo;
    if (pad > hi) pad = hi;
    int k = snprintf(out, cap, "https://%s%s?x_padding=", authority, path);
    if (k < 0 || (size_t)k + pad + 1 > cap) return H2_ETOOBIG;
    memset(out + k, 'X', pad);
    out[k + pad] = '\0';
    return 0;
}

static int up_write(void *ctx, const unsigned char *d, size_t n) {
    struct vless_up *u = ctx;
    if (u->plain) {
        size_t sent = 0;
        while (sent < n) {
            ssize_t w = write(u->fd, d + sent, n - sent);
            if (w <= 0) {
                if (w < 0 && errno == EINTR) continue;
                return VLESS_CONN_EIO;
            }
            sent += (size_t)w;
        }
        return 0;
    }
    return tls13_write(&u->tls, d, n);
}

static int up_read(void *ctx, unsigned char *d, size_t cap, size_t *got) {
    struct vless_up *u = ctx;
    /* Прямого копирования здесь не бывает: Vision живёт на потоке ЗАГРУЗКИ, а эта связь
     * только пишет. Ответы сервера на выгрузку — пустые 200, и читаются они лишь затем,
     * чтобы разобрать служебные кадры HTTP/2 и не переполнить окно.
     *
     * ЖДАТЬ ЗДЕСЬ НЕЛЬЗЯ. Слив ответов делается попутно с отправкой, и блокирующее чтение
     * остановило бы выгрузку до прихода ответа — то есть превратило бы поток в череду
     * «отправил и жду». Поверх TLS ожидания и нет: tls13_read опрашивает сокет с нулевым
     * сроком и отдаёт ноль байт, когда записи ещё нет. На голом сокете (security=none)
     * такого поведения нет, и опрос приходится ставить самим. */
    if (u->plain) {
        struct pollfd p = { .fd = u->fd, .events = POLLIN };
        if (poll(&p, 1, 0) <= 0 || !(p.revents & POLLIN)) { *got = 0; return 0; }
        ssize_t r = read(u->fd, d, cap);
        if (r == 0) return VLESS_CONN_ECLOSED;
        if (r < 0) {
            if (errno == EAGAIN || errno == EWOULDBLOCK || errno == EINTR) { *got = 0; return 0; }
            return VLESS_CONN_EIO;
        }
        *got = (size_t)r;
        return 0;
    }
    return tls13_read(&u->tls, d, cap, got);
}

/* Слить то, что сервер ответил на выгрузку.
 *
 * ЗАЧЕМ ЭТО ВООБЩЕ НАДО. На каждый кусок packet-up сервер отвечает пустым 200: заголовки,
 * пустой DATA, END_STREAM — десятки байт. Не читать их значит копить в приёмном буфере
 * сокета; когда он заполнится, сервер перестанет писать, а следом застрянет и разбор его
 * стороны — выгрузка встанет, причём тем позже, чем больше буфер, то есть «иногда и на
 * больших файлах». Заодно этот же вызов забирает служебные кадры HTTP/2 (SETTINGS,
 * WINDOW_UPDATE, PING) — без них окно соединения не пополнялось бы вовсе.
 *
 * Ничего не ждёт и ничего не отдаёт: прочитанное выбрасывается. */
static void up_drain(struct vless_up *u) {
    if (!u->started) return;
    static __thread unsigned char sink[H2_MIN_READ_CAP];
    for (int i = 0; i < 4; i++) {
        size_t got = 0;
        if (h2_read(&u->h2, sink, sizeof(sink), &got) != 0) return;
        if (!got) return;
    }
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
    snprintf(c->authority, sizeof(c->authority), "%s", authority);
    c->pad_from = n->pad_from;
    c->pad_to = n->pad_to;

    /* __thread: буфер живёт между вызовами, но потоков теперь несколько, и один общий
     * массив они переписывали бы друг под другом. Своя копия на поток — 1,4 КБ. */
    static __thread char ref[1400];

    if (c->xh == XH_STREAM_ONE) {
        if (xhttp_referer(ref, sizeof(ref), authority, path, n)) return H2_ETOOBIG;
        /* Content-Type: application/grpc и здесь — так делает Xray (FillStreamRequest ставит
         * его на любой запрос С ТЕЛОМ), и посредники по нему не пытаются буферизовать поток.
         * Всё остальное в заголовках — облик БРАУЗЕРА, а не gRPC: см. put_headers в h2.c. */
        return h2_start_ex(&c->h2, &io, authority, path, "application/grpc", ref,
                           H2_POST, 0, 1);
    }

    /* Два оставшихся режима начинаются одинаково: сессия получает имя, и по этому имени
     * сервер потом свяжет с ней запросы выгрузки. Имя дописывается к пути — так у Xray
     * задано по умолчанию (session placement = path), и так его читает hub.go. */
    char sid[40];
    session_id(sid, sizeof(sid));
    if (snprintf(c->up_path, sizeof(c->up_path), "%s%s", path, sid) >= (int)sizeof(c->up_path))
        return H2_ETOOBIG;

    /* ЭТА связь — за загрузкой, и запрос у неё GET без тела. Метод здесь не украшение:
     * сервер отличает выгрузку от загрузки именно им (hub.go: GET без номера куска — это
     * stream-down). POST без тела сервер счёл бы выгрузкой и стал бы ждать байт, которых
     * не будет, а вниз не отдал бы ничего. */
    if (xhttp_referer(ref, sizeof(ref), authority, c->up_path, n)) return H2_ETOOBIG;
    return h2_start_ex(&c->h2, &io, authority, c->up_path, NULL, ref, H2_GET, 1, 1);
}

/* Установление TCP живёт ниже по файлу: там же, где разрешение имени и happy-eyeballs.
 * Объявление здесь, а не перенос функции — перенос сдвинул бы полтораста строк и утопил бы
 * в диффе смысл правки. */
static int tcp_connect(const char *host, uint16_t port, int timeout_s);

/* Поднять вторую связь — под выгрузку. Тот же путь установления, что и у первой: TCP, и
 * дальше либо ничего (security=none), либо Reality, либо обычный TLS с проверкой. */
static int up_connect(struct vless_conn *c, const struct vless_node *n, int timeout_s) {
    struct vless_up *u = &c->up;
    memset(u, 0, sizeof(*u));
    u->fd = -1;

    int fd = tcp_connect(n->host, n->port, timeout_s);
    if (fd < 0) return fd;
    u->fd = fd;

    if (!strcmp(n->security, "none")) { u->plain = 1; return 0; }

    int is_tls = strcmp(n->security, "tls") == 0;
    const char *verify_host = n->sni[0] ? n->sni : n->host;
    struct reality_cfg cfg = {
        .sni = is_tls ? verify_host : n->sni,
        .pbk = n->pbk, .sid = n->sid, .fp = n->fp,
        .alpn = "h2",
        .plain = is_tls,
    };
    struct reality_state rst;
    unsigned char hello[2048];
    size_t hello_n = 0;
    int rc = reality_build_hello(&cfg, &rst, hello, sizeof(hello), &hello_n);
    if (rc) { close(fd); u->fd = -1; return rc; }

    size_t sent = 0;
    while (sent < hello_n) {
        ssize_t w = write(fd, hello + sent, hello_n - sent);
        if (w <= 0) {
            if (w < 0 && errno == EINTR) continue;
            close(fd); u->fd = -1;
            return VLESS_CONN_EIO;
        }
        sent += (size_t)w;
    }

    struct tls13_auth auth = { 0 };
    if (is_tls) auth.host = verify_host;
    else        auth.reality_key = rst.authkey;

    rc = tls13_handshake_auth(&u->tls, fd, hello, hello_n, rst.priv, &auth);
    if (rc) { close(fd); u->fd = -1; return rc; }
    if (u->tls.alpn[0] && strcmp(u->tls.alpn, "h2") != 0) {
        tls13_free(&u->tls); close(fd); u->fd = -1;
        return VLESS_CONN_ENOH2;
    }
    return 0;
}

/* Поднять выгрузку, если она нужна этому режиму. Для stream-one не делает ничего: там
 * выгрузка идёт телом того же единственного запроса. */
static int up_open(struct vless_conn *c, const struct vless_node *n, int timeout_s);

/* Открыть очередной запрос выгрузки. seq < 0 — постоянный поток stream-up (номера у него
 * нет), иначе номер куска packet-up. */
static int up_request(struct vless_conn *c, long long seq) {
    struct vless_up *u = &c->up;
    struct h2_io io = { .ctx = u, .write = up_write, .read = up_read };
    char path[320];
    if (seq < 0) snprintf(path, sizeof(path), "%s", c->up_path);
    else         snprintf(path, sizeof(path), "%s/%lld", c->up_path, seq);

    static __thread char ref[1400];
    if (xhttp_referer_r(ref, sizeof(ref), c->authority, path, c->pad_from, c->pad_to))
        return H2_ETOOBIG;

    if (!u->started) {
        int rc = h2_start_ex(&u->h2, &io, c->authority, path, "application/grpc", ref,
                             H2_POST, 0, 1);
        if (rc) return rc;
        u->started = 1;
        return 0;
    }
    return h2_next(&u->h2, c->authority, path, "application/grpc", ref, H2_POST);
}

static int up_open(struct vless_conn *c, const struct vless_node *n, int timeout_s) {
    if (c->tr != VT_XHTTP || c->xh == XH_STREAM_ONE) return 0;

    int rc = up_connect(c, n, timeout_s);
    if (rc) return rc;

    /* stream-up открывает свой POST сразу и держит его открытым до конца соединения: тело
     * этого запроса и есть канал наверх.
     *
     * packet-up НЕ открывает ничего заранее. Запрос там живёт ровно один кусок, и открыть
     * его до того, как кусок появился, значило бы держать на сервере пустую выгрузку —
     * причём с номером 0, который потом пришлось бы пропустить. Первый запрос откроется в
     * первой же отправке. */
    if (c->xh == XH_STREAM_UP) return up_request(c, -1);
    c->seq = 0;
    return 0;
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
    /* Режим определяется ЗДЕСЬ, один раз: дальше он читается и при открытии потоков, и при
     * каждой отправке, и три независимых разбора строки разошлись бы. */
    if (conn->tr == VT_XHTTP) conn->xh = xhttp_mode_of(node);

    if (strcmp(node->security, "none") == 0) {
        conn->plain = 1;
        /* Без TLS согласовывать ALPN нечем, поэтому HTTP/2 начинаем сразу: голый h2 по
         * TCP («h2c») сервер либо примет, либо ответит мусором, и это увидит проверка. */
        if (conn->tr == VT_RAW) return 0;
        rc_h2 = h2_open(conn, node);
        /* Единственная ветка отказа в этой функции, которая дескриптор НЕ закрывала —
         * все соседние закрывают. Узел security=none с транспортом grpc/xhttp, который
         * не отвечает по h2, за сутки опроса упирал процесс в RLIMIT_NOFILE. */
        if (rc_h2) { close(fd); conn->fd = -1; return rc_h2; }
        rc_h2 = up_open(conn, node, timeout_s);
        if (rc_h2) { vless_close(conn); return rc_h2; }
        return 0;
    }

    /* security=tls — обычный TLS, без Reality.
     *
     * Отличий от ветки Reality ровно три, и все три обязательны. ClientHello без
     * аутентификатора (иначе сервер увидел бы в session_id мусор — безвредный, но
     * бессмысленный). ИМЯ обязано быть: у Reality пустой SNI законен (сервер ждёт Hello без
     * расширения), а обычному TLS без имени нечего предъявить и нечем проверить сертификат.
     * И сама проверка сертификата — единственное, что здесь доказывает подлинность сервера.
     *
     * Имя берётся из sni, а host — только запасным: sni это то, что мы просим у сервера, и
     * проверять сертификат надо против него же. Узел, объявленный одним адресом без имени,
     * проверяется против адреса — и не пройдёт, если сертификат выдан не на него. Это
     * правильный отказ, а не наша строгость: ровно так же поступает Xray. */
    int is_tls = strcmp(node->security, "tls") == 0;
    const char *verify_host = node->sni[0] ? node->sni : node->host;

    struct reality_cfg cfg = {
        .sni = is_tls ? verify_host : node->sni,
        .pbk = node->pbk, .sid = node->sid, .fp = node->fp,
        /* ALPN просим ровно тогда, когда он нужен. Для tcp его нет — и Hello остаётся
         * тем самым, который проверен на живых узлах. */
        .alpn = conn->tr == VT_RAW ? NULL : "h2",
        .plain = is_tls,
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
    /* Чем доказывать подлинность — решается видом узла, и вариант всегда ровно один.
     * У обычного TLS это цепочка и имя, у Reality — HMAC в поле подписи временного
     * сертификата на ключе, который есть только у владельца постоянной пары. */
    struct tls13_auth auth = { 0 };
    if (is_tls) auth.host = verify_host;
    else        auth.reality_key = conn->rst.authkey;

    rc = tls13_handshake_auth(&conn->tls, fd, hello, hello_n, conn->rst.priv, &auth);
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
        rc = up_open(conn, node, timeout_s);
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
            switch (c->xh) {
                case XH_STREAM_ONE:
                    return h2_write(&c->h2, d, n);
                case XH_STREAM_UP:
                    /* Один длинный POST на всё соединение: пишем в него и попутно
                     * забираем то, что сервер успел ответить. */
                    { int rc = h2_write(&c->up.h2, d, n); up_drain(&c->up); return rc; }
                case XH_PACKET_UP: {
                    /* Кусок = отдельный запрос: открыть, записать, закрыть свою половину.
                     *
                     * БЕЗ НАКОПЛЕНИЯ. Xray собирает мелкие записи в куски до мегабайта и
                     * прямо пишет, что без этого полоса «крайне ограничена». У нас копить
                     * нечем: накопитель требует срока сброса, то есть таймера или своего
                     * потока на каждое соединение, — а туннель зовёт отправку сам и о
                     * времени ничего не знает. Поэтому один запрос на один вызов, и это
                     * честная плата за режим, который выбирают тогда, когда другие не
                     * проходят вовсе. */
                    int rc = up_request(c, (long long)c->seq);
                    if (rc) return rc;
                    rc = h2_write(&c->up.h2, d, n);
                    if (rc) return rc;
                    rc = h2_end_stream(&c->up.h2);
                    c->seq++;
                    up_drain(&c->up);
                    return rc;
                }
            }
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

    /* Вторая связь закрывается ЗДЕСЬ ЖЕ и по тому же доводу. Забыть её значило бы утечку
     * ровно вдвое злее обычной: на соединение приходится и лишний дескриптор, и лишний
     * набор контекстов AES. Существует она только у stream-up и packet-up; у остальных
     * fd равен нулю после memset, поэтому проверка на «больше нуля», а не «не -1». */
    if (c->up.fd > 0) close(c->up.fd);
    c->up.fd = -1;
    if (!c->up.plain) tls13_free(&c->up.tls);
    c->up.tls.ready = 0;
    c->up.started = 0;
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
        /* «Молчит», а не «ошибка»: соединение TCP встало, а на ClientHello ответа нет. Так
         * выглядит блокировка по имени в SNI, лежачий узел и потерянный пакет — то есть
         * причина снаружи движка, и текст обязан отправлять смотреть туда. */
        case TLS13_ETIMEOUT: return "узел не ответил на ClientHello (таймаут)";
        /* Причина у отказа проверки одна на код, но РАЗНАЯ по сути — «нечем проверить» это
         * не то же самое, что «проверили и не сошлось». Точный текст приносит tls13.c, и
         * общее слово добавляется здесь, чтобы человек видел, о чём вообще речь. */
        case TLS13_ECERT: {
            static __thread char why[128];
            const char *d = tls13_verify_reason();
            snprintf(why, sizeof why, "сервер не доказал подлинность%s%s",
                     d && d[0] ? ": " : "", d && d[0] ? d : "");
            return why;
        }
        default: return "неизвестная ошибка";
    }
}
