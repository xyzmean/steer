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
#include <arpa/inet.h>

#include "vless.h"
#include "reality.h"
#include "tls13.h"
#include "vless_proto.h"
#include "vision.h"
#include "client.h"

static int tcp_connect(const char *host, uint16_t port, int timeout_s) {
    char portstr[8];
    snprintf(portstr, sizeof(portstr), "%u", port);
    struct addrinfo hints = { .ai_family = AF_INET, .ai_socktype = SOCK_STREAM };
    struct addrinfo *res = NULL;
    if (getaddrinfo(host, portstr, &hints, &res) != 0 || !res) return VLESS_CONN_EDNS;

    int fd = socket(res->ai_family, SOCK_STREAM, 0);
    if (fd < 0) { freeaddrinfo(res); return VLESS_CONN_ESOCK; }

    /* Таймаут на чтение и запись. Без него мёртвый узел вешает проверку до таймаута
     * ядра — минуты, за которые сторож не успеет обойти остальных кандидатов. */
    struct timeval tv = { .tv_sec = timeout_s, .tv_usec = 0 };
    setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
    setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));
    int one = 1;
    setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, &one, sizeof(one));

    if (connect(fd, res->ai_addr, res->ai_addrlen) != 0) {
        close(fd);
        freeaddrinfo(res);
        return VLESS_CONN_ECONNECT;
    }
    freeaddrinfo(res);
    return fd;
}

/* Полное установление: TCP + Reality + TLS 1.3. Возвращает 0 и заполняет conn. */
int vless_connect(const struct vless_node *node, struct vless_conn *conn, int timeout_s) {
    memset(conn, 0, sizeof(*conn));
    conn->fd = -1;

    int fd = tcp_connect(node->host, node->port, timeout_s);
    if (fd < 0) return fd;
    conn->fd = fd;

    /* security=none — голый VLESS, без TLS вообще. Полезен в доверенной сети, и именно
     * поэтому он не «частный случай reality», а отдельная ветка: ставить TLS там, где
     * его нет, значило бы просто не соединиться. */
    if (strcmp(node->security, "none") == 0) {
        conn->plain = 1;
        return 0;
    }

    struct reality_cfg cfg = {
        .sni = node->sni, .pbk = node->pbk, .sid = node->sid, .fp = node->fp,
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
    return 0;
}

static int conn_write(struct vless_conn *c, const unsigned char *d, size_t n) {
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

static int conn_read(struct vless_conn *c, unsigned char *d, size_t cap, size_t *got) {
    if (c->plain) {
        ssize_t r = read(c->fd, d, cap);
        if (r <= 0) return r == 0 ? VLESS_CONN_ECLOSED : VLESS_CONN_EIO;
        *got = (size_t)r;
        return 0;
    }
    return tls13_read(&c->tls, d, cap, got);
}

/* Проверка узла: единственный способ узнать, признал ли нас Reality.
 *
 * Просим у сервера соединение с заведомо живым адресом и смотрим на ПЕРВЫЙ БАЙТ ответа.
 * Версия 0 — это ответ VLESS, то есть сервер наш. Что угодно другое означает, что нас не
 * признали и мы разговариваем с настоящим сайтом: соединение при этом рабочее, страница
 * откроется, и без этой проверки узел выглядел бы полностью здоровым.
 *
 * Обращаемся к 1.1.1.1:80 и ждём хоть какой-то ответ: цель не проверить интернет, а
 * получить от СЕРВЕРА подтверждение, что он понял запрос VLESS. */
int vless_probe(const struct vless_node *node, int timeout_s, char *why, size_t why_n) {
    struct vless_conn c;
    int rc = vless_connect(node, &c, timeout_s);
    if (rc) {
        snprintf(why, why_n, "%s", vless_strerror(rc));
        return rc;
    }

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
        static unsigned char framed[8192];
        /* Заголовок VLESS занимает первые header_n байт req — остальное это HTTP-данные. */
        size_t header_n = req_n - (sizeof(http) - 1);
        size_t fn = vision_wrap(&vis, req + header_n, req_n - header_n,
                                framed, sizeof(framed));
        if (!fn) { vless_close(&c); snprintf(why, why_n, "кадр Vision не собрался"); return VLESS_CONN_EIO; }
        /* Одной записью: заголовок и кадр должны уехать вместе, иначе их разделение по
         * записям само становится признаком. */
        static unsigned char together[8704];
        if (header_n + fn > sizeof(together)) { vless_close(&c); snprintf(why, why_n, "не влезло"); return VLESS_CONN_EIO; }
        memcpy(together, req, header_n);
        memcpy(together + header_n, framed, fn);
        rc = conn_write(&c, together, header_n + fn);
    } else {
        rc = conn_write(&c, req, req_n);
    }
    if (rc) { vless_close(&c); snprintf(why, why_n, "запрос не ушёл: %s", vless_strerror(rc)); return rc; }

    unsigned char buf[4096];
    size_t got = 0;
    rc = conn_read(&c, buf, sizeof(buf), &got);
    if (rc) { vless_close(&c); snprintf(why, why_n, "ответа нет: %s", vless_strerror(rc)); return rc; }

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

void vless_close(struct vless_conn *c) {
    if (c->fd >= 0) close(c->fd);
    c->fd = -1;
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
