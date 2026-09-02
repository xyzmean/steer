/* Мост Telegram → WebSocket: приложение не настраивают, соединение перехватывают.
 *
 * ЗАЧЕМ. Telegram ходит в свои дата-центры по TCP на их адреса, и режут именно это. У
 * веб-клиента есть второй путь: тот же MTProto, завёрнутый в WebSocket поверх TLS к
 * `wss://kwsN.web.telegram.org/apiws`, а эти имена стоят за Cloudflare — блокировать их
 * значит блокировать Cloudflare. Готовые прокси (tg-ws-proxy и родня) этим и живут, но
 * требуют вписать адрес и секрет В КАЖДОМ КЛИЕНТЕ. Здесь то же самое делается прозрачно:
 * правило nat заворачивает соединение на этот мост, а он уводит его веб-сокетом.
 *
 * ПОЧЕМУ ЧУЖОЙ ПРОКСИ СЮДА НЕ ПОСТАВИТЬ. Он ждёт рукопожатие MTPROXY: там есть секрет, и из
 * него же берётся номер дата-центра. Приложение, идущее в дата-центр напрямую, шлёт другое
 * рукопожатие — без секрета, и номера в нём нет вовсе. Завернуть одно в другое нечем, кроме
 * как разобрав его самим, — этим мост и занимается.
 *
 * ПОЧЕМУ ПОТОК ИДЁТ НАСКВОЗЬ. Обфускация MTProto ключей не согласовывает: клиент шлёт 64
 * случайных байта, и ключ с вектором — это байты [8..40] и [40..56] прямо из них, без
 * секрета (секрет подмешивается только у MTProxy — core.telegram.org/mtproto/
 * mtproto-transports). Точка `apiws` ждёт ровно такой же пакет. Значит расшифровывать и
 * перешифровывать поток не нужно вовсе: отдаём 64 байта клиента первым бинарным кадром и
 * дальше переливаем байты. Прикладной слой всё равно закрыт auth_key, и читать его нечем.
 *
 * ЧТО ВСЁ-ТАКИ ПРАВИТСЯ — ВОСЕМЬ БАЙТ ХВОСТА. В [56..64] лежат метка транспорта и номер ДЦ
 * (signed LE, отрицательный — медийный). У прямого соединения номера там нет — случайные
 * байты, — а точке `apiws` он нужен. Мы его вписываем: считаем гамму теми же сырыми ключами
 * и переXORиваем хвост. Ключи от этого не меняются: они выводятся из [8..56], которых мы не
 * трогаем, — поэтому остаток потока остаётся верным и расшифруется у дата-центра.
 *
 * ОТКУДА НОМЕР ДЦ. Из адреса назначения (SO_ORIGINAL_DST), потому что в рукопожатии его нет.
 * Таблица ниже, её можно дополнить файлом. НЕИЗВЕСТНЫЙ АДРЕС НЕ ПЕРЕХВАТЫВАЕТСЯ: соединение
 * просто переливается на исходный адрес как было. Увести соединение не в тот дата-центр —
 * значит сломать то, что работало, а промолчать об этом нечем: клиент получил бы ответы
 * чужого ДЦ и решил бы, что его выкинули.
 *
 * СЕРТИФИКАТ НЕ ПРОВЕРЯЕТСЯ, и это осознанно. В сборке нет ни X.509, ни PK, ни цепочек
 * доверия (см. шапку steer_mbedtls_config.h), а внутри едет MTProto, у которого своя
 * сквозная аутентификация: ключ согласуется по DH и подписан ключами Telegram, зашитыми в
 * приложение. Посредник во внешнем TLS не прочитает и не подделает ни одного сообщения —
 * ему остаётся только оборвать соединение, что он и так может. Эталонные реализации (в том
 * числе питоновская, с которой писали tg-ws-proxy) поступают так же.
 *
 * ЗВОНКИ СЮДА НЕ ПОПАДАЮТ. Голос идёт по UDP (P2P или через рефлекторы), MTProto участвует
 * только в установке. Перехват здесь только TCP — завернуть UDP в этот веб-сокет нечем.
 *
 * ПОТОК НА СОЕДИНЕНИЕ. Их единицы (клиент держит одно-два на дата-центр), и каждое почти всё
 * время спит. Городить здесь общий цикл epoll, как в туннеле, значило бы платить сложностью
 * за то, чего нет: там сотни соединений и путь данных, здесь — десяток и переливание. */

#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <pthread.h>
#include <signal.h>
#include <netdb.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <sys/socket.h>
#include <linux/netfilter_ipv4.h>

#include <mbedtls/aes.h>

#include "tgws.h"
#include "tls13.h"
#include "reality.h"
#include "../spec.h"

#define LOG_I "steer[info] tgws: "
#define LOG_W "steer[warn] tgws: "

#define HS_LEN        64        /* длина рукопожатия обфускации */
#define TAG_POS       56        /* метка транспорта */
#define DC_POS        60        /* номер ДЦ, signed LE */
#define BUF_N         16384     /* столько за раз переливаем в каждую сторону */
#define MAX_CONNS     64        /* больше клиент не открывает; предел от утечки потоков */
#define UP_TIMEOUT_S  10

/* ---- таблица дата-центров ---------------------------------------------------------
 *
 * Адреса встроены в клиенты Telegram и меняются редко. Медийные ДЦ обслуживают загрузку
 * файлов и объявляются отрицательным номером — у них своя точка `kwsN-1`.
 *
 * Таблицу можно дополнить файлом (STEER_TGWS_DCMAP, по умолчанию /etc/steer/tgws-dc.conf):
 * строки вида `149.154.167.220 2` или `149.154.164.250 4 media`. Файл, а не только сборка,
 * потому что список чужой: Telegram может добавить адрес, и чинить это перевыпуском пакета
 * — заведомо медленнее, чем строкой в конфигурации. */
struct dc_ent { uint32_t ip; short dc; short media; };
static struct dc_ent g_dc[64] = {
    { 0, 1, 0 }, { 0, 1, 0 },            /* заполняются в dc_table_init */
};
static size_t g_dc_n;

static const struct { const char *ip; short dc; short media; } DC_BUILTIN[] = {
    { "149.154.175.50",  1, 0 },
    { "149.154.175.53",  1, 0 },
    { "149.154.167.50",  2, 0 },
    { "149.154.167.51",  2, 0 },
    { "149.154.175.100", 3, 0 },
    { "149.154.167.91",  4, 0 },
    { "149.154.167.92",  4, 0 },
    { "149.154.171.5",   5, 0 },
    { "91.108.56.130",   5, 0 },
};

static void dc_add(const char *ip, short dc, short media) {
    struct in_addr a;
    if (g_dc_n >= sizeof(g_dc) / sizeof(g_dc[0])) return;
    if (inet_pton(AF_INET, ip, &a) != 1) return;
    for (size_t i = 0; i < g_dc_n; i++)
        if (g_dc[i].ip == a.s_addr) { g_dc[i].dc = dc; g_dc[i].media = media; return; }
    g_dc[g_dc_n].ip = a.s_addr;
    g_dc[g_dc_n].dc = dc;
    g_dc[g_dc_n].media = media;
    g_dc_n++;
}

static void dc_table_init(void) {
    g_dc_n = 0;
    for (size_t i = 0; i < sizeof(DC_BUILTIN) / sizeof(DC_BUILTIN[0]); i++)
        dc_add(DC_BUILTIN[i].ip, DC_BUILTIN[i].dc, DC_BUILTIN[i].media);

    const char *path = getenv("STEER_TGWS_DCMAP");
    if (!path) path = "/etc/steer/tgws-dc.conf";
    FILE *f = fopen(path, "r");
    if (!f) return;
    char line[128];
    size_t added = 0;
    while (fgets(line, sizeof(line), f)) {
        char ip[64], flag[16];
        int dc;
        flag[0] = '\0';
        if (line[0] == '#') continue;
        int n = sscanf(line, "%63s %d %15s", ip, &dc, flag);
        if (n < 2 || dc < 1 || dc > 9) continue;
        dc_add(ip, (short)dc, (short)(!strcmp(flag, "media")));
        added++;
    }
    fclose(f);
    if (added) fprintf(stderr, LOG_I "адресов ДЦ из %s: %zu\n", path, added);
}

/* Номер ДЦ по адресу назначения. 0 — адрес неизвестен, перехватывать нельзя. */
static short dc_of(uint32_t ip, short *media) {
    for (size_t i = 0; i < g_dc_n; i++)
        if (g_dc[i].ip == ip) { *media = g_dc[i].media; return g_dc[i].dc; }
    return 0;
}

/* ---- обфускация MTProto ------------------------------------------------------------ */

/* Гамма AES-256-CTR с начала потока: ключ [8..40], вектор [40..56] прямо из рукопожатия.
 * Сырые, без SHA-256 и без секрета, — так делает клиент, идущий в дата-центр напрямую, и
 * так же ждёт точка apiws. */
static int hs_keystream(const unsigned char hs[HS_LEN], unsigned char out[HS_LEN]) {
    mbedtls_aes_context aes;
    unsigned char nonce[16], sb[16], zeros[HS_LEN];
    size_t nc = 0;
    int rc;

    mbedtls_aes_init(&aes);
    memcpy(nonce, hs + 40, 16);
    memset(zeros, 0, sizeof(zeros));
    rc = mbedtls_aes_setkey_enc(&aes, hs + 8, 256);
    if (rc == 0) rc = mbedtls_aes_crypt_ctr(&aes, HS_LEN, &nc, nonce, sb, zeros, out);
    mbedtls_aes_free(&aes);
    return rc;
}

/* Разобрать рукопожатие и вписать в него номер ДЦ.
 *
 * Возвращает 1, если это MTProto (метка транспорта опознана) и хвост поправлен; 0 — если
 * нет: тогда соединение переливается на исходный адрес без перехвата. Метка нужна не ради
 * порядка — по ней отличается настоящий клиент от постороннего, случайно попавшего под
 * правило: перехватить чужое и увести в Telegram значило бы сломать чужое соединение. */
static int hs_patch_dc(unsigned char hs[HS_LEN], short dc, short media, unsigned char *tag) {
    unsigned char ks[HS_LEN];
    if (hs_keystream(hs, ks) != 0) return 0;

    unsigned char t[4];
    for (int i = 0; i < 4; i++) t[i] = hs[TAG_POS + i] ^ ks[TAG_POS + i];
    if (!((t[0] == 0xef && t[1] == 0xef && t[2] == 0xef && t[3] == 0xef) ||
          (t[0] == 0xee && t[1] == 0xee && t[2] == 0xee && t[3] == 0xee) ||
          (t[0] == 0xdd && t[1] == 0xdd && t[2] == 0xdd && t[3] == 0xdd)))
        return 0;
    *tag = t[0];

    int16_t idx = media ? (int16_t)-dc : (int16_t)dc;
    unsigned char d[2] = { (unsigned char)(idx & 0xff), (unsigned char)((idx >> 8) & 0xff) };
    hs[DC_POS + 0] = d[0] ^ ks[DC_POS + 0];
    hs[DC_POS + 1] = d[1] ^ ks[DC_POS + 1];
    return 1;
}

/* ---- транспорт: TLS либо голый сокет ----------------------------------------------
 *
 * Голый нужен стенду: поднимать в нём настоящий TLS означало бы проверять чужую библиотеку
 * вместо своего моста. Включается STEER_TGWS_PLAIN=1 и в бою не встречается. */
struct upstream {
    int fd;
    struct tls13 tls;
    int tls_on;
};

static int up_write(struct upstream *u, const unsigned char *p, size_t n) {
    if (u->tls_on) return tls13_write(&u->tls, p, n) == 0 ? (int)n : -1;
    size_t off = 0;
    while (off < n) {
        ssize_t w = send(u->fd, p + off, n - off, MSG_NOSIGNAL);
        if (w <= 0) { if (errno == EINTR) continue; return -1; }
        off += (size_t)w;
    }
    return (int)n;
}

static int up_read(struct upstream *u, unsigned char *p, size_t cap) {
    if (u->tls_on) {
        size_t got = 0;
        if (tls13_read(&u->tls, p, cap, &got) != 0) return -1;
        return (int)got;
    }
    ssize_t r = recv(u->fd, p, cap, 0);
    return r > 0 ? (int)r : -1;
}

/* ---- WebSocket (RFC 6455), ровно столько, сколько нужно ---------------------------
 *
 * Нужны только бинарные кадры в обе стороны, ping/pong и close. Расширений (permessage-
 * deflate) не запрашиваем: сжимать нечего — внутри шифрованный поток, — а согласование
 * добавило бы состояние на ровном месте. */

static void b64(const unsigned char *in, size_t n, char *out) {
    static const char A[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    size_t i = 0, o = 0;
    for (; i + 2 < n; i += 3) {
        out[o++] = A[in[i] >> 2];
        out[o++] = A[((in[i] & 3) << 4) | (in[i + 1] >> 4)];
        out[o++] = A[((in[i + 1] & 15) << 2) | (in[i + 2] >> 6)];
        out[o++] = A[in[i + 2] & 63];
    }
    if (i < n) {
        out[o++] = A[in[i] >> 2];
        if (i + 1 < n) {
            out[o++] = A[((in[i] & 3) << 4) | (in[i + 1] >> 4)];
            out[o++] = A[(in[i + 1] & 15) << 2];
        } else {
            out[o++] = A[(in[i] & 3) << 4];
            out[o++] = '=';
        }
        out[o++] = '=';
    }
    out[o] = '\0';
}

/* Рукопожатие HTTP: Upgrade к /apiws.
 *
 * Заголовки — те же, что шлёт веб-клиент Telegram (Origin и подпротокол `binary`): точка
 * `apiws` их ждёт, а нам заодно незачем выглядеть иначе, чем браузер, который к ней и ходит.
 *
 * Ответ читаем до пустой строки и сверяем только «101». Sec-WebSocket-Accept не проверяем
 * нарочно: он защищает от кэширующего посредника, принявшего апгрейд за обычный ответ, а у
 * нас поверх TLS посредника нет, и SHA-1 ради одной проверки в сборку тянуть незачем. */
static int ws_upgrade(struct upstream *u, const char *host) {
    unsigned char nonce[16];
    char key[32], req[512], resp[2048];

    if (xc_random(nonce, sizeof(nonce)) != 0) return -1;
    b64(nonce, sizeof(nonce), key);

    int n = snprintf(req, sizeof(req),
                     "GET /apiws HTTP/1.1\r\n"
                     "Host: %s\r\n"
                     "Upgrade: websocket\r\n"
                     "Connection: Upgrade\r\n"
                     "Sec-WebSocket-Key: %s\r\n"
                     "Sec-WebSocket-Version: 13\r\n"
                     "Sec-WebSocket-Protocol: binary\r\n"
                     "Origin: https://web.telegram.org\r\n"
                     "User-Agent: Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 "
                     "(KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36\r\n"
                     "\r\n", host, key);
    if (n <= 0 || up_write(u, (unsigned char *)req, (size_t)n) < 0) return -1;

    size_t got = 0;
    for (;;) {
        int r = up_read(u, (unsigned char *)resp + got, sizeof(resp) - 1 - got);
        if (r <= 0) return -1;
        got += (size_t)r;
        resp[got] = '\0';
        if (strstr(resp, "\r\n\r\n")) break;
        if (got >= sizeof(resp) - 1) return -1;
    }
    if (strncmp(resp, "HTTP/1.1 101", 12) != 0) {
        char *e = strchr(resp, '\r');
        if (e) *e = '\0';
        fprintf(stderr, LOG_W "%s: апгрейд отклонён (%s)\n", host, resp);
        return -1;
    }
    /* Тело после заголовков быть не должно: сервер отвечает 101 и молчит до первого кадра.
     * Если что-то пришло, это уже кадры — но их приход раньше нашего init означал бы, что
     * мы говорим не с той точкой, и разбирать это нечем. */
    return 0;
}

/* Кадр от клиента ОБЯЗАН быть замаскирован (RFC 6455 §5.3) — сервер рвёт соединение иначе. */
static int ws_send(struct upstream *u, const unsigned char *p, size_t n) {
    unsigned char hdr[14];
    size_t h = 0;
    unsigned char mask[4];

    if (xc_random(mask, 4) != 0) return -1;
    hdr[h++] = 0x82;                                  /* FIN + binary */
    if (n < 126) hdr[h++] = (unsigned char)(0x80 | n);
    else if (n < 65536) {
        hdr[h++] = 0x80 | 126;
        hdr[h++] = (unsigned char)(n >> 8);
        hdr[h++] = (unsigned char)(n & 0xff);
    } else {
        hdr[h++] = 0x80 | 127;
        for (int i = 7; i >= 0; i--) hdr[h++] = (unsigned char)((uint64_t)n >> (i * 8));
    }
    memcpy(hdr + h, mask, 4);
    h += 4;
    if (up_write(u, hdr, h) < 0) return -1;

    unsigned char buf[BUF_N];
    size_t off = 0;
    while (off < n) {
        size_t part = n - off;
        if (part > sizeof(buf)) part = sizeof(buf);
        for (size_t i = 0; i < part; i++) buf[i] = p[off + i] ^ mask[(off + i) & 3];
        if (up_write(u, buf, part) < 0) return -1;
        off += part;
    }
    return 0;
}

/* Приём кадров: накапливаем, пока не соберётся заголовок и тело.
 *
 * Свой буфер, а не чтение по байту: TLS отдаёт запись целиком, и в ней бывает несколько
 * кадров — читая по одному, второй оставляли бы ждать события, которого может не быть. */
struct ws_rx {
    unsigned char buf[BUF_N * 2];
    size_t n;
};

/* 1 — кадр разобран (payload/len), 0 — нужно ещё читать, -1 — ошибка/закрытие. */
static int ws_frame(struct ws_rx *rx, unsigned char **payload, size_t *len, int *opcode) {
    if (rx->n < 2) return 0;
    unsigned char b1 = rx->buf[1];
    size_t need = 2, plen = b1 & 0x7f;
    if (b1 & 0x80) return -1;                         /* сервер маскировать не должен */
    if (plen == 126) {
        if (rx->n < 4) return 0;
        plen = ((size_t)rx->buf[2] << 8) | rx->buf[3];
        need = 4;
    } else if (plen == 127) {
        if (rx->n < 10) return 0;
        plen = 0;
        for (int i = 0; i < 8; i++) plen = (plen << 8) | rx->buf[2 + i];
        need = 10;
    }
    if (plen > sizeof(rx->buf) - 16) return -1;       /* кадр больше буфера — не наш случай */
    if (rx->n < need + plen) return 0;
    *opcode = rx->buf[0] & 0x0f;
    *payload = rx->buf + need;
    *len = plen;
    return (int)(need + plen);
}

static void ws_consume(struct ws_rx *rx, size_t used) {
    memmove(rx->buf, rx->buf + used, rx->n - used);
    rx->n -= used;
}

/* ---- соединение с точкой apiws ---------------------------------------------------- */

static int tcp_connect(const char *host, const char *port, int timeout_s) {
    struct addrinfo hints, *res = NULL, *it;
    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_INET;                        /* IPv6 к ДЦ пока не перехватываем */
    hints.ai_socktype = SOCK_STREAM;
    if (getaddrinfo(host, port, &hints, &res) != 0) return -1;

    int fd = -1;
    for (it = res; it; it = it->ai_next) {
        fd = socket(it->ai_family, SOCK_STREAM, 0);
        if (fd < 0) continue;
        struct timeval tv = { .tv_sec = timeout_s, .tv_usec = 0 };
        setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
        setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));
        if (connect(fd, it->ai_addr, it->ai_addrlen) == 0) break;
        close(fd);
        fd = -1;
    }
    freeaddrinfo(res);
    if (fd >= 0) {
        int one = 1;
        setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, &one, sizeof(one));
    }
    return fd;
}

/* TLS 1.3 с обликом Chrome. Hello собирает reality.c — тот же, что у клиента VLESS, и это
 * не переиспользование ради экономии: отпечаток браузера должен жить в одном месте, иначе
 * две копии однажды разъедутся, а симптомом будет не ошибка, а молчаливая блокировка.
 *
 * session_id заполняется случайными байтами через носитель: аутентификатор Reality здесь не
 * нужен и не имеет смысла — мы говорим с настоящим Cloudflare, а не с сервером Reality. */
static int sid_random(void *ctx, unsigned char sid[32], const unsigned char *hs, size_t hs_n,
                      const unsigned char shared[32]) {
    (void)ctx; (void)hs; (void)hs_n; (void)shared;
    return xc_random(sid, 32);
}

static int tls_start(struct upstream *u, const char *sni) {
    unsigned char priv[32], pub[32], hello[4096];
    size_t hello_n = 0;
    /* Постоянный ключ «сервера» не используется (см. sid_random), но сборщику Hello он нужен
     * как вход: подставляем случайный. Секрет из него никуда не идёт. */
    unsigned char fake_pbk[32];
    char pbk_b64[64];
    if (xc_random(fake_pbk, sizeof(fake_pbk)) != 0) return -1;
    b64(fake_pbk, sizeof(fake_pbk), pbk_b64);
    for (char *p = pbk_b64; *p; p++) {                /* base64url, как ждёт reality.c */
        if (*p == '+') *p = '-';
        else if (*p == '/') *p = '_';
        else if (*p == '=') { *p = '\0'; break; }
    }

    if (xc_x25519_keypair(priv, pub) != 0) return -1;
    struct reality_cfg cfg = { .sni = sni, .pbk = pbk_b64, .sid = "", .fp = "chrome",
                               .alpn = "http/1.1" };
    struct reality_state st;
    struct reality_carrier car = { .priv = priv, .pub = pub, .fill_sid = sid_random };
    if (reality_build_hello_carry(&cfg, &st, &car, hello, sizeof(hello), &hello_n) != 0)
        return -1;
    if (up_write(u, hello, hello_n) < 0) return -1;
    memset(&u->tls, 0, sizeof(u->tls));
    if (tls13_handshake(&u->tls, u->fd, hello, hello_n, priv) != 0) return -1;
    u->tls_on = 1;
    return 0;
}

/* ---- переливание -------------------------------------------------------------------
 *
 * Обе стороны в одном цикле poll: отдельный поток на направление стоил бы второго стека и
 * согласования закрытия ради ровно той же работы. */
static void pump(int cfd, struct upstream *u) {
    struct ws_rx rx;
    unsigned char buf[BUF_N];
    rx.n = 0;

    for (;;) {
        struct pollfd p[2];
        p[0].fd = cfd;   p[0].events = POLLIN;  p[0].revents = 0;
        p[1].fd = u->fd; p[1].events = POLLIN;  p[1].revents = 0;
        /* Записи TLS могут уже лежать у нас в буфере — тогда ждать события на сокете
         * нельзя, иначе хвост ответа простоит до таймаута клиента (та же ловушка, что
         * закрыта в tls13_has_record). */
        int wait = (u->tls_on && tls13_has_record(&u->tls)) ? 0 : 60000;
        if (poll(p, 2, wait) < 0) {
            if (errno == EINTR) continue;
            return;
        }

        if (p[0].revents & POLLIN) {
            ssize_t r = recv(cfd, buf, sizeof(buf), 0);
            if (r <= 0) return;
            if (ws_send(u, buf, (size_t)r) < 0) return;
        }

        if ((p[1].revents & POLLIN) || wait == 0) {
            int r = up_read(u, rx.buf + rx.n, sizeof(rx.buf) - rx.n);
            if (r <= 0 && !(wait == 0 && r == 0)) return;
            if (r > 0) rx.n += (size_t)r;
            for (;;) {
                unsigned char *pl;
                size_t len;
                int op;
                int used = ws_frame(&rx, &pl, &len, &op);
                if (used == 0) break;
                if (used < 0) return;
                if (op == 0x8) return;                /* close */
                if (op == 0x9) {                      /* ping — отвечаем тем же телом */
                    unsigned char pong[128];
                    size_t pn = len > sizeof(pong) ? sizeof(pong) : len;
                    memcpy(pong, pl, pn);
                    ws_consume(&rx, (size_t)used);
                    /* pong — управляющий кадр, но маскировка та же; тело копируем заранее,
                     * потому что ws_consume сдвигает буфер под ним. */
                    unsigned char hdr[6];
                    hdr[0] = 0x8a;
                    hdr[1] = (unsigned char)(0x80 | pn);
                    unsigned char mask[4];
                    if (xc_random(mask, 4) != 0) return;
                    memcpy(hdr + 2, mask, 4);
                    if (up_write(u, hdr, 6) < 0) return;
                    for (size_t i = 0; i < pn; i++) pong[i] ^= mask[i & 3];
                    if (pn && up_write(u, pong, pn) < 0) return;
                    continue;
                }
                if (op == 0x1 || op == 0x2 || op == 0x0) {
                    size_t off = 0;
                    while (off < len) {
                        ssize_t w = send(cfd, pl + off, len - off, MSG_NOSIGNAL);
                        if (w <= 0) { if (errno == EINTR) continue; return; }
                        off += (size_t)w;
                    }
                }
                ws_consume(&rx, (size_t)used);
            }
        }
        if ((p[0].revents | p[1].revents) & (POLLERR | POLLHUP)) {
            if (!rx.n) return;
        }
    }
}

/* Переливание без перехвата: соединение уходит туда, куда шло. Так обрабатывается всё, чего
 * мост не понял, — неизвестный адрес ДЦ, не-MTProto, недоступная точка apiws. Молча рвать
 * такое нельзя: под правило попадает трафик человека, и «Telegram не работает» из-за нашей
 * осторожности ничем не лучше блокировки. */
static void relay_direct(int cfd, const struct sockaddr_in *dst,
                         const unsigned char *pre, size_t pre_n) {
    int fd = socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0) return;
    struct timeval tv = { .tv_sec = UP_TIMEOUT_S, .tv_usec = 0 };
    setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
    setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));
    if (connect(fd, (const struct sockaddr *)dst, sizeof(*dst)) != 0) { close(fd); return; }
    if (pre_n) {
        size_t off = 0;
        while (off < pre_n) {
            ssize_t w = send(fd, pre + off, pre_n - off, MSG_NOSIGNAL);
            if (w <= 0) { close(fd); return; }
            off += (size_t)w;
        }
    }
    unsigned char buf[BUF_N];
    for (;;) {
        struct pollfd p[2];
        p[0].fd = cfd; p[0].events = POLLIN; p[0].revents = 0;
        p[1].fd = fd;  p[1].events = POLLIN; p[1].revents = 0;
        if (poll(p, 2, 60000) <= 0) break;
        for (int i = 0; i < 2; i++) {
            if (!(p[i].revents & POLLIN)) continue;
            int from = i ? fd : cfd, to = i ? cfd : fd;
            ssize_t r = recv(from, buf, sizeof(buf), 0);
            if (r <= 0) goto out;
            size_t off = 0;
            while (off < (size_t)r) {
                ssize_t w = send(to, buf + off, (size_t)r - off, MSG_NOSIGNAL);
                if (w <= 0) goto out;
                off += (size_t)w;
            }
        }
        if ((p[0].revents | p[1].revents) & (POLLERR | POLLHUP)) break;
    }
out:
    close(fd);
}

/* ---- одно соединение ---------------------------------------------------------------- */

struct job { int fd; };
static volatile int g_live;
static pthread_mutex_t g_mu = PTHREAD_MUTEX_INITIALIZER;

static void *serve(void *arg) {
    struct job *j = arg;
    int cfd = j->fd;
    free(j);

    struct sockaddr_in dst;
    socklen_t dl = sizeof(dst);
    unsigned char hs[HS_LEN];
    size_t got = 0;
    short media = 0, dc = 0;
    unsigned char tag = 0;

    /* Куда клиент шёл на самом деле. Правило redirect подменило адрес, а исходный ядро
     * помнит — без него номер дата-центра взять неоткуда. */
    if (getsockopt(cfd, SOL_IP, SO_ORIGINAL_DST, &dst, &dl) != 0) {
        fprintf(stderr, LOG_W "исходный адрес не узнать (%s) — соединение закрыто\n",
                strerror(errno));
        goto done;
    }

    struct timeval tv = { .tv_sec = UP_TIMEOUT_S, .tv_usec = 0 };
    setsockopt(cfd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
    setsockopt(cfd, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));

    while (got < HS_LEN) {
        ssize_t r = recv(cfd, hs + got, HS_LEN - got, 0);
        if (r <= 0) goto done;
        got += (size_t)r;
    }

    char dsts[INET_ADDRSTRLEN] = "?";
    inet_ntop(AF_INET, &dst.sin_addr, dsts, sizeof(dsts));
    dc = dc_of(dst.sin_addr.s_addr, &media);
    if (!dc) {
        fprintf(stderr, LOG_I "%s: не наш дата-центр — пропускаю как есть\n", dsts);
        relay_direct(cfd, &dst, hs, got);
        goto done;
    }
    if (!hs_patch_dc(hs, dc, media, &tag)) {
        fprintf(stderr, LOG_I "%s: это не MTProto — пропускаю как есть\n", dsts);
        relay_direct(cfd, &dst, hs, got);
        goto done;
    }

    /* Куда идём. В бою — точка веб-сокета дата-центра; стенду адрес задают снаружи. */
    char host[128], sni[128];
    const char *port = "443";
    const char *ep = getenv("STEER_TGWS_ENDPOINT");
    snprintf(sni, sizeof(sni), media ? "kws%d-1.web.telegram.org" : "kws%d.web.telegram.org", dc);
    if (ep) {
        snprintf(host, sizeof(host), "%s", ep);
        char *c = strchr(host, ':');
        if (c) { *c = '\0'; port = c + 1; }
    } else {
        snprintf(host, sizeof(host), "%s", sni);
    }

    struct upstream u;
    memset(&u, 0, sizeof(u));
    u.fd = tcp_connect(host, port, UP_TIMEOUT_S);
    if (u.fd < 0) {
        fprintf(stderr, LOG_W "%s: не соединиться (ДЦ%d) — пропускаю как есть\n", host, dc);
        relay_direct(cfd, &dst, hs, got);
        goto done;
    }
    if (!getenv("STEER_TGWS_PLAIN") && tls_start(&u, sni) != 0) {
        fprintf(stderr, LOG_W "%s: TLS не поднялся — пропускаю как есть\n", sni);
        close(u.fd);
        relay_direct(cfd, &dst, hs, got);
        goto done;
    }
    if (ws_upgrade(&u, sni) != 0 || ws_send(&u, hs, HS_LEN) < 0) {
        if (u.tls_on) tls13_free(&u.tls);
        close(u.fd);
        relay_direct(cfd, &dst, hs, got);
        goto done;
    }

    fprintf(stderr, LOG_I "%s -> ДЦ%d%s через %s (транспорт 0x%02x)\n",
            dsts, dc, media ? "m" : "", sni, tag);
    pump(cfd, &u);
    if (u.tls_on) tls13_free(&u.tls);
    close(u.fd);

done:
    close(cfd);
    pthread_mutex_lock(&g_mu);
    g_live--;
    pthread_mutex_unlock(&g_mu);
    return NULL;
}

/* ---- служба ------------------------------------------------------------------------- */

int cmd_tgws(const char *spec, const char *name) {
    if (!name || !*name) { fprintf(stderr, LOG_W "нужно имя выхода\n"); return 2; }
    load_spec(spec);
    registry_assign();

    const struct output *o = NULL;
    for (size_t i = 0; i < g_out_n; i++)
        if (!strcmp(g_out[i].name, name)) { o = &g_out[i]; break; }
    if (!o) { fprintf(stderr, LOG_W "нет выхода %s\n", name); return 2; }
    if (o->kind != OUT_TGWS) {
        fprintf(stderr, LOG_W "выход %s не kind=tgws\n", name);
        return 2;
    }

    dc_table_init();
    int port = out_tgws_port(o);

    int srv = socket(AF_INET, SOCK_STREAM, 0);
    if (srv < 0) { perror("socket"); return 1; }
    int one = 1;
    setsockopt(srv, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one));
    struct sockaddr_in a;
    memset(&a, 0, sizeof(a));
    a.sin_family = AF_INET;
    a.sin_addr.s_addr = htonl(INADDR_ANY);
    a.sin_port = htons((uint16_t)port);
    if (bind(srv, (struct sockaddr *)&a, sizeof(a)) != 0) {
        fprintf(stderr, LOG_W "порт %d занят (%s)\n", port, strerror(errno));
        close(srv);
        return 1;
    }
    if (listen(srv, 32) != 0) { perror("listen"); close(srv); return 1; }

    fprintf(stderr, LOG_I "%s: жду перехваченные соединения на :%d, адресов ДЦ %zu\n",
            name, port, g_dc_n);

    signal(SIGPIPE, SIG_IGN);
    for (;;) {
        int fd = accept(srv, NULL, NULL);
        if (fd < 0) {
            if (errno == EINTR) continue;
            break;
        }
        pthread_mutex_lock(&g_mu);
        int live = g_live;
        if (live < MAX_CONNS) g_live++;
        pthread_mutex_unlock(&g_mu);
        if (live >= MAX_CONNS) {
            fprintf(stderr, LOG_W "разом больше %d соединений — отказ\n", MAX_CONNS);
            close(fd);
            continue;
        }
        struct job *j = malloc(sizeof(*j));
        if (!j) { close(fd); continue; }
        j->fd = fd;
        pthread_t t;
        pthread_attr_t at;
        pthread_attr_init(&at);
        pthread_attr_setdetachstate(&at, PTHREAD_CREATE_DETACHED);
        /* 128 КБ вместо восьми мегабайт по умолчанию: на роутере с 64 МБ памяти
         * шестьдесят четыре потока по умолчанию — это полтора гигабайта адресов. */
        pthread_attr_setstacksize(&at, 128 * 1024);
        if (pthread_create(&t, &at, serve, j) != 0) {
            pthread_mutex_lock(&g_mu);
            g_live--;
            pthread_mutex_unlock(&g_mu);
            close(fd);
            free(j);
        }
        pthread_attr_destroy(&at);
    }
    close(srv);
    return 0;
}
