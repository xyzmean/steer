/* Минимальный клиент HTTP/2: один запрос, один поток, тело в обе стороны.
 *
 * Зачем он здесь. Транспорты grpc и xhttp — это не «другой способ упаковать байты», а
 * HTTP/2: сервер ждёт преамбулу, кадры и управление потоком, и без них соединение просто
 * висит. Восемь узлов подписки из двадцати шести говорят по grpc и восемь по xhttp, то
 * есть без HTTP/2 две трети узлов недоступны. Это и есть причина писать его.
 *
 * Чего здесь сознательно НЕТ, и почему это можно:
 *
 *   - мультиплексирования. Поток всегда один, номер 1. Xray на каждое соединение VLESS
 *     открывает своё TCP+TLS, и мы делаем так же: мультиплексирование экономило бы
 *     рукопожатия, но потребовало бы планировщика окон между потоками — то есть кода,
 *     который на роутере с одним ядром отлаживать дороже, чем он стоит;
 *   - HPACK на приём. Заголовки ответа не разбираются, из них добывается только :status,
 *     и только когда он записан статическим индексом (в жизни — всегда). Полный HPACK
 *     потребовал бы динамической таблицы, то есть памяти на соединение и кода, который
 *     исполняется один раз за соединение;
 *   - PUSH_PROMISE. Выключается в SETTINGS, поэтому его не может быть;
 *   - приоритетов и TRAILERS. Первое ничего не решает, второе только закрывает поток.
 *
 * Память. По одному такому состоянию на соединение VLESS, а их до 64, поэтому буфера на
 * кадр здесь нет: записи читаются в общий буфер, а между вызовами переносится только то,
 * что нельзя разобрать сразу — обрывок заголовка кадра (9 байт), тело служебного кадра
 * (64) и счётчик непрочитанного тела. 16 КБ на соединение означали бы мегабайт на
 * коробке с пятнадцатью.
 */
#define _GNU_SOURCE
#include <stdio.h>
#include <string.h>
#include <sys/random.h>

#include "h2.h"
#include "tls13.h"

#define FR_DATA          0x00
#define FR_HEADERS       0x01
#define FR_RST_STREAM    0x03
#define FR_SETTINGS      0x04
#define FR_PING          0x06
#define FR_GOAWAY        0x07
#define FR_WINDOW_UPDATE 0x08

#define FLAG_END_STREAM  0x01
#define FLAG_ACK         0x01
#define FLAG_END_HEADERS 0x04

#define STREAM_ID        1u

/* Наше окно приёма. Большое намеренно: при 65535 по умолчанию каждые 64 КБ загрузки
 * требуют обмена WINDOW_UPDATE, и на канале с задержкой 100 мс это режет скорость до
 * ~5 Мбит независимо от полосы. Мегабайт стоит нам ничего — это лишь разрешение серверу
 * присылать, память под данные мы не держим. */
#define OUR_WINDOW       (1024 * 1024)
/* Когда пополнять: раз в 32 КБ, а не на каждый кадр. Пополнение на каждый кадр — это
 * лишняя запись TLS на каждые 16 КБ данных, то есть заметный признак в потоке. */
#define WINDOW_REFILL    (32 * 1024)

/* Максимум, который сервер обязан принимать по умолчанию (RFC 7540 §4.2). Больше можно
 * только если сервер сам разрешил в SETTINGS. */
#define DEFAULT_MAX_FRAME 16384

static void put32(unsigned char *p, uint32_t v) {
    p[0] = (unsigned char)(v >> 24); p[1] = (unsigned char)(v >> 16);
    p[2] = (unsigned char)(v >> 8);  p[3] = (unsigned char)v;
}
static uint32_t get32(const unsigned char *p) {
    return ((uint32_t)p[0] << 24) | ((uint32_t)p[1] << 16) | ((uint32_t)p[2] << 8) | p[3];
}

/* ---- HPACK на отправку ------------------------------------------------------
 *
 * Только «литеральное поле без индексации»: имя берётся из статической таблицы по
 * индексу, значение едет строкой как есть. Динамической таблицы у нас нет вовсе, и это
 * законно — HPACK разрешает не индексировать ничего. Huffman тоже не применяется: он
 * сэкономил бы десятки байт на соединение и потребовал бы таблицы кодов.
 *
 * Индексы статической таблицы (RFC 7541, приложение A) выписаны числами, потому что
 * таблица неизменна — это часть протокола, а не настройка. */
#define HP_AUTHORITY   1
#define HP_METHOD_POST 3
#define HP_PATH        4
#define HP_SCHEME_HTTPS 7
#define HP_CONTENT_TYPE 31
#define HP_REFERER     51
#define HP_USER_AGENT  58

struct wbuf { unsigned char *p; size_t n, cap; };

static void wb(struct wbuf *b, const void *d, size_t n) {
    if (b->n + n <= b->cap) memcpy(b->p + b->n, d, n);
    b->n += n;
}
static void wb8(struct wbuf *b, unsigned v) {
    unsigned char c = (unsigned char)v;
    wb(b, &c, 1);
}

/* Целое HPACK с префиксом в N бит. Нужно и для индексов, и для длин строк: длина пути с
 * набивкой xhttp доходит до тысячи, а в семь бит влезает только 126. */
static void hp_int(struct wbuf *b, unsigned prefix, unsigned bits, uint32_t v) {
    uint32_t max = (1u << bits) - 1;
    if (v < max) { wb8(b, prefix | v); return; }
    wb8(b, prefix | max);
    v -= max;
    while (v >= 128) { wb8(b, (v & 0x7F) | 0x80); v >>= 7; }
    wb8(b, v);
}

static void hp_str(struct wbuf *b, const char *s, size_t n) {
    hp_int(b, 0x00, 7, (uint32_t)n);     /* без Huffman: старший бит нулевой */
    wb(b, s, n);
}

/* Поле с именем из статической таблицы и своим значением. */
static void hp_field(struct wbuf *b, unsigned name_index, const char *value) {
    hp_int(b, 0x00, 4, name_index);      /* 0000 — литерал без индексации */
    hp_str(b, value, strlen(value));
}

/* Поле с именем, которого в таблице нет. */
static void hp_new(struct wbuf *b, const char *name, const char *value) {
    wb8(b, 0x00);
    hp_str(b, name, strlen(name));
    hp_str(b, value, strlen(value));
}

/* Индексированное поле: имя И значение из статической таблицы. */
static void hp_indexed(struct wbuf *b, unsigned index) {
    hp_int(b, 0x80, 7, index);
}

/* ---- кадры ------------------------------------------------------------------ */
static int frame_out(struct h2 *h, unsigned char type, unsigned char flags, uint32_t sid,
                     const unsigned char *body, size_t n) {
    unsigned char hdr[9];
    hdr[0] = (unsigned char)(n >> 16); hdr[1] = (unsigned char)(n >> 8); hdr[2] = (unsigned char)n;
    hdr[3] = type;
    hdr[4] = flags;
    put32(hdr + 5, sid);
    /* Заголовок и тело одной записью: разделение их по записям TLS создаёт узнаваемый
     * рисунок длин (9 + N, 9 + N, …), ради избавления от которого и существует Vision. */
    static __thread unsigned char one[9 + DEFAULT_MAX_FRAME];
    if (n > DEFAULT_MAX_FRAME) return H2_ETOOBIG;
    memcpy(one, hdr, 9);
    if (n) memcpy(one + 9, body, n);
    return h->io.write(h->io.ctx, one, 9 + n);
}

int h2_start(struct h2 *h, const struct h2_io *io, const char *authority,
             const char *path, const char *content_type, const char *referer) {
    memset(h, 0, sizeof(*h));
    h->io = *io;
    h->send_win = 65535;                 /* до SETTINGS сервера — значение по умолчанию */
    h->send_win_conn = 65535;

    static __thread unsigned char buf[4096];
    struct wbuf b = { buf, 0, sizeof(buf) };

    /* Преамбула. Байт в байт из RFC 7540 §3.5 — сервер сверяет её дословно. */
    wb(&b, "PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n", 24);

    /* SETTINGS: запретить push (нам он не нужен и только усложнил бы разбор) и объявить
     * своё окно потока. */
    {
        unsigned char s[12];
        s[0] = 0; s[1] = 0x02; put32(s + 2, 0);              /* ENABLE_PUSH = 0 */
        s[6] = 0; s[7] = 0x04; put32(s + 8, OUR_WINDOW);     /* INITIAL_WINDOW_SIZE */
        unsigned char hdr[9] = { 0, 0, 12, FR_SETTINGS, 0, 0, 0, 0, 0 };
        wb(&b, hdr, 9);
        wb(&b, s, 12);
    }

    /* Окно СОЕДИНЕНИЯ настройками не задаётся — только этим кадром. Без него сервер
     * пришлёт 65535 байт и остановится, а выглядеть это будет как «скачивание зависает
     * на 64 килобайтах». */
    {
        unsigned char wu[4];
        put32(wu, OUR_WINDOW - 65535);
        unsigned char hdr[9] = { 0, 0, 4, FR_WINDOW_UPDATE, 0, 0, 0, 0, 0 };
        wb(&b, hdr, 9);
        wb(&b, wu, 4);
    }

    /* HEADERS. Псевдозаголовки обязаны идти первыми и в этом порядке. */
    {
        static __thread unsigned char hb[2048];
        struct wbuf hp = { hb, 0, sizeof(hb) };
        hp_indexed(&hp, HP_METHOD_POST);
        hp_indexed(&hp, HP_SCHEME_HTTPS);
        hp_field(&hp, HP_PATH, path);
        hp_field(&hp, HP_AUTHORITY, authority);
        if (content_type) hp_field(&hp, HP_CONTENT_TYPE, content_type);
        if (referer) hp_field(&hp, HP_REFERER, referer);
        /* te: trailers — единственный заголовок из «запрещённых для HTTP/2», который
         * разрешён явно, и gRPC его требует. */
        hp_new(&hp, "te", "trailers");
        hp_field(&hp, HP_USER_AGENT, "grpc-go/1.60.0");
        if (hp.n > sizeof(hb)) return H2_ETOOBIG;

        /* END_STREAM НЕ ставим: тело запроса — это наш канал наверх, и он живёт всё
         * соединение. END_HEADERS ставим: продолжений не бывает, заголовки короткие. */
        unsigned char hdr[9];
        hdr[0] = (unsigned char)(hp.n >> 16); hdr[1] = (unsigned char)(hp.n >> 8);
        hdr[2] = (unsigned char)hp.n;
        hdr[3] = FR_HEADERS;
        hdr[4] = FLAG_END_HEADERS;
        put32(hdr + 5, STREAM_ID);
        wb(&b, hdr, 9);
        wb(&b, hb, hp.n);
    }

    if (b.n > sizeof(buf)) return H2_ETOOBIG;
    /* Всё одной записью: преамбула, настройки и запрос уезжают вместе, как это делает
     * любой браузер. Порознь они дали бы три записи подряд характерных длин.
     *
     * Ответа НЕ ждём. Сервер пришлёт свои SETTINGS и HEADERS, но ждать их здесь значило
     * бы добавить круг задержки перед первым байтом данных — а данные можно отправлять
     * сразу, HTTP/2 это разрешает. Статус узнаем при первом чтении. */
    h->started = 1;
    return h->io.write(h->io.ctx, buf, b.n);
}

/* Пополнить окно приёма, если накопилось достаточно. Оба уровня сразу: соединение и
 * поток считаются отдельно, и забыть один — значит остановиться на его пределе. */
static int window_refill(struct h2 *h) {
    if (h->recv_credit < WINDOW_REFILL) return 0;
    unsigned char wu[4];
    put32(wu, (uint32_t)h->recv_credit);
    int rc = frame_out(h, FR_WINDOW_UPDATE, 0, STREAM_ID, wu, 4);
    if (rc) return rc;
    rc = frame_out(h, FR_WINDOW_UPDATE, 0, 0, wu, 4);
    if (rc) return rc;
    h->recv_credit = 0;
    return 0;
}

/* Разобрать служебный кадр, тело которого собрано целиком. */
static int ctl_handle(struct h2 *h) {
    switch (h->frame_type) {
        case FR_SETTINGS:
            if (h->frame_flags & FLAG_ACK) return 0;
            /* Настройки сервера, которые нас касаются. INITIAL_WINDOW_SIZE меняет окно
             * ОТПРАВКИ уже открытого потока на разницу — так требует RFC 7540 §6.9.2, и
             * без этого мы либо не используем данное нам окно, либо переполняем его. */
            for (size_t i = 0; i + 6 <= h->ctl_n; i += 6) {
                unsigned id = ((unsigned)h->ctl[i] << 8) | h->ctl[i + 1];
                uint32_t v = get32(h->ctl + i + 2);
                /* MAX_FRAME_SIZE сервера сознательно не читается: по RFC он не может быть
                 * меньше 16384, а больше нам не нужно — крупные кадры не дают ничего,
                 * зато потребовали бы буфер под них на каждое соединение. Мы всегда
                 * отправляем не больше 16384, и это законно при любых его настройках. */
                if (id == 0x04) {
                    /* Окно ПОТОКА сдвигается на разницу; окно соединения настройками не
                     * меняется вовсе — только кадром WINDOW_UPDATE. */
                    h->send_win += (int32_t)v - 65535;
                }
            }
            return frame_out(h, FR_SETTINGS, FLAG_ACK, 0, NULL, 0);

        case FR_PING:
            if (h->frame_flags & FLAG_ACK) return 0;
            /* Ответить обязательно: сервер шлёт PING как keep-alive и молчание считает
             * мёртвым соединением. Xray ставит период по образцу Chrome. */
            return frame_out(h, FR_PING, FLAG_ACK, 0, h->ctl, h->ctl_n);

        case FR_WINDOW_UPDATE: {
            if (h->ctl_n < 4) return 0;
            int32_t inc = (int32_t)(get32(h->ctl) & 0x7FFFFFFF);
            if (h->frame_ours) h->send_win += inc;
            else h->send_win_conn += inc;
            return 0;
        }

        case FR_RST_STREAM:
        case FR_GOAWAY:
            return H2_ERESET;
    }
    return 0;
}

/* Статус ответа из первых байт HEADERS.
 *
 * Разбираем только то, что можно разобрать без динамической таблицы. В жизни сервер
 * отдаёт «:status 200» индексом 8 — один байт 0x88. Если встретилось что-то другое,
 * ставим -1 и НЕ считаем это ошибкой: догадка о статусе хуже, чем его отсутствие, а
 * пришли данные или нет — покажет чтение. */
static void status_peek(struct h2 *h, const unsigned char *p, size_t n) {
    size_t i = 0;
    /* Обновление размера динамической таблицы (001xxxxx) идёт первым, если вообще есть.
     * Значение — целое с префиксом в 5 бит: при 0x1F в младших битах продолжение лежит
     * в следующих байтах со старшим битом 1. */
    while (i < n && (p[i] & 0xE0) == 0x20) {
        int cont = (p[i] & 0x1F) == 0x1F;
        i++;
        if (!cont) continue;
        while (i < n && (p[i] & 0x80)) i++;
        if (i < n) i++;
    }
    if (i >= n) { h->status = -1; return; }
    switch (p[i]) {
        case 0x88: h->status = 200; break;
        case 0x89: h->status = 204; break;
        case 0x8A: h->status = 206; break;
        case 0x8B: h->status = 304; break;
        case 0x8C: h->status = 400; break;
        case 0x8D: h->status = 404; break;
        case 0x8E: h->status = 500; break;
        default:
            /* Литерал с именем :status (индекс 8) — значение строкой из трёх цифр. */
            if ((p[i] & 0x0F) == 0x08 && i + 2 < n) {
                size_t len = p[i + 1] & 0x7F;
                if (!(p[i + 1] & 0x80) && len == 3 && i + 4 < n) {
                    h->status = (p[i + 2] - '0') * 100 + (p[i + 3] - '0') * 10 + (p[i + 4] - '0');
                    break;
                }
            }
            h->status = -1;
    }
}

int h2_read(struct h2 *h, unsigned char *out, size_t cap, size_t *got) {
    *got = 0;
    if (!h->started) return H2_EPROTO;
    if (h->done) return H2_ERESET;

    /* Общий буфер на всех: разбор идёт в один поток, и держать по 16 КБ на соединение
     * значило бы мегабайт там, где хватает одного буфера. */
    static __thread unsigned char rec[TLS13_MAX_PLAIN + sizeof(h->pend)];
    size_t avail = 0;
    if (h->pend_n) {
        memcpy(rec, h->pend, h->pend_n);
        avail = h->pend_n;
        h->pend_n = 0;
    }

    size_t r = 0;
    int rc = h->io.read(h->io.ctx, rec + avail, sizeof(rec) - avail, &r);
    if (rc) return rc;
    avail += r;

    size_t p = 0;
    while (p < avail) {
        if (h->frame_left) {
            size_t take = h->frame_left < avail - p ? h->frame_left : avail - p;
            if (h->frame_type == FR_DATA && h->frame_ours) {
                if (*got + take > cap) return H2_ETOOBIG;
                memcpy(out + *got, rec + p, take);
                *got += take;
                h->recv_credit += (int32_t)take;
            } else if (h->frame_type == FR_HEADERS) {
                if (h->frame_ours && h->status == 0) status_peek(h, rec + p, take);
            } else {
                /* Служебный кадр: собираем тело, пока влезает. Не влезло — значит это
                 * SETTINGS с десятком настроек, из которых нас интересуют первые. */
                size_t room = sizeof(h->ctl) - h->ctl_n;
                size_t cp = take < room ? take : room;
                if (cp) memcpy(h->ctl + h->ctl_n, rec + p, cp);
                h->ctl_n = (unsigned char)(h->ctl_n + cp);
            }
            p += take;
            h->frame_left -= (uint32_t)take;
            if (h->frame_left == 0) {
                if (h->frame_type != FR_DATA && h->frame_type != FR_HEADERS) {
                    rc = ctl_handle(h);
                    if (rc) return rc;
                }
                if ((h->frame_flags & FLAG_END_STREAM) && h->frame_ours &&
                    (h->frame_type == FR_DATA || h->frame_type == FR_HEADERS))
                    h->done = 1;
                h->frame_type = 0xFF;
            }
            continue;
        }

        if (avail - p < 9) {
            /* Заголовок кадра разорван границей записи. Девять байт — весь перенос
             * состояния, который для этого нужен. */
            h->pend_n = avail - p;
            memcpy(h->pend, rec + p, h->pend_n);
            break;
        }

        uint32_t len = ((uint32_t)rec[p] << 16) | ((uint32_t)rec[p + 1] << 8) | rec[p + 2];
        h->frame_type = rec[p + 3];
        h->frame_flags = rec[p + 4];
        uint32_t sid = get32(rec + p + 5) & 0x7FFFFFFF;
        h->frame_ours = (sid == STREAM_ID);
        h->frame_left = len;
        h->ctl_n = 0;
        p += 9;

        /* Кадр без тела обрабатывается сразу: цикл выше ждёт байт, которых не будет. */
        if (len == 0) {
            if (h->frame_type != FR_DATA && h->frame_type != FR_HEADERS) {
                rc = ctl_handle(h);
                if (rc) return rc;
            }
            if ((h->frame_flags & FLAG_END_STREAM) && h->frame_ours) h->done = 1;
            h->frame_type = 0xFF;
        }
    }

    if (h->status > 0 && h->status != 200) return H2_ESTATUS;
    rc = window_refill(h);
    if (rc) return rc;
    /* Ноль байт — это законный результат: в записи мог приехать только PING или SETTINGS.
     * Возвращать при этом ошибку значило бы рвать рабочее соединение из-за служебного
     * кадра, а закрытие — потерять его. Вызывающий обязан отличать «нечего отдать» от
     * «конец потока», и именно поэтому конец приходит кодом, а не нулём. */
    return 0;
}

/* Отправить данные ЦЕЛИКОМ или не отправлять вовсе.
 *
 * «Или ничего» — не упрощение, а единственный вариант без буфера. Выше нас лежит Vision,
 * и половина кадра, ушедшая в сеть, ломает поток безвозвратно. Значит либо мы держим
 * недоотправленный остаток у себя (16 КБ на каждое из 64 соединений), либо не отправляем
 * ничего и говорим об этом вызывающему.
 *
 * Второе к тому же честнее по отношению к TCP: закрытое окно означает, что сервер не
 * успевает, и правильная реакция — НЕ подтверждать пакет клиенту. Клиент повторит его
 * сам, ровно так, как повёл бы себя при потере, а память под это не нужна вовсе. Именно
 * поэтому здесь нет ни ожидания окна, ни чтения: и то и другое означало бы, что кто-то
 * должен куда-то деть уже прочитанные данные. */
int h2_write(struct h2 *h, const unsigned char *d, size_t n) {
    if (!h->started) return H2_EPROTO;
    if (n > (size_t)h->send_win || n > (size_t)h->send_win_conn) return H2_EWINDOW;

    while (n) {
        size_t chunk = n > DEFAULT_MAX_FRAME ? DEFAULT_MAX_FRAME : n;
        int rc = frame_out(h, FR_DATA, 0, STREAM_ID, d, chunk);
        if (rc) return rc;
        h->send_win -= (int32_t)chunk;
        h->send_win_conn -= (int32_t)chunk;
        d += chunk;
        n -= chunk;
    }
    return 0;
}

const char *h2_strerror(int rc) {
    switch (rc) {
        case H2_EIO: return "обрыв HTTP/2";
        case H2_EPROTO: return "неожиданный кадр HTTP/2";
        case H2_ESTATUS: return "сервер ответил не 200";
        case H2_ERESET: return "поток закрыт сервером (RST/GOAWAY)";
        case H2_ETOOBIG: return "кадр не влез";
        case H2_EWINDOW: return "окно HTTP/2 закрыто";
        default: return "неизвестная ошибка HTTP/2";
    }
}
