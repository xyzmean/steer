/* Наборы правил sing-box (`.srs`) — читатель: набор как полноценный источник списка.
 *
 * ЗАЧЕМ ЭТО В ДВИЖКЕ. Списки доменов и подсетей, которыми пользуется половина роутеров с
 * обходом, публикуются itdoginfo/allow-domains, и в релизе там НЕТ ни одного текстового
 * файла: 25 `.srs` (sing-box), 25+11 `.mrs` (mihomo), один `geosite.dat` (Xray). Плоские
 * `.lst` лежат только в дереве ветки. Раньше движок умел только разложить `.srs` на три файла
 * (`steer srs-read`: домены, подсети, строка сужения), и управляющий слой подключал их к
 * каналу по отдельности. Теперь набор — ключ `srs_files` в канале, и его читают сами
 * компилятор набора правил (подсети) и резолвер (имена), каждый потоком и только своё.
 *
 * ПОЧЕМУ ЧИТАТЕЛЬ, А НЕ ВТОРОЙ СОПОСТАВИТЕЛЬ. В формате пять видов доменного элемента, и у
 * каждого в dnsd УЖЕ есть точное соответствие (enum srs_dom в srs.h): ключ дерева без метки —
 * точное имя, метка 0x0A — «имя и поддомены» (RULE_NAMESPACE — буквально rootLabel sing-box),
 * метка 0x0D — буквальный суффикс строки, keyword — подстрока, regex — выражение. Поэтому свой
 * индекс не нужен: элементы уходят в тот же ruleset_add, что строки `.lst`.
 *
 * РАСКЛАДКА ФОРМАТА (проверена по исходникам sing-box и разбором настоящих файлов):
 *
 *     "SRS" | uint8 version (1..5) | zlib-поток до конца файла
 *     тело: uvarint rule_count, далее rule_count правил
 *     rule: uint8 kind; 0 — обычное, 1 — логическое (mode, uvarint n, n правил, invert)
 *     обычное: пары {uint8 тип, содержимое}, конец 0xFF, затем uint8 invert
 *
 * Целые — LEB128 без знака (как в protobuf); всё фиксированной ширины — big-endian.
 *
 * ДВЕ ЛОВУШКИ. Первая: слова битовых карт записаны big-endian, а биты ВНУТРИ слова читаются
 * little-endian (`слово[i>>6] >> (i&63)`) — перепутать значит получить дерево, которое
 * разбирается без ошибок и даёт мусор. Вторая: ключи хранятся ОБРАЩЁННЫМИ («youtube.com» →
 * «moc.ebutuoy»), и разворот в sing-box идёт по РУНАМ UTF-8, а метки дерева байтовые; обратно
 * мы разворачиваем их тоже по рунам: побайтовый разворот (как было в srs-read до 1.8) давал
 * верное имя только на ASCII. Проверяется на не-ASCII именах (tests/srsunit.c).
 *
 * ВЕРСИЯ 1 КОДИРУЕТ СУФФИКС ИНАЧЕ: `domain_suffix: ["x.com"]` писалось двумя ключами — «x.com»
 * и «\r.x.com», — с версии 2 одним «\nx.com». Читателю это знать не нужно: `=x.com` плюс
 * `*.x.com` — ровно то же множество имён, что `x.com`.
 *
 * ПОТОК, А НЕ БУФЕР. Тело распаковывается окном в 32 КБ (puff_stream, src/lib/puff.c) и
 * читается кусками. Чего потребитель не просил, то пропускается, не выделяя памяти: компилятору
 * набора правил не нужны имена, и дерево имён на сотни тысяч ключей для него не строится вовсе;
 * резолверу не нужны подсети. Дерево имён, когда оно нужно, живёт в памяти только на время
 * своего обхода — его ключи уходят потребителю по одному.
 *
 * ДВА ПРОХОДА. Сужение правила (network, port) в файле идёт вперемешку с его элементами — у
 * `discord.srs` network стоит ДО подсетей, а port_range ПОСЛЕ. Потребителю же нужно знать
 * сужение раньше элементов: от него зависит, в какой набор элемент идёт. Поэтому первый проход
 * (srs_open) проходит файл, ничего не собирая, кроме разметки, и строит нормальную форму;
 * второй (srs_walk) отдаёт элементы уже с номером клаузы. Цена — вторая распаковка; для
 * настоящих наборов это миллисекунды.
 *
 * НОРМАЛЬНАЯ ФОРМА: КЛАУЗЫ. Набор sing-box — «или» его правил; правило — «и» групп условий
 * (назначение: имена или подсети; сеть; порты; источник; приложение…), логическое правило —
 * «и»/«или» вложенных, у любого бывает invert. Клауза — то, что ложится в ядро одним куском:
 *
 *   - ОДНО назначение: имена ИЛИ подсети. Правило с тем и другим даёт две клаузы с одним
 *     сужением: имена сопоставляет резолвер, подсети — набор nftables, и исключения делятся так
 *     же — имя нельзя исключить из набора подсетей, и наоборот;
 *   - сужение по протоколу и портам (struct l4match);
 *   - ограничение по клиенту (source_ip_cidr) и приложению (package_name);
 *   - исключения того же вида, что назначение («и не эти имена» / «и не эти подсети»).
 *
 * Логическое «или» — объединение: его ветви становятся клаузами наравне с правилами верхнего
 * уровня. Логическое «и» — пересечение: сужения пересекаются, назначение и ограничения берутся у
 * той ветви, у которой они есть, а ветвь с invert становится исключением («x.com, но не
 * y.x.com») или дополнением сужения («не udp» → tcp, «не порт 443» → все остальные порты).
 * Одинаковые клаузы без исключений склеиваются: набор из ста тысяч правил по одному имени —
 * одна клауза, а не сто тысяч.
 *
 * НЕВЫРАЗИМОЕ — СНИМАЕТСЯ ПРАВИЛОМ ЦЕЛИКОМ, И ТОЛЬКО В СТОРОНУ СУЖЕНИЯ. Набор — «или» правил,
 * поэтому снятое правило верхнего уровня делает набор уже, а не шире: трафик, который оно
 * ловило, просто не попадает в канал. Снимается целиком, а не по частям, потому что снятое
 * условие внутри правила ДЕЛАЛО БЫ его шире: «x.com только для процесса P» без процесса — это
 * x.com для всех. Что снимается и почему:
 *
 *   - условия, которые на этой платформе никогда не истинны или нам не видны: процессы,
 *     Wi-Fi (SSID/BSSID), тип и признаки сети, адреса интерфейсов, вид DNS-запроса, порт
 *     источника, регулярные выражения пакетов, транспорт не tcp и не udp;
 *   - правило верхнего уровня с invert («всё, кроме …») и логическое с invert: это весь
 *     трафик за вычетом, то есть канал «весь трафик», который по спеке требует явного согласия;
 *   - «и» с двумя назначениями, двумя источниками или двумя перечнями приложений, «или» внутри
 *     «и», исключение с двумя условиями сразу («не (udp и порт 443)»), исключение не того вида
 *     (подсети из клаузы имён);
 *   - правило без назначения и без приложения — весь трафик по протоколу или портам;
 *   - adguard_domain — сам элемент (образцы с якорями AdGuard, а не имена); остальное правило
 *     остаётся, потому что внутри группы назначения элементы — «или».
 *
 * Про снятое печатается одна строка steer[warn] на файл (srs_skipped), и файл принимается.
 * Отказом (−1) остаётся только испорченный файл: половина разобранного набора — не набор.
 *
 * IPv6. Подсети v6 назначения читаются и отдаются с семейством 6 (srs_elem.family) — задел под
 * 1.9 (docs/architecture.md, «4б»); потребители сегодня пропускают их с предупреждением.
 * source_ip_cidr v6 снимается сразу: клиенты у нас IPv4, и v6-источник не совпадёт ни с кем.
 */
#define _GNU_SOURCE
#include <stdarg.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <errno.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/mman.h>
#include <sys/stat.h>

#include "puff.h"
#include "srs.h"

#define SRS_VER_MAX     5

/* Типы элементов правила. Нумерация — iota в sing-box/common/srs/binary.go и стабильна с
 * версии 1.8.0; читатель гейтов по версии не имеет (их имеет только запись), поэтому здесь
 * перечислены все известные, включая те, которых в наших списках не бывает. */
enum {
    IT_QUERY_TYPE = 0, IT_NETWORK = 1, IT_DOMAIN = 2, IT_DOMAIN_KEYWORD = 3,
    IT_DOMAIN_REGEX = 4, IT_SOURCE_IP_CIDR = 5, IT_IP_CIDR = 6, IT_SOURCE_PORT = 7,
    IT_SOURCE_PORT_RANGE = 8, IT_PORT = 9, IT_PORT_RANGE = 10, IT_PROCESS_NAME = 11,
    IT_PROCESS_PATH = 12, IT_PACKAGE_NAME = 13, IT_WIFI_SSID = 14, IT_WIFI_BSSID = 15,
    IT_ADGUARD_DOMAIN = 16, IT_PROCESS_PATH_REGEX = 17, IT_NETWORK_TYPE = 18,
    IT_NET_EXPENSIVE = 19, IT_NET_CONSTRAINED = 20, IT_IFACE_ADDR = 21,
    IT_DEFAULT_IFACE_ADDR = 22, IT_PACKAGE_NAME_REGEX = 23,
    IT_FINAL = 0xFF
};

/* Служебные метки матчера доменов (sing/common/domain/matcher.go). */
#define LBL_PREFIX  0x0D   /* '\r' — «дальше что угодно»: суффикс с ведущей точкой */
#define LBL_ROOT    0x0A   /* '\n' — «домен и его поддомены» (с версии 2)          */

#define MAX_KEY     512    /* ключ дерева: домен плюс метка; с запасом на UTF-8 */
#define MAX_DEPTH   512    /* глубина обхода не больше длины ключа              */
#define MAX_STR     4096   /* строка элемента (keyword, regex, пакет): длиннее — не наш файл */

/* ---- причины снять правило ------------------------------------------------------------ */
enum {
    DR_PROC = 1u << 0, DR_WIFI = 1u << 1, DR_NETTYPE = 1u << 2, DR_NETFLAG = 1u << 3,
    DR_IFACE = 1u << 4, DR_QTYPE = 1u << 5, DR_SPORT = 1u << 6, DR_NET = 1u << 7,
    DR_PKGRE = 1u << 8, DR_PORTS = 1u << 9, DR_SRCOVER = 1u << 10, DR_TOPINV = 1u << 11,
    DR_LOGINV = 1u << 12, DR_ANDOR = 1u << 13, DR_AND2 = 1u << 14, DR_EXCL = 1u << 15,
    DR_NODEST = 1u << 16, DR_PKGOVER = 1u << 17, DR_ADGUARD = 1u << 18,
};
static const struct { unsigned bit; const char *what; } DR_TEXT[] = {
    { DR_PROC,    "процессы" },
    { DR_WIFI,    "Wi-Fi" },
    { DR_NETTYPE, "тип сети" },
    { DR_NETFLAG, "признаки сети" },
    { DR_IFACE,   "адреса интерфейсов" },
    { DR_QTYPE,   "вид DNS-запроса" },
    { DR_SPORT,   "порт источника" },
    { DR_NET,     "транспорт не tcp и не udp" },
    { DR_PKGRE,   "шаблоны пакетов" },
    { DR_PORTS,   "портов больше, чем выражается" },
    { DR_SRCOVER, "источников больше, чем выражается" },
    { DR_PKGOVER, "приложений больше, чем выражается" },
    { DR_TOPINV,  "«всё, кроме …»" },
    { DR_LOGINV,  "логическое правило с invert" },
    { DR_ANDOR,   "«или» внутри «и»" },
    { DR_AND2,    "«и» с двумя назначениями или источниками" },
    { DR_EXCL,    "исключение, которое не выражается" },
    { DR_NODEST,  "правило без назначения" },
    { DR_ADGUARD, "adguard_domain" },
};

/* ---- файл и распаковка ---------------------------------------------------------------- */

struct srs_file {
    const unsigned char *map;
    size_t size;
    int mapped;
};

static void file_close(struct srs_file *f) {
    if (!f->map) return;
    if (f->mapped) munmap((void *)f->map, f->size);
    else free((void *)f->map);
    f->map = NULL;
}

static int errf(struct err *e, const char *path, const char *fmt, ...)
    __attribute__((format(printf, 3, 4)));
static int errf(struct err *e, const char *path, const char *fmt, ...) {
    char msg[600];
    int k = snprintf(msg, sizeof(msg), "srs: %.300s: ", path);
    if (k < 0) k = 0;
    if ((size_t)k < sizeof(msg)) {
        va_list ap;
        va_start(ap, fmt);
        vsnprintf(msg + k, sizeof(msg) - (size_t)k, fmt, ap);
        va_end(ap);
    }
    return err_set(e, "%s", msg);
}

/* Открыть и проверить обёртку: подпись, версия, заголовок zlib. На выходе — сырой DEFLATE
 * (z, zn) без двух байт заголовка; хвост Adler-32 сверяется после распаковки. */
static int file_open(const char *path, struct srs_file *f, struct stat *st, struct err *e) {
    memset(f, 0, sizeof(*f));
    int fd = open(path, O_RDONLY | O_CLOEXEC);
    if (fd < 0) return errf(e, path, "не открылся (%s)", strerror(errno));
    if (fstat(fd, st) != 0 || !S_ISREG(st->st_mode)) {
        close(fd);
        return errf(e, path, "не файл");
    }
    if (st->st_size < 6 || st->st_size > 64L * 1024 * 1024) {
        close(fd);
        return errf(e, path, "неправдоподобный размер %lld", (long long)st->st_size);
    }
    f->size = (size_t)st->st_size;
    /* mmap, а не чтение в кучу: сжатое тело лежит в кэше страниц и так, и своя копия в куче
     * стоила бы его размер на всё время разбора. Не вышло (файловая система без mmap) —
     * читаем. */
    void *m = mmap(NULL, f->size, PROT_READ, MAP_PRIVATE, fd, 0);
    if (m != MAP_FAILED) {
        f->map = m;
        f->mapped = 1;
    } else {
        unsigned char *b = malloc(f->size);
        size_t got = 0;
        while (b && got < f->size) {
            ssize_t k = read(fd, b + got, f->size - got);
            if (k <= 0) break;
            got += (size_t)k;
        }
        if (!b || got != f->size) {
            free(b);
            close(fd);
            return errf(e, path, "файл не прочитался целиком");
        }
        f->map = b;
    }
    close(fd);
    if (memcmp(f->map, "SRS", 3) != 0) {
        file_close(f);
        return errf(e, path, "это не набор правил sing-box (нет подписи SRS)");
    }
    unsigned ver = f->map[3];
    if (ver < 1 || ver > SRS_VER_MAX) {
        file_close(f);
        return errf(e, path, "версия формата %u, эта сборка знает 1..%d", ver, SRS_VER_MAX);
    }
    /* zlib-обёртка (RFC 1950): два байта заголовка, дальше сырой DEFLATE, в конце Adler-32.
     * Заголовок снимаем сами и проверяем — без проверки битый файл выглядел бы как файл с
     * другим содержимым. */
    const unsigned char *z = f->map + 4;
    size_t zn = f->size - 4;
    unsigned cmf = z[0], flg = z[1];
    if (zn < 6 || (cmf & 0x0F) != 8 || ((cmf << 8) | flg) % 31 != 0 || (flg & 0x20)) {
        file_close(f);
        return errf(e, path, "тело сжато не zlib-ом (CMF %02x FLG %02x)", cmf, flg);
    }
    return 0;
}

/* ---- чтение распакованного потока ------------------------------------------------------
 * Один флаг ошибки на весь разбор вместо проверки на каждом вызове: испорченный файл должен
 * приводить к отказу, а не к разбору половины. Все читатели на выставленном флаге возвращают
 * нули и ничего не двигают, поэтому проверить его достаточно в конце. */
#define RD_BUF 16384
struct rd {
    struct puff_stream ps;
    const unsigned char *zbody;
    size_t zlen;
    unsigned char buf[RD_BUF];
    size_t pos, len;
    int err;
};

static void rd_init(struct rd *r, const struct srs_file *f) {
    memset(r, 0, offsetof(struct rd, buf));
    r->pos = r->len = 0;
    r->err = 0;
    r->zbody = f->map + 4 + 2;
    r->zlen = f->size - 4 - 2;
    puff_stream_init(&r->ps, r->zbody, (unsigned long)r->zlen);
}

/* Добрать в буфер не меньше need байт подряд. */
static int rd_need(struct rd *r, size_t need) {
    if (r->err) return -1;
    if (r->len - r->pos >= need) return 0;
    if (need > RD_BUF) { r->err = 1; return -1; }
    memmove(r->buf, r->buf + r->pos, r->len - r->pos);
    r->len -= r->pos;
    r->pos = 0;
    while (r->len < need) {
        long k = puff_stream_read(&r->ps, r->buf + r->len, RD_BUF - r->len);
        if (k <= 0) { r->err = 1; return -1; }
        r->len += (size_t)k;
    }
    return 0;
}

static const unsigned char *rd_take(struct rd *r, size_t n) {
    if (rd_need(r, n) != 0) return NULL;
    const unsigned char *q = r->buf + r->pos;
    r->pos += n;
    return q;
}

/* Пропустить или скопировать сколько угодно байт — кусками, без требования «подряд». */
static int rd_move(struct rd *r, unsigned char *dst, uint64_t n) {
    while (n) {
        size_t chunk = n > RD_BUF ? RD_BUF : (size_t)n;
        const unsigned char *q = rd_take(r, chunk);
        if (!q) return -1;
        if (dst) { memcpy(dst, q, chunk); dst += chunk; }
        n -= chunk;
    }
    return 0;
}

static unsigned rd_u8(struct rd *r) {
    const unsigned char *q = rd_take(r, 1);
    return q ? *q : 0;
}

static uint64_t rd_uvarint(struct rd *r) {
    uint64_t v = 0;
    unsigned shift = 0;
    for (;;) {
        const unsigned char *q = rd_take(r, 1);
        if (!q) return 0;
        v |= (uint64_t)(*q & 0x7F) << shift;
        if (!(*q & 0x80)) return v;
        shift += 7;
        if (shift > 63) { r->err = 1; return 0; }  /* больше 64 бит — не наш файл */
    }
}

static uint64_t rd_u64be(struct rd *r) {
    const unsigned char *q = rd_take(r, 8);
    if (!q) return 0;
    uint64_t v = 0;
    for (int i = 0; i < 8; i++) v = (v << 8) | q[i];
    return v;
}

/* Конец тела: ни байта сверх разобранного, поток дошёл до последнего блока, Adler-32 сошёлся.
 * Хвост означает, что раскладка понята неверно, даже если всё «разобралось». */
static int rd_finish(struct rd *r, const char *path, struct err *e) {
    if (r->err) return errf(e, path, "набор не разобран");
    if (r->len != r->pos) return errf(e, path, "после разбора осталось %zu байт", r->len - r->pos);
    unsigned char extra;
    long k = puff_stream_read(&r->ps, &extra, 1);
    if (k != 0 || !puff_stream_done(&r->ps))
        return errf(e, path, k > 0 ? "после разбора остались байты" : "тело не распаковалось");
    unsigned long at = r->ps.incnt;
    if (at + 4 > r->zlen) return errf(e, path, "нет контрольной суммы zlib");
    const unsigned char *t = r->zbody + at;
    unsigned long want = ((unsigned long)t[0] << 24) | ((unsigned long)t[1] << 16) |
                         ((unsigned long)t[2] << 8) | t[3];
    if (want != puff_stream_adler(&r->ps))
        return errf(e, path, "контрольная сумма тела не сошлась — файл испорчен");
    return 0;
}

/* ---- разложение диапазонов на префиксы -------------------------------------------------
 * netipx.IPSet хранит диапазоны [от, до] ВКЛЮЧИТЕЛЬНО, а набору nftables и спискам нужны
 * префиксы. Раскладка — минимальная: на каждом шаге наибольший выровненный блок, не выходящий
 * за верхнюю границу. Одна функция на оба семейства: адрес — 128 бит двумя словами, у IPv4
 * старшие 96 бит нулевые. */
struct u128 { uint64_t hi, lo; };

static int u128_lt(struct u128 a, struct u128 b) {
    return a.hi < b.hi || (a.hi == b.hi && a.lo < b.lo);
}
static struct u128 u128_sub(struct u128 a, struct u128 b) {
    struct u128 r = { a.hi - b.hi - (a.lo < b.lo), a.lo - b.lo };
    return r;
}
static int u128_ctz(struct u128 a) {
    if (a.lo) return __builtin_ctzll(a.lo);
    if (a.hi) return 64 + __builtin_ctzll(a.hi);
    return 128;
}
/* floor(log2(a + 1)) — сколько бит у наибольшего блока, влезающего в «от лo, ещё a адресов». */
static int u128_blockbits(struct u128 a) {
    if (a.hi == UINT64_MAX && a.lo == UINT64_MAX) return 128;
    struct u128 b = a;
    b.lo++;
    if (!b.lo) b.hi++;
    if (b.hi) return 127 - __builtin_clzll(b.hi);
    return 63 - __builtin_clzll(b.lo);
}
static struct u128 u128_from(const unsigned char *p, size_t n) {
    struct u128 r = { 0, 0 };
    for (size_t i = 0; i < n; i++) {
        r.hi = (r.hi << 8) | (r.lo >> 56);
        r.lo = (r.lo << 8) | p[i];
    }
    return r;
}
static void u128_to(struct u128 a, unsigned char *p, size_t n) {
    for (size_t i = n; i-- > 0; ) {
        p[i] = (unsigned char)(a.lo & 0xFF);
        a.lo = (a.lo >> 8) | (a.hi << 56);
        a.hi >>= 8;
    }
}

/* Обойти префиксы диапазона [lo, hi] в семействе с bits битами адреса; cb == NULL — только
 * счёт. Возвращает число префиксов или (size_t)-1, если cb прервал обход (*stop — его код). */
typedef int (*pfx_cb)(void *ctx, struct u128 net, int plen);
static size_t range_pfx(struct u128 lo, struct u128 hi, int bits, pfx_cb cb, void *ctx, int *stop) {
    size_t n = 0;
    for (;;) {
        int k = u128_ctz(lo);
        int m = u128_blockbits(u128_sub(hi, lo));
        if (k > bits) k = bits;
        if (m < k) k = m;
        n++;
        if (cb) {
            int rc = cb(ctx, lo, bits - k);
            if (rc) { *stop = rc; return (size_t)-1; }
        }
        if (k >= bits) break;                       /* весь диапазон семейства */
        struct u128 step = { 0, 0 };
        if (k >= 64) step.hi = 1ULL << (k - 64); else step.lo = 1ULL << k;
        struct u128 next = { lo.hi + step.hi, lo.lo + step.lo };
        if (next.lo < lo.lo) next.hi++;
        /* Переполнение (вышли за конец семейства) или перешли верхнюю границу — конец. */
        if (u128_lt(next, lo) || u128_lt(hi, next)) break;
        if (bits == 32 && (next.hi || next.lo > 0xFFFFFFFFull)) break;
        lo = next;
    }
    return n;
}

/* ---- разметка первого прохода ----------------------------------------------------------- */

#define D_DOM  1u
#define D_V4   2u
#define D_V6   4u

/* Итог одного обычного правила. */
struct drule {
    uint32_t occ;               /* номер обычного правила в порядке файла (для второго прохода) */
    int invert;
    unsigned has;               /* D_*: какие элементы назначения есть */
    unsigned items;             /* какие группы условий есть: см. G_* */
    size_t n_dom, n_v4, n_v6;
    int net_tcp, net_udp;
    struct port_range ports[MAX_PORTS];
    unsigned char ports_range[MAX_PORTS];
    size_t ports_n;
    unsigned drop;              /* DR_*: из-за чего правило не выражается */
    unsigned skip;              /* DR_*: что снято без снятия правила (adguard_domain) */
    struct srs_pfx4 *src;
    size_t src_n;
    int src_seen;               /* был ли source_ip_cidr вообще (v6-только — тоже был) */
    char **pkg;
    size_t pkg_n;
};
#define G_NET   1u
#define G_PORT  2u
#define G_SRC   4u
#define G_PKG   8u

struct lnode {
    int logical;
    int mode;                   /* 0 — and, 1 — or */
    int invert;
    struct drule d;
    struct lnode **kids;
    size_t nkids;
};

static void lnode_free(struct lnode *n) {
    if (!n) return;
    for (size_t i = 0; i < n->nkids; i++) lnode_free(n->kids[i]);
    free(n->kids);
    free(n->d.src);
    for (size_t i = 0; i < n->d.pkg_n; i++) free(n->d.pkg[i]);
    free(n->d.pkg);
    free(n);
}

/* Счёт одного диапазона для разметки и v4-источников. */
struct src_ctx { struct drule *d; };
static int src_add(void *ctx, struct u128 net, int plen) {
    struct drule *d = ((struct src_ctx *)ctx)->d;
    if (d->src_n >= SRS_MAX_SRC) { d->drop |= DR_SRCOVER; return 0; }
    if (!d->src) {
        d->src = calloc(SRS_MAX_SRC, sizeof(*d->src));
        if (!d->src) return 1;
    }
    d->src[d->src_n].net = (uint32_t)net.lo;
    d->src[d->src_n].plen = plen;
    d->src_n++;
    return 0;
}

/* netipx.IPSet: uint8 версия (обязательно 1), uint64 BE число диапазонов, затем пары границ,
 * каждая — uvarint длины (4 или 16) и байты адреса. Сначала IPv4, затем IPv6. В первом проходе
 * — счёт префиксов (и сами префиксы, если это источники). */
static int scan_ipset(struct rd *r, size_t *n4, size_t *n6, struct drule *src_to) {
    unsigned ver = rd_u8(r);
    if (ver != 1) { r->err = 1; return -1; }
    uint64_t n = rd_u64be(r);
    if (r->err || n > 10000000u) { r->err = 1; return -1; }
    for (uint64_t k = 0; k < n; k++) {
        uint64_t la = rd_uvarint(r);
        if (r->err || (la != 4 && la != 16)) { r->err = 1; return -1; }
        unsigned char a[16], b[16];
        const unsigned char *q = rd_take(r, (size_t)la);
        if (!q) return -1;
        memcpy(a, q, (size_t)la);
        uint64_t lb = rd_uvarint(r);
        if (r->err || lb != la) { r->err = 1; return -1; }
        q = rd_take(r, (size_t)lb);
        if (!q) return -1;
        memcpy(b, q, (size_t)lb);
        struct u128 lo = u128_from(a, (size_t)la), hi = u128_from(b, (size_t)la);
        if (u128_lt(hi, lo)) { r->err = 1; return -1; }
        int stop = 0;
        if (la == 4) {
            if (src_to) {
                struct src_ctx c = { src_to };
                if (range_pfx(lo, hi, 32, src_add, &c, &stop) == (size_t)-1) { r->err = 1; return -1; }
            } else if (n4) {
                *n4 += range_pfx(lo, hi, 32, NULL, NULL, &stop);
            }
        } else if (n6 && !src_to) {
            *n6 += range_pfx(lo, hi, 128, NULL, NULL, &stop);
        }
    }
    return 0;
}

/* Массив uint64 big-endian: в первом проходе — только пропуск (или счёт единиц, если count). */
static int scan_u64_array(struct rd *r, size_t *popcount) {
    uint64_t n = rd_uvarint(r);
    /* Предел от испорченного файла: 1 млн слов это 64 Мбит карты, чего быть не может. */
    if (r->err || n > 1000000u) { r->err = 1; return -1; }
    if (!popcount) return rd_move(r, NULL, n * 8);
    for (uint64_t i = 0; i < n; i++) {
        uint64_t w = rd_u64be(r);
        *popcount += (size_t)__builtin_popcountll(w);
    }
    return r->err ? -1 : 0;
}

static int scan_domain_matcher(struct rd *r, size_t *nkeys) {
    (void)rd_u8(r);                          /* зарезервированный байт: пишется 0 */
    if (scan_u64_array(r, nkeys) != 0) return -1;   /* leaves: единица — конец ключа */
    if (scan_u64_array(r, NULL) != 0) return -1;    /* bitmap */
    uint64_t nlab = rd_uvarint(r);
    if (r->err || nlab > 100000000u) { r->err = 1; return -1; }
    return rd_move(r, NULL, nlab);
}

/* Список строк: uvarint число, затем каждая как uvarint длины и байты. */
static int scan_strings(struct rd *r, size_t *count) {
    uint64_t n = rd_uvarint(r);
    if (r->err || n > 10000000u) { r->err = 1; return -1; }
    for (uint64_t i = 0; i < n; i++) {
        uint64_t l = rd_uvarint(r);
        if (r->err || rd_move(r, NULL, l) != 0) { r->err = 1; return -1; }
    }
    if (count) *count += (size_t)n;
    return 0;
}

static void port_add(struct drule *d, unsigned lo, unsigned hi, int range) {
    for (size_t i = 0; i < d->ports_n; i++)
        if (d->ports[i].lo == lo && d->ports[i].hi == hi) return;
    if (d->ports_n >= MAX_PORTS) { d->drop |= DR_PORTS; return; }
    d->ports[d->ports_n].lo = (unsigned short)lo;
    d->ports[d->ports_n].hi = (unsigned short)hi;
    d->ports_range[d->ports_n] = (unsigned char)range;
    d->ports_n++;
}

/* Число порта из текста port_range; пусто — граница открыта. -1 — не число. */
static long port_text(const unsigned char *p, size_t n) {
    if (!n) return -2;
    long v = 0;
    for (size_t i = 0; i < n; i++) {
        if (p[i] < '0' || p[i] > '9') return -1;
        v = v * 10 + (p[i] - '0');
        if (v > 65535) return -1;
    }
    return v;
}

/* Элементы, общие обоим проходам: пропуск структурно по формату, как их пишет sing-box. */
static int skip_iface_addr(struct rd *r) {
    uint64_t entries = rd_uvarint(r);
    if (r->err || entries > 1000000u) { r->err = 1; return -1; }
    for (uint64_t i = 0; i < entries; i++) {
        (void)rd_u8(r);
        uint64_t cnt = rd_uvarint(r);
        if (r->err || cnt > 1000000u) { r->err = 1; return -1; }
        for (uint64_t k = 0; k < cnt; k++) {
            uint64_t l = rd_uvarint(r);
            if (r->err || rd_move(r, NULL, l) != 0 || !rd_take(r, 1)) { r->err = 1; return -1; }
        }
    }
    return 0;
}

static int skip_default_iface_addr(struct rd *r) {
    uint64_t cnt = rd_uvarint(r);
    if (r->err || cnt > 1000000u) { r->err = 1; return -1; }
    for (uint64_t k = 0; k < cnt; k++) {
        uint64_t l = rd_uvarint(r);
        if (r->err || rd_move(r, NULL, l) != 0 || !rd_take(r, 1)) { r->err = 1; return -1; }
    }
    return 0;
}

static int skip_adguard(struct rd *r) {
    (void)rd_u8(r);
    if (scan_u64_array(r, NULL) != 0 || scan_u64_array(r, NULL) != 0) return -1;
    uint64_t nl = rd_uvarint(r);
    if (r->err || nl > 100000000u) { r->err = 1; return -1; }
    return rd_move(r, NULL, nl);
}

static int skip_u16_list(struct rd *r) {
    uint64_t n = rd_uvarint(r);
    if (r->err || n > 10000000u) { r->err = 1; return -1; }
    return rd_move(r, NULL, n * 2);
}

/* Одно обычное правило первого прохода. */
static int scan_default(struct rd *r, struct drule *d) {
    for (;;) {
        unsigned t = rd_u8(r);
        if (r->err) return -1;
        if (t == IT_FINAL) {
            d->invert = rd_u8(r) != 0;
            return r->err ? -1 : 0;
        }
        switch (t) {
        case IT_DOMAIN: {
            size_t k = 0;
            if (scan_domain_matcher(r, &k) != 0) return -1;
            if (k) { d->has |= D_DOM; d->n_dom += k; }
            break;
        }
        case IT_DOMAIN_KEYWORD:
        case IT_DOMAIN_REGEX: {
            size_t k = 0;
            if (scan_strings(r, &k) != 0) return -1;
            if (k) { d->has |= D_DOM; d->n_dom += k; }
            break;
        }
        case IT_IP_CIDR: {
            size_t a = 0, b = 0;
            if (scan_ipset(r, &a, &b, NULL) != 0) return -1;
            if (a) { d->has |= D_V4; d->n_v4 += a; }
            if (b) { d->has |= D_V6; d->n_v6 += b; }
            break;
        }
        case IT_SOURCE_IP_CIDR:
            d->items |= G_SRC;
            d->src_seen = 1;
            if (scan_ipset(r, NULL, NULL, d) != 0) return -1;
            break;
        case IT_NETWORK: {
            uint64_t n = rd_uvarint(r);
            if (r->err || n > 64) { r->err = 1; return -1; }
            d->items |= G_NET;
            for (uint64_t i = 0; i < n; i++) {
                uint64_t l = rd_uvarint(r);
                if (r->err || l > MAX_STR) { r->err = 1; return -1; }
                const unsigned char *q = rd_take(r, (size_t)l);
                if (!q) return -1;
                if (l == 3 && !memcmp(q, "tcp", 3)) d->net_tcp = 1;
                else if (l == 3 && !memcmp(q, "udp", 3)) d->net_udp = 1;
                /* Транспорт, которого мы не знаем (icmp у новых sing-box), нельзя ни выразить,
                 * ни отбросить: отбросив, мы расширили бы совпадение. Правило снимается. */
                else d->drop |= DR_NET;
            }
            break;
        }
        case IT_PORT: {
            uint64_t n = rd_uvarint(r);
            if (r->err || n > 10000u) { r->err = 1; return -1; }
            d->items |= G_PORT;
            for (uint64_t i = 0; i < n; i++) {
                const unsigned char *q = rd_take(r, 2);
                if (!q) return -1;
                unsigned p = ((unsigned)q[0] << 8) | q[1];
                port_add(d, p, p, 0);
            }
            break;
        }
        case IT_PORT_RANGE: {
            /* Форма у sing-box «50000:65535», у нас «50000-65535». Открытые с одной стороны
             * («:3000», «4000:») у sing-box значат «до 3000» и «от 4000» — так и берём. */
            uint64_t n = rd_uvarint(r);
            if (r->err || n > 10000u) { r->err = 1; return -1; }
            d->items |= G_PORT;
            for (uint64_t i = 0; i < n; i++) {
                uint64_t l = rd_uvarint(r);
                if (r->err || l > 64) { r->err = 1; return -1; }
                const unsigned char *q = rd_take(r, (size_t)l);
                if (!q) return -1;
                const unsigned char *colon = memchr(q, ':', (size_t)l);
                long lo, hi;
                if (colon) {
                    lo = port_text(q, (size_t)(colon - q));
                    hi = port_text(colon + 1, (size_t)(q + l - colon - 1));
                    if (lo == -2) lo = 0;
                    if (hi == -2) hi = 65535;
                } else {
                    lo = hi = port_text(q, (size_t)l);
                }
                if (lo < 0 || hi < 0 || lo > hi) { d->drop |= DR_PORTS; continue; }
                port_add(d, (unsigned)lo, (unsigned)hi, colon != NULL);
            }
            break;
        }
        case IT_PACKAGE_NAME: {
            uint64_t n = rd_uvarint(r);
            if (r->err || n > 100000u) { r->err = 1; return -1; }
            d->items |= G_PKG;
            for (uint64_t i = 0; i < n; i++) {
                uint64_t l = rd_uvarint(r);
                if (r->err || l > MAX_STR) { r->err = 1; return -1; }
                const unsigned char *q = rd_take(r, (size_t)l);
                if (!q) return -1;
                if (d->pkg_n >= SRS_MAX_PKG || l >= 128) { d->drop |= DR_PKGOVER; continue; }
                if (!d->pkg && !(d->pkg = calloc(SRS_MAX_PKG, sizeof(char *)))) { r->err = 1; return -1; }
                char *s = malloc((size_t)l + 1);
                if (!s) { r->err = 1; return -1; }
                memcpy(s, q, (size_t)l);
                s[l] = '\0';
                d->pkg[d->pkg_n++] = s;
            }
            break;
        }
        case IT_SOURCE_PORT_RANGE:
            if (scan_strings(r, NULL) != 0) return -1;
            d->drop |= DR_SPORT;
            break;
        case IT_SOURCE_PORT:
            if (skip_u16_list(r) != 0) return -1;
            d->drop |= DR_SPORT;
            break;
        case IT_QUERY_TYPE:
            if (skip_u16_list(r) != 0) return -1;
            d->drop |= DR_QTYPE;
            break;
        case IT_PROCESS_NAME: case IT_PROCESS_PATH: case IT_PROCESS_PATH_REGEX:
            if (scan_strings(r, NULL) != 0) return -1;
            d->drop |= DR_PROC;
            break;
        case IT_PACKAGE_NAME_REGEX:
            if (scan_strings(r, NULL) != 0) return -1;
            d->drop |= DR_PKGRE;
            break;
        case IT_WIFI_SSID: case IT_WIFI_BSSID:
            if (scan_strings(r, NULL) != 0) return -1;
            d->drop |= DR_WIFI;
            break;
        case IT_NETWORK_TYPE:
            if (scan_strings(r, NULL) != 0) return -1;
            d->drop |= DR_NETTYPE;
            break;
        case IT_ADGUARD_DOMAIN:
            /* Тот же succinct-набор, но с другими метками (`*` и 0x08): правила AdGuard — не
             * имена, а образцы с якорями. Снимается сам элемент: внутри группы назначения
             * элементы — «или», и без него правило только уже. */
            if (skip_adguard(r) != 0) return -1;
            d->skip |= DR_ADGUARD;
            break;
        case IT_NET_EXPENSIVE: case IT_NET_CONSTRAINED:
            /* Полезной нагрузки нет: сам тег и есть значение. */
            d->drop |= DR_NETFLAG;
            break;
        case IT_IFACE_ADDR:
            if (skip_iface_addr(r) != 0) return -1;
            d->drop |= DR_IFACE;
            break;
        case IT_DEFAULT_IFACE_ADDR:
            if (skip_default_iface_addr(r) != 0) return -1;
            d->drop |= DR_IFACE;
            break;
        default:
            /* Неизвестный тип — не «пропустим и поедем дальше»: длину его содержимого мы не
             * знаем, а угадав, разобрали бы остаток файла как попало. */
            r->err = 2;
            return -1;
        }
    }
}

static struct lnode *scan_rule(struct rd *r, int depth, uint32_t *occ) {
    if (depth > 100) { r->err = 1; return NULL; }   /* тот же предел, что у sing-box */
    unsigned kind = rd_u8(r);
    if (r->err) return NULL;
    struct lnode *n = calloc(1, sizeof(*n));
    if (!n) { r->err = 1; return NULL; }
    if (kind == 0) {
        n->d.occ = (*occ)++;
        if (scan_default(r, &n->d) != 0) { lnode_free(n); return NULL; }
        n->invert = n->d.invert;
        return n;
    }
    if (kind == 1) {
        n->logical = 1;
        n->mode = rd_u8(r) ? 1 : 0;
        uint64_t cnt = rd_uvarint(r);
        if (r->err || cnt > 100000u) { r->err = 1; lnode_free(n); return NULL; }
        n->kids = calloc(cnt ? (size_t)cnt : 1, sizeof(*n->kids));
        if (!n->kids) { r->err = 1; lnode_free(n); return NULL; }
        for (uint64_t i = 0; i < cnt; i++) {
            struct lnode *k = scan_rule(r, depth + 1, occ);
            if (!k) { lnode_free(n); return NULL; }
            n->kids[n->nkids++] = k;
        }
        n->invert = rd_u8(r) != 0;
        if (r->err) { lnode_free(n); return NULL; }
        return n;
    }
    r->err = 3;
    lnode_free(n);
    return NULL;
}

/* ---- набор после первого прохода ------------------------------------------------------- */

#define OCC_NONE  0xFFFFFFFFu
#define OCC_EXCL  0x80000000u

struct occ_map { uint32_t dom, cidr; };

struct srs_set {
    int refs;                   /* ссылка кэша + каждого, кто открыл и ещё не отпустил */
    char *path;
    dev_t dev;
    ino_t ino;
    off_t size;
    struct timespec mtime;
    struct srs_clause *cl;
    size_t cl_n, cl_cap;
    struct occ_map *occ;
    size_t occ_n;
    unsigned dropped_why;
    size_t dropped;
    char skipped[400];
    /* Склейка одинаковых клауз: хеш по метаданным → номер клаузы + 1 (0 — пусто). */
    uint32_t *hash;
    size_t hash_cap;
};

static void set_free(struct srs_set *s) {
    if (!s) return;
    for (size_t i = 0; i < s->cl_n; i++) {
        free((void *)s->cl[i].src);
        if (s->cl[i].pkg) {
            for (size_t k = 0; k < s->cl[i].pkg_n; k++) free((void *)s->cl[i].pkg[k]);
            free((void *)s->cl[i].pkg);
        }
    }
    free(s->cl);
    free(s->occ);
    free(s->hash);
    free(s->path);
    free(s);
}

/* ---- сужение: множества протоколов и портов --------------------------------------------- */

/* Протоколы битами: TCP, UDP и «прочие» (icmp, gre, esp…). ALL — без сужения по протоколу. */
#define PM_TCP   1u
#define PM_UDP   2u
#define PM_OTHER 4u
#define PM_ALL   7u

/* Множество портов: отсортированные непересекающиеся диапазоны, all — «любой порт». */
struct pset {
    int all;
    struct port_range r[MAX_PORTS * 2 + 2];
    size_t n;
};

static int pr_cmp(const void *a, const void *b) {
    const struct port_range *x = a, *y = b;
    return x->lo != y->lo ? (x->lo < y->lo ? -1 : 1) : (x->hi < y->hi ? -1 : x->hi > y->hi);
}

/* Отсортировать и слить. */
static void pset_norm(struct pset *p) {
    if (p->all || p->n < 2) return;
    qsort(p->r, p->n, sizeof(p->r[0]), pr_cmp);
    size_t w = 0;
    for (size_t i = 1; i < p->n; i++) {
        if ((unsigned)p->r[i].lo <= (unsigned)p->r[w].hi + 1u) {
            if (p->r[i].hi > p->r[w].hi) p->r[w].hi = p->r[i].hi;
        } else {
            p->r[++w] = p->r[i];
        }
    }
    p->n = w + 1;
}

static void pset_from(struct pset *p, const struct port_range *r, size_t n) {
    p->all = n == 0;
    p->n = 0;
    for (size_t i = 0; i < n && i < sizeof(p->r) / sizeof(p->r[0]); i++) p->r[p->n++] = r[i];
    pset_norm(p);
}

static void pset_and(struct pset *a, const struct pset *b) {
    if (b->all) return;
    if (a->all) { *a = *b; return; }
    struct pset o = { .all = 0, .n = 0 };
    for (size_t i = 0; i < a->n; i++)
        for (size_t k = 0; k < b->n; k++) {
            unsigned lo = a->r[i].lo > b->r[k].lo ? a->r[i].lo : b->r[k].lo;
            unsigned hi = a->r[i].hi < b->r[k].hi ? a->r[i].hi : b->r[k].hi;
            if (lo <= hi && o.n < sizeof(o.r) / sizeof(o.r[0])) {
                o.r[o.n].lo = (unsigned short)lo;
                o.r[o.n].hi = (unsigned short)hi;
                o.n++;
            }
        }
    pset_norm(&o);
    *a = o;
}

/* Дополнение до 0-65535. */
static void pset_not(struct pset *p) {
    if (p->all) { p->all = 0; p->n = 0; return; }
    struct pset o = { .all = 0, .n = 0 };
    unsigned next = 0;
    for (size_t i = 0; i < p->n; i++) {
        if (p->r[i].lo > next) {
            o.r[o.n].lo = (unsigned short)next;
            o.r[o.n].hi = (unsigned short)(p->r[i].lo - 1);
            o.n++;
        }
        next = (unsigned)p->r[i].hi + 1u;
    }
    if (next <= 65535) {
        o.r[o.n].lo = (unsigned short)next;
        o.r[o.n].hi = 65535;
        o.n++;
    }
    *p = o;
}

/* Протоколы и порты → struct l4match. 0 — пусто (ни один пакет), -1 — не выражается
 * (портов больше MAX_PORTS), -2 — не выражается (остались только протоколы без портов, не tcp
 * и не udp), 1 — готово.
 *
 * Прочие протоколы выражаются только вместе с tcp и udp («без сужения»): у канала нет «tcp и
 * icmp». Если они остались без полного набора — снимаются, это сужение, а не расширение.
 * «tcp и udp без портов» — не пустое сужение: оно не пускает icmp, поэтому записывается портами
 * 0-65535 (x_l4 тогда пинит протокол множеством { tcp, udp }). */
static int l4_make(unsigned pm, const struct pset *ps, struct l4match *out) {
    memset(out, 0, sizeof(*out));
    if (!ps->all && ps->n == 0) return 0;
    if (pm == PM_ALL && ps->all) return 1;              /* без сужения */
    unsigned tu = pm & (PM_TCP | PM_UDP);
    if (!tu) return (pm & PM_OTHER) ? -2 : 0;     /* только не tcp и не udp — не выражается */
    out->proto = tu == PM_TCP ? CH_PROTO_TCP : tu == PM_UDP ? CH_PROTO_UDP : CH_PROTO_ANY;
    if (ps->all) {
        if (out->proto == CH_PROTO_ANY) {
            out->ports[0].lo = 0;
            out->ports[0].hi = 65535;
            out->ports_n = 1;
        }
        return 1;
    }
    if (ps->n > MAX_PORTS) return -1;
    for (size_t i = 0; i < ps->n; i++) out->ports[i] = ps->r[i];
    out->ports_n = ps->n;
    return 1;
}

static unsigned pm_of(const struct drule *d) {
    if (!(d->items & G_NET)) return PM_ALL;
    return (d->net_tcp ? PM_TCP : 0) | (d->net_udp ? PM_UDP : 0);
}

/* ---- нормальная форма ---------------------------------------------------------------- */

#define MAX_XOCC 64
struct conj {
    unsigned pm;
    struct pset ps;
    const struct drule *dest;       /* правило, дающее назначение */
    const struct drule *src;
    const struct drule *pkg;
    const struct drule *first;      /* первое положительное правило */
    size_t npos, nneg;
    const struct drule *x[MAX_XOCC];
    size_t xn;
    unsigned why;                   /* причина, если не выражается */
    int empty;                      /* выражается, но пусто — снимается молча */
};

static void conj_init(struct conj *c) {
    memset(c, 0, sizeof(*c));
    c->pm = PM_ALL;
    c->ps.all = 1;
}

static int conj_pos(struct conj *c, const struct drule *d) {
    if (d->drop) { c->why |= d->drop; return -1; }
    if (!c->npos++) c->first = d;
    c->pm &= pm_of(d);
    if (d->items & G_PORT) {
        struct pset p;
        pset_from(&p, d->ports, d->ports_n);
        pset_and(&c->ps, &p);
    }
    if (d->has) {
        if (c->dest) { c->why |= DR_AND2; return -1; }
        c->dest = d;
    }
    if (d->items & G_SRC) {
        if (c->src) { c->why |= DR_AND2; return -1; }
        c->src = d;
    }
    if (d->items & G_PKG) {
        if (c->pkg) { c->why |= DR_AND2; return -1; }
        c->pkg = d;
    }
    return 0;
}

/* Ветвь «и» с invert: «… и НЕ это». Выражается, только если у неё ОДНО условие. */
static int conj_neg(struct conj *c, const struct drule *d) {
    c->nneg++;
    if (d->drop || d->skip) { c->why |= DR_EXCL | d->drop; return -1; }
    int dims = (d->has != 0) + ((d->items & G_NET) != 0) + ((d->items & G_PORT) != 0) +
               ((d->items & G_SRC) != 0) + ((d->items & G_PKG) != 0);
    if (dims == 0) { c->empty = 1; return 0; }          /* «и не (всё)» — не совпадает ничто */
    if (dims > 1 || (d->items & (G_SRC | G_PKG))) { c->why |= DR_EXCL; return -1; }
    if (d->has) {
        if (c->xn >= MAX_XOCC) { c->why |= DR_EXCL; return -1; }
        c->x[c->xn++] = d;
        return 0;
    }
    if (d->items & G_NET) {
        c->pm &= ~pm_of(d);
        return 0;
    }
    /* «не эти порты»: у пакета без портов (icmp) порта нет, и под «не порт 443» он попадает;
     * выразить это рядом с портами нечем — прочие протоколы снимаются (сужение). */
    struct pset p;
    pset_from(&p, d->ports, d->ports_n);
    pset_not(&p);
    pset_and(&c->ps, &p);
    c->pm &= ~PM_OTHER;
    return 0;
}

static int conj_and(struct conj *c, const struct lnode *n) {
    for (size_t i = 0; i < n->nkids; i++) {
        const struct lnode *k = n->kids[i];
        if (!k->logical) {
            if ((k->invert ? conj_neg(c, &k->d) : conj_pos(c, &k->d)) != 0) return -1;
        } else if (k->mode == 0 && !k->invert) {
            if (conj_and(c, k) != 0) return -1;
        } else {
            c->why |= k->invert ? DR_LOGINV : DR_ANDOR;
            return -1;
        }
    }
    return 0;
}

static uint32_t clause_hash(const struct srs_clause *c) {
    uint32_t h = 2166136261u;
    const unsigned char *p = (const unsigned char *)&c->l4;
    for (size_t i = 0; i < sizeof(c->l4); i++) h = (h ^ p[i]) * 16777619u;
    h = (h ^ c->kind) * 16777619u;
    for (size_t i = 0; i < c->src_n; i++) h = (h ^ c->src[i].net ^ (uint32_t)c->src[i].plen) * 16777619u;
    for (size_t i = 0; i < c->pkg_n; i++)
        for (const char *q = c->pkg[i]; *q; q++) h = (h ^ (unsigned char)*q) * 16777619u;
    return h;
}

static int clause_same_meta(const struct srs_clause *a, const struct srs_clause *b) {
    if (a->kind != b->kind || (a->flags & (SRS_F_XDOM | SRS_F_XCIDR)) ||
        (b->flags & (SRS_F_XDOM | SRS_F_XCIDR)))
        return 0;
    if (memcmp(&a->l4, &b->l4, sizeof(a->l4)) != 0) return 0;
    if (a->net_tcp != b->net_tcp || a->net_udp != b->net_udp || a->raw_n != b->raw_n) return 0;
    if (memcmp(a->raw, b->raw, a->raw_n * sizeof(a->raw[0])) != 0 ||
        memcmp(a->raw_range, b->raw_range, a->raw_n) != 0) return 0;
    if (a->src_n != b->src_n || a->pkg_n != b->pkg_n) return 0;
    if (a->src_n && memcmp(a->src, b->src, a->src_n * sizeof(a->src[0])) != 0) return 0;
    for (size_t i = 0; i < a->pkg_n; i++) if (strcmp(a->pkg[i], b->pkg[i])) return 0;
    return 1;
}

static int hash_grow(struct srs_set *s) {
    size_t cap = s->hash_cap ? s->hash_cap * 2 : 64;
    uint32_t *h = calloc(cap, sizeof(*h));
    if (!h) return -1;
    for (size_t i = 0; i < s->hash_cap; i++) {
        uint32_t v = s->hash[i];
        if (!v) continue;
        size_t k = clause_hash(&s->cl[v - 1]) & (cap - 1);
        while (h[k]) k = (k + 1) & (cap - 1);
        h[k] = v;
    }
    free(s->hash);
    s->hash = h;
    s->hash_cap = cap;
    return 0;
}

/* Завести клаузу (или найти такую же без исключений). Возвращает номер или OCC_NONE при нехватке
 * памяти. src/pkg переходят во владение набора (копией). */
static uint32_t clause_put(struct srs_set *s, struct srs_clause *c, int mergeable) {
    if (mergeable && s->hash_cap) {
        size_t k = clause_hash(c) & (s->hash_cap - 1);
        while (s->hash[k]) {
            struct srs_clause *o = &s->cl[s->hash[k] - 1];
            if (clause_same_meta(o, c)) {
                o->n_v4 += c->n_v4;
                o->n_v6 += c->n_v6;
                o->n_dom += c->n_dom;
                o->flags |= c->flags;
                return s->hash[k] - 1;
            }
            k = (k + 1) & (s->hash_cap - 1);
        }
    }
    if (s->cl_n == s->cl_cap) {
        size_t cap = s->cl_cap ? s->cl_cap * 2 : 8;
        struct srs_clause *n = realloc(s->cl, cap * sizeof(*n));
        if (!n) return OCC_NONE;
        s->cl = n;
        s->cl_cap = cap;
    }
    struct srs_clause *d = &s->cl[s->cl_n];
    *d = *c;
    d->src = NULL;
    d->pkg = NULL;
    if (c->src_n) {
        struct srs_pfx4 *p = malloc(c->src_n * sizeof(*p));
        if (!p) return OCC_NONE;
        memcpy(p, c->src, c->src_n * sizeof(*p));
        d->src = p;
    }
    if (c->pkg_n) {
        char **p = calloc(c->pkg_n, sizeof(*p));
        if (!p) return OCC_NONE;
        for (size_t i = 0; i < c->pkg_n; i++) p[i] = strdup(c->pkg[i]);
        d->pkg = (const char *const *)p;
    }
    uint32_t idx = (uint32_t)s->cl_n++;
    if (mergeable) {
        if ((s->cl_n) * 2 > s->hash_cap && hash_grow(s) != 0) return OCC_NONE;
        size_t k = clause_hash(d) & (s->hash_cap - 1);
        while (s->hash[k]) k = (k + 1) & (s->hash_cap - 1);
        s->hash[k] = idx + 1;
    }
    return idx;
}

static void drop_rule(struct srs_set *s, unsigned why) {
    if (!why) return;
    s->dropped++;
    s->dropped_why |= why;
}

/* Клаузы одного правила верхнего уровня из пересечения c. 0 — готово, -1 — нет памяти. */
static int conj_emit(struct srs_set *s, struct conj *c, uint32_t rule) {
    if (c->empty) return 0;
    struct l4match l4;
    int lr = l4_make(c->pm, &c->ps, &l4);
    if (lr == 0) return 0;                              /* пусто: не совпадает ничто */
    if (lr < 0) { drop_rule(s, lr == -2 ? DR_NET : DR_PORTS); return 0; }
    struct srs_clause base;
    memset(&base, 0, sizeof(base));
    base.l4 = l4;
    base.rule = rule;
    const struct drule *single = c->npos == 1 && !c->nneg ? c->first : NULL;
    if (single) {
        /* Правило как записано — для srs-read, чей вывод обязан остаться прежним. */
        base.net_tcp = single->net_tcp;
        base.net_udp = single->net_udp;
        base.raw_n = single->ports_n;
        memcpy(base.raw, single->ports, base.raw_n * sizeof(base.raw[0]));
        memcpy(base.raw_range, single->ports_range, base.raw_n);
    } else {
        base.net_tcp = l4.proto != CH_PROTO_UDP && !l4match_empty(&l4);
        base.net_udp = l4.proto != CH_PROTO_TCP && !l4match_empty(&l4);
        base.raw_n = l4.ports_n;
        memcpy(base.raw, l4.ports, l4.ports_n * sizeof(l4.ports[0]));
        for (size_t i = 0; i < l4.ports_n; i++)
            base.raw_range[i] = l4.ports[i].lo != l4.ports[i].hi;
    }
    if (c->src) {
        /* Только v6-источники: IPv4-клиентов у такой клаузы нет — не совпадает ничто. */
        if (!c->src->src_n) return 0;
        base.src = c->src->src;
        base.src_n = c->src->src_n;
    }
    if (c->pkg) {
        base.pkg = (const char *const *)c->pkg->pkg;
        base.pkg_n = c->pkg->pkg_n;
    }
    if (c->dest && c->dest->skip) s->dropped_why |= c->dest->skip;
    if (!c->dest) {
        if (!c->pkg) { drop_rule(s, DR_NODEST); return 0; }
        if (c->xn) { drop_rule(s, DR_EXCL); return 0; }
        base.kind = SRS_C_ALL;
        return clause_put(s, &base, 1) == OCC_NONE ? -1 : 0;
    }
    const struct drule *d = c->dest;
    unsigned xd = 0, xc = 0;
    size_t xv4 = 0;
    for (size_t i = 0; i < c->xn; i++) {
        xd |= c->x[i]->has & D_DOM;
        xc |= c->x[i]->has & (D_V4 | D_V6);
        xv4 += c->x[i]->n_v4;
    }
    uint32_t cdom = OCC_NONE, ccidr = OCC_NONE;
    if (d->has & D_DOM) {
        /* Исключение-подсети из клаузы имён не выражается: резолвер про адреса не спрашивает, а
         * в наборе у имени поддельный адрес. Снимается клауза имён, подсети правила остаются. */
        if (xc) drop_rule(s, DR_EXCL);
        else {
            struct srs_clause k = base;
            k.kind = SRS_C_DOM;
            k.n_dom = d->n_dom;
            k.flags = xd ? SRS_F_XDOM : 0;
            cdom = clause_put(s, &k, !xd);
            if (cdom == OCC_NONE) return -1;
        }
    }
    if (d->has & (D_V4 | D_V6)) {
        if (xd) drop_rule(s, DR_EXCL);
        else {
            struct srs_clause k = base;
            k.kind = SRS_C_CIDR;
            k.n_v4 = d->n_v4;
            k.n_v6 = d->n_v6;
            k.n_xv4 = xv4;
            k.flags = ((d->has & D_V4) ? SRS_F_V4 : 0) | ((d->has & D_V6) ? SRS_F_V6 : 0) |
                      (xc ? SRS_F_XCIDR : 0);
            ccidr = clause_put(s, &k, !xc);
            if (ccidr == OCC_NONE) return -1;
        }
    }
    if (d->occ < s->occ_n) {
        s->occ[d->occ].dom = cdom;
        s->occ[d->occ].cidr = ccidr;
    }
    for (size_t i = 0; i < c->xn; i++) {
        uint32_t o = c->x[i]->occ;
        if (o >= s->occ_n) continue;
        if (cdom != OCC_NONE) s->occ[o].dom = cdom | OCC_EXCL;
        if (ccidr != OCC_NONE) s->occ[o].cidr = ccidr | OCC_EXCL;
    }
    return 0;
}

static int norm_top(struct srs_set *s, const struct lnode *n, uint32_t rule) {
    struct conj c;
    conj_init(&c);
    if (!n->logical) {
        if (n->invert) { drop_rule(s, DR_TOPINV); return 0; }
        if (conj_pos(&c, &n->d) != 0) { drop_rule(s, c.why); return 0; }
        return conj_emit(s, &c, rule);
    }
    if (n->invert) { drop_rule(s, DR_LOGINV); return 0; }
    if (n->mode == 1) {
        for (size_t i = 0; i < n->nkids; i++)
            if (norm_top(s, n->kids[i], rule) != 0) return -1;
        return 0;
    }
    if (conj_and(&c, n) != 0) { drop_rule(s, c.why); return 0; }
    return conj_emit(s, &c, rule);
}

static int occ_reserve(struct srs_set *s, size_t need) {
    if (need <= s->occ_n) return 0;
    struct occ_map *m = realloc(s->occ, need * sizeof(*m));
    if (!m) return -1;
    for (size_t i = s->occ_n; i < need; i++) m[i].dom = m[i].cidr = OCC_NONE;
    s->occ = m;
    s->occ_n = need;
    return 0;
}

static void build_skipped(struct srs_set *s) {
    s->skipped[0] = '\0';
    if (!s->dropped_why) return;
    size_t k = 0;
    int w;
    if (s->dropped)
        w = snprintf(s->skipped, sizeof(s->skipped), "снято правил: %zu (", s->dropped);
    else
        w = snprintf(s->skipped, sizeof(s->skipped), "снято элементов (");
    if (w > 0) k = (size_t)w;
    const char *sep = "";
    for (size_t i = 0; i < sizeof(DR_TEXT) / sizeof(DR_TEXT[0]); i++) {
        if (!(s->dropped_why & DR_TEXT[i].bit)) continue;
        w = snprintf(s->skipped + k, k < sizeof(s->skipped) ? sizeof(s->skipped) - k : 0,
                     "%s%s", sep, DR_TEXT[i].what);
        if (w > 0 && k + (size_t)w < sizeof(s->skipped)) k += (size_t)w;
        sep = ", ";
    }
    if (k + 2 < sizeof(s->skipped)) { s->skipped[k++] = ')'; s->skipped[k] = '\0'; }
}

static const char *rd_errtext(int code) {
    switch (code) {
    case 2: return "неизвестный тип элемента";
    case 3: return "неизвестный вид правила";
    default: return "набор не разобран";
    }
}

static struct srs_set *prescan(const char *path, struct err *e) {
    struct srs_file f;
    struct stat st;
    if (file_open(path, &f, &st, e) != 0) return NULL;
    struct rd *r = malloc(sizeof(*r));
    struct srs_set *s = calloc(1, sizeof(*s));
    if (!r || !s || !(s->path = strdup(path))) {
        free(r); free(s);
        file_close(&f);
        errf(e, path, "нет памяти");
        return NULL;
    }
    s->dev = st.st_dev;
    s->ino = st.st_ino;
    s->size = st.st_size;
    s->mtime = st.st_mtim;
    rd_init(r, &f);
    uint64_t nrules = rd_uvarint(r);
    int bad = r->err || nrules > 100000u;
    uint32_t occ = 0;
    for (uint64_t i = 0; !bad && i < nrules; i++) {
        struct lnode *n = scan_rule(r, 0, &occ);
        if (!n) { bad = 1; break; }
        if (occ_reserve(s, occ) != 0 || norm_top(s, n, (uint32_t)i) != 0) {
            lnode_free(n);
            r->err = 1;
            bad = 1;
            break;
        }
        lnode_free(n);
    }
    if (occ_reserve(s, occ) != 0) bad = 1;
    s->occ_n = occ;
    int code = r->err;
    int rc = bad ? errf(e, path, "%s", rd_errtext(code)) : rd_finish(r, path, e);
    free(r);
    file_close(&f);
    if (rc != 0) { set_free(s); return NULL; }
    free(s->hash);
    s->hash = NULL;
    s->hash_cap = 0;
    build_skipped(s);
    return s;
}

/* ---- кэш разборов ------------------------------------------------------------------------
 * Один файл спрашивают несколько мест одного процесса — группы компилятора, имена наборов
 * (group_set_name), резолвер, проверка размеров. Разбор делается один раз, пока файл не
 * изменился: смену выдают размер, время изменения и inode (обновление списков пишет файл
 * заново и переименовывает). */
#define SRS_CACHE 128
static struct srs_set *g_cache[SRS_CACHE];
static size_t g_cache_n;

/* Разбор отдаётся, когда его не держит ни кэш, ни тот, кто открыл: раскладка канала хранит
 * указатели на клаузы до конца жизни групп, а файл тем временем может смениться (обновление
 * списков) — тогда кэш заводит новый разбор, а прежний живёт, пока его отпускают. */
void srs_release(const struct srs_set *cs) {
    struct srs_set *s = (struct srs_set *)cs;
    if (s && --s->refs <= 0) set_free(s);
}

void srs_cache_drop(void) {
    for (size_t i = 0; i < g_cache_n; i++) srs_release(g_cache[i]);
    g_cache_n = 0;
}

int srs_open(const char *path, const struct srs_set **out, struct err *e) {
    struct stat st;
    if (stat(path, &st) != 0) return errf(e, path, "не открылся (%s)", strerror(errno));
    for (size_t i = 0; i < g_cache_n; i++) {
        struct srs_set *c = g_cache[i];
        if (strcmp(c->path, path) != 0) continue;
        if (c->dev == st.st_dev && c->ino == st.st_ino && c->size == st.st_size &&
            c->mtime.tv_sec == st.st_mtim.tv_sec && c->mtime.tv_nsec == st.st_mtim.tv_nsec) {
            c->refs++;
            *out = c;
            return 0;
        }
        g_cache[i] = g_cache[--g_cache_n];
        srs_release(c);
        break;
    }
    struct srs_set *s = prescan(path, e);
    if (!s) return -1;
    if (g_cache_n == SRS_CACHE) {
        srs_release(g_cache[0]);
        memmove(g_cache, g_cache + 1, (SRS_CACHE - 1) * sizeof(g_cache[0]));
        g_cache_n--;
    }
    s->refs = 2;                /* кэш и вызывающий */
    g_cache[g_cache_n++] = s;
    *out = s;
    return 0;
}

size_t srs_clause_n(const struct srs_set *s) { return s->cl_n; }
const struct srs_clause *srs_clause(const struct srs_set *s, size_t i) {
    return i < s->cl_n ? &s->cl[i] : NULL;
}
const char *srs_path(const struct srs_set *s) { return s->path; }
const char *srs_skipped(const struct srs_set *s) { return s->skipped[0] ? s->skipped : NULL; }
int srs_any_kind(const struct srs_set *s, unsigned kind) {
    for (size_t i = 0; i < s->cl_n; i++) if (s->cl[i].kind == kind) return 1;
    return 0;
}
int srs_any_flag(const struct srs_set *s, unsigned flag) {
    for (size_t i = 0; i < s->cl_n; i++) if (s->cl[i].flags & flag) return 1;
    return 0;
}

int srs_sniff(const char *path) {
    int fd = open(path, O_RDONLY | O_CLOEXEC);
    if (fd < 0) return 0;
    char b[3];
    ssize_t k = read(fd, b, 3);
    close(fd);
    return k == 3 && !memcmp(b, "SRS", 3);
}

/* ---- второй проход ------------------------------------------------------------------------ */

struct walk {
    struct rd *r;
    const struct srs_set *s;
    unsigned want;
    const uint8_t *sel;
    srs_cb cb;
    void *ctx;
    int stop;                   /* код прерывания от cb */
};

static int sel_on(const struct walk *w, uint32_t target) {
    if (target == OCC_NONE) return 0;
    uint32_t c = target & ~OCC_EXCL;
    return !w->sel || (w->sel[c >> 3] & (1u << (c & 7)));
}

/* ---- succinct-дерево доменов ---------------------------------------------------------
 *
 * Хранится LOUDS: `labels` — метки рёбер в порядке обхода в ширину, `label_bitmap` — по
 * нулю на каждое ребро и единице на конец списка детей узла, `leaves` — «в этом узле
 * кончается ключ».
 *
 * ЧТО НУЖНО ДЛЯ ОБХОДА. Узел с номером k начинается в битовой карте сразу за (k-1)-й единицей
 * (select1). Таблицы rank1 не требуется: число нулей до начала списка детей выводится из номера
 * узла, а при последовательном проходе по детям растёт на единицу за ребро.
 *
 * ПОЗИЦИИ ЕДИНИЦ — ВЫБОРКОЙ, А НЕ ВСЕ. Полный массив позиций стоил 4 байта на узел, то есть
 * вчетверо больше самих меток: на наборе в 200 тысяч имён это 7 МБ временной памяти у
 * резолвера поверх его собственного индекса. Хранится позиция каждой 64-й единицы, а до
 * нужной досчитывается по словам карты (popcount): единица — это конец списка детей, их
 * примерно половина битов, и 64 единицы — это два-три слова. */
#define SAMPLE 64
struct succinct {
    uint64_t *leaves;
    size_t nleaves;
    uint64_t *bitmap;
    size_t nbitmap;
    unsigned char *labels;
    size_t nlabels;
    uint32_t *samp;              /* samp[k] — позиция единицы номер k*SAMPLE */
    size_t nones;
};

/* Позиция единицы номер j (с нуля). */
static size_t select1(const struct succinct *s, size_t j) {
    size_t p = s->samp[j / SAMPLE];
    size_t rem = j % SAMPLE;
    if (!rem) return p;
    size_t at = p + 1;
    size_t w = at >> 6;
    uint64_t word = w < s->nbitmap ? s->bitmap[w] & (~0ULL << (at & 63)) : 0;
    for (;;) {
        size_t c = (size_t)__builtin_popcountll(word);
        if (c >= rem) {
            while (--rem) word &= word - 1;
            return (w << 6) + (size_t)__builtin_ctzll(word);
        }
        rem -= c;
        if (++w >= s->nbitmap) return (size_t)-1;
        word = s->bitmap[w];
    }
}

static int bit_at(const uint64_t *w, size_t nwords, size_t i) {
    if ((i >> 6) >= nwords) return 0;   /* leaves короче карты — добиваем нулями, как sing-box */
    return (int)((w[i >> 6] >> (i & 63)) & 1);
}

static uint64_t *read_u64_array(struct rd *r, size_t *out_n) {
    uint64_t n = rd_uvarint(r);
    if (r->err || n > 1000000u) { r->err = 1; return NULL; }
    *out_n = (size_t)n;
    uint64_t *a = calloc(n ? (size_t)n : 1, sizeof(uint64_t));
    if (!a) { r->err = 1; return NULL; }
    for (size_t i = 0; i < (size_t)n; i++) a[i] = rd_u64be(r);
    if (r->err) { free(a); return NULL; }
    return a;
}

/* Ключ дерева → элемент. Ключ лежит обращённым и с терминатором в конце; терминатор он же
 * вид. Разворот обратно — по рунам (см. шапку, «две ловушки»). */
static int emit_key(struct walk *w, uint32_t target, const unsigned char *key, size_t n) {
    if (n == 0) return 0;
    unsigned term = key[n - 1];
    size_t body_n = n - 1;
    char buf[MAX_KEY + 1];
    enum srs_dom dom;
    if (term == LBL_ROOT) dom = SRS_DOM_SUFFIX;
    else if (term == LBL_PREFIX) dom = SRS_DOM_WILDCARD;
    else { dom = SRS_DOM_EXACT; body_n = n; }
    if (body_n == 0 || body_n > MAX_KEY) return 0;
    /* Разворот по РУНАМ, как его делает sing-box при записи (reverseDomain: руны в обратном
     * порядке, байты каждой — в прямом). Ключ идёт вперёд, от руны к руне, и каждая руна
     * ложится с конца буфера. Побайтовый разворот давал верное имя только на ASCII: у
     * «пример.рф» байты каждой буквы выходили задом наперёд. Байт, который не начинает
     * последовательность UTF-8 (sing-box таких не пишет), считается руной из одного байта. */
    for (size_t i = 0; i < body_n; ) {
        unsigned char b = key[i];
        size_t w = b < 0x80 ? 1 : (b >> 5) == 6 ? 2 : (b >> 4) == 14 ? 3 : (b >> 3) == 30 ? 4 : 1;
        if (i + w > body_n) w = 1;
        for (size_t k = 1; k < w; k++)
            if ((key[i + k] & 0xC0) != 0x80) { w = 1; break; }
        memcpy(buf + body_n - i - w, key + i, w);
        i += w;
    }
    buf[body_n] = '\0';
    struct srs_elem el;
    memset(&el, 0, sizeof(el));
    el.kind = SRS_EL_DOMAIN;
    el.excl = (target & OCC_EXCL) != 0;
    el.clause = target & ~OCC_EXCL;
    el.dom = dom;
    el.str = buf;
    el.len = body_n;
    int rc = w->cb(w->ctx, &el);
    if (rc) w->stop = rc;
    return rc;
}

/* Обход дерева с явным стеком: глубину задаёт СОДЕРЖИМОЕ ФАЙЛА, и рекурсия ею бы управляла.
 *
 * ПОЧЕМУ МЕТКА ЛЕЖИТ В ЗАПИСИ СТЕКА, А НЕ ПИШЕТСЯ В БУФЕР СРАЗУ. Буфер ключа один на весь
 * обход, и все дети одного узла делят В НЁМ ОДИН И ТОТ ЖЕ индекс. Записав метки всех детей
 * при укладке на стек, мы бы оставили там метку последнего — и все ветки, кроме одной, дали
 * бы неверные имена. Поэтому метка едет вместе с узлом и попадает в буфер в момент СНЯТИЯ:
 * между укладкой узла и его снятием снимаются только узлы из поддеревьев старших братьев, а
 * они пишут в индексы правее. */
struct swalk {
    uint32_t node;
    uint32_t bm;
    uint16_t plen;
    unsigned char label;
};

static int succinct_walk(struct walk *w, uint32_t target, const struct succinct *s) {
    size_t nbits = s->nbitmap * 64;
    struct swalk *stack = malloc(MAX_DEPTH * sizeof(*stack));
    unsigned char key[MAX_KEY];
    if (!stack) return -1;
    int sp = 0;
    stack[sp].node = 0; stack[sp].bm = 0; stack[sp].plen = 0; stack[sp].label = 0;
    sp++;
    int rc = 0;
    while (sp > 0 && !rc) {
        struct swalk e = stack[--sp];
        if (e.plen > 0) key[e.plen - 1] = e.label;
        if (bit_at(s->leaves, s->nleaves, e.node) && emit_key(w, target, key, e.plen)) break;
        size_t zeros = (size_t)e.bm - (size_t)e.node;
        for (size_t i = e.bm; i < nbits && bit_at(s->bitmap, s->nbitmap, i) == 0; i++, zeros++) {
            if (zeros >= s->nlabels) { rc = -1; break; }        /* карта врёт про метки */
            uint32_t child = (uint32_t)zeros + 1;
            if ((size_t)child > s->nones) { rc = -1; break; }   /* нет позиции для узла */
            if (sp >= MAX_DEPTH || e.plen >= MAX_KEY) { rc = -1; break; }
            size_t pos = select1(s, child - 1);
            if (pos == (size_t)-1) { rc = -1; break; }
            stack[sp].node  = child;
            stack[sp].bm    = (uint32_t)(pos + 1);
            stack[sp].plen  = (uint16_t)(e.plen + 1);
            stack[sp].label = s->labels[zeros];
            sp++;
        }
    }
    free(stack);
    return rc;
}

static int walk_domain_matcher(struct walk *w, uint32_t target) {
    struct rd *r = w->r;
    if (!(w->want & SRS_EL_DOMAIN) || !sel_on(w, target)) return scan_domain_matcher(r, NULL);
    (void)rd_u8(r);
    struct succinct s;
    memset(&s, 0, sizeof(s));
    s.leaves = read_u64_array(r, &s.nleaves);
    s.bitmap = read_u64_array(r, &s.nbitmap);
    uint64_t nlab = rd_uvarint(r);
    int rc = -1;
    if (!r->err && nlab <= 100000000u && s.leaves && s.bitmap) {
        s.labels = malloc(nlab ? (size_t)nlab : 1);
        if (s.labels && rd_move(r, s.labels, nlab) == 0) {
            s.nlabels = (size_t)nlab;
            size_t total = 0;
            for (size_t i = 0; i < s.nbitmap; i++) total += (size_t)__builtin_popcountll(s.bitmap[i]);
            s.samp = malloc((total / SAMPLE + 1) * sizeof(uint32_t));
            if (s.samp) {
                for (size_t i = 0; i < s.nbitmap; i++) {
                    uint64_t word = s.bitmap[i];
                    while (word) {
                        if (s.nones % SAMPLE == 0)
                            s.samp[s.nones / SAMPLE] = (uint32_t)((i << 6) + (size_t)__builtin_ctzll(word));
                        s.nones++;
                        word &= word - 1;
                    }
                }
                rc = succinct_walk(w, target, &s);
            }
        }
    }
    free(s.samp); free(s.labels); free(s.leaves); free(s.bitmap);
    if (rc < 0 && !w->stop) r->err = 1;
    return rc < 0 || w->stop ? -1 : 0;
}

static int walk_strings(struct walk *w, uint32_t target, enum srs_dom dom) {
    struct rd *r = w->r;
    if (!(w->want & SRS_EL_DOMAIN) || !sel_on(w, target)) return scan_strings(r, NULL);
    uint64_t n = rd_uvarint(r);
    if (r->err || n > 10000000u) { r->err = 1; return -1; }
    char buf[MAX_STR + 1];
    for (uint64_t i = 0; i < n; i++) {
        uint64_t l = rd_uvarint(r);
        if (r->err || l > MAX_STR) { r->err = 1; return -1; }
        const unsigned char *q = rd_take(r, (size_t)l);
        if (!q) return -1;
        memcpy(buf, q, (size_t)l);
        buf[l] = '\0';
        struct srs_elem el;
        memset(&el, 0, sizeof(el));
        el.kind = SRS_EL_DOMAIN;
        el.excl = (target & OCC_EXCL) != 0;
        el.clause = target & ~OCC_EXCL;
        el.dom = dom;
        el.str = buf;
        el.len = (size_t)l;
        int rc = w->cb(w->ctx, &el);
        if (rc) { w->stop = rc; return -1; }
    }
    return 0;
}

struct pfx_emit { struct walk *w; uint32_t target; int family; };
static int pfx_emit_cb(void *ctx, struct u128 net, int plen) {
    struct pfx_emit *p = ctx;
    struct srs_elem el;
    memset(&el, 0, sizeof(el));
    el.kind = SRS_EL_CIDR;
    el.excl = (p->target & OCC_EXCL) != 0;
    el.clause = p->target & ~OCC_EXCL;
    el.family = p->family;
    u128_to(net, el.addr, p->family == 4 ? 4 : 16);
    el.plen = plen;
    return p->w->cb(p->w->ctx, &el);
}

static int walk_ipset(struct walk *w, uint32_t target) {
    struct rd *r = w->r;
    if (!(w->want & SRS_EL_CIDR) || !sel_on(w, target)) return scan_ipset(r, NULL, NULL, NULL);
    unsigned ver = rd_u8(r);
    if (ver != 1) { r->err = 1; return -1; }
    uint64_t n = rd_u64be(r);
    if (r->err || n > 10000000u) { r->err = 1; return -1; }
    for (uint64_t k = 0; k < n; k++) {
        uint64_t la = rd_uvarint(r);
        if (r->err || (la != 4 && la != 16)) { r->err = 1; return -1; }
        unsigned char a[16], b[16];
        const unsigned char *q = rd_take(r, (size_t)la);
        if (!q) return -1;
        memcpy(a, q, (size_t)la);
        uint64_t lb = rd_uvarint(r);
        if (r->err || lb != la) { r->err = 1; return -1; }
        q = rd_take(r, (size_t)lb);
        if (!q) return -1;
        memcpy(b, q, (size_t)lb);
        struct u128 lo = u128_from(a, (size_t)la), hi = u128_from(b, (size_t)la);
        if (u128_lt(hi, lo)) { r->err = 1; return -1; }
        struct pfx_emit p = { w, target, la == 4 ? 4 : 6 };
        int stop = 0;
        if (range_pfx(lo, hi, la == 4 ? 32 : 128, pfx_emit_cb, &p, &stop) == (size_t)-1) {
            w->stop = stop;
            return -1;
        }
    }
    return 0;
}

static int walk_default(struct walk *w, uint32_t occ) {
    struct rd *r = w->r;
    struct occ_map m = { OCC_NONE, OCC_NONE };
    if (occ < w->s->occ_n) m = w->s->occ[occ];
    for (;;) {
        unsigned t = rd_u8(r);
        if (r->err) return -1;
        if (t == IT_FINAL) { (void)rd_u8(r); return r->err ? -1 : 0; }
        int rc = 0;
        switch (t) {
        case IT_DOMAIN:          rc = walk_domain_matcher(w, m.dom); break;
        case IT_DOMAIN_KEYWORD:  rc = walk_strings(w, m.dom, SRS_DOM_KEYWORD); break;
        case IT_DOMAIN_REGEX:    rc = walk_strings(w, m.dom, SRS_DOM_REGEX); break;
        case IT_IP_CIDR:         rc = walk_ipset(w, m.cidr); break;
        case IT_SOURCE_IP_CIDR:  rc = scan_ipset(r, NULL, NULL, NULL); break;
        case IT_NETWORK: case IT_PORT_RANGE: case IT_PACKAGE_NAME: case IT_SOURCE_PORT_RANGE:
        case IT_PROCESS_NAME: case IT_PROCESS_PATH: case IT_PROCESS_PATH_REGEX:
        case IT_PACKAGE_NAME_REGEX: case IT_WIFI_SSID: case IT_WIFI_BSSID: case IT_NETWORK_TYPE:
            rc = scan_strings(r, NULL);
            break;
        case IT_PORT: case IT_SOURCE_PORT: case IT_QUERY_TYPE:
            rc = skip_u16_list(r);
            break;
        case IT_ADGUARD_DOMAIN:      rc = skip_adguard(r); break;
        case IT_NET_EXPENSIVE: case IT_NET_CONSTRAINED: break;
        case IT_IFACE_ADDR:          rc = skip_iface_addr(r); break;
        case IT_DEFAULT_IFACE_ADDR:  rc = skip_default_iface_addr(r); break;
        default:
            r->err = 2;
            return -1;
        }
        if (rc) return -1;
    }
}

static int walk_rule(struct walk *w, int depth, uint32_t *occ) {
    struct rd *r = w->r;
    if (depth > 100) { r->err = 1; return -1; }
    unsigned kind = rd_u8(r);
    if (r->err) return -1;
    if (kind == 0) return walk_default(w, (*occ)++);
    if (kind == 1) {
        (void)rd_u8(r);
        uint64_t n = rd_uvarint(r);
        if (r->err || n > 100000u) { r->err = 1; return -1; }
        for (uint64_t i = 0; i < n; i++)
            if (walk_rule(w, depth + 1, occ) != 0) return -1;
        (void)rd_u8(r);
        return r->err ? -1 : 0;
    }
    r->err = 3;
    return -1;
}

int srs_walk(const struct srs_set *s, unsigned want, const uint8_t *sel,
             srs_cb cb, void *ctx, struct err *e) {
    struct srs_file f;
    struct stat st;
    if (file_open(s->path, &f, &st, e) != 0) return -1;
    /* Файл сменился между проходами (обновление списков переименовало новый поверх) — номера
     * клауз первого прохода к нему не относятся, и отдать элементы по ним значило бы разложить
     * их не туда. Отказ; следующий вызов srs_open разберёт новый файл. */
    if (st.st_ino != s->ino || st.st_size != s->size || st.st_mtim.tv_sec != s->mtime.tv_sec ||
        st.st_mtim.tv_nsec != s->mtime.tv_nsec) {
        file_close(&f);
        return errf(e, s->path, "файл изменился во время чтения — повторите");
    }
    struct rd *r = malloc(sizeof(*r));
    if (!r) { file_close(&f); return errf(e, s->path, "нет памяти"); }
    rd_init(r, &f);
    struct walk w = { r, s, want, sel, cb, ctx, 0 };
    uint64_t nrules = rd_uvarint(r);
    int bad = r->err || nrules > 100000u;
    uint32_t occ = 0;
    for (uint64_t i = 0; !bad && i < nrules; i++)
        if (walk_rule(&w, 0, &occ) != 0) bad = 1;
    int rc;
    if (w.stop) rc = w.stop;
    else if (bad) rc = errf(e, s->path, "%s", rd_errtext(r->err));
    else if (occ != s->occ_n) rc = errf(e, s->path, "файл изменился во время чтения — повторите");
    else rc = rd_finish(r, s->path, e);
    free(r);
    file_close(&f);
    return rc;
}

/* ---- сужение: операции для потребителей -------------------------------------------------- */

static void pset_of(const struct l4match *m, struct pset *p, unsigned *pm) {
    if (l4match_empty(m)) { *pm = PM_ALL; p->all = 1; p->n = 0; return; }
    *pm = m->proto == CH_PROTO_TCP ? PM_TCP : m->proto == CH_PROTO_UDP ? PM_UDP :
          (m->ports_n ? (PM_TCP | PM_UDP) : PM_ALL);
    pset_from(p, m->ports, m->ports_n);
}

int l4_same_set(const struct l4match *a, const struct l4match *b) {
    struct pset pa, pb;
    unsigned ma, mb;
    pset_of(a, &pa, &ma);
    pset_of(b, &pb, &mb);
    if (ma != mb || pa.all != pb.all || pa.n != pb.n) return 0;
    for (size_t i = 0; i < pa.n; i++)
        if (pa.r[i].lo != pb.r[i].lo || pa.r[i].hi != pb.r[i].hi) return 0;
    return 1;
}

int l4_intersect(const struct l4match *a, const struct l4match *b, struct l4match *out) {
    if (l4match_empty(b)) { *out = *a; return 1; }
    if (l4match_empty(a)) { *out = *b; return 1; }
    struct pset pa, pb;
    unsigned ma, mb;
    pset_of(a, &pa, &ma);
    pset_of(b, &pb, &mb);
    pset_and(&pa, &pb);
    struct l4match o;
    int r = l4_make(ma & mb, &pa, &o);
    if (r <= 0) return 0;               /* пусто или не выражается — не пересекаются */
    if (l4_same_set(&o, a)) o = *a;
    else if (l4_same_set(&o, b)) o = *b;
    *out = o;
    return 1;
}

size_t l4_boxes(const struct l4match *m, struct l4box *out) {
    if (l4match_empty(m)) {
        out[0].plo = 0; out[0].phi = 255; out[0].lo = 0; out[0].hi = 65535;
        return 1;
    }
    unsigned char protos[2];
    size_t np = 0;
    if (m->proto != CH_PROTO_UDP) protos[np++] = 6;
    if (m->proto != CH_PROTO_TCP) protos[np++] = 17;
    size_t n = 0;
    for (size_t p = 0; p < np; p++) {
        if (!m->ports_n) {
            out[n].plo = out[n].phi = protos[p];
            out[n].lo = 0; out[n].hi = 65535;
            n++;
            continue;
        }
        for (size_t i = 0; i < m->ports_n; i++) {
            out[n].plo = out[n].phi = protos[p];
            out[n].lo = m->ports[i].lo;
            out[n].hi = m->ports[i].hi;
            n++;
        }
    }
    return n;
}

size_t l4_union_boxes(const struct l4match *const *ms, size_t n, struct l4box *out) {
    /* «Без сужения» накрывает всё — один ящик. Иначе у каждого из двух протоколов свои порты,
     * слитые в непересекающиеся диапазоны: ящики tcp и udp не пересекаются по протоколу. */
    struct pset t = { .all = 0, .n = 0 }, u = { .all = 0, .n = 0 };
    for (size_t i = 0; i < n; i++) {
        const struct l4match *m = ms[i];
        if (l4match_empty(m)) return l4_boxes(m, out);
        struct pset p;
        pset_from(&p, m->ports, m->ports_n);
        if (p.all) { p.all = 0; p.r[0].lo = 0; p.r[0].hi = 65535; p.n = 1; }
        for (int k = 0; k < 2; k++) {
            if (k == 0 && m->proto == CH_PROTO_UDP) continue;
            if (k == 1 && m->proto == CH_PROTO_TCP) continue;
            struct pset *d = k == 0 ? &t : &u;
            for (size_t j = 0; j < p.n && d->n < sizeof(d->r) / sizeof(d->r[0]); j++)
                d->r[d->n++] = p.r[j];
            pset_norm(d);
        }
    }
    size_t o = 0;
    for (size_t j = 0; j < t.n && o < L4BOX_MAX; j++) {
        out[o].plo = out[o].phi = 6; out[o].lo = t.r[j].lo; out[o].hi = t.r[j].hi; o++;
    }
    for (size_t j = 0; j < u.n && o < L4BOX_MAX; j++) {
        out[o].plo = out[o].phi = 17; out[o].lo = u.r[j].lo; out[o].hi = u.r[j].hi; o++;
    }
    return o;
}

void l4_box_text(const struct l4box *b, char *dst, size_t n) {
    char p[16], q[16];
    if (b->plo == b->phi) snprintf(p, sizeof(p), "%u", b->plo);
    else snprintf(p, sizeof(p), "%u-%u", b->plo, b->phi);
    if (b->lo == b->hi) snprintf(q, sizeof(q), "%u", b->lo);
    else snprintf(q, sizeof(q), "%u-%u", b->lo, b->hi);
    snprintf(dst, n, "%s . %s", p, q);
}

void l4_to_text(const struct l4match *m, char *dst, size_t n) {
    if (!n) return;
    if (l4match_empty(m)) { snprintf(dst, n, "-"); return; }
    size_t k = 0;
    int w = snprintf(dst, n, "%s", m->proto == CH_PROTO_TCP ? "tcp" :
                                   m->proto == CH_PROTO_UDP ? "udp" : "any");
    if (w > 0) k = (size_t)w;
    for (size_t i = 0; i < m->ports_n && k < n; i++) {
        if (m->ports[i].lo == m->ports[i].hi)
            w = snprintf(dst + k, n - k, "%c%u", i ? '+' : '/', m->ports[i].lo);
        else
            w = snprintf(dst + k, n - k, "%c%u-%u", i ? '+' : '/', m->ports[i].lo, m->ports[i].hi);
        if (w > 0) k += (size_t)w;
    }
}

int l4_from_text(const char *s, size_t len, struct l4match *m) {
    memset(m, 0, sizeof(*m));
    if (len == 1 && s[0] == '-') return 0;
    size_t i = 0;
    if (len >= 3 && !strncmp(s, "tcp", 3)) m->proto = CH_PROTO_TCP;
    else if (len >= 3 && !strncmp(s, "udp", 3)) m->proto = CH_PROTO_UDP;
    else if (len >= 3 && !strncmp(s, "any", 3)) m->proto = CH_PROTO_ANY;
    else return -1;
    i = 3;
    while (i < len) {
        if (s[i] != '/' && s[i] != '+') return -1;
        i++;
        unsigned long lo = 0, hi;
        size_t st = i;
        while (i < len && s[i] >= '0' && s[i] <= '9') lo = lo * 10 + (unsigned long)(s[i++] - '0');
        if (i == st || lo > 65535) return -1;
        hi = lo;
        if (i < len && s[i] == '-') {
            i++;
            st = i;
            hi = 0;
            while (i < len && s[i] >= '0' && s[i] <= '9') hi = hi * 10 + (unsigned long)(s[i++] - '0');
            if (i == st || hi > 65535 || hi < lo) return -1;
        }
        if (m->ports_n >= MAX_PORTS) return -1;
        m->ports[m->ports_n].lo = (unsigned short)lo;
        m->ports[m->ports_n].hi = (unsigned short)hi;
        m->ports_n++;
    }
    return 0;
}
