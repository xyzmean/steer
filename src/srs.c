/* Скомпилированные наборы правил sing-box (`.srs`) — чтение в наш синтаксис списка.
 *
 * ЗАЧЕМ ЭТО В ДВИЖКЕ. Списки доменов и подсетей, которыми пользуется половина роутеров с
 * обходом, публикуются itdoginfo/allow-domains, и в релизе там НЕТ ни одного текстового
 * файла: 25 `.srs` (sing-box), 25+11 `.mrs` (mihomo), один `geosite.dat` (Xray). Плоские
 * `.lst` лежат только в дереве ветки. Значит либо мы берём не то, что берут все, либо учимся
 * читать `.srs`.
 *
 * ПОЧЕМУ ЧИТАТЕЛЬ, А НЕ ВТОРОЙ СОПОСТАВИТЕЛЬ. В формате четыре вида правила на домен, и у
 * каждого в dnsd УЖЕ есть точное соответствие (см. dnsd.c, enum rule_type и разбор строки
 * списка):
 *
 *     .srs                                        наш список          тип dnsd
 *     ключ без метки          (domain)            =x.com              RULE_EXACT
 *     терминатор 0x0A '\n'    (domain_suffix)     x.com               RULE_NAMESPACE
 *     терминатор 0x0D '\r'    (domain_suffix .x)  *.x.com             RULE_WILDCARD
 *     domain_keyword                              *слово*             RULE_WILDCARD
 *     domain_regex                                re:...              RULE_REGEX
 *
 * `RULE_NAMESPACE` описан в dnsd.c дословно как «шаблон — это само имя или его суффикс,
 * начинающийся на границе точки», то есть буквально rootLabel sing-box. Поэтому здесь не
 * нужен ни свой индекс, ни своё сопоставление: достаточно перечислить ключи и напечатать их
 * тем синтаксисом, который dnsd читает с первого дня. Побочная выгода — напечатанное
 * читается глазами, и человек видит, что именно приехало из двоичного файла.
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
 * ДВЕ ЛОВУШКИ, НА КОТОРЫХ ЛЕГКО СЕСТЬ.
 *
 * Первая: слова битовых карт записаны big-endian, а биты ВНУТРИ слова читаются
 * little-endian (`слово[i>>6] >> (i&63)`). Перепутать — получить дерево, которое
 * разбирается без ошибок и даёт мусор.
 *
 * Вторая: ключи хранятся ОБРАЩЁННЫМИ («youtube.com» → «moc.ebutuoy»), чтобы сопоставление
 * по суффиксу стало сопоставлением по префиксу. Разворот в sing-box идёт по РУНАМ UTF-8, а
 * не по байтам, — но метки дерева байтовые, поэтому обратно мы разворачиваем байты и
 * получаем исходную строку ровно потому, что двойной разворот байтов возвращает исходную
 * последовательность. Проверять на не-ASCII именах обязательно (стенд srsmatch это делает).
 *
 * ВЕРСИЯ 1 КОДИРУЕТ СУФФИКС ИНАЧЕ. До версии 2 запись `domain_suffix: ["x.com"]` писалась
 * ДВУМЯ ключами — «x.com» и «\r.x.com», — а с версии 2 одним «\nx.com». Читателю про это
 * знать не нужно (он печатает то, что лежит), но следствие важно: на файле версии 1 одна
 * запись даёт две строки списка, и они не противоречат друг другу — `=x.com` плюс `*.x.com`
 * это ровно то же множество имён, что `x.com`.
 *
 * ПРОТОКОЛ И ПОРТЫ — ТРЕТИЙ ВЫХОД, а не отказ. `discord.srs` — единственный файл этого
 * издателя без доменов вовсе: `network: udp` плюс `ip_cidr 104.16.0.0/12` плюс
 * `port_range 50000:65535, 19000:20000`. Взять его подсети и отбросить порты нельзя:
 * 104.16.0.0/12 это Cloudflare, и весь TCP к нему уехал бы в туннель молча.
 *
 * До схемы 2 у канала не было ни протокола, ни портов, и такой набор отвергался целиком с
 * кодом 2 — «понят, но не выразим». Теперь измерение есть (`proto` и `ports` в match, см.
 * spec.h), поэтому сужение НЕ выбрасывается и не остаётся догадкой управляющего слоя: оно
 * печатается третьим потоком (`--meta-out`) в виде `proto=` и `ports=`, готовом к переносу
 * в канал.
 *
 * ПОЧЕМУ ОТДЕЛЬНЫМ ПОТОКОМ, а не строкой в списке. Список читают dnsd и компилятор набора
 * правил, и обоим `proto=udp` — мусор: первый сочтёт это доменным правилом, второй
 * пропустит как не-адрес. Сужение принадлежит КАНАЛУ, а не списку: один и тот же список
 * подсетей может быть подключён к каналу с портами и к каналу без них.
 *
 * ЧЕГО МЫ ВЫРАЗИТЬ ПО-ПРЕЖНЕМУ НЕ МОЖЕМ (и отвергаем целиком, кодом 2): правило с
 * `invert` (список исключений у нас не выражается), `source_ip_cidr` (это `from` канала, а
 * не назначение), логические правила «и»/«или», и всё, что про процессы, пакеты и Wi-Fi.
 * Половина набора — это не набор, поэтому такие файлы не «читаются как можем».
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

#include "puff.h"
#include "srs.h"

#define SRS_MAGIC       "SRS"
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

/* ---- чтение по буферу ---------------------------------------------------------------
 * Один флаг ошибки на весь разбор вместо проверки на каждом вызове: испорченный файл
 * должен приводить к отказу, а не к разбору половины. Все читатели на выставленном флаге
 * возвращают нули и ничего не двигают, поэтому проверить его достаточно в конце. */
struct rd {
    const unsigned char *p, *end;
    int err;
};

static const unsigned char *rd_take(struct rd *r, size_t n) {
    if (r->err || (size_t)(r->end - r->p) < n) { r->err = 1; return NULL; }
    const unsigned char *q = r->p;
    r->p += n;
    return q;
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

/* ---- succinct-дерево доменов ---------------------------------------------------------
 *
 * Хранится LOUDS: `labels` — метки рёбер в порядке обхода в ширину, `label_bitmap` — по
 * нулю на каждое ребро и единице на конец списка детей узла, `leaves` — «в этом узле
 * кончается ключ».
 *
 * ЧТО НУЖНО ДЛЯ ОБХОДА И ЧЕГО НЕ НУЖНО. Узел с номером k начинается в битовой карте сразу
 * за (k-1)-й единицей, поэтому достаточно ОДНОГО массива — позиций единиц (select1).
 * Таблицы rank1 по всей карте, как в разборе на Python, не требуется: число нулей до
 * начала списка детей выводится из номера узла (перед позицией ones[k-1]+1 стоит ровно
 * k-1 единиц), а дальше при последовательном проходе по детям оно растёт на единицу за
 * ребро. Это разница между 40 КБ и 120 КБ временной памяти на списке из 1200 доменов —
 * на роутере с шестью мегабайтами overlay такие числа считать стоит.
 */
struct succinct {
    const uint64_t *leaves;
    size_t nleaves;              /* слов, не бит */
    const uint64_t *bitmap;
    size_t nbitmap;
    const unsigned char *labels;
    size_t nlabels;
    uint32_t *ones;              /* позиции единиц: ones[k] — конец списка детей узла k */
    size_t nones;
};

static int bit_at(const uint64_t *w, size_t nwords, size_t i) {
    if ((i >> 6) >= nwords) return 0;   /* leaves короче карты — добиваем нулями, как sing-box */
    return (int)((w[i >> 6] >> (i & 63)) & 1);
}

/* Прочитать массив uint64 big-endian. Возвращает указатель на СВЕЖУЮ память или NULL. */
static uint64_t *rd_u64_array(struct rd *r, size_t *out_n) {
    uint64_t n = rd_uvarint(r);
    if (r->err) return NULL;
    /* Предел от испорченного файла: 1 млн слов это 64 Мбит карты, чего быть не может. */
    if (n > 1000000u) { r->err = 1; return NULL; }
    *out_n = (size_t)n;
    if (n == 0) return calloc(1, sizeof(uint64_t));   /* не NULL, чтобы отличать от ошибки */
    uint64_t *a = calloc((size_t)n, sizeof(uint64_t));
    if (!a) { r->err = 1; return NULL; }
    for (size_t i = 0; i < (size_t)n; i++) a[i] = rd_u64be(r);
    if (r->err) { free(a); return NULL; }
    return a;
}

/* Напечатать один ключ дерева нашим синтаксисом.
 *
 * Ключ лежит обращённым и с терминатором в конце; терминатор он же тип правила. Разворот
 * обратно — побайтовый: двойной разворот байтов возвращает исходную последовательность
 * независимо от того, что разворот при записи шёл по рунам. */
static void emit_key(FILE *out, const unsigned char *key, size_t n) {
    if (!out || n == 0) return;
    unsigned term = key[n - 1];
    size_t body_n = n - 1;
    char buf[MAX_KEY + 1];

    if (term != LBL_ROOT && term != LBL_PREFIX) {
        /* Метки нет вовсе — это точный домен, и тогда телом является весь ключ. */
        term = 0;
        body_n = n;
    }
    if (body_n == 0 || body_n > MAX_KEY) return;
    for (size_t i = 0; i < body_n; i++) buf[i] = (char)key[body_n - 1 - i];
    buf[body_n] = '\0';

    switch (term) {
        case LBL_ROOT:
            /* «домен и его поддомены» — обычная строка нашего списка */
            fprintf(out, "%s\n", buf);
            break;
        case LBL_PREFIX:
            /* буквальный суффикс строки: `.ua` ловит `*.ua`, но не сам `ua` */
            fprintf(out, "*%s\n", buf);
            break;
        default:
            /* точное имя: только оно само, без поддоменов */
            fprintf(out, "=%s\n", buf);
            break;
    }
}

/* Обход дерева с явным стеком: рекурсия здесь опасна не глубиной (её ограничивает длина
 * ключа), а тем, что глубину задаёт СОДЕРЖИМОЕ ФАЙЛА.
 *
 * ПОЧЕМУ МЕТКА ЛЕЖИТ В ЗАПИСИ СТЕКА, А НЕ ПИШЕТСЯ В БУФЕР СРАЗУ. Буфер ключа один на весь
 * обход, и все дети одного узла делят В НЁМ ОДИН И ТОТ ЖЕ индекс. Записав метки всех детей
 * при укладке на стек, мы бы оставили там метку последнего — и все ветки, кроме одной, дали
 * бы неверные имена, разобравшись при этом без единой ошибки. Поэтому метка едет вместе с
 * узлом и попадает в буфер в момент СНЯТИЯ.
 *
 * Что при этом гарантирует целость префикса: между укладкой узла и его снятием со стека
 * снимаются только узлы из поддеревьев его старших братьев, а они лежат глубже и пишут в
 * индексы правее. Значит к моменту снятия узла глубины d байты 0..d-2 — это ровно путь до
 * его родителя.
 *
 * Порядок перечисления ключей не важен: на выходе список, а не дерево. */
struct swalk {
    uint32_t node;
    uint32_t bm;
    uint16_t plen;
    unsigned char label;
};

static int succinct_walk(const struct succinct *s, FILE *out) {
    size_t nbits = s->nbitmap * 64;
    struct swalk stack[MAX_DEPTH];
    unsigned char key[MAX_KEY];
    int sp = 0;

    stack[sp].node = 0; stack[sp].bm = 0; stack[sp].plen = 0; stack[sp].label = 0;
    sp++;
    while (sp > 0) {
        struct swalk e = stack[--sp];
        if (e.plen > 0) key[e.plen - 1] = e.label;

        if (bit_at(s->leaves, s->nleaves, e.node)) emit_key(out, key, e.plen);

        /* Дети — нули в карте начиная с e.bm. Число нулей до этой позиции равно
         * e.bm - e.node: перед ней стоит ровно e.node единиц (позиция получена как
         * ones[e.node - 1] + 1, а для корня это 0 при 0 единиц). */
        size_t zeros = (size_t)e.bm - (size_t)e.node;
        for (size_t i = e.bm; i < nbits && bit_at(s->bitmap, s->nbitmap, i) == 0; i++, zeros++) {
            if (zeros >= s->nlabels) return -1;               /* карта врёт про метки */
            uint32_t child = (uint32_t)zeros + 1;
            if ((size_t)child > s->nones) return -1;          /* нет позиции для узла */
            if (sp >= MAX_DEPTH) return -1;                   /* ключ длиннее предела */
            if (e.plen >= MAX_KEY) return -1;
            stack[sp].node  = child;
            stack[sp].bm    = s->ones[child - 1] + 1;
            stack[sp].plen  = (uint16_t)(e.plen + 1);
            stack[sp].label = s->labels[zeros];
            sp++;
        }
    }
    return 0;
}

static int read_domain_matcher(struct rd *r, FILE *out) {
    (void)rd_u8(r);                       /* зарезервированный байт: пишется 0, читать нечего */
    struct succinct s;
    memset(&s, 0, sizeof(s));
    uint64_t *leaves = rd_u64_array(r, &s.nleaves);
    uint64_t *bitmap = rd_u64_array(r, &s.nbitmap);
    uint64_t nlab = rd_uvarint(r);
    if (r->err || nlab > 100000000u) { free(leaves); free(bitmap); r->err = 1; return -1; }
    const unsigned char *labels = rd_take(r, (size_t)nlab);
    if (!labels) { free(leaves); free(bitmap); return -1; }

    s.leaves = leaves; s.bitmap = bitmap; s.labels = labels; s.nlabels = (size_t)nlab;

    /* Позиции единиц. Их столько же, сколько узлов; массив временный и освобождается сразу. */
    size_t nbits = s.nbitmap * 64;
    s.ones = calloc(nbits ? nbits : 1, sizeof(uint32_t));
    if (!s.ones) { free(leaves); free(bitmap); r->err = 1; return -1; }
    s.nones = 0;
    for (size_t i = 0; i < nbits; i++)
        if (bit_at(s.bitmap, s.nbitmap, i)) s.ones[s.nones++] = (uint32_t)i;

    int rc = succinct_walk(&s, out);
    free(s.ones); free(leaves); free(bitmap);
    if (rc != 0) { r->err = 1; return -1; }
    return 0;
}

/* ---- подсети ------------------------------------------------------------------------
 * netipx.IPSet: uint8 версия (обязательно 1), uint64 BE число диапазонов, затем пары
 * границ ВКЛЮЧИТЕЛЬНО, каждая — uvarint длины (4 или 16) и байты адреса. Сначала все
 * диапазоны IPv4, затем все IPv6.
 *
 * Диапазон, а не префикс, — то есть обратно его надо разложить на минимальный набор
 * префиксов. Иначе набору nftables нечего скормить: он принимает `адрес/длина`. */
static void emit_v4_range(FILE *out, uint32_t lo, uint32_t hi) {
    while (lo <= hi) {
        /* Наибольший блок, который начинается в lo и не выходит за hi. */
        int len = 32;
        while (len > 0) {
            uint32_t size = 1u << (32 - (len - 1));
            uint32_t mask = size - 1;
            if ((lo & mask) != 0) break;                    /* не выровнен */
            if ((uint64_t)lo + size - 1 > (uint64_t)hi) break; /* не влезает */
            len--;
        }
        uint32_t size = (len == 0) ? 0u : (1u << (32 - len));
        fprintf(out, "%u.%u.%u.%u/%d\n",
                (lo >> 24) & 0xFF, (lo >> 16) & 0xFF, (lo >> 8) & 0xFF, lo & 0xFF, len);
        if (len == 0) break;                                /* весь диапазон адресов */
        uint64_t next = (uint64_t)lo + size;
        if (next > 0xFFFFFFFFull) break;
        lo = (uint32_t)next;
    }
}

static int read_ip_set(struct rd *r, FILE *out, int *saw_v6) {
    unsigned ver = rd_u8(r);
    if (ver != 1) { r->err = 1; return -1; }
    uint64_t n = rd_u64be(r);
    if (r->err || n > 10000000u) { r->err = 1; return -1; }
    for (uint64_t k = 0; k < n; k++) {
        uint64_t la = rd_uvarint(r);
        const unsigned char *a = rd_take(r, (size_t)la);
        uint64_t lb = rd_uvarint(r);
        const unsigned char *b = rd_take(r, (size_t)lb);
        if (!a || !b || la != lb || (la != 4 && la != 16)) { r->err = 1; return -1; }
        if (la == 16) {
            /* IPv6 в наших наборах правил не участвует (spec: только IPv4), а молча
             * выбросить его нельзя — иначе список выглядел бы прочитанным целиком. */
            *saw_v6 = 1;
            continue;
        }
        uint32_t lo = ((uint32_t)a[0] << 24) | ((uint32_t)a[1] << 16) | ((uint32_t)a[2] << 8) | a[3];
        uint32_t hi = ((uint32_t)b[0] << 24) | ((uint32_t)b[1] << 16) | ((uint32_t)b[2] << 8) | b[3];
        if (lo > hi) { r->err = 1; return -1; }
        if (out) emit_v4_range(out, lo, hi);
    }
    return 0;
}

/* ---- список строк -------------------------------------------------------------------
 * uvarint число, затем каждая как uvarint длины и байты. Печатать умеем не все — какие
 * именно, решает вызывающий; здесь только чтение. */
static int skip_string_list(struct rd *r) {
    uint64_t n = rd_uvarint(r);
    if (r->err || n > 10000000u) { r->err = 1; return -1; }
    for (uint64_t i = 0; i < n; i++) {
        uint64_t l = rd_uvarint(r);
        if (!rd_take(r, (size_t)l)) return -1;
    }
    return 0;
}

static int emit_string_list(struct rd *r, FILE *out, const char *prefix, const char *suffix) {
    uint64_t n = rd_uvarint(r);
    if (r->err || n > 10000000u) { r->err = 1; return -1; }
    for (uint64_t i = 0; i < n; i++) {
        uint64_t l = rd_uvarint(r);
        const unsigned char *q = rd_take(r, (size_t)l);
        if (!q) return -1;
        if (out) fprintf(out, "%s%.*s%s\n", prefix, (int)l, (const char *)q, suffix);
    }
    return 0;
}

/* ---- правила ------------------------------------------------------------------------ */

#define MAX_META_PORTS 32
#define META_PORT_LEN  16

struct ctx {
    FILE *dom, *pfx, *meta;
    int unsupported;        /* встретилось выразимое, но не выражаемое у нас */
    const char *why;        /* чем именно */
    int saw_v6;
    /* Сужение канала: протокол и порты назначения. Копится ЗДЕСЬ, а не печатается на месте,
     * потому что набор может нести и то и другое разными элементами, а вывести надо две
     * строки, а не четыре. */
    int have_tcp, have_udp;
    char ports[MAX_META_PORTS][META_PORT_LEN];
    size_t ports_n;
    int ports_over;         /* портов больше, чем мы берём — это отказ, а не усечение */
};

/* Добавить один порт или диапазон в нашей записи. Повторы отбрасываются: у sing-box один и
 * тот же диапазон встречается в двух элементах, а nft на дубле в множестве отвергает весь
 * набор правил. */
static void meta_port_add(struct ctx *c, const char *s) {
    if (c->ports_over) return;
    for (size_t i = 0; i < c->ports_n; i++)
        if (!strcmp(c->ports[i], s)) return;
    if (c->ports_n >= MAX_META_PORTS) { c->ports_over = 1; return; }
    snprintf(c->ports[c->ports_n], META_PORT_LEN, "%s", s);
    c->ports_n++;
}

/* `network`: строки «tcp» и «udp». Что-то третье — отказ: транспорт, которого мы не знаем,
 * нельзя ни выразить, ни отбросить (отбросив, мы расширили бы совпадение). */
static int collect_network(struct rd *r, struct ctx *c) {
    uint64_t n = rd_uvarint(r);
    if (r->err || n > 64) { r->err = 1; return -1; }
    for (uint64_t i = 0; i < n; i++) {
        uint64_t l = rd_uvarint(r);
        const unsigned char *q = rd_take(r, (size_t)l);
        if (!q) return -1;
        if (l == 3 && !memcmp(q, "tcp", 3)) c->have_tcp = 1;
        else if (l == 3 && !memcmp(q, "udp", 3)) c->have_udp = 1;
        else if (!c->unsupported) {
            c->unsupported = 1;
            c->why = "network: транспорт не tcp и не udp";
        }
    }
    return 0;
}

/* `port_range`: строки вида «50000:65535» у sing-box. Переводим в нашу запись через тире —
 * ту же, которой у нас записан диапазон адресов. Одиночное число тоже законно. */
static int collect_port_range(struct rd *r, struct ctx *c) {
    uint64_t n = rd_uvarint(r);
    if (r->err || n > 10000u) { r->err = 1; return -1; }
    for (uint64_t i = 0; i < n; i++) {
        uint64_t l = rd_uvarint(r);
        const unsigned char *q = rd_take(r, (size_t)l);
        if (!q) return -1;
        char buf[META_PORT_LEN];
        if (l >= sizeof(buf)) {
            if (!c->unsupported) { c->unsupported = 1; c->why = "port_range: запись длиннее нашей"; }
            continue;
        }
        size_t w = 0;
        for (size_t k = 0; k < (size_t)l && w + 1 < sizeof(buf); k++)
            buf[w++] = q[k] == ':' ? '-' : (char)q[k];
        buf[w] = '\0';
        /* Открытые с одной стороны диапазоны sing-box пишет как «:1000» или «1000:». У нас
         * такой записи нет, и додумывать границу нельзя: «1000-» это либо один порт, либо
         * все до 65535, и разница — весь остальной трафик. */
        if (w == 0 || buf[0] == '-' || buf[w - 1] == '-') {
            if (!c->unsupported) {
                c->unsupported = 1;
                c->why = "port_range: диапазон открыт с одной стороны, границу додумывать нельзя";
            }
            continue;
        }
        meta_port_add(c, buf);
    }
    return 0;
}

/* `port`: одиночные порты числами по два байта. */
static int collect_ports(struct rd *r, struct ctx *c) {
    uint64_t n = rd_uvarint(r);
    if (r->err || n > 10000u) { r->err = 1; return -1; }
    for (uint64_t i = 0; i < n; i++) {
        const unsigned char *q = rd_take(r, 2);
        if (!q) return -1;
        char buf[META_PORT_LEN];
        snprintf(buf, sizeof(buf), "%u", (unsigned)((q[0] << 8) | q[1]));
        meta_port_add(c, buf);
    }
    return 0;
}

static int read_rule(struct rd *r, struct ctx *c, int depth);

static int read_default_rule(struct rd *r, struct ctx *c) {
    for (;;) {
        unsigned t = rd_u8(r);
        if (r->err) return -1;
        if (t == IT_FINAL) {
            unsigned invert = rd_u8(r);
            if (invert && !c->unsupported) {
                /* Правило-исключение. Наш список не умеет «всё, кроме», и притворяться, что
                 * умеет, значит маршрутизировать ровно то, что просили не маршрутизировать. */
                c->unsupported = 1;
                c->why = "правило с invert: набор описывает исключение, а список исключений у нас нет";
            }
            return r->err ? -1 : 0;
        }
        switch (t) {
            case IT_DOMAIN:
                if (read_domain_matcher(r, c->dom) != 0) return -1;
                break;
            case IT_DOMAIN_KEYWORD:
                /* Ключевое слово выражается нашим шаблоном: `*слово*`. */
                if (emit_string_list(r, c->dom, "*", "*") != 0) return -1;
                break;
            case IT_DOMAIN_REGEX:
                if (emit_string_list(r, c->dom, "re:", "") != 0) return -1;
                break;
            case IT_IP_CIDR:
                if (read_ip_set(r, c->pfx, &c->saw_v6) != 0) return -1;
                break;
            case IT_SOURCE_IP_CIDR:
                /* Источник — это `from` канала, а не список. Молча смешать с назначением
                 * нельзя: получился бы канал, ловящий не то, что описано. */
                if (read_ip_set(r, NULL, &c->saw_v6) != 0) return -1;
                if (!c->unsupported) {
                    c->unsupported = 1;
                    c->why = "source_ip_cidr: набор описывает клиентов, а не назначение";
                }
                break;
            case IT_NETWORK:
                /* `tcp`, `udp` или оба. Больше одного значения означает «оба», и наш
                 * `both` — ровно это; третьего вида транспорта в наборах не встречается. */
                if (collect_network(r, c) != 0) return -1;
                break;
            case IT_PORT_RANGE:
                /* Форма у sing-box `50000:65535`, у нас `50000-65535`. Переводим ЗДЕСЬ,
                 * при чтении чужого файла: спека не обязана знать чужую запись. */
                if (collect_port_range(r, c) != 0) return -1;
                break;
            case IT_SOURCE_PORT_RANGE:
                /* Порт ИСТОЧНИКА — это про клиента, а не про назначение, и у канала такого
                 * измерения нет. Смешать с портом назначения нельзя: получился бы канал,
                 * ловящий не то, что описано. */
                if (skip_string_list(r) != 0) return -1;
                if (!c->unsupported) {
                    c->unsupported = 1;
                    c->why = "source_port_range: набор сужен по порту клиента, а не назначения";
                }
                break;
            case IT_PROCESS_NAME: case IT_PROCESS_PATH: case IT_PACKAGE_NAME:
            case IT_WIFI_SSID: case IT_WIFI_BSSID: case IT_PROCESS_PATH_REGEX:
            case IT_NETWORK_TYPE: case IT_PACKAGE_NAME_REGEX:
                if (skip_string_list(r) != 0) return -1;
                if (!c->unsupported) {
                    c->unsupported = 1;
                    c->why = "правило про процесс, пакет или Wi-Fi";
                }
                break;
            case IT_PORT: {
                /* Одиночные порты — то же измерение, что диапазоны, только записанные
                 * числами по два байта. В наш вид (`443`) переводятся здесь же. */
                if (collect_ports(r, c) != 0) return -1;
                break;
            }
            case IT_QUERY_TYPE: case IT_SOURCE_PORT: {
                uint64_t n = rd_uvarint(r);
                if (r->err || n > 10000000u) { r->err = 1; return -1; }
                if (!rd_take(r, (size_t)n * 2)) return -1;
                if (!c->unsupported) {
                    c->unsupported = 1;
                    c->why = (t == IT_QUERY_TYPE) ? "query_type: набор описывает вид DNS-запроса"
                                                  : "source_port: сужение по порту клиента";
                }
                break;
            }
            case IT_ADGUARD_DOMAIN: {
                /* Тот же succinct-набор, но с другими метками (`*` и 0x08): прочитать его
                 * нашим обходом можно, а истолковать — нет, потому что правила AdGuard
                 * описывают не имена, а образцы с якорями. Пропускаем структурно. */
                (void)rd_u8(r);
                size_t n1 = 0, n2 = 0;
                uint64_t *a = rd_u64_array(r, &n1);
                uint64_t *b = rd_u64_array(r, &n2);
                uint64_t nl = rd_uvarint(r);
                const unsigned char *lab = (r->err || nl > 100000000u) ? NULL : rd_take(r, (size_t)nl);
                free(a); free(b);
                if (!lab) { r->err = 1; return -1; }
                if (!c->unsupported) { c->unsupported = 1; c->why = "adguard_domain"; }
                break;
            }
            case IT_NET_EXPENSIVE: case IT_NET_CONSTRAINED:
                /* Полезной нагрузки нет: сам тег и есть значение. */
                if (!c->unsupported) { c->unsupported = 1; c->why = "признак вида сети"; }
                break;
            case IT_IFACE_ADDR: {
                uint64_t entries = rd_uvarint(r);
                if (r->err || entries > 1000000u) { r->err = 1; return -1; }
                for (uint64_t i = 0; i < entries; i++) {
                    (void)rd_u8(r);
                    uint64_t cnt = rd_uvarint(r);
                    if (r->err || cnt > 1000000u) { r->err = 1; return -1; }
                    for (uint64_t k = 0; k < cnt; k++) {
                        uint64_t l = rd_uvarint(r);
                        if (!rd_take(r, (size_t)l) || !rd_take(r, 1)) return -1;
                    }
                }
                if (!c->unsupported) { c->unsupported = 1; c->why = "адреса интерфейса"; }
                break;
            }
            case IT_DEFAULT_IFACE_ADDR: {
                uint64_t cnt = rd_uvarint(r);
                if (r->err || cnt > 1000000u) { r->err = 1; return -1; }
                for (uint64_t k = 0; k < cnt; k++) {
                    uint64_t l = rd_uvarint(r);
                    if (!rd_take(r, (size_t)l) || !rd_take(r, 1)) return -1;
                }
                if (!c->unsupported) { c->unsupported = 1; c->why = "адреса интерфейса по умолчанию"; }
                break;
            }
            default:
                /* Неизвестный тип — не «пропустим и поедем дальше»: длину его содержимого
                 * мы не знаем, а угадав, разобрали бы остаток файла как попало. */
                fprintf(stderr, "steer: srs: неизвестный тип элемента %u\n", t);
                r->err = 1;
                return -1;
        }
    }
}

static int read_rule(struct rd *r, struct ctx *c, int depth) {
    if (depth > 100) { r->err = 1; return -1; }   /* тот же предел, что у sing-box */
    unsigned kind = rd_u8(r);
    if (r->err) return -1;
    if (kind == 0) return read_default_rule(r, c);
    if (kind == 1) {
        (void)rd_u8(r);                            /* mode: 0 — and, 1 — or */
        uint64_t n = rd_uvarint(r);
        if (r->err || n > 100000u) { r->err = 1; return -1; }
        for (uint64_t i = 0; i < n; i++)
            if (read_rule(r, c, depth + 1) != 0) return -1;
        (void)rd_u8(r);                            /* invert */
        if (!c->unsupported) {
            c->unsupported = 1;
            c->why = "логическое правило: список не выражает «и»/«или» между условиями";
        }
        return r->err ? -1 : 0;
    }
    fprintf(stderr, "steer: srs: неизвестный вид правила %u\n", kind);
    r->err = 1;
    return -1;
}

/* ---- вход --------------------------------------------------------------------------- */

static int srs_dump_to(const char *path, FILE *dom, FILE *pfx, FILE *meta) {
    FILE *f = fopen(path, "rb");
    if (!f) { fprintf(stderr, "steer: srs: не открылся %s\n", path); return 1; }
    if (fseek(f, 0, SEEK_END) != 0) { fclose(f); fprintf(stderr, "steer: srs: не файл\n"); return 1; }
    long sz = ftell(f);
    if (sz < 6 || sz > 64L * 1024 * 1024) {
        fclose(f);
        fprintf(stderr, "steer: srs: неправдоподобный размер %ld\n", sz);
        return 1;
    }
    rewind(f);
    unsigned char *raw = malloc((size_t)sz);
    if (!raw || fread(raw, 1, (size_t)sz, f) != (size_t)sz) {
        free(raw); fclose(f);
        fprintf(stderr, "steer: srs: файл не прочитался целиком\n");
        return 1;
    }
    fclose(f);

    if (memcmp(raw, SRS_MAGIC, 3) != 0) {
        free(raw);
        fprintf(stderr, "steer: srs: это не набор правил sing-box (нет подписи SRS)\n");
        return 1;
    }
    unsigned ver = raw[3];
    if (ver < 1 || ver > SRS_VER_MAX) {
        free(raw);
        fprintf(stderr, "steer: srs: версия формата %u, эта сборка знает 1..%d\n", ver, SRS_VER_MAX);
        return 1;
    }

    /* zlib-обёртка (RFC 1950): два байта заголовка, дальше сырой DEFLATE, в конце Adler-32.
     * puff распаковывает именно СЫРОЙ поток, поэтому заголовок снимаем сами и проверяем —
     * без проверки битый файл выглядел бы как файл с другим содержимым. */
    unsigned char *z = raw + 4;
    size_t zn = (size_t)sz - 4;
    if (zn < 6) { free(raw); fprintf(stderr, "steer: srs: тело короче обёртки\n"); return 1; }
    unsigned cmf = z[0], flg = z[1];
    if ((cmf & 0x0F) != 8 || ((cmf << 8) | flg) % 31 != 0 || (flg & 0x20)) {
        free(raw);
        fprintf(stderr, "steer: srs: тело сжато не zlib-ом (CMF %02x FLG %02x)\n", cmf, flg);
        return 1;
    }

    /* Первый проход — узнать размер: puff с NIL считает, не записывая. */
    unsigned long out_len = 0, in_len = zn - 2 - 4;
    int prc = puff(NIL, &out_len, z + 2, &in_len);
    if (prc != 0 || out_len == 0 || out_len > 64UL * 1024 * 1024) {
        free(raw);
        fprintf(stderr, "steer: srs: тело не распаковалось (puff %d)\n", prc);
        return 1;
    }
    unsigned char *body = malloc(out_len);
    if (!body) { free(raw); fprintf(stderr, "steer: srs: нет памяти на %lu байт\n", out_len); return 1; }
    unsigned long got = out_len;
    in_len = zn - 2 - 4;
    prc = puff(body, &got, z + 2, &in_len);
    if (prc != 0 || got != out_len) {
        free(body); free(raw);
        fprintf(stderr, "steer: srs: распаковка разошлась со своим же счётом (puff %d)\n", prc);
        return 1;
    }
    free(raw);

    struct rd r = { body, body + got, 0 };
    struct ctx c;
    memset(&c, 0, sizeof(c));
    c.dom = dom; c.pfx = pfx; c.meta = meta;

    uint64_t nrules = rd_uvarint(&r);
    int bad = r.err || nrules > 100000u;
    for (uint64_t i = 0; !bad && i < nrules; i++)
        if (read_rule(&r, &c, 0) != 0) bad = 1;

    if (!bad && r.p != r.end) {
        /* Хвост означает, что раскладка понята неверно, даже если всё «разобралось». */
        fprintf(stderr, "steer: srs: после разбора осталось %ld байт\n", (long)(r.end - r.p));
        bad = 1;
    }
    free(body);
    if (bad) { fprintf(stderr, "steer: srs: набор не разобран\n"); return 1; }
    /* Уровень обязателен: разбор УДАЛСЯ, значит это строка журнала во время работы, а не
     * отказ вызывающему (контракт docs/contract-v1.md §5). Голое «steer: » законно только
     * там, где команда заканчивается ненулевым кодом. */
    if (c.saw_v6)
        fprintf(stderr, "steer[warn] srs: в наборе есть подсети IPv6 — они пропущены, "
                        "правила работают по IPv4\n");
    if (c.ports_over && !c.unsupported) {
        c.unsupported = 1;
        c.why = "портов в наборе больше, чем канал может сузить";
    }
    if (c.unsupported) {
        fprintf(stderr, "steer: srs: набор понят, но не выразим списком — %s\n", c.why);
        return 2;
    }
    /* Сужение печатается ПОСЛЕ разбора и только целиком: элементы `network` и `port_range`
     * идут в наборе врозь, и печатать их на месте значило бы отдать четыре строки вместо
     * двух — а вызывающему нужен готовый к переносу в канал вид. */
    if (c.meta) {
        if (c.have_tcp && c.have_udp) fprintf(c.meta, "proto=both\n");
        else if (c.have_tcp)          fprintf(c.meta, "proto=tcp\n");
        else if (c.have_udp)          fprintf(c.meta, "proto=udp\n");
        if (c.ports_n) {
            fprintf(c.meta, "ports=");
            for (size_t i = 0; i < c.ports_n; i++)
                fprintf(c.meta, "%s%s", i ? "," : "", c.ports[i]);
            fprintf(c.meta, "\n");
        }
    }
    /* Сужение есть, а печатать его некуда — это ОТКАЗ, а не мелочь. Отдать подсети
     * Cloudflare без «только udp 50000-65535» значит увести в туннель весь TCP к
     * 104.16.0.0/12, и вызывающий об этом даже не узнает. */
    if (!c.meta && (c.have_tcp || c.have_udp || c.ports_n)) {
        fprintf(stderr, "steer: srs: набор сужен по протоколу или портам — нужен --meta-out, "
                        "иначе сужение потеряется, а подсети уедут в туннель целиком\n");
        return 2;
    }
    return 0;
}

/* Открыть оба выхода, разобрать, закрыть. Оба открываются ДО разбора: файл, который не
 * удалось создать, надо назвать раньше, чем половина набора уехала в другой. */
int srs_dump(const char *path, const char *dom_path, const char *pfx_path,
             const char *meta_path) {
    FILE *dom = stdout, *pfx = stdout, *meta = NULL;
    if (dom_path && !(dom = fopen(dom_path, "w"))) {
        fprintf(stderr, "steer: srs: не создался %s\n", dom_path);
        return 1;
    }
    if (pfx_path && !(pfx = fopen(pfx_path, "w"))) {
        fprintf(stderr, "steer: srs: не создался %s\n", pfx_path);
        if (dom != stdout) fclose(dom);
        return 1;
    }
    if (meta_path && !(meta = fopen(meta_path, "w"))) {
        fprintf(stderr, "steer: srs: не создался %s\n", meta_path);
        if (dom != stdout) fclose(dom);
        if (pfx != stdout && pfx != dom) fclose(pfx);
        return 1;
    }
    int rc = srs_dump_to(path, dom, pfx, meta);
    /* Закрытие проверяется: на полном overlay ошибка приходит именно здесь, при сбросе
     * буфера, и «список записан» без этой проверки было бы неправдой. */
    if (dom != stdout && fclose(dom) != 0) {
        fprintf(stderr, "steer: srs: %s не записался до конца\n", dom_path);
        rc = rc ? rc : 1;
    }
    if (pfx != stdout && pfx != dom && fclose(pfx) != 0) {
        fprintf(stderr, "steer: srs: %s не записался до конца\n", pfx_path);
        rc = rc ? rc : 1;
    }
    if (meta && fclose(meta) != 0) {
        fprintf(stderr, "steer: srs: %s не записался до конца\n", meta_path);
        rc = rc ? rc : 1;
    }
    return rc;
}
