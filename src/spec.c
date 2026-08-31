/* Spec parsing and the mark/table registry — see spec.h for why this is shared. */
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>
#include <time.h>
#include <arpa/inet.h>
#include "spec.h"
#include "obfs.h"

/* Marks and tables live well away from what splify (0x40000/0x80000, tables
 * 200/202) and mwan3 use, so both can run on one box while the migration is in
 * progress. One bit per output keeps `nft` output readable. */
/* База метки и число бит — в spec.h: их знает не только распорядитель, но и тот, кто
 * ставит правило и генерирует ruleset, а маска выводится из них же. */
#define MARK_BASE   STEER_MARK_BASE
#define TABLE_BASE  300




struct output g_out[MAX_OUTPUTS];
size_t g_out_n;
struct channel g_ch[MAX_CHANNELS];
size_t g_ch_n;
char g_from_default[MAX_FROM][64];
size_t g_from_default_n;

/* Устройства, с которых движок забирает трафик клиентов. Умолчание — один `br-lan`: спека,
 * написанная до появления списка, обязана значить ровно то же, что значила.
 *
 * Именем, а не адресом, по двум причинам сразу. У локального префикса IPv6 стабильного
 * адреса нет (ULA плюс делегированный глобальный, который меняется), поэтому писать
 * `ip6 saddr` не во что. А у туннельных устройств вроде tailscale0 адрес на роутере обычно
 * /32, и подсеть пиров из него не выводится — там имя устройства единственный ответ. */
char g_lan_dev[MAX_LAN_DEV][64] = { "br-lan" };
size_t g_lan_dev_n = 1;
/* Opt-in, because it cannot work without a firewall rule the engine does not own —
 * see the comment on the generated chain in steer.c. Defaulting it on would turn
 * legible-but-wrong hops into no hops at all. */
int g_traceroute_hops;
const char *g_state_dir = "/var/lib/steer";
/* Имена таблиц для iproute2. Каталог, а не сам rt_tables: файл принадлежит пакету iproute2,
 * и дописывать в него значило бы править чужое; rt_tables.d для этого и существует. */
const char *g_rt_tables_d = "/etc/iproute2/rt_tables.d";

void die(const char *fmt, const char *a) {
    fprintf(stderr, "steer: ");
    fprintf(stderr, fmt, a);
    fputc('\n', stderr);
    exit(2);
}

/* Состав идентификатора, пришедшего из спеки: имя выхода, имя устройства, имя канала,
 * записи lan_devices.
 *
 * Заслон стоит В ПАРСЕРЕ, а не у каждого вызова оболочки, и это принципиально. Имена
 * отсюда подставляются в командные строки в нескольких разных местах — `pgrep -f 'steer
 * obfs %s'` и `nft list chain … o_%s` в diag, имя набора в set_count, — и проверять их по
 * месту значит проверять по разу в каждом и забыть в следующем. Забыли: спека с lan_device
 * вида «x;id>/tmp/pwned;#» уезжала в `ip -4 -o addr show %s` через popen и выполняла это от
 * root, причём у ЛЮБОЙ команды, читающей спеку, потому что автоопределение подсети
 * включалось штатно. Того вызова больше нет (клиенты выбираются по имени устройства, а не
 * по выведенной подсети), но проверка от этого не менее нужна: имя устройства теперь уходит
 * в текст правил nftables. Имя выхода с кавычкой давало то же самое через diag, а diag
 * дёргает rpcd интерфейса.
 *
 * Проверенное однажды при загрузке имя безопасно везде и навсегда, включая места,
 * которых ещё нет. Это то же решение, что с адресом в explain: там проверка формы стоит
 * до подстановки, и по той же причине — подстановка непроверенной строки уже была дырой.
 *
 * Состав нарочно уже, чем позволяет ядро: буквы, цифры, `_`, `-`, `.`. Имена интерфейсов
 * Linux этим и ограничены на практике, а имя выхода придумывает человек в интерфейсе —
 * ему хватает. Пустое имя отвергается тоже: оно ломает и набор, и pgrep. */
int name_ok(const char *s) {
    if (!s || !*s) return 0;
    for (const unsigned char *q = (const unsigned char *)s; *q; q++)
        if (!((*q >= 'a' && *q <= 'z') || (*q >= 'A' && *q <= 'Z') ||
              (*q >= '0' && *q <= '9') || *q == '_' || *q == '-' || *q == '.'))
            return 0;
    return 1;
}

/* Имя КАНАЛА — не идентификатор, а подпись, которую человек читает в интерфейсе, и
 * требовать от неё латиницу нельзя: каналы в этом проекте называют по-русски, и стенд
 * с «адресами»/«доменами» — ровно тот случай. В оболочку это имя не попадает никогда:
 * комментарий в ruleset собирается из имени ГРУППЫ, а то выводится из имени выхода.
 * Дойти оно может до JSON у status и до текста ruleset, поэтому запрещено ровно то, что
 * ломает их разбор: кавычка, обратная косая и управляющие символы. Всё остальное, включая
 * любой UTF-8, разрешено. */
int label_ok(const char *s) {
    if (!s || !*s) return 0;
    for (const unsigned char *q = (const unsigned char *)s; *q; q++)
        if (*q == '"' || *q == '\\' || *q < 0x20 || *q == 0x7F) return 0;
    return 1;
}

/* ---- имя набора группы -----------------------------------------------------
 *
 * Живёт ЗДЕСЬ, а не в компиляторе, потому что имя вычисляют двое: steer.c, когда
 * генерирует набор, и dnsd.c, когда решает, в какой набор класть адрес разрешённого
 * домена. Разойдись они — резолвер наполнял бы набор, которого нет, и доменная
 * маршрутизация молча переставала бы работать. Одна функция, два вызывающих.
 *
 * Почему у имени появился различитель. Раньше имя собиралось только из выхода и вида
 * (`vpn_ip`, `vpn_dom`), а группы компилятор разделяет ещё и по списку клиентов (`from`)
 * и по режиму резолвера. Две группы получали ОДНО имя, ядро сливало их наборы в один, и
 * список, заведённый «только для телевизора», уезжал в туннель для всей сети. Никакого
 * отказа при этом не было: nft принимает два объявления одного набора.
 *
 * Различитель — порядковый номер списка клиентов в спеке, а не хэш: номер точен, а хэш
 * мог бы совпасть у двух разных списков и вернуть ту же беду тихо. Номер считается по
 * g_ch в порядке спеки, поэтому оба вызывающих получают одно и то же число, не
 * сговариваясь.
 *
 * Умолчания суффикса не получают: `vpn_ip` у обычной конфигурации остаётся `vpn_ip`, и
 * на уже установленных роутерах имена наборов (а с ними и перенос счётчиков) не меняются.
 */
static int from_same(const char (*a)[64], size_t an, const char (*b)[64], size_t bn) {
    if (an != bn) return 0;
    for (size_t i = 0; i < an; i++) if (strcmp(a[i], b[i]) != 0) return 0;
    return 1;
}

/* Действующий список клиентов канала: свой, а если его нет — общий по умолчанию. Правило
 * то же, что у компилятора при сборке групп, и записано один раз здесь. */
static const char (*chan_from(const struct channel *c, size_t *n))[64] {
    if (c->from_n) { *n = c->from_n; return c->from; }
    *n = g_from_default_n;
    return g_from_default;
}

/* Номер списка клиентов среди РАЗЛИЧНЫХ списков, встреченных в спеке, в порядке первого
 * появления. Список по умолчанию участвует в нумерации наравне с прочими: он всё равно
 * попадает в ветку без суффикса, кроме случая realip. */
static int from_disc(const char (*from)[64], size_t from_n) {
    int idx = 0;
    for (size_t i = 0; i < g_ch_n; i++) {
        size_t cn;
        const char (*cf)[64] = chan_from(&g_ch[i], &cn);
        if (from_same(cf, cn, from, from_n)) return idx;
        /* Считаем только первое появление каждого списка. */
        int seen = 0;
        for (size_t k = 0; k < i && !seen; k++) {
            size_t kn;
            const char (*kf)[64] = chan_from(&g_ch[k], &kn);
            seen = from_same(kf, kn, cf, cn);
        }
        if (!seen) idx++;
    }
    return idx;
}

void group_set_name(char *dst, size_t n, const char *out, const char *kind,
                    const char (*from)[64], size_t from_n, int realip) {
    /* realip различает только доменные группы: у адресных резолвер не участвует. */
    int rip = realip && !strcmp(kind, "dom");
    if (!rip && from_same(from, from_n, g_from_default, g_from_default_n)) {
        snprintf(dst, n, "%.24s_%s", out, kind);
        return;
    }
    /* Выход обрезается сильнее, чтобы имя с суффиксом осталось коротким: у наборов
     * nftables на старых ядрах предел длины 32 символа. */
    snprintf(dst, n, "%.18s_%s_c%d%s", out, kind, from_disc(from, from_n), rip ? "r" : "");
}

/* ---- a JSON reader small enough to audit ---------------------------------- */
/* Deliberately not a general parser: it walks the document the shape of the spec
 * demands and refuses anything else. A router config that compiles into firewall
 * rules should fail loudly on an unexpected shape rather than guess — which is the
 * same reason the spec is JSON and not YAML. */
struct js { const char *p; };

static void js_ws(struct js *j) {
    while (*j->p == ' ' || *j->p == '\t' || *j->p == '\n' || *j->p == '\r') j->p++;
}
static int js_lit(struct js *j, char c) {
    js_ws(j);
    if (*j->p != c) return -1;
    j->p++;
    return 0;
}
static int js_str(struct js *j, char *buf, size_t n) {
    js_ws(j);
    if (*j->p != '"') return -1;
    j->p++;
    size_t i = 0;
    while (*j->p && *j->p != '"') {
        if (*j->p == '\\' && j->p[1]) j->p++;
        if (i + 1 < n) buf[i++] = *j->p;
        j->p++;
    }
    if (*j->p != '"') return -1;
    j->p++;
    buf[i] = '\0';
    return 0;
}
static long js_num(struct js *j) {
    js_ws(j);
    char *e = NULL;
    long v = strtol(j->p, &e, 10);
    j->p = e;
    return v;
}
/* Skips one value of any type, so unknown keys are tolerated (forward compat
 * within a schema major) without being silently interpreted. */
static void js_skip(struct js *j) {
    js_ws(j);
    if (*j->p == '"') { char t[512]; js_str(j, t, sizeof(t)); return; }
    if (*j->p == '{' || *j->p == '[') {
        char open = *j->p, close = open == '{' ? '}' : ']';
        int depth = 0;
        do {
            if (*j->p == '"') { char t[512]; js_str(j, t, sizeof(t)); continue; }
            if (*j->p == open) depth++;
            else if (*j->p == close) depth--;
            j->p++;
        } while (*j->p && depth > 0);
        return;
    }
    while (*j->p && *j->p != ',' && *j->p != '}' && *j->p != ']') j->p++;
}

/* Копия строки на всю жизнь процесса. Спека разбирается один раз, а живёт разобранной до
 * конца работы — освобождать эти строки некому и незачем; отказ malloc здесь равносилен
 * «спеку не прочитать», поэтому громкий. */
static const char *keep(const char *s) {
    size_t n = strlen(s) + 1;
    char *p = malloc(n);
    if (!p) die("out of memory reading the spec", NULL);
    memcpy(p, s, n);
    return p;
}

/* Списки путей. От str_array отличается тем, что хранит УКАЗАТЕЛИ, а не буферы: путей в
 * правиле теперь до шестидесяти четырёх, и массив фиксированных буферов по 256 байт стоил бы
 * 32 КБ на правило. */
static size_t str_list(struct js *j, const char **dst, size_t max) {
    if (js_lit(j, '[') != 0) return 0;
    size_t n = 0;
    js_ws(j);
    if (*j->p == ']') { j->p++; return 0; }
    for (;;) {
        char t[256];
        if (js_str(j, t, sizeof(t)) != 0) return n;
        if (n >= max) die("too many entries in list", NULL);
        dst[n++] = keep(t);
        js_ws(j);
        if (*j->p == ',') {
            /* Trailing comma (`[...,]`) раньше уходил в continue, js_str на ']' возвращал
             * -1 → return n до js_lit(']'), и несъеденная ']' вешала вызывающий цикл, не
             * проверяющий возврат js_str (цикл match в parse_channels). Отказываем громко,
             * как и на любой malformed форме. */
            j->p++;
            js_ws(j);
            if (*j->p == ']') die("list: trailing comma (expected a string)", NULL);
            continue;
        }
        break;
    }
    js_lit(j, ']');
    return n;
}

static int str_array(struct js *j, char dst[][64], size_t max, size_t *n) {
    if (js_lit(j, '[') != 0) return -1;
    *n = 0;
    js_ws(j);
    if (*j->p == ']') { j->p++; return 0; }
    for (;;) {
        char t[64];
        if (js_str(j, t, sizeof(t)) != 0) return -1;
        if (*n >= max) die("too many entries in array", NULL);
        snprintf(dst[(*n)++], 64, "%s", t);
        js_ws(j);
        if (*j->p == ',') {
            /* См. str_list: trailing comma → громкий отказ, а не продвижение к ']' и риск
             * зависания вызывающего цикла на несъеденной скобке. */
            j->p++;
            js_ws(j);
            if (*j->p == ']') die("array: trailing comma (expected a string)", NULL);
            continue;
        }
        break;
    }
    return js_lit(j, ']');
}

/* Массив целых. Отдельно от str_array, потому что js_num на не-числе НЕ ПРОДВИГАЕТ указатель
 * (strtol возвращает 0 и e == p), и цикл, не проверяющий этого, встал бы навсегда на
 * `"nodes": ["6"]`. Проверка сделана здесь, у единственного места, где числа читаются
 * массивом. */
static int num_array(struct js *j, int *dst, size_t max, size_t *n) {
    if (js_lit(j, '[') != 0) return -1;
    *n = 0;
    js_ws(j);
    if (*j->p == ']') { j->p++; return 0; }
    for (;;) {
        js_ws(j);
        const char *before = j->p;
        long v = js_num(j);
        if (j->p == before) return -1;          /* не число: строка, объект, мусор */
        if (*n >= max) die("too many entries in array", NULL);
        if (v < 0 || v > 100000) return -1;
        dst[(*n)++] = (int)v;
        js_ws(j);
        if (*j->p == ',') {
            /* См. str_list: trailing comma → громкий отказ. */
            j->p++;
            js_ws(j);
            if (*j->p == ']') die("array: trailing comma (expected a number)", NULL);
            continue;
        }
        break;
    }
    return js_lit(j, ']');
}

/* «адрес:порт» → адрес и порт. Живёт здесь, а не в obfs.c, потому что нужен обоим:
 * парсеру спеки при чтении и обфускатору при разборе своих аргументов, а линкуются
 * они всегда вместе. Порт по последнему двоеточию — чтобы форма не мешала будущему
 * IPv6-литералу. */
int obfs_split_hostport(const char *s, char *host, size_t hn, int *port) {
    const char *colon = strrchr(s, ':');
    if (!colon || colon == s) return -1;
    size_t hl = (size_t)(colon - s);
    if (hl + 1 > hn) return -1;
    memcpy(host, s, hl);
    host[hl] = '\0';
    char *end = NULL;
    long p = strtol(colon + 1, &end, 10);
    if (!end || *end || p < 1 || p > 65535) return -1;
    *port = (int)p;
    return 0;
}

/* Обфускация транспорта выхода. Форма:
 *
 *   "obfs": { "mode": "wg-over-tcp", "server": "203.0.113.10:4567",
 *             "listen": "127.0.0.1:51820" }
 *
 * `listen` обязателен и должен совпадать с `Endpoint` пира в /etc/config/network: это
 * единственное место, где две настройки обязаны знать друг о друге, и вывести одну из
 * другой движок не может — ключи и пиры не его. Несовпадение молчаливо: WireGuard шлёт
 * в никуда, туннель не поднимается, и причина не видна ниоткуда, кроме tcpdump. */
static void parse_obfs(struct js *j, struct output *o) {
    if (js_lit(j, '{') != 0) die("outputs.%s: obfs должен быть объектом", o->name);
    char mode[32] = "", server[80] = "", listen[80] = "";
    js_ws(j);
    while (*j->p != '}') {
        char key[32];
        if (js_str(j, key, sizeof(key)) != 0) die("outputs.%s: плохой ключ в obfs", o->name);
        js_lit(j, ':');
        if (!strcmp(key, "mode")) js_str(j, mode, sizeof(mode));
        else if (!strcmp(key, "server")) js_str(j, server, sizeof(server));
        else if (!strcmp(key, "listen")) js_str(j, listen, sizeof(listen));
        else js_skip(j);
        js_ws(j);
        if (*j->p == ',') { j->p++; js_ws(j); }
    }
    j->p++;

    /* Отсутствующий mode — это сегодняшний единственный режим: спека, написанная до
     * появления второго, обязана значить то же, что значила. Неизвестный — отказ, а не
     * молчаливое «наверное, тот самый»: обфускация, которой нет, выглядит как рабочий
     * выход, из которого не выходит ни один пакет. */
    if (mode[0] && strcmp(mode, "wg-over-tcp") != 0)
        die("outputs.%s: неизвестный obfs.mode (сейчас есть только wg-over-tcp)", o->name);
    if (!server[0]) die("outputs.%s: obfs нужен server вида адрес:порт", o->name);
    if (obfs_split_hostport(server, o->obfs.server, sizeof(o->obfs.server),
                            &o->obfs.server_port) != 0)
        die("outputs.%s: obfs.server должен быть вида адрес:порт", o->name);
    /* Имя, а не адрес — отказ. Имя пришлось бы разрешать, и разрешать его через тот
     * самый DNS, который может идти в туннель, который поднимается через этот самый
     * сервер. Управляющий слой резолвит один раз и кладёт сюда адрес — то же правило,
     * что со списками: движок читает то, что ему положили. */
    struct in_addr tmp;
    if (inet_pton(AF_INET, o->obfs.server, &tmp) != 1)
        die("outputs.%s: obfs.server должен быть адресом, а не именем", o->name);

    if (!listen[0]) die("outputs.%s: obfs нужен listen — тот же адрес и порт, что в "
                        "Endpoint пира WireGuard", o->name);
    if (obfs_split_hostport(listen, o->obfs.listen, sizeof(o->obfs.listen),
                            &o->obfs.listen_port) != 0)
        die("outputs.%s: obfs.listen должен быть вида адрес:порт", o->name);
    if (inet_pton(AF_INET, o->obfs.listen, &tmp) != 1)
        die("outputs.%s: obfs.listen должен быть адресом, а не именем", o->name);
    o->obfs.on = 1;
}

/* Виды выходов ОДНИМ списком: из него и печать (out_kind_name), и проверка флага
 * --kind (out_kind_known), и разбор поля kind ниже. Три места, читающие одну таблицу,
 * вместо трёх списков, которые расходятся молча — см. объяснение у объявлений в spec.h. */
static const struct { const char *name; enum out_kind kind; } KINDS[] = {
    { "direct",    OUT_DIRECT },
    { "interface", OUT_INTERFACE },
    { "vless",     OUT_VLESS },
    { "xsteer",    OUT_XSTEER },
};
#define KINDS_N (sizeof(KINDS) / sizeof(KINDS[0]))

const char *out_kind_name(enum out_kind k) {
    for (size_t i = 0; i < KINDS_N; i++)
        if (KINDS[i].kind == k) return KINDS[i].name;
    /* Недостижимо: вид приходит из этой же таблицы. Но возвращать здесь «interface»
     * значило бы напечатать неправду про вид, которого мы не знаем, — а именно это уже
     * делал тернарник, который эта функция заменила. */
    return "?";
}

int out_kind_known(const char *s) {
    for (size_t i = 0; i < KINDS_N; i++)
        if (!strcmp(KINDS[i].name, s)) return 1;
    return 0;
}

static void parse_outputs(struct js *j) {
    if (js_lit(j, '{') != 0) die("outputs: expected an object", NULL);
    js_ws(j);
    if (*j->p == '}') { j->p++; return; }
    for (;;) {
        struct output o = {0};
        /* Какой из двух форм записан выбор узлов. Нужно, чтобы отличить «поля нет» от «поле
         * задано» и поймать выход, где заданы обе: молча взять одну значило бы, что половина
         * написанного человеком не действует, и понять это было бы нечем (тот же приём, что
         * у lan_device/lan_devices в load_spec). */
        int node_one = 0, node_many = 0;
        if (js_str(j, o.name, sizeof(o.name)) != 0) die("outputs: expected a name", NULL);
        /* Состав имени — см. name_ok(). Оно уходит в командную строку через diag и в имя
         * набора, поэтому проверяется здесь, один раз, а не у каждого вызова. */
        if (!name_ok(o.name))
            die("outputs.%s: в имени выхода можно только буквы, цифры, _ - и точку", o.name);
        if (js_lit(j, ':') != 0) die("outputs.%s: expected ':'", o.name);
        if (js_lit(j, '{') != 0) die("outputs.%s: expected an object", o.name);
        char kind[32] = "";
        js_ws(j);
        while (*j->p != '}') {
            char key[32];
            if (js_str(j, key, sizeof(key)) != 0) die("outputs.%s: bad key", o.name);
            js_lit(j, ':');
            if (!strcmp(key, "kind")) js_str(j, kind, sizeof(kind));
            else if (!strcmp(key, "device")) {
                js_str(j, o.device, sizeof(o.device));
                if (!name_ok(o.device))
                    die("outputs.%s: имя устройства негодного состава", o.name);
            }
            else if (!strcmp(key, "devices")) {
                /* Кандидаты в порядке предпочтения. Единственное число остаётся
                 * сокращением для одного — прежние спеки не ломаются. */
                if (js_lit(j, '[') == 0) {
                    js_ws(j);
                    if (*j->p == ']') j->p++;
                    else for (;;) {
                        char t[32];
                        if (js_str(j, t, sizeof(t)) != 0) break;
                        if (o.devices_n >= MAX_DEVICES) die("outputs.%s: too many devices", o.name);
                        if (!name_ok(t)) die("outputs.%s: имя устройства негодного состава", o.name);
                        snprintf(o.devices[o.devices_n++], 32, "%s", t);
                        js_ws(j);
                        if (*j->p == ',') {
                            /* См. str_list: trailing comma → отказ, не продвижение к ']' и
                             * риск зависания parse_outputs на несъеденной скобке. */
                            j->p++;
                            js_ws(j);
                            if (*j->p == ']') die("outputs.%s: trailing comma in devices", o.name);
                            continue;
                        }
                        js_lit(j, ']');
                        break;
                    }
                }
            }
            else if (!strcmp(key, "obfs")) parse_obfs(j, &o);
            else if (!strcmp(key, "sub_file")) js_str(j, o.sub_file, sizeof(o.sub_file));
            else if (!strcmp(key, "conf")) js_str(j, o.xs_conf, sizeof(o.xs_conf));
            /* Транспорт выхода xsteer. Полем спеки, а не только ключом командной строки,
             * потому что процесс поднимает procd: ключи ему передать негде, а настройка
             * обязана переживать перезагрузку. */
            /* Проверяем на 't', как соседнее `enabled` проверяется на 'f': значение здесь
             * либо true, либо false, и разбирать его полноценным разбором JSON незачем. */
            else if (!strcmp(key, "stream")) { js_ws(j); o.xs_stream = (*j->p == 't'); js_skip(j); }
            else if (!strcmp(key, "stream_port")) o.xs_stream_port = (int)js_num(j);
            /* `node` — сокращение для списка из одного узла, `nodes` — сам список. Дальше по
             * коду путь один, ровно как у `device`/`devices`. Прежнее `-1` («первый рабочий»)
             * записывается пустым списком: это то же самое умолчание, только выраженное
             * отсутствием кандидатов, а не отрицательным номером. */
            else if (!strcmp(key, "node")) {
                long v = js_num(j);
                node_one = 1;
                if (v >= 0) { o.nodes[0] = (int)v; o.nodes_n = 1; }
                else o.nodes_n = 0;
            }
            else if (!strcmp(key, "nodes")) {
                if (num_array(j, o.nodes, MAX_NODE_SEL, &o.nodes_n) != 0)
                    die("outputs.%s: nodes — массив номеров узлов подписки", o.name);
                node_many = 1;
            }
            else if (!strcmp(key, "on_fail")) {
                char m[16];
                js_str(j, m, sizeof(m));
                if (!strcmp(m, "drop")) o.on_fail = FAIL_DROP;
                else if (!strcmp(m, "direct")) o.on_fail = FAIL_DIRECT;
                else if (!strcmp(m, "zapret")) o.on_fail = FAIL_ZAPRET;
                else die("outputs.%s: unknown on_fail (want drop, direct or zapret)", o.name);
            }
            else js_skip(j);
            js_ws(j);
            if (*j->p == ',') { j->p++; js_ws(j); }
        }
        j->p++;
        if (!strcmp(kind, "direct")) o.kind = OUT_DIRECT;
        else if (!strcmp(kind, "vless")) {
#ifndef STEER_EXTENDED
            /* Отказываем СРАЗУ, а не при подъёме: иначе спека применяется, правила
             * встают, и выход молча никуда не ведёт — то есть человек видит рабочую
             * конфигурацию, в которой трафик пропадает. */
            die("outputs.%s: kind vless требует пакет steer-extended", o.name);
#endif
            o.kind = OUT_VLESS;
            if (!o.sub_file[0])
                die("outputs.%s: kind vless нужен sub_file с подпиской", o.name);
            /* Имя устройства выводится из имени выхода: держать его отдельным полем
             * значило бы дать двум именам расходиться, а никакой пользы от их различия
             * нет. Ограничение в 15 символов — предел IFNAMSIZ. */
            if (!o.device[0]) snprintf(o.device, sizeof(o.device), "%.15s", o.name);
            if (!o.devices_n) snprintf(o.devices[o.devices_n++], 32, "%s", o.device);
        }
        else if (!strcmp(kind, "xsteer")) {
#ifndef STEER_EXTENDED
            /* Отказываем СРАЗУ и по той же причине, что у vless выше: иначе спека
             * применяется, правила и метки встают, а устройства не создаст никто —
             * человек видит рабочую конфигурацию, из которой не выходит ни один пакет.
             * Подстроку «steer-extended» здесь читают снаружи (см. src/steer.c). */
            die("outputs.%s: kind xsteer требует пакет steer-extended", o.name);
#endif
            o.kind = OUT_XSTEER;
            /* Имя устройства и путь к конфигурации выводятся из имени выхода — тот же
             * довод, что у vless: два имени, которым позволено разойтись, пользы не
             * приносят. Имя выхода уже проверено name_ok выше, поэтому путь собирается
             * из проверенного. */
            if (!o.device[0]) snprintf(o.device, sizeof(o.device), "%.15s", o.name);
            if (!o.devices_n) snprintf(o.devices[o.devices_n++], 32, "%s", o.device);
            if (!o.xs_conf[0])
                snprintf(o.xs_conf, sizeof(o.xs_conf), "/etc/steer/xsteer/%.200s.conf", o.name);
            /* Абсолютный путь: процесс запускает procd со своим рабочим каталогом, а не
             * наша оболочка, — относительный «работал бы из шелла» и не работал у
             * сервиса. Годность к JSON: путь печатается в status, diag и xsteer-peers. */
            else if (o.xs_conf[0] != '/' || !label_ok(o.xs_conf))
                die("outputs.%s: conf должен быть абсолютным путём без кавычек", o.name);
            if (o.xs_stream_port && (o.xs_stream_port < 1 || o.xs_stream_port > 65535))
                die("outputs.%s: stream_port вне 1..65535", o.name);
            /* Порт без режима — это настройка, которая ничего не делает: сказать «настроено»,
             * не настроив, хуже, чем отказать. Тот же довод, что у obfs при чужом kind. */
            if (o.xs_stream_port && !o.xs_stream)
                die("outputs.%s: stream_port без stream: транспорт остался бы поддельным TCP",
                    o.name);
        }
        else if (!strcmp(kind, "interface")) {
            o.kind = OUT_INTERFACE;
            /* device и devices описывают одно и то же с разных сторон: device — что
             * работает сейчас, devices — из чего выбирать. Задан один, выводится
             * второй, чтобы дальше по коду не было двух путей. */
            if (!o.devices_n && o.device[0]) snprintf(o.devices[o.devices_n++], 32, "%s", o.device);
            if (!o.device[0] && o.devices_n) snprintf(o.device, sizeof(o.device), "%s", o.devices[0]);
            if (!o.device[0]) die("outputs.%s: kind interface needs a device", o.name);
        } else die("outputs.%s: неизвестный kind "
                   "(нужен direct, interface, vless или xsteer)", o.name);
        /* Обфускация осмысленна только там, где транспорт — чужой UDP, до которого
         * движку не дотянуться иначе. У vless свой транспорт внутри движка (и свои
         * средства маскировки — Reality), у xsteer он свой и поддельный TCP уже внутри
         * него, у direct транспорта нет вовсе. Принять поле молча значило бы сказать
         * «настроено», не настроив ничего. */
        if (o.obfs.on && o.kind != OUT_INTERFACE)
            die("outputs.%s: obfs есть только у kind=interface", o.name);
        /* Режим потока — свойство транспорта xsteer, и у прочих видов выхода его нет. Принять
         * поле молча значило бы сказать «настроено», не настроив ничего. */
        if ((o.xs_stream || o.xs_stream_port) && o.kind != OUT_XSTEER)
            die("outputs.%s: stream есть только у kind=xsteer", o.name);
        if (node_one && node_many)
            die("outputs.%s: задано и node, и nodes — оставьте одно", o.name);
        /* Выбор узлов есть только у подписки. Отвергается ТОЛЬКО новая форма: `nodes` не
         * может стоять в спеке, написанной до этой версии, а `node` там стоять мог — и у
         * чужого вида выхода он и раньше ничего не делал. Отказать на нём сейчас значило бы
         * сломать применение спеки, которая работала, ради поля, которое ничего не меняет. */
        if (node_many && o.kind != OUT_VLESS)
            die("outputs.%s: nodes есть только у kind=vless — это номера узлов подписки",
                o.name);
        /* Дубликат номера делает перебор бессмысленным ровно так же, как дубликат устройства
         * в devices: второй кандидат ничем не отличается от первого. */
        for (size_t a = 0; a < o.nodes_n; a++)
            for (size_t b = a + 1; b < o.nodes_n; b++)
                if (o.nodes[a] == o.nodes[b])
                    die("outputs.%s: узел подписки указан в nodes дважды", o.name);
        if (g_out_n >= MAX_OUTPUTS) die("too many outputs", NULL);
        g_out[g_out_n++] = o;
        js_ws(j);
        if (*j->p == ',') { j->p++; continue; }
        break;
    }
    js_lit(j, '}');
}

static void parse_channels(struct js *j) {
    if (js_lit(j, '[') != 0) die("channels: expected an array", NULL);
    js_ws(j);
    if (*j->p == ']') { j->p++; return; }
    for (;;) {
        struct channel c = {0};
        if (js_lit(j, '{') != 0) die("channels: expected an object", NULL);
        js_ws(j);
        while (*j->p != '}') {
            char key[32];
            if (js_str(j, key, sizeof(key)) != 0) die("channels: bad key", NULL);
            js_lit(j, ':');
            if (!strcmp(key, "name")) js_str(j, c.name, sizeof(c.name));
            else if (!strcmp(key, "out")) js_str(j, c.out, sizeof(c.out));
            else if (!strcmp(key, "from")) str_array(j, c.from, MAX_FROM, &c.from_n);
            /* Отсутствие поля и `true` значат одно: правило работает. Проверяем на 'f',
             * потому что спека без этого поля обязана вести себя как прежде. */
            else if (!strcmp(key, "enabled")) { js_ws(j); c.disabled = (*j->p == 'f'); js_skip(j); }
            else if (!strcmp(key, "match")) {
                if (js_lit(j, '{') != 0) die("channels.%s: match must be an object", c.name);
                js_ws(j);
                while (*j->p != '}') {
                    char mk[32];
                    /* Возврат js_str проверяется, как во всех соседних циклах, и это не
                     * педантизм. На недописанной спеке (питание пропало посреди записи
                     * файла) js_str отказывал молча, js_lit тоже, а js_skip на '\0' не
                     * продвигает указатель ни на байт — условие цикла оставалось истинным
                     * вечно. `steer status` на таком файле уходил в бесконечный цикл со
                     * 100% CPU, а его опрашивает rpcd каждые пять секунд: каждый опрос
                     * плодил ещё один вечный процесс на единственном ядре роутера.
                     * Контракт обещает громкий отказ на битой спеке — вот он. */
                    if (js_str(j, mk, sizeof(mk)) != 0)
                        die("channels.%s: match: expected a key", c.name);
                    if (js_lit(j, ':') != 0)
                        die("channels.%s: match: expected ':'", c.name);
                    /* Singular is shorthand for a one-element list, so a spec written
                     * before this stayed valid. */
                    if (!strcmp(mk, "prefixes_file")) {
                        char one[256];
                        if (js_str(j, one, sizeof(one)) == 0) {
                            c.prefixes_files[0] = keep(one);
                            c.prefixes_n = 1;
                        }
                    } else if (!strcmp(mk, "domains_file")) {
                        char one[256];
                        if (js_str(j, one, sizeof(one)) == 0) {
                            c.domains_files[0] = keep(one);
                            c.domains_n = 1;
                        }
                    } else if (!strcmp(mk, "prefixes_files")) {
                        c.prefixes_n = str_list(j, c.prefixes_files, MAX_FILES);
                    } else if (!strcmp(mk, "domains_files")) {
                        c.domains_n = str_list(j, c.domains_files, MAX_FILES);
                    }
                    else if (!strcmp(mk, "mode")) {
                        char m[16]; js_str(j, m, sizeof(m));
                        if (!strcmp(m, "realip")) c.realip = 1;
                        else if (strcmp(m, "fakeip") != 0) die("channels: unknown mode %s (want fakeip or realip)", m);
                    }
                    else if (!strcmp(mk, "any")) { js_ws(j); c.any = (*j->p == 't'); js_skip(j); }
                    else if (!strcmp(mk, "allow_all")) { js_ws(j); c.allow_all = (*j->p == 't'); js_skip(j); }
                    else js_skip(j);
                    js_ws(j);
                    if (*j->p == ',') { j->p++; js_ws(j); }
                }
                j->p++;
            }
            else js_skip(j);
            js_ws(j);
            if (*j->p == ',') { j->p++; js_ws(j); }
        }
        j->p++;
        if (!c.name[0]) die("a channel has no name", NULL);
        /* Подпись, а не идентификатор: по-русски — можно, кавычкой — нельзя (см. label_ok). */
        if (!label_ok(c.name))
            die("channel %s: в имени нельзя кавычку, обратную косую и управляющие символы", c.name);
        if (!c.out[0]) die("channel %s has no out", c.name);
        if (!c.prefixes_n && !c.domains_n && !c.any)
            die("channel %s matches nothing (want prefixes_files, domains_files or any)", c.name);
        /* Адреса и домены в одном правиле — МОЖНО.
         *
         * Раньше запрещалось: набор один, а заполняются они по-разному — адреса читаются из
         * файла при компиляции, домены кладёт резолвер по мере запросов. Из этого следовало,
         * что человек выбирает не сервис, а ВИД СПИСКА: «YouTube (адреса)» и «YouTube
         * (домены)» приходилось заводить двумя правилами, хотя это один сервис.
         *
         * Ограничение оказалось нашим, а не ядра: набор с `flags interval,timeout` держит и
         * постоянные элементы из файла, и временные от резолвера — проверено опытом на живом
         * nft. Поэтому запрет снят, а набор такой группы объявляется с timeout. */
        if (g_ch_n >= MAX_CHANNELS) die("too many channels", NULL);
        g_ch[g_ch_n++] = c;
        js_ws(j);
        if (*j->p == ',') { j->p++; continue; }
        break;
    }
    js_lit(j, ']');
}

void load_spec(const char *path) {
    FILE *f = strcmp(path, "-") ? fopen(path, "r") : stdin;
    if (!f) die("%s: cannot open", path);
    static char buf[262144];
    size_t n = fread(buf, 1, sizeof(buf) - 1, f);
    if (n == sizeof(buf) - 1) {
        int c = fgetc(f);
        if (c != EOF) die("spec too large (max 256 KiB)", NULL);
    }
    buf[n] = '\0';
    if (f != stdin) fclose(f);

    struct js j = { buf };
    long schema = -1;
    /* Какой из двух форм записано локальное устройство. Нужно, чтобы отличить «поля нет» от
     * «поле задано» и поймать спеку, где заданы обе: молча взять одну значило бы, что
     * половина написанного человеком не действует, и понять это было бы нечем. */
    int lan_one = 0, lan_many = 0;
    if (js_lit(&j, '{') != 0) die("spec: expected an object", NULL);
    js_ws(&j);
    while (*j.p && *j.p != '}') {
        char key[64];
        if (js_str(&j, key, sizeof(key)) != 0) die("spec: bad key", NULL);
        js_lit(&j, ':');
        if (!strcmp(key, "schema")) schema = js_num(&j);
        else if (!strcmp(key, "outputs")) parse_outputs(&j);
        else if (!strcmp(key, "channels")) parse_channels(&j);
        else if (!strcmp(key, "from_default")) str_array(&j, g_from_default, MAX_FROM, &g_from_default_n);
        else if (!strcmp(key, "lan_device")) {
            /* Одиночная форма — сокращение для списка из одного элемента, ровно как
             * `device` у выхода. Дальше по коду путь один. */
            js_str(&j, g_lan_dev[0], sizeof(g_lan_dev[0]));
            g_lan_dev_n = 1;
            lan_one = 1;
        }
        else if (!strcmp(key, "lan_devices")) {
            if (str_array(&j, g_lan_dev, MAX_LAN_DEV, &g_lan_dev_n) != 0)
                die("lan_devices: ожидался массив строк", NULL);
            lan_many = 1;
        }
        else if (!strcmp(key, "traceroute_hops")) { js_ws(&j); g_traceroute_hops = (*j.p == 't'); js_skip(&j); }
        else js_skip(&j);
        js_ws(&j);
        if (*j.p == ',') { j.p++; js_ws(&j); }
    }
    if (lan_one && lan_many)
        die("задано и lan_device, и lan_devices — оставьте одно", NULL);
    /* Пустой список — это «клиентов нет», а правило без условия «кто» забирает ВЕСЬ транзит
     * роутера, включая путь из интернета внутрь. Отказ дешевле такой находки на живом
     * роутере. */
    if (!g_lan_dev_n)
        die("lan_devices: пустой список — некому адресовать правила", NULL);
    for (size_t i = 0; i < g_lan_dev_n; i++) {
        /* Самая дорогая из проверок этого набора: имя уходит и в текст правил nftables, и
         * в командные строки popen у любой команды, читающей спеку. */
        if (!name_ok(g_lan_dev[i]))
            die("lan_devices: негодный состав имени (%s)", g_lan_dev[i]);
        for (size_t k = i + 1; k < g_lan_dev_n; k++)
            if (!strcmp(g_lan_dev[i], g_lan_dev[k]))
                die("lan_devices: устройство %s указано дважды", g_lan_dev[i]);
    }
    /* Клиентов по умолчанию описывают ЛИБО подсети, либо устройства. Оба сразу — не
     * обогащение, а противоречие, и молчаливого разрешения у него нет ни в одну сторону.
     *
     * Взять только подсети значило бы, что человек добавил tailscale0 и ничего не
     * изменилось: перечень интерфейсов стал бы дорогим украшением, а понять это было бы
     * нечем — отказа нет, правила есть, трафик идёт мимо. Взять и то, и другое (вторым
     * правилом по `iifname`) — хуже: `from_default` пишут, чтобы клиентов ОГРАНИЧИТЬ,
     * гостевая подсеть на том же мосту нарочно остаётся вне списка, и второе правило молча
     * забрало бы её тоже. То есть добавление интерфейса меняло бы смысл строки, написанной
     * когда-то совсем про другое.
     *
     * Отказ узкий намеренно: одно устройство рядом с `from_default` — это спека, написанная
     * до появления перечня, и она обязана значить ровно то, что значила. Отвергается только
     * НОВАЯ возможность, применённая вместе со старой. */
    if (g_from_default_n && g_lan_dev_n > 1)
        die("клиенты описаны дважды: и from_default, и несколько lan_devices. "
            "Уберите from_default — устройства опишут клиентов точнее", NULL);
    /* Refusing an unknown major is the whole point of having the field: guessing
     * would mean compiling a config we do not understand into firewall rules. */
    if (schema != 1) {
        fprintf(stderr, "steer: spec schema %ld is not supported (this build speaks 1)\n", schema);
        exit(2);
    }
    /* ЗДЕСЬ БЫЛО АВТООПРЕДЕЛЕНИЕ ПОДСЕТИ. Движок читал адрес lan_device через popen и
     * выводил из него `from_default`, когда тот не задан. Нужно это было ради одной вещи:
     * без `from_default` не появлялось правило DNS-перенаправления, клиенты уходили к
     * dnsmasq напрямую, и fake-IP молча не работал — «с роутера работает, с устройств нет»
     * при синтаксически целой цепочке.
     *
     * Теперь на тот же вопрос отвечает имя устройства, и отвечает точнее. Выведенная
     * подсеть была ДОГАДКОЙ: у tailscale0 адрес на роутере /32, и догадка давала «клиент
     * один, и это сам роутер»; у клиентов за вторым роутером в LAN адреса чужой подсети, и
     * догадка их теряла. `iifname` не гадает вовсе. Заодно из загрузки спеки ушёл запуск
     * оболочки — тот самый, через который имя устройства однажды уезжало в popen.
     *
     * Явный `from_default` при этом остался и значит ровно то же, что значил: он и выбирает
     * клиентов, а устройства тогда не участвуют (см. emit_from в steer.c). */
    /* Пустая спека законна, и отказ на ней запирал настройку наглухо: чтобы завести
     * канал, нужен выход, а сохранить выход без каналов движок не давал — тупик, из
     * которого нельзя выйти изнутри интерфейса.
     *
     * "Выходы есть, каналов нет" — это осмысленное состояние: steer настроен, но
     * ничего не направляет. Оно же и правильное начальное: угадывать, какие списки
     * человеку нужны, хуже, чем не направлять ничего. */
    for (size_t i = 0; i < g_ch_n; i++) {
        size_t k = 0;
        for (; k < g_out_n; k++) if (!strcmp(g_ch[i].out, g_out[k].name)) break;
        if (k == g_out_n) die("channel %s points at an output that does not exist", g_ch[i].name);
    }

    /* ---- защита от конфигураций, которые отрежут доступ к роутеру -----------
     *
     * Всё ниже — про ошибки, которые компилируются и применяются без единой
     * жалобы, а замечаются как «роутер пропал». Отказать на них дешевле, чем
     * потом объяснять, как чинить коробку, до которой уже не достучаться.
     * Каждая проверка отвечает на «что человек сделает случайно», а не на
     * «что запрещено стандартом». */
    for (size_t i = 0; i < g_out_n; i++) {
        struct output *o = &g_out[i];
        if (!out_has_device(o)) continue;

        /* Выход в локальное устройство — это петля: помеченный пакет получает маршрут
         * обратно в ту же сеть, откуда пришёл. Проверяется ВЕСЬ список: выход в
         * tailscale0, с которого мы забираем клиентов, закольцуется ровно так же, как
         * выход в br-lan, и отличать одно от другого нечем. */
        for (size_t d = 0; d < g_lan_dev_n; d++)
            if (!strcmp(o->device, g_lan_dev[d])) {
                char msg[160];
                snprintf(msg, sizeof(msg),
                         "выход %s ведёт в %s — это локальная сеть, трафик закольцуется",
                         o->name, g_lan_dev[d]);
                die("%s", msg);
            }

        /* Дубликат устройства внутри одного выхода делает failover бессмысленным:
         * второй кандидат ничем не отличается от первого. */
        for (size_t a = 0; a < o->devices_n; a++)
            for (size_t b = a + 1; b < o->devices_n; b++)
                if (!strcmp(o->devices[a], o->devices[b])) {
                    char msg[160];
                    snprintf(msg, sizeof(msg), "выход %s: устройство %s указано дважды",
                             o->name, o->devices[a]);
                    die("%s", msg);
                }
    }

    for (size_t i = 0; i < g_ch_n; i++) {
        struct channel *c = &g_ch[i];
        /* Выключенное правило не проверяем: оно не действует, а отказ применить спеку из-за
         * него означал бы, что выключить сломанное правило нельзя — только удалить. */
        if (c->disabled) continue;

        /* Адреса и MAC-и в одном «кому» — нельзя. nft не умеет «или» внутри правила, и
         * смешанный список пришлось бы либо разбивать на два правила (тогда порядок и
         * приоритет расходятся с тем, что человек написал), либо взять половину молча — а
         * тогда часть устройств правило не касается, и понять это нечем. Отказываем громко. */
        if (c->from_n > 1) {
            int macs = 0;
            for (size_t k = 0; k < c->from_n; k++) if (strchr(c->from[k], ':')) macs++;
            if (macs && macs != (int)c->from_n)
                die("канал %s: в «кому» смешаны адреса и MAC-адреса. nft не умеет «или» внутри "
                    "правила — разделите на два канала", c->name);
        }
        struct output *o = out_by_name(c->out);
        /* Через out_has_device, а не сравнением с OUT_INTERFACE: у выхода kind=vless
         * последствие ровно то же — весь трафик клиента, включая доступ к роутеру и
         * его DNS, уходит в туннель. Проверка, знающая про один вид выхода, молча
         * пропускала бы вторую половину случаев, а «защита от дурака», работающая
         * через раз, хуже отсутствующей: на неё рассчитывают. */
        if (!o || !out_has_device(o)) continue;

        /* Канал `any` в туннель уводит ВЕСЬ трафик клиентов, включая их доступ к
         * самому роутеру и к его DNS. Это законная конфигурация, но только
         * осознанная: без явного признака она почти всегда описка вместо списка. */
        if (c->any && !c->prefixes_n && !c->domains_n && !c->allow_all)
            die("канал %s забирает ВЕСЬ трафик в туннель. Если это правда нужно, "
                "добавьте \"allow_all\": true — иначе выберите список", c->name);
    }
}

/* ---- mark/table registry -------------------------------------------------- */
/* Persisted, because an output must keep its mark across restarts: a reboot that
 * reshuffles marks leaves stale `ip rule` entries pointing at the wrong table,
 * and the symptom is traffic silently taking someone else's path. */
static void rt_tables_write(void);

void registry_assign(void) {
    char path[512];
    snprintf(path, sizeof(path), "%s/registry", g_state_dir);
    FILE *f = fopen(path, "r");
    if (f) {
        char name[32];
        unsigned mark;
        int table;
        while (fscanf(f, "%31s %x %d\n", name, &mark, &table) == 3)
            for (size_t i = 0; i < g_out_n; i++)
                if (!strcmp(g_out[i].name, name) && g_out[i].kind != OUT_DIRECT) {
                    g_out[i].mark = mark;
                    g_out[i].table = table;
                }
        fclose(f);
    }
    unsigned next_bit = 0;
    for (size_t i = 0; i < g_out_n; i++)
        if (g_out[i].mark) {
            unsigned b = 0;
            while ((MARK_BASE << b) < g_out[i].mark && b < STEER_MARK_BITS) b++;
            if (b + 1 > next_bit) next_bit = b + 1;
        }
    for (size_t i = 0; i < g_out_n; i++) {
        if (g_out[i].kind == OUT_DIRECT || g_out[i].mark) continue;
        if (next_bit >= STEER_MARK_BITS)
            die("out of mark bits for output %s", g_out[i].name);
        g_out[i].mark = MARK_BASE << next_bit;
        g_out[i].table = TABLE_BASE + (int)next_bit;
        next_bit++;
    }
    /* Прежде чем писать — сравнить с тем, что уже на диске. registry_assign
     * зовут все подкоманды, включая status, который интерфейс опрашивает каждые
     * пять секунд: безусловная перезапись — это ~17 тысяч записей файла в сутки
     * с неизменным содержимым. Сравнивается будущий текст целиком, а не «были ли
     * новые назначения»: перезапись заодно вычищает строки исчезнувших выходов,
     * и пропускать её можно только когда файл уже дословно совпадает. */
    char want[1024]; /* 16 выходов по ≤53 байта строки — влезает с запасом */
    size_t wn = 0;
    for (size_t i = 0; i < g_out_n && wn < sizeof(want); i++)
        if (g_out[i].kind != OUT_DIRECT) {
            int w = snprintf(want + wn, sizeof(want) - wn, "%s %x %d\n",
                             g_out[i].name, g_out[i].mark, g_out[i].table);
            if (w < 0 || (size_t)w >= sizeof(want) - wn) break; /* не бывает, но не рвём буфер */
            wn += (size_t)w;
        }
    f = fopen(path, "r");
    if (f) {
        char have[sizeof(want) + 1];
        size_t hn = fread(have, 1, sizeof(have), f);
        fclose(f);
        if (hn == wn && memcmp(have, want, wn) == 0) return;
    }
    mkdir(g_state_dir, 0755);
    f = fopen(path, "w");
    if (!f) return;             /* best effort: apply still works, next boot re-assigns */
    fwrite(want, 1, wn, f);
    fclose(f);
    rt_tables_write();
}

/* Объявить имена таблиц маршрутизации системе.
 *
 * ЗАЧЕМ. Номера таблиц (300, 301, ...) не говорят ничего: `ip route show table 300` требует
 * помнить, какой выход это был, а `ip rule show` печатает номер. iproute2 умеет имена —
 * для этого и существует /etc/iproute2/rt_tables.d, — и тогда диагностика становится
 * обычной: `ip route show table steer_vpn`. Проверено на живом роутере (10.8.1.87,
 * OpenWrt 25.12 с ip-full): имя из rt_tables.d принимается и в add, и в show.
 *
 * ПОЧЕМУ КАТАЛОГ, А НЕ САМ rt_tables. Файл rt_tables принадлежит пакету iproute2;
 * дописывать в чужой файл значило бы драться с его обновлением. Каталог .d для этого и
 * заведён.
 *
 * ПОЧЕМУ СРАВНЕНИЕ ПЕРЕД ЗАПИСЬЮ. registry_assign зовут все подкоманды, включая status,
 * который интерфейс опрашивает каждые пять секунд, — это та же причина, по которой не
 * перезаписывается сам реестр (см. выше): безусловная запись означала бы ~17 тысяч записей
 * файла в сутки с неизменным содержимым.
 *
 * Отказ здесь ничего не ломает: имена — удобство диагностики, номера работают и без них.
 * Поэтому молча, без предупреждений: на busybox-ip имён нет вовсе, и жаловаться было бы не
 * на что. */
static void rt_tables_write(void) {
    char path[512];
    snprintf(path, sizeof(path), "%s/steer.conf", g_rt_tables_d);

    char want[1024];
    size_t wn = 0;
    for (size_t i = 0; i < g_out_n && wn < sizeof(want); i++) {
        if (g_out[i].kind == OUT_DIRECT || !g_out[i].table) continue;
        /* Имя с приставкой: таблица принадлежит выходу, но пространство имён общее для всей
         * коробки, и «vpn» там заняли бы и mwan3, и человек руками. */
        int w = snprintf(want + wn, sizeof(want) - wn, "%d steer_%s\n",
                         g_out[i].table, g_out[i].name);
        if (w < 0 || (size_t)w >= sizeof(want) - wn) break;
        wn += (size_t)w;
    }

    FILE *f = fopen(path, "r");
    if (f) {
        char have[sizeof(want) + 1];
        size_t hn = fread(have, 1, sizeof(have), f);
        fclose(f);
        if (hn == wn && memcmp(have, want, wn) == 0) return;
    }
    /* Каталога может не быть: iproute2 создаёт его не всегда, а на busybox-сборке его нет
     * вовсе. mkdir по одному уровню — родителя (/etc/iproute2) тоже может не быть. */
    char parent[512];
    snprintf(parent, sizeof(parent), "%s", g_rt_tables_d);
    char *slash = strrchr(parent, '/');
    if (slash && slash != parent) { *slash = '\0'; mkdir(parent, 0755); }
    mkdir(g_rt_tables_d, 0755);
    f = fopen(path, "w");
    if (!f) return;
    fwrite(want, 1, wn, f);
    fclose(f);
}

struct output *out_by_name(const char *n) {
    for (size_t i = 0; i < g_out_n; i++) if (!strcmp(g_out[i].name, n)) return &g_out[i];
    return NULL;
}

/* Порядок перебора узлов подписки. Объяснение — у объявления в spec.h. */
size_t out_node_list(const struct output *o, size_t usable, int *dst, size_t max) {
    size_t n = 0;
    if (!o->nodes_n) {
        /* Кандидатов не выбирали — кандидаты все, в порядке подписки. Это прежнее
         * поведение `node: -1` и умолчание, которое рекомендует интерфейс: номер узла
         * меняется при обновлении подписки, а проверка находит живой сама. */
        for (size_t i = 0; i < usable && n < max; i++) dst[n++] = (int)i;
        return n;
    }
    for (size_t i = 0; i < o->nodes_n && n < max; i++)
        if (o->nodes[i] >= 0 && (size_t)o->nodes[i] < usable) dst[n++] = o->nodes[i];
    return n;
}

/* Назван ли узел человеком. Объяснение — у объявления в spec.h. */
int out_node_named(const struct output *o) {
    return o->nodes_n == 1;
}


/* ---- подъём выхода vless: ход перебора узлов --------------------------------------------
 *
 * Зачем это вообще есть и почему устаревание обезврежено двумя разными способами — в шапке
 * объявлений в spec.h. Здесь только формат и его разбор.
 *
 * Файл: одна строка «состояние узел всего pid время». Позиционно, а не ключами: строку читают
 * ровно два места в этом же дереве, а лишний разборщик на роутере — лишние байты. Лежит рядом
 * с реестром меток, в state_dir: на OpenWrt это tmpfs, поэтому перебор узлов не пишет во флеш
 * и не переживает перезагрузку — ровно то, чего от него и надо.
 */
#define PROBE_FAILED_TTL 120   /* «ни один не ответил» верно, пока свежо: procd пробует снова
                                * каждые пять секунд, значит запись старше двух минут означает,
                                * что никто больше не пробует. */

static void probe_path(char *buf, size_t n, const char *out_name) {
    snprintf(buf, n, "%s/probe-%.32s", g_state_dir, out_name);
}

void probe_report(const char *out_name, enum probe_state st, int node, int total) {
    char path[256];
    probe_path(path, sizeof(path), out_name);
    mkdir(g_state_dir, 0755);
    FILE *f = fopen(path, "w");
    if (!f) return;
    fprintf(f, "%s %d %d %ld %ld\n",
            st == PROBE_RUNNING ? "probing" : "failed",
            node, total, (long)getpid(), (long)time(NULL));
    fclose(f);
}

void probe_clear(const char *out_name) {
    char path[256];
    probe_path(path, sizeof(path), out_name);
    unlink(path);
}

struct probe_status probe_read(const char *out_name) {
    struct probe_status out = { PROBE_NONE, 0, 0 };
    char path[256];
    probe_path(path, sizeof(path), out_name);
    FILE *f = fopen(path, "r");
    if (!f) return out;
    char word[16] = "";
    int node = 0, total = 0;
    long pid = 0, at = 0;
    int got = fscanf(f, "%15s %d %d %ld %ld", word, &node, &total, &pid, &at);
    fclose(f);
    if (got != 5) return out;

    if (!strcmp(word, "probing")) {
        /* Верно, только пока жив написавший. Иначе перебор, прерванный на середине (движок
         * остановили, процесс убили), навсегда оставлял бы на экране «проверяю узлы» — то
         * есть обещание работы, которой никто не делает. */
        char proc[64];
        snprintf(proc, sizeof(proc), "/proc/%ld", pid);
        if (pid <= 0 || access(proc, F_OK) != 0) return out;
        out.state = PROBE_RUNNING;
        out.node = node;
        out.total = total;
        return out;
    }
    if (!strcmp(word, "failed")) {
        /* А это переживает смерть процесса намеренно: клиент выходит с кодом 1 именно потому,
         * что ни один узел не ответил, и приговор нужен ПОСЛЕ него. Живёт, пока свеж. */
        long now = (long)time(NULL);
        if (at <= 0 || now - at > PROBE_FAILED_TTL) return out;
        out.state = PROBE_FAILED;
        out.node = 0;
        out.total = total;
        return out;
    }
    return out;
}
