/* steer — compile a channel spec into nftables rules and policy routing.
 *
 * Own table, not an fw4 include. Three reasons, all learned from splify:
 *   * an fw4 reload REPLACES table inet fw4, which drains every set living inside
 *     it — a separate `table inet steer` simply survives;
 *   * one `nft -f` is atomic: either the whole channel set applies or nothing does,
 *     with no window where a rule references a set that is not there yet;
 *   * uninstall is `nft delete table inet steer`, and nothing of ours can break
 *     someone else's firewall by being malformed.
 *
 * Precedence is expressed with `return` rather than a "mark is still zero" guard:
 * inside our own chain the first matching rule wins by construction, which is
 * exactly the ordered-channels semantics the spec promises.
 */
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <errno.h>
#include <unistd.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <fcntl.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/time.h>

#include "spec.h"

int dnsd_main(int argc, char **argv);
int cmd_failover(const char *spec, int verbose);
/* Клиент VLESS есть только в расширенной сборке (steer-extended). В базовой команда
 * отвечает внятным отказом, а не отсутствует: «неизвестная команда» на steer vless
 * заставила бы искать опечатку вместо того, чтобы поставить нужный пакет. */
#ifdef STEER_EXTENDED
int cmd_vless(const char *spec_path, const char *out_name);
int cmd_vless_nodes(const char *spec_path, const char *out_name);
int cmd_vless_probe(const char *spec_path, const char *out_name, int node, int timeout_s);
#else
static int no_vless(void) {
    fprintf(stderr, "steer: клиент VLESS в этой сборке отсутствует — "
                    "нужен пакет steer-extended\n");
    return 2;
}
static int cmd_vless(const char *spec_path, const char *out_name) {
    (void)spec_path; (void)out_name;
    return no_vless();
}
static int cmd_vless_nodes(const char *spec_path, const char *out_name) {
    (void)spec_path; (void)out_name;
    return no_vless();
}
static int cmd_vless_probe(const char *spec_path, const char *out_name,
                           int node, int timeout_s) {
    (void)spec_path; (void)out_name; (void)node; (void)timeout_s;
    return no_vless();
}
#endif
int aggregate_main(int argc, char **argv);

/* ---- coalescing: one interface, at most two sets ---------------------------
 *
 * Channels are how a configuration is WRITTEN — a list, who it applies to, where it
 * goes. They are not how it has to be EXECUTED. Emitting one set and one rule per
 * channel means a box with a dozen enabled lists walks a dozen rules for every
 * packet and holds a dozen sets, when all of them lead to the same tunnel.
 *
 * So channels that agree on everything that matters to the kernel — the output, the
 * kind of list, the clients, and (for domains) the resolver mode — are merged into
 * one set and one rule. With one tunnel and every list enabled that is 2 sets and 2
 * rules instead of a dozen each: addresses and domains, because those two reach a
 * set by different routes and cannot share one.
 *
 * Expressiveness is not lost, only deduplicated: a channel that differs in `from` or
 * mode still gets its own group, so "only the TV, only this list" remains sayable.
 */
struct group {
    char name[64];              /* <output>_ip | <output>_dom, and the set name */
    const char *out;
    int domains;                /* addresses otherwise */
    int realip;
    const char (*from)[64];
    size_t from_n;
    /* ТОЛЬКО адресные файлы: их элементы уходят в набор при компиляции. Доменные читает
     * резолвер сам, из спеки, поэтому здесь их держать незачем — а держали, и из-за этого
     * группа не могла быть смешанной. */
    const char *files[MAX_CHANNELS * MAX_FILES];
    size_t files_n;
    /* Сколько доменных списков в группе. Нужно только чтобы сказать это человеку в status:
     * набор у них общий, а вот «сколько списков» он спрашивает про правило. */
    size_t dfiles_n;
    /* Which channels fed it — reported so a counter still has names behind it. */
    const char *members[MAX_CHANNELS];
    size_t members_n;
};

static struct group g_grp[MAX_CHANNELS];
static size_t g_grp_n;

static int same_from(const struct channel *c, const struct group *g) {
    const char (*cf)[64] = c->from_n ? c->from : g_from_default;
    size_t cn = c->from_n ? c->from_n : g_from_default_n;
    if (cn != g->from_n) return 0;
    for (size_t i = 0; i < cn; i++)
        if (strcmp(cf[i], g->from[i]) != 0) return 0;
    return 1;
}

/* Built once per run, in spec order: the first channel of a group fixes its place, so
 * "first match wins" still reads off the spec. */
static void build_groups(void) {
    g_grp_n = 0;
    for (size_t i = 0; i < g_ch_n; i++) {
        const struct channel *c = &g_ch[i];
        /* Выключенное правило не превращается ни в набор, ни в правило — то есть его нет в
         * ядре так же, как если бы его не было в спеке. Именно этого от выключателя и ждут:
         * «выключено» обязано значить «не действует», а не «действует тише». */
        if (c->disabled) continue;
        int domains = c->domains_n > 0;
        size_t k = 0;
        for (; k < g_grp_n; k++) {
            struct group *g = &g_grp[k];
            if (strcmp(g->out, c->out) != 0) continue;
            /* Вид больше НЕ разделяет группы: адресное и доменное правило одного сервиса,
             * ведущие в один outbound для одних клиентов, — это одно правило и один набор.
             * Разделение по виду было следствием запрета смешивать, а не требованием ядра. */
            if (domains && g->domains && g->realip != c->realip) continue;
            if (!same_from(c, g)) continue;
            break;
        }
        if (k == g_grp_n) {
            struct group *g = &g_grp[g_grp_n++];
            memset(g, 0, sizeof(*g));
            g->out = c->out;
            g->domains = 0;
            g->realip = c->realip;
            g->from = c->from_n ? c->from : g_from_default;
            g->from_n = c->from_n ? c->from_n : g_from_default_n;
            /* Имя ставим предварительно, окончательное — ниже: домены могут прийти вторым
             * правилом, и тогда набор обязан называться _dom, иначе резолвер его не найдёт
             * (он вычисляет имя сам, по тому же правилу). */
            snprintf(g->name, sizeof(g->name), "%.24s_%s", c->out, domains ? "dom" : "ip");
            /* An `any` channel has no set: it claims everything from those clients. */
            if (c->any && !c->prefixes_n && !c->domains_n)
                snprintf(g->name, sizeof(g->name), "%.24s_all", c->out);
        }
        struct group *g = &g_grp[k];
        /* Домены только помечаем: их файлы читает резолвер. Режим берём у первого доменного
         * правила в группе — у адресного его нет вовсе, и брать оттуда нечего. */
        if (domains) {
            if (!g->domains) g->realip = c->realip;
            g->domains = 1;
            g->dfiles_n += c->domains_n;
        }
        for (size_t f = 0; f < c->prefixes_n &&
                           g->files_n < (sizeof(g->files) / sizeof(g->files[0])); f++)
            g->files[g->files_n++] = c->prefixes_files[f];
        if (g->members_n < MAX_CHANNELS) g->members[g->members_n++] = c->name;
    }
    /* Окончательные имена. Группа с доменами — всегда _dom, потому что имя набора резолвер
     * вычисляет тем же правилом и по-другому его не найдёт. Группы `any` не трогаем: у них
     * набора нет вовсе. */
    for (size_t i = 0; i < g_grp_n; i++) {
        struct group *g = &g_grp[i];
        if (!g->files_n && !g->domains) continue;
        snprintf(g->name, sizeof(g->name), "%.24s_%s", g->out, g->domains ? "dom" : "ip");
    }
}

static int has_domains(void) {
    for (size_t i = 0; i < g_grp_n; i++) if (g_grp[i].domains) return 1;
    return 0;
}

static int has_fakeip(void) {
    for (size_t i = 0; i < g_grp_n; i++)
        if (g_grp[i].domains && !g_grp[i].realip) return 1;
    return 0;
}

/* Адрес это или MAC. Различаем по двоеточию: у IPv4 его нет, у MAC их пять.
 *
 * Зачем MAC вообще. «Только этот телевизор» — обычная просьба, а адрес у него меняется: DHCP
 * выдаёт другой после перезагрузки, и правило начинает касаться не того устройства. MAC
 * привязан к железу и живёт, пока живёт устройство.
 *
 * Чего он НЕ умеет: MAC виден только у соседа по L2. За вторым роутером или повторителем в
 * пакете будет MAC этого роутера, а не устройства, и правило накроет всех, кто за ним. Это
 * свойство сети, а не наша недоделка, но сказать об этом обязаны — в интерфейсе есть подсказка. */
static int is_mac(const char *s) {
    int colons = 0;
    for (const char *p = s; *p; p++) {
        if (*p == ':') { colons++; continue; }
        if (!((*p >= '0' && *p <= '9') || (*p >= 'a' && *p <= 'f') || (*p >= 'A' && *p <= 'F')))
            return 0;
    }
    return colons == 5;
}

/* «Кто» одной или двумя проверками.
 *
 * Адреса и MAC-и уходят РАЗНЫМИ выражениями, объединёнными по И... нет — по ИЛИ быть не может:
 * nft не умеет «или» внутри правила. Поэтому смешивать их в одном правиле нельзя, и это
 * проверяется при загрузке спеки: правило либо про адреса, либо про MAC-и. Молча взять только
 * половину значило бы, что часть устройств правило не касается, и понять это было бы нечем. */
static void emit_who(FILE *f, const struct group *g, int reverse) {
    if (!g->from_n) return;
    int mac = is_mac(g->from[0]);
    if (mac) fprintf(f, "ether %s { ", reverse ? "daddr" : "saddr");
    else fprintf(f, "ip %s { ", reverse ? "daddr" : "saddr");
    for (size_t i = 0; i < g->from_n; i++) fprintf(f, "%s%s", i ? ", " : "", g->from[i]);
    fprintf(f, " } ");
}

static void emit_from(FILE *f, const struct group *g) { emit_who(f, g, 0); }

/* То же «кто», но на встречном пути: там наш клиент — это ПОЛУЧАТЕЛЬ. */
static void emit_to(FILE *f, const struct group *g) { emit_who(f, g, 1); }

/* Elements come straight from the list files: the fitter (steer-aggregate) has
 * already decided what fits, and re-parsing them here would only add a second place
 * for the two to disagree. */
/* Похожа ли строка на адрес или префикс IPv4. Только форма, без проверки диапазонов:
 * нам надо отличить «1.2.3.0/24» от «amazon.com», а не проверять корректность маски —
 * второе сделает nft, и его сообщение об одном плохом элементе понятно. */
static int looks_like_addr(const char *s) {
    int digits = 0, dots = 0, slash = 0;
    for (const char *p = s; *p; p++) {
        if (*p >= '0' && *p <= '9') { digits++; continue; }
        if (*p == '.') { dots++; continue; }
        if (*p == '/') { slash++; continue; }
        return 0;                       /* буква, дефис, двоеточие — это не IPv4 */
    }
    return digits > 0 && dots == 3 && slash <= 1;
}

/* Прочитать список и посчитать, сколько строк в нём НЕ адреса.
 *
 * Отдельным проходом, до генерации: сообщение об ошибке должно появиться раньше, чем
 * мы начнём собирать набор, и раньше, чем что-либо будет применено. */
static void count_list(const char *path, size_t *total, size_t *bad,
                       char *first_bad, size_t first_bad_n, size_t *first_bad_line) {
    FILE *in = fopen(path, "r");
    if (!in) die("%s: cannot read a channel's list", path);
    char line[512];
    size_t lineno = 0;
    *total = *bad = 0;
    if (first_bad_n) first_bad[0] = '\0';
    while (fgets(line, sizeof(line), in)) {
        lineno++;
        char *nl = strpbrk(line, "\r\n");
        if (nl) *nl = '\0';
        char *p = line;
        while (*p == ' ' || *p == '\t') p++;
        if (!*p || *p == '#' || *p == ';') continue;
        (*total)++;
        if (looks_like_addr(p)) continue;
        if (!(*bad)++ && first_bad_n) {
            /* Точность в формате, а не только размер буфера: строка из файла бывает
             * длиннее образца, и обрезать её надо явно, а не «как получится». */
            snprintf(first_bad, first_bad_n, "%.100s", p);
            if (first_bad_line) *first_bad_line = lineno;
        }
    }
    fclose(in);
}

/* Проверить списки адресных каналов ДО того, как что-то применится.
 *
 * Зачем это здесь, а не «пусть nft разберётся». nft разбирается плохо: один доменный
 * список, подключённый как адресный, даёт «syntax error, unexpected string» с указанием
 * на середину строки в восемь тысяч символов — и отвергает НАБОР ЦЕЛИКОМ, то есть вся
 * маршрутизация остаётся на прежних правилах, а человек видит, что его выбор не подействовал,
 * без единого намёка на причину. Так и случилось: список «Хостинги и CDN» у издателя лежит
 * в адресных категориях и обещает 5444 подсети, а внутри 250 доменов и ни одного адреса.
 *
 * Поэтому разделяем два случая, и это не педантизм:
 *   весь список не адреса  — это НЕ ТОТ список, отказываемся и говорим, что делать;
 *   несколько строк плохие — это мусор в файле, предупреждаем и пропускаем их, потому что
 *                            ронять канал из 19 тысяч префиксов из-за одной строки хуже. */
static void check_address_lists(void) {
    for (size_t i = 0; i < g_grp_n; i++) {
        struct group *g = &g_grp[i];
        /* Раньше здесь стоял пропуск доменных групп целиком. Теперь у группы могут быть и
         * адресные файлы: пропускать её значило бы не заметить пустой или сломанный список. */
        for (size_t k = 0; k < g->files_n; k++) {
            size_t total = 0, bad = 0, bad_line = 0;
            char sample[128];
            count_list(g->files[k], &total, &bad, sample, sizeof(sample), &bad_line);
            if (!total) {
                fprintf(stderr, "steer: %s: список пуст — канал «%s» ничего не поймает\n",
                        g->files[k], g->members_n ? g->members[0] : g->name);
                continue;
            }
            if (bad == total) {
                /* die принимает одну подстановку, поэтому сообщение собирается здесь.
                 * Собрать его надо целиком: половина сведений («не тот список») без второй
                 * («какой именно файл и что в нём») не даёт человеку сделать шаг. */
                static char msg[1024];
                /* Называем КАНАЛ из спеки, а не имя группы: человек выбирал канал, а
                 * «vpn_ip» — наше внутреннее имя набора, по нему в интерфейсе искать
                 * нечего. Каналов в группе может быть несколько, поэтому берём первый и
                 * говорим, сколько их всего. */
                char who[128];
                if (g->members_n > 1)
                    snprintf(who, sizeof(who), "%.60s (и ещё %zu в том же наборе)",
                             g->members[0], g->members_n - 1);
                else
                    snprintf(who, sizeof(who), "%.60s",
                             g->members_n ? g->members[0] : g->name);
                snprintf(msg, sizeof(msg),
                         "%.400s: это доменный список — %zu имён, адресов нет. Канал «%s» "
                         "адресный, ему нужны подсети. Подключите список как доменный "
                         "или выберите другой. Первая строка: «%.100s»",
                         g->files[k], total, who, sample);
                die("%s", msg);
            }
            if (bad)
                fprintf(stderr, "steer: %s: строк не-адресов %zu из %zu, пропускаю их "
                                "(первая — %zu: «%s»)\n",
                        g->files[k], bad, total, bad_line, sample);
        }
    }
}

static size_t emit_elements(FILE *f, const char *path, size_t already) {
    FILE *in = fopen(path, "r");
    if (!in) die("%s: cannot read a channel's list", path);
    /* 512, а не 128: строка длиннее просто обрезалась бы посередине, и в набор уехал бы
     * обломок адреса — то есть тихо не тот адрес. */
    char line[512];
    size_t n = already;
    while (fgets(line, sizeof(line), in)) {
        char *nl = strpbrk(line, "\r\n");
        if (nl) *nl = '\0';
        char *p = line;
        while (*p == ' ' || *p == '\t') p++;
        if (!*p || *p == '#' || *p == ';') continue;
        /* Не-адреса пропускаем молча: про них уже сказал check_address_lists, а nft на
         * них отвергает ВЕСЬ набор, а не одну строку. */
        if (!looks_like_addr(p)) continue;
        fprintf(f, "%s%s", n ? ", " : "", p);
        n++;
    }
    fclose(in);
    return n - already;
}

/* ---- перенос счётчиков через apply ------------------------------------------
 *
 * `apply` сносит таблицу и загружает новую одной транзакцией, а счётчики живут в правилах —
 * значит каждый apply обнулял их. Само по себе это выглядело безобидно, но обновление списков
 * из splify2 вызывает apply по расписанию, раз в сутки в пять утра. То есть объёмы в
 * интерфейсе всегда были «с пяти утра», нигде об этом не сказано, и вопрос «сколько ушло за
 * сутки» ответа не имел. Замер: 4 090 141 байт до apply, 0 после.
 *
 * Поэтому перед генерацией читаем то, что накопилось, и вписываем в новые правила: nft
 * принимает `counter packets N bytes M` на входе — ровно в том виде, в каком сам печатает.
 *
 * Переносим ПО ИМЕНИ КАНАЛА, а не по номеру правила: правила перетасовываются при любой
 * правке спеки, и перенос по позиции приписал бы чужой трафик. Канал, которого в новой спеке
 * нет, свой счётчик теряет — это и правильно, его больше не существует.
 */
#define CTR_MAX MAX_CHANNELS
struct ctr { char name[32]; unsigned long pkts, bytes; };
static struct ctr g_ctr_up[CTR_MAX], g_ctr_down[CTR_MAX];
static size_t g_ctr_up_n, g_ctr_down_n;

/* Разбор вывода nft — ОДИН на apply и status. Раздельные разошлись бы в понимании одного и
 * того же текста, а расхождение здесь означало бы, что перенесённое и показанное — разные
 * числа. */
static void counters_load(void) {
    g_ctr_up_n = g_ctr_down_n = 0;
    /* Обе цепочки за один вызов: раздельные popen дали бы счётчики, снятые в разные моменты,
     * и «отдано больше, чем скачано» на глазах у человека объяснялось бы не маршрутизацией,
     * а нашей ленью. */
    FILE *nft = popen("nft -a list chain inet steer prerouting_mark 2>/dev/null; "
                      "nft -a list chain inet steer postrouting_down 2>/dev/null", "r");
    if (!nft) return;
    char line[1024];
    while (fgets(line, sizeof(line), nft)) {
        /* Встречный вид проверяется первым: «steer:» нашлось бы и внутри «steer-down:». */
        int down = 0;
        char *c = strstr(line, "comment \"steer-down:");
        if (c) { c += strlen("comment \"steer-down:"); down = 1; }
        else {
            c = strstr(line, "comment \"steer:");
            if (!c) continue;
            c += strlen("comment \"steer:");
        }
        char *e = strchr(c, '"');
        if (!e) continue;
        *e = '\0';
        unsigned long p = 0, b = 0;
        char *pc = strstr(line, "packets ");
        if (pc) sscanf(pc, "packets %lu bytes %lu", &p, &b);
        struct ctr *arr = down ? g_ctr_down : g_ctr_up;
        size_t *n = down ? &g_ctr_down_n : &g_ctr_up_n;
        if (*n < CTR_MAX) {
            snprintf(arr[*n].name, sizeof(arr[*n].name), "%s", c);
            arr[*n].pkts = p;
            arr[*n].bytes = b;
            (*n)++;
        }
    }
    pclose(nft);
}

/* Найти прежнее значение. -1 — канала в ядре не было (первый apply или новый канал). */
static int counter_find(const char *name, int down, unsigned long *p, unsigned long *b) {
    const struct ctr *arr = down ? g_ctr_down : g_ctr_up;
    size_t n = down ? g_ctr_down_n : g_ctr_up_n;
    for (size_t i = 0; i < n; i++)
        if (!strcmp(arr[i].name, name)) { *p = arr[i].pkts; *b = arr[i].bytes; return 0; }
    return -1;
}

/* `counter` с прежним значением, если оно есть. Нули печатаем коротким `counter`: так вывод
 * `--dry-run` на чистой машине остаётся тем же текстом, что и раньше. */
static void emit_counter(FILE *f, const char *name, int down) {
    unsigned long p = 0, b = 0;
    if (counter_find(name, down, &p, &b) == 0 && (p || b))
        fprintf(f, "counter packets %lu bytes %lu ", p, b);
    else
        fprintf(f, "counter ");
}

static void generate(FILE *f) {
    fprintf(f, "table inet steer {\n");
    for (size_t i = 0; i < g_grp_n; i++) {
        struct group *g = &g_grp[i];
        if (!g->files_n && !g->domains) continue;      /* an `any` group has no set */
        if (g->domains) {
            /* timeout — из-за резолвера: он кладёт адреса с TTL ответа, и адрес, который CDN
             * перестал отдавать, истекает сам, а не копится вечно.
             *
             * Адресные списки в ТОЙ ЖЕ группе печатаются элементами без timeout, то есть
             * остаются навсегда. Что набор держит и те, и другие — проверено на живом nft, а
             * не выведено: элемент без своего timeout в наборе с этим флагом постоянный. Это
             * и позволяет одному правилу быть про сервис, а не про вид списка. */
            fprintf(f, "    set %s {\n        type ipv4_addr\n"
                       "        flags interval,timeout\n        auto-merge\n", g->name);
            if (g->files_n) {
                fprintf(f, "        elements = { ");
                size_t written = 0;
                for (size_t k = 0; k < g->files_n; k++)
                    written += emit_elements(f, g->files[k], written);
                fprintf(f, " }\n");
            }
            fprintf(f, "    }\n");
        } else {
            /* auto-merge because several lists in one group WILL overlap — an address
             * list and a service list cover the same hosting — and folding duplicates
             * in the kernel is cheaper than rewriting the text. */
            fprintf(f, "    set %s {\n        type ipv4_addr\n"
                       "        flags interval\n        auto-merge\n", g->name);
            fprintf(f, "        elements = { ");
            size_t written = 0;
            for (size_t k = 0; k < g->files_n; k++)
                written += emit_elements(f, g->files[k], written);
            fprintf(f, " }\n    }\n");
        }
    }

    /* mangle + 1: the mark must exist before the routing decision, and staying one
     * step after mangle leaves room for anything that legitimately wants to run first. */
    fprintf(f, "    chain prerouting_mark {\n"
               "        type filter hook prerouting priority mangle + 1; policy accept;\n");
    for (size_t i = 0; i < g_grp_n; i++) {
        struct group *g = &g_grp[i];
        struct output *o = out_by_name(g->out);
        if (!o) die("channel group %s points at a missing output", g->name);
        fprintf(f, "        ");
        emit_from(f, g);
        if (g->files_n || g->domains) fprintf(f, "ip daddr @%s ", g->name);
        if (out_has_device(o)) fprintf(f, "meta mark set 0x%08x ", o->mark);
        /* `return` and not `accept`: it ends OUR chain, letting the rest of the
         * firewall proceed, while making the first matching group the winner. */
        emit_counter(f, g->name, 0);
        fprintf(f, "return comment \"steer:%s\"\n", g->name);
    }
    fprintf(f, "    }\n");

    /* Встречный путь — только чтобы его было ЧЕМ ПОСЧИТАТЬ. Метку здесь не ставим и
     * решений не принимаем: маршрут ответным пакетам не нужен, их ведёт conntrack.
     *
     * Зачем вообще. Счётчик в prerouting_mark стоит на правиле, ставящем метку, а метка
     * ставится по пути «из локальной сети наружу»: скачанное под `ip saddr <сеть>` не
     * подпадает и в него не попадает никогда. На живом роутере это выглядело как 4,3 МБ при
     * скачанных 223 МБ — человек видел одни подтверждения и не мог понять, куда ушёл
     * трафик. Объём по устройству выхода отвечал на «сколько всего», но не «сколько по
     * этому каналу».
     *
     * ПОЧЕМУ POSTROUTING, а не prerouting. Тут я ошибся и был поправлен опытом
     * (build/natorder.sh), поэтому вывод записан числами. Для доменного канала в наборе
     * лежат fake-IP, и у ответного пакета адрес источника обязан быть переведён обратно в
     * fake-IP, чтобы совпасть с набором. Этот обратный перевод — манипуляция ИСТОЧНИКОМ, а
     * она делается в postrouting: в prerouting в saddr стоит настоящий адрес сервера, каким
     * бы приоритет ни был. Опыт: мегабайт через fake-IP дал в prerouting (и на месте метки,
     * и после dstnat) ровно нуль, а в postrouting — 42 пакета и 1 050 973 байта.
     *
     * Адресному каналу postrouting тоже годится: там адрес источника настоящий с обеих
     * сторон и переводить его нечего — тот же мегабайт, те же 42 пакета. Поэтому одна
     * цепочка покрывает оба вида, и разделять их не нужно.
     *
     * Правило `counter` без вердикта: цепочка ничего не решает, policy accept, и на пути
     * скачивания это один поиск по набору на пакет. */
    fprintf(f, "\n    chain postrouting_down {\n"
               "        type filter hook postrouting priority srcnat + 10; policy accept;\n");
    for (size_t i = 0; i < g_grp_n; i++) {
        struct group *g = &g_grp[i];
        fprintf(f, "        ");
        emit_to(f, g);
        if (g->files_n || g->domains) fprintf(f, "ip saddr @%s ", g->name);
        emit_counter(f, g->name, 1);
        fprintf(f, "comment \"steer-down:%s\"\n", g->name);
    }
    fprintf(f, "    }\n");

    if (has_domains()) {
        if (has_fakeip()) {
            fprintf(f, "\n    map fakeip { type ipv4_addr : ipv4_addr; }\n");
            fprintf(f, "    chain prerouting_dnat {\n"
                       "        type nat hook prerouting priority dstnat; policy accept;\n"
                       "        ip daddr 198.18.0.0/15 dnat ip to ip daddr map @fakeip\n"
                       "    }\n");
        }
        /* Make traceroute show the REAL intermediate routers while the destination
         * stays the fake address.
         *
         * ONLY WORKS WHEN THE OUTPUT DOES NOT MASQUERADE — measured: with NAT on, 13
         * errors hit this rule, 0 reached the accept for untracked traffic, and every
         * hop after the first became an asterisk. With NAT the error is addressed to
         * the ROUTER, so only conntrack knows which client it belongs to; untracking
         * removes exactly that knowledge. Tracking is the delivery mechanism and being
         * tracked is what rewrites the source — one does not come without the other.
         *
         * Scope is just time-exceeded (type 11): dest-unreachable must stay tracked or
         * path-MTU discovery breaks, which trades a cosmetic win for broken transfers. */
        if (g_traceroute_hops) {
            fprintf(f, "    chain prerouting_raw {\n"
                       "        type filter hook prerouting priority raw; policy accept;\n"
                       "        meta l4proto icmp icmp type time-exceeded counter notrack "
                       "comment \"steer:traceroute-hops\"\n"
                       "    }\n");
        }
        /* The resolver only sees what is steered to it. IPv6 as well as IPv4: the
         * router advertises itself as an IPv6 resolver by default and clients prefer
         * that server, so an IPv4-only redirect catches almost nothing — measured on a
         * real client, 15 of its DNS packets went over IPv6 against 20 over IPv4.
         * TCP/53 stays with the system resolver: this daemon is UDP-only, so
         * redirecting TCP would break the truncated-answer retry. */
        fprintf(f, "    chain prerouting_dns {\n"
                   "        type nat hook prerouting priority dstnat; policy accept;\n");
        for (size_t i = 0; i < g_from_default_n; i++)
            fprintf(f, "        ip saddr %s udp dport 53 counter redirect to :%d\n",
                    g_from_default[i], DNS_PORT);
        if (g_lan_device[0])
            fprintf(f, "        meta nfproto ipv6 iifname \"%s\" udp dport 53 counter redirect to :%d\n",
                    g_lan_device, DNS_PORT);
        fprintf(f, "    }\n");
    }
    fprintf(f, "}\n");
}

/* ---- what an interface output depends on, and does not own ----------------- */
/* steer does not touch the firewall. It has no business rewriting someone's zones
 * or adding masquerade rules — that is the operator's configuration, and a routing
 * engine silently editing it is how two tools start fighting over one ruleset.
 *
 * But an interface output cannot work without it: packets leaving a tunnel with LAN
 * source addresses never come back, so the route looks applied, the channel counter
 * even rises, and every site behind it simply hangs. That failure is invisible from
 * inside steer's own state — which is exactly why it must be REPORTED.
 *
 * Both checks are textual and deliberately conservative: a false "looks fine" is
 * worse than a false warning, so anything unrecognised reads as missing. */
struct fwcheck { int in_firewall, masqueraded; };

/* Is DEVICE named here as a whole token? Substring matching is not good enough in
 * either direction: looking for it quoted missed fw4 entirely (see below), while a
 * bare substring would let "warp" answer for "warp0". */
static int names_device(const char *hay, const char *device) {
    size_t n = strlen(device);
    for (const char *p = strstr(hay, device); p; p = strstr(p + 1, device)) {
        char before = p == hay ? ' ' : p[-1];
        char after = p[n];
        int lb = (before >= 'a' && before <= 'z') || (before >= 'A' && before <= 'Z')
                 || (before >= '0' && before <= '9');
        int la = (after >= 'a' && after <= 'z') || (after >= 'A' && after <= 'Z')
                 || (after >= '0' && after <= '9');
        if (!lb && !la) return 1;
    }
    return 0;
}

static struct fwcheck fw_check(const char *device) {
    struct fwcheck r = { 0, 0 };
    /* --terse: без содержимого наборов. Проверка смотрит на имена устройств в правилах
     * и цепочках, а элементы наборов ей не нужны — при этом их бывают десятки тысяч, и
     * полный дамп на слабом роутере стоил секунды НА КАЖДЫЙ ВЫЗОВ. Вызовов же по одному
     * на выход в status (его интерфейс опрашивает каждые пять секунд), в diag и в apply:
     * ровно этим status и apply тормозили. Флаг есть в nft с 0.9.4 (OpenWrt 21+); на
     * случай древней сборки — откат к полному дампу, медленно, но не слепо. */
    FILE *f = popen("nft -t list ruleset 2>/dev/null || nft list ruleset 2>/dev/null", "r");
    if (!f) return r;
    char line[2048];
    char chain[128] = "";
    int in_steer = 0;
    while (fgets(line, sizeof(line), f)) {
        /* Our own table mentions the device too; it proves nothing about NAT. */
        if (strstr(line, "table inet steer")) in_steer = 1;
        else if (!strncmp(line, "table ", 6)) in_steer = 0;
        if (in_steer) continue;

        const char *c = strstr(line, "chain ");
        if (c) snprintf(chain, sizeof(chain), "%s", c + 6);

        if (names_device(line, device)) r.in_firewall = 1;
        /* fw4 does NOT name the device on the masquerade rule: it emits
         * `chain srcnat_warp0 { meta nfproto ipv4 masquerade comment "...warp0..." }`
         * and matches the device on the jump into that chain. Checking only the rule
         * line reported "no NAT" on a router whose NAT was working fine — a false
         * alarm that sent me diagnosing the wrong thing. So the enclosing chain name
         * counts as evidence too. */
        if (strstr(line, "masquerade") || strstr(line, "snat")) {
            if (names_device(line, device) || names_device(chain, device)) r.masqueraded = 1;
        }
    }
    pclose(f);
    return r;
}

static void report_traceroute_dep(void) {
    if (!g_traceroute_hops) return;
    /* Say the useless case out loud rather than leaving the operator to discover it
     * as a column of asterisks. */
    for (size_t i = 0; i < g_out_n; i++) {
        if (!out_has_device(&g_out[i])) continue;
        if (fw_check(g_out[i].device).masqueraded) {
            fprintf(stderr, "steer: traceroute_hops cannot work for output %s: %s "
                            "masquerades, so ICMP errors come addressed to the router "
                            "and only conntrack can route them to the client — "
                            "untracking them drops the hops entirely\n",
                    g_out[i].name, g_out[i].device);
            return;
        }
    }
    /* Тот же --terse, что в fw_check, и по той же причине: ищется правило, а не элементы. */
    FILE *f = popen("nft -t list ruleset 2>/dev/null || nft list ruleset 2>/dev/null", "r");
    int ok = 0;
    if (f) {
        char line[2048];
        while (fgets(line, sizeof(line), f))
            if (strstr(line, "untracked") && strstr(line, "accept")) ok = 1;
        pclose(f);
    }
    if (!ok)
        fprintf(stderr, "steer: traceroute_hops is on but no rule accepting untracked "
                        "packets was found — ICMP time-exceeded will be dropped by the "
                        "firewall and hops will show as asterisks. Needed once, in the "
                        "firewall (not here): accept ct state untracked icmp type "
                        "time-exceeded towards %s\n", g_lan_device);
}

static void report_output_deps(void) {
    for (size_t i = 0; i < g_out_n; i++) {
        if (!out_has_device(&g_out[i])) continue;
        struct fwcheck c = fw_check(g_out[i].device);
        if (!c.in_firewall)
            fprintf(stderr, "steer: output %s: %s is not mentioned by the firewall at all — "
                            "traffic steered there will not come back until it is in a zone\n",
                    g_out[i].name, g_out[i].device);
        /* Выходу vless NAT не нужен, и предупреждать о нём — значит посылать человека
         * настраивать то, чему нечего транслировать: клиент завершает TCP у себя и
         * соединяется с сервером обычным сокетом, поэтому адрес клиента наружу не уезжает
         * вовсе. Предупреждение «нет masquerade» здесь было ложной тревогой, а ложная
         * тревога дороже отсутствующей: по ней настраивают лишнее и перестают верить
         * настоящим. Про зону предупреждать всё равно надо — без неё fw4 не пропускает
         * транзит, и это проверено с настоящего клиента. */
        else if (g_out[i].kind == OUT_VLESS) {
            /* нечего проверять */
        }
        else if (!c.masqueraded)
            fprintf(stderr, "steer: output %s: no masquerade/snat rule found for %s — "
                            "if that path needs NAT, packets leave with LAN addresses and "
                            "the channel goes quiet while its counter still rises\n",
                    g_out[i].name, g_out[i].device);
    }
}

/* ---- apply ---------------------------------------------------------------- */
/* Экспортируется для failover.c: он запускает те же ip/ping, и второй такой же
 * помощник означал бы два места, где решается, куда девать вывод. */
int run_quiet(const char *const argv[]);
static int run(const char *const argv[]) {
    pid_t p = fork();
    if (p < 0) return -1;
    if (p == 0) {
        /* Both streams: `nft get element` prints the whole set on success, which
         * would otherwise land in the middle of explain's answer. */
        int devnull = open("/dev/null", O_WRONLY);
        if (devnull >= 0) { dup2(devnull, 1); dup2(devnull, 2); close(devnull); }
        execvp(argv[0], (char *const *)argv);
        _exit(127);
    }
    int st = 0;
    waitpid(p, &st, 0);
    return WIFEXITED(st) ? WEXITSTATUS(st) : -1;
}

int run_quiet(const char *const argv[]) { return run(argv); }

/* ---- снятие мёртвых правил маршрутизации ------------------------------------
 *
 * rename/remove выхода оставляли в ядре ip rule fwmark и его таблицу навсегда:
 * apply ставит правила только для ТЕКУЩИХ выходов по их НОВЫМ меткам, метка
 * назначается по имени из реестра, и правило переименованного выхода не снимал
 * никто (I-019). Мёртвые правила не матчатся — метку с них уже никто не ставит, —
 * но копятся с каждым переименованием и засоряют `ip rule show` ровно тогда,
 * когда по нему пытаются понять, куда ушёл трафик.
 *
 * Снимок прежнего реестра берётся ДО registry_assign — тот перезаписывает файл
 * текущими выходами, и после него сравнивать уже не с чем. Живой считается метка,
 * которую несёт ЛЮБОЙ текущий недирект-выход: устройство здесь не проверяется
 * нарочно, у vless его создаёт сам процесс туннеля, и снять правило выхода за то,
 * что его устройство ещё не поднялось, значило бы обрубить туннель на ровном
 * месте. */
struct oldreg { unsigned mark; int table; };
static struct oldreg g_oldreg[MAX_OUTPUTS];
static size_t g_oldreg_n;

static void registry_snapshot(void) {
    char path[512];
    snprintf(path, sizeof(path), "%s/registry", g_state_dir);
    FILE *f = fopen(path, "r");
    if (!f) return;
    char name[32];
    unsigned mark;
    int table;
    while (g_oldreg_n < MAX_OUTPUTS &&
           fscanf(f, "%31s %x %d\n", name, &mark, &table) == 3) {
        g_oldreg[g_oldreg_n].mark = mark;
        g_oldreg[g_oldreg_n].table = table;
        g_oldreg_n++;
    }
    fclose(f);
}

static void cleanup_stale_routing(void) {
    for (size_t i = 0; i < g_oldreg_n; i++) {
        int live = 0;
        for (size_t k = 0; k < g_out_n; k++)
            if (g_out[k].kind != OUT_DIRECT && g_out[k].mark == g_oldreg[i].mark) {
                live = 1;
                break;
            }
        if (live) continue;
        char mark[24], table[16];
        snprintf(mark, sizeof(mark), "0x%08x", g_oldreg[i].mark);
        snprintf(table, sizeof(table), "%d", g_oldreg[i].table);
        const char *del[] = { "ip", "rule", "del", "fwmark", mark, "table", table, NULL };
        while (run(del) == 0) ;
        const char *flush[] = { "ip", "route", "flush", "table", table, NULL };
        run(flush);
    }
}

/* Policy routing for interface outputs. Rules are removed before being added so a
 * re-apply cannot stack duplicates — `ip rule add` is happy to add the same rule
 * twice, and the second copy is invisible until someone deletes the first. */
static void apply_routing(void) {
    for (size_t i = 0; i < g_out_n; i++) {
        if (!out_has_device(&g_out[i])) continue;
        char mark[24], table[16];
        snprintf(mark, sizeof(mark), "0x%08x", g_out[i].mark);
        snprintf(table, sizeof(table), "%d", g_out[i].table);
        const char *del[] = { "ip", "rule", "del", "fwmark", mark, "table", table, NULL };
        while (run(del) == 0) ;                       /* drain older copies */
        const char *add[] = { "ip", "rule", "add", "fwmark", mark, "table", table, NULL };
        run(add);
        const char *flush[] = { "ip", "route", "flush", "table", table, NULL };
        run(flush);
        const char *route[] = { "ip", "route", "add", "default", "dev", g_out[i].device,
                                "table", table, NULL };
        if (run(route) != 0) {
            fprintf(stderr, "steer: output %s: cannot route via %s — is the device up?\n",
                    g_out[i].name, g_out[i].device);
            /* Пустая таблица — это не «нет маршрута», а «ищи дальше»: помеченный
             * пакет провалится в следующую таблицу и уйдёт напрямую, то есть ровно
             * туда, куда его не пускали. При on_fail=drop окно между apply и первым
             * тиком failover обязано быть закрыто, иначе защита работает не всегда,
             * а это хуже, чем не работает вовсе. */
            if (g_out[i].on_fail == FAIL_DROP) {
                const char *bh[] = { "ip", "route", "add", "blackhole", "default",
                                     "table", table, NULL };
                run(bh);
                fprintf(stderr, "steer: output %s: трафик остановлен до появления "
                                "рабочего устройства (on_fail=drop)\n", g_out[i].name);
            }
        }
    }
}

static int cmd_apply(const char *spec, int dry) {
    load_spec(spec);
    /* Снимок реестра — строго до registry_assign: тот перезапишет файл текущими
     * выходами, и метки удалённых/переименованных будут потеряны вместе с
     * единственным способом снять их правила из ядра. */
    registry_snapshot();
    registry_assign();
    build_groups();
    /* Проверка списков — ДО генерации и до dry-run.
     *
     * До dry-run намеренно: интерфейс проверяет спеку именно им, перед записью на диск.
     * Значит человек узнает про не тот список сразу при сохранении, а не потом, когда
     * apply молча не подействует. */
    check_address_lists();
    /* Снять накопленное ДО генерации: она вписывает эти значения в новые правила, иначе
     * каждый apply обнулял бы объёмы. Читаем и при --dry-run — так печатаемый текст остаётся
     * тем, что реально применится, а на машине без таблицы вывод не меняется вовсе. */
    counters_load();
    /* Ни одной группы — таблица всё равно ставится, с пустой цепочкой: так status
     * продолжает отвечать, а следующий apply не зависит от того, была ли таблица
     * раньше. */
    if (dry) { generate(stdout); return 0; }

    char tmp[] = "/tmp/steer-ruleset.XXXXXX";
    int fd = mkstemp(tmp);
    if (fd < 0) die("cannot create a temporary ruleset", NULL);
    FILE *f = fdopen(fd, "w");
    generate(f);
    fclose(f);

    /* Delete-then-load in ONE transaction: `nft -f` applies the whole file
     * atomically, so there is never a moment with our chain present and its sets
     * missing. The delete is tolerated failing on the very first apply. */
    const char *del[] = { "nft", "delete", "table", "inet", "steer", NULL };
    run(del);
    const char *load[] = { "nft", "-f", tmp, NULL };
    int rc = run(load);
    if (rc != 0) {
        fprintf(stderr, "steer: nft refused the ruleset (kept: %s)\n", tmp);
        const char *check[] = { "nft", "-c", "-f", tmp, NULL };
        run(check);
        return 1;
    }
    unlink(tmp);
    apply_routing();
    cleanup_stale_routing();
    report_output_deps();
    report_traceroute_dep();
    printf("steer: applied %zu channel(s), %zu output(s)\n", g_ch_n, g_out_n);
    return 0;
}

/* ---- status --------------------------------------------------------------- */
/* Counters come from the live chain, matched by the comment each rule carries —
 * which is why generation puts the channel name there. Without it the numbers
 * exist but belong to nobody. */
static int cmd_status(const char *spec) {
    load_spec(spec);
    registry_assign();
    build_groups();
    printf("{\"schema\":1,\"outputs\":{");
    for (size_t i = 0; i < g_out_n; i++) {
        char devpath[128];
        int up = 0;
        if (out_has_device(&g_out[i])) {
            snprintf(devpath, sizeof(devpath), "/sys/class/net/%s/operstate", g_out[i].device);
            FILE *df = fopen(devpath, "r");
            if (df) {
                char st[16] = "";
                if (fgets(st, sizeof(st), df)) up = strncmp(st, "down", 4) != 0;
                fclose(df);
            }
        }
        printf("%s\"%s\":{\"kind\":\"%s\"", i ? "," : "", g_out[i].name,
               g_out[i].kind == OUT_DIRECT ? "direct" :
               g_out[i].kind == OUT_VLESS ? "vless" : "interface");
        if (out_has_device(&g_out[i])) {
            struct fwcheck c = fw_check(g_out[i].device);
            printf(",\"device\":\"%s\",\"up\":%s,\"mark\":\"0x%08x\",\"table\":%d"
                   ",\"in_firewall\":%s,\"nat\":%s",
                   g_out[i].device, up ? "true" : "false", g_out[i].mark, g_out[i].table,
                   c.in_firewall ? "true" : "false", c.masqueraded ? "true" : "false");
            /* Кандидаты и режим отказа: без них failover не виден из интерфейса, и
             * человек не может понять, почему выход вдруг ведёт в другое устройство. */
            printf(",\"devices\":[");
            for (size_t d = 0; d < g_out[i].devices_n; d++)
                printf("%s\"%s\"", d ? "," : "", g_out[i].devices[d]);
            printf("],\"on_fail\":\"%s\"",
                   g_out[i].on_fail == FAIL_DROP ? "drop" :
                   g_out[i].on_fail == FAIL_ZAPRET ? "zapret" : "direct");
        }
        printf("}");
    }
    printf("},\"channels\":[");

    counters_load();
    for (size_t i = 0; i < g_grp_n; i++) {
        unsigned long up_p = 0, up_b = 0, dn_p = 0, dn_b = 0;
        int live = counter_find(g_grp[i].name, 0, &up_p, &up_b) == 0;
        int dn = counter_find(g_grp[i].name, 1, &dn_p, &dn_b) == 0;
        printf("%s{\"name\":\"%s\",\"out\":\"%s\",\"kind\":\"%s\",\"live\":%s",
               i ? "," : "", g_grp[i].name, g_grp[i].out,
               g_grp[i].domains ? "domains" : "prefixes", live ? "true" : "false");
        if (live) printf(",\"packets\":%lu,\"bytes\":%lu", up_p, up_b);
        /* Отдельными именами, а не вторым «bytes»: старое имя значило «наружу» и в таком
         * значении уже разошлось по установленным версиям splify2. Переопределить его
         * значило бы, что новый движок со старым интерфейсом молча показывает не то. */
        if (dn) printf(",\"down_packets\":%lu,\"down_bytes\":%lu", dn_p, dn_b);
        printf(",\"lists\":%zu,\"channels\":[", g_grp[i].files_n + g_grp[i].dfiles_n);
        for (size_t m = 0; m < g_grp[i].members_n; m++)
            printf("%s\"%s\"", m ? "," : "", g_grp[i].members[m]);
        printf("]}");
    }
    printf("]}\n");
    return 0;
}

/* ---- explain -------------------------------------------------------------- */
/* An address from the command line ends up in an nft invocation, so it is checked
 * against a whitelist first. The earlier version interpolated it into system(),
 * which made `steer explain '$(...)'` a command-injection hole; there is no shell
 * here now, and this refuses anything that is not address-shaped regardless. */
static int addr_ok(const char *a) {
    size_t n = 0;
    for (const char *p = a; *p; p++, n++) {
        if (!((*p >= '0' && *p <= '9') || *p == '.' || *p == '/')) return 0;
        if (n > 18) return 0;
    }
    return n > 0;
}

/* ---- diag --------------------------------------------------------------------
 *
 * Один вопрос: работает ли всё. Спрашивается у ЯДРА и у живых процессов, а не у спеки —
 * спека описывает намерение, и совпадение с ней ничего не доказывает. Каждая проверка
 * отвечает своей строкой: что смотрели, каков итог и что делать, если плохо.
 *
 * Зачем отдельная команда, если есть status. status отвечает «что применено», и по нему
 * человек, у которого сайт не открывается, вынужден сам догадываться, какие из полей
 * важны. Здесь набор проверок назван прямо, вместе с причиной, и в нём есть то, чего в
 * status нет вовсе: пустой набор при непустом списке, отсутствующий редирект DNS,
 * незапущенный резолвер и две ловушки, которые движок не решает, но обязан назвать (DoH и
 * IPv6). Ровно эти два случая выглядят как «список не работает» при исправной настройке.
 *
 * Итог у проверки один из четырёх:
 *
 *   ok   — проверено и хорошо;
 *   note — совет, а не находка: работает и будет работать, но человеку полезно знать;
 *   warn — работает, но есть чем объяснить будущую жалобу;
 *   fail — сломано, трафик идёт не туда.
 *
 * `note` появился потому, что без него советы считались предупреждениями. Совет «браузер с DoH
 * резолвит сам» верен ВСЕГДА, когда есть доменные правила: он не про эту установку, а про
 * устройство мира. Считая его предупреждением, движок делал итог «работает, но есть о чём
 * знать» постоянным, интерфейс красил состояние тревожным цветом — и человек видел тревогу на
 * исправном роутере. Постоянная метка учит не смотреть на метки вовсе.
 *
 * Поэтому в счётчики note не идёт: он не отвечает на «всё ли в порядке», он отвечает на «что
 * ещё стоит знать».
 */
static int g_diag_first = 1;
static int g_diag_warn, g_diag_fail;

static void diag(const char *id, const char *verdict, const char *what, const char *why) {
    /* note намеренно не считается: см. пояснение выше. */
    if (!strcmp(verdict, "warn")) g_diag_warn++;
    if (!strcmp(verdict, "fail")) g_diag_fail++;
    printf("%s{\"id\":\"%s\",\"verdict\":\"%s\",\"what\":\"%s\",\"why\":\"%s\"}",
           g_diag_first ? "" : ",", id, verdict, what, why);
    g_diag_first = 0;
}

/* Сколько элементов в наборе по мнению ядра. -1 — набора нет.
 *
 * Имя проверяется по составу, а не просто обрезается: оно уходит в командную строку через
 * popen. Имя набора собирается из имени выхода, а то приходит из спеки — то есть снаружи.
 * В этом файле такую дыру уже находили однажды, в explain, где адрес подставлялся в
 * system(); повторять не будем. */
static long set_count(const char *name) {
    for (const char *q = name; *q; q++)
        if (!((*q >= 'a' && *q <= 'z') || (*q >= 'A' && *q <= 'Z') ||
              (*q >= '0' && *q <= '9') || *q == '_' || *q == '-' || *q == '.'))
            return -1;
    char cmd[256];
    snprintf(cmd, sizeof(cmd), "nft list set inet steer %.64s 2>/dev/null", name);
    FILE *p = popen(cmd, "r");
    if (!p) return -1;
    long n = -1;
    char line[4096];
    int seen = 0;
    while (fgets(line, sizeof(line), p)) {
        seen = 1;
        char *e = strstr(line, "elements = {");
        if (!e) continue;
        n = 0;
        /* Считаем запятые, а не разбираем элементы: их бывают десятки тысяч, и разбор
         * ради одного числа значил бы держать в памяти весь список второй раз. */
        for (char *q = e; *q; q++) if (*q == ',') n++;
        /* Элементов на одну больше, чем запятых; продолжение приезжает следующими
         * строками, поэтому дальше просто добавляем. */
        n++;
        while (fgets(line, sizeof(line), p)) {
            for (char *q = line; *q; q++) if (*q == ',') n++;
            if (strchr(line, '}')) break;
        }
        break;
    }
    pclose(p);
    if (!seen) return -1;
    return n < 0 ? 0 : n;
}

static int nft_has(const char *what) {
    char cmd[256];
    /* --terse: ищутся цепочки, элементы наборов не нужны — а их дамп на большом
     * наборе стоит дороже всех остальных проверок diag вместе взятых. */
    snprintf(cmd, sizeof(cmd),
             "{ nft -t list table inet steer 2>/dev/null || "
             "nft list table inet steer 2>/dev/null; } | grep -qF '%s'", what);
    return system(cmd) == 0;
}

static int cmd_diag(const char *spec) {
    load_spec(spec);
    registry_assign();
    build_groups();
    printf("{\"schema\":1,\"checks\":[");

    /* 1. Таблица. Без неё всё остальное бессмысленно: apply не применялся или его снесли. */
    int table = nft_has("chain prerouting_mark");
    diag("table", table ? "ok" : "fail",
         table ? "правила движка в ядре" : "правил движка в ядре нет",
         table ? "" : "apply не применялся или таблицу снесли — нажмите «Применить»");

    /* 2. Встречная цепочка. Её отсутствие не ломает маршрутизацию, но объёмы «внутрь»
     *    будут пустыми, и это надо назвать, а не показывать нули. */
    if (table) {
        int down = nft_has("chain postrouting_down");
        diag("down_chain", down ? "ok" : "warn",
             down ? "скачанное считается" : "скачанное не считается",
             down ? "" : "правила от старой версии движка — примените настройку заново");
    }

    /* 3. Наборы. Пустой набор при непустом списке — самая частая настоящая поломка:
     *    правило на месте, трафик мимо, и по status этого не видно. */
    for (size_t i = 0; i < g_grp_n; i++) {
        struct group *g = &g_grp[i];
        if (!g->files_n && !g->domains) continue;
        long n = set_count(g->name);
        char what[160], why[240];
        if (n < 0) {
            snprintf(what, sizeof(what), "канал %.48s: набора в ядре нет", g->name);
            snprintf(why, sizeof(why), "apply не довёл набор до ядра — примените заново");
            diag("set", "fail", what, why);
        } else if (n == 0 && g->files_n) {
            snprintf(what, sizeof(what), "канал %.48s: набор пуст", g->name);
            snprintf(why, sizeof(why),
                     "списков %zu, но в ядре ни одного адреса — списки не скачались "
                     "или в них нет адресных строк", g->files_n);
            diag("set", "fail", what, why);
        } else if (n == 0) {
            snprintf(what, sizeof(what), "канал %.48s: набор пока пуст", g->name);
            snprintf(why, sizeof(why),
                     "доменный канал наполняет резолвер по мере запросов — это нормально "
                     "до первого обращения");
            /* Тоже совет, а не находка: пустой доменный набор до первого запроса — штатное
             * состояние, и тревожить им нельзя. */
            diag("set", "note", what, why);
        } else {
            snprintf(what, sizeof(what), "канал %.48s: адресов в ядре %ld", g->name, n);
            diag("set", "ok", what, "");
        }
    }

    /* 4. Резолвер и редирект. Доменные каналы держатся на обоих: без редиректа клиент
     *    спрашивает не нас, без процесса спрашивать некого. */
    if (has_domains()) {
        int redir = nft_has("chain prerouting_dns");
        diag("dns_redirect", redir ? "ok" : "fail",
             redir ? "запросы DNS заворачиваются на движок"
                   : "запросы DNS на движок не заворачиваются",
             redir ? "" : "доменные каналы без этого не работают вовсе — примените настройку");
        int alive = system("pgrep -f 'steer dnsd' >/dev/null 2>&1") == 0;
        diag("dnsd", alive ? "ok" : "fail",
             alive ? "резолвер доменных каналов работает" : "резолвер доменных каналов не запущен",
             alive ? "" : "запустите: /etc/init.d/steer restart");

        /* DoH — ловушка, которую движок не решает, но обязан назвать. Клиент с DoH
         * резолвит сам, fake-IP не появляется, и выглядит это как «список не работает»
         * при исправном наборе и правиле. */
        diag("doh", "note", "клиент может обходить DNS роутера",
             "браузер с DNS-over-HTTPS резолвит сам, и доменные каналы его трафик не видят: "
             "выключите DoH в браузере или пользуйтесь адресными списками");
    }

    /* 5. IPv6. Адресных каналов для IPv6 нет вовсе, значит при живом IPv6 наружу трафик
     *    к тем же целям уходит мимо канала. Для on_fail=drop это утечка, а не неудобство,
     *    поэтому там fail. Проверяем НАЛИЧИЕ маршрута, а не убеждения: без него нет и
     *    повода тревожить. */
    int v6 = system("ip -6 route show default 2>/dev/null | grep -q .") == 0;
    if (v6) {
        int drops = 0;
        for (size_t i = 0; i < g_out_n; i++)
            if (g_out[i].on_fail == FAIL_DROP) drops++;
        int dom_only = 1;
        for (size_t i = 0; i < g_grp_n; i++)
            if (g_grp[i].files_n) dom_only = 0;
        if (drops)
            diag("ipv6", "fail", "IPv6 наружу работает, а каналы его не разбирают",
                 "выход с on_fail=drop останавливает только IPv4: то, что должно быть "
                 "отброшено, уйдёт по IPv6 — отключите IPv6 у провайдера или на роутере");
        else if (!dom_only)
            diag("ipv6", "warn", "IPv6 наружу работает, а адресные каналы только про IPv4",
                 "сайт, доступный по IPv6, пойдёт мимо канала: доменные каналы прикрыты "
                 "подавлением AAAA, адресные — нет");
        else
            diag("ipv6", "ok", "IPv6 наружу работает, доменные каналы прикрыты",
                 "");
    }

    /* 6. UDP через VLESS. Туннель несёт только TCP: UDP-пакет получает ICMP «порт
     *    недостижим» и дальше не идёт (src/ext/tun.c, handle_packet). Для браузера это
     *    штатно — он бросает QUIC и берёт TCP. Но WireGuard, WARP и игровой трафик
     *    состоят из UDP целиком, и для них выход просто не работает: соединение доходит
     *    до конца и обрывается.
     *
     *    Сказать об этом обязан движок, потому что больше некому: в списке каналов это
     *    выглядит как обычный адресный список, а в журнале — как тишина. Наблюдение из
     *    публичного теста: пользователь направил в туннель категорию Cloudflare, а в неё
     *    входят 162.158.0.0/15 и 188.114.96.0/20 — адреса точек входа WARP. WARP на его
     *    компьютере доходил до 100% и сбрасывался во всех режимах, кроме DNS-режима, где
     *    он ходит по TCP.
     *
     *    Приговор note, а не warn: ограничение постоянное и верное всегда, а постоянный
     *    warn красит исправный роутер в жёлтый навсегда — ровно та же причина, по которой
     *    note выбран для doh. */
    for (size_t i = 0; i < g_grp_n; i++) {
        struct output *o = out_by_name(g_grp[i].out);
        if (!o || o->kind != OUT_VLESS) continue;
        diag("udp", "note", "выход VLESS несёт только TCP",
             "UDP в такой туннель не проходит: браузер сам перейдёт на TCP, а WARP, "
             "WireGuard и игровой трафик через него не заработают — им нужен "
             "выход-устройство или адреса вне списков этого канала");
        break;
    }

    /* 7. Выходы: устройство, зона фаервола, NAT. То же, что в status, но с приговором —
     *    в status это поля, и какие из них важны, человек угадывал сам. */
    for (size_t i = 0; i < g_out_n; i++) {
        if (!out_has_device(&g_out[i])) continue;
        char path[128];
        snprintf(path, sizeof(path), "/sys/class/net/%s/operstate", g_out[i].device);
        int present = access(path, R_OK) == 0;
        char what[160], why[240];
        if (!present) {
            snprintf(what, sizeof(what), "выход %.40s: устройства %.24s нет",
                     g_out[i].name, g_out[i].device);
            snprintf(why, sizeof(why), "туннель не поднят — %s",
                     g_out[i].kind == OUT_VLESS ? "смотрите журнал движка"
                                                : "проверьте настройку интерфейса");
            diag("output", "fail", what, why);
            continue;
        }
        struct fwcheck c = fw_check(g_out[i].device);
        if (!c.in_firewall) {
            snprintf(what, sizeof(what), "выход %.40s: %.24s вне зоны фаервола",
                     g_out[i].name, g_out[i].device);
            diag("output", "fail", what,
                 "фаервол отбросит ответы — добавьте устройство в зону");
        } else if (!c.masqueraded && g_out[i].kind != OUT_VLESS) {
            /* Только для kind=interface. Выходу vless masquerade не нужен: он завершает TCP
             * сам и наружу идёт от своего имени, адреса клиентов границу не переходят. Жалоба
             * на исправной системе — это постоянная жёлтая метка, которая учит не смотреть на
             * проверки вовсе. */
            snprintf(what, sizeof(what), "выход %.40s: у %.24s нет masquerade",
                     g_out[i].name, g_out[i].device);
            diag("output", "warn", what,
                 "без подмены адреса ответы не найдут дорогу назад, если туннель этого "
                 "не делает сам");
        } else if (c.masqueraded) {
            snprintf(what, sizeof(what), "выход %.40s: устройство %.24s в зоне, NAT есть",
                     g_out[i].name, g_out[i].device);
            diag("output", "ok", what, "");
        } else {
            /* Сюда попадает только vless без masquerade — для него это норма. Сказать
             * «NAT есть» было бы прямой неправдой: его нет, он просто не нужен. */
            snprintf(what, sizeof(what), "выход %.40s: устройство %.24s в зоне",
                     g_out[i].name, g_out[i].device);
            diag("output", "ok", what,
                 "masquerade не нужен: туннель завершает TCP сам, адреса клиентов наружу "
                 "не уходят");
        }
    }

    printf("],\"warn\":%d,\"fail\":%d}\n", g_diag_warn, g_diag_fail);
    /* Код возврата — чтобы это годилось в скрипт, а не только глазам. */
    return g_diag_fail ? 1 : 0;
}

/* ---- explain по имени --------------------------------------------------------
 *
 * Спрашиваем НАШ резолвер, а не getaddrinfo. Разница принципиальная: getaddrinfo пойдёт к
 * системному dnsmasq и вернёт настоящий адрес сервера, а доменные каналы работают на fake-IP —
 * том адресе, который выдал бы клиенту именно steer. То есть по системному ответу нельзя
 * сказать, попадёт ли имя в набор: набор заполнен fake-адресами.
 *
 * Поэтому запрос уходит прямо в dnsd на 127.0.0.1:DNS_PORT. Заодно это проверка самого
 * резолвера: не ответил — значит и клиентам он не отвечает, и это первое, что надо знать.
 *
 * Свой запрос из четырёх десятков строк, а не библиотека: тут нужен ровно один тип записи и
 * ровно один сервер, а тянуть resolver-библиотеку в статический бинарь для роутера — это
 * килобайты за то, что укладывается в один буфер.
 */
static int dns_ask(const char *name, char *out, size_t out_n) {
    unsigned char q[512];
    size_t n = 0;
    q[n++] = 0x12; q[n++] = 0x34;                 /* id — постоянный: один запрос за процесс */
    q[n++] = 0x01; q[n++] = 0x00;                 /* стандартный запрос, рекурсия желательна */
    q[n++] = 0x00; q[n++] = 0x01;                 /* вопросов 1 */
    q[n++] = 0x00; q[n++] = 0x00;                 /* ответов 0 */
    q[n++] = 0x00; q[n++] = 0x00;
    q[n++] = 0x00; q[n++] = 0x00;
    /* Имя метками. Пустая метка (две точки подряд) сделала бы запрос неразбираемым. */
    const char *p = name;
    while (*p) {
        const char *dot = strchr(p, '.');
        size_t len = dot ? (size_t)(dot - p) : strlen(p);
        if (!len || len > 63 || n + len + 1 >= sizeof(q) - 5) return -1;
        q[n++] = (unsigned char)len;
        memcpy(q + n, p, len);
        n += len;
        if (!dot) break;
        p = dot + 1;
    }
    q[n++] = 0x00;
    q[n++] = 0x00; q[n++] = 0x01;                 /* тип A */
    q[n++] = 0x00; q[n++] = 0x01;                 /* класс IN */

    int fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (fd < 0) return -1;
    struct timeval tv = { .tv_sec = 2, .tv_usec = 0 };
    setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof tv);
    struct sockaddr_in a = { .sin_family = AF_INET, .sin_port = htons(DNS_PORT) };
    a.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    if (sendto(fd, q, n, 0, (struct sockaddr *)&a, sizeof a) < 0) { close(fd); return -1; }

    unsigned char r[1024];
    ssize_t rn = recv(fd, r, sizeof r, 0);
    close(fd);
    if (rn < 12) return -1;
    unsigned ancount = ((unsigned)r[6] << 8) | r[7];
    if (!ancount) return -2;                       /* ответ есть, адреса нет — NODATA */
    /* Пропускаем раздел вопроса. */
    size_t i = 12;
    while (i < (size_t)rn && r[i]) {
        if ((r[i] & 0xC0) == 0xC0) { i += 2; break; }
        i += r[i] + 1;
    }
    if (i < (size_t)rn && !r[i]) i++;
    i += 4;
    /* Первый ответ типа A. CNAME пропускаем: dnsd их не выдаёт, но чужой ответ может. */
    for (unsigned k = 0; k < ancount && i + 12 <= (size_t)rn; k++) {
        if ((r[i] & 0xC0) == 0xC0) i += 2;
        else { while (i < (size_t)rn && r[i]) i += r[i] + 1; i++; }
        if (i + 10 > (size_t)rn) return -1;
        unsigned type = ((unsigned)r[i] << 8) | r[i + 1];
        unsigned rdlen = ((unsigned)r[i + 8] << 8) | r[i + 9];
        i += 10;
        if (type == 1 && rdlen == 4 && i + 4 <= (size_t)rn) {
            snprintf(out, out_n, "%u.%u.%u.%u", r[i], r[i + 1], r[i + 2], r[i + 3]);
            return 0;
        }
        i += rdlen;
    }
    return -2;
}

/* Похоже ли на имя, а не на адрес. Заодно единственная проверка перед подстановкой в
 * командную строку nft: адрес проверяет addr_ok, имя — этот набор символов. */
static int looks_like_name(const char *s) {
    size_t n = 0;
    int alpha = 0;
    for (const char *p = s; *p; p++, n++) {
        if ((*p >= 'a' && *p <= 'z') || (*p >= 'A' && *p <= 'Z')) { alpha = 1; continue; }
        if ((*p >= '0' && *p <= '9') || *p == '.' || *p == '-' || *p == '_') continue;
        return 0;
    }
    return alpha && n > 0 && n < 254;
}

/* Asks the KERNEL, channel by channel in spec order, instead of re-reading the
 * list files: the answer has to describe what the box will actually do, including
 * the case where a set failed to load. This is the one answer raw nft cannot give. */
static int cmd_explain(const char *spec, const char *what) {
    load_spec(spec);
    registry_assign();
    build_groups();

    /* Имя сначала превращаем в адрес — и печатаем, во что именно. Без этой строки человек
     * видел бы вердикт по адресу, которого не спрашивал, и не мог бы понять, тот ли это
     * адрес: у доменного канала он fake, и с настоящим адресом сайта не совпадает вовсе. */
    char resolved[32];
    const char *addr = what;
    if (looks_like_name(what)) {
        int rc = dns_ask(what, resolved, sizeof resolved);
        if (rc == -1) {
            /* Два разных случая, и путать их нельзя. Нет доменных правил — резолвер и не
             * должен работать, а «не отвечает» звучало бы как поломка. Есть — тогда молчание
             * резолвера и есть поломка, причём для всех клиентов сразу. */
            if (!has_domains())
                printf("%s -> в настройке нет ни одного правила по доменам, поэтому резолвер "
                       "steer не запущен: имена он не разбирает, спрашивайте адресом\n", what);
            else
                printf("%s -> резолвер steer не ответил на 127.0.0.1:%d — доменные правила "
                       "сейчас не работают ни для кого\n", what, DNS_PORT);
            return 1;
        }
        if (rc == -2) {
            printf("%s -> резолвер ответил, но адреса не дал: имени нет либо оно не в "
                   "доменных списках, а вышестоящий сервер его не знает\n", what);
            return 0;
        }
        int fake = strncmp(resolved, "198.18.", 7) == 0 || strncmp(resolved, "198.19.", 7) == 0;
        printf("%s -> %s (%s)\n", what, resolved,
               fake ? "fake-IP, выдан steer — значит имя в доменном списке"
                    : "настоящий адрес — имя ни в одном доменном списке не нашлось");
        addr = resolved;
    }
    for (size_t i = 0; i < g_grp_n; i++) {
        int hit = !g_grp[i].files_n && !g_grp[i].domains;   /* an `any` group */
        /* Domain channels own a set too — it is just filled by the resolver. Asking
         * only the prefix channels made explain answer "no channel matches" for
         * every fake IP, i.e. exactly the addresses a user is most likely to ask
         * about. Same oversight the generator had one commit earlier. */
        if (!hit) {
            char setname[72], elem[64];
            /* Which sets were consulted, in order — the difference between "no
             * channel matches" meaning "not listed" and meaning "explain never
             * looked". */
            if (getenv("STEER_EXPLAIN_TRACE"))
                fprintf(stderr, "checking %.63s\n", g_grp[i].name);
            snprintf(setname, sizeof(setname), "%.63s", g_grp[i].name);
            snprintf(elem, sizeof(elem), "{ %s }", addr);
            const char *q[] = { "nft", "get", "element", "inet", "steer", setname, elem, NULL };
            hit = run(q) == 0;
        }
        if (!hit) continue;
        struct output *o = out_by_name(g_grp[i].out);
        if (!o) die("group %s points at a missing output", g_grp[i].name);
        printf("%s -> %s \"%s\" -> output \"%s\"", addr,
               g_grp[i].domains ? "domain set" : "address set", g_grp[i].name, o->name);
        if (out_has_device(o))
            printf(" -> dev %s (mark 0x%08x, table %d)\n", o->device, o->mark, o->table);
        else
            printf(" -> direct\n");
        return 0;
    }
    printf("%s -> no channel matches -> direct (steer does not touch it)\n", addr);
    return 0;
}

int main(int argc, char **argv) {
    const char *spec = "/etc/steer/spec.json";
    if (argc < 2) {
        fputs("usage: steer apply [--dry-run] [--spec FILE]\n"
              "       steer dnsd  [--spec FILE]   (resolver for domain channels)\n"
              "       steer failover [--spec FILE] [-v]   (pick a live device per output)\n"
              "       steer fit --budget N [IN]   (подогнать список под память)\n"
              "       steer vless OUTPUT          (поднять TUN для выхода kind=vless)\n"
              "       steer vless-nodes OUTPUT    (узлы подписки, JSON)\n"
              "       steer vless-probe OUTPUT [--node N] [--timeout S]\n"
              "                                   (проверить узел и замерить задержку)\n"
              "       steer outputs [--kind K]    (перечислить выходы)\n"
              "       steer needs-dnsd            (exit 0 if the spec has domain channels)\n"
              "       steer status [--spec FILE]\n"
              "       steer diag [--spec FILE]    (проверки состояния, JSON; код 1 при поломке)\n"
              "       steer explain АДРЕС|ИМЯ [--spec FILE]\n", stderr);
        return 2;
    }
    const char *cmd = argv[1], *arg = NULL;
    int dry = 0, verbose = 0;
    /* Умолчание по узлу — «до первого рабочего»: то же решение, что принимает подъём
     * выхода, поэтому проверка отвечает на вопрос «что будет, если применить». */
    int node = -1, timeout = 5;
    for (int i = 2; i < argc; i++) {
        if (!strcmp(argv[i], "--spec") && i + 1 < argc) spec = argv[++i];
        else if (!strcmp(argv[i], "--dry-run")) dry = 1;
        else if (!strcmp(argv[i], "-v") || !strcmp(argv[i], "--verbose")) verbose = 1;
        else if (!strcmp(argv[i], "--state-dir") && i + 1 < argc) g_state_dir = argv[++i];
        else if (!strcmp(argv[i], "--node") && i + 1 < argc) node = atoi(argv[++i]);
        else if (!strcmp(argv[i], "--timeout") && i + 1 < argc) timeout = atoi(argv[++i]);
        /* Значения флагов разбираются ЗДЕСЬ, а не в ветке команды: общий цикл иначе
         * принял бы «--node» и «3» за имя выхода, и последнее слово в строке молча
         * становилось бы именем. Так уже случалось с fit, у которого свои аргументы. */
        else arg = argv[i];
    }
    if (timeout < 1) timeout = 1;
    /* Does this spec need the resolver? Asked by the init script instead of guessing
     * from the file's text — it used to grep for the literal `"domains_file"`, and when
     * the spec gained the plural `domains_files` the match silently stopped working:
     * the resolver never started while apply still installed the DNS redirect, so
     * every LAN query went to a closed port and DNS died. The engine is the only thing
     * that knows what it will generate, so it answers. */
    /* Перечислить выходы заданного вида. Init-скрипту нужно знать, для каких выходов
     * поднимать процесс, и спрашивать об этом движок — то же правило, что с needs-dnsd:
     * grep по ключу в JSON ломается при первом же переименовании поля, причём молча. */
    if (!strcmp(cmd, "outputs")) {
        const char *want = NULL;
        for (int i = 2; i < argc; i++)
            if (!strcmp(argv[i], "--kind") && i + 1 < argc) want = argv[i + 1];
        load_spec(spec);
        for (size_t i = 0; i < g_out_n; i++) {
            const char *k = g_out[i].kind == OUT_DIRECT ? "direct" :
                            g_out[i].kind == OUT_VLESS ? "vless" : "interface";
            if (want && strcmp(want, k) != 0) continue;
            printf("%s\n", g_out[i].name);
        }
        return 0;
    }
    if (!strcmp(cmd, "needs-dnsd")) {
        load_spec(spec);
        registry_assign();
        build_groups();
        return has_domains() ? 0 : 1;
    }
    /* Раньше остальных: у fit свои аргументы, и разбирать их общим циклом значило бы
     * молча съесть, например, --budget. */
    if (!strcmp(cmd, "fit")) return aggregate_main(argc - 1, argv + 1);
    if (!strcmp(cmd, "vless")) {
        if (!arg) die("нужно имя выхода: steer vless <output>", NULL);
        return cmd_vless(spec, arg);
    }
    if (!strcmp(cmd, "vless-nodes")) {
        if (!arg) die("нужно имя выхода: steer vless-nodes <output>", NULL);
        return cmd_vless_nodes(spec, arg);
    }
    if (!strcmp(cmd, "vless-probe")) {
        if (!arg) die("нужно имя выхода: steer vless-probe <output>", NULL);
        return cmd_vless_probe(spec, arg, node, timeout);
    }
    if (!strcmp(cmd, "failover")) return cmd_failover(spec, verbose);
    if (!strcmp(cmd, "dnsd")) return dnsd_main(argc - 2, argv + 2);
    if (!strcmp(cmd, "apply")) return cmd_apply(spec, dry);
    if (!strcmp(cmd, "status")) return cmd_status(spec);
    if (!strcmp(cmd, "diag")) return cmd_diag(spec);
    if (!strcmp(cmd, "explain")) {
        if (!arg) die("explain needs an address or a name", NULL);
        /* Адрес ИЛИ имя. Проверка формы обязательна для обоих: аргумент подставляется в
         * вызов nft, и именно здесь однажды была дыра — адрес уходил в system(). */
        if (!addr_ok(arg) && !looks_like_name(arg))
            die("это не адрес и не имя: %s", arg);
        return cmd_explain(spec, arg);
    }
    die("unknown command: %s", cmd);
    return 2;
}

