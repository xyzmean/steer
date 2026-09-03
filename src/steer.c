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
#include <time.h>

#include "spec.h"
#include "obfs.h"
#include "cli.h"

/* Уровень в журнале — см. одноимённые макросы в failover.c и obfs.c. Метка подсистемы
 * здесь «apply»: все строки ниже пишутся при компиляции и применении спеки. Отказы
 * вызывающему (die и разбор аргументов) уровня НЕ несут и несут «steer: » — это ответ
 * тому, кто позвал, а не запись в журнал; так и записано в контракте. */
#define LOG_W "steer[warn] apply: "

int dnsd_main(int argc, char **argv);

/* Путь снимка состояния. Объявлен здесь потому, что apply его СНИМАЕТ (см. там же), а сам
 * снимок живёт ниже, рядом с тем, что его пишет. */
static void status_snap_path(char *buf, size_t n);
int cmd_failover(const char *spec, int verbose);
/* Свои флаги эти двое печатают сами — см. комментарии у объявлений. Справка по ним
 * склеивается из таблицы (что команда делает) и этих строк (чем ей управляют). */
void dnsd_usage_flags(FILE *out);
void aggregate_usage_flags(FILE *out);
/* Клиент VLESS есть только в расширенной сборке (steer-extended). В базовой команда
 * отвечает внятным отказом, а не отсутствует: «неизвестная команда» на steer vless
 * заставила бы искать опечатку вместо того, чтобы поставить нужный пакет. */
#ifdef STEER_EXTENDED
int cmd_vless(const char *spec_path, const char *out_name);
int cmd_vless_nodes(const char *spec_path, const char *out_name);
int cmd_vless_probe(const char *spec_path, const char *out_name, int node, int timeout_s);
/* Мост Telegram → веб-сокет; объяснение целиком — в src/ext/tgws.c. */
int cmd_tgws(const char *spec_path, const char *out_name);
int cmd_tgws_probe(int dc, int media);
int cmd_tls_probe(const char *host, const char *addr, int port, int local_port, int quiet);
/* Скачивание и обработка подписки. Объявления — в src/ext/subfetch.h, там же и рассказ,
 * почему это работа движка, а не управляющего слоя. */
#include "ext/subfetch.h"
#else
/* ПОДСТРОКУ «steer-extended» ЗДЕСЬ ЧИТАЮТ СНАРУЖИ — это контракт, а не просто текст.
 * splify2 определяет вид установленного пакета так:
 *     out="$(steer vless '' 2>&1)"; case "$out" in *steer-extended*) vless=0 ;; esac
 * и по результату решает, показывать ли вкладку VLESS целиком. Переформулировать отказ
 * можно как угодно, но слово steer-extended обязано в нём остаться; закреплено стендом
 * tests/climatch.sh («vless '' называет пакет»). */
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
static int cmd_sub_fetch(const char *url, const char *out_path, const char *info_path) {
    (void)url; (void)out_path; (void)info_path;
    return no_vless();
}
static int cmd_sub_quota(const char *url, const char *info_path) {
    (void)url; (void)info_path;
    return no_vless();
}
static int cmd_sub_hwid(void) { return no_vless(); }
static int cmd_tgws(const char *spec_path, const char *out_name) {
    (void)spec_path; (void)out_name;
    return no_vless();
}
static int cmd_tgws_probe(int dc, int media) { (void)dc; (void)media; return no_vless(); }
static int cmd_tls_probe(const char *host, const char *addr, int port, int local_port, int quiet) {
    (void)host; (void)addr; (void)port; (void)local_port; (void)quiet; return no_vless();
}
#endif

/* Клиент и хаб xsteer. Клиент — расширенная сборка, хаб — серверная: на роутере хабу делать
 * нечего, и подкоманды, поднимающей слушателя на публичном порту, там быть не должно. */
/* Клиент — только расширенная сборка. А вот проверка конфигурации и генерация ключей нужны и
 * серверной: без них оператор хаба не смог бы ни ключ сделать, ни файл проверить. */
#if defined(STEER_EXTENDED) || defined(STEER_SERVER)
int cmd_xsteer_key(void);
int cmd_xsteer_check(const char *conf);
int cmd_xsteer_link(const char *what, const char *name);
#else
static int no_xsteer_admin(void) {
    fprintf(stderr, "steer: служебные команды xsteer в этой сборке отсутствуют — "
                    "нужен пакет steer-extended\n");
    return 2;
}
static int cmd_xsteer_key(void) { return no_xsteer_admin(); }
static int cmd_xsteer_check(const char *conf) { (void)conf; return no_xsteer_admin(); }
static int cmd_xsteer_link(const char *what, const char *name) {
    (void)what; (void)name; return no_xsteer_admin();
}
#endif

#ifdef STEER_EXTENDED
int cmd_xsteer(const char *spec_path, const char *out_name, const char *conf,
               const char *device, int stream, int stream_port);
int cmd_xsteer_peers(const char *spec_path, const char *out_name, const char *conf);
#else
static int no_xsteer(void) {
    /* Та же контрактная подстрока «steer-extended», что у VLESS, и по той же причине:
     * splify2 определяет вид пакета пробой `steer xsteer ''`. */
    fprintf(stderr, "steer: клиент xsteer в этой сборке отсутствует — "
                    "нужен пакет steer-extended\n");
    return 2;
}
static int cmd_xsteer(const char *spec_path, const char *out_name, const char *conf,
                      const char *device, int stream, int stream_port) {
    (void)spec_path; (void)out_name; (void)conf; (void)device;
    (void)stream; (void)stream_port;
    return no_xsteer();
}
static int cmd_xsteer_peers(const char *spec_path, const char *out_name, const char *conf) {
    (void)spec_path; (void)out_name; (void)conf;
    return no_xsteer();
}
#endif

#ifdef STEER_SERVER
int cmd_xsteer_hub(const char *conf);
#else
static int cmd_xsteer_hub(const char *conf) {
    (void)conf;
    /* ВТОРАЯ контрактная подстрока — «steer-hub». Она отличает «нужен другой пакет для
     * роутера» от «нужен артефакт для сервера», и без этого различия человека посылали бы
     * ставить steer-extended туда, где хаба всё равно не будет. */
    fprintf(stderr, "steer: хаб xsteer в этой сборке отсутствует — "
                    "он ставится на VPS из архива steer-hub\n");
    return 2;
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
    /* Группа «весь трафик»: набора у неё нет, правило безусловное. Признак входит в ключ
     * слияния — см. build_groups, почему такую группу нельзя объединять со списочной. */
    int all;
    int realip;
    const char (*from)[64];
    size_t from_n;
    /* ТОЛЬКО адресные файлы: их элементы уходят в набор при компиляции. Доменные читает
     * резолвер сам, из спеки, поэтому здесь их держать незачем — а держали, и из-за этого
     * группа не могла быть смешанной. */
    /* Адресные списки группы. Вектор, а не массив на MAX_CHANNELS*MAX_FILES: с пределом в
     * шестьдесят четыре файла на правило такой массив стоил бы 32 КБ на группу и два
     * мегабайта на все — при том, что обычная группа держит один-два файла. */
    const char **files;
    size_t files_n, files_cap;
    /* Сколько доменных списков в группе. Нужно только чтобы сказать это человеку в status:
     * набор у них общий, а вот «сколько списков» он спрашивает про правило. */
    size_t dfiles_n;
    /* Все адресные списки группы оказались непрочитанными — набор и правило остаются, но
     * набор пуст.
     *
     * Почему не выбросить группу совсем: правило без `ip daddr @набор` это «весь трафик
     * этих клиентов в туннель», то есть пропавший список молча превратил бы узкий канал в
     * полный туннель. Почему не оставить как было (die на первом непрочитанном файле):
     * тогда не появляется НИ ОДНОГО правила, и напрямую идёт весь роутер, включая каналы,
     * чьи списки на месте (I-136). Пустой набор — единственный вариант, при котором
     * пропавший список уносит ровно свои адреса и ничего больше. */
    int emptied;
    /* Which channels fed it — reported so a counter still has names behind it. */
    const char *members[MAX_CHANNELS];
    size_t members_n;
};

static struct group g_grp[MAX_CHANNELS];

/* Дописать адресный список в группу, растя вектор вдвое. Отказ памяти здесь — это «правила
 * не собрать», поэтому громкий: тихо потерянный список превратил бы узкий канал в широкий. */
static void group_add_file(struct group *g, const char *path) {
    if (g->files_n == g->files_cap) {
        size_t cap = g->files_cap ? g->files_cap * 2 : 8;
        const char **p = realloc(g->files, cap * sizeof(*p));
        if (!p) die("out of memory building channel groups", NULL);
        g->files = p;
        g->files_cap = cap;
    }
    g->files[g->files_n++] = path;
}
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
        /* Канал, забирающий ВЕСЬ трафик: у него нет набора вовсе. */
        int all = c->any && !c->prefixes_n && !c->domains_n;
        size_t k = 0;
        for (; k < g_grp_n; k++) {
            struct group *g = &g_grp[k];
            if (strcmp(g->out, c->out) != 0) continue;
            /* «Весь трафик» и «трафик из списка» — РАЗНЫЕ группы, даже когда выход и
             * клиенты совпадают. Слияние их было молчаливой потерей: правило группы
             * получало имя _ip и начинало проверять набор, то есть канал «весь трафик
             * этой сети в туннель» превращался в «только адреса из списка», и об этом не
             * сообщалось ни отказом, ни в status, ни в diag. */
            if (g->all != all) continue;
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
            g->all = all;
            g->realip = c->realip;
            g->from = c->from_n ? c->from : g_from_default;
            g->from_n = c->from_n ? c->from_n : g_from_default_n;
            /* Имя ставим предварительно, окончательное — ниже: домены могут прийти вторым
             * правилом, и тогда набор обязан называться _dom, иначе резолвер его не найдёт
             * (он вычисляет имя сам, той же функцией group_set_name). */
            group_set_name(g->name, sizeof(g->name), g->out, all ? "all" : domains ? "dom" : "ip",
                           g->from, g->from_n, g->realip);
        }
        struct group *g = &g_grp[k];
        /* Домены только помечаем: их файлы читает резолвер. Режим берём у первого доменного
         * правила в группе — у адресного его нет вовсе, и брать оттуда нечего. */
        if (domains) {
            if (!g->domains) g->realip = c->realip;
            g->domains = 1;
            g->dfiles_n += c->domains_n;
        }
        for (size_t f = 0; f < c->prefixes_n; f++) group_add_file(g, c->prefixes_files[f]);
        if (g->members_n < MAX_CHANNELS) g->members[g->members_n++] = c->name;
    }
    /* Окончательные имена. Группа с доменами — всегда _dom, потому что имя набора резолвер
     * вычисляет тем же правилом и по-другому его не найдёт. Группы `any` не трогаем: у них
     * набора нет вовсе. */
    for (size_t i = 0; i < g_grp_n; i++) {
        struct group *g = &g_grp[i];
        if (!g->files_n && !g->domains) continue;
        group_set_name(g->name, sizeof(g->name), g->out, g->domains ? "dom" : "ip",
                       g->from, g->from_n, g->realip);
    }
    /* Страховка, а не проверка входа: имя обязано быть уникальным по построению, и если
     * оно всё-таки повторилось — значит различитель не различил (например, два имени
     * выхода совпали после обрезки до 18 символов). Молчать здесь нельзя: именно молчание
     * и было прежней бедой — ядро сливает одноимённые наборы, и трафик уходит не туда без
     * единой строки. Лучше громкий отказ применить спеку, чем тихая ошибка маршрутизации. */
    for (size_t i = 0; i < g_grp_n; i++)
        for (size_t k = i + 1; k < g_grp_n; k++)
            if (!strcmp(g_grp[i].name, g_grp[k].name))
                die("два разных набора каналов получили одно имя %s — "
                    "укоротите или разведите имена выходов", g_grp[i].name);
}

static int has_domains(void) {
    for (size_t i = 0; i < g_grp_n; i++) if (g_grp[i].domains) return 1;
    return 0;
}

/* Есть ли хоть один выход kind=zapret. Отдельной функцией по той же причине, что
 * has_domains: цепочка очередей пишется только когда ей есть что писать, а пустая базовая
 * цепочка в postrouting — это лишний проход по правилам на КАЖДОМ пакете роутера. */
static int has_zapret(void) {
    for (size_t i = 0; i < g_out_n; i++)
        if (g_out[i].kind == OUT_ZAPRET) return 1;
    return 0;
}

/* Есть ли хоть один выход kind=tgws. Тот же довод, что у has_zapret: цепочка перехвата
 * пишется, только когда ей есть что перехватывать. */
static int has_tgws(void) {
    for (size_t i = 0; i < g_out_n; i++)
        if (g_out[i].kind == OUT_TGWS) return 1;
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

/* «Кто» по устройству: клиенты, которых мы узнаём по интерфейсу, а не по адресу.
 *
 * ИМЕНЕМ (`iifname`), А НЕ НОМЕРОМ (`iif`). Разница не косметическая: `iif` ядро разрешает
 * в индекс в момент ЗАГРУЗКИ правила и на отсутствующем устройстве отказывает всей
 * транзакции. А tailscale0 и zt* появляются позже сети и пропадают при перезапуске своего
 * демона — то есть на `iif` перезагрузка роутера оставляла бы человека вообще без правил.
 * `iifname` сверяется по имени в момент прохода пакета: правило спокойно грузится на
 * отсутствующее устройство и начинает работать само, когда оно поднимется.
 *
 * Один элемент печатается без фигурных скобок: так вывод `--dry-run` у обычной
 * конфигурации остаётся тем же текстом, что и раньше, и nft печатает его так же. */
static void emit_ifs(FILE *f, int reverse) {
    const char *kw = reverse ? "oifname" : "iifname";
    if (g_lan_dev_n == 1) { fprintf(f, "%s \"%s\" ", kw, g_lan_dev[0]); return; }
    fprintf(f, "%s { ", kw);
    for (size_t i = 0; i < g_lan_dev_n; i++)
        fprintf(f, "%s\"%s\"", i ? ", " : "", g_lan_dev[i]);
    fprintf(f, " } ");
}

/* «Кто» у правила группы. Способ ровно один, и это принципиально: адреса ИЛИ устройства, а
 * не то и другое сразу.
 *
 * ПОЧЕМУ НЕ ОБА. Соблазн был — добавлять правило по устройствам вдобавок к адресному, чтобы
 * перечень интерфейсов действовал всегда. Но `from_default` пишут в спеке, чтобы клиентов
 * ОГРАНИЧИТЬ: гостевая подсеть на том же мосту нарочно остаётся за пределами списка. Второе
 * правило по `iifname "br-lan"` молча забрало бы и её — то есть добавление интерфейса меняло
 * бы смысл давно написанной строки. Поэтому явный `from_default` значит ровно то, что
 * написано, а противоречие «клиенты описаны и подсетями, и несколькими устройствами»
 * отвергается при загрузке спеки (см. load_spec), а не разрешается движком на свой вкус. */
static void emit_from(FILE *f, const struct group *g) {
    if (g->from_n) emit_who(f, g, 0); else emit_ifs(f, 0);
}

/* То же «кто», но на встречном пути: там наш клиент — это ПОЛУЧАТЕЛЬ. */
static void emit_to(FILE *f, const struct group *g) {
    if (g->from_n) emit_who(f, g, 1); else emit_ifs(f, 1);
}

/* Elements come straight from the list files: the fitter (steer-aggregate) has
 * already decided what fits, and re-parsing them here would only add a second place
 * for the two to disagree. */
/* Похожа ли строка на адрес или префикс IPv4. Только форма, без проверки диапазонов:
 * нам надо отличить «1.2.3.0/24» от «amazon.com», а не проверять корректность маски —
 * второе сделает nft, и его сообщение об одном плохом элементе понятно. */
/* Одна половина: «A.B.C.D» или «A.B.C.D/N». Точную проверку значений делает nft — здесь
 * различается ФОРМА, чтобы отделить адресный список от доменного. */
static int addr_half_ok(const char *s, const char *end) {
    int digits = 0, dots = 0, slash = 0;
    for (const char *p = s; p < end; p++) {
        if (*p >= '0' && *p <= '9') { digits++; continue; }
        if (*p == '.') { dots++; continue; }
        if (*p == '/') { slash++; continue; }
        return 0;                       /* буква, двоеточие — это не IPv4 */
    }
    return digits > 0 && dots == 3 && slash <= 1;
}

/* Похожа ли строка на адресную запись: «10.0.0.1», «10.0.0.0/8» или ДИАПАЗОН
 * «10.0.0.1-10.0.0.9».
 *
 * Диапазон здесь обязателен, и это не расширение ради полноты. `steer fit` — та самая
 * команда, ради которой заведены большие списки, — сама ВЫДАЁТ диапазоны: два соседних
 * адреса, не складывающихся в выровненный префикс, объединяются именно так (см. emit_range
 * в aggregate.c, и tests/run.sh это закрепляет). Раньше дефис отвергался, поэтому
 * подогнанный список, поданный каналу, терял такие строки целиком — а на списке, где
 * диапазон оказывался единственной строкой, движок объявлял файл ДОМЕННЫМ и советовал
 * «подключите список как доменный». То есть штатный путь работы с большим списком
 * заканчивался пустым каналом и советом не по делу.
 *
 * Набор для этого готов: он объявлен с `flags interval` и `auto-merge`, и nft принимает
 * «a-b» как обычный элемент. */
static int looks_like_addr(const char *s) {
    const char *dash = strchr(s, '-');
    const char *end = s + strlen(s);
    if (!dash) return addr_half_ok(s, end);
    /* Ровно один дефис, и обе половины — адреса. */
    if (strchr(dash + 1, '-')) return 0;
    return addr_half_ok(s, dash) && addr_half_ok(dash + 1, end);
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
        /* Непрочитанный файл выбрасывается из группы ЗДЕСЬ, до подсчёта и до генерации:
         * дальше по коду его отсутствие уже не отличить от «списка не было», а разница
         * важна — про пропажу надо сказать. Причина почти всегда одна: обновление образа
         * сохранило спеку (она в keep.d) и не сохранило каталог списков — он там не
         * объявлен намеренно, это решение владельца (splicicd#6). */
        for (size_t k = 0; k < g->files_n; ) {
            FILE *probe = fopen(g->files[k], "r");
            if (probe) { fclose(probe); k++; continue; }
            fprintf(stderr, LOG_W "%s: список канала не читается (%s) — его адреса в набор "
                            "не попадут\n", g->files[k], strerror(errno));
            for (size_t m = k + 1; m < g->files_n; m++) g->files[m - 1] = g->files[m];
            g->files_n--;
        }
        if (!g->files_n && !g->domains && !g->all) {
            /* Ни одного читаемого адресного списка, доменов нет. Канал остаётся пустым —
             * почему именно так, сказано у поля `emptied`. */
            g->emptied = 1;
            fprintf(stderr, LOG_W "канал «%s»: ни один из его списков не читается — правило "
                            "остаётся, но не совпадает ни с чем\n",
                    g->members_n ? g->members[0] : g->name);
        }
        /* Раньше здесь стоял пропуск доменных групп целиком. Теперь у группы могут быть и
         * адресные файлы: пропускать её значило бы не заметить пустой или сломанный список. */
        for (size_t k = 0; k < g->files_n; k++) {
            size_t total = 0, bad = 0, bad_line = 0;
            char sample[128];
            count_list(g->files[k], &total, &bad, sample, sizeof(sample), &bad_line);
            if (!total) {
                fprintf(stderr, LOG_W "%s: список пуст — канал «%s» ничего не поймает\n",
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
                fprintf(stderr, LOG_W "%s: строк не-адресов %zu из %zu, пропускаю их "
                                "(первая — %zu: «%s»)\n",
                        g->files[k], bad, total, bad_line, sample);
        }
    }
}

static size_t emit_elements(FILE *f, const char *path, size_t already) {
    FILE *in = fopen(path, "r");
    /* Не die: читаемость всех файлов уже проверена (check_address_lists), и попасть сюда
     * можно только гонкой — список удалили между проверкой и генерацией. Ронять из-за неё
     * весь набор правил незачем: пропадут адреса одного списка, и про это будет сказано. */
    if (!in) {
        fprintf(stderr, LOG_W "%s: список исчез во время сборки набора правил\n", path);
        return 0;
    }
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
        /* fputs, а не fprintf: на списке в сотни тысяч элементов разбор
         * форматной строки на каждый — это заметная доля времени apply. */
        if (n) fputs(", ", f);
        fputs(p, f);
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
        /* `any`-группе набор не нужен; опустевшей — нужен, иначе её правило потеряет
         * `ip daddr` и станет безусловным (см. поле `emptied`). */
        if (!g->files_n && !g->domains && !g->emptied) continue;
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
            /* Пустой набор объявляется БЕЗ строки elements: `elements = {  }` nft не примет,
             * а объявление без элементов — обычное дело (так же начинают жизнь доменные
             * наборы, которые наполняет резолвер). */
            if (g->files_n) {
                fprintf(f, "        elements = { ");
                size_t written = 0;
                for (size_t k = 0; k < g->files_n; k++)
                    written += emit_elements(f, g->files[k], written);
                fprintf(f, " }\n");
            }
            fprintf(f, "    }\n");
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
        if (g->files_n || g->domains || g->emptied) fprintf(f, "ip daddr @%s ", g->name);
        /* НАШИ биты, а не всё слово: `mark and ~маска or метка`. Перезапись стирала метку
         * mwan3/pbr/sqm молча, а их перезапись — нашу, и тогда помеченный пакет уходил по
         * таблице main, минуя запрет on_fail=drop (I-135). Диапазон объявлен в spec.h и в
         * контракте. Ядро при выводе канонизирует выражение (оно само выставляет в маске
         * бит, который следующий `or` всё равно поднимает) — на поведение это не влияет,
         * проверено на живом роутере. */
        if (out_needs_mark(o))
            /* Метка ПАКЕТА решает маршрут, метка СОЕДИНЕНИЯ позволяет с этим соединением
             * потом что-то сделать. Без второй запись conntrack про выход не знает ничего
             * (mark=0 в дампе), и «сними соединения этого выхода» выразить нечем — а это
             * единственный способ пересмотреть маршрут уже установленного соединения.
             *
             * Понадобилось это из-за выгрузки потоков: замер на роутере показал, что при
             * flow_offloading=1 наша цепочка видит 2-7 пакетов соединения вместо
             * одиннадцати тысяч, то есть после установления маршрут больше не
             * пересматривается — и запрет on_fail=drop до такого соединения не доходит
             * (R-096). Тот же приём и по той же причине использует mwan3. */
            /* У kind=zapret к нашей метке добавляется чужой бит — тот, которым системный
             * zapret узнаёт «этот пакет не мой» (ZAPRET_SKIP_MARK, см. spec.h). Без него
             * трафик разбирали бы двое: сначала общий обход своей стратегией, потом наш
             * экземпляр своей, — и вышло бы не то, что выбрал человек, ни в одном из двух
             * смыслов. Ставится ЗДЕСЬ, в prerouting, потому что цепочки zapret висят на
             * postrouting: позже было бы поздно. */
            fprintf(f, "meta mark set mark and 0x%08x or 0x%08x ct mark set mark ",
                    ~STEER_MARK_MASK,
                    o->kind == OUT_ZAPRET ? (o->mark | ZAPRET_SKIP_MARK) : o->mark);
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

    /* ---- выходы kind=zapret: помеченный трафик уходит в свой nfqws ----------------
     *
     * ЗДЕСЬ И БОЛЬШЕ НИГДЕ движок соприкасается с обходом DPI. Никаких стратегий он не
     * знает, ключей nfqws не разбирает и процесс отсюда не запускает: его дело — сказать
     * ядру, какой помеченный трафик в какую очередь отдать, и это ровно то же самое, что
     * он делает метками и таблицами для туннелей.
     *
     * Всё, что ниже, СВЕРЕНО С ЖИВЫМ НАБОРОМ ПРАВИЛ zapret, а не выведено из документации:
     * пакет remittor/zapret-openwrt v72.20260307 поставлен на роутер 10.8.1.87 (OpenWrt
     * 25.12.5, nftables 1.1.6), и `nft list table inet zapret` показал вот что.
     *
     *   chain postnat_hook { type filter hook postrouting priority srcnat + 1;
     *       meta mark & 0x40000000 == 0x00000000 jump postnat }
     *   chain postnat { oifname @wanif tcp dport {...} ct original packets 1-9
     *       ip daddr != @nozapret meta mark set meta mark | 0x20000000
     *       ct mark set ct mark | 0x40000000 queue flags bypass to 200 }
     *   chain predefrag { type filter hook output priority -401;
     *       meta mark & 0x40000000 != 0x00000000 jump predefrag_nfqws }
     *   chain predefrag_nfqws { meta mark & 0x20000000 != 0x00000000 notrack ... }
     *
     * Из этого следуют ТРИ решения, и ни одно из них не про вкус.
     *
     * ПРИОРИТЕТ srcnat + 2, а не mangle. Сначала здесь стояло `mangle + 10` (то есть -140),
     * и это было неверно дважды. Во-первых, mangle идёт ДО трансляции адресов, а nfqws
     * обязан видеть пакет таким, каким тот уйдёт с роутера: у zapret на OpenWrt для этого
     * есть отдельный режим POSTNAT, включённый по умолчанию, и его цепочка висит на
     * srcnat + 1 именно поэтому. Чинить ClientHello с адресом источника из локальной сети —
     * значит чинить пакет, которого в сети не будет. Во-вторых, до нашей цепочки должна
     * успеть отработать цепочка zapret: она увидит нашу метку, пропустит наш трафик, и
     * пакет дойдёт сюда нетронутым. Обратный порядок дал бы два обхода на одном пакете.
     *
     * ЧУЖИЕ БИТЫ МЕТКИ. На исходный пакет мы ставим 0x40000000 (это делает prerouting_mark
     * выше) — по нему postnat_hook говорит «не мой» и трафик выхода мимо общего обхода
     * проходит целиком. Свой обработчик поднимается с --dpi-desync-fwmark=0x60000000, то
     * есть его собственные пакеты (подделки, повторы, куски разрезанного) несут ОБА бита:
     * 0x40000000 уводит их и от общего обхода, и в predefrag_nfqws — там их снимают с учёта
     * conntrack, без чего ядро отбросило бы их как INVALID; 0x20000000 выводит их из НАШЕЙ
     * очереди первым правилом ниже. Разные биты у исходного и у порождённого — единственный
     * способ различить их здесь: у обоих есть 0x40000000, и один бит на двоих означал бы
     * либо круг (свой пакет снова в свою очередь), либо неразобранный исходный.
     *
     * ПРЕДЕЛ ПАКЕТОВ. `ct original packets 1-N` — не осторожность, а цена: без него в
     * userspace уезжает КАЖДЫЙ пакет соединения, то есть весь поток видео проходит через
     * копирование в nfqws и обратно на 880 МГц. Обходу нужны только первые пакеты — там
     * лежат SYN, ClientHello и QUIC Initial; zapret по той же причине ставит свой предел
     * (NFQWS_TCP_PKT_OUT, по умолчанию 9), и число здесь взято его же.
     *
     * BYPASS ВЫРАЖАЕТ on_fail, и выражает его САМО ЯДРО, без сторожа и без опроса:
     *   on_fail=direct — `bypass`: нет процесса на очереди, пакет идёт дальше как обычный;
     *   on_fail=drop   — без `bypass`: нет процесса — пакет отбрасывается.
     * Умолчание общее для всех выходов — drop, и здесь оно значит то же, что везде: канал
     * заводят ради обхода, и молча вернуть трафик на открытый путь в момент, когда обход
     * умер, — значит нарушить единственное обещание выхода ровно тогда, когда это важнее
     * всего. Оговорка у `bypass` одна и её стоит знать: он срабатывает и на ПЕРЕПОЛНЕНИИ
     * очереди, а не только на отсутствии процесса. */
    if (has_zapret()) {
        fprintf(f, "\n    chain zapret_queue {\n"
                   "        type filter hook postrouting priority srcnat + 2; policy accept;\n");
        fprintf(f, "        meta mark and 0x%08x == 0x%08x counter return "
                   "comment \"steer:zapret-own\"\n", ZAPRET_MINE_BIT, ZAPRET_MINE_BIT);
        /* БИТ 0x40000000 СНИМАЕТСЯ С ПАКЕТА ПЕРЕД ОЧЕРЕДЬЮ, и без этого выход не работал
         * вовсе. nfqws считает своим порождённым любой пакет, у которого с его
         * --dpi-desync-fwmark есть хоть один общий бит, и пропускает такой без обработки
         * («ignoring generated packet» в его отладке). Наш обработчик поднят с 0x60000000,
         * бит 0x40000000 в него входит — а на исходном пакете он стоит с prerouting, чтобы
         * общий обход сказал «не мой». Пока бит доезжал до очереди, обработчик не трогал
         * НИ ОДНОГО пакета: снято с роутера владельца — YouTube через выход 3 из 37 при
         * любой стратегии, со снятым битом 33 из 37. Снимать здесь безопасно: цепочка
         * общего обхода (srcnat + 1) уже позади, дальше бит никому не нужен, а свои восемь
         * бит метки (маршрут) целы. */
        for (size_t i = 0; i < g_out_n; i++) {
            struct output *o = &g_out[i];
            if (o->kind != OUT_ZAPRET) continue;
            fprintf(f, "        meta mark and 0x%08x == 0x%08x ct original packets 1-%d "
                       "meta mark set mark and 0x%08x counter queue num %d%s "
                       "comment \"steer:zapret:%s\"\n",
                    STEER_MARK_MASK, o->mark, ZAPRET_FIRST_PACKETS, ~ZAPRET_SKIP_MARK,
                    out_zapret_queue(o), o->on_fail == FAIL_DROP ? "" : " bypass", o->name);
        }
        fprintf(f, "    }\n");
        /* Ответные пакеты — SYN-ACK и два за ним — тоже в очередь, как у zapret
         * (`ct reply packets 1-3`): по ним nfqws узнаёт TTL сервера для autottl и состояние
         * соединения; без них стратегии с autottl работали бы вслепую. Соединение узнаётся по
         * ct mark — он ставится вместе с меткой в prerouting и несёт номер выхода. Всегда с
         * bypass: ответ терять нельзя ни при каком on_fail, исходные пакеты и так решают
         * судьбу соединения. */
        fprintf(f, "\n    chain zapret_queue_in {\n"
                   "        type filter hook prerouting priority mangle; policy accept;\n");
        for (size_t i = 0; i < g_out_n; i++) {
            struct output *o = &g_out[i];
            if (o->kind != OUT_ZAPRET) continue;
            fprintf(f, "        ct mark and 0x%08x == 0x%08x ct reply packets 1-3 "
                       "counter queue num %d bypass comment \"steer:zapret-reply:%s\"\n",
                    STEER_MARK_MASK, o->mark, out_zapret_queue(o), o->name);
        }
        fprintf(f, "    }\n");
        /* СВОЯ predefrag, а не расчёт на цепочку zapret. Порождённые обработчиком пакеты
         * (подделки, повторы, куски разрезанного) для conntrack — мусор: чужие номера
         * последовательности, дубли, части без начала. Учтённые, они становятся INVALID, и
         * fw4 их отбрасывает — обход молча не работает, хотя обработчик жив и очередь
         * считает пакеты. Снятие с учёта (notrack) делает predefrag_nfqws системного
         * zapret, и до сих пор мы на неё и рассчитывали: у порождённых пакетов поднят
         * 0x40000000, её условие. Но эта цепочка живёт в таблице СЛУЖБЫ zapret и исчезает
         * вместе с ней — а выключить общий обход и оставить обход только одному выходу
         * (например, YouTube) — ровно то, ради чего выход kind=zapret и заводят. Снято с
         * живого роутера владельца: общий обход выключен, выход стоит, стратегия рабочая,
         * очередь считает пакеты — YouTube не открывается; проверка стратегий при этом даёт
         * числа, равные «без обхода», по той же причине.
         *
         * Правила — те же четыре, что у zapret (postnat-метка, два вида фрагментов,
         * данные без ACK), и на том же приоритете -401 — до conntrack. Две одинаковые
         * цепочки при работающем общем обходе не мешают друг другу: notrack дважды — это
         * notrack. */
        fprintf(f, "\n    chain zapret_predefrag {\n"
                   "        type filter hook output priority -401; policy accept;\n"
                   "        meta mark and 0x%08x != 0x00000000 jump zapret_predefrag_nfqws "
                   "comment \"steer:zapret-notrack\"\n"
                   "    }\n"
                   "    chain zapret_predefrag_nfqws {\n"
                   "        meta mark and 0x%08x != 0x00000000 notrack comment \"postnat traffic\"\n"
                   "        ip frag-off and 0x1fff != 0x0 notrack comment \"ipfrag\"\n"
                   "        exthdr frag exists notrack comment \"ipfrag\"\n"
                   "        tcp flags ! syn,rst,ack notrack comment \"datanoack\"\n"
                   "    }\n", ZAPRET_SKIP_MARK, ZAPRET_MINE_BIT);
    }

    /* ---- перехват Telegram у выходов kind=tgws ------------------------------------
     *
     * ПЕРЕХВАТ, А НЕ МАРШРУТ. Приложению ничего не настраивают: соединение с дата-центром
     * заворачивается на мост здесь же, в ядре, а он уводит его веб-сокетом (см. длинное
     * объяснение у TGWS_PORT_BASE в spec.h).
     *
     * ПРИОРИТЕТ dstnat + 1, и оба слова важны. Метку канала ставит prerouting на
     * `mangle + 1` (то есть -149), а трансляция адресов идёт на -100 — значит к моменту
     * этой цепочки метка на пакете уже есть и по ней можно узнать выход. Плюс единица —
     * чтобы пропустить вперёд свою же цепочку fakeip: доменное правило сначала должно
     * вернуть настоящий адрес, и только потом мы решаем, наш ли он.
     *
     * ТОЛЬКО PREROUTING, то есть только трафик клиентов сети. Трафик самого роутера сюда
     * не попадает нарочно: перехватывать собственные соединения движка (обновление
     * списков, проверки) значило бы заворачивать в мост то, что к Telegram отношения не
     * имеет, а разделять их было бы нечем.
     *
     * ПОРТЫ — те, на которых Telegram держит MTProto: 443 и 80 (обычные), 5222 (запасной у
     * старых клиентов). UDP здесь нет: голос звонков в веб-сокет не заворачивается (см.
     * spec.h), и пусть идёт своим путём.
     *
     * redirect, а не dnat на петлю: redirect подставляет адрес того интерфейса, откуда
     * пришёл пакет, и обратный путь ядро собирает само. Исходный адрес назначения мост
     * узнаёт у ядра через SO_ORIGINAL_DST — из него же выводится номер дата-центра. */
    if (has_tgws()) {
        fprintf(f, "\n    chain tgws_redirect {\n"
                   "        type nat hook prerouting priority dstnat + 1; policy accept;\n");
        for (size_t i = 0; i < g_out_n; i++) {
            struct output *o = &g_out[i];
            if (o->kind != OUT_TGWS) continue;
            fprintf(f, "        meta mark and 0x%08x == 0x%08x tcp dport { 443, 80, 5222 } "
                       "counter redirect to :%d comment \"steer:tgws:%s\"\n",
                    STEER_MARK_MASK, o->mark, out_tgws_port(o), o->name);
        }
        fprintf(f, "    }\n");
    }

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
         * redirecting TCP would break the truncated-answer retry.
         *
         * Форм у правила две, и выбирает между ними то же, что выбирает «кто» у каналов.
         * Заданы подсети — забираем IPv4 по адресу, а IPv6 по устройству, потому что
         * стабильного `ip6 saddr` у локального префикса нет; это ровно то, что было.
         * Подсетей нет — забираем по устройству ОБА семейства одним правилом: пометка
         * семейства там не нужна, а без неё уходит и прежняя асимметрия. */
        fprintf(f, "    chain prerouting_dns {\n"
                   "        type nat hook prerouting priority dstnat; policy accept;\n");
        for (size_t i = 0; i < g_from_default_n; i++)
            fprintf(f, "        ip saddr %s udp dport 53 counter redirect to :%d\n",
                    g_from_default[i], DNS_PORT);
        fprintf(f, "        ");
        if (g_from_default_n) fprintf(f, "meta nfproto ipv6 ");
        emit_ifs(f, 0);
        fprintf(f, "udp dport 53 counter redirect to :%d\n", DNS_PORT);
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

/* Имя цепочки — первое слово: и в заголовке (`chain srcnat_vpn {`), и в переходе
 * (`jump srcnat_vpn comment ...`) оно стоит первым и кончается пробелом или скобкой. */
static void chain_token(const char *s, char *out, size_t cap) {
    size_t i = 0;
    while (*s == ' ' || *s == '\t') s++;
    while (i + 1 < cap && s[i] && s[i] != ' ' && s[i] != '\t' && s[i] != '\n'
           && s[i] != '{' && s[i] != ';')
        out[i] = s[i], i++;
    out[i] = 0;
}

#define FWC_CHAINS 16
static void remember_chain(char tab[FWC_CHAINS][64], size_t *n, const char *name) {
    if (!*name || *n >= FWC_CHAINS) return;
    for (size_t i = 0; i < *n; i++)
        if (!strcmp(tab[i], name)) return;
    snprintf(tab[(*n)++], 64, "%s", name);
}

/* Один дамп набора правил на процесс.
 *
 * fw_check дёргается по разу на выход, report_traceroute_dep добавляет свой
 * дамп — то есть status (а его интерфейс опрашивает каждые пять секунд) и apply
 * платили sh+nft и полный обход ruleset ядром по два-пять раз за запуск, на
 * одни и те же данные. На слабом роутере это был главный фоновый расход CPU
 * всей системы. Кэш корректен ровно потому, что все читатели работают ПОСЛЕ
 * любых изменений набора правил в этом же процессе: в apply отчёты идут после
 * `nft -f`, а status/diag ruleset не трогают. Дамп по-прежнему --terse (см.
 * комментарий в fw_check), так что в памяти он занимает килобайты, а живёт до
 * конца короткоживущего CLI-процесса. */
/* Кэш всегда либо NULL, либо получен malloc'ом: tests/fwmatch.c сбрасывает его
 * между пробами обычным free(), изображая свежий процесс на каждую пробу. */
static char *g_ruleset_dump;

static const char *ruleset_dump(void) {
    if (g_ruleset_dump) return g_ruleset_dump;
    size_t cap = 65536, n = 0;
    char *buf = malloc(cap);
    if (!buf) return ""; /* не кэшируем — следующий вызов попробует снова */
    FILE *f = popen("nft -t list ruleset 2>/dev/null || "
                    "nft list ruleset 2>/dev/null", "r");
    if (!f) { buf[0] = '\0'; return g_ruleset_dump = buf; }
    for (;;) {
        if (n + 4096 + 1 > cap) {
            char *nb = realloc(buf, cap *= 2);
            if (!nb) break; /* сколько влезло — с тем и работаем */
            buf = nb;
        }
        size_t r = fread(buf + n, 1, 4096, f);
        if (!r) break;
        n += r;
    }
    pclose(f);
    buf[n] = '\0';
    return g_ruleset_dump = buf;
}

/* Следующая «строка» кэша с семантикой fgets: длинная строка выдаётся кусками
 * по cap-1 — читатели ниже написаны в этих терминах. Возвращает позицию
 * продолжения или NULL в конце. */
static const char *dump_line(const char *p, char *line, size_t cap) {
    if (!p || !*p) return NULL;
    size_t len = 0;
    while (len < cap - 1 && p[len] && p[len] != '\n') len++;
    if (len < cap - 1 && p[len] == '\n') len++;
    memcpy(line, p, len);
    line[len] = '\0';
    return p + len;
}

static struct fwcheck fw_check(const char *device) {
    struct fwcheck r = { 0, 0 };
    /* Зона может называться не так, как устройство, и тогда оба признака ниже молчат:
     * fw4 пишет имя ЗОНЫ и в имя цепочки (`srcnat_vpn`), и в комментарий правила
     * ("Masquerade IPv4 vpn traffic"), а устройство называет ТОЛЬКО на переходе в эту
     * цепочку: `oifname "warp0" jump srcnat_vpn`. Снято с fw4 25.12: при зоне с именем,
     * отличным от имени устройства, во всём наборе нет ни одной строки, где устройство
     * стояло бы рядом со словом masquerade, — и выход получал «нет masquerade» при
     * включённом masq (splicicd#8). Поэтому цепочка, в которую устройство уходит по oif,
     * засчитывается вместе со своим содержимым. Порядок строк не предполагается: дамп
     * может назвать цепочку и до перехода, и после, поэтому оба множества собираются за
     * один проход и пересекаются в конце. */
    char dev_chain[FWC_CHAINS][64], masq_chain[FWC_CHAINS][64];
    size_t dev_chain_n = 0, masq_chain_n = 0;
    /* --terse: без содержимого наборов. Проверка смотрит на имена устройств в правилах
     * и цепочках, а элементы наборов ей не нужны — при этом их бывают десятки тысяч, и
     * полный дамп на слабом роутере стоил секунды НА КАЖДЫЙ ВЫЗОВ. Флаг есть в nft
     * с 0.9.4 (OpenWrt 21+); на случай древней сборки — откат к полному дампу,
     * медленно, но не слепо. Сам дамп берётся из ruleset_dump() — один на процесс. */
    const char *pos = ruleset_dump();
    char line[2048];
    char chain[128] = "";
    int in_steer = 0;
    while ((pos = dump_line(pos, line, sizeof(line))) != NULL) {
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
        /* Переход, на котором названо устройство: `oifname "warp0" jump srcnat_vpn`.
         * Требование oif намеренное — masquerade живёт на выходе, и переход по входящему
         * устройству (dstnat) про NAT наружу не говорит ничего. */
        const char *j = strstr(line, "jump ");
        if (j && strstr(line, "oif") && names_device(line, device)) {
            char t[64];
            chain_token(j + 5, t, sizeof t);
            remember_chain(dev_chain, &dev_chain_n, t);
        }
        if (strstr(line, "masquerade") || strstr(line, "snat")) {
            if (names_device(line, device) || names_device(chain, device)) r.masqueraded = 1;
            else {
                char t[64];
                chain_token(chain, t, sizeof t);
                remember_chain(masq_chain, &masq_chain_n, t);
            }
        }
    }
    for (size_t i = 0; i < dev_chain_n && !r.masqueraded; i++)
        for (size_t k = 0; k < masq_chain_n; k++)
            if (!strcmp(dev_chain[i], masq_chain[k])) { r.masqueraded = 1; break; }
    return r;
}

static void report_traceroute_dep(void) {
    if (!g_traceroute_hops) return;
    /* Say the useless case out loud rather than leaving the operator to discover it
     * as a column of asterisks. */
    for (size_t i = 0; i < g_out_n; i++) {
        if (!out_has_device(&g_out[i])) continue;
        if (fw_check(g_out[i].device).masqueraded) {
            fprintf(stderr, LOG_W "traceroute_hops cannot work for output %s: %s "
                            "masquerades, so ICMP errors come addressed to the router "
                            "and only conntrack can route them to the client — "
                            "untracking them drops the hops entirely\n",
                    g_out[i].name, g_out[i].device);
            return;
        }
    }
    /* Тот же кэшированный дамп, что в fw_check: ищется правило, а не элементы. */
    const char *pos = ruleset_dump();
    int ok = 0;
    char line[2048];
    while ((pos = dump_line(pos, line, sizeof(line))) != NULL)
        if (strstr(line, "untracked") && strstr(line, "accept")) ok = 1;
    if (!ok)
        fprintf(stderr, LOG_W "traceroute_hops is on but no rule accepting untracked "
                        "packets was found — ICMP time-exceeded will be dropped by the "
                        "firewall and hops will show as asterisks. Needed once, in the "
                        "firewall (not here): accept ct state untracked icmp type "
                        "time-exceeded towards %s\n", g_lan_dev[0]);
}

static void report_output_deps(void) {
    for (size_t i = 0; i < g_out_n; i++) {
        if (!out_has_device(&g_out[i])) continue;
        struct fwcheck c = fw_check(g_out[i].device);
        if (!c.in_firewall)
            fprintf(stderr, LOG_W "output %s: %s is not mentioned by the firewall at all — "
                            "traffic steered there will not come back until it is in a zone\n",
                    g_out[i].name, g_out[i].device);
        /* Выходу vless NAT не нужен, и предупреждать о нём — значит посылать человека
         * настраивать то, чему нечего транслировать: клиент завершает TCP у себя и
         * соединяется с сервером обычным сокетом, поэтому адрес клиента наружу не уезжает
         * вовсе. Предупреждение «нет masquerade» здесь было ложной тревогой, а ложная
         * тревога дороже отсутствующей: по ней настраивают лишнее и перестают верить
         * настоящим. Про зону предупреждать всё равно надо — без неё fw4 не пропускает
         * транзит, и это проверено с настоящего клиента.
         *
         * У xsteer тот же итог по другой причине: адреса клиентов границу переходят, но
         * переходят к хабу внутри туннеля, где транслировать их нечем. Там NAT не просто
         * не нужен, а вреден — он скрывает, от какой пира пришёл пакет, и ломает
         * обратный поиск по AllowedIPs. Условие поэтому одно (out_self_natting), а
         * объяснения в diag разные: см. ветку про masquerade в cmd_diag.
         *
         * Спрашивается ВЛАДЕЛЕЦ устройства, а не выход, который его назвал (out_for_device):
         * в пуле kind=interface активным может быть устройство VLESS-туннеля, и вопрос «нужен
         * ли ему masquerade» решает то, чем устройство является, а не то, кто его перечислил.
         * Иначе — постоянная жалоба на исправной настройке. */
        else if (out_self_natting(out_for_device(&g_out[i], g_out[i].device))) {
            /* нечего проверять */
        }
        else if (!c.masqueraded)
            fprintf(stderr, LOG_W "output %s: no masquerade/snat rule found for %s — "
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
        char table[16];
        snprintf(table, sizeof(table), "%d", g_oldreg[i].table);
        rule_drop(g_oldreg[i].mark, g_oldreg[i].table);
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
        char table[16];
        snprintf(table, sizeof(table), "%d", g_out[i].table);
        rule_drop(g_out[i].mark, g_out[i].table);     /* обе формы, включая копии */
        rule_add(g_out[i].mark, g_out[i].table);
        const char *flush[] = { "ip", "route", "flush", "table", table, NULL };
        run(flush);
        const char *route[] = { "ip", "route", "add", "default", "dev", g_out[i].device,
                                "table", table, NULL };
        if (run(route) != 0) {
            fprintf(stderr, LOG_W "output %s: cannot route via %s — is the device up?\n",
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
                fprintf(stderr, LOG_W "output %s: трафик остановлен до появления "
                                "рабочего устройства (on_fail=drop)\n", g_out[i].name);
            }
        }
    }
}

/* Умеет ли ЯДРО отдавать пакеты в очередь nfqueue.
 *
 * ЗАЧЕМ ОТДЕЛЬНАЯ ПРОВЕРКА. Без модуля nft_queue правило `queue num N` не отвергается
 * разбором — оно отвергается ядром, и nft говорит об этом так: «Could not process rule: No
 * such file or directory» с указателем на слово queue. Дословно проверено на роутере
 * (OpenWrt 25.12, nftables 1.1.6, kmod-nft-queue не установлен). Прочитать в этом «нет
 * пакета kmod-nft-queue» невозможно, а последствие — отказ ВСЕЙ транзакции: `nft -f`
 * атомарен, поэтому вместе с очередью не встают ни наборы, ни метки, ни перенаправление
 * DNS. То есть один незнакомый роутеру вид выхода снимает маршрутизацию целиком.
 *
 * Зависимость пакета этого не закрывает, и это главный довод. Движок ставят файлом из
 * GitHub Releases (install.sh), а файл зависимостей не разрешает — их проверяет только
 * менеджер пакетов. Объявить kmod-nft-queue в .apk нужно (и объявлено), но полагаться на
 * это как на единственную защиту значит защитить не тот путь установки.
 *
 * ПРОБА, А НЕ ПОИСК МОДУЛЯ. Спросить у ядра «есть ли nft_queue» нечем: /proc/modules врёт о
 * встроенном в ядро (=y вместо =m), а перечня поддерживаемых выражений nftables не отдаёт.
 * Поэтому спрашивается ровно то, что нам нужно: примет ли ядро правило с queue. Стоит это
 * одного запуска nft и только когда в спеке есть выход kind=zapret. */
static int nfqueue_supported(void) {
    char tmp[] = "/tmp/steer-qprobe.XXXXXX";
    int fd = mkstemp(tmp);
    if (fd < 0) return 1;   /* не смогли проверить — не мешаем: решать будет сам nft */
    FILE *f = fdopen(fd, "w");
    if (!f) { close(fd); unlink(tmp); return 1; }
    /* Своё имя таблицы: `nft -c` ничего не создаёт, но столкнуться именем с чужой живой
     * таблицей всё равно нельзя — проверка тогда проверяла бы её содержимое. */
    fprintf(f, "table inet steer_qprobe {\n"
               "    chain c {\n"
               "        type filter hook output priority mangle + 10; policy accept;\n"
               "        meta mark and 0x%08x == 0x%08x queue num %d bypass\n"
               "    }\n}\n", STEER_MARK_MASK, STEER_MARK_BASE, ZAPRET_QUEUE_BASE);
    fclose(f);
    const char *check[] = { "nft", "-c", "-f", tmp, NULL };
    int rc = run_quiet(check);
    unlink(tmp);
    return rc == 0;
}

static int cmd_apply(const char *spec, int dry) {
    load_spec(spec);
    /* Снимок реестра — строго до registry_assign: тот перезапишет файл текущими
     * выходами, и метки удалённых/переименованных будут потеряны вместе с
     * единственным способом снять их правила из ядра. */
    registry_snapshot();
    registry_assign();
    build_groups();
    /* Устройство выхода — то, что несёт трафик сейчас, а не первое в списке кандидатов.
     * Иначе применение настройки уводило бы таблицу с работающего запасного устройства на
     * неработающее основное, а при on_fail=drop ещё и ставило запрет — то есть каждое
     * сохранение в интерфейсе роняло бы пул до следующего прохода сторожа (до минуты). */
    outputs_adopt_active();
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

    /* Отказываем ДО транзакции и НАЗЫВАЕМ причину: иначе человек получит отказ всей
     * маршрутизации с сообщением про несуществующий файл. Пакет назван прямо — его же
     * тянет за собой zapret, поэтому у тех, кто обходом уже пользуется, он стоит. */
    if (has_zapret() && !nfqueue_supported())
        die("в спеке есть выход kind=zapret, а ядро не принимает правило queue — "
            "нужен пакет kmod-nft-queue (его ставит и сам zapret). Правила НЕ применены: "
            "nft грузит набор целиком, и отказ на очереди снял бы заодно наборы, метки и "
            "перенаправление DNS", NULL);

    char tmp[] = "/tmp/steer-ruleset.XXXXXX";
    int fd = mkstemp(tmp);
    if (fd < 0) die("cannot create a temporary ruleset", NULL);
    FILE *f = fdopen(fd, "w");
    /* Крупный буфер на чисто дозаписывающий поток: musl по умолчанию даёт
     * BUFSIZ в 1 КБ, и набор на сотни тысяч элементов дробился на тысячи
     * мелких write. Статический — чтобы не зависеть от кучи в момент,
     * когда рядом nft уже строит своё дерево разбора. */
    static char genbuf[65536];
    setvbuf(f, genbuf, _IOFBF, sizeof(genbuf));
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
        fprintf(stderr, LOG_W "nft refused the ruleset (kept: %s)\n", tmp);
        const char *check[] = { "nft", "-c", "-f", tmp, NULL };
        run(check);
        return 1;
    }
    unlink(tmp);
    apply_routing();
    cleanup_stale_routing();
    /* Снимок состояния СНИМАЕТСЯ: он описывает то, что было применено до этой транзакции, и
     * `status --fast` отдавал бы его как нынешнее — то есть прежние выходы и прежние каналы
     * ровно в тот момент, когда человек нажал «Применить» и смотрит, подействовало ли.
     * Пересобрать его здесь нельзя честно: правила уже стоят, а вот таблицы маршрутизации
     * привязывают к своим устройствам сами процессы выходов, и снимок, снятый сейчас, врал
     * бы в другую сторону. Пустое место `--fast` переживает — он тогда считает всё сам. */
    char snap[256];
    status_snap_path(snap, sizeof snap);
    unlink(snap);
    report_output_deps();
    report_traceroute_dep();
    printf("steer: applied %zu channel(s), %zu output(s)\n", g_ch_n, g_out_n);
    return 0;
}

/* ---- status --------------------------------------------------------------- */
/* Counters come from the live chain, matched by the comment each rule carries —
 * which is why generation puts the channel name there. Without it the numbers
 * exist but belong to nobody. */

/* СНИМОК СОСТОЯНИЯ: зачем движок помнит свой последний ответ.
 *
 * Полный ответ стоит работы: разбор спеки, обход выходов с чтением /sys, чтение счётчиков
 * из живой цепочки nft. Замерено на стенде (mipsel 24kc, 880 МГц): 91 мс на вызов, из них
 * основное — запуск и разбор вывода nft. Пока на это смотрел только круг опроса раз в пять
 * секунд, цена была не видна; но ровно этот ответ нужен ПЕРВЫМ при открытии окна splify2, и
 * там он складывается со всем остальным, что страница спрашивает в тот же миг, — человек
 * ждёт на пустом экране.
 *
 * Поэтому движок пишет свой ответ рядом с остальным состоянием и умеет отдать запомненное
 * немедленно (`--fast`). Снимок обновляют двое: любой полный `status` (то есть каждый круг
 * опроса открытой страницы) и отдельный экземпляр procd раз в пять минут — чтобы на только
 * что открытой странице лежало не вчерашнее.
 *
 * ЧЕСТНОСТЬ ЗДЕСЬ ГЛАВНОЕ. Запомненный ответ отдаётся с двумя полями: `at` — когда его
 * собрали, `cached: true` — что это не измерение, а память. Без них интерфейс нарисовал бы
 * запомненное как живое, и «Работает» стояло бы на упавшем туннеле; в проекте это уже
 * стоило отдельного признака `stale` в самом интерфейсе, и повторять ту же ошибку на
 * ступень ниже незачем.
 *
 * Устаревший снимок при этом НЕ отвергается: смысл `--fast` в том, чтобы показать хоть
 * что-то сразу, а решение «это слишком старо, чтобы показывать» принимает тот, кто
 * спрашивает, — у него есть `at`. Снимка нет вовсе — команда считает всё честно, то есть
 * `--fast` никогда не отвечает пустотой.
 */
static void status_snap_path(char *buf, size_t n) {
    snprintf(buf, n, "%s/status.json", g_state_dir);
}

/* Снимок больше этого не бывает: сотня выходов и сотня каналов — это единицы килобайт.
 * Предел стоит потому, что файл читается в буфер на стеке, а писать его мог не только
 * движок. */
#define STATUS_SNAP_MAX 262144

/* Отдать запомненное. 0 — отдали, -1 — снимка нет или он не похож на наш ответ.
 *
 * `cached` дописывается ПЕРЕД закрывающей скобкой, а не в начало: так порядок полей ответа
 * остаётся тем же, каким его видят все нынешние читатели, и `{"schema":1,...` по-прежнему
 * первое, что стоит в строке. */
static int status_from_snapshot(void) {
    char snap[256];
    status_snap_path(snap, sizeof snap);
    FILE *f = fopen(snap, "r");
    if (!f) return -1;
    static char buf[STATUS_SNAP_MAX];
    size_t n = fread(buf, 1, sizeof buf, f);
    int truncated = !feof(f);
    fclose(f);
    if (truncated) return -1;   /* не влез — значит это не наш снимок */
    while (n && (buf[n - 1] == '\n' || buf[n - 1] == ' ')) n--;
    /* Проверка формы, а не доверие имени файла: оборванная запись оставила бы обрубок,
     * и отдать его значило бы выдать половину JSON за ответ движка. */
    if (n < 3 || buf[0] != '{' || buf[n - 1] != '}') return -1;
    fwrite(buf, 1, n - 1, stdout);
    fputs(",\"cached\":true}\n", stdout);
    return 0;
}

/* Сам ответ. Поток параметром, потому что печатается он ДВАЖДЫ в разные места: в снимок на
 * диске и человеку (точнее, тому, кто позвал). Считать его два раза было бы вдвое дороже
 * ровно того, ради чего снимок и заведён. */
static void status_emit(FILE *out) {
    /* УМЕНИЯ ДВИЖКА — перечнем имён и верхним уровнем.
     *
     * Зачем вообще. Незнакомый ключ спеки движок пропускает МОЛЧА (js_skip) — это и есть
     * совместимость вперёд внутри мажора, — поэтому управляющий слой, записавший новое поле
     * в движок постарше, получает применённую спеку и трафик не туда, куда просил. Узнать
     * поколение до записи он обязан сам, и до сих пор узнавал по косвенным признакам:
     * наличию `lan_devices` здесь и поля `nodes` у выхода kind=vless. Второй признак виден
     * ТОЛЬКО на роутере, где такой выход уже есть, — а смешанный пул нужнее всего там, где
     * его нет вовсе (xsteer плюс wireguard), и там же движок постарше молча уводит канал в
     * blackhole. Интерфейс поэтому вынужден был запрещать пул до первого применённого
     * выхода подписки (splify2, запуск 69).
     *
     * ПОЧЕМУ ИМЕНА, А НЕ НОМЕР ВЕРСИИ. Версию в дерево проставляет релизный workflow, а не
     * коммит: движок из main через два коммита после релиза называет то же число, что и
     * релиз (I-054). Сравнивать по нему — значит однажды объявить умеющим движок, который
     * не умеет. Имя умения печатает тот же код, который его и делает.
     *
     * ДОГОВОР О ПЕРЕЧНЕ. Поля нет вовсе — движок старше 1.3.0, и тогда судить о нём
     * по-прежнему нечем, кроме косвенных признаков. Набор имён может и расти, и сокращаться
     * между версиями: потребитель обязан терпеть незнакомые имена и не должен требовать
     * наличия какого-либо конкретного. */
    /* КОГДА СОБРАН ЭТОТ ОТВЕТ. Печатается всегда, а не только в снимке, и это не
     * избыточность: ответ движка теперь бывает запомненным, и различить измерение от памяти
     * по одному лишь `cached` было бы нечем — интерфейсу нужен возраст, чтобы сказать
     * человеку «данные такой-то давности», а не рисовать их живыми. У живого ответа возраст
     * нулевой, и это тот же контракт, а не особый случай. */
    fprintf(out, "{\"schema\":1,\"at\":%ld,"
                 "\"features\":[\"lan_devices\",\"nodes\",\"pool\",\"active_device\","
                 "\"status_cache\",\"xslink\",\"xsteer_state\"]",
            (long)time(NULL));
    /* Локальные устройства — следом: интерфейс показывает, с чего забирается трафик, и
     * без этого поля ему пришлось бы читать спеку вторым источником, то есть однажды
     * показать не то, что применено. */
    fprintf(out, ",\"lan_devices\":[");
    for (size_t i = 0; i < g_lan_dev_n; i++)
        fprintf(out, "%s\"%s\"", i ? "," : "", g_lan_dev[i]);
    fprintf(out, "],\"outputs\":{");
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
        fprintf(out, "%s\"%s\":{\"kind\":\"%s\"", i ? "," : "", g_out[i].name,
               out_kind_name(g_out[i].kind));
        if (out_has_device(&g_out[i])) {
            struct fwcheck c = fw_check(g_out[i].device);
            fprintf(out, ",\"device\":\"%s\",\"up\":%s,\"mark\":\"0x%08x\",\"table\":%d"
                   ",\"in_firewall\":%s,\"nat\":%s",
                   g_out[i].device, up ? "true" : "false", g_out[i].mark, g_out[i].table,
                   c.in_firewall ? "true" : "false", c.masqueraded ? "true" : "false");
            /* Кандидаты и режим отказа: без них failover не виден из интерфейса, и
             * человек не может понять, почему выход вдруг ведёт в другое устройство. */
            /* Ход подъёма — рядом с up, а не отдельным вызовом: интерфейс уже читает
             * status по кругу, и второй источник дал бы на экране два разных мгновения.
             * Поля нет вовсе, когда сказать нечего (устройство есть, файла нет, он устарел
             * или писавший процесс мёртв) — «не знаем» не должно читаться как «плохо». */
            if (!up) {
                /* Ход подъёма спрашивается у ВЛАДЕЛЬЦА устройства, а не у выхода, который
                 * его назвал: запись перебора узлов пишет клиент vless под своим именем, и
                 * пул, ждущий этот туннель, иначе отдавал бы «устройства нет» вместо
                 * «проверяю узлы, 3 из 26» — то же враньё, ради снятия которого перебор и
                 * стал виден (I-100). */
                struct probe_status pr =
                    probe_read(out_for_device(&g_out[i], g_out[i].device)->name);
                if (pr.state == PROBE_RUNNING)
                    fprintf(out, ",\"probe\":{\"state\":\"probing\",\"node\":%d,\"total\":%d}",
                           pr.node, pr.total);
                else if (pr.state == PROBE_FAILED)
                    fprintf(out, ",\"probe\":{\"state\":\"failed\",\"total\":%d}", pr.total);
                /* Номер вне подписки — СВОЁ состояние, а не разновидность failed: интерфейс
                 * обязан уметь сказать «поправьте номер», а не «поменяйте подписку». Оба
                 * числа рядом, потому что порознь они ничего не значат. */
                else if (pr.state == PROBE_NO_SUCH_NODE)
                    fprintf(out, ",\"probe\":{\"state\":\"no_such_node\",\"node\":%d"
                                 ",\"total\":%d}", pr.node, pr.total);
            }
            fprintf(out, ",\"devices\":[");
            for (size_t d = 0; d < g_out[i].devices_n; d++)
                fprintf(out, "%s\"%s\"", d ? "," : "", g_out[i].devices[d]);
            fprintf(out, "],\"on_fail\":\"%s\"",
                   g_out[i].on_fail == FAIL_DROP ? "drop" :
                   g_out[i].on_fail == FAIL_ZAPRET ? "zapret" : "direct");
            /* Выбранные узлы подписки — рядом с devices, потому что это то же самое: список
             * кандидатов выхода, только у vless кандидаты называются номерами узлов.
             * Печатается ВСЕГДА, в том числе пустым, и это главное здесь: незнакомый ключ
             * спеки движок пропускает молча (js_skip), поэтому интерфейс, записавший `nodes`
             * в старый движок, получил бы применённую спеку и трафик через узел, которого не
             * выбирал. Наличие поля в status — единственный способ узнать движок, который
             * `nodes` понимает, до того как их писать. Тем же приёмом узнаётся движок с
             * lan_devices. */
            if (g_out[i].kind == OUT_VLESS) {
                fprintf(out, ",\"nodes\":[");
                for (size_t d = 0; d < g_out[i].nodes_n; d++)
                    fprintf(out, "%s%d", d ? "," : "", g_out[i].nodes[d]);
                fprintf(out, "]");
            }
            /* Обфускация — поле, а не отдельный вид выхода, поэтому и в статусе она
             * поле. Признак живости здесь не печатается намеренно: status опрашивают
             * раз в пять секунд, а pgrep — это запуск процесса; приговор о живости
             * даёт diag, который спрашивают по нажатию. */
            if (g_out[i].obfs.on)
                fprintf(out, ",\"obfs\":{\"mode\":\"wg-over-tcp\",\"server\":\"%s:%d\""
                       ",\"listen\":\"%s:%d\"}",
                       g_out[i].obfs.server, g_out[i].obfs.server_port,
                       g_out[i].obfs.listen, g_out[i].obfs.listen_port);
        }
        /* Выход kind=zapret: устройства нет, поэтому и ветка своя. Печатается всё, что о
         * нём вообще можно знать снаружи, и ничего сверх того:
         *
         *   mark, queue  — по ним управляющий слой находит СВОЙ процесс на СВОЕЙ очереди.
         *                  Номер очереди выводится из метки (см. out_zapret_queue), и
         *                  печатать его надо именно потому, что вывод — наше внутреннее
         *                  дело: второй, повторяющий его расчёт снаружи разошёлся бы.
         *   opts_file    — какой файл стратегии отдан процессу. Без него «стратегия не та»
         *                  выясняется только чтением командной строки процесса.
         *   up           — жив ли обработчик очереди. Спрашивается у /proc, а не у ядра:
         *                  списка «кто слушает очередь N» ядро не отдаёт, а процесс с
         *                  --qnum=N в командной строке отвечает на тот же вопрос точно.
         *
         * Признак живости здесь всё же печатается, в отличие от obfs, и разница
         * оправданна: у obfs он стоил бы pgrep на каждый круг опроса ради поля, которое
         * дублирует diag; здесь без него у выхода не было бы вообще НИ ОДНОГО признака
         * работы — устройства нет, счётчик канала растёт одинаково при живом и мёртвом
         * обходе (пакеты уходят и так, разница в том, доходят ли они). */
        if (g_out[i].kind == OUT_ZAPRET) {
            int q = out_zapret_queue(&g_out[i]);
            fprintf(out, ",\"mark\":\"0x%08x\",\"queue\":%d,\"opts_file\":\"%s\""
                   ",\"up\":%s,\"on_fail\":\"%s\"",
                   g_out[i].mark, q, g_out[i].zp_opts,
                   nfqws_on_queue(q) ? "true" : "false",
                   g_out[i].on_fail == FAIL_DROP ? "drop" : "direct");
        }
        fprintf(out, "}");
    }
    fprintf(out, "},\"channels\":[");

    counters_load();
    for (size_t i = 0; i < g_grp_n; i++) {
        unsigned long up_p = 0, up_b = 0, dn_p = 0, dn_b = 0;
        int live = counter_find(g_grp[i].name, 0, &up_p, &up_b) == 0;
        int dn = counter_find(g_grp[i].name, 1, &dn_p, &dn_b) == 0;
        fprintf(out, "%s{\"name\":\"%s\",\"out\":\"%s\",\"kind\":\"%s\",\"live\":%s",
               i ? "," : "", g_grp[i].name, g_grp[i].out,
               g_grp[i].domains ? "domains" : "prefixes", live ? "true" : "false");
        if (live) fprintf(out, ",\"packets\":%lu,\"bytes\":%lu", up_p, up_b);
        /* Отдельными именами, а не вторым «bytes»: старое имя значило «наружу» и в таком
         * значении уже разошлось по установленным версиям splify2. Переопределить его
         * значило бы, что новый движок со старым интерфейсом молча показывает не то. */
        if (dn) fprintf(out, ",\"down_packets\":%lu,\"down_bytes\":%lu", dn_p, dn_b);
        fprintf(out, ",\"lists\":%zu,\"channels\":[", g_grp[i].files_n + g_grp[i].dfiles_n);
        for (size_t m = 0; m < g_grp[i].members_n; m++)
            fprintf(out, "%s\"%s\"", m ? "," : "", g_grp[i].members[m]);
        fprintf(out, "]}");
    }
    fprintf(out, "]}\n");
}

/* Полный ответ: посчитать, запомнить и напечатать.
 *
 * Снимок пишется через временный файл и rename, как и всё прочее состояние: оборванная
 * запись поверх прежнего снимка оставила бы обрубок, а `--fast` тогда отдавал бы половину
 * ответа. Не записалось (нет места, каталог только для чтения) — печатаем и молчим об этом:
 * снимок это УСКОРЕНИЕ, и терять из-за него сам ответ было бы обменом наоборот.
 *
 * Печатается ФАЙЛ, а не второй проход печати: обход выходов читает /sys, а счётчики — живую
 * цепочку nft, и второй проход дал бы в снимке и на экране два разных мгновения. */
static int cmd_status(const char *spec, int fast) {
    /* Запомненное — раньше разбора спеки: смысл `--fast` в том, чтобы не делать работу
     * вовсе. Спека при этом не читается, то есть негодная спека `--fast` не ломает — он
     * отвечает тем, что было применено, пока она была годной. */
    if (fast && status_from_snapshot() == 0) return 0;

    load_spec(spec);
    registry_assign();
    build_groups();
    /* О том же устройстве, к которому apply привязал таблицу, — см. outputs_adopt_active.
     * Без этого пул, уведённый сторожем на запасное устройство, отдавался бы интерфейсу
     * основным устройством с `up: false`: рабочий выход, нарисованный сломанным. */
    outputs_adopt_active();

    char snap[256], tmp[288];
    status_snap_path(snap, sizeof snap);
    snprintf(tmp, sizeof tmp, "%s.new", snap);
    mkdir(g_state_dir, 0755);
    FILE *f = fopen(tmp, "w");
    if (!f) { status_emit(stdout); return 0; }
    status_emit(f);
    if (fclose(f) != 0 || rename(tmp, snap) != 0) {
        unlink(tmp);
        status_emit(stdout);
        return 0;
    }
    f = fopen(snap, "r");
    if (!f) { status_emit(stdout); return 0; }
    char buf[8192];
    size_t n;
    while ((n = fread(buf, 1, sizeof buf, f)) > 0) fwrite(buf, 1, n, stdout);
    fclose(f);
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

/* ---- публичные резолверы внутри адресного списка ----------------------------
 *
 * Списки издателя собираются по номеру автономной системы целиком, поэтому адрес
 * публичного резолвера приезжает в категорию вместе со всем остальным, что живёт в той же
 * AS: 8.8.8.0/24 и 8.8.4.0/24 входят в «YouTube» и «Google» (AS15169), 1.1.1.0/24 — в
 * «Cloudflare» (AS13335). Человек выбирал видеохостинг, а получил заодно резолвер, и ни
 * одна сторона ему об этом не говорит.
 *
 * Таблица короткая нарочно: это не «все резолверы мира», а те, которые прописывают руками
 * и на которые поэтому реально ссылается настройка клиента. Резолвер, о котором клиент не
 * знает, в туннеле никому не мешает. */
static const struct { const char *addr; const char *who; } RESOLVERS[] = {
    { "8.8.8.8",         "Google Public DNS" },
    { "8.8.4.4",         "Google Public DNS" },
    { "1.1.1.1",         "Cloudflare DNS" },
    { "1.0.0.1",         "Cloudflare DNS" },
    { "9.9.9.9",         "Quad9" },
    { "149.112.112.112", "Quad9" },
    { "94.140.14.14",    "AdGuard DNS" },
    { "94.140.15.15",    "AdGuard DNS" },
    { "77.88.8.8",       "Яндекс DNS" },
    { "77.88.8.1",       "Яндекс DNS" },
    { "208.67.222.222",  "OpenDNS" },
    { "208.67.220.220",  "OpenDNS" },
};

/* MTU устройства из sysfs. -1, если устройства нет. Читаем файл, а не спрашиваем ip:
 * это один открытый файл против запуска процесса, а ответ тот же. */
static int dev_mtu(const char *dev) {
    char path[128];
    snprintf(path, sizeof(path), "/sys/class/net/%.32s/mtu", dev);
    FILE *f = fopen(path, "r");
    if (!f) return -1;
    int mtu = -1;
    if (fscanf(f, "%d", &mtu) != 1) mtu = -1;
    fclose(f);
    return mtu;
}

/* Через какое устройство ядро отправит пакет к адресу и каков MTU этого устройства.
 * Возвращает MTU (или -1) и пишет имя устройства в dev.
 *
 * Адрес попадает в командную строку, поэтому обязан быть проверен ДО вызова: здесь он
 * приходит из спеки, где парсер уже отверг всё, что не является литералом IPv4
 * (inet_pton). Это то же требование, из-за которого в explain появилась проверка
 * формы: подстановка непроверенной строки в вызов однажды уже была дырой. */
static int route_egress(const char *addr, char *dev, size_t devn) {
    dev[0] = '\0';
    char cmd[160];
    snprintf(cmd, sizeof(cmd), "ip route get %.45s 2>/dev/null", addr);
    FILE *p = popen(cmd, "r");
    if (!p) return -1;
    char line[512];
    if (fgets(line, sizeof(line), p)) {
        char *d = strstr(line, " dev ");
        if (d) {
            d += 5;
            size_t k = 0;
            while (d[k] && d[k] != ' ' && d[k] != '\n' && k + 1 < devn) { dev[k] = d[k]; k++; }
            dev[k] = '\0';
        }
    }
    pclose(p);
    return dev[0] ? dev_mtu(dev) : -1;
}

/* "A.B.C.D[/N]" → сеть и маска. 0, если строка не префикс.
 *
 * Сдвиг на 32 — неопределённое поведение, поэтому нулевая длина считается отдельно, а не
 * выводится из общей формулы: /0 в списке встречается («весь интернет в туннель»), и на
 * нём же общая формула и сломалась бы. */
static int parse_prefix(const char *s, uint32_t *net, uint32_t *mask) {
    unsigned a, b, c, d, len = 32;
    int n = sscanf(s, "%u.%u.%u.%u/%u", &a, &b, &c, &d, &len);
    if (n < 4 || a > 255 || b > 255 || c > 255 || d > 255 || len > 32) return 0;
    *mask = len ? ~0u << (32 - len) : 0;
    *net = (((uint32_t)a << 24) | ((uint32_t)b << 16) | ((uint32_t)c << 8) | d) & *mask;
    return 1;
}

/* Первый публичный резолвер, накрытый префиксом из файла списка. Возвращает его имя (и
 * пишет в found сам префикс) либо NULL.
 *
 * Один проход по файлу на все резолверы, а не проход на каждого: в списке категории бывает
 * семнадцать тысяч строк, и двенадцать проходов по нему — это двенадцать чтений с флешки
 * роутера ради одного и того же ответа. */
static const char *list_finds_resolver(const char *path, char *found, size_t found_sz) {
    FILE *in = fopen(path, "r");
    if (!in) return NULL;                 /* про нечитаемый список говорит своя проверка */
    /* Двенадцать адресов резолверов — константы времени компиляции, и разбирать их заново
     * на КАЖДОЙ строке списка значило звать sscanf тринадцать раз вместо одного. На списке
     * категории в семнадцать тысяч строк это двести тысяч лишних разборов одного и того же
     * текста, а на национальном блок-листе — миллионы; diag человек нажимает и ждёт.
     * Замер на 500 000 строк: 0,83 с против 0,09 с. */
    static uint32_t r_addr[sizeof(RESOLVERS) / sizeof(RESOLVERS[0])];
    static int r_ok[sizeof(RESOLVERS) / sizeof(RESOLVERS[0])];
    static int r_ready;
    if (!r_ready) {
        for (size_t i = 0; i < sizeof(RESOLVERS) / sizeof(RESOLVERS[0]); i++) {
            uint32_t m32;
            r_ok[i] = parse_prefix(RESOLVERS[i].addr, &r_addr[i], &m32);
        }
        r_ready = 1;
    }
    char line[512];
    const char *who = NULL;
    while (!who && fgets(line, sizeof(line), in)) {
        char *nl = strpbrk(line, "\r\n");
        if (nl) *nl = '\0';
        char *p = line;
        while (*p == ' ' || *p == '\t') p++;
        if (!*p || *p == '#' || *p == ';') continue;
        uint32_t net, mask;
        if (!parse_prefix(p, &net, &mask)) continue;
        for (size_t i = 0; i < sizeof(RESOLVERS) / sizeof(RESOLVERS[0]); i++) {
            if (!r_ok[i]) continue;
            if ((r_addr[i] & mask) == net) {
                snprintf(found, found_sz, "%.40s", p);   /* префикс короче, точность — от -Wformat-truncation */
                who = RESOLVERS[i].who;
                break;
            }
        }
    }
    fclose(in);
    return who;
}

static int cmd_diag(const char *spec) {
    load_spec(spec);
    registry_assign();
    build_groups();
    /* Приговор выносится тому устройству, которое несёт трафик, — тому же, о котором
     * рассказывает status и к которому привязал таблицу apply (outputs_adopt_active). */
    outputs_adopt_active();
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

    /* 3a. Локальные устройства. Правила по ним грузятся и на отсутствующее устройство —
     *     `iifname` сверяется по имени в момент прохода пакета, — и это правильно: zt* и
     *     tailscale0 появляются позже сети. Но «правило есть, а устройства нет» означает
     *     «правило не сработает ни разу», и молчать об этом нельзя: у человека, опечатавшегося
     *     в имени, ровно та же картина, что у исправной настройки.
     *
     *     Спрашиваем /sys/class/net, а не спеку: спека описывает намерение, а вопрос здесь
     *     про роутер. warn, а не fail — остальные устройства при этом работают. */
    for (size_t i = 0; i < g_lan_dev_n; i++) {
        char devpath[128], what[160];
        snprintf(devpath, sizeof(devpath), "/sys/class/net/%.63s", g_lan_dev[i]);
        if (access(devpath, F_OK) == 0) {
            snprintf(what, sizeof(what), "трафик забирается с %.64s", g_lan_dev[i]);
            diag("lan_device", "ok", what, "");
        } else {
            snprintf(what, sizeof(what), "%.64s перечислен, но такого устройства на роутере нет",
                     g_lan_dev[i]);
            diag("lan_device", "warn", what,
                 "правила по нему не сработают: проверьте имя или поднимите интерфейс "
                 "(у Tailscale и ZeroTier устройство появляется вместе со своим демоном)");
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

    /* 6. Публичный резолвер внутри списка канала на выходе VLESS.
     *
     *    Раньше здесь стояли ДВЕ проверки: общая («выход VLESS несёт только TCP») и эта.
     *    Общая ушла вместе с ограничением — туннель несёт UDP командой VLESS 2, и QUIC,
     *    WireGuard и игры через него работают. Врать о снятом ограничении хуже, чем молчать:
     *    по такой заметке уходят настраивать обход, которого больше не нужно.
     *
     *    А эта осталась, потому что осталась ЕЁ причина, только другая. Метка ставится по
     *    `ip daddr @набор` без разбора протокола, поэтому UDP-запрос к резолверу из списка
     *    уходит в туннель наравне с TCP. Пройти он теперь пройдёт — но у UDP поток к узлу
     *    свой на каждую пару адрес-порт, а у DNS каждый запрос идёт с нового порта. То есть
     *    на каждое имя приходится своё рукопожатие с узлом: имена разрешаются, но дорого и
     *    медленно, и таблица соединений заполняется однократными потоками.
     *
     *    Приговор note в обоих случаях, а не warn: имена РАЗРЕШАЮТСЯ, поломки нет. Разница
     *    лишь в том, кого это касается — при доменных правилах клиентов из from_default
     *    прикрывает перенаправление DNS на свой резолвер, и цену платят только остальные.
     *
     *    ТОЛЬКО vless, и на xsteer это НЕ распространяется, хотя оба вида — наши туннели.
     *    Причина заметки в том, что у VLESS поток к узлу свой на каждую пару адрес-порт;
     *    xsteer несёт сырой IP, как wireguard, никаких потоков к узлу у него нет, и цены
     *    тоже нет. Скопировать заметку на xsteer значило бы напечатать постоянную заметку
     *    без причины — ровно то, из-за чего была убрана проверка `udp`. */
    for (size_t i = 0; i < g_grp_n; i++) {
        struct output *o = out_by_name(g_grp[i].out);
        if (!o || o->kind != OUT_VLESS) continue;
        char found[64];
        const char *who = NULL;
        for (size_t k = 0; k < g_grp[i].files_n && !who; k++)
            who = list_finds_resolver(g_grp[i].files[k], found, sizeof(found));
        if (!who) continue;
        /* Буферы с запасом: строки русские, в UTF-8 это два байта на букву, и обрезка по
         * границе буфера разрубила бы букву посередине. Ровно этим ломался вывод при первом
         * прогоне стенда — недобитый байт делал JSON неразбираемым (см. I-029). */
        char what[256], why[512];
        snprintf(what, sizeof(what), "канал %.40s: в списке %.20s — это %.40s",
                 g_grp[i].members_n ? g_grp[i].members[0] : g_grp[i].name, found, who);
        if (has_domains())
            snprintf(why, sizeof(why),
                     "запросы DNS уйдут в туннель, а там на каждый запрос свой поток к узлу "
                     "со своим рукопожатием: имена разрешатся, но медленнее. Клиентов из "
                     "from_default прикрывает перенаправление DNS на свой резолвер, "
                     "остальные платят эту цену");
        else
            snprintf(why, sizeof(why),
                     "запросы DNS уйдут в туннель, а там на каждый запрос свой поток к узлу "
                     "со своим рукопожатием: имена разрешатся, но медленнее. Перехватить "
                     "запрос нечем — доменных правил нет, значит нет и перенаправления DNS; "
                     "уберите из списка канала категорию с адресами резолвера");
        diag("resolver", "note", what, why);
        break;                            /* одного примера довольно: причина у них общая */
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
            /* Устройства нет — но это ТРИ разных случая, а не один, и раньше все три
             * назывались одинаково: «устройства нет, туннель не поднят» (I-100).
             *
             * Клиент vless создаёт устройство только после выбора узла, а при `node: -1`
             * выбор — это перебор подписки с таймаутом восемь секунд на узел. На трёх
             * десятках нерабочих узлов исправная настройка минутами выглядела сломанной, а
             * настоящий отказ — медленной проверкой. Теперь клиент говорит, что делает, и
             * приговор берётся у него.
             *
             * PROBE_NONE — «не знаем»: файла нет, он устарел или писавший процесс мёртв.
             * Тогда ветка прежняя, слово в слово: отсутствие данных не повод менять
             * приговор. */
            /* У владельца устройства, а не у назвавшего его выхода: см. ту же строку в
             * cmd_status. */
            const struct output *po = out_for_device(&g_out[i], g_out[i].device);
            struct probe_status pr = probe_read(po->name);
            if (pr.state == PROBE_RUNNING) {
                snprintf(what, sizeof(what), "выход %.40s: проверяю узлы, %d из %d",
                         g_out[i].name, pr.node, pr.total);
                /* Строка короткая не для красоты: буфер 240 байт, а кириллица — два байта
                 * на знак, и обрезка пришлась бы посреди последовательности UTF-8. */
                snprintf(why, sizeof(why),
                         "узлы проверяются по очереди, до восьми секунд на каждый. "
                         "Устройство появится с первым ответившим — ждать, а не чинить");
                /* Совет, а не находка: идёт штатная работа. Красить этим состояние значило
                 * бы держать жёлтую метку на исправном роутере всё время подъёма. */
                diag("output", "note", what, why);
                continue;
            }
            /* Выбранный номер узла за пределами подписки. Отдельная ветка, и это
             * исправление вранья, снятого с живого роутера: раньше такой выход попадал в
             * ветку PROBE_FAILED с total=0 и получал приговор «в подписке нет пригодных
             * узлов» — на подписке из двадцати девяти живых узлов. Человек по такому
             * приговору идёт перекачивать подписку и менять поставщика, а поправить надо
             * одно число. */
            if (pr.state == PROBE_NO_SUCH_NODE) {
                snprintf(what, sizeof(what),
                         "выход %.40s: выбран узел %d, а пригодных в подписке %d",
                         g_out[i].name, pr.node, pr.total);
                /* Текст короткий не для красоты: буфер 240 байт, а кириллица — два байта на
                 * знак, и обрезка пришлась бы посреди последовательности UTF-8. Ровно на
                 * этом компилятор и поймал первую редакцию (301 байт). */
                snprintf(why, sizeof(why),
                         "номер вне подписки: она обновилась, узлов стало меньше. Лучше не "
                         "задавать номер — «первый рабочий» найдёт живой сам");
                diag("output", "fail", what, why);
                continue;
            }
            if (pr.state == PROBE_FAILED) {
                if (pr.total > 0)
                    snprintf(what, sizeof(what),
                             "выход %.40s: ни один узел подписки не ответил (проверено %d)",
                             g_out[i].name, pr.total);
                else
                    snprintf(what, sizeof(what), "выход %.40s: в подписке нет пригодных узлов",
                             g_out[i].name);
                /* Два готовых текста вместо одного с подстановкой: с подстановкой длинная
                 * ветка не влезала в буфер, а обрезка кириллицы рвёт знак пополам. */
                if (pr.total > 0)
                    snprintf(why, sizeof(why),
                             "живого узла не нашлось. Причины по каждому движок пишет в "
                             "журнал; смените узел или обновите подписку");
                else
                    snprintf(why, sizeof(why),
                             "подписка скачана, но узлов нужного вида в ней нет; проверьте "
                             "ссылку и поддержку vless/reality у поставщика");
                diag("output", "fail", what, why);
                continue;
            }
            snprintf(what, sizeof(what), "выход %.40s: устройства %.24s нет",
                     g_out[i].name, g_out[i].device);
            snprintf(why, sizeof(why), "туннель не поднят — %s",
                     out_engine_managed(po) ? "смотрите журнал движка"
                                            : "проверьте настройку интерфейса");
            diag("output", "fail", what, why);
            continue;
        }
        struct fwcheck c = fw_check(g_out[i].device);
        /* Нужен ли masquerade — свойство УСТРОЙСТВА, а не выхода, который его назвал: в пуле
         * kind=interface активным бывает устройство VLESS-туннеля или хаба xsteer, и вопрос
         * решает его владелец. Без этого исправно собранный пул получал бы вечное «нет
         * masquerade» — ту самую жёлтую метку, из-за которой перестают смотреть на проверки. */
        const struct output *nat_o = out_for_device(&g_out[i], g_out[i].device);
        if (!c.in_firewall) {
            snprintf(what, sizeof(what), "выход %.40s: %.24s вне зоны фаервола",
                     g_out[i].name, g_out[i].device);
            diag("output", "fail", what,
                 "фаервол отбросит ответы — добавьте устройство в зону");
        } else if (!c.masqueraded && !out_self_natting(nat_o)) {
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
            /* Сюда попадает выход без masquerade, которому он и не нужен (vless, xsteer)
             * — для него это норма. Сказать «NAT есть» было бы прямой неправдой: его нет,
             * он просто не нужен.
             *
             * Тексты РАЗНЫЕ, и это не оформление. Формулировка vless («туннель завершает
             * TCP сам, адреса клиентов наружу не уходят») для xsteer неверна: адреса
             * уходят, к хабу. Расширить условие через ||, оставив прежнее объяснение,
             * значило бы записать в диагностику неправду — а по ней настраивают. */
            snprintf(what, sizeof(what), "выход %.40s: устройство %.24s в зоне",
                     g_out[i].name, g_out[i].device);
            diag("output", "ok", what,
                 nat_o->kind == OUT_XSTEER
                     ? "masquerade не нужен и вреден: адреса клиентов уходят к хабу, а NAT "
                       "скрыл бы, от какой пира пришёл пакет"
                     : "masquerade не нужен: туннель завершает TCP сам, адреса клиентов "
                       "наружу не уходят");
        }
    }

    /* 8. Обфускация транспорта (WireGuard поверх поддельного TCP).
     *
     *    Четыре проверки, и каждая — про отказ, который иначе виден только как «туннель
     *    не поднимается»: процесса нет; правило против RST не встало (тогда сессию рвёт
     *    собственное ядро); маршрут к серверу обфускации идёт через сам туннель (петля,
     *    которую не разорвать изнутри); MTU туннеля больше того, что помещается в
     *    поддельный TCP (тогда работает всё, кроме больших пакетов). */
    for (size_t i = 0; i < g_out_n; i++) {
        if (!g_out[i].obfs.on) continue;
        char what[200], why[400], cmdline[128];

        snprintf(cmdline, sizeof(cmdline), "pgrep -f 'steer obfs %.32s' >/dev/null 2>&1",
                 g_out[i].name);
        int alive = system(cmdline) == 0;
        snprintf(what, sizeof(what), "выход %.40s: обфускатор %s",
                 g_out[i].name, alive ? "работает" : "не запущен");
        diag("obfs", alive ? "ok" : "fail", what,
             alive ? "" : "перезапустите движок: /etc/init.d/steer restart");

        /* nft_has смотрит в таблицу steer, здесь нужна соседняя — поэтому свой вызов. */
        snprintf(cmdline, sizeof(cmdline),
                 "nft list chain inet steer_obfs o_%.32s >/dev/null 2>&1", g_out[i].name);
        int guard = system(cmdline) == 0;
        if (!guard) {
            snprintf(what, sizeof(what), "выход %.40s: правила против RST нет",
                     g_out[i].name);
            diag("obfs", "warn", what,
                 "ядро отвечает RST на входящие сегменты обфускатора и рвёт его же сессию — "
                 "проверьте, что nft доступен процессу");
        }

        char dev[64] = "";
        int link_mtu = route_egress(g_out[i].obfs.server, dev, sizeof(dev));
        if (dev[0] && !strcmp(dev, g_out[i].device)) {
            snprintf(what, sizeof(what), "выход %.40s: маршрут к %.20s идёт через %.24s",
                     g_out[i].name, g_out[i].obfs.server, dev);
            diag("obfs", "fail", what,
                 "сервер обфускации доступен только через туннель, который сам через него и "
                 "поднимается: петля. Уберите адрес сервера из списков канала или пропишите "
                 "к нему отдельный маршрут");
        }

        int wg_mtu = dev_mtu(g_out[i].device);
        /* 20 внешний IP + 20 поддельный TCP + 32 сам WireGuard. Считаем от MTU того
         * устройства, которым пакет уходит наружу, а не от 1500: на PPPoE это 1492, и
         * разница ровно в те восемь байт, на которых «всё работает, кроме больших
         * страниц». */
        if (link_mtu > 0 && wg_mtu > 0 && wg_mtu > link_mtu - 72) {
            snprintf(what, sizeof(what), "выход %.40s: MTU %d великоват для обфускации",
                     g_out[i].name, wg_mtu);
            snprintf(why, sizeof(why),
                     "поверх поддельного TCP в %d байт канала помещается %d: поставьте "
                     "интерфейсу %.24s MTU %d и тот же MTU на другой стороне туннеля, иначе "
                     "пропадать будут только большие пакеты",
                     link_mtu, link_mtu - 72, g_out[i].device, link_mtu - 72);
            diag("obfs", "warn", what, why);
        }
    }

    /* 9. Выходы kind=zapret (обход DPI своим обработчиком на свою очередь).
     *
     *    У такого выхода НЕТ НИ ОДНОГО обычного признака работы: устройства нет, таблицы
     *    маршрутизации нет, а счётчик канала растёт одинаково при живом и мёртвом обходе —
     *    пакеты уходят и так, разница лишь в том, доходят ли они. То есть «не открывается
     *    YouTube» здесь не отличить от «всё в порядке» ничем, кроме этих проверок.
     *
     *    Три вопроса, и каждый про свой отказ: нет пакета zapret (обработчика взять негде),
     *    нет файла стратегии (обработчику нечего применять), обработчик не запущен (при
     *    on_fail=drop это ещё и остановленный трафик канала, что человек читает как
     *    «интернета нет», а не как «обход упал»). */
    for (size_t i = 0; i < g_out_n; i++) {
        if (g_out[i].kind != OUT_ZAPRET) continue;
        char what[200], why[400];
        int q = out_zapret_queue(&g_out[i]);

        if (access(NFQWS_PATH, X_OK) != 0) {
            snprintf(what, sizeof(what), "выход %.40s: обход DPI не установлен",
                     g_out[i].name);
            snprintf(why, sizeof(why),
                     "нет " NFQWS_PATH " — поставьте пакет zapret. Правило очереди при этом "
                     "стоит, и при on_fail=%s трафик канала %s",
                     g_out[i].on_fail == FAIL_DROP ? "drop" : "direct",
                     g_out[i].on_fail == FAIL_DROP ? "остановлен" : "идёт без обхода");
            diag("zapret", "fail", what, why);
            continue;
        }
        if (access(g_out[i].zp_opts, R_OK) != 0) {
            snprintf(what, sizeof(what), "выход %.40s: файла стратегии нет", g_out[i].name);
            snprintf(why, sizeof(why),
                     "%.200s не читается — стратегию выбирают в splify2, вкладка Zapret. "
                     "Без файла обработчик не поднимается вовсе",
                     g_out[i].zp_opts);
            diag("zapret", "fail", what, why);
            continue;
        }
        int alive = nfqws_on_queue(q);
        snprintf(what, sizeof(what), "выход %.40s: обработчик очереди %d %s",
                 g_out[i].name, q, alive ? "работает" : "не запущен");
        snprintf(why, sizeof(why), "%s",
                 alive ? ""
                 : g_out[i].on_fail == FAIL_DROP
                   ? "перезапустите движок: /etc/init.d/steer restart. До тех пор трафик "
                     "канала ОСТАНОВЛЕН — так выражен on_fail=drop, очередь стоит без bypass"
                   : "перезапустите движок: /etc/init.d/steer restart. До тех пор трафик "
                     "канала идёт без обхода — так выражен on_fail=direct");
        diag("zapret", alive ? "ok" : "fail", what, why);
    }

    printf("],\"warn\":%d,\"fail\":%d}\n", g_diag_warn, g_diag_fail);
    /* Код возврата — чтобы это годилось в скрипт, а не только глазам. */
    return g_diag_fail ? 1 : 0;
}

/* Чем именно объяснять совпадение: адресным списком, доменным или обоими.
 *
 * ЗАЧЕМ ФУНКЦИЯ, А НЕ ТЕРНАРНИК НА МЕСТЕ. Фраза выводилась из ИМЕНИ набора: у группы с
 * доменами она всегда была «domain set». Но группа, у которой есть и адресный список, и
 * доменный, держит оба в ОДНОМ наборе — так его находит резолвер (см. build_groups), — и
 * адрес из АДРЕСНОГО списка объяснялся как совпадение по домену. Человек, выясняющий,
 * почему 142.250.1.1 идёт в туннель, получал ответ про DNS, которого там не было. Снято с
 * живого роутера: канал с обоими списками, адрес из youtube.lst, ответ «domain set».
 *
 * Теперь фраза отвечает на «откуда этот адрес взялся в наборе»:
 *
 *   fake-IP            — его выдал резолвер, значит имя нашлось в доменном списке;
 *   есть оба списка    — по настоящему адресу различить нельзя (в режиме realip резолвер
 *                        кладёт в набор настоящие адреса), и честнее назвать оба, чем
 *                        угадать один;
 *   один вид списка    — ответ тот же, что был.
 *
 * Отдельной функцией — чтобы это проверялось стендом: разбор ответа ядра для проверки
 * требует живого nft, а выбор фразы — нет. */
static const char *explain_set_phrase(const char *addr, int has_files, int has_domains) {
    int fake = addr && (strncmp(addr, "198.18.", 7) == 0 || strncmp(addr, "198.19.", 7) == 0);
    if (fake) return "domain set";
    if (has_files && has_domains) return "address+domain set";
    return has_domains ? "domain set" : "address set";
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
               explain_set_phrase(addr, g_grp[i].files_n > 0, g_grp[i].domains),
               g_grp[i].name, o->name);
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
    if (argc < 2) {
        cli_usage_short(stderr);
        return 2;
    }
    const char *cmd = argv[1];

    /* Справка и версия — до поиска команды: это не команды движка, а вопросы к нему.
     * Обе формы, и слово, и флаг: `steer --help` человек набирает не задумываясь, а
     * раньше получал «unknown command: --help» с кодом 2. */
    if (!strcmp(cmd, "help") || !strcmp(cmd, "--help") || !strcmp(cmd, "-h")) {
        if (argc > 2) {
            const struct cli_cmd *c = cli_lookup(argv[2]);
            if (!c) cli_unknown(argv[2]);
            cli_help(stdout, c);
        } else {
            cli_help(stdout, NULL);
        }
        return 0;
    }
    if (!strcmp(cmd, "version") || !strcmp(cmd, "--version") || !strcmp(cmd, "-V")) {
        cli_version(stdout);
        return 0;
    }
    /* Флаг вместо команды. Отдельная строка, потому что «нет такой команды: --spec»
     * не объясняет, что именно не так с порядком слов. */
    if (cmd[0] == '-') {
        fprintf(stderr, "steer: флаги идут после команды, а не до неё: %s\n", cmd);
        fputs("       например: steer apply --spec /etc/steer/spec.json\n"
              "       список команд: steer help\n", stderr);
        return 2;
    }

    const struct cli_cmd *c = cli_lookup(cmd);
    if (!c) cli_unknown(cmd);
    /* Просьба о справке перехватывается ДО разбора, одинаково для всех команд —
     * включая fit и dnsd, у которых свои парсеры аргументов. */
    if (cli_wants_help(argc - 2, argv + 2)) {
        cli_help(stdout, c);
        /* У команд со своим разбором список флагов знает только их парсер, поэтому
         * справка склеивается из двух половин. */
        if (c->passthru) {
            fputs("\nФлаги:\n", stdout);
            if (!strcmp(cmd, "fit")) aggregate_usage_flags(stdout);
            else dnsd_usage_flags(stdout);
        }
        return 0;
    }

    /* У fit и dnsd свои аргументы, и общий разбор молча съел бы, например, --budget.
     * Такие команды помечены в таблице как passthru и получают argv как есть. */
    if (c->passthru) {
        if (!strcmp(cmd, "fit")) return aggregate_main(argc - 1, argv + 1);
        return dnsd_main(argc - 2, argv + 2);
    }

    struct cli_args a;
    cli_parse(c, argc, argv, 2, &a);
    if (a.state_dir) g_state_dir = a.state_dir;
    const char *spec = a.spec, *arg = a.npos ? a.pos[0] : NULL;

    if (!strcmp(cmd, "apply")) return cmd_apply(spec, a.dry_run);
    if (!strcmp(cmd, "status")) return cmd_status(spec, a.fast);
    if (!strcmp(cmd, "diag")) return cmd_diag(spec);
    if (!strcmp(cmd, "failover")) return cmd_failover(spec, a.verbose);
    if (!strcmp(cmd, "explain")) {
        /* Адрес ИЛИ имя. Проверка формы обязательна для обоих: аргумент подставляется в
         * вызов nft, и именно здесь однажды была дыра — адрес уходил в system(). */
        if (!addr_ok(arg) && !looks_like_name(arg))
            die("это не адрес и не имя: %s", arg);
        return cmd_explain(spec, arg);
    }
    /* Перечислить выходы заданного вида. Init-скрипту нужно знать, для каких выходов
     * поднимать процесс, и спрашивать об этом движок — то же правило, что с needs-dnsd:
     * grep по ключу в JSON ломается при первом же переименовании поля, причём молча. */
    if (!strcmp(cmd, "outputs")) {
        /* Вид проверяется по списку, а не сравнивается как есть: `--kind vles` (опечатка)
         * давал пустой вывод и код 0, а по этому выводу init-скрипт решает, каким выходам
         * поднимать процессы. Тишина вместо отказа означала бы не поднятый туннель без
         * единой строки о причине. */
        if (a.kind && !out_kind_known(a.kind))
            die("--kind: нужен interface, vless, xsteer, zapret или direct, а не %s", a.kind);
        load_spec(spec);
        for (size_t i = 0; i < g_out_n; i++) {
            const char *k = out_kind_name(g_out[i].kind);
            if (a.kind && strcmp(a.kind, k) != 0) continue;
            /* --obfs — отдельный признак, а не вид: обфускация есть свойство выхода,
             * и init-скрипту нужен именно список тех, кому поднимать процесс. */
            if (a.obfs && !g_out[i].obfs.on) continue;
            /* --devices печатает устройство, и выход без устройства (kind=direct) при этом
             * пропускается: пустая строка в списке для настройки фаервола хуже её отсутствия. */
            if (a.devices) {
                if (g_out[i].device[0]) printf("%s\n", g_out[i].device);
                continue;
            }
            printf("%s\n", g_out[i].name);
        }
        return 0;
    }
    /* Нужен ли этой спеке резолвер. Спрашивают у движка, а не угадывают по тексту
     * файла: init-скрипт когда-то искал в нём буквальное `"domains_file"`, спека
     * обзавелась множественным `domains_files`, и совпадение молча перестало
     * находиться — резолвер не поднимался, а apply при этом ставил перенаправление
     * DNS, и каждый запрос из LAN уходил в закрытый порт. Что будет сгенерировано,
     * знает только движок, поэтому отвечает он. */
    /* Что поднимать для выходов kind=zapret: по строке на выход, поля через табуляцию —
     * имя, номер очереди, файл ключей. Отдельной командой, а не полем `outputs`, потому
     * что читает её init-скрипт, а не человек, и читает построчно: разбирать в shell
     * ответ `status` (JSON, сотни байт на выход, jsonfilter на каждое поле) значило бы
     * платить за каждую перезагрузку сети разбором, который тут не нужен.
     *
     * Номер очереди печатает движок, а не считает init-скрипт. Вывод номера из метки —
     * наше внутреннее дело (out_zapret_queue), и второй, повторяющий его расчёт в shell
     * разошёлся бы при первой правке: процесс встал бы на очередь, в которую ядро ничего
     * не отдаёт, и выглядело бы это как «стратегия применилась и не действует».
     *
     * Код возврата — как у needs-dnsd: 0, если поднимать есть что. */
    if (!strcmp(cmd, "zapret-instances")) {
        load_spec(spec);
        registry_assign();
        int n = 0;
        for (size_t i = 0; i < g_out_n; i++) {
            if (g_out[i].kind != OUT_ZAPRET) continue;
            printf("%s\t%d\t%s\n", g_out[i].name, out_zapret_queue(&g_out[i]),
                   g_out[i].zp_opts);
            n++;
        }
        return n ? 0 : 1;
    }
    /* Что поднимать для выходов kind=tgws: имя и порт, по строке на выход. Тот же довод,
     * что у zapret-instances выше, включая главный: порт выводит движок (out_tgws_port), а
     * не считает init-скрипт — второй расчёт того же в shell разошёлся бы при первой
     * правке, и мост слушал бы порт, на который ядро ничего не заворачивает. */
    if (!strcmp(cmd, "tgws-instances")) {
        load_spec(spec);
        registry_assign();
        int n = 0;
        for (size_t i = 0; i < g_out_n; i++) {
            if (g_out[i].kind != OUT_TGWS) continue;
            printf("%s\t%d\n", g_out[i].name, out_tgws_port(&g_out[i]));
            n++;
        }
        return n ? 0 : 1;
    }
    if (!strcmp(cmd, "needs-dnsd")) {
        load_spec(spec);
        registry_assign();
        build_groups();
        return has_domains() ? 0 : 1;
    }
    if (!strcmp(cmd, "tgws")) return cmd_tgws(spec, arg);
    if (!strcmp(cmd, "tls-probe")) {
        /* ХОСТ[:ПОРТ]; адрес назначения — флагом --out, исходящий порт — флагом --node.
         * Своих флагов не заводим: эти уже есть и значат ровно то, что нужно. */
        char hb[256];
        const char *h = arg ? arg : "";
        int pt = 443;
        snprintf(hb, sizeof(hb), "%s", h);
        char *c = strrchr(hb, ':');
        if (c) { *c = '\0'; pt = atoi(c + 1); }
        if (!hb[0]) { fprintf(stderr, "нужно имя узла\n"); return 2; }
        return cmd_tls_probe(hb, a.out_file, pt, a.node > 0 ? a.node : 0, 0);
    }
    if (!strcmp(cmd, "tgws-probe"))
        return cmd_tgws_probe(a.node > 0 ? a.node : 2, arg && !strcmp(arg, "media"));
    if (!strcmp(cmd, "vless")) return cmd_vless(spec, arg);
    if (!strcmp(cmd, "vless-nodes")) return cmd_vless_nodes(spec, arg);
    if (!strcmp(cmd, "vless-probe")) return cmd_vless_probe(spec, arg, a.node, a.timeout);
    if (!strcmp(cmd, "sub-fetch")) return cmd_sub_fetch(arg, a.out_file, a.info_file);
    if (!strcmp(cmd, "sub-quota")) return cmd_sub_quota(arg, a.info_file);
    if (!strcmp(cmd, "sub-hwid")) return cmd_sub_hwid();
    if (!strcmp(cmd, "obfs")) {
        load_spec(spec);
        struct output *o = out_by_name(arg);
        if (!o) die("нет такого выхода: %s", arg);
        if (!o->obfs.on) die("у выхода %s не настроен obfs", arg);
        return obfs_client(o->name, o->obfs.server, o->obfs.server_port,
                           o->obfs.listen, o->obfs.listen_port);
    }
    /* Серверная половина. Спека ей не нужна и не читается: сервер живёт на VPS, где
     * ни выходов, ни каналов нет — есть порт, который слушать, и локальный WireGuard,
     * которому пересылать. */
    if (!strcmp(cmd, "xsteer"))
        return cmd_xsteer(spec, arg, a.config, a.device, a.stream, a.stream_port);
    if (!strcmp(cmd, "xsteer-peers")) return cmd_xsteer_peers(spec, arg, a.config);
    if (!strcmp(cmd, "xsteer-key")) return cmd_xsteer_key();
    if (!strcmp(cmd, "xsteer-check")) return cmd_xsteer_check(a.config);
    /* Источник — позиционный аргумент, а если его нет, то --config: команда одинаково удобна и
     * в конвейере («steer xsteer-link -»), и там, где путь уже назван флагом, как у соседей. */
    if (!strcmp(cmd, "xsteer-link"))
        return cmd_xsteer_link(a.npos > 0 ? a.pos[0] : a.config, a.name);
    /* Хаб живёт на VPS: спека ему не нужна и не читается — там ни выходов, ни каналов, а
     * есть конфигурация звезды и порт. Прецедент тот же, что у obfs-server. */
    if (!strcmp(cmd, "xsteer-hub")) return cmd_xsteer_hub(a.config);
    if (!strcmp(cmd, "obfs-server")) {
        if (!a.listen) die("нужен --listen ПОРТ (порт поддельного TCP)", NULL);
        if (!a.forward) die("нужен --forward АДРЕС:ПОРТ (куда отдавать датаграммы)", NULL);
        char host[80];
        int fport = 0;
        if (obfs_split_hostport(a.forward, host, sizeof(host), &fport) != 0)
            die("--forward должен быть вида адрес:порт, а не %s", a.forward);
        return obfs_server(a.listen, host, fport);
    }
    /* Сюда попасть нельзя: имя нашлось в таблице, значит ветка для него есть. Если
     * всё-таки попали — в таблицу добавили команду и забыли про диспетчер. */
    die("команда %s объявлена, но не подключена — это ошибка в движке", cmd);
    return 2;
}

