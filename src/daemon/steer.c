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
#include <linux/netlink.h>
#include <linux/rtnetlink.h>
#include <poll.h>
#include <signal.h>
#include <fcntl.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/time.h>
#include <time.h>

#include "spec.h"
#include "awg.h"
#include "hwid.h"
#include "obfs.h"
#include "cli.h"
#include "srs.h"
#include "ctl.h"

/* Уровень в журнале — см. одноимённые макросы в failover.c и obfs.c. Метка подсистемы
 * здесь «apply»: все строки ниже пишутся при компиляции и применении спеки. Отказы
 * вызывающему (die и разбор аргументов) уровня НЕ несут и несут «steer: » — это ответ
 * тому, кто позвал, а не запись в журнал; так и записано в контракте. */
#define LOG_W "steer[warn] apply: "

int dnsd_main(int argc, char **argv);

/* Имя таблицы правил (nft_table) — в spec.h: его спрашивает и сторож, см. failopen_mark в
 * failover.c. */

/* Путь снимка состояния. Объявлен здесь потому, что apply его СНИМАЕТ (см. там же), а сам
 * снимок живёт ниже, рядом с тем, что его пишет. */
static void status_snap_path(char *buf, size_t n);
int cmd_failover(const char *spec, int verbose);
void probe_rule_cleanup(void);   /* failover.c */
#ifdef STEER_ANDROID
static void android_masq_drop_all(void);   /* ниже, у apply_routing */
static void android_masq_ensure(void);
#endif
/* Свои флаги эти двое печатают сами — см. комментарии у объявлений. Справка по ним
 * склеивается из таблицы (что команда делает) и этих строк (чем ей управляют). */
void dnsd_usage_flags(FILE *out);
void aggregate_usage_flags(FILE *out);
/* Подпись таблицы доменных каналов: ею init-скрипт решает, хватит ли резолверу SIGHUP или
 * нужен перезапуск с пятисекундной паузой procd. Живёт в dnsd.c — там таблица. */
int dnsd_sig_print(const char *spec, FILE *out);
/* Соединения с меткой движка (дамп ctnetlink) и журнал имён работающего резолвера — обе в
 * dnsd.c: первая рядом с другим разговором с conntrack, вторая рядом с самим журналом. */
int ctnl_conns_print(FILE *out);
int dlog_print(FILE *out);
/* Клиент VLESS есть только в расширенной сборке (steer-extended). В базовой команда
 * отвечает внятным отказом, а не отсутствует: «неизвестная команда» на steer vless
 * заставила бы искать опечатку вместо того, чтобы поставить нужный пакет. */
/* МИНИ-СБОРКА (STEER_TGWS) — это тот же движок без всего, кроме перехвата Telegram.
 *
 * Заводится она для отдельного микропакета tgws: там нужен ровно мост, спека с одним выходом
 * и правила к нему, а клиент VLESS, звезда xsteer и работа с подпиской не нужны вовсе. На
 * роутере с шестью с половиной мегабайтами overlay это не придирка: расширенная сборка весит
 * три четверти мегабайта, мини — вдвое меньше, и в пакет с бинарником внутри это заметно.
 *
 * Подкоманды, которых в мини-сборке нет, отвечают той же внятной заглушкой, что и в базовой:
 * «неизвестная команда» заставила бы искать опечатку вместо нужного пакета. */
#if defined(STEER_EXTENDED) || defined(STEER_TGWS)
/* Мост Telegram → веб-сокет; объяснение целиком — в src/proto/tgws/tgws.c. */
int cmd_tgws(const char *spec_path, const char *out_name);
int cmd_tgws_probe(int dc, int media, int direct, int timeout_s);
int cmd_tls_probe(const char *host, const char *addr, int port, int local_port, int quiet);
#endif
#ifdef STEER_EXTENDED
int cmd_vless(const char *spec_path, const char *out_name);
int cmd_vless_nodes(const char *spec_path, const char *out_name);
int cmd_vless_probe(const char *spec_path, const char *out_name, int node, int timeout_s);
/* Скачивание и обработка подписки. Реализация и рассказ, почему это работа движка, а не
 * управляющего слоя, — в src/proto/vless/subfetch.{c,h}. Объявлены здесь, как соседние
 * cmd_vless*, а не подключением subfetch.h: ядро не включает заголовков протоколов, иначе
 * его сборка без расширенной части (профили base, server, tgws) формально зависела бы от
 * subfetch.c — tests/buildmatch.sh сверяет это замыканием по #include. */
int cmd_sub_fetch(const char *url, const char *out_path, const char *info_path);
int cmd_sub_quota(const char *url, const char *info_path);
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
/* ЕДИНСТВЕННАЯ ПОДКОМАНДА «VLESS», КОТОРАЯ ОТВЕЧАЕТ И ЗДЕСЬ. Идентификатор роутера считает
 * src/tools/hwid.c, входящий в обе сборки: читателей у него стало двое, и второй (телеметрия
 * splify2) работает на роутере, где расширенной сборки нет. Заглушки поэтому нет — есть
 * настоящая функция, объявленная в hwid.h. */
#ifndef STEER_TGWS
static int cmd_tgws(const char *spec_path, const char *out_name) {
    (void)spec_path; (void)out_name;
    return no_vless();
}
static int cmd_tgws_probe(int dc, int media, int direct, int timeout_s) {
    (void)dc; (void)media; (void)direct; (void)timeout_s; return no_vless();
}
static int cmd_tls_probe(const char *host, const char *addr, int port, int local_port, int quiet) {
    (void)host; (void)addr; (void)port; (void)local_port; (void)quiet; return no_vless();
}
#endif
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
    /* Сужение по протоколу и портам — УКАЗАТЕЛЬ на сужение первого канала группы, ровно как
     * `from` указывает на его список клиентов. Каналы группы по этому признаку совпадают
     * (он входит в ключ слияния), а спека разобранной живёт до конца процесса, так что
     * копировать 68 байт в каждую группу незачем. NULL быть не может: у канала без сужения
     * структура просто пустая, и l4match_empty отвечает про неё то же самое. */
    const struct l4match *l4;
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
    /* Сколько АДРЕСНЫХ строк во всех файлах группы — считает check_address_lists. Ноль при
     * непустом files_n бывает законно (файл из одних имён, см. там же), и тогда набор
     * объявляется без строки elements: `elements = {  }` nft не принимает и отвергает весь
     * набор правил — то есть один такой список снимал бы маршрутизацию целиком. */
    size_t addrs;
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

/* Built once per run: the first channel of a group fixes its place, so "first match wins"
 * still reads off the spec.
 *
 * ПРОХОДОВ ДВА, И ПЕРВЫЙ — ПРАВИЛА НА УСТРОЙСТВО. Порядок совпадения в цепочке и есть
 * приоритет: правило заканчивается `return`, поэтому побеждает первое совпавшее. Пока
 * порядок читался только со спеки, правило «этот телефон не маршрутизируем» работало ровно
 * до тех пор, пока человек держал его выше глобальных: стоило добавить новое глобальное и
 * поставить его первым — и исключение для телефона перестало действовать, молча.
 *
 * Владелец потребовал обратного: правило на устройство старше глобального ВСЕГДА. Значит
 * приоритет обязан быть свойством правила, а не порядка в списке, — и обеспечивается он
 * здесь, а не просьбой к человеку не переставлять строки.
 *
 * Внутри каждой из двух групп порядок спеки сохраняется: два правила на разные устройства
 * или два глобальных по-прежнему читаются сверху вниз, как и раньше. */
static void build_groups(void) {
    g_grp_n = 0;
    for (int pass = 0; pass < 2; pass++)
    for (size_t i = 0; i < g_ch_n; i++) {
        const struct channel *c = &g_ch[i];
        /* Первый проход берёт только правила на устройство, второй — только остальные. */
        if ((pass == 0) != (c->dev_scope != 0)) continue;
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
            /* СУЖЕНИЕ ПО ПРОТОКОЛУ И ПОРТАМ РАЗДЕЛЯЕТ ГРУППЫ так же, как выход и клиенты.
             *
             * Слить их было бы молчаливой потерей смысла в обе стороны сразу: набор у группы
             * один, правило одно, и ограничение либо распространилось бы на чужие адреса
             * (сузили то, чего человек не просил), либо пропало бы вовсе — а «пропало»
             * означает весь TCP к Cloudflare в туннель, потому что канал Discord это
             * 104.16.0.0/12 плюс udp 50000-65535. Об этом не сообщил бы ни отказ, ни status,
             * ни diag: правила выглядят применёнными. Та же болезнь, от которой выше
             * разделены группы `all` и списочные. */
            if (!l4match_same(g->l4, &c->l4)) continue;
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
            g->l4 = &c->l4;
            /* Имя ставим предварительно, окончательное — ниже: домены могут прийти вторым
             * правилом, и тогда набор обязан называться _dom, иначе резолвер его не найдёт
             * (он вычисляет имя сам, той же функцией group_set_name). */
            group_set_name(g->name, sizeof(g->name), g->out, all ? "all" : domains ? "dom" : "ip",
                           g->from, g->from_n, g->realip, g->l4);
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
                       g->from, g->from_n, g->realip, g->l4);
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

/* КАРТА ПОДМЕНЫ fake→real ЗАСЕВАЕТСЯ ПРЯМО В НАБОРЕ ПРАВИЛ — из файла состояния резолвера
 * (<state-dir>/fakeip.state, строки «домен\tподдельный\tнастоящий»), а не остаётся пустой до
 * перезапуска dnsd.
 *
 * ЗАЧЕМ. apply пересобирает таблицу целиком, и карта на мгновение исчезала вместе с ней; dnsd
 * восстанавливал её только при своём перезапуске, секундой позже. Запрос, пришедший в это окно,
 * не мог добавить подмену (карты нет), и dnsd по правилу fail-open отдавал клиенту НАСТОЯЩИЙ
 * адрес: сайт, который человек велел вести в туннель, уходил напрямую, а клиент запоминал этот
 * адрес на весь TTL записи. Снято с живого роутера: после «Применить» посреди просмотра YouTube
 * узел googlevideo остался в состоянии без настоящего адреса, а ролики не открывались до
 * перезапуска браузера — уже при исправном туннеле. С засеянной картой окна нет: пакеты к
 * поддельным адресам переводятся тем же набором правил, который их и метит.
 *
 * Только строки с настоящим адресом: без него подменять нечего, и dnsd такую запись тоже не
 * восстанавливает. Повтор поддельного адреса пропускается — nft отвергает набор с двойным
 * ключом целиком, а в файле повторы законны (первая раздача побеждает, как у dnsd). Файла нет —
 * карта пустая, как и раньше: так на роутере, где резолвер ещё ничего не раздал. */
static void emit_fakeip_elements(FILE *f) {
    char path[512];
    if (snprintf(path, sizeof(path), "%s/fakeip.state", g_state_dir) >= (int)sizeof(path)) return;
    FILE *s = fopen(path, "r");
    if (!s) return;
    static uint8_t seen[131072 / 8];       /* 198.18.0.0/15 — бит на адрес */
    memset(seen, 0, sizeof(seen));
    char line[1024];
    int n = 0;
    while (fgets(line, sizeof(line), s)) {
        char *t1 = strchr(line, '\t');
        if (!t1) continue;
        char *fake = t1 + 1;
        char *t2 = strchr(fake, '\t');
        if (!t2) continue;
        *t2 = '\0';
        char *real = t2 + 1;
        char *end = real + strcspn(real, "\t\r\n");
        *end = '\0';
        struct in_addr a, b;
        if (inet_aton(fake, &a) == 0 || inet_aton(real, &b) == 0 || b.s_addr == 0) continue;
        uint32_t fh = ntohl(a.s_addr);
        if ((fh & 0xfffe0000u) != 0xc6120000u) continue;   /* вне 198.18.0.0/15 — не наше */
        uint32_t idx = fh - 0xc6120000u;
        if (seen[idx >> 3] & (uint8_t)(1u << (idx & 7))) continue;
        seen[idx >> 3] |= (uint8_t)(1u << (idx & 7));
        /* В набор едет РАЗОБРАННЫЙ адрес, а не байты строки. inet_aton принимает не только
         * точечную запись: «0xc6120009», «3323068425» и «198.18.9» — то же самое 198.18.0.9,
         * и проверку диапазона выше такая строка проходит честно. А nft такого ключа не
         * понимает и отвергает набор ЦЕЛИКОМ (`nft -f` атомарен) — то есть одна нетипичная
         * строка в файле состояния оставила бы роутер вообще без правил: ни маршрутизации,
         * ни подмены, ни меток. Раз адрес уже разобран, печатать надо его, а не то, из чего
         * он разобран.
         *
         * Два своих буфера, а не inet_ntoa дважды: inet_ntoa отдаёт статический буфер, и
         * второй вызов в том же fprintf перезаписал бы результат первого. */
        char fs[INET_ADDRSTRLEN], rs[INET_ADDRSTRLEN];
        if (!inet_ntop(AF_INET, &a, fs, sizeof(fs)) ||
            !inet_ntop(AF_INET, &b, rs, sizeof(rs))) continue;
        fprintf(f, n ? ",\n            %s : %s" : "        elements = { %s : %s", fs, rs);
        n++;
    }
    if (n) fprintf(f, " }\n");
    fclose(s);
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

/* Группа каналов на сам телефон, а не на клиентов раздачи (см. from_is_local в spec.h).
 * Смешанных групп не бывает: спека отвергает «кому» из себя и клиентов сразу. */
static int group_is_local(const struct group *g) {
    return g->from_n && from_is_local(g->from[0]);
}

#ifdef STEER_ANDROID
static int has_local(void) {
    for (size_t i = 0; i < g_grp_n; i++) if (group_is_local(&g_grp[i])) return 1;
    return 0;
}

/* Есть ли доменный канал на сам телефон. Тогда DNS приложений заворачивается к резолверу —
 * см. emit_local_dns. */
static int has_local_domains(void) {
    for (size_t i = 0; i < g_grp_n; i++)
        if (group_is_local(&g_grp[i]) && g_grp[i].domains) return 1;
    return 0;
}

/* Есть ли в спеке туннель через via — тогда его сокет несёт STEER_TUNNEL_BIT, и заворот DNS
 * обязан его пропускать (см. emit_local_dns_redirect). */
static int has_via(void) {
    for (size_t i = 0; i < g_out_n; i++) if (g_out[i].via[0]) return 1;
    return 0;
}

/* ---- DNS приложений телефона — к резолверу движка -------------------------------------
 *
 * Доменный канал на сам телефон видит только те имена, что спросили через наш резолвер. DNS
 * приложений делает DnsResolver (netd) — сокетом, который он приписывает UID приложения, — к
 * серверам текущей сети; правило ниже заворачивает эти запросы к нам, а резолвер переспрашивает
 * тот же сервер (dnsd --upstream-origdst: адрес берётся из conntrack).
 *
 * ВСЕ приложения, а не только приложения каналов. У DnsResolver общий кэш на сеть: заверни мы
 * только своих, настоящий адрес, полученный чужим приложением первым, достался бы из кэша и
 * своему — мимо набора канала, то есть мимо туннеля. Кроме root: это сам резолвер (его запрос
 * наверх иначе завернулся бы по кругу) и прочие демоны.
 *
 * И перевод поддельных адресов для соединений самого телефона — тот же, что prerouting_dnat
 * делает для раздачи: поддельный адрес из кэша DnsResolver получает любое приложение, и у
 * приложения вне канала соединение должно уйти напрямую к настоящему адресу, а не в никуда.
 *
 * И UDP, и TCP: по TCP приходят переспросы после усечённого ответа (TC=1) и запросы приложений,
 * которые ходят по TCP сразу, — без заворота имя, спрошенное так, прошло бы мимо канала, и
 * соединение ушло бы по настоящему адресу. Резолвер слушает TCP на том же порту и переспрашивает
 * тот же сервер тоже по TCP (см. «DNS по TCP» в dnsd.c).
 *
 * ОБА СЕМЕЙСТВА. Запрос по IPv6 (сервер сети из RDNSS, в том числе link-local) заворачивается
 * так же: резолвер ищет исходное назначение и в AF_INET6 и переспрашивает тот же IPv6-сервер
 * (см. g_origdst в dnsd.c). В современной раскладке это одно правило в inet, в старой — по
 * цепочке nat output в ip и ip6 (emit_local_dns_redirect); на старом ядре без nat в ip6
 * (NFTC_IP6NAT) IPv6-половины нет — там такого правила не поставить, и apply об этом говорит. */

/* Само правило заворота — одно на всех раскладках и семействах (по правилу на протокол).
 *
 * Всех, кроме собственного запроса резолвера наверх (STEER_SELF_MARK) и собственного трафика
 * туннелей (без via — тот же STEER_SELF_MARK, с via — STEER_TUNNEL_BIT, см. ниже): DnsResolver
 * шлёт запросы приложений от root, поэтому по UID отличить нельзя. Метка «сам движок» у переспроса по TCP та же, что по UDP
 * (tcpu_open в dnsd.c).
 *
 * `ct mark set mark` — чтобы резолвер узнал метку сети исходного запроса: на 4.9 принятому сокету
 * метку датаграммы не узнать (SO_RCVMARK — с 5.19), а запись conntrack резолвер и так читает
 * целиком (подробно — у g_up_mark в dnsd.c). У TCP это та же запись conntrack, что ищет резолвер
 * по соединению, и цепочка nat видит её первый пакет (SYN) — метку сокета приложения. Копируется
 * метка ЦЕЛИКОМ, и это не расходится с тем, как метку соединения пишет сам движок: разметка
 * каналов (output_mark, раньше по приоритету) тоже делает `ct mark set mark` целиком
 * (out_needs_ctmark верно для всякого выхода канала телефона: tgws там спека отвергает), то есть к
 * этому правилу пакет приходит с той же меткой, что уже лежит в ct mark, и перезапись ничего не
 * меняет. У запроса, который канал не пометил, ct mark получает fwmark netd — поле движка там
 * нулевое, и читателям ct mark движка (сравнения `ct mark and МАСКА == метка`) это ничего не
 * значит. Смешать метку пакета со старой ct mark (`ct mark and … or mark`) на 4.9 нельзя вовсе:
 * там нет bitwise двух регистров. Цепочка nat видит только первый пакет соединения — ровно тот
 * момент, когда метку и надо запомнить. */
/* Туннели через via — тоже мимо заворота. Сокет наверх такого туннеля несёт метку ЦЕЛИ, а не
 * «сам движок», и у сервера на 53-м порту (UDP или TCP — их и выбирают, чтобы пройти там, где
 * режут остальное) заворот забрал бы соединение туннеля к нашему резолверу: туннель не встал бы
 * вовсе. Пропуск — по биту STEER_TUNNEL_BIT, который такой сокет несёт рядом с меткой цели (почему
 * бит, а не UID помощника, — у определения в spec.h). Условие пишется только в спеке с via: у
 * остальных текст правил остаётся прежним побайтно, а бита там не ставит никто. */
static void emit_local_dns_redirect(FILE *f) {
    char tun[64] = "";
    if (has_via())
        snprintf(tun, sizeof(tun), "meta mark and 0x%08x == 0x00000000 ", STEER_TUNNEL_BIT);
    fprintf(f, "        meta mark and 0x%08x != 0x%08x %sudp dport 53 ct mark set mark counter "
               "redirect to :%d comment \"steer-dns-local\"\n",
            STEER_MARK_MASK, STEER_SELF_MARK, tun, DNS_PORT);
    fprintf(f, "        meta mark and 0x%08x != 0x%08x %stcp dport 53 ct mark set mark counter "
               "redirect to :%d comment \"steer-dns-local-tcp\"\n",
            STEER_MARK_MASK, STEER_SELF_MARK, tun, DNS_PORT);
}

static void emit_local_dns(FILE *f, const char *dnat_kw) {
    emit_local_dns_redirect(f);
    if (has_fakeip())
        fprintf(f, "        ip daddr 198.18.0.0/15 counter %s to ip daddr map @fakeip "
                   "comment \"steer-fakeip-local\"\n", dnat_kw);
}

/* «Кто» у группы на сам телефон: владелец сокета. "self" — все приложения (UID от
 * STEER_APP_UID_MIN; почему не демоны — у from_is_local); "uid:N[-M]" — перечисленные. У
 * пакета без сокета (RST и ICMP, которые ядро шлёт само) владельца нет, и skuid не совпадает
 * ни с чем — такие пакеты идут обычным путём.
 *
 * `ct direction original` — только соединения, которые приложение ОТКРЫЛО само. Ответы на
 * входящие (беспроводной adb, сервер в приложении) обязаны уйти тем же путём, каким пришёл
 * запрос, а не в туннель. */
static void emit_local_who(FILE *f, const struct group *g) {
    if (!strcmp(g->from[0], "self")) {
        fprintf(f, "meta skuid >= %u ct direction original ", STEER_APP_UID_MIN);
        return;
    }
    int one = g->from_n == 1 && !strchr(g->from[0], '-');
    fprintf(f, one ? "meta skuid " : "meta skuid { ");
    for (size_t i = 0; i < g->from_n; i++) {
        unsigned lo, hi;
        if (from_uid_range(g->from[i], &lo, &hi) != 0)
            die("группа %s: негодный UID", g->name);   /* спека это уже отвергла */
        if (lo == hi) fprintf(f, "%s%u", i ? ", " : "", lo);
        else fprintf(f, "%s%u-%u", i ? ", " : "", lo, hi);
    }
    fprintf(f, one ? " ct direction original " : " } ct direction original ");
}

#endif

/* «Чем и куда именно»: сужение канала по протоколу и портам назначения (схема 2).
 *
 * ПОЧЕМУ `meta l4proto` ПЛЮС `th dport`, А НЕ `tcp dport`/`udp dport`. Две причины, и
 * первая решающая.
 *
 * Первая: nft не умеет «или» внутри правила. Слово `tcp dport` само тянет за собой
 * зависимость «протокол tcp», поэтому «и TCP, и UDP на этих портах» им не записать — пришлось
 * бы ставить ДВА правила на один канал. А правило у канала одно не для красоты: на нём висит
 * счётчик (второе правило разделило бы объёмы канала на две половины, и ни одна не была бы
 * ответом на «сколько ушло»), и на нём же держится «первое совпадение выигрывает» — порядок,
 * который человек читает прямо по спеке. `meta l4proto { tcp, udp }` — это МНОЖЕСТВО, а не
 * «или», и оно укладывается в то же одно правило.
 *
 * Вторая: одна форма и для одного протокола, и для двух. Ветка «а если протокол один,
 * печатаем по-другому» — это второй путь, по которому пойдёт ровно половина каналов, и
 * расходиться этим двум путям негде, кроме опыта на живом роутере.
 *
 * И ЭТО НЕ КОМПРОМИСС: разницы с «правильной» формой нет никакой. Проверено загрузкой в
 * ядро (nftables 1.0.9): `meta l4proto udp th dport { … }` ядро печатает обратно как
 * `udp dport { … }`, а `meta l4proto tcp th dport 1-1024` — как `tcp dport 1-1024`. То
 * есть специальная форма и есть наша, просто записанная короче, — а множество из двух
 * протоколов ядро оставляет как написано, потому что короче его не записать.
 *
 * ЗАЧЕМ ПРОТОКОЛ ОБЯЗАТЕЛЕН ПЕРЕД ПОРТОМ. `th` — это смещение в транспортном заголовке, и
 * никакой проверки протокола в нём нет. У icmp, esp, gre по этому смещению лежат чужие байты,
 * и `th dport 50000-65535` совпал бы на них — то есть канал забирал бы пакеты, у которых
 * портов не бывает вовсе. Поэтому при заданных портах протокол пинится ВСЕГДА, и когда
 * человек его не назвал — множеством `{ tcp, udp }`, которое здесь работает носителем для
 * чтения порта, а не сужением по протоколу.
 *
 * СЕМЕЙСТВА АДРЕСОВ. Таблица `inet` несёт и IPv4, и IPv6; `meta l4proto` и `th` смотрят на
 * транспортный уровень и одинаково верны для обоих — в отличие от `ip saddr`, которому нужен
 * близнец `ip6 saddr` (см. emit_ifs и правило DNS). Пометки семейства здесь поэтому нет.
 *
 * ПОРЯДОК В ПРАВИЛЕ: сужение стоит ПЕРЕД поиском по набору адресов. Сравнение одного байта
 * протокола дешевле поиска в наборе на 19 тысяч префиксов, и для канала «только UDP» оно
 * отбрасывает весь TCP роутера до поиска, а не после. На пакет это один и тот же путь, но
 * пакетов, которым канал не подходит, всегда больше.
 *
 * reverse — встречный путь: там наш клиент получатель, а порт сервера ИСХОДЯЩИЙ. */
static void emit_l4(FILE *f, const struct l4match *m, int reverse) {
    if (l4match_empty(m)) return;
    if (m->proto == CH_PROTO_TCP)      fprintf(f, "meta l4proto tcp ");
    else if (m->proto == CH_PROTO_UDP) fprintf(f, "meta l4proto udp ");
    else                               fprintf(f, "meta l4proto { tcp, udp } ");
    if (!m->ports_n) return;
    fprintf(f, "th %s ", reverse ? "sport" : "dport");
    /* Один диапазон печатается без фигурных скобок — ровно как одно устройство в emit_ifs, и
     * по той же причине: так это печатает сам nft, и вывод `--dry-run` совпадает с тем, что
     * человек потом увидит в `nft list`. */
    int one = m->ports_n == 1;
    if (!one) fprintf(f, "{ ");
    for (size_t i = 0; i < m->ports_n; i++) {
        if (i) fprintf(f, ", ");
        if (m->ports[i].lo == m->ports[i].hi) fprintf(f, "%u", m->ports[i].lo);
        else fprintf(f, "%u-%u", m->ports[i].lo, m->ports[i].hi);
    }
    fprintf(f, one ? " " : " } ");
}

/* Сужение словами, для explain. Отдельно от emit_l4, потому что там формат nftables, а
 * здесь фраза человеку; печатать в ответ человеку синтаксис ядра значило бы объяснять
 * настройку языком, которого он не выбирал.
 *
 * Дописывается КУСКАМИ С ПРОВЕРКОЙ МЕСТА, а не сложением возвратов snprintf, и это не
 * педантизм: snprintf возвращает длину, которая ПОЛУЧИЛАСЬ БЫ, а не записанную. Сложение
 * таких возвратов уводит смещение за буфер, и следующий `n - k` уходит в подпол size_t,
 * превращая ограничение длины в «сколько угодно». Шестнадцать диапазонов по «50000-65535» —
 * это 217 байт, то есть предел MAX_PORTS переполняет любой разумный буфер, и случай не
 * гипотетический. Не влезло — обрываем на границе куска: обрезанный перечень портов в
 * ПОЯСНЕНИИ безобиден, порванная память — нет. */
static void l4_describe(const struct l4match *m, char *dst, size_t n) {
    if (!n) return;
    size_t k = 0;
    dst[0] = '\0';
    char piece[32];
    snprintf(piece, sizeof(piece), "%s",
             m->proto == CH_PROTO_TCP ? "tcp" :
             m->proto == CH_PROTO_UDP ? "udp" : "tcp и udp");
    for (size_t i = 0; i <= m->ports_n; i++) {
        if (i) {
            if (m->ports[i - 1].lo == m->ports[i - 1].hi)
                snprintf(piece, sizeof(piece), "%s%u", i > 1 ? ", " : " ",
                         m->ports[i - 1].lo);
            else
                snprintf(piece, sizeof(piece), "%s%u-%u", i > 1 ? ", " : " ",
                         m->ports[i - 1].lo, m->ports[i - 1].hi);
        }
        size_t len = strlen(piece);
        if (k + len + 1 > n) return;
        memcpy(dst + k, piece, len);
        k += len;
        dst[k] = '\0';
    }
}

/* Elements come straight from the list files: the fitter (steer-aggregate) has
 * already decided what fits, and re-parsing them here would only add a second place
 * for the two to disagree. */
/* Похожа ли строка на адрес или префикс IPv4. Только форма, без проверки диапазонов:
 * нам надо отличить «1.2.3.0/24» от «amazon.com», а не проверять корректность маски —
 * второе сделает nft, и его сообщение об одном плохом элементе понятно. */
/* Одна половина: «A.B.C.D» или «A.B.C.D/N». Точную проверку значений делает nft — здесь
 * различается ФОРМА, чтобы отделить адресный список от доменного. */
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
        if (spec_line_is_addr(p)) continue;
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
            g->addrs += total - bad;
            if (!total) {
                fprintf(stderr, LOG_W "%s: список пуст — канал «%s» ничего не поймает\n",
                        g->files[k], g->members_n ? g->members[0] : g->name);
                continue;
            }
            /* РАНЬШЕ ЗДЕСЬ БЫЛ ОТКАЗ, и он был прав. Список без единого адреса,
             * подключённый адресным ключом, означал канал, который не поймает ничего:
             * компилятор брал из файла только адреса, а доменные строки не брал никто.
             * Отказ с указанием файла и первой строки был единственным способом это
             * назвать — nft на таком списке отвергает НАБОР ЦЕЛИКОМ с указанием на
             * середину строки в восемь тысяч символов.
             *
             * С гибридными списками это перестало быть ошибкой: доменные строки из этого
             * же файла теперь берёт резолвер (load_rules_into в dnsd.c), и список из одних
             * имён просто работает — как доменный. Тот самый список «Хостинги и CDN» у
             * издателя, из-за которого отказ и появился (лежит в адресных категориях,
             * внутри 250 имён и ни одного адреса), заработал сам собой.
             *
             * Строка всё равно печатается, и с уровнем: канал, у которого в наборе нет ни
             * одного адреса, — это законное, но НЕОЖИДАННОЕ состояние, и человек, который
             * выбирал «подсети», должен узнать, что получил маршрутизацию по именам. */
            if (bad == total) {
                char who[128];
                if (g->members_n > 1)
                    snprintf(who, sizeof(who), "%.60s (и ещё %zu в том же наборе)",
                             g->members[0], g->members_n - 1);
                else
                    snprintf(who, sizeof(who), "%.60s",
                             g->members_n ? g->members[0] : g->name);
                /* По именам канал работает, только когда у его группы есть доменный набор,
                 * то есть рядом стоит канал с доменными списками того же выхода, тех же
                 * клиентов и того же сужения (build_groups; резолвер повторяет это же
                 * решение в dch_join_domain_group). Без такого соседа имена из файла не
                 * берёт никто, и обещать «будет работать» значило бы соврать. */
                if (g->domains)
                    fprintf(stderr, LOG_W "%s: адресов нет вовсе, только имена (%zu) — канал "
                                    "«%s» будет работать по именам через резолвер. Первая "
                                    "строка: «%s»\n",
                            g->files[k], total, who, sample);
                else
                    fprintf(stderr, LOG_W "%s: адресов нет вовсе, только имена (%zu) — канал "
                                    "«%s» ничего не поймает: имена резолвер берёт у каналов с "
                                    "доменными списками, а у этого их нет. Подключите файл "
                                    "доменным списком (domains_files). Первая строка: «%s»\n",
                            g->files[k], total, who, sample);
                continue;
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
        if (!spec_line_is_addr(p)) continue;
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
 * `apply` заменяет таблицу новой одной транзакцией, а счётчики живут в правилах —
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
    /* Таблица — своя у каждой сборки (nft_table): у мини-сборки моста это inet stgws, и с
     * жёстким «inet steer» её счётчики через apply не переносились. */
    char cmd[256];
    snprintf(cmd, sizeof(cmd),
             "nft -a list chain inet %s prerouting_mark 2>/dev/null; "
             "nft -a list chain inet %s postrouting_down 2>/dev/null", nft_table(), nft_table());
    FILE *nft = popen(cmd, "r");
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
        /* Одно имя — одно число. В современной раскладке имена в цепочке уникальны и эта
         * ветка не срабатывает; в старой у доменной группы с префиксами правил два (по одному
         * на половину набора, см. generate), и объём канала — их сумма. */
        size_t k = 0;
        while (k < *n && strcmp(arr[k].name, c) != 0) k++;
        if (k < *n) {
            arr[k].pkts += p;
            arr[k].bytes += b;
            continue;
        }
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

/* РАСКЛАДКА НАБОРА ПРАВИЛ ЭТОГО ЗАПУСКА — флаги NFTC_* из nft_compat (spec.h). Ставит cmd_apply
 * перед генерацией; ноль — современное ядро, и тогда текст печатается ровно тот же, что до
 * появления старой раскладки, байт в байт: ветки legacy стоят рядом с прежними строками, а то,
 * что печатают обе раскладки, перенесено в функции дословно. На этом держатся все стенды
 * компилятора и то, что роутеры после обновления получают тот же набор правил.
 *
 * Что меняется в старой раскладке — коротко; доводы у каждого места ниже:
 *   - таблиц становится две-три: `inet` (наборы, разметка, счётчики, очереди — всё, что
 *     filter), `ip` (карта fakeip и ОДНА цепочка nat на prerouting) и `ip6` (заворот DNS по
 *     IPv6, если ядро умеет nat в ip6). Наборы между таблицами не видны, поэтому карта fakeip
 *     живёт там же, где правило dnat, — в ip;
 *   - доменный набор делится надвое: интервальный без сроков (<имя>_n, префиксы из списков) и
 *     hash со сроками (<имя>, туда пишет резолвер); правило канала повторяется на каждую
 *     половину;
 *   - notrack — только если ядро его знает (NFTC_NOTRACK), `exthdr … exists` — заменён. */
static int g_nftc;
#define NFT_LEGACY (g_nftc & NFTC_LEGACY)

/* Есть ли у доменной группы статическая половина в старой раскладке: адресные строки в её
 * списках. Та же проверка, что решает про строку elements в современном наборе. */
static int legacy_has_static(const struct group *g) {
    return NFT_LEGACY && g->domains && g->files_n && g->addrs;
}

/* То же для читателей ядра — diag и explain. Они списков не разбирают (addrs считает только
 * check_address_lists в apply), поэтому спрашивают вторую половину у всякой доменной группы с
 * адресными списками; нет её в ядре — ответ «набора нет», и он просто не прибавляется. */
static int legacy_may_have_static(const struct group *g) {
    return NFT_LEGACY && g->domains && g->files_n;
}

/* Интервальный набор с элементами из адресных списков группы — статическая половина доменного
 * набора в старой раскладке. Тот же текст, что у адресного набора в generate. */
static void emit_static_set(FILE *f, const struct group *g, const char *name) {
    fprintf(f, "    set %s {\n        type ipv4_addr\n"
               "        flags interval\n        auto-merge\n", name);
    if (g->files_n && g->addrs) {
        fprintf(f, "        elements = { ");
        size_t written = 0;
        for (size_t k = 0; k < g->files_n; k++)
            written += emit_elements(f, g->files[k], written);
        fprintf(f, " }\n");
    }
    fprintf(f, "    }\n");
}

/* Цепочка для traceroute_hops — объяснение у места вызова в generate. Функцией, потому что
 * печатают её две раскладки. */
static void emit_traceroute_raw(FILE *f) {
    fprintf(f, "    chain prerouting_raw {\n"
               "        type filter hook prerouting priority raw; policy accept;\n"
               "        meta l4proto icmp icmp type time-exceeded counter notrack "
               "comment \"steer:traceroute-hops\"\n"
               "    }\n");
}

/* Правила перехвата Telegram — объяснение у цепочки tgws_redirect в generate. Функцией по
 * той же причине: в старой раскладке они живут в общей цепочке nat таблицы ip. */
static void emit_tgws_rules(FILE *f) {
    for (size_t i = 0; i < g_out_n; i++) {
        struct output *o = &g_out[i];
        if (o->kind != OUT_TGWS) continue;
        fprintf(f, "        meta mark and 0x%08x == 0x%08x tcp dport { 443, 80, 5222 } "
                   "counter redirect to :%d comment \"steer:tgws:%s\"\n",
                STEER_MARK_MASK, o->mark, out_tgws_port(o), o->name);
    }
}

/* Какие таблицы, кроме inet, есть в старой раскладке. Спрашивают двое — генератор и шапка
 * файла в cmd_apply (добавить-и-удалить каждую таблицу раскладки одной транзакцией), — и
 * ответ у них обязан совпадать, иначе `delete table` встретил бы таблицу, которой файл не
 * создаёт, или наоборот. */
static int legacy_has_ip(void) {
    if (!NFT_LEGACY) return 0;
    if (has_tgws()) return 1;
#ifdef STEER_TGWS
    return 0;
#else
    return 1;                       /* заворот DNS стоит всегда — см. prerouting_dns */
#endif
}

static int legacy_has_ip6(void) {
#ifdef STEER_TGWS
    return 0;
#else
    return NFT_LEGACY && (g_nftc & NFTC_IP6NAT);
#endif
}

#ifdef STEER_ANDROID
/* ---- каналы на сам телефон: разметка на выходе ------------------------------------
 *
 * Тот же приём, что prerouting_mark для раздачи, но на хуке output: «первое совпадение
 * решает», одно правило на группу (два — на две половины доменного набора старой раскладки),
 * метка — наши биты с маской, метка соединения — как там.
 *
 * Тип цепочки зависит от раскладки. В современной (ядро с nat в inet) это route прямо в
 * inet, где и наборы: смена метки в ней сама заставляет ядро искать маршрут заново. В старой
 * route в inet нет, поэтому здесь filter, а к метке добавляется STEER_REROUTE_BIT — его
 * снимает цепочка route в таблице ip (generate_legacy_tail), и маршрут пересматривается там
 * (подробно — у STEER_REROUTE_BIT в spec.h).
 *
 * IPv6. Наборы каналов — IPv4, и правило с набором IPv6 не касается. Но у группы «весь
 * трафик» набора нет, и её IPv6 ушёл бы мимо туннеля: маршруты выхода движок ставит только
 * для IPv4. Поэтому такой группе IPv6 отвечается отказом — приложения переходят на IPv4 (так
 * устроен выбор адреса у любого клиента с двумя стеками), и ничего не утекает напрямую. */
static void emit_output_mark(FILE *f) {
    fprintf(f, "\n    chain output_mark {\n"
               "        type %s hook output priority mangle + 1; policy accept;\n",
            NFT_LEGACY ? "filter" : "route");
    for (size_t i = 0; i < g_grp_n; i++) {
        struct group *g = &g_grp[i];
        if (!group_is_local(g)) continue;
        struct output *o = out_by_name(g->out);
        if (!o) die("channel group %s points at a missing output", g->name);
        if (g->all && out_needs_mark(o)) {
            /* С тем же сужением по протоколу и портам, что и канал: канал «UDP 50000-65535»
             * не вправе отнимать у приложения весь IPv6. Своя сеть (петля, link-local, ULA,
             * мультикаст) — не наружу и не мимо туннеля, её не трогаем. */
            fprintf(f, "        ");
            emit_local_who(f, g);
            fprintf(f, "meta nfproto ipv6 ");
            emit_l4(f, g->l4, 0);
            fprintf(f, "oifname != \"lo\" ip6 daddr != { fe80::/10, fc00::/7, ff00::/8 } "
                       "counter reject comment \"steer-v6:%s\"\n", g->name);
        }
        int halves = legacy_has_static(g) ? 2 : 1;
        for (int h = 0; h < halves; h++) {
            char sn[80];
            const char *set = g->name;
            if (halves == 2 && h == 0) { nft_static_set_name(sn, sizeof(sn), g->name); set = sn; }
            fprintf(f, "        ");
            emit_local_who(f, g);
            /* «Весь трафик» — это интернет, а не своя сеть: принтер, NAS и Chromecast в Wi-Fi
             * через туннель не видны. Только IPv4 — IPv6 такой группы отвергнут строкой выше. */
            if (g->all)
                fprintf(f, "meta nfproto ipv4 ip daddr != { 10.0.0.0/8, 127.0.0.0/8, "
                           "169.254.0.0/16, 172.16.0.0/12, 192.168.0.0/16, 224.0.0.0/4, "
                           "255.255.255.255 } ");
            emit_l4(f, g->l4, 0);
            if (g->files_n || g->domains || g->emptied) fprintf(f, "ip daddr @%s ", set);
            /* Бит перемаршрутизации ставится ПОСЛЕ метки соединения: в conntrack ему не место,
             * он живёт на пакете до цепочки route в таблице ip. */
            if (out_needs_mark(o))
            {
                fprintf(f, "meta mark set mark and 0x%08x or 0x%08x %s",
                        ~STEER_MARK_MASK, o->mark,
                        out_needs_ctmark(o) ? "ct mark set mark " : "");
                if (NFT_LEGACY) fprintf(f, "meta mark set mark or 0x%08x ", STEER_REROUTE_BIT);
            }
            if (h == 0) emit_counter(f, g->name, 0);
            else fprintf(f, "counter ");
            fprintf(f, "return comment \"steer:%s\"\n", g->name);
        }
    }
    fprintf(f, "    }\n");
}

#endif

/* ХВОСТ НАБОРА ПРАВИЛ В СТАРОЙ РАСКЛАДКЕ: закрыть inet и собрать nat в ip/ip6.
 *
 * ПОЧЕМУ ОДНА ЦЕПОЧКА NAT, а не три, как в современной раскладке (prerouting_dns,
 * prerouting_dnat, tgws_redirect). До 4.18 каждая базовая цепочка nat — отдельный хук, и
 * первый из них, где ни одно правило не совпало, ставит новому соединению «пустую»
 * трансляцию (nf_nat_alloc_null_binding в nf_nat_ipv4_fn); остальные хуки видят
 * nf_nat_initialized и своих правил уже не проверяют. Три цепочки на 4.9 значили бы, что для
 * запроса DNS работает только первая, а для поддельного адреса — ни одна, если первой стоит
 * цепочка DNS. В одной цепочке правила проверяются по очереди и первое совпавшее ставит
 * трансляцию — ровно то, что делают три цепочки на современном ядре (там после первой
 * состоявшейся трансляции остальные цепочки тоже пропускаются). Порядок правил повторяет
 * порядок цепочек: DNS и fakeip на dstnat в порядке регистрации, мост на dstnat + 1.
 *
 * ПОЧЕМУ dstnat - 1. Тот же механизм «пустой трансляции» действует между нами и таблицей
 * nat iptables: её хук на том же приоритете -100 зарегистрирован раньше (при загрузке), и
 * при равном приоритете идёт первым. На Android iptables nat есть всегда (netd держит там
 * правила раздачи интернета), то есть на -100 наша цепочка не увидела бы ни одного нового
 * соединения: ни заворота DNS, ни fakeip. На -101 первыми идём мы. Цена — обратная: для
 * соединения, которое не забрали мы, «пустую» трансляцию назначения ставим уже мы, и правила
 * PREROUTING в iptables nat до него не доходят. У netd там только пустая цепочка oem_nat_pre,
 * раздача интернета живёт в POSTROUTING, которого мы не касаемся; на прочих старых системах
 * с пробросами портов в iptables apply об этом предупреждает (report_legacy_gaps).
 *
 * Карта fakeip — в той же таблице ip, что и правило dnat: наборы между таблицами не видны.
 * Синтаксис `dnat to` без слова ip: в таблице одного семейства семейство и так известно.
 *
 * ПОЧЕМУ ПУСТАЯ ЦЕПОЧКА postrouting_nat. До 4.18 ядро переписывает адреса только в тех хуках,
 * где зарегистрирована хоть одна цепочка nat, — и обратную трансляцию ответов тоже. Ответ на
 * заворот DNS или на dnat по карте fakeip уходит клиенту через POSTROUTING, и там его адрес
 * источника обязан вернуться к тому, куда клиент спрашивал (1.1.1.1, поддельный 198.18.x.x).
 * Без цепочки на этом хуке ответ ушёл бы с настоящим адресом, и клиент его отбросил бы как
 * чужой. Снято на стенде tools/vm49: правила prerouting срабатывают (счётчики по единице), а
 * SYN-ACK приходит от 10.99.0.1:8080 вместо 198.18.0.0:8080 — пока цепочки нет. На Android её
 * роль и так выполнял бы хук nat iptables, но полагаться на чужую таблицу незачем.
 * Приоритет srcnat + 1, то есть ПОСЛЕ nat iptables (100): пустая цепочка тоже ставит
 * соединению «пустую» трансляцию источника, и окажись она первой — MASQUERADE раздачи
 * интернета у netd больше не сработал бы.
 *
 * ip6 — только заворот DNS, и только если ядро умеет nat в ip6 (NFTC_IP6NAT): без этого вся
 * транзакция отверглась бы из-за одной таблицы. Пустая цепочка postrouting — там же и по той
 * же причине. */
static void generate_legacy_tail(FILE *f) {
    if (has_domains() && g_traceroute_hops && (g_nftc & NFTC_NOTRACK)) emit_traceroute_raw(f);
    fprintf(f, "}\n");
    int fakeip = has_domains() && has_fakeip();
    if (legacy_has_ip()) {
        fprintf(f, "table ip %s {\n", nft_table());
        if (fakeip) {
            fprintf(f, "    map fakeip {\n        type ipv4_addr : ipv4_addr;\n");
            emit_fakeip_elements(f);
            fprintf(f, "    }\n");
        }
        fprintf(f, "    chain prerouting_nat {\n"
                   "        type nat hook prerouting priority dstnat - 1; policy accept;\n");
#ifndef STEER_TGWS
        /* IPv4-половина prerouting_dns: подсети клиентов по адресу, а без подсетей — по
         * устройству. Устройственное правило при заданных подсетях в современной раскладке
         * помечено `meta nfproto ipv6` — здесь оно уезжает в таблицу ip6. */
        for (size_t i = 0; i < g_from_default_n; i++)
            fprintf(f, "        ip saddr %s udp dport 53 counter redirect to :%d\n",
                    g_from_default[i], DNS_PORT);
        if (!g_from_default_n) {
            fprintf(f, "        ");
            emit_ifs(f, 0);
            fprintf(f, "udp dport 53 counter redirect to :%d\n", DNS_PORT);
        }
        /* TCP/53 рядом с UDP/53 — почему, сказано у prerouting_dns в generate. */
        for (size_t i = 0; i < g_from_default_n; i++)
            fprintf(f, "        ip saddr %s tcp dport 53 counter redirect to :%d\n",
                    g_from_default[i], DNS_PORT);
        if (!g_from_default_n) {
            fprintf(f, "        ");
            emit_ifs(f, 0);
            fprintf(f, "tcp dport 53 counter redirect to :%d\n", DNS_PORT);
        }
#endif
        if (fakeip)
            fprintf(f, "        ip daddr 198.18.0.0/15 counter dnat to ip daddr map @fakeip\n");
        emit_tgws_rules(f);
        fprintf(f, "    }\n");
#ifdef STEER_ANDROID
        if (has_local_domains()) {
            fprintf(f, "    chain output_nat {\n"
                       "        type nat hook output priority dstnat - 1; policy accept;\n");
            emit_local_dns(f, "dnat");
            fprintf(f, "    }\n");
        }
        /* Снятие бита перемаршрутизации — см. STEER_REROUTE_BIT в spec.h. mangle + 2: сразу
         * после разметки (output_mark в inet, mangle + 1) и до nat на выходе. */
        if (has_local())
            fprintf(f, "    chain output_reroute {\n"
                       "        type route hook output priority mangle + 2; policy accept;\n"
                       "        meta mark and 0x%08x == 0x%08x meta mark set mark and 0x%08x "
                       "counter comment \"steer-reroute\"\n"
                       "    }\n", STEER_REROUTE_BIT, STEER_REROUTE_BIT, ~STEER_REROUTE_BIT);
#endif
        fprintf(f, "    chain postrouting_nat {\n"
                   "        type nat hook postrouting priority srcnat + 1; policy accept;\n"
                   "    }\n}\n");
    }
    if (legacy_has_ip6()) {
        fprintf(f, "table ip6 %s {\n"
                   "    chain prerouting_nat {\n"
                   "        type nat hook prerouting priority dstnat - 1; policy accept;\n"
                   "        ", nft_table());
        emit_ifs(f, 0);
        fprintf(f, "udp dport 53 counter redirect to :%d\n", DNS_PORT);
        fprintf(f, "        ");
        emit_ifs(f, 0);
        fprintf(f, "tcp dport 53 counter redirect to :%d\n", DNS_PORT);
        fprintf(f, "    }\n");
#ifdef STEER_ANDROID
        /* IPv6-половина заворота DNS приложений (см. emit_local_dns): та же цепочка, что в
         * таблице ip, без fakeip — поддельные адреса только IPv4. */
        if (has_local_domains()) {
            fprintf(f, "    chain output_nat {\n"
                       "        type nat hook output priority dstnat - 1; policy accept;\n");
            emit_local_dns_redirect(f);
            fprintf(f, "    }\n");
        }
#endif
        fprintf(f, "    chain postrouting_nat {\n"
                   "        type nat hook postrouting priority srcnat + 1; policy accept;\n"
                   "    }\n}\n");
    }
}

static void generate(FILE *f) {
    fprintf(f, "table inet %s {\n", nft_table());
    for (size_t i = 0; i < g_grp_n; i++) {
        struct group *g = &g_grp[i];
        /* `any`-группе набор не нужен; опустевшей — нужен, иначе её правило потеряет
         * `ip daddr` и станет безусловным (см. поле `emptied`). */
        if (!g->files_n && !g->domains && !g->emptied) continue;
        if (g->domains && NFT_LEGACY) {
            /* СТАРОЕ ЯДРО: интервальный набор со сроками не грузится (у nft_set_rbtree в 4.9
             * нет NFT_SET_TIMEOUT), а одному набору здесь нужно и то и другое — префиксы из
             * списков навсегда и адреса резолвера на TTL. Поэтому набора два.
             *
             * Динамический — hash со сроками, и он сохраняет ИМЯ ГРУППЫ: резолвер вычисляет
             * имя той же group_set_name и пишет туда не зная про раскладку ничего, кроме
             * одного — что интервальной пары там больше нет (см. nft_add_element в dnsd.c).
             * auto-merge здесь не нужен и не принимается: сливать в hash нечего.
             *
             * Статический — интервальный, с суффиксом _n, и только когда в списках группы
             * есть адресные строки: пустой интервальный набор на каждый доменный канал был бы
             * лишним поиском на каждом пакете. */
            fprintf(f, "    set %s {\n        type ipv4_addr\n        flags timeout\n    }\n",
                    g->name);
            if (legacy_has_static(g)) {
                char sn[80];
                nft_static_set_name(sn, sizeof(sn), g->name);
                emit_static_set(f, g, sn);
            }
            continue;
        }
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
            if (g->files_n && g->addrs) {
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
            if (g->files_n && g->addrs) {
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
        /* Каналы на сам телефон — на хуке output, см. emit_output_mark. */
        if (group_is_local(g)) continue;
        /* ПРАВИЛ У ГРУППЫ ОБЫЧНО ОДНО, в старой раскладке у доменной группы с префиксами — два:
         * по правилу на каждую половину набора (см. generate выше). nft не умеет «или» внутри
         * правила, а объединить интервальный набор с hash-набором нечем. Оба правила
         * одинаковы во всём, кроме набора, и оба кончаются return — первое совпавшее решает,
         * как и раньше. Комментарий у них ОДИН И ТОТ ЖЕ: счётчики читаются по нему, и
         * counters_load складывает правила с одним именем — объём канала остаётся одним
         * числом. Перенесённое значение ложится в первое правило, второе начинает с нуля:
         * сумма от этого не меняется. */
        int halves = legacy_has_static(g) ? 2 : 1;
        for (int h = 0; h < halves; h++) {
            char sn[80];
            const char *set = g->name;
            if (halves == 2 && h == 0) { nft_static_set_name(sn, sizeof(sn), g->name); set = sn; }
            fprintf(f, "        ");
            emit_from(f, g);
            emit_l4(f, g->l4, 0);
            if (g->files_n || g->domains || g->emptied) fprintf(f, "ip daddr @%s ", set);
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
                /* Ко всем выходам, КРОМЕ kind=direct, к нашей метке добавляется чужой бит —
                 * тот, которым системный zapret узнаёт «этот пакет не мой» (ZAPRET_SKIP_MARK,
                 * см. spec.h; кому именно и почему — out_skips_zapret там же).
                 *
                 * У kind=zapret без него трафик разбирали бы двое: сначала общий обход своей
                 * стратегией, потом наш экземпляр своей, — и вышло бы не то, что выбрал
                 * человек, ни в одном из двух смыслов. У туннельных выходов причина другая и
                 * не менее веская: обход стал бы рассинхронизировать ВНЕШНИЕ пакеты туннеля,
                 * до полезной нагрузки не добираясь вовсе.
                 *
                 * Ставится ЗДЕСЬ, в prerouting, потому что цепочки zapret висят на
                 * postrouting: позже было бы поздно. */
                /* Метка СОЕДИНЕНИЯ ставится не всем: она живёт в conntrack и переживает
                 * снятие правил, поэтому у выходов, которым она не нужна, её нет вовсе — см.
                 * out_needs_ctmark в spec.h и что из-за неё случалось после удаления tgws. */
                fprintf(f, "meta mark set mark and 0x%08x or 0x%08x %s",
                        ~STEER_MARK_MASK,
                        out_skips_zapret(o) ? (o->mark | ZAPRET_SKIP_MARK) : o->mark,
                        out_needs_ctmark(o) ? "ct mark set mark " : "");
            /* `return` and not `accept`: it ends OUR chain, letting the rest of the
             * firewall proceed, while making the first matching group the winner. */
            if (h == 0) emit_counter(f, g->name, 0);
            else fprintf(f, "counter ");
            fprintf(f, "return comment \"steer:%s\"\n", g->name);
        }
    }
    fprintf(f, "    }\n");

#ifdef STEER_ANDROID
    if (has_local()) emit_output_mark(f);
#endif

    /* ВЫХОД УПАЛ И ПУЩЕН НАПРЯМУЮ — бит «не для zapret» снимается. Правило разметки выше
     * ставит его безусловно, а при on_fail=direct/zapret упавший выход отдаёт трафик
     * таблице main, то есть открытому пути; там пакет обязан быть обычным трафиком роутера
     * и для общего обхода тоже. Какие выходы сейчас в таком состоянии, знает сторож: он
     * держит их метки в наборе. Зачем именно так — у out_failopen_capable в spec.h.
     *
     * mangle + 2 — сразу после разметки (mangle + 1), то есть задолго до цепочек zapret на
     * postrouting. Счётчик — чтобы по дампу было видно, что правило действительно брало
     * пакеты, а не только стояло. */
    int failopen = 0;
    for (size_t i = 0; i < g_out_n; i++)
        if (out_failopen_capable(&g_out[i])) failopen = 1;
    if (failopen)
        fprintf(f, "\n    set %s {\n        type mark\n    }\n"
                   "    chain prerouting_failopen {\n"
                   "        type filter hook prerouting priority mangle + 2; policy accept;\n"
                   "        meta mark and 0x%08x @%s meta mark set mark and 0x%08x counter "
                   "comment \"steer-failopen\"\n"
                   "    }\n",
                FAILOPEN_SET, STEER_MARK_MASK, FAILOPEN_SET, ~ZAPRET_SKIP_MARK);

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
        /* Скачанное каналом на сам телефон этой цепочкой не считается: получатель у него —
         * сокет телефона, и пакет идёт через input, а не через postrouting. */
        if (group_is_local(g)) continue;
        /* Две половины доменного набора в старой раскладке — два правила с одним
         * комментарием, как в prerouting_mark и по той же причине. */
        int halves = legacy_has_static(g) ? 2 : 1;
        for (int h = 0; h < halves; h++) {
            char sn[80];
            const char *set = g->name;
            if (halves == 2 && h == 0) { nft_static_set_name(sn, sizeof(sn), g->name); set = sn; }
            fprintf(f, "        ");
            emit_to(f, g);
            /* Зеркало сужения: без него счётчик скачанного считал бы и тот трафик, который
             * правило разметки не берёт, — то есть врал бы ровно на ту величину, ради которой
             * порты и заведены. Тот же довод, что у emit_to рядом. */
            emit_l4(f, g->l4, 1);
            if (g->files_n || g->domains) fprintf(f, "ip saddr @%s ", set);
            if (h == 0) emit_counter(f, g->name, 1);
            else fprintf(f, "counter ");
            fprintf(f, "comment \"steer-down:%s\"\n", g->name);
        }
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
        /* ВЫХОД УЗНАЁТСЯ ПО МЕТКЕ СОЕДИНЕНИЯ (ct mark), А НЕ ПАКЕТА. Обе ставятся одним
         * правилом в prerouting и до маршрутизации совпадают, но между маршрутизацией и этой
         * цепочкой лежит хук forward — и там метку пакета переписывают чужие. Tailscale на
         * каждом пакете с tailscale0 делает `meta mark set mark and 0xff00ffff xor 0x40000`:
         * биты 16-23 стираются, а наши восемь бит начинаются с двадцатого, то есть у первых
         * четырёх выходов метка до очереди не доезжала вовсе. Снаружи это выглядело как
         * «добавил tailscale0 в клиенты — с телефона обход не работает, из LAN работает»:
         * правило стоит, счётчик нулевой, обработчик жив. Метку соединения никто из соседей
         * не трогает — она наша по назначению, тот же довод, что у conntrack_evict. Цепочка
         * ответов (zapret_queue_in) по ct mark работала и прежде. */
        for (size_t i = 0; i < g_out_n; i++) {
            struct output *o = &g_out[i];
            if (o->kind != OUT_ZAPRET) continue;
            fprintf(f, "        ct mark and 0x%08x == 0x%08x ct original packets 1-%d "
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
        /* СТАРОЕ ЯДРО БЕЗ notrack — цепочки нет вовсе. На ядре телефона выражения нет
         * (nft_ct.c в 4.9 его не знает), и строка с ним отвергла бы всю транзакцию. Цена
         * названа при apply (report_legacy_gaps): порождённые обработчиком пакеты остаются на
         * учёте conntrack. Очередь при этом работает — это другие цепочки выше. */
        if (!NFT_LEGACY || (g_nftc & NFTC_NOTRACK))
        fprintf(f, "\n    chain zapret_predefrag {\n"
                   "        type filter hook output priority -401; policy accept;\n"
                   "        meta mark and 0x%08x != 0x00000000 jump zapret_predefrag_nfqws "
                   "comment \"steer:zapret-notrack\"\n"
                   "    }\n"
                   "    chain zapret_predefrag_nfqws {\n"
                   /* ПРАВИЛА ТРИ, А НЕ ЧЕТЫРЕ: правила zapret про «postnat traffic» здесь быть
                    * не должно, и это не упрощение, а починка отказа, из-за которого выход
                    * kind=zapret не работал ни у кого, кто выбрал стратегию.
                    *
                    * У zapret бит 0x20000000 (DESYNC_MARK_POSTNAT) значит «пакет взят из
                    * цепочки ПОСЛЕ трансляции адресов», и ставит его само правило очереди. У
                    * нас этот бит значит другое — «пакет нашего обработчика» (ZAPRET_MINE_BIT,
                    * см. spec.h): без него порождённый пакет вернулся бы в нашу же очередь.
                    * Правило мы взяли у zapret вместе с его смыслом бита, и получилось, что
                    * снимаются с учёта ВСЕ пакеты нашего nfqws.
                    *
                    * Цена этого — весь канал. Снятый учёт означает, что к пакету не
                    * применяется трансляция адресов; а nfqws строит свои копии из ИСХОДНОГО
                    * кортежа соединения, то есть с адресом клиента из локальной сети. Такие
                    * копии уходят в интернет с частным адресом источника, сервер их не
                    * узнаёт, и соединение виснет до таймаута.
                    *
                    * Снято на стенде в QEMU с настоящим клиентом за LAN. Рукопожатие уходит
                    * верно (10.77.0.2 -> сервер, сервер отвечает), а каждый пакет данных —
                    * «192.168.1.2 -> сервер», шесть копий подряд (--dpi-desync-repeats=6).
                    * Клиент получает таймаут, 5 проб из 5. Тот же nfqws и та же стратегия на
                    * ВЕСЬ роутер службой zapret работают: HTTP 200 за 20-113 мс, 4 из 4, —
                    * значит дело не в стенде и не в обходе, а в этом правиле. Проверено
                    * счётчиками, что до очереди пакет доезжает уже оттранслированным (38 из
                    * 38 с адресом WAN), то есть исправлять надо именно обратный путь.
                    *
                    * Остальные три правила остаются: фрагменты и данные без ACK для conntrack
                    * действительно мусор, и учтённые они стали бы INVALID. */
                   "        ip frag-off and 0x1fff != 0x0 notrack comment \"ipfrag\"\n"
                   /* `exthdr frag exists` на 4.9 НЕ отвергается, а ПОДМЕНЯЕТСЯ: флага «есть
                    * ли заголовок» там нет, ядро выбрасывает незнакомый атрибут и грузит
                    * сравнение поля frag nexthdr с единицей (снято на стенде tools/vm49).
                    * Замена `frag frag-off >= 0` значит то же самое на любом ядре: выражение
                    * exthdr без флага ищет заголовок фрагмента в цепочке заголовков и при
                    * его отсутствии правило не совпадает, а сравнение `>= 0` верно всегда.
                    * Проверено там же сырыми пакетами: совпадает и [ipv6][frag], и
                    * [ipv6][hop-by-hop][frag], и не совпадает с пакетом без фрагмента. */
                   "        %s notrack comment \"ipfrag\"\n"
                   "        tcp flags ! syn,rst,ack notrack comment \"datanoack\"\n"
                   "    }\n", ZAPRET_SKIP_MARK,
                NFT_LEGACY ? "frag frag-off >= 0" : "exthdr frag exists");
    }

    /* Всё, что ниже, — nat и то, что стоит рядом с ним. В старой раскладке оно устроено
     * иначе целиком (другие таблицы, одна цепочка nat), и смешивать две раскладки строками
     * через одну значило бы читать каждую строку дважды. Поэтому отдельная функция. */
    if (NFT_LEGACY) { generate_legacy_tail(f); return; }

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
        emit_tgws_rules(f);
        fprintf(f, "    }\n");
    }

    /* ПЕРЕНАПРАВЛЕНИЕ DNS СТОИТ ВСЕГДА, а не только при доменных каналах.
     *
     * Раньше оно появлялось и исчезало вместе с has_domains(), и это была переменная,
     * от которой зависели три вещи в разных местах: сам резолвер (needs-dnsd в
     * init-скрипте), это правило и ключ force_dns у https-dns-proxy в splify2. Две
     * последние обязаны меняться вместе — два перенаправления порта 53 в одной точке
     * nat prerouting выигрывает то, которое зарегистрировалось раньше, а проигравший
     * молчит: домены перестают маршрутизироваться, сайты при этом открываются.
     *
     * Пока «нужен ли резолвер» выводилось из спеки, синхронизировать их успевал метод
     * apply управляющего слоя. С гибридными списками (домен и подсеть в одном файле)
     * доменность стала бы зависеть от СОДЕРЖИМОГО файла — то есть могла бы перевернуться
     * ночным обновлением списков, которое зовёт `steer apply` напрямую, минуя метод и
     * его синхронизацию. Решение владельца: резолвер держим всегда, и тогда переворачивать
     * нечего — force_dns навсегда 0, а гонки не существует.
     *
     * Цена названа вслух: у роутера без единого доменного канала DNS всё равно идёт через
     * наш резолвер. Взамен уходит целый класс отказов «доменность изменилась, а что-то не
     * пересинхронизировалось».
     *
     * Форм у правила две, и выбирает между ними то же, что выбирает «кто» у каналов.
     * Заданы подсети — забираем IPv4 по адресу, а IPv6 по устройству, потому что
     * стабильного `ip6 saddr` у локального префикса нет. Подсетей нет — забираем по
     * устройству ОБА семейства одним правилом. */
    /* НО НЕ В МИНИ-СБОРКЕ, И ЭТО НЕ ЭКОНОМИЯ, А ИСПРАВЛЕНИЕ ОТКАЗА.
     *
     * Микропакет tgws поднимает ровно мост (см. его init-скрипт: procd получает только
     * экземпляры `tgws`), резолвера в нём не поднимает никто и спека у него адресная —
     * канал по prefixes_files, ни одного имени. А правило ставилось всё равно, потому что
     * решение «резолвер держим всегда» принималось для полного движка, где init поднимает
     * dnsd безусловно.
     *
     * Получалось так: пакет встаёт, подбор домена заканчивается через минуту, apply
     * ставит таблицу — и весь DNS локальной сети заворачивается на порт 5300, где никто
     * не слушает. У сети пропадает разрешение имён целиком, а Telegram продолжает
     * работать, потому что его клиент ходит к дата-центрам по вшитым адресам и DNS не
     * спрашивает. Снаружи это выглядит как «поставил прокси, через минуту помер
     * интернет, помогло только удаление и ребут» — ребут помогает потому, что правила
     * nft не сохраняются между загрузками. Ровно это сообщение и пришло от человека, и
     * воспроизведено в openwrt/rootfs:x86-64-24.10.6.
     *
     * Инвариант поэтому привязан к сборке, а не к спеке и не к настройке: правило
     * существует там и только там, где существует поднимающий резолвер. Настройкой этот
     * выбор делать нельзя — разошедшиеся правило и процесс это ровно тот отказ, который
     * здесь и починен.
     */
#ifndef STEER_TGWS
    fprintf(f, "    chain prerouting_dns {\n"
               "        type nat hook prerouting priority dstnat; policy accept;\n");
    for (size_t i = 0; i < g_from_default_n; i++)
        fprintf(f, "        ip saddr %s udp dport 53 counter redirect to :%d\n",
                g_from_default[i], DNS_PORT);
    fprintf(f, "        ");
    if (g_from_default_n) fprintf(f, "meta nfproto ipv6 ");
    emit_ifs(f, 0);
    fprintf(f, "udp dport 53 counter redirect to :%d\n", DNS_PORT);
    /* TCP/53 рядом с UDP/53. Резолвер слушает TCP на том же порту (dnsd.c, «DNS по TCP»), а без
     * заворота доменный канал слеп ко всему, что спрошено по TCP: к переспросу после усечённого
     * ответа (TC=1) и к клиентам, которые ходят по TCP сразу. Имя, спрошенное так, не получает
     * fakeip и не попадает в набор, и соединение уходит по настоящему адресу мимо выхода.
     * Замерено на живом роутере с steer 1.5.8: Windows-клиент за несколько минут задал 22
     * вопроса по TCP к IPv6-адресу роутера — все мимо резолвера, прямо в dnsmasq. */
    for (size_t i = 0; i < g_from_default_n; i++)
        fprintf(f, "        ip saddr %s tcp dport 53 counter redirect to :%d\n",
                g_from_default[i], DNS_PORT);
    fprintf(f, "        ");
    if (g_from_default_n) fprintf(f, "meta nfproto ipv6 ");
    emit_ifs(f, 0);
    fprintf(f, "tcp dport 53 counter redirect to :%d\n", DNS_PORT);
    fprintf(f, "    }\n");
#endif

    /* Остальное по-прежнему по факту доменных каналов: карта fakeip и цепочка dstnat
     * стоят per-packet, и держать их пустыми на роутере без доменов незачем. Это гейт
     * по СТОИМОСТИ, а не по смыслу, и переворачиваться он может свободно — ни один
     * чужой ключ от него не зависит. */
    if (has_domains()) {
        if (has_fakeip()) {
            fprintf(f, "\n    map fakeip {\n        type ipv4_addr : ipv4_addr;\n");
            emit_fakeip_elements(f);
            fprintf(f, "    }\n");
            /* Счётчик здесь обязателен, и это не единообразие с соседями. Правило
             * отвечает на единственный вопрос, который встаёт, когда «домены не
             * работают»: доехал ли поддельный адрес до роутера вообще. Без счётчика
             * «клиент не прислал» и «прислал, а мы не развернули» различаются только
             * tcpdump'ом на роутере, а первое — обычное дело у клиента из mesh-VPN
             * (Tailscale, ZeroTier): 198.18.0.0/15 уходит в туннель, только если роутер
             * объявил этот диапазон маршрутом, и по умолчанию он его не объявляет. Из
             * локальной сети вопрос не встаёт вовсе — там роутер и есть шлюз. */
            fprintf(f, "    chain prerouting_dnat {\n"
                       "        type nat hook prerouting priority dstnat; policy accept;\n"
                       "        ip daddr 198.18.0.0/15 counter dnat ip to ip daddr map @fakeip\n"
                       "    }\n");
        }
#ifdef STEER_ANDROID
        if (has_local_domains()) {
            fprintf(f, "    chain output_dns {\n"
                       "        type nat hook output priority dstnat; policy accept;\n");
            emit_local_dns(f, "dnat ip");
            fprintf(f, "    }\n");
        }
#endif
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
        if (g_traceroute_hops) emit_traceroute_raw(f);
        /* The resolver only sees what is steered to it. IPv6 as well as IPv4: the
         * router advertises itself as an IPv6 resolver by default and clients prefer
         * that server, so an IPv4-only redirect catches almost nothing — measured on a
         * real client, 15 of its DNS packets went over IPv6 against 20 over IPv4.
         * TCP/53 is redirected alongside UDP/53 (prerouting_dns above): the daemon
         * listens on TCP too (dnsd.c, «DNS по TCP»).
         */
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
        {
            char want[80];
            snprintf(want, sizeof(want), "table inet %s", nft_table());
            if (strstr(line, want)) in_steer = 1;
            else if (!strncmp(line, "table ", 6)) in_steer = 0;
        }
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

#ifndef STEER_ANDROID   /* на телефоне не зовётся — см. конец cmd_apply */
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
#endif

/* ЧУЖИЕ ПРАВИЛА НА БИТАХ 16-23 — предупреждение, а не отказ.
 *
 * Поле метки движка — биты 20-27 (STEER_MARK_MASK, контракт). Tailscale и pbr держат свою
 * метку маской 0x00ff0000, то есть битами 16-23, и на битах 20-23 два поля ПЕРЕСЕКАЮТСЯ —
 * подробно у STEER_MARK_MASK в spec.h. Раскладку не меняем: это контракт, и сдвиг поля
 * означал бы новые метки у всех выходов на всех роутерах. Зато говорим, когда соседство
 * действительно есть, — иначе его последствия выглядят как «канал иногда идёт мимо выхода»
 * без единой строки в журнале.
 *
 * Признак — число в выражении с меткой в ЧУЖОЙ таблице: 0x00ff0000 (маска поля 16-23) или
 * 0xff00ffff (она же, дополнением: «стереть биты 16-23»). Так их печатает nft и для
 * Tailscale (снято с роутера: `meta mark set mark and 0xff00ffff xor 0x40000`), и для
 * всякого, кто метит по той же схеме. Разбираются числа, а не строка: ведущие нули nft то
 * печатает, то нет.
 *
 * Не отказ, потому что соседство законно и чаще всего безвредно: Tailscale переписывает
 * метку в хуке forward, то есть ПОСЛЕ решения о маршруте, и ip rule выхода его не замечает;
 * единственный наш читатель метки после forward — очередь kind=zapret — узнаёт выход по
 * метке соединения. Отказ применить спеку на роутере с Tailscale снял бы маршрутизацию у
 * людей, у которых всё работает. Вредные случаи — чужое правило, которое метит ТОТ ЖЕ пакет
 * в prerouting после нас (стирает наши биты — пакет уходит по main, мимо выхода и мимо
 * запрета on_fail=drop), или до нас (мы стираем его биты 20-23 — его политика на этом
 * пакете перестаёт совпадать), — по дампу не отличить, поэтому о них говорится словами.
 *
 * Возвращает, о скольких таблицах сказано: стенд fwmatch проверяет признак на дампах. */
static int report_mark_overlap(void) {
    /* Поле целиком выше бита 23 (мини-сборка моста живёт в бите 28) — с масками 16-23 оно не
     * пересекается, и говорить не о чем. */
    if (STEER_MARK_LOBIT > 23) return 0;
    const char *pos = ruleset_dump();
    char line[2048], table[96] = "", said[8][96];
    int n_said = 0;
    while ((pos = dump_line(pos, line, sizeof(line))) != NULL) {
        const char *p = line;
        while (*p == ' ' || *p == '\t') p++;
        if (!strncmp(p, "table ", 6)) {
            snprintf(table, sizeof(table), "%s", p + 6);
            char *b = strchr(table, '{');
            if (b) *b = '\0';
            for (size_t k = strlen(table); k && table[k - 1] == ' '; k--) table[k - 1] = '\0';
            continue;
        }
        if (!*table || !strstr(p, "mark")) continue;
        /* Своя таблица — «семейство имя», имя вторым словом. */
        const char *tn = strchr(table, ' ');
        if (tn && !strcmp(tn + 1, nft_table())) continue;
        int hit = 0;
        for (const char *q = p; (q = strstr(q, "0x")) != NULL; q += 2) {
            unsigned long v = strtoul(q, NULL, 16);
            if (v == 0x00ff0000ul || v == 0xff00fffful) { hit = 1; break; }
        }
        if (!hit) continue;
        int dup = 0;
        for (int k = 0; k < n_said; k++) if (!strcmp(said[k], table)) dup = 1;
        if (dup || n_said >= 8) continue;
        snprintf(said[n_said++], sizeof(said[0]), "%s", table);
        /* Биты — из базы и ширины поля (STEER_MARK_LOBIT/HIBIT), а не строкой: у сборки под
         * Android поле 22-27, и пересекается оно с 16-23 на двух битах, а не на четырёх. */
        fprintf(stderr, LOG_W "таблица %s метит пакеты маской 0x00ff0000 (биты 16-23, так "
                        "работают Tailscale и pbr), а поле движка — биты %d-%d: на битах "
                        "%d-23 метки пересекаются. Если её правило метит тот же пакет в "
                        "prerouting после нас, трафик канала уйдёт мимо выхода; если до нас — "
                        "перестанет действовать её политика на этом пакете\n", table,
                STEER_MARK_LOBIT, STEER_MARK_HIBIT, STEER_MARK_LOBIT);
    }
    return n_said;
}

#ifndef STEER_ANDROID   /* на телефоне не зовётся — см. конец cmd_apply */
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
#endif

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
        /* Чужой диапазон — чужие правила и чужая таблица (см. registry_assign): снимать их
         * по такой записи значило бы опустошить таблицу другого экземпляра движка. */
        if (!mark || (mark & ~STEER_MARK_MASK)) continue;
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

/* ---- down: снять всё, что поставил движок ------------------------------------
 *
 * То же, что stop_service в files/etc/init.d/steer, но командой движка. На роутере снятие —
 * это десяток строк shell; у init Android shell нет (сервис — один исполняемый файл), а
 * выдать домену steerd /system/bin/sh значило бы разрешить ему любую команду. Командой
 * движка оно и точнее: маска метки здесь STEER_MARK_MASK той сборки, что правила ставила
 * (под STEER_ANDROID она другая, 0x0fc00000), а в shell её пришлось бы повторять литералом.
 *
 * Зачем снимать при выключении, если перезапуск нарочно правил не трогает. Перезапуск — это
 * мгновение, после которого демоны встают снова, и открыть трафик на это мгновение хуже, чем
 * подержать правила. Выключение — другое: резолвер погашен навсегда, а правило заворота DNS
 * на его порт осталось бы в ядре, и у всех, чей DNS заворачивался, имена перестали бы
 * разрешаться вовсе. То же с on_fail=drop: blackhole в таблице выхода пережил бы выключение
 * и держал трафик закрытым без всякой видимой причины.
 *
 * Все таблицы — в каждой раскладке: inet (обычное ядро), ip/ip6 (nat старого ядра, см.
 * nft_compat) и steer_obfs (правила обфускаторов). Какой таблицы нет — отказ nft молча
 * значит «нечего снимать». Спека не читается: снимать надо и то, что поставила прежняя
 * спека, а реестр в состоянии — это и есть список того, что стоит в ядре. */
static int cmd_down(void) {
    static const char *const tabs[][2] = {
        { "inet", NULL }, { "ip", NULL }, { "ip6", NULL }, { "inet", "steer_obfs" },
    };
    for (size_t i = 0; i < sizeof tabs / sizeof tabs[0]; i++) {
        const char *del[] = { "nft", "delete", "table", tabs[i][0],
                              tabs[i][1] ? tabs[i][1] : nft_table(), NULL };
        run(del);
    }
    registry_snapshot();
    for (size_t i = 0; i < g_oldreg_n; i++) {
        char table[16];
        snprintf(table, sizeof(table), "%d", g_oldreg[i].table);
        rule_drop(g_oldreg[i].mark, g_oldreg[i].table);
        const char *flush[] = { "ip", "route", "flush", "table", table, NULL };
        run(flush);
    }
    /* Правило и таблица пробы сторожа. Сторож снимает их сам при выходе, но init Android гасит
     * сервис SIGKILL (без gentle_kill — сразу, с ним — через 200 мс), и уборка при выходе может
     * не успеть. */
    probe_rule_cleanup();
#ifdef STEER_ANDROID
    android_masq_drop_all();
#endif
    /* Туннели kind=awg заводил движок — ему их и снимать; без этого интерфейс с ключами пира
     * пережил бы выключение и продолжал бы отвечать на рукопожатия. */
    awg_down_all();
    return 0;
}

/* Policy routing for interface outputs. Дубликаты правил не копятся: rule_ensure считает копии
 * в ядре и лишние снимает — но только ПОСЛЕ того, как верная стоит, а не «снять всё и
 * поставить заново» (см. table_bind в failover.c: в том промежутке трафик уходил напрямую). */
#ifdef STEER_ANDROID
/* ---- masquerade у выходов-интерфейсов: правилом iptables, а не nft ----------------------
 *
 * ЗАЧЕМ. На роутере адрес источника у пакетов в туннель подменяет firewall (зона выхода с
 * masq). На телефоне такого firewall нет: netd делает NAT только для раздачи на её восходящий
 * интерфейс. Пакет раздачи или приложения, уведённый меткой в туннель, уходил бы с адресом
 * Wi-Fi или сотовой сети — сервер туннеля такой пакет не примет.
 *
 * ПОЧЕМУ iptables. На ядре 4.9 каждая регистрация nat (цепочка nat nft, таблица nat iptables)
 * решает судьбу нового соединения сама: первая сработавшая, не найдя правила, ставит «пустую»
 * привязку, и следующие для этого соединения уже не вычисляются (nf_nat_ipv4_fn в
 * nf_nat_l3proto_ipv4.c). netd держит nat в iptables на srcnat (100). Цепочка nft после неё
 * не срабатывает никогда, а до неё — отнимает у netd раздачу целиком. Правило в той же таблице
 * nat iptables, первым в POSTROUTING, живёт с правилами netd в одном проходе.
 *
 * Только наш помеченный трафик и только на устройствах выхода. Правила узнаются по маске
 * поля метки в тексте `iptables -S` — чужих с нашей маской не бывает. Выходы vless и xsteer
 * здесь не нужны: их устройство обслуживает наш процесс, адреса он переводит сам. Выход
 * kind=awg — нужен, как interface: туннель в ядре несёт пакет с тем адресом источника, что
 * был, а сервер WireGuard примет только адрес из своих AllowedIPs, то есть адрес туннеля. */
static void android_masq_drop_all(void) {
    char mask[24];
    snprintf(mask, sizeof(mask), "/0x%x ", STEER_MARK_MASK);
    FILE *p = popen("iptables -w -t nat -S POSTROUTING 2>/dev/null", "r");
    if (!p) return;
    char line[512], lines[64][512];
    int n = 0;
    while (n < 64 && fgets(line, sizeof(line), p)) {
        if (strncmp(line, "-A POSTROUTING ", 15) || !strstr(line, mask) ||
            !strstr(line, "-j MASQUERADE")) continue;
        snprintf(lines[n++], sizeof(lines[0]), "%s", line + 15);
    }
    pclose(p);
    for (int i = 0; i < n; i++) {
        const char *argv[32] = { "iptables", "-w", "-t", "nat", "-D", "POSTROUTING" };
        int k = 6;
        for (char *t = strtok(lines[i], " \n"); t && k < 31; t = strtok(NULL, " \n"))
            argv[k++] = t;
        argv[k] = NULL;
        run(argv);
    }
}

/* Вернуть недостающие правила masquerade, не трогая стоящие. Зовёт сторож после каждого
 * прохода: netd при (пере)запуске перестраивает iptables и наши правила пропадают, а apply
 * после этого случится, только если его позовёт init (см. steerd.rc). */
static void android_masq_ensure(void) {
    for (size_t i = 0; i < g_out_n; i++) {
        const struct output *o = &g_out[i];
        if (o->kind != OUT_INTERFACE && o->kind != OUT_AWG) continue;
        char mk[32];
        snprintf(mk, sizeof(mk), "0x%x/0x%x", o->mark, STEER_MARK_MASK);
        for (size_t k = 0; k < o->devices_n; k++) {
            const char *chk[] = { "iptables", "-w", "-t", "nat", "-C", "POSTROUTING",
                                  "-o", o->devices[k], "-m", "mark", "--mark", mk,
                                  "-j", "MASQUERADE", NULL };
            if (run(chk) == 0) continue;
            const char *add[] = { "iptables", "-w", "-t", "nat", "-I", "POSTROUTING", "1",
                                  "-o", o->devices[k], "-m", "mark", "--mark", mk,
                                  "-j", "MASQUERADE", NULL };
            if (run(add) == 0)
                fprintf(stderr, "steer[info] failover: masquerade на %s возвращён\n",
                        o->devices[k]);
        }
    }
}

static void android_masq_sync(void) {
    android_masq_drop_all();
    for (size_t i = 0; i < g_out_n; i++) {
        const struct output *o = &g_out[i];
        if (o->kind != OUT_INTERFACE && o->kind != OUT_AWG) continue;
        char mk[32];
        snprintf(mk, sizeof(mk), "0x%x/0x%x", o->mark, STEER_MARK_MASK);
        for (size_t k = 0; k < o->devices_n; k++) {
            const char *add[] = { "iptables", "-w", "-t", "nat", "-I", "POSTROUTING", "1",
                                  "-o", o->devices[k], "-m", "mark", "--mark", mk,
                                  "-j", "MASQUERADE", NULL };
            if (run(add) != 0)
                fprintf(stderr, LOG_W "output %s: masquerade на %s не встал (iptables)\n",
                        o->name, o->devices[k]);
        }
    }
}
#endif

static void apply_routing(void) {
    for (size_t i = 0; i < g_out_n; i++) {
        if (!out_has_device(&g_out[i])) continue;
        char table[16];
        snprintf(table, sizeof(table), "%d", g_out[i].table);
        /* Маршрут — заменой, правило — не снимая стоящего (table_bind и rule_ensure в
         * failover.c). Прежде здесь были `rule_drop` + `rule_add` и `flush` + `add`, и на
         * каждом apply помеченный трафик выхода на миг оставался без правила и без маршрута,
         * то есть уходил напрямую, мимо туннеля, — подробно у table_bind. Маршрут первым: если
         * правила не было, появившееся должно найти в таблице устройство, а не пустоту. */
        int rc = table_bind(&g_out[i], g_out[i].device);
        rule_ensure(g_out[i].mark, g_out[i].table);
        if (rc != 0) {
            fprintf(stderr, LOG_W "output %s: cannot route via %s — is the device up?\n",
                    g_out[i].name, g_out[i].device);
            /* Пустая таблица — это не «нет маршрута», а «ищи дальше»: помеченный
             * пакет провалится в следующую таблицу и уйдёт напрямую, то есть ровно
             * туда, куда его не пускали. При on_fail=drop окно между apply и первым
             * тиком failover обязано быть закрыто, иначе защита работает не всегда,
             * а это хуже, чем не работает вовсе. */
            if (g_out[i].on_fail == FAIL_DROP) {
                table_bind(&g_out[i], NULL);
                fprintf(stderr, LOG_W "output %s: трафик остановлен до появления "
                                "рабочего устройства (on_fail=drop)\n", g_out[i].name);
            } else {
                /* direct/zapret: таблица пуста, пакет уйдёт напрямую — значит и через общий
                 * обход, как обычный (см. out_failopen_capable в spec.h). Таблица правил к
                 * этому мгновению уже загружена, набор в ней есть. Сброс — потому что замена не
                 * прошла и в таблице могло остаться прежнее устройство. */
                const char *flush[] = { "ip", "route", "flush", "table", table, NULL };
                run(flush);
                failopen_mark(&g_out[i], 1);
            }
        }
    }
}

/* Стоит ли в ядре таблица «<семейство> <наша таблица>». Один `nft list tables` на процесс:
 * спрашивают о двух семействах подряд, а перечень таблиц за это время не меняется. Не смогли
 * спросить — «нет»: лишний `delete` отверг бы весь набор правил, а пропущенный оставляет
 * только чужую теперь таблицу, о которой скажет diag. */
static int nft_table_exists(const char *fam) {
    static char list[4096];
    static int loaded;
    if (!loaded) {
        loaded = 1;
        FILE *p = popen("nft list tables 2>/dev/null", "r");
        if (p) {
            size_t n = fread(list, 1, sizeof(list) - 1, p);
            list[n] = '\0';
            pclose(p);
        }
    }
    char want[96];
    snprintf(want, sizeof(want), "table %s %s", fam, nft_table());
    size_t wn = strlen(want);
    for (const char *q = list; (q = strstr(q, want)) != NULL; q += wn)
        if ((q == list || q[-1] == '\n') && (q[wn] == '\n' || q[wn] == '\0')) return 1;
    return 0;
}

/* ЧЕГО НЕ БУДЕТ НА СТАРОМ ЯДРЕ — вслух, при каждом apply в старой раскладке.
 *
 * Раскладка для 4.9 собирает всё, что ядро умеет, а без чего-то приходится обходиться. Молча
 * выбросить правило значило бы, что человек узнает о нём по симптому, — поэтому каждое
 * выброшенное называется здесь вместе с последствием. Строки идут в stderr и в журнал, как
 * остальные предупреждения apply. */
static void report_legacy_gaps(void) {
    if (!NFT_LEGACY) return;
    fprintf(stderr, "steer[info] apply: ядро без nat в семействе inet — правила собраны для "
                    "nftables старого ядра: таблицы inet и ip%s\n",
            legacy_has_ip6() ? " и ip6" : "");
    if (has_zapret() && !(g_nftc & NFTC_NOTRACK))
        fprintf(stderr, LOG_W "ядро не знает notrack: порождённые обработчиком zapret пакеты "
                        "(подделки, куски разрезанного) остаются на учёте conntrack. Где "
                        "firewall отбрасывает ct state invalid, обход выходов kind=zapret "
                        "может не срабатывать\n");
    if (g_traceroute_hops && has_domains() && !(g_nftc & NFTC_NOTRACK))
        fprintf(stderr, LOG_W "ядро не знает notrack: traceroute_hops на нём не действует, "
                        "промежуточные узлы будут видны как прежде\n");
#ifndef STEER_TGWS
    if (!(g_nftc & NFTC_IP6NAT))
        fprintf(stderr, LOG_W "ядро не умеет nat для IPv6: запросы DNS клиентов по IPv6 идут "
                        "мимо резолвера движка, и доменные каналы видят только тех, кто "
                        "спрашивает по IPv4\n");
#endif
#ifdef STEER_ANDROID
    if (!(g_nftc & NFTC_IP6NAT) && has_local_domains())
        fprintf(stderr, LOG_W "ядро не умеет nat для IPv6: запросы DNS приложений телефона по "
                        "IPv6 идут мимо резолвера движка, и доменные каналы телефона их не "
                        "видят\n");
#endif
#ifndef STEER_ANDROID
    /* На Android таблица nat iptables есть всегда, но PREROUTING в ней у netd — пустая
     * oem_nat_pre, и предупреждать там не о чем. Почему это вообще важно — у
     * generate_legacy_tail. */
    FILE *t = fopen("/proc/net/ip_tables_names", "r");
    if (t) {
        char line[64];
        int nat = 0;
        while (fgets(line, sizeof(line), t)) if (!strncmp(line, "nat", 3)) nat = 1;
        fclose(t);
        if (nat)
            fprintf(stderr, LOG_W "на этом ядре работает и nat iptables: для соединений, "
                            "которые не забрал движок, его правила PREROUTING (пробросы "
                            "портов) не сработают — старое ядро не даёт двум таблицам nat "
                            "поделить один хук\n");
    }
#endif
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
    char tmp[256];
    steer_tmp_template(tmp, sizeof(tmp), "steer-qprobe");
    int fd = mkstemp(tmp);
    if (fd < 0) return 1;   /* не смогли проверить — не мешаем: решать будет сам nft */
    FILE *f = fdopen(fd, "w");
    if (!f) { close(fd); unlink(tmp); return 1; }
    /* Своё имя таблицы: `nft -c` ничего не создаёт, но столкнуться именем с чужой живой
     * таблицей всё равно нельзя — проверка тогда проверяла бы её содержимое. */
    fprintf(f, "table inet %s_qprobe {\n"
               "    chain c {\n"
               "        type filter hook output priority mangle + 10; policy accept;\n"
               "        meta mark and 0x%08x == 0x%08x queue num %d bypass\n"
               "    }\n}\n", nft_table(), STEER_MARK_MASK, STEER_MARK_BASE, ZAPRET_QUEUE_BASE);
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
    /* ДОМЕННЫЙ КАНАЛ В МИНИ-СБОРКЕ — ОТКАЗ, А НЕ ПРЕДУПРЕЖДЕНИЕ.
     *
     * Домены маршрутизируются через резолвер движка, а мини-сборка его не поднимает и
     * перенаправления DNS не ставит (см. генератор правил). Такая спека применилась бы и
     * не работала: имена не разрешаются нами, fake-адрес не появляется, канал стоит
     * пустым. Молчаливое применение здесь хуже отказа — искать причину пришлось бы на
     * роутере. */
#ifdef STEER_TGWS
    for (size_t i = 0; i < g_grp_n; i++)
        if (g_grp[i].domains)
            die("канал «%s» доменный, а эта сборка резолвера не поднимает: разрешать имена "
                "ей нечем. Переведите канал на адресный список или поставьте полный движок",
                g_grp[i].name);
#endif
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
    /* Раскладка набора правил — до генерации и до dry-run: интерфейс проверяет спеку именно
     * dry-run'ом, и печатать ему надо то, что реально встанет на этом ядре. */
    g_nftc = nft_compat();
    report_legacy_gaps();
    /* Снять накопленное ДО генерации: она вписывает эти значения в новые правила, иначе
     * каждый apply обнулял бы объёмы. Читаем и при --dry-run — так печатаемый текст остаётся
     * тем, что реально применится, а на машине без таблицы вывод не меняется вовсе. */
    counters_load();
    /* Ни одной группы — таблица всё равно ставится, с пустой цепочкой: так status
     * продолжает отвечать, а следующий apply не зависит от того, была ли таблица
     * раньше. */
    /* Файлы выходов kind=awg — проверяются и при --dry-run: им интерфейс проверяет спеку
     * перед записью, и ошибка в файле туннеля должна быть видна тогда же, а не после
     * применения. Предупреждением в stderr: набор правил от файла туннеля не зависит. */
    if (dry) { awg_check_all(); generate(stdout); return 0; }

    /* Отказываем ДО транзакции и НАЗЫВАЕМ причину: иначе человек получит отказ всей
     * маршрутизации с сообщением про несуществующий файл. Пакет назван прямо — его же
     * тянет за собой zapret, поэтому у тех, кто обходом уже пользуется, он стоит. */
    if (has_zapret() && !nfqueue_supported())
        die("в спеке есть выход kind=zapret, а ядро не принимает правило queue — "
            "нужен пакет kmod-nft-queue (его ставит и сам zapret). Правила НЕ применены: "
            "nft грузит набор целиком, и отказ на очереди снял бы заодно наборы, метки и "
            "перенаправление DNS", NULL);

    char tmp[256];
    steer_tmp_template(tmp, sizeof(tmp), "steer-ruleset");
    int fd = mkstemp(tmp);
    if (fd < 0) die("cannot create a temporary ruleset", NULL);
    FILE *f = fdopen(fd, "w");
    /* Крупный буфер на чисто дозаписывающий поток: musl по умолчанию даёт
     * BUFSIZ в 1 КБ, и набор на сотни тысяч элементов дробился на тысячи
     * мелких write. Статический — чтобы не зависеть от кучи в момент,
     * когда рядом nft уже строит своё дерево разбора. */
    static char genbuf[65536];
    setvbuf(f, genbuf, _IOFBF, sizeof(genbuf));
    /* ЗАМЕНА ТАБЛИЦЫ — ОДНОЙ ТРАНЗАКЦИЕЙ, и все три строки для этого нужны.
     *
     * Раньше здесь было два запуска nft: `nft delete table`, затем `nft -f` с новой таблицей,
     * хотя комментарий уже тогда обещал одну транзакцию. Между ними таблицы не было вовсе, а
     * на наборе в сотни тысяч элементов второй запуск на слабом роутере идёт секунды. Всё это
     * время DNS клиентов, который перенаправляет наша таблица, уходил в dnsmasq мимо
     * резолвера (имена доменных каналов разрешались настоящими адресами и шли напрямую), метки
     * не ставились, а запрет on_fail=drop держался только на маршрутной таблице. И если новый
     * набор nft отвергал, прежнего уже не было: один неудачный apply снимал маршрутизацию
     * целиком до следующего удачного.
     *
     * Теперь всё — в ОДНОМ файле, а `nft -f` применяет файл целиком или не применяет ничего:
     *   `table inet X`         — добавить таблицу, если её нет (без тела это «add», и на
     *                            существующей таблице он ничего не делает). Без этой строки
     *                            `delete` на самом первом apply отказал бы, а с ним — и
     *                            весь файл;
     *   `delete table inet X`  — снять прежнюю вместе с наборами и цепочками;
     *   `table inet X { … }`   — новая, из generate().
     * Снаружи видно либо прежнюю таблицу, либо новую, промежутка нет. Отказ nft оставляет
     * ПРЕЖНЮЮ таблицу стоять — то есть неудачный apply больше ничего не ломает.
     *
     * Цена одна, и её стоит знать: пока транзакция не закрыта, ядро держит и старые, и новые
     * наборы, то есть на время загрузки памяти под них нужно вдвое больше. Раньше старые
     * освобождались до загрузки новых. Проверено в `unshare -n` на nftables 1.0.9: файл такого
     * вида проходит и когда таблица есть, и когда её нет.
     *
     * В --dry-run эти две строки не печатаются: там выводится сам набор правил (его сверяют
     * стенды и интерфейс), а замена — дело применения. */
    fprintf(f, "table inet %s\ndelete table inet %s\n", nft_table(), nft_table());
    /* Таблицы ip и ip6 — тем же приёмом и в той же транзакции. Их создаёт только старая
     * раскладка (generate_legacy_tail), но УДАЛЯТЬ их обязана любая: ядро телефона обновится
     * до нового (Android 17 — ядра новее 5.2), apply выберет современную раскладку, и
     * оставшаяся от старой цепочка nat заворачивала бы DNS второй раз, а карта fakeip в ней
     * отставала бы от резолвера. И наоборот, выход раскладки из ip6 (ядро перестало
     * принимать nat в ip6) не должен оставлять прежнюю таблицу. Отсутствующую таблицу
     * удалять нельзя — `delete` отверг бы весь файл, — поэтому для таблицы вне раскладки
     * спрашиваем ядро, есть ли она (один `nft list tables` на apply). На роутере, где старой
     * раскладки не было никогда, файл остаётся прежним, байт в байт. */
    {
        static const char *const fams[2] = { "ip", "ip6" };
        int want[2] = { legacy_has_ip(), legacy_has_ip6() };
        for (int k = 0; k < 2; k++) {
            if (want[k])
                fprintf(f, "table %s %s\ndelete table %s %s\n",
                        fams[k], nft_table(), fams[k], nft_table());
            else if (nft_table_exists(fams[k]))
                fprintf(f, "delete table %s %s\n", fams[k], nft_table());
        }
    }
    generate(f);
    fclose(f);

    const char *load[] = { "nft", "-f", tmp, NULL };
    int rc = run(load);
    if (rc != 0) {
        fprintf(stderr, LOG_W "nft refused the ruleset, the previous one stays (kept: %s)\n",
                tmp);
        const char *check[] = { "nft", "-c", "-f", tmp, NULL };
        run(check);
        return 1;
    }
    unlink(tmp);
    /* Устройства выходов kind=awg — до привязки таблиц: apply_routing ставит маршрут в
     * устройство, и устройства к этому мгновению обязаны быть (см. src/kinds/awg.c). Отказ одного
     * туннеля не отменяет применённых правил: его таблица получит то же, что у любого выхода
     * без устройства (blackhole при on_fail=drop), а причина уже названа в журнале. */
    awg_apply_all();
    apply_routing();
#ifdef STEER_ANDROID
    android_masq_sync();
#endif
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
    /* Проверки чужого firewall — про fw4: зона выхода и masquerade в его наборе правил. На
     * телефоне fw4 нет, трафик раздачи транслирует netd через iptables, и по дампу nftables
     * эти проверки говорили бы «устройство не упомянуто в firewall» и «нет masquerade» на
     * каждом apply — ложные тревоги, после которых настоящим перестают верить. */
#ifndef STEER_ANDROID
    report_output_deps();
    report_traceroute_dep();
#endif
    report_mark_overlap();
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
                 "\"status_cache\",\"xslink\",\"xsteer_state\",\"spec_schema2\",\"awg\","
                 "\"via\"]",
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
        /* Через какой выход идёт туннель этого выхода (`via`, см. «вложенные выходы» в
         * spec.h). Поля нет, когда туннель идёт напрямую, — как в спеке. Живость цели здесь не
         * повторяется: она видна у самой цели в этом же ответе, а второй источник того же
         * ответа однажды разошёлся бы с первым. */
        if (g_out[i].via[0]) fprintf(out, ",\"via\":\"%s\"", g_out[i].via);
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
            /* Туннель kind=awg: рукопожатие, счётчики, эндпоинт — из ядра, см. awg_status_json. */
            if (g_out[i].kind == OUT_AWG) awg_status_json(out, &g_out[i]);
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
    snprintf(cmd, sizeof(cmd), "nft list set inet %s %.64s 2>/dev/null", nft_table(), name);
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
    char cmd[512];
    /* --terse: ищутся цепочки, элементы наборов не нужны — а их дамп на большом
     * наборе стоит дороже всех остальных проверок diag вместе взятых. */
    /* В старой раскладке nat живёт в таблице ip (generate_legacy_tail), и искать заворот DNS
     * только в inet значило бы объявить его пропавшим на исправном телефоне. */
    if (NFT_LEGACY)
        snprintf(cmd, sizeof(cmd),
                 "{ nft -t list table inet %s 2>/dev/null || "
                 "nft list table inet %s 2>/dev/null; "
                 "nft -t list table ip %s 2>/dev/null || "
                 "nft list table ip %s 2>/dev/null; } | grep -qF '%s'",
                 nft_table(), nft_table(), nft_table(), nft_table(), what);
    else
        snprintf(cmd, sizeof(cmd),
                 "{ nft -t list table inet %s 2>/dev/null || "
                 "nft list table inet %s 2>/dev/null; } | grep -qF '%s'",
                 nft_table(), nft_table(), what);
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

/* Пропускает ли мост кадры через ip-хуки netfilter: 1 — да, 0 — нет, -1 — не знаем.
 *
 * Файл существует ровно тогда, когда загружен модуль br_netfilter: sysctl-и регистрирует он,
 * а не сам мост. Поэтому «файла нет» — это полноценный ответ «мост через netfilter не ходит»,
 * а не отсутствие данных. Не знаем мы только одно: когда в файле лежит не 0 и не 1 — такого
 * не бывает, но приговор наугад хуже молчания, и различать эти случаи надо.
 *
 * Путь — швом, по той же причине, что g_state_dir у остальной части движка: загрузить модуль
 * в контейнере стенда нельзя, а приговор обязан проверяться так же, как все прочие. Имя
 * переменной STEER_BRIDGE_NF, читается один раз. */
#ifndef STEER_ANDROID   /* на телефоне не зовётся — см. проверку 3b в cmd_diag */
static int bridge_nf_on(void) {
    const char *path = getenv("STEER_BRIDGE_NF");
    if (!path || !*path) path = "/proc/sys/net/bridge/bridge-nf-call-iptables";
    FILE *f = fopen(path, "r");
    if (!f) return 0;                     /* модуля нет — значит и хождения нет */
    int c = fgetc(f);
    fclose(f);
    if (c == '0') return 0;
    if (c == '1') return 1;
    return -1;
}
#endif

static int cmd_diag(const char *spec) {
    load_spec(spec);
    registry_assign();
    build_groups();
    /* Приговор выносится тому устройству, которое несёт трафик, — тому же, о котором
     * рассказывает status и к которому привязал таблицу apply (outputs_adopt_active). */
    outputs_adopt_active();
    /* Раскладка — чтобы искать правила там, где их ставит apply (nft_has, наборы ниже). */
    g_nftc = nft_compat();
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
        /* Старая раскладка: префиксы доменной группы лежат во второй половине набора (<имя>_n,
         * см. generate). Адресов у канала — сумма обеих. */
        if (n >= 0 && legacy_may_have_static(g)) {
            char sn[80];
            nft_static_set_name(sn, sizeof(sn), g->name);
            long m = set_count(sn);
            if (m > 0) n += m;
        }
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

    /* 3b. br_netfilter: кадры, ходящие ВНУТРИ моста, проходят через ip-хуки netfilter.
     *
     *     ЧТО ИМЕННО ИЗ ЭТОГО СЛЕДУЕТ ДЛЯ НАС. Модуль br_netfilter вместе с
     *     `net.bridge.bridge-nf-call-iptables=1` отдаёт мостовые кадры в ip-хуки
     *     PREROUTING/FORWARD/POSTROUTING — то есть в те же, на которых висим мы. Значит наше
     *     перенаправление порта 53 начинает касаться запросов, которые из роутера не выходят
     *     вовсе: правило `… udp dport 53 counter redirect to :DNS_PORT` условия на
     *     ПОЛУЧАТЕЛЯ не имеет (и не должно — оно про клиентов), поэтому запрос клиента к
     *     DNS-серверу на той же LAN (Pi-hole, второй роутер, AdGuard на NAS) заворачивается
     *     к нам. Человек видит «Pi-hole перестал получать запросы» при исправном steer, и
     *     объяснить это нечем: в наборе правил всё верно, а в спеке про мост ничего нет.
     *
     *     ЧЕГО ЗДЕСЬ НЕ НАПИСАНО, ХОТЯ ПРОСИЛОСЬ. Цепочка разметки эти кадры тоже видит, и
     *     метка на них ложится — но в туннель они от этого НЕ уедут: мостовой кадр
     *     форвардится на L2, маршрутного поиска для него нет, а политика по fwmark (`ip
     *     rule`) спрашивается только при маршрутном поиске. Приговор поэтому говорит про
     *     перенаправление DNS, где следствие прямое, и не обещает того, чего проверить не
     *     удалось. Исключение — тот самый мостовой кадр, которому мы сами меняем получателя
     *     на локальный адрес: там br_netfilter маршрутный поиск делает, и это ровно
     *     перенаправление DNS, то есть уже названный случай.
     *
     *     МОДУЛЬ МЫ НЕ ВЫКЛЮЧАЕМ. Настройка чужая и общесистемная: её ставят docker и
     *     libvirt, у них на это свои причины, и снять её значило бы сломать соседа ради
     *     своего удобства. Наше дело — сказать.
     *
     *     warn, а не note, и разница с советом про DoH принципиальна: DoH — свойство мира,
     *     верное всегда, и warn на нём красил бы исправный роутер жёлтым навсегда. Здесь же
     *     переключаемая настройка ЭТОЙ системы с наблюдаемым следствием — то есть находка,
     *     которая объясняет будущую жалобу, и она обязана попасть в счётчик. */
#ifndef STEER_ANDROID
    /* На телефоне моста с br_netfilter нет (раздача интернета идёт без моста Linux), а
     * приговор «кадры внутри моста идут мимо наших правил» был бы ответом на вопрос, которого
     * там никто не задаёт. */
    {
        int brnf = bridge_nf_on();
        if (brnf == 1)
            diag("bridge_nf", "warn", "мост пропускает кадры через netfilter",
                 "загружен br_netfilter и net.bridge.bridge-nf-call-iptables=1: запросы DNS "
                 "между клиентами одной LAN тоже заворачиваются на наш резолвер — правило "
                 "порта 53 смотрит на клиента, а не на получателя, поэтому DNS-сервер внутри "
                 "сети (Pi-hole, второй роутер) перестаёт получать запросы. Движок эту "
                 "настройку не трогает, она общесистемная (её ставят docker и libvirt); если "
                 "она вам не нужна: sysctl -w net.bridge.bridge-nf-call-iptables=0");
        else if (brnf == 0)
            diag("bridge_nf", "ok", "кадры внутри моста идут мимо наших правил", "");
        /* brnf < 0 — в файле не 0 и не 1. Молчим: приговор наугад хуже молчания. */
    }
#endif

    /* 4. Резолвер и редирект. Доменные каналы держатся на обоих: без редиректа клиент
     *    спрашивает не нас, без процесса спрашивать некого. */
    if (has_domains()) {
        /* В старой раскладке у заворота нет своей цепочки — он правило общей цепочки nat
         * (generate_legacy_tail), и узнаётся по самому правилу. */
        char redir_rule[40];
        snprintf(redir_rule, sizeof(redir_rule), "redirect to :%d", DNS_PORT);
        int redir = nft_has(NFT_LEGACY ? redir_rule : "chain prerouting_dns");
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
/* Адрес или префикс IPv4 в диапазон [lo, hi]. 0 — не адрес. Диапазон «a-b» — тоже: так nft
 * печатает интервалы, не укладывающиеся в один префикс. */
static int ipv4_span(const char *t, uint32_t *lo, uint32_t *hi) {
    char buf[40];
    size_t n = strlen(t);
    if (!n || n >= sizeof(buf)) return 0;
    memcpy(buf, t, n + 1);
    char *dash = strchr(buf, '-');
    if (dash) {
        *dash = '\0';
        struct in_addr a, b;
        if (inet_pton(AF_INET, buf, &a) != 1 || inet_pton(AF_INET, dash + 1, &b) != 1) return 0;
        *lo = ntohl(a.s_addr);
        *hi = ntohl(b.s_addr);
        return *lo <= *hi;
    }
    char *sl = strchr(buf, '/');
    int len = 32;
    if (sl) {
        *sl = '\0';
        char *e;
        long v = strtol(sl + 1, &e, 10);
        if (*e || v < 0 || v > 32) return 0;
        len = (int)v;
    }
    struct in_addr a;
    if (inet_pton(AF_INET, buf, &a) != 1) return 0;
    uint32_t m = len ? 0xffffffffu << (32 - len) : 0;
    *lo = ntohl(a.s_addr) & m;
    *hi = *lo | ~m;
    return 1;
}

/* Лежит ли адрес (или весь префикс) в наборе — по его дампу, без `nft get element`.
 *
 * Нужна ядру 4.9: NFT_MSG_GETSETELEM там отвечает только на дамп, а на запрос одного элемента
 * — -EOPNOTSUPP (одиночный get появился в 4.15). Без этой ветки explain на телефоне отвечал бы
 * «ни один канал не забирает» про каждый адрес, в том числе про те, что прямо в списке.
 *
 * Разбирается не формат nft целиком, а слова из цифр, точек, дробей и дефисов после
 * «elements = {»: адрес, префикс, диапазон. Прочее (timeout 1h, expires 59m) адресом не
 * читается и пропускается само. */
static int set_scan(const char *set, const char *addr) {
    for (const char *q = set; *q; q++)
        if (!((*q >= 'a' && *q <= 'z') || (*q >= 'A' && *q <= 'Z') ||
              (*q >= '0' && *q <= '9') || *q == '_' || *q == '-'))
            return 0;
    uint32_t qlo, qhi;
    if (!ipv4_span(addr, &qlo, &qhi)) return 0;
    char cmd[256];
    snprintf(cmd, sizeof(cmd), "nft list set inet %s %.64s 2>/dev/null", nft_table(), set);
    FILE *p = popen(cmd, "r");
    if (!p) return 0;
    int in = 0, hit = 0, c;
    char tok[40];
    size_t tn = 0;
    const char *key = "elements = {";
    size_t kpos = 0;
    while (!hit && (c = fgetc(p)) != EOF) {
        if (!in) {
            kpos = (c == key[kpos]) ? kpos + 1 : (c == key[0] ? 1 : 0);
            if (!key[kpos]) in = 1;
            continue;
        }
        if ((c >= '0' && c <= '9') || c == '.' || c == '/' || c == '-') {
            if (tn + 1 < sizeof(tok)) tok[tn++] = (char)c;
            continue;
        }
        if (tn) {
            tok[tn] = '\0';
            tn = 0;
            uint32_t lo, hi;
            if (ipv4_span(tok, &lo, &hi) && lo <= qlo && qhi <= hi) hit = 1;
        }
        if (c == '}') in = 0;
    }
    pclose(p);
    return hit;
}

/* Есть ли адрес в наборе: одиночным `nft get element`, а на старом ядре, где его нет, —
 * разбором дампа (set_scan). На современном ядре путь прежний, один запуск nft. */
static int set_lookup(const char *set, const char *elem, const char *addr) {
    const char *q[] = { "nft", "get", "element", "inet", nft_table(), set, elem, NULL };
    if (run(q) == 0) return 1;
    return NFT_LEGACY && set_scan(set, addr);
}

static int cmd_explain(const char *spec, const char *what) {
    load_spec(spec);
    registry_assign();
    build_groups();
    g_nftc = nft_compat();

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
            hit = set_lookup(setname, elem, addr);
            /* Старая раскладка: у доменной группы вторая половина набора, с префиксами. */
            if (!hit && legacy_may_have_static(&g_grp[i])) {
                nft_static_set_name(setname, sizeof(setname), g_grp[i].name);
                hit = set_lookup(setname, elem, addr);
            }
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
        /* Канал бывает СУЖЕН по протоколу и портам, а спрошен был адрес. Адрес в наборе
         * лежит — но «идёт туда» верно не для всего его трафика, и промолчать значило бы
         * ответить правдой наполовину: человек, выясняющий, почему TCP к 104.16.0.1 идёт
         * напрямую, получил бы подтверждение, что канал его забирает. Отдельной строкой,
         * чтобы первая осталась той же, что была, — её читают и глазами, и разбором. */
        if (!l4match_empty(g_grp[i].l4)) {
            /* С запасом на предел MAX_PORTS: шестнадцать диапазонов вида «50000-65535» с
             * разделителями — это 217 байт, и обрезанное пояснение было бы хуже полного. */
            char d[256];
            l4_describe(g_grp[i].l4, d, sizeof(d));
            printf("      канал сужен: только %s — остальной трафик к этому адресу "
                   "идёт мимо канала\n", d);
        }
        return 0;
    }
    printf("%s -> no channel matches -> direct (steer does not touch it)\n", addr);
    return 0;
}

/* ---- supervise: помощники выходов одним сервисом -------------------------------------
 *
 * На роутере init-скрипт поднимает по экземпляру procd на каждый выход, которому нужен свой
 * процесс (vless, xsteer, obfs, tgws), и procd перезапускает упавший через пять секунд. У init
 * Android так нельзя: сервисы объявлены в rc статически, а состав выходов известен только из
 * спеки. Поэтому один сервис — этот — поднимает их сам и держит.
 *
 * СОСТАВ считается в ДОЧЕРНЕМ процессе и приезжает строками через трубу: спеку загружают в
 * глобальные массивы, и второй load_spec в том же процессе склеил бы выходы двух чтений (тот
 * же довод, что у failover_loop). Спека не разобралась — состав остаётся прежним, а не пустым.
 *
 * ПЕРЕЗАПУСК — как у procd: через пять секунд. Но помощник, падающий сразу (сервер туннеля
 * недоступен, в спеке ошибка), перезапускался бы каждые пять секунд всю ночь, а на телефоне
 * это батарея. Поэтому пауза удваивается, пока помощник живёт меньше минуты, до пяти минут, и
 * сбрасывается, когда он проработал дольше. Ждёт супервизор в sigtimedwait: таймер монотонный,
 * во сне устройства стоит и не будит его.
 *
 * SIGHUP — сверить состав со спекой: ушедшим выходам — SIGTERM, новым — запуск, остальным —
 * ничего, если не изменились их параметры (см. sup_sig): у изменившихся помощник гасится и
 * поднимается сразу, без пятисекундной паузы. SIGTERM — погасить всех и выйти (init шлёт его
 * группе, это на случай kill). SIGHUP шлёт управляющий сокет после каждого удачного apply
 * (src/daemon/ctl.c, reload).
 *
 * zapret здесь нет: его обработчик — отдельная программа (steer-nfqws), а в сборке под
 * Android zapret нет вовсе. В базовой сборке нет и vless, xsteer и tgws — их команды есть только
 * в расширенной, и запускать их значило бы перезапускать отказ по кругу. */
#define SUP_MAX 32
struct sup_helper {
    char cmd[8];
    char name[32];
    pid_t pid;
    long next_ms;       /* когда можно запускать (0 — сразу) */
    long started_ms;
    long delay_ms;      /* пауза следующего перезапуска */
    int gone;           /* выход убран из спеки: не перезапускать */
    unsigned long long sig;   /* подпись параметров, которые помощник читает при старте */
    int restart;        /* погашен ради новых параметров: поднять сразу, без паузы */
};

/* ПОДПИСЬ ПАРАМЕТРОВ ПОМОЩНИКА — то, что он читает из спеки ОДИН РАЗ, при старте.
 *
 * Состав («команда выход») SIGHUP сверял и раньше, а смену параметров оставленного выхода — нет:
 * человек выбирал другой узел подписки или другой сервер обфускации, apply проходил, а помощник
 * продолжал работать со старым до своего перезапуска, то есть до перезагрузки. Тот же открытый
 * пункт закрывает на роутере сам splify2 отпечатками vless_fingerprint и obfs_fingerprint
 * (rpcd/m-spec.sh); здесь поля те же, и по тем же доводам в подпись входит ТОЛЬКО то, что
 * помощник действительно читает при старте. Правка устройства, on_fail или каналов помощника
 * не касается, а перезапуск рвёт туннель и меняет выходной адрес — трогать его из-за неё нельзя.
 *
 * Поля по видам: vless — файл подписки и выбор узлов; xsteer — файл конфигурации и режим
 * потока; tgws — домен точек; obfs — сервер и локальный адрес. Содержимое файлов (подписка
 * обновилась) подписью не ловится, как и на роутере: это отдельный повод со своим путём. */
static void sup_fnv(unsigned long long *h, const void *p, size_t n) {
    const unsigned char *b = p;
    for (size_t i = 0; i < n; i++) { *h ^= b[i]; *h *= 1099511628211ULL; }
    *h ^= 0xff; *h *= 1099511628211ULL;   /* граница поля: «ab»+«c» не равно «a»+«bc» */
}
static unsigned long long sup_sig(const char *cmd, const struct output *o) {
    unsigned long long h = 14695981039346656037ULL;
    if (!strcmp(cmd, "vless")) {
        sup_fnv(&h, o->sub_file, strlen(o->sub_file));
        for (size_t i = 0; i < o->nodes_n; i++) sup_fnv(&h, &o->nodes[i], sizeof(o->nodes[i]));
    } else if (!strcmp(cmd, "xsteer")) {
        sup_fnv(&h, o->xs_conf, strlen(o->xs_conf));
        sup_fnv(&h, &o->xs_stream, sizeof(o->xs_stream));
        sup_fnv(&h, &o->xs_stream_port, sizeof(o->xs_stream_port));
    } else if (!strcmp(cmd, "tgws")) {
        sup_fnv(&h, o->tg_domain, strlen(o->tg_domain));
    } else if (!strcmp(cmd, "obfs")) {
        sup_fnv(&h, o->obfs.server, strlen(o->obfs.server));
        sup_fnv(&h, &o->obfs.server_port, sizeof(o->obfs.server_port));
        sup_fnv(&h, o->obfs.listen, strlen(o->obfs.listen));
        sup_fnv(&h, &o->obfs.listen_port, sizeof(o->obfs.listen_port));
    }
    /* Цель `via` помощник тоже читает при старте: метку сокета наверх он берёт один раз
     * (out_underlay_mark), и смена цели без перезапуска оставила бы туннель в прежнем выходе.
     * Только когда поле задано — подпись выхода без via остаётся прежней, и обновление движка
     * не перезапускает ни одного помощника.
     *
     * И сама МЕТКА цели, а не только её имя. Цель могли убрать из спеки и вернуть под тем же
     * именем — реестр выдаст ей другое место, то есть другую метку и таблицу, — а помощник со
     * старой меткой продолжал бы метить сокет значением, которое теперь ведёт в чужую таблицу
     * или никуда (то есть напрямую, мимо цели), до своего перезапуска. С меткой в подписи
     * reload после такого apply перезапускает его сразу. Метку считает out_underlay_mark — ровно
     * то значение, что помощник поставит на сокет (с битом туннеля на телефоне). */
    if (o->via[0]) {
        sup_fnv(&h, o->via, strlen(o->via));
        uint32_t um = out_underlay_mark(o);
        sup_fnv(&h, &um, sizeof(um));
    }
    return h;
}

static long sup_now_ms(void) {
    struct timespec t;
    clock_gettime(CLOCK_MONOTONIC, &t);
    return (long)t.tv_sec * 1000L + t.tv_nsec / 1000000L;
}

/* Состав помощников по спеке — строками «команда имя подпись». -1 — спека не разобралась. */
static int sup_list(const char *spec, struct sup_helper *out, size_t *n) {
    int pfd[2];
    if (pipe(pfd) != 0) return -1;
    pid_t pid = fork();
    if (pid < 0) { close(pfd[0]); close(pfd[1]); return -1; }
    if (pid == 0) {
        close(pfd[0]);
        FILE *w = fdopen(pfd[1], "w");
        if (!w) _exit(1);
        load_spec(spec);
        /* Метки выходов — из реестра: без них out_underlay_mark в подписи (sup_sig) вернул бы
         * «мимо каналов» при любой цели, и смена метки цели не была бы видна. Только при via —
         * у спеки без него реестр здесь не нужен, и супервизор его не трогает (registry_assign
         * пишет файл, лишь когда тот расходится с назначением, — как у помощников при старте). */
        for (size_t i = 0; i < g_out_n; i++)
            if (g_out[i].via[0]) { registry_assign(); break; }
        /* В порядке зависимостей via: цель поднимается раньше того, чей туннель через неё
         * идёт, — иначе первый подъём внутреннего перебирал бы узлы через ещё не созданное
         * устройство и уходил в паузу перезапуска. Гарантии готовности это не даёт (цель
         * поднимается секунды), но у спеки без via порядок прежний, спековый. */
        for (int depth = 0; depth <= MAX_VIA_DEPTH; depth++) {
            for (size_t i = 0; i < g_out_n; i++) {
                const struct output *o = &g_out[i];
                if (out_via_depth(o) != depth) continue;
#if defined(STEER_EXTENDED)
                if (o->kind == OUT_VLESS)
                    fprintf(w, "vless %s %llx\n", o->name, sup_sig("vless", o));
                if (o->kind == OUT_XSTEER)
                    fprintf(w, "xsteer %s %llx\n", o->name, sup_sig("xsteer", o));
                if (o->kind == OUT_TGWS)
                    fprintf(w, "tgws %s %llx\n", o->name, sup_sig("tgws", o));
#endif
                if (o->obfs.on)
                    fprintf(w, "obfs %s %llx\n", o->name, sup_sig("obfs", o));
            }
        }
        fclose(w);
        _exit(0);
    }
    close(pfd[1]);
    FILE *r = fdopen(pfd[0], "r");
    size_t k = 0;
    char line[128];
    while (r && fgets(line, sizeof(line), r) && k < SUP_MAX) {
        char c[8], nm[32];
        unsigned long long sg = 0;
        if (sscanf(line, "%7s %31s %llx", c, nm, &sg) != 3) continue;
        memset(&out[k], 0, sizeof(out[k]));
        snprintf(out[k].cmd, sizeof(out[k].cmd), "%s", c);
        snprintf(out[k].name, sizeof(out[k].name), "%s", nm);
        out[k].sig = sg;
        out[k].delay_ms = 5000;
        k++;
    }
    if (r) fclose(r); else close(pfd[0]);
    int st = 0;
    while (waitpid(pid, &st, 0) < 0 && errno == EINTR) {}
    if (!WIFEXITED(st) || WEXITSTATUS(st) != 0) return -1;
    *n = k;
    return 0;
}

static void sup_start(struct sup_helper *h, const char *exe, const char *spec,
                      const sigset_t *blocked) {
    pid_t pid = fork();
    if (pid < 0) { h->next_ms = sup_now_ms() + h->delay_ms; return; }
    if (pid == 0) {
        sigprocmask(SIG_UNBLOCK, blocked, NULL);
        /* Каталог состояния — тот же, что у супервизора, если его задали: помощник читает оттуда
         * реестр меток (метку цели via), и разойдись каталоги — подпись в супервизоре считалась бы
         * по одной метке, а сокет помощника ставился бы по другой. */
        const char *argv[] = { exe, h->cmd, h->name, "--spec", spec, NULL, NULL, NULL };
        if (strcmp(g_state_dir, STEER_STATE_DIR) != 0) {
            argv[5] = "--state-dir";
            argv[6] = g_state_dir;
        }
        execv(exe, (char *const *)argv);
        _exit(127);
    }
    h->pid = pid;
    h->started_ms = sup_now_ms();
    fprintf(stderr, "steer[info] supervise: %s %s запущен (pid %d)\n", h->cmd, h->name, (int)pid);
}

static int cmd_supervise(const char *spec) {
    char exe[512];
    /* Шов стенда: STEER_SUPERVISE_EXE подставляет вместо движка свою программу-помощника
     * (tests/supervisematch.sh), которая только записывает, с чем её позвали. */
    const char *seam = getenv("STEER_SUPERVISE_EXE");
    if (seam && *seam) snprintf(exe, sizeof(exe), "%s", seam);
    else {
        ssize_t el = readlink("/proc/self/exe", exe, sizeof(exe) - 1);
        if (el <= 0) die("supervise: не найти свой исполняемый файл (%s)", strerror(errno));
        exe[el] = '\0';
    }
    if (!spec) spec = STEER_ETC_DIR "/spec.json";

    sigset_t set;
    sigemptyset(&set);
    sigaddset(&set, SIGCHLD); sigaddset(&set, SIGHUP);
    sigaddset(&set, SIGTERM); sigaddset(&set, SIGINT);
    sigprocmask(SIG_BLOCK, &set, NULL);

    static struct sup_helper h[SUP_MAX];
    size_t n = 0;
    if (sup_list(spec, h, &n) != 0)
        die("supervise: спека %s не разобралась — поднимать нечего", spec);
    if (!n) fprintf(stderr, "steer[info] supervise: выходов со своим процессом в спеке нет\n");

    for (;;) {
        long now = sup_now_ms();
        long wait = -1;
        for (size_t i = 0; i < n; i++) {
            if (h[i].pid || h[i].gone) continue;
            if (h[i].next_ms <= now) sup_start(&h[i], exe, spec, &set);
            if (!h[i].pid && (wait < 0 || h[i].next_ms - now < wait))
                wait = h[i].next_ms - now > 0 ? h[i].next_ms - now : 0;
        }
        siginfo_t si;
        int sig;
        if (wait < 0) sig = sigwaitinfo(&set, &si);
        else {
            struct timespec ts = { wait / 1000, (wait % 1000) * 1000000L };
            sig = sigtimedwait(&set, &si, &ts);
        }
        if (sig < 0) continue;                         /* таймаут или EINTR */
        if (sig == SIGCHLD) {
            int st;
            pid_t p;
            while ((p = waitpid(-1, &st, WNOHANG)) > 0) {
                for (size_t i = 0; i < n; i++) {
                    if (h[i].pid != p) continue;
                    h[i].pid = 0;
                    /* Погашен нами ради новых параметров — поднять сразу: это не падение,
                     * и ни пауза, ни её рост к нему не относятся. */
                    if (h[i].restart) {
                        h[i].restart = 0;
                        h[i].delay_ms = 5000;
                        h[i].next_ms = 0;
                        if (!h[i].gone)
                            fprintf(stderr, "steer[info] supervise: %s %s — параметры выхода "
                                            "изменились, поднимаю заново\n", h[i].cmd, h[i].name);
                        continue;
                    }
                    /* Проработал дольше минуты — пауза снова пять секунд. Эта пауза и
                     * ждётся сейчас, а удваивается следующая: первый перезапуск упавшего
                     * всегда через пять секунд, как у procd. */
                    long lived = sup_now_ms() - h[i].started_ms;
                    if (lived >= 60000) h[i].delay_ms = 5000;
                    h[i].next_ms = sup_now_ms() + h[i].delay_ms;
                    if (!h[i].gone)
                        fprintf(stderr, "steer[warn] supervise: %s %s вышел (%s %d) — перезапуск "
                                        "через %ld с\n", h[i].cmd, h[i].name,
                                WIFEXITED(st) ? "код" : "сигнал",
                                WIFEXITED(st) ? WEXITSTATUS(st) : WTERMSIG(st),
                                h[i].delay_ms / 1000);
                    if (lived < 60000 && h[i].delay_ms < 300000)
                        h[i].delay_ms = h[i].delay_ms * 2 > 300000 ? 300000 : h[i].delay_ms * 2;
                }
            }
            /* Убранные из спеки и уже погасшие — вычистить из таблицы. */
            size_t w = 0;
            for (size_t i = 0; i < n; i++)
                if (!(h[i].gone && !h[i].pid)) h[w++] = h[i];
            n = w;
        } else if (sig == SIGHUP) {
            static struct sup_helper fresh[SUP_MAX];
            size_t fn = 0;
            if (sup_list(spec, fresh, &fn) != 0) {
                fprintf(stderr, "steer[warn] supervise: спека не разобралась — состав прежний\n");
                continue;
            }
            for (size_t i = 0; i < n; i++) {
                int keep = 0;
                for (size_t k = 0; k < fn; k++)
                    if (!strcmp(h[i].cmd, fresh[k].cmd) && !strcmp(h[i].name, fresh[k].name))
                        keep = 1;
                if (!keep && !h[i].gone) {
                    h[i].gone = 1;
                    if (h[i].pid) kill(h[i].pid, SIGTERM);
                }
            }
            /* Оставленные выходы с новыми параметрами: запомнить подпись и перезапустить
             * живого помощника. Не запущенный (ждёт паузы после падения) поднимется уже с
             * новыми — его достаточно запомнить. */
            for (size_t i = 0; i < n; i++) {
                if (h[i].gone) continue;
                for (size_t k = 0; k < fn; k++) {
                    if (strcmp(h[i].cmd, fresh[k].cmd) || strcmp(h[i].name, fresh[k].name) ||
                        h[i].sig == fresh[k].sig)
                        continue;
                    h[i].sig = fresh[k].sig;
                    if (h[i].pid && !h[i].restart) {
                        h[i].restart = 1;
                        kill(h[i].pid, SIGTERM);
                    }
                }
            }
            for (size_t k = 0; k < fn && n < SUP_MAX; k++) {
                int have = 0;
                for (size_t i = 0; i < n; i++) {
                    if (strcmp(h[i].cmd, fresh[k].cmd) || strcmp(h[i].name, fresh[k].name))
                        continue;
                    /* Выход вернули в спеку, пока его прежний помощник ещё гаснет: не второй
                     * экземпляр рядом, а тот же слот — перезапустится, когда прежний выйдет. */
                    h[i].gone = 0;
                    h[i].sig = fresh[k].sig;
                    have = 1;
                }
                if (!have) h[n++] = fresh[k];
            }
            /* Спеку исправили — упавшему незачем досиживать растущую паузу до пяти минут. */
            for (size_t i = 0; i < n; i++)
                if (!h[i].pid) { h[i].delay_ms = 5000; h[i].next_ms = 0; }
            size_t w = 0;
            for (size_t i = 0; i < n; i++)
                if (!(h[i].gone && !h[i].pid)) h[w++] = h[i];
            n = w;
        } else {                                       /* SIGTERM, SIGINT */
            for (size_t i = 0; i < n; i++) if (h[i].pid) kill(h[i].pid, SIGTERM);
            for (int t = 0; t < 31; t++) {
                /* Три секунды на уборку, дальше — SIGKILL: супервизор не выходит, оставив
                 * помощника жить без присмотра. */
                if (t == 30)
                    for (size_t i = 0; i < n; i++) if (h[i].pid) kill(h[i].pid, SIGKILL);
                int left = 0;
                for (size_t i = 0; i < n; i++) {
                    if (!h[i].pid) continue;
                    if (waitpid(h[i].pid, NULL, WNOHANG) == h[i].pid) h[i].pid = 0;
                    else left = 1;
                }
                if (!left) break;
                struct timespec ts = { 0, 100000000L };
                nanosleep(&ts, NULL);
            }
            return 0;
        }
    }
}

/* Сторож по кругу: `steer failover --loop СЕК`.
 *
 * На роутере круг крутит procd строкой `while :; do steer failover; sleep 60; done`. У init
 * Android такой строки нет: сервис — это один исполняемый файл, и запускать его через
 * /system/bin/sh значило бы выдать домену steerd право исполнять shell — то есть любую
 * команду, которую удастся подсунуть в спеку. Поэтому круг здесь, в движке.
 *
 * КАЖДЫЙ ПРОХОД — ОТДЕЛЬНЫЙ ПРОЦЕСС (fork). cmd_failover писан под «один проход и выход»:
 * спека грузится в глобальные массивы один раз, и повторный load_spec в том же процессе
 * склеил бы выходы двух чтений. Дочерний процесс получает чистую память и выходит через
 * exit, так что его atexit (снятие probe-rule) срабатывает, как и при запуске из shell; die()
 * в нём — это конец одного прохода, а не сторожа: следующий проход перечитает спеку, и
 * исправленная спека подхватится без перезапуска сервиса — ровно как в круге procd.
 *
 * СОН НА CLOCK_MONOTONIC — требование батареи. Этот таймер во сне устройства стоит и не
 * будит его (будят только *_ALARM и удерживаемый wakelock, которых здесь нет): пока телефон
 * спит, сторож молчит, а проснувшись, досыпает остаток периода.
 *
 * ПО СОБЫТИЯМ, А НЕ ТОЛЬКО ПО ПЕРИОДУ: смена интерфейса или адреса (сеть сменилась, TUN выхода
 * поднялся или упал) — внеочередной проход через пять секунд после события, см.
 * failover_events_open. Период остаётся для того, чего событием не увидеть: туннель поднят,
 * а трафик через него не идёт.
 *
 * init гасит сервис сигналом всей группе процессов, поэтому дочерний проход получает свой
 * SIGTERM и убирает за собой так же, как от kill на роутере. */
/* Сокет событий ядра для сторожа: смена состояния интерфейса и его адресов. -1 — не
 * открылся, и сторож живёт одним периодом, как раньше.
 *
 * ИНТЕРФЕЙСЫ И АДРЕСА, НО НЕ МАРШРУТЫ. Маршруты в таблицах выходов меняет сам сторож (и apply)
 * — подписка на них будила бы его собственными действиями по кругу. А то, ради чего события и
 * нужны, видно именно здесь: сменилась сеть (у Wi-Fi или сотовой появился или пропал адрес),
 * поднялся TUN выхода, который создал помощник, упал интерфейс туннеля. */
static int failover_events_open(void) {
    int fd = socket(AF_NETLINK, SOCK_RAW | SOCK_CLOEXEC | SOCK_NONBLOCK, NETLINK_ROUTE);
    if (fd < 0) return -1;
    struct sockaddr_nl a;
    memset(&a, 0, sizeof(a));
    a.nl_family = AF_NETLINK;
    a.nl_groups = RTMGRP_LINK | RTMGRP_IPV4_IFADDR | RTMGRP_IPV6_IFADDR;
    if (bind(fd, (struct sockaddr *)&a, sizeof(a)) != 0) { close(fd); return -1; }
    return fd;
}

/* Дочитать всё, что накопилось. 1 — было хоть одно событие. */
static int failover_events_drain(int fd) {
    char buf[8192];
    int any = 0;
    ssize_t r;
    while ((r = recv(fd, buf, sizeof(buf), 0)) > 0 || (r < 0 && errno == ENOBUFS))
        any = 1;   /* ENOBUFS — события потеряны переполнением: это тоже «что-то сменилось» */
    return any;
}

static int failover_loop(const char *spec, int verbose, int period) {
    int ev = failover_events_open();
    for (;;) {
        /* ПАМЯТЬ МЕЖДУ ПРОХОДАМИ — у родителя, а не в файлах каталога состояния: на телефоне это
         * /data, флеш, и запись на каждом проходе (раз в минуту и по каждому событию сети) шла бы
         * круглые сутки. Замеры счётчиков туннелей awg дочерний проход получает копией памяти при
         * fork, а свои новые отдаёт по трубе (awg_hs_send / awg_hs_recv, src/kinds/awg.c). Остальное, что
         * проход пишет, — выбор устройств (active), реестр меток, подпись awg — пишется только
         * при изменении. Нет трубы — этот проход работает по-старому, файлом: без памяти
         * приговор «туннель молчит» не вынести вовсе. O_CLOEXEC — чтобы команды, которые проход
         * запускает (ip, nft), не держали конец записи и родитель не ждал их, читая трубу. */
        int pfd[2];
        int piped = pipe2(pfd, O_CLOEXEC) == 0;
        awg_hs_memory(piped);
        pid_t pid = fork();
        if (pid == 0) {
            if (piped) close(pfd[0]);
            int rc = cmd_failover(spec, verbose);
#ifdef STEER_ANDROID
            android_masq_ensure();      /* спека уже загружена проходом */
#endif
            if (piped) awg_hs_send(pfd[1]);
            exit(rc);
        }
        if (piped) close(pfd[1]);
        if (pid > 0) {
            /* Сначала дочитать трубу (до конца файла — проход вышел), потом ждать: сообщение
             * короче буфера трубы, так что проход не встанет на записи, но порядок и так верный. */
            if (piped) awg_hs_recv(pfd[0]);
            while (waitpid(pid, NULL, 0) < 0 && errno == EINTR) {}
        } else
            fprintf(stderr, "steer[warn] failover: fork: %s\n", strerror(errno));
        if (piped) close(pfd[0]);
#ifndef STEER_ANDROID
        /* На роутере проход сам делает ifdown/ifup мёртвому интерфейсу, и события за время
         * прохода — его же следы: реагировать на них значило бы будить себя по кругу. На
         * телефоне сторож интерфейсы не трогает (только ждёт), и событие за время прохода —
         * настоящее: например, TUN, который как раз поднял помощник выхода. */
        if (ev >= 0) failover_events_drain(ev);
#endif

        /* Ждать период ИЛИ событие. poll на монотонном времени: во сне устройства ожидание
         * стоит и не будит его. Событие — не повод бежать сразу: смена сети приходит пачкой
         * (адрес ушёл, интерфейс лёг, поднялся, адрес пришёл), и проход на середине увидел бы
         * полусобранную сеть. Пять секунд — и чтобы она закончилась, и чтобы мигающий
         * интерфейс не гонял проходы подряд. */
        long left = (long)period * 1000;
        struct timespec t0;
        clock_gettime(CLOCK_MONOTONIC, &t0);
        for (;;) {
            struct pollfd p = { ev, POLLIN, 0 };
            int r = ev >= 0 ? poll(&p, 1, (int)(left > 0x7fffffff ? 0x7fffffff : left))
                            : poll(NULL, 0, (int)(left > 0x7fffffff ? 0x7fffffff : left));
            if (r > 0 && failover_events_drain(ev)) {
                struct timespec q = { 5, 0 };
                while (nanosleep(&q, &q) != 0 && errno == EINTR) {}
                failover_events_drain(ev);
                if (verbose)
                    fprintf(stderr, "steer[info] failover: сеть изменилась — проверяю выходы\n");
                break;
            }
            struct timespec t1;
            clock_gettime(CLOCK_MONOTONIC, &t1);
            long spent = (t1.tv_sec - t0.tv_sec) * 1000L + (t1.tv_nsec - t0.tv_nsec) / 1000000L;
            if (spent >= (long)period * 1000) break;
            left = (long)period * 1000 - spent;
        }
    }
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
        fputs("       например: steer apply --spec " STEER_ETC_DIR "/spec.json\n"
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
            else if (!strcmp(cmd, "ctl-serve") || !strcmp(cmd, "ctl")) ctl_usage_flags(stdout);
            else dnsd_usage_flags(stdout);
        }
        return 0;
    }

    /* У fit и dnsd свои аргументы, и общий разбор молча съел бы, например, --budget.
     * Такие команды помечены в таблице как passthru и получают argv как есть. */
    if (c->passthru) {
        if (!strcmp(cmd, "fit")) return aggregate_main(argc - 1, argv + 1);
        if (!strcmp(cmd, "ctl-serve")) return ctl_serve_main(argc - 2, argv + 2);
        if (!strcmp(cmd, "ctl")) return ctl_client_main(argc - 2, argv + 2);
        return dnsd_main(argc - 2, argv + 2);
    }

    struct cli_args a;
    cli_parse(c, argc, argv, 2, &a);
    if (a.state_dir) g_state_dir = a.state_dir;
    const char *spec = a.spec, *arg = a.npos ? a.pos[0] : NULL;

    if (!strcmp(cmd, "apply")) return cmd_apply(spec, a.dry_run);
    if (!strcmp(cmd, "status")) return cmd_status(spec, a.fast);
    if (!strcmp(cmd, "diag")) return cmd_diag(spec);
    if (!strcmp(cmd, "down")) return cmd_down();
    if (!strcmp(cmd, "supervise")) return cmd_supervise(spec);
    if (!strcmp(cmd, "failover"))
        return a.loop ? failover_loop(spec, a.verbose, a.loop) : cmd_failover(spec, a.verbose);
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
            if (a.via) {
                if (g_out[i].via[0]) printf("%s\t%s\n", g_out[i].name, g_out[i].via);
                continue;
            }
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
     * ВЫХОД БЕЗ ФАЙЛА СТРАТЕГИИ НЕ НАЗЫВАЕТСЯ ВОВСЕ, и это не экономия, а исправление
     * наблюдаемого отказа.
     *
     * Так выглядит только что заведённый выход: интерфейс создаёт его пустым, стратегию к
     * нему выбирают следующим действием. Пока файла нет, обёртка steer-nfqws выходит с
     * кодом 2 сразу, procd поднимает её снова через свои пять секунд — и так бесконечно.
     * Замерено на живом роутере (10.8.1.1, OpenWrt 25.12.5): три записи в daemon.err за
     * пятнадцать секунд, то есть примерно семнадцать тысяч строк в сутки на выход, который
     * человек просто не докрутил. Журнал после этого бесполезен для всего остального, а
     * вкладка «Логи» — главный способ, которым сообщество разбирается со своими роутерами.
     *
     * Служба, которая не может встать без действия человека, — это не служба в отказе, а
     * служба, которой ещё нет. Сказать об этом всё равно надо, поэтому причина печатается в
     * stderr: init-скрипт читает только stdout, а в журнале строка окажется ОДИН раз за
     * запуск, а не раз в пять секунд. Человеку то же самое говорят двое: apply («выбрана ли
     * стратегия во вкладке Zapret?») и diag («файла стратегии нет»).
     *
     * Обратная сторона названа честно: файл, удалённый у РАБОТАЮЩЕГО выхода, тоже уберёт
     * экземпляр при следующем `start`. Это верно — ключей для запуска всё равно больше нет.
     *
     * Код возврата — как у needs-dnsd: 0, если поднимать есть что. */
    if (!strcmp(cmd, "zapret-instances")) {
        load_spec(spec);
        registry_assign();
        int n = 0;
        for (size_t i = 0; i < g_out_n; i++) {
            if (g_out[i].kind != OUT_ZAPRET) continue;
            if (access(g_out[i].zp_opts, R_OK) != 0) {
                /* С УРОВНЕМ, а не голым «steer: ». Голый префикс в этом движке
                 * зарезервирован за отказами вызывающему (die и разбор аргументов), которые
                 * кончаются кодом 2 и до журнала не доходят; барьер в buildmatch.sh это и
                 * сторожит. Эта строка — сообщение, а не отказ: команда продолжает работу и
                 * называет остальные выходы. */
                fprintf(stderr, "steer[warn] zapret %s: файла стратегии %s нет — "
                                "поднимать нечем, выберите стратегию\n",
                        g_out[i].name, g_out[i].zp_opts);
                continue;
            }
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
    /* ХВАТИТ ЛИ РЕЗОЛВЕРУ SIGHUP. Печатает подпись таблицы каналов по текущей спеке; сам
     * резолвер положил такую же в каталог состояния при запуске. Совпали — init-скрипт
     * посылает HUP, и локальная сеть не теряет разрешение имён ни на секунду; разошлись —
     * нужен перезапуск, потому что состав каналов HUP не пересобирает.
     *
     * Отдельной командой, а не полем status: её читает оболочка построчно и сравнивает
     * целиком, а не разбирает. Тот же довод, что у zapret-instances и needs-dnsd. */
    if (!strcmp(cmd, "dnsd-sig")) return dnsd_sig_print(spec, stdout);
    /* Спеку обе не читают: соединения сопоставляются с выходами по реестру меток (метки
     * ПРИМЕНЁННОЙ спеки — см. ctnl_conns_print), журнал отдаёт сам резолвер. --spec они
     * принимают ради управляющего сокета, который передаёт его каждой подкоманде. */
    if (!strcmp(cmd, "conns")) return ctnl_conns_print(stdout);
    if (!strcmp(cmd, "dns-log")) return dlog_print(stdout);
    if (!strcmp(cmd, "needs-dnsd")) {
        /* ВСЕГДА 0 — решение владельца, и оно про устройство, а не про экономию.
         *
         * Спека всё равно загружается: команда обязана отвечать отказом на спеке, которую
         * движок не понимает, иначе init-скрипт поднял бы резолвер под конфигурацию,
         * которую applyиный проход отверг бы. Ответ же не зависит от её содержимого:
         * перенаправление DNS теперь стоит всегда (см. генератор набора правил), и
         * резолвер, к которому оно ведёт, обязан существовать всегда вместе с ним.
         *
         * Чем это лучше прежнего `has_domains() ? 0 : 1`: доменность канала стала
         * зависеть от содержимого файлов списков (домен и подсеть лежат в одном), то есть
         * могла бы перевернуться ночным обновлением. Раньше этот код отвечал на вопрос
         * «нужен ли», теперь — «поднимаем», и переворачиваться нечему. */
        load_spec(spec);
        registry_assign();
        build_groups();
        /* В мини-сборке — «поднимать нечего», и это тот же ответ, что даёт генератор
         * правил: он там перенаправления DNS не ставит. Два ответа обязаны совпадать,
         * иначе init-скрипт однажды поднимет резолвер без правила или, хуже, правило
         * останется без резолвера. */
#ifdef STEER_TGWS
        return 1;
#else
        return 0;
#endif
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
        if (c) {
            *c = '\0';
            /* Порт — число 1..65535, иначе отказ: atoi на «host:abc» давал 0, и проба шла на
             * порт 0 с приговором «не отвечает» про узел, который никто не спрашивал. */
            char *pe = NULL;
            long v = strtol(c + 1, &pe, 10);
            if (pe == c + 1 || *pe || v < 1 || v > 65535) {
                fprintf(stderr, "неверный порт: %s\n", c + 1);
                return 2;
            }
            pt = (int)v;
        }
        if (!hb[0]) { fprintf(stderr, "нужно имя узла\n"); return 2; }
        return cmd_tls_probe(hb, a.out_file, pt, a.node > 0 ? a.node : 0, 0);
    }
    if (!strcmp(cmd, "tgws-probe")) {
        /* Позиционный — не имя, а переключатель, и понимается ровно одно слово. Прежде
         * всё, что не «media», молча значило обычную точку: «steer tgws-probe medai»
         * проверял другую точку и отвечал «ок» (I-316). */
        if (arg && strcmp(arg, "media") != 0) {
            fprintf(stderr, "steer: команда tgws-probe понимает аргументом только «media», "
                    "а получила «%s»\n", arg);
            return 2;
        }
        return cmd_tgws_probe(a.node > 0 ? a.node : 2, arg && !strcmp(arg, "media"),
                              a.direct, a.timeout);
    }
    if (!strcmp(cmd, "vless")) return cmd_vless(spec, arg);
    if (!strcmp(cmd, "vless-nodes")) return cmd_vless_nodes(spec, arg);
    if (!strcmp(cmd, "vless-probe")) return cmd_vless_probe(spec, arg, a.node, a.timeout);
    if (!strcmp(cmd, "sub-fetch")) return cmd_sub_fetch(arg, a.out_file, a.info_file);
    if (!strcmp(cmd, "sub-quota")) return cmd_sub_quota(arg, a.info_file);
    if (!strcmp(cmd, "sub-hwid")) return cmd_sub_hwid();
    if (!strcmp(cmd, "dev-id")) return cmd_dev_id();
    if (!strcmp(cmd, "srs-read")) return srs_dump(arg, a.out_file, a.prefixes_out, a.meta_out);
    if (!strcmp(cmd, "obfs")) {
        load_spec(spec);
        struct output *o = out_by_name(arg);
        if (!o) die("нет такого выхода: %s", arg);
        if (!o->obfs.on) die("у выхода %s не настроен obfs", arg);
        /* Метка сокета к серверу обфускации — out_underlay_mark (см. «вложенные выходы» в
         * spec.h). При via она — метка выхода-цели, а та появляется только в реестре: без
         * registry_assign функция вернула бы ноль, то есть «напрямую», молча. Без via реестр
         * не нужен и не трогается — у этого процесса его прежде не было. */
        if (o->via[0]) registry_assign();
        obfs_set_sock_mark(out_underlay_mark(o), o->via[0] != 0);
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

