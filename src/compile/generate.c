/* ---- генератор: спека и группы каналов → дерево набора правил -----------------------------
 *
 * С 1.7 генератор строит дерево (ir.h), а не печатает текст: печатает print.c, раскладку
 * старого ядра делает legacy.c преобразованием этого же дерева, и здесь про неё не знают
 * ничего — всё, что ниже, это набор правил современного ядра.
 *
 * Части, которые зависят от вида выхода, — kind_ops.emit модулей видов (zapret_emit в
 * kinds/zapret.c, tgws_emit в kinds/tgws.c, docs/architecture.md, «Вид выхода»): их зовёт
 * kind_emit_all (kind.c) двумя проходами по видам в порядке реестра, поэтому здесь про них не
 * знают ничего, кроме самого вызова в nft_build. Части, которые есть только на телефоне
 * (разметка на выходе, счёт скачанного на входе, заворот DNS приложений, «кто» по владельцу
 * сокета), — nft_emit_output_mark, nft_emit_output_dns и local_who; их заберёт platform_ops. */
#define _GNU_SOURCE
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "spec.h"
#include "generate.h"

/* Короткий строковый буфер для выражений-перечней («ip saddr { a, b }», «th dport { … }»).
 * 4 КБ с запасом: самый длинный перечень — MAX_FROM (32) адресов или устройств по 63 символа,
 * это около 2,2 КБ; порты — MAX_PORTS (16) диапазонов по 11 символов. */
struct sbuf { char s[4096]; size_t n; };

static void sb_add(struct sbuf *b, const char *fmt, ...) __attribute__((format(printf, 2, 3)));
static void sb_add(struct sbuf *b, const char *fmt, ...) {
    if (b->n >= sizeof(b->s) - 1) return;
    va_list ap;
    va_start(ap, fmt);
    int k = vsnprintf(b->s + b->n, sizeof(b->s) - b->n, fmt, ap);
    va_end(ap);
    if (k < 0) return;
    b->n += (size_t)k;
    if (b->n > sizeof(b->s) - 1) b->n = sizeof(b->s) - 1;
}

/* Единственные оставшиеся в этом файле пользователи — построители цепочек output для каналов
 * на само устройство ниже (plat()->local_channels): kind_ops.emit видов zapret/tgws берёт
 * таблицу так же, но своим вызовом ir_table_find в src/kinds. */
static struct nft_table *inet_table(struct nft_rs *rs) {
    return ir_table_find(rs, NFT_FAM_INET, NULL);
}

/* «Кто» одной или двумя проверками.
 *
 * Адреса и MAC-и уходят РАЗНЫМИ выражениями, объединёнными по И... нет — по ИЛИ быть не может:
 * nft не умеет «или» внутри правила. Поэтому смешивать их в одном правиле нельзя, и это
 * проверяется при загрузке спеки: правило либо про адреса, либо про MAC-и. Молча взять только
 * половину значило бы, что часть устройств правило не касается, и понять это было бы нечем. */
static void x_who(struct nft_rule *r, const struct group *g, int reverse) {
    if (!g->from_n) return;
    struct sbuf b = { .n = 0 };
    sb_add(&b, "%s %s { ", is_mac(g->from[0]) ? "ether" : "ip", reverse ? "daddr" : "saddr");
    for (size_t i = 0; i < g->from_n; i++) sb_add(&b, "%s%s", i ? ", " : "", g->from[i]);
    sb_add(&b, " }");
    ir_x(r, "%s", b.s);
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
static void x_ifs(struct nft_rule *r, const struct spec *sp, int reverse) {
    const char *kw = reverse ? "oifname" : "iifname";
    if (sp->lan_dev_n == 1) { ir_x(r, "%s \"%s\"", kw, sp->lan_dev[0]); return; }
    struct sbuf b = { .n = 0 };
    sb_add(&b, "%s { ", kw);
    for (size_t i = 0; i < sp->lan_dev_n; i++)
        sb_add(&b, "%s\"%s\"", i ? ", " : "", sp->lan_dev[i]);
    sb_add(&b, " }");
    ir_x(r, "%s", b.s);
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
static void x_from(struct nft_rule *r, const struct spec *sp, const struct group *g) {
    if (g->from_n) x_who(r, g, 0); else x_ifs(r, sp, 0);
}

/* То же «кто», но на встречном пути: там наш клиент — это ПОЛУЧАТЕЛЬ. */
static void x_to(struct nft_rule *r, const struct spec *sp, const struct group *g) {
    if (g->from_n) x_who(r, g, 1); else x_ifs(r, sp, 1);
}

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
 * близнец `ip6 saddr` (см. x_ifs и правило DNS). Пометки семейства здесь поэтому нет.
 *
 * ПОРЯДОК В ПРАВИЛЕ: сужение стоит ПЕРЕД поиском по набору адресов. Сравнение одного байта
 * протокола дешевле поиска в наборе на 19 тысяч префиксов, и для канала «только UDP» оно
 * отбрасывает весь TCP роутера до поиска, а не после. На пакет это один и тот же путь, но
 * пакетов, которым канал не подходит, всегда больше.
 *
 * reverse — встречный путь: там наш клиент получатель, а порт сервера ИСХОДЯЩИЙ. */
static void x_l4(struct nft_rule *r, const struct l4match *m, int reverse) {
    if (l4match_empty(m)) return;
    if (m->proto == CH_PROTO_TCP)      ir_x(r, "meta l4proto tcp");
    else if (m->proto == CH_PROTO_UDP) ir_x(r, "meta l4proto udp");
    else                               ir_x(r, "meta l4proto { tcp, udp }");
    if (!m->ports_n) return;
    /* Один диапазон печатается без фигурных скобок — ровно как одно устройство в x_ifs, и
     * по той же причине: так это печатает сам nft, и вывод `--dry-run` совпадает с тем, что
     * человек потом увидит в `nft list`. */
    int one = m->ports_n == 1;
    struct sbuf b = { .n = 0 };
    sb_add(&b, "th %s %s", reverse ? "sport" : "dport", one ? "" : "{ ");
    for (size_t i = 0; i < m->ports_n; i++) {
        if (i) sb_add(&b, ", ");
        if (m->ports[i].lo == m->ports[i].hi) sb_add(&b, "%u", m->ports[i].lo);
        else sb_add(&b, "%u-%u", m->ports[i].lo, m->ports[i].hi);
    }
    if (!one) sb_add(&b, " }");
    ir_x(r, "%s", b.s);
}

/* Сужение словами, для explain. Отдельно от x_l4, потому что там формат nftables, а
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
void l4_describe(const struct l4match *m, char *dst, size_t n) {
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
void counters_load(void) {
    g_ctr_up_n = g_ctr_down_n = 0;
    /* Обе цепочки за один вызов: раздельные popen дали бы счётчики, снятые в разные моменты,
     * и «отдано больше, чем скачано» на глазах у человека объяснялось бы не маршрутизацией,
     * а нашей ленью. */
    /* Таблица — своя у каждой сборки (nft_table): у мини-сборки моста это inet stgws, и с
     * жёстким «inet steer» её счётчики через apply не переносились. */
    /* Каналы на сам телефон считаются в своих цепочках: отданное — в output_mark (правило
     * разметки на хуке output), скачанное — в input_down (см. nft_emit_output_mark). Без них
     * status не отдавал для таких каналов ни одного байта, и экран приложения показывал
     * пустой «трафик по правилам» при живом туннеле. На роутере этих цепочек нет, и nft
     * просто молчит об отсутствующей. */
    char cmd[512];
    snprintf(cmd, sizeof(cmd),
             "nft -a list chain inet %s prerouting_mark 2>/dev/null; "
             "nft -a list chain inet %s postrouting_down 2>/dev/null; "
             "nft -a list chain inet %s output_mark 2>/dev/null; "
             "nft -a list chain inet %s input_down 2>/dev/null",
             nft_table(), nft_table(), nft_table(), nft_table());
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
         * на половину набора, см. legacy.c), и объём канала — их сумма. */
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
int counter_find(const char *name, int down, unsigned long *p, unsigned long *b) {
    const struct ctr *arr = down ? g_ctr_down : g_ctr_up;
    size_t n = down ? g_ctr_down_n : g_ctr_up_n;
    for (size_t i = 0; i < n; i++)
        if (!strcmp(arr[i].name, name)) { *p = arr[i].pkts; *b = arr[i].bytes; return 0; }
    return -1;
}

/* `counter` с прежним значением, если оно есть (нули печатник пишет коротким `counter`). */
static void x_counter_carried(struct nft_rule *r, const char *name, int down) {
    unsigned long p = 0, b = 0;
    if (counter_find(name, down, &p, &b) != 0) p = b = 0;
    ir_counter(r, p, b);
}

/* Разметка пакета выходом: НАШИ биты, а не всё слово — см. у prerouting_mark. */
static void x_mark(struct nft_rule *r, const struct output *o, unsigned mark) {
    if (!out_needs_mark(o)) return;
    ir_markset(r, "meta mark set mark and 0x%08x or 0x%08x", ~STEER_MARK_MASK, mark);
    if (out_needs_ctmark(o)) ir_x(r, "ct mark set mark");
}

/* ---- наборы групп ----------------------------------------------------------------------- */
static void build_group_sets(struct nft_table *t, const struct groups *gr) {
    for (size_t i = 0; i < gr->n; i++) {
        const struct group *g = &gr->g[i];
        /* `any`-группе набор не нужен; опустевшей — нужен, иначе её правило потеряет
         * `ip daddr` и станет безусловным (см. поле `emptied`). */
        if (!g->files_n && !g->domains && !g->emptied) continue;
        struct nft_set *s = ir_set_add(t, g->name, "ipv4_addr");
        if (!s) return;
        /* Доменный набор — timeout из-за резолвера: он кладёт адреса с TTL ответа, и адрес,
         * который CDN перестал отдавать, истекает сам, а не копится вечно.
         *
         * Адресные списки в ТОЙ ЖЕ группе печатаются элементами без timeout, то есть
         * остаются навсегда. Что набор держит и те, и другие — проверено на живом nft, а
         * не выведено: элемент без своего timeout в наборе с этим флагом постоянный. Это
         * и позволяет одному правилу быть про сервис, а не про вид списка.
         *
         * auto-merge because several lists in one group WILL overlap — an address
         * list and a service list cover the same hosting — and folding duplicates
         * in the kernel is cheaper than rewriting the text. */
        s->flags = NFT_SET_INTERVAL | (g->domains ? NFT_SET_TIMEOUT : 0);
        s->auto_merge = 1;
        /* Пустой набор объявляется БЕЗ строки elements: `elements = {  }` nft не примет,
         * а объявление без элементов — обычное дело (так же начинают жизнь доменные
         * наборы, которые наполняет резолвер). Списки в набор — ССЫЛКАМИ: элементы читает
         * печатник потоком (ir.h, «Память»). */
        if (g->files_n && g->addrs)
            for (size_t k = 0; k < g->files_n; k++) ir_set_file(s, g->files[k]);
    }
}

/* ---- разметка: prerouting_mark ------------------------------------------------------------
 *
 * mangle + 1: the mark must exist before the routing decision, and staying one
 * step after mangle leaves room for anything that legitimately wants to run first. */
static int build_prerouting_mark(struct nft_table *t, const struct spec *sp,
                                 const struct groups *gr, struct err *e) {
    struct nft_chain *c = ir_base_chain_add(t, "prerouting_mark", "filter", "prerouting",
                                            "mangle", 1);
    for (size_t i = 0; i < gr->n; i++) {
        const struct group *g = &gr->g[i];
        struct output *o = out_by_name(sp, g->out);
        if (!o) return err_set(e, "channel group %s points at a missing output", g->name);
        /* Каналы на сам телефон — на хуке output, см. nft_emit_output_mark. */
        if (group_is_local(g)) continue;
        /* ПРАВИЛО У ГРУППЫ ОДНО (в старой раскладке у доменной группы с префиксами их
         * становится два — см. legacy.c, шаг 1). */
        struct nft_rule *r = ir_rule(c);
        x_from(r, sp, g);
        x_l4(r, g->l4, 0);
        if (g->files_n || g->domains || g->emptied) ir_setref(r, "ip daddr", g->name);
        /* НАШИ биты, а не всё слово: `mark and ~маска or метка`. Перезапись стирала метку
         * mwan3/pbr/sqm молча, а их перезапись — нашу, и тогда помеченный пакет уходил по
         * таблице main, минуя запрет on_fail=drop (I-135). Диапазон объявлен в spec.h и в
         * контракте. Ядро при выводе канонизирует выражение (оно само выставляет в маске
         * бит, который следующий `or` всё равно поднимает) — на поведение это не влияет,
         * проверено на живом роутере. */
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
        x_mark(r, o, out_skips_zapret(o) ? (o->mark | ZAPRET_SKIP_MARK) : o->mark);
        /* `return` and not `accept`: it ends OUR chain, letting the rest of the
         * firewall proceed, while making the first matching group the winner. */
        x_counter_carried(r, g->name, 0);
        ir_x(r, "return");
        ir_comment(r, "steer:%s", g->name);
    }
    return 0;
}

/* ВЫХОД УПАЛ И ПУЩЕН НАПРЯМУЮ — бит «не для zapret» снимается. Правило разметки выше
 * ставит его безусловно, а при on_fail=direct/zapret упавший выход отдаёт трафик
 * таблице main, то есть открытому пути; там пакет обязан быть обычным трафиком роутера
 * и для общего обхода тоже. Какие выходы сейчас в таком состоянии, знает сторож: он
 * держит их метки в наборе. Зачем именно так — у out_failopen_capable в spec.h.
 *
 * mangle + 2 — сразу после разметки (mangle + 1), то есть задолго до цепочек zapret на
 * postrouting. Счётчик — чтобы по дампу было видно, что правило действительно брало
 * пакеты, а не только стояло. */
static void build_failopen(struct nft_table *t, const struct spec *sp) {
    int failopen = 0;
    for (size_t i = 0; i < sp->out_n; i++)
        if (out_failopen_capable(&sp->out[i])) failopen = 1;
    if (!failopen) return;
    ir_gap(ir_set_add(t, FAILOPEN_SET, "mark"));
    struct nft_rule *r = ir_rule(ir_base_chain_add(t, "prerouting_failopen", "filter",
                                                   "prerouting", "mangle", 2));
    char m[40];
    snprintf(m, sizeof(m), "meta mark and 0x%08x", STEER_MARK_MASK);
    ir_setref(r, m, FAILOPEN_SET);
    ir_markset(r, "meta mark set mark and 0x%08x", ~ZAPRET_SKIP_MARK);
    ir_counter(r, 0, 0);
    ir_comment(r, "steer-failopen");
}

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
static void build_postrouting_down(struct nft_table *t, const struct spec *sp,
                                   const struct groups *gr) {
    struct nft_chain *c = ir_base_chain_add(t, "postrouting_down", "filter", "postrouting",
                                            "srcnat", 10);
    ir_gap(c);
    for (size_t i = 0; i < gr->n; i++) {
        const struct group *g = &gr->g[i];
        /* Скачанное каналом на сам телефон этой цепочкой не считается: получатель у него —
         * сокет телефона, и пакет идёт через input, а не через postrouting. */
        if (group_is_local(g)) continue;
        struct nft_rule *r = ir_rule(c);
        x_to(r, sp, g);
        /* Зеркало сужения: без него счётчик скачанного считал бы и тот трафик, который
         * правило разметки не берёт, — то есть врал бы ровно на ту величину, ради которой
         * порты и заведены. Тот же довод, что у x_to рядом. */
        x_l4(r, g->l4, 1);
        if (g->files_n || g->domains) ir_setref(r, "ip saddr", g->name);
        x_counter_carried(r, g->name, 1);
        ir_comment(r, "steer-down:%s", g->name);
    }
}

#ifndef STEER_TGWS
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
 * устройству ОБА семейства одним правилом.
 *
 * TCP/53 рядом с UDP/53. Резолвер слушает TCP на том же порту (dnsd.c, «DNS по TCP»), а без
 * заворота доменный канал слеп ко всему, что спрошено по TCP: к переспросу после усечённого
 * ответа (TC=1) и к клиентам, которые ходят по TCP сразу. Имя, спрошенное так, не получает
 * fakeip и не попадает в набор, и соединение уходит по настоящему адресу мимо выхода.
 * Замерено на живом роутере с steer 1.5.8: Windows-клиент за несколько минут задал 22
 * вопроса по TCP к IPv6-адресу роутера — все мимо резолвера, прямо в dnsmasq.
 *
 * The resolver only sees what is steered to it. IPv6 as well as IPv4: the router
 * advertises itself as an IPv6 resolver by default and clients prefer that server, so an
 * IPv4-only redirect catches almost nothing — measured on a real client, 15 of its DNS
 * packets went over IPv6 against 20 over IPv4.
 *
 * НО НЕ В МИНИ-СБОРКЕ, И ЭТО НЕ ЭКОНОМИЯ, А ИСПРАВЛЕНИЕ ОТКАЗА.
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
 * здесь и починен. */
static void build_dns_redirect(struct nft_table *t, const struct spec *sp) {
    struct nft_chain *c = ir_base_chain_add(t, "prerouting_dns", "nat", "prerouting",
                                            "dstnat", 0);
    static const char *const protos[2] = { "udp", "tcp" };
    for (int k = 0; k < 2; k++) {
        for (size_t i = 0; i < sp->from_default_n; i++) {
            struct nft_rule *r = ir_rule(c);
            ir_rule_fam(r, 4);
            ir_x(r, "ip saddr %s", sp->from_default[i]);
            ir_x(r, "%s dport 53", protos[k]);
            ir_counter(r, 0, 0);
            ir_x(r, "redirect to :%d", DNS_PORT);
        }
        struct nft_rule *r = ir_rule(c);
        if (sp->from_default_n) ir_family(r, 6);
        x_ifs(r, sp, 0);
        ir_x(r, "%s dport 53", protos[k]);
        ir_counter(r, 0, 0);
        ir_x(r, "redirect to :%d", DNS_PORT);
    }
}
#endif

/* Карта подмены fake→real и её правило dnat. Элементы карты — из файла состояния резолвера,
 * читает печатник (почему она засевается — у emit_fakeip_elements в print.c).
 *
 * Счётчик здесь обязателен, и это не единообразие с соседями. Правило
 * отвечает на единственный вопрос, который встаёт, когда «домены не
 * работают»: доехал ли поддельный адрес до роутера вообще. Без счётчика
 * «клиент не прислал» и «прислал, а мы не развернули» различаются только
 * tcpdump'ом на роутере, а первое — обычное дело у клиента из mesh-VPN
 * (Tailscale, ZeroTier): 198.18.0.0/15 уходит в туннель, только если роутер
 * объявил этот диапазон маршрутом, и по умолчанию он его не объявляет. Из
 * локальной сети вопрос не встаёт вовсе — там роутер и есть шлюз. */
static void build_fakeip(struct nft_table *t) {
    struct nft_set *m = ir_map_add(t, "fakeip", "ipv4_addr", "ipv4_addr");
    ir_gap(m);
    char path[512];
    if (snprintf(path, sizeof(path), "%s/fakeip.state", steer_state_dir()) < (int)sizeof(path))
        ir_set_fakeip_state(m, path);
    struct nft_rule *r = ir_rule(ir_base_chain_add(t, "prerouting_dnat", "nat", "prerouting",
                                                   "dstnat", 0));
    ir_rule_fam(r, 4);
    ir_x(r, "ip daddr 198.18.0.0/15");
    ir_counter(r, 0, 0);
    ir_dnat(r, "ip daddr", "fakeip");
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
static void build_traceroute_raw(struct nft_table *t) {
    struct nft_rule *r = ir_rule(ir_base_chain_add(t, "prerouting_raw", "filter", "prerouting",
                                                   "raw", 0));
    ir_x(r, "meta l4proto icmp");
    ir_x(r, "icmp type time-exceeded");
    ir_counter(r, 0, 0);
    ir_notrack(r);
    ir_comment(r, "steer:traceroute-hops");
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
 * цепочке nat output в ip и ip6 (legacy.c разносит его по семействам); на старом ядре без nat в
 * ip6 (NFTC_IP6NAT) IPv6-половины нет — там такого правила не поставить, и apply об этом говорит. */

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
static void local_dns_redirect(struct nft_chain *c, const struct spec *sp) {
    static const char *const protos[2] = { "udp", "tcp" };
    static const char *const names[2] = { "steer-dns-local", "steer-dns-local-tcp" };
    for (int k = 0; k < 2; k++) {
        struct nft_rule *r = ir_rule(c);
        ir_x(r, "meta mark and 0x%08x != 0x%08x", STEER_MARK_MASK, STEER_SELF_MARK);
        if (has_via(sp)) ir_x(r, "meta mark and 0x%08x == 0x00000000", STEER_TUNNEL_BIT);
        ir_x(r, "%s dport 53", protos[k]);
        ir_x(r, "ct mark set mark");
        ir_counter(r, 0, 0);
        ir_x(r, "redirect to :%d", DNS_PORT);
        ir_comment(r, "%s", names[k]);
    }
}

/* Заворот DNS приложений и перевод поддельных адресов для соединений самого телефона —
 * цепочка nat на хуке output. */
void nft_emit_output_dns(struct nft_rs *rs, const struct spec *sp, const struct groups *gr) {
    struct nft_chain *c = ir_base_chain_add(inet_table(rs), "output_dns", "nat", "output",
                                            "dstnat", 0);
    local_dns_redirect(c, sp);
    if (!has_fakeip(gr)) return;
    struct nft_rule *r = ir_rule(c);
    ir_rule_fam(r, 4);
    ir_x(r, "ip daddr 198.18.0.0/15");
    ir_counter(r, 0, 0);
    ir_dnat(r, "ip daddr", "fakeip");
    ir_comment(r, "steer-fakeip-local");
}

/* «Кто» у группы на сам телефон: владелец сокета. "self" — все приложения (UID от
 * STEER_APP_UID_MIN; почему не демоны — у from_is_local); "uid:N[-M]" — перечисленные. У
 * пакета без сокета (RST и ICMP, которые ядро шлёт само) владельца нет, и skuid не совпадает
 * ни с чем — такие пакеты идут обычным путём.
 *
 * `ct direction original` — только соединения, которые приложение ОТКРЫЛО само. Ответы на
 * входящие (беспроводной adb, сервер в приложении) обязаны уйти тем же путём, каким пришёл
 * запрос, а не в туннель.
 *
 * `meta mark and <поле движка> == 0` — пакет, у которого поле метки движка уже заполнено, не
 * наш клиент, а собственный трафик туннеля, и перемечать его нельзя. Найдено на телефоне:
 * WireGuard (и AmneziaWG) в ядре шифрует пакет приложения на месте и отправляет внешний UDP
 * с тем же skb->sk — от сокета отвязывает (skb_orphan) только пока ждёт рукопожатия. Хук
 * OUTPUT видит у внешнего пакета uid приложения, группа «весь трафик» метила его меткой
 * выхода, и он уходил в тот же туннель: петля, сотни мегабайт исходящих за секунды при почти
 * нулевом входящем и ни одного рабочего соединения. Внешний пакет туннель метит сам
 * (WGDEVICE_A_FWMARK) — STEER_SELF_MARK, а при via меткой цели, — то есть поле движка у него
 * всегда не пустое; у пакета приложения до нашего правила в слове метки только биты netd
 * (0-19), поле движка пустое. Так же пропускается и переспрос резолвера (STEER_SELF_MARK). */
static int local_who(struct nft_rule *r, const struct group *g, struct err *e) {
    ir_x(r, "meta mark and 0x%08x == 0x00000000", STEER_MARK_MASK);
    if (!strcmp(g->from[0], "self")) {
        ir_x(r, "meta skuid >= %u", STEER_APP_UID_MIN);
        ir_x(r, "ct direction original");
        return 0;
    }
    int one = g->from_n == 1 && !strchr(g->from[0], '-');
    struct sbuf b = { .n = 0 };
    sb_add(&b, "%s", one ? "meta skuid " : "meta skuid { ");
    for (size_t i = 0; i < g->from_n; i++) {
        unsigned lo, hi;
        if (from_uid_range(g->from[i], &lo, &hi) != 0)
            return err_set(e, "группа %s: негодный UID", g->name);   /* спека это уже отвергла */
        if (lo == hi) sb_add(&b, "%s%u", i ? ", " : "", lo);
        else sb_add(&b, "%s%u-%u", i ? ", " : "", lo, hi);
    }
    if (!one) sb_add(&b, " }");
    ir_x(r, "%s", b.s);
    ir_x(r, "ct direction original");
    return 0;
}

/* ---- каналы на сам телефон: разметка на выходе ------------------------------------
 *
 * Тот же приём, что prerouting_mark для раздачи, но на хуке output: «первое совпадение
 * решает», одно правило на группу, метка — наши биты с маской, метка соединения — как там.
 *
 * Тип цепочки — route, прямо в inet, где и наборы: смена метки в ней сама заставляет ядро
 * искать маршрут заново. В старой раскладке route в inet нет — там её переделывает legacy.c
 * (шаг 2: filter и бит перемаршрутизации).
 *
 * IPv6. Наборы каналов — IPv4, и правило с набором IPv6 не касается. Но у группы «весь
 * трафик» набора нет, и её IPv6 ушёл бы мимо туннеля: маршруты выхода движок ставит только
 * для IPv4. Поэтому такой группе IPv6 отвечается отказом — приложения переходят на IPv4 (так
 * устроен выбор адреса у любого клиента с двумя стеками), и ничего не утекает напрямую. */
int nft_emit_output_mark(struct nft_rs *rs, const struct spec *sp, const struct groups *gr,
                         struct err *e) {
    struct nft_table *t = inet_table(rs);
    struct nft_chain *c = ir_base_chain_add(t, "output_mark", "route", "output", "mangle", 1);
    ir_gap(c);
    for (size_t i = 0; i < gr->n; i++) {
        const struct group *g = &gr->g[i];
        if (!group_is_local(g)) continue;
        struct output *o = out_by_name(sp, g->out);
        if (!o) return err_set(e, "channel group %s points at a missing output", g->name);
        if (g->all && out_needs_mark(o)) {
            /* С тем же сужением по протоколу и портам, что и канал: канал «UDP 50000-65535»
             * не вправе отнимать у приложения весь IPv6. Своя сеть (петля, link-local, ULA,
             * мультикаст) — не наружу и не мимо туннеля, её не трогаем. */
            struct nft_rule *r = ir_rule(c);
            if (local_who(r, g, e) != 0) return -1;
            ir_family(r, 6);
            x_l4(r, g->l4, 0);
            ir_x(r, "oifname != \"lo\"");
            ir_x(r, "ip6 daddr != { fe80::/10, fc00::/7, ff00::/8 }");
            ir_counter(r, 0, 0);
            ir_x(r, "reject");
            ir_comment(r, "steer-v6:%s", g->name);
        }
        struct nft_rule *r = ir_rule(c);
        if (local_who(r, g, e) != 0) return -1;
        /* «Весь трафик» — это интернет, а не своя сеть: принтер, NAS и Chromecast в Wi-Fi
         * через туннель не видны. Только IPv4 — IPv6 такой группы отвергнут правилом выше. */
        if (g->all) {
            ir_family(r, 4);
            ir_x(r, "ip daddr != { 10.0.0.0/8, 127.0.0.0/8, 169.254.0.0/16, 172.16.0.0/12, "
                    "192.168.0.0/16, 224.0.0.0/4, 255.255.255.255 }");
        }
        x_l4(r, g->l4, 0);
        if (g->files_n || g->domains || g->emptied) ir_setref(r, "ip daddr", g->name);
        x_mark(r, o, o->mark);
        x_counter_carried(r, g->name, 0);
        ir_x(r, "return");
        ir_comment(r, "steer:%s", g->name);
    }

    /* Скачанное каналами на сам телефон. Ответ приходит сокету телефона и идёт через input, а
     * не через postrouting — postrouting_down его не видит (см. там). Узнаётся по метке
     * соединения: правило разметки выше пишет в ct mark метку выхода, и у ответных пакетов
     * того же соединения она та же. Канал со списком дополнительно сужается адресом
     * источника ответа — это адрес сервера из его набора, — чтобы два канала на один выход
     * не считали трафик друг друга; у канала «весь трафик» набора нет, и два таких канала на
     * одном выходе покажут одно и то же скачанное. Цепочка ничего не решает: policy accept,
     * правила без вердикта. */
    c = ir_base_chain_add(t, "input_down", "filter", "input", "filter", 10);
    ir_gap(c);
    for (size_t i = 0; i < gr->n; i++) {
        const struct group *g = &gr->g[i];
        if (!group_is_local(g)) continue;
        struct output *o = out_by_name(sp, g->out);
        if (!o || !out_needs_mark(o) || !out_needs_ctmark(o)) continue;
        struct nft_rule *r = ir_rule(c);
        ir_x(r, "ct direction reply");
        ir_x(r, "ct mark and 0x%08x == 0x%08x", STEER_MARK_MASK, o->mark);
        x_l4(r, g->l4, 1);
        if (g->files_n || g->domains || g->emptied) ir_setref(r, "ip saddr", g->name);
        x_counter_carried(r, g->name, 1);
        ir_comment(r, "steer-down:%s", g->name);
    }
    return 0;
}

/* Дерево набора правил современной раскладки. Порядок объектов — порядок печати, и он
 * прежний до байта (снимок tests/golden/ruleset). */
int nft_build(struct nft_rs *rs, const struct spec *sp, const struct groups *gr,
              struct err *e) {
    struct nft_table *t = ir_table_add(rs, NFT_FAM_INET, nft_table());
    build_group_sets(t, gr);
    if (build_prerouting_mark(t, sp, gr, e) != 0) return -1;
    if (plat()->local_channels && has_local(gr) && nft_emit_output_mark(rs, sp, gr, e) != 0)
        return -1;
    build_failopen(t, sp);
    build_postrouting_down(t, sp, gr);
    /* Построители видов (kind_ops.emit): по видам, в порядке реестра, поэтому все цепочки
     * zapret в тексте стоят раньше цепочки моста, в каком бы порядке выходы ни шли в спеке
     * (kind.c: kind_emit_all). */
    kind_emit_all(rs, sp);
#ifndef STEER_TGWS
    build_dns_redirect(t, sp);
#endif
    /* Остальное по-прежнему по факту доменных каналов: карта fakeip и цепочка dstnat
     * стоят per-packet, и держать их пустыми на роутере без доменов незачем. Это гейт
     * по СТОИМОСТИ, а не по смыслу, и переворачиваться он может свободно — ни один
     * чужой ключ от него не зависит. */
    if (has_domains(gr)) {
        if (has_fakeip(gr)) build_fakeip(t);
        if (plat()->local_channels && has_local_domains(gr)) nft_emit_output_dns(rs, sp, gr);
        if (sp->traceroute_hops) build_traceroute_raw(t);
    }
    if (rs->oom) return err_set(e, "out of memory building the ruleset", NULL);
    return 0;
}

/* Текст набора правил этого запуска: дерево, раскладка ядра (g_nftc) и печать. На отказе в f
 * не пишется ничего — дерево строится целиком до печати. */
int generate(const struct spec *sp, const struct groups *gr, FILE *f, struct err *e) {
    struct nft_rs rs;
    nft_rs_init(&rs);
    int rc = nft_build(&rs, sp, gr, e);
    if (rc == 0) rc = legacy_rewrite(&rs, sp, g_nftc, e);
    if (rc == 0) nft_print(&rs, f);
    nft_rs_free(&rs);
    return rc;
}
