#include "dnsd_int.h"
#include "srsplan.h"

struct dchan g_dch[MAX_CHANNELS];
size_t g_dch_n;

/* Все доменные каналы, которым принадлежит имя, — по биту на канал.
 *
 * ВСЕ, а не первый: одно имя законно названо в нескольких правилах (правило на
 * телевизор и правило на всю сеть), и каждому из них нужен свой набор, иначе клиенты
 * второго остаются с поддельным адресом, которого нет ни в одном правиле. Кто из
 * правил заберёт пакет, решает порядок цепочки — тот же порядок, в котором правила
 * стоят у человека на экране. */
uint64_t dch_match_mask(const char *host) {
    uint64_t m = 0;
    for (size_t i = 0; i < g_dch_n && i < 64; i++)
        if (dch_matches(&g_dch[i], host)) m |= 1ULL << i;
    return m;
}

/* Первый (то есть старший по порядку правил) канал из набора; -1 — набор пуст.
 * Он и решает, каким будет ОТВЕТ клиенту: ответ один, а режимов у каналов два. */
int dch_first(uint64_t mask) {
    for (size_t i = 0; i < g_dch_n && i < 64; i++)
        if (mask & (1ULL << i)) return (int)i;
    return -1;
}

/* Только каналы поддельного адреса из набора. Канал реального адреса поддельный к
 * себе не берёт: в его наборе лежат настоящие адреса из ответа, а поддельного клиент
 * в этом режиме и не получает. */
uint64_t dch_fakeip_only(uint64_t mask) {
    for (size_t i = 0; i < g_dch_n && i < 64; i++)
        if ((mask & (1ULL << i)) && g_dch[i].realip) mask &= ~(1ULL << i);
    return mask;
}

/* Сборка таблицы объявлена заранее: подпись считается по ней, а сама сборка описана ниже —
 * рядом с доводами о слиянии каналов, где ей и место. */

/* ПОДПИСЬ ТАБЛИЦЫ КАНАЛОВ: то, что SIGHUP перечитать НЕ может.
 *
 * Зачем она нужна. `reload_dnsd` после каждого apply убивал резолвер сигналом TERM, а procd
 * поднимает его заново не сразу, а через свою паузу (`respawn 3600 5 0`). Пять секунд
 * резолвера нет, заворот `udp dport 53 -> :5300` при этом стоит — и ВСЯ локальная сеть
 * получает на каждый запрос имени «port unreachable». Замерено на стенде в QEMU: ровно 5
 * секунд, первый запрос клиента после «Применить» не разрешается.
 *
 * Между тем резолвер умеет SIGHUP и по нему перечитывает файлы списков, не теряя запросов в
 * полёте (см. reload_rules). Чего HUP не делает — так это не пересобирает саму таблицу
 * каналов: имена наборов, режим realip и перечень файлов у каждого канала берутся из спеки
 * один раз, при запуске. Значит различать надо два случая, и различать их обязан ТОТ, КТО
 * ЗНАЕТ, — движок, а не init-скрипт по виду спеки.
 *
 * Отсюда подпись: строка на канал, «набор|режим|файлы». Резолвер пишет её при запуске в
 * каталог состояния, а команда `dnsd-sig` печатает то же самое по текущей спеке. Совпали —
 * достаточно HUP и провала нет вовсе; разошлись — нужен перезапуск, и пауза procd в этом
 * случае оправдана: конфигурация стала другой.
 *
 * Формат нарочно текстовый и построчный: его сравнивает оболочка, а не мы. */
static void dch_signature(FILE *out) {
    for (size_t i = 0; i < g_dch_n; i++) {
        fprintf(out, "%s|%d", g_dch[i].set, g_dch[i].realip ? 1 : 0);
        for (size_t k = 0; k < g_dch[i].rules_n; k++)
            fprintf(out, "|%s", g_dch[i].rules_path[k]);
        fprintf(out, "\n");
    }
}

/* Путь подписи. Рядом с остальным состоянием, тем же швом --state-dir: стенду нужно писать
 * её в песочницу, а не в /var/lib роутера, на котором он идёт. */
static void dch_sig_path(char *dst, size_t n) {
    snprintf(dst, n, "%s/dnsd.sig", steer_state_dir());
}

/* Записать подпись — атомарно, через файл рядом. Обрыв на середине оставил бы обрубок,
 * который не совпадёт ни с чем, и мы получили бы перезапуск там, где хватило бы HUP: это
 * ровно то поведение, от которого здесь уходим, только теперь молча и через раз. */
void dch_sig_write(void) {
    char path[PATH_MAX], tmp[PATH_MAX];
    dch_sig_path(path, sizeof(path));
    if ((size_t)snprintf(tmp, sizeof(tmp), "%s.new", path) >= sizeof(tmp)) return;
    FILE *f = fopen(tmp, "w");
    if (!f) return;
    dch_signature(f);
    int ok = fflush(f) == 0;
    fclose(f);
    if (ok) { if (rename(tmp, path) != 0) unlink(tmp); }
    else unlink(tmp);
}

/* Команда `dnsd-sig`: подпись по спеке, без запуска резолвера. Её печать и есть весь ответ
 * на вопрос «хватит ли HUP». */
int dnsd_sig_print(const char *spec, FILE *out) {
    /* Правило 5, docs/architecture.md, раздел 2: err_die здесь довершает то, что раньше делал
     * die() изнутри load_spec.
     *
     * Спека — значение (правило 6): свой экземпляр у этой точки входа. */
    static struct spec cfg;
    struct err e = {0};
    if (load_spec(spec, &cfg, &e) < 0) err_die(&e);
    dch_build(&cfg);
    dch_signature(out);
    return 0;
}

/* Таблица доменных каналов резолвера из уже прочитанной спеки.
 *
 * Отдельной функцией, а не куском cmd_dnsd, ради стенда: пропуск выключенного правила
 * и слияние каналов в один набор — решения о смысле, и проверять их надо прямо, а не
 * через запуск резолвера с сетью и netlink. */
/* Имя доменного набора канала `c`, если бы у него был режим `realip`. */
static void dch_name(const struct spec *sp, char *dst, size_t n, const struct channel *c, int realip) {
    size_t fn = c->from_n ? c->from_n : sp->from_default_n;
    const char (*fr)[64] = c->from_n ? c->from : sp->from_default;
    group_set_name(sp, dst, n, c->out, "dom", fr, fn, realip, &c->l4);
}

/* ---- каналы с наборами sing-box -----------------------------------------------------------
 *
 * Канал с `srs_files` раскладывается на части (src/model/srsplan.c) — той же функцией, что у
 * компилятора, поэтому имена наборов и то, какие клаузы в какой набор, совпадают без сговора.
 * Доменная «единица» — это обычный канал или часть такого канала; имя её набора считается так
 * же, как его считает build_groups для группы этой части. */
static struct srs_plan g_plans[MAX_CHANNELS];
static int g_plan_ok[MAX_CHANNELS];

static void unit_name(const struct spec *sp, const struct channel *c, const struct srs_part *p,
                      int realip, char *dst, size_t n) {
    if (!p) { dch_name(sp, dst, n, c, realip); return; }
    size_t fn = c->from_n ? c->from_n : sp->from_default_n;
    const char (*fr)[64] = c->from_n ? c->from : sp->from_default;
    if (p->kind == SP_COMPOSITE)
        group_set_name_mixed(sp, dst, n, c->out, "dom", fr, fn, realip);
    else if (p->kind == SP_EXTRA)
        group_set_name_extra(sp, dst, n, c->out, "dom", fr, fn, realip, p->id);
    else
        group_set_name(sp, dst, n, c->out, "dom", fr, fn, realip,
                       l4match_same(&p->l4, &c->l4) ? &c->l4 : &p->l4);
}

/* Строки источников, собранные здесь (выбор клауз), живут до следующей сборки таблицы. */
static char **g_strs;
static size_t g_strs_n, g_strs_cap;

static const char *keep_str(char *s) {
    if (!s) return NULL;
    if (g_strs_n == g_strs_cap) {
        size_t cap = g_strs_cap ? g_strs_cap * 2 : 16;
        char **p = realloc(g_strs, cap * sizeof(*p));
        if (!p) { free(s); return NULL; }
        g_strs = p;
        g_strs_cap = cap;
    }
    g_strs[g_strs_n++] = s;
    return s;
}

static void strs_free(void) {
    for (size_t i = 0; i < g_strs_n; i++) free(g_strs[i]);
    g_strs_n = 0;
}

/* «srs:<клаузы>:<путь>» для клауз имён части. Обычный набор — номера (соседние — диапазоном);
 * составной — номер и сужение каждой («0=udp/50000-65535»): у элементов набора оно своё. */
static const char *srs_source(const struct srs_psel *ps, int composite) {
    size_t cap = 64 + strlen(ps->path), n = 0;
    char *b = malloc(cap);
    if (!b) return NULL;
    n = (size_t)snprintf(b, cap, "srs:");
    int first = 1;
    for (size_t i = 0; i < ps->ncl; i++) {
        if (!(ps->sel[i >> 3] & (1u << (i & 7)))) continue;
        if (srs_clause(ps->set, i)->kind != SRS_C_DOM) continue;
        size_t j = i;
        if (!composite)
            while (j + 1 < ps->ncl && (ps->sel[(j + 1) >> 3] & (1u << ((j + 1) & 7))) &&
                   srs_clause(ps->set, j + 1)->kind == SRS_C_DOM)
                j++;
        char item[200], l4t[160];
        if (composite) {
            l4_to_text(&ps->eff[i], l4t, sizeof(l4t));
            snprintf(item, sizeof(item), "%s%zu=%s", first ? "" : ",", i, l4t);
        } else if (j > i) {
            snprintf(item, sizeof(item), "%s%zu-%zu", first ? "" : ",", i, j);
        } else {
            snprintf(item, sizeof(item), "%s%zu", first ? "" : ",", i);
        }
        size_t il = strlen(item);
        if (n + il + strlen(ps->path) + 4 > cap) {
            cap = (n + il + strlen(ps->path) + 4) * 2;
            char *nb = realloc(b, cap);
            if (!nb) { free(b); return NULL; }
            b = nb;
        }
        memcpy(b + n, item, il + 1);
        n += il;
        first = 0;
        i = j;
    }
    snprintf(b + n, cap - n, ":%s", ps->path);
    return keep_str(b);
}

static const char *cl_source(const struct l4match *l4, const char *path) {
    char t[160];
    l4_to_text(l4, t, sizeof(t));
    size_t n = strlen(t) + strlen(path) + 8;
    char *b = malloc(n);
    if (!b) return NULL;
    snprintf(b, n, "cl:%s:%s", t, path);
    return keep_str(b);
}

/* В какой доменный набор компилятор кладёт канал БЕЗ доменных списков. 1 — в набор `set`
 * с режимом `*realip`, 0 — ни в какой: его группа адресная, и доменной части у канала нет.
 *
 * ЗАЧЕМ. Прежде резолвер заводил доменную часть каждому каналу с адресными файлами — ради
 * гибридных списков (см. ниже), — и имя ей считал сам, словно канал доменный. Но набор
 * `_dom` у компилятора появляется, только если в группе есть хоть один канал с доменными
 * списками (build_groups в steer.c: `domains = c->domains_n > 0`). Канал голоса Discord —
 * одни подсети Cloudflare плюс udp и порты — давал у резолвера канал `vpn_dom_c0_p1`, а в
 * ядре был только `vpn_ip_c0_p1`. Имя, совпавшее с правилом такого канала, получало
 * поддельный адрес для набора, которого нет: вставка отказывала, и резолвер держал SERVFAIL
 * окно пересборки (map_refusal_is_window), вместо того чтобы сразу ответить настоящим.
 *
 * Решение повторяет компилятор, а не угадывает. Адресный канал попадает в доменную группу,
 * когда совпадает с доменным каналом по выходу, клиентам и сужению — ровно то, что входит в
 * имя набора; режим группы — у первого такого доменного канала в порядке компилятора
 * (сначала правила на устройство, потом остальные). Поэтому имя адресного канала считается
 * с режимом каждого кандидата и сравнивается с именем кандидата: совпало — это его группа.
 *
 * Доменный кандидат — обычный канал с domains_files или часть канала с наборами, в которой
 * есть имена (unit_name). */
static int dch_join_domain_group(const struct spec *sp, const struct channel *c,
                                 const struct srs_part *cp, char *set, size_t n, int *realip) {
    for (int pass = 0; pass < 2; pass++)
        for (size_t j = 0; j < sp->ch_n; j++) {
            const struct channel *d = &sp->ch[j];
            if ((pass == 0) != (d->dev_scope != 0)) continue;
            if (d->disabled) continue;
            size_t np = d->srs_n ? (g_plan_ok[j] ? g_plans[j].n : 0) : 1;
            for (size_t k = 0; k < np; k++) {
                const struct srs_part *dp = d->srs_n ? &g_plans[j].p[k] : NULL;
                if (dp ? !dp->has_dom : !d->domains_n) continue;
                char want[64], mine[64];
                unit_name(sp, d, dp, d->realip, want, sizeof(want));
                unit_name(sp, c, cp, d->realip, mine, sizeof(mine));
                if (strcmp(want, mine)) continue;
                snprintf(set, n, "%s", want);
                *realip = d->realip;
                return 1;
            }
        }
    return 0;
}

/* Найти или завести канал резолвера под набор set. */
static struct dchan *dch_slot(const char *set, int realip, const char *out) {
    size_t k = 0;
    for (; k < g_dch_n; k++)
        if (!strcmp(g_dch[k].set, set) && g_dch[k].realip == realip) return &g_dch[k];
    if (g_dch_n >= MAX_CHANNELS) return NULL;
    memset(&g_dch[g_dch_n], 0, sizeof(g_dch[g_dch_n]));
    snprintf(g_dch[g_dch_n].set, sizeof(g_dch[g_dch_n].set), "%s", set);
    snprintf(g_dch[g_dch_n].out, sizeof(g_dch[g_dch_n].out), "%.31s", out);
    g_dch[g_dch_n].realip = realip;
    return &g_dch[g_dch_n++];
}

static void dch_name_rule(struct dchan *d, const struct channel *c, int dom) {
    if (!d->chan[0] || (!d->chan_dom && dom)) {
        snprintf(d->chan, sizeof(d->chan), "%.31s", c->name);
        d->chan_dom = dom;
    }
}

static void dch_src(struct dchan *d, const char *src) {
    if (src && d->rules_n < MAX_FILES) d->rules_path[d->rules_n++] = src;
}

/* Канал с наборами: его части с именами — каналы резолвера (или, без имён, но со своими
 * адресными списками, — часть доменной группы соседа, как у обычного канала). */
static void dch_add_srs_channel(const struct spec *sp, size_t ci) {
    const struct channel *c = &sp->ch[ci];
    if (!g_plan_ok[ci]) return;
    for (size_t pi = 0; pi < g_plans[ci].n; pi++) {
        const struct srs_part *p = &g_plans[ci].p[pi];
        char set[64];
        int realip = c->realip;
        if (p->has_dom) unit_name(sp, c, p, realip, set, sizeof(set));
        else if (!(p->own && c->prefixes_n && p->kind != SP_EXTRA) ||
                 !dch_join_domain_group(sp, c, p, set, sizeof(set), &realip))
            continue;
        struct dchan *d = dch_slot(set, realip, c->out);
        if (!d) return;
        dch_name_rule(d, c, p->has_dom);
        int composite = p->kind == SP_COMPOSITE;
        if (p->own) {
            for (size_t f = 0; f < c->domains_n; f++)
                dch_src(d, composite ? cl_source(&c->l4, c->domains_files[f]) : c->domains_files[f]);
            for (size_t f = 0; f < c->prefixes_n; f++)
                dch_src(d, composite ? cl_source(&c->l4, c->prefixes_files[f]) : c->prefixes_files[f]);
        }
        for (size_t k = 0; k < p->sel_n; k++)
            if (p->sel[k].has_dom) dch_src(d, srs_source(&p->sel[k], composite));
    }
}

void dch_build(const struct spec *sp) {
    g_dch_n = 0;
    strs_free();
    for (size_t i = 0; i < sp->ch_n && i < MAX_CHANNELS; i++) {
        if (g_plan_ok[i]) srs_plan_free(&g_plans[i]);
        g_plan_ok[i] = 0;
        if (!sp->ch[i].srs_n || sp->ch[i].disabled) continue;
        struct err e = {0};
        g_plan_ok[i] = srs_plan_channel(sp, &sp->ch[i], -1, &g_plans[i], &e) == 0;
    }
    /* Same coalescing the compiler does, and it must agree with it exactly: the set
     * names here ARE the sets it generated. Domain channels that share an output, the
     * same clients and the same mode are one set — which is why this groups by
     * (out, realip) rather than walking channels one by one. */
    /* ГИБРИДНЫЕ СПИСКИ: канал попадает сюда и по адресным файлам тоже — но только если у
     * его группы в ядре есть доменный набор (см. dch_join_domain_group выше).
     *
     * Прежде здесь стоял пропуск канала без `domains_files`, и это был не гейт по цене, а
     * решение о смысле: доменность канала определялась ИМЕНЕМ КЛЮЧА в спеке. Из этого
     * следовало, что человек выбирает не сервис, а вид списка — тот самый довод, по
     * которому в spec.c уже снят запрет на адреса и домены в одном правиле.
     *
     * Теперь оба массива читаются одинаково, а кому какая СТРОКА принадлежит, решает
     * spec_line_is_addr на месте чтения: адресные строки берёт компилятор набора, доменные
     * — резолвер. Один файл может содержать и то и другое, и «движок сам разберётся»
     * означает буквально это.
     *
     * Разбирается он, впрочем, не в один механизм, а в два: `8.8.8.0/24` ляжет в набор
     * настоящим префиксом, а `youtube.com` — поддельным адресом плюс правилом DNAT. Набор
     * с `flags interval,timeout` держит и то и то (проверено опытом, см. spec.c). */
    for (size_t i = 0; i < sp->ch_n; i++) {
        /* ВЫКЛЮЧЕННОЕ ПРАВИЛО РЕЗОЛВЕР НЕ БЕРЁТ. Компилятор набора его уже не берёт
         * (steer.c), а здесь брал — и это худший из возможных исходов, потому что «не
         * действует» превращалось в «ломает».
         *
         * Как ломало. Резолвер выдаёт клиенту поддельный адрес и кладёт его в набор своего
         * канала; набора выключенного канала в ядре нет вовсе. То есть имя разрешалось в
         * адрес, которого нет ни в одном правиле: ни маршрута, ни метки, ни возврата к
         * настоящему адресу. Домен переставал открываться СОВСЕМ — и у тех клиентов, кого
         * выключенное правило касалось, и у тех, кого касалось соседнее включённое: первым
         * совпадением здесь забирает имя себе первый канал, а он выключен.
         *
         * Снаружи это выглядело так, что выключатель не действует: «отключить правило —
         * ничего не меняется, надо именно удалить» (обратка, два роутера с одинаковым
         * набором правил). Ровно та же строка, что в steer.c, и по той же причине. */
        if (sp->ch[i].disabled) continue;
        if (sp->ch[i].srs_n) { dch_add_srs_channel(sp, i); continue; }
        if (!sp->ch[i].domains_n && !sp->ch[i].prefixes_n) continue;
        char set[64];
        int realip = sp->ch[i].realip;
        /* Имя считает ОБЩАЯ функция, та же, что у компилятора: своя формула здесь была
         * `%.24s_dom` и не знала ни про список клиентов, ни про режим, поэтому доменные
         * каналы одного выхода с разными from сливались в один набор, а fakeip и realip
         * попадали туда же вместе. Разойтись двум формулам теперь негде — она одна.
         *
         * Сужение канала (протокол и порты) уходит в имя набора наравне с `from` и
         * режимом: компилятор по нему РАЗДЕЛЯЕТ наборы, и резолвер, не передавший его,
         * наполнял бы набор, которого нет. Ровно та беда, от которой эта функция общая.
         *
         * Канал без доменных списков доменной части не получает, если только компилятор не
         * положил его в доменную группу соседа, — см. dch_join_domain_group. */
        if (sp->ch[i].domains_n) dch_name(sp, set, sizeof(set), &sp->ch[i], realip);
        else if (!dch_join_domain_group(sp, &sp->ch[i], NULL, set, sizeof(set), &realip)) continue;
        size_t k = 0;
        for (; k < g_dch_n; k++)
            if (!strcmp(g_dch[k].set, set) && g_dch[k].realip == realip) break;
        if (k == g_dch_n) {
            if (g_dch_n >= MAX_CHANNELS) break;
            memset(&g_dch[g_dch_n], 0, sizeof(g_dch[g_dch_n]));
            snprintf(g_dch[g_dch_n].set, sizeof(g_dch[g_dch_n].set), "%s", set);
            snprintf(g_dch[g_dch_n].out, sizeof(g_dch[g_dch_n].out), "%.31s", sp->ch[i].out);
            g_dch[g_dch_n].realip = realip;
            k = g_dch_n++;
        }
        if (!g_dch[k].chan[0] || (!g_dch[k].chan_dom && sp->ch[i].domains_n)) {
            snprintf(g_dch[k].chan, sizeof(g_dch[k].chan), "%.31s", sp->ch[i].name);
            g_dch[k].chan_dom = sp->ch[i].domains_n > 0;
        }
        for (size_t f = 0; f < sp->ch[i].domains_n && g_dch[k].rules_n < MAX_FILES; f++)
            g_dch[k].rules_path[g_dch[k].rules_n++] = sp->ch[i].domains_files[f];
        /* Адресные файлы того же канала — сюда же: доменные строки в них есть у половины
         * категорий издателя (список «Хостинги и CDN» лежит в адресных и целиком состоит
         * из имён), и раньше они пропадали с предупреждением. */
        for (size_t f = 0; f < sp->ch[i].prefixes_n && g_dch[k].rules_n < MAX_FILES; f++)
            g_dch[k].rules_path[g_dch[k].rules_n++] = sp->ch[i].prefixes_files[f];
    }
}
