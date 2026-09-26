/* Spec parsing — see spec.h for why this is shared. */
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <arpa/inet.h>
#include "spec.h"
#include "srsplan.h"
#include "awg.h"   /* имя устройства kind=awg — static inline, без awg.c */
#include "obfs.h"


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
 * sp->ch в порядке спеки, поэтому оба вызывающих получают одно и то же число, не
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
static const char (*chan_from(const struct spec *sp, const struct channel *c, size_t *n))[64] {
    if (c->from_n) { *n = c->from_n; return c->from; }
    *n = sp->from_default_n;
    return sp->from_default;
}

/* Номер списка клиентов среди РАЗЛИЧНЫХ списков, встреченных в спеке, в порядке первого
 * появления. Список по умолчанию участвует в нумерации наравне с прочими: он всё равно
 * попадает в ветку без суффикса, кроме случая realip. */
static int from_disc(const struct spec *sp, const char (*from)[64], size_t from_n) {
    int idx = 0;
    for (size_t i = 0; i < sp->ch_n; i++) {
        size_t cn;
        const char (*cf)[64] = chan_from(sp, &sp->ch[i], &cn);
        if (from_same(cf, cn, from, from_n)) return idx;
        /* Считаем только первое появление каждого списка. */
        int seen = 0;
        for (size_t k = 0; k < i && !seen; k++) {
            size_t kn;
            const char (*kf)[64] = chan_from(sp, &sp->ch[k], &kn);
            seen = from_same(kf, kn, cf, cn);
        }
        if (!seen) idx++;
    }
    return idx;
}

int l4match_same(const struct l4match *a, const struct l4match *b) {
    int ae = l4match_empty(a), be = l4match_empty(b);
    if (ae || be) return ae && be;
    if (a->proto != b->proto || a->ports_n != b->ports_n) return 0;
    /* ПОРЯДОК ЗНАЧИМ, и это сознательно. Два канала с одними диапазонами, записанными в
     * разном порядке, дадут разные группы и разные наборы — то есть лишнее правило вместо
     * слияния. Цена ошибки в эту сторону — одно правило; в другую (счесть разное одним) —
     * молча поделённый набор адресов. Сортировать перед сравнением значило бы завести
     * второй порядок помимо написанного человеком, а он виден в тексте правил. */
    for (size_t i = 0; i < a->ports_n; i++)
        if (a->ports[i].lo != b->ports[i].lo || a->ports[i].hi != b->ports[i].hi) return 0;
    return 1;
}

/* Номер СУЖЕНИЯ среди различных сужений, встреченных в спеке, в порядке первого появления.
 * Нуль — сужения нет.
 *
 * Тот же приём и та же причина, что у from_disc: ядро сливает одноимённые наборы МОЛЧА, и
 * два канала одного выхода с разными портами поделили бы один набор адресов. Тогда
 * ограничение по портам либо распространилось бы на чужие адреса (сузили то, чего не
 * просили), либо пропало бы вовсе (весь TCP к Cloudflare в туннель) — в зависимости от
 * того, чьё правило встанет первым. Номер, а не хэш: номер точен, а хэш мог бы совпасть у
 * двух разных сужений и вернуть ту же беду тихо.
 *
 * Считается по sp->ch в порядке спеки, поэтому компилятор и резолвер получают одно и то же
 * число, не сговариваясь. */
/* Различные сужения клауз наборов, которых нет среди сужений каналов, — в порядке появления. */
struct l4seen { const struct spec *sp; struct l4match *v; size_t n; };
static void l4seen_add(void *ctx, const struct l4match *m) {
    struct l4seen *c = ctx;
    for (size_t i = 0; i < c->sp->ch_n; i++)
        if (!l4match_empty(&c->sp->ch[i].l4) && l4match_same(&c->sp->ch[i].l4, m)) return;
    for (size_t k = 0; k < c->n; k++) if (l4match_same(&c->v[k], m)) return;
    if (c->n < 256) c->v[c->n++] = *m;
}

static int l4_disc(const struct spec *sp, const struct l4match *m) {
    if (l4match_empty(m)) return 0;
    int idx = 0;
    for (size_t i = 0; i < sp->ch_n; i++) {
        const struct l4match *c = &sp->ch[i].l4;
        if (l4match_empty(c)) continue;
        int seen = 0;
        for (size_t k = 0; k < i && !seen; k++)
            seen = l4match_same(&sp->ch[k].l4, c);
        if (seen) continue;                 /* посчитан при первом появлении */
        idx++;
        if (l4match_same(c, m)) return idx;
    }
    /* Сужение не из канала — значит из набора .srs (у клаузы набора своё сужение, см.
     * src/model/srsplan.c). Такие нумеруются ПОСЛЕ сужений каналов, в порядке каналов, файлов и
     * клауз: номера каналов тогда не сдвигаются от того, что в спеке появился набор, и имена
     * наборов у прежних каналов — а от них зависит перенос счётчиков — остаются прежними. */
    static struct l4match seen[256];
    struct l4seen c = { sp, seen, 0 };
    for (size_t i = 0; i < sp->ch_n; i++)
        if (sp->ch[i].srs_n) srs_chan_l4_each(&sp->ch[i], l4seen_add, &c);
    for (size_t k = 0; k < c.n; k++)
        if (l4match_same(&seen[k], m)) return idx + 1 + (int)k;
    /* Недостижимо: сужение приходит из спеки или её наборов. Возвращать здесь нуль значило бы
     * отдать имя без суффикса, то есть ровно то слияние наборов, от которого функция и
     * заведена, — поэтому число, которого ни у кого нет. */
    return idx + 1 + (int)c.n;
}

void group_set_name(const struct spec *sp, char *dst, size_t n, const char *out, const char *kind,
                    const char (*from)[64], size_t from_n, int realip,
                    const struct l4match *l4) {
    /* realip различает только доменные группы: у адресных резолвер не участвует. */
    int rip = realip && !strcmp(kind, "dom");
    int pd = l4_disc(sp, l4);
    /* Ветки без сужения оставлены КАК БЫЛИ, до последнего символа формата. От имени набора
     * зависит перенос счётчиков между применениями (см. counter_find в steer.c), и
     * переименование стоило бы обнулённых объёмов у каждого канала на каждом установленном
     * роутере — при обновлении движка, которое для человека выглядит как «ничего не менял». */
    if (!pd) {
        if (!rip && from_same(from, from_n, sp->from_default, sp->from_default_n)) {
            snprintf(dst, n, "%.24s_%s", out, kind);
            return;
        }
        /* Выход обрезается сильнее, чтобы имя с суффиксом осталось коротким: у наборов
         * nftables на старых ядрах предел длины 32 символа. */
        snprintf(dst, n, "%.18s_%s_c%d%s", out, kind, from_disc(sp, from, from_n), rip ? "r" : "");
        return;
    }
    /* Выход обрезается ещё сильнее: суффиксов теперь два, а предел в 32 символа тот же. */
    snprintf(dst, n, "%.14s_%s_c%d%s_p%d", out, kind, from_disc(sp, from, from_n),
             rip ? "r" : "", pd);
}

/* Имя СОСТАВНОГО набора канала со смешанным сужением (src/model/srsplan.c): у элементов свои
 * протокол и порты, поэтому сужения в имени нет — только выход, вид, клиенты и режим, как у
 * группы без сужения, и свой хвост «_m», чтобы с ней не совпасть. Выход обрезается до 16:
 * имя обязано уложиться в 31 символ (старые ядра). */
void group_set_name_mixed(const struct spec *sp, char *dst, size_t n, const char *out,
                          const char *kind, const char (*from)[64], size_t from_n, int realip) {
    int rip = realip && !strcmp(kind, "dom");
    snprintf(dst, n, "%.16s_%s_c%d%s_m", out, kind, from_disc(sp, from, from_n), rip ? "r" : "");
}

/* Имя доп. группы канала — клауз набора с условиями, которых у канала нет (клиент, приложение,
 * исключения-подсети): номер id задаёт раскладка (номер канала * 100 + порядковый), и рядом с
 * ним остаётся место на «_x» набора исключений. */
void group_set_name_extra(const struct spec *sp, char *dst, size_t n, const char *out,
                          const char *kind, const char (*from)[64], size_t from_n, int realip,
                          unsigned id) {
    int rip = realip && !strcmp(kind, "dom");
    snprintf(dst, n, "%.12s_%s_c%d%s_e%u", out, kind, from_disc(sp, from, from_n),
             rip ? "r" : "", id);
}

/* «443» или «50000-65535» → диапазон портов.
 *
 * ТИРЕ, А НЕ ДВОЕТОЧИЕ, хотя в `.srs` у sing-box записано `port_range 50000:65535`. Тире —
 * это форма, которой у нас уже пишется диапазон АДРЕСОВ в списках (`10.0.9.0-10.0.9.5`), и
 * два синтаксиса диапазона в одной настройке — это вопрос «а тут как?» на каждом поле.
 * Чужую форму переводит тот, кто читает чужой файл, а не спека.
 *
 * Разбор свой, а не strtol по месту, ровно по той причине, по которой заведён num_array:
 * strtol на не-числе НЕ ПРОДВИГАЕТ указатель и возвращает нуль, то есть «abc» без явной
 * проверки прошло бы как порт 0. Проверяется поэтому КАЖДЫЙ символ, и хвост тоже: «1-2-3»
 * это описка, а не «1-2 и ещё что-то».
 *
 * Возврат: 0 — разобрано, -1 — негодная запись. Отказ громкий делает вызывающий: только он
 * знает имя канала, а без имени сообщение не говорит, что чинить. */
static int port_num(const char **pp, long *out) {
    const char *p = *pp;
    if (*p < '0' || *p > '9') return -1;
    long v = 0;
    while (*p >= '0' && *p <= '9') {
        v = v * 10 + (*p++ - '0');
        if (v > 65535) return -1;           /* обрываем до переполнения, а не после */
    }
    if (v < 1) return -1;                   /* порт 0 не адресуем ничем */
    *pp = p;
    *out = v;
    return 0;
}

static int port_range_parse(const char *s, struct port_range *r) {
    long lo = 0, hi = 0;
    const char *p = s;
    if (port_num(&p, &lo) != 0) return -1;
    hi = lo;                                /* одиночный порт — диапазон из одного */
    if (*p == '-') {
        p++;
        if (port_num(&p, &hi) != 0) return -1;
    }
    if (*p) return -1;                      /* хвост: «1-2-3», «443 », «443/tcp» */
    if (lo > hi) return -1;                 /* «9-1» — почти наверняка перепутанные концы */
    r->lo = (unsigned short)lo;
    r->hi = (unsigned short)hi;
    return 0;
}

/* Перечень диапазонов портов канала.
 *
 * Отдельно от str_list, хотя читает такой же массив строк, потому что каждая строка здесь
 * ПРОВЕРЯЕТСЯ на месте: отложить проверку до генерации значило бы отдать негодный элемент
 * в `nft -f`, а тот отвергает НАБОР ПРАВИЛ ЦЕЛИКОМ. На роутере это выглядит как «мой выбор
 * не подействовал» — прежние правила остались, отказа человек не видел. Тот же довод, что у
 * check_address_lists в steer.c, и та же беда, которую он лечит.
 *
 * Пересечения тоже отвергаются здесь: множество nftables с накладывающимися интервалами
 * (`{ 1-100, 50-60 }`) ядро не принимает, а повтор (`{ 443, 443 }`) — тем более. Отказать
 * при загрузке дешевле, чем при применении: при загрузке ничего ещё не изменено.
 *
 * 0 — разобрано, *out_n заполнен; -1 — отказ, текст уже в e->msg (см. правило 5). */
static int port_list(struct js *j, const char *chan, struct port_range *dst, size_t max,
                     size_t *out_n, struct err *e) {
    /* Буфер с запасом: строки русские, в UTF-8 это два байта на букву, и обрезка по границе
     * буфера разрубила бы букву посередине — на этом ломался вывод при первом прогоне
     * стенда однажды уже (см. I-029). */
    char msg[320];
    if (js_lit(j, '[') != 0) {
        snprintf(msg, sizeof(msg), "channels.%.24s: ports — массив строк вида "
                 "[\"443\", \"50000-65535\"]", chan);
        return err_set(e, "%s", msg);
    }
    size_t n = 0;
    js_ws(j);
    if (*j->p == ']') { j->p++; *out_n = 0; return 0; }
    for (;;) {
        char t[32];
        int r = js_str(j, t, sizeof(t), e);
        if (r != 0) {
            if (e->msg[0]) return -1;
            snprintf(msg, sizeof(msg), "channels.%.24s: ports: диапазон пишется СТРОКОЙ "
                     "(\"443\", а не 443)", chan);
            return err_set(e, "%s", msg);
        }
        if (n >= max) {
            snprintf(msg, sizeof(msg), "channels.%.24s: слишком много диапазонов портов "
                     "(предел %zu)", chan, max);
            return err_set(e, "%s", msg);
        }
        if (port_range_parse(t, &dst[n]) != 0) {
            snprintf(msg, sizeof(msg), "channels.%.24s: ports: негодная запись «%.20s» — "
                     "нужно «443» или «50000-65535», числа от 1 до 65535, начало не больше "
                     "конца", chan, t);
            return err_set(e, "%s", msg);
        }
        /* Пересечение с уже прочитанным. Квадрат по шестнадцати записям — это дешевле, чем
         * сортировка, и сообщение остаётся про ту пару, которую человек написал. */
        for (size_t k = 0; k < n; k++)
            if (dst[k].lo <= dst[n].hi && dst[n].lo <= dst[k].hi) {
                snprintf(msg, sizeof(msg), "channels.%.24s: ports: диапазоны %u-%u и %u-%u "
                         "пересекаются — сложите их в один", chan,
                         dst[k].lo, dst[k].hi, dst[n].lo, dst[n].hi);
                return err_set(e, "%s", msg);
            }
        n++;
        js_ws(j);
        if (*j->p == ',') {
            /* См. str_list: висящая запятая — громкий отказ, а не продвижение к ']' и риск
             * зависания вызывающего цикла на несъеденной скобке. */
            j->p++;
            js_ws(j);
            if (*j->p == ']') {
                snprintf(msg, sizeof(msg), "channels.%.24s: ports: висящая запятая "
                         "(ожидалась строка)", chan);
                return err_set(e, "%s", msg);
            }
            continue;
        }
        break;
    }
    js_lit(j, ']');
    *out_n = n;
    return 0;
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
static int parse_obfs(struct js *j, const char *name, struct out_obfs *ob, struct err *e) {
    if (js_lit(j, '{') != 0) return err_set(e, "outputs.%s: obfs должен быть объектом", name);
    char mode[32] = "", server[80] = "", listen[80] = "";
    js_ws(j);
    while (*j->p != '}') {
        char key[32];
        if (js_str(j, key, sizeof(key), e) != 0)
            return err_prop(e, "outputs.%s: плохой ключ в obfs", name);
        if (js_lit(j, ':') != 0) return err_set(e, "outputs.%s: в obfs после ключа нет двоеточия", name);
        if (!strcmp(key, "mode")) { if (js_str(j, mode, sizeof(mode), e) != 0 && e->msg[0]) return -1; }
        else if (!strcmp(key, "server")) { if (js_str(j, server, sizeof(server), e) != 0 && e->msg[0]) return -1; }
        else if (!strcmp(key, "listen")) { if (js_str(j, listen, sizeof(listen), e) != 0 && e->msg[0]) return -1; }
        else { if (js_skip(j, e) != 0) return -1; }
        js_ws(j);
        if (*j->p == ',') { j->p++; js_ws(j); }
    }
    j->p++;

    /* Отсутствующий mode — это сегодняшний единственный режим: спека, написанная до
     * появления второго, обязана значить то же, что значила. Неизвестный — отказ, а не
     * молчаливое «наверное, тот самый»: обфускация, которой нет, выглядит как рабочий
     * выход, из которого не выходит ни один пакет. */
    if (mode[0] && strcmp(mode, "wg-over-tcp") != 0)
        return err_set(e, "outputs.%s: неизвестный obfs.mode (сейчас есть только wg-over-tcp)", name);
    if (!server[0]) return err_set(e, "outputs.%s: obfs нужен server вида адрес:порт", name);
    if (obfs_split_hostport(server, ob->server, sizeof(ob->server),
                            &ob->server_port) != 0)
        return err_set(e, "outputs.%s: obfs.server должен быть вида адрес:порт", name);
    /* Имя, а не адрес — отказ. Имя пришлось бы разрешать, и разрешать его через тот
     * самый DNS, который может идти в туннель, который поднимается через этот самый
     * сервер. Управляющий слой резолвит один раз и кладёт сюда адрес — то же правило,
     * что со списками: движок читает то, что ему положили. */
    struct in_addr tmp;
    if (inet_pton(AF_INET, ob->server, &tmp) != 1)
        return err_set(e, "outputs.%s: obfs.server должен быть адресом, а не именем", name);

    if (!listen[0]) return err_set(e, "outputs.%s: obfs нужен listen — тот же адрес и порт, что в "
                        "Endpoint пира WireGuard", name);
    if (obfs_split_hostport(listen, ob->listen, sizeof(ob->listen),
                            &ob->listen_port) != 0)
        return err_set(e, "outputs.%s: obfs.listen должен быть вида адрес:порт", name);
    if (inet_pton(AF_INET, ob->listen, &tmp) != 1)
        return err_set(e, "outputs.%s: obfs.listen должен быть адресом, а не именем", name);
    ob->on = 1;
    return 0;
}

static int parse_outputs(struct js *j, struct spec *s, struct err *e) {
    if (js_lit(j, '{') != 0) return err_set(e, "outputs: expected an object", NULL);
    js_ws(j);
    if (*j->p == '}') { j->p++; return 0; }
    for (;;) {
        struct output o = {0};
        /* Ключи видов — сюда, до того как известен вид: `kind` может стоять в объекте последним.
         * Разбираются они здесь для всех видов, в том числе не вошедших в сборку: ошибка в
         * значении ключа и отказ «ключ чужого вида» обязаны звучать одинаково в любой сборке.
         * Что значения значат, решает вид (kind_ops.parse). */
        struct out_keys k = {0};
        if (js_str(j, o.name, sizeof(o.name), e) != 0)
            return err_prop(e, "outputs: expected a name", NULL);
        /* Состав имени — см. name_ok(). Оно уходит в командную строку через diag и в имя
         * набора, поэтому проверяется здесь, один раз, а не у каждого вызова. */
        if (!name_ok(o.name))
            return err_set(e, "outputs.%s: в имени выхода можно только буквы, цифры, _ - и точку", o.name);
        if (js_lit(j, ':') != 0) return err_set(e, "outputs.%s: expected ':'", o.name);
        if (js_lit(j, '{') != 0) return err_set(e, "outputs.%s: expected an object", o.name);
        char kind[32] = "";
        js_ws(j);
        while (*j->p != '}') {
            char key[32];
            if (js_str(j, key, sizeof(key), e) != 0) return err_prop(e, "outputs.%s: bad key", o.name);
            if (js_lit(j, ':') != 0) return err_set(e, "outputs.%s: после ключа нет двоеточия", o.name);
            if (!strcmp(key, "kind")) { if (js_str(j, kind, sizeof(kind), e) != 0 && e->msg[0]) return -1; }
            else if (!strcmp(key, "device")) {
                if (js_str(j, o.device, sizeof(o.device), e) != 0 && e->msg[0]) return -1;
                if (!name_ok(o.device))
                    return err_set(e, "outputs.%s: имя устройства негодного состава", o.name);
            }
            else if (!strcmp(key, "devices")) {
                /* Кандидаты в порядке предпочтения. Единственное число остаётся
                 * сокращением для одного — прежние спеки не ломаются. */
                if (js_lit(j, '[') == 0) {
                    js_ws(j);
                    if (*j->p == ']') j->p++;
                    else for (;;) {
                        char t[32];
                        int r = js_str(j, t, sizeof(t), e);
                        if (r != 0) { if (e->msg[0]) return -1; break; }
                        if (o.devices_n >= MAX_DEVICES) return err_set(e, "outputs.%s: too many devices", o.name);
                        if (!name_ok(t)) return err_set(e, "outputs.%s: имя устройства негодного состава", o.name);
                        snprintf(o.devices[o.devices_n++], 32, "%s", t);
                        js_ws(j);
                        if (*j->p == ',') {
                            /* См. str_list: trailing comma → отказ, не продвижение к ']' и
                             * риск зависания parse_outputs на несъеденной скобке. */
                            j->p++;
                            js_ws(j);
                            if (*j->p == ']') return err_set(e, "outputs.%s: trailing comma in devices", o.name);
                            continue;
                        }
                        js_lit(j, ']');
                        break;
                    }
                }
            }
            else if (!strcmp(key, "obfs")) { if (parse_obfs(j, o.name, &k.obfs, e) != 0) return -1; }
            else if (!strcmp(key, "sub_file")) { if (js_str(j, k.sub_file, sizeof(k.sub_file), e) != 0 && e->msg[0]) return -1; }
            else if (!strcmp(key, "conf")) { if (js_str(j, k.conf, sizeof(k.conf), e) != 0 && e->msg[0]) return -1; }
            /* Файл ключей nfqws у kind=zapret. Отдельным ключом, а не переиспользованным
             * `conf`: у xsteer там конфигурация в стиле wg с приватным ключом, здесь —
             * список ключей командной строки, и одно имя для двух разных вещей однажды
             * привело бы к попытке поднять туннель по стратегии обхода. */
            else if (!strcmp(key, "opts_file")) { if (js_str(j, k.opts_file, sizeof(k.opts_file), e) != 0 && e->msg[0]) return -1; }
            else if (!strcmp(key, "domain")) { if (js_str(j, k.domain, sizeof(k.domain), e) != 0 && e->msg[0]) return -1; }
            /* Через какой выход идёт трафик самого туннеля — см. блок «вложенные выходы» в
             * spec.h. Состав имени проверяется тем же name_ok, что имя выхода: строка уходит в
             * status и в подпись помощника, а годное имя выхода по-другому и не выглядит.
             * Всё остальное (есть ли такой выход, годится ли он, нет ли круга) проверяет
             * via_check после разбора — цель может стоять в спеке ниже. */
            else if (!strcmp(key, "via")) {
                /* Пустая строка — «напрямую», как отсутствие ключа: так поле очищает
                 * интерфейс, который держит его в форме, и отказ на ней был бы придиркой. */
                if (js_str(j, o.via, sizeof(o.via), e) != 0 && e->msg[0]) return -1;
                if (o.via[0] && !name_ok(o.via))
                    return err_set(e, "outputs.%s: via — имя другого выхода (буквы, цифры, _ - и точка)",
                        o.name);
            }
            /* Транспорт выхода xsteer. Полем спеки, а не только ключом командной строки,
             * потому что процесс поднимает procd: ключи ему передать негде, а настройка
             * обязана переживать перезагрузку. */
            /* Проверяем на 't', как соседнее `enabled` проверяется на 'f': значение здесь
             * либо true, либо false, и разбирать его полноценным разбором JSON незачем. */
            else if (!strcmp(key, "stream")) { js_ws(j); k.stream = (*j->p == 't'); if (js_skip(j, e) != 0) return -1; }
            else if (!strcmp(key, "stream_port")) {
                long v = 0;
                if (js_num(j, &v, e) != 0) return -1;
                k.stream_port = (int)v;
            }
            /* `node` — сокращение для списка из одного узла, `nodes` — сам список. Дальше по
             * коду путь один, ровно как у `device`/`devices`. Прежнее `-1` («первый рабочий»)
             * записывается пустым списком: это то же самое умолчание, только выраженное
             * отсутствием кандидатов, а не отрицательным номером. */
            else if (!strcmp(key, "node")) {
                long v = 0;
                if (js_num(j, &v, e) != 0) return -1;
                k.node_one = 1;
                if (v >= 0) { k.nodes[0] = (int)v; k.nodes_n = 1; }
                else k.nodes_n = 0;
            }
            else if (!strcmp(key, "nodes")) {
                if (num_array(j, k.nodes, MAX_NODE_SEL, &k.nodes_n, e) != 0)
                    return err_prop(e, "outputs.%s: nodes — массив номеров узлов подписки", o.name);
                k.node_many = 1;
            }
            else if (!strcmp(key, "on_fail")) {
                char m[16];
                if (js_str(j, m, sizeof(m), e) != 0 && e->msg[0]) return -1;
                if (!strcmp(m, "drop")) o.on_fail = FAIL_DROP;
                else if (!strcmp(m, "direct")) o.on_fail = FAIL_DIRECT;
                /* zapret на телефоне нет — см. out_skips_zapret в spec.h. */
                else if (!strcmp(m, "zapret") && !plat()->zapret)
                    return err_set(e, "outputs.%s: on_fail zapret — в сборке под Android zapret нет "
                        "(want drop or direct)", o.name);
                else if (!strcmp(m, "zapret")) o.on_fail = FAIL_ZAPRET;
                else if (!plat()->zapret)
                    return err_set(e, "outputs.%s: unknown on_fail (want drop or direct)", o.name);
                else return err_set(e, "outputs.%s: unknown on_fail (want drop, direct or zapret)", o.name);
            }
            /* Вторая ось сторожа. Значение по умолчанию — `order`, то есть сегодняшнее
             * поведение; см. рассуждение у поля prefer_latency в spec.h. */
            else if (!strcmp(key, "prefer")) {
                char m[16];
                if (js_str(j, m, sizeof(m), e) != 0 && e->msg[0]) return -1;
                if (!strcmp(m, "latency")) o.prefer_latency = 1;
                else if (strcmp(m, "order") != 0)
                    return err_set(e, "outputs.%s: unknown prefer (want order or latency)", o.name);
            }
            else if (!strcmp(key, "latency_tolerance_ms")) {
                long v = 0;
                if (js_num(j, &v, e) != 0) return -1;
                /* Ноль законен и означает «переключаться на любое улучшение». Отрицательное
                 * — нет: оно означало бы «переключаться на ухудшение», и это не настройка, а
                 * опечатка, которую надо назвать. */
                if (v < 0 || v > 60000)
                    return err_set(e, "outputs.%s: latency_tolerance_ms — от 0 до 60000", o.name);
                o.lat_tolerance_ms = (int)v;
            }
            else if (!strcmp(key, "latency_interval_s")) {
                long v = 0;
                if (js_num(j, &v, e) != 0) return -1;
                /* Нижний предел не косметика: замер опрашивает ВСЕХ кандидатов, и интервал
                 * короче тика сторожа означал бы замер на каждом тике — то есть таймаут за
                 * каждого мёртвого кандидата каждую минуту. */
                if (v < 30 || v > 86400)
                    return err_set(e, "outputs.%s: latency_interval_s — от 30 до 86400", o.name);
                o.lat_interval_s = (int)v;
            }
            else { if (js_skip(j, e) != 0) return -1; }
            js_ws(j);
            if (*j->p == ',') { j->p++; js_ws(j); }
        }
        j->p++;
        /* Вид — по имени из реестра (src/kinds/kind.c). Вид, не вошедший в сборку, отвечает своей
         * строкой отказа СРАЗУ, а не при подъёме: иначе спека применяется, правила встают, и выход
         * молча никуда не ведёт. */
        const struct kind_ops *kd = kind_by_name(kind);
        if (!kd) return err_set(e, "outputs.%s: неизвестный kind "
                   "(нужен direct, interface, vless, xsteer, zapret, tgws или awg)", o.name);
        if (kd->absent) {
            static char msg[256];
            snprintf(msg, sizeof(msg), "outputs.%s: %s", o.name, kd->absent);
            return err_set(e, "%s", msg);
        }
        o.kind = kd;
        if (kd->parse && kd->parse(&o, &k, e) != 0) return -1;
        /* КЛЮЧ ЧУЖОГО ВИДА — отказ. Поле, принятое молча у чужого вида выхода, — это
         * «настроено», сказанное о том, что не настроено. Проверки стоят ПОСЛЕ разбора вида,
         * и порядок их прежний: сообщение называет первый чужой ключ.
         *
         * Обфускация осмысленна только там, где транспорт — чужой UDP, до которого
         * движку не дотянуться иначе. У vless свой транспорт внутри движка (и свои
         * средства маскировки — Reality), у xsteer он свой и поддельный TCP уже внутри
         * него, у direct транспорта нет вовсе. Режим потока — свойство транспорта xsteer. */
        if (k.obfs.on && !(kd->keys & KK_OBFS))
            return err_set(e, "outputs.%s: obfs есть только у kind=interface", o.name);
        if ((k.stream || k.stream_port) && !(kd->keys & KK_STREAM))
            return err_set(e, "outputs.%s: stream есть только у kind=xsteer", o.name);
        if (k.opts_file[0] && !(kd->keys & KK_OPTS))
            return err_set(e, "outputs.%s: opts_file есть только у kind=zapret", o.name);
        if (k.domain[0] && !(kd->keys & KK_DOMAIN))
            return err_set(e, "outputs.%s: domain есть только у kind=tgws", o.name);
        /* Своя проверка вида после общих — то, что зависит от общих полей (on_fail у zapret и
         * tgws). */
        if (kd->check && kd->check(s, &o, e) != 0) return -1;
        /* Какой из двух форм записан выбор узлов. Нужно, чтобы отличить «поля нет» от «поле
         * задано» и поймать выход, где заданы обе: молча взять одну значило бы, что половина
         * написанного человеком не действует, и понять это было бы нечем (тот же приём, что
         * у lan_device/lan_devices в load_spec). */
        if (k.node_one && k.node_many)
            return err_set(e, "outputs.%s: задано и node, и nodes — оставьте одно", o.name);
        /* Выбор узлов есть только у подписки. Отвергается ТОЛЬКО новая форма: `nodes` не
         * может стоять в спеке, написанной до этой версии, а `node` там стоять мог — и у
         * чужого вида выхода он и раньше ничего не делал. Отказать на нём сейчас значило бы
         * сломать применение спеки, которая работала, ради поля, которое ничего не меняет. */
        if (k.node_many && !(kd->keys & KK_NODES))
            return err_set(e, "outputs.%s: nodes есть только у kind=vless — это номера узлов подписки",
                o.name);
        /* Дубликат номера делает перебор бессмысленным ровно так же, как дубликат устройства
         * в devices: второй кандидат ничем не отличается от первого. */
        for (size_t a = 0; a < k.nodes_n; a++)
            for (size_t b = a + 1; b < k.nodes_n; b++)
                if (k.nodes[a] == k.nodes[b])
                    return err_set(e, "outputs.%s: узел подписки указан в nodes дважды", o.name);
        if (s->out_n >= MAX_OUTPUTS) return err_set(e, "too many outputs", NULL);
        /* Два выхода с одним именем: реестр раздаст две метки, init поднимет два процесса
         * на одно имя, а out_by_name всегда возьмёт первый — как у devices и nodes, это
         * отказ, не молчаливая победа одного из двух. */
        for (size_t a = 0; a < s->out_n; a++)
            if (!strcmp(s->out[a].name, o.name))
                return err_set(e, "outputs.%s: имя выхода повторяется", o.name);
        s->out[s->out_n++] = o;
        js_ws(j);
        if (*j->p == ',') { j->p++; continue; }
        break;
    }
    /* Закрывающая скобка обязательна: без неё это оборванный файл (питание пропало посреди
     * записи), и половина спеки применялась бы без единой жалобы. */
    if (js_lit(j, '}') != 0) return err_set(e, "outputs: нет закрывающей скобки — спека оборвана?", NULL);
    return 0;
}

static int parse_channels(struct js *j, struct spec *s, struct err *e) {
    if (js_lit(j, '[') != 0) return err_set(e, "channels: expected an array", NULL);
    js_ws(j);
    if (*j->p == ']') { j->p++; return 0; }
    for (;;) {
        struct channel c = {0};
        /* Какой из двух форм записаны списки совпадения — как у device/devices: заданы обе
         * значит половина написанного человеком молча не действует. */
        int pf_one = 0, pf_many = 0, df_one = 0, df_many = 0, sf_one = 0, sf_many = 0;
        if (js_lit(j, '{') != 0) return err_set(e, "channels: expected an object", NULL);
        js_ws(j);
        while (*j->p != '}') {
            char key[32];
            if (js_str(j, key, sizeof(key), e) != 0) return err_prop(e, "channels: bad key", NULL);
            if (js_lit(j, ':') != 0) return err_set(e, "channels: после ключа «%s» нет двоеточия", key);
            if (!strcmp(key, "name")) { if (js_str(j, c.name, sizeof(c.name), e) != 0 && e->msg[0]) return -1; }
            else if (!strcmp(key, "out")) { if (js_str(j, c.out, sizeof(c.out), e) != 0 && e->msg[0]) return -1; }
            else if (!strcmp(key, "from")) { if (str_array(j, c.from, MAX_FROM, &c.from_n, e) != 0 && e->msg[0]) return -1; }
            /* СХЕМА 2: правило на одно устройство, старше глобальных по построению.
             * Разрешено только при `schema: 2` — проверяется ниже, вместе с proto/ports, и
             * по той же причине: движок постарше ключ пропустит и положит правило в порядке
             * спеки, то есть исключение для телефона проиграет глобальному правилу молча. */
            else if (!strcmp(key, "scope")) {
                char sc[16];
                if (js_str(j, sc, sizeof(sc), e) != 0 && e->msg[0]) return -1;
                if (!strcmp(sc, "device")) { c.dev_scope = 1; c.l4_written = 1; }
                else if (strcmp(sc, "global") != 0)
                    return err_set(e, "channels.%s: unknown scope (want device or global)", c.name);
            }
            /* Отсутствие поля и `true` значат одно: правило работает, — спека без этого
             * поля обязана вести себя как прежде. «Нет» — и `false`, и `0`: jshn пишет
             * логическое значение то словом, то единицей (см. any ниже), а проверка по
             * первой букве 'f' включала канал, выключенный человеком, на `"enabled":0`
             * (I-315). Непонятное значение канал по-прежнему не выключает, но называется. */
            else if (!strcmp(key, "enabled")) {
                js_ws(j);
                const char *v = j->p;
                if (js_skip(j, e) != 0) return -1;
                size_t vl = (size_t)(j->p - v);
                while (vl && (v[vl - 1] == ' ' || v[vl - 1] == '\t' ||
                              v[vl - 1] == '\n' || v[vl - 1] == '\r')) vl--;
                if ((vl == 5 && !strncmp(v, "false", 5)) || (vl == 1 && *v == '0'))
                    c.disabled = 1;
                else if (!(vl == 4 && !strncmp(v, "true", 4)) && !(vl == 1 && *v == '1'))
                    fprintf(stderr, "steer[warn] channels.%s: enabled=%.*s не понят — канал "
                            "остаётся включённым; запишите true или false\n",
                            c.name[0] ? c.name : "?", (int)(vl > 16 ? 16 : vl), v);
            }
            else if (!strcmp(key, "match")) {
                if (js_lit(j, '{') != 0) return err_set(e, "channels.%s: match must be an object", c.name);
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
                    if (js_str(j, mk, sizeof(mk), e) != 0)
                        return err_prop(e, "channels.%s: match: expected a key", c.name);
                    if (js_lit(j, ':') != 0)
                        return err_set(e, "channels.%s: match: expected ':'", c.name);
                    /* Singular is shorthand for a one-element list, so a spec written
                     * before this stayed valid. */
                    if (!strcmp(mk, "prefixes_file")) {
                        if (pf_many) return err_set(e, "channels.%s: prefixes_file рядом с prefixes_files", c.name);
                        pf_one = 1;
                        char one[256];
                        int r = js_str(j, one, sizeof(one), e);
                        if (r != 0 && e->msg[0]) return -1;
                        if (r == 0) {
                            const char *kept = keep(one, e);
                            if (!kept) return -1;
                            c.prefixes_files[0] = kept;
                            c.prefixes_n = 1;
                        }
                    } else if (!strcmp(mk, "domains_file")) {
                        if (df_many) return err_set(e, "channels.%s: domains_file рядом с domains_files", c.name);
                        df_one = 1;
                        char one[256];
                        int r = js_str(j, one, sizeof(one), e);
                        if (r != 0 && e->msg[0]) return -1;
                        if (r == 0) {
                            const char *kept = keep(one, e);
                            if (!kept) return -1;
                            c.domains_files[0] = kept;
                            c.domains_n = 1;
                        }
                    } else if (!strcmp(mk, "prefixes_files")) {
                        if (pf_one) return err_set(e, "channels.%s: prefixes_files рядом с prefixes_file", c.name);
                        pf_many = 1;
                        size_t sl = str_list(j, c.prefixes_files, MAX_FILES, e);
                        if (sl == (size_t)-1) return -1;
                        c.prefixes_n = sl;
                    } else if (!strcmp(mk, "domains_files")) {
                        if (df_one) return err_set(e, "channels.%s: domains_files рядом с domains_file", c.name);
                        df_many = 1;
                        size_t sl = str_list(j, c.domains_files, MAX_FILES, e);
                        if (sl == (size_t)-1) return -1;
                        c.domains_n = sl;
                    }
                    /* Наборы sing-box (`.srs`) — полноценный источник списка: имена из них
                     * берёт резолвер, подсети — компилятор, сужение по протоколу и портам
                     * применяется к каналу само (src/model/srs.c, src/compile/groups.c). Форма —
                     * та же пара, что у prefixes_file/prefixes_files. Содержимое здесь не
                     * читается: разбор спеки не открывает списков, их открывает тот, кому они
                     * нужны. */
                    else if (!strcmp(mk, "srs_file")) {
                        if (sf_many) return err_set(e, "channels.%s: srs_file рядом с srs_files", c.name);
                        sf_one = 1;
                        char one[256];
                        int r = js_str(j, one, sizeof(one), e);
                        if (r != 0 && e->msg[0]) return -1;
                        if (r == 0) {
                            const char *kept = keep(one, e);
                            if (!kept) return -1;
                            c.srs_files[0] = kept;
                            c.srs_n = 1;
                        }
                    } else if (!strcmp(mk, "srs_files")) {
                        if (sf_one) return err_set(e, "channels.%s: srs_files рядом с srs_file", c.name);
                        sf_many = 1;
                        size_t sl = str_list(j, c.srs_files, MAX_FILES, e);
                        if (sl == (size_t)-1) return -1;
                        c.srs_n = sl;
                    }
                    else if (!strcmp(mk, "mode")) {
                        char m[16];
                        if (js_str(j, m, sizeof(m), e) != 0 && e->msg[0]) return -1;
                        if (!strcmp(m, "realip")) {
                            c.realip = 1;
                            /* РЕЖИМ УХОДИТ (решение владельца, запуск 65), но принимается
                             * по-прежнему: спеки с ним уже лежат на роутерах, и отказ
                             * означал бы, что обновление движка снимает маршрутизацию.
                             * Поэтому предупреждение, а не die, — и с уровнем, потому что
                             * спека разобрана и работа продолжается.
                             *
                             * Что теряется при переходе на fakeip: читаемость traceroute.
                             * В real-IP ответ идёт клиенту нетронутым, DNAT нет, ICMP не
                             * переписывается и трассировка показывает настоящие узлы (см.
                             * dnsd.c). Взамен fakeip даёт точность на домен: в real-IP два
                             * домена за одним адресом склеиваются, и если они в разных
                             * каналах, первый разрешённый решает за оба. Пул поддельных
                             * адресов исчерпать нечем — 198.18.0.0/15 это 131072 адреса
                             * против полутора тысяч имён в самом большом списке. */
                            fprintf(stderr, "steer[warn] channel %s: mode=realip уходит из "
                                    "движка — переведите канал на fakeip; сейчас режим ещё "
                                    "работает\n", c.name);
                        }
                        else if (strcmp(m, "fakeip") != 0) return err_set(e, "channels: unknown mode %s (want fakeip or realip)", m);
                    }
                    /* ---- СХЕМА 2: протокол и порты назначения ----------------------
                     *
                     * Разрешены только при `schema: 2`, и проверяется это НЕ ЗДЕСЬ, а в
                     * load_spec: у JSON нет порядка ключей, и `schema` законно стоит после
                     * `channels`. Здесь запоминаем сам факт (l4_written), а судим потом,
                     * когда прочитан весь документ. */
                    else if (!strcmp(mk, "proto")) {
                        char pr[16] = "";
                        if (js_str(j, pr, sizeof(pr), e) != 0)
                            return err_prop(e, "channels.%s: proto — строка: tcp, udp или both", c.name);
                        c.l4_written = 1;
                        if (!strcmp(pr, "tcp")) c.l4.proto = CH_PROTO_TCP;
                        else if (!strcmp(pr, "udp")) c.l4.proto = CH_PROTO_UDP;
                        /* `both` — записанное умолчание: сужения по протоколу из него не
                         * выходит. Принимается затем, чтобы у интерфейса с тремя пунктами в
                         * списке не было особого случая «третий пункт — не писать ключ». */
                        else if (!strcmp(pr, "both")) c.l4.proto = CH_PROTO_ANY;
                        else {
                            char msg[160];
                            snprintf(msg, sizeof(msg), "channels.%.24s: неизвестный proto "
                                     "«%.12s» (нужен tcp, udp или both)", c.name, pr);
                            return err_set(e, "%s", msg);
                        }
                    }
                    else if (!strcmp(mk, "ports")) {
                        c.l4_written = 1;
                        if (port_list(j, c.name, c.l4.ports, MAX_PORTS, &c.l4.ports_n, e) != 0) return -1;
                    }
                    /* «Да» — и `true`, и `1`. Спеку пишет не только человек: jshn у OpenWrt
                     * в разных сборках выдаёт логическое значение то словом, то единицей, а
                     * канал, чьё `any` не понято, объявляется «не подходящим ни к чему» и
                     * роняет всю спеку. Ошибка при этом выглядит как «сплошной канал не
                     * работает», хотя написан он верно. */
                    else if (!strcmp(mk, "any")) { js_ws(j); c.any = (*j->p == 't' || *j->p == '1'); if (js_skip(j, e) != 0) return -1; }
                    else if (!strcmp(mk, "allow_all")) { js_ws(j); c.allow_all = (*j->p == 't' || *j->p == '1'); if (js_skip(j, e) != 0) return -1; }
                    else { if (js_skip(j, e) != 0) return -1; }
                    js_ws(j);
                    if (*j->p == ',') { j->p++; js_ws(j); }
                }
                j->p++;
            }
            else { if (js_skip(j, e) != 0) return -1; }
            js_ws(j);
            if (*j->p == ',') { j->p++; js_ws(j); }
        }
        j->p++;
        if (!c.name[0]) return err_set(e, "a channel has no name", NULL);
        /* Подпись, а не идентификатор: по-русски — можно, кавычкой — нельзя (см. label_ok). */
        if (!label_ok(c.name))
            return err_set(e, "channel %s: в имени нельзя кавычку, обратную косую и управляющие символы", c.name);
        if (!c.out[0]) return err_set(e, "channel %s has no out", c.name);
        /* ПОРТЫ ИСТОЧНИКОМ СОВПАДЕНИЯ НЕ ЯВЛЯЮТСЯ, и в это условие они не входят
         * намеренно. «Канал ловит по портам» выразить нечем: правило без `ip daddr @набор`
         * безусловно, то есть udp 50000-65535 ко ВСЕМУ интернету уехало бы в туннель. Порты
         * без списка адресов — это недописанная настройка, и отказ на ней прежний. */
        if (!c.prefixes_n && !c.domains_n && !c.srs_n && !c.any)
            return err_set(e, "channel %s matches nothing (want prefixes_files, domains_files or any)", c.name);
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
        if (s->ch_n >= MAX_CHANNELS) return err_set(e, "too many channels", NULL);
        s->ch[s->ch_n++] = c;
        js_ws(j);
        if (*j->p == ',') { j->p++; continue; }
        break;
    }
    if (js_lit(j, ']') != 0) return err_set(e, "channels: нет закрывающей скобки — спека оборвана?", NULL);
    return 0;
}

/* ---- вложенные выходы: проверка `via` --------------------------------------------------
 *
 * Смысл поля — в блоке «вложенные выходы» в spec.h. Здесь — то, что обязано быть отказом, а не
 * применённой спекой, и у каждого отказа своя причина:
 *
 *   - `via` у выхода без своего соединения с сервером (direct, zapret, tgws, обычный interface)
 *     ничего бы не сделало: метку ставит тот, кто открывает сокет (или, у awg, настраивает
 *     устройство), а у этих видов его открывает не движок. Принять поле молча — сказать «настроено», не настроив;
 *   - цели нет в спеке или она без устройства — метке некуда вести, и туннель тихо ушёл бы
 *     напрямую (правила на метку нет — пакет идёт по main);
 *   - круг (a → b → a, в том числе a → a) — пакет туннеля вечно заворачивался бы сам в себя:
 *     соединение a идёт в устройство b, соединение b — в устройство a, и не встаёт ни одно;
 *   - круг ЧЕРЕЗ ПУЛ: цель — выход kind=interface, среди устройств которого устройство самого
 *     выхода или выхода, который сам зависит от него. Снаружи в спеке круга не видно — он
 *     проходит через имя устройства, — а по сути это тот же круг, только проявится он лишь в
 *     тот момент, когда сторож переключит пул на это устройство;
 *   - цепочка длиннее MAX_VIA_DEPTH переходов — скорее описка, чем замысел (см. spec.h).
 *
 * Проверяется ПОСЛЕ разбора всех выходов: цель может стоять ниже того, кто на неё ссылается. */
static int via_idx(const struct spec *sp, const struct output *o) { return (int)(o - sp->out); }

/* Выход, которому принадлежит устройство пула, — тот же ответ, что device_owner в failover.c
 * (владелец — выход, чей процесс устройство создаёт). Своя копия, а не вызов: specmatch
 * собирает этот файл без failover.c. Отвечает она на узкий вопрос этой проверки и расходиться
 * с той функцией ей негде — обе смотрят на out_engine_managed и имя устройства. */
static const struct output *via_dev_owner(const struct spec *sp, const char *dev, const struct output *not) {
    for (size_t i = 0; i < sp->out_n; i++)
        if (&sp->out[i] != not && out_engine_managed(&sp->out[i]) && !strcmp(sp->out[i].device, dev))
            return &sp->out[i];
    return NULL;
}

static int via_check(const struct spec *sp, struct err *e) {
    static char msg[512];
    for (size_t i = 0; i < sp->out_n; i++) {
        const struct output *o = &sp->out[i];
        if (!o->via[0]) continue;
        if (!out_via_capable(o)) {
            snprintf(msg, sizeof(msg),
                     "выход %.31s: via есть только у выходов со своим соединением с сервером — "
                     "vless, xsteer, awg и interface с obfs; у kind=%s соединение открывает не движок, "
                     "и пустить его через другой выход нечем", o->name,
                     kind_of(o)->novia ? kind_of(o)->novia : kind_of(o)->name);
            return err_set(e, "%s", msg);
        }
        if (!strcmp(o->via, o->name))
            return err_set(e, "выход %s: via указывает на него самого — туннель не может идти внутри себя",
                o->name);
        const struct output *v = out_via(sp, o);
        if (!v) {
            snprintf(msg, sizeof(msg), "выход %.31s: via «%.31s» — такого выхода в спеке нет",
                     o->name, o->via);
            return err_set(e, "%s", msg);
        }
        if (!out_via_target_ok(v)) {
            snprintf(msg, sizeof(msg),
                     "выход %.31s: via «%.31s» — это kind=%s, у него нет устройства, в которое "
                     "можно пустить туннель (нужен выход с устройством: interface, vless, xsteer, awg)",
                     o->name, v->name, kind_of(v)->name);
            return err_set(e, "%s", msg);
        }

        /* Цепочка по одним via: круг и глубина. Путь печатается целиком — по одному имени
         * человек круга не найдёт, если в спеке шестнадцать выходов. */
        char path[256];
        int on_path[MAX_OUTPUTS] = {0};
        size_t pl = (size_t)snprintf(path, sizeof(path), "%s", o->name);
        on_path[via_idx(sp, o)] = 1;
        int hops = 0;
        for (const struct output *t = o, *n; (n = out_via(sp, t)); t = n) {
            hops++;
            if (pl < sizeof(path))
                pl += (size_t)snprintf(path + pl, sizeof(path) - pl, " → %s", n->name);
            if (on_path[via_idx(sp, n)]) {
                snprintf(msg, sizeof(msg), "выход %.31s: via замыкается в круг (%s) — туннели "
                         "заворачивались бы друг в друга, и не встал бы ни один", o->name, path);
                return err_set(e, "%s", msg);
            }
            on_path[via_idx(sp, n)] = 1;
            if (hops > MAX_VIA_DEPTH) {
                snprintf(msg, sizeof(msg), "выход %.31s: цепочка via длиннее %d переходов (%s)",
                         o->name, MAX_VIA_DEPTH, path);
                return err_set(e, "%s", msg);
            }
        }

        /* Круг через пул: обход всего, во что может уйти трафик туннеля o, — цели via и
         * владельцев устройств в пулах целей. Встретить устройство самого o или сам o — круг. */
        int seen[MAX_OUTPUTS] = {0};
        int stack[MAX_OUTPUTS * (MAX_DEVICES + 1)];
        /* Не "sp": имя занято параметром const struct spec *sp этой функции. */
        int top = 0;
        stack[top++] = via_idx(sp, v);
        while (top) {
            const struct output *t = &sp->out[stack[--top]];
            if (seen[via_idx(sp, t)]) continue;
            seen[via_idx(sp, t)] = 1;
            if (t == o) {
                snprintf(msg, sizeof(msg), "выход %.31s: via замыкается в круг через устройства "
                         "пула — туннель однажды пошёл бы внутрь себя", o->name);
                return err_set(e, "%s", msg);
            }
            for (size_t d = 0; d < t->devices_n; d++) {
                for (size_t k = 0; k < o->devices_n; k++)
                    if (!strcmp(t->devices[d], o->devices[k])) {
                        snprintf(msg, sizeof(msg), "выход %.31s: via ведёт в %.31s, а среди его "
                                 "устройств %.31s — устройство самого выхода, туннель пошёл бы "
                                 "внутрь себя", o->name, t->name, t->devices[d]);
                        return err_set(e, "%s", msg);
                    }
                const struct output *w = via_dev_owner(sp, t->devices[d], t);
                if (w && !seen[via_idx(sp, w)]) stack[top++] = via_idx(sp, w);
            }
            const struct output *n = out_via(sp, t);
            if (n && !seen[via_idx(sp, n)]) stack[top++] = via_idx(sp, n);
        }
    }
    return 0;
}

int load_spec(const char *path, struct spec *s, struct err *e) {
    /* Спека — значение (правило 6): экземпляр обнуляется здесь, а не оставляется на
     * совести вызывающего, и получает те же умолчания, что раньше стояли инициализаторами
     * глобалов — один br-lan клиентским устройством, всё остальное пусто/нуль. */
    memset(s, 0, sizeof(*s));
    snprintf(s->lan_dev[0], sizeof(s->lan_dev[0]), "br-lan");
    s->lan_dev_n = 1;
    FILE *f = strcmp(path, "-") ? fopen(path, "r") : stdin;
    if (!f) return err_set(e, "%s: cannot open", path);
    static char buf[262144];
    size_t n = fread(buf, 1, sizeof(buf) - 1, f);
    if (n == sizeof(buf) - 1) {
        int c = fgetc(f);
        if (c != EOF) {
            if (f != stdin) fclose(f);
            return err_set(e, "spec too large (max 256 KiB)", NULL);
        }
    }
    buf[n] = '\0';
    if (f != stdin) fclose(f);

    struct js j = { buf };
    long schema = -1;
    /* Какой из двух форм записано локальное устройство. Нужно, чтобы отличить «поля нет» от
     * «поле задано» и поймать спеку, где заданы обе: молча взять одну значило бы, что
     * половина написанного человеком не действует, и понять это было бы нечем. */
    int lan_one = 0, lan_many = 0;
    if (js_lit(&j, '{') != 0) return err_set(e, "spec: expected an object", NULL);
    js_ws(&j);
    while (*j.p && *j.p != '}') {
        char key[64];
        if (js_str(&j, key, sizeof(key), e) != 0) return err_prop(e, "spec: bad key", NULL);
        /* Возврат проверяется, как в цикле match: без этого {"kind" "direct"} читался как
         * {"kind":"direct"} — не JSON, который интерфейс не разберёт, а движок молча принимал
         * (I-315). То же в циклах выходов, каналов и obfs. */
        if (js_lit(&j, ':') != 0) return err_set(e, "spec: после ключа «%s» нет двоеточия", key);
        if (!strcmp(key, "schema")) {
            long v = 0;
            if (js_num(&j, &v, e) != 0) return -1;
            schema = v;
        }
        else if (!strcmp(key, "outputs")) { if (parse_outputs(&j, s, e) != 0) return -1; }
        else if (!strcmp(key, "channels")) { if (parse_channels(&j, s, e) != 0) return -1; }
        else if (!strcmp(key, "from_default")) {
            if (str_array(&j, s->from_default, MAX_FROM, &s->from_default_n, e) != 0 && e->msg[0]) return -1;
        }
        else if (!strcmp(key, "lan_device")) {
            /* Одиночная форма — сокращение для списка из одного элемента, ровно как
             * `device` у выхода. Дальше по коду путь один. */
            if (js_str(&j, s->lan_dev[0], sizeof(s->lan_dev[0]), e) != 0 && e->msg[0]) return -1;
            s->lan_dev_n = 1;
            lan_one = 1;
        }
        else if (!strcmp(key, "lan_devices")) {
            if (str_array(&j, s->lan_dev, MAX_LAN_DEV, &s->lan_dev_n, e) != 0)
                return err_prop(e, "lan_devices: ожидался массив строк", NULL);
            lan_many = 1;
        }
        else if (!strcmp(key, "traceroute_hops")) { js_ws(&j); s->traceroute_hops = (*j.p == 't'); if (js_skip(&j, e) != 0) return -1; }
        else { if (js_skip(&j, e) != 0) return -1; }
        js_ws(&j);
        if (*j.p == ',') { j.p++; js_ws(&j); }
    }
    /* Закрывающая скобка обязательна: без неё это файл, оборванный посреди записи (питание
     * пропало), и половина спеки применялась без единой жалобы. Комментарий выше обещает
     * громкий отказ на битой спеке; до этой правки он был только при обрыве внутри строки.
     * Текст ПОСЛЕ скобки по-прежнему не читается и не мешает: так было всегда, и на это
     * опираются стенды. */
    if (js_lit(&j, '}') != 0) return err_set(e, "spec: нет закрывающей скобки — файл оборван?", NULL);
    if (lan_one && lan_many)
        return err_set(e, "задано и lan_device, и lan_devices — оставьте одно", NULL);
    /* Пустой список — это «клиентов нет», а правило без условия «кто» забирает ВЕСЬ транзит
     * роутера, включая путь из интернета внутрь. Отказ дешевле такой находки на живом
     * роутере. */
    if (!s->lan_dev_n)
        return err_set(e, "lan_devices: пустой список — некому адресовать правила", NULL);
    for (size_t i = 0; i < s->lan_dev_n; i++) {
        /* Самая дорогая из проверок этого набора: имя уходит и в текст правил nftables, и
         * в командные строки popen у любой команды, читающей спеку. */
        if (!name_ok(s->lan_dev[i]))
            return err_set(e, "lan_devices: негодный состав имени (%s)", s->lan_dev[i]);
        for (size_t k = i + 1; k < s->lan_dev_n; k++)
            if (!strcmp(s->lan_dev[i], s->lan_dev[k]))
                return err_set(e, "lan_devices: устройство %s указано дважды", s->lan_dev[i]);
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
    if (s->from_default_n && s->lan_dev_n > 1)
        return err_set(e, "клиенты описаны дважды: и from_default, и несколько lan_devices. "
            "Уберите from_default — устройства опишут клиентов точнее", NULL);
    /* Refusing an unknown major is the whole point of having the field: guessing
     * would mean compiling a config we do not understand into firewall rules. */
    /* ЧЕМ ОТЛИЧАЮТСЯ 1 И 2 — и почему второй версии нельзя было обойтись ключом.
     *
     * Отличие ровно одно: в схеме 2 у `match` канала есть измерение «протокол и порты»
     * (`proto`, `ports`). Всё остальное совпадает буква в букву, и спека `schema: 1`
     * применяется этой сборкой без единого изменения в поведении — включая текст
     * генерируемых правил и имена наборов nftables, от которых зависит перенос счётчиков.
     *
     * ПОЧЕМУ НЕ ХВАТИЛО НОВОГО КЛЮЧА. Неизвестный КЛЮЧ движок пропускает (js_skip выше), и
     * для всего, что совпадение РАСШИРЯЕТ, этого достаточно: старая сборка не поняла новое
     * поле — она просто не получила новой возможности, а то, что было, работает как было.
     * Порты совпадение СУЖАЮТ. Пропущенный ключ здесь означает «сузить забыли»: канал
     * Discord — это 104.16.0.0/12 (Cloudflare) плюс udp 50000-65535, и без портов он
     * забирает весь TCP к Cloudflare, то есть половину интернета, в туннель. Молча. Разница
     * между «не получил новую возможность» и «сделал не то, что написано» — это и есть
     * граница major, и она здесь пройдена.
     *
     * ПОЧЕМУ ЭТО НЕ ЛОМАЕТ РОУТЕР со старым движком. Управляющий слой (splify2, метод
     * spec_set) проверяет спеку компилятором — `apply --dry-run` — ДО записи на диск.
     * Старая сборка ответит на `schema: 2` тем же отказом кодом 2 (раньше — прямым exit
     * отсюда, теперь — через err_die у точки входа: сообщение то же), метод скажет
     * человеку «обновите движок», а на роутере останутся прежние правила. Отказ громкий и
     * заранее — ровно то, ради чего поле существует; понятая наполовину спека такого шанса
     * не даёт. */
    if (schema != 1 && schema != 2) {
        char msg[96];
        snprintf(msg, sizeof(msg), "spec schema %ld is not supported (this build speaks 1 and 2)", schema);
        return err_set(e, "%s", msg);
    }
    /* Поля схемы 2 в спеке схемы 1 — ОТКАЗ, а не молчаливое игнорирование.
     *
     * Игнорирование здесь и есть та беда, от которой заведена версия, только с другой
     * стороны: человек написал порты, увидел, что спека применилась, и считает, что сузил
     * канал. Не сузил. Отказ называет и канал, и что поднять.
     *
     * Проверяются ВСЕ каналы, включая выключенные, в отличие от проверок ниже. Исключение
     * для выключенных сделано затем, чтобы сломанное правило можно было выключить, а не
     * только удалить; здесь же чинить надо не правило, а число схемы у всей спеки, и
     * выключенный канал этому ничуть не мешает. */
    if (schema == 1)
        for (size_t i = 0; i < s->ch_n; i++)
            if (s->ch[i].l4_written) {
                /* Буфер с запасом: строка русская, в UTF-8 это два байта на букву, и
                 * обрезка по границе буфера разрубила бы букву посередине. */
                char msg[400];
                snprintf(msg, sizeof(msg),
                         "канал %.24s: proto и ports появились в schema 2, а в спеке "
                         "schema 1. Поднимите \"schema\": 2 — иначе движок постарше поймёт "
                         "спеку наполовину и канал заберёт больше, чем вы написали",
                         s->ch[i].name);
                return err_set(e, "%s", msg);
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
    for (size_t i = 0; i < s->ch_n; i++) {
        size_t k = 0;
        for (; k < s->out_n; k++) if (!strcmp(s->ch[i].out, s->out[k].name)) break;
        if (k == s->out_n) return err_set(e, "channel %s points at an output that does not exist", s->ch[i].name);
    }

    /* ---- защита от конфигураций, которые отрежут доступ к роутеру -----------
     *
     * Всё ниже — про ошибки, которые компилируются и применяются без единой
     * жалобы, а замечаются как «роутер пропал». Отказать на них дешевле, чем
     * потом объяснять, как чинить коробку, до которой уже не достучаться.
     * Каждая проверка отвечает на «что человек сделает случайно», а не на
     * «что запрещено стандартом». */
    for (size_t i = 0; i < s->out_n; i++) {
        struct output *o = &s->out[i];
        if (!out_has_device(o)) continue;

        /* Выход в локальное устройство — это петля: помеченный пакет получает маршрут
         * обратно в ту же сеть, откуда пришёл. Проверяется ВЕСЬ список: выход в
         * tailscale0, с которого мы забираем клиентов, закольцуется ровно так же, как
         * выход в br-lan, и отличать одно от другого нечем. */
        for (size_t d = 0; d < s->lan_dev_n; d++)
            if (!strcmp(o->device, s->lan_dev[d])) {
                /* 256, не 160: через указатель на struct spec gcc считает границы имени и
                 * устройства не так точно, как считал их у прежних глобальных массивов, и
                 * -Wformat-truncation видит в этом реальный риск (-Werror с ним не собрался
                 * бы). Значения по-прежнему ограничены name[32] и lan_dev[64] — 256 просто
                 * достаточно, чтобы gcc в этом убедился тоже. */
                char msg[256];
                snprintf(msg, sizeof(msg),
                         "выход %s ведёт в %s — это локальная сеть, трафик закольцуется",
                         o->name, s->lan_dev[d]);
                return err_set(e, "%s", msg);
            }

        /* Дубликат устройства внутри одного выхода делает failover бессмысленным:
         * второй кандидат ничем не отличается от первого. */
        for (size_t a = 0; a < o->devices_n; a++)
            for (size_t b = a + 1; b < o->devices_n; b++)
                if (!strcmp(o->devices[a], o->devices[b])) {
                    char msg[160];
                    snprintf(msg, sizeof(msg), "выход %s: устройство %s указано дважды",
                             o->name, o->devices[a]);
                    return err_set(e, "%s", msg);
                }
    }

    if (via_check(s, e) != 0) return -1;

    /* from_default — это клиенты раздачи; сам телефон называет канал, а не умолчание для всех
     * каналов. Проверка вне цикла по каналам: from_default уходит в правило заворота DNS и
     * тогда, когда у каждого канала свой from, — и «ip saddr self» nft отверг бы синтаксической
     * ошибкой вместо слова о спеке. */
    for (size_t k = 0; k < s->from_default_n; k++)
        if (from_is_local(s->from_default[k]))
            return err_set(e, "from_default: «%s» — сам телефон, а не клиенты; укажите его в from канала",
                s->from_default[k]);
    for (size_t i = 0; i < s->ch_n; i++) {
        struct channel *c = &s->ch[i];
        /* Выключенное правило не проверяем: оно не действует, а отказ применить спеку из-за
         * него означал бы, что выключить сломанное правило нельзя — только удалить. */
        if (c->disabled) continue;

        /* Пустая строка в «кому» уходила в правило как «ip saddr {  }», и nft отвергал ВСЁ
         * применение синтаксической ошибкой вместо слова о спеке (I-315).
         *
         * У своего from канала это не отказ, а предупреждение: такой from пишет сам
         * интерфейс splify2 — выбор «только эти устройства» без единого устройства хранится
         * как [""]. Пустые строки выбрасываются; если не осталось ничего, канал не
         * применяется. Отдать его «всем» (пустой from значит from_default) нельзя: человек
         * выбрал «только эти», а получил бы правило на всю сеть.
         *
         * У from_default пустая строка — отказ: её не пишет ни один наш источник, а
         * выбросить её значило бы сузить или расширить «кому» у всех каналов сразу. */
        if (c->from_n) {
            size_t w = 0;
            for (size_t k = 0; k < c->from_n; k++)
                if (c->from[k][0]) memmove(c->from[w++], c->from[k], sizeof(c->from[0]));
            if (w != c->from_n) {
                c->from_n = w;
                if (!w) {
                    fprintf(stderr, "steer[warn] канал %s: в «кому» не выбрано ни одного "
                            "устройства — канал не применяется; выберите устройства или "
                            "«все»\n", c->name);
                    c->disabled = 1;
                    continue;
                }
                fprintf(stderr, "steer[warn] канал %s: в «кому» пустая строка — пропущена\n",
                        c->name);
            }
        } else {
            for (size_t k = 0; k < s->from_default_n; k++)
                if (!s->from_default[k][0])
                    return err_set(e, "канал %s берёт «кому» из from_default, а в нём пустая строка — "
                        "уберите её", c->name);
        }

        /* Адреса и MAC-и в одном «кому» — нельзя. nft не умеет «или» внутри правила, и
         * смешанный список пришлось бы либо разбивать на два правила (тогда порядок и
         * приоритет расходятся с тем, что человек написал), либо взять половину молча — а
         * тогда часть устройств правило не касается, и понять это нечем. Отказываем громко. */
        /* Правило на устройство: `from` обязателен и только одиночные хозяева.
         *
         * Подсеть здесь означала бы, что приоритет получил не телефон, а половина сети, —
         * и получила бы тихо: снаружи такое правило выглядит точно так же. Пустой `from`
         * означал бы правило «на устройство», действующее на всех, то есть глобальное с
         * приоритетом глобальных — самое опасное из возможных недоразумений. */
        /* «Кто» на самом устройстве — см. from_is_local в spec.h. */
        size_t local = 0;
        for (size_t k = 0; k < c->from_n; k++) if (from_is_local(c->from[k])) local++;
        if (local) {
            if (!plat()->local_channels)
                return err_set(e, "канал %s: «self» и «uid:» в from — только в сборке под Android", c->name);
            if (local != c->from_n)
                return err_set(e, "канал %s: в «кому» смешаны сам телефон и клиенты раздачи — это разные "
                    "пути пакета, разделите на два канала", c->name);
            for (size_t k = 0; k < c->from_n; k++) {
                unsigned lo, hi;
                if (!strcmp(c->from[k], "self")) {
                    if (c->from_n > 1)
                        return err_set(e, "канал %s: «self» уже включает все приложения — уберите из "
                            "«кому» остальное", c->name);
                    continue;
                }
                static char msg[300];
                if (from_uid_range(c->from[k], &lo, &hi) != 0) {
                    snprintf(msg, sizeof(msg), "канал %.40s: «%.40s» — не UID приложения "
                             "(want uid:N or uid:N-M)", c->name, c->from[k]);
                    return err_set(e, "%s", msg);
                }
                if (lo == 0)
                    return err_set(e, "канал %s: uid:0 — это root, то есть сам движок и системные демоны; "
                        "их трафик каналом не маршрутизируется", c->name);
                /* Правило на устройство — на ОДНО приложение, диапазон тут был бы тем же
                 * «приоритет получила половина сети», что и подсеть у адресов. */
                if (c->dev_scope && lo != hi) {
                    snprintf(msg, sizeof(msg), "канал %.40s: правило на устройство принимает "
                             "одно приложение, а «%.40s» — диапазон", c->name, c->from[k]);
                    return err_set(e, "%s", msg);
                }
            }
        }

        if (c->dev_scope && !local) {
            if (!c->from_n)
                return err_set(e, "канал %s объявлен правилом на устройство, но в нём нет ни одного "
                    "хозяина: добавьте адрес или MAC в \"from\"", c->name);
            for (size_t k = 0; k < c->from_n; k++)
                if (!spec_one_host(c->from[k])) {
                    static char msg[400];
                    snprintf(msg, sizeof(msg),
                             "канал %.24s: правило на устройство принимает только одиночных "
                             "хозяев, а «%.40s» — подсеть. Приоритет достался бы не одному "
                             "устройству, а всем в ней",
                             c->name, c->from[k]);
                    return err_set(e, "%s", msg);
                }
        }

        if (c->from_n > 1 && !local) {
            int macs = 0;
            for (size_t k = 0; k < c->from_n; k++) if (strchr(c->from[k], ':')) macs++;
            if (macs && macs != (int)c->from_n)
                return err_set(e, "канал %s: в «кому» смешаны адреса и MAC-адреса. nft не умеет «или» внутри "
                    "правила — разделите на два канала", c->name);
        }
        /* КАНАЛ `any` БЕЗ СПИСКОВ ЗАБИРАЕТ ВЕСЬ ТРАФИК КЛИЕНТОВ — и проверять это надо
         * ДО всего, что касается выхода.
         *
         * Проверка стояла ниже, за `continue` по «у выхода нет устройства», и из-за этого не
         * срабатывала там, где последствие самое тяжёлое. У выхода kind=zapret устройства нет
         * по определению (движок его прямо запрещает), значит канал `any` на обход DPI
         * проезжал молча — и весь трафик локальной сети уходил в nfqws, а при on_fail=drop
         * умирал целиком. То же с kind=tgws и kind=direct.
         *
         * Воспроизведено на стенде в QEMU: спека с `{"any": true}` и выходом kind=zapret
         * принимается, правило выходит без `ip daddr @набор`, и счётчик растёт на ЛЮБОМ
         * трафике клиента (59 -> 97 пакетов, пока клиент ходил на два несвязанных сайта).
         *
         * Условие от выхода не зависит вовсе: «весь трафик вместо списка» — это свойство
         * КАНАЛА, и место ему здесь, до поиска выхода. У правила на устройство согласия
         * по-прежнему не требуется: запрет заведён против «все клиенты без интернета и
         * починка с провода», а у правила на одно устройство цена ошибки — один хозяин, и он
         * же её заметит. Ровно эта пара («весь трафик телефона в туннель» и «этот ноутбук не
         * маршрутизируем») и просилась. */
        if (c->any && !c->prefixes_n && !c->domains_n && !c->srs_n && !c->allow_all && !c->dev_scope)
            return err_set(e, "канал %s забирает ВЕСЬ трафик в туннель. Если это правда нужно, "
                "добавьте \"allow_all\": true — иначе выберите список", c->name);

        struct output *o = out_by_name(s, c->out);
        /* Выход, который работает только для клиентов раздачи (мост Telegram перехватывает
         * соединения только в prerouting): канал «приложение → такой выход» стоял бы
         * применённым, не делая ничего. Почему — говорит вид (kind_ops.lan_only). */
        if (local && o && kind_of(o)->lan_only) {
            static char msg[300];
            snprintf(msg, sizeof(msg), "канал %s: выход kind=%s работает только для клиентов раздачи — %s",
                     c->name, kind_of(o)->name, kind_of(o)->lan_only);
            return err_set(e, "%s", msg);
        }
        /* Дальше — проверки, которым нужен выход С УСТРОЙСТВОМ. Через out_has_device, а не
         * сравнением с видом interface: у выхода kind=vless последствие ровно то же — весь
         * трафик клиента, включая доступ к роутеру и его DNS, уходит в туннель. Проверка,
         * знающая про один вид выхода, молча пропускала бы вторую половину случаев, а
         * «защита от дурака», работающая через раз, хуже отсутствующей: на неё рассчитывают. */
        if (!o || !out_has_device(o)) continue;
    }
    return 0;
}

struct output *out_by_name(const struct spec *sp, const char *n) {
    /* Возврат — НЕ const: правило 6 просит sp константным параметром (эта функция только
     * ищет), а вызывающие с изменяемой спекой (load_spec, registry_assign) правят найденный
     * выход дальше — тем же способом, каким это делал g_out[i] до перехода на struct spec.
     * Приведение снимает константность указателя, а не массива за ним: массив мутабелен
     * ровно тогда, когда мутабелен *sp у вызывающего. */
    for (size_t i = 0; i < sp->out_n; i++)
        if (!strcmp(sp->out[i].name, n)) return (struct output *)&sp->out[i];
    return NULL;
}


/* ---- что такое строка списка -------------------------------------------------------
 *
 * ЖИВЁТ ЗДЕСЬ, А НЕ В steer.c, потому что читателей стало двое. Компилятор набора правил
 * берёт из файла адресные строки (emit_elements), резолвер — доменные (ruleset_add), и с
 * гибридными списками они читают ОДИН И ТОТ ЖЕ файл. Две копии этого правила означали бы
 * строку, которую не взял никто, или строку, которую взяли оба, — и ни то ни другое не
 * заметно снаружи: набор соберётся, резолвер запустится, а часть списка просто не будет
 * действовать.
 *
 * Проверяется ФОРМА, а не значения октетов: `1.1.1.1` и `8.8.8.0/24` адреса, `youtube.com`
 * нет. Строка вроде `123.456.789.0` формой проходит, а адресом не является — её отвергнет
 * nft, и это правильное место для такого отказа: там она названа по имени, а угадывать
 * здесь значило бы завести второй разборщик адресов рядом с ядерным. */
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

/* Диапазон здесь обязателен, и это не расширение ради полноты: `steer fit` сам ВЫДАЁТ
 * диапазоны — два соседних адреса, не складывающихся в выровненный префикс, объединяются
 * именно так (emit_range в aggregate.c). Раньше дефис отвергался, поэтому подогнанный
 * список, поданный каналу, терял такие строки целиком. */
/* Одиночный хозяин: адрес без маски, адрес с /32 или MAC. Всё остальное — подсеть или не
 * адрес вовсе.
 *
 * Нужно правилу на устройство: приоритет там даётся ОДНОМУ хозяину, и подсеть в этом месте
 * означала бы приоритет для всех в ней. Проверяется форма, а не значения октетов, — по той
 * же причине, что у spec_line_is_addr ниже. */
int spec_one_host(const char *s) {
    if (!s || !*s) return 0;
    /* MAC: шесть пар шестнадцатеричных через двоеточие. Точную форму проверяет is_mac в
     * генераторе; здесь достаточно отличить его от адреса — двоеточие в IPv4 не бывает. */
    if (strchr(s, ':')) return 1;
    const char *sl = strchr(s, '/');
    if (sl && strcmp(sl, "/32") != 0) return 0;
    char buf[64];
    size_t n = sl ? (size_t)(sl - s) : strlen(s);
    if (n >= sizeof(buf)) return 0;
    memcpy(buf, s, n);
    buf[n] = '\0';
    return spec_line_is_addr(buf) && !strchr(buf, '-');
}

int from_is_local(const char *s) {
    return s && (!strcmp(s, "self") || !strncmp(s, "uid:", 4));
}

int from_uid_range(const char *s, unsigned *lo, unsigned *hi) {
    if (!s || strncmp(s, "uid:", 4)) return -1;
    const char *p = s + 4;
    unsigned long a, b;
    char *end;
    if (*p < '0' || *p > '9') return -1;
    a = strtoul(p, &end, 10);
    if (*end == '-') {
        p = end + 1;
        if (*p < '0' || *p > '9') return -1;
        b = strtoul(p, &end, 10);
    } else {
        b = a;
    }
    /* UID ядра — 32 бита, но (uid_t)-1 означает «нет» и в правило попадать не должен. */
    if (*end || a > 0x7fffffffUL || b > 0x7fffffffUL || a > b) return -1;
    *lo = (unsigned)a;
    *hi = (unsigned)b;
    return 0;
}

int spec_line_is_addr(const char *s) {
    const char *dash = strchr(s, '-');
    const char *end = s + strlen(s);
    if (!dash) return addr_half_ok(s, end);
    /* Ровно один дефис, и обе половины — адреса. */
    if (strchr(dash + 1, '-')) return 0;
    return addr_half_ok(s, dash) && addr_half_ok(dash + 1, end);
}
