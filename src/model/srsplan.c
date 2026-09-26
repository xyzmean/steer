/* Канал с наборами sing-box: раскладка на группы.
 *
 * Набор .srs — это не один список, а несколько клауз (src/model/srs.c, «Нормальная форма»): у
 * каждой своё назначение и, бывает, своё сужение по протоколу и портам, своё ограничение по
 * клиенту или приложению, свои исключения. Канал же в ядре — правило и набор адресов. Здесь
 * решается, сколько правил и наборов получится из канала и что в каждом.
 *
 * СУЖЕНИЕ. У каждой клаузы оно своё, и к нему добавляется сужение самого канала (proto/ports в
 * match): действует пересечение. Пустое пересечение — отказ спеке: канал явно сузили так, что
 * из набора он не поймал бы ничего, и это почти наверняка перенесённое вручную старое сужение
 * (`srs-read --meta-out` → proto/ports), которое теперь применяется само.
 *
 * ОДНО СУЖЕНИЕ НА ВЕСЬ СПИСОК (или никакого) — обычная группа, ровно как канал с proto/ports:
 * набор адресов и одно правило с `meta l4proto … th dport …`. Так выходит почти всегда —
 * наборы itdoginfo и геоданные sing-box сужения не несут вовсе.
 *
 * СМЕШАННОЕ СУЖЕНИЕ (у discord.srs: имена без сужения, подсети Cloudflare — «udp 50000-65535»
 * и «udp 19000-20000»; собственные списки канала — тоже без сужения) — решение владельца:
 * ОДИН составной набор `ipv4_addr . inet_proto . inet_service` с флагом interval, у каждого
 * элемента свои протокол и порты, и одно правило `ip daddr . meta l4proto . th dport @набор`.
 * Элемент без сужения получает протокол 0-255 и порты 0-65535, и тогда ловится любой трафик к
 * нему, включая ICMP, GRE и ESP: `th dport` у протокола без портов не проваливается, а читает
 * два байта его заголовка (у ICMP — контрольную сумму), и они попадают в 0-65535. Отдельного
 * правила для «не TCP и не UDP» поэтому не нужно. Составной интервальный набор ядро принимает
 * с 5.6; на старой раскладке и на ядре, которое его не принимает (nft_concat_ok), канал
 * делится на группы — по группе на вариант сужения, как делились бы каналы с разными портами.
 *
 * УСЛОВИЯ, КОТОРЫХ У КАНАЛА НЕТ, — отдельной группой («доп. группа», SP_EXTRA) со своим
 * правилом: ограничение по клиенту (source_ip_cidr) дописывается к «кому» канала вторым
 * `ip saddr`, приложение (package_name, только у канала на сам телефон) заменяет «кому» на
 * UID приложения, исключения-подсети — набор `<группа>_x` и `ip daddr != @…` перед поиском.
 * Исключения-имена в ядро не идут вовсе: их применяет резолвер, и клауза с ними остаётся в
 * общей группе.
 *
 * ЧТО СНИМАЕТСЯ С ПРЕДУПРЕЖДЕНИЕМ (набор от этого только уже): клауза про приложение у канала
 * для клиентов раздачи (у их пакетов нет приложения) или для приложения, которого на телефоне
 * нет; клауза про клиента у канала на сам телефон; подсети IPv6 (1.9). Непрочитанный или
 * испорченный файл — как непрочитанный адресный список: его элементы не попадут никуда, про
 * это сказано, остальные списки канала работают. */
#define _GNU_SOURCE
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

#include "srsplan.h"
#include "nftcompat.h"

int srs_concat_override = -1;

static void warn_add(struct srs_plan *pl, const char *fmt, ...) __attribute__((format(printf, 2, 3)));
static void warn_add(struct srs_plan *pl, const char *fmt, ...) {
    size_t k = strlen(pl->warn);
    if (k + 2 >= sizeof(pl->warn)) return;
    if (k) pl->warn[k++] = '\n';
    va_list ap;
    va_start(ap, fmt);
    vsnprintf(pl->warn + k, sizeof(pl->warn) - k, fmt, ap);
    va_end(ap);
}

/* ---- приложения: имя пакета → UID ---------------------------------------------------------
 * /data/system/packages.list: «имя uid отлаживаемый каталог seinfo gid…» строкой на пакет.
 * Путь — у платформы; STEER_PACKAGES_LIST переопределяет (стенды). */
static long pkg_uid(const char *name) {
    const char *path = getenv("STEER_PACKAGES_LIST");
    if (!path || !*path) path = plat()->packages_list;
    if (!path) return -1;
    FILE *f = fopen(path, "r");
    if (!f) return -1;
    char line[1024];
    long uid = -1;
    size_t nl = strlen(name);
    while (uid < 0 && fgets(line, sizeof(line), f)) {
        if (strncmp(line, name, nl) != 0 || line[nl] != ' ') continue;
        char *end = NULL;
        long v = strtol(line + nl + 1, &end, 10);
        if (end != line + nl + 1 && v > 0) uid = v;
    }
    fclose(f);
    return uid;
}

/* UID приложений клаузы, которые покрывает «кому» канала на телефоне. */
static size_t uids_for(const struct channel *c, const struct srs_clause *cl, char (*out)[64],
                       size_t max, int *unknown) {
    size_t n = 0;
    for (size_t i = 0; i < cl->pkg_n && n < max; i++) {
        long u = pkg_uid(cl->pkg[i]);
        if (u < 0) { (*unknown)++; continue; }
        int in = 0;
        for (size_t k = 0; k < c->from_n && !in; k++) {
            unsigned lo, hi;
            if (!strcmp(c->from[k], "self")) in = (unsigned long)u >= plat()->app_uid_min;
            else if (from_uid_range(c->from[k], &lo, &hi) == 0) in = (unsigned long)u >= lo && (unsigned long)u <= hi;
        }
        if (!in) continue;
        int dup = 0;
        char s[64];
        snprintf(s, sizeof(s), "uid:%ld", u);
        for (size_t k = 0; k < n && !dup; k++) dup = !strcmp(out[k], s);
        if (!dup) snprintf(out[n++], 64, "%s", s);
    }
    return n;
}

/* ---- раскладка ------------------------------------------------------------------------------ */

struct item {
    int own;                    /* собственные списки канала */
    size_t fi, ci;              /* файл и клауза */
    struct l4match eff;
    int extra;                  /* 1 — у клаузы условия, которых нет у канала */
    int all, xcidr;
    const struct srs_pfx4 *src;
    size_t src_n;
    char uid[SRS_MAX_PKG][64];
    size_t uid_n;
    const struct srs_clause *cl;
    int part;                   /* куда попала */
};

static int extra_same(const struct item *a, const struct item *b) {
    if (a->xcidr || b->xcidr) return 0;        /* исключения — свои у каждой клаузы */
    if (a->all != b->all || a->src_n != b->src_n || a->uid_n != b->uid_n) return 0;
    if (a->src_n && memcmp(a->src, b->src, a->src_n * sizeof(a->src[0]))) return 0;
    for (size_t i = 0; i < a->uid_n; i++) if (strcmp(a->uid[i], b->uid[i])) return 0;
    return l4match_same(&a->eff, &b->eff);
}

/* Адресных строк в собственных списках канала — для предела составного набора. */
static size_t count_addr_lines(const struct channel *c) {
    size_t n = 0;
    for (size_t f = 0; f < c->prefixes_n; f++) {
        FILE *in = fopen(c->prefixes_files[f], "r");
        if (!in) continue;
        char line[512];
        while (fgets(line, sizeof(line), in)) {
            char *p = line;
            while (*p == ' ' || *p == '\t') p++;
            p[strcspn(p, "\r\n")] = '\0';
            if (*p && *p != '#' && *p != ';' && spec_line_is_addr(p)) n++;
        }
        fclose(in);
    }
    return n;
}

static struct item *item_new(struct item **items, size_t *n, size_t *cap) {
    if (*n == *cap) {
        size_t nc = *cap ? *cap * 2 : 16;
        struct item *ni = realloc(*items, nc * sizeof(*ni));
        if (!ni) return NULL;
        *items = ni;
        *cap = nc;
    }
    struct item *it = &(*items)[(*n)++];
    memset(it, 0, sizeof(*it));
    return it;
}

static struct srs_part *part_new(struct srs_plan *pl, int kind) {
    struct srs_part *p = realloc(pl->p, (pl->n + 1) * sizeof(*p));
    if (!p) return NULL;
    pl->p = p;
    memset(&p[pl->n], 0, sizeof(p[pl->n]));
    p[pl->n].kind = kind;
    return &p[pl->n++];
}

void srs_plan_free(struct srs_plan *pl) {
    for (size_t i = 0; i < pl->n; i++) {
        struct srs_part *p = &pl->p[i];
        for (size_t k = 0; k < p->sel_n; k++) { free(p->sel[k].sel); free(p->sel[k].eff); }
        free(p->sel);
        free(p->uid);
    }
    free(pl->p);
    pl->p = NULL;
    pl->n = 0;
    for (size_t i = 0; i < pl->held_n; i++) srs_release(pl->held[i]);
    pl->held_n = 0;
}

/* Клаузу it (файла sets[it->fi]) — в часть p. */
static int part_take(struct srs_part *p, const struct item *it, const char *path,
                     const struct srs_set *set) {
    /* «Весь трафик приложения» элементов не несёт: набора у такой группы нет вовсе. */
    if (it->cl->kind == SRS_C_ALL) return 0;
    size_t k = 0;
    while (k < p->sel_n && p->sel[k].set != set) k++;
    if (k == p->sel_n) {
        struct srs_psel *s = realloc(p->sel, (p->sel_n + 1) * sizeof(*s));
        if (!s) return -1;
        p->sel = s;
        struct srs_psel *n = &s[p->sel_n++];
        memset(n, 0, sizeof(*n));
        n->path = path;
        n->set = set;
        n->ncl = srs_clause_n(set);
        n->sel = calloc((n->ncl + 7) / 8 + 1, 1);
        n->eff = calloc(n->ncl ? n->ncl : 1, sizeof(*n->eff));
        if (!n->sel || !n->eff) return -1;
    }
    struct srs_psel *s = &p->sel[k];
    s->sel[it->ci >> 3] |= (uint8_t)(1u << (it->ci & 7));
    s->eff[it->ci] = it->eff;
    if (it->cl->kind == SRS_C_DOM) { s->has_dom = 1; p->has_dom = 1; }
    if (it->cl->kind == SRS_C_CIDR && (it->cl->flags & SRS_F_V4)) {
        s->has_v4 = 1;
        p->has_v4 = 1;
        p->n_v4 += it->cl->n_v4;
    }
    return 0;
}

int srs_plan_channel(const struct spec *sp, const struct channel *c, int concat,
                     struct srs_plan *pl, struct err *e) {
    (void)sp;
    memset(pl, 0, sizeof(*pl));
    const struct l4match *E = &c->l4;
    int local = c->from_n && from_is_local(c->from[0]);
    const struct srs_set *sets[MAX_FILES];
    size_t nitems = 0, cap = 0;
    struct item *items = NULL;
    int rc = -1;

    if (c->prefixes_n || c->domains_n) {
        struct item *it = item_new(&items, &nitems, &cap);
        if (!it) goto oom;
        it->own = 1;
        it->eff = *E;
    }
    for (size_t fi = 0; fi < c->srs_n; fi++) {
        struct err fe = {0};
        sets[fi] = NULL;
        if (srs_open(c->srs_files[fi], &sets[fi], &fe) != 0) {
            warn_add(pl, "%s — его элементы в канал «%s» не попадут", fe.msg, c->name);
            continue;
        }
        const struct srs_set *s = sets[fi];
        pl->held[pl->held_n++] = s;
        if (srs_skipped(s)) warn_add(pl, "srs: %s: %s", c->srs_files[fi], srs_skipped(s));
        int v6 = 0, pkg_far = 0, pkg_unknown = 0, src_local = 0;
        size_t before = nitems;
        for (size_t ci = 0; ci < srs_clause_n(s); ci++) {
            const struct srs_clause *cl = srs_clause(s, ci);
            if (cl->flags & SRS_F_V6) v6 = 1;
            if (cl->kind == SRS_C_CIDR && !(cl->flags & SRS_F_V4)) continue;   /* только v6 */
            struct item tmp;
            memset(&tmp, 0, sizeof(tmp));
            tmp.fi = fi;
            tmp.ci = ci;
            tmp.cl = cl;
            if (!l4_intersect(E, &cl->l4, &tmp.eff)) {
                char a[120], b[120], msg[1000];
                l4_to_text(E, a, sizeof(a));
                l4_to_text(&cl->l4, b, sizeof(b));
                snprintf(msg, sizeof(msg), "канал %.40s: сужение канала (%s) и правила набора "
                         "%.160s (%s) не пересекаются — из набора канал не поймал бы ничего. "
                         "Сужение набора применяется само: уберите proto и ports из канала",
                         c->name, a, c->srs_files[fi], b);
                err_set(e, "%s", msg);
                goto out;
            }
            if (cl->pkg_n) {
                if (!local) { pkg_far = 1; continue; }
                tmp.uid_n = uids_for(c, cl, tmp.uid, SRS_MAX_PKG, &pkg_unknown);
                if (!tmp.uid_n) continue;
                tmp.extra = 1;
            }
            if (cl->kind == SRS_C_ALL) tmp.all = tmp.extra = 1;
            if (cl->src_n) {
                if (local) { src_local = 1; continue; }
                tmp.src = cl->src;
                tmp.src_n = cl->src_n;
                tmp.extra = 1;
            }
            if (cl->flags & SRS_F_XCIDR) tmp.xcidr = tmp.extra = 1;
            struct item *it = item_new(&items, &nitems, &cap);
            if (!it) goto oom;
            *it = tmp;
        }
        if (v6) warn_add(pl, "srs: %s: подсети IPv6 пропущены — правила работают по IPv4",
                         c->srs_files[fi]);
        if (nitems == before && !v6 && !pkg_far && !pkg_unknown && !src_local)
            warn_add(pl, "srs: %s: в наборе нет ни имён, ни подсетей — канал «%s» из него ничего "
                     "не поймает", c->srs_files[fi], c->name);
        if (pkg_far)
            warn_add(pl, "srs: %s: правила про приложения сняты — канал «%s» не на само "
                     "устройство, у пакетов его клиентов приложения нет", c->srs_files[fi], c->name);
        if (pkg_unknown)
            warn_add(pl, "srs: %s: приложений из набора на устройстве нет (%d) — их правила не "
                     "действуют", c->srs_files[fi], pkg_unknown);
        if (src_local)
            warn_add(pl, "srs: %s: правила про клиентов (source_ip_cidr) сняты — канал на само "
                     "устройство", c->srs_files[fi]);
    }

    /* Общие клаузы: варианты сужения. */
    struct l4match var[64];
    size_t nvar = 0;
    int have_E = 0;
    for (size_t i = 0; i < nitems; i++) {
        if (items[i].extra) continue;
        if (l4_same_set(&items[i].eff, E)) { items[i].eff = *E; have_E = 1; }
        size_t k = 0;
        while (k < nvar && !l4match_same(&var[k], &items[i].eff)) k++;
        if (k == nvar) {
            if (nvar == sizeof(var) / sizeof(var[0])) { items[i].part = -1; continue; }
            var[nvar++] = items[i].eff;
        }
    }
    (void)have_E;
    if (nvar > 1 && concat < 0)
        concat = srs_concat_override >= 0 ? srs_concat_override : nft_concat_ok();
    /* Составной набор на десятки тысяч элементов дорог: pipapo в ядре и разбор nft при
     * загрузке. Замер на Linux 6.8, nft 1.0.9, 50 тысяч подсетей: `nft -f` — 99 МБ и 2,3 с
     * против 43 МБ и 0,3 с у того же списка обычными наборами, память набора в ядре — вдвое
     * больше; на 200 тысячах — 382 МБ и 28 с. Поэтому за пределом SRS_MIXED_MAX элементов канал
     * делится по сужению, как на ядре без составных наборов: смешанное сужение у больших
     * списков — редкость, а роутер на 128 МБ такой загрузки не переживёт. */
    if (nvar > 1 && concat) {
        size_t n = 0;
        for (size_t i = 0; i < nitems; i++) {
            if (items[i].extra) continue;
            if (items[i].own) n += count_addr_lines(c);
            else if (items[i].cl->kind == SRS_C_CIDR) n += items[i].cl->n_v4;
        }
        if (n > SRS_MIXED_MAX) {
            warn_add(pl, "канал «%s»: у списка смешанное сужение, но элементов %zu (больше %d) — "
                     "вместо одного составного набора канал поделён по сужению", c->name, n,
                     SRS_MIXED_MAX);
            concat = 0;
        }
    }
    if (nvar == 1 || (nvar > 1 && !concat)) {
        for (size_t k = 0; k < nvar; k++) {
            struct srs_part *p = part_new(pl, SP_PLAIN);
            if (!p) goto oom;
            p->l4 = var[k];
        }
    } else if (nvar > 1) {
        if (!part_new(pl, SP_COMPOSITE)) goto oom;
    }
    size_t nbase = pl->n;
    for (size_t i = 0; i < nitems; i++) {
        struct item *it = &items[i];
        if (it->extra || it->part < 0) continue;
        if (!nbase) break;
        size_t k = 0;
        if (pl->p[0].kind == SP_PLAIN)
            while (k < nbase && !l4match_same(&pl->p[k].l4, &it->eff)) k++;
        if (k == nbase) continue;
        struct srs_part *p = &pl->p[k];
        if (it->own) {
            p->own = 1;
            if (c->domains_n) p->has_dom = 1;
            continue;
        }
        if (part_take(p, it, c->srs_files[it->fi], sets[it->fi]) != 0) goto oom;
    }

    /* Доп. группы: по одной на набор условий и сужение. */
    size_t ci_idx = (size_t)(c - sp->ch);
    unsigned next_id = 1;
    for (size_t i = 0; i < nitems; i++) {
        struct item *it = &items[i];
        if (!it->extra) continue;
        size_t k = nbase;
        for (; k < pl->n; k++) {
            /* Первая клауза части — образец её условий. */
            const struct srs_part *p = &pl->p[k];
            struct item probe;
            memset(&probe, 0, sizeof(probe));
            probe.all = p->all;
            probe.xcidr = p->xcidr;
            probe.src = p->src;
            probe.src_n = p->src_n;
            probe.uid_n = p->uid_n;
            for (size_t u = 0; u < p->uid_n; u++) snprintf(probe.uid[u], 64, "%s", p->uid[u]);
            probe.eff = p->l4;
            if (extra_same(&probe, it)) break;
        }
        if (k == pl->n) {
            if (next_id >= 100) {
                warn_add(pl, "канал «%s»: правил с особыми условиями больше 99 — остальные сняты",
                         c->name);
                continue;
            }
            struct srs_part *p = part_new(pl, SP_EXTRA);
            if (!p) goto oom;
            p->l4 = it->eff;
            p->id = (unsigned)(ci_idx * 100 + next_id++);
            p->all = it->all;
            p->xcidr = it->xcidr;
            p->src = it->src;
            p->src_n = it->src_n;
            if (it->uid_n) {
                p->uid = calloc(it->uid_n, sizeof(*p->uid));
                if (!p->uid) goto oom;
                for (size_t u = 0; u < it->uid_n; u++) snprintf(p->uid[u], 64, "%s", it->uid[u]);
                p->uid_n = it->uid_n;
            }
        }
        if (part_take(&pl->p[k], it, c->srs_files[it->fi], sets[it->fi]) != 0) goto oom;
    }

    /* Ни одного читаемого списка: часть без содержимого остаётся — пустой набор, а не «весь
     * трафик» (см. поле emptied у struct group). */
    if (!pl->n) {
        struct srs_part *p = part_new(pl, SP_PLAIN);
        if (!p) goto oom;
        p->l4 = *E;
    }
    rc = 0;
    goto out;
oom:
    err_set(e, "канал %s: не хватило памяти на раскладку наборов", c->name);
out:
    free(items);
    if (rc != 0) srs_plan_free(pl);
    return rc;
}

void srs_chan_l4_each(const struct channel *c, void (*cb)(void *ctx, const struct l4match *m),
                      void *ctx) {
    for (size_t fi = 0; fi < c->srs_n; fi++) {
        const struct srs_set *s;
        struct err e = {0};
        if (srs_open(c->srs_files[fi], &s, &e) != 0) continue;
        for (size_t ci = 0; ci < srs_clause_n(s); ci++) {
            struct l4match m;
            if (!l4_intersect(&c->l4, &srs_clause(s, ci)->l4, &m)) continue;
            if (l4_same_set(&m, &c->l4)) m = c->l4;
            if (!l4match_empty(&m)) cb(ctx, &m);
        }
        srs_release(s);
    }
}
