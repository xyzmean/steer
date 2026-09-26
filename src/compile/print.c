/* Печать дерева набора правил (ir.h) в текст nftables — один печатник на обе раскладки.
 *
 * Печатник знает только синтаксис nft и раскладку текста: отступы в четыре пробела, пустые
 * строки там, где их поставил строитель (obj->gap), «dnat ip to» в inet и «dnat to» в
 * таблице одного семейства. Что стоит в ядре, решают генератор (generate.c) и раскладка
 * старого ядра (legacy.c). Текст обязан совпадать с тем, что печатал прежний генератор, до
 * байта: на этом держится снимок tests/golden/ruleset. */
#define _GNU_SOURCE
#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <arpa/inet.h>
#include <netinet/in.h>

#include <stdlib.h>

#include "spec.h"
#include "srs.h"
#include "ir.h"

#define LOG_W "steer[warn] apply: "

/* Elements come straight from the list files: the fitter (steer-aggregate) has
 * already decided what fits, and re-parsing them here would only add a second place
 * for the two to disagree. */
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

/* ---- подсети набора .srs (NFT_EL_SRS) -------------------------------------------------------
 * Потоком, как адресный список: читатель отдаёт префиксы по одному (srs_walk), и в памяти не
 * лежит ничего, кроме окна распаковки. Имена набора не читаются вовсе — их берёт резолвер. */
struct srs_pr { FILE *f; size_t n; int excl; };

static int srs_pr_cb(void *ctx, const struct srs_elem *el) {
    struct srs_pr *p = ctx;
    if (el->kind != SRS_EL_CIDR || el->family != 4 || el->excl != p->excl) return 0;
    /* Та же запись, что у srs-read: набор, подключённый ключом, и набор, разложенный в списки,
     * дают один и тот же текст. */
    char b[24];
    snprintf(b, sizeof(b), "%u.%u.%u.%u/%d", el->addr[0], el->addr[1], el->addr[2],
             el->addr[3], el->plen);
    if (p->n) fputs(", ", p->f);
    fputs(b, p->f);
    p->n++;
    return 0;
}

static size_t emit_srs(FILE *f, const char *path, const struct ir_srs *src, size_t already) {
    struct srs_pr p = { f, already, src->excl };
    struct err e = {0};
    /* Не отказ: разбор набора уже прошёл (check_address_lists), и сюда попадают только гонкой —
     * файл заменили между проверкой и печатью. Пропадут подсети одного набора, про это сказано. */
    if (srs_walk(src->set, SRS_EL_CIDR, src->sel, srs_pr_cb, &p, &e) != 0)
        fprintf(stderr, LOG_W "%s — его подсети в набор правил не попали\n",
                e.msg[0] ? e.msg : path);
    return p.n - already;
}

/* ---- составной набор (NFT_EL_MIXED) ----------------------------------------------------------
 *
 * Ключ — адрес . протокол . порты, и ядро НЕ ПРИНИМАЕТ пересекающихся элементов: `10.0.0.0/8 .
 * 17 . 1-100` и `10.1.0.0/16 . 17 . 50-60` отвергаются целиком (EEXIST), auto-merge сливает
 * только точные повторы. А пересечения здесь обычны: подсеть без сужения из собственного
 * списка канала и та же подсеть с «udp 50000-65535» из набора, два списка одного хостинга.
 *
 * Поэтому элементы собираются в память и раскладываются заново: проход по адресной оси, на
 * каждом отрезке — множество действующих сужений, и оно печатается НЕПЕРЕСЕКАЮЩИМИСЯ ящиками
 * «протокол × порты» (l4_union_boxes). Соседние отрезки с одинаковым множеством сливаются.
 * Память — 32 байта на подсеть, и только у составного набора: он бывает лишь у канала со
 * смешанным сужением, а у обычного набора элементы по-прежнему идут потоком. */
struct mx_ev { uint64_t pos; uint16_t l4; int16_t d; };
struct mx {
    struct mx_ev *ev;
    size_t n, cap;
    const struct l4match *l4s[64];
    size_t nl4;
    int over;
};

static int mx_l4(struct mx *m, const struct l4match *l4) {
    for (size_t i = 0; i < m->nl4; i++)
        if (m->l4s[i] == l4 || l4match_same(m->l4s[i], l4)) return (int)i;
    if (m->nl4 == 64) { m->over = 1; return -1; }
    m->l4s[m->nl4] = l4;
    return (int)m->nl4++;
}

static int mx_add(struct mx *m, uint32_t lo, uint32_t hi, int l4) {
    if (l4 < 0) return 0;
    if (m->n + 2 > m->cap) {
        size_t cap = m->cap ? m->cap * 2 : 1024;
        struct mx_ev *e = realloc(m->ev, cap * sizeof(*e));
        if (!e) return -1;
        m->ev = e;
        m->cap = cap;
    }
    m->ev[m->n++] = (struct mx_ev){ lo, (uint16_t)l4, 1 };
    m->ev[m->n++] = (struct mx_ev){ (uint64_t)hi + 1, (uint16_t)l4, -1 };
    return 0;
}

struct mx_srs { struct mx *m; const struct l4match *eff; };
static int mx_srs_cb(void *ctx, const struct srs_elem *el) {
    struct mx_srs *c = ctx;
    if (el->kind != SRS_EL_CIDR || el->family != 4 || el->excl) return 0;
    uint32_t a = ((uint32_t)el->addr[0] << 24) | ((uint32_t)el->addr[1] << 16) |
                 ((uint32_t)el->addr[2] << 8) | el->addr[3];
    uint32_t span = el->plen >= 32 ? 0 : (el->plen <= 0 ? 0xFFFFFFFFu : (0xFFFFFFFFu >> el->plen));
    return mx_add(c->m, a, a | span, mx_l4(c->m, &c->eff[el->clause])) ? -1 : 0;
}

/* Адресная строка списка → диапазон: «a.b.c.d», «a.b.c.d/n», «a-b». 0 — не адрес. */
static int line_range(const char *p, uint32_t *lo, uint32_t *hi) {
    char buf[64];
    size_t n = strcspn(p, " \t");
    if (n >= sizeof(buf)) return 0;
    memcpy(buf, p, n);
    buf[n] = '\0';
    char *dash = strchr(buf, '-'), *slash = strchr(buf, '/');
    struct in_addr a, b;
    if (dash) {
        *dash = '\0';
        if (inet_pton(AF_INET, buf, &a) != 1 || inet_pton(AF_INET, dash + 1, &b) != 1) return 0;
        *lo = ntohl(a.s_addr);
        *hi = ntohl(b.s_addr);
        return *lo <= *hi;
    }
    int plen = 32;
    if (slash) {
        *slash = '\0';
        char *end = NULL;
        long v = strtol(slash + 1, &end, 10);
        if (!end || *end || v < 0 || v > 32) return 0;
        plen = (int)v;
    }
    if (inet_pton(AF_INET, buf, &a) != 1) return 0;
    uint32_t span = plen >= 32 ? 0 : (plen <= 0 ? 0xFFFFFFFFu : (0xFFFFFFFFu >> plen));
    *lo = ntohl(a.s_addr) & ~span;
    *hi = *lo | span;
    return 1;
}

static int ev_cmp(const void *a, const void *b) {
    const struct mx_ev *x = a, *y = b;
    return x->pos < y->pos ? -1 : x->pos > y->pos;
}

static void addr_text(uint32_t lo, uint32_t hi, char *dst, size_t n) {
    uint32_t span = hi - lo;
    int aligned = ((span + 1u) & span) == 0 && (lo & span) == 0;   /* степень двойки и выровнен */
    if (lo == 0 && hi == 0xFFFFFFFFu) aligned = 1;
    if (aligned) {
        int plen = 32;
        while (plen > 0 && (span >> (32 - plen)) != 0) plen--;
        if (lo == 0 && hi == 0xFFFFFFFFu) plen = 0;
        if (plen == 32)
            snprintf(dst, n, "%u.%u.%u.%u", lo >> 24, (lo >> 16) & 255, (lo >> 8) & 255, lo & 255);
        else
            snprintf(dst, n, "%u.%u.%u.%u/%d", lo >> 24, (lo >> 16) & 255, (lo >> 8) & 255,
                     lo & 255, plen);
        return;
    }
    snprintf(dst, n, "%u.%u.%u.%u-%u.%u.%u.%u", lo >> 24, (lo >> 16) & 255, (lo >> 8) & 255,
             lo & 255, hi >> 24, (hi >> 16) & 255, (hi >> 8) & 255, hi & 255);
}

/* Один отрезок адресов с множеством сужений act — непересекающимися ящиками. */
static void mx_print(FILE *f, const struct mx *m, uint64_t lo, uint64_t hi, uint64_t act,
                     size_t *written) {
    const struct l4match *ms[64];
    size_t k = 0;
    for (size_t b = 0; b < m->nl4; b++) if (act & (1ULL << b)) ms[k++] = m->l4s[b];
    struct l4box box[L4BOX_MAX];
    size_t nb = l4_union_boxes(ms, k, box);
    char at[40], bt[48];
    addr_text((uint32_t)lo, (uint32_t)hi, at, sizeof(at));
    for (size_t j = 0; j < nb; j++) {
        l4_box_text(&box[j], bt, sizeof(bt));
        fprintf(f, (*written)++ ? ", %s . %s" : "        elements = { %s . %s", at, bt);
    }
}

static void emit_mixed(FILE *f, const struct ir_mixed *mix) {
    struct mx m;
    memset(&m, 0, sizeof(m));
    for (size_t i = 0; i < mix->n; i++) {
        const struct ir_mixed_src *s = &mix->v[i];
        if (s->set) {
            struct mx_srs c = { &m, s->eff };
            struct err e = {0};
            if (srs_walk(s->set, SRS_EL_CIDR, s->sel, mx_srs_cb, &c, &e) != 0)
                fprintf(stderr, LOG_W "%s — его подсети в набор правил не попали\n",
                        e.msg[0] ? e.msg : s->path);
            continue;
        }
        FILE *in = fopen(s->path, "r");
        if (!in) {
            fprintf(stderr, LOG_W "%s: список исчез во время сборки набора правил\n", s->path);
            continue;
        }
        int l4 = mx_l4(&m, s->l4);
        char line[512];
        while (fgets(line, sizeof(line), in)) {
            char *nl = strpbrk(line, "\r\n");
            if (nl) *nl = '\0';
            char *p = line;
            while (*p == ' ' || *p == '\t') p++;
            if (!*p || *p == '#' || *p == ';' || !spec_line_is_addr(p)) continue;
            uint32_t lo, hi;
            if (line_range(p, &lo, &hi) && mx_add(&m, lo, hi, l4) != 0) break;
        }
        fclose(in);
    }
    if (m.over)
        fprintf(stderr, LOG_W "составной набор: вариантов сужения больше 64 — лишние не вошли\n");
    qsort(m.ev, m.n, sizeof(m.ev[0]), ev_cmp);
    int cnt[64] = {0};
    uint64_t act = 0, prev = 0;
    struct { uint64_t lo, hi, act; int have; } pend = { 0, 0, 0, 0 };
    size_t written = 0;
    for (size_t i = 0; i <= m.n; ) {
        uint64_t pos = i < m.n ? m.ev[i].pos : ((uint64_t)1 << 32);
        /* Отрезок [prev, pos) с множеством act — к отложенному, если продолжает его. */
        if (pos > prev && act) {
            if (pend.have && pend.act == act && pend.hi + 1 == prev) {
                pend.hi = pos - 1;
            } else {
                if (pend.have) mx_print(f, &m, pend.lo, pend.hi, pend.act, &written);
                pend.lo = prev;
                pend.hi = pos - 1;
                pend.act = act;
                pend.have = 1;
            }
        }
        if (i == m.n) break;
        for (; i < m.n && m.ev[i].pos == pos; i++) {
            int l = m.ev[i].l4;
            cnt[l] += m.ev[i].d;
            if (cnt[l] > 0) act |= 1ULL << l; else act &= ~(1ULL << l);
        }
        prev = pos;
    }
    if (pend.have) mx_print(f, &m, pend.lo, pend.hi, pend.act, &written);
    if (written) fprintf(f, " }\n");
    free(m.ev);
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
static void emit_fakeip_elements(FILE *f, const char *path) {
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

/* Элементы набора. Источник fakeip.state печатается своей раскладкой (пары по строке, и
 * строки elements нет вовсе, если пар нет); остальные — одной строкой через запятую.
 *
 * Строка elements у адресных источников печатается, даже если в файлах не нашлось ни одной
 * адресной строки: строитель кладёт файлы в набор, только когда check_address_lists насчитал
 * в них адреса, и пустым набор здесь выйдет лишь гонкой (список исчез после проверки) —
 * ровно как у прежнего генератора. */
static void print_elements(FILE *f, const struct nft_set *s) {
    int list = 0;
    for (const struct nft_elsrc *e = s->els; e; e = e->next) {
        if (e->k == NFT_EL_FAKEIP_STATE) emit_fakeip_elements(f, e->s);
        else if (e->k == NFT_EL_MIXED) emit_mixed(f, e->p);
        else list = 1;
    }
    if (!list) return;
    fprintf(f, "        elements = { ");
    size_t written = 0;
    for (const struct nft_elsrc *e = s->els; e; e = e->next) {
        if (e->k == NFT_EL_ADDR_FILE) written += emit_elements(f, e->s, written);
        else if (e->k == NFT_EL_SRS) written += emit_srs(f, e->s, e->p, written);
        else if (e->k == NFT_EL_VALUE) {
            if (written++) fputs(", ", f);
            fputs(e->s, f);
        }
    }
    fprintf(f, " }\n");
}

static void print_set(FILE *f, const struct nft_set *s) {
    fprintf(f, "%s    %s %s {\n", s->o.gap ? "\n" : "", s->data ? "map" : "set", s->o.name);
    if (s->data) fprintf(f, "        type %s : %s;\n", s->key, s->data);
    else fprintf(f, "        type %s\n", s->key);
    if (s->flags) {
        fprintf(f, "        flags ");
        const char *sep = "";
        if (s->flags & NFT_SET_INTERVAL) { fprintf(f, "%sinterval", sep); sep = ","; }
        if (s->flags & NFT_SET_TIMEOUT) fprintf(f, "%stimeout", sep);
        fprintf(f, "\n");
    }
    if (s->auto_merge) fprintf(f, "        auto-merge\n");
    print_elements(f, s);
    fprintf(f, "    }\n");
}

static void print_expr(FILE *f, const struct nft_table *t, const struct nft_rule *r,
                       const struct nft_expr *x) {
    switch (x->k) {
    case NFT_X_RAW:
    case NFT_X_MARKSET:
    case NFT_X_NOTRACK:
    case NFT_X_FRAG6:
        fputs(x->text, f);
        break;
    case NFT_X_FAMILY:
        fprintf(f, "meta nfproto ipv%d", x->fam);
        break;
    case NFT_X_SETREF:
        fprintf(f, "%s @%s", x->text, x->arg);
        break;
    case NFT_X_COUNTER:
        /* Нули — коротким `counter`: так вывод `--dry-run` на чистой машине остаётся тем же
         * текстом, что и раньше. */
        if (r->pkts || r->bytes) fprintf(f, "counter packets %lu bytes %lu", r->pkts, r->bytes);
        else fputs("counter", f);
        break;
    case NFT_X_DNAT:
        /* В таблице одного семейства семейство и так известно, и слово ip после dnat там
         * лишнее; в inet без него nft не знает, адрес какого семейства подставлять. */
        fprintf(f, "dnat %sto %s map @%s", t->fam == NFT_FAM_INET ? "ip " : "", x->text, x->arg);
        break;
    case NFT_X_JUMP:
        fprintf(f, "jump %s", x->arg);
        break;
    }
}

static void print_rule(FILE *f, const struct nft_table *t, const struct nft_rule *r) {
    fputs("        ", f);
    int first = 1;
    for (const struct nft_expr *x = r->x; x; x = x->next) {
        /* «meta nfproto ipvN» в таблице ip/ip6 ничего не сужает — семейство задала таблица. */
        if (x->k == NFT_X_FAMILY && t->fam != NFT_FAM_INET) continue;
        if (!first) fputc(' ', f);
        print_expr(f, t, r, x);
        first = 0;
    }
    if (r->comment) fprintf(f, "%scomment \"%s\"", first ? "" : " ", r->comment);
    fputc('\n', f);
}

static void print_chain(FILE *f, const struct nft_table *t, const struct nft_chain *c) {
    fprintf(f, "%s    chain %s {\n", c->o.gap ? "\n" : "", c->o.name);
    if (c->type) {
        char prio[48];
        ir_prio_str(c, prio, sizeof(prio));
        fprintf(f, "        type %s hook %s priority %s; policy %s;\n",
                c->type, c->hook, prio, c->policy ? c->policy : "accept");
    }
    for (const struct nft_rule *r = c->rules; r; r = r->next) print_rule(f, t, r);
    fprintf(f, "    }\n");
}

static const char *fam_name(enum nft_family fam) {
    switch (fam) {
    case NFT_FAM_IP: return "ip";
    case NFT_FAM_IP6: return "ip6";
    case NFT_FAM_INET: break;
    }
    return "inet";
}

void nft_print(const struct nft_rs *rs, FILE *f) {
    for (const struct nft_table *t = rs->tables; t; t = t->next) {
        fprintf(f, "table %s %s {\n", fam_name(t->fam), t->name);
        for (struct nft_obj *o = t->objs; o; o = o->next) {
            if (o->k == NFT_OBJ_SET) print_set(f, (const struct nft_set *)o);
            else print_chain(f, t, (const struct nft_chain *)o);
        }
        fprintf(f, "}\n");
    }
}
