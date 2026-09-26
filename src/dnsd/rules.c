#include "dnsd_int.h"
#include "srs.h"

#define MAX_RULE_LINES 65536

/* ---------------------------------------------------------------------- */
/* rule matching                                                          */
/* ---------------------------------------------------------------------- */

static const char *ruleset_key(const void *owner, uint32_t idx) {
    return ((const struct ruleset *)owner)->rules[idx].pattern;
}

void ruleset_free(struct ruleset *rs) {
    for (size_t i = 0; i < rs->n; i++) {
        free(rs->rules[i].pattern);
        if (rs->rules[i].re_valid)
            regfree(&rs->rules[i].re);
    }
    free(rs->rules);
    sindex_free(&rs->idx);
    free(rs->fancy);
    rs->rules = NULL;
    rs->fancy = NULL;
    rs->fancy_n = rs->fancy_cap = 0;
    rs->n = 0;
    rs->cap = 0;
}

/* strip \r, comments (#...), surrounding whitespace; returns 0 for a blank
 * line the caller should skip. */
static int clean_line(char *line) {
    char *h = strchr(line, '#');
    if (h) *h = '\0';
    size_t n = strlen(line);
    while (n > 0 && (line[n - 1] == '\r' || line[n - 1] == '\n' ||
                     line[n - 1] == ' ' || line[n - 1] == '\t')) {
        line[--n] = '\0';
    }
    char *start = line;
    while (*start == ' ' || *start == '\t') start++;
    if (start != line) memmove(line, start, strlen(start) + 1);
    return line[0] != '\0';
}

int ruleset_add(struct ruleset *rs, const char *raw) {
    if (rs->n >= MAX_RULE_LINES) return -1;
    if (rs->n == rs->cap) {
        size_t newcap = rs->cap ? rs->cap * 2 : 64;
        struct rule *nr = realloc(rs->rules, newcap * sizeof(*nr));
        if (!nr) return -1;
        rs->rules = nr;
        rs->cap = newcap;
    }
    struct rule *r = &rs->rules[rs->n];
    memset(r, 0, sizeof(*r));

    if (strncmp(raw, "re:", 3) == 0) {
        r->type = RULE_REGEX;
        if (regcomp(&r->re, raw + 3, REG_EXTENDED | REG_ICASE | REG_NOSUB) != 0)
            return -1; /* bad pattern: skip this rule, don't crash the daemon */
        r->re_valid = 1;
        r->pattern = strdup(raw + 3);
    } else if (raw[0] == '=') {
        r->type = RULE_EXACT;
        r->pattern = strdup(raw + 1);
        str_lower(r->pattern);
    } else if (strchr(raw, '*') || strchr(raw, '?')) {
        r->type = RULE_WILDCARD;
        r->pattern = strdup(raw);
        str_lower(r->pattern);
    } else {
        r->type = RULE_NAMESPACE;
        r->pattern = strdup(raw);
        str_lower(r->pattern);
    }
    if (!r->pattern && r->type != RULE_REGEX) return -1;
    /* Запись FQDN с завершающей точкой (`foo.org.`) — законная для человека, но имя вопроса
     * из пакета собирается без неё, и такое правило не совпадало ни с чем: канал молча не
     * брал домен (I-318). Точка снимается. Если после этого не осталось ни буквы, ни цифры
     * (`.`, `*.`), правила нет: такая строка и прежде не совпадала ни с чем, и снятая точка
     * не должна превращать её в «всё». */
    if (r->type != RULE_REGEX) {
        size_t pl = strlen(r->pattern), was = pl;
        while (pl > 0 && r->pattern[pl - 1] == '.') r->pattern[--pl] = '\0';
        int named = 0;
        for (size_t i = 0; i < pl; i++)
            if (isalnum((unsigned char)r->pattern[i])) { named = 1; break; }
        if (pl != was && !named) { free(r->pattern); r->pattern = NULL; return -1; }
    }
    rs->n++;

    /* Место в индексе — сразу при добавлении, а не отдельным проходом после загрузки: иначе
     * появилось бы состояние «правила загружены, индекс ещё нет», в котором подбор молча
     * отвечает «не совпало». Такую ошибку не видно вовсе — трафик просто идёт мимо канала. */
    if (r->type == RULE_EXACT || r->type == RULE_NAMESPACE) {
        unsigned tag = r->type == RULE_EXACT ? RTAG_EXACT : RTAG_NAMESPACE;
        if (sindex_put(&rs->idx, rs, ruleset_key, r->pattern, (uint32_t)(rs->n - 1), tag) != 0)
            return -1;
    } else {
        if (rs->fancy_n == rs->fancy_cap) {
            size_t nc = rs->fancy_cap ? rs->fancy_cap * 2 : 16;
            uint32_t *nf = realloc(rs->fancy, nc * sizeof(*nf));
            if (!nf) return -1;
            rs->fancy = nf;
            rs->fancy_cap = nc;
        }
        rs->fancy[rs->fancy_n++] = (uint32_t)(rs->n - 1);
    }
    return 0;
}

/* ---- наборы sing-box (.srs) -------------------------------------------------------------
 *
 * Доменный элемент набора — строка правила в том же синтаксисе, что строка `.lst` (соответствие
 * видов — enum srs_dom в srs.h), поэтому дальше он идёт тем же ruleset_add, и сопоставление у
 * имён из набора и из списка одно. Подсети набора резолверу не нужны: их кладёт в набор
 * компилятор. */
static int dom_rule(const struct srs_elem *el, char *buf, size_t n) {
    switch (el->dom) {
    case SRS_DOM_EXACT:    return snprintf(buf, n, "=%s", el->str);
    case SRS_DOM_SUFFIX:   return snprintf(buf, n, "%s", el->str);
    case SRS_DOM_WILDCARD: return snprintf(buf, n, "*%s", el->str);
    case SRS_DOM_KEYWORD:  return snprintf(buf, n, "*%s*", el->str);
    case SRS_DOM_REGEX:    return snprintf(buf, n, "re:%s", el->str);
    }
    return -1;
}

/* Куда класть элемент каждой клаузы: правила назначения и исключений (NULL — клауза не
 * выбрана). */
struct srs_to { struct ruleset **dst; struct ruleset **excl; };

static int srs_to_rules(void *ctx, const struct srs_elem *el) {
    struct srs_to *t = ctx;
    if (el->kind != SRS_EL_DOMAIN) return 0;
    struct ruleset *rs = el->excl ? t->excl[el->clause] : t->dst[el->clause];
    if (!rs) return 0;
    char buf[4200];
    int k = dom_rule(el, buf, sizeof(buf));
    if (k > 0 && (size_t)k < sizeof(buf)) ruleset_add(rs, buf);
    return 0;
}

/* Имена набора целиком — в rs: клаузы имён без исключений (путь к `.srs` без выбора клауз, как
 * путь к `.lst`). Клаузы с исключениями так не выражаются — их берёт dch_rules_load по выбору
 * из таблицы каналов. */
static int load_srs_all(const char *path, struct ruleset *rs) {
    const struct srs_set *s;
    struct err e = {0};
    if (srs_open(path, &s, &e) != 0) {
        fprintf(stderr, "steer[warn] dnsd: %s\n", e.msg);
        return -1;
    }
    size_t n = srs_clause_n(s);
    struct ruleset **dst = calloc(n ? n : 1, sizeof(*dst));
    struct ruleset **excl = calloc(n ? n : 1, sizeof(*excl));
    if (!dst || !excl) { free(dst); free(excl); srs_release(s); return -1; }
    for (size_t i = 0; i < n; i++) {
        const struct srs_clause *c = srs_clause(s, i);
        if (c->kind == SRS_C_DOM && !(c->flags & SRS_F_XDOM) && !c->src_n && !c->pkg_n)
            dst[i] = rs;
    }
    struct srs_to t = { dst, excl };
    int rc = srs_walk(s, SRS_EL_DOMAIN, NULL, srs_to_rules, &t, &e);
    if (rc != 0) fprintf(stderr, "steer[warn] dnsd: %s\n", e.msg);
    free(dst);
    free(excl);
    srs_release(s);
    return rc ? -1 : 0;
}

/* APPENDS, so several lists can feed one channel. The caller clears the ruleset
 * before the first file — reloading must not accumulate the previous generation.
 *
 * Набор sing-box узнаётся по подписи «SRS» в первых байтах, а не по расширению: файл списка
 * называет управляющий слой как хочет, а подпись у формата одна (srs_sniff). */
int load_rules_into(const char *path, struct ruleset *rs) {
    if (srs_sniff(path)) return load_srs_all(path, rs);
    FILE *f = fopen(path, "r");
    if (!f) return -1; /* missing file: caller keeps what it has, not an error */
    char line[512];
    while (fgets(line, sizeof(line), f)) {
        if (!clean_line(line)) continue;
        /* Адресные строки — не наши: их из этого же файла возьмёт компилятор набора правил
         * (emit_elements). Пропуск обязателен, а не косметичен: без него `8.8.8.0/24` стал
         * бы доменным правилом RULE_NAMESPACE для имени «8.8.8.0/24», то есть правилом,
         * которое не совпадёт ни с одним запросом и займёт место в индексе. На списке из
         * девятнадцати тысяч префиксов таких правил было бы девятнадцать тысяч. */
        if (spec_line_is_addr(line)) continue;
        ruleset_add(rs, line);
    }
    fclose(f);
    return 0;
}

/* ---- источники правил канала ------------------------------------------------------------ */

void dch_parts_free(struct dpart *parts, size_t n) {
    for (size_t i = 0; i < n; i++) {
        ruleset_free(&parts[i].rules);
        ruleset_free(&parts[i].excl);
    }
    free(parts);
}

static struct dpart *part_get(struct dpart **parts, size_t *n, const struct l4match *l4,
                              int with_excl) {
    if (!with_excl)
        for (size_t i = 0; i < *n; i++)
            if (!(*parts)[i].has_excl && l4match_same(&(*parts)[i].l4, l4)) return &(*parts)[i];
    struct dpart *p = realloc(*parts, (*n + 1) * sizeof(*p));
    if (!p) return NULL;
    *parts = p;
    memset(&p[*n], 0, sizeof(p[*n]));
    p[*n].l4 = *l4;
    p[*n].has_excl = with_excl;
    return &p[(*n)++];
}

/* «N», «N-M», «N=сужение» через запятую: клаузы набора и (у составного) их сужение. Сужение —
 * l4_to_text: «-», «udp/50000-65535+19000-20000». */
static int sel_parse(const char *s, size_t len, size_t ncl, uint8_t *bits, struct l4match *eff,
                     int *annotated) {
    size_t i = 0;
    while (i < len) {
        size_t st = i;
        unsigned long lo = 0, hi;
        while (i < len && s[i] >= '0' && s[i] <= '9') lo = lo * 10 + (unsigned long)(s[i++] - '0');
        if (i == st) return -1;
        hi = lo;
        if (i < len && s[i] == '-') {
            i++;
            st = i;
            hi = 0;
            while (i < len && s[i] >= '0' && s[i] <= '9') hi = hi * 10 + (unsigned long)(s[i++] - '0');
            if (i == st || hi < lo) return -1;
        }
        struct l4match m;
        memset(&m, 0, sizeof(m));
        if (i < len && s[i] == '=') {
            i++;
            st = i;
            while (i < len && s[i] != ',') i++;
            if (l4_from_text(s + st, i - st, &m) != 0) return -1;
            *annotated = 1;
        }
        for (unsigned long c = lo; c <= hi && c < ncl; c++) {
            bits[c >> 3] |= (uint8_t)(1u << (c & 7));
            eff[c] = m;
        }
        if (i < len && s[i] != ',') return -1;
        if (i < len) i++;
    }
    return 0;
}

/* Один источник вида «srs:<клаузы>:<путь>». */
static int load_srs_sel(const char *sel, size_t sel_len, const char *path, struct ruleset *main,
                        struct dpart **parts, size_t *parts_n, int *composite) {
    const struct srs_set *s;
    struct err e = {0};
    if (srs_open(path, &s, &e) != 0) {
        fprintf(stderr, "steer[warn] dnsd: %s\n", e.msg);
        return -1;
    }
    size_t n = srs_clause_n(s);
    uint8_t *bits = calloc((n + 7) / 8 + 1, 1);
    struct l4match *eff = calloc(n ? n : 1, sizeof(*eff));
    struct ruleset **dst = calloc(n ? n : 1, sizeof(*dst));
    struct ruleset **excl = calloc(n ? n : 1, sizeof(*excl));
    int annotated = 0, rc = -1;
    if (!bits || !eff || !dst || !excl) goto out;
    if (sel_parse(sel, sel_len, n, bits, eff, &annotated) != 0) {
        fprintf(stderr, "steer[warn] dnsd: %s: испорченный выбор клауз «%.*s»\n", path,
                (int)sel_len, sel);
        goto out;
    }
    if (annotated) *composite = 1;
    /* Сначала — в какую часть идёт каждая клауза (номером: realloc частей их сдвигает), потом
     * указатели на готовые части. */
    long *pi = calloc(n ? n : 1, sizeof(*pi));
    if (!pi) goto out;
    for (size_t i = 0; i < n; i++) {
        pi[i] = -1;
        if (!(bits[i >> 3] & (1u << (i & 7)))) continue;
        const struct srs_clause *c = srs_clause(s, i);
        if (c->kind != SRS_C_DOM) continue;
        int x = (c->flags & SRS_F_XDOM) != 0;
        if (!annotated && !x) { pi[i] = -2; continue; }
        /* Исключения — своя часть на клаузу: «x.com, но не y.x.com» не должно снимать y.x.com
         * у соседней клаузы, где он назван без исключений. */
        struct dpart *p = part_get(parts, parts_n, &eff[i], x);
        if (!p) { free(pi); goto out; }
        pi[i] = (long)(p - *parts);
    }
    for (size_t i = 0; i < n; i++) {
        if (pi[i] == -2) dst[i] = main;
        else if (pi[i] >= 0) {
            dst[i] = &(*parts)[pi[i]].rules;
            if ((*parts)[pi[i]].has_excl) excl[i] = &(*parts)[pi[i]].excl;
        }
    }
    free(pi);
    struct srs_to t = { dst, excl };
    rc = srs_walk(s, SRS_EL_DOMAIN, bits, srs_to_rules, &t, &e);
    if (rc != 0) fprintf(stderr, "steer[warn] dnsd: %s\n", e.msg);
out:
    free(bits); free(eff); free(dst); free(excl);
    srs_release(s);
    return rc ? -1 : 0;
}

int dch_rules_load(const struct dchan *d, struct ruleset *main, struct dpart **parts,
                   size_t *parts_n, int *composite) {
    memset(main, 0, sizeof(*main));
    *parts = NULL;
    *parts_n = 0;
    *composite = 0;
    int missing = 0;
    for (size_t k = 0; k < d->rules_n; k++) {
        const char *src = d->rules_path[k];
        if (!strncmp(src, "srs:", 4)) {
            const char *sel = src + 4, *colon = strchr(sel, ':');
            if (!colon || load_srs_sel(sel, (size_t)(colon - sel), colon + 1, main, parts,
                                       parts_n, composite) != 0)
                missing++;
        } else if (!strncmp(src, "cl:", 3)) {
            /* Собственный список канала в составном наборе: все его имена — с сужением канала. */
            const char *l4t = src + 3, *colon = strchr(l4t, ':');
            struct l4match m;
            struct dpart *p;
            *composite = 1;
            if (!colon || l4_from_text(l4t, (size_t)(colon - l4t), &m) != 0 ||
                !(p = part_get(parts, parts_n, &m, 0)) || load_rules_into(colon + 1, &p->rules) != 0)
                missing++;
        } else if (load_rules_into(src, main) != 0) {
            missing++;
        }
    }
    return missing;
}

int dch_matches(const struct dchan *d, const char *host) {
    if (ruleset_match(&d->rules, host)) return 1;
    for (size_t i = 0; i < d->parts_n; i++)
        if (ruleset_match(&d->parts[i].rules, host) &&
            !(d->parts[i].has_excl && ruleset_match(&d->parts[i].excl, host)))
            return 1;
    return 0;
}

int load_rules(const char *path, struct ruleset *rs) {
    ruleset_free(rs);
    memset(rs, 0, sizeof(*rs));
    return load_rules_into(path, rs);
}

/* namespace match: exact hostname match, or hostname ends with "." + pattern */
static int match_namespace(const char *pattern, const char *host) {
    size_t hl = strlen(host), pl = strlen(pattern);
    if (hl == pl) return strcmp(host, pattern) == 0;
    if (hl > pl + 1 && host[hl - pl - 1] == '.')
        return strcmp(host + hl - pl, pattern) == 0;
    return 0;
}

static int rule_matches(const struct rule *r, const char *host_lower) {
    switch (r->type) {
        case RULE_EXACT:
            return strcmp(r->pattern, host_lower) == 0;
        case RULE_NAMESPACE:
            return match_namespace(r->pattern, host_lower);
        case RULE_WILDCARD:
            return fnmatch(r->pattern, host_lower, 0) == 0;
        case RULE_REGEX:
            return r->re_valid && regexec(&r->re, host_lower, 0, NULL, 0) == 0;
    }
    return 0;
}

/* Совпадает ли имя с каким-нибудь правилом набора.
 *
 * Точные и доменные правила проверяются НЕ ПЕРЕБОРОМ, а по суффиксам имени: доменное
 * правило совпадает тогда и только тогда, когда его шаблон — это само имя или его суффикс,
 * начинающийся на границе точки. Значит достаточно спросить индекс про «a.b.c», «b.c», «c»
 * — то есть сделать столько поисков, сколько в имени точек плюс один. Для обычного имени
 * это два-четыре обращения вместо тысяч сравнений строк.
 *
 * Правило «точное» отличается тем, что годится только на первом шаге: оно совпадает с самим
 * именем и не совпадает с его поддоменами. Метка в индексе это и различает. */
int ruleset_match(const struct ruleset *rs, const char *host) {
    char lower[MAX_HOSTNAME];
    size_t n = strlen(host);
    if (n >= sizeof(lower)) n = sizeof(lower) - 1;
    memcpy(lower, host, n);
    lower[n] = '\0';
    str_lower(lower);

    for (const char *suf = lower;; ) {
        uint32_t hit = sindex_get(&rs->idx, rs, ruleset_key, suf);
        if (hit) {
            unsigned tag = hit >> SIDX_TAG_SHIFT;
            if (tag & RTAG_NAMESPACE) return 1;
            if ((tag & RTAG_EXACT) && suf == lower) return 1;
        }
        const char *dot = strchr(suf, '.');
        if (!dot) break;
        suf = dot + 1;
    }

    for (size_t i = 0; i < rs->fancy_n; i++)
        if (rule_matches(&rs->rules[rs->fancy[i]], lower)) return 1;
    return 0;
}
