#include "dnsd_int.h"

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

/* APPENDS, so several lists can feed one channel. The caller clears the ruleset
 * before the first file — reloading must not accumulate the previous generation. */
int load_rules_into(const char *path, struct ruleset *rs) {
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
