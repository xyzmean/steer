/* Юнит-стенд читателя наборов sing-box (src/model/srs.c) и раскладки канала (srsplan.c).
 *
 * Что проверяется:
 *   - настоящие файлы издателя (tests/srs/discord, telegram, youtube .srs): обход отдаёт ровно
 *     то, что печатал прежний `steer srs-read` (его вывод снят до переделки и лежит рядом —
 *     *.read.dom/.pfx/.meta), и сужение discord — по клаузам, а не одно на набор;
 *   - потоковость: чего не просили (want), того нет; выбор клауз (sel) отдаёт только их;
 *   - не-ASCII имена (tests/srs/idn.srs, собран tests/srs/mksrs.py): разворот ключа по рунам;
 *   - версия 1 формата (суффикс двумя ключами);
 *   - нормальная форма (logic.srs): «или» — объединение, «и» — пересечение сужений,
 *     исключения имён и подсетей, дополнение портов, source_ip_cidr, package_name, «весь
 *     трафик приложения»; снятое — одной строкой с причинами;
 *   - IPv6 назначения — с семейством 6;
 *   - отказы на испорченном: подпись, версия, обрыв, контрольная сумма;
 *   - операции над сужением: пересечение, непересекающиеся ящики, текст туда и обратно;
 *   - раскладка канала: одно сужение — обычная часть, смешанное — составная или деление,
 *     сужение канала против сужения набора — пересечение или отказ.
 *
 * Модули линкуются (Makefile: MODEL_KINDS), запускается из корня репозитория. */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "spec.h"
#include "srs.h"
#include "srsplan.h"
#include "unit.h"

#define FIX "tests/srs/"

static char *slurp(const char *path) {
    FILE *f = fopen(path, "rb");
    if (!f) return strdup("");
    fseek(f, 0, SEEK_END);
    long n = ftell(f);
    rewind(f);
    char *b = malloc((size_t)n + 1);
    size_t got = fread(b, 1, (size_t)n, f);
    b[got] = '\0';
    fclose(f);
    return b;
}

/* Сборщик вывода в синтаксисе srs-read. */
struct buf { char *p; size_t n, cap; };
static void bput(struct buf *b, const char *s) {
    size_t l = strlen(s);
    if (b->n + l + 1 > b->cap) {
        b->cap = (b->n + l + 1) * 2;
        b->p = realloc(b->p, b->cap);
    }
    memcpy(b->p + b->n, s, l + 1);
    b->n += l;
}

struct coll {
    struct buf dom, pfx, xdom, xpfx;
    size_t ndom, n4, n6, nx;
    int last_clause;
};

static int collect(void *ctx, const struct srs_elem *el) {
    struct coll *c = ctx;
    char line[600];
    c->last_clause = (int)el->clause;
    if (el->kind == SRS_EL_DOMAIN) {
        switch (el->dom) {
        case SRS_DOM_SUFFIX:   snprintf(line, sizeof(line), "%s\n", el->str); break;
        case SRS_DOM_WILDCARD: snprintf(line, sizeof(line), "*%s\n", el->str); break;
        case SRS_DOM_EXACT:    snprintf(line, sizeof(line), "=%s\n", el->str); break;
        case SRS_DOM_KEYWORD:  snprintf(line, sizeof(line), "*%s*\n", el->str); break;
        case SRS_DOM_REGEX:    snprintf(line, sizeof(line), "re:%s\n", el->str); break;
        }
        bput(el->excl ? &c->xdom : &c->dom, line);
        if (el->excl) c->nx++; else c->ndom++;
        return 0;
    }
    if (el->family == 6) { c->n6++; return 0; }
    snprintf(line, sizeof(line), "%u.%u.%u.%u/%d\n", el->addr[0], el->addr[1], el->addr[2],
             el->addr[3], el->plen);
    bput(el->excl ? &c->xpfx : &c->pfx, line);
    if (el->excl) c->nx++; else c->n4++;
    return 0;
}

static void coll_free(struct coll *c) {
    free(c->dom.p); free(c->pfx.p); free(c->xdom.p); free(c->xpfx.p);
    memset(c, 0, sizeof(*c));
}

static const char *S(const struct buf *b) { return b->p ? b->p : ""; }

static int walk(const char *path, unsigned want, const uint8_t *sel, struct coll *c) {
    const struct srs_set *s;
    struct err e = {0};
    memset(c, 0, sizeof(*c));
    if (srs_open(path, &s, &e) != 0) { printf("  (%s)\n", e.msg); return -1; }
    int rc = srs_walk(s, want, sel, collect, c, &e);
    if (rc) printf("  (%s)\n", e.msg);
    return rc;
}

/* Сужение набора так, как его печатал srs-read: одно на весь набор. */
static void meta_of(const struct srs_set *s, struct buf *m) {
    int tcp = 0, udp = 0;
    char ports[32][16];
    size_t pn = 0;
    for (size_t i = 0; i < srs_clause_n(s); i++) {
        const struct srs_clause *c = srs_clause(s, i);
        tcp |= c->net_tcp;
        udp |= c->net_udp;
        for (size_t k = 0; k < c->raw_n; k++) {
            char b[16];
            if (c->raw_range[k] || c->raw[k].lo != c->raw[k].hi)
                snprintf(b, sizeof(b), "%u-%u", c->raw[k].lo, c->raw[k].hi);
            else
                snprintf(b, sizeof(b), "%u", c->raw[k].lo);
            size_t j = 0;
            while (j < pn && strcmp(ports[j], b)) j++;
            if (j == pn && pn < 32) snprintf(ports[pn++], 16, "%s", b);
        }
    }
    if (tcp && udp) bput(m, "proto=both\n");
    else if (tcp) bput(m, "proto=tcp\n");
    else if (udp) bput(m, "proto=udp\n");
    if (pn) {
        bput(m, "ports=");
        for (size_t i = 0; i < pn; i++) { if (i) bput(m, ","); bput(m, ports[i]); }
        bput(m, "\n");
    }
}

static void t_publisher(void) {
    static const char *const names[] = { "discord", "telegram", "youtube" };
    for (size_t i = 0; i < 3; i++) {
        char path[128], want[128], what[128];
        snprintf(path, sizeof(path), FIX "%s.srs", names[i]);
        struct coll c;
        snprintf(what, sizeof(what), "%s: разобран", names[i]);
        check(what, 0, walk(path, SRS_EL_DOMAIN | SRS_EL_CIDR, NULL, &c));
        snprintf(want, sizeof(want), FIX "%s.read.dom", names[i]);
        char *w = slurp(want);
        snprintf(what, sizeof(what), "%s: имена — как у прежнего srs-read, до байта", names[i]);
        check_str(what, w, S(&c.dom));
        free(w);
        snprintf(want, sizeof(want), FIX "%s.read.pfx", names[i]);
        w = slurp(want);
        snprintf(what, sizeof(what), "%s: подсети — как у прежнего srs-read, до байта", names[i]);
        check_str(what, w, S(&c.pfx));
        free(w);
        const struct srs_set *s;
        struct err e = {0};
        srs_open(path, &s, &e);
        struct buf m = { 0 };
        meta_of(s, &m);
        snprintf(want, sizeof(want), FIX "%s.read.meta", names[i]);
        w = slurp(want);
        snprintf(what, sizeof(what), "%s: сужение набора целиком — как у прежнего srs-read", names[i]);
        check_str(what, w, S(&m));
        free(w);
        free(m.p);
        snprintf(what, sizeof(what), "%s: ничего не снято", names[i]);
        check(what, 1, srs_skipped(s) == NULL);
        coll_free(&c);
    }
}

static void t_discord_clauses(void) {
    const struct srs_set *s;
    struct err e = {0};
    check("discord: открыт", 0, srs_open(FIX "discord.srs", &s, &e));
    check("discord: клауз три — по правилу набора", 3, (long)srs_clause_n(s));
    const struct srs_clause *c0 = srs_clause(s, 0), *c1 = srs_clause(s, 1), *c2 = srs_clause(s, 2);
    check("клауза 0 — имена", SRS_C_DOM, c0->kind);
    check("у имён сужения нет", 1, l4match_empty(&c0->l4));
    check("имён 20", 20, (long)c0->n_dom);
    check("клауза 1 — подсети", SRS_C_CIDR, c1->kind);
    char t[64];
    l4_to_text(&c1->l4, t, sizeof(t));
    check_str("у клаузы 1 сужение своё: udp 50000-65535", "udp/50000-65535", t);
    check("и 8 префиксов", 8, (long)c1->n_v4);
    l4_to_text(&c2->l4, t, sizeof(t));
    check_str("у клаузы 2 — udp 19000-20000", "udp/19000-20000", t);
    check("и один префикс", 1, (long)c2->n_v4);
    /* Выбор клауз: только клауза 2. */
    uint8_t sel[1] = { 1u << 2 };
    struct coll c;
    walk(FIX "discord.srs", SRS_EL_DOMAIN | SRS_EL_CIDR, sel, &c);
    check_str("выбор клауз: только подсети клаузы 2", "104.16.0.0/12\n", S(&c.pfx));
    check("и ни одного имени", 0, (long)c.ndom);
    coll_free(&c);
}

static void t_want(void) {
    struct coll c;
    walk(FIX "telegram.srs", SRS_EL_CIDR, NULL, &c);
    check("want=подсети: имён не отдано", 0, (long)c.ndom);
    check("а подсетей 10", 10, (long)c.n4);
    coll_free(&c);
    walk(FIX "telegram.srs", SRS_EL_DOMAIN, NULL, &c);
    check("want=имена: подсетей не отдано", 0, (long)c.n4);
    check("а имён 20", 20, (long)c.ndom);
    coll_free(&c);
}

static void t_idn(void) {
    struct coll c;
    check("не-ASCII: разобран", 0, walk(FIX "idn.srs", SRS_EL_DOMAIN, NULL, &c));
    const char *d = S(&c.dom);
    check("точное имя по-русски — буквы не задом наперёд", 1, strstr(d, "=пример.рф\n") != NULL);
    check("суффикс по-русски", 1, strstr(d, "\nпочта.рф\n") != NULL || !strncmp(d, "почта.рф\n", strlen("почта.рф\n")));
    check("буквальный суффикс с точкой", 1, strstr(d, "*.тест.рф\n") != NULL);
    check("греческий", 1, strstr(d, "δοκιμή.gr\n") != NULL);
    check("punycode как есть", 1, strstr(d, "=xn--e1afmkfd.xn--p1ai\n") != NULL);
    check("ключевое слово", 1, strstr(d, "*ключ*\n") != NULL);
    coll_free(&c);
}

static void t_v1(void) {
    struct coll c, o;
    check("версия 1: разобран", 0, walk(FIX "telegram-v1.srs", SRS_EL_DOMAIN | SRS_EL_CIDR, NULL, &c));
    walk(FIX "telegram.srs", SRS_EL_DOMAIN | SRS_EL_CIDR, NULL, &o);
    check("суффикс версии 1 — два ключа на запись", (long)o.ndom * 2, (long)c.ndom);
    check("«=имя» и «*.имя» на каждую запись", 1,
          strstr(S(&c.dom), "=telegram.org\n") && strstr(S(&c.dom), "*.telegram.org\n"));
    check("подсети те же", 1, o.n4 == c.n4 && o.n4 == 10);
    coll_free(&c);
    coll_free(&o);
}

static const struct srs_clause *find_clause(const struct srs_set *s, unsigned kind,
                                            unsigned rule) {
    for (size_t i = 0; i < srs_clause_n(s); i++)
        if (srs_clause(s, i)->kind == kind && srs_clause(s, i)->rule == rule) return srs_clause(s, i);
    return NULL;
}

static void t_logic(void) {
    const struct srs_set *s;
    struct err e = {0};
    check("логика: разобран", 0, srs_open(FIX "logic.srs", &s, &e));
    /* «или» — две клаузы одного правила верхнего уровня. */
    check("«или»: клауза имён", 1, find_clause(s, SRS_C_DOM, 0) != NULL);
    check("«или»: клауза подсетей", 1, find_clause(s, SRS_C_CIDR, 0) != NULL);
    const struct srs_clause *x = find_clause(s, SRS_C_DOM, 1);
    check("«и» с исключением имени: клауза есть", 1, x != NULL);
    check("и с флагом исключений-имён", 1, x && (x->flags & SRS_F_XDOM));
    const struct srs_clause *p = find_clause(s, SRS_C_CIDR, 2);
    char t[80] = "";
    if (p) l4_to_text(&p->l4, t, sizeof(t));
    check_str("«и» udp, 1000-2000, не 1500: дополнение портов", "udp/1000-1499+1501-2000", t);
    const struct srs_clause *src = find_clause(s, SRS_C_CIDR, 3);
    check("source_ip_cidr: клауза с источником", 1, src && src->src_n == 1 &&
          src->src[0].net == 0xC0A80100u && src->src[0].plen == 28);
    const struct srs_clause *pk = find_clause(s, SRS_C_CIDR, 4);
    check_str("package_name: приложение при клаузе", "org.telegram.messenger",
              pk && pk->pkg_n ? pk->pkg[0] : "");
    const struct srs_clause *all = find_clause(s, SRS_C_ALL, 5);
    check("только package_name: весь трафик приложения", 1, all != NULL);
    check("процесс: правило снято", 1, find_clause(s, SRS_C_DOM, 6) == NULL);
    check("invert верхнего уровня: снято", 1, find_clause(s, SRS_C_DOM, 7) == NULL);
    check("«и» с двумя назначениями: снято", 1, find_clause(s, SRS_C_DOM, 8) == NULL &&
          find_clause(s, SRS_C_CIDR, 8) == NULL);
    const struct srs_clause *xc = find_clause(s, SRS_C_CIDR, 9);
    check("«и» с исключением подсети: флаг", 1, xc && (xc->flags & SRS_F_XCIDR));
    check("и подсетей исключения v4 — одна", 1, xc && xc->n_xv4 == 1);
    check("только сеть без назначения: снято", 1, find_clause(s, SRS_C_ALL, 10) == NULL);
    const char *sk = srs_skipped(s);
    check("снятое названо одной строкой", 1, sk != NULL);
    if (!sk) sk = "";
    printf("     снято: %s\n", sk);
    check("… с процессами", 1, strstr(sk, "процессы") != NULL);
    check("… со «всё, кроме»", 1, strstr(sk, "всё, кроме") != NULL);
    check("… с двумя назначениями", 1, strstr(sk, "двумя назначениями") != NULL);
    check("… с правилом без назначения", 1, strstr(sk, "без назначения") != NULL);
    check("… и их число", 1, strstr(sk, "снято правил: 4") != NULL);
    struct coll c;
    walk(FIX "logic.srs", SRS_EL_DOMAIN | SRS_EL_CIDR, NULL, &c);
    check_str("исключение-имя отдано с пометкой excl", "=y.x.example\n", S(&c.xdom));
    check_str("исключение-подсеть — тоже", "10.10.1.0/24\n", S(&c.xpfx));
    check("снятые правила элементов не дают", 1, !strstr(S(&c.dom), "proc.example") &&
          !strstr(S(&c.dom), "inv.example") && !strstr(S(&c.pfx), "10.9.0.0"));
    check("keyword и regex на месте", 1, strstr(S(&c.dom), "*kw*\n") && strstr(S(&c.dom), "re:^re\\.example$\n"));
    coll_free(&c);
}

static void t_v6(void) {
    const struct srs_set *s;
    struct err e = {0};
    srs_open(FIX "v6.srs", &s, &e);
    const struct srs_clause *c = srs_clause(s, 0);
    check("IPv6: флаги v4 и v6", SRS_F_V4 | SRS_F_V6, c ? (long)(c->flags & (SRS_F_V4 | SRS_F_V6)) : -1);
    check("IPv6: префиксов v6 два", 2, c ? (long)c->n_v6 : -1);
    struct coll k;
    walk(FIX "v6.srs", SRS_EL_CIDR, NULL, &k);
    check("отданы с семейством 6", 2, (long)k.n6);
    check("v4 — отдельно", 1, (long)k.n4);
    coll_free(&k);
}

static int write_file(const char *path, const void *b, size_t n) {
    FILE *f = fopen(path, "wb");
    if (!f) return -1;
    fwrite(b, 1, n, f);
    fclose(f);
    return 0;
}

static void t_broken(void) {
    char dir[] = "/tmp/srsunit.XXXXXX";
    if (!mkdtemp(dir)) return;
    char p[256];
    const struct srs_set *s = NULL;
    struct err e;
    size_t n = 0;
    char *good = NULL;
    {
        FILE *f = fopen(FIX "youtube.srs", "rb");
        good = malloc(4096);
        n = fread(good, 1, 4096, f);
        fclose(f);
    }
    snprintf(p, sizeof(p), "%s/magic.srs", dir);
    write_file(p, "NOTSRS\0\0\0\0\0\0", 12);
    memset(&e, 0, sizeof(e));
    check("чужой файл — отказ", -1, srs_open(p, &s, &e));
    check("и сказано про подпись SRS", 1, strstr(e.msg, "SRS") != NULL);
    check("и назван файл", 1, strstr(e.msg, "magic.srs") != NULL);

    snprintf(p, sizeof(p), "%s/ver.srs", dir);
    char *v = malloc(n);
    memcpy(v, good, n);
    v[3] = (char)255;
    write_file(p, v, n);
    memset(&e, 0, sizeof(e));
    check("неизвестная версия — отказ", -1, srs_open(p, &s, &e));
    check("и версия названа", 1, strstr(e.msg, "255") != NULL);

    snprintf(p, sizeof(p), "%s/trunc.srs", dir);
    write_file(p, good, 120);
    memset(&e, 0, sizeof(e));
    check("обрыв — отказ", -1, srs_open(p, &s, &e));

    snprintf(p, sizeof(p), "%s/adler.srs", dir);
    memcpy(v, good, n);
    v[n - 1] ^= 0x5A;
    write_file(p, v, n);
    memset(&e, 0, sizeof(e));
    check("контрольная сумма не сошлась — отказ", -1, srs_open(p, &s, &e));
    check("и так и сказано", 1, strstr(e.msg, "контрольная сумма") != NULL);
    if (!strstr(e.msg, "контрольная сумма")) printf("     (%s)\n", e.msg);

    snprintf(p, sizeof(p), "%s/body.srs", dir);
    write_file(p, "SRS\001\x78\x9c garbage garbage", 22);
    memset(&e, 0, sizeof(e));
    check("тело — мусор: отказ", -1, srs_open(p, &s, &e));

    snprintf(p, sizeof(p), "%s/none.srs", dir);
    memset(&e, 0, sizeof(e));
    check("нет файла — отказ", -1, srs_open(p, &s, &e));
    check("с путём", 1, strstr(e.msg, "none.srs") != NULL);

    /* Файл сменился между проходами — второй проход не отдаёт элементы по старой разметке. */
    snprintf(p, sizeof(p), "%s/swap.srs", dir);
    write_file(p, good, n);
    memset(&e, 0, sizeof(e));
    check("целый файл по новому пути — разобран", 0, srs_open(p, &s, &e));
    FILE *f = fopen(FIX "telegram.srs", "rb");
    char tg[4096];
    size_t tn = fread(tg, 1, sizeof(tg), f);
    fclose(f);
    char tmp[300];
    snprintf(tmp, sizeof(tmp), "%s/swap.new", dir);
    write_file(tmp, tg, tn);
    rename(tmp, p);
    struct coll c;
    memset(&c, 0, sizeof(c));
    memset(&e, 0, sizeof(e));
    check("файл сменился между проходами — отказ", 1,
          s && srs_walk(s, SRS_EL_DOMAIN, NULL, collect, &c, &e) != 0 && strstr(e.msg, "изменился"));
    coll_free(&c);
    srs_cache_drop();
    free(v);
    free(good);
    char cmd[300];
    snprintf(cmd, sizeof(cmd), "rm -rf %s", dir);
    if (system(cmd) != 0) printf("  (не убран %s)\n", dir);
}

static void t_l4(void) {
    struct l4match a, b, o;
    char t[128];
    l4_from_text("udp/50000-65535", 15, &a);
    memset(&b, 0, sizeof(b));
    check("пересечение с «без сужения» — то же самое", 1, l4_intersect(&a, &b, &o) && l4match_same(&o, &a));
    l4_from_text("tcp", 3, &b);
    check("udp и tcp не пересекаются", 0, l4_intersect(&a, &b, &o));
    l4_from_text("any/40000-60000", 15, &b);
    check("udp 50000-65535 и tcp/udp 40000-60000 пересекаются", 1, l4_intersect(&a, &b, &o));
    l4_to_text(&o, t, sizeof(t));
    check_str("… в udp 50000-60000", "udp/50000-60000", t);
    l4_from_text("any/443+80", 10, &a);
    l4_from_text("any/80+443", 10, &b);
    check("одно множество в разном порядке — равны как множества", 1, l4_same_set(&a, &b));
    check("… и не равны по порядку (имя набора зависит от написанного)", 0, l4match_same(&a, &b));
    check("пересечение, совпавшее с первым, — первое как написано", 1,
          l4_intersect(&a, &b, &o) && l4match_same(&o, &a));
    /* Ящики. */
    struct l4match u1, u2, u3;
    l4_from_text("udp/50000-65535", 15, &u1);
    l4_from_text("udp/19000-20000+60000-65535", 27, &u2);
    l4_from_text("tcp", 3, &u3);
    const struct l4match *ms[3] = { &u1, &u2, &u3 };
    struct l4box bx[L4BOX_MAX];
    size_t nb = l4_union_boxes(ms, 3, bx);
    struct buf out = { 0 };
    for (size_t i = 0; i < nb; i++) {
        l4_box_text(&bx[i], t, sizeof(t));
        bput(&out, t);
        bput(&out, ";");
    }
    check_str("объединение — непересекающиеся ящики, udp слиты",
              "6 . 0-65535;17 . 19000-20000;17 . 50000-65535;", S(&out));
    free(out.p);
    struct l4match none;
    memset(&none, 0, sizeof(none));
    const struct l4match *ms2[2] = { &u1, &none };
    nb = l4_union_boxes(ms2, 2, bx);
    l4_box_text(&bx[0], t, sizeof(t));
    check("с «без сужения» — один ящик", 1, (long)nb);
    check_str("… 0-255 × 0-65535", "0-255 . 0-65535", t);
    l4_to_text(&u2, t, sizeof(t));
    struct l4match back;
    check("текст сужения читается обратно", 0, l4_from_text(t, strlen(t), &back));
    check("… в то же самое", 1, l4match_same(&back, &u2));
    check("испорченный текст — отказ", -1, l4_from_text("udp/9-1", 7, &back));
}

static struct spec g_sp;

static struct channel *chan(const char *srs, const char *l4) {
    memset(&g_sp, 0, sizeof(g_sp));
    struct channel *c = &g_sp.ch[0];
    g_sp.ch_n = 1;
    snprintf(c->name, sizeof(c->name), "discord");
    snprintf(c->out, sizeof(c->out), "vpn");
    c->srs_files[0] = srs;
    c->srs_n = 1;
    if (l4) l4_from_text(l4, strlen(l4), &c->l4);
    return c;
}

static void t_plan(void) {
    struct srs_plan pl;
    struct err e = {0};
    struct channel *c = chan(FIX "discord.srs", NULL);
    check("discord, ядро с составными наборами: разложен", 0, srs_plan_channel(&g_sp, c, 1, &pl, &e));
    check("… одной составной частью", 1, pl.n == 1 && pl.p[0].kind == SP_COMPOSITE);
    check("… с именами и подсетями", 1, pl.n && pl.p[0].has_dom && pl.p[0].has_v4);
    check("… подсетей 9", 9, pl.n ? (long)pl.p[0].n_v4 : -1);
    srs_plan_free(&pl);
    check("discord, без составных: разложен", 0, srs_plan_channel(&g_sp, c, 0, &pl, &e));
    check("… на три части", 3, (long)pl.n);
    char t[80] = "";
    if (pl.n == 3) l4_to_text(&pl.p[1].l4, t, sizeof(t));
    check_str("… вторая — udp 50000-65535", "udp/50000-65535", t);
    check("… имена — в первой, без сужения", 1, pl.n == 3 && pl.p[0].has_dom && l4match_empty(&pl.p[0].l4));
    srs_plan_free(&pl);
    c = chan(FIX "discord.srs", "tcp");
    memset(&e, 0, sizeof(e));
    check("канал tcp + набор udp: отказ", -1, srs_plan_channel(&g_sp, c, 1, &pl, &e));
    check("… и сказано, что не пересекаются", 1, strstr(e.msg, "не пересекаются") != NULL);
    c = chan(FIX "uniform.srs", NULL);
    memset(&e, 0, sizeof(e));
    check("одно сужение у всего набора: разложен", 0, srs_plan_channel(&g_sp, c, 1, &pl, &e));
    check("… обычной частью, не составной", 1, pl.n == 1 && pl.p[0].kind == SP_PLAIN);
    if (pl.n) l4_to_text(&pl.p[0].l4, t, sizeof(t));
    check_str("… с сужением набора", "udp/50000-65535", t);
    srs_plan_free(&pl);
    c = chan(FIX "uniform.srs", "udp/50000-65535");
    check("то же сужение и у канала: разложен", 0, srs_plan_channel(&g_sp, c, 1, &pl, &e));
    check("… сужение части — канала (одно и то же)", 1, pl.n == 1 && l4match_same(&pl.p[0].l4, &c->l4));
    srs_plan_free(&pl);
    c = chan(FIX "logic.srs", NULL);
    check("логика на роутере: разложен", 0, srs_plan_channel(&g_sp, c, 1, &pl, &e));
    int extra_src = 0, extra_x = 0;
    for (size_t i = 0; i < pl.n; i++) {
        if (pl.p[i].kind == SP_EXTRA && pl.p[i].src_n) extra_src = 1;
        if (pl.p[i].kind == SP_EXTRA && pl.p[i].xcidr) extra_x = 1;
    }
    check("источник — доп. частью", 1, extra_src);
    check("исключения-подсети — доп. частью", 1, extra_x);
    check("приложения на роутере сняты с предупреждением", 1, strstr(pl.warn, "приложения") != NULL);
    srs_plan_free(&pl);
    c = chan(FIX "v6.srs", NULL);
    check("IPv6: разложен", 0, srs_plan_channel(&g_sp, c, 1, &pl, &e));
    check("… и сказано, что v6 пропущены", 1, strstr(pl.warn, "IPv6") != NULL);
    srs_plan_free(&pl);
    c = chan("/nonexistent/x.srs", NULL);
    check("нет файла: не отказ спеке", 0, srs_plan_channel(&g_sp, c, 1, &pl, &e));
    check("… а предупреждение и пустая часть", 1, pl.n == 1 && strstr(pl.warn, "x.srs") != NULL);
    srs_plan_free(&pl);
}

int main(void) {
    t_publisher();
    t_discord_clauses();
    t_want();
    t_idn();
    t_v1();
    t_logic();
    t_v6();
    t_broken();
    t_l4();
    t_plan();
    return unit_done("srsunit");
}
