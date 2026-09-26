/* Промежуточное дерево набора правил: арена, построение, поиск, переделка. Устройство и
 * уровень детализации — в шапке ir.h. */
#include <stdarg.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include "ir.h"

/* ---- арена ---------------------------------------------------------------------------
 *
 * Куски по 4 КБ, выделение сдвигом, освобождение одно — на всё дерево сразу. Дерево живёт
 * одну генерацию и целиком умирает после печати, отдельные узлы не освобождаются никогда,
 * так что счётчик ссылок или free по узлу были бы работой ради работы. 4 КБ — потому что
 * обычное дерево (десяток цепочек, пара десятков правил) укладывается в два-три куска, а
 * элементы наборов в арену не попадают вовсе (см. ir.h, «Память»). Кусок больше 4 КБ
 * выделяется под одну просьбу, если она сама больше. */
#define IR_CHUNK 4096

struct ir_chunk {
    struct ir_chunk *next;
    size_t used, cap;
    /* Выравнивание данных — как у самого строгого из того, что в арене лежит. */
    union { void *p; long long ll; double d; } data[];
};

static void *ir_alloc(struct nft_rs *rs, size_t n) {
    if (rs->oom) return NULL;
    const size_t al = sizeof(((struct ir_chunk *)0)->data[0]);
    n = (n + al - 1) / al * al;
    struct ir_chunk *c = rs->arena;
    if (!c || c->cap - c->used < n) {
        size_t cap = n > IR_CHUNK ? n : IR_CHUNK;
        c = malloc(sizeof(*c) + cap);
        if (!c) { rs->oom = 1; return NULL; }
        c->next = rs->arena;
        c->used = 0;
        c->cap = cap;
        rs->arena = c;
    }
    void *p = (char *)c->data + c->used;
    c->used += n;
    memset(p, 0, n);
    return p;
}

void nft_rs_init(struct nft_rs *rs) {
    memset(rs, 0, sizeof(*rs));
    rs->tables_tail = &rs->tables;
}

void nft_rs_free(struct nft_rs *rs) {
    struct ir_chunk *c = rs->arena;
    while (c) {
        struct ir_chunk *n = c->next;
        free(c);
        c = n;
    }
    nft_rs_init(rs);
}

const char *ir_strdup(struct nft_rs *rs, const char *s) {
    if (!s) return NULL;
    size_t n = strlen(s) + 1;
    char *p = ir_alloc(rs, n);
    if (p) memcpy(p, s, n);
    return p;
}

static const char *ir_vprintf(struct nft_rs *rs, const char *fmt, va_list ap) {
    va_list aq;
    va_copy(aq, ap);
    int n = vsnprintf(NULL, 0, fmt, aq);
    va_end(aq);
    if (n < 0) { rs->oom = 1; return NULL; }
    char *p = ir_alloc(rs, (size_t)n + 1);
    if (p) vsnprintf(p, (size_t)n + 1, fmt, ap);
    return p;
}

const char *ir_printf(struct nft_rs *rs, const char *fmt, ...) {
    va_list ap;
    va_start(ap, fmt);
    const char *p = ir_vprintf(rs, fmt, ap);
    va_end(ap);
    return p;
}

/* ---- построение ---------------------------------------------------------------------- */

struct nft_table *ir_table_add(struct nft_rs *rs, enum nft_family fam, const char *name) {
    struct nft_table *t = ir_alloc(rs, sizeof(*t));
    if (!t) return NULL;
    t->fam = fam;
    t->name = ir_strdup(rs, name);
    t->objs_tail = &t->objs;
    t->rs = rs;
    *rs->tables_tail = t;
    rs->tables_tail = &t->next;
    return t;
}

void ir_obj_append(struct nft_table *t, struct nft_obj *o) {
    if (!t || !o) return;
    o->table = t;
    o->next = NULL;
    *t->objs_tail = o;
    t->objs_tail = &o->next;
}

void ir_obj_unlink(struct nft_obj *o) {
    if (!o || !o->table) return;
    struct nft_table *t = o->table;
    struct nft_obj **pp = &t->objs;
    while (*pp && *pp != o) pp = &(*pp)->next;
    if (!*pp) return;
    *pp = o->next;
    if (t->objs_tail == &o->next) t->objs_tail = pp;
    o->next = NULL;
    o->table = NULL;
}

void ir_obj_insert_after(struct nft_obj *after, struct nft_obj *o) {
    if (!after || !o || !after->table) return;
    struct nft_table *t = after->table;
    o->table = t;
    o->next = after->next;
    after->next = o;
    if (t->objs_tail == &after->next) t->objs_tail = &o->next;
}

struct nft_set *ir_set_add(struct nft_table *t, const char *name, const char *key) {
    if (!t) return NULL;
    struct nft_set *s = ir_alloc(t->rs, sizeof(*s));
    if (!s) return NULL;
    s->o.k = NFT_OBJ_SET;
    s->o.name = ir_strdup(t->rs, name);
    s->key = ir_strdup(t->rs, key);
    s->els_tail = &s->els;
    ir_obj_append(t, &s->o);
    return s;
}

struct nft_set *ir_map_add(struct nft_table *t, const char *name, const char *key,
                           const char *data) {
    struct nft_set *s = ir_set_add(t, name, key);
    if (s) s->data = ir_strdup(t->rs, data);
    return s;
}

static struct nft_elsrc *ir_set_src(struct nft_set *s, enum nft_elk k, const char *str) {
    if (!s || !s->o.table) return NULL;
    struct nft_elsrc *e = ir_alloc(s->o.table->rs, sizeof(*e));
    if (!e) return NULL;
    e->k = k;
    e->s = ir_strdup(s->o.table->rs, str);
    *s->els_tail = e;
    s->els_tail = &e->next;
    return e;
}

void *ir_mem(struct nft_rs *rs, size_t n) { return ir_alloc(rs, n); }

void ir_set_srs(struct nft_set *s, const char *path, const struct ir_srs *src) {
    struct nft_elsrc *e = ir_set_src(s, NFT_EL_SRS, path);
    if (e) e->p = src;
}

void ir_set_mixed(struct nft_set *s, const struct ir_mixed *m) {
    struct nft_elsrc *e = ir_set_src(s, NFT_EL_MIXED, "");
    if (e) e->p = m;
}

void ir_set_value(struct nft_set *s, const char *v) { ir_set_src(s, NFT_EL_VALUE, v); }
void ir_set_file(struct nft_set *s, const char *path) { ir_set_src(s, NFT_EL_ADDR_FILE, path); }
void ir_set_fakeip_state(struct nft_set *s, const char *path) {
    ir_set_src(s, NFT_EL_FAKEIP_STATE, path);
}

struct nft_chain *ir_chain_add(struct nft_table *t, const char *name) {
    if (!t) return NULL;
    struct nft_chain *c = ir_alloc(t->rs, sizeof(*c));
    if (!c) return NULL;
    c->o.k = NFT_OBJ_CHAIN;
    c->o.name = ir_strdup(t->rs, name);
    c->rules_tail = &c->rules;
    ir_obj_append(t, &c->o);
    return c;
}

struct nft_chain *ir_base_chain_add(struct nft_table *t, const char *name, const char *type,
                                    const char *hook, const char *prio_name, int prio_off) {
    struct nft_chain *c = ir_chain_add(t, name);
    if (!c) return NULL;
    c->type = ir_strdup(t->rs, type);
    c->hook = ir_strdup(t->rs, hook);
    c->prio_name = ir_strdup(t->rs, prio_name);
    c->prio_off = prio_off;
    c->policy = "accept";
    return c;
}

void ir_gap(void *obj) {
    if (obj) ((struct nft_obj *)obj)->gap = 1;
}

static struct nft_rs *rule_rs(const struct nft_rule *r) {
    return r->chain->o.table->rs;
}

struct nft_rule *ir_rule(struct nft_chain *c) {
    if (!c || !c->o.table) return NULL;
    struct nft_rule *r = ir_alloc(c->o.table->rs, sizeof(*r));
    if (!r) return NULL;
    r->x_tail = &r->x;
    r->chain = c;
    *c->rules_tail = r;
    c->rules_tail = &r->next;
    return r;
}

struct nft_expr *ir_expr_insert(struct nft_rule *r, struct nft_expr *before, enum nft_xk k,
                                const char *text, const char *arg) {
    if (!r) return NULL;
    struct nft_expr *x = ir_alloc(rule_rs(r), sizeof(*x));
    if (!x) return NULL;
    x->k = k;
    x->text = text;
    x->arg = arg;
    struct nft_expr **pp = &r->x;
    while (*pp && *pp != before) pp = &(*pp)->next;
    x->next = *pp;
    *pp = x;
    if (!x->next) r->x_tail = &x->next;
    return x;
}

static struct nft_expr *ir_push(struct nft_rule *r, enum nft_xk k, const char *text,
                                const char *arg) {
    return ir_expr_insert(r, NULL, k, text, arg);
}

void ir_x(struct nft_rule *r, const char *fmt, ...) {
    if (!r) return;
    va_list ap;
    va_start(ap, fmt);
    const char *s = ir_vprintf(rule_rs(r), fmt, ap);
    va_end(ap);
    if (s) ir_push(r, NFT_X_RAW, s, NULL);
}

void ir_markset(struct nft_rule *r, const char *fmt, ...) {
    if (!r) return;
    va_list ap;
    va_start(ap, fmt);
    const char *s = ir_vprintf(rule_rs(r), fmt, ap);
    va_end(ap);
    if (s) ir_push(r, NFT_X_MARKSET, s, NULL);
}

void ir_family(struct nft_rule *r, int fam) {
    if (!r) return;
    struct nft_expr *x = ir_push(r, NFT_X_FAMILY, NULL, NULL);
    if (x) x->fam = fam;
    r->fam = fam;
}

void ir_setref(struct nft_rule *r, const char *match, const char *set) {
    if (!r) return;
    ir_push(r, NFT_X_SETREF, ir_strdup(rule_rs(r), match), ir_strdup(rule_rs(r), set));
}

void ir_counter(struct nft_rule *r, unsigned long pkts, unsigned long bytes) {
    if (!r) return;
    r->pkts = pkts;
    r->bytes = bytes;
    ir_push(r, NFT_X_COUNTER, NULL, NULL);
}

void ir_dnat(struct nft_rule *r, const char *key, const char *map) {
    if (!r) return;
    ir_push(r, NFT_X_DNAT, ir_strdup(rule_rs(r), key), ir_strdup(rule_rs(r), map));
}

void ir_jump(struct nft_rule *r, const char *chain) {
    if (!r) return;
    ir_push(r, NFT_X_JUMP, NULL, ir_strdup(rule_rs(r), chain));
}

void ir_notrack(struct nft_rule *r) {
    if (r) ir_push(r, NFT_X_NOTRACK, "notrack", NULL);
}

void ir_frag6(struct nft_rule *r, const char *text) {
    if (r) ir_push(r, NFT_X_FRAG6, ir_strdup(rule_rs(r), text), NULL);
}

void ir_comment(struct nft_rule *r, const char *fmt, ...) {
    if (!r) return;
    va_list ap;
    va_start(ap, fmt);
    r->comment = ir_vprintf(rule_rs(r), fmt, ap);
    va_end(ap);
}

void ir_rule_fam(struct nft_rule *r, int fam) {
    if (r) r->fam = fam;
}

struct nft_rule *ir_rule_clone(struct nft_chain *dst, const struct nft_rule *r) {
    if (!r || !r->chain) return NULL;
    struct nft_rs *rs = rule_rs(r);
    struct nft_rule *n = ir_alloc(rs, sizeof(*n));
    if (!n) return NULL;
    n->x_tail = &n->x;
    n->fam = r->fam;
    n->pkts = r->pkts;
    n->bytes = r->bytes;
    n->comment = r->comment;
    for (const struct nft_expr *x = r->x; x; x = x->next) {
        struct nft_expr *c = ir_alloc(rs, sizeof(*c));
        if (!c) return NULL;
        *c = *x;
        c->next = NULL;
        *n->x_tail = c;
        n->x_tail = &c->next;
    }
    if (dst) {
        n->chain = dst;
        *dst->rules_tail = n;
        dst->rules_tail = &n->next;
    } else {
        struct nft_chain *c = r->chain;
        n->chain = c;
        n->next = r->next;
        ((struct nft_rule *)r)->next = n;
        if (c->rules_tail == &((struct nft_rule *)r)->next) c->rules_tail = &n->next;
    }
    return n;
}

/* ---- поиск --------------------------------------------------------------------------- */

struct nft_table *ir_table_find(const struct nft_rs *rs, enum nft_family fam, const char *name) {
    for (struct nft_table *t = rs->tables; t; t = t->next)
        if (t->fam == fam && (!name || (t->name && !strcmp(t->name, name)))) return t;
    return NULL;
}

static struct nft_obj *obj_find(const struct nft_table *t, enum nft_objk k, const char *name) {
    if (!t) return NULL;
    for (struct nft_obj *o = t->objs; o; o = o->next)
        if (o->k == k && o->name && !strcmp(o->name, name)) return o;
    return NULL;
}

struct nft_set *ir_set_find(const struct nft_table *t, const char *name) {
    return ir_obj_set(obj_find(t, NFT_OBJ_SET, name));
}

struct nft_chain *ir_chain_find(const struct nft_table *t, const char *name) {
    return ir_obj_chain(obj_find(t, NFT_OBJ_CHAIN, name));
}

static int comment_is(const struct nft_rule *r, const char *comment) {
    if (!comment) return 1;
    return r->comment && !strcmp(r->comment, comment);
}

struct nft_rule *ir_rule_find(const struct nft_chain *c, const char *comment) {
    if (!c) return NULL;
    for (struct nft_rule *r = c->rules; r; r = r->next)
        if (comment_is(r, comment)) return r;
    return NULL;
}

size_t ir_rule_count(const struct nft_chain *c, const char *comment) {
    size_t n = 0;
    if (!c) return 0;
    for (struct nft_rule *r = c->rules; r; r = r->next)
        if (comment_is(r, comment)) n++;
    return n;
}

struct nft_expr *ir_expr_find(const struct nft_rule *r, enum nft_xk k) {
    if (!r) return NULL;
    for (struct nft_expr *x = r->x; x; x = x->next)
        if (x->k == k) return x;
    return NULL;
}

int ir_rule_has(const struct nft_rule *r, const char *needle) {
    if (!r) return 0;
    for (struct nft_expr *x = r->x; x; x = x->next)
        if ((x->text && strstr(x->text, needle)) || (x->arg && strstr(x->arg, needle)))
            return 1;
    return 0;
}

/* Именованные приоритеты nft (таблица из nftables: doc/nft.txt, «PRIORITY»). */
static const struct { const char *name; int v; } prio_names[] = {
    { "raw", -300 }, { "mangle", -150 }, { "dstnat", -100 }, { "filter", 0 },
    { "security", 50 }, { "srcnat", 100 },
};

int ir_prio_value(const struct nft_chain *c) {
    int base = 0;
    if (c->prio_name)
        for (size_t i = 0; i < sizeof(prio_names) / sizeof(prio_names[0]); i++)
            if (!strcmp(prio_names[i].name, c->prio_name)) base = prio_names[i].v;
    return base + c->prio_off;
}

void ir_prio_str(const struct nft_chain *c, char *dst, size_t n) {
    if (!c->prio_name) snprintf(dst, n, "%d", c->prio_off);
    else if (c->prio_off > 0) snprintf(dst, n, "%s + %d", c->prio_name, c->prio_off);
    else if (c->prio_off < 0) snprintf(dst, n, "%s - %d", c->prio_name, -c->prio_off);
    else snprintf(dst, n, "%s", c->prio_name);
}
