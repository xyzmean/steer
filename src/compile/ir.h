#ifndef STEER_IR_H
#define STEER_IR_H

/* ---- промежуточное дерево набора правил nftables -------------------------------------
 *
 * ЗАЧЕМ. До 1.7 генератор печатал текст nftables прямо в FILE*, и всё, что хотело знать о
 * наборе правил что-то кроме текста, — старая раскладка ядра 4.9, стенды, будущие модули
 * видов и платформ — должно было либо вклиниваться в fprintf ветками, либо разбирать текст
 * обратно. Дерево разводит эти две заботы: генератор (generate.c) и модули видов строят
 * ЧТО стоит в ядре, раскладка старого ядра (legacy.c) переделывает дерево, а печатник
 * (print.c) один на всех и знает только синтаксис nft.
 *
 * СТРУКТУРА. Набор правил (struct nft_rs) — список таблиц в порядке печати; таблица
 * (семейство, имя) — упорядоченный список объектов: наборов/карт (struct nft_set) и цепочек
 * (struct nft_chain) вперемешку, потому что в тексте они и идут вперемешку (набор failopen
 * стоит между цепочками, карта fakeip — рядом со своей цепочкой dnat), а снимок генератора
 * обязан совпадать до байта. Цепочка — базовая (type/hook/priority/policy) или обычная
 * (type == NULL), с правилами в порядке проверки.
 *
 * УРОВЕНЬ ДЕТАЛИЗАЦИИ ПРАВИЛА — последовательность выражений-токенов, каждое со своим
 * видом (enum nft_xk). Почти все выражения — NFT_X_RAW, то есть готовый текст nft
 * («meta l4proto tcp», «ip saddr { 192.168.1.0/24 }»): глубокая типизация каждого
 * сравнения ничего бы сейчас не дала, а стоила бы второго словаря nft внутри движка. Свой
 * вид получают только те выражения, которые кто-то ищет или переделывает, не разбирая текст:
 *
 *   NFT_X_SETREF   поиск в наборе — старая раскладка переименовывает набор и удваивает
 *                  правило на каждую его половину, стенды спрашивают «правило смотрит в @X»;
 *   NFT_X_COUNTER  место счётчика в правиле (оно не всегда в конце: «counter redirect…»),
 *                  сами значения — в полях pkts/bytes правила: перенос счётчиков через apply
 *                  кладёт их туда, клон правила обнуляет;
 *   NFT_X_MARKSET  запись метки пакета — после неё старая раскладка дописывает бит
 *                  перемаршрутизации (STEER_REROUTE_BIT) в цепочках type route;
 *   NFT_X_FAMILY   «meta nfproto ipvN» — в таблице одного семейства лишнее и не печатается;
 *   NFT_X_DNAT     dnat по карте — в inet пишется «dnat ip to», в ip/ip6 «dnat to»;
 *   NFT_X_JUMP, NFT_X_NOTRACK, NFT_X_FRAG6 — чтобы старая раскладка могла снять цепочки с
 *                  notrack (и прыгающие в них) и заменить «exthdr frag exists».
 *
 * comment — отдельным полем: по нему стенды и перенос счётчиков находят правило
 * («steer:<группа>», «steer-down:<группа>»), и печатается он всегда последним. fam — для
 * какого семейства правило (0 — для обоих, 4, 6): в inet это только пометка, а когда
 * старая раскладка разносит nat по таблицам ip и ip6, она решает, куда правило идёт.
 *
 * ПАМЯТЬ. Всё дерево — в арене (цепочка кусков), освобождение одно: nft_rs_free. Элементы
 * наборов в дерево НЕ загружаются: списки бывают на сотни тысяч префиксов, а роутер — на
 * 64 МБ. Набор держит ИСТОЧНИКИ элементов (struct nft_elsrc): путь к адресному списку,
 * путь к файлу состояния fakeip или встроенное значение, — и печатник читает файлы потоком,
 * строка за строкой, как прежде emit_elements. Пиковая память печати та же, что у прямой.
 *
 * ОТКАЗ ПАМЯТИ. Строители не проверяют каждый вызов: при нехватке арены rs->oom ставится в
 * 1, дальнейшие вызовы на NULL-объектах ничего не делают, и тот, кто строил, один раз
 * спрашивает rs->oom и возвращает отказ (правило 5, docs/architecture.md, раздел 2). */

#include <stddef.h>
#include <stdio.h>

enum nft_family { NFT_FAM_INET, NFT_FAM_IP, NFT_FAM_IP6 };

enum nft_xk {
    NFT_X_RAW,       /* text — готовый текст nft */
    NFT_X_FAMILY,    /* «meta nfproto ipv<fam>»; печатается только в inet */
    NFT_X_SETREF,    /* «<text> @<arg>» — поиск в наборе arg */
    NFT_X_MARKSET,   /* text — запись метки пакета («meta mark set …») */
    NFT_X_COUNTER,   /* «counter» или «counter packets N bytes M» (значения — в правиле) */
    NFT_X_DNAT,      /* «dnat [ip ]to <text> map @<arg>» */
    NFT_X_JUMP,      /* «jump <arg>» */
    NFT_X_NOTRACK,   /* «notrack» */
    NFT_X_FRAG6,     /* text — «есть заголовок фрагмента IPv6», запись зависит от ядра */
};

struct nft_expr {
    enum nft_xk k;
    int fam;                    /* NFT_X_FAMILY: 4 или 6 */
    const char *text;
    const char *arg;
    struct nft_expr *next;
};

struct nft_chain;
struct nft_table;
struct nft_rs;

struct nft_rule {
    struct nft_expr *x, **x_tail;
    int fam;                    /* 0 — оба семейства, 4, 6 */
    unsigned long pkts, bytes;  /* значения NFT_X_COUNTER; нули печатаются коротким «counter» */
    const char *comment;        /* NULL — без комментария */
    struct nft_chain *chain;
    struct nft_rule *next;
};

enum nft_objk { NFT_OBJ_SET, NFT_OBJ_CHAIN };

/* Общая голова набора и цепочки — первый член обеих структур. */
struct nft_obj {
    enum nft_objk k;
    const char *name;
    int gap;                    /* пустая строка перед объектом — ради совпадения текста */
    struct nft_table *table;
    struct nft_obj *next;
};

#define NFT_SET_INTERVAL 1u
#define NFT_SET_TIMEOUT  2u

enum nft_elk {
    NFT_EL_VALUE,               /* s — один элемент как есть */
    NFT_EL_ADDR_FILE,           /* s — путь к списку: адресные строки, прочее пропускается */
    NFT_EL_FAKEIP_STATE,        /* s — путь к fakeip.state резолвера: пары «поддельный : настоящий» */
};

struct nft_elsrc {
    enum nft_elk k;
    const char *s;
    struct nft_elsrc *next;
};

struct nft_set {
    struct nft_obj o;
    const char *key;            /* «ipv4_addr», «mark» */
    const char *data;           /* не NULL — это карта (map), тип значения */
    unsigned flags;             /* NFT_SET_* */
    int auto_merge;
    struct nft_elsrc *els, **els_tail;
};

struct nft_chain {
    struct nft_obj o;
    const char *type;           /* NULL — обычная цепочка, без хука */
    const char *hook;
    const char *prio_name;      /* «mangle», «dstnat»…; NULL — приоритет числом prio_off */
    int prio_off;
    const char *policy;
    struct nft_rule *rules, **rules_tail;
};

struct nft_table {
    enum nft_family fam;
    const char *name;
    struct nft_obj *objs, **objs_tail;
    struct nft_rs *rs;
    struct nft_table *next;
};

struct ir_chunk;
struct nft_rs {
    struct nft_table *tables, **tables_tail;
    struct ir_chunk *arena;
    int oom;
};

/* ---- жизнь дерева ---- */
void nft_rs_init(struct nft_rs *rs);
void nft_rs_free(struct nft_rs *rs);
const char *ir_strdup(struct nft_rs *rs, const char *s);
const char *ir_printf(struct nft_rs *rs, const char *fmt, ...)
    __attribute__((format(printf, 2, 3)));

/* ---- построение ---- */
struct nft_table *ir_table_add(struct nft_rs *rs, enum nft_family fam, const char *name);
struct nft_set *ir_set_add(struct nft_table *t, const char *name, const char *key);
struct nft_set *ir_map_add(struct nft_table *t, const char *name, const char *key, const char *data);
void ir_set_value(struct nft_set *s, const char *v);
void ir_set_file(struct nft_set *s, const char *path);
void ir_set_fakeip_state(struct nft_set *s, const char *path);
struct nft_chain *ir_chain_add(struct nft_table *t, const char *name);
struct nft_chain *ir_base_chain_add(struct nft_table *t, const char *name, const char *type,
                                    const char *hook, const char *prio_name, int prio_off);
/* Пустая строка перед набором или цепочкой (obj — struct nft_set* или struct nft_chain*). */
void ir_gap(void *obj);

struct nft_rule *ir_rule(struct nft_chain *c);
void ir_x(struct nft_rule *r, const char *fmt, ...) __attribute__((format(printf, 2, 3)));
void ir_family(struct nft_rule *r, int fam);
void ir_setref(struct nft_rule *r, const char *match, const char *set);
void ir_markset(struct nft_rule *r, const char *fmt, ...) __attribute__((format(printf, 2, 3)));
void ir_counter(struct nft_rule *r, unsigned long pkts, unsigned long bytes);
void ir_dnat(struct nft_rule *r, const char *key, const char *map);
void ir_jump(struct nft_rule *r, const char *chain);
void ir_notrack(struct nft_rule *r);
void ir_frag6(struct nft_rule *r, const char *text);
void ir_comment(struct nft_rule *r, const char *fmt, ...) __attribute__((format(printf, 2, 3)));
void ir_rule_fam(struct nft_rule *r, int fam);

/* ---- поиск ---- */
/* name == NULL — первая таблица этого семейства. */
struct nft_table *ir_table_find(const struct nft_rs *rs, enum nft_family fam, const char *name);
struct nft_set *ir_set_find(const struct nft_table *t, const char *name);
struct nft_chain *ir_chain_find(const struct nft_table *t, const char *name);
/* Первое правило с таким комментарием и сколько их (comment == NULL — все правила). */
struct nft_rule *ir_rule_find(const struct nft_chain *c, const char *comment);
size_t ir_rule_count(const struct nft_chain *c, const char *comment);
/* Первое выражение этого вида в правиле или NULL. */
struct nft_expr *ir_expr_find(const struct nft_rule *r, enum nft_xk k);
/* Есть ли в правиле выражение, чей текст содержит needle (для стендов). */
int ir_rule_has(const struct nft_rule *r, const char *needle);
/* Приоритет числом (mangle + 1 = -149) и словами, как пишет nft. */
int ir_prio_value(const struct nft_chain *c);
void ir_prio_str(const struct nft_chain *c, char *dst, size_t n);

static inline struct nft_set *ir_obj_set(struct nft_obj *o) {
    return o && o->k == NFT_OBJ_SET ? (struct nft_set *)o : NULL;
}
static inline struct nft_chain *ir_obj_chain(struct nft_obj *o) {
    return o && o->k == NFT_OBJ_CHAIN ? (struct nft_chain *)o : NULL;
}

/* ---- переделка (раскладки) ---- */
void ir_obj_unlink(struct nft_obj *o);
void ir_obj_append(struct nft_table *t, struct nft_obj *o);
void ir_obj_insert_after(struct nft_obj *after, struct nft_obj *o);
/* Копия правила со своими выражениями (строки общие): в конец dst или сразу за r (dst NULL). */
struct nft_rule *ir_rule_clone(struct nft_chain *dst, const struct nft_rule *r);
/* Новое выражение перед before (before == NULL — в конец). */
struct nft_expr *ir_expr_insert(struct nft_rule *r, struct nft_expr *before, enum nft_xk k,
                                const char *text, const char *arg);

/* ---- печать (print.c) ---- */
/* Текст nft всего дерева в f. Элементы наборов читаются из файлов потоком. */
void nft_print(const struct nft_rs *rs, FILE *f);

#endif
