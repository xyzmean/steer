/* ---- раскладка старого ядра: переделка дерева --------------------------------------------
 *
 * Генератор (generate.c) строит дерево набора правил для современного ядра и про старое не
 * знает ничего. Всё, чем раскладка Linux 4.9 отличается, сделано здесь — ПРЕОБРАЗОВАНИЕМ
 * готового дерева, а печатник у обеих раскладок один (print.c).
 *
 * ПОЧЕМУ ПРЕОБРАЗОВАНИЕ, А НЕ СВОЯ ЧАСТЬ ДЕРЕВА. Старая раскладка — это та же самая политика
 * (те же наборы, те же правила каналов, тот же заворот DNS), только разложенная иначе. Строй
 * она свою часть сама, ей пришлось бы повторять решения генератора — какие правила DNS
 * ставить, какие у группы наборы, где fakeip, — и два повтора одного решения расходятся
 * молча: так и было до 1.7, когда заворот DNS писался дважды, в generate и в хвосте старой
 * раскладки. Преобразование берёт уже принятое решение и меняет только форму, по признакам в
 * самом дереве (вид выражения, тип цепочки, флаги набора, семейство правила), а не по именам
 * групп и выходов. Новое правило генератора попадает в старую раскладку само.
 *
 * Что меняется — по шагам ниже, доводы у каждого:
 *   1. доменный набор (interval + timeout) делится надвое, правила на него — удваиваются;
 *   2. цепочки type route в inet становятся filter + бит перемаршрутизации, снимает его
 *      цепочка route в таблице ip;
 *   3. без notrack в ядре — цепочки с notrack (и прыгающие в них) снимаются, «exthdr frag
 *      exists» заменяется;
 *   4. nat уходит из inet в таблицы ip и ip6, по ОДНОЙ цепочке nat на хук. */
#include <stdlib.h>
#include <string.h>

#include "spec.h"
#include "ir.h"
#include "legacy.h"

/* РАСКЛАДКА НАБОРА ПРАВИЛ ЭТОГО ЗАПУСКА — флаги NFTC_* из nft_compat (nftcompat.h). Ставит
 * cmd_apply перед генерацией; ноль — современное ядро, и тогда дерево не переделывается вовсе,
 * то есть текст тот же, что до появления старой раскладки, байт в байт. На этом держатся все
 * стенды компилятора и то, что роутеры после обновления получают тот же набор правил.
 *
 * Что меняется в старой раскладке — коротко; доводы у каждого шага ниже:
 *   - таблиц становится две-три: `inet` (наборы, разметка, счётчики, очереди — всё, что
 *     filter), `ip` (карта fakeip и ОДНА цепочка nat на prerouting) и `ip6` (заворот DNS по
 *     IPv6, если ядро умеет nat в ip6). Наборы между таблицами не видны, поэтому карта fakeip
 *     живёт там же, где правило dnat, — в ip;
 *   - доменный набор делится надвое: интервальный без сроков (<имя>_n, префиксы из списков) и
 *     hash со сроками (<имя>, туда пишет резолвер); правило канала повторяется на каждую
 *     половину;
 *   - notrack — только если ядро его знает (NFTC_NOTRACK), `exthdr … exists` — заменён. */
int g_nftc;

/* Какие таблицы, кроме inet, есть в старой раскладке. Спрашивают двое — это преобразование
 * и шапка файла в cmd_apply (добавить-и-удалить каждую таблицу раскладки одной транзакцией), —
 * и ответ у них обязан совпадать, иначе `delete table` встретил бы таблицу, которой файл не
 * создаёт, или наоборот. Поэтому и преобразование спрашивает эти же функции, а не выводит
 * ответ из дерева. */
static int has_ip(const struct spec *sp, int nftc) {
    if (!(nftc & NFTC_LEGACY)) return 0;
    if (tgws_present(sp)) return 1;
#ifdef STEER_TGWS
    return 0;
#else
    return 1;                       /* заворот DNS стоит всегда — см. prerouting_dns */
#endif
}

static int has_ip6(int nftc) {
#ifdef STEER_TGWS
    (void)nftc;
    return 0;
#else
    return (nftc & NFTC_LEGACY) && (nftc & NFTC_IP6NAT);
#endif
}

int legacy_has_ip(const struct spec *sp) { return has_ip(sp, g_nftc); }
int legacy_has_ip6(void) { return has_ip6(g_nftc); }

/* Для читателей ядра — diag и explain. Они списков не разбирают (addrs считает только
 * check_address_lists в apply), поэтому спрашивают вторую половину у всякой доменной группы с
 * адресными списками; нет её в ядре — ответ «набора нет», и он просто не прибавляется. */
int legacy_may_have_static(const struct group *g) {
    return NFT_LEGACY && g->domains && g->files_n;
}

/* ---- 1. доменный набор надвое -------------------------------------------------------------
 *
 * СТАРОЕ ЯДРО: интервальный набор со сроками не грузится (у nft_set_rbtree в 4.9 нет
 * NFT_SET_TIMEOUT), а одному набору здесь нужно и то и другое — префиксы из списков навсегда и
 * адреса резолвера на TTL. Поэтому набора два.
 *
 * Динамический — hash со сроками, и он сохраняет ИМЯ ГРУППЫ: резолвер вычисляет имя той же
 * group_set_name и пишет туда не зная про раскладку ничего, кроме одного — что интервальной
 * пары там больше нет (см. nft_add_element в dnsd.c). auto-merge здесь не нужен и не
 * принимается: сливать в hash нечего.
 *
 * Статический — интервальный, с суффиксом _n (nft_static_set_name), и только когда в списках
 * группы есть адресные строки — то есть когда у набора в дереве есть элементы: генератор кладёт
 * списки в набор только тогда. Пустой интервальный набор на каждый доменный канал был бы
 * лишним поиском на каждом пакете.
 *
 * ПРАВИЛ У ГРУППЫ СТАНОВИТСЯ ДВА — по правилу на каждую половину набора. nft не умеет «или»
 * внутри правила, а объединить интервальный набор с hash-набором нечем. Оба правила одинаковы
 * во всём, кроме набора, и первое совпавшее решает, как и раньше. Комментарий у них ОДИН И ТОТ
 * ЖЕ: счётчики читаются по нему, и counters_load складывает правила с одним именем — объём
 * канала остаётся одним числом. Перенесённое значение ложится в первое правило (статическая
 * половина), второе начинает с нуля: сумма от этого не меняется. */
static void split_rules(struct nft_table *t, const char *dyn, const char *stat) {
    for (struct nft_obj *o = t->objs; o; o = o->next) {
        struct nft_chain *c = ir_obj_chain(o);
        if (!c) continue;
        for (struct nft_rule *r = c->rules; r; r = r->next) {
            struct nft_expr *x = ir_expr_find(r, NFT_X_SETREF);
            if (!x || strcmp(x->arg, dyn) != 0) continue;
            struct nft_rule *n = ir_rule_clone(NULL, r);
            if (!n) return;
            n->pkts = n->bytes = 0;
            x->arg = stat;
            r = n;                      /* копию не переделывать второй раз */
        }
    }
}

static void split_timeout_sets(struct nft_table *t) {
    for (struct nft_obj *o = t->objs; o; o = o->next) {
        struct nft_set *s = ir_obj_set(o);
        if (!s || s->data || s->flags != (NFT_SET_INTERVAL | NFT_SET_TIMEOUT)) continue;
        s->flags = NFT_SET_TIMEOUT;
        s->auto_merge = 0;
        if (!s->els) continue;
        char sn[80];
        nft_static_set_name(sn, sizeof(sn), s->o.name);
        /* Новый набор встаёт сразу за динамическим: ir_set_add кладёт в конец таблицы, и
         * его приходится переставить. */
        struct nft_set *st = ir_set_add(t, sn, s->key);
        if (!st) return;
        ir_obj_unlink(&st->o);
        ir_obj_insert_after(&s->o, &st->o);
        st->flags = NFT_SET_INTERVAL;
        st->auto_merge = 1;
        st->els = s->els;
        st->els_tail = s->els_tail;
        s->els = NULL;
        s->els_tail = &s->els;
        split_rules(t, s->o.name, st->o.name);
        o = &st->o;
    }
}

/* ---- 2. цепочки type route -----------------------------------------------------------------
 *
 * В современной раскладке (ядро с nat в inet) разметка на хуке output — цепочка route прямо в
 * inet, где и наборы: смена метки в ней сама заставляет ядро искать маршрут заново. В старой
 * route в inet нет, поэтому там filter, а к метке добавляется STEER_REROUTE_BIT — его снимает
 * цепочка output_reroute в таблице ip (шаг 4), и маршрут пересматривается там (подробно — у
 * STEER_REROUTE_BIT в marks.h). Бит ставится ПОСЛЕ метки соединения, прямо перед счётчиком: в
 * conntrack ему не место, он живёт на пакете до цепочки route в таблице ip. */
static int route_to_filter(struct nft_table *t) {
    int any = 0;
    /* Бит есть только там, где цепочки route строятся (каналы на сам телефон,
     * src/platform/android.c); без него и переделывать нечего. */
    if (!STEER_REROUTE_BIT) return 0;
    for (struct nft_obj *o = t->objs; o; o = o->next) {
        struct nft_chain *c = ir_obj_chain(o);
        if (!c || !c->type || strcmp(c->type, "route") != 0) continue;
        c->type = "filter";
        any = 1;
        for (struct nft_rule *r = c->rules; r; r = r->next) {
            if (!ir_expr_find(r, NFT_X_MARKSET)) continue;
            ir_expr_insert(r, ir_expr_find(r, NFT_X_COUNTER), NFT_X_MARKSET,
                           ir_printf(t->rs, "meta mark set mark or 0x%08x", STEER_REROUTE_BIT),
                           NULL);
        }
    }
    return any;
}

/* ---- 3. notrack и exthdr -------------------------------------------------------------------
 *
 * СТАРОЕ ЯДРО БЕЗ notrack — цепочек с ним нет вовсе. На ядре телефона выражения нет (nft_ct.c в
 * 4.9 его не знает), и строка с ним отвергла бы всю транзакцию. Снимается и цепочка, которая в
 * снятую прыгает, — иначе `jump` в несуществующую отверг бы файл так же. Цена названа при apply
 * (report_legacy_gaps): порождённые обработчиком zapret пакеты остаются на учёте conntrack,
 * traceroute_hops не действует.
 *
 * `exthdr frag exists` на 4.9 НЕ отвергается, а ПОДМЕНЯЕТСЯ: флага «есть ли заголовок» там нет,
 * ядро выбрасывает незнакомый атрибут и грузит сравнение поля frag nexthdr с единицей (снято на
 * стенде tools/vm49). Замена `frag frag-off >= 0` значит то же самое на любом ядре: выражение
 * exthdr без флага ищет заголовок фрагмента в цепочке заголовков и при его отсутствии правило
 * не совпадает, а сравнение `>= 0` верно всегда. Проверено там же сырыми пакетами: совпадает и
 * [ipv6][frag], и [ipv6][hop-by-hop][frag], и не совпадает с пакетом без фрагмента. */
static int chain_has(const struct nft_chain *c, enum nft_xk k, const char *arg) {
    for (struct nft_rule *r = c->rules; r; r = r->next)
        for (struct nft_expr *x = r->x; x; x = x->next)
            if (x->k == k && (!arg || (x->arg && !strcmp(x->arg, arg)))) return 1;
    return 0;
}

static void drop_notrack(struct nft_table *t) {
    for (;;) {
        struct nft_obj *victim = NULL;
        for (struct nft_obj *o = t->objs; o && !victim; o = o->next) {
            struct nft_chain *c = ir_obj_chain(o);
            if (c && chain_has(c, NFT_X_NOTRACK, NULL)) victim = o;
        }
        if (!victim) return;
        const char *name = victim->name;
        ir_obj_unlink(victim);
        /* Прыгающие в снятую — тоже, по кругу, пока снимать нечего. */
        for (int again = 1; again; ) {
            again = 0;
            for (struct nft_obj *o = t->objs; o; o = o->next) {
                struct nft_chain *c = ir_obj_chain(o);
                if (c && chain_has(c, NFT_X_JUMP, name)) {
                    name = o->name;
                    ir_obj_unlink(o);
                    again = 1;
                    break;
                }
            }
        }
    }
}

static void frag6_compat(struct nft_table *t) {
    for (struct nft_obj *o = t->objs; o; o = o->next) {
        struct nft_chain *c = ir_obj_chain(o);
        if (!c) continue;
        for (struct nft_rule *r = c->rules; r; r = r->next)
            for (struct nft_expr *x = r->x; x; x = x->next)
                if (x->k == NFT_X_FRAG6) x->text = "frag frag-off >= 0";
    }
}

/* ---- 4. nat — в таблицы ip и ip6 ---------------------------------------------------------
 *
 * ПОЧЕМУ ОДНА ЦЕПОЧКА NAT НА ХУК, а не столько, сколько в современной раскладке
 * (prerouting_dns, prerouting_dnat, tgws_redirect). До 4.18 каждая базовая цепочка nat —
 * отдельный хук, и первый из них, где ни одно правило не совпало, ставит новому соединению
 * «пустую» трансляцию (nf_nat_alloc_null_binding в nf_nat_ipv4_fn); остальные хуки видят
 * nf_nat_initialized и своих правил уже не проверяют. Три цепочки на 4.9 значили бы, что для
 * запроса DNS работает только первая, а для поддельного адреса — ни одна, если первой стоит
 * цепочка DNS. В одной цепочке правила проверяются по очереди и первое совпавшее ставит
 * трансляцию — ровно то, что делают три цепочки на современном ядре (там после первой
 * состоявшейся трансляции остальные цепочки тоже пропускаются). Порядок правил повторяет
 * порядок цепочек: по приоритету, при равном — в порядке регистрации (DNS и fakeip на dstnat,
 * мост на dstnat + 1).
 *
 * ПОЧЕМУ dstnat - 1. Тот же механизм «пустой трансляции» действует между нами и таблицей nat
 * iptables: её хук на том же приоритете -100 зарегистрирован раньше (при загрузке), и при
 * равном приоритете идёт первым. На Android iptables nat есть всегда (netd держит там правила
 * раздачи интернета), то есть на -100 наша цепочка не увидела бы ни одного нового соединения:
 * ни заворота DNS, ни fakeip. На -101 первыми идём мы. Цена — обратная: для соединения, которое
 * не забрали мы, «пустую» трансляцию назначения ставим уже мы, и правила PREROUTING в iptables
 * nat до него не доходят. У netd там только пустая цепочка oem_nat_pre, раздача интернета живёт
 * в POSTROUTING, которого мы не касаемся; на прочих старых системах с пробросами портов в
 * iptables apply об этом предупреждает (report_legacy_gaps).
 *
 * СЕМЕЙСТВА. Правило идёт в ту таблицу, для чьего семейства оно написано (nft_rule.fam):
 * заворот DNS по подсетям клиентов и правила fakeip и моста — только в ip, заворот по
 * устройству — в обе (в ip6 без «meta nfproto ipv6»: там его печатник и не пишет). Устройственное
 * правило, помеченное в современной раскладке `meta nfproto ipv6` (подсети клиентов заданы),
 * уезжает только в ip6. ip6 — только если ядро умеет nat в ip6 (NFTC_IP6NAT): без этого вся
 * транзакция отверглась бы из-за одной таблицы.
 *
 * Карта fakeip — в той же таблице ip, что и правило dnat: наборы между таблицами не видны.
 * Синтаксис `dnat to` без слова ip печатник выбирает сам по семейству таблицы.
 *
 * ПОЧЕМУ ПУСТАЯ ЦЕПОЧКА postrouting_nat. До 4.18 ядро переписывает адреса только в тех хуках,
 * где зарегистрирована хоть одна цепочка nat, — и обратную трансляцию ответов тоже. Ответ на
 * заворот DNS или на dnat по карте fakeip уходит клиенту через POSTROUTING, и там его адрес
 * источника обязан вернуться к тому, куда клиент спрашивал (1.1.1.1, поддельный 198.18.x.x).
 * Без цепочки на этом хуке ответ ушёл бы с настоящим адресом, и клиент его отбросил бы как
 * чужой. Снято на стенде tools/vm49: правила prerouting срабатывают (счётчики по единице), а
 * SYN-ACK приходит от 10.99.0.1:8080 вместо 198.18.0.0:8080 — пока цепочки нет. На Android её
 * роль и так выполнял бы хук nat iptables, но полагаться на чужую таблицу незачем. Приоритет
 * srcnat + 1, то есть ПОСЛЕ nat iptables (100): пустая цепочка тоже ставит соединению «пустую»
 * трансляцию источника, и окажись она первой — MASQUERADE раздачи интернета у netd больше не
 * сработал бы. В ip6 — там же и по той же причине. */
static int is_nat(const struct nft_chain *c) {
    return c && c->type && !strcmp(c->type, "nat");
}

/* Правила nat-цепочек inet на хуке hook — в цепочку dst, по приоритету (при равном — в
 * порядке цепочек), только подходящие семейству fam. */
static void merge_nat(struct nft_table *in, const char *hook, struct nft_chain *dst, int fam) {
    struct nft_chain *src[16];
    size_t n = 0;
    for (struct nft_obj *o = in->objs; o && n < sizeof(src) / sizeof(src[0]); o = o->next) {
        struct nft_chain *c = ir_obj_chain(o);
        if (is_nat(c) && !strcmp(c->hook, hook)) src[n++] = c;
    }
    /* Вставками — устойчиво: равный приоритет сохраняет порядок цепочек. */
    for (size_t i = 1; i < n; i++)
        for (size_t k = i; k > 0 && ir_prio_value(src[k - 1]) > ir_prio_value(src[k]); k--) {
            struct nft_chain *tmp = src[k];
            src[k] = src[k - 1];
            src[k - 1] = tmp;
        }
    for (size_t i = 0; i < n; i++)
        for (struct nft_rule *r = src[i]->rules; r; r = r->next)
            if (!r->fam || r->fam == fam) ir_rule_clone(dst, r);
}

static int hook_has_nat(const struct nft_table *in, const char *hook) {
    for (struct nft_obj *o = in->objs; o; o = o->next) {
        struct nft_chain *c = ir_obj_chain(o);
        if (is_nat(c) && !strcmp(c->hook, hook)) return 1;
    }
    return 0;
}

static void build_family(struct nft_rs *rs, struct nft_table *in, enum nft_family famk,
                         int reroute) {
    int fam = famk == NFT_FAM_IP ? 4 : 6;
    struct nft_table *t = ir_table_add(rs, famk, in->name);
    if (!t) return;
    /* Карты, в которые смотрят правила dnat этого семейства, переезжают вместе с ними. */
    if (fam == 4)
        for (struct nft_obj *o = in->objs; o; o = o->next) {
            struct nft_chain *c = ir_obj_chain(o);
            if (!is_nat(c)) continue;
            for (struct nft_rule *r = c->rules; r; r = r->next) {
                struct nft_expr *x = ir_expr_find(r, NFT_X_DNAT);
                struct nft_set *m = x ? ir_set_find(in, x->arg) : NULL;
                if (!m || (r->fam && r->fam != fam)) continue;
                ir_obj_unlink(&m->o);
                m->o.gap = 0;
                ir_obj_append(t, &m->o);
            }
        }
    merge_nat(in, "prerouting",
              ir_base_chain_add(t, "prerouting_nat", "nat", "prerouting", "dstnat", -1), fam);
    if (hook_has_nat(in, "output"))
        merge_nat(in, "output",
                  ir_base_chain_add(t, "output_nat", "nat", "output", "dstnat", -1), fam);
    /* Снятие бита перемаршрутизации (шаг 2) — см. STEER_REROUTE_BIT в marks.h. mangle + 2:
     * сразу после разметки (output_mark в inet, mangle + 1) и до nat на выходе. */
    if (reroute && fam == 4 && STEER_REROUTE_BIT) {
        struct nft_rule *r = ir_rule(ir_base_chain_add(t, "output_reroute", "route", "output",
                                                       "mangle", 2));
        ir_x(r, "meta mark and 0x%08x == 0x%08x", STEER_REROUTE_BIT, STEER_REROUTE_BIT);
        ir_markset(r, "meta mark set mark and 0x%08x", ~STEER_REROUTE_BIT);
        ir_counter(r, 0, 0);
        ir_comment(r, "steer-reroute");
    }
    merge_nat(in, "postrouting",
              ir_base_chain_add(t, "postrouting_nat", "nat", "postrouting", "srcnat", 1), fam);
}

static void drop_nat(struct nft_table *in) {
    for (struct nft_obj *o = in->objs; o; ) {
        struct nft_obj *next = o->next;
        struct nft_chain *c = ir_obj_chain(o);
        if (is_nat(c)) {
            /* Карта, оставшаяся без таблицы ip, уходит вместе со своими правилами. */
            for (struct nft_rule *r = c->rules; r; r = r->next) {
                struct nft_expr *x = ir_expr_find(r, NFT_X_DNAT);
                struct nft_set *m = x ? ir_set_find(in, x->arg) : NULL;
                if (m) {
                    if (next == &m->o) next = m->o.next;
                    ir_obj_unlink(&m->o);
                }
            }
            ir_obj_unlink(o);
        }
        o = next;
    }
}

int legacy_rewrite(struct nft_rs *rs, const struct spec *sp, int nftc, struct err *e) {
    if (!(nftc & NFTC_LEGACY)) return 0;
    struct nft_table *in = ir_table_find(rs, NFT_FAM_INET, NULL);
    if (!in) return 0;
    split_timeout_sets(in);
    int reroute = route_to_filter(in);
    if (nftc & NFTC_NOTRACK) frag6_compat(in);
    else drop_notrack(in);
    if (has_ip(sp, nftc)) build_family(rs, in, NFT_FAM_IP, reroute);
    if (has_ip6(nftc)) build_family(rs, in, NFT_FAM_IP6, reroute);
    drop_nat(in);
    if (rs->oom) return err_set(e, "out of memory building the ruleset", NULL);
    return 0;
}
