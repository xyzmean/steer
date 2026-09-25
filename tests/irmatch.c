/* Стенд дерева набора правил (src/compile/ir.h): генератор строит дерево по спеке, стенд
 * проверяет его СТРУКТУРУ запросами к дереву — какие таблицы, цепочки с каким хуком и
 * приоритетом, правило с каким комментарием смотрит в какой набор, какие у набора флаги и
 * откуда его элементы, — а не сравнением текста.
 *
 * Зачем, если есть снимок (tests/snapshot.sh). Снимок отвечает «текст не изменился» и молчит о
 * том, ЧТО в нём стоит: переделанное дерево, которое печатается тем же текстом, он пропустит, а
 * верное изменение текста потребует перезаписи снимка, после которой уже не видно, что именно
 * должно было остаться. Здесь записаны сами свойства — «у доменного набора в старой раскладке
 * две половины и по правилу на каждую», «nat уходит из inet в ip», — и они переживают любую
 * перезапись снимка.
 *
 * Модули линкуются (Makefile: MODEL_SRC и COMPILE_SRC), не подключаются #include.
 * Собирается дважды: роутер и телефон (-DSTEER_ANDROID, цепочки на output; выходов zapret и
 * tgws в сборке телефона нет, поэтому случаи с ними — только в роутерной). */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "spec.h"
#include "groups.h"
#include "generate.h"
#include "unit.h"

static char g_tmp[256];
static struct spec g_spec;
static struct groups g_gr;

static void put(const char *name, const char *text) {
    char p[512];
    snprintf(p, sizeof(p), "%s/%s", g_tmp, name);
    FILE *f = fopen(p, "w");
    if (!f) { perror(p); exit(2); }
    fputs(text, f);
    fclose(f);
}

/* Спека из текста: «TMP» заменяется каталогом стенда. Разбор, метки выходов, группы и
 * проверка списков — ровно те шаги, что делает cmd_apply перед генерацией. */
static int load(const char *tmpl) {
    char buf[4096], *o = buf;
    for (const char *s = tmpl; *s && o < buf + sizeof(buf) - 256; ) {
        if (!strncmp(s, "TMP", 3)) { o += sprintf(o, "%s", g_tmp); s += 3; }
        else *o++ = *s++;
    }
    *o = '\0';
    put("spec.json", buf);
    memset(&g_spec, 0, sizeof(g_spec));
    strcpy(g_spec.lan_dev[0], "br-lan");
    g_spec.lan_dev_n = 1;
    char p[512];
    snprintf(p, sizeof(p), "%s/spec.json", g_tmp);
    struct err e = {0};
    if (load_spec(p, &g_spec, &e) < 0 || registry_assign(&g_spec, &e) < 0 ||
        build_groups(&g_spec, &g_gr, &e) < 0 || check_address_lists(&g_gr, &e) < 0) {
        printf("спека не разобрана: %s\n", e.msg);
        return -1;
    }
    return 0;
}

static int build(struct nft_rs *rs, int nftc) {
    struct err e = {0};
    nft_rs_init(rs);
    if (nft_build(rs, &g_spec, &g_gr, &e) < 0 || legacy_rewrite(rs, &g_spec, nftc, &e) < 0) {
        printf("дерево не построено: %s\n", e.msg);
        return -1;
    }
    return 0;
}

static const struct group *group_of(const char *out, int domains) {
    for (size_t i = 0; i < g_gr.n; i++)
        if (!strcmp(g_gr.g[i].out, out) && g_gr.g[i].domains == domains) return &g_gr.g[i];
    return NULL;
}

static const char *cm(const char *pfx, const char *name) {
    static char b[4][96];
    static int k;
    k = (k + 1) % 4;
    snprintf(b[k], sizeof(b[k]), "%s%s", pfx, name);
    return b[k];
}

static const char *setref(const struct nft_rule *r) {
    const struct nft_expr *x = ir_expr_find(r, NFT_X_SETREF);
    return x ? x->arg : "";
}

static int nobjs(const struct nft_table *t, enum nft_objk k) {
    int n = 0;
    for (struct nft_obj *o = t ? t->objs : NULL; o; o = o->next) n += o->k == k;
    return n;
}


static const char *ctype(const struct nft_chain *c) { return c && c->type ? c->type : "-"; }
static const char *chook(const struct nft_chain *c) { return c && c->hook ? c->hook : "-"; }
static int cprio(const struct nft_chain *c) { return c ? ir_prio_value(c) : 9999; }

/* ---- 1. адресные каналы на роутере ---------------------------------------------------- */
static void t_router_basic(void) {
    printf("\n-- адресные каналы, современная раскладка --\n");
    put("a.lst", "203.0.113.0/24\n198.51.100.5\n");
    put("b.lst", "198.51.100.5\n");
    if (load("{ \"schema\": 1, \"from_default\": [\"192.168.1.0/24\"],"
             "  \"outputs\": { \"direct\": { \"kind\": \"direct\" },"
             "               \"vpn\": { \"kind\": \"interface\", \"device\": \"wg0\" } },"
             "  \"channels\": ["
             "    { \"name\": \"keep\", \"match\": { \"prefixes_file\": \"TMP/b.lst\" }, \"out\": \"direct\" },"
             "    { \"name\": \"blocked\", \"match\": { \"prefixes_file\": \"TMP/a.lst\" }, \"out\": \"vpn\" } ] }")) {
        check("спека разобрана", 0, 1);
        return;
    }
    struct nft_rs rs;
    if (build(&rs, 0)) { check("дерево построено", 0, 1); return; }
    struct nft_table *t = ir_table_find(&rs, NFT_FAM_INET, NULL);
    check("есть таблица inet", 1, t != NULL);
    check_str("имя таблицы — nft_table()", nft_table(), t ? t->name : "");
    check("таблиц ip/ip6 нет", 0, ir_table_find(&rs, NFT_FAM_IP, NULL) ||
                                  ir_table_find(&rs, NFT_FAM_IP6, NULL));

    struct nft_set *s = ir_set_find(t, "vpn_ip");
    check("набор vpn_ip есть", 1, s != NULL);
    check("у адресного набора flags interval без timeout", NFT_SET_INTERVAL, s ? (long)s->flags : -1);
    check("и auto-merge", 1, s ? s->auto_merge : 0);
    check("элементы — ссылкой на файл списка, не загружены", NFT_EL_ADDR_FILE,
          s && s->els ? (long)s->els->k : -1);
    char want[512];
    snprintf(want, sizeof(want), "%s/a.lst", g_tmp);
    check_str("это тот самый список", want, s && s->els ? s->els->s : "");

    struct nft_chain *pm = ir_chain_find(t, "prerouting_mark");
    check_str("prerouting_mark — filter", "filter", ctype(pm));
    check_str("на хуке prerouting", "prerouting", chook(pm));
    check("приоритет mangle + 1 = -149", -149, cprio(pm));
    struct nft_rule *r = ir_rule_find(pm, "steer:vpn_ip");
    check("правило steer:vpn_ip есть", 1, r != NULL);
    check_str("и смотрит в @vpn_ip", "vpn_ip", setref(r));
    check("ставит метку пакета", 1, ir_expr_find(r, NFT_X_MARKSET) != NULL);
    check("и считает", 1, ir_expr_find(r, NFT_X_COUNTER) != NULL);
    check("правило direct метку не ставит", 0,
          ir_expr_find(ir_rule_find(pm, "steer:direct_ip"), NFT_X_MARKSET) != NULL);
    check("правило на группу одно", 1, (long)ir_rule_count(pm, "steer:vpn_ip"));

    struct nft_chain *pd = ir_chain_find(t, "postrouting_down");
    check("postrouting_down — prio srcnat + 10 = 110", 110, cprio(pd));
    r = ir_rule_find(pd, "steer-down:vpn_ip");
    check("правило steer-down:vpn_ip есть", 1, r != NULL);
    check_str("встречный путь смотрит в ip saddr", "ip saddr",
              ir_expr_find(r, NFT_X_SETREF) ? ir_expr_find(r, NFT_X_SETREF)->text : "");

    struct nft_chain *dns = ir_chain_find(t, "prerouting_dns");
    check_str("заворот DNS — nat", "nat", ctype(dns));
    check("четыре правила: udp/tcp по подсети и по устройству", 4, (long)ir_rule_count(dns, NULL));
    check("карта fakeip без доменов не строится", 0, ir_set_find(t, "fakeip") != NULL);
    check("цепочек zapret без выходов zapret нет", 0, ir_chain_find(t, "zapret_queue") != NULL);
    nft_rs_free(&rs);
}

#ifndef STEER_ANDROID
/* ---- 2. домены, zapret, tgws: обе раскладки -------------------------------------------- */
static int nat_chains(const struct nft_table *t) {
    int n = 0;
    for (struct nft_obj *o = t ? t->objs : NULL; o; o = o->next) {
        struct nft_chain *c = ir_obj_chain(o);
        n += c && c->type && !strcmp(c->type, "nat");
    }
    return n;
}

static const char *mixed =
    "{ \"schema\": 2, \"from_default\": [\"192.168.1.0/24\"],"
    "  \"outputs\": { \"vpn\": { \"kind\": \"interface\", \"device\": \"wg0\" },"
    "               \"yt\": { \"kind\": \"zapret\" },"
    "               \"tg\": { \"kind\": \"tgws\", \"domain\": \"ex.co.uk\" } },"
    "  \"channels\": ["
    "    { \"name\": \"dom\", \"match\": { \"domains_files\": [\"TMP/d.lst\"], \"prefixes_files\": [\"TMP/a.lst\"] }, \"out\": \"vpn\" },"
    "    { \"name\": \"z\", \"match\": { \"prefixes_file\": \"TMP/b.lst\" }, \"out\": \"yt\" },"
    "    { \"name\": \"t\", \"match\": { \"prefixes_file\": \"TMP/b.lst\" }, \"out\": \"tg\" } ] }";

static void t_mixed_modern(void) {
    printf("\n-- домены, zapret и tgws, современная раскладка --\n");
    if (load(mixed)) { check("спека разобрана", 0, 1); return; }
    const struct group *dg = group_of("vpn", 1);
    check("доменная группа есть", 1, dg != NULL);
    if (!dg) return;
    struct nft_rs rs;
    if (build(&rs, 0)) { check("дерево построено", 0, 1); return; }
    struct nft_table *t = ir_table_find(&rs, NFT_FAM_INET, NULL);
    struct nft_set *s = ir_set_find(t, dg->name);
    check("доменный набор — interval,timeout", NFT_SET_INTERVAL | NFT_SET_TIMEOUT,
          s ? (long)s->flags : -1);
    check("адресные строки списка — элементами из файла", NFT_EL_ADDR_FILE,
          s && s->els ? (long)s->els->k : -1);
    struct nft_set *m = ir_set_find(t, "fakeip");
    check("карта fakeip есть", 1, m != NULL);
    check_str("и это карта ipv4_addr : ipv4_addr", "ipv4_addr", m && m->data ? m->data : "");
    check("её элементы — из файла состояния резолвера", NFT_EL_FAKEIP_STATE,
          m && m->els ? (long)m->els->k : -1);
    struct nft_chain *dn = ir_chain_find(t, "prerouting_dnat");
    struct nft_rule *r = ir_rule_find(dn, NULL);
    check("правило fakeip — dnat по карте", 1, ir_expr_find(r, NFT_X_DNAT) != NULL);
    check("и помечено IPv4", 4, r ? r->fam : 0);

    struct nft_chain *zq = ir_chain_find(t, "zapret_queue");
    check_str("zapret_queue на postrouting", "postrouting", chook(zq));
    check("приоритет srcnat + 2 = 102", 102, cprio(zq));
    check("своё правило первым", 1, ir_rule_find(zq, NULL) == ir_rule_find(zq, "steer:zapret-own"));
    check("правило очереди выхода yt", 1, ir_rule_find(zq, "steer:zapret:yt") != NULL);
    check("ответы — в zapret_queue_in", 1,
          ir_rule_find(ir_chain_find(t, "zapret_queue_in"), "steer:zapret-reply:yt") != NULL);
    struct nft_chain *nq = ir_chain_find(t, "zapret_predefrag_nfqws");
    check("predefrag_nfqws — обычная цепочка без хука", 1, nq && !nq->type);
    check("три правила notrack", 3, (long)ir_rule_count(nq, NULL));
    check("predefrag прыгает в неё", 1,
          ir_expr_find(ir_rule_find(ir_chain_find(t, "zapret_predefrag"), NULL), NFT_X_JUMP) != NULL);
    check("фрагмент IPv6 — exthdr frag exists", 1,
          ir_rule_has(ir_rule_find(nq, NULL)->next, "exthdr frag exists"));

    struct nft_chain *tg = ir_chain_find(t, "tgws_redirect");
    check_str("перехват Telegram — nat", "nat", ctype(tg));
    check("после трансляции адресов: dstnat + 1 = -99", -99, cprio(tg));
    r = ir_rule_find(tg, "steer:tgws:tg");
    check("правило моста есть", 1, r != NULL);
    check("и помечено IPv4", 4, r ? r->fam : 0);
    check("nat-цепочек в inet три (tgws, dns, dnat)", 3, nat_chains(t));
    nft_rs_free(&rs);
}

static void t_mixed_legacy(int nftc) {
    printf("\n-- домены, zapret и tgws, раскладка 4.9 (%s) --\n",
           nftc & NFTC_IP6NAT ? "nat в ip6, notrack" : "legacy-min");
    if (load(mixed)) { check("спека разобрана", 0, 1); return; }
    const struct group *dg = group_of("vpn", 1);
    if (!dg) { check("доменная группа есть", 0, 1); return; }
    struct nft_rs rs;
    if (build(&rs, nftc)) { check("дерево построено", 0, 1); return; }
    struct nft_table *in = ir_table_find(&rs, NFT_FAM_INET, NULL);
    struct nft_table *t4 = ir_table_find(&rs, NFT_FAM_IP, nft_table());
    struct nft_table *t6 = ir_table_find(&rs, NFT_FAM_IP6, nft_table());
    check("в inet nat не осталось", 0, nat_chains(in));
    check("карта fakeip ушла из inet", 0, ir_set_find(in, "fakeip") != NULL);
    check("есть таблица ip", 1, t4 != NULL);
    check("и карта fakeip в ней", 1, ir_set_find(t4, "fakeip") != NULL);
    check("таблица ip6 — только при nat в ip6", !!(nftc & NFTC_IP6NAT), t6 != NULL);

    struct nft_chain *pn = ir_chain_find(t4, "prerouting_nat");
    check_str("prerouting_nat в ip — nat", "nat", ctype(pn));
    check("на dstnat - 1 = -101", -101, cprio(pn));
    check("в таблице ip ровно две цепочки nat (prerouting, postrouting)", 2, nat_chains(t4));
    /* Порядок: DNS (dstnat), fakeip (dstnat), мост (dstnat + 1) — по приоритету прежних цепочек. */
    struct nft_rule *r = ir_rule_find(pn, NULL);
    check("первым — заворот DNS", 1, ir_rule_has(r, "dport 53"));
    int dnat_at = -1, tg_at = -1, i = 0;
    for (r = pn ? pn->rules : NULL; r; r = r->next, i++) {
        if (ir_expr_find(r, NFT_X_DNAT)) dnat_at = i;
        if (r->comment && !strcmp(r->comment, "steer:tgws:tg")) tg_at = i;
    }
    check("dnat fakeip есть", 1, dnat_at >= 0);
    check("мост — после fakeip", 1, tg_at > dnat_at);
    check("правил DNS в ip — только по подсети (2)", 2, i - 2);
    struct nft_chain *pp = ir_chain_find(t4, "postrouting_nat");
    check("пустая postrouting_nat на srcnat + 1 = 101", 101, cprio(pp));
    check("и в ней ни одного правила", 0, (long)ir_rule_count(pp, NULL));

    struct nft_set *dyn = ir_set_find(in, dg->name);
    char sn[80];
    nft_static_set_name(sn, sizeof(sn), dg->name);
    struct nft_set *st = ir_set_find(in, sn);
    check("динамическая половина — только timeout", NFT_SET_TIMEOUT, dyn ? (long)dyn->flags : -1);
    check("без элементов и без auto-merge", 0, dyn ? (dyn->els != NULL) + dyn->auto_merge : -1);
    check("статическая половина _n — interval", NFT_SET_INTERVAL, st ? (long)st->flags : -1);
    check("с элементами из списка", NFT_EL_ADDR_FILE, st && st->els ? (long)st->els->k : -1);
    check("и стоит сразу за динамической", 1, dyn && dyn->o.next == &st->o);
    struct nft_chain *pm = ir_chain_find(in, "prerouting_mark");
    check("правил канала — по одному на половину", 2,
          (long)ir_rule_count(pm, cm("steer:", dg->name)));
    r = ir_rule_find(pm, cm("steer:", dg->name));
    check_str("первое — в статическую", sn, setref(r));
    check_str("второе — в динамическую", dg->name, r ? setref(r->next) : "");
    check("встречных правил тоже два", 2,
          (long)ir_rule_count(ir_chain_find(in, "postrouting_down"), cm("steer-down:", dg->name)));

    struct nft_chain *nq = ir_chain_find(in, "zapret_predefrag_nfqws");
    if (nftc & NFTC_NOTRACK) {
        check("с notrack predefrag остаётся", 1, nq != NULL);
        check("фрагмент IPv6 — frag frag-off >= 0", 1,
              nq && ir_rule_has(ir_rule_find(nq, NULL)->next, "frag frag-off >= 0"));
        struct nft_chain *p6 = ir_chain_find(t6, "prerouting_nat");
        check("в ip6 заворот DNS по устройству (udp, tcp)", 2, (long)ir_rule_count(p6, NULL));
        check("без правил моста и fakeip", 0, ir_rule_find(p6, "steer:tgws:tg") != NULL);
        check("и своя пустая postrouting_nat", 1, ir_chain_find(t6, "postrouting_nat") != NULL);
    } else {
        check("без notrack predefrag_nfqws нет", 0, nq != NULL);
        check("и прыгающей в неё predefrag тоже", 0, ir_chain_find(in, "zapret_predefrag") != NULL);
        check("очередь при этом стоит", 1, ir_chain_find(in, "zapret_queue") != NULL);
    }
    nft_rs_free(&rs);
}

/* ---- 2б. emit вида подключён, и порядок в тексте не зависит от порядка выходов в спеке --- */
static const char *mixed_rev =
    "{ \"schema\": 2, \"from_default\": [\"192.168.1.0/24\"],"
    "  \"outputs\": { \"vpn\": { \"kind\": \"interface\", \"device\": \"wg0\" },"
    "               \"tg\": { \"kind\": \"tgws\", \"domain\": \"ex.co.uk\" },"
    "               \"yt\": { \"kind\": \"zapret\" } },"
    "  \"channels\": ["
    "    { \"name\": \"dom\", \"match\": { \"domains_files\": [\"TMP/d.lst\"], \"prefixes_files\": [\"TMP/a.lst\"] }, \"out\": \"vpn\" },"
    "    { \"name\": \"t\", \"match\": { \"prefixes_file\": \"TMP/b.lst\" }, \"out\": \"tg\" },"
    "    { \"name\": \"z\", \"match\": { \"prefixes_file\": \"TMP/b.lst\" }, \"out\": \"yt\" } ] }";

static void t_mixed_order(void) {
    printf("\n-- emit вида подключён; порядок выходов в спеке текст не меняет --\n");
    check("kind zapret даёт emit", 1, kind_by_name("zapret") && kind_by_name("zapret")->emit != NULL);
    check("kind tgws даёт emit", 1, kind_by_name("tgws") && kind_by_name("tgws")->emit != NULL);

    /* Та же спека, что у mixed, но tg (tgws) объявлен ПЕРЕД yt (zapret) — и в outputs, и в
     * channels. kind_emit_all зовёт виды в порядке реестра (zapret раньше tgws), а не в
     * порядке их появления в спеке, поэтому в дереве цепочки zapret обязаны стоять раньше
     * цепочки моста так же, как в t_mixed_modern. */
    if (load(mixed_rev)) { check("спека разобрана", 0, 1); return; }
    struct nft_rs rs;
    if (build(&rs, 0)) { check("дерево построено", 0, 1); return; }
    struct nft_table *t = ir_table_find(&rs, NFT_FAM_INET, NULL);
    int zi = -1, ti = -1, i = 0;
    for (struct nft_obj *o = t ? t->objs : NULL; o; o = o->next, i++) {
        if (!strcmp(o->name, "zapret_queue")) zi = i;
        if (!strcmp(o->name, "tgws_redirect")) ti = i;
    }
    check("цепочка zapret_queue построена", 1, zi >= 0);
    check("цепочка tgws_redirect построена", 1, ti >= 0);
    check("правило очереди выхода yt на месте", 1,
          ir_rule_find(ir_chain_find(t, "zapret_queue"), "steer:zapret:yt") != NULL);
    check("правило моста выхода tg на месте", 1,
          ir_rule_find(ir_chain_find(t, "tgws_redirect"), "steer:tgws:tg") != NULL);
    check("zapret в тексте раньше моста, хоть в спеке он объявлен вторым", 1,
          zi >= 0 && ti >= 0 && zi < ti);
    nft_rs_free(&rs);
}

#else
/* ---- 3. каналы на сам телефон ------------------------------------------------------------ */
static const char *phone =
    "{ \"schema\": 2, \"lan_devices\": [\"rndis0\"],"
    "  \"outputs\": { \"vpn\": { \"kind\": \"interface\", \"device\": \"wg0\" } },"
    "  \"channels\": ["
    "    { \"name\": \"s\", \"from\": [\"self\"], \"match\": { \"any\": true, \"allow_all\": true, \"proto\": \"udp\", \"ports\": [\"50000-65535\"] }, \"out\": \"vpn\" },"
    "    { \"name\": \"d\", \"from\": [\"uid:10124\"], \"match\": { \"domains_files\": [\"TMP/d.lst\"] }, \"out\": \"vpn\" } ] }";

static void t_phone(int nftc) {
    printf("\n-- каналы на сам телефон (%s) --\n", !nftc ? "современная" :
           nftc & NFTC_IP6NAT ? "раскладка 4.9, nat в ip6" : "раскладка 4.9");
    if (load(phone)) { check("спека разобрана", 0, 1); return; }
    const struct group *all = NULL, *dom = group_of("vpn", 1);
    for (size_t i = 0; i < g_gr.n; i++) if (g_gr.g[i].all) all = &g_gr.g[i];
    if (!all || !dom) { check("группы телефона есть", 0, 1); return; }
    struct nft_rs rs;
    if (build(&rs, nftc)) { check("дерево построено", 0, 1); return; }
    struct nft_table *in = ir_table_find(&rs, NFT_FAM_INET, NULL);
    struct nft_chain *om = ir_chain_find(in, "output_mark");
    check_str("output_mark на хуке output", "output", chook(om));
    check_str(nftc ? "в 4.9 — filter" : "в современной — route", nftc ? "filter" : "route",
              ctype(om));
    struct nft_rule *v6 = ir_rule_find(om, cm("steer-v6:", all->name));
    check("«весь трафик» отказывает IPv6", 1, v6 != NULL);
    struct nft_expr *fx = ir_expr_find(v6, NFT_X_FAMILY);
    check("правило отказа — про IPv6", 6, fx ? fx->fam : 0);
    struct nft_rule *r = ir_rule_find(om, cm("steer:", all->name));
    check("правило разметки группы есть", 1, r != NULL);
    check("бит перемаршрутизации — только в 4.9", !!nftc, ir_rule_has(r, "mark or 0x00200000"));
    check("скачанное — в input_down", 1,
          ir_rule_find(ir_chain_find(in, "input_down"), cm("steer-down:", all->name)) != NULL);
    struct nft_table *t4 = ir_table_find(&rs, NFT_FAM_IP, NULL);
    if (!nftc) {
        struct nft_chain *od = ir_chain_find(in, "output_dns");
        check_str("заворот DNS приложений — nat output", "output", chook(od));
        check("udp, tcp и fakeip", 3, (long)ir_rule_count(od, NULL));
        check("таблицы ip нет", 0, t4 != NULL);
    } else {
        struct nft_chain *rr = ir_chain_find(t4, "output_reroute");
        check_str("в ip — output_reroute типа route", "route", ctype(rr));
        check("на mangle + 2 = -148", -148, cprio(rr));
        struct nft_chain *on = ir_chain_find(t4, "output_nat");
        check("output_nat в ip: udp, tcp и fakeip", 3, (long)ir_rule_count(on, NULL));
        check("output_dns в inet не осталось", 0, ir_chain_find(in, "output_dns") != NULL);
        struct nft_table *t6 = ir_table_find(&rs, NFT_FAM_IP6, NULL);
        check("ip6 — только при nat в ip6", !!(nftc & NFTC_IP6NAT), t6 != NULL);
        if (t6)
            check("output_nat в ip6 — udp и tcp, без fakeip", 2,
                  (long)ir_rule_count(ir_chain_find(t6, "output_nat"), NULL));
    }
    nft_rs_free(&rs);
}
#endif

/* ---- 4. само дерево: поиск, клон, арена ------------------------------------------------- */
static void t_tree(void) {
    printf("\n-- дерево: поиск и переделка --\n");
    struct nft_rs rs;
    nft_rs_init(&rs);
    struct nft_table *t = ir_table_add(&rs, NFT_FAM_INET, "x");
    struct nft_chain *c = ir_base_chain_add(t, "c", "filter", "input", "filter", -5);
    struct nft_rule *r = ir_rule(c);
    ir_x(r, "tcp dport %d", 22);
    ir_counter(r, 7, 700);
    ir_comment(r, "k");
    struct nft_rule *n = ir_rule_clone(NULL, r);
    check("клон встал сразу за оригиналом", 1, r->next == n && n->next == NULL);
    check("и у него свои выражения", 1, n->x != r->x && !strcmp(n->x->text, r->x->text));
    check("счётчик копируется", 700, n ? (long)n->bytes : 0);
    ir_rule(c);
    check("хвост цепочки после клона верен", 3, (long)ir_rule_count(c, NULL));
    check("по комментарию — два", 2, (long)ir_rule_count(c, "k"));
    char p[32];
    ir_prio_str(c, p, sizeof(p));
    check_str("приоритет словами", "filter - 5", p);
    struct nft_set *s1 = ir_set_add(t, "s1", "ipv4_addr");
    struct nft_set *s2 = ir_set_add(t, "s2", "ipv4_addr");
    ir_obj_unlink(&s2->o);
    ir_obj_insert_after(&c->o, &s2->o);
    check("вставка после объекта", 1, c->o.next == &s2->o && s2->o.next == &s1->o);
    check("наборов два, цепочка одна", 21, nobjs(t, NFT_OBJ_SET) * 10 + nobjs(t, NFT_OBJ_CHAIN));
    /* Строка длиннее куска арены — свой кусок, а не отказ. */
    char big[10000];
    memset(big, 'a', sizeof(big) - 1);
    big[sizeof(big) - 1] = '\0';
    check("длинная строка в арене", (long)sizeof(big) - 1, (long)strlen(ir_strdup(&rs, big)));
    check("отказа памяти не было", 0, rs.oom);
    nft_rs_free(&rs);
    check("после освобождения таблиц нет", 1, rs.tables == NULL && rs.arena == NULL);
}

int main(void) {
    const char *td = getenv("TMPDIR");
    snprintf(g_tmp, sizeof(g_tmp), "%s/irmatch.XXXXXX", td ? td : "/tmp");
    if (!mkdtemp(g_tmp)) { perror("mkdtemp"); return 2; }
    g_state_dir = g_tmp;
    put("d.lst", "example.com\n");
    t_tree();
    t_router_basic();
#ifndef STEER_ANDROID
    t_mixed_modern();
    t_mixed_legacy(NFTC_LEGACY);
    t_mixed_legacy(NFTC_LEGACY | NFTC_IP6NAT | NFTC_NOTRACK);
    t_mixed_order();
#else
    t_phone(0);
    t_phone(NFTC_LEGACY);
    t_phone(NFTC_LEGACY | NFTC_IP6NAT);
#endif
    groups_free(&g_gr);
    char cmd[300];
    snprintf(cmd, sizeof(cmd), "rm -rf '%s'", g_tmp);
    if (system(cmd) != 0) printf("не удалось убрать %s\n", g_tmp);
#ifdef STEER_ANDROID
    return unit_done("irmatch-android");
#else
    return unit_done("irmatch");
#endif
}
