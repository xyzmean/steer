/*
 * splify-dnsd — transparent DNS forwarding proxy that routes matched domains
 * into splify's existing nftables sets (splify_vpn_v4 / splify_direct_v4) at
 * resolve time, based on richer domain-rule matching (exact / namespace /
 * wildcard / regex) than dnsmasq's `nftset=` directive supports.
 *
 * It NEVER resolves anything itself: a query that needs real data is forwarded
 * byte-for-byte to the real resolver (dnsmasq, 127.0.0.1:53). For a domain
 * that does NOT match a rule (the overwhelming majority), the answer is
 * relayed back byte-for-byte, unmodified. For a MATCHED domain the answer is
 * synthesized straight from the QUERY whenever it does not depend on upstream
 * data — a repeat A for an already-mapped fake IP, and AAAA/HTTPS/SVCB (always
 * NODATA for a matched name) — so the client-visible latency of fake-ip is one
 * upstream round-trip on the very first A of a new domain and ~zero after;
 * the upstream is still asked in the background to keep the DNAT map fresh. For a domain that DOES match, the
 * real answer is NOT relayed — the client is instead handed a synthetic,
 * domain-exclusive "fake" IPv4 from a private pool (198.18.0.0/15) that this
 * daemon allocates and persists 1:1 per domain (see the fakeip_* pool
 * below); an nftables DNAT rule (installed by splify-apply) then rewrites
 * that fake IP back to the real backend before the packet leaves the
 * router. This sidesteps two problems a real-IP-based approach can't: real
 * CDN IPs (Cloudflare etc.) are shared across many unrelated domains from a
 * dynamic pool, so tagging the real IP is collision-prone; and the decision
 * here is made from the DNS question name — always visible in plaintext —
 * rather than from the TLS SNI, so it works even when ECH hides the SNI.
 * AAAA answers for a matched domain are suppressed (NODATA) rather than
 * relayed, since splify has no IPv6 routing at all and letting a real AAAA
 * through would let a dual-stack client bypass the split entirely.
 *
 * A parsing failure, an unmatched domain, or anything this daemon can't
 * substitute (pool exhausted, no real A answer yet, non-A/AAAA query type)
 * NEVER blocks or alters the DNS transaction — fail open, always: relay the
 * real answer unchanged.
 *
 * Usage:
 *   splify-dnsd --listen-port P --upstream-port P --vpn-set NAME
 *               --direct-set NAME --vpn-rules PATH --direct-rules PATH
 *               --fakeip-state PATH [--fakeip-map NAME]
 *               [--table inet fw4]
 *   splify-dnsd --selftest
 *   splify-dnsd --match RULES_PATH HOSTNAME
 *   splify-dnsd --fakeip STATE_PATH DOMAIN
 *
 * The fake-IP / DNAT entries in the kernel's nftables sets and map are
 * written via direct nfnetlink (NFNL_SUBSYS_NFTABLES / NFT_MSG_NEWSETELEM),
 * NOT by forking the `nft` CLI: each `nft` subprocess reparses the whole
 * ruleset into 40-70MB of its own memory, which on a ~240MB router gets
 * OOM-killed under any DNS burst and wedges clients on fake IPs whose DNAT
 * never landed. Netlink sends only the element delta (~40 bytes); the kernel
 * resolves name->handle internally, peak daemon memory stays constant.
 *
 * SIGHUP reloads both rule files without dropping in-flight queries.
 */
#include "dnsd_int.h"
#include "nftnl.h"

static int cmd_match(const char *path, const char *host) {
    struct ruleset rs = {0};
    if (load_rules(path, &rs) != 0) {
        fprintf(stderr, "cannot read rules file: %s\n", path);
        return 2;
    }
    int m = ruleset_match(&rs, host);
    ruleset_free(&rs);
    printf("%s\n", m ? "match" : "nomatch");
    return m ? 0 : 1;
}

static int cmd_selftest(void) {
    int fails = 0;
    struct ruleset rs = {0};

    ruleset_add(&rs, "example.com");             /* namespace */
    ruleset_add(&rs, "=exact-only.com");          /* exact */
    ruleset_add(&rs, "*.wild.example.net");       /* wildcard */
    ruleset_add(&rs, "re:^.*\\.regex\\.example$"); /* regex */

#define CHECK(host, want) do { \
    int got = ruleset_match(&rs, host); \
    if (got != (want)) { \
        fprintf(stderr, "FAIL: %s expected=%d got=%d\n", host, (want), got); \
        fails++; \
    } else { \
        fprintf(stderr, "ok: %s -> %d\n", host, got); \
    } \
} while (0)

    CHECK("example.com", 1);
    CHECK("sub.example.com", 1);
    CHECK("notexample.com", 0);
    CHECK("exact-only.com", 1);
    CHECK("sub.exact-only.com", 0);
    CHECK("foo.wild.example.net", 1);
    CHECK("wild.example.net", 0); /* wildcard pattern requires the "*." prefix segment */
    CHECK("a.regex.example", 1);
    CHECK("a.b.regex.example", 1);
    CHECK("regex.example", 0);

#undef CHECK

    ruleset_free(&rs);

    /* Netlink message builder: construct a NEWSETELEM for a map (fake->real)
     * and confirm it fits in NFTLK_MSG_CAP without overflow. We validate the
     * STRUCTURE offline (no socket, no kernel) so CI runs without CAP_NET_ADMIN
     * still exercise the wire-format path — the property that broke hardest on
     * the router was a misformed transaction silently failing the ack. */
    {
        uint32_t key = htonl(0xC6120000u), data = htonl(0x6812202Fu);
        uint8_t buf[NFTLK_MSG_CAP];
        struct nlbuf b;
        nlbuf_init(&b, buf, sizeof(buf));

        struct nlmsghdr *nh = (struct nlmsghdr *)b.p; b.p += NLMSG_ALIGN(sizeof(*nh));
        struct nfgenmsg *nfg = (struct nfgenmsg *)b.p; b.p += NLMSG_ALIGN(sizeof(*nfg));
        nlbuf_put_str(&b, NFTA_SET_ELEM_LIST_TABLE, "fw4");
        nlbuf_put_str(&b, NFTA_SET_ELEM_LIST_SET, "splify_fakeip_map");
        struct nlattr *elems = nlbuf_begin_nested(&b, NFTA_SET_ELEM_LIST_ELEMENTS);
        struct nlattr *elem  = nlbuf_begin_nested(&b, NFTA_LIST_ELEM);
        struct nlattr *keya  = nlbuf_begin_nested(&b, NFTA_SET_ELEM_KEY);
        nlbuf_put_data(&b, NFTA_DATA_VALUE, &key, 4);
        nlbuf_end_nested(&b, keya);
        struct nlattr *dataa = nlbuf_begin_nested(&b, NFTA_SET_ELEM_DATA);
        nlbuf_put_data(&b, NFTA_DATA_VALUE, &data, 4);
        nlbuf_end_nested(&b, dataa);
        nlbuf_end_nested(&b, elem);
        nlbuf_end_nested(&b, elems);

        size_t total = (size_t)(b.p - buf);
        /* nla_len of the top-level nested ELEMENTS must enclose both the elem
         * and the key+data children; if end_nested mis-computed, this fails. */
        size_t elems_len = (size_t)elems->nla_len;
        if (total == 0 || total > NFTLK_MSG_CAP) {
            fprintf(stderr, "FAIL: netlink msg build bad total=%zu cap=%d\n", total, NFTLK_MSG_CAP);
            fails++;
        } else if (elems_len == 0 || elems_len > total) {
            fprintf(stderr, "FAIL: netlink nested len bad elems_len=%zu total=%zu\n", elems_len, total);
            fails++;
        } else {
            fprintf(stderr, "ok: netlink NEWSETELEM built, %zu bytes\n", total);
        }
        /* suppress unused-field warnings in the no-send validation path */
        (void)nh; (void)nfg;
    }

    fprintf(stderr, fails ? "SELFTEST: %d failure(s)\n" : "SELFTEST: all passed\n", fails);
    return fails ? 1 : 0;
}

/* --fakeip STATE_PATH DOMAIN: loads (or creates) the state file, allocates or
 * looks up DOMAIN's fake IP exactly as the running daemon would, persists it,
 * and prints it. A second invocation against the same path/domain must print
 * the SAME address (persistence); a different domain must print a different
 * one (collision-freedom) — that's what the bats coverage exercises. */
static int cmd_fakeip(const char *state_path, const char *domain) {
    g_fakeip_state_path = state_path;
    fakeip_state_load(state_path);
    uint32_t addr;
    if (fakeip_lookup_or_alloc(domain, &addr) != 0) {
        fprintf(stderr, "fake-ip pool exhausted\n");
        return 1;
    }
    struct in_addr a; a.s_addr = htonl(addr);
    char ipstr[INET_ADDRSTRLEN];
    if (!inet_ntop(AF_INET, &a, ipstr, sizeof(ipstr))) return 1;
    printf("%s\n", ipstr);
    return 0;
}

/* Флаги резолвера печатает он сам, а не таблица в src/cli/cli.c: у dnsd свой разбор
 * аргументов, и описание, лежащее отдельно от него, разошлось бы с ним при первой же
 * правке. Формат строк — тот же, что у общих флагов. */
void dnsd_usage_flags(FILE *out) {
    fputs("  --spec ФАЙЛ              спека каналов (по умолчанию " STEER_ETC_DIR "/spec.json)\n"
          "  --state-dir КАТАЛОГ      каталог состояния (по умолчанию " STEER_STATE_DIR ")\n"
          "  --listen-port ПОРТ       порт, на котором отвечать LAN (по умолчанию 5300)\n"
          "  --upstream-port ПОРТ     порт апстрима, куда переспрашивать (по умолчанию 53)\n"
          "  --upstream-origdst       переспрашивать тот сервер, к которому шёл запрос\n"
          "                           (адрес из conntrack); без записи — 127.0.0.1\n"
          "  --fakeip-state ФАЙЛ      где хранить раздачу поддельных адресов\n"
          "\n"
          "Разовые проверки, вместо запуска резолвера:\n"
          "  --selftest               прогнать разбор и сборку пакетов на своих фикстурах\n"
          "  --match ПРАВИЛА ИМЯ      какое правило поймает это имя\n"
          "  --fakeip СОСТОЯНИЕ ДОМЕН какой поддельный адрес выдан домену\n", out);
}

static void dnsd_usage(void) {
    fputs("steer: dnsd: непонятный флаг\n"
          "использование: steer dnsd [флаги]\n"
          "флаги:\n", stderr);
    dnsd_usage_flags(stderr);
    fputs("подробности: steer help dnsd\n", stderr);
}

int dnsd_main(int argc, char **argv) {
    int listen_port = 5300;
    int upstream_port = 53;
    const char *spec = STEER_ETC_DIR "/spec.json";

    for (int i = 0; i < argc; i++) {
        if (strcmp(argv[i], "--selftest") == 0) {
            return cmd_selftest();
        } else if (strcmp(argv[i], "--match") == 0 && i + 2 < argc) {
            return cmd_match(argv[i + 1], argv[i + 2]);
        } else if (strcmp(argv[i], "--fakeip") == 0 && i + 2 < argc) {
            return cmd_fakeip(argv[i + 1], argv[i + 2]);
        } else if (strcmp(argv[i], "--spec") == 0 && i + 1 < argc) {
            spec = argv[++i];
        } else if (strcmp(argv[i], "--listen-port") == 0 && i + 1 < argc) {
            listen_port = atoi(argv[++i]);
        } else if (strcmp(argv[i], "--upstream-port") == 0 && i + 1 < argc) {
            upstream_port = atoi(argv[++i]);
        } else if (strcmp(argv[i], "--upstream-origdst") == 0) {
            g_origdst = 1;
        } else if (strcmp(argv[i], "--fakeip-state") == 0 && i + 1 < argc) {
            g_fakeip_state_path = argv[++i];
        } else if (strcmp(argv[i], "--state-dir") == 0 && i + 1 < argc) {
            /* Резолвер каталог состояния ИСПОЛЬЗУЕТ — fakeip.state кладётся именно туда
             * (см. ниже), — но флага не понимал, в отличие от всех прочих команд, читающих
             * спеку. Запуск с чужим --state-dir поэтому молча писал состояние в
             * /var/lib/steer, то есть мимо того каталога, которым живёт остальной запуск. */
            g_state_dir = argv[++i];
        } else {
            dnsd_usage();
            return 2;
        }
    }

    /* Channels come from the spec, in spec order — the same file and the same
     * parser the compiler used, so the sets named here are exactly the sets it
     * generated. */
    load_spec(spec);
    dch_build();
    /* Раскладка — та же проба, что у apply, и тем же ответом: наборы и карту резолвер находит
     * по именам, и искать их не в той таблице значило бы наполнять пустоту. Спрашивается у
     * ядра, а не у файла, который оставил apply: резолвер поднимается и раньше первого apply
     * (загрузка), и ответ ядра от порядка запуска не зависит. Имя таблицы — своё у сборки
     * (nft_table), как у всего остального движка. */
    {
        static char sets_tbl[64], map_tbl[64];
        int legacy = nft_compat() & NFTC_LEGACY;
        snprintf(sets_tbl, sizeof(sets_tbl), "inet %s", nft_table());
        snprintf(map_tbl, sizeof(map_tbl), "%s %s", legacy ? "ip" : "inet", nft_table());
        g_nft_table = sets_tbl;
        g_nft_map_table = map_tbl;
        g_nft_sets_interval = !legacy;
    }
    /* Подпись пишется СРАЗУ ПОСЛЕ сборки таблицы и до всего остального: с этой секунды
     * `reload_dnsd` вправе сравнивать её со свежей и выбирать HUP вместо перезапуска. */
    dch_sig_write();
    /* НИ ОДНОГО ДОМЕННОГО КАНАЛА — ЭТО НЕ ПРИЧИНА ВЫЙТИ, А ОБЫЧНЫЙ РЕЖИМ РАБОТЫ.
     *
     * Здесь стоял ранний `return 0` со словами «nothing to do», и он делал ровно то, от
     * чего полная сборка защищена в генераторе правил: разводил правило и процесс.
     * Заворот `udp dport 53 → :5300` полная сборка ставит БЕЗУСЛОВНО (steer.c, chain
     * prerouting_dns под `#ifndef STEER_TGWS`), needs-dnsd отвечает «поднимаем» всегда, а
     * init-скрипт по этому ответу заводит экземпляр. Резолвер поднимался, видел спеку без
     * доменов — адресные правила, один обход DPI, чистый туннель по подсетям — и выходил
     * с кодом 0. Оставался заворот на порт, где больше никто не слушает, и весь DNS
     * локальной сети умирал. Это регрессия от b20d0af: тот снял гейт с правила, но ранний
     * выход в резолвере не тронул, а 5d92776 через два дня починил тот же отказ только для
     * мини-сборки.
     *
     * Инвариант тот же, что записан в генераторе, и теперь он выполняется с обеих сторон:
     * правило существует там и только там, где существует поднимающий резолвер, — значит
     * резолвер обязан СУЩЕСТВОВАТЬ везде, где стоит правило. Без доменных каналов он
     * просто пересылает запросы наверх и отдаёт ответы как есть: ни одного совпадения,
     * ни одного поддельного адреса, ни одной записи в наборах (все проходы по каналам
     * идут по g_dch_n и при нуле не делают ничего). Для сети это неотличимо от прямого
     * dnsmasq, а для нас — работающий порт вместо закрытого.
     *
     * Строка в журнале остаётся: она полезна при разборе («почему домен не уходит в
     * туннель» — потому что доменных каналов нет вовсе), но это уведомление, а не отказ. */
    if (!g_dch_n)
        fprintf(stderr, "steer dnsd: no channel in %s matches domains — "
                        "forwarding only, no domain routing\n", spec);
    if (!g_fakeip_state_path) {
        static char st[PATH_MAX];
        int need = snprintf(st, sizeof(st), "%s/fakeip.state", g_state_dir);
        if (need < 0 || (size_t)need >= sizeof(st)) {
            fprintf(stderr, "steer dnsd: --state-dir too long, no room for fakeip.state\n");
            return 1;
        }
        g_fakeip_state_path = st;
    }
    return run_proxy(listen_port, upstream_port);
}
