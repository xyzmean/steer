/* steer — compile a channel spec into nftables rules and policy routing.
 *
 * Own table, not an fw4 include. Three reasons, all learned from splify:
 *   * an fw4 reload REPLACES table inet fw4, which drains every set living inside
 *     it — a separate `table inet steer` simply survives;
 *   * one `nft -f` is atomic: either the whole channel set applies or nothing does,
 *     with no window where a rule references a set that is not there yet;
 *   * uninstall is `nft delete table inet steer`, and nothing of ours can break
 *     someone else's firewall by being malformed.
 *
 * Precedence is expressed with `return` rather than a "mark is still zero" guard:
 * inside our own chain the first matching rule wins by construction, which is
 * exactly the ordered-channels semantics the spec promises.
 */
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <errno.h>
#include <unistd.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <fcntl.h>

#include "spec.h"

int dnsd_main(int argc, char **argv);

/* ---- ruleset generation --------------------------------------------------- */
static void emit_from(FILE *f, const struct channel *c) {
    const char (*list)[64] = c->from_n ? c->from : g_from_default;
    size_t n = c->from_n ? c->from_n : g_from_default_n;
    if (!n) return;
    fprintf(f, "ip saddr { ");
    for (size_t i = 0; i < n; i++) fprintf(f, "%s%s", i ? ", " : "", list[i]);
    fprintf(f, " } ");
}

/* Elements come straight from the list file: the fitter (steer-aggregate) has
 * already decided what fits, and re-parsing 10 000 prefixes here would only add a
 * second place for the two to disagree. */
static size_t emit_elements(FILE *f, const char *path) {
    FILE *in = fopen(path, "r");
    if (!in) die("%s: cannot read the channel's list", path);
    char line[128];
    size_t n = 0;
    while (fgets(line, sizeof(line), in)) {
        char *nl = strpbrk(line, "\r\n");
        if (nl) *nl = '\0';
        char *p = line;
        while (*p == ' ' || *p == '\t') p++;
        if (!*p || *p == '#' || *p == ';') continue;
        fprintf(f, "%s%s", n ? ", " : "", p);
        n++;
    }
    fclose(in);
    return n;
}

static int has_domains(void) {
    for (size_t i = 0; i < g_ch_n; i++) if (g_ch[i].domains_file[0]) return 1;
    return 0;
}

/* The fake-IP map and its DNAT chain are only worth generating when some channel
 * actually hands out fake addresses. A spec whose domain channels are all realip
 * needs the DNS redirect but no translation at all. */
static int has_fakeip(void) {
    for (size_t i = 0; i < g_ch_n; i++)
        if (g_ch[i].domains_file[0] && !g_ch[i].realip) return 1;
    return 0;
}

static void generate(FILE *f) {
    fprintf(f, "table inet steer {\n");
    for (size_t i = 0; i < g_ch_n; i++) {
        if (g_ch[i].prefixes_file[0]) {
            fprintf(f, "    set ch_%s {\n        type ipv4_addr\n        flags interval\n",
                    g_ch[i].name);
            fprintf(f, "        elements = { ");
            emit_elements(f, g_ch[i].prefixes_file);
            fprintf(f, " }\n    }\n");
        } else if (g_ch[i].domains_file[0]) {
            /* Declared EMPTY on purpose: the resolver fills it as answers arrive,
             * and a set with no inline `elements =` keeps its contents across a
             * reload. Timeouts come from each answer's TTL, so an address a CDN
             * stops using expires on its own instead of accumulating forever. */
            fprintf(f, "    set ch_%s {\n        type ipv4_addr\n"
                       "        flags interval,timeout\n        auto-merge\n    }\n",
                    g_ch[i].name);
        }
    }
    /* mangle + 1, like splify: the mark must exist before the routing decision,
     * and staying one step after mangle leaves room for anything that legitimately
     * wants to run first. */
    fprintf(f, "    chain prerouting_mark {\n"
               "        type filter hook prerouting priority mangle + 1; policy accept;\n");
    for (size_t i = 0; i < g_ch_n; i++) {
        struct output *o = out_by_name(g_ch[i].out);
        if (!o) die("channel %s points at a missing output", g_ch[i].name);
        fprintf(f, "        ");
        emit_from(f, &g_ch[i]);
        /* Both kinds of channel own a set — a domain channel's is just filled by
         * the resolver instead of from a file. Emitting the daddr match only for
         * the prefix kind left a domain channel matching EVERYTHING from the LAN
         * and marking it into that channel's tunnel. Only `any` matches all. */
        if (g_ch[i].prefixes_file[0] || g_ch[i].domains_file[0])
            fprintf(f, "ip daddr @ch_%s ", g_ch[i].name);
        if (o->kind == OUT_INTERFACE) fprintf(f, "meta mark set 0x%08x ", o->mark);
        /* `return` and not `accept`: it ends OUR chain, letting the rest of the
         * firewall proceed, while making the first matching channel the winner. */
        fprintf(f, "counter return comment \"steer:%s\"\n", g_ch[i].name);
    }
    fprintf(f, "    }\n");

    /* Fake-IP plumbing, only when some channel actually matches domains.
     *
     * A domain channel hands the client an address out of 198.18.0.0/15 instead of
     * the real one, so two sites behind one CDN address stop being the same thing
     * to the router. That address has to be translated back on the way out, which
     * is what the map and this chain do — filled live by `steer dnsd`. */
    if (has_domains()) {
        if (has_fakeip()) {
            fprintf(f, "\n    map fakeip { type ipv4_addr : ipv4_addr; }\n");
            fprintf(f, "    chain prerouting_dnat {\n"
                       "        type nat hook prerouting priority dstnat; policy accept;\n"
                       "        ip daddr 198.18.0.0/15 dnat ip to ip daddr map @fakeip\n"
                       "    }\n");
        }
        /* Make traceroute show the REAL intermediate routers while the destination
         * stays the fake address.
         *
         * By default every hop shows the fake IP, including the first: an ICMP error
         * belonging to a DNATed flow gets its OUTER source rewritten to the address
         * the client addressed, because otherwise the client would not recognise the
         * error as its own. Taking those errors out of conntrack stops that rewrite,
         * so they arrive from the router that actually sent them.
         *
         * Scope is deliberately just time-exceeded (type 11). dest-unreachable must
         * stay tracked — path-MTU discovery rides on it, and untracking that would
         * trade a cosmetic win for silently broken large transfers.
         *
         * The final hop is unaffected: it is an Echo Reply on the tracked flow, so
         * conntrack still translates it back to the fake address.
         *
         * ONLY WORKS WHEN THE OUTPUT DOES NOT MASQUERADE, and that is not a detail —
         * it is what makes this useless for most tunnels. Measured on a real client
         * with masquerade on: 13 errors hit this rule, 0 reached the accept for
         * untracked traffic, and every hop after the first turned into an asterisk.
         *
         * With NAT in the path the error is addressed to the ROUTER, not the client,
         * so only conntrack knows which client it belongs to. Untracking removes
         * exactly that knowledge: the packet is delivered locally instead of being
         * forwarded, and never reaches the LAN at all. Tracking is the delivery
         * mechanism, and being tracked is what rewrites the source. There is no third
         * option short of rewriting the embedded header inside the ICMP payload.
         *
         * So this is opt-in, apply refuses to pretend it will help when the output
         * masquerades, and it also needs the firewall to accept untracked ICMP toward
         * the LAN — which steer does not add, because it does not own the firewall. */
        if (g_traceroute_hops) {
            fprintf(f, "    chain prerouting_raw {\n"
                       "        type filter hook prerouting priority raw; policy accept;\n"
                       "        meta l4proto icmp icmp type time-exceeded counter notrack "
                       "comment \"steer:traceroute-hops\"\n"
                       "    }\n");
        }
        /* The resolver only sees what is steered to it. IPv6 as well as IPv4: the
         * router advertises itself as an IPv6 resolver by default and clients
         * prefer that server, so an IPv4-only redirect catches almost nothing —
         * measured on a real client, 15 of its DNS packets went over IPv6 against
         * 20 over IPv4. TCP/53 stays with the system resolver: this daemon is
         * UDP-only, so redirecting TCP would break the truncated-answer retry. */
        fprintf(f, "    chain prerouting_dns {\n"
                   "        type nat hook prerouting priority dstnat; policy accept;\n");
        for (size_t i = 0; i < g_from_default_n; i++)
            fprintf(f, "        ip saddr %s udp dport 53 counter redirect to :%d\n",
                    g_from_default[i], DNS_PORT);
        if (g_lan_device[0])
            fprintf(f, "        meta nfproto ipv6 iifname \"%s\" udp dport 53 counter redirect to :%d\n",
                    g_lan_device, DNS_PORT);
        fprintf(f, "    }\n");
    }
    fprintf(f, "}\n");
}

/* ---- what an interface output depends on, and does not own ----------------- */
/* steer does not touch the firewall. It has no business rewriting someone's zones
 * or adding masquerade rules — that is the operator's configuration, and a routing
 * engine silently editing it is how two tools start fighting over one ruleset.
 *
 * But an interface output cannot work without it: packets leaving a tunnel with LAN
 * source addresses never come back, so the route looks applied, the channel counter
 * even rises, and every site behind it simply hangs. That failure is invisible from
 * inside steer's own state — which is exactly why it must be REPORTED.
 *
 * Both checks are textual and deliberately conservative: a false "looks fine" is
 * worse than a false warning, so anything unrecognised reads as missing. */
struct fwcheck { int in_firewall, masqueraded; };

/* Is DEVICE named here as a whole token? Substring matching is not good enough in
 * either direction: looking for it quoted missed fw4 entirely (see below), while a
 * bare substring would let "warp" answer for "warp0". */
static int names_device(const char *hay, const char *device) {
    size_t n = strlen(device);
    for (const char *p = strstr(hay, device); p; p = strstr(p + 1, device)) {
        char before = p == hay ? ' ' : p[-1];
        char after = p[n];
        int lb = (before >= 'a' && before <= 'z') || (before >= 'A' && before <= 'Z')
                 || (before >= '0' && before <= '9');
        int la = (after >= 'a' && after <= 'z') || (after >= 'A' && after <= 'Z')
                 || (after >= '0' && after <= '9');
        if (!lb && !la) return 1;
    }
    return 0;
}

static struct fwcheck fw_check(const char *device) {
    struct fwcheck r = { 0, 0 };
    FILE *f = popen("nft list ruleset 2>/dev/null", "r");
    if (!f) return r;
    char line[2048];
    char chain[128] = "";
    int in_steer = 0;
    while (fgets(line, sizeof(line), f)) {
        /* Our own table mentions the device too; it proves nothing about NAT. */
        if (strstr(line, "table inet steer")) in_steer = 1;
        else if (!strncmp(line, "table ", 6)) in_steer = 0;
        if (in_steer) continue;

        const char *c = strstr(line, "chain ");
        if (c) snprintf(chain, sizeof(chain), "%s", c + 6);

        if (names_device(line, device)) r.in_firewall = 1;
        /* fw4 does NOT name the device on the masquerade rule: it emits
         * `chain srcnat_warp0 { meta nfproto ipv4 masquerade comment "...warp0..." }`
         * and matches the device on the jump into that chain. Checking only the rule
         * line reported "no NAT" on a router whose NAT was working fine — a false
         * alarm that sent me diagnosing the wrong thing. So the enclosing chain name
         * counts as evidence too. */
        if (strstr(line, "masquerade") || strstr(line, "snat")) {
            if (names_device(line, device) || names_device(chain, device)) r.masqueraded = 1;
        }
    }
    pclose(f);
    return r;
}

static void report_traceroute_dep(void) {
    if (!g_traceroute_hops) return;
    /* Say the useless case out loud rather than leaving the operator to discover it
     * as a column of asterisks. */
    for (size_t i = 0; i < g_out_n; i++) {
        if (g_out[i].kind != OUT_INTERFACE) continue;
        if (fw_check(g_out[i].device).masqueraded) {
            fprintf(stderr, "steer: traceroute_hops cannot work for output %s: %s "
                            "masquerades, so ICMP errors come addressed to the router "
                            "and only conntrack can route them to the client — "
                            "untracking them drops the hops entirely\n",
                    g_out[i].name, g_out[i].device);
            return;
        }
    }
    FILE *f = popen("nft list ruleset 2>/dev/null", "r");
    int ok = 0;
    if (f) {
        char line[2048];
        while (fgets(line, sizeof(line), f))
            if (strstr(line, "untracked") && strstr(line, "accept")) ok = 1;
        pclose(f);
    }
    if (!ok)
        fprintf(stderr, "steer: traceroute_hops is on but no rule accepting untracked "
                        "packets was found — ICMP time-exceeded will be dropped by the "
                        "firewall and hops will show as asterisks. Needed once, in the "
                        "firewall (not here): accept ct state untracked icmp type "
                        "time-exceeded towards %s\n", g_lan_device);
}

static void report_output_deps(void) {
    for (size_t i = 0; i < g_out_n; i++) {
        if (g_out[i].kind != OUT_INTERFACE) continue;
        struct fwcheck c = fw_check(g_out[i].device);
        if (!c.in_firewall)
            fprintf(stderr, "steer: output %s: %s is not mentioned by the firewall at all — "
                            "traffic steered there will not come back until it is in a zone\n",
                    g_out[i].name, g_out[i].device);
        else if (!c.masqueraded)
            fprintf(stderr, "steer: output %s: no masquerade/snat rule found for %s — "
                            "if that path needs NAT, packets leave with LAN addresses and "
                            "the channel goes quiet while its counter still rises\n",
                    g_out[i].name, g_out[i].device);
    }
}

/* ---- apply ---------------------------------------------------------------- */
static int run(const char *const argv[]) {
    pid_t p = fork();
    if (p < 0) return -1;
    if (p == 0) {
        /* Both streams: `nft get element` prints the whole set on success, which
         * would otherwise land in the middle of explain's answer. */
        int devnull = open("/dev/null", O_WRONLY);
        if (devnull >= 0) { dup2(devnull, 1); dup2(devnull, 2); close(devnull); }
        execvp(argv[0], (char *const *)argv);
        _exit(127);
    }
    int st = 0;
    waitpid(p, &st, 0);
    return WIFEXITED(st) ? WEXITSTATUS(st) : -1;
}

/* Policy routing for interface outputs. Rules are removed before being added so a
 * re-apply cannot stack duplicates — `ip rule add` is happy to add the same rule
 * twice, and the second copy is invisible until someone deletes the first. */
static void apply_routing(void) {
    for (size_t i = 0; i < g_out_n; i++) {
        if (g_out[i].kind != OUT_INTERFACE) continue;
        char mark[24], table[16];
        snprintf(mark, sizeof(mark), "0x%08x", g_out[i].mark);
        snprintf(table, sizeof(table), "%d", g_out[i].table);
        const char *del[] = { "ip", "rule", "del", "fwmark", mark, "table", table, NULL };
        while (run(del) == 0) ;                       /* drain older copies */
        const char *add[] = { "ip", "rule", "add", "fwmark", mark, "table", table, NULL };
        run(add);
        const char *flush[] = { "ip", "route", "flush", "table", table, NULL };
        run(flush);
        const char *route[] = { "ip", "route", "add", "default", "dev", g_out[i].device,
                                "table", table, NULL };
        if (run(route) != 0)
            fprintf(stderr, "steer: output %s: cannot route via %s — is the device up?\n",
                    g_out[i].name, g_out[i].device);
    }
}

static int cmd_apply(const char *spec, int dry) {
    load_spec(spec);
    registry_assign();
    if (dry) { generate(stdout); return 0; }

    char tmp[] = "/tmp/steer-ruleset.XXXXXX";
    int fd = mkstemp(tmp);
    if (fd < 0) die("cannot create a temporary ruleset", NULL);
    FILE *f = fdopen(fd, "w");
    generate(f);
    fclose(f);

    /* Delete-then-load in ONE transaction: `nft -f` applies the whole file
     * atomically, so there is never a moment with our chain present and its sets
     * missing. The delete is tolerated failing on the very first apply. */
    const char *del[] = { "nft", "delete", "table", "inet", "steer", NULL };
    run(del);
    const char *load[] = { "nft", "-f", tmp, NULL };
    int rc = run(load);
    if (rc != 0) {
        fprintf(stderr, "steer: nft refused the ruleset (kept: %s)\n", tmp);
        const char *check[] = { "nft", "-c", "-f", tmp, NULL };
        run(check);
        return 1;
    }
    unlink(tmp);
    apply_routing();
    report_output_deps();
    report_traceroute_dep();
    printf("steer: applied %zu channel(s), %zu output(s)\n", g_ch_n, g_out_n);
    return 0;
}

/* ---- status --------------------------------------------------------------- */
/* Counters come from the live chain, matched by the comment each rule carries —
 * which is why generation puts the channel name there. Without it the numbers
 * exist but belong to nobody. */
static int cmd_status(const char *spec) {
    load_spec(spec);
    registry_assign();
    printf("{\"schema\":1,\"outputs\":{");
    for (size_t i = 0; i < g_out_n; i++) {
        char devpath[128];
        int up = 0;
        if (g_out[i].kind == OUT_INTERFACE) {
            snprintf(devpath, sizeof(devpath), "/sys/class/net/%s/operstate", g_out[i].device);
            FILE *df = fopen(devpath, "r");
            if (df) {
                char st[16] = "";
                if (fgets(st, sizeof(st), df)) up = strncmp(st, "down", 4) != 0;
                fclose(df);
            }
        }
        printf("%s\"%s\":{\"kind\":\"%s\"", i ? "," : "", g_out[i].name,
               g_out[i].kind == OUT_DIRECT ? "direct" : "interface");
        if (g_out[i].kind == OUT_INTERFACE) {
            struct fwcheck c = fw_check(g_out[i].device);
            printf(",\"device\":\"%s\",\"up\":%s,\"mark\":\"0x%08x\",\"table\":%d"
                   ",\"in_firewall\":%s,\"nat\":%s",
                   g_out[i].device, up ? "true" : "false", g_out[i].mark, g_out[i].table,
                   c.in_firewall ? "true" : "false", c.masqueraded ? "true" : "false");
        }
        printf("}");
    }
    printf("},\"channels\":[");

    FILE *nft = popen("nft -a list chain inet steer prerouting_mark 2>/dev/null", "r");
    char line[1024];
    char names[MAX_CHANNELS][32];
    unsigned long pkts[MAX_CHANNELS] = {0}, bytes[MAX_CHANNELS] = {0};
    size_t found = 0;
    if (nft) {
        while (fgets(line, sizeof(line), nft)) {
            char *c = strstr(line, "comment \"steer:");
            if (!c) continue;
            c += strlen("comment \"steer:");
            char *e = strchr(c, '"');
            if (!e) continue;
            *e = '\0';
            unsigned long p = 0, b = 0;
            char *pc = strstr(line, "packets ");
            if (pc) sscanf(pc, "packets %lu bytes %lu", &p, &b);
            if (found < MAX_CHANNELS) {
                snprintf(names[found], sizeof(names[found]), "%s", c);
                pkts[found] = p;
                bytes[found] = b;
                found++;
            }
        }
        pclose(nft);
    }
    for (size_t i = 0; i < g_ch_n; i++) {
        long p = -1, b = -1;
        for (size_t k = 0; k < found; k++)
            if (!strcmp(names[k], g_ch[i].name)) { p = (long)pkts[k]; b = (long)bytes[k]; }
        printf("%s{\"name\":\"%s\",\"out\":\"%s\",\"live\":%s",
               i ? "," : "", g_ch[i].name, g_ch[i].out, p >= 0 ? "true" : "false");
        if (p >= 0) printf(",\"packets\":%ld,\"bytes\":%ld", p, b);
        printf("}");
    }
    printf("]}\n");
    return 0;
}

/* ---- explain -------------------------------------------------------------- */
/* An address from the command line ends up in an nft invocation, so it is checked
 * against a whitelist first. The earlier version interpolated it into system(),
 * which made `steer explain '$(...)'` a command-injection hole; there is no shell
 * here now, and this refuses anything that is not address-shaped regardless. */
static int addr_ok(const char *a) {
    size_t n = 0;
    for (const char *p = a; *p; p++, n++) {
        if (!((*p >= '0' && *p <= '9') || *p == '.' || *p == '/')) return 0;
        if (n > 18) return 0;
    }
    return n > 0;
}

/* Asks the KERNEL, channel by channel in spec order, instead of re-reading the
 * list files: the answer has to describe what the box will actually do, including
 * the case where a set failed to load. This is the one answer raw nft cannot give. */
static int cmd_explain(const char *spec, const char *addr) {
    load_spec(spec);
    registry_assign();
    for (size_t i = 0; i < g_ch_n; i++) {
        int hit = g_ch[i].any;
        /* Domain channels own a set too — it is just filled by the resolver. Asking
         * only the prefix channels made explain answer "no channel matches" for
         * every fake IP, i.e. exactly the addresses a user is most likely to ask
         * about. Same oversight the generator had one commit earlier. */
        if (!hit && (g_ch[i].prefixes_file[0] || g_ch[i].domains_file[0])) {
            char setname[40], elem[32];
            /* Which sets were consulted, in order — the difference between "no
             * channel matches" meaning "not listed" and meaning "explain never
             * looked". */
            if (getenv("STEER_EXPLAIN_TRACE"))
                fprintf(stderr, "checking ch_%.31s\n", g_ch[i].name);
            snprintf(setname, sizeof(setname), "ch_%.31s", g_ch[i].name);
            snprintf(elem, sizeof(elem), "{ %s }", addr);
            const char *q[] = { "nft", "get", "element", "inet", "steer", setname, elem, NULL };
            hit = run(q) == 0;
        }
        if (!hit) continue;
        struct output *o = out_by_name(g_ch[i].out);
        if (!o) die("channel %s points at a missing output", g_ch[i].name);
        printf("%s -> channel \"%s\" -> output \"%s\"", addr, g_ch[i].name, o->name);
        if (o->kind == OUT_INTERFACE)
            printf(" -> dev %s (mark 0x%08x, table %d)\n", o->device, o->mark, o->table);
        else
            printf(" -> direct\n");
        return 0;
    }
    printf("%s -> no channel matches -> direct (steer does not touch it)\n", addr);
    return 0;
}

int main(int argc, char **argv) {
    const char *spec = "/etc/steer/spec.json";
    if (argc < 2) {
        fputs("usage: steer apply [--dry-run] [--spec FILE]\n"
              "       steer dnsd  [--spec FILE]   (resolver for domain channels)\n"
              "       steer status [--spec FILE]\n"
              "       steer explain ADDRESS [--spec FILE]\n", stderr);
        return 2;
    }
    const char *cmd = argv[1], *arg = NULL;
    int dry = 0;
    for (int i = 2; i < argc; i++) {
        if (!strcmp(argv[i], "--spec") && i + 1 < argc) spec = argv[++i];
        else if (!strcmp(argv[i], "--dry-run")) dry = 1;
        else if (!strcmp(argv[i], "--state-dir") && i + 1 < argc) g_state_dir = argv[++i];
        else arg = argv[i];
    }
    if (!strcmp(cmd, "dnsd")) return dnsd_main(argc - 2, argv + 2);
    if (!strcmp(cmd, "apply")) return cmd_apply(spec, dry);
    if (!strcmp(cmd, "status")) return cmd_status(spec);
    if (!strcmp(cmd, "explain")) {
        if (!arg) die("explain needs an address", NULL);
        if (!addr_ok(arg)) die("not an address: %s", arg);
        return cmd_explain(spec, arg);
    }
    die("unknown command: %s", cmd);
    return 2;
}

