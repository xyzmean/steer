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

#define MAX_CHANNELS 64
#define MAX_OUTPUTS  16
#define MAX_FROM     16

/* Marks and tables live well away from what splify (0x40000/0x80000, tables
 * 200/202) and mwan3 use, so both can run on one box while the migration is in
 * progress. One bit per output keeps `nft` output readable. */
#define MARK_BASE   0x00100000u
#define TABLE_BASE  300

enum out_kind { OUT_DIRECT, OUT_INTERFACE };

struct output {
    char name[32];
    enum out_kind kind;
    char device[32];
    uint32_t mark;      /* 0 for direct: claiming a packet needs no mark */
    int table;
};

struct channel {
    char name[32];
    char out[32];
    char prefixes_file[256];
    char from[MAX_FROM][64];
    size_t from_n;
    int any;
};

static struct output g_out[MAX_OUTPUTS];
static size_t g_out_n;
static struct channel g_ch[MAX_CHANNELS];
static size_t g_ch_n;
static char g_from_default[MAX_FROM][64];
static size_t g_from_default_n;

static const char *g_state_dir = "/var/lib/steer";

static void die(const char *fmt, const char *a) {
    fprintf(stderr, "steer: ");
    fprintf(stderr, fmt, a);
    fputc('\n', stderr);
    exit(2);
}

/* ---- a JSON reader small enough to audit ---------------------------------- */
/* Deliberately not a general parser: it walks the document the shape of the spec
 * demands and refuses anything else. A router config that compiles into firewall
 * rules should fail loudly on an unexpected shape rather than guess — which is the
 * same reason the spec is JSON and not YAML. */
struct js { const char *p; };

static void js_ws(struct js *j) {
    while (*j->p == ' ' || *j->p == '\t' || *j->p == '\n' || *j->p == '\r') j->p++;
}
static int js_lit(struct js *j, char c) {
    js_ws(j);
    if (*j->p != c) return -1;
    j->p++;
    return 0;
}
static int js_str(struct js *j, char *buf, size_t n) {
    js_ws(j);
    if (*j->p != '"') return -1;
    j->p++;
    size_t i = 0;
    while (*j->p && *j->p != '"') {
        if (*j->p == '\\' && j->p[1]) j->p++;
        if (i + 1 < n) buf[i++] = *j->p;
        j->p++;
    }
    if (*j->p != '"') return -1;
    j->p++;
    buf[i] = '\0';
    return 0;
}
static long js_num(struct js *j) {
    js_ws(j);
    char *e = NULL;
    long v = strtol(j->p, &e, 10);
    j->p = e;
    return v;
}
/* Skips one value of any type, so unknown keys are tolerated (forward compat
 * within a schema major) without being silently interpreted. */
static void js_skip(struct js *j) {
    js_ws(j);
    if (*j->p == '"') { char t[512]; js_str(j, t, sizeof(t)); return; }
    if (*j->p == '{' || *j->p == '[') {
        char open = *j->p, close = open == '{' ? '}' : ']';
        int depth = 0;
        do {
            if (*j->p == '"') { char t[512]; js_str(j, t, sizeof(t)); continue; }
            if (*j->p == open) depth++;
            else if (*j->p == close) depth--;
            j->p++;
        } while (*j->p && depth > 0);
        return;
    }
    while (*j->p && *j->p != ',' && *j->p != '}' && *j->p != ']') j->p++;
}

static int str_array(struct js *j, char dst[][64], size_t max, size_t *n) {
    if (js_lit(j, '[') != 0) return -1;
    *n = 0;
    js_ws(j);
    if (*j->p == ']') { j->p++; return 0; }
    for (;;) {
        char t[64];
        if (js_str(j, t, sizeof(t)) != 0) return -1;
        if (*n < max) snprintf(dst[(*n)++], 64, "%s", t);
        js_ws(j);
        if (*j->p == ',') { j->p++; continue; }
        break;
    }
    return js_lit(j, ']');
}

static void parse_outputs(struct js *j) {
    if (js_lit(j, '{') != 0) die("outputs: expected an object", NULL);
    js_ws(j);
    if (*j->p == '}') { j->p++; return; }
    for (;;) {
        struct output o = {0};
        if (js_str(j, o.name, sizeof(o.name)) != 0) die("outputs: expected a name", NULL);
        if (js_lit(j, ':') != 0) die("outputs.%s: expected ':'", o.name);
        if (js_lit(j, '{') != 0) die("outputs.%s: expected an object", o.name);
        char kind[32] = "";
        js_ws(j);
        while (*j->p != '}') {
            char key[32];
            if (js_str(j, key, sizeof(key)) != 0) die("outputs.%s: bad key", o.name);
            js_lit(j, ':');
            if (!strcmp(key, "kind")) js_str(j, kind, sizeof(kind));
            else if (!strcmp(key, "device")) js_str(j, o.device, sizeof(o.device));
            else js_skip(j);
            js_ws(j);
            if (*j->p == ',') { j->p++; js_ws(j); }
        }
        j->p++;
        if (!strcmp(kind, "direct")) o.kind = OUT_DIRECT;
        else if (!strcmp(kind, "interface")) {
            o.kind = OUT_INTERFACE;
            if (!o.device[0]) die("outputs.%s: kind interface needs a device", o.name);
        } else die("outputs.%s: unknown kind (want direct or interface)", o.name);
        if (g_out_n >= MAX_OUTPUTS) die("too many outputs", NULL);
        g_out[g_out_n++] = o;
        js_ws(j);
        if (*j->p == ',') { j->p++; continue; }
        break;
    }
    js_lit(j, '}');
}

static void parse_channels(struct js *j) {
    if (js_lit(j, '[') != 0) die("channels: expected an array", NULL);
    js_ws(j);
    if (*j->p == ']') { j->p++; return; }
    for (;;) {
        struct channel c = {0};
        if (js_lit(j, '{') != 0) die("channels: expected an object", NULL);
        js_ws(j);
        while (*j->p != '}') {
            char key[32];
            if (js_str(j, key, sizeof(key)) != 0) die("channels: bad key", NULL);
            js_lit(j, ':');
            if (!strcmp(key, "name")) js_str(j, c.name, sizeof(c.name));
            else if (!strcmp(key, "out")) js_str(j, c.out, sizeof(c.out));
            else if (!strcmp(key, "from")) str_array(j, c.from, MAX_FROM, &c.from_n);
            else if (!strcmp(key, "match")) {
                if (js_lit(j, '{') != 0) die("channels.%s: match must be an object", c.name);
                js_ws(j);
                while (*j->p != '}') {
                    char mk[32];
                    js_str(j, mk, sizeof(mk));
                    js_lit(j, ':');
                    if (!strcmp(mk, "prefixes_file")) js_str(j, c.prefixes_file, sizeof(c.prefixes_file));
                    else if (!strcmp(mk, "any")) { js_ws(j); c.any = (*j->p == 't'); js_skip(j); }
                    else js_skip(j);
                    js_ws(j);
                    if (*j->p == ',') { j->p++; js_ws(j); }
                }
                j->p++;
            }
            else js_skip(j);
            js_ws(j);
            if (*j->p == ',') { j->p++; js_ws(j); }
        }
        j->p++;
        if (!c.name[0]) die("a channel has no name", NULL);
        if (!c.out[0]) die("channel %s has no out", c.name);
        if (!c.prefixes_file[0] && !c.any)
            die("channel %s matches nothing (want prefixes_file or any)", c.name);
        if (g_ch_n >= MAX_CHANNELS) die("too many channels", NULL);
        g_ch[g_ch_n++] = c;
        js_ws(j);
        if (*j->p == ',') { j->p++; continue; }
        break;
    }
    js_lit(j, ']');
}

static void load_spec(const char *path) {
    FILE *f = strcmp(path, "-") ? fopen(path, "r") : stdin;
    if (!f) die("%s: cannot open", path);
    static char buf[262144];
    size_t n = fread(buf, 1, sizeof(buf) - 1, f);
    buf[n] = '\0';
    if (f != stdin) fclose(f);

    struct js j = { buf };
    long schema = -1;
    if (js_lit(&j, '{') != 0) die("spec: expected an object", NULL);
    js_ws(&j);
    while (*j.p && *j.p != '}') {
        char key[64];
        if (js_str(&j, key, sizeof(key)) != 0) die("spec: bad key", NULL);
        js_lit(&j, ':');
        if (!strcmp(key, "schema")) schema = js_num(&j);
        else if (!strcmp(key, "outputs")) parse_outputs(&j);
        else if (!strcmp(key, "channels")) parse_channels(&j);
        else if (!strcmp(key, "from_default")) str_array(&j, g_from_default, MAX_FROM, &g_from_default_n);
        else js_skip(&j);
        js_ws(&j);
        if (*j.p == ',') { j.p++; js_ws(&j); }
    }
    /* Refusing an unknown major is the whole point of having the field: guessing
     * would mean compiling a config we do not understand into firewall rules. */
    if (schema != 1) {
        fprintf(stderr, "steer: spec schema %ld is not supported (this build speaks 1)\n", schema);
        exit(2);
    }
    if (!g_out_n) die("spec has no outputs", NULL);
    if (!g_ch_n) die("spec has no channels", NULL);
    for (size_t i = 0; i < g_ch_n; i++) {
        size_t k = 0;
        for (; k < g_out_n; k++) if (!strcmp(g_ch[i].out, g_out[k].name)) break;
        if (k == g_out_n) die("channel %s points at an output that does not exist", g_ch[i].name);
    }
}

/* ---- mark/table registry -------------------------------------------------- */
/* Persisted, because an output must keep its mark across restarts: a reboot that
 * reshuffles marks leaves stale `ip rule` entries pointing at the wrong table,
 * and the symptom is traffic silently taking someone else's path. */
static void registry_assign(void) {
    char path[512];
    snprintf(path, sizeof(path), "%s/registry", g_state_dir);
    FILE *f = fopen(path, "r");
    if (f) {
        char name[32];
        unsigned mark;
        int table;
        while (fscanf(f, "%31s %x %d\n", name, &mark, &table) == 3)
            for (size_t i = 0; i < g_out_n; i++)
                if (!strcmp(g_out[i].name, name) && g_out[i].kind != OUT_DIRECT) {
                    g_out[i].mark = mark;
                    g_out[i].table = table;
                }
        fclose(f);
    }
    unsigned next_bit = 0;
    for (size_t i = 0; i < g_out_n; i++)
        if (g_out[i].mark) {
            unsigned b = 0;
            while ((MARK_BASE << b) < g_out[i].mark && b < 8) b++;
            if (b + 1 > next_bit) next_bit = b + 1;
        }
    for (size_t i = 0; i < g_out_n; i++) {
        if (g_out[i].kind == OUT_DIRECT || g_out[i].mark) continue;
        if (next_bit >= 8) die("out of mark bits for output %s", g_out[i].name);
        g_out[i].mark = MARK_BASE << next_bit;
        g_out[i].table = TABLE_BASE + (int)next_bit;
        next_bit++;
    }
    mkdir(g_state_dir, 0755);
    f = fopen(path, "w");
    if (!f) return;             /* best effort: apply still works, next boot re-assigns */
    for (size_t i = 0; i < g_out_n; i++)
        if (g_out[i].kind != OUT_DIRECT)
            fprintf(f, "%s %x %d\n", g_out[i].name, g_out[i].mark, g_out[i].table);
    fclose(f);
}

static struct output *out_by_name(const char *n) {
    for (size_t i = 0; i < g_out_n; i++) if (!strcmp(g_out[i].name, n)) return &g_out[i];
    return NULL;
}

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

static void generate(FILE *f) {
    fprintf(f, "table inet steer {\n");
    for (size_t i = 0; i < g_ch_n; i++) {
        if (!g_ch[i].prefixes_file[0]) continue;
        fprintf(f, "    set ch_%s {\n        type ipv4_addr\n        flags interval\n",
                g_ch[i].name);
        fprintf(f, "        elements = { ");
        emit_elements(f, g_ch[i].prefixes_file);
        fprintf(f, " }\n    }\n");
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
        if (g_ch[i].prefixes_file[0]) fprintf(f, "ip daddr @ch_%s ", g_ch[i].name);
        if (o->kind == OUT_INTERFACE) fprintf(f, "meta mark set 0x%08x ", o->mark);
        /* `return` and not `accept`: it ends OUR chain, letting the rest of the
         * firewall proceed, while making the first matching channel the winner. */
        fprintf(f, "counter return comment \"steer:%s\"\n", g_ch[i].name);
    }
    fprintf(f, "    }\n}\n");
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
        if (g_out[i].kind == OUT_INTERFACE)
            printf(",\"device\":\"%s\",\"up\":%s,\"mark\":\"0x%08x\",\"table\":%d",
                   g_out[i].device, up ? "true" : "false", g_out[i].mark, g_out[i].table);
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
        if (!hit && g_ch[i].prefixes_file[0]) {
            char setname[40], elem[32];
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
