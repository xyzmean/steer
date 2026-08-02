/* steer aggregate — fit a prefix list into a budgeted number of set elements.
 *
 * The problem this solves, measured on a Mi Router 4C (mipsel, one 580MHz core,
 * 13-15MB free): the RU blocklist aggregates to 28 559 prefixes, a set element
 * costs ~1.3KB to load, and the box cannot hold that. splify's shell version
 * bridged GAPS between ranges ("slack"), which has two measured problems:
 *
 *   slack 0      19 122 elements
 *   slack 256    13 155
 *   slack 1024   17 125    <- larger
 *   slack 4096   20 801    <- larger than no aggregation at all
 *
 * Gap bridging bottoms out around 12 000 elements no matter how wide the slack,
 * which still does not fit; and past a point it makes the list BIGGER, because a
 * widening blocked by an excluded address has to be cut into fragments around it.
 * So the shell version fell through to dropping the tail of the list — and the cut
 * is positional, which means everything above one address silently loses routing.
 * On the 4C that boundary landed at 198.38.96.0, so youtube.com worked or not
 * depending on which A record DNS happened to return (142.250.x below the cut was
 * routed, 216.58.x above it was not).
 *
 * This uses DENSITY instead: if a /24 holds two or more listed addresses, take the
 * whole /24. Measured on the same list: 10 716 elements with FULL coverage — fewer
 * than the truncated list the box holds today, so the hole disappears while using
 * about half the memory. The cost is ~580 000 extra addresses (0.013% of IPv4)
 * routed through the tunnel.
 *
 * The >=2 threshold is not arbitrary: 8 428 of the 10 716 /24s in that list hold
 * exactly ONE address, where collapsing buys nothing and costs 255 addresses.
 */
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <inttypes.h>
#include <errno.h>

/* An inclusive address range. Everything downstream of parsing works in ranges
 * rather than prefixes: an nftables interval set stores one element per range, so
 * emitting ranges instead of decomposing them back into aligned prefixes is a
 * straight memory win on the router. */
struct range { uint32_t lo, hi; };

struct list {
    struct range *v;
    size_t n, cap;
};

static void die(const char *msg) {
    fprintf(stderr, "steer aggregate: %s\n", msg);
    exit(2);
}

static void list_push(struct list *l, uint32_t lo, uint32_t hi) {
    if (l->n == l->cap) {
        size_t nc = l->cap ? l->cap * 2 : 1024;
        struct range *nv = realloc(l->v, nc * sizeof(*nv));
        if (!nv) die("out of memory");
        l->v = nv;
        l->cap = nc;
    }
    l->v[l->n].lo = lo;
    l->v[l->n].hi = hi;
    l->n++;
}

static int parse_addr(const char *s, const char *end, uint32_t *out) {
    uint32_t v = 0;
    int octets = 0;
    while (s < end) {
        if (*s < '0' || *s > '9') return -1;
        unsigned o = 0;
        while (s < end && *s >= '0' && *s <= '9') {
            o = o * 10 + (unsigned)(*s++ - '0');
            if (o > 255) return -1;
        }
        v = (v << 8) | o;
        octets++;
        if (s == end) break;
        if (*s != '.') return -1;
        s++;
    }
    if (octets != 4) return -1;
    *out = v;
    return 0;
}

/* Accepts "a.b.c.d", "a.b.c.d/len" and "a.b.c.d-e.f.g.h" — the last one because
 * this tool's own output uses ranges, so its output must be valid input (that is
 * what makes the ladder below composable and the golden tests round-trippable). */
static int parse_line(const char *line, uint32_t *lo, uint32_t *hi) {
    const char *p = line;
    while (*p == ' ' || *p == '\t') p++;
    if (*p == '#' || *p == ';' || *p == '\0' || *p == '\n') return -1;

    const char *e = p;
    while (*e && *e != '\n' && *e != '\r' && *e != ' ' && *e != '\t'
           && *e != '/' && *e != '-') e++;
    uint32_t a;
    if (parse_addr(p, e, &a) != 0) return -1;

    if (*e == '/') {
        char *endp = NULL;
        long len = strtol(e + 1, &endp, 10);
        if (len < 0 || len > 32) return -1;
        uint32_t mask = len ? (uint32_t)(0xFFFFFFFFu << (32 - len)) : 0;
        *lo = a & mask;
        *hi = *lo | ~mask;
        return 0;
    }
    if (*e == '-') {
        const char *s2 = e + 1, *e2 = s2;
        while (*e2 && *e2 != '\n' && *e2 != '\r' && *e2 != ' ' && *e2 != '\t') e2++;
        uint32_t b;
        if (parse_addr(s2, e2, &b) != 0 || b < a) return -1;
        *lo = a;
        *hi = b;
        return 0;
    }
    *lo = *hi = a;
    return 0;
}

static int cmp_range(const void *x, const void *y) {
    const struct range *a = x, *b = y;
    if (a->lo != b->lo) return a->lo < b->lo ? -1 : 1;
    if (a->hi != b->hi) return a->hi < b->hi ? -1 : 1;
    return 0;
}

/* Lossless: join ranges that overlap or touch. Nothing here widens coverage, so it
 * runs before every fit attempt and after every collapse level. */
static void merge_lossless(struct list *l) {
    if (l->n == 0) return;
    qsort(l->v, l->n, sizeof(*l->v), cmp_range);
    size_t w = 0;
    for (size_t i = 1; i < l->n; i++) {
        /* +1 in 64-bit: hi can be 255.255.255.255 and hi+1 would wrap. */
        if ((uint64_t)l->v[i].lo <= (uint64_t)l->v[w].hi + 1) {
            if (l->v[i].hi > l->v[w].hi) l->v[w].hi = l->v[i].hi;
        } else {
            l->v[++w] = l->v[i];
        }
    }
    l->n = w + 1;
}

/* ---- exclusions ---------------------------------------------------------- */
/* Addresses that must NOT be swallowed by a widening — in splify's case the RU/CN
 * list, because an address dragged into a tunnel-bound range loses its direct
 * route. Checked PER CANDIDATE network, which is what keeps this cheap: the shell
 * version checked every gap bridge, and a refused bridge is exactly what made wide
 * slack fragment the list and grow it. */
static struct list g_excl;

static int excl_hits(uint32_t lo, uint32_t hi) {
    if (g_excl.n == 0) return 0;
    size_t a = 0, b = g_excl.n;
    while (a < b) {                       /* first range with hi >= lo */
        size_t m = a + (b - a) / 2;
        if (g_excl.v[m].hi < lo) a = m + 1; else b = m;
    }
    return a < g_excl.n && g_excl.v[a].lo <= hi;
}

/* ---- density collapse ---------------------------------------------------- */
/* One pass over the sorted list: for each /LEVEL network, count the entries that
 * fall entirely inside it; if there are at least MIN_COUNT of them and the network
 * holds nothing excluded, replace them all with the network itself.
 *
 * Returns the number of addresses added to the covered set (the "waste"), so the
 * caller can report the real cost instead of a reassuring element count. */
/* What to do with a candidate network that holds excluded addresses. Measured on
 * the RU blocklist against the 44 095-prefix RU/CN exclusion:
 *
 *   REFUSE  14 665 elements — 4 400 collapses lost to the exclusion, does not fit
 *   PUNCH   10 225 + 443    — collapse anyway and hand the 443 intersecting
 *                             excluded ranges back to the caller
 *
 * PUNCH wins by 10x because the exclusion is enormous (44k prefixes) while its
 * overlap with dense blocklist /24s is tiny (443 ranges in 361 networks). The
 * caller keeps those ranges direct in a higher-priority channel, so coverage of
 * the blocklist AND of the excluded addresses is complete — which REFUSE cannot
 * achieve at this budget at all. */
enum excl_mode { EXCL_REFUSE, EXCL_PUNCH };
static enum excl_mode g_excl_mode = EXCL_REFUSE;
static struct list g_punch;   /* excluded ranges swallowed by a collapse */

static void punch_record(uint32_t lo, uint32_t hi) {
    if (g_excl.n == 0) return;
    size_t a = 0, b = g_excl.n;
    while (a < b) {
        size_t m = a + (b - a) / 2;
        if (g_excl.v[m].hi < lo) a = m + 1; else b = m;
    }
    for (size_t i = a; i < g_excl.n && g_excl.v[i].lo <= hi; i++) {
        uint32_t s = g_excl.v[i].lo > lo ? g_excl.v[i].lo : lo;
        uint32_t e = g_excl.v[i].hi < hi ? g_excl.v[i].hi : hi;
        list_push(&g_punch, s, e);
    }
}

static uint64_t collapse_level(struct list *l, unsigned level, size_t min_count) {
    if (level == 0 || level > 32 || l->n == 0) return 0;
    uint32_t mask = (uint32_t)(0xFFFFFFFFu << (32 - level));
    uint64_t waste = 0;
    struct list out = {0};

    size_t i = 0;
    while (i < l->n) {
        uint32_t net = l->v[i].lo & mask;
        uint32_t net_end = net | ~mask;

        /* A range wider than one network cannot be "inside" it — keep it as is and
         * move on, or the walk would not advance. */
        if (l->v[i].hi > net_end) {
            list_push(&out, l->v[i].lo, l->v[i].hi);
            i++;
            continue;
        }
        size_t j = i, count = 0;
        uint64_t covered = 0;
        while (j < l->n && l->v[j].lo >= net && l->v[j].hi <= net_end) {
            covered += (uint64_t)l->v[j].hi - l->v[j].lo + 1;
            count++;
            j++;
        }
        int blocked = excl_hits(net, net_end);
        if (count >= min_count && (!blocked || g_excl_mode == EXCL_PUNCH)) {
            if (blocked) punch_record(net, net_end);
            list_push(&out, net, net_end);
            waste += ((uint64_t)net_end - net + 1) - covered;
        } else {
            for (size_t k = i; k < j; k++) list_push(&out, l->v[k].lo, l->v[k].hi);
        }
        i = j;
    }
    free(l->v);
    *l = out;
    merge_lossless(l);
    return waste;
}

/* ---- output -------------------------------------------------------------- */
static void fmt_addr(uint32_t a, char *buf, size_t n) {
    snprintf(buf, n, "%u.%u.%u.%u", a >> 24, (a >> 16) & 255, (a >> 8) & 255, a & 255);
}

/* A range as one CIDR when it happens to be aligned, else as "lo-hi". nft accepts
 * both in an interval set and stores either as ONE element, so this never trades
 * memory for looks. */
static void emit_range(FILE *f, uint32_t lo, uint32_t hi) {
    char a[16], b[16];
    uint64_t size = (uint64_t)hi - lo + 1;
    if ((size & (size - 1)) == 0 && (lo & (uint32_t)(size - 1)) == 0) {
        unsigned len = 32;
        while (((uint64_t)1 << (32 - len)) < size) len--;
        fmt_addr(lo, a, sizeof(a));
        if (len == 32) fprintf(f, "%s\n", a);
        else fprintf(f, "%s/%u\n", a, len);
        return;
    }
    fmt_addr(lo, a, sizeof(a));
    fmt_addr(hi, b, sizeof(b));
    fprintf(f, "%s-%s\n", a, b);
}

static void read_file(const char *path, struct list *l, unsigned long *bad) {
    FILE *f = strcmp(path, "-") ? fopen(path, "r") : stdin;
    if (!f) { fprintf(stderr, "steer aggregate: %s: %s\n", path, strerror(errno)); exit(2); }
    char line[256];
    while (fgets(line, sizeof(line), f)) {
        uint32_t lo, hi;
        if (parse_line(line, &lo, &hi) == 0) list_push(l, lo, hi);
        else if (bad) (*bad)++;
    }
    if (f != stdin) fclose(f);
}

static void usage(void) {
    fputs("usage: steer-aggregate [--budget N] [--exclude FILE] [--min-count N]\n"
          "                       [--report FILE] [--levels 'LVL:MIN ...'] [--truncate]\n"
          "                       [--punch-out FILE] [IN]\n"
          "\n"
          "Fits a prefix list into at most N set elements. Without --budget it only\n"
          "merges losslessly. Writes the fitted list to stdout and a JSON report of\n"
          "what it cost to --report (default: stderr). Exits 1 when it does not fit.\n"
          "\n"
          "--truncate allows dropping the tail as a last resort. Without it a list that\n"
          "cannot be compressed enough is emitted whole with fits:false, because a\n"
          "silent hole above one address is worse than an honest refusal.\n", stderr);
    exit(2);
}

int main(int argc, char **argv) {
    const char *in = "-", *excl_path = NULL, *report_path = NULL, *punch_path = NULL;
    const char *levels = "24:2 22:4 20:8 16:16";
    size_t budget = 0, min_count = 2;
    int do_truncate = 0;

    for (int i = 1; i < argc; i++) {
        if (!strcmp(argv[i], "--budget") && i + 1 < argc) budget = strtoul(argv[++i], NULL, 10);
        else if (!strcmp(argv[i], "--exclude") && i + 1 < argc) excl_path = argv[++i];
        else if (!strcmp(argv[i], "--min-count") && i + 1 < argc) min_count = strtoul(argv[++i], NULL, 10);
        else if (!strcmp(argv[i], "--report") && i + 1 < argc) report_path = argv[++i];
        else if (!strcmp(argv[i], "--levels") && i + 1 < argc) levels = argv[++i];
        else if (!strcmp(argv[i], "--truncate")) do_truncate = 1;
        else if (!strcmp(argv[i], "--punch-out") && i + 1 < argc) {
            punch_path = argv[++i];
            g_excl_mode = EXCL_PUNCH;
        }
        else if (!strcmp(argv[i], "-h") || !strcmp(argv[i], "--help")) usage();
        else if (argv[i][0] == '-' && argv[i][1]) usage();
        else in = argv[i];
    }
    if (min_count < 1) min_count = 1;

    /* Merged and sorted, because excl_hits() binary-searches it. */
    if (excl_path) {
        read_file(excl_path, &g_excl, NULL);
        merge_lossless(&g_excl);
    }

    struct list l = {0};
    unsigned long bad = 0;
    read_file(in, &l, &bad);
    size_t src_n = l.n;
    merge_lossless(&l);

    uint64_t waste = 0;
    unsigned used_level = 0;
    int truncated = 0;

    /* Ladder, cheapest first: stop at the first level that fits. A router with room
     * to spare must not route one extra address, which is why this never starts
     * from the widest level. */
    if (budget && l.n > budget) {
        const char *p = levels;
        while (*p && l.n > budget) {
            char *endp = NULL;
            unsigned lvl = (unsigned)strtoul(p, &endp, 10);
            if (endp == p) break;
            p = endp;
            /* Optional per-level threshold, "24:2". A wider network MUST demand more
             * entries: at a flat threshold of 2, a /16 holding two lonely addresses
             * would swallow 65 534 of them for one element saved. The default ladder
             * keeps the waste-per-element-saved roughly flat. */
            size_t mc = min_count;
            if (*p == ':') {
                p++;
                mc = strtoul(p, &endp, 10);
                p = endp;
                if (mc < 1) mc = 1;
            }
            while (*p == ' ' || *p == ',') p++;
            if (lvl == 0 || lvl > 32) continue;
            size_t before = l.n;
            waste += collapse_level(&l, lvl, mc);
            /* Only a level that actually changed something gets reported — saying
             * "level 16" for a run where nothing collapsed reads as if the widest
             * rung had been used. */
            if (l.n != before) used_level = lvl;
        }
    }

    /* Dropping the tail is a hole in coverage, not a smaller list, so it is OPT-IN:
     * without --truncate the tool emits everything it has and reports fits:false,
     * leaving the caller to choose between a hole and no list at all. Defaulting to
     * truncation is how a router ends up silently unprotected above one address with
     * nothing in the logs to connect the symptom to memory.
     *
     * When it is requested, the report must name the boundary — "kept 19122 of
     * 30726" tells a user nothing they can act on, "protected through 198.38.96.0"
     * does. */
    uint32_t covered_through = 0;
    int fits = !(budget && l.n > budget);
    if (!fits && do_truncate) {
        l.n = budget;
        truncated = 1;
        if (l.n) covered_through = l.v[l.n - 1].hi;
    }

    for (size_t i = 0; i < l.n; i++) emit_range(stdout, l.v[i].lo, l.v[i].hi);

    /* The ranges a collapse swallowed. The caller MUST route these ahead of the
     * fitted list, or the addresses it promised to keep direct ride the tunnel. */
    if (punch_path) {
        merge_lossless(&g_punch);
        FILE *pf = fopen(punch_path, "w");
        if (!pf) { fprintf(stderr, "steer aggregate: %s: %s\n", punch_path, strerror(errno)); return 2; }
        for (size_t i = 0; i < g_punch.n; i++) emit_range(pf, g_punch.v[i].lo, g_punch.v[i].hi);
        fclose(pf);
    }

    FILE *rf = stderr;
    if (report_path) {
        rf = fopen(report_path, "w");
        if (!rf) { fprintf(stderr, "steer aggregate: %s: %s\n", report_path, strerror(errno)); return 2; }
    }
    fprintf(rf, "{\"source\":%zu,\"kept\":%zu,\"waste_addresses\":%" PRIu64
                ",\"level\":%u,\"min_count\":%zu,\"malformed\":%lu,\"truncated\":%s",
            src_n, l.n, waste, used_level, min_count, bad, truncated ? "true" : "false");
    fprintf(rf, ",\"fits\":%s,\"punched\":%zu", fits ? "true" : "false", g_punch.n);
    if (truncated) {
        char a[16];
        fmt_addr(covered_through, a, sizeof(a));
        fprintf(rf, ",\"covered_through\":\"%s\"", a);
    }
    fprintf(rf, "}\n");
    if (rf != stderr) fclose(rf);
    return fits ? 0 : 1;
}
