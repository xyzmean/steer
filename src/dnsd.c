/*
 * splify-dnsd — transparent DNS forwarding proxy that routes matched domains
 * into splify's existing nftables sets (splify_vpn_v4 / splify_direct_v4) at
 * resolve time, based on richer domain-rule matching (exact / namespace /
 * wildcard / regex) than dnsmasq's `nftset=` directive supports.
 *
 * It NEVER resolves anything itself: every client query is forwarded
 * byte-for-byte to the real resolver (dnsmasq, 127.0.0.1:53). For a domain
 * that does NOT match a rule (the overwhelming majority), the answer is
 * relayed back byte-for-byte, unmodified. For a domain that DOES match, the
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

#include <arpa/inet.h>
#include <ctype.h>
#include <errno.h>
#include <fcntl.h>
#include <fnmatch.h>
#include <netinet/in.h>
#include <regex.h>
#include <signal.h>
#include <stdint.h>
#include "spec.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/epoll.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

#define MAX_PKT 4096
#define MAX_PENDING 256
#define PENDING_TTL_SEC 5
#define MAX_RULE_LINES 65536
#define MAX_HOSTNAME 256

/* ---------------------------------------------------------------------- */
/* rule matching                                                          */
/* ---------------------------------------------------------------------- */

enum rule_type { RULE_EXACT, RULE_NAMESPACE, RULE_WILDCARD, RULE_REGEX };

struct rule {
    enum rule_type type;
    char *pattern;   /* lowercased source pattern, kept for EXACT/NAMESPACE/WILDCARD */
    regex_t re;      /* compiled only when type == RULE_REGEX */
    int re_valid;
};

struct ruleset {
    struct rule *rules;
    size_t n;
    size_t cap;
};

static void ruleset_free(struct ruleset *rs) {
    for (size_t i = 0; i < rs->n; i++) {
        free(rs->rules[i].pattern);
        if (rs->rules[i].re_valid)
            regfree(&rs->rules[i].re);
    }
    free(rs->rules);
    rs->rules = NULL;
    rs->n = 0;
    rs->cap = 0;
}

static void str_lower(char *s) {
    for (; *s; s++) *s = (char)tolower((unsigned char)*s);
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

static int ruleset_add(struct ruleset *rs, const char *raw) {
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
    rs->n++;
    return 0;
}

static int load_rules(const char *path, struct ruleset *rs) {
    struct ruleset tmp = {0};
    FILE *f = fopen(path, "r");
    if (!f) return -1; /* missing file: caller keeps empty ruleset, not an error */
    char line[512];
    while (fgets(line, sizeof(line), f)) {
        if (!clean_line(line)) continue;
        ruleset_add(&tmp, line);
    }
    fclose(f);
    ruleset_free(rs);
    *rs = tmp;
    return 0;
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

static int ruleset_match(const struct ruleset *rs, const char *host) {
    char lower[MAX_HOSTNAME];
    size_t n = strlen(host);
    if (n >= sizeof(lower)) n = sizeof(lower) - 1;
    memcpy(lower, host, n);
    lower[n] = '\0';
    str_lower(lower);
    for (size_t i = 0; i < rs->n; i++)
        if (rule_matches(&rs->rules[i], lower)) return 1;
    return 0;
}

/* ---------------------------------------------------------------------- */
/* DNS wire-format parsing (read-only; never mutates the packet)          */
/* ---------------------------------------------------------------------- */

/* Decodes a (possibly compressed) name starting at pos into out (dot-joined,
 * NUL terminated), and returns via *next the stream position right after the
 * name (following RFC1035 compression-pointer semantics: only the FIRST
 * pointer counts toward the caller's next-field offset). */
static int parse_name_adv(const uint8_t *pkt, size_t len, size_t pos, char *out,
                           size_t outlen, size_t *next) {
    size_t start = pos;
    size_t opos = 0;
    int jumps = 0;
    size_t cursor = pos;
    size_t advance_to = 0;
    int pointer_taken = 0;

    for (;;) {
        if (cursor >= len) return -1;
        uint8_t lbl = pkt[cursor];
        if (lbl == 0) {
            if (!pointer_taken) advance_to = cursor + 1;
            break;
        }
        if ((lbl & 0xC0) == 0xC0) {
            if (cursor + 1 >= len) return -1;
            size_t target = ((size_t)(lbl & 0x3F) << 8) | pkt[cursor + 1];
            if (!pointer_taken) {
                advance_to = cursor + 2;
                pointer_taken = 1;
            }
            if (++jumps > 32) return -1;
            cursor = target;
            continue;
        }
        if ((lbl & 0xC0) != 0) return -1;
        size_t label_len = lbl;
        cursor++;
        if (cursor + label_len > len) return -1;
        if (opos + label_len + 1 >= outlen) return -1;
        if (opos > 0) out[opos++] = '.';
        memcpy(out + opos, pkt + cursor, label_len);
        opos += label_len;
        cursor += label_len;
    }
    out[opos] = '\0';
    (void)start;
    *next = advance_to;
    return 0;
}

#define DNS_TYPE_A    1
#define DNS_TYPE_AAAA 28

struct answer_ip {
    uint32_t addr; /* network byte order */
    uint32_t ttl;
};

/* Parses a DNS response: extracts the question name (out_qname), question
 * type (out_qtype), the stream offset right after the question section
 * (out_qend — the header[0,12) + question[12,*out_qend) prefix is byte-
 * identical between the real response and anything we build to replace it,
 * so callers can reuse it verbatim), and every A-record (class IN) answer
 * IP+TTL, up to max_ips entries. Only correct for qdcount==1 (universally
 * true for a resolver's own queries) — anything else is treated as
 * unparseable. Returns the number of A-record IPs found, or -1 on a
 * malformed/short/multi-question packet (caller must still relay the raw
 * bytes to the client regardless). */
static int parse_response(const uint8_t *pkt, size_t len, char *out_qname,
                           size_t qname_len, uint16_t *out_qtype,
                           size_t *out_qend, struct answer_ip *ips,
                           int max_ips) {
    if (len < 12) return -1;
    uint16_t qdcount = (pkt[4] << 8) | pkt[5];
    uint16_t ancount = (pkt[6] << 8) | pkt[7];

    size_t pos = 12;
    if (qdcount != 1) return -1;

    size_t next = 0;
    if (parse_name_adv(pkt, len, pos, out_qname, qname_len, &next) != 0)
        return -1;
    pos = next;
    if (pos + 4 > len) return -1;
    *out_qtype = (uint16_t)((pkt[pos] << 8) | pkt[pos + 1]);
    pos += 4; /* qtype + qclass */
    *out_qend = pos;

    int found = 0;
    for (uint16_t a = 0; a < ancount && pos < len; a++) {
        char rrname[MAX_HOSTNAME];
        if (parse_name_adv(pkt, len, pos, rrname, sizeof(rrname), &next) != 0)
            break;
        pos = next;
        if (pos + 10 > len) break;
        uint16_t rtype = (pkt[pos] << 8) | pkt[pos + 1];
        uint16_t rclass = (pkt[pos + 2] << 8) | pkt[pos + 3];
        uint32_t ttl = ((uint32_t)pkt[pos + 4] << 24) | ((uint32_t)pkt[pos + 5] << 16) |
                       ((uint32_t)pkt[pos + 6] << 8) | pkt[pos + 7];
        uint16_t rdlen = (pkt[pos + 8] << 8) | pkt[pos + 9];
        pos += 10;
        if (pos + rdlen > len) break;
        if (rtype == DNS_TYPE_A && rclass == 1 /* IN */ && rdlen == 4 &&
            found < max_ips) {
            uint32_t addr;
            memcpy(&addr, pkt + pos, 4);
            ips[found].addr = addr;
            ips[found].ttl = ttl;
            found++;
        }
        pos += rdlen;
    }
    return found;
}

/* ---------------------------------------------------------------------- */
/* nftables integration — direct netlink (no fork/exec, no `nft` CLI)     */
/* ---------------------------------------------------------------------- */
/* Why this is NOT fork+exec("nft add element ...") anymore.
 *
 * The previous implementation fired one `nft` subprocess per matched DNS
 * resolution. Each `nft` invocation loads and reparses the ENTIRE live
 * ruleset into its own address space (measured 40-70MB per process, even
 * with NFNL_F_NO_GEN-tracking). On a memory-constrained OpenWrt box
 * (~240MB total) this is catastrophic: under a burst of new domains the
 * OOM-killer murders `nft` (10x) and `dnsmasq` (3x) live on real hardware,
 * leaving the fakeip map half-empty — clients then receive a fake IP whose
 * DNAT entry was never installed and hang on TCP retries for ~130s. That
 * is exactly the "locks up the router for 2-3 minutes" symptom.
 *
 * The fix is the same insight sing-box/Clash use for their fakeip: keep a
 * single long-lived process and mutate kernel state in-process, with no
 * subprocess per operation. We speak nfnetlink directly. A `NEWSETELEM`
 * carries only the element delta (~40 bytes) plus table/set NAMES — the
 * kernel resolves name->handle internally, so the full ruleset is never
 * serialized into userspace. Cost per add: a single sendmsg + one ack
 * recv, sub-millisecond. Peak memory of this daemon stays constant
 * (~250KB RSS) regardless of traffic burst.
 *
 * ACK discipline: every transaction carries NLM_F_ACK, so we synchronously
 * read the kernel's NLMSG_ERROR reply. For the DNAT map (the part whose
 * absence hangs clients) we block on the ack BEFORE handing the client the
 * fake IP — if it fails, we relay the real answer instead (fail-open). For
 * the routing set (best-effort policy mark) we fire-and-forget after the
 * reply, since the default policy covers a missing entry anyway.
 */
#include <linux/netlink.h>
#include <linux/netfilter/nfnetlink.h>
#include <linux/netfilter/nf_tables.h>

static const char *g_nft_table = "inet steer"; /* "<family> <table>" */

/* nfgenmsg::nfgen_family takes a NFPROTO_* constant (NOT AF_* despite the
 * kernel header's misleading "AF_xxx" comment — nf_tables predates that
 * comment and libnftnl/nft both use NFPROTO_*). We do NOT rely on the
 * <linux/netfilter.h> enum here: several cross-toolchain sysroots ship a
 * header where NFPROTO_* are defined as bare enum constants that a static
 * build can resolve to 0 (verified: glibc-cross 13 gives NFPROTO_INET==0),
 * whereas the kernel's canonical values are fixed ABI numbers. Hard-code the
 * stable uapi values instead — they never change. */
#define SPL_NFPROTO_UNSPEC  0
#define SPL_NFPROTO_INET    1   /* nft's "inet" family — the only one we use */
#define SPL_NFPROTO_IPV4    2
#define SPL_NFPROTO_ARP     3
#define SPL_NFPROTO_NETDEV  5
#define SPL_NFPROTO_BRIDGE  7
#define SPL_NFPROTO_IPV6    10

/* Map the textual table family (first token of "--table", e.g. "inet") to its
 * NFPROTO number. Defaults to INET — this daemon only ever targets "inet fw4". */
static uint8_t nftlk_family(const char *fam) {
    if (!fam) return SPL_NFPROTO_INET;
    if (strcmp(fam, "inet") == 0)    return SPL_NFPROTO_INET;
    if (strcmp(fam, "ip") == 0)      return SPL_NFPROTO_IPV4;
    if (strcmp(fam, "ip6") == 0)     return SPL_NFPROTO_IPV6;
    if (strcmp(fam, "arp") == 0)     return SPL_NFPROTO_ARP;
    if (strcmp(fam, "bridge") == 0)  return SPL_NFPROTO_BRIDGE;
    if (strcmp(fam, "netdev") == 0)  return SPL_NFPROTO_NETDEV;
    return SPL_NFPROTO_INET;
}
static void nftlk_split_table(const char *fam_tbl, const char **out_fam, const char **out_tbl) {
    const char *sp = strchr(fam_tbl, ' ');
    if (sp) { *out_fam = fam_tbl; *out_tbl = sp + 1; }
    else    { *out_fam = fam_tbl; *out_tbl = "fw4"; }
}

/* ---- minimal nla (netlink attribute) builder -------------------------- */
/* Builds one nfnetlink message in a flat buffer using standard netlink TLV
 * semantics: NLA_HEADER(2B len incl header, 2B type) + payload padded to 4B.
 * Nested attrs use NLA_F_NESTED in the type. We only ever build one
 * NEWSETELEM transaction at a time, so a single reentrant builder suffices. */
/* NLA_F_NESTED, NLA_HDRLEN, NLA_ALIGN come from <linux/netlink.h>. */
#define NFTLK_MSG_CAP     512   /* biggest msg we build: hdrs + ~3 nested attrs */
#define ACK_TIMEOUT_MS    100   /* recv() wait for the kernel's NLM_F_ACK reply */

struct nlbuf {
    uint8_t *base;    /* start of nlmsghdr */
    uint8_t *p;       /* next write position */
    uint8_t *end;     /* one past last writable byte */
};

static void nlbuf_init(struct nlbuf *b, void *mem, size_t cap) {
    b->base = mem; b->p = mem; b->end = (uint8_t *)mem + cap;
}

static struct nlattr *nlbuf_reserve(struct nlbuf *b, uint16_t type, size_t pay_len) {
    size_t aligned = (NLA_HDRLEN + pay_len + 3) & ~(size_t)3;
    if (b->p + aligned > b->end) return NULL;
    struct nlattr *a = (struct nlattr *)b->p;
    a->nla_len = (uint16_t)(NLA_HDRLEN + pay_len);
    a->nla_type = type;
    b->p += aligned;
    return a; /* caller writes payload into (a+1) immediately */
}
/* Scalar nf_tables attributes are BIG-ENDIAN on the wire: the kernel parses
 * NFTA_SET_ELEM_TIMEOUT with nla_get_be64(). Writing host order on a
 * little-endian box turned a 60000ms timeout into an astronomically large value,
 * and nf_msecs_to_jiffies64() rejected it with -ERANGE — which is exactly why
 * inserts into the timeout-flagged VPN/direct sets failed while the map (which
 * carries no timeout) succeeded. Confirmed on the test router: ack error=-34 for
 * the set, error=0 for the map, same code path otherwise. */
static void nlbuf_put_be32(struct nlbuf *b, uint16_t type, uint32_t v) {
    struct nlattr *a = nlbuf_reserve(b, type, 4);
    if (!a) return;
    uint32_t be = htonl(v);
    memcpy(a + 1, &be, 4);
}

static void nlbuf_put_be64(struct nlbuf *b, uint16_t type, uint64_t v) {
    struct nlattr *a = nlbuf_reserve(b, type, 8);
    if (!a) return;
    uint8_t be[8];
    for (int i = 0; i < 8; i++) be[i] = (uint8_t)(v >> (56 - 8 * i));
    memcpy(a + 1, be, 8);
}
static void nlbuf_put_str(struct nlbuf *b, uint16_t type, const char *s) {
    size_t n = strlen(s) + 1;
    struct nlattr *a = nlbuf_reserve(b, type, n);
    if (a) memcpy(a + 1, s, n);
}
/* Fixed binary blob (e.g. a 4-byte IPv4 key). */
static void nlbuf_put_data(struct nlbuf *b, uint16_t type, const void *d, size_t n) {
    struct nlattr *a = nlbuf_reserve(b, type, n);
    if (a) memcpy(a + 1, d, n);
}
/* Begin a nested attribute; returns an opaque cookie (the nlattr*) to pass to
 * nlbuf_end_nested(), which backpatches nla_len with the filled size. */
static struct nlattr *nlbuf_begin_nested(struct nlbuf *b, uint16_t type) {
    struct nlattr *a = nlbuf_reserve(b, type | NLA_F_NESTED, 0);
    return a; /* nla_len currently == NLA_HDRLEN; end_nested fixes it */
}
static void nlbuf_end_nested(struct nlbuf *b, struct nlattr *outer) {
    outer->nla_len = (uint16_t)((b->p) - (uint8_t *)outer);
}

/* ---- netlink socket --------------------------------------------------- */
static int g_nlk_fd = -1;
/* Monotonic request sequence. Also used to match the kernel's ack to the request
 * that caused it: a stale ack left in the socket buffer by a timed-out earlier
 * transaction would otherwise be read as this one's result. */
static uint32_t g_nlk_seq = 0;

/* nf_tables mutations are TRANSACTIONAL: the kernel registers only batch
 * handlers for this subsystem, so a standalone NFT_MSG_NEWSETELEM is rejected
 * outright. Verified against a live 6.x kernel on the test router:
 *
 *   standalone NFT_MSG_NEWSETELEM        -> ack error=-22 (EINVAL), no element
 *   same message inside BATCH_BEGIN/END  -> ack error=0, element present
 *
 * That is why this file's first netlink version silently added nothing: every
 * insert failed and the daemon fell back to relaying the real answer, so the
 * fake-IP map stayed empty and domain routing never took effect.
 *
 * Builds one NFNL_MSG_BATCH_BEGIN or _END message into `out`; res_id carries the
 * subsystem the transaction belongs to. */
static size_t nftlk_build_batch(uint8_t *out, uint32_t seq, int begin) {
    struct nlmsghdr *nh = (struct nlmsghdr *)out;
    struct nfgenmsg *ng = (struct nfgenmsg *)(out + NLMSG_ALIGN(sizeof(*nh)));
    size_t len = NLMSG_ALIGN(sizeof(*nh)) + NLMSG_ALIGN(sizeof(*ng));
    memset(out, 0, len);
    nh->nlmsg_len   = (uint32_t)len;
    nh->nlmsg_type  = begin ? NFNL_MSG_BATCH_BEGIN : NFNL_MSG_BATCH_END;
    nh->nlmsg_flags = NLM_F_REQUEST;
    nh->nlmsg_seq   = seq;
    ng->nfgen_family = AF_UNSPEC;
    ng->version      = NFNETLINK_V0;
    ng->res_id       = htons(NFNL_SUBSYS_NFTABLES);
    return len;
}

static int nftlk_open(void) {
    int fd = socket(AF_NETLINK, SOCK_RAW | SOCK_CLOEXEC, NETLINK_NETFILTER);
    if (fd < 0) return -1;
    struct sockaddr_nl sa = { .nl_family = AF_NETLINK };
    if (bind(fd, (struct sockaddr *)&sa, sizeof(sa)) != 0) { close(fd); return -1; }
    int sndbuf = 1 << 16;
    setsockopt(fd, SOL_SOCKET, SO_SNDBUF, &sndbuf, sizeof(sndbuf));
    /* Hard recv timeout so a missing ack can never wedge the (single-threaded)
     * main loop: if the kernel hasn't replied within ACK_TIMEOUT_MS we treat
     * the transaction as failed and fail-open the DNS answer. */
    struct timeval tv = { .tv_sec = 0, .tv_usec = ACK_TIMEOUT_MS * 1000 };
    setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
    g_nlk_fd = fd;
    return 0;
}

/* Build & send one set-element message inside a transaction, then synchronously
 * drain the kernel's NLM_F_ACK reply. Returns 0 on a successful ack, -1 on any
 * failure (send error, timeout, error ack).
 *
 * A re-insert of an element that already exists returns -EEXIST — NOT 0, despite
 * what an earlier version of this comment claimed. Measured on the test router:
 * every repeat query for an already-mapped domain got `error=-17 (File exists)`
 * for the fake-IP map, the caller treated that as failure and fell back to
 * relaying the REAL address — so a domain was routed through the tunnel exactly
 * once and silently went direct from the second query onward. Callers must map
 * EEXIST onto "already in the desired state" (see nft_map_set_element), and an
 * element whose DATA must change has to be deleted first.
 *
 *   table      : "inet fw4" (family+table combined, like g_nft_table)
 *   obj_name   : the set or map name ("splify_vpn_v4", "splify_fakeip_map")
 *   key_host   : element KEY as 4 bytes in NETWORK order (inet_pton'd IPv4)
 *   data_host  : element DATA as 4 bytes, or NULL for a plain set (no mapping)
 *   timeout_ms : element timeout in ms (nft 'timeout'), or 0 for none
 */
static int nftlk_elem_msg(uint16_t nft_msg_type, const char *table,
                          const char *obj_name, const void *key_net,
                          int interval, const void *data_net,
                          uint64_t timeout_ms) {
    if (g_nlk_fd < 0) return -1;
    const char *fam_str, *tbl_str;
    nftlk_split_table(table, &fam_str, &tbl_str);

    /* Build the whole message in a stack buffer (no malloc in the hot path). */
    uint8_t buf[NFTLK_MSG_CAP];
    struct nlbuf b;
    nlbuf_init(&b, buf, sizeof(buf));

    /* Reserve the fixed headers up front, then fill attrs, then patch nlmsg_len. */
    struct nlmsghdr *nh = (struct nlmsghdr *)b.p;
    b.p += NLMSG_ALIGN(sizeof(*nh));
    struct nfgenmsg *nfg = (struct nfgenmsg *)b.p;
    b.p += NLMSG_ALIGN(sizeof(*nfg));

    /* NFTA_SET_ELEM_LIST: TABLE, SET, ELEMENTS — attribute order matches the
     * libnftnl/nft wire format (TABLE before SET). The kernel resolves the
     * set/map by (family, table, name). SET_ID is omitted: it's only needed
     * when NEWSETELEM is part of a transaction that references the set by id,
     * and a standalone add-by-name is rejected (EINVAL) when SET_ID is present. */
    nlbuf_put_str(&b, NFTA_SET_ELEM_LIST_TABLE, tbl_str);
    nlbuf_put_str(&b, NFTA_SET_ELEM_LIST_SET, obj_name);

    struct nlattr *elems = nlbuf_begin_nested(&b, NFTA_SET_ELEM_LIST_ELEMENTS);
    struct nlattr *elem  = nlbuf_begin_nested(&b, NFTA_LIST_ELEM);

    /* KEY: nested nft_data { NFTA_DATA_VALUE = 4 bytes IPv4 }. */
    struct nlattr *key = nlbuf_begin_nested(&b, NFTA_SET_ELEM_KEY);
    nlbuf_put_data(&b, NFTA_DATA_VALUE, key_net, 4);
    nlbuf_end_nested(&b, key);

    /* DATA: present only for maps (fake->real). Omitted for plain sets. */
    if (data_net) {
        struct nlattr *d = nlbuf_begin_nested(&b, NFTA_SET_ELEM_DATA);
        nlbuf_put_data(&b, NFTA_DATA_VALUE, data_net, 4);
        nlbuf_end_nested(&b, d);
    }
    if (timeout_ms) nlbuf_put_be64(&b, NFTA_SET_ELEM_TIMEOUT, timeout_ms);

    nlbuf_end_nested(&b, elem);

    /* A set declared `flags interval` (which is how splify-apply declares the
     * VPN/direct sets — see emit_set) stores RANGE BOUNDARIES, not addresses: a
     * range is the start element plus an end marker carrying
     * NFT_SET_ELEM_INTERVAL_END. Sending only the start leaves the range open,
     * and the kernel then reports the element as
     * 198.18.0.0-255.255.255.255 — with `ip daddr @splify_vpn_v4` marking
     * traffic into the tunnel, ONE resolved domain diverted every address above
     * the fake IP into the VPN. That is the "one request and the router is dead"
     * symptom, reproduced in the lab.
     *
     * This is exactly what nft itself emits for `add element … { 1.2.3.4 }` on an
     * interval set (verified with nft --debug=netlink on the same kernel):
     *   element 1.2.3.4 flags=0   +   element 1.2.3.5 flags=INTERVAL_END
     * i.e. the end boundary is key+1, exclusive. Both boundaries go in the same
     * message so the pair is applied atomically.
     *
     * KEY_END (the newer single-element form) was tried first and the kernel
     * rejected it with -EINVAL here, so this uses the representation nft uses. */
    if (interval) {
        uint32_t end_host = ntohl(*(const uint32_t *)key_net);
        if (end_host != 0xFFFFFFFFu) {          /* no successor to 255.255.255.255 */
            uint32_t end_net = htonl(end_host + 1);
            struct nlattr *e2 = nlbuf_begin_nested(&b, NFTA_LIST_ELEM);
            struct nlattr *k2 = nlbuf_begin_nested(&b, NFTA_SET_ELEM_KEY);
            nlbuf_put_data(&b, NFTA_DATA_VALUE, &end_net, 4);
            nlbuf_end_nested(&b, k2);
            nlbuf_put_be32(&b, NFTA_SET_ELEM_FLAGS, NFT_SET_ELEM_INTERVAL_END);
            /* NO timeout on the end marker. Probed against a live kernel with
             * every plausible encoding (see the lab probe):
             *   start only, no marker              -> accepted, but stores
             *                                         198.18.9.0-255.255.255.255
             *   start + marker, timeout on BOTH    -> -EINVAL
             *   start + marker, timeout on start   -> accepted, stores 198.18.9.0
             *   single element with KEY_END        -> -EINVAL
             * The kernel drops the whole range when the start element expires, so
             * the marker needs no timeout of its own. */
            nlbuf_end_nested(&b, e2);
        }
    }

    nlbuf_end_nested(&b, elems);

    /* Backfill the fixed headers now that total length is known.
     *
     * NLM_F_CREATE matters: without it the kernel rejects an element that is not
     * already present, which is every element we ever add.
     *
     * The sequence number must be unique per request, not a timestamp: two
     * inserts within the same second would share a seq, and the ack matcher
     * below could then credit one transaction with the other's result. */
    nh->nlmsg_len   = (uint32_t)(b.p - buf);
    nh->nlmsg_type  = (uint16_t)((NFNL_SUBSYS_NFTABLES << 8) | nft_msg_type);
    /* NLM_F_CREATE only makes sense for an add; a delete must not carry it. */
    nh->nlmsg_flags = NLM_F_REQUEST | NLM_F_ACK
                    | (nft_msg_type == NFT_MSG_NEWSETELEM ? NLM_F_CREATE : 0);
    nh->nlmsg_seq   = (g_nlk_seq += 2);   /* leaves room for the batch-begin seq below */
    nh->nlmsg_pid   = 0;
    nfg->nfgen_family = nftlk_family(fam_str);
    nfg->version      = NFNETLINK_V0;
    nfg->res_id       = 0; /* res_id encodes the hw protocol family; 0 = any */

    if (getenv("SPLIFY_DNSD_DEBUG")) {
        fprintf(stderr, "nftlk: fam_str='%s' -> nfgen_family=%u, total=%u bytes, hex:",
                fam_str, nfg->nfgen_family, nh->nlmsg_len);
        for (uint32_t i = 0; i < nh->nlmsg_len; i++) {
            if (i % 16 == 0) fprintf(stderr, "\n  ");
            fprintf(stderr, "%02x ", buf[i]);
        }
        fprintf(stderr, "\n");
    }

    /* One transaction: BATCH_BEGIN + the element + BATCH_END, in a single
     * sendmsg so the kernel can never see a half-open transaction if we are
     * interrupted between writes. The begin/end messages carry no NLM_F_ACK, so
     * the only ack that comes back is the element's own. */
    uint8_t bbuf[64], ebuf[64];
    size_t blen = nftlk_build_batch(bbuf, nh->nlmsg_seq - 1, 1);
    size_t elen = nftlk_build_batch(ebuf, nh->nlmsg_seq + 1, 0);
    g_nlk_seq = nh->nlmsg_seq + 1;   /* keep the counter past the end message */

    struct sockaddr_nl dst = { .nl_family = AF_NETLINK };
    struct iovec iov[3] = { { bbuf, blen },
                            { buf, nh->nlmsg_len },
                            { ebuf, elen } };
    struct msghdr msg = { .msg_name = &dst, .msg_namelen = sizeof(dst),
                          .msg_iov = iov, .msg_iovlen = 3 };
    uint32_t want_seq = nh->nlmsg_seq;
    if (sendmsg(g_nlk_fd, &msg, 0) < 0) {
        if (getenv("SPLIFY_DNSD_DEBUG")) fprintf(stderr, "nftlk: sendmsg fail errno=%d\n", errno);
        return -1;
    }

    /* Drain until we see the ack for OUR request. The kernel replies with an
     * NLMSG_ERROR whose nlmsgerr::error is 0 on success or a negative errno on
     * failure; acks for other sequence numbers are leftovers from a transaction
     * that timed out earlier and must not be mistaken for this one's result. */
    uint8_t rbuf[256];
    for (;;) {
        ssize_t r = recv(g_nlk_fd, rbuf, sizeof(rbuf), 0);
        if (r < (ssize_t)NLMSG_HDRLEN) {
            if (getenv("SPLIFY_DNSD_DEBUG")) fprintf(stderr, "nftlk: ack recv short/timeout r=%zd errno=%d\n", r, errno);
            return -1; /* timeout / truncated */
        }
        struct nlmsghdr *rh = (struct nlmsghdr *)rbuf;
        if (rh->nlmsg_type == NLMSG_ERROR) {
            struct nlmsgerr *e = NLMSG_DATA(rh);
            if (rh->nlmsg_seq != want_seq) {
                if (getenv("SPLIFY_DNSD_DEBUG"))
                    fprintf(stderr, "nftlk: stale ack seq=%u (want %u), ignoring\n",
                            rh->nlmsg_seq, want_seq);
                continue;
            }
            if (e->error != 0 && getenv("SPLIFY_DNSD_DEBUG"))
                fprintf(stderr, "nftlk: kernel ack error=%d (%s) for %s/%s\n",
                        e->error, strerror(-e->error), tbl_str, obj_name);
            /* The kernel's errno is returned as-is (negative): EEXIST and ENOENT
             * are meaningful outcomes for the callers below, not plain failures. */
            return e->error;
        }
        if (rh->nlmsg_type == NLMSG_DONE) return 0;
        /* multipart / unrelated: keep draining until we see the ack */
    }
}

/* ---- typed wrappers (the call sites below use these) ------------------ */

/* Adds an IPv4 element to a timeout-flagged set (nft 'timeout'). ttl is in
 * seconds; clamped to [1, 86400] so a hostile/huge record TTL can never pin
 * an entry for longer than a day. */
static int nft_add_element(const char *set_name, uint32_t key_host, uint32_t ttl) {
    if (ttl < 1) ttl = 1;
    if (ttl > 86400) ttl = 86400;
    uint32_t key_net = htonl(key_host);
    int rc = nftlk_elem_msg(NFT_MSG_NEWSETELEM, g_nft_table, set_name,
                            &key_net, 1 /* interval set */, NULL,
                            (uint64_t)ttl * 1000);
    if (rc == -EINVAL)
        fprintf(stderr, "splify-dnsd: %s rejected an interval element (-EINVAL) — "
                        "is it declared without `flags interval`?\n", set_name);
    /* Already there = already in the desired state. (A refreshed timeout would be
     * nicer, but the element only has to outlive the client's cached answer, and
     * a re-resolve after expiry re-adds it.) */
    return (rc == 0 || rc == -EEXIST) ? 0 : -1;
}

/* Points a fake IP (key) at its real backend (data) in the DNAT map splify-apply
 * installs (`ip daddr 198.18.0.0/15 dnat ip to ip daddr map @<map_name>`). No
 * timeout: the fake IP is a stable, exclusive allocation for this domain, so the
 * mapping lives as long as the domain does.
 *
 * "Just add it again with the new value" does NOT work — nf_tables answers
 * -EEXIST and keeps the old data, which for a CDN-fronted domain means the DNAT
 * keeps pointing at a backend the domain has since moved off. So an existing key
 * whose value must change is deleted and re-added inside ONE transaction (the
 * pair is atomic: no packet can observe the fake IP without a mapping).
 *
 * `known_real` is what we believe is currently installed (0 = nothing), so the
 * common case — same backend as last time — costs one add that the kernel
 * answers EEXIST to, and the uncommon case costs a delete plus an add.
 * Both addrs are HOST order here. */
static int nft_map_set_element(const char *map_name, uint32_t fake_host,
                               uint32_t real_host, uint32_t known_real) {
    uint32_t k = htonl(fake_host), d = htonl(real_host);
    if (known_real != 0 && known_real != real_host) {
        /* Value must change: drop the stale mapping first. ENOENT is fine — it
         * means the kernel already lost it (e.g. an fw4 reload flushed the map),
         * which is exactly the state the add below wants. */
        int drc = nftlk_elem_msg(NFT_MSG_DELSETELEM, g_nft_table, map_name,
                                 &k, 0, NULL, 0);
        if (drc != 0 && drc != -ENOENT && getenv("SPLIFY_DNSD_DEBUG"))
            fprintf(stderr, "nftlk: map delete for update failed rc=%d\n", drc);
    }
    int rc = nftlk_elem_msg(NFT_MSG_NEWSETELEM, g_nft_table, map_name,
                            &k, 0 /* plain map, not interval */, &d, 0);
    if (rc == -EEXIST) {
        /* Present with the value we wanted (known_real told us so, or a restart
         * lost our bookkeeping and the kernel kept the mapping) — desired state. */
        return 0;
    }
    return rc == 0 ? 0 : -1;
}

/* ---------------------------------------------------------------------- */
/* fake-IP pool: one stable, exclusive synthetic IPv4 per matched domain    */
/* ---------------------------------------------------------------------- */
/* Real CDN-fronted IPs (Cloudflare etc.) are shared across many unrelated
 * customer domains from a dynamic anycast pool — there is no fixed 1:1
 * domain->IP mapping, so tagging the real resolved IP into a set (as
 * nft_add_element above does) is collision-prone: two configured domains
 * can end up sharing one real IP, and then whichever one's set entry is
 * freshest decides routing for BOTH. Handing the client a synthetic IP that
 * THIS daemon allocates and owns 1:1 per domain makes that collision
 * structurally impossible, and — since the decision is made from the DNS
 * question name, always visible in plaintext — sidesteps ECH entirely (no
 * TLS/SNI parsing needed at all). Pool: 198.18.0.0/15, the RFC 2544
 * benchmarking range, the same convention already used by Clash/sing-box/
 * mihomo for this exact purpose; effectively never a real destination. */
#define FAKEIP_POOL_BASE 0xC6120000u /* 198.18.0.0 */
#define FAKEIP_POOL_SIZE 131072u     /* 198.18.0.0 - 198.19.255.255 */

struct fakeip_entry {
    char *domain; /* lowercased, matches the ruleset's own lowercasing */
    uint32_t addr;      /* host byte order */
    uint32_t real_host; /* last-seen real backend, host order; 0 if unknown */
};

struct fakeip_table {
    struct fakeip_entry *entries;
    size_t n, cap;
};

static struct fakeip_table g_fakeip;
static const char *g_fakeip_state_path;

static uint32_t fakeip_index_to_addr(size_t idx) { return FAKEIP_POOL_BASE + (uint32_t)idx; }

/* Next pool index to hand out — a HIGH-WATER MARK, not the entry count.
 *
 * Deriving the index from t->n only works while the file is a dense 0..n-1
 * prefix, and it is not: the --fakeip CLI appends an entry it just looked up, so
 * a duplicate line is normal, and a skipped (malformed) line leaves a hole. With
 * a count-based index, `a -> .3` alone in the file makes the fourth new domain
 * allocate .3 as well — two domains on ONE fake IP, whose DNAT entry then points
 * at whichever was inserted last, i.e. one of them silently reaches the other's
 * site. */
static size_t g_fakeip_next;

static int fakeip_table_add(struct fakeip_table *t, const char *domain, uint32_t addr) {
    if (t->n == t->cap) {
        size_t newcap = t->cap ? t->cap * 2 : 64;
        struct fakeip_entry *ne = realloc(t->entries, newcap * sizeof(*ne));
        if (!ne) return -1;
        t->entries = ne;
        t->cap = newcap;
    }
    t->entries[t->n].domain = strdup(domain);
    if (!t->entries[t->n].domain) return -1;
    t->entries[t->n].addr = addr;
    t->entries[t->n].real_host = 0;
    t->n++;
    if (addr >= FAKEIP_POOL_BASE) {
        size_t idx = (size_t)(addr - FAKEIP_POOL_BASE);
        if (idx + 1 > g_fakeip_next) g_fakeip_next = idx + 1;
    }
    return 0;
}

/* 0 iff DOMAIN already has an allocation. */
static int fakeip_table_has(const struct fakeip_table *t, const char *domain) {
    for (size_t i = 0; i < t->n; i++)
        if (strcmp(t->entries[i].domain, domain) == 0) return 0;
    return -1;
}

/* State file format: one entry per line.
 *   domain\tfake_ip            (legacy / --fakeip CLI output)
 *   domain\tfake_ip\treal_ip   (extended: real backend, for post-restart rehydrate)
 * Missing file -> empty table, not an error (first run). A malformed line is
 * skipped, not fatal — the domain simply gets re-allocated (a fresh index) on
 * the next match. The legacy 2-field form is parsed identically to before, so
 * an existing state file upgrades transparently. */
static void fakeip_state_load(const char *path) {
    FILE *f = fopen(path, "r");
    if (!f) return;
    char line[MAX_HOSTNAME + 64];
    while (fgets(line, sizeof(line), f)) {
        char *nl = strchr(line, '\n'); if (nl) *nl = '\0';
        char *tab1 = strchr(line, '\t');
        if (!tab1) continue;
        *tab1 = '\0';
        /* Terminate the fake-IP field BEFORE parsing it. inet_aton() rejects a
         * string with anything after the address, so reading the 3-field form
         * without cutting at the second tab fed it "198.18.0.0\t104.20.39.144"
         * and skipped the line — and since the daemon REWRITES the file in the
         * 3-field form as soon as a domain's real backend is known, that made
         * every restart lose the whole table. Consequences, in order of how much
         * they hurt: fake IPs are handed out again from the start of the pool, so
         * an address a client still has cached now DNATs to a DIFFERENT site's
         * backend; the rehydrate pass below never had anything to rehydrate; and
         * the first query per domain after a restart relays the real answer. */
        char *fake_s = tab1 + 1;
        char *tab2 = strchr(fake_s, '\t');
        if (tab2) *tab2 = '\0';
        struct in_addr a;
        if (inet_aton(fake_s, &a) == 0) continue;
        /* Keep the FIRST allocation for a domain: a duplicate line is expected
         * (the --fakeip CLI appends what it looked up), and adding it twice would
         * both bloat the table and, before the high-water mark above, corrupt the
         * next index. */
        if (fakeip_table_has(&g_fakeip, line) == 0) continue;
        if (fakeip_table_add(&g_fakeip, line, ntohl(a.s_addr)) != 0) continue;

        if (tab2) { /* optional third field: last-seen real backend */
            struct in_addr r;
            if (inet_aton(tab2 + 1, &r) != 0)
                g_fakeip.entries[g_fakeip.n - 1].real_host = ntohl(r.s_addr);
        }
    }
    fclose(f);
}

static void fakeip_state_append(const char *path, const char *domain, uint32_t addr) {
    FILE *f = fopen(path, "a");
    if (!f) return;
    struct in_addr a; a.s_addr = htonl(addr);
    char ipstr[INET_ADDRSTRLEN];
    if (inet_ntop(AF_INET, &a, ipstr, sizeof(ipstr)))
        fprintf(f, "%s\t%s\n", domain, ipstr);
    fclose(f);
}

/* Rewrites the whole state file from g_fakeip in the extended 3-field format.
 * Called after we learn a fresh real_ip for an already-allocated domain, so
 * the next restart can rehydrate the DNAT map without re-resolving. Best-effort
 * (atomic via rename); a failure just means a later restart re-resolves. */
static void fakeip_state_rewrite(void) {
    if (!g_fakeip_state_path) return;
    char tmp[MAX_HOSTNAME];
    snprintf(tmp, sizeof(tmp), "%s.tmp", g_fakeip_state_path);
    FILE *f = fopen(tmp, "w");
    if (!f) return;
    for (size_t i = 0; i < g_fakeip.n; i++) {
        struct in_addr fa; fa.s_addr = htonl(g_fakeip.entries[i].addr);
        char fstr[INET_ADDRSTRLEN];
        if (!inet_ntop(AF_INET, &fa, fstr, sizeof(fstr))) continue;
        if (g_fakeip.entries[i].real_host) {
            struct in_addr ra; ra.s_addr = htonl(g_fakeip.entries[i].real_host);
            char rstr[INET_ADDRSTRLEN];
            if (inet_ntop(AF_INET, &ra, rstr, sizeof(rstr)))
                fprintf(f, "%s\t%s\t%s\n", g_fakeip.entries[i].domain, fstr, rstr);
            else
                fprintf(f, "%s\t%s\n", g_fakeip.entries[i].domain, fstr);
        } else {
            fprintf(f, "%s\t%s\n", g_fakeip.entries[i].domain, fstr);
        }
    }
    fflush(f);
    if (rename(tmp, g_fakeip_state_path) != 0) {
        unlink(tmp);
    }
    fclose(f);
}

/* Looks up domain's existing fake IP, or allocates the next free one and
 * persists it. Returns 0 and fills *out_addr (host order) on success; -1 if
 * the pool is exhausted (caller falls back to relaying the real answer
 * unchanged — fail open, never block DNS over an exhausted pool). */
static int fakeip_lookup_or_alloc(const char *domain, uint32_t *out_addr) {
    for (size_t i = 0; i < g_fakeip.n; i++) {
        if (strcmp(g_fakeip.entries[i].domain, domain) == 0) {
            *out_addr = g_fakeip.entries[i].addr;
            return 0;
        }
    }
    if (g_fakeip_next >= FAKEIP_POOL_SIZE) return -1;
    uint32_t addr = fakeip_index_to_addr(g_fakeip_next);
    if (fakeip_table_add(&g_fakeip, domain, addr) != 0) return -1;
    if (g_fakeip_state_path) fakeip_state_append(g_fakeip_state_path, domain, addr);
    *out_addr = addr;
    return 0;
}

/* Records the last-seen real backend for an allocated domain. Called after a
 * successful DNAT-map insert so the mapping can survive a restart via the
 * rehydrate pass (run_proxy's startup). Triggers a one-shot state rewrite so
 * the extended 3-field form persists. */
/* The real backend we last installed for this domain, or 0 if we never did. */
static uint32_t fakeip_entry_get_real(const char *domain) {
    for (size_t i = 0; i < g_fakeip.n; i++)
        if (strcmp(g_fakeip.entries[i].domain, domain) == 0)
            return g_fakeip.entries[i].real_host;
    return 0;
}

static void fakeip_entry_set_real(const char *domain, uint32_t real_host) {
    for (size_t i = 0; i < g_fakeip.n; i++) {
        if (strcmp(g_fakeip.entries[i].domain, domain) == 0) {
            if (g_fakeip.entries[i].real_host != real_host) {
                g_fakeip.entries[i].real_host = real_host;
                fakeip_state_rewrite();
            }
            return;
        }
    }
}

/* ---------------------------------------------------------------------- */
/* proxy state                                                           */
/* ---------------------------------------------------------------------- */

/* sockaddr_storage, not sockaddr_in: the listen socket is dual-stack, so a
 * client can be IPv6. See run_proxy's socket setup for why that matters. */
struct pending {
    int fd;
    int in_use;
    struct sockaddr_storage client;
    socklen_t client_len;
    time_t expire;
};

static struct pending g_pending[MAX_PENDING];
static int g_epfd = -1;
static int g_listen_fd = -1;
/* One entry per channel that matches domains, in SPEC ORDER. */
struct dchan {
    char set[64];               /* the nft set the compiler generated for it */
    const char *rules_path;     /* the channel's domains_file */
    struct ruleset rules;
    int realip;                 /* put the real answers in the set, do not fake */
};
static struct dchan g_dch[MAX_CHANNELS];
static size_t g_dch_n;
static const char *g_fakeip_map = "fakeip";
static volatile int g_reload_pending = 0;
static volatile int g_running = 1;

static void on_sighup(int sig) { (void)sig; g_reload_pending = 1; }
static void on_sigterm(int sig) { (void)sig; g_running = 0; }

static void reload_rules(void) {
    for (size_t i = 0; i < g_dch_n; i++)
        if (g_dch[i].rules_path) load_rules(g_dch[i].rules_path, &g_dch[i].rules);
    for (size_t i = 0; i < g_dch_n; i++)
        fprintf(stderr, "steer dnsd: channel %s: %zu rule(s)\n",
                g_dch[i].set, g_dch[i].rules.n);
}

static struct pending *pending_alloc(void) {
    time_t now = time(NULL);
    for (int i = 0; i < MAX_PENDING; i++) {
        if (g_pending[i].in_use && g_pending[i].expire < now) {
            epoll_ctl(g_epfd, EPOLL_CTL_DEL, g_pending[i].fd, NULL);
            close(g_pending[i].fd);
            g_pending[i].in_use = 0;
        }
    }
    for (int i = 0; i < MAX_PENDING; i++)
        if (!g_pending[i].in_use) return &g_pending[i];
    return NULL;
}

static void handle_client_query(int upstream_port) {
    uint8_t buf[MAX_PKT];
    /* Dual-stack listener -> the client may be IPv6 (or v4-mapped). The reply is
     * sent back to exactly these bytes, so the family never has to be inspected. */
    struct sockaddr_storage from;
    socklen_t fromlen = sizeof(from);
    ssize_t n = recvfrom(g_listen_fd, buf, sizeof(buf), 0, (struct sockaddr *)&from, &fromlen);
    if (n <= 0) return;

    struct pending *p = pending_alloc();
    if (!p) return; /* under load: drop, client's own resolver will retry/timeout */

    int fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (fd < 0) return;
    struct sockaddr_in up = {0};
    up.sin_family = AF_INET;
    up.sin_port = htons((uint16_t)upstream_port);
    up.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    if (connect(fd, (struct sockaddr *)&up, sizeof(up)) != 0) { close(fd); return; }
    if (send(fd, buf, (size_t)n, 0) < 0) { close(fd); return; }

    p->fd = fd;
    p->in_use = 1;
    p->client = from;
    p->client_len = fromlen;
    p->expire = time(NULL) + PENDING_TTL_SEC;

    struct epoll_event ev = {0};
    ev.events = EPOLLIN;
    ev.data.ptr = p;
    epoll_ctl(g_epfd, EPOLL_CTL_ADD, fd, &ev);
}

/* FAKEIP_ANSWER_TTL is independent of the real record's TTL — the fake IP
 * itself never needs to expire from the client's cache the way a real
 * record does (it's a stable, persistent allocation); this just needs to be
 * short enough that the client re-queries periodically, e.g. after a NAT-map
 * refresh. */
#define FAKEIP_ANSWER_TTL 60

/* Builds a reply reusing the original response's header+question bytes
 * verbatim ([0, qend) — same transaction ID, same echoed question), with
 * ancount/nscount/arcount patched and (if with_answer) exactly one A record
 * appended pointing at fake_addr_host. nscount/arcount are always zeroed:
 * dropping any authority/additional section (e.g. an upstream EDNS OPT
 * record) is fine, our substitute answer is tiny and needs neither. Returns
 * the built length, or 0 if it wouldn't fit (defensive only — qend is
 * bounded by MAX_HOSTNAME and the answer is a fixed 16 bytes, so this never
 * actually happens with out_cap sized as callers use it below). */
static size_t build_rewritten_response(const uint8_t *orig, size_t qend,
                                        uint8_t *out, size_t out_cap,
                                        int with_answer, uint32_t fake_addr_host) {
    if (qend > out_cap) return 0;
    memcpy(out, orig, qend);
    out[6] = 0; out[7] = with_answer ? 1 : 0;               /* ancount */
    out[8] = 0; out[9] = 0; out[10] = 0; out[11] = 0;       /* nscount, arcount */

    size_t pos = qend;
    if (with_answer) {
        if (pos + 16 > out_cap) return 0;
        out[pos++] = 0xC0; out[pos++] = 0x0C; /* name: pointer to question @ offset 12 */
        out[pos++] = 0x00; out[pos++] = 0x01; /* type A */
        out[pos++] = 0x00; out[pos++] = 0x01; /* class IN */
        out[pos++] = 0x00; out[pos++] = 0x00;
        out[pos++] = 0x00; out[pos++] = FAKEIP_ANSWER_TTL;  /* ttl (fits in one byte) */
        out[pos++] = 0x00; out[pos++] = 0x04;               /* rdlength */
        uint32_t addr_net = htonl(fake_addr_host);
        memcpy(out + pos, &addr_net, 4);
        pos += 4;
    }
    return pos;
}

static void handle_upstream_response(struct pending *p) {
    uint8_t buf[MAX_PKT];
    ssize_t n = recv(p->fd, buf, sizeof(buf), 0);

    epoll_ctl(g_epfd, EPOLL_CTL_DEL, p->fd, NULL);
    close(p->fd);
    p->in_use = 0;

    if (n <= 0) return;

    char qname[MAX_HOSTNAME];
    uint16_t qtype = 0;
    size_t qend = 0;
    struct answer_ip ips[32];
    int nips = parse_response(buf, (size_t)n, qname, sizeof(qname), &qtype, &qend, ips, 32);

    /* Unparseable (malformed, or the rare qdcount != 1) or no rule match:
     * relay the real answer unchanged, exactly as before this feature. */
    /* First match wins, exactly like the generated chain: a domain listed twice
     * belongs to the channel written first, and the fake IP goes into THAT set
     * only. Putting it in several sets would leave the winner to chain order. */
    int hit = -1;
    if (nips >= 0)
        for (size_t i = 0; i < g_dch_n && hit < 0; i++)
            if (ruleset_match(&g_dch[i].rules, qname)) hit = (int)i;
    if (nips < 0 || hit < 0) {
        sendto(g_listen_fd, buf, (size_t)n, 0, (struct sockaddr *)&p->client, p->client_len);
        return;
    }

    /* Matched a rule. AAAA is suppressed outright (NODATA) rather than
     * relayed: splify has no IPv6 routing at all (VPN_SET/DIRECT_SET are
     * IPv4-only, same as the rest of the project), so letting a real AAAA
     * answer through would hand a dual-stack client a real, completely
     * unmanaged address that bypasses the split entirely — and Happy-
     * Eyeballs-style clients commonly PREFER IPv6 when it's offered. */
    if (qtype == DNS_TYPE_AAAA) {
        uint8_t out[512];
        size_t len = build_rewritten_response(buf, qend, out, sizeof(out), 0, 0);
        sendto(g_listen_fd, len ? out : buf, len ? len : (size_t)n, 0,
               (struct sockaddr *)&p->client, p->client_len);
        return;
    }

    /* real-IP mode: the answer goes to the client untouched and every address in it
     * joins the channel's set with its own TTL. No DNAT is involved, so ICMP errors
     * are not rewritten and a traceroute shows the actual hops — which is the whole
     * reason this mode exists. The cost is precision: two domains behind one address
     * become one entry, and if they belong to different channels the first one to be
     * resolved decides for both. */
    if (g_dch[hit].realip) {
        if (qtype == DNS_TYPE_A)
            for (int k = 0; k < nips; k++)
                nft_add_element(g_dch[hit].set, ntohl(ips[k].addr), ips[k].ttl);
        sendto(g_listen_fd, buf, (size_t)n, 0, (struct sockaddr *)&p->client, p->client_len);
        return;
    }

    if (qtype == DNS_TYPE_A && nips > 0) {
        uint32_t fake_addr;
        if (fakeip_lookup_or_alloc(qname, &fake_addr) == 0) {
            uint32_t real_host = ntohl(ips[0].addr);
            if (getenv("SPLIFY_DNSD_DEBUG"))
                fprintf(stderr, "nftlk-debug: matched qname=%s qtype=%u nips=%d fake=0x%08x real=0x%08x nlk_fd=%d\n",
                        qname, qtype, nips, fake_addr, real_host, g_nlk_fd);
            /* DNAT map FIRST, synchronously, and ONLY hand the client the fake
             * IP once the kernel has acked the fake->real mapping. This is the
             * fix for the "locks up the router" symptom: previously the fake IP
             * was returned immediately while the (fork/exec'd, OOM-prone) map
             * add raced asynchronously and usually lost, leaving clients with a
             * fake IP whose DNAT entry never landed — a SYN into the tunnel to
             * nowhere, hanging on TCP retries for minutes. Now a failed/missing
             * ack makes us relay the REAL answer instead (fail-open). */
            int maprc = nft_map_set_element(g_fakeip_map, fake_addr, real_host,
                                            fakeip_entry_get_real(qname));
            if (getenv("SPLIFY_DNSD_DEBUG"))
                fprintf(stderr, "nftlk-debug: nft_map_set_element -> %d\n", maprc);
            if (maprc == 0) {
                /* Record the real backend so a post-restart rehydrate can rebuild
                 * the DNAT map from state without re-resolving every domain. */
                fakeip_entry_set_real(qname, real_host);

                /* Routing set is best-effort and not correctness-critical: a
                 * missing entry just means default policy applies (fine). Fire
                 * after the reply — the netlink send itself is sub-ms. */
                /* A domain in the geo list goes ONLY into the geo set: it names a
                 * specific interface, and adding the same fake IP to the VPN set
                 * as well would leave which mark wins to chain order. */
                nft_add_element(g_dch[hit].set, fake_addr, ips[0].ttl);

                uint8_t out[512];
                size_t len = build_rewritten_response(buf, qend, out, sizeof(out), 1, fake_addr);
                if (len > 0) {
                    sendto(g_listen_fd, out, len, 0, (struct sockaddr *)&p->client, p->client_len);
                    return;
                }
            }
        }
    }

    /* Fallback: matched but nothing to substitute (qtype other than A/AAAA
     * — e.g. HTTPS/SVCB — zero real A answers yet, or the fake-IP pool is
     * exhausted). Relay the real answer unchanged — fail open, never block
     * the DNS transaction. */
    sendto(g_listen_fd, buf, (size_t)n, 0, (struct sockaddr *)&p->client, p->client_len);
}

static int run_proxy(int listen_port, int upstream_port) {
    /* Dual-stack on ONE socket (AF_INET6 with IPV6_V6ONLY off), because an
     * IPv4-only listener silently loses most of the LAN's DNS.
     *
     * OpenWrt advertises the router as an IPv6 resolver by default (odhcpd RA +
     * DHCPv6), and Windows/Android/iOS then prefer the IPv6 server. Measured on a
     * real client: 15 of its DNS packets went to the router over IPv6 against 20
     * over IPv4, and `nslookup claude.ai` answered with the REAL address via
     * fdd6:...::1 while the same query forced to 192.168.1.1 answered 198.18.0.5.
     * Both stacks get asked and the first reply wins, so the unproxied one wins
     * essentially always — domain routing appeared to do nothing at all.
     *
     * MUST bind the wildcard address, not loopback: nft's `redirect` DNATs the
     * destination to the box's own address on the inbound (LAN) interface, not to
     * 127.0.0.1 — only LAN-sourced traffic ever reaches this port because
     * splify-apply scopes the redirect rule to the LAN.
     *
     * Falls back to AF_INET if the kernel has no IPv6 at all, so a build for a
     * v4-only box keeps working exactly as before. */
    int reuse = 1;
    g_listen_fd = socket(AF_INET6, SOCK_DGRAM, 0);
    if (g_listen_fd >= 0) {
        int v6only = 0;
        setsockopt(g_listen_fd, SOL_SOCKET, SO_REUSEADDR, &reuse, sizeof(reuse));
        if (setsockopt(g_listen_fd, IPPROTO_IPV6, IPV6_V6ONLY, &v6only, sizeof(v6only)) != 0) {
            /* Can't serve IPv4 through it -> a v4 client would break. Drop back. */
            close(g_listen_fd);
            g_listen_fd = -1;
        } else {
            struct sockaddr_in6 a6 = {0};
            a6.sin6_family = AF_INET6;
            a6.sin6_port = htons((uint16_t)listen_port);
            a6.sin6_addr = in6addr_any;
            if (bind(g_listen_fd, (struct sockaddr *)&a6, sizeof(a6)) != 0) {
                close(g_listen_fd);
                g_listen_fd = -1;
            }
        }
    }
    if (g_listen_fd < 0) {
        g_listen_fd = socket(AF_INET, SOCK_DGRAM, 0);
        if (g_listen_fd < 0) { perror("socket"); return 1; }
        setsockopt(g_listen_fd, SOL_SOCKET, SO_REUSEADDR, &reuse, sizeof(reuse));
        struct sockaddr_in addr = {0};
        addr.sin_family = AF_INET;
        addr.sin_port = htons((uint16_t)listen_port);
        addr.sin_addr.s_addr = htonl(INADDR_ANY);
        if (bind(g_listen_fd, (struct sockaddr *)&addr, sizeof(addr)) != 0) {
            perror("bind");
            return 1;
        }
        fprintf(stderr, "splify-dnsd: no IPv6 on this kernel — listening on IPv4 only\n");
    }

    g_epfd = epoll_create1(0);
    if (g_epfd < 0) { perror("epoll_create1"); return 1; }
    struct epoll_event ev = {0};
    ev.events = EPOLLIN;
    ev.data.ptr = NULL; /* NULL marks the listen socket */
    epoll_ctl(g_epfd, EPOLL_CTL_ADD, g_listen_fd, &ev);

    signal(SIGHUP, on_sighup);
    signal(SIGTERM, on_sigterm);
    signal(SIGINT, on_sigterm);
    signal(SIGPIPE, SIG_IGN);

    /* Open the long-lived nfnetlink socket BEFORE we load state, so the
     * rehydrate pass below can re-install the DNAT map synchronously. A
     * failure here is not fatal: we still proxy DNS, we just can't install
     * fake-IP mappings — every matched domain then relays its real answer
     * (fail-open), exactly as if the rules never matched. */
    int nk_open = nftlk_open();

    reload_rules();
    if (g_fakeip_state_path) fakeip_state_load(g_fakeip_state_path);

    /* Rehydrate the DNAT map after a (re)start. fw4 reload / a daemon restart
     * wipes the live splify_fakeip_map contents (the schema is reinstalled by
     * splify-apply, but the elements are gone). For every domain we already
     * know a real backend for (from the extended 3-field state), re-insert
     * fake->real now, so clients don't have to re-resolve to un-wedge an
     * existing fake IP. Best-effort: a failed insert just leaves that domain
     * to be re-resolved on demand. */
    size_t restored = 0;
    if (nk_open == 0) {
        for (size_t i = 0; i < g_fakeip.n; i++) {
            /* known_real = 0: after a restart the kernel map is empty as far as we
             * know, so this is a plain add (and an EEXIST just means the map
             * survived, which is equally fine). */
            if (g_fakeip.entries[i].real_host &&
                nft_map_set_element(g_fakeip_map, g_fakeip.entries[i].addr,
                                     g_fakeip.entries[i].real_host, 0) == 0)
                restored++;
        }
    }
    fprintf(stderr, "splify-dnsd: listening on :%d -> upstream 127.0.0.1:%d "
            "(netlink:%s fakeip:%zu loaded, %zu map rehydrated)\n",
            listen_port, upstream_port, nk_open == 0 ? "ok" : "FAILED",
            g_fakeip.n, restored);

    struct epoll_event events[32];
    while (g_running) {
        if (g_reload_pending) { g_reload_pending = 0; reload_rules(); }
        int n = epoll_wait(g_epfd, events, 32, 1000);
        if (n < 0) {
            if (errno == EINTR) continue;
            break;
        }
        for (int i = 0; i < n; i++) {
            if (events[i].data.ptr == NULL)
                handle_client_query(upstream_port);
            else
                handle_upstream_response((struct pending *)events[i].data.ptr);
        }
    }

    if (g_nlk_fd >= 0) close(g_nlk_fd);
    close(g_listen_fd);
    close(g_epfd);
    for (size_t i = 0; i < g_dch_n; i++) ruleset_free(&g_dch[i].rules);
    return 0;
}

/* ---------------------------------------------------------------------- */
/* CLI                                                                    */
/* ---------------------------------------------------------------------- */

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

static void dnsd_usage(void) {
    fprintf(stderr,
        "usage: steer dnsd [--spec FILE] [--listen-port P] [--upstream-port P]\n"
        "                  [--fakeip-state PATH]\n"
        "       steer dnsd --selftest\n"
        "       steer dnsd --match RULES_PATH HOSTNAME\n"
        "       steer dnsd --fakeip STATE_PATH DOMAIN\n");
}

int dnsd_main(int argc, char **argv) {
    int listen_port = 5300;
    int upstream_port = 53;
    const char *spec = "/etc/steer/spec.json";

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
        } else if (strcmp(argv[i], "--fakeip-state") == 0 && i + 1 < argc) {
            g_fakeip_state_path = argv[++i];
        } else {
            dnsd_usage();
            return 2;
        }
    }

    /* Channels come from the spec, in spec order — the same file and the same
     * parser the compiler used, so the sets named here are exactly the sets it
     * generated. */
    load_spec(spec);
    for (size_t i = 0; i < g_ch_n && g_dch_n < MAX_CHANNELS; i++) {
        if (!g_ch[i].domains_file[0]) continue;
        snprintf(g_dch[g_dch_n].set, sizeof(g_dch[g_dch_n].set), "ch_%.31s", g_ch[i].name);
        g_dch[g_dch_n].rules_path = g_ch[i].domains_file;
        g_dch[g_dch_n].realip = g_ch[i].realip;
        g_dch_n++;
    }
    if (!g_dch_n) {
        fprintf(stderr, "steer dnsd: no channel in %s matches domains — nothing to do\n", spec);
        return 0;
    }
    if (!g_fakeip_state_path) {
        static char st[256];
        snprintf(st, sizeof(st), "%s/fakeip.state", g_state_dir);
        g_fakeip_state_path = st;
    }
    return run_proxy(listen_port, upstream_port);
}
