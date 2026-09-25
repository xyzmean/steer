#include "nftnl.h"
#include <arpa/inet.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <unistd.h>

/* SPLIFY_DNSD_DEBUG решается один раз: getenv — линейный проход по environ с
 * strncmp на каждую переменную, а спрашивали его до восьми раз на один
 * запрос — только чтобы решить «не печатать». Окружение демона после старта
 * не меняется, так что кэшировать ответ безопасно. */
static int g_debug = -1;
int dbg(void) {
    if (g_debug < 0) g_debug = getenv("SPLIFY_DNSD_DEBUG") != NULL;
    return g_debug;
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
const char *g_nft_table = "inet steer"; /* "<family> <table>" */
/* Где лежит карта fakeip. В современной раскладке — там же, где наборы каналов; в старой
 * (ядро 4.9, см. nft_compat в spec.h) — в таблице ip, рядом с единственной цепочкой nat,
 * потому что наборы между таблицами не видны, а nat в inet на таком ядре нет вовсе. */
const char *g_nft_map_table = "inet steer";
/* Интервальные ли наборы каналов. В старой раскладке доменный набор — hash со сроками
 * (интервальный набор со сроками ядро 4.9 не умеет), и элемент туда идёт ОДИН, без пары
 * «начало + конец диапазона»: конец с флагом INTERVAL_END hash-набор отверг бы. */
int g_nft_sets_interval = 1;

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
/* Сравнивается ПЕРВОЕ СЛОВО, а не строка целиком: nftlk_split_table отдаёт семейство
 * указателем на начало «ip steer», без обрезки, и strcmp с "ip" там не совпадал никогда —
 * любое семейство молча становилось inet. Пока все наши объекты жили в inet, этого не было
 * видно; карта fakeip в таблице ip (старая раскладка, см. nft_compat) получала ENOENT. */
static uint8_t nftlk_family(const char *fam) {
    if (!fam) return SPL_NFPROTO_INET;
    size_t n = strcspn(fam, " ");
    static const struct { const char *name; uint8_t proto; } FAM[] = {
        { "inet", SPL_NFPROTO_INET }, { "ip", SPL_NFPROTO_IPV4 }, { "ip6", SPL_NFPROTO_IPV6 },
        { "arp", SPL_NFPROTO_ARP }, { "bridge", SPL_NFPROTO_BRIDGE },
        { "netdev", SPL_NFPROTO_NETDEV },
    };
    for (size_t i = 0; i < sizeof(FAM) / sizeof(FAM[0]); i++)
        if (strlen(FAM[i].name) == n && !strncmp(fam, FAM[i].name, n)) return FAM[i].proto;
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
#define ACK_TIMEOUT_MS    100   /* recv() wait for the kernel's NLM_F_ACK reply */

/* ---- netlink socket --------------------------------------------------- */
int g_nlk_fd = -1;
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

int nftlk_open(void) {
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

/* Build one set-element message (NFT_MSG_NEWSETELEM / DELSETELEM) into `buf`
 * with sequence number `seq`; returns its length. Sending is nftlk_txn's job, so
 * several of these can go into ONE transaction (see nft_map_set_element).
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
static size_t nftlk_elem_build(uint8_t *buf, size_t cap, uint32_t seq,
                               uint16_t nft_msg_type, const char *table,
                               const char *obj_name, const void *key_net,
                               int interval, const void *data_net,
                               uint64_t timeout_ms) {
    const char *fam_str, *tbl_str;
    nftlk_split_table(table, &fam_str, &tbl_str);

    /* The caller's stack buffer (no malloc in the hot path). */
    struct nlbuf b;
    nlbuf_init(&b, buf, cap);

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
     * The sequence number comes from nftlk_seq_reserve: it is how nftlk_txn tells
     * this message's ack from its neighbours' and from stale ones. */
    nh->nlmsg_len   = (uint32_t)(b.p - buf);
    nh->nlmsg_type  = (uint16_t)((NFNL_SUBSYS_NFTABLES << 8) | nft_msg_type);
    /* NLM_F_CREATE only makes sense for an add; a delete must not carry it. */
    nh->nlmsg_flags = NLM_F_REQUEST | NLM_F_ACK
                    | (nft_msg_type == NFT_MSG_NEWSETELEM ? NLM_F_CREATE : 0);
    nh->nlmsg_seq   = seq;
    nh->nlmsg_pid   = 0;
    nfg->nfgen_family = nftlk_family(fam_str);
    nfg->version      = NFNETLINK_V0;
    nfg->res_id       = 0; /* res_id encodes the hw protocol family; 0 = any */

    if (dbg()) {
        fprintf(stderr, "nftlk: fam_str='%s' -> nfgen_family=%u, total=%u bytes, hex:",
                fam_str, nfg->nfgen_family, nh->nlmsg_len);
        for (uint32_t i = 0; i < nh->nlmsg_len; i++) {
            if (i % 16 == 0) fprintf(stderr, "\n  ");
            fprintf(stderr, "%02x ", buf[i]);
        }
        fprintf(stderr, "\n");
    }

    return nh->nlmsg_len;
}

/* One nf_tables TRANSACTION of `n` element messages: BATCH_BEGIN, the messages,
 * BATCH_END — in a single sendmsg, so the kernel can never see a half-open
 * transaction if we are interrupted between writes. The kernel applies the batch
 * all-or-nothing: if ANY message fails, every message in it is rolled back.
 *
 * Every element message carries NLM_F_ACK (begin/end do not), and the kernel
 * reports ALL of them once the whole batch has been processed — including a 0 for
 * a message that was fine but rolled back because a neighbour failed. So errs[i]
 * alone does not say "applied": the batch committed only if every errs[i] is 0.
 *
 * msgs[i] must have been built with seq = first_seq + i (see nftlk_seq_reserve).
 * Returns 0 once every message's ack has been read (errs[] filled with the
 * kernel's negative errno or 0), -1 if the batch could not be sent or an ack did
 * not arrive in ACK_TIMEOUT_MS — the outcome is then unknown. */
static int nftlk_txn(uint8_t *const msgs[], const size_t lens[], int n,
                     uint32_t first_seq, int errs[]) {
    if (g_nlk_fd < 0 || n < 1 || n > 4) return -1;
    uint8_t bbuf[64], ebuf[64];
    size_t blen = nftlk_build_batch(bbuf, first_seq - 1, 1);
    size_t elen = nftlk_build_batch(ebuf, first_seq + (uint32_t)n, 0);

    struct sockaddr_nl dst = { .nl_family = AF_NETLINK };
    struct iovec iov[6];
    int k = 0;
    iov[k++] = (struct iovec){ bbuf, blen };
    for (int i = 0; i < n; i++) iov[k++] = (struct iovec){ msgs[i], lens[i] };
    iov[k++] = (struct iovec){ ebuf, elen };
    struct msghdr msg = { .msg_name = &dst, .msg_namelen = sizeof(dst),
                          .msg_iov = iov, .msg_iovlen = (size_t)k };
    if (sendmsg(g_nlk_fd, &msg, 0) < 0) {
        if (dbg()) fprintf(stderr, "nftlk: sendmsg fail errno=%d\n", errno);
        return -1;
    }

    /* Drain until every message of THIS batch has its ack. The kernel replies with
     * an NLMSG_ERROR whose nlmsgerr::error is 0 on success or a negative errno;
     * acks for other sequence numbers are leftovers from a transaction that timed
     * out earlier and must not be mistaken for this one's result. An error acked
     * against BATCH_BEGIN's own seq is a batch-level refusal (e.g. ENOMEM): none
     * of the messages then get an ack of their own. */
    int got = 0, seen[4] = {0};
    uint8_t rbuf[1024];
    while (got < n) {
        ssize_t r = recv(g_nlk_fd, rbuf, sizeof(rbuf), 0);
        if (r < (ssize_t)NLMSG_HDRLEN) {
            if (dbg()) fprintf(stderr, "nftlk: ack recv short/timeout r=%zd errno=%d\n", r, errno);
            return -1; /* timeout / truncated */
        }
        size_t left = (size_t)r;
        for (struct nlmsghdr *rh = (struct nlmsghdr *)rbuf; NLMSG_OK(rh, left);
             rh = NLMSG_NEXT(rh, left)) {
            if (rh->nlmsg_type != NLMSG_ERROR) continue; /* multipart / unrelated */
            struct nlmsgerr *e = NLMSG_DATA(rh);
            if (rh->nlmsg_seq == first_seq - 1 && e->error != 0) {
                if (dbg()) fprintf(stderr, "nftlk: batch refused error=%d\n", e->error);
                return -1;
            }
            uint32_t i = rh->nlmsg_seq - first_seq;
            if (i >= (uint32_t)n || seen[i]) {
                if (dbg())
                    fprintf(stderr, "nftlk: stale ack seq=%u (want %u..%u), ignoring\n",
                            rh->nlmsg_seq, first_seq, first_seq + (uint32_t)n - 1);
                continue;
            }
            seen[i] = 1;
            errs[i] = e->error;
            got++;
        }
    }
    return 0;
}

/* Sequence numbers for one transaction of `n` messages: begin, n messages, end.
 * Returns the first MESSAGE seq. Unique per request, not a timestamp: two inserts
 * within the same second would share a seq, and the ack matcher could then credit
 * one transaction with the other's result. */
static uint32_t nftlk_seq_reserve(int n) {
    uint32_t first = g_nlk_seq + 2;           /* g_nlk_seq + 1 is BATCH_BEGIN */
    g_nlk_seq = first + (uint32_t)n;          /* ... and this one is BATCH_END */
    return first;
}

/* One element message in its own transaction. Returns the kernel's errno as-is
 * (0 or negative): EEXIST and ENOENT are meaningful outcomes for the callers
 * below, not plain failures. -ETIMEDOUT when the outcome is unknown (send
 * failure / no ack in time), -ENOTCONN without a netlink socket. */
int nftlk_elem_msg(uint16_t nft_msg_type, const char *table,
                    const char *obj_name, const void *key_net,
                    int interval, const void *data_net,
                    uint64_t timeout_ms) {
    if (g_nlk_fd < 0) return -ENOTCONN;
    uint8_t buf[NFTLK_MSG_CAP];
    uint32_t seq = nftlk_seq_reserve(1);
    size_t len = nftlk_elem_build(buf, sizeof(buf), seq, nft_msg_type, table, obj_name,
                                  key_net, interval, data_net, timeout_ms);
    uint8_t *msgs[1] = { buf };
    int err = 0;
    if (nftlk_txn(msgs, &len, 1, seq, &err) != 0) return -ETIMEDOUT;
    if (err != 0 && dbg())
        fprintf(stderr, "nftlk: kernel ack error=%d (%s) for %s/%s\n",
                err, strerror(-err), table, obj_name);
    return err;
}

/* ---- typed wrappers (the call sites below use these) ------------------ */

/* Adds an IPv4 element to a timeout-flagged set (nft 'timeout'). ttl is in
 * seconds; clamped to [1, 86400] so a hostile/huge record TTL can never pin
 * an entry for longer than a day. ttl == 0 is a PERMANENT element (no timeout
 * attribute at all): used for fake-IP, which must outlive the client's cached
 * answer — see fakeip_route_set. */
/* Срок элемента набора канала из TTL ответа: 1..86400 с. Ноль здесь НЕ «навечно»: TTL 0 у
 * A-записи законен (балансировщики), а нулевой аргумент у nft_add_element означает постоянный
 * элемент — так реальный, часто общий CDN-адрес навечно оставался в наборе канала, и весь
 * чужой трафик на него шёл в канал до пересборки набора. */
uint32_t set_ttl_clamp(uint32_t ttl) {
    if (ttl < 1) return 1;
    if (ttl > 86400) return 86400;
    return ttl;
}

int nft_add_element(const char *set_name, uint32_t key_host, uint32_t ttl) {
    uint64_t timeout_ms;
    if (ttl == 0) {
        timeout_ms = 0;                          /* permanent: no NFTA_SET_ELEM_TIMEOUT */
    } else {
        if (ttl < 1) ttl = 1;
        if (ttl > 86400) ttl = 86400;
        timeout_ms = (uint64_t)ttl * 1000;
    }
    uint32_t key_net = htonl(key_host);
    int rc = nftlk_elem_msg(NFT_MSG_NEWSETELEM, g_nft_table, set_name,
                            &key_net, g_nft_sets_interval, NULL, timeout_ms);
    if (rc == -EINVAL && g_nft_sets_interval)
        /* Имя splify-dnsd осталось от предыдущего проекта, и строка из-за него не
         * доезжала до интерфейса вовсе: журнал там собирается как `logread | grep steer`,
         * а подстроки steer в ней не было. При этом сообщение важное — доменная
         * маршрутизация не наполняется. */
        fprintf(stderr, "steer[warn] dnsd: %s rejected an interval element (-EINVAL) — "
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
 * ONE transaction, not two back to back — which is what this used to be, despite
 * the paragraph above: delete in its own batch, add in the next. Between them was
 * a kernel generation with no mapping at all, and if the add then failed (100 ms
 * ack timeout, the table mid-rebuild) the delete stayed committed: the map lost
 * the element while the fast path kept handing out the fake IP from our own
 * bookkeeping — clients went to 198.18.x.x with no DNAT behind it. Now a refused
 * add rolls the delete back with it, the OLD mapping stays in the kernel, we
 * return -1 and the caller keeps `known_real` as the installed value (it only
 * records the new backend on 0). Covered by tests/dnsnft.sh.
 *
 * The one catch of all-or-nothing: a delete of an element that is not there
 * answers -ENOENT, and that alone rolls back the add in the same batch. That state
 * is legitimate (an fw4 reload flushed the map) and is exactly what a plain add
 * wants, so on ENOENT for the delete we retry the add on its own.
 *
 * Returns 0 when the kernel holds the wanted mapping, otherwise the kernel's
 * negative errno (-ETIMEDOUT: outcome unknown) — the caller decides by it whether
 * this is the table-rebuild window or a lasting refusal (see map_refusal_is_window).
 *
 * `known_real` is what we believe is currently installed (0 = nothing), so the
 * common case — same backend as last time — costs one add that the kernel
 * answers EEXIST to, and the uncommon case costs a delete plus an add.
 * Both addrs are HOST order here. */
int nft_map_set_element(const char *map_name, uint32_t fake_host,
                         uint32_t real_host, uint32_t known_real) {
    uint32_t k = htonl(fake_host), d = htonl(real_host);
    if (known_real != 0 && known_real != real_host) {
        if (g_nlk_fd < 0) return -ENOTCONN;
        uint8_t del[NFTLK_MSG_CAP], add[NFTLK_MSG_CAP];
        uint32_t seq = nftlk_seq_reserve(2);
        size_t lens[2];
        lens[0] = nftlk_elem_build(del, sizeof(del), seq, NFT_MSG_DELSETELEM, g_nft_map_table,
                                   map_name, &k, 0, NULL, 0);
        lens[1] = nftlk_elem_build(add, sizeof(add), seq + 1, NFT_MSG_NEWSETELEM,
                                   g_nft_map_table, map_name, &k, 0, &d, 0);
        uint8_t *msgs[2] = { del, add };
        int errs[2] = { 0, 0 };
        if (nftlk_txn(msgs, lens, 2, seq, errs) != 0) return -ETIMEDOUT;
        if (errs[0] == 0 && errs[1] == 0) return 0;   /* committed: new value in place */
        if (dbg())
            fprintf(stderr, "nftlk: map update rolled back del=%d add=%d\n",
                    errs[0], errs[1]);
        /* Rolled back. Only a missing old element is worth a retry (see above);
         * anything else leaves the old mapping in place and fails the update. */
        if (errs[0] != -ENOENT) return errs[0] ? errs[0] : errs[1];
    }
    int rc = nftlk_elem_msg(NFT_MSG_NEWSETELEM, g_nft_map_table, map_name,
                            &k, 0 /* plain map, not interval */, &d, 0);
    if (rc == -EEXIST) {
        /* Present with the value we wanted (known_real told us so, or a restart
         * lost our bookkeeping and the kernel kept the mapping) — desired state. */
        return 0;
    }
    return rc;
}
