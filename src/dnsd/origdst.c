#include "dnsd_int.h"
#include "ctnl.h"
#include <linux/netlink.h>
#include <linux/netfilter/nfnetlink.h>
#include <linux/netfilter/nfnetlink_conntrack.h>

/* Исходное назначение запроса из conntrack. 0 — найдено (out заполнен), -1 — нет.
 *
 * Семейство — по клиенту: IPv4 (в том числе v4-mapped у двойного стека) ищется в AF_INET,
 * настоящий IPv6 — в AF_INET6; адрес приёма обязан быть того же семейства, иначе такой
 * записи не бывает. Попутно — метка соединения (CTA_MARK): *mark и *have_mark, см. g_up_mark.
 * Атрибута нет (ядро собрано без метки соединений) — *have_mark остаётся 0. */
int ct_origdst(const struct sockaddr_storage *cli, const struct dnsd_local *local,
               int lport, union dnsd_sa *out, uint32_t *mark, int *have_mark) {
    int fam;
    uint8_t caddr[16];
    uint16_t cport;
    *have_mark = 0;
    if (cli->ss_family == AF_INET) {
        const struct sockaddr_in *c4 = (const struct sockaddr_in *)cli;
        fam = AF_INET;
        memcpy(caddr, &c4->sin_addr, 4);
        cport = c4->sin_port;
    } else if (cli->ss_family == AF_INET6) {
        const struct sockaddr_in6 *c6 = (const struct sockaddr_in6 *)cli;
        if (IN6_IS_ADDR_V4MAPPED(&c6->sin6_addr)) {
            fam = AF_INET;
            memcpy(caddr, &c6->sin6_addr.s6_addr[12], 4);
        } else {
            fam = AF_INET6;
            memcpy(caddr, &c6->sin6_addr, 16);
        }
        cport = c6->sin6_port;
    } else {
        return -1;
    }
    if (local->af != fam) return -1;
    size_t alen = fam == AF_INET ? 4 : 16;
    const void *laddr = fam == AF_INET ? (const void *)&local->v4 : (const void *)&local->v6;
    if (g_ct_fd < 0) {
        g_ct_fd = socket(AF_NETLINK, SOCK_RAW | SOCK_CLOEXEC, NETLINK_NETFILTER);
        if (g_ct_fd < 0) return -1;
        struct timeval tv = { 0, 200000 };        /* ядро отвечает сразу; это страховка */
        setsockopt(g_ct_fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
    }
    static uint32_t seq;
    uint8_t req[256];
    memset(req, 0, sizeof(req));
    struct nlmsghdr *nh = (struct nlmsghdr *)req;
    nh->nlmsg_type = (NFNL_SUBSYS_CTNETLINK << 8) | IPCTNL_MSG_CT_GET;
    nh->nlmsg_flags = NLM_F_REQUEST;
    nh->nlmsg_seq = ++seq;
    struct nfgenmsg *nf = (struct nfgenmsg *)NLMSG_DATA(nh);
    nf->nfgen_family = (uint8_t)fam;
    nf->version = NFNETLINK_V0;
    size_t pos = NLMSG_LENGTH(sizeof(*nf));
    /* Вложенные атрибуты по-простому: длина вложения дописывается после содержимого. */
#define CT_PUT(type, data, len) do { \
        struct nlattr *a_ = (struct nlattr *)(req + pos); \
        a_->nla_type = (type); a_->nla_len = (uint16_t)(NLA_HDRLEN + (len)); \
        memcpy(req + pos + NLA_HDRLEN, (data), (len)); \
        pos += NLA_ALIGN(a_->nla_len); } while (0)
#define CT_OPEN(type, at) do { at = pos; \
        ((struct nlattr *)(req + pos))->nla_type = (type) | NLA_F_NESTED; pos += NLA_HDRLEN; } while (0)
#define CT_CLOSE(at) (((struct nlattr *)(req + (at)))->nla_len = (uint16_t)(pos - (at)))
    size_t t, ip, pr;
    /* Протокол — тот, которым пришёл запрос: у соединения TCP своя запись conntrack. */
    uint8_t proto = g_tcp_cur ? IPPROTO_TCP : IPPROTO_UDP;
    uint16_t lp = htons((uint16_t)lport);
    CT_OPEN(CTA_TUPLE_REPLY, t);
    CT_OPEN(CTA_TUPLE_IP, ip);
    CT_PUT(fam == AF_INET ? CTA_IP_V4_SRC : CTA_IP_V6_SRC, laddr, alen);
    CT_PUT(fam == AF_INET ? CTA_IP_V4_DST : CTA_IP_V6_DST, caddr, alen);
    CT_CLOSE(ip);
    CT_OPEN(CTA_TUPLE_PROTO, pr);
    CT_PUT(CTA_PROTO_NUM, &proto, 1);
    CT_PUT(CTA_PROTO_SRC_PORT, &lp, 2);
    CT_PUT(CTA_PROTO_DST_PORT, &cport, 2);
    CT_CLOSE(pr);
    CT_CLOSE(t);
#undef CT_PUT
#undef CT_OPEN
#undef CT_CLOSE
    nh->nlmsg_len = (uint32_t)pos;
    struct sockaddr_nl k = { .nl_family = AF_NETLINK };
    if (sendto(g_ct_fd, req, pos, 0, (struct sockaddr *)&k, sizeof(k)) < 0) return -1;

    uint8_t buf[4096];
    int dst_attr = fam == AF_INET ? CTA_IP_V4_DST : CTA_IP_V6_DST;
    for (;;) {
        ssize_t n = recv(g_ct_fd, buf, sizeof(buf), 0);
        if (n <= 0) return -1;
        int len = (int)n;
        for (struct nlmsghdr *h = (struct nlmsghdr *)buf; len > 0 && NLMSG_OK(h, (unsigned)len);
             h = NLMSG_NEXT(h, len)) {
            if (h->nlmsg_seq != seq) continue;           /* ответ на прежний, опоздавший */
            if (h->nlmsg_type == NLMSG_ERROR) return -1; /* записи нет — ENOENT */
            if (h->nlmsg_len < NLMSG_LENGTH(sizeof(struct nfgenmsg))) return -1;
            /* Верхний уровень: CTA_TUPLE_ORIG (в нём IP и порт назначения) и CTA_MARK. */
            const uint8_t *a = (const uint8_t *)NLMSG_DATA(h) + NLMSG_ALIGN(sizeof(struct nfgenmsg));
            const uint8_t *end = (const uint8_t *)h + h->nlmsg_len;
            const struct nlattr *cm = ct_attr(a, end, CTA_MARK);
            if (cm && cm->nla_len >= NLA_HDRLEN + 4) {
                uint32_t m;
                memcpy(&m, (const uint8_t *)cm + NLA_HDRLEN, 4);
                *mark = ntohl(m);
                *have_mark = 1;
            }
            const struct nlattr *orig = ct_attr(a, end, CTA_TUPLE_ORIG);
            const struct nlattr *tip = ct_attr_in(orig, CTA_TUPLE_IP);
            const struct nlattr *tpr = ct_attr_in(orig, CTA_TUPLE_PROTO);
            const struct nlattr *dst = ct_attr_in(tip, dst_attr);
            const struct nlattr *dpt = ct_attr_in(tpr, CTA_PROTO_DST_PORT);
            uint8_t oaddr[16];
            uint16_t oport = 0;
            int got_ip = 0, got_port = 0;
            if (dst && dst->nla_len >= NLA_HDRLEN + alen) {
                memcpy(oaddr, (const uint8_t *)dst + NLA_HDRLEN, alen); got_ip = 1;
            }
            if (dpt && dpt->nla_len >= NLA_HDRLEN + 2) {
                memcpy(&oport, (const uint8_t *)dpt + NLA_HDRLEN, 2); got_port = 1;
            }
            if (!got_ip || !got_port) return -1;
            /* Назначение — мы сами: к резолверу обратились напрямую, NAT не было. */
            if (!memcmp(oaddr, laddr, alen) && ntohs(oport) == lport) return -1;
            memset(out, 0, sizeof(*out));
            if (fam == AF_INET) {
                out->v4.sin_family = AF_INET;
                memcpy(&out->v4.sin_addr, oaddr, 4);
                out->v4.sin_port = oport;
            } else {
                out->v6.sin6_family = AF_INET6;
                memcpy(&out->v6.sin6_addr, oaddr, 16);
                out->v6.sin6_port = oport;
            }
            return 0;
        }
    }
}
