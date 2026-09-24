/* Помощник стенда ctnl49: завести запись conntrack и посмотреть таблицу — без инструмента
 * conntrack, которого нет ни на стенде 4.9, ни в образе Android.
 *
 *   ctnl49-tool udp АДРЕС ПОРТ   одна датаграмма UDP на АДРЕС:ПОРТ (IPv4 или IPv6) — ядро
 *                                заводит запись conntrack, правило nft сценария ставит ей метку
 *   ctnl49-tool list             все записи UDP обоих семейств: «v4 ПОРТ_НАЗНАЧЕНИЯ 0xМЕТКА»
 *
 * Список читается дампом ctnetlink, и код этого дампа здесь СВОЙ, а не движка. Нарочно:
 * стенд проверяет снятие записей движком, и проверять его результат тем же разбором значило бы
 * пропустить ошибку, общую для обоих. /proc/net/nf_conntrack не годится — у ядра телефона нет
 * CONFIG_NF_CONNTRACK_PROCFS, а на свежих ядрах его чаще всего нет тоже.
 *
 * Сборка (musl, статически, как остальные помощники стенда):
 *   musl-gcc -static -idirafter /root/vm49/sysroot/kinc -O2 -o ctnl49-tool tests/ctnl49-tool.c */
#include <arpa/inet.h>
#include <linux/netfilter/nfnetlink.h>
#include <linux/netfilter/nfnetlink_conntrack.h>
#include <linux/netlink.h>
#include <netinet/in.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

static int send_udp(const char *addr, int port) {
    struct sockaddr_storage ss;
    memset(&ss, 0, sizeof(ss));
    socklen_t sl;
    struct sockaddr_in *a4 = (struct sockaddr_in *)&ss;
    struct sockaddr_in6 *a6 = (struct sockaddr_in6 *)&ss;
    if (inet_pton(AF_INET, addr, &a4->sin_addr) == 1) {
        a4->sin_family = AF_INET; a4->sin_port = htons((uint16_t)port); sl = sizeof(*a4);
    } else if (inet_pton(AF_INET6, addr, &a6->sin6_addr) == 1) {
        a6->sin6_family = AF_INET6; a6->sin6_port = htons((uint16_t)port); sl = sizeof(*a6);
    } else {
        fprintf(stderr, "не адрес: %s\n", addr);
        return 2;
    }
    int fd = socket(ss.ss_family, SOCK_DGRAM, 0);
    if (fd < 0) { perror("socket"); return 1; }
    if (sendto(fd, "x", 1, 0, (struct sockaddr *)&ss, sl) != 1) { perror("sendto"); return 1; }
    close(fd);
    return 0;
}

/* Атрибут по типу среди [p, end); NULL — нет или сообщение битое. */
static const struct nlattr *attr(const uint8_t *p, const uint8_t *end, int type) {
    while (p && p + NLA_HDRLEN <= end) {
        const struct nlattr *x = (const struct nlattr *)p;
        if (x->nla_len < NLA_HDRLEN || p + x->nla_len > end) return NULL;
        if ((x->nla_type & NLA_TYPE_MASK) == type) return x;
        p += NLA_ALIGN(x->nla_len);
    }
    return NULL;
}
static const struct nlattr *sub(const struct nlattr *in, int type) {
    if (!in) return NULL;
    return attr((const uint8_t *)in + NLA_HDRLEN, (const uint8_t *)in + in->nla_len, type);
}

static int list_family(int fd, uint8_t family) {
    struct { struct nlmsghdr h; struct nfgenmsg g; } req;
    memset(&req, 0, sizeof(req));
    req.h.nlmsg_len = sizeof(req);
    req.h.nlmsg_type = (NFNL_SUBSYS_CTNETLINK << 8) | IPCTNL_MSG_CT_GET;
    req.h.nlmsg_flags = NLM_F_REQUEST | NLM_F_DUMP;
    req.h.nlmsg_seq = family;
    req.g.nfgen_family = family;
    req.g.version = NFNETLINK_V0;
    struct sockaddr_nl k = { .nl_family = AF_NETLINK };
    if (sendto(fd, &req, sizeof(req), 0, (struct sockaddr *)&k, sizeof(k)) < 0) {
        perror("sendto netlink");
        return 1;
    }
    static uint8_t buf[65536];
    for (;;) {
        ssize_t n = recv(fd, buf, sizeof(buf), 0);
        if (n <= 0) { perror("recv netlink"); return 1; }
        int len = (int)n;
        for (struct nlmsghdr *h = (struct nlmsghdr *)buf; len > 0 && NLMSG_OK(h, (unsigned)len);
             h = NLMSG_NEXT(h, len)) {
            if (h->nlmsg_type == NLMSG_DONE) return 0;
            if (h->nlmsg_type == NLMSG_ERROR) {
                int e = ((struct nlmsgerr *)NLMSG_DATA(h))->error;
                if (e == 0) return 0;
                fprintf(stderr, "дамп: ошибка %d\n", e);
                return 1;
            }
            const uint8_t *a = (const uint8_t *)NLMSG_DATA(h) + NLMSG_ALIGN(sizeof(struct nfgenmsg));
            const uint8_t *end = (const uint8_t *)h + h->nlmsg_len;
            const struct nlattr *pr = sub(attr(a, end, CTA_TUPLE_ORIG), CTA_TUPLE_PROTO);
            const struct nlattr *num = sub(pr, CTA_PROTO_NUM);
            const struct nlattr *dp = sub(pr, CTA_PROTO_DST_PORT);
            if (!num || !dp || *((const uint8_t *)num + NLA_HDRLEN) != IPPROTO_UDP) continue;
            uint16_t port;
            memcpy(&port, (const uint8_t *)dp + NLA_HDRLEN, 2);
            uint32_t mark = 0;
            const struct nlattr *m = attr(a, end, CTA_MARK);
            if (m) { memcpy(&mark, (const uint8_t *)m + NLA_HDRLEN, 4); mark = ntohl(mark); }
            printf("%s %u 0x%08x\n", family == AF_INET ? "v4" : "v6", ntohs(port), mark);
        }
    }
}

int main(int argc, char **argv) {
    if (argc == 4 && !strcmp(argv[1], "udp")) return send_udp(argv[2], atoi(argv[3]));
    if (argc == 2 && !strcmp(argv[1], "list")) {
        int fd = socket(AF_NETLINK, SOCK_RAW, NETLINK_NETFILTER);
        if (fd < 0) { perror("socket netlink"); return 1; }
        int r = list_family(fd, AF_INET) | list_family(fd, AF_INET6);
        close(fd);
        return r;
    }
    fprintf(stderr, "использование: ctnl49-tool udp АДРЕС ПОРТ | list\n");
    return 2;
}
