#include "ctnl.h"
#include <arpa/inet.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>
#include <linux/netlink.h>
#include <linux/netfilter/nfnetlink.h>
#include <linux/netfilter/nfnetlink_conntrack.h>
#include "nlbuf.h"

static const struct nlattr *ct_attr(const uint8_t *p, const uint8_t *end, int type) {
    if (!p) return NULL;
    while (p + NLA_HDRLEN <= end) {
        const struct nlattr *x = (const struct nlattr *)p;
        if (x->nla_len < NLA_HDRLEN || p + x->nla_len > end) return NULL;
        if ((x->nla_type & NLA_TYPE_MASK) == type) return x;
        p += NLA_ALIGN(x->nla_len);
    }
    return NULL;
}
static const struct nlattr *ct_attr_in(const struct nlattr *in, int type) {
    if (!in) return NULL;
    return ct_attr((const uint8_t *)in + NLA_HDRLEN, (const uint8_t *)in + in->nla_len, type);
}

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

/* ---- снятие записей conntrack выхода: ctnetlink без инструмента conntrack -------------
 *
 * ЗАЧЕМ ЗДЕСЬ. Снимать соединения выхода при смене его маршрута нужно сторожу
 * (conntrack_evict в failover.c, там же — почему снимать вообще). До сих пор это делал
 * внешний `conntrack -D --mark`, а его нет в образе Android: на телефоне смена выхода
 * оставляла уже установленные соединения на прежнем, возможно мёртвом, выходе до их
 * естественной смерти — то есть долгие соединения мессенджеров висели минутами. Разговор с
 * conntrack по netlink в движке уже был — вот он, выше, у исходного назначения резолвера, —
 * поэтому код лежит рядом с ним и берёт тот же разбор атрибутов (ct_attr) и тот же
 * построитель сообщений (nlbuf), а не заводит свой файл: новый файл означал бы правку пяти
 * списков сборки (Makefile, Android.bp, build.sh, стенды) ради одной функции.
 *
 * КАК, И ПОЧЕМУ НЕ ОДНИМ СООБЩЕНИЕМ. У ctnetlink есть «снять всё» — IPCTNL_MSG_CT_DELETE без
 * кортежа, — и с атрибутами CTA_MARK/CTA_MARK_MASK оно снимает только совпавшее. В 4.9
 * телефона этот фильтр есть (ctnetlink_flush_conntrack), но опора на него хрупкая с двух
 * сторон: ядро старше фильтра атрибуты молча пропустит, а 4.9 без ОБОИХ атрибутов (скажем,
 * маска потерялась при правке этого же кода) фильтра не заводит вовсе — и в обоих случаях
 * сбрасывается ВСЯ таблица: у телефона — все соединения всех приложений, у роутера — вся
 * сеть за ним. Ошибка такой цены не стоит одного сэкономленного сообщения, поэтому путь тот
 * же, что у самого `conntrack -D --mark`: дамп (с фильтром по
 * метке — его 4.9 уже знает, ctnetlink_dump_table проверено по дереву ядра телефона), и
 * каждая совпавшая запись снимается ОТДЕЛЬНО по своему исходному кортежу. Метка сверяется
 * ещё раз здесь, по CTA_MARK самой записи: если ядро фильтр дампа не поняло и прислало всё,
 * чужое всё равно не будет тронуто. Запись без CTA_MARK (метка 0) не наша никогда — ноль
 * метку выхода не несёт.
 *
 * Снимается строго запись с тем же CTA_ID: между дампом и удалением соединение могло умереть,
 * а на его кортеже родиться новое — чужое, — и удаление по одному кортежу сняло бы его. С
 * CTA_ID ядро отвечает ENOENT, и это не ошибка. CTA_ZONE копируется, если есть: без него
 * поиск идёт в нулевой зоне, и запись другой зоны не нашлась бы.
 *
 * Семейства — по одному дампу на каждое: запрос с AF_UNSPEC в 4.9 отдаёт оба, но в свежих
 * ядрах фильтр дампа переписан, и полагаться на смысл нуля в двух реализациях незачем, когда
 * два дампа стоят один лишний системный вызов.
 *
 * Два сокета: дамп идёт частями — следующая часть готовится ядром на каждом recv, — и
 * удаление на том же сокете смешало бы свои подтверждения с частями дампа. На втором сокете
 * удаление идёт между частями, как у conntrack -D, и памяти под список найденного не нужно:
 * запись, которую ядро держит как точку продолжения дампа, userspace ещё не видел и снять
 * не мог, остальные из корзины уже отданы.
 *
 * БАТАРЕЯ. Один проход, без таймеров и повторов: ядро отвечает на каждый запрос сразу,
 * внутри того же системного вызова. SO_RCVTIMEO — только страховка от вечного recv при
 * невозможном «ядро не ответило», как у ct_origdst; в обычной работе он не срабатывает.
 *
 * Возврат: сколько записей снято (0 и больше) или -1 — «разговор с ctnetlink не состоялся»:
 * нет сокета NETLINK_NETFILTER (на роутере нет nfnetlink), ядро не знает подсистемы
 * conntrack (нет модуля nf_conntrack_netlink), нет прав. Тогда вызывающий пробует внешний
 * инструмент. */
#define CTNL_RCVBUF 32768   /* больше части дампа ядро не шлёт: netlink_dump режет по 32 КиБ */

static int ctnl_socket(void) {
    int fd = socket(AF_NETLINK, SOCK_RAW | SOCK_CLOEXEC, NETLINK_NETFILTER);
    if (fd < 0) return -1;
    struct sockaddr_nl sa = { .nl_family = AF_NETLINK };
    if (bind(fd, (struct sockaddr *)&sa, sizeof(sa)) != 0) { close(fd); return -1; }
    struct timeval tv = { 1, 0 };
    setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
    return fd;
}

/* Заголовки сообщения ctnetlink в начале буфера; атрибуты дописываются за ними. */
static struct nlmsghdr *ctnl_msg(struct nlbuf *b, void *mem, size_t cap, int type,
                                 int flags, uint32_t seq, uint8_t family) {
    size_t hl = NLMSG_ALIGN(sizeof(struct nlmsghdr)) + NLMSG_ALIGN(sizeof(struct nfgenmsg));
    memset(mem, 0, hl);
    nlbuf_init(b, mem, cap);
    struct nlmsghdr *nh = (struct nlmsghdr *)b->p;
    nh->nlmsg_type = (uint16_t)((NFNL_SUBSYS_CTNETLINK << 8) | type);
    nh->nlmsg_flags = (uint16_t)flags;
    nh->nlmsg_seq = seq;
    struct nfgenmsg *nf = (struct nfgenmsg *)(b->p + NLMSG_ALIGN(sizeof(*nh)));
    nf->nfgen_family = family;
    nf->version = NFNETLINK_V0;
    b->p += hl;
    return nh;
}

/* Атрибут из ответа ядра — в запрос как есть, вместе с вложенным содержимым. */
static int ctnl_copy_attr(struct nlbuf *b, const struct nlattr *x) {
    if (!x) return 0;
    size_t n = NLA_ALIGN(x->nla_len);
    if (b->p + n > b->end) return -1;
    memset(b->p, 0, n);
    memcpy(b->p, x, x->nla_len);
    b->p += n;
    return 0;
}

/* Снять одну запись; 1 — снята, 0 — нет (уже умерла или ядро отказало). */
static int ctnl_delete(int fd, uint8_t family, uint32_t seq, const struct nlattr *tuple,
                       const struct nlattr *id, const struct nlattr *zone) {
    uint8_t req[512];
    struct nlbuf b;
    struct nlmsghdr *nh = ctnl_msg(&b, req, sizeof(req), IPCTNL_MSG_CT_DELETE,
                                   NLM_F_REQUEST | NLM_F_ACK, seq, family);
    if (ctnl_copy_attr(&b, tuple) || ctnl_copy_attr(&b, id) || ctnl_copy_attr(&b, zone))
        return 0;
    nh->nlmsg_len = (uint32_t)(b.p - b.base);
    struct sockaddr_nl k = { .nl_family = AF_NETLINK };
    if (sendto(fd, req, nh->nlmsg_len, 0, (struct sockaddr *)&k, sizeof(k)) < 0) return 0;
    uint8_t ack[512];
    for (;;) {
        ssize_t n = recv(fd, ack, sizeof(ack), 0);
        if (n <= 0) return 0;
        int len = (int)n;
        for (struct nlmsghdr *h = (struct nlmsghdr *)ack; len > 0 && NLMSG_OK(h, (unsigned)len);
             h = NLMSG_NEXT(h, len)) {
            if (h->nlmsg_seq != seq || h->nlmsg_type != NLMSG_ERROR) continue;
            if (h->nlmsg_len < NLMSG_LENGTH(sizeof(struct nlmsgerr))) return 0;
            return ((struct nlmsgerr *)NLMSG_DATA(h))->error == 0;
        }
    }
}

/* ДАМП CONNTRACK ОДНОГО СЕМЕЙСТВА — общий для двух читателей: снятия записей выхода (ниже,
 * ctnl_evict_mark) и списка соединений для приложения (ctnl_conns_print). Каждая запись дампа
 * отдаётся обработчику fn атрибутами [a, end); что с ней делать, решает он.
 *
 * С filter — дамп с фильтром ядра по метке (CTA_MARK/CTA_MARK_MASK, см. довод у снятия выше):
 * ядро пришлёт только совпавшее, если фильтр понимает. Полагаться на это обработчик всё равно
 * не должен — метку он сверяет сам. Без filter — все записи семейства: список соединений
 * отбирает записи по ПОЛЮ метки движка (любое ненулевое значение поля), а такое условие одной
 * парой «значение и маска» ядру не выразить.
 *
 * Возврат: 0 — дамп пройден до конца; 1 — ядро отвергло фильтр по метке (EOPNOTSUPP: ядро
 * собрано без CONFIG_NF_CONNTRACK_MARK, записей с меткой у него нет вовсе); -1 — разговор не
 * состоялся (или обработчик попросил прервать, вернув не 0). */
typedef int (*ctnl_rec_fn)(const uint8_t *a, const uint8_t *end, uint8_t family, void *ctx);

static int ctnl_dump(int dfd, uint8_t family, int filter, uint32_t val, uint32_t mask,
                     uint32_t *seq, uint8_t *buf, ctnl_rec_fn fn, void *ctx) {
    uint8_t req[128];
    struct nlbuf b;
    uint32_t dseq = ++*seq;
    struct nlmsghdr *nh = ctnl_msg(&b, req, sizeof(req), IPCTNL_MSG_CT_GET,
                                   NLM_F_REQUEST | NLM_F_DUMP, dseq, family);
    if (filter) {
        nlbuf_put_be32(&b, CTA_MARK, val);
        nlbuf_put_be32(&b, CTA_MARK_MASK, mask);
    }
    nh->nlmsg_len = (uint32_t)(b.p - b.base);
    struct sockaddr_nl k = { .nl_family = AF_NETLINK };
    if (sendto(dfd, req, nh->nlmsg_len, 0, (struct sockaddr *)&k, sizeof(k)) < 0) return -1;

    for (;;) {
        /* MSG_TRUNC: recv возвращает настоящую длину части. Больше буфера — значит часть
         * обрезана, и разбирать её остаток нельзя; при CTNL_RCVBUF этого не бывает. */
        ssize_t n = recv(dfd, buf, CTNL_RCVBUF, MSG_TRUNC);
        if (n <= 0 || n > CTNL_RCVBUF) return -1;
        int len = (int)n;
        for (struct nlmsghdr *h = (struct nlmsghdr *)buf; len > 0 && NLMSG_OK(h, (unsigned)len);
             h = NLMSG_NEXT(h, len)) {
            if (h->nlmsg_seq != dseq) continue;
            if (h->nlmsg_type == NLMSG_DONE) return 0;
            if (h->nlmsg_type == NLMSG_ERROR) {
                if (h->nlmsg_len < NLMSG_LENGTH(sizeof(struct nlmsgerr))) return -1;
                int err = ((struct nlmsgerr *)NLMSG_DATA(h))->error;
                /* EOPNOTSUPP на фильтре — ядро собрано без CONFIG_NF_CONNTRACK_MARK. Метки
                 * соединения у такого ядра нет вовсе, а значит и записей с меткой выхода. */
                if (filter && err == -EOPNOTSUPP) return 1;
                return err == 0 ? 0 : -1;
            }
            if ((h->nlmsg_type >> 8) != NFNL_SUBSYS_CTNETLINK ||
                h->nlmsg_len < NLMSG_LENGTH(sizeof(struct nfgenmsg)))
                continue;
            const uint8_t *a = (const uint8_t *)NLMSG_DATA(h) + NLMSG_ALIGN(sizeof(struct nfgenmsg));
            const uint8_t *end = (const uint8_t *)h + h->nlmsg_len;
            if (fn(a, end, family, ctx) != 0) return -1;
        }
    }
}

/* Метка записи (CTA_MARK); 0 — атрибута нет (ядро без метки соединений или запись без метки:
 * ноль ядро не шлёт вовсе). */
static uint32_t ct_mark_of(const uint8_t *a, const uint8_t *end) {
    const struct nlattr *m = ct_attr(a, end, CTA_MARK);
    if (!m || m->nla_len < NLA_HDRLEN + 4) return 0;
    uint32_t mv;
    memcpy(&mv, (const uint8_t *)m + NLA_HDRLEN, 4);
    return ntohl(mv);
}

struct ctnl_evict_ctx {
    int xfd;
    uint32_t val, mask;
    uint32_t *seq;
    int evicted;
};

/* Запись дампа при снятии: совпала по метке — снять отдельно, по исходному кортежу и CTA_ID. */
static int ctnl_evict_rec(const uint8_t *a, const uint8_t *end, uint8_t family, void *ctx) {
    struct ctnl_evict_ctx *x = ctx;
    uint32_t mv = ct_mark_of(a, end);
    if (!mv || (mv & x->mask) != x->val) return 0;
    const struct nlattr *tuple = ct_attr(a, end, CTA_TUPLE_ORIG);
    if (!tuple) return 0;
    x->evicted += ctnl_delete(x->xfd, family, ++*x->seq, tuple, ct_attr(a, end, CTA_ID),
                              ct_attr(a, end, CTA_ZONE));
    return 0;
}

int ctnl_evict_mark(uint32_t val, uint32_t mask) {
    /* Нулевое значение совпало бы с каждой записью без метки — то есть со всем чужим. Метка
     * выхода нулём не бывает; защита от ошибки вызывающего, а не от ядра. */
    if (!val || (val & ~mask)) return 0;
    int dfd = ctnl_socket(), xfd = ctnl_socket();
    uint8_t *buf = malloc(CTNL_RCVBUF);
    int total = -1;
    if (dfd >= 0 && xfd >= 0 && buf) {
        static const uint8_t fam[] = { AF_INET, AF_INET6 };
        uint32_t seq = (uint32_t)time(NULL);
        struct ctnl_evict_ctx x = { xfd, val, mask, &seq, 0 };
        total = 0;
        for (size_t i = 0; i < sizeof(fam); i++) {
            /* 1 (фильтр отвергнут: меток у ядра нет) — снимать в этом семействе нечего, и
             * внешний инструмент здесь не нужен: это не «разговор не состоялся». */
            if (ctnl_dump(dfd, fam[i], 1, val, mask, &seq, buf, ctnl_evict_rec, &x) < 0) {
                total = -1;
                break;
            }
        }
        if (total == 0) total = x.evicted;
    }
    free(buf);
    if (dfd >= 0) close(dfd);
    if (xfd >= 0) close(xfd);
    return total;
}

/* ---- соединения движка: `steer conns` (команда conns управляющего сокета) --------------
 *
 * ЗАЧЕМ. Экран «Соединения» приложения (план C1): какие соединения сейчас идут через каналы
 * движка и в какой выход. Источник правды — conntrack: метку выхода соединению ставят правила
 * движка (ct mark), и она же решает маршрут каждого следующего пакета, то есть запись
 * conntrack с меткой — это ровно «соединение, которое движок куда-то повёл». Инструмента
 * conntrack в образе Android нет, /proc/net/nf_conntrack у ядра телефона нет тоже
 * (CONFIG_NF_CONNTRACK_PROCFS выключен), поэтому — тот же дамп ctnetlink, что у снятия.
 *
 * ЧТО ПОПАДАЕТ. Записи, у которых ПОЛЕ метки движка (STEER_MARK_MASK) не ноль. Чужие биты вне
 * поля (netd на телефоне кладёт в метку номер сети и права) не мешают и не показываются.
 * Значение «все биты поля» на телефоне — не выход, а собственный трафик движка
 * (STEER_SELF_MARK: запросы резолвера наверх), и в список оно не идёт: человеку в «Соединениях»
 * нужны его приложения, а не служебные запросы DNS самого движка.
 *
 * ВЫХОД — по метке из реестра меток каталога состояния (<state>/registry, «имя метка таблица»),
 * а не из спеки. В ядре стоят метки ПРИМЕНЁННОЙ спеки, и реестр — их запись; сохранённая, но
 * не применённая спека (движок выключен, apply отвергнут ядром) меток в пакетах не меняла.
 * Метки нет в реестре (выход убран, а его соединения ещё доживают) — "out":null.
 *
 * UID ПРИЛОЖЕНИЯ здесь нет и не выдумывается: conntrack его не хранит (метка сокета и skuid
 * живут в сокете, а не в записи соединения), и угадывать его по порту значило бы показывать
 * человеку неправду.
 *
 * СЧЁТЧИКИ (packets/bytes, reply_packets/reply_bytes) — только если ядро их ведёт: у 4.9 и у
 * свежих ядер это sysctl net.netfilter.nf_conntrack_acct, по умолчанию выключенный, и запись,
 * заведённая без него, счётчиков не получает и потом. Нет атрибута — нет поля: ноль означал бы
 * «ничего не передано», а это неправда.
 *
 * ПРЕДЕЛ — CONNS_MAX записей в ответе; остальные считаются (total), но не печатаются, и ответ
 * несёт "truncated":true. Запись — до ~350 байт JSON (два адреса IPv6), 2000 записей — ~700 КиБ,
 * с запасом внутри предела вывода управляющего сокета (1 МиБ, CTL_OUT_MAX в ctl.c): ответ
 * через сокет обрезаться посреди JSON не должен никогда. На телефоне живых соединений сотни.
 *
 * БАТАРЕЯ. Одна команда — два дампа (IPv4 и IPv6) по запросу экрана; ничего не остаётся жить. */
#define CONNS_MAX 2000

struct conns_reg { char name[32]; uint32_t mark; };
/* dlog_json_str определена в dlog.c, объявлена в dnsd_int.h — строка JSON у журнала имён. */

struct ctnl_conns_ctx {
    FILE *out;
    int shown, total;
    struct conns_reg reg[STEER_MARK_SLOTS * 2];
    size_t reg_n;
};

static const char *ct_proto_name(uint8_t p) {
    switch (p) {
    case IPPROTO_TCP: return "tcp";
    case IPPROTO_UDP: return "udp";
    case IPPROTO_ICMP: return "icmp";
    case IPPROTO_ICMPV6: return "icmpv6";
    case IPPROTO_SCTP: return "sctp";
    case IPPROTO_UDPLITE: return "udplite";
    case IPPROTO_DCCP: return "dccp";
    case IPPROTO_GRE: return "gre";
    default: return NULL;
    }
}

/* Состояние TCP из conntrack — те же имена, что печатает инструмент conntrack, строчными.
 * Номера — enum tcp_conntrack ядра; они не менялись с 2.6 (SYN_SENT2 = 9, прежний LISTEN). */
static const char *ct_tcp_state(uint8_t st) {
    static const char *const N[] = { "none", "syn_sent", "syn_recv", "established", "fin_wait",
                                     "close_wait", "last_ack", "time_wait", "close", "syn_sent2" };
    return st < sizeof(N) / sizeof(N[0]) ? N[st] : NULL;
}

/* Число из атрибута счётчика: be64 у свежих ядер и у 4.9, be32 у очень старых (CTA_COUNTERS32_*).
 * Атрибут be64 в сообщении выровнен только на 4 байта — поэтому чтение по байтам, а не
 * разыменование. */
static int ct_counter(const struct nlattr *nest, int t64, int t32, unsigned long long *v) {
    const struct nlattr *x = ct_attr_in(nest, t64);
    if (x && x->nla_len >= NLA_HDRLEN + 8) {
        /* По байтам, старший первым: так одинаково верно и на little-endian телефоне, и на
         * big-endian роутере (MIPS), без be64toh, которого нет в каждой libc. */
        const uint8_t *q = (const uint8_t *)x + NLA_HDRLEN;
        unsigned long long r = 0;
        for (int i = 0; i < 8; i++) r = (r << 8) | q[i];
        *v = r;
        return 1;
    }
    x = ct_attr_in(nest, t32);
    if (x && x->nla_len >= NLA_HDRLEN + 4) {
        uint32_t b;
        memcpy(&b, (const uint8_t *)x + NLA_HDRLEN, 4);
        *v = ntohl(b);
        return 1;
    }
    return 0;
}

static void ct_print_counters(FILE *out, const struct nlattr *nest, const char *pfx) {
    unsigned long long v;
    if (!nest) return;
    if (ct_counter(nest, CTA_COUNTERS_PACKETS, CTA_COUNTERS32_PACKETS, &v))
        fprintf(out, ",\"%spackets\":%llu", pfx, v);
    if (ct_counter(nest, CTA_COUNTERS_BYTES, CTA_COUNTERS32_BYTES, &v))
        fprintf(out, ",\"%sbytes\":%llu", pfx, v);
}

static int ctnl_conns_rec(const uint8_t *a, const uint8_t *end, uint8_t family, void *vctx) {
    struct ctnl_conns_ctx *x = vctx;
    uint32_t field = ct_mark_of(a, end) & STEER_MARK_MASK;
    if (!field) return 0;
#ifdef STEER_SELF_MARK
    if (field == (STEER_SELF_MARK & STEER_MARK_MASK)) return 0;
#endif
    const struct nlattr *orig = ct_attr(a, end, CTA_TUPLE_ORIG);
    const struct nlattr *tip = ct_attr_in(orig, CTA_TUPLE_IP);
    const struct nlattr *tpr = ct_attr_in(orig, CTA_TUPLE_PROTO);
    int v6 = family == AF_INET6;
    size_t alen = v6 ? 16 : 4;
    const struct nlattr *sa = ct_attr_in(tip, v6 ? CTA_IP_V6_SRC : CTA_IP_V4_SRC);
    const struct nlattr *da = ct_attr_in(tip, v6 ? CTA_IP_V6_DST : CTA_IP_V4_DST);
    const struct nlattr *pn = ct_attr_in(tpr, CTA_PROTO_NUM);
    if (!sa || !da || !pn || sa->nla_len < NLA_HDRLEN + alen || da->nla_len < NLA_HDRLEN + alen ||
        pn->nla_len < NLA_HDRLEN + 1)
        return 0;                              /* запись без кортежа — показывать нечего */
    x->total++;
    if (x->shown >= CONNS_MAX) return 0;
    char s[INET6_ADDRSTRLEN], d[INET6_ADDRSTRLEN];
    inet_ntop(family, (const uint8_t *)sa + NLA_HDRLEN, s, sizeof(s));
    inet_ntop(family, (const uint8_t *)da + NLA_HDRLEN, d, sizeof(d));
    uint8_t proto = *((const uint8_t *)pn + NLA_HDRLEN);
    FILE *out = x->out;
    fprintf(out, "%s{\"family\":\"%s\",\"proto\":", x->shown ? "," : "", v6 ? "ipv6" : "ipv4");
    const char *pnm = ct_proto_name(proto);
    if (pnm) fprintf(out, "\"%s\"", pnm);
    else fprintf(out, "\"%u\"", proto);
    fprintf(out, ",\"src\":\"%s\"", s);
    /* Порты — только у протоколов с портами: у ICMP в кортеже вместо них тип, код и номер. */
    const struct nlattr *sp = ct_attr_in(tpr, CTA_PROTO_SRC_PORT);
    const struct nlattr *dp = ct_attr_in(tpr, CTA_PROTO_DST_PORT);
    uint16_t pv;
    if (sp && sp->nla_len >= NLA_HDRLEN + 2) {
        memcpy(&pv, (const uint8_t *)sp + NLA_HDRLEN, 2);
        fprintf(out, ",\"sport\":%u", ntohs(pv));
    }
    fprintf(out, ",\"dst\":\"%s\"", d);
    if (dp && dp->nla_len >= NLA_HDRLEN + 2) {
        memcpy(&pv, (const uint8_t *)dp + NLA_HDRLEN, 2);
        fprintf(out, ",\"dport\":%u", ntohs(pv));
    }
    fprintf(out, ",\"mark\":\"0x%08x\",\"out\":", field);
    const char *on = NULL;
    for (size_t i = 0; i < x->reg_n; i++)
        if (x->reg[i].mark == field) { on = x->reg[i].name; break; }
    /* Имя выхода из спеки проверено name_ok, но реестр — файл на диске, и строку JSON из него
     * собирает тот же экранирующий писатель, что у журнала имён. */
    if (on) dlog_json_str(out, on);
    else fputs("null", out);
    if (proto == IPPROTO_TCP) {
        const struct nlattr *pi = ct_attr(a, end, CTA_PROTOINFO);
        const struct nlattr *st = ct_attr_in(ct_attr_in(pi, CTA_PROTOINFO_TCP),
                                             CTA_PROTOINFO_TCP_STATE);
        const char *sn = st && st->nla_len >= NLA_HDRLEN + 1
                             ? ct_tcp_state(*((const uint8_t *)st + NLA_HDRLEN)) : NULL;
        if (sn) fprintf(out, ",\"state\":\"%s\"", sn);
    }
    ct_print_counters(out, ct_attr(a, end, CTA_COUNTERS_ORIG), "");
    ct_print_counters(out, ct_attr(a, end, CTA_COUNTERS_REPLY), "reply_");
    fputc('}', out);
    x->shown++;
    return 0;
}

/* Реестр меток: «имя метка таблица» построчно — тот же разбор, что у registry_assign (spec.c),
 * и то же отсечение меток вне поля: такая запись осталась от сборки с другим полем и
 * сопоставлять её с записями conntrack нельзя. Только читается: conns ничего не раздаёт. */
static void conns_registry(struct ctnl_conns_ctx *x) {
    char path[PATH_MAX];
    snprintf(path, sizeof(path), "%s/registry", g_state_dir);
    FILE *f = fopen(path, "r");
    if (!f) return;
    char name[32];
    unsigned mark;
    int table;
    while (x->reg_n < sizeof(x->reg) / sizeof(x->reg[0]) &&
           fscanf(f, "%31s %x %d\n", name, &mark, &table) == 3) {
        if (!mark || (mark & ~STEER_MARK_MASK)) continue;
        snprintf(x->reg[x->reg_n].name, sizeof(x->reg[0].name), "%s", name);
        x->reg[x->reg_n++].mark = mark;
    }
    fclose(f);
}

/* Печать ответа `steer conns`. 0 — готово; 1 — conntrack недоступен (нет сокета
 * NETLINK_NETFILTER, модуля nf_conntrack_netlink или прав), причина — в stderr, stdout пуст. */
int ctnl_conns_print(FILE *out) {
    static struct ctnl_conns_ctx x;
    memset(&x, 0, sizeof(x));
    x.out = out;
    conns_registry(&x);
    int dfd = ctnl_socket();
    uint8_t *buf = malloc(CTNL_RCVBUF);
    if (dfd < 0 || !buf) {
        fprintf(stderr, "steer[warn] conns: нет сокета ctnetlink (%s)\n", strerror(errno));
        if (dfd >= 0) close(dfd);
        free(buf);
        return 1;
    }
    /* Ответ копится в памяти, а не пишется по ходу: разговор с ядром может оборваться на
     * втором семействе, и тогда в stdout не должно остаться половины JSON. */
    char *mem = NULL;
    size_t memn = 0;
    FILE *m = open_memstream(&mem, &memn);
    if (!m) { close(dfd); free(buf); return 1; }
    x.out = m;
    static const uint8_t fam[] = { AF_INET, AF_INET6 };
    uint32_t seq = (uint32_t)time(NULL);
    int rc = 0;
    for (size_t i = 0; i < sizeof(fam) && rc == 0; i++)
        rc = ctnl_dump(dfd, fam[i], 0, 0, 0, &seq, buf, ctnl_conns_rec, &x);
    fclose(m);
    close(dfd);
    free(buf);
    if (rc != 0) {
        fprintf(stderr, "steer[warn] conns: conntrack не ответил на дамп — нет модуля "
                        "nf_conntrack_netlink или прав\n");
        free(mem);
        return 1;
    }
    fprintf(out, "{\"schema\":1,\"conns\":[%s],\"shown\":%d,\"total\":%d,\"truncated\":%s}\n",
            mem ? mem : "", x.shown, x.total, x.total > x.shown ? "true" : "false");
    free(mem);
    return 0;
}
