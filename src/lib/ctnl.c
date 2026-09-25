#include "ctnl.h"
#include <arpa/inet.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/time.h>
#include <time.h>
#include <unistd.h>
#include <linux/netlink.h>
#include <linux/netfilter/nfnetlink.h>
#include <linux/netfilter/nfnetlink_conntrack.h>
#include "nlbuf.h"

const struct nlattr *ct_attr(const uint8_t *p, const uint8_t *end, int type) {
    if (!p) return NULL;
    while (p + NLA_HDRLEN <= end) {
        const struct nlattr *x = (const struct nlattr *)p;
        if (x->nla_len < NLA_HDRLEN || p + x->nla_len > end) return NULL;
        if ((x->nla_type & NLA_TYPE_MASK) == type) return x;
        p += NLA_ALIGN(x->nla_len);
    }
    return NULL;
}
const struct nlattr *ct_attr_in(const struct nlattr *in, int type) {
    if (!in) return NULL;
    return ct_attr((const uint8_t *)in + NLA_HDRLEN, (const uint8_t *)in + in->nla_len, type);
}

/* ---- снятие записей conntrack выхода: ctnetlink без инструмента conntrack -------------
 *
 * ЗАЧЕМ ЗДЕСЬ. Снимать соединения выхода при смене его маршрута нужно сторожу
 * (conntrack_evict в failover.c, там же — почему снимать вообще). До сих пор это делал
 * внешний `conntrack -D --mark`, а его нет в образе Android: на телефоне смена выхода
 * оставляла уже установленные соединения на прежнем, возможно мёртвом, выходе до их
 * естественной смерти — то есть долгие соединения мессенджеров висели минутами. Разбор
 * атрибутов (ct_attr, выше) и построитель сообщений (nlbuf) — общий разговор с ctnetlink,
 * которым пользуется и исходное назначение резолвера (src/dnsd/origdst.c), и список
 * соединений `steer conns` (src/daemon/conns.c, через ctnl_dump ниже); снятие берёт ту же
 * пару, а не собственную копию раскладки атрибута.
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

int ctnl_socket(void) {
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

int ctnl_dump(int dfd, uint8_t family, int filter, uint32_t val, uint32_t mask,
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
uint32_t ct_mark_of(const uint8_t *a, const uint8_t *end) {
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
