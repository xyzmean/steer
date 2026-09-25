#include "ctnl.h"
#include "jsonw.h"
#include "spec.h"
#include <arpa/inet.h>
#include <errno.h>
#include <limits.h>
#include <string.h>
#include <time.h>
#include <unistd.h>
#include <linux/netlink.h>
#include <linux/netfilter/nfnetlink_conntrack.h>

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
    if (on) jsonw_str_ascii(out, on);
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
