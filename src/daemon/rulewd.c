/* Страж правил выходов: чужое удаление наших ip rule демон замечает сам и возвращает правила.
 *
 * ЗАЧЕМ. netd на телефоне при каждом своём (пере)запуске стирает все правила маршрутизации,
 * кроме приоритета 0 (RouteController::Init → flushRules), и перестраивает свои цепочки iptables —
 * вместе с ними пропадают правила fwmark наших выходов (приоритет 9000) и masquerade. До этого
 * их возвращал только очередной проход сторожа («маршрутизация разъехалась») — через минуту, а
 * masquerade — через десять; всё это время помеченный трафик уходил напрямую, мимо туннеля. На
 * роутере то же делает чужой `ip rule flush` (скрипт, другой пакет маршрутизации). Поэтому механизм
 * один на обе платформы и живёт в демоне-движке (`--watch`).
 *
 * СОБЫТИЯ. Отдельный сокет rtnetlink на группы RTNLGRP_IPV4_RULE и RTNLGRP_IPV6_RULE (IPv6 —
 * задел: свои правила IPv6 движок пока не ставит, и проверка ниже смотрит только IPv4). Фильтр BPF
 * на сокете пропускает из ядра только RTM_DELRULE: netd добавляет и снимает свои правила на каждой
 * смене сети, и будить демон ради чужих добавлений незачем. Из удалений повод — только наше
 * правило: метка в поле меток движка с нашей маской (STEER_MARK_MASK) или, где приоритет свой
 * (телефон, rule_pref), правило с меткой на этом приоритете. Правило пробы сторожа (from-правило
 * без метки) поводом не бывает.
 *
 * ПАЧКА — ОДНА ПОЧИНКА. flush снимает правила по одному, и событий приходит пачка. Проверка
 * идёт через секунду после последнего события пачки, но не позже двух секунд после первого:
 * правило возвращается за три секунды даже тогда, когда кто-то снимает правила без остановки.
 *
 * СВОИ УДАЛЕНИЯ — НЕ ПОВОД. Демон и сам снимает правила: apply-сверка — правило убранного выхода
 * (--drop) и лишние копии (rule_ensure), сторож — правило выхода в отказе с on_fail=direct, `steer
 * down` — все. Флаг «идёт своя операция» здесь не годится один: событие своего удаления приходит
 * асинхронно, а проход сторожа и init с `steer down` — не команды очереди. Поэтому решает не
 * событие, а сверка с ожидаемым набором, и событие только зовёт её:
 *   правило выхода ОБЯЗАНО стоять, если таблица выхода чем-то занята — маршрутом на устройство,
 *   запретом или запасным запретом (STEER_BACKSTOP_METRIC). Все наши собственные снятия правила
 *   сбрасывают и таблицу (apply --drop, отказ direct у сторожа, `steer down`), а лишние копии
 *   снимаются, только когда верная стоит. Чужое снятие таблицу не трогает — netd правил своих
 *   таблиц не касается, `ip rule flush` маршрутов не снимает. «Правила нет, а таблица занята» —
 *   значит, правило сняли не мы.
 * Сверка — два дампа rtnetlink в процессе (rtnl_rules_text, rtnl_routes_text) и разбор тем же
 * route_facts_of, которым сверяет маршрутизацию сторож, — без единого процесса. Пока идёт своя
 * изменяющая команда (посреди apply-commit правило бывает уже снято, а таблица ещё не сброшена),
 * проверка ждёт её конца (rulewd_kick). Таблицы движка в ядре нет — движок снят целиком (`steer
 * down`), и возвращать правила, которые никуда не ведут, незачем.
 *
 * ЧИНИТ сервер сокета (ctl.c, починка в очереди изменяющих команд): ребёнок `apply-commit --rule
 * <выходы> --masq-ensure` — правило тем же rule_ensure, что у apply, masquerade тем же
 * iptables_masq_ensure, что у сторожа. Таблица не перепривязывается: она цела (это условие
 * починки), а в ней может стоять запрет сторожа при on_fail=drop, который перепривязка к
 * устройству сняла бы до следующего прохода. После починки — внеочередной проход сторожа, который
 * сверяет остальное, и событие repaired подписчикам.
 *
 * БАТАРЕЯ. Сокет открыт, только пока движок включён: выключенному стражу нечего стеречь (правила
 * снял init), и событие чужих правил не будит демон. Таймер — только на время пачки. */
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <stdint.h>
#include <sys/socket.h>
#include <sys/epoll.h>
#include <linux/netlink.h>
#include <linux/rtnetlink.h>
#include <linux/fib_rules.h>
#include <linux/filter.h>

#include "platform.h"
#include "spec.h"
#include "loop.h"
#include "state.h"
#include "rtnl.h"
#include "recon.h"
#include "failover_int.h"
#include "rulewd.h"

/* Тишина после последнего события пачки и предел от первого. */
#define RULEWD_QUIET_MS 1000
#define RULEWD_MAX_MS   2000

struct rulewd {
    struct steerd *d;
    struct loop *l;
    struct rulewd_conf cf;
    int on;
    int nl;
    struct loop_timer *tm;
    int pending;                  /* было наше удаление — нужна проверка */
    long first;                   /* когда пришло первое событие пачки, мс монотонных */
};

/* ---- проверка ------------------------------------------------------------------------------ */

int rulewd_missing(const struct spec *sp, char *list, size_t n) {
    static char rules[16384], routes[8192];
    if (n) list[0] = '\0';
    if (!sp) return 0;
    if (rtnl_rules_text(rules, sizeof(rules)) != 0 || !rules[0]) return -1;
    int cnt = 0;
    size_t k = 0;
    for (size_t i = 0; i < sp->out_n; i++) {
        const struct output *o = &sp->out[i];
        if (!out_has_device(o) || !o->mark || !o->table) continue;
        if (rtnl_routes_text(o->table, routes, sizeof(routes)) != 0) return -1;
        struct route_facts f = route_facts_of(rules, routes, o->mark, o->table);
        if (!f.known) return -1;
        /* Таблица пуста — правило снято вместе с ней, и это наше решение (см. шапку). */
        if (f.rule || (f.table == TBL_EMPTY && !f.backstop)) continue;
        int w = snprintf(list + k, n > k ? n - k : 0, "%s%s", cnt ? "," : "", o->name);
        if (w > 0 && k + (size_t)w < n) k += (size_t)w;
        cnt++;
    }
    return cnt;
}

static void rulewd_check(struct rulewd *r) {
    struct steerd *d = r->d;
    r->pending = 0;
    if (!r->on || !d->have) return;
    /* Таблицы движка нет — движок снят целиком (`steer down`): правила вести некуда. Спросить не
     * вышло (-1) — проверяем как обычно. */
    uint64_t h;
    if (recon_table_handle(nft_table(), &h) == 1) return;
    char list[512];
    if (rulewd_missing(d->sp, list, sizeof(list)) > 0) r->cf.repair(r->cf.arg);
}

static void rulewd_timer(struct loop *l, struct loop_timer *t, void *arg) {
    (void)l; (void)t;
    struct rulewd *r = arg;
    if (!r->pending) return;
    /* Своя операция идёт — проверка после неё (rulewd_kick из конца операции). */
    if (r->cf.busy && r->cf.busy(r->cf.arg)) return;
    rulewd_check(r);
}

/* ---- события ------------------------------------------------------------------------------- */

/* Наше ли снятое правило (см. шапку, «СОБЫТИЯ»). */
static int rule_is_ours(const struct nlmsghdr *h) {
    const struct fib_rule_hdr *fr = NLMSG_DATA(h);
    size_t hl = NLMSG_ALIGN(sizeof(*fr));
    if (h->nlmsg_len < NLMSG_HDRLEN + hl) return 0;
    uint32_t mark = 0, mask = 0xffffffffu, prio = 0;
    int have_mark = 0;
    const char *p = (const char *)fr + hl, *e = (const char *)h + h->nlmsg_len;
    while (p + sizeof(struct rtattr) <= e) {
        const struct rtattr *a = (const struct rtattr *)p;
        if (a->rta_len < sizeof(*a) || p + a->rta_len > e) break;
        if (RTA_PAYLOAD(a) >= 4) {
            uint32_t v;
            memcpy(&v, RTA_DATA(a), 4);
            if (a->rta_type == FRA_FWMARK) { mark = v; have_mark = 1; }
            else if (a->rta_type == FRA_FWMASK) mask = v;
            else if (a->rta_type == FRA_PRIORITY) prio = v;
        }
        p += RTA_ALIGN(a->rta_len);
    }
    if (!have_mark || !(mark & STEER_MARK_MASK)) return 0;
    if (mask == STEER_MARK_MASK && !(mark & ~STEER_MARK_MASK)) return 1;
    return STEER_RULE_PREF && prio == (uint32_t)STEER_RULE_PREF;
}

static void rulewd_nl(struct loop *l, int fd, uint32_t ev, void *arg) {
    (void)l; (void)ev;
    struct rulewd *r = arg;
    char buf[8192];
    int ours = 0;
    for (;;) {
        ssize_t m = recv(fd, buf, sizeof(buf), 0);
        if (m < 0 && errno == EINTR) continue;
        /* Переполнение: события потеряны — среди них могли быть и наши. */
        if (m < 0 && errno == ENOBUFS) { ours = 1; continue; }
        if (m <= 0) break;
        for (struct nlmsghdr *h = (struct nlmsghdr *)buf; NLMSG_OK(h, (size_t)m);
             h = NLMSG_NEXT(h, m))
            if (h->nlmsg_type == RTM_DELRULE && rule_is_ours(h)) ours = 1;
    }
    if (!ours || !r->on) return;
    long now = loop_now_ms();
    if (!r->pending) { r->pending = 1; r->first = now; }
    long left = r->first + RULEWD_MAX_MS - now;
    loop_timer_set(r->tm, left < RULEWD_QUIET_MS ? (left > 0 ? left : 0) : RULEWD_QUIET_MS);
}

/* Сокет на группы правил IPv4 и IPv6 с фильтром «только RTM_DELRULE». -1 — не открылся. */
static int rulewd_open(void) {
    int fd = socket(AF_NETLINK, SOCK_RAW | SOCK_CLOEXEC | SOCK_NONBLOCK, NETLINK_ROUTE);
    if (fd < 0) return -1;
    /* Фильтр ядру: сообщение уведомления правил — одно на пакет, тип — u16 по смещению 4
     * (nlmsghdr.nlmsg_type, порядок байт хоста: BPF_H в сокетном фильтре читает сетевой, поэтому
     * сравнение — с обоими видами). Не встал фильтр — живём без него: разбор ниже тот же. */
    uint16_t t = RTM_DELRULE;
    uint16_t sw = (uint16_t)((t >> 8) | (t << 8));
    struct sock_filter code[] = {
        BPF_STMT(BPF_LD | BPF_H | BPF_ABS, 4),
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, t, 2, 0),
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, sw, 1, 0),
        BPF_STMT(BPF_RET | BPF_K, 0),
        BPF_STMT(BPF_RET | BPF_K, 0xffff),
    };
    struct sock_fprog prog = { (unsigned short)(sizeof(code) / sizeof(code[0])), code };
    setsockopt(fd, SOL_SOCKET, SO_ATTACH_FILTER, &prog, sizeof(prog));
    struct sockaddr_nl a;
    memset(&a, 0, sizeof(a));
    a.nl_family = AF_NETLINK;
    a.nl_groups = (1u << (RTNLGRP_IPV4_RULE - 1)) | (1u << (RTNLGRP_IPV6_RULE - 1));
    if (bind(fd, (struct sockaddr *)&a, sizeof(a)) != 0) { close(fd); return -1; }
    return fd;
}

/* ---- заведение ---------------------------------------------------------------------------- */

struct rulewd *rulewd_start(struct steerd *d, const struct rulewd_conf *c, int on) {
    struct rulewd *r = calloc(1, sizeof(*r));
    if (!r) return NULL;
    r->d = d;
    r->l = d->loop;
    r->cf = *c;
    r->nl = -1;
    r->tm = loop_timer_new(r->l, rulewd_timer, r);
    if (!r->tm) { free(r); return NULL; }
    rulewd_enable(r, on);
    return r;
}

void rulewd_enable(struct rulewd *r, int on) {
    if (!r || r->on == !!on) return;
    r->on = !!on;
    if (on) {
        r->nl = rulewd_open();
        if (r->nl >= 0 && loop_fd_add(r->l, r->nl, EPOLLIN, rulewd_nl, r) != 0) {
            close(r->nl);
            r->nl = -1;
        }
        if (r->nl < 0)
            fprintf(stderr, "steer[warn] rules: события правил недоступны — снятые правила "
                            "вернёт только проход сторожа\n");
        return;
    }
    r->pending = 0;
    loop_timer_stop(r->tm);
    if (r->nl >= 0) {
        loop_fd_del(r->l, r->nl);
        close(r->nl);
        r->nl = -1;
    }
}

void rulewd_kick(struct rulewd *r) {
    if (!r || !r->pending || !r->on) return;
    loop_timer_set(r->tm, 0);
}
