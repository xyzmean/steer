/* Сторож выходов в демоне: `steer daemon --watch` вместо `steer failover --loop`.
 *
 * Шаг 3 устройства 1.8 (docs/architecture.md, «4а»): таймер и события netlink в цикле демона,
 * память выходов — в памяти демона. Проход тот же, что у `steer failover`, — автомат прохода
 * failover.c (fo_pass_start), а не его копия; отличается только то, где лежит память между
 * проходами (fostate.h), кто зовёт проход и куда уходят его новости.
 *
 * ВКЛЮЧАЕТСЯ ФЛАГОМ. До шага 6 procd и init по-прежнему держат `steer failover --loop`, а демон
 * на телефоне поднят всегда. Два сторожа сразу дрались бы за одни и те же таблицы выходов и
 * оживляли бы одни и те же устройства дважды, поэтому демон сторожит только с `--watch`, а
 * сервис, который его так запускает, обязан снять старый круг.
 *
 * ПРОХОД — В ЦИКЛЕ ДЕМОНА, БЕЗ FORK. Решение владельца: без процесса на проход. Проход —
 * конечный автомат на цикле демона: пробы (TCP connect, эхо ICMP из сырого или ping-сокета),
 * ожидание подъёма устройства (таймер шага и события netlink), внешние команды оживления
 * (ifdown/ifup, ubus — ребёнок на ДЕЙСТВИЕ, выход через loop_child), разрешение имени Endpoint
 * у awg (рабочий поток) — всё это ждётся шагами автомата, а не синхронно. Цикл демона во время
 * прохода свободен: status, subscribe, apply отвечают, пока проба ждёт ответа (стенд ctlmatch
 * меряет это пробой, которая ждёт три секунды), и проход по исправной спеке не запускает ни
 * одного процесса (тот же стенд считает процессы в своём пространстве PID). Устройство
 * автомата и что в нём по-прежнему синхронно — в failover.c, «ПРОХОД — КОНЕЧНЫЙ АВТОМАТ».
 *
 * Раньше (6c0cecf) проход шёл в ребёнке — копии демона без exec, с ответом по трубе: пробы и
 * оживление ждали синхронно, а неблокирующий проход был бы второй логикой рядом с
 * `steer failover`. Теперь автомат у них общий — `steer failover` крутит его на своём цикле до
 * конца прохода, — и копия с трубой ушли.
 *
 * Спека прохода — своя копия спеки демона (проход пишет в неё выбранные устройства, а apply
 * посреди прохода может заменить спеку демона); память — прямо память демона: проход кладёт
 * `active` в конце, и status посреди прохода видит прежний выбор целиком, а не половину.
 * Предел прохода остаётся (WATCHD_PASS_MAX_S): каждое ожидание автомата имеет свой срок, но
 * проход, который его всё же превысит, прерывается — с уборкой правила пробы и команды.
 *
 * РАСПИСАНИЕ — как у `failover --loop` (watch.c): первый проход при старте, следующий — через
 * период после конца предыдущего; событие сети (RTMGRP_LINK, адреса IPv4/IPv6) — внеочередной
 * проход через WATCH_SETTLE_S секунд после первого события пачки. На роутере (plat()->netifd)
 * события, пришедшие за время прохода, — следы его же ifdown/ifup, и они выбрасываются; на
 * телефоне сторож интерфейсы не трогает, и событие за время прохода настоящее — после прохода
 * ещё один через WATCH_SETTLE_S. Смена спеки в памяти демона (apply, reload, SIGHUP) — тоже
 * внеочередной проход: `failover --loop` перечитывал спеку на каждом проходе, демон — при смене.
 * В тишине демон просыпается только таймером периода (timerfd на CLOCK_MONOTONIC: во сне
 * устройства он стоит и не будит его) — не чаще, чем `--loop`.
 *
 * ВЫКЛЮЧЕННЫЙ ДВИЖОК — НОЛЬ ПРОБУЖДЕНИЙ (требование батареи телефона). Демон работает и при
 * выключенном движке — он же управляющий сокет, — но сторожить тогда нечего: правила снял init, а
 * трогать маршрутизацию нельзя. Раньше таймер периода тикал и так — просыпался, видел «выключен»
 * и заводился снова: раз в минуту ради ответа «нет». Теперь выключенный сторож не держит ни
 * таймера, ни сокета событий сети (событие сети будило бы его ради того же «нет»), и демон спит
 * в epoll_wait без срока до запроса по сокету. Положение выключателя сторожу говорит сервер
 * сокета (watchd_enable) — после apply, reload и SIGHUP, то есть тогда, когда init включает или
 * выключает движок; выключатель, сменившийся без reload, сторож замечает на ближайшем своём
 * таймере и засыпает сам. Без спеки — то же: проходить нечем, и первый проход зовёт прочитанная
 * спека.
 *
 * ПЕРВЫЙ ПРОХОД — ПОСЛЕ СТАРТОВОГО APPLY. С --apply демон при старте ставит спеку в ядро сам, и
 * проход раньше этого видел бы ядро без правил (их снял `steerd down` при остановке сервиса):
 * «маршрутизация разъехалась (правила fwmark нет)» у каждого выхода, выбор которого остался в
 * `active`, и «туннель молчит» у тех, чьи помощники ещё не подняты. Поэтому сторож заводится
 * придержанным (hold) и первый проход делает watchd_release — по концу стартового apply,
 * удачного или нет. Раньше тот же порядок держала только проверка «идёт изменяющая команда» в
 * таймере — случайно, а не по устройству.
 *
 * ПАМЯТЬ ВЫХОДОВ — в демоне: `active`, `latency`, `restart-*` (fostate.h) и замеры awg
 * (awg_hs_memory, как у `--loop`). status демона берёт выбор устройств отсюда. `active` при
 * этом ещё и отражается в файл — только при изменении, как и раньше: до шага 6 status, diag и
 * apply подкомандой (rpcd на роутере, дети демона) читают выбор сторожа из файла, и без него
 * apply привязал бы таблицу пула к первому кандидату в обход выбора сторожа. `latency` и
 * `restart-*` на диск больше не пишутся вовсе. При старте демон берёт `active` из файла — ровно
 * то, что увидел бы очередной `steer failover`, — и не перепривязывает выходы на пустом месте
 * (перепривязка снимает соединения выхода).
 *
 * ЗДОРОВЬЕ ПОМОЩНИКОВ (демон ещё и с --supervise). Помощники — дети демона, и их состояние он
 * знает по событиям из трубы (helpers.h, helper_state_of). Проход берёт его отсюда — источник
 * здоровья помощника в памяти (fostate.h), — а не из файлов probe-* и xsteer-*.json, которые
 * помощники с трубой событий и не пишут; обфускатор выхода interface оживляется перезапуском в
 * супервизоре демона (supd_restart), а не сигналом экземпляру procd через ubus. Смена состояния
 * помощника vless или xsteer (up, down, процесс вышел после up) — внеочередной проход через
 * WATCH_SETTLE_S, как событие сети: упавший туннель не ждёт периода. Без --supervise источник — прежние файлы.
 *
 * СОБЫТИЯ подписчикам (docs/ctl.md): switched, failed, revived — копятся за проход и уходят
 * после его конца, когда память выходов уже новая (подписчик, спросивший status по событию,
 * видит уже новое).
 *
 * MASQUERADE НА ТЕЛЕФОНЕ (plat()->iptables_masq): netd при перезапуске перестраивает iptables, и
 * правило masquerade пропадает — сторож его возвращает (iptables_masq_ensure в apply.c). Это
 * `iptables -C` на устройство, то есть процессы, и потому не на каждом проходе: после прохода
 * по событию сети или смене спеки и не реже раза в WATCH_MASQ_S (watch_masq_due в watch.c). */
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/epoll.h>

#include "platform.h"
#include "spec.h"
#include "awg.h"
#include "daemon.h"
#include "loop.h"
#include "state.h"
#include "fostate.h"
#include "helpers.h"
#include "watchd.h"

#define LOG_WW "steer[warn] watch: "

/* Проход дольше этого — зависание: каждое ожидание автомата имеет свой срок (пробы — секунды,
 * команда оживления — минута), так что сюда проход может прийти только очень длинным списком
 * мёртвых устройств. Прерывается с уборкой (fo_pass_abort). С запасом: восемь выходов по восемь
 * мёртвых устройств с оживлением и замером — это минуты, а не десять. */
#define WATCHD_PASS_MAX_S 600
/* Событий за проход — не больше, чем решений у выходов: по одному-два на выход. */
#define WATCHD_EV_MAX 64

/* ---- память выходов ------------------------------------------------------------------ */

struct fo_blob {
    char name[48];
    char *p;
    size_t n;
};

struct fo_mem {
    struct fo_store base;
    struct fo_blob *b;
    size_t n, cap;
    int mirror;          /* active — ещё и в файл (см. шапку) */
};

static struct fo_blob *mem_find(struct fo_mem *m, const char *name) {
    for (size_t i = 0; i < m->n; i++)
        if (!strcmp(m->b[i].name, name)) return &m->b[i];
    return NULL;
}

static FILE *mem_open_r(struct fo_store *st, const char *name) {
    struct fo_blob *b = mem_find((struct fo_mem *)st, name);
    /* Пустая запись — как пустой файл: читать нечего. fmemopen нулевой длины musl отвергает. */
    if (!b || !b->n) return NULL;
    return fmemopen(b->p, b->n, "r");
}

/* Положить запись; та же — ничего не делать (и в файл не писать). 0 — положено. */
static int mem_set(struct fo_mem *m, const char *name, const char *data, size_t n) {
    struct fo_blob *b = mem_find(m, name);
    if (b && b->n == n && (!n || !memcmp(b->p, data, n))) return 1;
    if (strlen(name) >= sizeof(b->name)) return -1;
    char *p = malloc(n ? n : 1);
    if (!p) return -1;
    if (n) memcpy(p, data, n);
    if (!b) {
        if (m->n == m->cap) {
            size_t nc = m->cap ? m->cap * 2 : 16;
            struct fo_blob *nb = realloc(m->b, nc * sizeof(*nb));
            if (!nb) { free(p); return -1; }
            m->b = nb;
            m->cap = nc;
        }
        b = &m->b[m->n++];
        snprintf(b->name, sizeof(b->name), "%s", name);
        b->p = NULL;
    }
    free(b->p);
    b->p = p;
    b->n = n;
    return 0;
}

static void mem_put(struct fo_store *st, const char *name, const char *data, size_t n) {
    struct fo_mem *m = (struct fo_mem *)st;
    if (mem_set(m, name, data, n) == 0 && m->mirror && !strcmp(name, "active"))
        fo_store_files.ops->put(&fo_store_files, name, data, n);
}

static const struct fo_store_ops mem_ops = { mem_open_r, mem_put };

/* ---- здоровье помощников из памяти супервизора (fostate.h) ---------------------------------- */

struct fo_hmem {
    struct fo_hsrc base;
    struct steerd *d;
};

/* Помощник, которого демон не держит (вид без команды в этой сборке, движок выключен), —
 * прежним путём, по файлам: пишет их тот, кто его поднял. */
static int hmem_state(struct fo_hsrc *hs, const char *out, struct fo_hstate *h) {
    const struct helper_state *st = helper_state_of(((struct fo_hmem *)hs)->d, out);
    if (!st) return fo_hsrc_files.ops->state(&fo_hsrc_files, out, h);
    h->node = h->total = 0;
    if (st->nonode) {
        h->st = FO_HS_NONODE;
        h->node = (int)st->nonode;
        h->total = (int)st->total;
    } else if (!st->running) {
        h->st = FO_HS_DOWN;
    } else if (st->up) {
        h->st = FO_HS_UP;
    } else if (st->known) {
        h->st = FO_HS_DOWN;
    } else if (st->node > 0) {
        h->st = FO_HS_PROBING;
        h->node = (int)st->node;
        h->total = (int)st->total;
    } else {
        h->st = FO_HS_STARTING;
    }
    return 0;
}

/* Туннель xsteer, поднятый netifd, — не ребёнок демона: его клиент пишет файл, как и раньше. */
static int hmem_xsdev(struct fo_hsrc *hs, const char *dev, int *up, int *fresh) {
    (void)hs;
    return fo_hsrc_files.ops->xsdev(&fo_hsrc_files, dev, up, fresh);
}

static int hmem_restart(struct fo_hsrc *hs, const char *out, const char *cmd) {
    return supd_restart(((struct fo_hmem *)hs)->d->sup, out, cmd);
}

static const struct fo_hsrc_ops hmem_ops = {
    hmem_state, hmem_xsdev, hmem_restart, "процесс туннеля поднимет заново демон",
};


/* ---- сторож ---------------------------------------------------------------------------- */

/* Событие прохода, отложенное до его конца (см. шапку). */
struct wev {
    enum fo_ev_kind kind;
    char out[48], from[48], to[48], why[24], of[16];
};

struct watchd {
    struct steerd *d;
    struct loop *l;
    struct watchd_conf cf;
    int nl;                       /* netlink; -1 — живём одним периодом */
    struct loop_timer *tm;        /* следующий проход: период или успокоение после события */
    struct loop_timer *kill_tm;   /* срок идущего прохода */
    int settling;                 /* tm стоит на успокоении, а не на периоде */
    int pending;                  /* после идущего прохода нужен ещё один */
    int eventful;                 /* проход идёт по событию сети или смене спеки */
    int on;                       /* движок включён: без этого ни таймера, ни сокета событий */
    int hold;                     /* первый проход ждёт конца стартового apply (watchd_release) */
    unsigned long passes;         /* проходов с начала — первый отмечается в журнале */
    struct fo_run *run;           /* идущий проход; NULL — нет */
    struct spec *sp;              /* копия спеки для прохода */
    struct wev ev[WATCHD_EV_MAX];
    int ev_n;
    long masq_at;                 /* когда последний раз возвращали masquerade (телефон) */
    struct fo_mem mem;
    struct fo_hmem hmem;          /* здоровье помощников — у супервизора демона (--supervise) */
};

static void watchd_pass_start(struct watchd *w);

/* Сторож спит: движок выключен или первый проход ждёт стартового apply. Ни один таймер тогда
 * не заводится — ни успокоение, ни период (см. шапку, «ВЫКЛЮЧЕННЫЙ ДВИЖОК»). */
static int watchd_dormant(const struct watchd *w) {
    return !w->on || w->hold;
}

static void watchd_settle(struct watchd *w) {
    w->eventful = 1;
    if (watchd_dormant(w)) return;
    if (w->settling) return;      /* пачка уже ждёт своего прохода — срок не отодвигаем */
    w->settling = 1;
    loop_timer_set(w->tm, WATCH_SETTLE_S * 1000L);
}

static void watchd_period(struct watchd *w) {
    w->settling = 0;
    if (watchd_dormant(w)) { loop_timer_stop(w->tm); return; }
    loop_timer_set(w->tm, w->cf.period_s * 1000L);
}

static void watchd_timer(struct loop *l, struct loop_timer *t, void *arg) {
    (void)l; (void)t;
    struct watchd *w = arg;
    w->settling = 0;
    if (w->run) return;           /* не бывает: таймер снят на время прохода */
    /* Спеки нет — проходить нечем, и тикать впустую незачем: прочитанная спека (apply, reload,
     * SIGHUP) сама позовёт проход через watchd_spec_changed. Выключатель сменился без
     * reload — сторож засыпает сам, а не проверяет его раз в период. */
    if (!w->d->have) return;
    if (w->cf.enabled && !w->cf.enabled()) { watchd_enable(w, 0); return; }
    if (w->cf.busy && w->cf.busy(w->cf.busy_arg)) { watchd_settle(w); return; }
    if (w->nl >= 0) watch_nl_drain(w->nl);   /* пачка, ради которой ждали, — в этот проход */
    watchd_pass_start(w);
}

static void watchd_nl(struct loop *l, int fd, uint32_t ev, void *arg) {
    (void)l; (void)ev;
    struct watchd *w = arg;
    if (!watch_nl_drain(fd)) return;
    if (watchd_dormant(w)) return;
    /* Во время прохода: на роутере — следы его же ifdown/ifup (выбрасываются после прохода),
     * на телефоне — настоящее событие, и после прохода нужен ещё один. */
    if (w->run) {
        if (!plat()->netifd) w->pending = 1;
        return;
    }
    watchd_settle(w);
}

void watchd_spec_changed(struct watchd *w) {
    if (!w || watchd_dormant(w)) return;
    if (w->run) w->pending = 1;
    else watchd_settle(w);
}

void watchd_helper_changed(struct watchd *w) {
    watchd_spec_changed(w);
}

/* ---- проход ------------------------------------------------------------------------------ */

/* Событие прохода — в очередь до конца прохода. */
static void watchd_ev(void *arg, const struct fo_event *e) {
    struct watchd *w = arg;
    if (w->ev_n >= WATCHD_EV_MAX) return;
    struct wev *q = &w->ev[w->ev_n++];
    q->kind = e->kind;
    snprintf(q->out, sizeof(q->out), "%s", e->out ? e->out : "");
    snprintf(q->from, sizeof(q->from), "%s", e->from ? e->from : "");
    snprintf(q->to, sizeof(q->to), "%s", e->to ? e->to : "");
    snprintf(q->why, sizeof(q->why), "%s", e->why ? e->why : "");
    snprintf(q->of, sizeof(q->of), "%s", e->on_fail ? e->on_fail : "");
}

/* Одно событие прохода — подписчикам (поля — docs/ctl.md). */
static void watchd_emit(struct watchd *w, const struct wev *q) {
    char out[112], from[112], to[112], why[64], of[48], f[640];
    steerd_json_str(out, sizeof(out), q->out);
    if (q->from[0]) steerd_json_str(from, sizeof(from), q->from); else strcpy(from, "null");
    if (q->to[0]) steerd_json_str(to, sizeof(to), q->to); else strcpy(to, "null");
    steerd_json_str(why, sizeof(why), q->why);
    steerd_json_str(of, sizeof(of), q->of);
    switch (q->kind) {
    case FO_EV_SWITCHED:
        snprintf(f, sizeof(f), ",\"out\":%s,\"from\":%s,\"to\":%s,\"why\":%s", out, from, to, why);
        steerd_emit(w->d, "switched", f);
        break;
    case FO_EV_FAILED:
        snprintf(f, sizeof(f), ",\"out\":%s,\"from\":%s,\"on_fail\":%s,\"why\":%s", out, from, of, why);
        steerd_emit(w->d, "failed", f);
        break;
    case FO_EV_REVIVED:
        snprintf(f, sizeof(f), ",\"out\":%s,\"dev\":%s", out, to);
        steerd_emit(w->d, "revived", f);
        break;
    }
}

static void watchd_after(struct watchd *w) {
    w->run = NULL;
    loop_timer_stop(w->kill_tm);
    /* Память выходов уже новая — теперь события (см. шапку). */
    int n = w->ev_n;
    w->ev_n = 0;
    for (int i = 0; i < n; i++) watchd_emit(w, &w->ev[i]);
    /* masquerade правилом iptables (телефон) — см. шапку: не на каждом проходе. */
    if (plat()->iptables_masq && w->d->have && watch_masq_due(&w->masq_at, w->eventful))
        iptables_masq_ensure(w->d->sp);
    w->eventful = 0;
    /* На роутере события за время прохода — следы его же ifdown/ifup (см. шапку). */
    if (plat()->netifd && w->nl >= 0) watch_nl_drain(w->nl);
    if (w->pending) {
        w->pending = 0;
        watchd_settle(w);
    } else {
        watchd_period(w);
    }
}

static void watchd_pass_done(void *arg, int res) {
    (void)res;
    watchd_after(arg);
}

static void watchd_kill(struct loop *l, struct loop_timer *t, void *arg) {
    (void)l; (void)t;
    struct watchd *w = arg;
    if (!w->run) return;
    fprintf(stderr, LOG_WW "проход идёт дольше %d с — прерываю\n", WATCHD_PASS_MAX_S);
    fo_pass_abort(w->run);
    /* Выбор прерванного прохода не записан (active кладётся в конце) — и его события тоже не
     * уходят: следующий проход решит заново и скажет сам. */
    w->ev_n = 0;
    watchd_after(w);
}

static void watchd_pass_start(struct watchd *w) {
    if (!w->sp) w->sp = malloc(sizeof(*w->sp));
    if (!w->sp) {
        fprintf(stderr, LOG_WW "нет памяти под проход\n");
        watchd_period(w);
        return;
    }
    /* Проход меняет device у выходов — своя копия, а спека демона остаётся нетронутой для
     * status и masquerade (они смотрят на спеку так, как её прочитал бы свежий процесс). */
    memcpy(w->sp, w->d->sp, sizeof(*w->sp));
    w->ev_n = 0;
    if (!w->passes++) fprintf(stderr, "steer[info] watch: первый проход\n");
    loop_timer_stop(w->tm);
    w->run = fo_pass_start(w->l, w->sp, &w->mem.base, 0, watchd_ev, w, watchd_pass_done, w);
    if (!w->run) {
        fprintf(stderr, LOG_WW "нет памяти под проход\n");
        watchd_period(w);
        return;
    }
    /* Супервизор заводится после сторожа — спрашивается на каждый проход. */
    if (w->d->sup) fo_pass_helpers(w->run, &w->hmem.base);
    loop_timer_set(w->kill_tm, WATCHD_PASS_MAX_S * 1000L);
}

/* ---- заведение и уход ------------------------------------------------------------------ */

/* Сокет событий сети: открыт, только пока движок включён. */
static void watchd_nl_up(struct watchd *w) {
    if (w->nl >= 0) return;
    w->nl = watch_nl_open();
    if (w->nl >= 0 && loop_fd_add(w->l, w->nl, EPOLLIN, watchd_nl, w) != 0) {
        close(w->nl);
        w->nl = -1;
    }
    if (w->nl < 0)
        fprintf(stderr, LOG_WW "события сети недоступны — проход только по периоду\n");
}

static void watchd_nl_down(struct watchd *w) {
    if (w->nl < 0) return;
    loop_fd_del(w->l, w->nl);
    close(w->nl);
    w->nl = -1;
}

struct watchd *watchd_start(struct steerd *d, const struct watchd_conf *c, int on, int hold) {
    struct watchd *w = calloc(1, sizeof(*w));
    if (!w) return NULL;
    w->d = d;
    w->l = d->loop;
    w->cf = *c;
    if (w->cf.period_s <= 0) w->cf.period_s = 60;
    w->mem.base.ops = &mem_ops;
    w->hmem.base.ops = &hmem_ops;
    w->hmem.d = d;
    w->tm = loop_timer_new(w->l, watchd_timer, w);
    w->kill_tm = loop_timer_new(w->l, watchd_kill, w);
    if (!w->tm || !w->kill_tm) {
        loop_timer_free(w->tm);
        loop_timer_free(w->kill_tm);
        free(w);
        return NULL;
    }
    /* Выбор устройств, оставленный прежним сторожем (или этим же демоном до перезапуска), —
     * как его увидел бы очередной `steer failover`. */
    FILE *f = fo_store_files.ops->open_r(&fo_store_files, "active");
    if (f) {
        char buf[MAX_OUTPUTS * 80 + 1];
        size_t n = fread(buf, 1, sizeof(buf), f);
        fclose(f);
        if (n < sizeof(buf)) mem_set(&w->mem, "active", buf, n);
    }
    w->mem.mirror = 1;
    /* Замеры awg — в памяти процесса, как у `failover --loop`. */
    awg_hs_memory(1);
    /* Правило пробы, оставшееся от сторожа, убитого SIGKILL (прежний круг, прежний демон), —
     * один раз при старте: свои правила проход снимает сам (и при отмене). */
    cleanup_probe_rule();
    w->nl = -1;
    d->outs = &w->mem.base;
    d->watch = w;
    w->eventful = 1;              /* первый проход — как по событию: masquerade проверить */
    w->hold = hold;
    if (on) watchd_enable(w, 1);
    return w;
}

void watchd_enable(struct watchd *w, int on) {
    if (!w || w->on == !!on) return;
    w->on = !!on;
    if (on) {
        watchd_nl_up(w);
        w->eventful = 1;
        w->settling = 0;
        if (!w->hold) loop_timer_set(w->tm, 0);
        return;
    }
    /* Выключили: маршрутизацию трогать больше нельзя — идущий проход прерывается с уборкой
     * правила пробы, его события не уходят (решения прерванного прохода не записаны). */
    if (w->run) {
        fo_pass_abort(w->run);
        w->run = NULL;
        w->ev_n = 0;
    }
    loop_timer_stop(w->kill_tm);
    loop_timer_stop(w->tm);
    w->settling = w->pending = 0;
    watchd_nl_down(w);
}

void watchd_release(struct watchd *w) {
    if (!w || !w->hold) return;
    w->hold = 0;
    if (!w->on || w->run) return;
    w->eventful = 1;
    w->settling = 0;
    loop_timer_set(w->tm, 0);
}

void watchd_stop(struct watchd *w) {
    if (w && w->run) {
        fo_pass_abort(w->run);
        w->run = NULL;
    }
}
