/* Сторож выходов в демоне: `steer daemon --watch` вместо `steer failover --loop`.
 *
 * Шаг 3 устройства 1.8 (docs/architecture.md, «4а»): таймер и события netlink в цикле демона,
 * память выходов — в памяти демона. Проход тот же, что у `steer failover`, — failover_pass
 * (failover.c), а не его копия; отличается только то, где лежит память между проходами
 * (fostate.h), кто зовёт проход и куда уходят его новости.
 *
 * ВКЛЮЧАЕТСЯ ФЛАГОМ. До шага 6 procd и init по-прежнему держат `steer failover --loop`, а демон
 * на телефоне поднят всегда. Два сторожа сразу дрались бы за одни и те же таблицы выходов и
 * оживляли бы одни и те же устройства дважды, поэтому демон сторожит только с `--watch`, а
 * сервис, который его так запускает, обязан снять старый круг.
 *
 * ПРОХОД — В ОТДЕЛЬНОМ ПРОЦЕССЕ (fork без exec), ответ — по трубе. Выбирали из трёх:
 *
 *   1) неблокирующие пробы в цикле демона — TCP connect в epoll, ICMP через SOCK_DGRAM/
 *      IPPROTO_ICMP. Пробы — не единственное, что в проходе ждёт. Порядок проб зависит от их
 *      ответов (первое здоровое останавливает перебор, гистерезис спрашивает текущее, замер —
 *      всех, выход с via спрашивается после цели), а оживление — это ifdown/ifup, сигнал
 *      помощнику через ubus и до десяти секунд ожидания подъёма, у awg — перенастройка через
 *      netlink ядра. Сделать всё это неблокирующим значило бы переписать проход автоматом
 *      состояний рядом с прежним, то есть завести вторую логику, которая разойдётся с первой
 *      молча, — а `steer failover` до шага 6 обязан жить;
 *   2) пробы ребёнком (ping через loop_child) при решениях в демоне — то же дробление прохода
 *      на шаги, только ожидание переезжает в ребёнка;
 *   3) проход целиком в ребёнке — выбран. Ребёнок — копия демона: спека, группы и память
 *      выходов у него уже есть (копией при fork, без чтения файлов), и он исполняет тот же
 *      failover_pass, который исполняет `steer failover`. Назад по трубе он отдаёт новую память
 *      выходов, события прохода и замеры awg; демон принимает их целиком или никак (проход,
 *      умерший на полпути, не оставляет полупамяти). Действия над ядром (ip rule/route,
 *      conntrack) делает тот же ребёнок — посреди прохода, как и раньше, иначе решения прохода
 *      пришлось бы откладывать до его конца.
 *
 *   Цикл демона во время прохода свободен: status, subscribe, apply отвечают, пока ребёнок ждёт
 *   ping или подъёма туннеля (стенд ctlmatch меряет это пробой, которая спит три секунды). Цена
 *   — fork раз в период: копия при записи, без exec и без разбора спеки, доли миллисекунды раз
 *   в минуту. Прежний довод fork у `failover --loop` (глобальные массивы спеки) здесь ни при
 *   чём: память между проходами живёт у демона, ребёнок её только читает и возвращает.
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
 * ПАМЯТЬ ВЫХОДОВ — в демоне: `active`, `latency`, `restart-*` (fostate.h) и замеры awg
 * (awg_hs_memory, как у `--loop`). status демона берёт выбор устройств отсюда. `active` при
 * этом ещё и отражается в файл — только при изменении, как и раньше: до шага 6 status, diag и
 * apply подкомандой (rpcd на роутере, дети демона) читают выбор сторожа из файла, и без него
 * apply привязал бы таблицу пула к первому кандидату в обход выбора сторожа. `latency` и
 * `restart-*` на диск больше не пишутся вовсе. При старте демон берёт `active` из файла — ровно
 * то, что увидел бы очередной `steer failover`, — и не перепривязывает выходы на пустом месте
 * (перепривязка снимает соединения выхода).
 *
 * СОБЫТИЯ подписчикам (docs/ctl.md): switched, failed, revived — строками из прохода, после того
 * как демон принял его память (подписчик, спросивший status по событию, видит уже новое). */
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <fcntl.h>
#include <signal.h>
#include <dirent.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <sys/epoll.h>

#include "platform.h"
#include "spec.h"
#include "awg.h"
#include "daemon.h"
#include "loop.h"
#include "state.h"
#include "fostate.h"
#include "watchd.h"

#define LOG_WW "steer[warn] watch: "

/* Проход дольше этого — зависание (nft, ip, помощник, не отвечающий ubus): ребёнка убиваем, и
 * следующий проход начнётся с уборки правила пробы (failover_pass_guard). С запасом: восемь
 * выходов по восемь мёртвых устройств с оживлением и замером — это минуты, а не десять. */
#define WATCHD_PASS_MAX_S 600
/* Предел ответа прохода: память выходов — десятки строк, события — по строке. */
#define WATCHD_MSG_MAX (1 << 20)

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

static void mem_clear(struct fo_mem *m) {
    for (size_t i = 0; i < m->n; i++) free(m->b[i].p);
    free(m->b);
    m->b = NULL;
    m->n = m->cap = 0;
}

/* ---- сторож ---------------------------------------------------------------------------- */

struct watchd {
    struct steerd *d;
    struct loop *l;
    struct watchd_conf cf;
    int nl;                       /* netlink; -1 — живём одним периодом */
    struct loop_timer *tm;        /* следующий проход: период или успокоение после события */
    struct loop_timer *kill_tm;   /* срок идущего прохода */
    int settling;                 /* tm стоит на успокоении, а не на периоде */
    int pending;                  /* после идущего прохода нужен ещё один */
    pid_t pid;                    /* идущий проход; 0 — нет */
    int pfd;
    int reaped, status;
    char *msg;
    size_t msg_n;
    int msg_over;
    struct fo_mem mem;
};

static void watchd_pass_start(struct watchd *w);

static void watchd_settle(struct watchd *w) {
    if (w->settling) return;      /* пачка уже ждёт своего прохода — срок не отодвигаем */
    w->settling = 1;
    loop_timer_set(w->tm, WATCH_SETTLE_S * 1000L);
}

static void watchd_period(struct watchd *w) {
    w->settling = 0;
    loop_timer_set(w->tm, w->cf.period_s * 1000L);
}

static void watchd_timer(struct loop *l, struct loop_timer *t, void *arg) {
    (void)l; (void)t;
    struct watchd *w = arg;
    w->settling = 0;
    if (w->pid) return;           /* не бывает: таймер снят на время прохода */
    if (!w->d->have || (w->cf.enabled && !w->cf.enabled())) { watchd_period(w); return; }
    if (w->cf.busy && w->cf.busy(w->cf.busy_arg)) { watchd_settle(w); return; }
    if (w->nl >= 0) watch_nl_drain(w->nl);   /* пачка, ради которой ждали, — в этот проход */
    watchd_pass_start(w);
}

static void watchd_nl(struct loop *l, int fd, uint32_t ev, void *arg) {
    (void)l; (void)ev;
    struct watchd *w = arg;
    if (!watch_nl_drain(fd)) return;
    if (w->pid) {
        if (!plat()->netifd) w->pending = 1;
        return;
    }
    watchd_settle(w);
}

void watchd_spec_changed(struct watchd *w) {
    if (!w) return;
    if (w->pid) w->pending = 1;
    else watchd_settle(w);
}

/* ---- ребёнок: проход и ответ ----------------------------------------------------------- */

/* Слово ответа: имена выходов и устройств пробелов не содержат, но строка события — это
 * слова через пробел, и чужой знак в ней не должен сдвинуть поля. */
static void ev_word(FILE *f, const char *s) {
    if (!s || !*s) { fputs(" -", f); return; }
    fputc(' ', f);
    for (; *s; s++) fputc((unsigned char)*s <= ' ' || *s == 0x7f ? '_' : *s, f);
}

static void child_ev(void *arg, const struct fo_event *e) {
    FILE *f = arg;
    static const char *const kinds[] = { "switched", "failed", "revived" };
    fprintf(f, "ev %s", kinds[e->kind]);
    ev_word(f, e->out);
    ev_word(f, e->from);
    ev_word(f, e->to);
    ev_word(f, e->why);
    ev_word(f, e->on_fail);
    fputc('\n', f);
}

/* Закрыть всё унаследованное, кроме stdin/stdout/stderr и трубы ответа. Сокеты демона —
 * слушающий и соединения — у ребёнка не должны жить: клиент, которому демон ответил и закрыл
 * соединение, иначе не увидел бы конца ответа, пока идёт проход. */
static void child_close_fds(int keep) {
    int fds[1024];
    int n = 0;
    DIR *dir = opendir("/proc/self/fd");
    if (dir) {
        int self = dirfd(dir);
        struct dirent *de;
        while ((de = readdir(dir)) != NULL && n < (int)(sizeof(fds) / sizeof(*fds))) {
            int fd = atoi(de->d_name);
            if (fd > 2 && fd != keep && fd != self) fds[n++] = fd;
        }
        closedir(dir);
        for (int i = 0; i < n; i++) close(fds[i]);
        return;
    }
    for (int fd = 3; fd < 1024; fd++) if (fd != keep) close(fd);
}

static int write_all(int fd, const char *p, size_t n) {
    while (n) {
        ssize_t w = write(fd, p, n);
        if (w < 0 && errno == EINTR) continue;
        if (w <= 0) return -1;
        p += w;
        n -= (size_t)w;
    }
    return 0;
}

static void watchd_child(struct watchd *w, int fd) __attribute__((noreturn));
static void watchd_child(struct watchd *w, int fd) {
    loop_child_reset();
    child_close_fds(fd);
    failover_pass_guard();
    /* Проход меняет device у выходов — своя копия, а спека демона остаётся нетронутой для
     * masquerade ниже (он смотрит на спеку так, как её прочитал бы свежий процесс). */
    static struct spec sp;
    memcpy(&sp, w->d->sp, sizeof(sp));
    char *evs = NULL;
    size_t evn = 0;
    FILE *evf = open_memstream(&evs, &evn);
    failover_pass(&sp, &w->mem.base, 0, evf ? child_ev : NULL, evf);
    cleanup_probe_rule();
    /* Как у `failover --loop`: netd при перезапуске перестраивает iptables, и masquerade
     * правилом iptables (телефон) пропадает — вернуть (iptables_masq_ensure в apply.c). */
    if (plat()->iptables_masq) iptables_masq_ensure(w->d->sp);
    fflush(stdout);
    fflush(stderr);
    if (evf) fclose(evf);

    char *msg = NULL;
    size_t mn = 0;
    FILE *m = open_memstream(&msg, &mn);
    if (!m) _exit(1);
    for (size_t i = 0; i < w->mem.n; i++) {
        fprintf(m, "fo %s %zu\n", w->mem.b[i].name, w->mem.b[i].n);
        if (w->mem.b[i].n) fwrite(w->mem.b[i].p, 1, w->mem.b[i].n, m);
        fputc('\n', m);
    }
    if (evs && evn) fwrite(evs, 1, evn, m);
    fputs("fo-end\n", m);
    if (fclose(m) != 0 || write_all(fd, msg, mn) != 0) _exit(1);
    awg_hs_send(fd);
    _exit(0);
}

/* ---- демон: приём ответа --------------------------------------------------------------- */

/* Одно событие прохода — подписчикам. Слова: вид, выход, from, to, why, on_fail («-» — нет). */
static void watchd_emit(struct watchd *w, char *line) {
    char *wd[7];
    int k = 0;
    for (char *save = NULL, *t = strtok_r(line, " ", &save); t && k < 7; t = strtok_r(NULL, " ", &save))
        wd[k++] = t;
    if (k != 7) return;
    char out[96], from[96], to[96], why[48], of[32], f[512];
    steerd_json_str(out, sizeof(out), wd[2]);
    if (strcmp(wd[3], "-")) steerd_json_str(from, sizeof(from), wd[3]); else strcpy(from, "null");
    if (strcmp(wd[4], "-")) steerd_json_str(to, sizeof(to), wd[4]); else strcpy(to, "null");
    steerd_json_str(why, sizeof(why), wd[5]);
    steerd_json_str(of, sizeof(of), wd[6]);
    if (!strcmp(wd[1], "switched"))
        snprintf(f, sizeof(f), ",\"out\":%s,\"from\":%s,\"to\":%s,\"why\":%s", out, from, to, why);
    else if (!strcmp(wd[1], "failed"))
        snprintf(f, sizeof(f), ",\"out\":%s,\"from\":%s,\"on_fail\":%s,\"why\":%s", out, from, of, why);
    else if (!strcmp(wd[1], "revived"))
        snprintf(f, sizeof(f), ",\"out\":%s,\"dev\":%s", out, to);
    else
        return;
    steerd_emit(w->d, wd[1], f);
}

/* Разобрать ответ прохода: память выходов целиком, события, хвост — замеры awg. Ответ без
 * «fo-end» (проход умер или убит) не принимается вовсе: демон держит прежнюю память. */
static void watchd_accept(struct watchd *w) {
    char *p = w->msg, *end = w->msg + w->msg_n;
    struct fo_mem nm = { { &mem_ops }, NULL, 0, 0, 0 };
    char *evs[64];
    int evn = 0, done = 0;
    while (p < end) {
        char *nl = memchr(p, '\n', (size_t)(end - p));
        if (!nl) break;
        *nl = '\0';
        if (!strcmp(p, "fo-end")) { p = nl + 1; done = 1; break; }
        if (!strncmp(p, "fo ", 3)) {
            char name[64];
            size_t n = 0;
            if (sscanf(p + 3, "%63s %zu", name, &n) != 2 || n > (size_t)(end - nl - 1) ||
                nl + 1 + n >= end || nl[1 + n] != '\n')
                break;
            if (mem_set(&nm, name, nl + 1, n) < 0) break;
            p = nl + 1 + n + 1;
            continue;
        }
        if (!strncmp(p, "ev ", 3) && evn < (int)(sizeof(evs) / sizeof(*evs))) evs[evn++] = p;
        p = nl + 1;
    }
    if (!done) {
        fprintf(stderr, LOG_WW "проход не договорил — память выходов прежняя\n");
        mem_clear(&nm);
        return;
    }
    nm.mirror = w->mem.mirror;
    mem_clear(&w->mem);
    w->mem = nm;
    awg_hs_recv_buf(p, (size_t)(end - p));
    for (int i = 0; i < evn; i++) watchd_emit(w, evs[i]);
}

static void watchd_pass_check(struct watchd *w) {
    if (!w->pid || w->pfd >= 0 || !w->reaped) return;
    w->pid = 0;
    loop_timer_stop(w->kill_tm);
    if (WIFEXITED(w->status) && WEXITSTATUS(w->status) == 0 && !w->msg_over)
        watchd_accept(w);
    else if (WIFSIGNALED(w->status))
        fprintf(stderr, LOG_WW "проход убит сигналом %d\n", WTERMSIG(w->status));
    free(w->msg);
    w->msg = NULL;
    w->msg_n = 0;
    w->msg_over = 0;
    /* На роутере события за время прохода — следы его же ifdown/ifup (см. шапку). */
    if (plat()->netifd && w->nl >= 0) watch_nl_drain(w->nl);
    if (w->pending) {
        w->pending = 0;
        watchd_settle(w);
    } else {
        watchd_period(w);
    }
}

static void watchd_pipe(struct loop *l, int fd, uint32_t ev, void *arg) {
    (void)ev;
    struct watchd *w = arg;
    char buf[16384];
    for (;;) {
        ssize_t r = read(fd, buf, sizeof(buf));
        if (r < 0 && errno == EINTR) continue;
        if (r < 0 && (errno == EAGAIN || errno == EWOULDBLOCK)) return;
        if (r <= 0) break;
        if (w->msg_n + (size_t)r > WATCHD_MSG_MAX) { w->msg_over = 1; continue; }
        char *nb = realloc(w->msg, w->msg_n + (size_t)r + 1);
        if (!nb) { w->msg_over = 1; continue; }
        w->msg = nb;
        memcpy(w->msg + w->msg_n, buf, (size_t)r);
        w->msg_n += (size_t)r;
    }
    loop_fd_del(l, fd);
    close(fd);
    w->pfd = -1;
    watchd_pass_check(w);
}

static void watchd_child_done(struct loop *l, pid_t pid, int status, void *arg) {
    (void)l; (void)pid;
    struct watchd *w = arg;
    w->reaped = 1;
    w->status = status;
    watchd_pass_check(w);
}

static void watchd_kill(struct loop *l, struct loop_timer *t, void *arg) {
    (void)l; (void)t;
    struct watchd *w = arg;
    if (!w->pid) return;
    fprintf(stderr, LOG_WW "проход идёт дольше %d с — прерываю\n", WATCHD_PASS_MAX_S);
    kill(w->pid, SIGKILL);
}

static void watchd_pass_start(struct watchd *w) {
    int p[2];
    if (pipe2(p, O_CLOEXEC) != 0) {
        fprintf(stderr, LOG_WW "pipe: %s\n", strerror(errno));
        watchd_period(w);
        return;
    }
    fflush(NULL);                 /* буферы stdio не должны уйти дважды — из демона и из ребёнка */
    pid_t pid = fork();
    if (pid == 0) {
        close(p[0]);
        watchd_child(w, p[1]);
    }
    close(p[1]);
    if (pid < 0) {
        fprintf(stderr, LOG_WW "fork: %s\n", strerror(errno));
        close(p[0]);
        watchd_period(w);
        return;
    }
    fcntl(p[0], F_SETFL, fcntl(p[0], F_GETFL) | O_NONBLOCK);
    w->pid = pid;
    w->pfd = p[0];
    w->reaped = 0;
    w->status = 0;
    loop_timer_stop(w->tm);
    if (loop_fd_add(w->l, w->pfd, EPOLLIN, watchd_pipe, w) != 0) {
        close(w->pfd);
        w->pfd = -1;
    }
    loop_child(w->l, pid, watchd_child_done, w);
    loop_timer_set(w->kill_tm, WATCHD_PASS_MAX_S * 1000L);
}

/* ---- заведение и уход ------------------------------------------------------------------ */

struct watchd *watchd_start(struct steerd *d, const struct watchd_conf *c) {
    struct watchd *w = calloc(1, sizeof(*w));
    if (!w) return NULL;
    w->d = d;
    w->l = d->loop;
    w->cf = *c;
    if (w->cf.period_s <= 0) w->cf.period_s = 60;
    w->pfd = -1;
    w->mem.base.ops = &mem_ops;
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
    /* Замеры awg — в памяти, как у `failover --loop`: ребёнок получает их копией и отдаёт новые
     * хвостом ответа. */
    awg_hs_memory(1);
    w->nl = watch_nl_open();
    if (w->nl >= 0 && loop_fd_add(w->l, w->nl, EPOLLIN, watchd_nl, w) != 0) {
        close(w->nl);
        w->nl = -1;
    }
    if (w->nl < 0)
        fprintf(stderr, LOG_WW "события сети недоступны — проход только по периоду\n");
    d->outs = &w->mem.base;
    loop_timer_set(w->tm, 0);
    return w;
}

void watchd_stop(struct watchd *w) {
    if (w && w->pid) kill(w->pid, SIGTERM);
}
