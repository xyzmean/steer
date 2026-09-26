/* Супервизор в демоне: `steer daemon --supervise` — помощники выходов и резолвер детьми демона.
 *
 * Шаг 4 устройства 1.8 (docs/architecture.md, «4а», «Дети и здоровье», «dnsd»). Что поднимать,
 * в каком порядке и когда перезапускать — общая с `steer supervise` логика (helpers.c); здесь —
 * то, как это живёт в цикле событий демона, и то, чего у `supervise` нет: трубы событий
 * помощников и резолвер на таблице.
 *
 * ВКЛЮЧАЕТСЯ ФЛАГОМ, как сторож (--watch). До шага 6 на роутере помощников и резолвер держит
 * procd (init.d/steer), на телефоне — сервисы `steer supervise` и dnsd. Два супервизора сразу
 * подняли бы по два экземпляра каждого помощника (второй обфускатор на том же порту, второй
 * резолвер на 5300), поэтому демон супервизор только с --supervise, а сервис, который его так
 * запускает, обязан снять прежние.
 *
 * ДЕТИ — fork+exec без ожиданий в цикле: выход ребёнка приходит через loop_child, срок
 * следующего запуска — одним таймером цикла на ближайший срок (в тишине таймер снят, и демон
 * не просыпается). Запуск помощника — та же командная строка, что у init.d и `supervise`
 * (helper_argv); дочерний процесс не знает, кто его поднял, кроме одной переменной:
 *
 * ТРУБА СОБЫТИЙ. Каждому помощнику — своя труба: конец записи он получает номером в
 * STEER_EVENT_FD (формат строк — src/lib/evline.h), конец чтения — в epoll демона. Пишет
 * помощник только при смене состояния, поэтому в тишине труба молчит. Демон разбирает строки
 * evline_parse и держит по выходу struct helper_state (поднят ли, почему упал, какой узел
 * проверяется, с какого времени), а подписчикам шлёт helper-up, helper-down и node (docs/ctl.md).
 * Процесс, вышедший молча после up, — тоже helper-down: причина — код выхода. Труба своя у
 * каждого запуска: события прежнего экземпляра не спутать с событиями нового.
 *
 * РЕЗОЛВЕР НА ТАБЛИЦЕ. `steer dnsd --table-fd N`: спеку он не читает — таблицу доменных каналов
 * (src/dnsd/tabfmt.h) демон пишет ему в трубу при запуске и при каждой смене спеки в памяти
 * (apply, reload, SIGHUP), и резолвер заменяет её без перезапуска (и перечитывает файлы списков
 * — то, что прежде делал SIGHUP). Поэтому ни подпись dnsd.sig, ни выбор «HUP или перезапуск»
 * здесь не нужны. Закрытая демоном труба — резолвер выходит сам: он не переживает демона, даже
 * убитого SIGKILL. Нужен ли резолвер, решает то же, что у init.d (needs-dnsd, dnsd_wanted).
 *
 * ВЫКЛЮЧАТЕЛЬ. Движок выключен (телефон) — состав пустой: ни помощников, ни резолвера, и
 * поднятые гаснут при очередной сверке (apply, reload, SIGHUP — то, после чего демон перечитывает
 * спеку и спрашивает выключатель).
 *
 * ОСТАНОВКА — supd_stop: резолверу закрыть трубу, помощникам по одному в обратном порядке
 * подъёма SIGTERM и по сроку SIGKILL (helpers_stop). */
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <limits.h>
#include <unistd.h>
#include <fcntl.h>
#include <signal.h>
#include <time.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <sys/epoll.h>

#include "platform.h"
#include "spec.h"
#include "evline.h"
#include "tabfmt.h"
#include "daemon.h"
#include "loop.h"
#include "state.h"
#include "helpers.h"

#define LOG_SW "steer[warn] supervise: "
/* Таблицы, не забранные резолвером: одна — десятки килобайт; больше мегабайта в очереди —
 * резолвер не читает трубу вовсе, и труба закрывается (он выйдет и поднимется заново). */
#define SUPD_TABQ_MAX (1024 * 1024)
#define SUPD_DNSD_FLAGS 8

struct supd {
    struct steerd *d;
    struct loop *l;
    int (*enabled)(void);
    const char *dnsd_flags[SUPD_DNSD_FLAGS + 1];
    struct helper_set set;
    struct helper fresh[HELPERS_MAX];
    struct loop_timer *tm;
    char exe[PATH_MAX];       /* движок или шов STEER_SUPERVISE_EXE */
    char self[PATH_MAX];      /* настоящий файл движка: резолвер и помощники-программы */
    int seam;
    int stopping;
    /* Резолвер: конец записи трубы таблицы и не отданные ещё байты. */
    int dn_fd;
    int dn_out;               /* ждём EPOLLOUT */
    char *q;
    size_t qn, qoff, qcap;
};

static void supd_kick(struct supd *s);

/* ---- события помощников ------------------------------------------------------------------- */

static struct helper *by_fd(struct supd *s, int fd) {
    for (size_t i = 0; i < s->set.n; i++)
        if (s->set.h[i].evfd == fd) return &s->set.h[i];
    return NULL;
}

static void emit_state(struct supd *s, const struct helper *h, const char *ev, const char *why) {
    char out[80], w[512], f[700];
    steerd_json_str(out, sizeof(out), h->name);
    if (why) {
        steerd_json_str(w, sizeof(w), why);
        snprintf(f, sizeof(f), ",\"out\":%s,\"helper\":\"%s\",\"why\":%s", out, h->cmd, w);
    } else {
        snprintf(f, sizeof(f), ",\"out\":%s,\"helper\":\"%s\"", out, h->cmd);
    }
    steerd_emit(s->d, ev, f);
}

static void ev_line(struct supd *s, struct helper *h, const char *line) {
    struct evline e;
    if (evline_parse(line, &e) != 0) return;
    struct helper_state *st = &h->st;
    long v, t;
    if (!strcmp(e.ev, "up")) {
        st->up = 1;
        st->known = 1;
        st->since = (long)time(NULL);
        st->why[0] = '\0';
        emit_state(s, h, "helper-up", NULL);
    } else if (!strcmp(e.ev, "down")) {
        const char *why = evline_str(&e, "why");
        st->up = 0;
        st->known = 1;
        st->since = (long)time(NULL);
        snprintf(st->why, sizeof(st->why), "%s", why ? why : "");
        emit_state(s, h, "helper-down", st->why);
    } else if (!strcmp(e.ev, "node")) {
        if (!evline_int(&e, "n", &v) || !evline_int(&e, "total", &t)) return;
        st->node = v;
        st->total = t;
        char out[80], f[160];
        steerd_json_str(out, sizeof(out), h->name);
        snprintf(f, sizeof(f), ",\"out\":%s,\"n\":%ld,\"total\":%ld", out, v, t);
        steerd_emit(s->d, "node", f);
    } else if (!strcmp(e.ev, "nonode")) {
        if (evline_int(&e, "node", &v)) st->nonode = v;
        if (evline_int(&e, "total", &t)) st->total = t;
    }
    /* health (мост tgws) — оценка пути до ДЦ, а не помощника целиком: в состоянии помощника ей
     * места нет, сторожу она пока не нужна. */
}

/* Дочитать трубу помощника. 1 — открыта, 0 — конец (закрыта здесь же). */
static int ev_drain(struct supd *s, struct helper *h) {
    for (;;) {
        size_t room = sizeof(h->evbuf) - 1 - h->evlen;
        ssize_t m = read(h->evfd, h->evbuf + h->evlen, room);
        if (m < 0 && errno == EINTR) continue;
        if (m < 0 && (errno == EAGAIN || errno == EWOULDBLOCK)) return 1;
        if (m <= 0) {
            loop_fd_del(s->l, h->evfd);
            close(h->evfd);
            h->evfd = -1;
            h->evlen = 0;
            return 0;
        }
        h->evlen += (size_t)m;
        h->evbuf[h->evlen] = '\0';
        char *p = h->evbuf, *nl;
        while ((nl = memchr(p, '\n', h->evlen - (size_t)(p - h->evbuf)))) {
            *nl = '\0';
            ev_line(s, h, p);
            p = nl + 1;
        }
        size_t rest = h->evlen - (size_t)(p - h->evbuf);
        /* Строка длиннее буфера — не наша (evline пишет короткие): выбросить. */
        if (rest == sizeof(h->evbuf) - 1) rest = 0;
        memmove(h->evbuf, p, rest);
        h->evlen = rest;
    }
}

static void ev_cb(struct loop *l, int fd, uint32_t events, void *arg) {
    (void)l; (void)events;
    struct supd *s = arg;
    struct helper *h = by_fd(s, fd);
    if (!h) { loop_fd_del(s->l, fd); close(fd); return; }
    ev_drain(s, h);
}

/* ---- резолвер: таблица в трубу ------------------------------------------------------------ */

static void tab_close(struct supd *s) {
    if (s->dn_fd >= 0) {
        if (s->dn_out) loop_fd_del(s->l, s->dn_fd);
        close(s->dn_fd);
    }
    s->dn_fd = -1;
    s->dn_out = 0;
    s->qn = s->qoff = 0;
}

static void tab_out_cb(struct loop *l, int fd, uint32_t events, void *arg);

static void tab_flush(struct supd *s) {
    while (s->qoff < s->qn) {
        ssize_t w = write(s->dn_fd, s->q + s->qoff, s->qn - s->qoff);
        if (w > 0) { s->qoff += (size_t)w; continue; }
        if (w < 0 && errno == EINTR) continue;
        if (w < 0 && (errno == EAGAIN || errno == EWOULDBLOCK)) {
            if (!s->dn_out && loop_fd_add(s->l, s->dn_fd, EPOLLOUT, tab_out_cb, s) == 0)
                s->dn_out = 1;
            return;
        }
        /* EPIPE — резолвер вышел; его выход придёт через loop_child. */
        tab_close(s);
        return;
    }
    s->qn = s->qoff = 0;
    if (s->dn_out) { loop_fd_del(s->l, s->dn_fd); s->dn_out = 0; }
}

static void tab_out_cb(struct loop *l, int fd, uint32_t events, void *arg) {
    (void)l; (void)fd; (void)events;
    tab_flush(arg);
}

/* Собрать таблицу по спеке в памяти и поставить в трубу. */
static void tab_send(struct supd *s) {
    if (s->dn_fd < 0 || !s->d->have) return;
    char *p = NULL;
    size_t n = 0;
    FILE *f = open_memstream(&p, &n);
    if (!f) return;
    tabfmt_build(s->d->sp, f);
    if (fclose(f) != 0 || !p) { free(p); return; }
    if (s->qoff) {
        memmove(s->q, s->q + s->qoff, s->qn - s->qoff);
        s->qn -= s->qoff;
        s->qoff = 0;
    }
    if (s->qn + n > SUPD_TABQ_MAX) {
        fprintf(stderr, LOG_SW "резолвер не забирает таблицу — закрываю трубу\n");
        free(p);
        tab_close(s);
        return;
    }
    if (s->qn + n > s->qcap) {
        size_t c = s->qcap ? s->qcap : 65536;
        while (c < s->qn + n) c *= 2;
        char *q = realloc(s->q, c);
        if (!q) { free(p); return; }
        s->q = q;
        s->qcap = c;
    }
    memcpy(s->q + s->qn, p, n);
    s->qn += n;
    free(p);
    tab_flush(s);
}

/* ---- запуск ------------------------------------------------------------------------------- */

/* В ребёнке до exec: конец трубы — дескриптором 3, без O_CLOEXEC. Номер один и тот же у каждого
 * запуска, а не случайный номер демона: помощник на shell (стенды, отладка) перенаправляет только
 * однозначные дескрипторы, и «STEER_EVENT_FD=3» в окружении процесса читается глазами. Что было на
 * 3 у демона, помечено O_CLOEXEC (все его дескрипторы) и закрылось бы при exec всё равно. */
static void child_fd3(int fd) {
    if (fd == 3) fcntl(3, F_SETFD, 0);
    else if (dup2(fd, 3) == 3) close(fd);
}

static int start_dnsd(struct supd *s, struct helper *h) {
    int p[2];
    if (pipe2(p, O_CLOEXEC) != 0) return -1;
    const char *av[8 + SUPD_DNSD_FLAGS];
    size_t n = 0;
    av[n++] = s->self;
    av[n++] = "dnsd";
    av[n++] = "--table-fd";
    av[n++] = "3";
    if (strcmp(steer_state_dir(), plat()->state_dir) != 0) {
        av[n++] = "--state-dir";
        av[n++] = steer_state_dir();
    }
    for (size_t i = 0; s->dnsd_flags[i]; i++) av[n++] = s->dnsd_flags[i];
    av[n] = NULL;
    pid_t pid = fork();
    if (pid < 0) { close(p[0]); close(p[1]); return -1; }
    if (pid == 0) {
        loop_child_reset();
        child_fd3(p[0]);
        execv(av[0], (char *const *)av);
        _exit(127);
    }
    close(p[0]);
    fcntl(p[1], F_SETFL, fcntl(p[1], F_GETFL) | O_NONBLOCK);
    tab_close(s);
    s->dn_fd = p[1];
    helper_started(h, pid);
    tab_send(s);
    return 0;
}

static void child_cb(struct loop *l, pid_t pid, int status, void *arg);

static int start_one(struct helper *h, void *arg) {
    struct supd *s = arg;
    if (s->enabled && !s->enabled()) return -1;
    if (h->table) {
        if (start_dnsd(s, h) != 0) return -1;
    } else {
        int p[2];
        if (pipe2(p, O_CLOEXEC) != 0) return -1;
        const char *av[12];
        char prog[PATH_MAX + 32];
        helper_argv(h, s->exe, s->self, s->seam, s->d->spec_path, prog, sizeof(prog), av);
        pid_t pid = fork();
        if (pid < 0) { close(p[0]); close(p[1]); return -1; }
        if (pid == 0) {
            loop_child_reset();
            child_fd3(p[1]);
            putenv("STEER_EVENT_FD=3");
            if (h->env[0]) putenv(h->env);
            execv(av[0], (char *const *)av);
            _exit(127);
        }
        close(p[1]);
        fcntl(p[0], F_SETFL, fcntl(p[0], F_GETFL) | O_NONBLOCK);
        h->evfd = p[0];
        h->evlen = 0;
        if (loop_fd_add(s->l, h->evfd, EPOLLIN, ev_cb, s) != 0) { close(h->evfd); h->evfd = -1; }
        if (h->st.started) h->st.restarts++;
        h->st.running = 1;
        h->st.up = h->st.known = 0;
        h->st.node = h->st.total = h->st.nonode = 0;
        h->st.started = (long)time(NULL);
        helper_started(h, pid);
    }
    loop_child(s->l, h->pid, child_cb, s);
    return 0;
}

static void supd_timer(struct loop *l, struct loop_timer *t, void *arg) {
    (void)l; (void)t;
    supd_kick(arg);
}

static void supd_kick(struct supd *s) {
    if (s->stopping) return;
    long wait = helpers_due(&s->set, start_one, s);
    if (wait < 0) loop_timer_stop(s->tm);
    else loop_timer_set(s->tm, wait);
}

static void child_cb(struct loop *l, pid_t pid, int status, void *arg) {
    (void)l;
    struct supd *s = arg;
    if (s->stopping) return;
    for (size_t i = 0; i < s->set.n; i++) {
        struct helper *h = &s->set.h[i];
        if (h->pid != pid) continue;
        if (h->table) { tab_close(s); break; }
        /* Что помощник успел написать перед выходом, — раньше, чем вывод о его выходе. */
        if (h->evfd >= 0) ev_drain(s, h);
        if (h->evfd >= 0) { loop_fd_del(s->l, h->evfd); close(h->evfd); h->evfd = -1; }
        int was_up = h->st.up;
        h->st.running = 0;
        h->st.up = 0;
        /* Погашен нами — причина наша, а не код выхода, который это «вышел по SIGTERM». */
        if (h->gone)
            snprintf(h->st.why, sizeof(h->st.why), "выход убран из спеки");
        else if (h->restart)
            snprintf(h->st.why, sizeof(h->st.why), "перезапуск: параметры выхода изменились");
        else if (WIFEXITED(status))
            snprintf(h->st.why, sizeof(h->st.why), "процесс вышел (код %d)", WEXITSTATUS(status));
        else
            snprintf(h->st.why, sizeof(h->st.why), "процесс убит (сигнал %d)", WTERMSIG(status));
        if (was_up) {
            h->st.since = (long)time(NULL);
            emit_state(s, h, "helper-down", h->st.why);
        }
        break;
    }
    helpers_exited(&s->set, pid, status);
    helpers_compact(&s->set);
    supd_kick(s);
}

/* Поднимать ли резолвер — ответ needs-dnsd (там же доводы, почему «всегда»); по нему же решает
 * супервизор демона. Здесь, а не в main.c: стенды компонуют модули демона без main.c. В
 * мини-сборке — «поднимать нечего», и это тот же ответ, что даёт генератор правил: он там
 * перенаправления DNS не ставит. Два ответа обязаны совпадать, иначе init-скрипт однажды поднимет
 * резолвер без правила или, хуже, правило останется без резолвера. */
int dnsd_wanted(void) {
#ifdef STEER_TGWS
    return 0;
#else
    return 1;
#endif
}

/* ---- состав -------------------------------------------------------------------------------- */

static size_t supd_plan(struct supd *s) {
    size_t n = 0;
    if (!s->d->have || (s->enabled && !s->enabled())) return 0;
    n = helpers_plan(s->d->sp, s->fresh, HELPERS_MAX - 1, NULL);
    if (dnsd_wanted()) {
        struct helper *h = &s->fresh[n++];
        memset(h, 0, sizeof(*h));
        snprintf(h->cmd, sizeof(h->cmd), "dnsd");
        h->table = 1;
        h->sig = KIND_SIG_INIT;
        h->delay_ms = HELPERS_DELAY_MS;
        h->evfd = -1;
    }
    return n;
}

struct supd *supd_start(struct steerd *d, const struct supd_conf *c) {
    struct supd *s = calloc(1, sizeof(*s));
    if (!s) return NULL;
    s->d = d;
    s->l = d->loop;
    s->enabled = c->enabled;
    s->dn_fd = -1;
    for (size_t i = 0; c->dnsd_flags && c->dnsd_flags[i] && i < SUPD_DNSD_FLAGS; i++)
        s->dnsd_flags[i] = c->dnsd_flags[i];
    ssize_t el = readlink("/proc/self/exe", s->self, sizeof(s->self) - 1);
    if (el <= 0) { free(s); return NULL; }
    s->self[el] = '\0';
    /* Шов стенда — тот же, что у `steer supervise`: помощником становится программа стенда. */
    const char *seam = getenv("STEER_SUPERVISE_EXE");
    s->seam = seam && *seam;
    snprintf(s->exe, sizeof(s->exe), "%s", s->seam ? seam : s->self);
    s->tm = loop_timer_new(s->l, supd_timer, s);
    if (!s->tm) { free(s); return NULL; }
    d->sup = s;
    size_t fn = supd_plan(s);
    memcpy(s->set.h, s->fresh, fn * sizeof(s->fresh[0]));
    s->set.n = fn;
    if (d->have && fn == (size_t)(dnsd_wanted() && (!s->enabled || s->enabled())))
        fprintf(stderr, "steer[info] supervise: выходов со своим процессом в спеке нет\n");
    supd_kick(s);
    return s;
}

void supd_spec_changed(struct supd *s) {
    if (!s || s->stopping) return;
    size_t fn = supd_plan(s);
    helpers_merge(&s->set, s->fresh, fn);
    helpers_compact(&s->set);
    tab_send(s);
    supd_kick(s);
}

void supd_stop(struct supd *s) {
    if (!s || s->stopping) return;
    s->stopping = 1;
    loop_timer_stop(s->tm);
    /* Резолверу — конец трубы: он выходит сам, пока гаснут помощники. */
    tab_close(s);
    for (size_t i = 0; i < s->set.n; i++)
        if (s->set.h[i].evfd >= 0) {
            loop_fd_del(s->l, s->set.h[i].evfd);
            close(s->set.h[i].evfd);
            s->set.h[i].evfd = -1;
        }
    helpers_stop(&s->set, 1);
}

const struct helper_state *helper_state_of(const struct steerd *d, const char *out) {
    const struct supd *s = d ? d->sup : NULL;
    if (!s || !out) return NULL;
    for (size_t i = 0; i < s->set.n; i++) {
        const struct helper *h = &s->set.h[i];
        if (!h->table && !h->gone && !strcmp(h->name, out)) return &h->st;
    }
    return NULL;
}
