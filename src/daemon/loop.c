/* Цикл событий демона — устройство и доводы в loop.h. */
#define _GNU_SOURCE
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <fcntl.h>
#include <signal.h>
#include <time.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <sys/epoll.h>
#include <sys/signalfd.h>
#include <sys/timerfd.h>

#include "loop.h"

/* Запись дескриптора. Снятая (dead) доживает до конца пачки событий: указатель на неё мог
 * остаться в массиве, который epoll_wait уже вернул. */
struct loop_io {
    struct loop_io *next;
    int fd;
    int dead;
    loop_fd_cb cb;
    void *arg;
};

struct loop_timer {
    struct loop_timer *next;
    struct loop *l;
    long due;                 /* срок, мс CLOCK_MONOTONIC; 0 — не заведён */
    loop_timer_cb cb;
    void *arg;
};

struct loop_kid {
    struct loop_kid *next;
    pid_t pid;
    int status;
    loop_child_cb cb;
    void *arg;
};

struct loop_sig {
    int signo;
    loop_sig_cb cb;
    void *arg;
};

struct loop {
    int ep, sfd, tfd;
    struct loop_io *ios;
    struct loop_timer *timers;
    struct loop_kid *kids;
    struct loop_sig sigs[3];          /* SIGHUP, SIGTERM, SIGINT */
    long armed;                       /* на какой срок взведён timerfd; 0 — снят */
    int stop, code;
    int reap_dead;                    /* в ios есть снятые записи */
};

/* Маркеры для data.ptr своих дескрипторов — сравниваются по адресу. */
static char LOOP_SIG_TAG, LOOP_TIMER_TAG;

long loop_now_ms(void) {
    struct timespec t;
    clock_gettime(CLOCK_MONOTONIC, &t);
    return (long)t.tv_sec * 1000L + t.tv_nsec / 1000000L;
}

static void loop_sigset(sigset_t *s) {
    sigemptyset(s);
    sigaddset(s, SIGCHLD);
    sigaddset(s, SIGHUP);
    sigaddset(s, SIGTERM);
    sigaddset(s, SIGINT);
}

struct loop *loop_new(void) {
    struct loop *l = calloc(1, sizeof(*l));
    if (!l) return NULL;
    l->ep = l->sfd = l->tfd = -1;
    l->sigs[0].signo = SIGHUP;
    l->sigs[1].signo = SIGTERM;
    l->sigs[2].signo = SIGINT;
    sigset_t s;
    loop_sigset(&s);
    if (sigprocmask(SIG_BLOCK, &s, NULL) != 0) goto fail;
    l->ep = epoll_create1(EPOLL_CLOEXEC);
    l->sfd = signalfd(-1, &s, SFD_CLOEXEC | SFD_NONBLOCK);
    l->tfd = timerfd_create(CLOCK_MONOTONIC, TFD_CLOEXEC | TFD_NONBLOCK);
    if (l->ep < 0 || l->sfd < 0 || l->tfd < 0) goto fail;
    struct epoll_event ev;
    memset(&ev, 0, sizeof(ev));
    ev.events = EPOLLIN;
    ev.data.ptr = &LOOP_SIG_TAG;
    if (epoll_ctl(l->ep, EPOLL_CTL_ADD, l->sfd, &ev) != 0) goto fail;
    ev.data.ptr = &LOOP_TIMER_TAG;
    if (epoll_ctl(l->ep, EPOLL_CTL_ADD, l->tfd, &ev) != 0) goto fail;
    return l;
fail:
    loop_free(l);
    return NULL;
}

void loop_free(struct loop *l) {
    if (!l) return;
    while (l->ios) { struct loop_io *n = l->ios->next; free(l->ios); l->ios = n; }
    while (l->timers) { struct loop_timer *n = l->timers->next; free(l->timers); l->timers = n; }
    while (l->kids) { struct loop_kid *n = l->kids->next; free(l->kids); l->kids = n; }
    if (l->ep >= 0) close(l->ep);
    if (l->sfd >= 0) close(l->sfd);
    if (l->tfd >= 0) close(l->tfd);
    free(l);
}

void loop_stop(struct loop *l, int code) {
    l->stop = 1;
    l->code = code;
}

/* ---- дескрипторы ---------------------------------------------------------------------- */

static struct loop_io *io_find(struct loop *l, int fd) {
    for (struct loop_io *io = l->ios; io; io = io->next)
        if (io->fd == fd && !io->dead) return io;
    return NULL;
}

int loop_fd_add(struct loop *l, int fd, uint32_t events, loop_fd_cb cb, void *arg) {
    struct loop_io *io = calloc(1, sizeof(*io));
    if (!io) return -1;
    io->fd = fd;
    io->cb = cb;
    io->arg = arg;
    struct epoll_event ev;
    memset(&ev, 0, sizeof(ev));
    ev.events = events;
    ev.data.ptr = io;
    if (epoll_ctl(l->ep, EPOLL_CTL_ADD, fd, &ev) != 0) { free(io); return -1; }
    io->next = l->ios;
    l->ios = io;
    return 0;
}

int loop_fd_mod(struct loop *l, int fd, uint32_t events) {
    struct loop_io *io = io_find(l, fd);
    if (!io) { errno = ENOENT; return -1; }
    struct epoll_event ev;
    memset(&ev, 0, sizeof(ev));
    ev.events = events;
    ev.data.ptr = io;
    return epoll_ctl(l->ep, EPOLL_CTL_MOD, fd, &ev);
}

void loop_fd_del(struct loop *l, int fd) {
    struct loop_io *io = io_find(l, fd);
    if (!io) return;
    epoll_ctl(l->ep, EPOLL_CTL_DEL, fd, NULL);
    io->dead = 1;
    l->reap_dead = 1;
}

static void io_reap(struct loop *l) {
    if (!l->reap_dead) return;
    struct loop_io **pp = &l->ios;
    while (*pp) {
        if ((*pp)->dead) { struct loop_io *d = *pp; *pp = d->next; free(d); }
        else pp = &(*pp)->next;
    }
    l->reap_dead = 0;
}

/* ---- таймеры -------------------------------------------------------------------------- */

struct loop_timer *loop_timer_new(struct loop *l, loop_timer_cb cb, void *arg) {
    struct loop_timer *t = calloc(1, sizeof(*t));
    if (!t) return NULL;
    t->l = l;
    t->cb = cb;
    t->arg = arg;
    t->next = l->timers;
    l->timers = t;
    return t;
}

void loop_timer_set(struct loop_timer *t, long ms) {
    long due = loop_now_ms() + (ms > 0 ? ms : 0);
    t->due = due > 0 ? due : 1;
}

void loop_timer_stop(struct loop_timer *t) { if (t) t->due = 0; }

int loop_timer_armed(const struct loop_timer *t) { return t && t->due != 0; }

void loop_timer_free(struct loop_timer *t) {
    if (!t) return;
    struct loop *l = t->l;
    for (struct loop_timer **pp = &l->timers; *pp; pp = &(*pp)->next)
        if (*pp == t) { *pp = t->next; break; }
    free(t);
}

/* Взвести timerfd на самый ранний срок — перед каждым сном. Ни одного заведённого — снять:
 * тогда сон действительно бессрочный. Пересчёт дешёвый (таймеров единицы), а системный
 * вызов делается, только если срок изменился. */
static void timers_arm(struct loop *l) {
    long first = 0;
    for (struct loop_timer *t = l->timers; t; t = t->next)
        if (t->due && (!first || t->due < first)) first = t->due;
    if (first == l->armed) return;
    struct itimerspec its;
    memset(&its, 0, sizeof(its));
    if (first) {
        its.it_value.tv_sec = first / 1000;
        its.it_value.tv_nsec = (first % 1000) * 1000000L;
    }
    timerfd_settime(l->tfd, first ? TFD_TIMER_ABSTIME : 0, &its, NULL);
    l->armed = first;
}

/* Сработавшие таймеры — по одному, заново ища следующий после каждого вызова: обратный вызов
 * может освободить или переставить любой таймер, включая соседей по списку. */
static void timers_fire(struct loop *l) {
    uint64_t n;
    while (read(l->tfd, &n, sizeof(n)) > 0) {}
    l->armed = -1;                         /* взведённого больше нет — пересчитать перед сном */
    for (;;) {
        long now = loop_now_ms();
        struct loop_timer *due = NULL;
        for (struct loop_timer *t = l->timers; t; t = t->next)
            if (t->due && t->due <= now && (!due || t->due < due->due)) due = t;
        if (!due) break;
        due->due = 0;
        due->cb(l, due, due->arg);
    }
}

/* ---- сигналы и дети ------------------------------------------------------------------- */

int loop_signal(struct loop *l, int signo, loop_sig_cb cb, void *arg) {
    for (size_t i = 0; i < sizeof(l->sigs) / sizeof(l->sigs[0]); i++)
        if (l->sigs[i].signo == signo) { l->sigs[i].cb = cb; l->sigs[i].arg = arg; return 0; }
    return -1;
}

int loop_child(struct loop *l, pid_t pid, loop_child_cb cb, void *arg) {
    struct loop_kid *k = calloc(1, sizeof(*k));
    if (!k) return -1;
    k->pid = pid;
    k->cb = cb;
    k->arg = arg;
    k->next = l->kids;
    l->kids = k;
    return 0;
}

void loop_child_reset(void) {
    sigset_t s;
    sigemptyset(&s);
    sigprocmask(SIG_SETMASK, &s, NULL);
    signal(SIGPIPE, SIG_DFL);
}

/* Пожать названных детей. Сначала снять с учёта всех вышедших, потом звать обратные вызовы:
 * вызов может запустить следующего ребёнка (шаги apply), и тот не должен попасть в обход,
 * который сейчас идёт. ECHILD (ребёнка пожал кто-то другой — не должно случаться) считается
 * выходом с кодом 127, чтобы ждущий не повис навсегда. */
static void kids_reap(struct loop *l) {
    struct loop_kid *done = NULL, **pp = &l->kids;
    while (*pp) {
        struct loop_kid *k = *pp;
        int st = 0;
        pid_t w = waitpid(k->pid, &st, WNOHANG);
        if (w == k->pid || (w < 0 && errno == ECHILD)) {
            k->status = w < 0 ? (127 << 8) : st;
            *pp = k->next;
            k->next = done;
            done = k;
        } else {
            pp = &k->next;
        }
    }
    while (done) {
        struct loop_kid *k = done;
        done = k->next;
        k->cb(l, k->pid, k->status, k->arg);
        free(k);
    }
}

static void sigs_read(struct loop *l) {
    struct signalfd_siginfo si[8];
    int chld = 0;
    for (;;) {
        ssize_t m = read(l->sfd, si, sizeof(si));
        if (m <= 0) break;
        for (size_t i = 0; i < (size_t)m / sizeof(si[0]); i++) {
            int s = (int)si[i].ssi_signo;
            if (s == SIGCHLD) { chld = 1; continue; }
            for (size_t k = 0; k < sizeof(l->sigs) / sizeof(l->sigs[0]); k++)
                if (l->sigs[k].signo == s && l->sigs[k].cb) l->sigs[k].cb(l, s, l->sigs[k].arg);
        }
    }
    /* Несколько SIGCHLD сливаются в один — поэтому обходятся все названные дети, а не тот,
     * о ком сказал siginfo. */
    if (chld) kids_reap(l);
}

/* ---- оборот цикла ---------------------------------------------------------------------- */

int loop_run(struct loop *l) {
    struct epoll_event evs[32];
    while (!l->stop) {
        timers_arm(l);
        int n = epoll_wait(l->ep, evs, (int)(sizeof(evs) / sizeof(evs[0])), -1);
        if (n < 0) {
            if (errno == EINTR) continue;
            return -1;
        }
        for (int i = 0; i < n && !l->stop; i++) {
            void *p = evs[i].data.ptr;
            if (p == &LOOP_SIG_TAG) sigs_read(l);
            else if (p == &LOOP_TIMER_TAG) timers_fire(l);
            else {
                struct loop_io *io = p;
                if (!io->dead) io->cb(l, io->fd, evs[i].events, io->arg);
            }
        }
        io_reap(l);
    }
    return l->code;
}
