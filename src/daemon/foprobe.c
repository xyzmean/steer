/* Ожидания сторожа на цикле событий — устройство и доводы в foprobe.h. */
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <errno.h>
#include <unistd.h>
#include <fcntl.h>
#include <signal.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <sys/socket.h>
#include <sys/epoll.h>
#include <netinet/in.h>
#include <netinet/ip_icmp.h>
#include <arpa/inet.h>

#include "loop.h"
#include "foprobe.h"

#define LOG_W "steer[warn] failover: "

/* Фильтр сырого сокета ICMP (linux/icmp.h). Заголовок ядра рядом с netinet/ip_icmp.h
 * определяет struct icmphdr второй раз, поэтому число — здесь. */
#ifndef ICMP_FILTER
#define ICMP_FILTER 1
#endif
#ifndef SOL_RAW
#define SOL_RAW 255
#endif

enum { PK_TCP, PK_RAW, PK_DGRAM, PK_PING };

struct foprobe {
    struct loop *l;
    int kind;
    int fd;
    struct loop_timer *tm;
    struct fospawn *sp;
    foprobe_cb cb;
    void *arg;
    long t0;
    struct in_addr dst;
    uint16_t id, seq;
};

static void probe_free(struct foprobe *p) {
    if (p->fd >= 0) {
        loop_fd_del(p->l, p->fd);
        close(p->fd);
    }
    loop_timer_free(p->tm);
    if (p->sp) fospawn_cancel(p->sp);
    free(p);
}

/* Итог — одним вызовом: ресурсы пробы сняты до него, обратный вызов волен начать следующую. */
static void probe_finish(struct foprobe *p, int ok, int ms) {
    foprobe_cb cb = p->cb;
    void *arg = p->arg;
    probe_free(p);
    cb(arg, ok, ms);
}

static void probe_timeout(struct loop *l, struct loop_timer *t, void *arg) {
    (void)l; (void)t;
    struct foprobe *p = arg;
    p->tm = NULL;              /* сработавший таймер освобождается в probe_free — не дважды */
    loop_timer_free(t);
    probe_finish(p, 0, -1);
}

static int elapsed_ms(long t0) {
    long ms = loop_now_ms() - t0;
    if (ms < 0) ms = 0;
    if (ms > 1000000) ms = 1000000;
    return (int)ms;
}

static struct foprobe *probe_new(struct loop *l, int kind, foprobe_cb cb, void *arg, int timeout_ms) {
    struct foprobe *p = calloc(1, sizeof(*p));
    if (!p) return NULL;
    p->l = l;
    p->kind = kind;
    p->fd = -1;
    p->cb = cb;
    p->arg = arg;
    p->t0 = loop_now_ms();
    p->tm = loop_timer_new(l, probe_timeout, p);
    if (!p->tm) { free(p); return NULL; }
    loop_timer_set(p->tm, timeout_ms);
    return p;
}

/* ---- TCP ----------------------------------------------------------------------------------- */

static void tcp_ready(struct loop *l, int fd, uint32_t ev, void *arg) {
    (void)l; (void)ev;
    struct foprobe *p = arg;
    int err = 0;
    socklen_t el = sizeof(err);
    int ok = getsockopt(fd, SOL_SOCKET, SO_ERROR, &err, &el) == 0 && err == 0;
    probe_finish(p, ok, ok ? elapsed_ms(p->t0) : -1);
}

struct foprobe *foprobe_tcp(struct loop *l, const char *dev, const char *host, int port,
                            int timeout_ms, foprobe_cb cb, void *arg, int *ok, int *ms) {
    *ok = 0;
    *ms = -1;
    long t0 = loop_now_ms();
    struct in_addr a;
    if (inet_aton(host, &a) == 0) return NULL;
    int fd = socket(AF_INET, SOCK_STREAM | SOCK_NONBLOCK | SOCK_CLOEXEC, 0);
    if (fd < 0) return NULL;
    if (setsockopt(fd, SOL_SOCKET, SO_BINDTODEVICE, dev, (socklen_t)strlen(dev) + 1) != 0) {
        close(fd);
        return NULL;
    }
    struct sockaddr_in sa;
    memset(&sa, 0, sizeof(sa));
    sa.sin_family = AF_INET;
    sa.sin_port = htons((uint16_t)port);
    sa.sin_addr = a;
    if (connect(fd, (struct sockaddr *)&sa, sizeof(sa)) == 0) {
        /* Соединилось мгновенно — обычно сосед по L2. */
        close(fd);
        *ok = 1;
        *ms = elapsed_ms(t0);
        return NULL;
    }
    if (errno != EINPROGRESS) { close(fd); return NULL; }
    struct foprobe *p = probe_new(l, PK_TCP, cb, arg, timeout_ms);
    if (!p) { close(fd); return NULL; }
    p->t0 = t0;
    p->fd = fd;
    if (loop_fd_add(l, fd, EPOLLOUT, tcp_ready, p) != 0) {
        p->fd = -1;
        close(fd);
        probe_free(p);
        return NULL;
    }
    return p;
}

/* ---- ICMP ---------------------------------------------------------------------------------- */

/* Способ, с которого начинать: неудавшийся по отказу в правах больше не пробуется (см. шапку
 * foprobe.h). Причины — для одной строки журнала при переходе на ping. */
static int g_icmp_from = PK_RAW;
static char g_why_raw[64], g_why_dgram[64];
static int g_ping_told;
static uint16_t g_icmp_seq;

static int perm_errno(int e) {
    return e == EPERM || e == EACCES || e == EPROTONOSUPPORT || e == ESOCKTNOSUPPORT ||
           e == EAFNOSUPPORT;
}

static uint16_t csum(const uint8_t *b, size_t n) {
    uint32_t s = 0;
    for (size_t i = 0; i + 1 < n; i += 2) s += (uint32_t)(b[i] << 8 | b[i + 1]);
    if (n & 1) s += (uint32_t)(b[n - 1] << 8);
    while (s >> 16) s = (s & 0xffff) + (s >> 16);
    return (uint16_t)~s;
}

static void icmp_ready(struct loop *l, int fd, uint32_t ev, void *arg) {
    (void)l; (void)ev;
    struct foprobe *p = arg;
    uint8_t buf[1500];
    for (;;) {
        struct sockaddr_in from;
        socklen_t fl = sizeof(from);
        ssize_t n = recvfrom(fd, buf, sizeof(buf), 0, (struct sockaddr *)&from, &fl);
        if (n < 0) {
            if (errno == EINTR) continue;
            return;            /* EAGAIN — ждём дальше; иное — срок решит */
        }
        const uint8_t *ic = buf;
        size_t il = (size_t)n;
        if (p->kind == PK_RAW) {
            /* Сырой сокет отдаёт пакет с заголовком IP. */
            if (il < 20) continue;
            size_t hl = (size_t)(buf[0] & 0x0f) * 4;
            if (hl < 20 || il < hl + 8 || buf[9] != IPPROTO_ICMP) continue;
            ic += hl;
            il -= hl;
        }
        if (il < 8 || ic[0] != ICMP_ECHOREPLY) continue;
        if (fl >= sizeof(from) && from.sin_addr.s_addr != p->dst.s_addr) continue;
        uint16_t id = (uint16_t)(ic[4] << 8 | ic[5]), seq = (uint16_t)(ic[6] << 8 | ic[7]);
        /* Ping-сокету номер выдаёт ядро и ответы разбирает само; сырой видит все ответы на
         * устройстве — свой узнаётся по номеру. */
        if (seq != p->seq || (p->kind == PK_RAW && id != p->id)) continue;
        probe_finish(p, 1, elapsed_ms(p->t0));
        return;
    }
}

/* Открыть сокет способа kind, привязать к устройству и адресу. 0 — готов (*fd); -1 — способ
 * недоступен (отказ в правах, why — почему); 1 — не вышло по причине устройства (проба
 * отвечает «нет»). */
static int icmp_open(int kind, const char *dev, struct in_addr src, int *fd, char *why, size_t wn) {
    int type = kind == PK_RAW ? SOCK_RAW : SOCK_DGRAM;
    int s = socket(AF_INET, type | SOCK_NONBLOCK | SOCK_CLOEXEC, IPPROTO_ICMP);
    if (s < 0) {
        snprintf(why, wn, "%s", strerror(errno));
        return perm_errno(errno) ? -1 : 1;
    }
    if (setsockopt(s, SOL_SOCKET, SO_BINDTODEVICE, dev, (socklen_t)strlen(dev) + 1) != 0) {
        int e = errno;
        close(s);
        snprintf(why, wn, "SO_BINDTODEVICE: %s", strerror(e));
        return perm_errno(e) ? -1 : 1;
    }
    struct sockaddr_in sa;
    memset(&sa, 0, sizeof(sa));
    sa.sin_family = AF_INET;
    sa.sin_addr = src;
    if (bind(s, (struct sockaddr *)&sa, sizeof(sa)) != 0) {
        int e = errno;
        close(s);
        snprintf(why, wn, "bind: %s", strerror(e));
        return perm_errno(e) ? -1 : 1;
    }
    if (kind == PK_RAW) {
        uint32_t filt = ~(1u << ICMP_ECHOREPLY);
        setsockopt(s, SOL_RAW, ICMP_FILTER, &filt, sizeof(filt));
    }
    *fd = s;
    return 0;
}

static void ping_done(void *arg, int rc) {
    struct foprobe *p = arg;
    p->sp = NULL;
    probe_finish(p, rc == 0, -1);
}

struct foprobe *foprobe_icmp(struct loop *l, const char *dev, const char *src, const char *host,
                             int timeout_ms, foprobe_cb cb, void *arg, int *ok) {
    *ok = 0;
    struct in_addr s4, d4;
    if (inet_aton(src, &s4) == 0 || inet_aton(host, &d4) == 0) return NULL;
    int fd = -1, kind = g_icmp_from;
    while (kind != PK_PING) {
        char *why = kind == PK_RAW ? g_why_raw : g_why_dgram;
        int r = icmp_open(kind, dev, s4, &fd, why, sizeof(g_why_raw));
        if (r == 0) break;
        if (r > 0) return NULL;
        kind = kind == PK_RAW ? PK_DGRAM : PK_PING;
        g_icmp_from = kind;
    }
    if (kind == PK_PING) {
        if (!g_ping_told) {
            g_ping_told = 1;
            fprintf(stderr, LOG_W "проба ICMP из процесса недоступна (сырой сокет: %s; ping-сокет: "
                            "%s) — проверяю внешним ping, процесс на каждую пробу\n",
                    g_why_raw[0] ? g_why_raw : "-", g_why_dgram[0] ? g_why_dgram : "-");
        }
        char w[16];
        snprintf(w, sizeof(w), "%d", timeout_ms > 999 ? timeout_ms / 1000 : 1);
        const char *argv[] = { "ping", "-c", "1", "-W", w, "-I", dev, "-q", host, NULL };
        /* Сам ping ждёт свой срок; предел ребёнку — с запасом, от зависшего ping. */
        struct foprobe *p = probe_new(l, PK_PING, cb, arg, timeout_ms + 5000);
        if (!p) return NULL;
        int rc = -1;
        p->sp = fospawn_start(l, argv, timeout_ms + 4000, ping_done, p, &rc);
        if (!p->sp) {
            probe_free(p);
            *ok = rc == 0;
            return NULL;
        }
        return p;
    }
    uint8_t pkt[64];
    memset(pkt, 0, sizeof(pkt));
    uint16_t seq = ++g_icmp_seq;
    uint16_t id = (uint16_t)(getpid() ^ 0x5354);
    pkt[0] = ICMP_ECHO;
    pkt[4] = (uint8_t)(id >> 8);
    pkt[5] = (uint8_t)id;
    pkt[6] = (uint8_t)(seq >> 8);
    pkt[7] = (uint8_t)seq;
    for (size_t i = 8; i < sizeof(pkt); i++) pkt[i] = (uint8_t)i;
    uint16_t c = csum(pkt, sizeof(pkt));
    pkt[2] = (uint8_t)(c >> 8);
    pkt[3] = (uint8_t)c;
    struct sockaddr_in to;
    memset(&to, 0, sizeof(to));
    to.sin_family = AF_INET;
    to.sin_addr = d4;
    struct foprobe *p = probe_new(l, kind, cb, arg, timeout_ms);
    if (!p) { close(fd); return NULL; }
    p->fd = fd;
    p->dst = d4;
    p->id = id;
    p->seq = seq;
    if (loop_fd_add(l, fd, EPOLLIN, icmp_ready, p) != 0 ||
        sendto(fd, pkt, sizeof(pkt), 0, (struct sockaddr *)&to, sizeof(to)) < 0) {
        probe_free(p);
        return NULL;
    }
    return p;
}

void foprobe_cancel(struct foprobe *p) {
    if (p) probe_free(p);
}

/* ---- команда ------------------------------------------------------------------------------- */

struct fospawn {
    struct loop *l;
    pid_t pid;
    struct loop_timer *tm;
    fospawn_cb cb;
    void *arg;
    int cancelled;
};

static void spawn_reaped(struct loop *l, pid_t pid, int status, void *arg) {
    (void)l; (void)pid;
    struct fospawn *s = arg;
    loop_timer_free(s->tm);
    if (!s->cancelled) {
        fospawn_cb cb = s->cb;
        void *a = s->arg;
        free(s);
        cb(a, WIFEXITED(status) ? WEXITSTATUS(status) : -1);
        return;
    }
    free(s);
}

static void spawn_timeout(struct loop *l, struct loop_timer *t, void *arg) {
    (void)l; (void)t;
    struct fospawn *s = arg;
    kill(-s->pid, SIGKILL);
    kill(s->pid, SIGKILL);
}

struct fospawn *fospawn_start(struct loop *l, const char *const argv[], int timeout_ms,
                              fospawn_cb cb, void *arg, int *rc) {
    *rc = -1;
    struct fospawn *s = calloc(1, sizeof(*s));
    if (!s) return NULL;
    s->l = l;
    s->cb = cb;
    s->arg = arg;
    s->tm = loop_timer_new(l, spawn_timeout, s);
    if (!s->tm) { free(s); return NULL; }
    fflush(NULL);              /* буферы stdio не должны уйти и из ребёнка */
    pid_t pid = fork();
    if (pid < 0) {
        loop_timer_free(s->tm);
        free(s);
        return NULL;
    }
    if (pid == 0) {
        /* Своя группа: по сроку снимается и то, что команда успела запустить. Вывод — в
         * /dev/null, как у run_quiet; сигналы цикла — по умолчанию (loop_child_reset). */
        setpgid(0, 0);
        int nul = open("/dev/null", O_RDWR);
        if (nul >= 0) { dup2(nul, 0); dup2(nul, 1); dup2(nul, 2); if (nul > 2) close(nul); }
        loop_child_reset();
        execvp(argv[0], (char *const *)argv);
        _exit(127);
    }
    setpgid(pid, pid);
    s->pid = pid;
    if (loop_child(l, pid, spawn_reaped, s) != 0) {
        /* Следить не за чем — ждём здесь: это отказ памяти, а не обычный путь. */
        int st = 0;
        while (waitpid(pid, &st, 0) < 0 && errno == EINTR) {}
        loop_timer_free(s->tm);
        free(s);
        *rc = WIFEXITED(st) ? WEXITSTATUS(st) : -1;
        return NULL;
    }
    loop_timer_set(s->tm, timeout_ms);
    return s;
}

void fospawn_cancel(struct fospawn *s) {
    if (!s || s->cancelled) return;
    s->cancelled = 1;
    loop_timer_stop(s->tm);
    kill(-s->pid, SIGKILL);
    kill(s->pid, SIGKILL);
}
