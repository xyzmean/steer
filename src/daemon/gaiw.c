/* getaddrinfo рабочим потоком — устройство и доводы в gaiw.h. */
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <fcntl.h>
#include <pthread.h>
#include <netdb.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/epoll.h>
#include <netinet/in.h>

#include "loop.h"
#include "gaiw.h"

struct gaiw {
    struct loop *l;
    int fd;
    gaiw_cb cb;
    void *arg;
    size_t n, got;
    struct kind_name names[KIND_NAMES_MAX];
};

struct gaiw_work {
    int fd;
    size_t n;
    struct kind_name names[KIND_NAMES_MAX];
};

void gaiw_resolve(struct kind_name *nm) {
    struct addrinfo hints;
    memset(&hints, 0, sizeof(hints));
    hints.ai_family = nm->v4only ? AF_INET : AF_UNSPEC;
    hints.ai_socktype = SOCK_DGRAM;
    hints.ai_protocol = IPPROTO_UDP;
    char port[8];
    snprintf(port, sizeof(port), "%u", (unsigned)nm->port);
    struct addrinfo *res = NULL;
    nm->addr_len = 0;
    nm->rc = getaddrinfo(nm->host, port, &hints, &res);
    if (nm->rc == 0 && !res) nm->rc = EAI_NONAME;
    if (nm->rc == 0) {
        if (res->ai_addrlen <= sizeof(nm->addr)) {
            memcpy(&nm->addr, res->ai_addr, res->ai_addrlen);
            nm->addr_len = res->ai_addrlen;
        } else nm->rc = EAI_FAMILY;
    }
    if (res) freeaddrinfo(res);
}

static void *gaiw_thread(void *arg) {
    struct gaiw_work *w = arg;
    for (size_t i = 0; i < w->n; i++) gaiw_resolve(&w->names[i]);
    const char *p = (const char *)w->names;
    size_t left = w->n * sizeof(w->names[0]);
    while (left) {
        ssize_t k = send(w->fd, p, left, MSG_NOSIGNAL);
        if (k < 0 && errno == EINTR) continue;
        if (k <= 0) break;     /* отменено: другой конец закрыт */
        p += k;
        left -= (size_t)k;
    }
    close(w->fd);
    free(w);
    return NULL;
}

static void gaiw_free(struct gaiw *g) {
    loop_fd_del(g->l, g->fd);
    close(g->fd);
    free(g);
}

static void gaiw_ready(struct loop *l, int fd, uint32_t ev, void *arg) {
    (void)l; (void)ev;
    struct gaiw *g = arg;
    size_t want = g->n * sizeof(g->names[0]);
    for (;;) {
        if (g->got >= want) break;
        ssize_t k = recv(fd, (char *)g->names + g->got, want - g->got, 0);
        if (k < 0 && errno == EINTR) continue;
        if (k < 0 && (errno == EAGAIN || errno == EWOULDBLOCK)) return;
        if (k <= 0) break;
        g->got += (size_t)k;
    }
    if (g->got < want)
        for (size_t i = 0; i < g->n; i++) { g->names[i].rc = EAI_SYSTEM; g->names[i].addr_len = 0; }
    gaiw_cb cb = g->cb;
    void *a = g->arg;
    struct kind_name names[KIND_NAMES_MAX];
    size_t n = g->n;
    memcpy(names, g->names, n * sizeof(names[0]));
    gaiw_free(g);
    cb(a, names, n);
}

struct gaiw *gaiw_start(struct loop *l, struct kind_name *names, size_t n, gaiw_cb cb, void *arg) {
    if (n > KIND_NAMES_MAX) n = KIND_NAMES_MAX;
    struct gaiw *g = calloc(1, sizeof(*g));
    struct gaiw_work *w = calloc(1, sizeof(*w));
    int sv[2] = { -1, -1 };
    pthread_attr_t at;
    int attr_ok = 0;
    if (!g || !w || socketpair(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0, sv) != 0) goto sync;
    fcntl(sv[0], F_SETFL, fcntl(sv[0], F_GETFL) | O_NONBLOCK);
    g->l = l;
    g->fd = sv[0];
    g->cb = cb;
    g->arg = arg;
    g->n = n;
    w->fd = sv[1];
    w->n = n;
    memcpy(w->names, names, n * sizeof(names[0]));
    if (loop_fd_add(l, sv[0], EPOLLIN, gaiw_ready, g) != 0) goto sync;
    pthread_t th;
    attr_ok = pthread_attr_init(&at) == 0;
    if (attr_ok) pthread_attr_setdetachstate(&at, PTHREAD_CREATE_DETACHED);
    if (pthread_create(&th, attr_ok ? &at : NULL, gaiw_thread, w) != 0) {
        loop_fd_del(l, sv[0]);
        goto sync;
    }
    if (attr_ok) pthread_attr_destroy(&at);
    return g;
sync:
    if (attr_ok) pthread_attr_destroy(&at);
    if (sv[0] >= 0) close(sv[0]);
    if (sv[1] >= 0) close(sv[1]);
    free(g);
    free(w);
    for (size_t i = 0; i < n; i++) gaiw_resolve(&names[i]);
    return NULL;
}

void gaiw_cancel(struct gaiw *g) {
    if (g) gaiw_free(g);
}
