/* Состояние демона: спека в памяти и рассылка событий — см. state.h. */
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <unistd.h>
#include <fcntl.h>

#include "state.h"
#include "err.h"
#include "registry.h"

int steerd_init(struct steerd *d, struct loop *l, const char *spec_path, const char *state_dir) {
    memset(d, 0, sizeof(*d));
    d->loop = l;
    d->spec_path = spec_path;
    d->state_dir = state_dir;
    d->sp = calloc(1, sizeof(*d->sp));
    d->gr = calloc(1, sizeof(*d->gr));
    d->view = calloc(1, sizeof(*d->view));
    return d->sp && d->gr && d->view ? 0 : -1;
}

/* Отпечаток — FNV-1a 64 по байтам файла: подписчику нужно отличить «та же спека» от «другая»,
 * а не проверять подлинность. Криптографическая сумма дала бы то же различение за сотни строк
 * кода в ядре, которому TLS не положен (sha256 живёт в proto/tls). */
static void spec_fp(const char *path, char out[17]) {
    uint64_t h = 1469598103934665603ULL;
    int fd = open(path, O_RDONLY | O_CLOEXEC);
    if (fd >= 0) {
        unsigned char buf[16384];
        ssize_t m;
        while ((m = read(fd, buf, sizeof(buf))) > 0)
            for (ssize_t i = 0; i < m; i++) { h ^= buf[i]; h *= 1099511628211ULL; }
        close(fd);
    }
    snprintf(out, 17, "%016llx", (unsigned long long)h);
}

int steerd_load(struct steerd *d) {
    struct spec *ns = calloc(1, sizeof(*ns));
    struct groups *ng = calloc(1, sizeof(*ng));
    struct err e = {0};
    if (!ns || !ng) {
        free(ns);
        free(ng);
        snprintf(d->err, sizeof(d->err), "нет памяти под спеку");
        return -1;
    }
    /* Тот же порядок, что у cmd_status: разбор, метки из реестра, группы. */
    if (load_spec(d->spec_path, ns, &e) < 0 || registry_assign(ns, &e) < 0 ||
        build_groups(ns, ng, &e) < 0) {
        snprintf(d->err, sizeof(d->err), "%s", e.msg);
        groups_free(ng);
        free(ng);
        free(ns);
        return -1;
    }
    groups_free(d->gr);
    free(d->gr);
    free(d->sp);
    d->sp = ns;
    d->gr = ng;
    d->have = 1;
    d->err[0] = '\0';
    spec_fp(d->spec_path, d->fp);
    return 0;
}

void steerd_sub_add(struct steerd *d, struct steerd_sub *s) {
    s->next = d->subs;
    d->subs = s;
    d->subs_n++;
}

void steerd_sub_del(struct steerd *d, struct steerd_sub *s) {
    for (struct steerd_sub **pp = &d->subs; *pp; pp = &(*pp)->next)
        if (*pp == s) { *pp = s->next; d->subs_n--; s->next = NULL; return; }
}

void steerd_json_str(char *buf, size_t n, const char *s) {
    size_t k = 0;
    if (n < 3) { if (n) buf[0] = '\0'; return; }
    buf[k++] = '"';
    for (; *s; s++) {
        unsigned char c = (unsigned char)*s;
        char e[8];
        size_t el;
        if (c == '"' || c == '\\') { e[0] = '\\'; e[1] = (char)c; el = 2; }
        else if (c == '\n') { memcpy(e, "\\n", 2); el = 2; }
        else if (c == '\t') { memcpy(e, "\\t", 2); el = 2; }
        else if (c < 0x20 || c == 0x7f) { el = (size_t)snprintf(e, sizeof(e), "\\u%04x", c); }
        else { e[0] = (char)c; el = 1; }
        if (k + el + 2 > n) break;
        memcpy(buf + k, e, el);
        k += el;
    }
    /* Обрезанный посреди символа UTF-8 хвост — срезать целиком: разборщик подписчика заменил
     * бы его мусором. */
    size_t i = k, cont = 0;
    while (i > 1 && cont < 4 && ((unsigned char)buf[i - 1] & 0xC0) == 0x80) { i--; cont++; }
    if (i > 1 && cont) {
        unsigned char lead = (unsigned char)buf[i - 1];
        size_t need = lead >= 0xF0 ? 3 : lead >= 0xE0 ? 2 : lead >= 0xC0 ? 1 : 0;
        if (need != cont) k = lead >= 0xC0 ? i - 1 : k;
    }
    buf[k++] = '"';
    buf[k] = '\0';
}

/* Рассылка. Подписчик может отписаться (и освободиться) прямо в push — например, когда
 * событие переполнило его очередь, — поэтому следующий берётся до вызова. */
void steerd_emit(struct steerd *d, const char *ev, const char *fields) {
    if (!d->subs) return;
    size_t fl = fields ? strlen(fields) : 0;
    size_t cap = fl + strlen(ev) + 32;
    char *line = malloc(cap);
    if (!line) return;
    int n = snprintf(line, cap, "{\"v\":1,\"ev\":\"%s\"%s}\n", ev, fields ? fields : "");
    if (n <= 0 || (size_t)n >= cap) { free(line); return; }
    for (struct steerd_sub *s = d->subs, *next; s; s = next) {
        next = s->next;
        s->push(s, line, (size_t)n);
    }
    free(line);
}
