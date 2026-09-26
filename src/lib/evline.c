/* Формат целиком — в шапке evline.h. Здесь — запись (сторона помощника) и разбор (сторона
 * демона) одной и той же строки. */
#include "evline.h"
#include "jsonw.h"

#include <ctype.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

/* -2 — evline_open() ещё не звали (ленивая инициализация из evline_emit); -1 — звали, и
 * труба выключена; иначе — дескриптор. Один процесс — одна труба, глобал оправдан тем же,
 * чем оправдан он у остальных помощников (g_sp, g_cf и соседи в xsclient.c): второй трубы
 * событий у процесса не бывает. */
static int g_fd = -2;

void evline_open(void) {
    if (g_fd != -2) return;             /* идемпотентно — вторая попытка ничего не меняет */
    g_fd = -1;
    const char *s = getenv("STEER_EVENT_FD");
    if (!s || !*s) return;              /* нет переменной — выключено */
    char *end = NULL;
    errno = 0;
    long v = strtol(s, &end, 10);
    if (errno || end == s || *end || v < 0 || v > INT_MAX) return;   /* негодная — выключено */
    int fd = (int)v;
    int fl = fcntl(fd, F_GETFL);
    if (fl < 0) return;                 /* дескриптора нет вовсе — выключено */
    if (fcntl(fd, F_SETFL, fl | O_NONBLOCK) < 0) return;
    g_fd = fd;
}

static void evline_ensure_open(void) {
    if (g_fd == -2) evline_open();
}

/* С запасом ниже PIPE_BUF (POSIX гарантирует его минимум 512, на Linux 4096): событие с
 * контрактными двумя-тремя полями сюда влезает многократно, а если когда-нибудь не влезло —
 * лучше потерять его целиком, чем отправить обрезанный и невалидный JSON в трубу. */
#define EVLINE_WRITE_MAX 480

void evline_emit(const char *ev, ...) {
    evline_ensure_open();
    if (g_fd < 0) return;

    char *mem = NULL;
    size_t n = 0;
    FILE *f = open_memstream(&mem, &n);
    if (!f) return;

    fputs("{\"ev\":", f);
    jsonw_str_ascii(f, ev);

    va_list ap;
    va_start(ap, ev);
    for (;;) {
        const char *key = va_arg(ap, const char *);
        if (!key) break;
        enum evline_type type = (enum evline_type)va_arg(ap, int);
        fputc(',', f);
        jsonw_str_ascii(f, key);
        fputc(':', f);
        if (type == EVLINE_STR) {
            const char *sv = va_arg(ap, const char *);
            jsonw_str_ascii(f, sv);
        } else {
            long iv = va_arg(ap, long);
            fprintf(f, "%ld", iv);
        }
    }
    va_end(ap);
    fputs("}\n", f);
    fclose(f);

    /* Одна запись, атомарная по построению трубы; O_NONBLOCK (evline_open) не даёт ей
     * заблокировать помощника, если демон отстал, — короткая запись или EAGAIN теряют
     * событие молча, ошибку никому сообщать не нужно (следующее событие важнее этого). */
    if (mem && n > 0 && n <= EVLINE_WRITE_MAX) { ssize_t w = write(g_fd, mem, n); (void)w; }
    free(mem);
}

/* ---- разбор ------------------------------------------------------------------------- */

/* Строка в кавычках, курсор *p стоит на открывающей. Разворачивает ТЕ escape-последовательности,
 * которые сама печатает jsonw_str_ascii (\", \\, управляющие и байты вне ASCII через \u00XX —
 * то есть кодовая точка не больше 0xff, она же исходный байт) плюс обычные \/ \b \f \n \r \t на
 * случай ручной строки в отладке. Что не влезло в буфер — обрезается, разбор всё равно
 * заканчивается корректно (курсор доходит до закрывающей кавычки). Возвращает указатель СРАЗУ
 * ЗА закрывающей кавычкой, либо NULL, если строка не закрылась. */
static const char *parse_jstr(const char *p, char *out, size_t outsz) {
    if (*p != '"') return NULL;
    p++;
    size_t o = 0;
    while (*p && *p != '"') {
        unsigned char c = (unsigned char)*p;
        if (c == '\\') {
            p++;
            if (!*p) return NULL;
            char v;
            switch (*p) {
            case '"': v = '"'; break;
            case '\\': v = '\\'; break;
            case '/': v = '/'; break;
            case 'b': v = '\b'; break;
            case 'f': v = '\f'; break;
            case 'n': v = '\n'; break;
            case 'r': v = '\r'; break;
            case 't': v = '\t'; break;
            case 'u': {
                if (!isxdigit((unsigned char)p[1]) || !isxdigit((unsigned char)p[2]) ||
                    !isxdigit((unsigned char)p[3]) || !isxdigit((unsigned char)p[4]))
                    return NULL;
                char hex[5] = { p[1], p[2], p[3], p[4], 0 };
                unsigned code = (unsigned)strtoul(hex, NULL, 16);
                /* Свой писатель кодирует только исходный байт (0..0xff) в нижних двух шестнадцатеричных
                 * цифрах — старшая половина всегда 00. Значение вне этого — не наша строка, но не
                 * повод отказывать разбору целиком: кладём как есть, обрезав до байта. */
                if (o + 1 < outsz) out[o++] = (char)(code & 0xff);
                p += 5;
                continue;
            }
            default:
                return NULL;
            }
            if (o + 1 < outsz) out[o++] = v;
            p++;
        } else {
            if (o + 1 < outsz) out[o++] = (char)c;
            p++;
        }
    }
    if (*p != '"') return NULL;
    out[o < outsz ? o : outsz - 1] = 0;
    return p + 1;
}

static const char *skip_ws(const char *p) {
    while (*p == ' ' || *p == '\t') p++;
    return p;
}

int evline_parse(const char *line, struct evline *out) {
    memset(out, 0, sizeof(*out));
    const char *p = skip_ws(line);
    if (*p != '{') return -1;
    p++;
    int have_ev = 0;
    for (;;) {
        p = skip_ws(p);
        if (*p == '}') { p++; break; }
        char key[EVLINE_KEYLEN];
        const char *q = parse_jstr(p, key, sizeof(key));
        if (!q) return -1;
        p = skip_ws(q);
        if (*p != ':') return -1;
        p = skip_ws(p + 1);

        if (!strcmp(key, "ev")) {
            const char *r = parse_jstr(p, out->ev, sizeof(out->ev));
            if (!r) return -1;
            have_ev = 1;
            p = r;
        } else if (*p == '"') {
            char val[EVLINE_VALLEN];
            const char *r = parse_jstr(p, val, sizeof(val));
            if (!r) return -1;
            p = r;
            if (out->n < EVLINE_MAXFIELDS) {
                struct evline_field *fl = &out->f[out->n++];
                snprintf(fl->key, sizeof(fl->key), "%s", key);
                fl->type = EVLINE_STR;
                snprintf(fl->v.s, sizeof(fl->v.s), "%s", val);
            }
        } else {
            char *end = NULL;
            errno = 0;
            long iv = strtol(p, &end, 10);
            if (end == p) return -1;
            if (out->n < EVLINE_MAXFIELDS) {
                struct evline_field *fl = &out->f[out->n++];
                snprintf(fl->key, sizeof(fl->key), "%s", key);
                fl->type = EVLINE_INT;
                fl->v.i = iv;
            }
            p = end;
        }
        p = skip_ws(p);
        if (*p == ',') { p++; continue; }
        if (*p == '}') { p++; break; }
        return -1;
    }
    return have_ev ? 0 : -1;
}

const char *evline_str(const struct evline *e, const char *key) {
    for (int i = 0; i < e->n; i++)
        if (e->f[i].type == EVLINE_STR && !strcmp(e->f[i].key, key)) return e->f[i].v.s;
    return NULL;
}

int evline_int(const struct evline *e, const char *key, long *out) {
    for (int i = 0; i < e->n; i++)
        if (e->f[i].type == EVLINE_INT && !strcmp(e->f[i].key, key)) { *out = e->f[i].v.i; return 1; }
    return 0;
}
