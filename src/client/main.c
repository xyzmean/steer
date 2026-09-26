/* steer — клиент демона движка (docs/architecture.md, раздел 4а, «Бинарники»; протокол —
 * docs/ctl.md).
 *
 * ЗАЧЕМ ОТДЕЛЬНАЯ ПРОГРАММА. Движок — это steerd: демон, компилятор, apply, помощники и
 * инструменты одним файлом. Но зовут его под именем `steer` все, кто был до демона: rpcd и
 * скрипты splify2, init-скрипт, стенды, человек в shell. Команды, на которые теперь отвечает
 * демон из своей памяти (status, diag, explain, conns, dns-log) или которые он исполняет сам
 * (apply — сверка с применённым, reload, subscribe), должны идти к нему: иначе status мимо демона
 * не видит хода перебора узлов, а apply мимо демона не знает, что помощников и резолвер держит
 * он. Всё остальное — и любая команда, когда демона нет, — работа самого движка, и её клиент
 * отдаёт steerd, заменяя себя им (execv с теми же аргументами). Так вызов `steer <команда>`
 * остаётся тем же для каждого, кто его делал, а клиент весит десятки килобайт: в нём нет ни
 * разбора спеки, ни компилятора — только разбор команды, протокол v1 и exec.
 *
 * ВЫВОД ТОТ ЖЕ. Ответ демона несёт код возврата, stdout и stderr одноимённой подкоманды — их
 * клиент и печатает, байт в байт, и выходит тем же кодом. Отказ самого сервера без кода
 * (denied, internal, bad-request…) — не ответ на вопрос, и клиент тогда тоже отдаёт команду
 * движку: прежнее поведение лучше отказа, который раньше не случался.
 *
 * К ТОМУ ЛИ ДЕМОНУ. Сокет — STEER_SOCKET или путь платформы. Демон на нём может обслуживать
 * другую спеку или другой каталог состояния (стенд, ручной запуск с --spec), и тогда ответ на
 * `steer status --spec X` был бы ответом про чужую спеку. Поэтому перед командой клиент
 * спрашивает `version`: демон называет свою спеку и каталог состояния, и команда идёт к нему,
 * только если они те же, что у вызова (пути сверяются после realpath). Иначе — движку.
 *
 * ГДЕ ДВИЖОК. STEER_ENGINE, иначе steerd в том же каталоге, что сам клиент (/proc/self/exe):
 * в пакете оба в /usr/sbin, на телефоне — в /system_ext/bin/der, у стендов — в build/. */
#define _GNU_SOURCE
#include <errno.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <sys/time.h>

#include "platform.h"

/* Пределы протокола v1 — те же, что у сервера (src/daemon/ctl.c, CTL_LINE_MAX, CTL_BODY_MAX). */
#define LINE_MAX_V1 512
#define BODY_MAX_V1 (1024L * 1024L)
/* Ответ: stdout до 1 МиБ и stderr до 64 КиБ, а экранирование (\u00XX) раздувает до шести раз. */
#define RESP_MAX (8UL * 1024UL * 1024UL)

/* Код выхода «демона нет» у команд, которые исполняет только он (reload, subscribe): отличим от
 * кодов подкоманд (0, 1 — поломка, 2 — отказ разбора), чтобы init.d мог сказать «демон не
 * запущен» отдельно от «reload не прошёл». */
#define EXIT_NODAEMON 3

static char **g_argv;
static char g_engine[PATH_MAX + 16];

static void engine_path(void) {
    const char *e = getenv("STEER_ENGINE");
    if (e && *e) {
        snprintf(g_engine, sizeof(g_engine), "%s", e);
        return;
    }
    char self[PATH_MAX];
    ssize_t n = readlink("/proc/self/exe", self, sizeof(self) - 1);
    if (n > 0) {
        self[n] = '\0';
        char *sl = strrchr(self, '/');
        if (sl) {
            *sl = '\0';
            snprintf(g_engine, sizeof(g_engine), "%s/steerd", self);
            return;
        }
    }
    snprintf(g_engine, sizeof(g_engine), "steerd");
}

/* Отдать команду движку: тот же argv, включая argv[0] — в списке процессов вызов выглядит так
 * же, как выглядел, а роль steerd по argv[0] выбирается только для steer-tools. */
static void run_engine(void) {
    if (strchr(g_engine, '/')) execv(g_engine, g_argv);
    else execvp(g_engine, g_argv);
    fprintf(stderr, "steer: не запустить движок %s: %s\n", g_engine, strerror(errno));
    exit(127);
}

/* ---- вызов ------------------------------------------------------------------------------ */

enum { K_LOCAL, K_ROUTE, K_DAEMON };   /* движку; демону, если он есть; только демону */

struct call {
    const char *cmd;
    int kind;
    const char *spec, *state_dir;
    const char *pos;          /* explain */
    int fast, dry_run;
};

/* Разобрать вызов так же строго, как движок, но только ради одного решения — к демону или нет.
 * Всё, что не укладывается в форму команды демона (другой флаг, справка, лишнее слово), идёт
 * движку: он и откажет своими словами, и справку напечатает свою. */
static int parse_call(int argc, char **argv, struct call *c) {
    memset(c, 0, sizeof(*c));
    int i = 1;
    /* --platform понимает любая команда в любом месте строки (src/daemon/main.c). */
    for (int k = 1; k < argc; k++) {
        if (strcmp(argv[k], "--platform") != 0) continue;
        if (k + 1 >= argc || plat_select(argv[k + 1]) != 0) return K_LOCAL;
        k++;
    }
    while (i < argc && !strcmp(argv[i], "--platform")) i += 2;
    if (i >= argc) return K_LOCAL;
    c->cmd = argv[i];
    int st = 0, sd = 0, fa = 0, dr = 0, pos = 0, npos = 0;
    if (!strcmp(c->cmd, "status")) { st = sd = fa = 1; c->kind = K_ROUTE; }
    else if (!strcmp(c->cmd, "diag") || !strcmp(c->cmd, "conns") || !strcmp(c->cmd, "dns-log")) {
        st = sd = 1;
        c->kind = K_ROUTE;
    } else if (!strcmp(c->cmd, "explain")) { st = sd = 1; pos = 1; c->kind = K_ROUTE; }
    else if (!strcmp(c->cmd, "apply")) { st = sd = dr = 1; c->kind = K_ROUTE; }
    else if (!strcmp(c->cmd, "reload") || !strcmp(c->cmd, "subscribe")) {
        st = sd = 1;
        c->kind = K_DAEMON;
    } else return K_LOCAL;

    for (int k = i + 1; k < argc; k++) {
        const char *a = argv[k];
        if (!strcmp(a, "--platform")) { k++; continue; }
        if (st && !strcmp(a, "--spec") && k + 1 < argc && argv[k + 1][0] != '-') {
            c->spec = argv[++k];
            continue;
        }
        if (sd && !strcmp(a, "--state-dir") && k + 1 < argc && argv[k + 1][0] != '-') {
            c->state_dir = argv[++k];
            continue;
        }
        if (fa && !strcmp(a, "--fast")) { c->fast = 1; continue; }
        if (dr && !strcmp(a, "--dry-run")) { c->dry_run = 1; continue; }
        if (pos && a[0] != '-' && a[0] && npos == 0) { c->pos = a; npos++; continue; }
        return K_LOCAL;
    }
    if (pos && !npos) return K_LOCAL;
    /* Проверка без применения — работа компилятора, демону в ней делать нечего. */
    if (c->dry_run) return K_LOCAL;
    /* Слово идёт в строку запроса, где разделитель — пробел, а конец — перевод строки. Слово с
     * ними исказило бы запрос, а не просто получило бы отказ; такое — движку (он и откажет). */
    if (c->pos && strpbrk(c->pos, " \t\r\n")) return K_LOCAL;
    return c->kind;
}

/* ---- сокет -------------------------------------------------------------------------------- */

static const char *g_sock;

/* Срок ответа: apply у демона идёт до 420 с (план и применение), сверх того — зависание. */
static int sock_open(int timeout_s) {
    struct sockaddr_un a;
    memset(&a, 0, sizeof(a));
    a.sun_family = AF_UNIX;
    if (strlen(g_sock) >= sizeof(a.sun_path)) return -1;
    snprintf(a.sun_path, sizeof(a.sun_path), "%s", g_sock);
    int s = socket(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0);
    if (s < 0) return -1;
    if (connect(s, (struct sockaddr *)&a, sizeof(a)) != 0) {
        close(s);
        return -1;
    }
    struct timeval tv = { timeout_s, 0 };
    if (timeout_s > 0) setsockopt(s, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
    return s;
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

/* Один запрос — один ответ: строка JSON до '\n'. NULL — соединения нет или ответ не пришёл. */
static char *roundtrip(const char *line, const char *body, size_t body_n, int timeout_s) {
    int s = sock_open(timeout_s);
    if (s < 0) return NULL;
    /* Ошибка записи не повод молчать: сервер мог отказать (тело больше предела) и закрыть
     * соединение, не читая, — его ответ всё равно лежит в сокете. */
    if (write_all(s, line, strlen(line)) == 0 && body_n) write_all(s, body, body_n);
    size_t cap = 4096, n = 0;
    char *r = malloc(cap);
    if (!r) { close(s); return NULL; }
    for (;;) {
        if (n + 1 >= cap) {
            if (cap >= RESP_MAX) break;
            char *q = realloc(r, cap * 2);
            if (!q) break;
            r = q;
            cap *= 2;
        }
        ssize_t m = read(s, r + n, cap - n - 1);
        if (m < 0 && errno == EINTR) continue;
        if (m <= 0) break;
        n += (size_t)m;
        if (memchr(r + n - (size_t)m, '\n', (size_t)m)) break;
    }
    close(s);
    r[n] = '\0';
    char *nl = strchr(r, '\n');
    if (!nl) { free(r); return NULL; }
    *nl = '\0';
    return r;
}

/* ---- ответ --------------------------------------------------------------------------------
 *
 * Разбор ровно того, что пишет сервер (src/daemon/ctl.c): объект верхнего уровня, строки с
 * экранированием cb_json (\" \\ \n \t \r и \u00XX для управляющих байтов; байты от 0x80 идут
 * как есть), целые, true/false, вложенные объекты и массивы (reload, changed) — пропускаются. */

struct str { char *p; size_t n; };

struct resp {
    int has_code, code;
    struct str out, err, error, message, spec_path, state_dir;
    int truncated, enabled, applied;
};

static const char *skip_ws(const char *s) {
    while (*s == ' ' || *s == '\t' || *s == '\r' || *s == '\n') s++;
    return s;
}

static int hexv(char c) {
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    return -1;
}

/* Строка JSON с s на открывающей кавычке. dst NULL — только пропустить. NULL — не строка. */
static const char *json_str(const char *s, struct str *dst) {
    if (*s != '"') return NULL;
    s++;
    size_t cap = 64, n = 0;
    char *b = dst ? malloc(cap) : NULL;
    if (dst && !b) return NULL;
    while (*s && *s != '"') {
        unsigned cp;
        int esc_u = 0;
        if (*s == '\\') {
            s++;
            switch (*s) {
            case 'n': cp = '\n'; break;
            case 't': cp = '\t'; break;
            case 'r': cp = '\r'; break;
            case 'b': cp = '\b'; break;
            case 'f': cp = '\f'; break;
            case 'u': {
                int h[4];
                for (int k = 0; k < 4; k++)
                    if ((h[k] = hexv(s[1 + k])) < 0) { free(b); return NULL; }
                cp = (unsigned)(h[0] << 12 | h[1] << 8 | h[2] << 4 | h[3]);
                esc_u = 1;
                s += 4;
                break;
            }
            case '\0': free(b); return NULL;
            default: cp = (unsigned char)*s; break;
            }
            s++;
        } else {
            cp = (unsigned char)*s++;
        }
        if (!dst) continue;
        unsigned char enc[4];
        size_t k = 0;
        /* Байт как есть — и сырой байт строки (UTF-8 сервер не экранирует), и \u00XX ниже 0x80
         * (так сервер пишет управляющие байты). Выше 0x7f через \u сервер не пишет; если
         * придёт — кодируется в UTF-8 честно. */
        if (!esc_u || cp < 0x80) enc[k++] = (unsigned char)cp;
        else if (cp < 0x800) {
            enc[k++] = (unsigned char)(0xC0 | cp >> 6);
            enc[k++] = (unsigned char)(0x80 | (cp & 0x3F));
        } else {
            enc[k++] = (unsigned char)(0xE0 | cp >> 12);
            enc[k++] = (unsigned char)(0x80 | ((cp >> 6) & 0x3F));
            enc[k++] = (unsigned char)(0x80 | (cp & 0x3F));
        }
        if (n + k + 1 > cap) {
            while (n + k + 1 > cap) cap *= 2;
            char *q = realloc(b, cap);
            if (!q) { free(b); return NULL; }
            b = q;
        }
        memcpy(b + n, enc, k);
        n += k;
    }
    if (*s != '"') { free(b); return NULL; }
    if (dst) {
        b[n] = '\0';
        dst->p = b;
        dst->n = n;
    }
    return s + 1;
}

/* Пропустить значение любого вида. */
static const char *json_skip(const char *s) {
    s = skip_ws(s);
    if (*s == '"') return json_str(s, NULL);
    if (*s == '{' || *s == '[') {
        int depth = 0;
        while (*s) {
            if (*s == '"') { s = json_str(s, NULL); if (!s) return NULL; continue; }
            if (*s == '{' || *s == '[') depth++;
            else if (*s == '}' || *s == ']') { if (--depth == 0) return s + 1; }
            s++;
        }
        return NULL;
    }
    while (*s && *s != ',' && *s != '}') s++;
    return s;
}

static int resp_parse(const char *s, struct resp *r) {
    memset(r, 0, sizeof(*r));
    r->enabled = r->applied = -1;
    s = skip_ws(s);
    if (*s++ != '{') return -1;
    for (;;) {
        s = skip_ws(s);
        if (*s == '}') return 0;
        struct str key = {0};
        if (!(s = json_str(s, &key))) return -1;
        s = skip_ws(s);
        if (*s++ != ':') { free(key.p); return -1; }
        s = skip_ws(s);
        struct str *dst = NULL;
        if (!strcmp(key.p, "stdout")) dst = &r->out;
        else if (!strcmp(key.p, "stderr")) dst = &r->err;
        else if (!strcmp(key.p, "error")) dst = &r->error;
        else if (!strcmp(key.p, "message")) dst = &r->message;
        else if (!strcmp(key.p, "spec_path")) dst = &r->spec_path;
        else if (!strcmp(key.p, "state_dir")) dst = &r->state_dir;
        if (dst && *s == '"') {
            free(dst->p);
            s = json_str(s, dst);
        } else if (!strcmp(key.p, "code")) {
            char *e = NULL;
            long v = strtol(s, &e, 10);
            if (e == s) { free(key.p); return -1; }
            r->has_code = 1;
            r->code = (int)v;
            s = e;
        } else {
            int *flag = !strcmp(key.p, "truncated") ? &r->truncated :
                        !strcmp(key.p, "enabled") ? &r->enabled :
                        !strcmp(key.p, "applied") ? &r->applied : NULL;
            if (flag && !strncmp(s, "true", 4)) *flag = 1;
            else if (flag && !strncmp(s, "false", 5)) *flag = 0;
            s = json_skip(s);
        }
        free(key.p);
        if (!s) return -1;
        s = skip_ws(s);
        if (*s == ',') { s++; continue; }
        if (*s == '}') return 0;
        return -1;
    }
}

/* Путь для сверки: realpath, если файл есть, иначе как написан. */
static void canon(const char *p, char *buf, size_t n) {
    char rp[PATH_MAX];
    snprintf(buf, n, "%s", realpath(p, rp) ? rp : p);
}

/* Демон на сокете обслуживает эти же спеку и каталог состояния? */
static int same_daemon(const struct call *c) {
    char *raw = roundtrip("version\n", NULL, 0, 10);
    if (!raw) return 0;
    struct resp r;
    int ok = resp_parse(raw, &r) == 0 && r.spec_path.p && r.state_dir.p;
    free(raw);
    if (ok) {
        char a[PATH_MAX + 1], b[PATH_MAX + 1];
        canon(c->spec ? c->spec : plat()->spec_path, a, sizeof(a));
        canon(r.spec_path.p, b, sizeof(b));
        ok = !strcmp(a, b);
        canon(c->state_dir ? c->state_dir : plat()->state_dir, a, sizeof(a));
        canon(r.state_dir.p, b, sizeof(b));
        ok = ok && !strcmp(a, b);
    }
    free(r.out.p); free(r.err.p); free(r.error.p); free(r.message.p);
    free(r.spec_path.p); free(r.state_dir.p);
    return ok;
}

static char *read_file(const char *path, size_t *n) {
    FILE *f = fopen(path, "rb");
    if (!f) return NULL;
    size_t cap = 65536, got = 0;
    char *b = malloc(cap);
    while (b) {
        size_t m = fread(b + got, 1, cap - got, f);
        got += m;
        if (got > (size_t)BODY_MAX_V1) break;
        if (m == 0) break;
        if (got == cap) {
            char *q = realloc(b, cap * 2);
            if (!q) { free(b); b = NULL; break; }
            b = q;
            cap *= 2;
        }
    }
    int bad = ferror(f);
    fclose(f);
    if (!b || bad || got > (size_t)BODY_MAX_V1) { free(b); return NULL; }
    *n = got;
    return b;
}

static void nap_ms(long ms) {
    struct timespec ts = { ms / 1000, (ms % 1000) * 1000000L };
    while (nanosleep(&ts, &ts) != 0 && errno == EINTR) {}
}

/* ---- subscribe: поток событий --------------------------------------------------------------- */

static int do_subscribe(void) {
    int s = sock_open(0);
    if (s < 0) return -1;
    if (write_all(s, "subscribe\n", 10) != 0) { close(s); return -1; }
    char buf[16384];
    ssize_t m;
    int first = 1, ok = 0;
    while ((m = read(s, buf, sizeof(buf))) > 0 || (m < 0 && errno == EINTR)) {
        if (m <= 0) continue;
        if (first) {
            /* Код выхода — по первой строке, ответу на сам subscribe. */
            ok = memmem(buf, (size_t)m, "\"code\":0", 8) != NULL &&
                 memmem(buf, (size_t)m, "\"error\":", 8) == NULL;
            first = 0;
        }
        fwrite(buf, 1, (size_t)m, stdout);
        fflush(stdout);
    }
    close(s);
    return first ? 2 : ok ? 0 : 1;
}

int main(int argc, char **argv) {
    g_argv = argv;
    engine_path();
    struct call c;
    int kind = parse_call(argc, argv, &c);
    if (kind == K_LOCAL) run_engine();

    const char *e = getenv("STEER_SOCKET");
    g_sock = e && *e ? e : plat()->ctl_sock;
    if (!same_daemon(&c)) {
        if (kind == K_ROUTE) run_engine();
        fprintf(stderr, "steer: %s: демон движка не отвечает на %s (или обслуживает другую "
                        "спеку) — %s исполняет только он\n", c.cmd, g_sock, c.cmd);
        return EXIT_NODAEMON;
    }
    if (!strcmp(c.cmd, "subscribe")) {
        int rc = do_subscribe();
        if (rc < 0) {
            fprintf(stderr, "steer: subscribe: нет соединения с %s\n", g_sock);
            return EXIT_NODAEMON;
        }
        return rc;
    }

    char line[LINE_MAX_V1 + 32];
    char *body = NULL;
    size_t body_n = 0;
    int readonly = 1;
    if (!strcmp(c.cmd, "status")) snprintf(line, sizeof(line), "status%s\n", c.fast ? " fast" : "");
    else if (!strcmp(c.cmd, "explain")) {
        if (strlen(c.pos) > LINE_MAX_V1 - 16) run_engine();
        snprintf(line, sizeof(line), "explain %s\n", c.pos);
    } else if (!strcmp(c.cmd, "apply")) {
        /* Спеку демону — телом, как её присылает приложение: он проверит её, положит на место
         * (это тот же файл — сверено выше) и применит только изменившееся. */
        body = read_file(c.spec ? c.spec : plat()->spec_path, &body_n);
        if (!body) run_engine();
        snprintf(line, sizeof(line), "apply %zu\n", body_n);
        readonly = 0;
    } else {
        snprintf(line, sizeof(line), "%s\n", c.cmd);
        if (!strcmp(c.cmd, "reload")) readonly = 0;
    }

    /* busy — четыре запроса уже идут: подождать, а не отдавать команду движку в обход демона
     * (apply рядом с идущим apply демона спорил бы с ним за одни таблицы). */
    struct resp r;
    char *raw = NULL;
    for (int tries = 0;; tries++) {
        raw = roundtrip(line, body, body_n, 600);
        if (!raw || resp_parse(raw, &r) != 0) {
            free(raw);
            if (readonly || kind == K_ROUTE) {
                if (!readonly) fprintf(stderr, "steer[warn] демон не ответил на %s — "
                                               "исполняю движком\n", c.cmd);
                free(body);
                run_engine();
            }
            fprintf(stderr, "steer: %s: демон не ответил\n", c.cmd);
            return EXIT_NODAEMON;
        }
        if (r.error.p && !strcmp(r.error.p, "busy") && tries < 100) {
            free(raw);
            nap_ms(100);
            continue;
        }
        break;
    }
    free(raw);
    free(body);

    if (!r.has_code) {
        /* Отказ сервера без исполнения: прежний путь — движок — лучше отказа, которого раньше не
         * было. Только демону принадлежащие команды отказом и отвечают. */
        if (kind == K_ROUTE) run_engine();
        fprintf(stderr, "steer: %s: %s\n", c.cmd, r.message.p ? r.message.p :
                r.error.p ? r.error.p : "демон отказал");
        return 1;
    }
    /* Обрезанный вывод читающей команды — повторить движком целиком, а не отдать обрубок. */
    if (r.truncated && readonly) run_engine();
    if (r.err.n) fwrite(r.err.p, 1, r.err.n, stderr);
    if (r.out.n) fwrite(r.out.p, 1, r.out.n, stdout);
    if (r.error.p)
        fprintf(stderr, "steer: %s: %s\n", c.cmd, r.message.p ? r.message.p : r.error.p);
    if (!strcmp(c.cmd, "apply") && r.applied == 0 && r.enabled == 0)
        fputs("steer: движок выключен — спека сохранена, в ядро не применялась\n", stderr);
    fflush(stdout);
    return r.error.p && r.code == 0 ? 1 : r.code;
}
