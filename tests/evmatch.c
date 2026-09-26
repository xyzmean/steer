/* Стенд формата событий помощников (src/lib/evline.h): запись в трубу, разбор обратно,
 * выключенность без STEER_EVENT_FD, потеря на полной трубе без блокировки и экранирование
 * строки why. Каждый сценарий — В ДОЧЕРНЕМ ПРОЦЕССЕ: evline_open() запоминает решение один
 * раз на весь процесс (g_fd), и внутри одного бинарника проверить и «нет переменной», и
 * «переменная есть», и «труба полна» можно только так же, как это происходит по-настоящему —
 * заново запущенным процессом с новым окружением. Родитель ничего не проверяет ВНУТРИ
 * потомка (unit_pass/unit_fail — статика процесса, потомку и родителю разные копии); он только
 * смотрит, что осталось в трубе, и это единственное наблюдаемое поведение, которое контракт
 * обещает читателю на другом конце.
 *
 * Пишущий конец трубы наследуется через fork() как обычный дескриптор: сравнивается не то,
 * умеет ли ребёнок ПОЛУЧИТЬ дескриптор (это делает демон — не наша забота здесь), а то, что
 * evline_open() слушается ИМЕННО переменной окружения, а не самого факта, что дескриптор
 * открыт и наследуется. */
#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

#include "evline.h"
#include "unit.h"

/* Забирает всё, что накопилось в трубе ПРЯМО СЕЙЧАС, не дожидаясь EOF (пишущий конец у нас
 * часто остаётся открытым и после потомка — закрывать его нельзя, иначе следующий сценарий
 * не смог бы писать в ту же трубу). poll с недолгим сроком: если событие пишется, оно уже
 * там к моменту, когда потомок завершился (обычный fork+exit, а не что-то асинхронное). */
static size_t drain(int fd, char *buf, size_t cap) {
    size_t n = 0;
    for (;;) {
        struct pollfd p = { fd, POLLIN, 0 };
        int pr = poll(&p, 1, 200);
        if (pr <= 0 || !(p.revents & POLLIN)) break;
        if (n + 1 >= cap) break;
        ssize_t r = read(fd, buf + n, cap - n - 1);
        if (r <= 0) break;
        n += (size_t)r;
    }
    buf[n] = 0;
    return n;
}

/* Запускает fn(arg) в отдельном процессе и ждёт его — С ПОТОЛКОМ. Потомок, который завис,
 * сам по себе провал: «неблокирующая труба» — это утверждение именно про то, что процесс
 * ВЕРНЁТСЯ, а не про то, что он вернётся и при этом ничего не запишет. */
static int run_child(void (*fn)(int), int arg) {
    pid_t pid = fork();
    if (pid < 0) return -1;
    if (pid == 0) {
        fn(arg);
        _exit(0);
    }
    time_t deadline = time(NULL) + 3;
    for (;;) {
        int status = 0;
        pid_t w = waitpid(pid, &status, WNOHANG);
        if (w == pid) return 0;
        if (time(NULL) >= deadline) {
            kill(pid, SIGKILL);
            waitpid(pid, &status, 0);
            return -1;               /* потомок висел — evline_emit заблокировался на трубе */
        }
        usleep(10000);
    }
}

/* ---- сценарий 1: без STEER_EVENT_FD — молчание, даже если дескриптор открыт и унаследован */

static void child_no_env(int wfd) {
    (void)wfd;
    unsetenv("STEER_EVENT_FD");
    evline_emit("up", (const char *)NULL);
}

/* ---- сценарий 2: переменная есть, но негодная — тоже молчание */

static void child_bad_negative(int wfd) {
    (void)wfd;
    setenv("STEER_EVENT_FD", "-5", 1);
    evline_emit("up", (const char *)NULL);
}
static void child_bad_text(int wfd) {
    (void)wfd;
    setenv("STEER_EVENT_FD", "не число", 1);
    evline_emit("up", (const char *)NULL);
}
static void child_bad_closed(int wfd) {
    (void)wfd;
    setenv("STEER_EVENT_FD", "999", 1);   /* такого дескриптора в чистом процессе нет */
    evline_emit("up", (const char *)NULL);
}

/* ---- сценарий 3: труба открыта по-настоящему — запись и разбор дают то же событие */

static void child_roundtrip(int wfd) {
    char envbuf[16];
    snprintf(envbuf, sizeof envbuf, "%d", wfd);
    setenv("STEER_EVENT_FD", envbuf, 1);
    /* Кавычка и байт вне ASCII в одной строке: жду экранирования и того, и другого, а не
     * только удобного случая из пары «\\» да «латиница». */
    evline_emit("down", "why", EVLINE_STR, "сервер \"замолчал\" — совсем",
                 "n", EVLINE_INT, 3L, (const char *)NULL);
}

/* ---- сценарий 4: труба полна — запись теряется, потомок не виснет */

static void child_full_pipe(int wfd) {
    char envbuf[16];
    snprintf(envbuf, sizeof envbuf, "%d", wfd);
    setenv("STEER_EVENT_FD", envbuf, 1);
    evline_emit("up", (const char *)NULL);
}

int main(void) {
    /* Сценарий 1. */
    {
        int p[2];
        if (pipe(p) != 0) { perror("pipe"); return 1; }
        run_child(child_no_env, p[1]);
        char buf[512];
        size_t n = drain(p[0], buf, sizeof buf);
        check("без STEER_EVENT_FD событие не уходит (дескриптор всё равно открыт)", 0, (long)n);
        close(p[0]); close(p[1]);
    }

    /* Сценарий 2, три негодных значения переменной. */
    {
        int p[2];
        if (pipe(p) != 0) { perror("pipe"); return 1; }
        run_child(child_bad_negative, p[1]);
        char buf[512];
        size_t n = drain(p[0], buf, sizeof buf);
        check("STEER_EVENT_FD=-5 — выключено", 0, (long)n);
        close(p[0]); close(p[1]);
    }
    {
        int p[2];
        if (pipe(p) != 0) { perror("pipe"); return 1; }
        run_child(child_bad_text, p[1]);
        char buf[512];
        size_t n = drain(p[0], buf, sizeof buf);
        check("STEER_EVENT_FD=не число — выключено", 0, (long)n);
        close(p[0]); close(p[1]);
    }
    {
        int p[2];
        if (pipe(p) != 0) { perror("pipe"); return 1; }
        run_child(child_bad_closed, p[1]);
        char buf[512];
        size_t n = drain(p[0], buf, sizeof buf);
        check("STEER_EVENT_FD=999 (нет такого) — выключено", 0, (long)n);
        close(p[0]); close(p[1]);
    }

    /* Сценарий 3: запись и разбор. */
    {
        int p[2];
        if (pipe(p) != 0) { perror("pipe"); return 1; }
        run_child(child_roundtrip, p[1]);
        char buf[512];
        size_t n = drain(p[0], buf, sizeof buf);
        check("событие с трубой ушло", 1, n > 0 ? 1 : 0);

        /* Сама строка на проводе экранирует и кавычку, и байт вне ASCII — это то, что
         * jsonw_str_ascii обязана сделать, и то, ради чего evline_emit зовёт именно её. */
        int has_escaped_quote = strstr(buf, "\\\"") != NULL;
        int has_u00 = strstr(buf, "\\u00") != NULL;
        check("why: кавычка экранирована (\\\")", 1, has_escaped_quote);
        check("why: байт вне ASCII экранирован (\\u00XX)", 1, has_u00);
        check("строка кончается переводом строки", 1, n > 0 && buf[n - 1] == '\n' ? 1 : 0);

        struct evline e;
        char *nl = strchr(buf, '\n');
        if (nl) *nl = 0;
        int rc = evline_parse(buf, &e);
        check("evline_parse разобрал строку", 0, rc);
        check_str("ev — \"down\"", "down", e.ev);
        const char *why = evline_str(&e, "why");
        check_str("why дошёл ПОБАЙТОВО, кавычка и не-ASCII восстановлены",
                   "сервер \"замолчал\" — совсем", why ? why : "(нет поля)");
        long nval = -1;
        int has_n = evline_int(&e, "n", &nval);
        check("поле n нашлось", 1, has_n);
        check("поле n — число 3", 3, nval);
        close(p[0]); close(p[1]);
    }

    /* Сценарий 4: труба полна. Пишущий конец переводится в неблокирующий режим здесь же —
     * ровно так evline_open() поступил бы сам, только на этот раз до фактического открытия
     * трубы помощником, чтобы заполнение не повисло у СТЕНДА. */
    {
        int p[2];
        if (pipe(p) != 0) { perror("pipe"); return 1; }
        int fl = fcntl(p[1], F_GETFL, 0);
        fcntl(p[1], F_SETFL, fl | O_NONBLOCK);
        size_t prefilled = 0;
        char junk[4096];
        memset(junk, 'X', sizeof junk);
        for (;;) {
            ssize_t w = write(p[1], junk, sizeof junk);
            if (w <= 0) break;
            prefilled += (size_t)w;
        }
        check("труба и правда заполнена (запись без места отказала)", 1,
              prefilled > 0 ? 1 : 0);

        time_t t0 = time(NULL);
        int rc = run_child(child_full_pipe, p[1]);
        time_t took = time(NULL) - t0;
        check("потомок на полной трубе не завис", 0, rc);
        check("потомок вернулся быстро (не ждал места в трубе)", 1, took < 2 ? 1 : 0);

        /* Читаем ВСЁ, что накопилось (наш мусор + возможную дописку), и сравниваем со
         * своим же мусором: событие потерялось молча — то есть новых байт не появилось. */
        char *all = malloc(prefilled + 4096);
        size_t got = 0;
        for (;;) {
            struct pollfd pf = { p[0], POLLIN, 0 };
            if (poll(&pf, 1, 100) <= 0 || !(pf.revents & POLLIN)) break;
            ssize_t r = read(p[0], all + got, prefilled + 4096 - got);
            if (r <= 0) break;
            got += (size_t)r;
        }
        check("на полной трубе новых байт не прибавилось (событие потеряно, не встало в очередь)",
              (long)prefilled, (long)got);
        free(all);
        close(p[0]); close(p[1]);
    }

    return unit_done("evmatch");
}
