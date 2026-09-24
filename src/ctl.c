/* Управляющий сокет движка: `steer ctl-serve` (сервер) и `steer ctl` (клиент для отладки).
 *
 * ЗАЧЕМ. На роутере управляющий слой splify2 зовёт движок как программу: rpcd исполняет
 * `steer status`, кладёт спеку в /etc/steer и зовёт `steer apply`. На телефоне так нельзя.
 * Приложение splify2 живёт в домене splify2_app (vendor/der/sepolicy), и политика нарочно не
 * даёт ему ни исполнить движок, ни прочитать его файлы: движок невидим для всех приложений, и
 * исключение для одного из них — это одна дверь, а не ключи от всего дома. Эта дверь —
 * unix-сокет с меткой steerd_socket, к которому SELinux пускает только splify2_app. За дверью
 * сидит этот сервер и делает от имени приложения ровно то, что перечислено в таблице команд
 * ниже, — и ничего сверх.
 *
 * ПРОТОКОЛ (версия 1; то же самое для автора моста в приложении — в docs/ctl.md).
 *
 *   Одно соединение — один запрос и один ответ, затем сервер закрывает соединение.
 *
 *   Запрос — строка ASCII до 512 байт с '\n' в конце: имя команды и её слова через ОДИН
 *   пробел. У команд с телом (apply, check) последнее слово — длина тела в байтах десятичным
 *   числом, и сразу за '\n' идёт ровно столько байт тела:
 *       status\n
 *       explain youtube.com\n
 *       apply 1834\n{"schema":2,...}
 *   Тело — не больше 1 МиБ. На весь запрос, строку и тело, — пять секунд.
 *
 *   Ответ — один объект JSON в одну строку с '\n' в конце:
 *       {"v":1,"cmd":"status","code":0,"stdout":"...","stderr":"..."}
 *   code — код возврата одноимённой подкоманды движка (0 — успех), stdout и stderr — её вывод
 *   строками (у status и diag stdout — сам JSON, его разбирают второй раз). stdout
 *   обрезается на 1 МиБ, stderr на 64 КиБ; обрезанное помечается "truncated":true.
 *   Отказ самого сервера — без code, с полем error и человеческим message:
 *       {"v":1,"error":"denied","message":"..."}
 *   Значения error: bad-request, too-large, unknown-command, denied, busy, internal и timeout
 *   (у timeout code есть: команда шла и была убита, её вывод до этого момента приложен).
 *   Команды apply и reload добавляют свои поля — см. их обработчики и docs/ctl.md.
 *
 * ПОЧЕМУ СТРОКА И ДЛИНА, а не JSON в запросе. Запрос короткий и его слова всё равно идут в
 * argv подкоманды — разбирать ради них JSON в движке значило бы завести второй разборщик
 * рядом со спекой ради двух слов. Длина тела объявляется ЗАРАНЕЕ, а не «читать до закрытия»:
 * так слишком большое тело отвергается до того, как прочитан первый его байт, а у клиента
 * не требуется полузакрытия сокета (у LocalSocket Android оно есть, но лишнее условие
 * совместимости — лишний способ сломаться).
 *
 * ИСПОЛНЕНИЕ — fork+exec самого себя с нужной подкомандой и захватом вывода. Не вызов
 * функций в процессе сервера, и доводов три. (1) Команды движка загружают спеку в
 * глобальные массивы, и второй load_spec в том же процессе склеил бы два чтения — тот же
 * довод, что у failover_loop и supervise. (2) Сбой команды — die() с exit, утечка, зависание
 * на nft — задевает только её процесс: сервер продолжает принимать. (3) Ответ приложению —
 * ровно то, что человек увидит, набрав ту же подкоманду руками в adb root shell, то есть
 * одна правда на двоих, а не вторая реализация status «для сокета».
 *
 * КОГО ПУСКАТЬ. Первый замок — SELinux: connectto к steerd разрешён splify2_app, и кроме него
 * к сокету может прийти разве что root (su на userdebug) и init. Второй замок — здесь, по
 * SO_PEERCRED и SO_PEERSEC: uid 0 (root) и 1000 (system) — да; процесс в домене splify2_app
 * — да, если он у владельца устройства (пользователь 0); прочие uid — только названные
 * флагом --allow-uid (стенд, отладка). UID приложения нигде не записан и не угадывается:
 * он назначается при установке и у каждого телефона свой, а читать /data/system/packages.list
 * значило бы дать движку ещё одно право. Вместо этого спрашивается ядро — какой у собеседника
 * контекст SELinux, — и ответ «splify2_app» дан той же привязкой в seapp_contexts (имя пакета
 * плюс платформенная подпись), на которой держится весь запрет. Подменить его приложению с
 * тем же именем пакета, но чужой подписью нельзя: seinfo считается по сертификату.
 * Почему только пользователь 0: движок меняет маршрутизацию ВСЕГО устройства, а гостевой
 * пользователь или рабочий профиль — не тот, кто ею распоряжается; Android по той же логике
 * не даёт вторичным пользователям настройки сети устройства.
 *
 * ПРЕДЕЛЫ. Не больше четырёх запросов одновременно (пятому — busy сразу, не очередь: очередь
 * держала бы соединения открытыми на неопределённое время); строка 512 байт, тело 1 МиБ; пять
 * секунд на запрос; у каждой команды свой срок исполнения, по истечении — SIGKILL всей группе
 * процессов команды (nft и ip, которых она запустила, тоже). Сервер обслуживает соединение в
 * отдельном процессе, поэтому медленный или молчащий клиент держит только свой процесс.
 *
 * БАТАРЕЯ. Сервер спит в ppoll без срока: ни таймеров, ни периодических действий. Проснуться
 * его может только соединение или сигнал. Сроки запроса и команды существуют лишь пока идёт
 * запрос и считаются на CLOCK_MONOTONIC.
 *
 * ГДЕ СОКЕТ. /data/misc/steer/steer.sock, создаёт его сам сервер. Почему не опция `socket` у
 * init (сокет в /dev/socket, как у netd): каталог /dev/socket может листать любой домен
 * (system/sepolicy, domain.te: `allow domain socket_device:dir r_dir_perms`), то есть имя
 * steerd увидело бы любое приложение простым `ls` — а требование владельца в том, чтобы
 * движка для приложений не было видно. Каталог /data/misc/steer со своим типом приложениям
 * не листается; метку steerd_socket сокету ставит type_transition по имени файла (см.
 * vendor/der/sepolicy/private/steerd.te). Цена своего сокета — убрать прежний файл при
 * старте: сервер сначала пробует к нему подключиться (живой соседний сервер — отказ стартовать),
 * и только мёртвый файл удаляет. */
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>
#include <stdint.h>
#include <errno.h>
#include <unistd.h>
#include <fcntl.h>
#include <signal.h>
#include <poll.h>
#include <time.h>
#include <dirent.h>
#include <limits.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <sys/file.h>
#ifdef __BIONIC__
#include <sys/system_properties.h>
#endif

#include "paths.h"
#include "ctl.h"

/* Путь сокета по умолчанию. Под #ifndef, как корни в paths.h: сборка может задать свой. */
#ifndef STEER_CTL_SOCK
#define STEER_CTL_SOCK STEER_ETC_DIR "/steer.sock"
#endif
/* Выключатель движка — то же свойство, за которым следит init (vendor/der/init/steerd.rc). */
#define STEER_CTL_PROP "persist.der.steer.enabled"

#define CTL_LINE_MAX    512
#define CTL_BODY_MAX    (1024 * 1024)
#define CTL_OUT_MAX     (1024 * 1024)
#define CTL_ERR_MAX     (64 * 1024)
#define CTL_CLIENTS_MAX 4
#define CTL_REQ_MS      5000
/* Последняя страховка процесса-обработчика: если что-то в нём зависнет мимо всех сроков
 * (блокировка apply, которую держит зависший сосед), он умирает сам, а клиент видит закрытое
 * соединение. Больше самого длинного срока команды (apply) с запасом на ожидание блокировки. */
#define CTL_HANDLER_S   900
#define CTL_ALLOW_UIDS  8
#define CTL_AID_SYSTEM  1000
#define CTL_USER_RANGE  100000   /* AID_USER_OFFSET: uid = пользователь * 100000 + приложение */

#define LOG_W "steer[warn] ctl: "
#define LOG_I "steer[info] ctl: "

struct ctl_conf {
    const char *sock;
    const char *spec;
    const char *state_dir;       /* NULL — умолчание движка, флаг подкомандам не передаётся */
    const char *allow_domain;    /* NULL или "" — по домену не пускать */
    uid_t allow_uid[CTL_ALLOW_UIDS];
    int allow_uid_n;
    char exe[PATH_MAX];
};

/* ---- буфер ---------------------------------------------------------------------------- */

struct cbuf {
    char *p;
    size_t n, cap;
    size_t max;      /* 0 — без предела */
    int trunc;
};

static void cb_put(struct cbuf *b, const void *s, size_t n) {
    if (b->max && b->n + n > b->max) {
        n = b->max > b->n ? b->max - b->n : 0;
        b->trunc = 1;
    }
    if (b->n + n + 1 > b->cap) {
        size_t c = b->cap ? b->cap : 1024;
        while (c < b->n + n + 1) c *= 2;
        char *q = realloc(b->p, c);
        if (!q) { b->trunc = 1; return; }
        b->p = q;
        b->cap = c;
    }
    if (n) memcpy(b->p + b->n, s, n);
    b->n += n;
    b->p[b->n] = '\0';
}

static void cb_str(struct cbuf *b, const char *s) { cb_put(b, s, strlen(s)); }

static void cb_fmt(struct cbuf *b, const char *fmt, ...) {
    char t[1024];
    va_list ap;
    va_start(ap, fmt);
    int k = vsnprintf(t, sizeof(t), fmt, ap);
    va_end(ap);
    if (k > 0) cb_put(b, t, (size_t)k < sizeof(t) ? (size_t)k : sizeof(t) - 1);
}

/* Обрезанный на пределе вывод может кончиться посреди символа UTF-8 (движок пишет
 * по-русски), и такой хвост разборщик приложения заменил бы мусором. Срезаем недописанный
 * символ целиком. */
static void cb_utf8_trim(struct cbuf *b) {
    if (!b->trunc || !b->n) return;
    size_t i = b->n, k = 0;
    while (i > 0 && k < 4 && ((unsigned char)b->p[i - 1] & 0xC0) == 0x80) { i--; k++; }
    if (i == 0) return;
    unsigned char lead = (unsigned char)b->p[i - 1];
    size_t need = lead >= 0xF0 ? 3 : lead >= 0xE0 ? 2 : lead >= 0xC0 ? 1 : 0;
    if (need != k) { b->n = lead >= 0xC0 ? i - 1 : b->n; b->p[b->n] = '\0'; }
}

/* Строка JSON. Байты от 0x80 идут как есть: вывод движка — UTF-8. */
static void cb_json(struct cbuf *b, const char *s, size_t n) {
    cb_put(b, "\"", 1);
    size_t st = 0;
    for (size_t i = 0; i < n; i++) {
        unsigned char c = (unsigned char)s[i];
        const char *e = NULL;
        char u[8];
        if (c == '"') e = "\\\"";
        else if (c == '\\') e = "\\\\";
        else if (c == '\n') e = "\\n";
        else if (c == '\t') e = "\\t";
        else if (c == '\r') e = "\\r";
        else if (c < 0x20 || c == 0x7f) { snprintf(u, sizeof(u), "\\u%04x", c); e = u; }
        if (!e) continue;
        cb_put(b, s + st, i - st);
        cb_str(b, e);
        st = i + 1;
    }
    cb_put(b, s + st, n - st);
    cb_put(b, "\"", 1);
}

static void cb_jstr(struct cbuf *b, const char *s) { cb_json(b, s, strlen(s)); }

/* ---- время и ввод-вывод со сроком ---------------------------------------------------- */

static long ctl_now_ms(void) {
    struct timespec t;
    clock_gettime(CLOCK_MONOTONIC, &t);
    return (long)t.tv_sec * 1000L + t.tv_nsec / 1000000L;
}

/* Прочитать ровно n байт до срока. 0 — прочитано, -1 — обрыв или срок. */
static int ctl_read_full(int fd, char *buf, size_t n, long deadline) {
    size_t got = 0;
    while (got < n) {
        long left = deadline - ctl_now_ms();
        if (left <= 0) return -1;
        struct pollfd p = { fd, POLLIN, 0 };
        int r = poll(&p, 1, (int)left);
        if (r < 0 && errno == EINTR) continue;
        if (r <= 0) return -1;
        ssize_t m = read(fd, buf + got, n - got);
        if (m < 0 && (errno == EINTR || errno == EAGAIN)) continue;
        if (m <= 0) return -1;
        got += (size_t)m;
    }
    return 0;
}

/* Строка запроса — по байту: строка короткая, запросы редки, а чтение по байту не
 * захватывает начало тела, которое пришлось бы потом возвращать. 0 — есть строка (без '\n'),
 * -1 — обрыв или срок, -2 — длиннее предела. */
static int ctl_read_line(int fd, char *line, size_t cap, long deadline) {
    size_t n = 0;
    for (;;) {
        char c;
        if (ctl_read_full(fd, &c, 1, deadline) != 0) return -1;
        if (c == '\n') break;
        if (n + 1 >= cap) return -2;
        line[n++] = c;
    }
    if (n && line[n - 1] == '\r') n--;
    line[n] = '\0';
    return 0;
}

static int ctl_write_all(int fd, const char *s, size_t n) {
    while (n) {
        ssize_t w = write(fd, s, n);
        if (w < 0 && errno == EINTR) continue;
        if (w <= 0) return -1;
        s += w;
        n -= (size_t)w;
    }
    return 0;
}

/* ---- ответы ---------------------------------------------------------------------------- */

static void resp_begin(struct cbuf *r, const char *cmd) {
    cb_str(r, "{\"v\":1");
    if (cmd) { cb_str(r, ",\"cmd\":"); cb_jstr(r, cmd); }
}

static void resp_error(struct cbuf *r, const char *err, const char *msg) {
    cb_str(r, ",\"error\":");
    cb_jstr(r, err);
    cb_str(r, ",\"message\":");
    cb_jstr(r, msg);
}

static void resp_run(struct cbuf *r, int code, struct cbuf *out, struct cbuf *err) {
    cb_utf8_trim(out);
    cb_utf8_trim(err);
    cb_fmt(r, ",\"code\":%d,\"stdout\":", code);
    cb_json(r, out->p ? out->p : "", out->n);
    cb_str(r, ",\"stderr\":");
    cb_json(r, err->p ? err->p : "", err->n);
    if (out->trunc || err->trunc) cb_str(r, ",\"truncated\":true");
}

static void resp_send(int c, struct cbuf *r) {
    cb_str(r, "}\n");
    if (r->p) ctl_write_all(c, r->p, r->n);
}

/* Закрыть соединение, не оставив в нём непрочитанного запроса.
 *
 * Unix-сокет, закрытый с непрочитанными данными, ставит собеседнику ECONNRESET (ядро,
 * unix_release_sock), и тот получает его следующим чтением — СРАЗУ ПОСЛЕ нашего ответа. Ответ
 * при этом не теряется, но клиент, читающий «до закрытия», вместо конца потока получает
 * исключение (у LocalSocket Android — IOException). Так закрывался бы каждый отказ: слишком
 * длинная строка, тело больше предела, busy — всё это отвечается, не дочитав запрос. Поэтому:
 * полузакрыть запись (клиент видит конец ответа), дочитать и выбросить то, что он успел
 * прислать, и только потом закрыть. wait_ms — сколько ждать остатка: обработчик может
 * позволить себе секунду, сам сервер (denied, busy) — нет, он дочитывает только то, что уже
 * пришло. */
static void ctl_close(int c, int wait_ms) {
    shutdown(c, SHUT_WR);
    long deadline = ctl_now_ms() + wait_ms;
    size_t total = 0;
    char buf[16384];
    while (total < 4 * (size_t)CTL_BODY_MAX) {
        long left = deadline - ctl_now_ms();
        if (wait_ms > 0) {
            if (left <= 0) break;
            struct pollfd p = { c, POLLIN, 0 };
            int r = poll(&p, 1, (int)left);
            if (r < 0 && errno == EINTR) continue;
            if (r <= 0) break;
        }
        ssize_t m = recv(c, buf, sizeof(buf), wait_ms > 0 ? 0 : MSG_DONTWAIT);
        if (m < 0 && errno == EINTR) continue;
        if (m <= 0) break;
        total += (size_t)m;
    }
    close(c);
}

/* Отказ одной строкой — для тех, кого не пустили или кому некогда: процесса-обработчика у
 * них нет, отвечает сам сервер. Ответ короче буфера сокета, запись не блокирует. */
static void ctl_refuse(int c, const char *cmd, const char *err, const char *msg) {
    struct cbuf r = {0};
    resp_begin(&r, cmd);
    resp_error(&r, err, msg);
    resp_send(c, &r);
    free(r.p);
}

/* ---- исполнение подкоманды ------------------------------------------------------------- */

/* Запустить движок с argv, собрать stdout и stderr, ждать не дольше timeout_s. Возвращает
 * код возврата (убитой сигналом — 128 + номер, как в shell) или -1, если запустить не
 * удалось. *timed_out — команда убита по сроку. */
static int ctl_exec(const char *exe, char *const argv[], int timeout_s,
                    struct cbuf *out, struct cbuf *err, int *timed_out) {
    int po[2], pe[2];
    *timed_out = 0;
    if (pipe2(po, O_CLOEXEC) != 0) return -1;
    if (pipe2(pe, O_CLOEXEC) != 0) { close(po[0]); close(po[1]); return -1; }
    pid_t pid = fork();
    if (pid < 0) {
        close(po[0]); close(po[1]); close(pe[0]); close(pe[1]);
        return -1;
    }
    if (pid == 0) {
        /* Своя группа процессов: по сроку убивается и то, что команда успела запустить
         * (nft, ip, iptables), а не только она сама. */
        setpgid(0, 0);
        int nul = open("/dev/null", O_RDONLY);
        if (nul >= 0) dup2(nul, 0);
        dup2(po[1], 1);
        dup2(pe[1], 2);
        /* Игнорирование SIGPIPE наследуется через exec, а подкоманды рассчитывают на
         * обычное поведение. */
        signal(SIGPIPE, SIG_DFL);
        sigset_t none;
        sigemptyset(&none);
        sigprocmask(SIG_SETMASK, &none, NULL);
        execv(exe, argv);
        dprintf(2, LOG_W "не запустить %s: %s\n", exe, strerror(errno));
        _exit(127);
    }
    close(po[1]);
    close(pe[1]);
    long deadline = ctl_now_ms() + (long)timeout_s * 1000L;
    struct pollfd p[2] = { { po[0], POLLIN, 0 }, { pe[0], POLLIN, 0 } };
    int open_n = 2, killed = 0;
    char buf[16384];
    while (open_n > 0) {
        long left = deadline - ctl_now_ms();
        if (left <= 0) {
            if (killed) break;          /* убита, а трубы держит кто-то вне группы — хватит */
            kill(-pid, SIGKILL);
            kill(pid, SIGKILL);
            killed = 1;
            *timed_out = 1;
            deadline = ctl_now_ms() + 2000;
            continue;
        }
        int r = poll(p, 2, (int)left);
        if (r < 0 && errno == EINTR) continue;
        if (r < 0) break;
        for (int k = 0; k < 2; k++) {
            if (p[k].fd < 0 || !p[k].revents) continue;
            ssize_t m = read(p[k].fd, buf, sizeof(buf));
            if (m > 0) cb_put(k ? err : out, buf, (size_t)m);
            else if (m == 0 || (errno != EINTR && errno != EAGAIN)) {
                close(p[k].fd);
                p[k].fd = -1;
                open_n--;
            }
        }
    }
    for (int k = 0; k < 2; k++) if (p[k].fd >= 0) close(p[k].fd);

    /* Трубы закрыты — почти всегда это и есть выход команды. Ждём его без блокировки
     * навсегда: команда, закрывшая вывод и оставшаяся жить, не должна держать ответ. */
    int st = 0;
    long nap = 1;
    for (;;) {
        pid_t w = waitpid(pid, &st, WNOHANG);
        if (w == pid) break;
        if (w < 0 && errno != EINTR) return -1;
        if (ctl_now_ms() >= deadline) {
            if (killed) { waitpid(pid, &st, 0); break; }
            kill(-pid, SIGKILL);
            kill(pid, SIGKILL);
            killed = 1;
            *timed_out = 1;
            deadline = ctl_now_ms() + 2000;
        }
        struct timespec ts = { 0, nap * 1000000L };
        nanosleep(&ts, NULL);
        if (nap < 50) nap *= 2;
    }
    if (WIFEXITED(st)) return WEXITSTATUS(st);
    if (WIFSIGNALED(st)) return 128 + WTERMSIG(st);
    return -1;
}

/* ---- выключатель движка ---------------------------------------------------------------- */

#ifdef __BIONIC__
static void ctl_prop_cb(void *cookie, const char *name, const char *value, uint32_t serial) {
    (void)name; (void)serial;
    snprintf((char *)cookie, PROP_VALUE_MAX, "%s", value);
}
#endif

/* Включён ли движок. На телефоне это свойство, которое ставит приложение и за которым
 * следит init: при выключенном движке apply через сокет только СОХРАНЯЕТ спеку — поставить
 * правила в ядро значило бы включить движок в обход выключателя, а демонов, которым их
 * обслуживать (резолвер, сторож), init при выключенном не держит. Включат — init применит
 * сохранённую спеку сам (steerd.rc).
 *
 * Вне bionic свойств нет; там это шов стенда STEER_CTL_ENABLED=0, по умолчанию «включён». */
static int ctl_enabled(void) {
#ifdef __BIONIC__
    char v[PROP_VALUE_MAX] = "";
    const prop_info *pi = __system_property_find(STEER_CTL_PROP);
    if (pi) __system_property_read_callback(pi, ctl_prop_cb, v);
    return !strcmp(v, "1");
#else
    const char *e = getenv("STEER_CTL_ENABLED");
    return !(e && !strcmp(e, "0"));
#endif
}

/* ---- таблица команд ------------------------------------------------------------------- */

enum ctl_argkind {
    CA_NONE = 0,
    CA_NAME,      /* имя выхода: [A-Za-z0-9_.-], до 31 знака, не с «-» и не с «.» */
    CA_TARGET,    /* адрес или имя для explain: ещё «:» и «/», до 253 знаков */
    CA_INT,       /* целое в [lo, hi] */
    CA_LIT,       /* ровно слово lit; уходит в argv одним флагом без значения */
};

struct ctl_arg {
    enum ctl_argkind kind;
    const char *flag;    /* NULL — позиционный аргумент подкоманды */
    const char *lit;
    long lo, hi;
};

struct ctl_req;
typedef void (*ctl_fn)(const struct ctl_req *q, struct cbuf *r);

struct ctl_cmd {
    const char *name;
    const char *sub;          /* подкоманда движка; NULL — своя обработка (fn) */
    ctl_fn fn;
    int body;                 /* после строки идёт тело, последнее слово — его длина */
    int argmin, argmax;
    struct ctl_arg args[3];
    int timeout_s;
    int spec;                 /* передать подкоманде --spec и --state-dir сервера */
};

struct ctl_req {
    const struct ctl_cmd *cmd;
    const struct ctl_conf *cf;
    const char *argv[3];
    int argc;
    const char *body;
    size_t body_n;
};

static void ctl_do_apply(const struct ctl_req *q, struct cbuf *r);
static void ctl_do_check(const struct ctl_req *q, struct cbuf *r);
static void ctl_do_reload(const struct ctl_req *q, struct cbuf *r);

/* ТАБЛИЦА — единственное, что сервер умеет. Команда, которой здесь нет, не исполняется ни в
 * каком виде: слова запроса никогда не становятся именем подкоманды, в argv идут только
 * проверенные по виду аргументы на заранее назначенных местах.
 *
 * Новая команда поверх готовой подкоманды движка — одна строка. Так войдут следующей волной
 * соединения и журнал резолвера, когда у движка появятся подкоманды для них:
 *   {"conns",   "conns",   NULL, 0, 0, 0, {{0}}, 15, 1},
 *   {"dns-log", "dns-log", NULL, 0, 0, 0, {{0}}, 15, 1},
 *
 * Сроки: status и explain — десятки миллисекунд на роутере, срок с запасом на медленное
 * хранилище телефона; diag вдвое дороже status; vless-probe без номера узла перебирает
 * узлы подписки по очереди, каждый со своим --timeout. */
static const struct ctl_cmd CTL_CMDS[] = {
    {"version",     "version",     NULL, 0, 0, 0, {{0}}, 5, 0},
    {"status",      "status",      NULL, 0, 0, 1, {{CA_LIT, "--fast", "fast", 0, 0}}, 15, 1},
    {"diag",        "diag",        NULL, 0, 0, 0, {{0}}, 30, 1},
    {"explain",     "explain",     NULL, 0, 1, 1, {{CA_TARGET, NULL, NULL, 0, 0}}, 15, 1},
    {"vless-nodes", "vless-nodes", NULL, 0, 1, 1, {{CA_NAME, NULL, NULL, 0, 0}}, 15, 1},
    {"vless-probe", "vless-probe", NULL, 0, 1, 3,
        {{CA_NAME, NULL, NULL, 0, 0},
         {CA_INT, "--node", NULL, -1, 9999},
         {CA_INT, "--timeout", NULL, 1, 30}}, 180, 1},
    {"check",       NULL, ctl_do_check,  1, 0, 0, {{0}}, 0, 1},
    {"apply",       NULL, ctl_do_apply,  1, 0, 0, {{0}}, 0, 1},
    {"reload",      NULL, ctl_do_reload, 0, 0, 0, {{0}}, 0, 1},
};

static const struct ctl_cmd *ctl_lookup(const char *name) {
    for (size_t i = 0; i < sizeof(CTL_CMDS) / sizeof(CTL_CMDS[0]); i++)
        if (!strcmp(CTL_CMDS[i].name, name)) return &CTL_CMDS[i];
    return NULL;
}

/* Проверка слова по виду. Слова идут в argv без shell, но слово с «-» в начале подкоманда
 * приняла бы за флаг — `explain --spec` читал бы чужой файл, — поэтому вид проверяется
 * строго, до запуска. */
static const char *ctl_arg_bad(const struct ctl_arg *a, const char *w) {
    size_t n = strlen(w);
    switch (a->kind) {
    case CA_LIT:
        return strcmp(w, a->lit) ? "здесь понимается только одно слово" : NULL;
    case CA_INT: {
        char *e = NULL;
        errno = 0;
        long v = strtol(w, &e, 10);
        if (!n || n > 6 || *e || errno) return "нужно целое число";
        if (v < a->lo || v > a->hi) return "число вне допустимого";
        return NULL;
    }
    case CA_NAME:
    case CA_TARGET: {
        size_t lim = a->kind == CA_NAME ? 31 : 253;
        if (!n || n > lim) return "слишком длинное или пустое";
        if (w[0] == '-' || w[0] == '.') return "не может начинаться с «-» или «.»";
        for (size_t i = 0; i < n; i++) {
            unsigned char c = (unsigned char)w[i];
            int ok = (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') ||
                     (c >= '0' && c <= '9') || c == '_' || c == '.' || c == '-';
            if (a->kind == CA_TARGET && (c == ':' || c == '/')) ok = 1;
            if (!ok) return "недопустимый знак";
        }
        return NULL;
    }
    default:
        return "лишнее слово";
    }
}

/* argv подкоманды: движок, подкоманда, аргументы по местам, затем спека и состояние. */
static size_t ctl_argv(const struct ctl_req *q, const char *sub, char **av, size_t cap) {
    size_t n = 0;
    av[n++] = (char *)q->cf->exe;
    av[n++] = (char *)sub;
    for (int i = 0; i < q->argc && n + 2 < cap; i++) {
        const struct ctl_arg *a = &q->cmd->args[i];
        if (a->flag) av[n++] = (char *)a->flag;
        if (a->kind != CA_LIT || !a->flag) av[n++] = (char *)q->argv[i];
    }
    if (q->cmd->spec && n + 5 < cap) {
        av[n++] = "--spec";
        av[n++] = (char *)q->cf->spec;
        if (q->cf->state_dir) {
            av[n++] = "--state-dir";
            av[n++] = (char *)q->cf->state_dir;
        }
    }
    av[n] = NULL;
    return n;
}

/* Общий случай: исполнить подкоманду и отдать её код и вывод. */
static void ctl_run_sub(const struct ctl_req *q, struct cbuf *r) {
    char *av[16];
    ctl_argv(q, q->cmd->sub, av, sizeof(av) / sizeof(av[0]));
    struct cbuf out = { .max = CTL_OUT_MAX }, err = { .max = CTL_ERR_MAX };
    int to = 0;
    int code = ctl_exec(q->cf->exe, av, q->cmd->timeout_s, &out, &err, &to);
    if (code < 0) resp_error(r, "internal", "не удалось запустить движок");
    else {
        resp_run(r, code, &out, &err);
        if (to) resp_error(r, "timeout", "команда не уложилась в свой срок и остановлена");
    }
    free(out.p);
    free(err.p);
}

/* ---- apply и check ---------------------------------------------------------------------- */

static const char *ctl_state_dir(const struct ctl_conf *cf) {
    return cf->state_dir ? cf->state_dir : STEER_STATE_DIR;
}

/* Записать данные во временный файл РЯДОМ с целевым (тот же довод, что у spec_set в
 * splify2: rename атомарен только внутри одной файловой системы). 0 — готово, имя в tmp. */
static int ctl_write_tmp(const char *final, const char *data, size_t n, char *tmp, size_t tn) {
    if ((size_t)snprintf(tmp, tn, "%s.ctl-XXXXXX", final) >= tn) return -1;
    int fd = mkostemp(tmp, O_CLOEXEC);
    if (fd < 0) return -1;
    int ok = ctl_write_all(fd, data, n) == 0 && fsync(fd) == 0;
    if (close(fd) != 0) ok = 0;
    if (!ok) { unlink(tmp); return -1; }
    return 0;
}

/* Каталог после rename — чтобы новое имя пережило обрыв питания, а не только новое
 * содержимое. */
static void ctl_fsync_dir(const char *path) {
    char d[PATH_MAX];
    snprintf(d, sizeof(d), "%s", path);
    char *s = strrchr(d, '/');
    if (!s) snprintf(d, sizeof(d), ".");
    else if (s == d) d[1] = '\0';
    else *s = '\0';
    int fd = open(d, O_RDONLY | O_DIRECTORY | O_CLOEXEC);
    if (fd >= 0) { fsync(fd); close(fd); }
}

/* Прочитать файл целиком. 1 — прочитан, 0 — его нет, -1 — не прочитать. */
static int ctl_read_file(const char *path, struct cbuf *b, size_t max) {
    int fd = open(path, O_RDONLY | O_CLOEXEC);
    if (fd < 0) return errno == ENOENT ? 0 : -1;
    char buf[16384];
    ssize_t m;
    b->max = max;
    while ((m = read(fd, buf, sizeof(buf))) > 0) cb_put(b, buf, (size_t)m);
    close(fd);
    if (m < 0 || b->trunc) return -1;
    if (!b->p) cb_put(b, "", 0);
    return 1;
}

/* Блокировка изменяющих команд: два apply подряд из двух экранов приложения не должны
 * писать спеку и грузить правила вперемешку. flock, а не своя логика: снимается ядром со
 * смертью процесса, то есть убитый по сроку обработчик соседа не запирает. */
static int ctl_lock(const struct ctl_conf *cf) {
    char p[PATH_MAX];
    snprintf(p, sizeof(p), "%s/ctl.lock", ctl_state_dir(cf));
    int fd = open(p, O_RDWR | O_CREAT | O_CLOEXEC, 0600);
    if (fd < 0) return -1;
    while (flock(fd, LOCK_EX) != 0) {
        if (errno != EINTR) { close(fd); return -1; }
    }
    return fd;
}

static void resp_bool(struct cbuf *r, const char *k, int v) {
    cb_fmt(r, ",\"%s\":%s", k, v ? "true" : "false");
}

/* Проверить кандидата тем же разбором, что и apply: `apply --dry-run` по временному файлу.
 * Так же поступает интерфейс роутера перед записью спеки (splify2, m-spec.sh): компилятор —
 * единственный судья, он же будет это применять. Текст набора правил (stdout) не нужен и не
 * копится; stderr — предупреждения и причина отказа — идёт в ответ. */
static int ctl_dry_run(const struct ctl_req *q, const char *path, struct cbuf *err, int *to) {
    struct cbuf out = { .max = 1 };
    char *av[10];
    size_t n = 0;
    av[n++] = (char *)q->cf->exe;
    av[n++] = "apply";
    av[n++] = "--dry-run";
    av[n++] = "--spec";
    av[n++] = (char *)path;
    if (q->cf->state_dir) { av[n++] = "--state-dir"; av[n++] = (char *)q->cf->state_dir; }
    av[n] = NULL;
    int code = ctl_exec(q->cf->exe, av, 120, &out, err, to);
    free(out.p);
    return code;
}

static void ctl_reload_into(const struct ctl_conf *cf, struct cbuf *r);

/* check — проверить присланную спеку и ничего не менять: для кнопки «Проверить» и для
 * предупреждений до сохранения.
 *
 * Под той же блокировкой, что apply, хотя спеку не трогает: dry-run не чисто читающий — он
 * раздаёт выходам метки в реестре каталога состояния (registry_assign в cmd_apply), и проверка,
 * идущая одновременно с чужим apply, писала бы реестр посреди его применения. */
static void ctl_do_check(const struct ctl_req *q, struct cbuf *r) {
    char tmp[PATH_MAX];
    int lk = ctl_lock(q->cf);
    if (lk < 0) {
        resp_error(r, "internal", "не удалось взять блокировку в каталоге состояния");
        return;
    }
    if (ctl_write_tmp(q->cf->spec, q->body, q->body_n, tmp, sizeof(tmp)) != 0) {
        resp_error(r, "internal", "не удалось записать временный файл спеки");
        close(lk);
        return;
    }
    struct cbuf out = {0}, err = { .max = CTL_ERR_MAX };
    int to = 0;
    int code = ctl_dry_run(q, tmp, &err, &to);
    unlink(tmp);
    close(lk);
    if (code < 0) resp_error(r, "internal", "не удалось запустить движок");
    else {
        resp_run(r, code, &out, &err);
        if (to) resp_error(r, "timeout", "проверка не уложилась в свой срок и остановлена");
    }
    free(out.p);
    free(err.p);
}

/* apply — приложение присылает спеку ЦЕЛИКОМ; сервер проверяет её, атомарно кладёт на место
 * и применяет. Порядок и доводы:
 *
 *   1. Блокировка (см. ctl_lock).
 *   2. Кандидат — во временный файл рядом со спекой и `apply --dry-run` по нему. Отказ —
 *      временный файл удаляется, spec.json не тронут; в ответе код и stderr проверки,
 *      "saved":false.
 *   3. Прежняя спека читается в память — на случай отката в п. 5 — и кандидат становится
 *      spec.json переименованием: снаружи виден либо прежний файл, либо новый целиком.
 *   4. Движок выключен — на этом всё: "saved":true, "applied":false, "enabled":false.
 *      Правила поставит init, когда движок включат (см. ctl_enabled).
 *   5. `apply` по новой спеке. Отказ (ядро не приняло набор — dry-run ядро не спрашивает) —
 *      прежняя спека возвращается на место, и в ядре, и на диске остаётся то, что было:
 *      иначе init повторял бы отвергнутую спеку на каждой загрузке и перезапуске netd.
 *      "saved":false, "rolled_back":true.
 *   6. Успех — перечитать спеку резолвером и супервизором (как reload), "reload" в ответе.
 *
 * Сторожу (failover --loop) сигнал не нужен: каждый его проход — новый процесс, который
 * читает спеку заново. */
static void ctl_do_apply(const struct ctl_req *q, struct cbuf *r) {
    const char *spec = q->cf->spec;
    int lk = ctl_lock(q->cf);
    if (lk < 0) {
        resp_error(r, "internal", "не удалось взять блокировку в каталоге состояния");
        return;
    }
    char tmp[PATH_MAX];
    struct cbuf out = { .max = CTL_OUT_MAX }, err = { .max = CTL_ERR_MAX }, old = {0};
    int to = 0;
    if (ctl_write_tmp(spec, q->body, q->body_n, tmp, sizeof(tmp)) != 0) {
        resp_error(r, "internal", "не удалось записать временный файл спеки");
        goto done;
    }
    int code = ctl_dry_run(q, tmp, &err, &to);
    if (code != 0 || to) {
        unlink(tmp);
        if (code < 0) { resp_error(r, "internal", "не удалось запустить движок"); goto done; }
        resp_run(r, code, &out, &err);
        resp_bool(r, "saved", 0);
        resp_bool(r, "applied", 0);
        if (to) resp_error(r, "timeout", "проверка не уложилась в свой срок и остановлена");
        goto done;
    }
    int had_old = ctl_read_file(spec, &old, 4 * CTL_BODY_MAX);
    if (rename(tmp, spec) != 0) {
        unlink(tmp);
        resp_error(r, "internal", "не удалось заменить спеку");
        goto done;
    }
    ctl_fsync_dir(spec);

    int en = ctl_enabled();
    if (!en) {
        resp_run(r, 0, &out, &err);
        resp_bool(r, "saved", 1);
        resp_bool(r, "applied", 0);
        resp_bool(r, "enabled", 0);
        goto done;
    }
    err.n = 0;
    err.trunc = 0;
    if (err.p) err.p[0] = '\0';
    char *av[10];
    size_t n = 0;
    av[n++] = (char *)q->cf->exe;
    av[n++] = "apply";
    av[n++] = "--spec";
    av[n++] = (char *)spec;
    if (q->cf->state_dir) { av[n++] = "--state-dir"; av[n++] = (char *)q->cf->state_dir; }
    av[n] = NULL;
    code = ctl_exec(q->cf->exe, av, 300, &out, &err, &to);
    if (code != 0 || to) {
        int rolled = 0;
        if (had_old == 1) {
            char t2[PATH_MAX];
            if (ctl_write_tmp(spec, old.p, old.n, t2, sizeof(t2)) == 0) {
                if (rename(t2, spec) == 0) rolled = 1;
                else unlink(t2);
            }
        } else if (had_old == 0) {
            rolled = unlink(spec) == 0;
        }
        if (rolled) ctl_fsync_dir(spec);
        else cb_str(&err, LOG_W "прежнюю спеку вернуть не удалось — на диске новая\n");
        fprintf(stderr, LOG_W "apply отвергнут (код %d)%s\n", code,
                rolled ? " — прежняя спека возвращена" : "");
        resp_run(r, code < 0 ? 127 : code, &out, &err);
        resp_bool(r, "saved", !rolled);
        resp_bool(r, "applied", 0);
        resp_bool(r, "enabled", 1);
        resp_bool(r, "rolled_back", rolled);
        if (to) resp_error(r, "timeout", "применение не уложилось в свой срок и остановлено");
        goto done;
    }
    fprintf(stderr, LOG_I "спека применена\n");
    resp_run(r, 0, &out, &err);
    resp_bool(r, "saved", 1);
    resp_bool(r, "applied", 1);
    resp_bool(r, "enabled", 1);
    ctl_reload_into(q->cf, r);
done:
    free(out.p);
    free(err.p);
    free(old.p);
    close(lk);
}

/* ---- reload ------------------------------------------------------------------------------ */

/* Процессы этого же движка с подкомандой sub: /proc/<pid>/exe совпадает с нашим, а второе
 * слово командной строки — sub. Искать по исполняемому файлу, а не по имени процесса:
 * имя подделать может любой, а на телефоне к тому же SELinux пускает steerd читать /proc
 * только своего домена (r_dir_file(domain, self)) — чужие процессы здесь не видны вовсе.
 * pid-файлов резолвер и супервизор не пишут, а заводить их ради этого — ещё одна вещь,
 * способная устареть (процесс умер, файл остался, сигнал ушёл чужому pid). */
static int ctl_find(const char *exe, const char *sub, pid_t *out, int max) {
    DIR *d = opendir("/proc");
    if (!d) return 0;
    int n = 0;
    pid_t me = getpid();
    struct dirent *e;
    while ((e = readdir(d)) && n < max) {
        char *end = NULL;
        long p = strtol(e->d_name, &end, 10);
        if (!end || *end || p <= 0 || p == me) continue;
        char path[64], link[PATH_MAX];
        snprintf(path, sizeof(path), "/proc/%ld/exe", p);
        ssize_t l = readlink(path, link, sizeof(link) - 1);
        if (l <= 0) continue;
        link[l] = '\0';
        if (strcmp(link, exe) != 0) continue;
        snprintf(path, sizeof(path), "/proc/%ld/cmdline", p);
        int fd = open(path, O_RDONLY | O_CLOEXEC);
        if (fd < 0) continue;
        char cl[256];
        ssize_t m = read(fd, cl, sizeof(cl) - 1);
        close(fd);
        if (m <= 0) continue;
        cl[m] = '\0';
        size_t a0 = strlen(cl);
        if ((ssize_t)a0 + 1 >= m) continue;
        if (strcmp(cl + a0 + 1, sub) != 0) continue;
        out[n++] = (pid_t)p;
    }
    closedir(d);
    return n;
}

static void ctl_rstrip(struct cbuf *b) {
    while (b->n && (b->p[b->n - 1] == '\n' || b->p[b->n - 1] == '\r')) b->p[--b->n] = '\0';
}

/* Перечитать спеку резолвером и супервизором помощников — поле "reload" ответа.
 *
 * РЕЗОЛВЕР — тем же решением, что init-скрипт роутера (files/etc/init.d/steer, reload_dnsd):
 * подпись таблицы каналов по новой спеке (`steer dnsd-sig`) сравнивается с той, что резолвер
 * положил в dnsd.sig при запуске. Совпали — SIGHUP: списки перечитываются без потери
 * запросов. Разошлись или подписи нет — SIGTERM: состав каналов HUP не пересобирает, а init
 * поднимает вышедший сервис заново (он не oneshot). "hup" | "restart" | "none" (не запущен).
 *
 * СУПЕРВИЗОР — SIGHUP: сверить состав помощников со спекой; помощник выхода, у которого
 * изменились параметры, перезапускается им же (см. cmd_supervise). "hup" | "none". */
static void ctl_reload_into(const struct ctl_conf *cf, struct cbuf *r) {
    pid_t pids[8];
    const char *dn = "none", *sv = "none";
    int k = ctl_find(cf->exe, "dnsd", pids, 8);
    if (k > 0) {
        char *av[8];
        size_t n = 0;
        av[n++] = (char *)cf->exe;
        av[n++] = "dnsd-sig";
        av[n++] = "--spec";
        av[n++] = (char *)cf->spec;
        if (cf->state_dir) { av[n++] = "--state-dir"; av[n++] = (char *)cf->state_dir; }
        av[n] = NULL;
        struct cbuf now = { .max = CTL_OUT_MAX }, e = { .max = CTL_ERR_MAX }, run = {0};
        int to = 0;
        int code = ctl_exec(cf->exe, av, 30, &now, &e, &to);
        char sp[PATH_MAX];
        snprintf(sp, sizeof(sp), "%s/dnsd.sig", ctl_state_dir(cf));
        int have = ctl_read_file(sp, &run, CTL_OUT_MAX) == 1;
        ctl_rstrip(&now);
        ctl_rstrip(&run);
        int same = code == 0 && !to && have && run.n && now.n == run.n &&
                   !memcmp(now.p, run.p, now.n);
        for (int i = 0; i < k; i++) kill(pids[i], same ? SIGHUP : SIGTERM);
        dn = same ? "hup" : "restart";
        free(now.p);
        free(e.p);
        free(run.p);
    }
    k = ctl_find(cf->exe, "supervise", pids, 8);
    for (int i = 0; i < k; i++) kill(pids[i], SIGHUP);
    if (k > 0) sv = "hup";
    cb_fmt(r, ",\"reload\":{\"dnsd\":\"%s\",\"outputs\":\"%s\"}", dn, sv);
}

static void ctl_do_reload(const struct ctl_req *q, struct cbuf *r) {
    int lk = ctl_lock(q->cf);
    cb_str(r, ",\"code\":0");
    resp_bool(r, "enabled", ctl_enabled());
    ctl_reload_into(q->cf, r);
    if (lk >= 0) close(lk);
}

/* ---- обработка соединения ------------------------------------------------------------------ */

static void ctl_handle(int c, const struct ctl_conf *cf) {
    alarm(CTL_HANDLER_S);
    struct timeval tv = { 5, 0 };
    setsockopt(c, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));
    long deadline = ctl_now_ms() + CTL_REQ_MS;
    char line[CTL_LINE_MAX + 1];
    int st = ctl_read_line(c, line, sizeof(line), deadline);
    if (st == -2) { ctl_refuse(c, NULL, "too-large", "строка запроса длиннее 512 байт"); return; }
    if (st < 0) {
        ctl_refuse(c, NULL, "bad-request", "запрос не пришёл целиком за 5 секунд");
        return;
    }
    char *tok[6];
    int nt = 0;
    for (char *s = line; nt < 6; ) {
        char *sp = strchr(s, ' ');
        if (sp) *sp = '\0';
        tok[nt++] = s;
        if (!sp) break;
        s = sp + 1;
        if (nt == 6) { ctl_refuse(c, NULL, "bad-request", "слишком много слов в запросе"); return; }
    }
    for (int i = 0; i < nt; i++)
        if (!tok[i][0]) { ctl_refuse(c, NULL, "bad-request", "пустое слово: слова разделяются одним пробелом"); return; }
    const struct ctl_cmd *cmd = ctl_lookup(tok[0]);
    if (!cmd) { ctl_refuse(c, NULL, "unknown-command", "такой команды нет"); return; }

    struct ctl_req q;
    memset(&q, 0, sizeof(q));
    q.cmd = cmd;
    q.cf = cf;
    int na = nt - 1;
    size_t blen = 0;
    if (cmd->body) {
        if (na < 1) { ctl_refuse(c, cmd->name, "bad-request", "нужна длина тела последним словом"); return; }
        const char *w = tok[nt - 1];
        size_t wl = strlen(w);
        if (wl > 10 || strspn(w, "0123456789") != wl) {
            ctl_refuse(c, cmd->name, "bad-request", "длина тела — десятичное число байт");
            return;
        }
        unsigned long long v = strtoull(w, NULL, 10);
        if (v > CTL_BODY_MAX) { ctl_refuse(c, cmd->name, "too-large", "тело больше 1 МиБ"); return; }
        blen = (size_t)v;
        na--;
    }
    if (na < cmd->argmin || na > cmd->argmax) {
        ctl_refuse(c, cmd->name, "bad-request", "не то число слов у команды");
        return;
    }
    for (int i = 0; i < na; i++) {
        const char *why = ctl_arg_bad(&cmd->args[i], tok[i + 1]);
        if (why) { ctl_refuse(c, cmd->name, "bad-request", why); return; }
        q.argv[i] = tok[i + 1];
    }
    q.argc = na;
    char *body = NULL;
    if (cmd->body) {
        body = malloc(blen + 1);
        if (!body) { ctl_refuse(c, cmd->name, "internal", "нет памяти под тело"); return; }
        if (ctl_read_full(c, body, blen, deadline) != 0) {
            free(body);
            ctl_refuse(c, cmd->name, "bad-request", "тело не пришло целиком за 5 секунд");
            return;
        }
        body[blen] = '\0';
        q.body = body;
        q.body_n = blen;
    }

    struct cbuf r = {0};
    resp_begin(&r, cmd->name);
    if (cmd->fn) cmd->fn(&q, &r);
    else ctl_run_sub(&q, &r);
    resp_send(c, &r);
    free(r.p);
    free(body);
}

/* ---- кого пускать ---------------------------------------------------------------------------- */

/* Домен из контекста SELinux «u:r:ДОМЕН:s0:c...» — третье поле. */
static int ctl_ctx_domain_is(const char *ctx, const char *dom) {
    const char *a = strchr(ctx, ':');
    if (!a) return 0;
    const char *b = strchr(a + 1, ':');
    if (!b) return 0;
    const char *e = strchr(b + 1, ':');
    size_t n = e ? (size_t)(e - (b + 1)) : strlen(b + 1);
    return n == strlen(dom) && !strncmp(b + 1, dom, n);
}

/* 1 — пустить. who — для журнала при отказе. */
static int ctl_peer_ok(int c, const struct ctl_conf *cf, char *who, size_t wn) {
    struct ucred uc;
    socklen_t l = sizeof(uc);
    if (getsockopt(c, SOL_SOCKET, SO_PEERCRED, &uc, &l) != 0) {
        snprintf(who, wn, "неизвестный собеседник (%s)", strerror(errno));
        return 0;
    }
    snprintf(who, wn, "uid %u pid %d", (unsigned)uc.uid, (int)uc.pid);
    if (uc.uid == 0 || uc.uid == CTL_AID_SYSTEM) return 1;
    for (int i = 0; i < cf->allow_uid_n; i++)
        if (cf->allow_uid[i] == uc.uid) return 1;
    if (cf->allow_domain && cf->allow_domain[0] && uc.uid < CTL_USER_RANGE) {
        char ctx[256];
        socklen_t cl = sizeof(ctx) - 1;
        if (getsockopt(c, SOL_SOCKET, SO_PEERSEC, ctx, &cl) == 0) {
            ctx[cl < sizeof(ctx) ? cl : sizeof(ctx) - 1] = '\0';
            if (ctl_ctx_domain_is(ctx, cf->allow_domain)) return 1;
            size_t wl = strlen(who);
            snprintf(who + wl, wn - wl, " %s", ctx);
        }
    }
    return 0;
}

/* ---- сервер ------------------------------------------------------------------------------------ */

static volatile sig_atomic_t g_ctl_chld, g_ctl_term;

static void ctl_on_sig(int s) {
    if (s == SIGCHLD) g_ctl_chld = 1;
    else g_ctl_term = 1;
}

static void ctl_bad_flag(const char *cmd, const char *msg, const char *arg) {
    fprintf(stderr, "steer: %s: %s%s%s\n", cmd, msg, arg ? ": " : "", arg ? arg : "");
    exit(2);
}

void ctl_usage_flags(FILE *out) {
    fputs("  --socket ФАЙЛ       управляющий сокет (по умолчанию " STEER_CTL_SOCK ")\n"
          "  --spec ФАЙЛ         ctl-serve: спека, которую читают и заменяют команды\n"
          "                      (по умолчанию " STEER_ETC_DIR "/spec.json)\n"
          "  --state-dir КАТАЛОГ ctl-serve: каталог состояния (по умолчанию " STEER_STATE_DIR ")\n"
          "  --allow-uid N       ctl-serve: пускать и этот uid (до восьми раз); root и system\n"
          "                      пускаются всегда\n"
          "  --allow-domain ИМЯ  ctl-serve: пускать процессы этого домена SELinux у владельца\n"
          "                      устройства (по умолчанию splify2_app в сборке под Android;\n"
          "                      пустое значение — не пускать по домену)\n", out);
}

static int ctl_listen(const struct ctl_conf *cf, ino_t *ino) {
    struct sockaddr_un a;
    memset(&a, 0, sizeof(a));
    a.sun_family = AF_UNIX;
    if (strlen(cf->sock) >= sizeof(a.sun_path)) ctl_bad_flag("ctl-serve", "слишком длинный путь сокета", cf->sock);
    snprintf(a.sun_path, sizeof(a.sun_path), "%s", cf->sock);

    /* Прежний файл: живой сервер за ним — отказ стартовать (второй сервер отнял бы сокет у
     * первого молча); мёртвый — удалить, это след упавшего или убитого. */
    int t = socket(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0);
    if (t >= 0) {
        if (connect(t, (struct sockaddr *)&a, sizeof(a)) == 0) {
            close(t);
            fprintf(stderr, LOG_W "на %s уже отвечает другой сервер — второй не нужен\n", cf->sock);
            exit(1);
        }
        close(t);
    }
    unlink(cf->sock);

    int s = socket(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC | SOCK_NONBLOCK, 0);
    if (s < 0) { fprintf(stderr, LOG_W "socket: %s\n", strerror(errno)); exit(1); }
    /* Права 0666 — с рождения, через umask, а не chmod после bind: так нет мгновения, когда
     * файл уже есть, а права у него чужие. Открыто по правам файла нарочно: у приложения свой
     * uid и своя группа, которых заранее не знать, а пускает его не DAC, а SELinux (connectto
     * и метка steerd_socket) и проверка собеседника в ctl_peer_ok. */
    mode_t old = umask(0111);
    int rc = bind(s, (struct sockaddr *)&a, sizeof(a));
    umask(old);
    if (rc != 0) {
        fprintf(stderr, LOG_W "не занять %s: %s\n", cf->sock, strerror(errno));
        exit(1);
    }
    if (listen(s, 16) != 0) {
        fprintf(stderr, LOG_W "listen: %s\n", strerror(errno));
        exit(1);
    }
    struct stat sb;
    *ino = stat(cf->sock, &sb) == 0 ? sb.st_ino : 0;
    return s;
}

int ctl_serve_main(int argc, char **argv) {
    static struct ctl_conf cf;
    cf.sock = STEER_CTL_SOCK;
    cf.spec = STEER_ETC_DIR "/spec.json";
#ifdef STEER_ANDROID
    cf.allow_domain = "splify2_app";
#endif
    for (int i = 0; i < argc; i++) {
        const char *f = argv[i];
        const char *v = i + 1 < argc ? argv[i + 1] : NULL;
        if (!strcmp(f, "--socket") || !strcmp(f, "--spec") || !strcmp(f, "--state-dir") ||
            !strcmp(f, "--allow-uid") || !strcmp(f, "--allow-domain")) {
            if (!v) ctl_bad_flag("ctl-serve", "у флага нет значения", f);
            i++;
            if (!strcmp(f, "--socket")) cf.sock = v;
            else if (!strcmp(f, "--spec")) cf.spec = v;
            else if (!strcmp(f, "--state-dir")) cf.state_dir = v;
            else if (!strcmp(f, "--allow-domain")) cf.allow_domain = v;
            else {
                char *e = NULL;
                unsigned long u = strtoul(v, &e, 10);
                if (!*v || *e || u > 0xfffffffful) ctl_bad_flag("ctl-serve", "--allow-uid: нужно число", v);
                if (cf.allow_uid_n >= CTL_ALLOW_UIDS) ctl_bad_flag("ctl-serve", "--allow-uid больше восьми раз", NULL);
                cf.allow_uid[cf.allow_uid_n++] = (uid_t)u;
            }
            continue;
        }
        ctl_bad_flag("ctl-serve", "неизвестный флаг", f);
    }
    ssize_t el = readlink("/proc/self/exe", cf.exe, sizeof(cf.exe) - 1);
    if (el <= 0) { fprintf(stderr, LOG_W "не найти свой исполняемый файл\n"); return 1; }
    cf.exe[el] = '\0';

    signal(SIGPIPE, SIG_IGN);
    struct sigaction sa;
    memset(&sa, 0, sizeof(sa));
    sa.sa_handler = ctl_on_sig;
    sigaction(SIGCHLD, &sa, NULL);
    sigaction(SIGTERM, &sa, NULL);
    sigaction(SIGINT, &sa, NULL);
    sigset_t blk, open_set;
    sigemptyset(&blk);
    sigaddset(&blk, SIGCHLD);
    sigaddset(&blk, SIGTERM);
    sigaddset(&blk, SIGINT);
    sigprocmask(SIG_BLOCK, &blk, NULL);
    sigemptyset(&open_set);

    ino_t ino = 0;
    int s = ctl_listen(&cf, &ino);
    fprintf(stderr, LOG_I "слушаю %s\n", cf.sock);
    int active = 0;
    for (;;) {
        struct pollfd p = { s, POLLIN, 0 };
        /* Сигналы открыты только на время сна: флаги ставятся атомарно с пробуждением, и
         * SIGCHLD между проверкой и сном не теряется. Срока у сна нет. */
        int r = ppoll(&p, 1, NULL, &open_set);
        if (g_ctl_chld) {
            g_ctl_chld = 0;
            while (waitpid(-1, NULL, WNOHANG) > 0) if (active > 0) active--;
        }
        if (g_ctl_term) {
            struct stat sb;
            if (ino && stat(cf.sock, &sb) == 0 && sb.st_ino == ino) unlink(cf.sock);
            return 0;
        }
        if (r <= 0 || !(p.revents & POLLIN)) continue;
        for (;;) {
            int c = accept4(s, NULL, NULL, SOCK_CLOEXEC);
            if (c < 0) {
                /* Нехватка дескрипторов или памяти не проходит сама за микросекунду, а
                 * соединение так и ждёт в очереди — ppoll вернулся бы сразу, и сервер крутился
                 * бы вхолостую. Короткая пауза вместо этого; в обычной работе сюда не попасть. */
                if (errno != EAGAIN && errno != EWOULDBLOCK && errno != EINTR &&
                    errno != ECONNABORTED) {
                    struct timespec ts = { 0, 200000000L };
                    nanosleep(&ts, NULL);
                }
                break;
            }
            char who[320];
            if (!ctl_peer_ok(c, &cf, who, sizeof(who))) {
                fprintf(stderr, LOG_W "отказ: %s\n", who);
                ctl_refuse(c, NULL, "denied", "этому процессу управлять движком нельзя");
                ctl_close(c, 0);
                continue;
            }
            if (active >= CTL_CLIENTS_MAX) {
                ctl_refuse(c, NULL, "busy", "сервер занят другими запросами — повторите позже");
                ctl_close(c, 0);
                continue;
            }
            pid_t pid = fork();
            if (pid == 0) {
                close(s);
                signal(SIGCHLD, SIG_DFL);
                signal(SIGTERM, SIG_DFL);
                signal(SIGINT, SIG_DFL);
                sigset_t none;
                sigemptyset(&none);
                sigprocmask(SIG_SETMASK, &none, NULL);
                ctl_handle(c, &cf);
                ctl_close(c, 1000);
                _exit(0);
            }
            if (pid < 0) {
                ctl_refuse(c, NULL, "internal", "не удалось начать обработку запроса");
                ctl_close(c, 0);
            } else {
                active++;
                close(c);
            }
        }
    }
}

/* ---- клиент ------------------------------------------------------------------------------------ */

/* `steer ctl [--socket ФАЙЛ] КОМАНДА [СЛОВО...]` — тот же запрос, что пошлёт приложение, для
 * adb root shell и стенда. Тело команд apply и check читается со стандартного ввода. Печатает
 * ответ сервера как есть (строка JSON). Код: 0 — ответ с "code":0 и без "error"; 1 — иной
 * ответ; 2 — ошибка вызова или нет соединения. */
int ctl_client_main(int argc, char **argv) {
    const char *sock = STEER_CTL_SOCK;
    int i = 0;
    for (; i < argc; i++) {
        if (!strcmp(argv[i], "--socket")) {
            if (i + 1 >= argc) ctl_bad_flag("ctl", "у флага нет значения", argv[i]);
            sock = argv[++i];
        } else break;
    }
    if (i >= argc) ctl_bad_flag("ctl", "нужна команда", NULL);
    struct cbuf req = {0}, body = {0};
    const struct ctl_cmd *cmd = ctl_lookup(argv[i]);
    for (int k = i; k < argc; k++) {
        if (k > i) cb_put(&req, " ", 1);
        cb_str(&req, argv[k]);
    }
    if (cmd && cmd->body) {
        char buf[65536];
        ssize_t m;
        body.max = 16 * CTL_BODY_MAX;
        while ((m = read(0, buf, sizeof(buf))) > 0) cb_put(&body, buf, (size_t)m);
        cb_fmt(&req, " %zu", body.n);
    }
    cb_put(&req, "\n", 1);

    struct sockaddr_un a;
    memset(&a, 0, sizeof(a));
    a.sun_family = AF_UNIX;
    snprintf(a.sun_path, sizeof(a.sun_path), "%s", sock);
    int s = socket(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0);
    if (s < 0 || connect(s, (struct sockaddr *)&a, sizeof(a)) != 0) {
        fprintf(stderr, "steer: ctl: нет соединения с %s: %s\n", sock, strerror(errno));
        return 2;
    }
    signal(SIGPIPE, SIG_IGN);
    /* Ошибка записи не повод молчать: сервер мог отказать (слишком большое тело) и закрыть
     * соединение, не читая, — его ответ всё равно лежит в сокете. */
    if (ctl_write_all(s, req.p, req.n) == 0 && body.n) ctl_write_all(s, body.p, body.n);
    shutdown(s, SHUT_WR);
    struct cbuf resp = {0};
    char buf[16384];
    ssize_t m;
    /* ECONNRESET после ответа — не ошибка: сервер отказал, не дочитав запрос (см. ctl_close),
     * а ответ уже прочитан. */
    while ((m = read(s, buf, sizeof(buf))) > 0 || (m < 0 && errno == EINTR))
        if (m > 0) cb_put(&resp, buf, (size_t)m);
    close(s);
    if (!resp.n) { fprintf(stderr, "steer: ctl: сервер закрыл соединение без ответа\n"); return 2; }
    fwrite(resp.p, 1, resp.n, stdout);
    int ok = strstr(resp.p, ",\"code\":0,") && !strstr(resp.p, "\"error\":");
    free(req.p);
    free(body.p);
    free(resp.p);
    return ok ? 0 : 1;
}
