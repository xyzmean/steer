/* Помощники выходов: состав по спеке, порядок подъёма, пауза перезапуска, подпись параметров —
 * и супервизор демона (`steer daemon --supervise`), который держит их детьми вместе с резолвером.
 *
 * ОДНА ЛОГИКА НА ДВА ПУТИ. До шага 6 устройства 1.8 (docs/architecture.md, «4а») помощников
 * поднимают по-разному: на телефоне — `steer supervise` (supervise.c), в демоне — супервизор с
 * --supervise (supd.c). Что поднимать, в каком порядке, когда перезапускать упавшего и когда
 * перезапускать живого из-за новых параметров — решает этот модуль (helpers.c), а пути
 * различаются только тем, как они ждут: `supervise` — в sigtimedwait, демон — в своём цикле
 * событий (loop_child, таймер). Так поведение, которое сторожит tests/supervisematch.sh, у
 * демона то же самое, а не пересказанное.
 *
 * ЗДОРОВЬЕ. Помощнику демона дан дескриптор трубы (STEER_EVENT_FD, формат — src/lib/evline.h);
 * его события демон держит по выходу в struct helper_state и рассылает подписчикам (helper-up,
 * helper-down, node — docs/ctl.md). Сторож демона (--watch вместе с --supervise) берёт здоровье
 * выходов vless и xsteer отсюда, а не из файлов probe-* и xsteer-*.json (helper_state_of, источник
 * здоровья помощника в fostate.h), и оживляет обфускатор перезапуском отсюда же (supd_restart). */
#ifndef STEER_HELPERS_H
#define STEER_HELPERS_H

#include <sys/types.h>

#include "spec.h"

#define HELPERS_MAX 32
/* Первый перезапуск упавшего — через пять секунд, как у procd; дальше пауза удваивается, пока
 * помощник живёт меньше минуты, до пяти минут (см. helpers_exited). */
#define HELPERS_DELAY_MS 5000L
#define HELPERS_DELAY_MAX_MS 300000L
#define HELPERS_STABLE_MS 60000L

/* Что демон знает о помощнике выхода по его событиям. Время — секунды Unix (time()). */
struct helper_state {
    int running;          /* процесс есть */
    int up;               /* последнее событие — up (и процесс с тех пор не выходил) */
    int known;            /* с запуска процесса было хоть одно up или down */
    char why[200];        /* причина последнего down (или выхода процесса); пусто — не было */
    long node, total;     /* последнее node: проверяется узел node из total; 0 — не было */
    long nonode;          /* последнее nonode: выбранного узла нет в подписке; 0 — не было */
    int said_down;        /* последнее событие самого помощника — down (а не выход процесса) */
    long since;           /* когда up сменилось (0 — ни разу) */
    long started;         /* когда запущен процесс */
    unsigned restarts;    /* сколько раз перезапущен с подъёма демона */
};

struct helper {
    /* Состав — из вида выхода (kind_ops.helper). */
    char cmd[8];
    char name[32];
    char prog[16];
    char arg[2][256];
    char env[32];
    unsigned long long sig;   /* подпись параметров, которые помощник читает при старте */
    /* Не помощник выхода, а резолвер на таблице (демон; name пуст): его запуск и труба — свои
     * (supd.c), а пауза, сверка и остановка — общие. */
    int table;

    /* Перезапуск. */
    pid_t pid;
    long next_ms;         /* когда можно запускать (монотонные мс; 0 — сразу) */
    long started_ms;
    long delay_ms;        /* пауза следующего перезапуска */
    int gone;             /* выход убран из спеки: не перезапускать */
    int restart;          /* погашен ради новых параметров: поднять сразу, без паузы */
    int revive;           /* ...и не ради параметров, а по просьбе сторожа (supd_restart) */

    /* Демон: труба событий (конец чтения; -1 — нет) и недочитанная строка. */
    int evfd;
    size_t evlen;
    char evbuf[512];
    struct helper_state st;
};

struct helper_set {
    struct helper h[HELPERS_MAX];
    size_t n;
};

/* Состав помощников по разобранной спеке — в порядке зависимостей via: цель раньше того, чей
 * туннель через неё идёт. Метки выходов с via (и zapret) уже должны быть назначены реестром;
 * *need_marks (может быть NULL) — 1, если кому-то из помощников нужны метки. */
size_t helpers_plan(const struct spec *sp, struct helper *out, size_t max, int *need_marks);

/* Сверить набор с новым составом (SIGHUP у supervise, смена спеки у демона): ушедшим — SIGTERM
 * и «не перезапускать», новым — место в наборе, оставленным с новой подписью — SIGTERM и подъём
 * сразу, как выйдут. Упавшим, ждущим паузы, пауза сбрасывается. */
void helpers_merge(struct helper_set *s, const struct helper *fresh, size_t fn);

/* Помощник pid вышел (status — как из waitpid). Возвращает его слот (NULL — не наш): pid снят,
 * назначен срок следующего запуска, в журнал сказано, почему. */
struct helper *helpers_exited(struct helper_set *s, pid_t pid, int status);

/* Убрать из набора убранные из спеки и уже погасшие. */
void helpers_compact(struct helper_set *s);

/* Запустить тех, кому пора (start — способ пути; -1 — не вышло, повтор через паузу). Возврат —
 * мс до ближайшего срока или -1, если ждать нечего. */
typedef int (*helper_start_fn)(struct helper *h, void *arg);
long helpers_due(struct helper_set *s, helper_start_fn start, void *arg);

/* Отметить запуск: pid, время, строка в журнал. */
void helper_started(struct helper *h, pid_t pid);

/* argv помощника: exe — движок (или шов STEER_SUPERVISE_EXE), self — настоящий файл движка (у
 * помощника-программы она лежит рядом с ним), seam — exe подменён швом. av — не меньше 10
 * мест. Помощник-подкоманда получает --state-dir, если каталог состояния не путь платформы. */
void helper_argv(const struct helper *h, const char *exe, const char *self, int seam,
                 const char *spec, char *progbuf, size_t pbn, const char **av);

/* argv[0] ребёнка, которого запускают файлом exe: «<каталог>/steer», если exe — steerd, иначе сам
 * exe. Процесс помощника в списке процессов выглядит так же, как до раздельных бинарников
 * («/usr/sbin/steer vless out»): по этой строке его ищут pgrep -f 'steer dnsd' в diag,
 * 'steer obfs <выход>' у вида interface и скрипты splify2. Запускается при этом steerd —
 * /proc/<pid>/exe указывает на него, и ctl_find демона сверяет именно exe. */
const char *helper_argv0(const char *exe, char *buf, size_t n);

/* Погасить всех: ordered=0 — SIGTERM всем сразу (supervise); 1 — по одному в обратном порядке
 * подъёма, дожидаясь выхода каждого (демон). Кто не вышел за свой срок — SIGKILL. Ждёт сам
 * (waitpid), цикл событий к этому моменту уже не крутится. */
void helpers_stop(struct helper_set *s, int ordered);

long helpers_now_ms(void);

/* ---- супервизор демона (supd.c) --------------------------------------------------------- */

struct steerd;
struct supd;

struct supd_conf {
    /* Включён ли движок (выключатель телефона). NULL — всегда. Выключен — помощников и резолвера
     * нет: состав считается пустым. */
    int (*enabled)(void);
    /* Лишние флаги резолверу (--dnsd-flag), до 8; NULL в конце. */
    const char *const *dnsd_flags;
};

/* Поднять детей по спеке в памяти демона: помощников и резолвер на таблице. NULL — нет памяти. */
struct supd *supd_start(struct steerd *d, const struct supd_conf *c);
/* Что тронула сверка (apply-сверка, docs/ctl.md, поле changed): выходы, чей помощник поднят,
 * перезапущен ради новых параметров или погашен; написана ли резолверу новая таблица. */
struct supd_changes {
    char helpers[HELPERS_MAX][32];
    size_t helpers_n;
    int dnsd;
};
/* Спека в памяти сменилась (apply, reload, SIGHUP): сверить помощников по подписям, послать
 * резолверу таблицу — только если изменился её текст или файлы списков, на которые она
 * ссылается. ch (может быть NULL) — что тронуто. */
void supd_spec_changed(struct supd *s, struct supd_changes *ch);
/* Демон уходит: резолверу — закрыть трубу, помощникам — SIGTERM в обратном порядке подъёма,
 * по сроку SIGKILL. Ждёт их выхода. */
void supd_stop(struct supd *s);

/* Состояние помощника выхода out из памяти демона. NULL — демон не супервизор (--supervise нет)
 * или у выхода нет помощника. */
const struct helper_state *helper_state_of(const struct steerd *d, const char *out);

/* Сторож оживляет выход: перезапустить помощника cmd выхода out сразу, без паузы (живого — SIGTERM
 * и подъём, как выйдет; ждущего паузы — подъём сейчас). 0 — заказано; -1 — такого помощника у
 * демона нет. */
int supd_restart(struct supd *s, const char *out, const char *cmd);

/* Ход перебора узлов клиентов vless из памяти демона — в запись окружения для детей демона
 * (`STEER_PROBE_MEM=…`, её читает probe_read вместо файлов probe-*; см. src/model/probe.h). Пусто
 * (buf[0] = 0) — демон не супервизор. */
void supd_probe_env(const struct supd *s, char *buf, size_t n);

#endif
