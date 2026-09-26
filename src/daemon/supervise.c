#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <sys/wait.h>
#include <signal.h>
#include <time.h>

#include "spec.h"
#include "registry.h"
#include "daemon.h"
#include "helpers.h"


/* ---- supervise: помощники выходов одним сервисом -------------------------------------
 *
 * На роутере init-скрипт поднимает по экземпляру procd на каждый выход, которому нужен свой
 * процесс (vless, xsteer, obfs, tgws), и procd перезапускает упавший через пять секунд. У init
 * Android так нельзя: сервисы объявлены в rc статически, а состав выходов известен только из
 * спеки. Поэтому один сервис — этот — поднимает их сам и держит.
 *
 * СОСТАВ считается в ДОЧЕРНЕМ процессе и приезжает через трубу: спеку загружают в
 * глобальные массивы, и второй load_spec в том же процессе склеил бы выходы двух чтений (тот
 * же довод, что у failover_loop). Спека не разобралась — состав остаётся прежним, а не пустым.
 *
 * ПЕРЕЗАПУСК — как у procd: через пять секунд. Но помощник, падающий сразу (сервер туннеля
 * недоступен, в спеке ошибка), перезапускался бы каждые пять секунд всю ночь, а на телефоне
 * это батарея. Поэтому пауза удваивается, пока помощник живёт меньше минуты, до пяти минут, и
 * сбрасывается, когда он проработал дольше. Ждёт супервизор в sigtimedwait: таймер монотонный,
 * во сне устройства стоит и не будит его.
 *
 * SIGHUP — сверить состав со спекой: ушедшим выходам — SIGTERM, новым — запуск, остальным —
 * ничего, если не изменились их параметры (подпись, helpers.c): у изменившихся помощник гасится и
 * поднимается сразу, без пятисекундной паузы. SIGTERM — погасить всех и выйти (init шлёт его
 * группе, это на случай kill). SIGHUP шлёт управляющий сокет после каждого удачного apply
 * (src/daemon/ctl.c, reload).
 *
 * Обработчик zapret (steer-nfqws) — помощник-программа рядом с движком, тот же, что у init.d; в
 * сборке под Android zapret нет вовсе, и там его не бывает. В базовой сборке нет vless, xsteer и
 * tgws — их команды есть только в расширенной, и запускать их значило бы перезапускать отказ по
 * кругу.
 *
 * Логика — что поднимать, в каком порядке, когда перезапускать, — общая с супервизором демона
 * (`steer daemon --supervise`) и живёт в helpers.c; здесь только то, как ждёт этот процесс. */

/* Состав помощников по спеке — в ДОЧЕРНЕМ процессе (довод в шапке), назад — записями struct
 * helper по трубе: ребёнок — копия этого же процесса без exec, раскладка у них одна. -1 — спека не
 * разобралась. */
static int sup_list(const char *spec, struct helper *out, size_t *n) {
    int pfd[2];
    if (pipe(pfd) != 0) return -1;
    pid_t pid = fork();
    if (pid < 0) { close(pfd[0]); close(pfd[1]); return -1; }
    if (pid == 0) {
        close(pfd[0]);
        FILE *w = fdopen(pfd[1], "w");
        if (!w) _exit(1);
        /* Разбор спеки возвращает отказ, а не завершает процесс сам (правило 5,
         * docs/architecture.md, раздел 2); err_die здесь, в этом форкнутом ребёнке, делает
         * ровно то же, что раньше делал die() изнутри load_spec — код 2, тот же текст.
         *
         * Спека — значение (правило 6): свой экземпляр у этого форкнутого ребёнка, который
         * и есть отдельная точка входа — он живёт в своём адресном пространстве и больше
         * ничего с родителем не делит. */
        static struct spec cfg;
        static struct helper h[HELPERS_MAX];
        struct err e = {0};
        if (load_spec(spec, &cfg, &e) < 0) err_die(&e);
        /* Метки выходов — из реестра: без них out_underlay_mark в подписи вернул бы «мимо
         * каналов» при любой цели, и смена метки цели не была бы видна. Только при via (и у
         * помощника, которому метки нужны сами, — очередь zapret) — у спеки без них реестр здесь
         * не нужен, и супервизор его не трогает (registry_assign пишет файл, лишь когда тот
         * расходится с назначением, — как у помощников при старте). */
        int marks = 0, need = 0;
        for (size_t i = 0; i < cfg.out_n; i++)
            if (cfg.out[i].via[0]) { if (registry_assign(&cfg, &e) < 0) err_die(&e); marks = 1; break; }
        size_t k = helpers_plan(&cfg, h, HELPERS_MAX, &need);
        if (need && !marks) {
            if (registry_assign(&cfg, &e) < 0) err_die(&e);
            k = helpers_plan(&cfg, h, HELPERS_MAX, NULL);
        }
        if (fwrite(&k, sizeof(k), 1, w) != 1 || (k && fwrite(h, sizeof(h[0]), k, w) != k)) _exit(1);
        if (fclose(w) != 0) _exit(1);
        _exit(0);
    }
    close(pfd[1]);
    FILE *r = fdopen(pfd[0], "r");
    size_t k = 0;
    int ok = r && fread(&k, sizeof(k), 1, r) == 1 && k <= HELPERS_MAX &&
             (!k || fread(out, sizeof(out[0]), k, r) == k);
    if (r) fclose(r); else close(pfd[0]);
    int st = 0;
    while (waitpid(pid, &st, 0) < 0 && errno == EINTR) {}
    if (!WIFEXITED(st) || WEXITSTATUS(st) != 0 || !ok) return -1;
    *n = k;
    return 0;
}

struct sup_run {
    const char *exe, *self, *spec;
    int seam;
    const sigset_t *blocked;
};

static int sup_start(struct helper *h, void *arg) {
    const struct sup_run *r = arg;
    const char *av[12];
    char prog[600];
    helper_argv(h, r->exe, r->self, r->seam, r->spec, prog, sizeof(prog), av);
    const char *path = av[0];
    char a0[600];
    av[0] = helper_argv0(path, a0, sizeof(a0));
    pid_t pid = fork();
    if (pid < 0) return -1;
    if (pid == 0) {
        sigprocmask(SIG_UNBLOCK, r->blocked, NULL);
        if (h->env[0]) putenv(h->env);
        execv(path, (char *const *)av);
        _exit(127);
    }
    helper_started(h, pid);
    return 0;
}

int cmd_supervise(const char *spec) {
    char exe[512], self[512];
    ssize_t el = readlink("/proc/self/exe", self, sizeof(self) - 1);
    if (el <= 0) die("supervise: не найти свой исполняемый файл (%s)", strerror(errno));
    self[el] = '\0';
    /* Шов стенда: STEER_SUPERVISE_EXE подставляет вместо движка свою программу-помощника
     * (tests/supervisematch.sh), которая только записывает, с чем её позвали. */
    const char *seam = getenv("STEER_SUPERVISE_EXE");
    snprintf(exe, sizeof(exe), "%s", seam && *seam ? seam : self);
    if (!spec) spec = plat()->spec_path;

    sigset_t set;
    sigemptyset(&set);
    sigaddset(&set, SIGCHLD); sigaddset(&set, SIGHUP);
    sigaddset(&set, SIGTERM); sigaddset(&set, SIGINT);
    sigprocmask(SIG_BLOCK, &set, NULL);

    static struct helper_set hs;
    static struct helper fresh[HELPERS_MAX];
    struct sup_run run = { exe, self, spec, seam && *seam, &set };
    if (sup_list(spec, hs.h, &hs.n) != 0)
        die("supervise: спека %s не разобралась — поднимать нечего", spec);
    if (!hs.n) fprintf(stderr, "steer[info] supervise: выходов со своим процессом в спеке нет\n");

    for (;;) {
        long wait = helpers_due(&hs, sup_start, &run);
        siginfo_t si;
        int sig;
        if (wait < 0) sig = sigwaitinfo(&set, &si);
        else {
            struct timespec ts = { wait / 1000, (wait % 1000) * 1000000L };
            sig = sigtimedwait(&set, &si, &ts);
        }
        if (sig < 0) continue;                         /* таймаут или EINTR */
        if (sig == SIGCHLD) {
            int st;
            pid_t p;
            while ((p = waitpid(-1, &st, WNOHANG)) > 0) helpers_exited(&hs, p, st);
            /* Убранные из спеки и уже погасшие — вычистить из таблицы. */
            helpers_compact(&hs);
        } else if (sig == SIGHUP) {
            size_t fn = 0;
            if (sup_list(spec, fresh, &fn) != 0) {
                fprintf(stderr, "steer[warn] supervise: спека не разобралась — состав прежний\n");
                continue;
            }
            helpers_merge(&hs, fresh, fn);
            helpers_compact(&hs);
        } else {                                       /* SIGTERM, SIGINT */
            helpers_stop(&hs, 0);
            return 0;
        }
    }
}
