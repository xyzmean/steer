#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <errno.h>
#include <unistd.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <linux/netlink.h>
#include <linux/rtnetlink.h>
#include <poll.h>
#include <signal.h>
#include <fcntl.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/time.h>
#include <time.h>

#include "spec.h"
#include "awg.h"
#include "hwid.h"
#include "obfs.h"
#include "cli.h"
#include "srs.h"
#include "ctl.h"
#include "daemon.h"


/* ---- supervise: помощники выходов одним сервисом -------------------------------------
 *
 * На роутере init-скрипт поднимает по экземпляру procd на каждый выход, которому нужен свой
 * процесс (vless, xsteer, obfs, tgws), и procd перезапускает упавший через пять секунд. У init
 * Android так нельзя: сервисы объявлены в rc статически, а состав выходов известен только из
 * спеки. Поэтому один сервис — этот — поднимает их сам и держит.
 *
 * СОСТАВ считается в ДОЧЕРНЕМ процессе и приезжает строками через трубу: спеку загружают в
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
 * ничего, если не изменились их параметры (см. sup_sig): у изменившихся помощник гасится и
 * поднимается сразу, без пятисекундной паузы. SIGTERM — погасить всех и выйти (init шлёт его
 * группе, это на случай kill). SIGHUP шлёт управляющий сокет после каждого удачного apply
 * (src/daemon/ctl.c, reload).
 *
 * zapret здесь нет: его обработчик — отдельная программа (steer-nfqws), а в сборке под
 * Android zapret нет вовсе. В базовой сборке нет и vless, xsteer и tgws — их команды есть только
 * в расширенной, и запускать их значило бы перезапускать отказ по кругу. */
#define SUP_MAX 32
struct sup_helper {
    char cmd[8];
    char name[32];
    pid_t pid;
    long next_ms;       /* когда можно запускать (0 — сразу) */
    long started_ms;
    long delay_ms;      /* пауза следующего перезапуска */
    int gone;           /* выход убран из спеки: не перезапускать */
    unsigned long long sig;   /* подпись параметров, которые помощник читает при старте */
    int restart;        /* погашен ради новых параметров: поднять сразу, без паузы */
};

/* ПОДПИСЬ ПАРАМЕТРОВ ПОМОЩНИКА — то, что он читает из спеки ОДИН РАЗ, при старте.
 *
 * Состав («команда выход») SIGHUP сверял и раньше, а смену параметров оставленного выхода — нет:
 * человек выбирал другой узел подписки или другой сервер обфускации, apply проходил, а помощник
 * продолжал работать со старым до своего перезапуска, то есть до перезагрузки. Тот же открытый
 * пункт закрывает на роутере сам splify2 отпечатками vless_fingerprint и obfs_fingerprint
 * (rpcd/m-spec.sh); здесь поля те же, и по тем же доводам в подпись входит ТОЛЬКО то, что
 * помощник действительно читает при старте. Правка устройства, on_fail или каналов помощника
 * не касается, а перезапуск рвёт туннель и меняет выходной адрес — трогать его из-за неё нельзя.
 *
 * Поля по видам называет сам вид (kind_ops.helper в src/kinds): vless — файл подписки и выбор
 * узлов; xsteer — файл конфигурации и режим потока; tgws — домен точек; obfs у interface —
 * сервер и локальный адрес. Содержимое файлов (подписка обновилась) подписью не ловится, как и
 * на роутере: это отдельный повод со своим путём. */
static unsigned long long sup_sig(const struct spec *sp, const struct output *o, const struct kind_helper *hp) {
    unsigned long long h = hp->sig;       /* поля вида уже подмешаны его kind_ops.helper */
    /* Цель `via` помощник тоже читает при старте: метку сокета наверх он берёт один раз
     * (out_underlay_mark), и смена цели без перезапуска оставила бы туннель в прежнем выходе.
     * Только когда поле задано — подпись выхода без via остаётся прежней, и обновление движка
     * не перезапускает ни одного помощника.
     *
     * И сама МЕТКА цели, а не только её имя. Цель могли убрать из спеки и вернуть под тем же
     * именем — реестр выдаст ей другое место, то есть другую метку и таблицу, — а помощник со
     * старой меткой продолжал бы метить сокет значением, которое теперь ведёт в чужую таблицу
     * или никуда (то есть напрямую, мимо цели), до своего перезапуска. С меткой в подписи
     * reload после такого apply перезапускает его сразу. Метку считает out_underlay_mark — ровно
     * то значение, что помощник поставит на сокет (с битом туннеля на телефоне). */
    if (o->via[0]) {
        kind_sig_mix(&h, o->via, strlen(o->via));
        uint32_t um = out_underlay_mark(sp, o);
        kind_sig_mix(&h, &um, sizeof(um));
    }
    return h;
}

static long sup_now_ms(void) {
    struct timespec t;
    clock_gettime(CLOCK_MONOTONIC, &t);
    return (long)t.tv_sec * 1000L + t.tv_nsec / 1000000L;
}

/* Состав помощников по спеке — строками «команда имя подпись». -1 — спека не разобралась. */
static int sup_list(const char *spec, struct sup_helper *out, size_t *n) {
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
        struct err e = {0};
        if (load_spec(spec, &cfg, &e) < 0) err_die(&e);
        /* Метки выходов — из реестра: без них out_underlay_mark в подписи (sup_sig) вернул бы
         * «мимо каналов» при любой цели, и смена метки цели не была бы видна. Только при via —
         * у спеки без него реестр здесь не нужен, и супервизор его не трогает (registry_assign
         * пишет файл, лишь когда тот расходится с назначением, — как у помощников при старте). */
        for (size_t i = 0; i < cfg.out_n; i++)
            if (cfg.out[i].via[0]) { if (registry_assign(&cfg, &e) < 0) err_die(&e); break; }
        /* В порядке зависимостей via: цель поднимается раньше того, чей туннель через неё
         * идёт, — иначе первый подъём внутреннего перебирал бы узлы через ещё не созданное
         * устройство и уходил в паузу перезапуска. Гарантии готовности это не даёт (цель
         * поднимается секунды), но у спеки без via порядок прежний, спековый. */
        for (int depth = 0; depth <= MAX_VIA_DEPTH; depth++) {
            for (size_t i = 0; i < cfg.out_n; i++) {
                const struct output *o = &cfg.out[i];
                if (out_via_depth(&cfg, o) != depth) continue;
                /* Какой помощник нужен выходу, говорит вид (kind_ops.helper). Вид, чьей команды
                 * в этой сборке нет, помощника не называет: vless и xsteer здесь только в
                 * расширенной сборке, мост tgws — там же (kinds/tgws.c). */
                const struct kind_ops *k = kind_of(o);
                struct kind_helper hp = { .sig = KIND_SIG_INIT };
                if (k->helper && k->helper(&cfg, o, &hp) == 0)
                    fprintf(w, "%s %s %llx\n", hp.cmd, o->name, sup_sig(&cfg, o, &hp));
            }
        }
        fclose(w);
        _exit(0);
    }
    close(pfd[1]);
    FILE *r = fdopen(pfd[0], "r");
    size_t k = 0;
    char line[128];
    while (r && fgets(line, sizeof(line), r) && k < SUP_MAX) {
        char c[8], nm[32];
        unsigned long long sg = 0;
        if (sscanf(line, "%7s %31s %llx", c, nm, &sg) != 3) continue;
        memset(&out[k], 0, sizeof(out[k]));
        snprintf(out[k].cmd, sizeof(out[k].cmd), "%s", c);
        snprintf(out[k].name, sizeof(out[k].name), "%s", nm);
        out[k].sig = sg;
        out[k].delay_ms = 5000;
        k++;
    }
    if (r) fclose(r); else close(pfd[0]);
    int st = 0;
    while (waitpid(pid, &st, 0) < 0 && errno == EINTR) {}
    if (!WIFEXITED(st) || WEXITSTATUS(st) != 0) return -1;
    *n = k;
    return 0;
}

static void sup_start(struct sup_helper *h, const char *exe, const char *spec,
                      const sigset_t *blocked) {
    pid_t pid = fork();
    if (pid < 0) { h->next_ms = sup_now_ms() + h->delay_ms; return; }
    if (pid == 0) {
        sigprocmask(SIG_UNBLOCK, blocked, NULL);
        /* Каталог состояния — тот же, что у супервизора, если его задали: помощник читает оттуда
         * реестр меток (метку цели via), и разойдись каталоги — подпись в супервизоре считалась бы
         * по одной метке, а сокет помощника ставился бы по другой. */
        const char *argv[] = { exe, h->cmd, h->name, "--spec", spec, NULL, NULL, NULL };
        if (strcmp(steer_state_dir(), plat()->state_dir) != 0) {
            argv[5] = "--state-dir";
            argv[6] = steer_state_dir();
        }
        execv(exe, (char *const *)argv);
        _exit(127);
    }
    h->pid = pid;
    h->started_ms = sup_now_ms();
    fprintf(stderr, "steer[info] supervise: %s %s запущен (pid %d)\n", h->cmd, h->name, (int)pid);
}

int cmd_supervise(const char *spec) {
    char exe[512];
    /* Шов стенда: STEER_SUPERVISE_EXE подставляет вместо движка свою программу-помощника
     * (tests/supervisematch.sh), которая только записывает, с чем её позвали. */
    const char *seam = getenv("STEER_SUPERVISE_EXE");
    if (seam && *seam) snprintf(exe, sizeof(exe), "%s", seam);
    else {
        ssize_t el = readlink("/proc/self/exe", exe, sizeof(exe) - 1);
        if (el <= 0) die("supervise: не найти свой исполняемый файл (%s)", strerror(errno));
        exe[el] = '\0';
    }
    if (!spec) spec = plat()->spec_path;

    sigset_t set;
    sigemptyset(&set);
    sigaddset(&set, SIGCHLD); sigaddset(&set, SIGHUP);
    sigaddset(&set, SIGTERM); sigaddset(&set, SIGINT);
    sigprocmask(SIG_BLOCK, &set, NULL);

    static struct sup_helper h[SUP_MAX];
    size_t n = 0;
    if (sup_list(spec, h, &n) != 0)
        die("supervise: спека %s не разобралась — поднимать нечего", spec);
    if (!n) fprintf(stderr, "steer[info] supervise: выходов со своим процессом в спеке нет\n");

    for (;;) {
        long now = sup_now_ms();
        long wait = -1;
        for (size_t i = 0; i < n; i++) {
            if (h[i].pid || h[i].gone) continue;
            if (h[i].next_ms <= now) sup_start(&h[i], exe, spec, &set);
            if (!h[i].pid && (wait < 0 || h[i].next_ms - now < wait))
                wait = h[i].next_ms - now > 0 ? h[i].next_ms - now : 0;
        }
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
            while ((p = waitpid(-1, &st, WNOHANG)) > 0) {
                for (size_t i = 0; i < n; i++) {
                    if (h[i].pid != p) continue;
                    h[i].pid = 0;
                    /* Погашен нами ради новых параметров — поднять сразу: это не падение,
                     * и ни пауза, ни её рост к нему не относятся. */
                    if (h[i].restart) {
                        h[i].restart = 0;
                        h[i].delay_ms = 5000;
                        h[i].next_ms = 0;
                        if (!h[i].gone)
                            fprintf(stderr, "steer[info] supervise: %s %s — параметры выхода "
                                            "изменились, поднимаю заново\n", h[i].cmd, h[i].name);
                        continue;
                    }
                    /* Проработал дольше минуты — пауза снова пять секунд. Эта пауза и
                     * ждётся сейчас, а удваивается следующая: первый перезапуск упавшего
                     * всегда через пять секунд, как у procd. */
                    long lived = sup_now_ms() - h[i].started_ms;
                    if (lived >= 60000) h[i].delay_ms = 5000;
                    h[i].next_ms = sup_now_ms() + h[i].delay_ms;
                    if (!h[i].gone)
                        fprintf(stderr, "steer[warn] supervise: %s %s вышел (%s %d) — перезапуск "
                                        "через %ld с\n", h[i].cmd, h[i].name,
                                WIFEXITED(st) ? "код" : "сигнал",
                                WIFEXITED(st) ? WEXITSTATUS(st) : WTERMSIG(st),
                                h[i].delay_ms / 1000);
                    if (lived < 60000 && h[i].delay_ms < 300000)
                        h[i].delay_ms = h[i].delay_ms * 2 > 300000 ? 300000 : h[i].delay_ms * 2;
                }
            }
            /* Убранные из спеки и уже погасшие — вычистить из таблицы. */
            size_t w = 0;
            for (size_t i = 0; i < n; i++)
                if (!(h[i].gone && !h[i].pid)) h[w++] = h[i];
            n = w;
        } else if (sig == SIGHUP) {
            static struct sup_helper fresh[SUP_MAX];
            size_t fn = 0;
            if (sup_list(spec, fresh, &fn) != 0) {
                fprintf(stderr, "steer[warn] supervise: спека не разобралась — состав прежний\n");
                continue;
            }
            for (size_t i = 0; i < n; i++) {
                int keep = 0;
                for (size_t k = 0; k < fn; k++)
                    if (!strcmp(h[i].cmd, fresh[k].cmd) && !strcmp(h[i].name, fresh[k].name))
                        keep = 1;
                if (!keep && !h[i].gone) {
                    h[i].gone = 1;
                    if (h[i].pid) kill(h[i].pid, SIGTERM);
                }
            }
            /* Оставленные выходы с новыми параметрами: запомнить подпись и перезапустить
             * живого помощника. Не запущенный (ждёт паузы после падения) поднимется уже с
             * новыми — его достаточно запомнить. */
            for (size_t i = 0; i < n; i++) {
                if (h[i].gone) continue;
                for (size_t k = 0; k < fn; k++) {
                    if (strcmp(h[i].cmd, fresh[k].cmd) || strcmp(h[i].name, fresh[k].name) ||
                        h[i].sig == fresh[k].sig)
                        continue;
                    h[i].sig = fresh[k].sig;
                    if (h[i].pid && !h[i].restart) {
                        h[i].restart = 1;
                        kill(h[i].pid, SIGTERM);
                    }
                }
            }
            for (size_t k = 0; k < fn && n < SUP_MAX; k++) {
                int have = 0;
                for (size_t i = 0; i < n; i++) {
                    if (strcmp(h[i].cmd, fresh[k].cmd) || strcmp(h[i].name, fresh[k].name))
                        continue;
                    /* Выход вернули в спеку, пока его прежний помощник ещё гаснет: не второй
                     * экземпляр рядом, а тот же слот — перезапустится, когда прежний выйдет. */
                    h[i].gone = 0;
                    h[i].sig = fresh[k].sig;
                    have = 1;
                }
                if (!have) h[n++] = fresh[k];
            }
            /* Спеку исправили — упавшему незачем досиживать растущую паузу до пяти минут. */
            for (size_t i = 0; i < n; i++)
                if (!h[i].pid) { h[i].delay_ms = 5000; h[i].next_ms = 0; }
            size_t w = 0;
            for (size_t i = 0; i < n; i++)
                if (!(h[i].gone && !h[i].pid)) h[w++] = h[i];
            n = w;
        } else {                                       /* SIGTERM, SIGINT */
            for (size_t i = 0; i < n; i++) if (h[i].pid) kill(h[i].pid, SIGTERM);
            for (int t = 0; t < 31; t++) {
                /* Три секунды на уборку, дальше — SIGKILL: супервизор не выходит, оставив
                 * помощника жить без присмотра. */
                if (t == 30)
                    for (size_t i = 0; i < n; i++) if (h[i].pid) kill(h[i].pid, SIGKILL);
                int left = 0;
                for (size_t i = 0; i < n; i++) {
                    if (!h[i].pid) continue;
                    if (waitpid(h[i].pid, NULL, WNOHANG) == h[i].pid) h[i].pid = 0;
                    else left = 1;
                }
                if (!left) break;
                struct timespec ts = { 0, 100000000L };
                nanosleep(&ts, NULL);
            }
            return 0;
        }
    }
}
