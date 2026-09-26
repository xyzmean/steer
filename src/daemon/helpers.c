/* Помощники выходов: общая логика `steer supervise` и супервизора демона — см. helpers.h.
 *
 * Всё, что здесь, раньше жило в supervise.c и перенесено без изменения поведения: состав по
 * видам в порядке via, подпись параметров, пауза перезапуска, сверка по SIGHUP. Доводы — у
 * каждой функции. */
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <errno.h>
#include <signal.h>
#include <time.h>
#include <unistd.h>
#include <sys/wait.h>

#include "spec.h"
#include "platform.h"
#include "helpers.h"

long helpers_now_ms(void) {
    struct timespec t;
    clock_gettime(CLOCK_MONOTONIC, &t);
    return (long)t.tv_sec * 1000L + t.tv_nsec / 1000000L;
}

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
 * сервер и локальный адрес; zapret — очередь, файл ключей и его содержимое (новая стратегия —
 * то, что init.d делает reload_zapret). Содержимое остальных файлов (подписка обновилась)
 * подписью не ловится, как и на роутере: это отдельный повод со своим путём. */
static unsigned long long helper_sig(const struct spec *sp, const struct output *o,
                                     const struct kind_helper *hp) {
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
     * сверка после такого apply перезапускает его сразу. Метку считает out_underlay_mark — ровно
     * то значение, что помощник поставит на сокет (с битом туннеля на телефоне). */
    if (o->via[0]) {
        kind_sig_mix(&h, o->via, strlen(o->via));
        uint32_t um = out_underlay_mark(sp, o);
        kind_sig_mix(&h, &um, sizeof(um));
    }
    return h;
}

size_t helpers_plan(const struct spec *sp, struct helper *out, size_t max, int *need_marks) {
    size_t k = 0;
    if (need_marks) *need_marks = 0;
    /* В порядке зависимостей via: цель поднимается раньше того, чей туннель через неё идёт, —
     * иначе первый подъём внутреннего перебирал бы узлы через ещё не созданное устройство и
     * уходил в паузу перезапуска. Гарантии готовности это не даёт (цель поднимается секунды),
     * но у спеки без via порядок прежний, спековый. */
    for (int depth = 0; depth <= MAX_VIA_DEPTH; depth++) {
        for (size_t i = 0; i < sp->out_n; i++) {
            const struct output *o = &sp->out[i];
            if (out_via_depth(sp, o) != depth) continue;
            /* Какой помощник нужен выходу, говорит вид (kind_ops.helper). Вид, чьей команды в
             * этой сборке нет, помощника не называет: vless и xsteer здесь только в расширенной
             * сборке, мост tgws — там же (kinds/tgws.c). */
            const struct kind_ops *kd = kind_of(o);
            struct kind_helper hp = { .sig = KIND_SIG_INIT };
            if (!kd->helper || kd->helper(sp, o, &hp) != 0) continue;
            if (hp.marks && need_marks) *need_marks = 1;
            if (k >= max) continue;
            struct helper *h = &out[k++];
            memset(h, 0, sizeof(*h));
            snprintf(h->cmd, sizeof(h->cmd), "%s", hp.cmd);
            snprintf(h->name, sizeof(h->name), "%s", o->name);
            memcpy(h->prog, hp.prog, sizeof(h->prog));
            memcpy(h->arg, hp.arg, sizeof(h->arg));
            memcpy(h->env, hp.env, sizeof(h->env));
            h->sig = helper_sig(sp, o, &hp);
            h->delay_ms = HELPERS_DELAY_MS;
            h->evfd = -1;
        }
    }
    return k;
}

/* Как назвать помощника в журнале: «obfs a»; у резолвера имени выхода нет — «dnsd». */
static const char *hname(const struct helper *h, char *buf, size_t n) {
    snprintf(buf, n, "%s%s%s", h->cmd, h->name[0] ? " " : "", h->name);
    return buf;
}

static int same_helper(const struct helper *a, const struct helper *b) {
    return !strcmp(a->cmd, b->cmd) && !strcmp(a->name, b->name);
}

/* Параметры запуска — из нового состава: у помощника-программы они в аргументах (очередь,
 * файл ключей zapret), и перезапуск ради новой подписи обязан взять новые. */
static void take_params(struct helper *h, const struct helper *f) {
    memcpy(h->prog, f->prog, sizeof(h->prog));
    memcpy(h->arg, f->arg, sizeof(h->arg));
    memcpy(h->env, f->env, sizeof(h->env));
}

void helpers_merge(struct helper_set *s, const struct helper *fresh, size_t fn) {
    struct helper *h = s->h;
    for (size_t i = 0; i < s->n; i++) {
        int keep = 0;
        for (size_t k = 0; k < fn; k++)
            if (same_helper(&h[i], &fresh[k])) keep = 1;
        if (!keep && !h[i].gone) {
            h[i].gone = 1;
            if (h[i].pid) kill(h[i].pid, SIGTERM);
        }
    }
    /* Оставленные выходы с новыми параметрами: запомнить подпись и перезапустить живого
     * помощника. Не запущенный (ждёт паузы после падения) поднимется уже с новыми — его
     * достаточно запомнить. */
    for (size_t i = 0; i < s->n; i++) {
        if (h[i].gone) continue;
        for (size_t k = 0; k < fn; k++) {
            if (!same_helper(&h[i], &fresh[k])) continue;
            take_params(&h[i], &fresh[k]);
            if (h[i].sig == fresh[k].sig) continue;
            h[i].sig = fresh[k].sig;
            h[i].revive = 0;      /* причина перезапуска теперь — параметры */
            if (h[i].pid && !h[i].restart) {
                h[i].restart = 1;
                kill(h[i].pid, SIGTERM);
            }
        }
    }
    for (size_t k = 0; k < fn && s->n < HELPERS_MAX; k++) {
        int have = 0;
        for (size_t i = 0; i < s->n; i++) {
            if (!same_helper(&h[i], &fresh[k])) continue;
            /* Выход вернули в спеку, пока его прежний помощник ещё гаснет: не второй экземпляр
             * рядом, а тот же слот — перезапустится, когда прежний выйдет. */
            h[i].gone = 0;
            h[i].sig = fresh[k].sig;
            take_params(&h[i], &fresh[k]);
            have = 1;
        }
        if (!have) h[s->n++] = fresh[k];
    }
    /* Спеку исправили — упавшему незачем досиживать растущую паузу до пяти минут. */
    for (size_t i = 0; i < s->n; i++)
        if (!h[i].pid) { h[i].delay_ms = HELPERS_DELAY_MS; h[i].next_ms = 0; }
}

struct helper *helpers_exited(struct helper_set *s, pid_t pid, int st) {
    char nb[48];
    for (size_t i = 0; i < s->n; i++) {
        struct helper *h = &s->h[i];
        if (h->pid != pid) continue;
        h->pid = 0;
        /* Погашен нами ради новых параметров (или по просьбе сторожа, supd_restart) — поднять
         * сразу: это не падение, и ни пауза, ни её рост к нему не относятся. */
        if (h->restart) {
            int rv = h->revive;
            h->restart = h->revive = 0;
            h->delay_ms = HELPERS_DELAY_MS;
            h->next_ms = 0;
            if (!h->gone)
                fprintf(stderr, "steer[info] supervise: %s — %s, поднимаю заново\n",
                        hname(h, nb, sizeof(nb)),
                        rv ? "выход не отвечает" : "параметры выхода изменились");
            return h;
        }
        /* Проработал дольше минуты — пауза снова пять секунд. Эта пауза и ждётся сейчас, а
         * удваивается следующая: первый перезапуск упавшего всегда через пять секунд, как у
         * procd. */
        long now = helpers_now_ms();
        long lived = now - h->started_ms;
        if (lived >= HELPERS_STABLE_MS) h->delay_ms = HELPERS_DELAY_MS;
        h->next_ms = now + h->delay_ms;
        if (!h->gone)
            fprintf(stderr, "steer[warn] supervise: %s вышел (%s %d) — перезапуск "
                            "через %ld с\n", hname(h, nb, sizeof(nb)),
                    WIFEXITED(st) ? "код" : "сигнал",
                    WIFEXITED(st) ? WEXITSTATUS(st) : WTERMSIG(st),
                    h->delay_ms / 1000);
        if (lived < HELPERS_STABLE_MS && h->delay_ms < HELPERS_DELAY_MAX_MS)
            h->delay_ms = h->delay_ms * 2 > HELPERS_DELAY_MAX_MS ? HELPERS_DELAY_MAX_MS
                                                                 : h->delay_ms * 2;
        return h;
    }
    return NULL;
}

void helpers_compact(struct helper_set *s) {
    size_t w = 0;
    for (size_t i = 0; i < s->n; i++)
        if (!(s->h[i].gone && !s->h[i].pid)) {
            if (w != i) s->h[w] = s->h[i];
            w++;
        }
    s->n = w;
}

long helpers_due(struct helper_set *s, helper_start_fn start, void *arg) {
    long now = helpers_now_ms();
    long wait = -1;
    for (size_t i = 0; i < s->n; i++) {
        struct helper *h = &s->h[i];
        if (h->pid || h->gone) continue;
        if (h->next_ms <= now && start(h, arg) != 0) h->next_ms = now + h->delay_ms;
        if (!h->pid && (wait < 0 || h->next_ms - now < wait))
            wait = h->next_ms - now > 0 ? h->next_ms - now : 0;
    }
    return wait;
}

void helper_started(struct helper *h, pid_t pid) {
    h->pid = pid;
    h->started_ms = helpers_now_ms();
    char nb[48];
    fprintf(stderr, "steer[info] supervise: %s запущен (pid %d)\n", hname(h, nb, sizeof(nb)),
            (int)pid);
}

void helper_argv(const struct helper *h, const char *exe, const char *self, int seam,
                 const char *spec, char *progbuf, size_t pbn, const char **av) {
    size_t n = 0;
    if (h->prog[0]) {
        /* Помощник-программа (steer-nfqws) лежит рядом с движком — как /usr/sbin у init.d.
         * Шов стенда подменяет и её, получая имя помощника и выход первыми словами. */
        if (seam) {
            av[n++] = exe;
            av[n++] = h->cmd;
            av[n++] = h->name;
        } else {
            const char *sl = strrchr(self, '/');
            int dl = sl ? (int)(sl - self) : 1;
            snprintf(progbuf, pbn, "%.*s/%s", dl, sl ? self : ".", h->prog);
            av[n++] = progbuf;
        }
        for (size_t i = 0; i < sizeof(h->arg) / sizeof(h->arg[0]) && h->arg[i][0]; i++)
            av[n++] = h->arg[i];
        av[n] = NULL;
        return;
    }
    av[n++] = exe;
    av[n++] = h->cmd;
    av[n++] = h->name;
    av[n++] = "--spec";
    av[n++] = spec;
    /* Каталог состояния — тот же, что у супервизора, если его задали: помощник читает оттуда
     * реестр меток (метку цели via), и разойдись каталоги — подпись в супервизоре считалась бы
     * по одной метке, а сокет помощника ставился бы по другой. */
    if (strcmp(steer_state_dir(), plat()->state_dir) != 0) {
        av[n++] = "--state-dir";
        av[n++] = steer_state_dir();
    }
    av[n] = NULL;
}

const char *helper_argv0(const char *exe, char *buf, size_t n) {
    const char *sl = strrchr(exe, '/');
    const char *base = sl ? sl + 1 : exe;
    if (strcmp(base, "steerd") != 0) return exe;
    snprintf(buf, n, "%.*ssteer", (int)(base - exe), exe);
    return buf;
}

/* Дождаться выхода pid до срока (монотонные мс). 1 — вышел (пожат). */
static int wait_until(pid_t pid, long deadline) {
    for (;;) {
        pid_t w = waitpid(pid, NULL, WNOHANG);
        if (w == pid || (w < 0 && errno == ECHILD)) return 1;
        if (helpers_now_ms() >= deadline) return 0;
        struct timespec ts = { 0, 50000000L };
        nanosleep(&ts, NULL);
    }
}

void helpers_stop(struct helper_set *s, int ordered) {
    struct helper *h = s->h;
    size_t n = s->n;
    if (!ordered) {
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
        return;
    }
    /* По одному, в обратном порядке подъёма: внешний туннель гаснет раньше того, через кого он
     * идёт, и не успевает перебрать узлы через уже снятое устройство. Каждому — три секунды на
     * уборку, всем вместе — не больше десяти: дальше оставшимся сразу SIGKILL (procd и init
     * ждут остановки службы не бесконечно). */
    long all = helpers_now_ms() + 10000L;
    for (size_t i = n; i-- > 0;) {
        if (!h[i].pid) continue;
        long now = helpers_now_ms();
        if (now < all) {
            kill(h[i].pid, SIGTERM);
            long dl = now + 3000L < all ? now + 3000L : all;
            if (wait_until(h[i].pid, dl)) { h[i].pid = 0; continue; }
        }
        kill(h[i].pid, SIGKILL);
        while (waitpid(h[i].pid, NULL, 0) < 0 && errno == EINTR) {}
        h[i].pid = 0;
    }
}
