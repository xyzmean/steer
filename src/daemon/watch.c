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
#include <sys/epoll.h>
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
#include "loop.h"
#include "fostate.h"


/* Сторож по кругу: `steer failover --loop СЕК`.
 *
 * На роутере круг крутит procd строкой `while :; do steer failover; sleep 60; done`. У init
 * Android такой строки нет: сервис — это один исполняемый файл, и запускать его через
 * /system/bin/sh значило бы выдать домену steerd право исполнять shell — то есть любую
 * команду, которую удастся подсунуть в спеку. Поэтому круг здесь, в движке.
 *
 * ПРОХОД — ТОТ ЖЕ АВТОМАТ, ЧТО У ДЕМОНА И `steer failover` (failover.c, «ПРОХОД — КОНЕЧНЫЙ
 * АВТОМАТ»), на своём цикле событий (loop.h), в этом же процессе, без fork. Раньше каждый проход
 * был отдельным процессом: cmd_failover писался под «один проход и выход» и грузил спеку в
 * глобальные массивы. Спека давно значение (правило 6), автомат ждёт на цикле, а не синхронно, и
 * копия процесса на проход ушла — вместе с трубой, по которой ребёнок отдавал замеры awg: они
 * теперь просто живут в памяти этого процесса (awg_hs_memory). Спека по-прежнему читается
 * заново на каждом проходе: исправленная спека подхватывается без перезапуска сервиса — ровно
 * как в круге procd, — а негодная означает только, что этот проход не состоится (строка отказа
 * та же, что напечатал бы `steer failover`).
 *
 * СОН НА CLOCK_MONOTONIC — требование батареи. Таймер цикла (timerfd на CLOCK_MONOTONIC) во сне
 * устройства стоит и не будит его (будят только *_ALARM и удерживаемый wakelock, которых здесь
 * нет): пока телефон спит, сторож молчит, а проснувшись, досыпает остаток периода.
 *
 * ПО СОБЫТИЯМ, А НЕ ТОЛЬКО ПО ПЕРИОДУ: смена интерфейса или адреса (сеть сменилась, TUN выхода
 * поднялся или упал) — внеочередной проход через пять секунд после события, см.
 * watch_nl_open. Период остаётся для того, чего событием не увидеть: туннель поднят,
 * а трафик через него не идёт. Следующий проход — через период после конца предыдущего.
 *
 * SIGTERM и SIGINT приходят через цикл: идущий проход прерывается с уборкой правила пробы, и
 * процесс уходит по сигналу, как уходил раньше. */
/* Сокет событий ядра для сторожа: смена состояния интерфейса и его адресов. -1 — не
 * открылся, и сторож живёт одним периодом, как раньше.
 *
 * ИНТЕРФЕЙСЫ И АДРЕСА, НО НЕ МАРШРУТЫ. Маршруты в таблицах выходов меняет сам сторож (и apply)
 * — подписка на них будила бы его собственными действиями по кругу. А то, ради чего события и
 * нужны, видно именно здесь: сменилась сеть (у Wi-Fi или сотовой появился или пропал адрес),
 * поднялся TUN выхода, который создал помощник, упал интерфейс туннеля. */
int watch_nl_open(void) {
    int fd = socket(AF_NETLINK, SOCK_RAW | SOCK_CLOEXEC | SOCK_NONBLOCK, NETLINK_ROUTE);
    if (fd < 0) return -1;
    struct sockaddr_nl a;
    memset(&a, 0, sizeof(a));
    a.nl_family = AF_NETLINK;
    a.nl_groups = RTMGRP_LINK | RTMGRP_IPV4_IFADDR | RTMGRP_IPV6_IFADDR;
    if (bind(fd, (struct sockaddr *)&a, sizeof(a)) != 0) { close(fd); return -1; }
    return fd;
}

/* Дочитать всё, что накопилось. 1 — было хоть одно событие. */
int watch_nl_drain(int fd) {
    char buf[8192];
    int any = 0;
    ssize_t r;
    while ((r = recv(fd, buf, sizeof(buf), 0)) > 0 || (r < 0 && errno == ENOBUFS))
        any = 1;   /* ENOBUFS — события потеряны переполнением: это тоже «что-то сменилось» */
    return any;
}

/* Возвращать ли masquerade (телефон, iptables_masq_ensure) после этого прохода. iptables -C —
 * процесс на устройство, а сторож работает без процессов на проход; правило же пропадает только
 * при перезапуске netd, который перестраивает iptables. Поэтому — после проходов по событию
 * сети или смене спеки (force) и не реже раза в WATCH_MASQ_S. */
int watch_masq_due(long *last, int force) {
    struct timespec t;
    clock_gettime(CLOCK_MONOTONIC, &t);
    long now = (long)t.tv_sec;
    if (!force && *last && now - *last < WATCH_MASQ_S) return 0;
    *last = now ? now : 1;
    return 1;
}

struct floop {
    struct loop *l;
    const char *spec;
    int verbose, period;
    int nl;
    struct loop_timer *tm;
    int settling, pending, eventful;
    struct fo_run *run;
    long masq_at;
};

/* Спека прохода — static: она большая, а проход один за раз. */
static struct spec g_loop_spec;

static void fl_period(struct floop *f) {
    f->settling = 0;
    loop_timer_set(f->tm, (long)f->period * 1000L);
}

/* Событие не повод бежать сразу: смена сети приходит пачкой (адрес ушёл, интерфейс лёг,
 * поднялся, адрес пришёл), и проход на середине увидел бы полусобранную сеть. Пять секунд — и
 * чтобы она закончилась, и чтобы мигающий интерфейс не гонял проходы подряд. */
static void fl_settle(struct floop *f) {
    f->eventful = 1;
    if (f->settling) return;
    f->settling = 1;
    loop_timer_set(f->tm, WATCH_SETTLE_S * 1000L);
}

static void fl_done(void *arg, int res) {
    (void)res;
    struct floop *f = arg;
    f->run = NULL;
    /* masquerade правилом iptables (телефон): netd при перезапуске перестраивает iptables, и
     * наши правила пропадают — вернуть их (iptables_masq_ensure в apply.c). Смотрит он на
     * кандидатов выхода (devices), а не на выбранное проходом устройство. */
    if (plat()->iptables_masq && watch_masq_due(&f->masq_at, f->eventful))
        iptables_masq_ensure(&g_loop_spec);
    f->eventful = 0;
    /* На роутере (plat()->netifd) проход сам делает ifdown/ifup мёртвому интерфейсу, и
     * события за время прохода — его же следы: реагировать на них значило бы будить себя
     * по кругу. На телефоне сторож интерфейсы не трогает (только ждёт), и событие за время
     * прохода — настоящее: например, TUN, который как раз поднял помощник выхода. */
    if (plat()->netifd && f->nl >= 0) watch_nl_drain(f->nl);
    if (f->pending) {
        f->pending = 0;
        fl_settle(f);
    } else {
        fl_period(f);
    }
}

static void fl_pass(struct floop *f) {
    memset(&g_loop_spec, 0, sizeof(g_loop_spec));
    struct err e = {0};
    if (load_spec(f->spec, &g_loop_spec, &e) < 0 || registry_assign(&g_loop_spec, &e) < 0) {
        /* Тот же текст, что у err_die в `steer failover`, — но конец прохода, а не круга. */
        fprintf(stderr, "steer: %s\n", e.msg);
        fl_period(f);
        return;
    }
    f->run = fo_pass_start(f->l, &g_loop_spec, &fo_store_files, f->verbose, NULL, NULL,
                           fl_done, f);
    if (!f->run) fl_period(f);
}

static void fl_timer(struct loop *l, struct loop_timer *t, void *arg) {
    (void)l; (void)t;
    struct floop *f = arg;
    f->settling = 0;
    if (f->run) return;
    if (f->nl >= 0 && watch_nl_drain(f->nl)) f->eventful = 1;
    if (f->eventful && f->verbose)
        fprintf(stderr, "steer[info] failover: сеть изменилась — проверяю выходы\n");
    fl_pass(f);
}

static void fl_nl(struct loop *l, int fd, uint32_t ev, void *arg) {
    (void)l; (void)ev;
    struct floop *f = arg;
    if (!watch_nl_drain(fd)) return;
    if (f->run) {
        if (!plat()->netifd) f->pending = 1;
        return;
    }
    fl_settle(f);
}

static void fl_sig(struct loop *l, int sig, void *arg) {
    (void)l;
    struct floop *f = arg;
    if (f->run) fo_pass_abort(f->run);
    f->run = NULL;
    cleanup_probe_rule();
    /* Уйти по сигналу, как уходил круг до цикла: кто его ждёт (procd, init), видит то же. */
    signal(sig, SIG_DFL);
    sigset_t s;
    sigemptyset(&s);
    sigaddset(&s, sig);
    sigprocmask(SIG_UNBLOCK, &s, NULL);
    raise(sig);
    _exit(128 + sig);
}

int failover_loop(const char *spec, int verbose, int period) {
    failover_pass_guard();
    awg_hs_memory(1);
    struct loop *l = loop_new();
    if (!l) {
        fprintf(stderr, "steer[warn] failover: цикл событий не завёлся: %s\n", strerror(errno));
        return 1;
    }
    static struct floop f;
    memset(&f, 0, sizeof(f));
    f.l = l;
    f.spec = spec;
    f.verbose = verbose;
    f.period = period > 0 ? period : 60;
    f.tm = loop_timer_new(l, fl_timer, &f);
    if (!f.tm) { loop_free(l); return 1; }
    f.nl = watch_nl_open();
    if (f.nl >= 0 && loop_fd_add(l, f.nl, EPOLLIN, fl_nl, &f) != 0) {
        close(f.nl);
        f.nl = -1;
    }
    loop_signal(l, SIGTERM, fl_sig, &f);
    loop_signal(l, SIGINT, fl_sig, &f);
    f.eventful = 1;               /* первый проход — как по событию: masquerade проверить */
    loop_timer_set(f.tm, 0);
    return loop_run(l);
}
