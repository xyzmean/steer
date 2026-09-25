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


/* Сторож по кругу: `steer failover --loop СЕК`.
 *
 * На роутере круг крутит procd строкой `while :; do steer failover; sleep 60; done`. У init
 * Android такой строки нет: сервис — это один исполняемый файл, и запускать его через
 * /system/bin/sh значило бы выдать домену steerd право исполнять shell — то есть любую
 * команду, которую удастся подсунуть в спеку. Поэтому круг здесь, в движке.
 *
 * КАЖДЫЙ ПРОХОД — ОТДЕЛЬНЫЙ ПРОЦЕСС (fork). cmd_failover писан под «один проход и выход»:
 * спека грузится в глобальные массивы один раз, и повторный load_spec в том же процессе
 * склеил бы выходы двух чтений. Дочерний процесс получает чистую память и выходит через
 * exit, так что его atexit (снятие probe-rule) срабатывает, как и при запуске из shell; die()
 * в нём — это конец одного прохода, а не сторожа: следующий проход перечитает спеку, и
 * исправленная спека подхватится без перезапуска сервиса — ровно как в круге procd.
 *
 * СОН НА CLOCK_MONOTONIC — требование батареи. Этот таймер во сне устройства стоит и не
 * будит его (будят только *_ALARM и удерживаемый wakelock, которых здесь нет): пока телефон
 * спит, сторож молчит, а проснувшись, досыпает остаток периода.
 *
 * ПО СОБЫТИЯМ, А НЕ ТОЛЬКО ПО ПЕРИОДУ: смена интерфейса или адреса (сеть сменилась, TUN выхода
 * поднялся или упал) — внеочередной проход через пять секунд после события, см.
 * failover_events_open. Период остаётся для того, чего событием не увидеть: туннель поднят,
 * а трафик через него не идёт.
 *
 * init гасит сервис сигналом всей группе процессов, поэтому дочерний проход получает свой
 * SIGTERM и убирает за собой так же, как от kill на роутере. */
/* Сокет событий ядра для сторожа: смена состояния интерфейса и его адресов. -1 — не
 * открылся, и сторож живёт одним периодом, как раньше.
 *
 * ИНТЕРФЕЙСЫ И АДРЕСА, НО НЕ МАРШРУТЫ. Маршруты в таблицах выходов меняет сам сторож (и apply)
 * — подписка на них будила бы его собственными действиями по кругу. А то, ради чего события и
 * нужны, видно именно здесь: сменилась сеть (у Wi-Fi или сотовой появился или пропал адрес),
 * поднялся TUN выхода, который создал помощник, упал интерфейс туннеля. */
static int failover_events_open(void) {
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
static int failover_events_drain(int fd) {
    char buf[8192];
    int any = 0;
    ssize_t r;
    while ((r = recv(fd, buf, sizeof(buf), 0)) > 0 || (r < 0 && errno == ENOBUFS))
        any = 1;   /* ENOBUFS — события потеряны переполнением: это тоже «что-то сменилось» */
    return any;
}

int failover_loop(const char *spec, int verbose, int period) {
    int ev = failover_events_open();
    for (;;) {
        /* ПАМЯТЬ МЕЖДУ ПРОХОДАМИ — у родителя, а не в файлах каталога состояния: на телефоне это
         * /data, флеш, и запись на каждом проходе (раз в минуту и по каждому событию сети) шла бы
         * круглые сутки. Замеры счётчиков туннелей awg дочерний проход получает копией памяти при
         * fork, а свои новые отдаёт по трубе (awg_hs_send / awg_hs_recv, src/kinds/awg.c). Остальное, что
         * проход пишет, — выбор устройств (active), реестр меток, подпись awg — пишется только
         * при изменении. Нет трубы — этот проход работает по-старому, файлом: без памяти
         * приговор «туннель молчит» не вынести вовсе. O_CLOEXEC — чтобы команды, которые проход
         * запускает (ip, nft), не держали конец записи и родитель не ждал их, читая трубу. */
        int pfd[2];
        int piped = pipe2(pfd, O_CLOEXEC) == 0;
        awg_hs_memory(piped);
        pid_t pid = fork();
        if (pid == 0) {
            if (piped) close(pfd[0]);
            int rc = cmd_failover(spec, verbose);
#ifdef STEER_ANDROID
            /* Свой экземпляр спеки (правило 6): та, что cmd_failover уже разобрал, живёт в
             * его собственном static struct spec и наружу не смотрит. Дочерний процесс за
             * миг до этого прошёл этим же load_spec внутри cmd_failover — если спека была
             * годной там, второй разбор здесь не откажет; не откажет — просто не подметём
             * masquerade в этом проходе, тем же кругом починится в следующем. */
            {
                static struct spec cfg;
                struct err e2 = {0};
                if (load_spec(spec, &cfg, &e2) == 0) android_masq_ensure(&cfg);
            }
#endif
            if (piped) awg_hs_send(pfd[1]);
            exit(rc);
        }
        if (piped) close(pfd[1]);
        if (pid > 0) {
            /* Сначала дочитать трубу (до конца файла — проход вышел), потом ждать: сообщение
             * короче буфера трубы, так что проход не встанет на записи, но порядок и так верный. */
            if (piped) awg_hs_recv(pfd[0]);
            while (waitpid(pid, NULL, 0) < 0 && errno == EINTR) {}
        } else
            fprintf(stderr, "steer[warn] failover: fork: %s\n", strerror(errno));
        if (piped) close(pfd[0]);
#ifndef STEER_ANDROID
        /* На роутере проход сам делает ifdown/ifup мёртвому интерфейсу, и события за время
         * прохода — его же следы: реагировать на них значило бы будить себя по кругу. На
         * телефоне сторож интерфейсы не трогает (только ждёт), и событие за время прохода —
         * настоящее: например, TUN, который как раз поднял помощник выхода. */
        if (ev >= 0) failover_events_drain(ev);
#endif

        /* Ждать период ИЛИ событие. poll на монотонном времени: во сне устройства ожидание
         * стоит и не будит его. Событие — не повод бежать сразу: смена сети приходит пачкой
         * (адрес ушёл, интерфейс лёг, поднялся, адрес пришёл), и проход на середине увидел бы
         * полусобранную сеть. Пять секунд — и чтобы она закончилась, и чтобы мигающий
         * интерфейс не гонял проходы подряд. */
        long left = (long)period * 1000;
        struct timespec t0;
        clock_gettime(CLOCK_MONOTONIC, &t0);
        for (;;) {
            struct pollfd p = { ev, POLLIN, 0 };
            int r = ev >= 0 ? poll(&p, 1, (int)(left > 0x7fffffff ? 0x7fffffff : left))
                            : poll(NULL, 0, (int)(left > 0x7fffffff ? 0x7fffffff : left));
            if (r > 0 && failover_events_drain(ev)) {
                struct timespec q = { 5, 0 };
                while (nanosleep(&q, &q) != 0 && errno == EINTR) {}
                failover_events_drain(ev);
                if (verbose)
                    fprintf(stderr, "steer[info] failover: сеть изменилась — проверяю выходы\n");
                break;
            }
            struct timespec t1;
            clock_gettime(CLOCK_MONOTONIC, &t1);
            long spent = (t1.tv_sec - t0.tv_sec) * 1000L + (t1.tv_nsec - t0.tv_nsec) / 1000000L;
            if (spent >= (long)period * 1000) break;
            left = (long)period * 1000 - spent;
        }
    }
}
