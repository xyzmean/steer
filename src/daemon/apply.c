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
#include "groups.h"
#include "generate.h"
#include "run.h"

#ifdef STEER_ANDROID
static void android_masq_drop_all(void);   /* ниже, у apply_routing */
#endif
/* ---- apply ---------------------------------------------------------------- */


/* ---- снятие мёртвых правил маршрутизации ------------------------------------
 *
 * rename/remove выхода оставляли в ядре ip rule fwmark и его таблицу навсегда:
 * apply ставит правила только для ТЕКУЩИХ выходов по их НОВЫМ меткам, метка
 * назначается по имени из реестра, и правило переименованного выхода не снимал
 * никто (I-019). Мёртвые правила не матчатся — метку с них уже никто не ставит, —
 * но копятся с каждым переименованием и засоряют `ip rule show` ровно тогда,
 * когда по нему пытаются понять, куда ушёл трафик.
 *
 * Снимок прежнего реестра берётся ДО registry_assign — тот перезаписывает файл
 * текущими выходами, и после него сравнивать уже не с чем. Живой считается метка,
 * которую несёт ЛЮБОЙ текущий недирект-выход: устройство здесь не проверяется
 * нарочно, у vless его создаёт сам процесс туннеля, и снять правило выхода за то,
 * что его устройство ещё не поднялось, значило бы обрубить туннель на ровном
 * месте. */
struct oldreg { unsigned mark; int table; };
static struct oldreg g_oldreg[MAX_OUTPUTS];
static size_t g_oldreg_n;

static void registry_snapshot(void) {
    char path[512];
    snprintf(path, sizeof(path), "%s/registry", g_state_dir);
    FILE *f = fopen(path, "r");
    if (!f) return;
    char name[32];
    unsigned mark;
    int table;
    while (g_oldreg_n < MAX_OUTPUTS &&
           fscanf(f, "%31s %x %d\n", name, &mark, &table) == 3) {
        /* Чужой диапазон — чужие правила и чужая таблица (см. registry_assign): снимать их
         * по такой записи значило бы опустошить таблицу другого экземпляра движка. */
        if (!mark || (mark & ~STEER_MARK_MASK)) continue;
        g_oldreg[g_oldreg_n].mark = mark;
        g_oldreg[g_oldreg_n].table = table;
        g_oldreg_n++;
    }
    fclose(f);
}

static void cleanup_stale_routing(void) {
    for (size_t i = 0; i < g_oldreg_n; i++) {
        int live = 0;
        for (size_t k = 0; k < g_out_n; k++)
            if (g_out[k].kind != OUT_DIRECT && g_out[k].mark == g_oldreg[i].mark) {
                live = 1;
                break;
            }
        if (live) continue;
        char table[16];
        snprintf(table, sizeof(table), "%d", g_oldreg[i].table);
        rule_drop(g_oldreg[i].mark, g_oldreg[i].table);
        const char *flush[] = { "ip", "route", "flush", "table", table, NULL };
        run(flush);
    }
}

/* ---- down: снять всё, что поставил движок ------------------------------------
 *
 * То же, что stop_service в files/etc/init.d/steer, но командой движка. На роутере снятие —
 * это десяток строк shell; у init Android shell нет (сервис — один исполняемый файл), а
 * выдать домену steerd /system/bin/sh значило бы разрешить ему любую команду. Командой
 * движка оно и точнее: маска метки здесь STEER_MARK_MASK той сборки, что правила ставила
 * (под STEER_ANDROID она другая, 0x0fc00000), а в shell её пришлось бы повторять литералом.
 *
 * Зачем снимать при выключении, если перезапуск нарочно правил не трогает. Перезапуск — это
 * мгновение, после которого демоны встают снова, и открыть трафик на это мгновение хуже, чем
 * подержать правила. Выключение — другое: резолвер погашен навсегда, а правило заворота DNS
 * на его порт осталось бы в ядре, и у всех, чей DNS заворачивался, имена перестали бы
 * разрешаться вовсе. То же с on_fail=drop: blackhole в таблице выхода пережил бы выключение
 * и держал трафик закрытым без всякой видимой причины.
 *
 * Все таблицы — в каждой раскладке: inet (обычное ядро), ip/ip6 (nat старого ядра, см.
 * nft_compat) и steer_obfs (правила обфускаторов). Какой таблицы нет — отказ nft молча
 * значит «нечего снимать». Спека не читается: снимать надо и то, что поставила прежняя
 * спека, а реестр в состоянии — это и есть список того, что стоит в ядре. */
int cmd_down(void) {
    static const char *const tabs[][2] = {
        { "inet", NULL }, { "ip", NULL }, { "ip6", NULL }, { "inet", "steer_obfs" },
    };
    for (size_t i = 0; i < sizeof tabs / sizeof tabs[0]; i++) {
        const char *del[] = { "nft", "delete", "table", tabs[i][0],
                              tabs[i][1] ? tabs[i][1] : nft_table(), NULL };
        run(del);
    }
    registry_snapshot();
    for (size_t i = 0; i < g_oldreg_n; i++) {
        char table[16];
        snprintf(table, sizeof(table), "%d", g_oldreg[i].table);
        rule_drop(g_oldreg[i].mark, g_oldreg[i].table);
        const char *flush[] = { "ip", "route", "flush", "table", table, NULL };
        run(flush);
    }
    /* Правило и таблица пробы сторожа. Сторож снимает их сам при выходе, но init Android гасит
     * сервис SIGKILL (без gentle_kill — сразу, с ним — через 200 мс), и уборка при выходе может
     * не успеть. */
    probe_rule_cleanup();
#ifdef STEER_ANDROID
    android_masq_drop_all();
#endif
    /* Туннели kind=awg заводил движок — ему их и снимать; без этого интерфейс с ключами пира
     * пережил бы выключение и продолжал бы отвечать на рукопожатия. */
    awg_down_all();
    return 0;
}

/* Policy routing for interface outputs. Дубликаты правил не копятся: rule_ensure считает копии
 * в ядре и лишние снимает — но только ПОСЛЕ того, как верная стоит, а не «снять всё и
 * поставить заново» (см. table_bind в failover.c: в том промежутке трафик уходил напрямую). */
#ifdef STEER_ANDROID
/* ---- masquerade у выходов-интерфейсов: правилом iptables, а не nft ----------------------
 *
 * ЗАЧЕМ. На роутере адрес источника у пакетов в туннель подменяет firewall (зона выхода с
 * masq). На телефоне такого firewall нет: netd делает NAT только для раздачи на её восходящий
 * интерфейс. Пакет раздачи или приложения, уведённый меткой в туннель, уходил бы с адресом
 * Wi-Fi или сотовой сети — сервер туннеля такой пакет не примет.
 *
 * ПОЧЕМУ iptables. На ядре 4.9 каждая регистрация nat (цепочка nat nft, таблица nat iptables)
 * решает судьбу нового соединения сама: первая сработавшая, не найдя правила, ставит «пустую»
 * привязку, и следующие для этого соединения уже не вычисляются (nf_nat_ipv4_fn в
 * nf_nat_l3proto_ipv4.c). netd держит nat в iptables на srcnat (100). Цепочка nft после неё
 * не срабатывает никогда, а до неё — отнимает у netd раздачу целиком. Правило в той же таблице
 * nat iptables, первым в POSTROUTING, живёт с правилами netd в одном проходе.
 *
 * Только наш помеченный трафик и только на устройствах выхода. Правила узнаются по маске
 * поля метки в тексте `iptables -S` — чужих с нашей маской не бывает. Выходы vless и xsteer
 * здесь не нужны: их устройство обслуживает наш процесс, адреса он переводит сам. Выход
 * kind=awg — нужен, как interface: туннель в ядре несёт пакет с тем адресом источника, что
 * был, а сервер WireGuard примет только адрес из своих AllowedIPs, то есть адрес туннеля. */
static void android_masq_drop_all(void) {
    char mask[24];
    snprintf(mask, sizeof(mask), "/0x%x ", STEER_MARK_MASK);
    FILE *p = popen("iptables -w -t nat -S POSTROUTING 2>/dev/null", "r");
    if (!p) return;
    char line[512], lines[64][512];
    int n = 0;
    while (n < 64 && fgets(line, sizeof(line), p)) {
        if (strncmp(line, "-A POSTROUTING ", 15) || !strstr(line, mask) ||
            !strstr(line, "-j MASQUERADE")) continue;
        snprintf(lines[n++], sizeof(lines[0]), "%s", line + 15);
    }
    pclose(p);
    for (int i = 0; i < n; i++) {
        const char *argv[32] = { "iptables", "-w", "-t", "nat", "-D", "POSTROUTING" };
        int k = 6;
        for (char *t = strtok(lines[i], " \n"); t && k < 31; t = strtok(NULL, " \n"))
            argv[k++] = t;
        argv[k] = NULL;
        run(argv);
    }
}

/* Вернуть недостающие правила masquerade, не трогая стоящие. Зовёт сторож после каждого
 * прохода: netd при (пере)запуске перестраивает iptables и наши правила пропадают, а apply
 * после этого случится, только если его позовёт init (см. steerd.rc). */
void android_masq_ensure(void) {
    for (size_t i = 0; i < g_out_n; i++) {
        const struct output *o = &g_out[i];
        if (o->kind != OUT_INTERFACE && o->kind != OUT_AWG) continue;
        char mk[32];
        snprintf(mk, sizeof(mk), "0x%x/0x%x", o->mark, STEER_MARK_MASK);
        for (size_t k = 0; k < o->devices_n; k++) {
            const char *chk[] = { "iptables", "-w", "-t", "nat", "-C", "POSTROUTING",
                                  "-o", o->devices[k], "-m", "mark", "--mark", mk,
                                  "-j", "MASQUERADE", NULL };
            if (run(chk) == 0) continue;
            const char *add[] = { "iptables", "-w", "-t", "nat", "-I", "POSTROUTING", "1",
                                  "-o", o->devices[k], "-m", "mark", "--mark", mk,
                                  "-j", "MASQUERADE", NULL };
            if (run(add) == 0)
                fprintf(stderr, "steer[info] failover: masquerade на %s возвращён\n",
                        o->devices[k]);
        }
    }
}

static void android_masq_sync(void) {
    android_masq_drop_all();
    for (size_t i = 0; i < g_out_n; i++) {
        const struct output *o = &g_out[i];
        if (o->kind != OUT_INTERFACE && o->kind != OUT_AWG) continue;
        char mk[32];
        snprintf(mk, sizeof(mk), "0x%x/0x%x", o->mark, STEER_MARK_MASK);
        for (size_t k = 0; k < o->devices_n; k++) {
            const char *add[] = { "iptables", "-w", "-t", "nat", "-I", "POSTROUTING", "1",
                                  "-o", o->devices[k], "-m", "mark", "--mark", mk,
                                  "-j", "MASQUERADE", NULL };
            if (run(add) != 0)
                fprintf(stderr, LOG_W "output %s: masquerade на %s не встал (iptables)\n",
                        o->name, o->devices[k]);
        }
    }
}
#endif

static void apply_routing(void) {
    for (size_t i = 0; i < g_out_n; i++) {
        if (!out_has_device(&g_out[i])) continue;
        char table[16];
        snprintf(table, sizeof(table), "%d", g_out[i].table);
        /* Маршрут — заменой, правило — не снимая стоящего (table_bind и rule_ensure в
         * failover.c). Прежде здесь были `rule_drop` + `rule_add` и `flush` + `add`, и на
         * каждом apply помеченный трафик выхода на миг оставался без правила и без маршрута,
         * то есть уходил напрямую, мимо туннеля, — подробно у table_bind. Маршрут первым: если
         * правила не было, появившееся должно найти в таблице устройство, а не пустоту. */
        int rc = table_bind(&g_out[i], g_out[i].device);
        rule_ensure(g_out[i].mark, g_out[i].table);
        if (rc != 0) {
            fprintf(stderr, LOG_W "output %s: cannot route via %s — is the device up?\n",
                    g_out[i].name, g_out[i].device);
            /* Пустая таблица — это не «нет маршрута», а «ищи дальше»: помеченный
             * пакет провалится в следующую таблицу и уйдёт напрямую, то есть ровно
             * туда, куда его не пускали. При on_fail=drop окно между apply и первым
             * тиком failover обязано быть закрыто, иначе защита работает не всегда,
             * а это хуже, чем не работает вовсе. */
            if (g_out[i].on_fail == FAIL_DROP) {
                table_bind(&g_out[i], NULL);
                fprintf(stderr, LOG_W "output %s: трафик остановлен до появления "
                                "рабочего устройства (on_fail=drop)\n", g_out[i].name);
            } else {
                /* direct/zapret: таблица пуста, пакет уйдёт напрямую — значит и через общий
                 * обход, как обычный (см. out_failopen_capable в spec.h). Таблица правил к
                 * этому мгновению уже загружена, набор в ней есть. Сброс — потому что замена не
                 * прошла и в таблице могло остаться прежнее устройство. */
                const char *flush[] = { "ip", "route", "flush", "table", table, NULL };
                run(flush);
                failopen_mark(&g_out[i], 1);
            }
        }
    }
}

/* Стоит ли в ядре таблица «<семейство> <наша таблица>». Один `nft list tables` на процесс:
 * спрашивают о двух семействах подряд, а перечень таблиц за это время не меняется. Не смогли
 * спросить — «нет»: лишний `delete` отверг бы весь набор правил, а пропущенный оставляет
 * только чужую теперь таблицу, о которой скажет diag. */
static int nft_table_exists(const char *fam) {
    static char list[4096];
    static int loaded;
    if (!loaded) {
        loaded = 1;
        FILE *p = popen("nft list tables 2>/dev/null", "r");
        if (p) {
            size_t n = fread(list, 1, sizeof(list) - 1, p);
            list[n] = '\0';
            pclose(p);
        }
    }
    char want[96];
    snprintf(want, sizeof(want), "table %s %s", fam, nft_table());
    size_t wn = strlen(want);
    for (const char *q = list; (q = strstr(q, want)) != NULL; q += wn)
        if ((q == list || q[-1] == '\n') && (q[wn] == '\n' || q[wn] == '\0')) return 1;
    return 0;
}

/* ЧЕГО НЕ БУДЕТ НА СТАРОМ ЯДРЕ — вслух, при каждом apply в старой раскладке.
 *
 * Раскладка для 4.9 собирает всё, что ядро умеет, а без чего-то приходится обходиться. Молча
 * выбросить правило значило бы, что человек узнает о нём по симптому, — поэтому каждое
 * выброшенное называется здесь вместе с последствием. Строки идут в stderr и в журнал, как
 * остальные предупреждения apply. */
static void report_legacy_gaps(void) {
    if (!NFT_LEGACY) return;
    fprintf(stderr, "steer[info] apply: ядро без nat в семействе inet — правила собраны для "
                    "nftables старого ядра: таблицы inet и ip%s\n",
            legacy_has_ip6() ? " и ip6" : "");
    if (has_zapret() && !(g_nftc & NFTC_NOTRACK))
        fprintf(stderr, LOG_W "ядро не знает notrack: порождённые обработчиком zapret пакеты "
                        "(подделки, куски разрезанного) остаются на учёте conntrack. Где "
                        "firewall отбрасывает ct state invalid, обход выходов kind=zapret "
                        "может не срабатывать\n");
    if (g_traceroute_hops && has_domains() && !(g_nftc & NFTC_NOTRACK))
        fprintf(stderr, LOG_W "ядро не знает notrack: traceroute_hops на нём не действует, "
                        "промежуточные узлы будут видны как прежде\n");
#ifndef STEER_TGWS
    if (!(g_nftc & NFTC_IP6NAT))
        fprintf(stderr, LOG_W "ядро не умеет nat для IPv6: запросы DNS клиентов по IPv6 идут "
                        "мимо резолвера движка, и доменные каналы видят только тех, кто "
                        "спрашивает по IPv4\n");
#endif
#ifdef STEER_ANDROID
    if (!(g_nftc & NFTC_IP6NAT) && has_local_domains())
        fprintf(stderr, LOG_W "ядро не умеет nat для IPv6: запросы DNS приложений телефона по "
                        "IPv6 идут мимо резолвера движка, и доменные каналы телефона их не "
                        "видят\n");
#endif
#ifndef STEER_ANDROID
    /* На Android таблица nat iptables есть всегда, но PREROUTING в ней у netd — пустая
     * oem_nat_pre, и предупреждать там не о чем. Почему это вообще важно — у
     * generate_legacy_tail. */
    FILE *t = fopen("/proc/net/ip_tables_names", "r");
    if (t) {
        char line[64];
        int nat = 0;
        while (fgets(line, sizeof(line), t)) if (!strncmp(line, "nat", 3)) nat = 1;
        fclose(t);
        if (nat)
            fprintf(stderr, LOG_W "на этом ядре работает и nat iptables: для соединений, "
                            "которые не забрал движок, его правила PREROUTING (пробросы "
                            "портов) не сработают — старое ядро не даёт двум таблицам nat "
                            "поделить один хук\n");
    }
#endif
}

/* Умеет ли ЯДРО отдавать пакеты в очередь nfqueue.
 *
 * ЗАЧЕМ ОТДЕЛЬНАЯ ПРОВЕРКА. Без модуля nft_queue правило `queue num N` не отвергается
 * разбором — оно отвергается ядром, и nft говорит об этом так: «Could not process rule: No
 * such file or directory» с указателем на слово queue. Дословно проверено на роутере
 * (OpenWrt 25.12, nftables 1.1.6, kmod-nft-queue не установлен). Прочитать в этом «нет
 * пакета kmod-nft-queue» невозможно, а последствие — отказ ВСЕЙ транзакции: `nft -f`
 * атомарен, поэтому вместе с очередью не встают ни наборы, ни метки, ни перенаправление
 * DNS. То есть один незнакомый роутеру вид выхода снимает маршрутизацию целиком.
 *
 * Зависимость пакета этого не закрывает, и это главный довод. Движок ставят файлом из
 * GitHub Releases (install.sh), а файл зависимостей не разрешает — их проверяет только
 * менеджер пакетов. Объявить kmod-nft-queue в .apk нужно (и объявлено), но полагаться на
 * это как на единственную защиту значит защитить не тот путь установки.
 *
 * ПРОБА, А НЕ ПОИСК МОДУЛЯ. Спросить у ядра «есть ли nft_queue» нечем: /proc/modules врёт о
 * встроенном в ядро (=y вместо =m), а перечня поддерживаемых выражений nftables не отдаёт.
 * Поэтому спрашивается ровно то, что нам нужно: примет ли ядро правило с queue. Стоит это
 * одного запуска nft и только когда в спеке есть выход kind=zapret. */
static int nfqueue_supported(void) {
    char tmp[256];
    steer_tmp_template(tmp, sizeof(tmp), "steer-qprobe");
    int fd = mkstemp(tmp);
    if (fd < 0) return 1;   /* не смогли проверить — не мешаем: решать будет сам nft */
    FILE *f = fdopen(fd, "w");
    if (!f) { close(fd); unlink(tmp); return 1; }
    /* Своё имя таблицы: `nft -c` ничего не создаёт, но столкнуться именем с чужой живой
     * таблицей всё равно нельзя — проверка тогда проверяла бы её содержимое. */
    fprintf(f, "table inet %s_qprobe {\n"
               "    chain c {\n"
               "        type filter hook output priority mangle + 10; policy accept;\n"
               "        meta mark and 0x%08x == 0x%08x queue num %d bypass\n"
               "    }\n}\n", nft_table(), STEER_MARK_MASK, STEER_MARK_BASE, ZAPRET_QUEUE_BASE);
    fclose(f);
    const char *check[] = { "nft", "-c", "-f", tmp, NULL };
    int rc = run_quiet(check);
    unlink(tmp);
    return rc == 0;
}

int cmd_apply(const char *spec, int dry) {
    load_spec(spec);
    /* Снимок реестра — строго до registry_assign: тот перезапишет файл текущими
     * выходами, и метки удалённых/переименованных будут потеряны вместе с
     * единственным способом снять их правила из ядра. */
    registry_snapshot();
    registry_assign();
    build_groups();
    /* ДОМЕННЫЙ КАНАЛ В МИНИ-СБОРКЕ — ОТКАЗ, А НЕ ПРЕДУПРЕЖДЕНИЕ.
     *
     * Домены маршрутизируются через резолвер движка, а мини-сборка его не поднимает и
     * перенаправления DNS не ставит (см. генератор правил). Такая спека применилась бы и
     * не работала: имена не разрешаются нами, fake-адрес не появляется, канал стоит
     * пустым. Молчаливое применение здесь хуже отказа — искать причину пришлось бы на
     * роутере. */
#ifdef STEER_TGWS
    for (size_t i = 0; i < g_grp_n; i++)
        if (g_grp[i].domains)
            die("канал «%s» доменный, а эта сборка резолвера не поднимает: разрешать имена "
                "ей нечем. Переведите канал на адресный список или поставьте полный движок",
                g_grp[i].name);
#endif
    /* Устройство выхода — то, что несёт трафик сейчас, а не первое в списке кандидатов.
     * Иначе применение настройки уводило бы таблицу с работающего запасного устройства на
     * неработающее основное, а при on_fail=drop ещё и ставило запрет — то есть каждое
     * сохранение в интерфейсе роняло бы пул до следующего прохода сторожа (до минуты). */
    outputs_adopt_active();
    /* Проверка списков — ДО генерации и до dry-run.
     *
     * До dry-run намеренно: интерфейс проверяет спеку именно им, перед записью на диск.
     * Значит человек узнает про не тот список сразу при сохранении, а не потом, когда
     * apply молча не подействует. */
    check_address_lists();
    /* Раскладка набора правил — до генерации и до dry-run: интерфейс проверяет спеку именно
     * dry-run'ом, и печатать ему надо то, что реально встанет на этом ядре. */
    g_nftc = nft_compat();
    report_legacy_gaps();
    /* Снять накопленное ДО генерации: она вписывает эти значения в новые правила, иначе
     * каждый apply обнулял бы объёмы. Читаем и при --dry-run — так печатаемый текст остаётся
     * тем, что реально применится, а на машине без таблицы вывод не меняется вовсе. */
    counters_load();
    /* Ни одной группы — таблица всё равно ставится, с пустой цепочкой: так status
     * продолжает отвечать, а следующий apply не зависит от того, была ли таблица
     * раньше. */
    /* Файлы выходов kind=awg — проверяются и при --dry-run: им интерфейс проверяет спеку
     * перед записью, и ошибка в файле туннеля должна быть видна тогда же, а не после
     * применения. Предупреждением в stderr: набор правил от файла туннеля не зависит. */
    if (dry) { awg_check_all(); generate(stdout); return 0; }

    /* Отказываем ДО транзакции и НАЗЫВАЕМ причину: иначе человек получит отказ всей
     * маршрутизации с сообщением про несуществующий файл. Пакет назван прямо — его же
     * тянет за собой zapret, поэтому у тех, кто обходом уже пользуется, он стоит. */
    if (has_zapret() && !nfqueue_supported())
        die("в спеке есть выход kind=zapret, а ядро не принимает правило queue — "
            "нужен пакет kmod-nft-queue (его ставит и сам zapret). Правила НЕ применены: "
            "nft грузит набор целиком, и отказ на очереди снял бы заодно наборы, метки и "
            "перенаправление DNS", NULL);

    char tmp[256];
    steer_tmp_template(tmp, sizeof(tmp), "steer-ruleset");
    int fd = mkstemp(tmp);
    if (fd < 0) die("cannot create a temporary ruleset", NULL);
    FILE *f = fdopen(fd, "w");
    /* Крупный буфер на чисто дозаписывающий поток: musl по умолчанию даёт
     * BUFSIZ в 1 КБ, и набор на сотни тысяч элементов дробился на тысячи
     * мелких write. Статический — чтобы не зависеть от кучи в момент,
     * когда рядом nft уже строит своё дерево разбора. */
    static char genbuf[65536];
    setvbuf(f, genbuf, _IOFBF, sizeof(genbuf));
    /* ЗАМЕНА ТАБЛИЦЫ — ОДНОЙ ТРАНЗАКЦИЕЙ, и все три строки для этого нужны.
     *
     * Раньше здесь было два запуска nft: `nft delete table`, затем `nft -f` с новой таблицей,
     * хотя комментарий уже тогда обещал одну транзакцию. Между ними таблицы не было вовсе, а
     * на наборе в сотни тысяч элементов второй запуск на слабом роутере идёт секунды. Всё это
     * время DNS клиентов, который перенаправляет наша таблица, уходил в dnsmasq мимо
     * резолвера (имена доменных каналов разрешались настоящими адресами и шли напрямую), метки
     * не ставились, а запрет on_fail=drop держался только на маршрутной таблице. И если новый
     * набор nft отвергал, прежнего уже не было: один неудачный apply снимал маршрутизацию
     * целиком до следующего удачного.
     *
     * Теперь всё — в ОДНОМ файле, а `nft -f` применяет файл целиком или не применяет ничего:
     *   `table inet X`         — добавить таблицу, если её нет (без тела это «add», и на
     *                            существующей таблице он ничего не делает). Без этой строки
     *                            `delete` на самом первом apply отказал бы, а с ним — и
     *                            весь файл;
     *   `delete table inet X`  — снять прежнюю вместе с наборами и цепочками;
     *   `table inet X { … }`   — новая, из generate().
     * Снаружи видно либо прежнюю таблицу, либо новую, промежутка нет. Отказ nft оставляет
     * ПРЕЖНЮЮ таблицу стоять — то есть неудачный apply больше ничего не ломает.
     *
     * Цена одна, и её стоит знать: пока транзакция не закрыта, ядро держит и старые, и новые
     * наборы, то есть на время загрузки памяти под них нужно вдвое больше. Раньше старые
     * освобождались до загрузки новых. Проверено в `unshare -n` на nftables 1.0.9: файл такого
     * вида проходит и когда таблица есть, и когда её нет.
     *
     * В --dry-run эти две строки не печатаются: там выводится сам набор правил (его сверяют
     * стенды и интерфейс), а замена — дело применения. */
    fprintf(f, "table inet %s\ndelete table inet %s\n", nft_table(), nft_table());
    /* Таблицы ip и ip6 — тем же приёмом и в той же транзакции. Их создаёт только старая
     * раскладка (generate_legacy_tail), но УДАЛЯТЬ их обязана любая: ядро телефона обновится
     * до нового (Android 17 — ядра новее 5.2), apply выберет современную раскладку, и
     * оставшаяся от старой цепочка nat заворачивала бы DNS второй раз, а карта fakeip в ней
     * отставала бы от резолвера. И наоборот, выход раскладки из ip6 (ядро перестало
     * принимать nat в ip6) не должен оставлять прежнюю таблицу. Отсутствующую таблицу
     * удалять нельзя — `delete` отверг бы весь файл, — поэтому для таблицы вне раскладки
     * спрашиваем ядро, есть ли она (один `nft list tables` на apply). На роутере, где старой
     * раскладки не было никогда, файл остаётся прежним, байт в байт. */
    {
        static const char *const fams[2] = { "ip", "ip6" };
        int want[2] = { legacy_has_ip(), legacy_has_ip6() };
        for (int k = 0; k < 2; k++) {
            if (want[k])
                fprintf(f, "table %s %s\ndelete table %s %s\n",
                        fams[k], nft_table(), fams[k], nft_table());
            else if (nft_table_exists(fams[k]))
                fprintf(f, "delete table %s %s\n", fams[k], nft_table());
        }
    }
    generate(f);
    fclose(f);

    const char *load[] = { "nft", "-f", tmp, NULL };
    int rc = run(load);
    if (rc != 0) {
        fprintf(stderr, LOG_W "nft refused the ruleset, the previous one stays (kept: %s)\n",
                tmp);
        const char *check[] = { "nft", "-c", "-f", tmp, NULL };
        run(check);
        return 1;
    }
    unlink(tmp);
    /* Устройства выходов kind=awg — до привязки таблиц: apply_routing ставит маршрут в
     * устройство, и устройства к этому мгновению обязаны быть (см. src/kinds/awg.c). Отказ одного
     * туннеля не отменяет применённых правил: его таблица получит то же, что у любого выхода
     * без устройства (blackhole при on_fail=drop), а причина уже названа в журнале. */
    awg_apply_all();
    apply_routing();
#ifdef STEER_ANDROID
    android_masq_sync();
#endif
    cleanup_stale_routing();
    /* Снимок состояния СНИМАЕТСЯ: он описывает то, что было применено до этой транзакции, и
     * `status --fast` отдавал бы его как нынешнее — то есть прежние выходы и прежние каналы
     * ровно в тот момент, когда человек нажал «Применить» и смотрит, подействовало ли.
     * Пересобрать его здесь нельзя честно: правила уже стоят, а вот таблицы маршрутизации
     * привязывают к своим устройствам сами процессы выходов, и снимок, снятый сейчас, врал
     * бы в другую сторону. Пустое место `--fast` переживает — он тогда считает всё сам. */
    char snap[256];
    status_snap_path(snap, sizeof snap);
    unlink(snap);
    /* Проверки чужого firewall — про fw4: зона выхода и masquerade в его наборе правил. На
     * телефоне fw4 нет, трафик раздачи транслирует netd через iptables, и по дампу nftables
     * эти проверки говорили бы «устройство не упомянуто в firewall» и «нет masquerade» на
     * каждом apply — ложные тревоги, после которых настоящим перестают верить. */
#ifndef STEER_ANDROID
    report_output_deps();
    report_traceroute_dep();
#endif
    report_mark_overlap();
    printf("steer: applied %zu channel(s), %zu output(s)\n", g_ch_n, g_out_n);
    return 0;
}
