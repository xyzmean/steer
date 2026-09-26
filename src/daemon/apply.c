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

static void iptables_masq_drop_all(void);   /* ниже, у apply_routing */
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
    snprintf(path, sizeof(path), "%s/registry", steer_state_dir());
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

static void cleanup_stale_routing(const struct spec *sp) {
    for (size_t i = 0; i < g_oldreg_n; i++) {
        int live = 0;
        for (size_t k = 0; k < sp->out_n; k++)
            if (out_needs_mark(&sp->out[k]) && sp->out[k].mark == g_oldreg[i].mark) {
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
 * движка оно и точнее: маска метки здесь STEER_MARK_MASK той платформы, что правила ставила
 * (у телефона она другая, 0x0fc00000), а в shell её пришлось бы повторять литералом.
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
    if (plat()->iptables_masq) iptables_masq_drop_all();
    /* Туннели kind=awg заводил движок — ему их и снимать; без этого интерфейс с ключами пира
     * пережил бы выключение и продолжал бы отвечать на рукопожатия. */
    awg_down_all();
    return 0;
}

/* Policy routing for interface outputs. Дубликаты правил не копятся: rule_ensure считает копии
 * в ядре и лишние снимает — но только ПОСЛЕ того, как верная стоит, а не «снять всё и
 * поставить заново» (см. table_bind в failover.c: в том промежутке трафик уходил напрямую). */
/* ---- masquerade у выходов-интерфейсов: правилом iptables, а не nft ----------------------
 *
 * Только на платформе с plat()->iptables_masq (телефон, src/platform/android.c).
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
static void iptables_masq_drop_all(void) {
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
void iptables_masq_ensure(const struct spec *sp) {
    for (size_t i = 0; i < sp->out_n; i++) {
        const struct output *o = &sp->out[i];
        /* masquerade — выходам с устройством, кроме тех, кто наружу ходит от своего имени
         * (out_self_natting): у interface и awg он нужен, у vless и xsteer — нет. */
        if (!out_has_device(o) || out_self_natting(o)) continue;
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

static void iptables_masq_sync(const struct spec *sp) {
    iptables_masq_drop_all();
    for (size_t i = 0; i < sp->out_n; i++) {
        const struct output *o = &sp->out[i];
        if (!out_has_device(o) || out_self_natting(o)) continue;
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

/* Привязка одного выхода — тело прежнего цикла apply_routing. Одна функция на два пути: apply
 * подкомандой проходит все выходы, apply-commit демона — только те, чья часть маршрутизации
 * изменилась (apply-сверка, src/daemon/recon.c). */
static void apply_routing_one(const struct output *o) {
    if (!out_has_device(o)) return;
    char table[16];
    snprintf(table, sizeof(table), "%d", o->table);
    /* Маршрут — заменой, правило — не снимая стоящего (table_bind и rule_ensure в
     * failover.c). Прежде здесь были `rule_drop` + `rule_add` и `flush` + `add`, и на
     * каждом apply помеченный трафик выхода на миг оставался без правила и без маршрута,
     * то есть уходил напрямую, мимо туннеля, — подробно у table_bind. Маршрут первым: если
     * правила не было, появившееся должно найти в таблице устройство, а не пустоту. */
    int rc = table_bind(o, o->device);
    rule_ensure(o->mark, o->table);
    if (rc != 0) {
        fprintf(stderr, LOG_W "output %s: cannot route via %s — is the device up?\n",
                o->name, o->device);
        /* Пустая таблица — это не «нет маршрута», а «ищи дальше»: помеченный
         * пакет провалится в следующую таблицу и уйдёт напрямую, то есть ровно
         * туда, куда его не пускали. При on_fail=drop окно между apply и первым
         * тиком failover обязано быть закрыто, иначе защита работает не всегда,
         * а это хуже, чем не работает вовсе. */
        if (o->on_fail == FAIL_DROP) {
            table_bind(o, NULL);
            fprintf(stderr, LOG_W "output %s: трафик остановлен до появления "
                            "рабочего устройства (on_fail=drop)\n", o->name);
        } else {
            /* direct/zapret: таблица пуста, пакет уйдёт напрямую — значит и через общий
             * обход, как обычный (см. out_failopen_capable в spec.h). Таблица правил к
             * этому мгновению уже загружена, набор в ней есть. Сброс — потому что замена не
             * прошла и в таблице могло остаться прежнее устройство. */
            const char *flush[] = { "ip", "route", "flush", "table", table, NULL };
            run(flush);
            failopen_mark(o, 1);
        }
    }
}

static void apply_routing(const struct spec *sp) {
    for (size_t i = 0; i < sp->out_n; i++) apply_routing_one(&sp->out[i]);
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
static void report_legacy_gaps(const struct spec *sp, const struct groups *gr) {
    if (!NFT_LEGACY) return;
    fprintf(stderr, "steer[info] apply: ядро без nat в семействе inet — правила собраны для "
                    "nftables старого ядра: таблицы inet и ip%s\n",
            legacy_has_ip6() ? " и ip6" : "");
    if (zapret_present(sp) && !(g_nftc & NFTC_NOTRACK))
        fprintf(stderr, LOG_W "ядро не знает notrack: порождённые обработчиком zapret пакеты "
                        "(подделки, куски разрезанного) остаются на учёте conntrack. Где "
                        "firewall отбрасывает ct state invalid, обход выходов kind=zapret "
                        "может не срабатывать\n");
    if (sp->traceroute_hops && has_domains(gr) && !(g_nftc & NFTC_NOTRACK))
        fprintf(stderr, LOG_W "ядро не знает notrack: traceroute_hops на нём не действует, "
                        "промежуточные узлы будут видны как прежде\n");
#ifndef STEER_TGWS
    if (!(g_nftc & NFTC_IP6NAT))
        fprintf(stderr, LOG_W "ядро не умеет nat для IPv6: запросы DNS клиентов по IPv6 идут "
                        "мимо резолвера движка, и доменные каналы видят только тех, кто "
                        "спрашивает по IPv4\n");
#endif
    if (plat()->local_channels && !(g_nftc & NFTC_IP6NAT) && has_local_domains(gr))
        fprintf(stderr, LOG_W "ядро не умеет nat для IPv6: запросы DNS приложений телефона по "
                        "IPv6 идут мимо резолвера движка, и доменные каналы телефона их не "
                        "видят\n");
    /* На Android таблица nat iptables есть всегда, но PREROUTING в ней у netd — пустая
     * oem_nat_pre, и предупреждать там не о чем (plat()->warn_iptables_nat). Почему это вообще
     * важно — у legacy.c (шаг 4, «почему dstnat - 1»). */
    FILE *t = plat()->warn_iptables_nat ? fopen("/proc/net/ip_tables_names", "r") : NULL;
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


/* ---- apply: общее начало, одна транзакция, конец ---------------------------------------
 *
 * cmd_apply (подкоманда `steer apply` — init.d, rpcd, init телефона) и служебные apply-plan и
 * apply-commit демона (apply-сверка, src/daemon/recon.c) — одни и те же шаги, нарезанные так,
 * чтобы демон мог сделать их по отдельности: план (разбор, проверки, компиляция в отпечаток) и
 * применение только изменившихся частей. Подкоманда проходит их все подряд, как раньше, байт в
 * байт тем же выводом. */

/* Общее начало: разбор, реестр, группы, проверки, раскладка. full=0 — только разбор, реестр и
 * выбор устройств (apply-commit без новых правил: ему нужны метки и таблицы выходов, а групп и
 * списков он не касается). nftc < 0 — раскладку спросить у ядра (nft_compat); иначе взять
 * готовую — её демон запомнил с первого плана и пробы ядра не повторяет. report — сказать о
 * том, чего не будет на старом ядре. */
static void apply_prepare(const char *spec, struct spec *cfg, struct groups *gr, int full,
                          int nftc, int report) {
    /* Разбор спеки и компиляция возвращают отказ, а не завершают процесс сами (правило 5,
     * docs/architecture.md, раздел 2) — err_die здесь, в точке входа, довершает то же самое:
     * код 2, тот же текст, что раньше печатал die() изнутри load_spec/build_groups/generate. */
    struct err e = {0};
    if (load_spec(spec, cfg, &e) < 0) err_die(&e);
    /* Снимок реестра — строго до registry_assign: тот перезапишет файл текущими
     * выходами, и метки удалённых/переименованных будут потеряны вместе с
     * единственным способом снять их правила из ядра. */
    registry_snapshot();
    if (registry_assign(cfg, &e) < 0) err_die(&e);
    if (!full) {
        outputs_adopt_active(cfg);
        return;
    }
    if (build_groups(cfg, gr, &e) < 0) err_die(&e);
    /* ДОМЕННЫЙ КАНАЛ В МИНИ-СБОРКЕ — ОТКАЗ, А НЕ ПРЕДУПРЕЖДЕНИЕ.
     *
     * Домены маршрутизируются через резолвер движка, а мини-сборка его не поднимает и
     * перенаправления DNS не ставит (см. генератор правил). Такая спека применилась бы и
     * не работала: имена не разрешаются нами, fake-адрес не появляется, канал стоит
     * пустым. Молчаливое применение здесь хуже отказа — искать причину пришлось бы на
     * роутере. */
#ifdef STEER_TGWS
    for (size_t i = 0; i < gr->n; i++)
        if (gr->g[i].domains)
            die("канал «%s» доменный, а эта сборка резолвера не поднимает: разрешать имена "
                "ей нечем. Переведите канал на адресный список или поставьте полный движок",
                gr->g[i].name);
#endif
    /* Устройство выхода — то, что несёт трафик сейчас, а не первое в списке кандидатов.
     * Иначе применение настройки уводило бы таблицу с работающего запасного устройства на
     * неработающее основное, а при on_fail=drop ещё и ставило запрет — то есть каждое
     * сохранение в интерфейсе роняло бы пул до следующего прохода сторожа (до минуты). */
    outputs_adopt_active(cfg);
    /* Проверка списков — ДО генерации и до dry-run.
     *
     * До dry-run намеренно: интерфейс проверяет спеку именно им, перед записью на диск.
     * Значит человек узнает про не тот список сразу при сохранении, а не потом, когда
     * apply молча не подействует. */
    if (check_address_lists(gr, &e) < 0) err_die(&e);
    /* Раскладка набора правил — до генерации и до dry-run: интерфейс проверяет спеку именно
     * dry-run'ом, и печатать ему надо то, что реально встанет на этом ядре. */
    g_nftc = nftc >= 0 ? nftc : nft_compat();
    if (report) report_legacy_gaps(cfg, gr);
}

/* Одна транзакция: проверка очереди zapret, файл «добавить — удалить — новая таблица», nft -f.
 * 0 — ядро приняло; 1 — отвергло (прежняя таблица стоит, причина в журнале). */
static int ruleset_load(const struct spec *cfg, const struct groups *gr) {
    struct err e = {0};
    /* Отказываем ДО транзакции и НАЗЫВАЕМ причину: иначе человек получит отказ всей
     * маршрутизации с сообщением про несуществующий файл. Пакет назван прямо — его же
     * тянет за собой zapret, поэтому у тех, кто обходом уже пользуется, он стоит. */
    if (zapret_present(cfg) && !nfqueue_supported())
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
     * раскладка (legacy.c), но УДАЛЯТЬ их обязана любая: ядро телефона обновится
     * до нового (Android 17 — ядра новее 5.2), apply выберет современную раскладку, и
     * оставшаяся от старой цепочка nat заворачивала бы DNS второй раз, а карта fakeip в ней
     * отставала бы от резолвера. И наоборот, выход раскладки из ip6 (ядро перестало
     * принимать nat в ip6) не должен оставлять прежнюю таблицу. Отсутствующую таблицу
     * удалять нельзя — `delete` отверг бы весь файл, — поэтому для таблицы вне раскладки
     * спрашиваем ядро, есть ли она (один `nft list tables` на apply). На роутере, где старой
     * раскладки не было никогда, файл остаётся прежним, байт в байт. */
    {
        static const char *const fams[2] = { "ip", "ip6" };
        int want[2] = { legacy_has_ip(cfg), legacy_has_ip6() };
        for (int k = 0; k < 2; k++) {
            if (want[k])
                fprintf(f, "table %s %s\ndelete table %s %s\n",
                        fams[k], nft_table(), fams[k], nft_table());
            else if (nft_table_exists(fams[k]))
                fprintf(f, "delete table %s %s\n", fams[k], nft_table());
        }
    }
    if (generate(cfg, gr, f, &e) < 0) err_die(&e);
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
    return 0;
}

/* Конец применения: снимок status, проверки чужого firewall, итоговая строка. */
static void apply_done_reports(const struct spec *cfg) {
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
    if (plat()->fw4) {
        report_output_deps(cfg);
        report_traceroute_dep(cfg);
    }
    report_mark_overlap();
    printf("steer: applied %zu channel(s), %zu output(s)\n", cfg->ch_n, cfg->out_n);
}

int cmd_apply(const char *spec, int dry) {
    /* Спека — значение, а не глобалы (правило 6): свой экземпляр у точки входа, static —
     * держать struct spec на стеке нельзя, он большой (g_ch один под 200 КБ). */
    static struct spec cfg;
    static struct groups gr;
    struct err e = {0};
    apply_prepare(spec, &cfg, &gr, 1, -1, 1);
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
    if (dry) {
        awg_check_all(&cfg);
        if (generate(&cfg, &gr, stdout, &e) < 0) err_die(&e);
        return 0;
    }

    if (ruleset_load(&cfg, &gr) != 0) return 1;
    /* Устройства выходов kind=awg — до привязки таблиц: apply_routing ставит маршрут в
     * устройство, и устройства к этому мгновению обязаны быть (см. src/kinds/awg.c). Отказ одного
     * туннеля не отменяет применённых правил: его таблица получит то же, что у любого выхода
     * без устройства (blackhole при on_fail=drop), а причина уже названа в журнале. */
    awg_apply_all(&cfg);
    apply_routing(&cfg);
    if (plat()->iptables_masq) iptables_masq_sync(&cfg);
    cleanup_stale_routing(&cfg);
    apply_done_reports(&cfg);
    return 0;
}

/* ---- служебные подкоманды демона: apply-plan и apply-commit ---------------------------------
 *
 * Apply-сверка (docs/architecture.md, «4а», шаг 5; устройство и доводы — в шапке
 * src/daemon/recon.c). Демон не компилирует спеку у себя в процессе: на больших списках это
 * секунды работы процессора и десятки мегабайт памяти, и цикл демона всё это время стоял бы, а
 * куча демона, который живёт месяцами, росла бы пиками. Поэтому план и применение — дети на
 * apply (процесс на команду, а не на проход), и обе половины — здесь, рядом с cmd_apply: те же
 * шаги тем же кодом, только нарезанные.
 *
 * В справке их нет: это не команды для человека, а договор демона с самим собой. Слова строки —
 * свои, короткий разбор ниже; неизвестное слово — отказ с кодом 2. */

struct recon_args {
    const char *spec, *state_dir;
    int nftc;                  /* -1 — спросить ядро */
    int ruleset, awg, masq, masq_ensure;
    const char *route, *drop;  /* через запятую; NULL — нет */
    const char *rule;          /* только правило выхода, таблицу не трогать (починка демона) */
};

static void recon_args_parse(int argc, char **argv, struct recon_args *a, const char *who) {
    memset(a, 0, sizeof(*a));
    a->nftc = -1;
    a->spec = plat()->spec_path;
    for (int i = 0; i < argc; i++) {
        const char *k = argv[i], *v = i + 1 < argc ? argv[i + 1] : NULL;
        int val = 1;
        if (!strcmp(k, "--spec") && v) a->spec = v;
        else if (!strcmp(k, "--state-dir") && v) a->state_dir = v;
        else if (!strcmp(k, "--nftc") && v) a->nftc = atoi(v);
        else if (!strcmp(k, "--route") && v) a->route = v;
        else if (!strcmp(k, "--drop") && v) a->drop = v;
        else if (!strcmp(k, "--rule") && v) a->rule = v;
        else {
            val = 0;
            if (!strcmp(k, "--ruleset")) a->ruleset = 1;
            else if (!strcmp(k, "--awg")) a->awg = 1;
            else if (!strcmp(k, "--masq")) a->masq = 1;
            else if (!strcmp(k, "--masq-ensure")) a->masq_ensure = 1;
            else {
                fprintf(stderr, "steer %s: непонятное слово %s\n", who, k);
                exit(2);
            }
        }
        i += val;
    }
    if (a->state_dir) steer_set_state_dir(a->state_dir);
}

/* Отпечаток набора правил без самого текста: generate пишет в поток, поток считает FNV-1a и
 * ничего не хранит. Текст бывает десятками мегабайт — держать его ради сравнения незачем ни в
 * плане, ни в демоне. */
static ssize_t fnv_write(void *c, const char *buf, size_t n) {
    unsigned long long *h = c;
    for (size_t i = 0; i < n; i++) { *h ^= (unsigned char)buf[i]; *h *= 1099511628211ULL; }
    return (ssize_t)n;
}
#ifdef __BIONIC__
/* Писатель для funopen (BSD): длина — int, а не size_t. */
static int fnv_write_bsd(void *c, const char *buf, int n) {
    return (int)fnv_write(c, buf, (size_t)n);
}
#endif

/* Подпись маршрутизации выхода — то, что apply ставит в ip rule и таблицу выхода и что
 * настраивает у выхода kind=awg: вид, метка, таблица, режим отказа, пул устройств (не выбранное
 * сторожем устройство: его смену сторож и так уже поставил в ядро), файл awg целиком. Изменилась
 * — выход привязывается заново; нет — его правило и таблица не трогаются. */
static unsigned long long out_route_sig(const struct output *o, int *awg) {
    unsigned long long h = KIND_SIG_INIT;
    const char *kn = kind_of(o)->name;
    kind_sig_mix(&h, kn, strlen(kn));
    kind_sig_mix(&h, &o->mark, sizeof(o->mark));
    kind_sig_mix(&h, &o->table, sizeof(o->table));
    int of = (int)o->on_fail;
    kind_sig_mix(&h, &of, sizeof(of));
    for (size_t k = 0; k < o->devices_n; k++)
        kind_sig_mix(&h, o->devices[k], strlen(o->devices[k]));
    if (!o->devices_n) kind_sig_mix(&h, o->device, strlen(o->device));
    *awg = !strcmp(kn, "awg");
    if (*awg) {
        /* Ключи и адреса — в файле, не в спеке: новый файл под тем же именем — тоже смена. */
        kind_sig_mix(&h, o->awg.conf, strlen(o->awg.conf));
        FILE *f = fopen(o->awg.conf, "r");
        if (f) {
            unsigned long long fh = KIND_SIG_INIT;
            char buf[4096];
            size_t m;
            while ((m = fread(buf, 1, sizeof(buf), f)) > 0) fnv_write(&fh, buf, m);
            fclose(f);
            kind_sig_mix(&h, &fh, sizeof(fh));
        }
    }
    return h;
}

/* Подпись того, что читает сторож (кроме помощника — его подпись сверяет супервизор): маршрут,
 * цель via, выбор по задержке. Изменилась — сторожу внеочередной проход. */
static unsigned long long out_watch_sig(const struct output *o, unsigned long long rsig) {
    unsigned long long h = rsig;
    kind_sig_mix(&h, o->via, strlen(o->via));
    int lat[3] = { o->prefer_latency, o->lat_tolerance_ms, o->lat_interval_s };
    kind_sig_mix(&h, lat, sizeof(lat));
    return h;
}

/* apply-plan --spec ПУТЬ [--state-dir …] [--nftc N]: всё, что делает `apply --dry-run` (те же
 * проверки, те же предупреждения в stderr, тот же код отказа), только набор правил не печатается,
 * а сворачивается в отпечаток. Счётчики из ядра не читаются нарочно: план не зовёт ни одного
 * процесса (раскладку демон передаёт готовой), а перенос счётчиков — дело apply-commit, который
 * пересобирает текст уже с ними. В stdout — план строками:
 *   nftc N                      раскладка набора правил (NFTC_*)
 *   ruleset ОТПЕЧАТОК           FNV-1a 64 текста набора правил без счётчиков
 *   counts КАНАЛОВ ВЫХОДОВ
 *   out ИМЯ МЕТКА ТАБЛИЦА С_УСТРОЙСТВОМ AWG ПОДПИСЬ_МАРШРУТА ПОДПИСЬ_СТОРОЖА
 *   stale МЕТКА ТАБЛИЦА         метка из прежнего реестра, которую не несёт ни один выход */
int cmd_apply_plan(int argc, char **argv) {
    struct recon_args a;
    recon_args_parse(argc, argv, &a, "apply-plan");
    static struct spec cfg;
    static struct groups gr;
    struct err e = {0};
    apply_prepare(a.spec, &cfg, &gr, 1, a.nftc, 1);
    awg_check_all(&cfg);
    unsigned long long h = 14695981039346656037ULL;
    /* Поток-отпечаток: fopencookie есть в glibc и musl, но в bionic его нет вовсе (даже с
     * _GNU_SOURCE) — там его BSD-двойник funopen с писателем на int. Текст набора правил не
     * собирается в буфер целиком нарочно: на больших списках это мегабайты. */
#ifdef __BIONIC__
    FILE *f = funopen(&h, NULL, fnv_write_bsd, NULL, NULL);
#else
    cookie_io_functions_t io = { .write = fnv_write };
    FILE *f = fopencookie(&h, "w", io);
#endif
    if (!f) die("cannot open a stream for the ruleset fingerprint", NULL);
    static char buf[65536];
    setvbuf(f, buf, _IOFBF, sizeof(buf));
    if (generate(&cfg, &gr, f, &e) < 0) err_die(&e);
    fclose(f);
    printf("nftc %d\nruleset %016llx\ncounts %zu %zu\n", g_nftc, h, cfg.ch_n, cfg.out_n);
    for (size_t i = 0; i < cfg.out_n; i++) {
        const struct output *o = &cfg.out[i];
        int awg = 0;
        unsigned long long rs = out_route_sig(o, &awg);
        printf("out %s %x %d %d %d %016llx %016llx\n", o->name, o->mark, o->table,
               out_has_device(o), awg, rs, out_watch_sig(o, rs));
    }
    for (size_t i = 0; i < g_oldreg_n; i++) {
        int live = 0;
        for (size_t k = 0; k < cfg.out_n; k++)
            if (out_needs_mark(&cfg.out[k]) && cfg.out[k].mark == g_oldreg[i].mark) live = 1;
        if (!live) printf("stale %x %d\n", g_oldreg[i].mark, g_oldreg[i].table);
    }
    return 0;
}

/* Есть ли в таблице выхода маршрут по умолчанию (устройство или запрет). Нет — выход пущен
 * напрямую (apply_failed в режиме direct/zapret или неудачная привязка выше). */
static int table_has_default(int table) {
    char cmd[64];
    snprintf(cmd, sizeof(cmd), "ip -4 route show table %d 2>/dev/null", table);
    FILE *p = popen(cmd, "r");
    if (!p) return 1;
    char line[512];
    int yes = 0;
    while (fgets(line, sizeof(line), p))
        if (!strncmp(line, "default", 7) || strstr(line, " default ")) yes = 1;
    pclose(p);
    return yes;
}

static int name_in_list(const char *list, const char *name) {
    if (!list) return 0;
    size_t n = strlen(name);
    for (const char *p = list; *p; ) {
        const char *e = strchr(p, ',');
        size_t l = e ? (size_t)(e - p) : strlen(p);
        if (l == n && !strncmp(p, name, n)) return 1;
        if (!e) break;
        p = e + 1;
    }
    return 0;
}

/* apply-commit --spec ПУТЬ [--ruleset] [--route А,Б] [--drop МЕТКА:ТАБЛИЦА,…] [--awg] [--masq]
 * [--nftc N] [--state-dir …]: применить ТОЛЬКО изменившиеся части — что именно, решил демон по
 * плану (recon.c).
 *   --ruleset  набор правил одной транзакцией, со счётчиками из ядра — тем же ruleset_load, что у
 *              подкоманды; отказ ядра — код 1, прежняя таблица стоит, остальное не трогается;
 *   --route    привязать таблицы и правила этих выходов (apply_routing_one);
 *   --drop     снять правило и таблицу меток, которых больше не несёт ни один выход (как
 *              cleanup_stale_routing);
 *   --awg      настроить устройства kind=awg (awg_apply_all — поверх, живые сессии не рвутся) и
 *              снять устройства убранных выходов;
 *   --masq     masquerade выходов на телефоне (iptables_masq_sync);
 *   --rule     вернуть только правило этих выходов (rule_ensure), таблицу не трогая, — починка
 *              демона после чужого удаления правил (src/daemon/rulewd.c): таблица выхода в этот
 *              момент цела, и в ней может стоять запрет сторожа (on_fail=drop), который
 *              перепривязка к устройству (--route) сняла бы до следующего прохода;
 *   --masq-ensure  вернуть недостающий masquerade, не снимая стоящего (iptables_masq_ensure):
 *              после перезапуска netd, а не после смены спеки.
 * Новый набор правил приходит с пустым набором «пущен напрямую», а выходы, которых --route не
 * касается, в него не попадут сами: их отметка возвращается здесь по таблице выхода. */
int cmd_apply_commit(int argc, char **argv) {
    struct recon_args a;
    recon_args_parse(argc, argv, &a, "apply-commit");
    static struct spec cfg;
    static struct groups gr;
    apply_prepare(a.spec, &cfg, &gr, a.ruleset, a.nftc, a.ruleset);
    if (a.ruleset) {
        counters_load();
        if (ruleset_load(&cfg, &gr) != 0) return 1;
    }
    /* Устройства kind=awg — до привязки таблиц, как у подкоманды. */
    if (a.awg) awg_apply_all(&cfg);
    for (size_t i = 0; i < cfg.out_n; i++)
        if (name_in_list(a.route, cfg.out[i].name)) apply_routing_one(&cfg.out[i]);
    if (a.ruleset)
        for (size_t i = 0; i < cfg.out_n; i++) {
            const struct output *o = &cfg.out[i];
            if (name_in_list(a.route, o->name) || !out_has_device(o) || !out_skips_zapret(o) ||
                !out_failopen_capable(o))
                continue;
            if (!table_has_default(o->table)) failopen_mark(o, 1);
        }
    for (const char *p = a.drop; p && *p; ) {
        unsigned mark = 0;
        int table = 0;
        if (sscanf(p, "%x:%d", &mark, &table) == 2 && mark && !(mark & ~STEER_MARK_MASK)) {
            int live = 0;
            for (size_t k = 0; k < cfg.out_n; k++)
                if (out_needs_mark(&cfg.out[k]) && cfg.out[k].mark == mark) live = 1;
            if (!live) {
                char t[16];
                snprintf(t, sizeof(t), "%d", table);
                rule_drop(mark, table);
                const char *flush[] = { "ip", "route", "flush", "table", t, NULL };
                run(flush);
            }
        }
        const char *e = strchr(p, ',');
        if (!e) break;
        p = e + 1;
    }
    for (size_t i = 0; i < cfg.out_n; i++) {
        const struct output *o = &cfg.out[i];
        if (name_in_list(a.rule, o->name) && out_has_device(o)) rule_ensure(o->mark, o->table);
    }
    if (a.masq && plat()->iptables_masq) iptables_masq_sync(&cfg);
    else if (a.masq_ensure && plat()->iptables_masq) iptables_masq_ensure(&cfg);
    /* Починка (только --rule и --masq-ensure) — не применение: снимок status описывает то же, что
     * и до неё, а отчёты apply о зависимостях и итоговая строка в журнале демона были бы
     * повтором последнего apply. */
    if (!a.ruleset && !a.route && !a.drop && !a.awg && !a.masq) return 0;
    apply_done_reports(&cfg);
    return 0;
}
