/* steer — compile a channel spec into nftables rules and policy routing.
 *
 * Own table, not an fw4 include. Three reasons, all learned from splify:
 *   * an fw4 reload REPLACES table inet fw4, which drains every set living inside
 *     it — a separate `table inet steer` simply survives;
 *   * one `nft -f` is atomic: either the whole channel set applies or nothing does,
 *     with no window where a rule references a set that is not there yet;
 *   * uninstall is `nft delete table inet steer`, and nothing of ours can break
 *     someone else's firewall by being malformed.
 *
 * Precedence is expressed with `return` rather than a "mark is still zero" guard:
 * inside our own chain the first matching rule wins by construction, which is
 * exactly the ordered-channels semantics the spec promises.
 */
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

/* Уровень в журнале — см. одноимённые макросы в failover.c и obfs.c. Метка подсистемы
 * здесь «apply»: все строки ниже пишутся при компиляции и применении спеки. Отказы
 * вызывающему (die и разбор аргументов) уровня НЕ несут и несут «steer: » — это ответ
 * тому, кто позвал, а не запись в журнал; так и записано в контракте. */
int dnsd_main(int argc, char **argv);

/* Имя таблицы правил (nft_table) — в spec.h: его спрашивает и сторож, см. failopen_mark в
 * failover.c. */

int cmd_failover(const char *spec, int verbose);
void probe_rule_cleanup(void);   /* failover.c */
/* Свои флаги эти двое печатают сами — см. комментарии у объявлений. Справка по ним
 * склеивается из таблицы (что команда делает) и этих строк (чем ей управляют). */
void dnsd_usage_flags(FILE *out);
void aggregate_usage_flags(FILE *out);
/* Подпись таблицы доменных каналов: ею init-скрипт решает, хватит ли резолверу SIGHUP или
 * нужен перезапуск с пятисекундной паузой procd. Живёт в dnsd.c — там таблица. */
int dnsd_sig_print(const char *spec, FILE *out);
/* Соединения с меткой движка (дамп ctnetlink) — src/daemon/conns.c, тем же разговором с
 * ctnetlink, что у ctnl.c; журнал имён работающего резолвера отдаёт сам резолвер, dlog.c. */
int ctnl_conns_print(FILE *out);
int dlog_print(FILE *out);
/* Клиент VLESS есть только в расширенной сборке (steer-extended). В базовой команда
 * отвечает внятным отказом, а не отсутствует: «неизвестная команда» на steer vless
 * заставила бы искать опечатку вместо того, чтобы поставить нужный пакет. */
/* МИНИ-СБОРКА (STEER_TGWS) — это тот же движок без всего, кроме перехвата Telegram.
 *
 * Заводится она для отдельного микропакета tgws: там нужен ровно мост, спека с одним выходом
 * и правила к нему, а клиент VLESS, звезда xsteer и работа с подпиской не нужны вовсе. На
 * роутере с шестью с половиной мегабайтами overlay это не придирка: расширенная сборка весит
 * три четверти мегабайта, мини — вдвое меньше, и в пакет с бинарником внутри это заметно.
 *
 * Подкоманды, которых в мини-сборке нет, отвечают той же внятной заглушкой, что и в базовой:
 * «неизвестная команда» заставила бы искать опечатку вместо нужного пакета. */
#if defined(STEER_EXTENDED) || defined(STEER_TGWS)
/* Мост Telegram → веб-сокет; объяснение целиком — в src/proto/tgws/tgws.c. */
int cmd_tgws(const char *spec_path, const char *out_name);
int cmd_tgws_probe(int dc, int media, int direct, int timeout_s);
int cmd_tls_probe(const char *host, const char *addr, int port, int local_port, int quiet);
#endif
#ifdef STEER_EXTENDED
int cmd_vless(const char *spec_path, const char *out_name);
int cmd_vless_nodes(const char *spec_path, const char *out_name);
int cmd_vless_probe(const char *spec_path, const char *out_name, int node, int timeout_s);
/* Скачивание и обработка подписки. Реализация и рассказ, почему это работа движка, а не
 * управляющего слоя, — в src/proto/vless/subfetch.{c,h}. Объявлены здесь, как соседние
 * cmd_vless*, а не подключением subfetch.h: ядро не включает заголовков протоколов, иначе
 * его сборка без расширенной части (профили base, server, tgws) формально зависела бы от
 * subfetch.c — tests/buildmatch.sh сверяет это замыканием по #include. */
int cmd_sub_fetch(const char *url, const char *out_path, const char *info_path);
int cmd_sub_quota(const char *url, const char *info_path);
#else
/* ПОДСТРОКУ «steer-extended» ЗДЕСЬ ЧИТАЮТ СНАРУЖИ — это контракт, а не просто текст.
 * splify2 определяет вид установленного пакета так:
 *     out="$(steer vless '' 2>&1)"; case "$out" in *steer-extended*) vless=0 ;; esac
 * и по результату решает, показывать ли вкладку VLESS целиком. Переформулировать отказ
 * можно как угодно, но слово steer-extended обязано в нём остаться; закреплено стендом
 * tests/climatch.sh («vless '' называет пакет»). */
static int no_vless(void) {
    fprintf(stderr, "steer: клиент VLESS в этой сборке отсутствует — "
                    "нужен пакет steer-extended\n");
    return 2;
}
static int cmd_vless(const char *spec_path, const char *out_name) {
    (void)spec_path; (void)out_name;
    return no_vless();
}
static int cmd_vless_nodes(const char *spec_path, const char *out_name) {
    (void)spec_path; (void)out_name;
    return no_vless();
}
static int cmd_vless_probe(const char *spec_path, const char *out_name,
                           int node, int timeout_s) {
    (void)spec_path; (void)out_name; (void)node; (void)timeout_s;
    return no_vless();
}
static int cmd_sub_fetch(const char *url, const char *out_path, const char *info_path) {
    (void)url; (void)out_path; (void)info_path;
    return no_vless();
}
static int cmd_sub_quota(const char *url, const char *info_path) {
    (void)url; (void)info_path;
    return no_vless();
}
/* ЕДИНСТВЕННАЯ ПОДКОМАНДА «VLESS», КОТОРАЯ ОТВЕЧАЕТ И ЗДЕСЬ. Идентификатор роутера считает
 * src/tools/hwid.c, входящий в обе сборки: читателей у него стало двое, и второй (телеметрия
 * splify2) работает на роутере, где расширенной сборки нет. Заглушки поэтому нет — есть
 * настоящая функция, объявленная в hwid.h. */
#ifndef STEER_TGWS
static int cmd_tgws(const char *spec_path, const char *out_name) {
    (void)spec_path; (void)out_name;
    return no_vless();
}
static int cmd_tgws_probe(int dc, int media, int direct, int timeout_s) {
    (void)dc; (void)media; (void)direct; (void)timeout_s; return no_vless();
}
static int cmd_tls_probe(const char *host, const char *addr, int port, int local_port, int quiet) {
    (void)host; (void)addr; (void)port; (void)local_port; (void)quiet; return no_vless();
}
#endif
#endif

/* Клиент и хаб xsteer. Клиент — расширенная сборка, хаб — серверная: на роутере хабу делать
 * нечего, и подкоманды, поднимающей слушателя на публичном порту, там быть не должно. */
/* Клиент — только расширенная сборка. А вот проверка конфигурации и генерация ключей нужны и
 * серверной: без них оператор хаба не смог бы ни ключ сделать, ни файл проверить. */
#if defined(STEER_EXTENDED) || defined(STEER_SERVER)
int cmd_xsteer_key(void);
int cmd_xsteer_check(const char *conf);
int cmd_xsteer_link(const char *what, const char *name);
#else
static int no_xsteer_admin(void) {
    fprintf(stderr, "steer: служебные команды xsteer в этой сборке отсутствуют — "
                    "нужен пакет steer-extended\n");
    return 2;
}
static int cmd_xsteer_key(void) { return no_xsteer_admin(); }
static int cmd_xsteer_check(const char *conf) { (void)conf; return no_xsteer_admin(); }
static int cmd_xsteer_link(const char *what, const char *name) {
    (void)what; (void)name; return no_xsteer_admin();
}
#endif

#ifdef STEER_EXTENDED
int cmd_xsteer(const char *spec_path, const char *out_name, const char *conf,
               const char *device, int stream, int stream_port);
int cmd_xsteer_peers(const char *spec_path, const char *out_name, const char *conf);
#else
static int no_xsteer(void) {
    /* Та же контрактная подстрока «steer-extended», что у VLESS, и по той же причине:
     * splify2 определяет вид пакета пробой `steer xsteer ''`. */
    fprintf(stderr, "steer: клиент xsteer в этой сборке отсутствует — "
                    "нужен пакет steer-extended\n");
    return 2;
}
static int cmd_xsteer(const char *spec_path, const char *out_name, const char *conf,
                      const char *device, int stream, int stream_port) {
    (void)spec_path; (void)out_name; (void)conf; (void)device;
    (void)stream; (void)stream_port;
    return no_xsteer();
}
static int cmd_xsteer_peers(const char *spec_path, const char *out_name, const char *conf) {
    (void)spec_path; (void)out_name; (void)conf;
    return no_xsteer();
}
#endif

#ifdef STEER_SERVER
int cmd_xsteer_hub(const char *conf);
#else
static int cmd_xsteer_hub(const char *conf) {
    (void)conf;
    /* ВТОРАЯ контрактная подстрока — «steer-hub». Она отличает «нужен другой пакет для
     * роутера» от «нужен артефакт для сервера», и без этого различия человека посылали бы
     * ставить steer-extended туда, где хаба всё равно не будет. */
    fprintf(stderr, "steer: хаб xsteer в этой сборке отсутствует — "
                    "он ставится на VPS из архива steer-hub\n");
    return 2;
}
#endif

int aggregate_main(int argc, char **argv);



int main(int argc, char **argv) {
    if (argc < 2) {
        cli_usage_short(stderr);
        return 2;
    }
    const char *cmd = argv[1];

    /* Справка и версия — до поиска команды: это не команды движка, а вопросы к нему.
     * Обе формы, и слово, и флаг: `steer --help` человек набирает не задумываясь, а
     * раньше получал «unknown command: --help» с кодом 2. */
    if (!strcmp(cmd, "help") || !strcmp(cmd, "--help") || !strcmp(cmd, "-h")) {
        if (argc > 2) {
            const struct cli_cmd *c = cli_lookup(argv[2]);
            if (!c) cli_unknown(argv[2]);
            cli_help(stdout, c);
        } else {
            cli_help(stdout, NULL);
        }
        return 0;
    }
    if (!strcmp(cmd, "version") || !strcmp(cmd, "--version") || !strcmp(cmd, "-V")) {
        cli_version(stdout);
        return 0;
    }
    /* Флаг вместо команды. Отдельная строка, потому что «нет такой команды: --spec»
     * не объясняет, что именно не так с порядком слов. */
    if (cmd[0] == '-') {
        fprintf(stderr, "steer: флаги идут после команды, а не до неё: %s\n", cmd);
        fputs("       например: steer apply --spec " STEER_ETC_DIR "/spec.json\n"
              "       список команд: steer help\n", stderr);
        return 2;
    }

    const struct cli_cmd *c = cli_lookup(cmd);
    if (!c) cli_unknown(cmd);
    /* Просьба о справке перехватывается ДО разбора, одинаково для всех команд —
     * включая fit и dnsd, у которых свои парсеры аргументов. */
    if (cli_wants_help(argc - 2, argv + 2)) {
        cli_help(stdout, c);
        /* У команд со своим разбором список флагов знает только их парсер, поэтому
         * справка склеивается из двух половин. */
        if (c->passthru) {
            fputs("\nФлаги:\n", stdout);
            if (!strcmp(cmd, "fit")) aggregate_usage_flags(stdout);
            else if (!strcmp(cmd, "ctl-serve") || !strcmp(cmd, "ctl")) ctl_usage_flags(stdout);
            else dnsd_usage_flags(stdout);
        }
        return 0;
    }

    /* У fit и dnsd свои аргументы, и общий разбор молча съел бы, например, --budget.
     * Такие команды помечены в таблице как passthru и получают argv как есть. */
    if (c->passthru) {
        if (!strcmp(cmd, "fit")) return aggregate_main(argc - 1, argv + 1);
        if (!strcmp(cmd, "ctl-serve")) return ctl_serve_main(argc - 2, argv + 2);
        if (!strcmp(cmd, "ctl")) return ctl_client_main(argc - 2, argv + 2);
        return dnsd_main(argc - 2, argv + 2);
    }

    struct cli_args a;
    /* Разбор спеки и раздача меток реестра возвращают отказ, а не завершают процесс сами
     * (правило 5, docs/architecture.md, раздел 2) — здесь, в точке входа, err_die довершает
     * то же самое: код 2, тот же текст, что раньше печатал die() изнутри load_spec. */
    struct err e = {0};
    /* Спека — значение, а не глобалы (правило 6): один экземпляр на весь диспетчер команд,
     * static — держать struct spec на стеке нельзя, он большой. */
    static struct spec cfg;
    static struct groups gr;
    cli_parse(c, argc, argv, 2, &a);
    if (a.state_dir) g_state_dir = a.state_dir;
    const char *spec = a.spec, *arg = a.npos ? a.pos[0] : NULL;

    if (!strcmp(cmd, "apply")) return cmd_apply(spec, a.dry_run);
    if (!strcmp(cmd, "status")) return cmd_status(spec, a.fast);
    if (!strcmp(cmd, "diag")) return cmd_diag(spec);
    if (!strcmp(cmd, "down")) return cmd_down();
    if (!strcmp(cmd, "supervise")) return cmd_supervise(spec);
    if (!strcmp(cmd, "failover"))
        return a.loop ? failover_loop(spec, a.verbose, a.loop) : cmd_failover(spec, a.verbose);
    if (!strcmp(cmd, "explain")) {
        /* Адрес ИЛИ имя. Проверка формы обязательна для обоих: аргумент подставляется в
         * вызов nft, и именно здесь однажды была дыра — адрес уходил в system(). */
        if (!addr_ok(arg) && !looks_like_name(arg))
            die("это не адрес и не имя: %s", arg);
        return cmd_explain(spec, arg);
    }
    /* Перечислить выходы заданного вида. Init-скрипту нужно знать, для каких выходов
     * поднимать процесс, и спрашивать об этом движок — то же правило, что с needs-dnsd:
     * grep по ключу в JSON ломается при первом же переименовании поля, причём молча. */
    if (!strcmp(cmd, "outputs")) {
        /* Вид проверяется по списку, а не сравнивается как есть: `--kind vles` (опечатка)
         * давал пустой вывод и код 0, а по этому выводу init-скрипт решает, каким выходам
         * поднимать процессы. Тишина вместо отказа означала бы не поднятый туннель без
         * единой строки о причине. */
        if (a.kind && !out_kind_known(a.kind))
            die("--kind: нужен interface, vless, xsteer, zapret или direct, а не %s", a.kind);
        if (load_spec(spec, &cfg, &e) < 0) err_die(&e);
        for (size_t i = 0; i < cfg.out_n; i++) {
            const char *k = out_kind_name(cfg.out[i].kind);
            if (a.kind && strcmp(a.kind, k) != 0) continue;
            /* --obfs — отдельный признак, а не вид: обфускация есть свойство выхода,
             * и init-скрипту нужен именно список тех, кому поднимать процесс. */
            if (a.obfs && !cfg.out[i].obfs.on) continue;
            if (a.via) {
                if (cfg.out[i].via[0]) printf("%s\t%s\n", cfg.out[i].name, cfg.out[i].via);
                continue;
            }
            /* --devices печатает устройство, и выход без устройства (kind=direct) при этом
             * пропускается: пустая строка в списке для настройки фаервола хуже её отсутствия. */
            if (a.devices) {
                if (cfg.out[i].device[0]) printf("%s\n", cfg.out[i].device);
                continue;
            }
            printf("%s\n", cfg.out[i].name);
        }
        return 0;
    }
    /* Нужен ли этой спеке резолвер. Спрашивают у движка, а не угадывают по тексту
     * файла: init-скрипт когда-то искал в нём буквальное `"domains_file"`, спека
     * обзавелась множественным `domains_files`, и совпадение молча перестало
     * находиться — резолвер не поднимался, а apply при этом ставил перенаправление
     * DNS, и каждый запрос из LAN уходил в закрытый порт. Что будет сгенерировано,
     * знает только движок, поэтому отвечает он. */
    /* Что поднимать для выходов kind=zapret: по строке на выход, поля через табуляцию —
     * имя, номер очереди, файл ключей. Отдельной командой, а не полем `outputs`, потому
     * что читает её init-скрипт, а не человек, и читает построчно: разбирать в shell
     * ответ `status` (JSON, сотни байт на выход, jsonfilter на каждое поле) значило бы
     * платить за каждую перезагрузку сети разбором, который тут не нужен.
     *
     * Номер очереди печатает движок, а не считает init-скрипт. Вывод номера из метки —
     * наше внутреннее дело (out_zapret_queue), и второй, повторяющий его расчёт в shell
     * разошёлся бы при первой правке: процесс встал бы на очередь, в которую ядро ничего
     * не отдаёт, и выглядело бы это как «стратегия применилась и не действует».
     *
     * ВЫХОД БЕЗ ФАЙЛА СТРАТЕГИИ НЕ НАЗЫВАЕТСЯ ВОВСЕ, и это не экономия, а исправление
     * наблюдаемого отказа.
     *
     * Так выглядит только что заведённый выход: интерфейс создаёт его пустым, стратегию к
     * нему выбирают следующим действием. Пока файла нет, обёртка steer-nfqws выходит с
     * кодом 2 сразу, procd поднимает её снова через свои пять секунд — и так бесконечно.
     * Замерено на живом роутере (10.8.1.1, OpenWrt 25.12.5): три записи в daemon.err за
     * пятнадцать секунд, то есть примерно семнадцать тысяч строк в сутки на выход, который
     * человек просто не докрутил. Журнал после этого бесполезен для всего остального, а
     * вкладка «Логи» — главный способ, которым сообщество разбирается со своими роутерами.
     *
     * Служба, которая не может встать без действия человека, — это не служба в отказе, а
     * служба, которой ещё нет. Сказать об этом всё равно надо, поэтому причина печатается в
     * stderr: init-скрипт читает только stdout, а в журнале строка окажется ОДИН раз за
     * запуск, а не раз в пять секунд. Человеку то же самое говорят двое: apply («выбрана ли
     * стратегия во вкладке Zapret?») и diag («файла стратегии нет»).
     *
     * Обратная сторона названа честно: файл, удалённый у РАБОТАЮЩЕГО выхода, тоже уберёт
     * экземпляр при следующем `start`. Это верно — ключей для запуска всё равно больше нет.
     *
     * Код возврата — как у needs-dnsd: 0, если поднимать есть что. */
    if (!strcmp(cmd, "zapret-instances")) {
        if (load_spec(spec, &cfg, &e) < 0) err_die(&e);
        if (registry_assign(&cfg, &e) < 0) err_die(&e);
        int n = 0;
        for (size_t i = 0; i < cfg.out_n; i++) {
            if (cfg.out[i].kind != OUT_ZAPRET) continue;
            if (access(cfg.out[i].zp_opts, R_OK) != 0) {
                /* С УРОВНЕМ, а не голым «steer: ». Голый префикс в этом движке
                 * зарезервирован за отказами вызывающему (die и разбор аргументов), которые
                 * кончаются кодом 2 и до журнала не доходят; барьер в buildmatch.sh это и
                 * сторожит. Эта строка — сообщение, а не отказ: команда продолжает работу и
                 * называет остальные выходы. */
                fprintf(stderr, "steer[warn] zapret %s: файла стратегии %s нет — "
                                "поднимать нечем, выберите стратегию\n",
                        cfg.out[i].name, cfg.out[i].zp_opts);
                continue;
            }
            printf("%s\t%d\t%s\n", cfg.out[i].name, out_zapret_queue(&cfg.out[i]),
                   cfg.out[i].zp_opts);
            n++;
        }
        return n ? 0 : 1;
    }
    /* Что поднимать для выходов kind=tgws: имя и порт, по строке на выход. Тот же довод,
     * что у zapret-instances выше, включая главный: порт выводит движок (out_tgws_port), а
     * не считает init-скрипт — второй расчёт того же в shell разошёлся бы при первой
     * правке, и мост слушал бы порт, на который ядро ничего не заворачивает. */
    if (!strcmp(cmd, "tgws-instances")) {
        if (load_spec(spec, &cfg, &e) < 0) err_die(&e);
        if (registry_assign(&cfg, &e) < 0) err_die(&e);
        int n = 0;
        for (size_t i = 0; i < cfg.out_n; i++) {
            if (cfg.out[i].kind != OUT_TGWS) continue;
            printf("%s\t%d\n", cfg.out[i].name, out_tgws_port(&cfg.out[i]));
            n++;
        }
        return n ? 0 : 1;
    }
    /* ХВАТИТ ЛИ РЕЗОЛВЕРУ SIGHUP. Печатает подпись таблицы каналов по текущей спеке; сам
     * резолвер положил такую же в каталог состояния при запуске. Совпали — init-скрипт
     * посылает HUP, и локальная сеть не теряет разрешение имён ни на секунду; разошлись —
     * нужен перезапуск, потому что состав каналов HUP не пересобирает.
     *
     * Отдельной командой, а не полем status: её читает оболочка построчно и сравнивает
     * целиком, а не разбирает. Тот же довод, что у zapret-instances и needs-dnsd. */
    if (!strcmp(cmd, "dnsd-sig")) return dnsd_sig_print(spec, stdout);
    /* Спеку обе не читают: соединения сопоставляются с выходами по реестру меток (метки
     * ПРИМЕНЁННОЙ спеки — см. ctnl_conns_print), журнал отдаёт сам резолвер. --spec они
     * принимают ради управляющего сокета, который передаёт его каждой подкоманде. */
    if (!strcmp(cmd, "conns")) return ctnl_conns_print(stdout);
    if (!strcmp(cmd, "dns-log")) return dlog_print(stdout);
    if (!strcmp(cmd, "needs-dnsd")) {
        /* ВСЕГДА 0 — решение владельца, и оно про устройство, а не про экономию.
         *
         * Спека всё равно загружается: команда обязана отвечать отказом на спеке, которую
         * движок не понимает, иначе init-скрипт поднял бы резолвер под конфигурацию,
         * которую applyиный проход отверг бы. Ответ же не зависит от её содержимого:
         * перенаправление DNS теперь стоит всегда (см. генератор набора правил), и
         * резолвер, к которому оно ведёт, обязан существовать всегда вместе с ним.
         *
         * Чем это лучше прежнего `has_domains() ? 0 : 1`: доменность канала стала
         * зависеть от содержимого файлов списков (домен и подсеть лежат в одном), то есть
         * могла бы перевернуться ночным обновлением. Раньше этот код отвечал на вопрос
         * «нужен ли», теперь — «поднимаем», и переворачиваться нечему. */
        if (load_spec(spec, &cfg, &e) < 0) err_die(&e);
        if (registry_assign(&cfg, &e) < 0) err_die(&e);
        if (build_groups(&cfg, &gr, &e) < 0) err_die(&e);
        /* В мини-сборке — «поднимать нечего», и это тот же ответ, что даёт генератор
         * правил: он там перенаправления DNS не ставит. Два ответа обязаны совпадать,
         * иначе init-скрипт однажды поднимет резолвер без правила или, хуже, правило
         * останется без резолвера. */
#ifdef STEER_TGWS
        return 1;
#else
        return 0;
#endif
    }
    if (!strcmp(cmd, "tgws")) return cmd_tgws(spec, arg);
    if (!strcmp(cmd, "tls-probe")) {
        /* ХОСТ[:ПОРТ]; адрес назначения — флагом --out, исходящий порт — флагом --node.
         * Своих флагов не заводим: эти уже есть и значат ровно то, что нужно. */
        char hb[256];
        const char *h = arg ? arg : "";
        int pt = 443;
        snprintf(hb, sizeof(hb), "%s", h);
        char *c = strrchr(hb, ':');
        if (c) {
            *c = '\0';
            /* Порт — число 1..65535, иначе отказ: atoi на «host:abc» давал 0, и проба шла на
             * порт 0 с приговором «не отвечает» про узел, который никто не спрашивал. */
            char *pe = NULL;
            long v = strtol(c + 1, &pe, 10);
            if (pe == c + 1 || *pe || v < 1 || v > 65535) {
                fprintf(stderr, "неверный порт: %s\n", c + 1);
                return 2;
            }
            pt = (int)v;
        }
        if (!hb[0]) { fprintf(stderr, "нужно имя узла\n"); return 2; }
        return cmd_tls_probe(hb, a.out_file, pt, a.node > 0 ? a.node : 0, 0);
    }
    if (!strcmp(cmd, "tgws-probe")) {
        /* Позиционный — не имя, а переключатель, и понимается ровно одно слово. Прежде
         * всё, что не «media», молча значило обычную точку: «steer tgws-probe medai»
         * проверял другую точку и отвечал «ок» (I-316). */
        if (arg && strcmp(arg, "media") != 0) {
            fprintf(stderr, "steer: команда tgws-probe понимает аргументом только «media», "
                    "а получила «%s»\n", arg);
            return 2;
        }
        return cmd_tgws_probe(a.node > 0 ? a.node : 2, arg && !strcmp(arg, "media"),
                              a.direct, a.timeout);
    }
    if (!strcmp(cmd, "vless")) return cmd_vless(spec, arg);
    if (!strcmp(cmd, "vless-nodes")) return cmd_vless_nodes(spec, arg);
    if (!strcmp(cmd, "vless-probe")) return cmd_vless_probe(spec, arg, a.node, a.timeout);
    if (!strcmp(cmd, "sub-fetch")) return cmd_sub_fetch(arg, a.out_file, a.info_file);
    if (!strcmp(cmd, "sub-quota")) return cmd_sub_quota(arg, a.info_file);
    if (!strcmp(cmd, "sub-hwid")) return cmd_sub_hwid();
    if (!strcmp(cmd, "dev-id")) return cmd_dev_id();
    if (!strcmp(cmd, "srs-read")) return srs_dump(arg, a.out_file, a.prefixes_out, a.meta_out);
    if (!strcmp(cmd, "obfs")) {
        if (load_spec(spec, &cfg, &e) < 0) err_die(&e);
        struct output *o = out_by_name(&cfg, arg);
        if (!o) die("нет такого выхода: %s", arg);
        if (!o->obfs.on) die("у выхода %s не настроен obfs", arg);
        /* Метка сокета к серверу обфускации — out_underlay_mark (см. «вложенные выходы» в
         * spec.h). При via она — метка выхода-цели, а та появляется только в реестре: без
         * registry_assign функция вернула бы ноль, то есть «напрямую», молча. Без via реестр
         * не нужен и не трогается — у этого процесса его прежде не было. */
        if (o->via[0] && registry_assign(&cfg, &e) < 0) err_die(&e);
        obfs_set_sock_mark(out_underlay_mark(&cfg, o), o->via[0] != 0);
        return obfs_client(o->name, o->obfs.server, o->obfs.server_port,
                           o->obfs.listen, o->obfs.listen_port);
    }
    /* Серверная половина. Спека ей не нужна и не читается: сервер живёт на VPS, где
     * ни выходов, ни каналов нет — есть порт, который слушать, и локальный WireGuard,
     * которому пересылать. */
    if (!strcmp(cmd, "xsteer"))
        return cmd_xsteer(spec, arg, a.config, a.device, a.stream, a.stream_port);
    if (!strcmp(cmd, "xsteer-peers")) return cmd_xsteer_peers(spec, arg, a.config);
    if (!strcmp(cmd, "xsteer-key")) return cmd_xsteer_key();
    if (!strcmp(cmd, "xsteer-check")) return cmd_xsteer_check(a.config);
    /* Источник — позиционный аргумент, а если его нет, то --config: команда одинаково удобна и
     * в конвейере («steer xsteer-link -»), и там, где путь уже назван флагом, как у соседей. */
    if (!strcmp(cmd, "xsteer-link"))
        return cmd_xsteer_link(a.npos > 0 ? a.pos[0] : a.config, a.name);
    /* Хаб живёт на VPS: спека ему не нужна и не читается — там ни выходов, ни каналов, а
     * есть конфигурация звезды и порт. Прецедент тот же, что у obfs-server. */
    if (!strcmp(cmd, "xsteer-hub")) return cmd_xsteer_hub(a.config);
    if (!strcmp(cmd, "obfs-server")) {
        if (!a.listen) die("нужен --listen ПОРТ (порт поддельного TCP)", NULL);
        if (!a.forward) die("нужен --forward АДРЕС:ПОРТ (куда отдавать датаграммы)", NULL);
        char host[80];
        int fport = 0;
        if (obfs_split_hostport(a.forward, host, sizeof(host), &fport) != 0)
            die("--forward должен быть вида адрес:порт, а не %s", a.forward);
        return obfs_server(a.listen, host, fport);
    }
    /* Сюда попасть нельзя: имя нашлось в таблице, значит ветка для него есть. Если
     * всё-таки попали — в таблицу добавили команду и забыли про диспетчер. */
    die("команда %s объявлена, но не подключена — это ошибка в движке", cmd);
    return 2;
}

