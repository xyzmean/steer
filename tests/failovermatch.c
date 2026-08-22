/* Стенд сторожа туннелей: уборка правила пробы и — главное — СВЕРКА фактической
 * маршрутизации выхода.
 *
 * Зачем сверка закрыта стендом. На живом роутере наблюдалось: выход kind=vless
 * поднимается, пинг через устройство идёт, splify2 показывает выход живым, а все каналы
 * через него молчат до перезапуска движка. Причина — состояние маршрутизации правилось
 * только по событию «сменилось устройство»: пока имя устройства то же, никто не смотрел,
 * что в таблице лежит на самом деле, и оставленный кем-то blackhole (или снесённое
 * правило fwmark) жил вечно. Регресс этой правки НЕ ВИДЕН ни в одной другой проверке:
 * движок работает, устройство отвечает, ошибок нет — просто трафик каналов мёртв. Поэтому
 * здесь она и стоит.
 *
 * Как это проверяется без роутера. run_quiet подменён и записывает команды вместо их
 * запуска, а `ip rule show` и `ip route show table N` читаются через popen — он подменён
 * на чтение из памяти (тот же приём, что в tests/fwmatch.c). Выход берётся kind=xsteer:
 * его проба здоровья — наличие устройства (см. device_healthy_for), поэтому стенду не
 * нужны ни сеть, ни root, а устройством служит lo. */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>
#include <sys/stat.h>

int rule_added = 0;
int rule_deleted = 0;

/* Записанные команды: одной строкой, чтобы искать подстрокой. */
static char g_cmd[64][256];
static int g_cmd_n;

/* Заставить `ip route add default dev ...` отказать: устройство исчезло между
 * проверкой и привязкой, таблица занята, нет прав. Подделать это можно только здесь —
 * настоящего ядра у стенда нет. */
int g_route_add_fails = 0;

int run_quiet(const char *const argv[]) {
    if (!argv || !argv[0]) return -1;
    /* Ядро изображается ровно в одном: `ip rule del` удаляет ПО ОДНОМУ правилу и в
     * какой-то момент обязан отказать. Привязка сливает дубликаты циклом
     * `while (run_quiet(del) == 0)`, поэтому мок, который всегда отвечает «удалил»,
     * подвесил бы стенд навсегда — а не поймал бы ошибку. Считаем, что правило было
     * одно: повторный тот же del отвечает отказом. */
    char joined[256];
    size_t jn = 0;
    for (int i = 0; argv[i] && jn < sizeof(joined) - 2; i++)
        jn += (size_t)snprintf(joined + jn, sizeof(joined) - jn, i ? " %s" : "%s", argv[i]);
    if (strstr(joined, " rule del") && g_cmd_n > 0 && !strcmp(g_cmd[g_cmd_n - 1], joined))
        return 1;
    if (g_cmd_n < (int)(sizeof(g_cmd) / sizeof(*g_cmd))) {
        snprintf(g_cmd[g_cmd_n], sizeof(g_cmd[0]), "%s", joined);
        g_cmd_n++;
    }
    /* Счётчики правил считают ОБЕ формы вызова: уборка пробы зовёт `ip -4 rule ...`,
     * а привязка выхода — `ip rule ...`. Раньше счёт шёл по argv[2] и видел только
     * первую, из-за чего добавление правила выхода стенду было невидимо. */
    if (!strcmp(argv[0], "ip")) {
        int i = 1;
        if (argv[i] && !strcmp(argv[i], "-4")) i++;
        if (argv[i] && !strcmp(argv[i], "rule") && argv[i + 1]) {
            if (!strcmp(argv[i + 1], "add")) rule_added++;
            if (!strcmp(argv[i + 1], "del")) rule_deleted++;
        }
    }
    /* Отказывает только привязка к устройству: blackhole в ту же таблицу обязан
     * пройти, иначе стенд проверял бы не то. */
    if (g_route_add_fails && strstr(joined, "route add default dev")) return 2;
    return 0;
}

static int cmd_seen(const char *needle) {
    for (int i = 0; i < g_cmd_n; i++)
        if (strstr(g_cmd[i], needle)) return 1;
    return 0;
}

/* Что «ответит» ядро на запросы состояния. */
static const char *g_rules = "";
static const char *g_routes = "";

static FILE *test_popen(const char *cmd, const char *mode) {
    (void)mode;
    const char *text = strstr(cmd, "rule") ? g_rules : g_routes;
    return fmemopen((void *)text, strlen(text), "r");
}

#define popen(cmd, mode) test_popen(cmd, mode)
#define pclose(f) fclose(f)

#include "../src/spec.h"

/* Mock globals */
size_t g_out_n = 0;
struct output g_out[MAX_OUTPUTS];
const char *g_state_dir = "/tmp";
void load_spec(const char *path) { (void)path; }
void registry_assign(void) {}

#include "../src/failover.c"

#undef popen
#undef pclose

static int g_fail;

static void check(const char *what, int got, int want) {
    if (got == want) return;
    fprintf(stderr, "failovermatch: %s: получено %d, ожидалось %d\n", what, got, want);
    g_fail++;
}

/* Дословный вывод `ip rule show` с живого роутера: правило выхода стоит между local и
 * main, метка печатается БЕЗ ведущих нулей (мы задаём её как 0x00100000). */
#define RULES_WITH \
    "0:\tfrom all lookup local\n" \
    "32764:\tfrom all fwmark 0x100000 lookup 300\n" \
    "32766:\tfrom all lookup main\n" \
    "32767:\tfrom all lookup default\n"
#define RULES_WITHOUT \
    "0:\tfrom all lookup local\n" \
    "32766:\tfrom all lookup main\n" \
    "32767:\tfrom all lookup default\n"

/* ---- разбор состояния (чистая функция) ------------------------------------- */
static void facts_cases(void) {
    struct route_facts f;

    f = route_facts_of(RULES_WITH, "default dev vl scope link \n", 0x100000, 300);
    check("живое состояние — правило", f.rule, 1);
    check("живое состояние — таблица", f.table == TBL_DEV, 1);
    check("живое состояние — устройство", strcmp(f.dev, "vl") == 0, 1);
    check("живое состояние годится", routing_live_ok(&f, "vl"), 1);
    check("живое состояние не годится для отказа", routing_failed_ok(&f, FAIL_DROP), 0);

    /* Ровно то, что оставляет apply_failed при on_fail=drop. Устройство при этом живое —
     * значит для живого выхода состояние НЕ годится и обязано быть исправлено. */
    f = route_facts_of(RULES_WITH, "blackhole default \n", 0x100000, 300);
    check("blackhole — таблица", f.table == TBL_BLACKHOLE, 1);
    check("blackhole не годится живому выходу", routing_live_ok(&f, "vl"), 0);
    check("blackhole годится отказу drop", routing_failed_ok(&f, FAIL_DROP), 1);
    check("blackhole не годится отказу direct", routing_failed_ok(&f, FAIL_DIRECT), 0);

    /* Ядро вычистило маршрут вместе с исчезнувшим TUN: таблица пуста, а это не «нет
     * пути», а «ищи дальше» — помеченный трафик утекает напрямую. */
    f = route_facts_of(RULES_WITH, "", 0x100000, 300);
    check("пустая таблица", f.table == TBL_EMPTY, 1);
    check("пустая таблица не годится живому выходу", routing_live_ok(&f, "vl"), 0);
    check("пустая таблица не годится отказу drop", routing_failed_ok(&f, FAIL_DROP), 0);

    f = route_facts_of(RULES_WITHOUT, "default dev vl scope link\n", 0x100000, 300);
    check("правила нет", f.rule, 0);
    check("без правила живому выходу не годится", routing_live_ok(&f, "vl"), 0);
    check("без правила отказ direct годится", routing_failed_ok(&f, FAIL_DIRECT), 1);

    /* default остался на прежнем устройстве после переключения. */
    f = route_facts_of(RULES_WITH, "default dev wg0 scope link\n", 0x100000, 300);
    check("чужое устройство в таблице", routing_live_ok(&f, "vl"), 0);

    /* Метка чужого выхода не должна считаться своей по совпадению префикса:
     * 0x1000000 начинается теми же цифрами, что 0x100000. */
    f = route_facts_of("32764:\tfrom all fwmark 0x1000000 lookup 301\n",
                       "default dev vl\n", 0x100000, 300);
    check("метка по префиксу не своя", f.rule, 0);

    /* Правило с маской ставит кто-то другой: наше без маски. */
    f = route_facts_of("32764:\tfrom all fwmark 0x100000/0xff lookup 300\n",
                       "default dev vl\n", 0x100000, 300);
    check("метка с маской не своя", f.rule, 0);

    /* Своя метка, но правило смотрит в другую таблицу — правило пересоздать. */
    f = route_facts_of("32764:\tfrom all fwmark 0x100000 lookup 305\n",
                       "default dev vl\n", 0x100000, 300);
    check("правило смотрит не в свою таблицу", f.rule, 0);
}

/* ---- поведение прохода ------------------------------------------------------ */
static char g_dir[64];

static void state_write(const char *name, const char *text) {
    char path[128];
    snprintf(path, sizeof(path), "%s/%s", g_dir, name);
    FILE *f = fopen(path, "w");
    if (!f) { perror("state_write"); exit(1); }
    fputs(text, f);
    fclose(f);
}

/* Выход kind=xsteer с одним устройством: здоровье такого выхода — наличие устройства,
 * поэтому ни сети, ни root стенду не нужно. */
static void out_set(const char *dev, enum on_fail of) {
    memset(g_out, 0, sizeof(g_out));
    g_out_n = 1;
    snprintf(g_out[0].name, sizeof(g_out[0].name), "%s", "vl");
    g_out[0].kind = OUT_XSTEER;
    g_out[0].on_fail = of;
    snprintf(g_out[0].devices[0], sizeof(g_out[0].devices[0]), "%s", dev);
    g_out[0].devices_n = 1;
    g_out[0].mark = 0x100000;
    g_out[0].table = 300;
}

static void tick(const char *rules, const char *routes) {
    g_cmd_n = 0;
    rule_added = rule_deleted = 0;
    g_rules = rules;
    g_routes = routes;
    cmd_failover("/dev/null", 0);
}

int main(void) {
    /* Своя папка состояния, и ДО первого прохода: проход пишет active и метки
     * перезапусков, а делать это в общем /tmp значило бы и зависеть от того, что там
     * оставил кто-то другой, и оставлять следы самому. */
    snprintf(g_dir, sizeof(g_dir), "/tmp/failovermatch-XXXXXX");
    if (!mkdtemp(g_dir)) { perror("mkdtemp"); return 1; }
    g_state_dir = g_dir;

    /* Test sig_cleanup/cleanup_probe_rule indirectly by checking rule_deleted */
    cleanup_probe_rule();
    if (rule_deleted != 1) {
        fprintf(stderr, "FAIL: cleanup_probe_rule did not run ip rule del\n");
        return 1;
    }

    /* I-022: probe-rule снимается В НАЧАЛЕ прохода, а не только при завершении.
     * atexit/SIGTERM не покрывают SIGKILL и OOM-killer, поэтому проход обязан
     * прибрать за предыдущим процессом до того, как поставит своё правило.
     * Выходов нет — значит единственный `ip rule del` может прийти только из
     * уборки в начале, и его отсутствие означает регресс ровно этой строки. */
    rule_deleted = 0;
    /* Журнал команд сбрасывается: мок отвечает «нечего удалять» на ПОВТОРНЫЙ тот же
     * `rule del`, а уборка выше уже сделала точно такой же вызов. */
    g_cmd_n = 0;
    cmd_failover("/dev/null", 0);
    if (rule_deleted < 1) {
        fprintf(stderr, "FAIL: cmd_failover does not clean the stale probe rule up front\n");
        return 1;
    }

    facts_cases();

    /* 1. Устройство живое, имя не менялось, а в таблице blackhole (его оставил прошлый
     *    отказ или apply, не нашедший устройства). Сторож ОБЯЗАН вернуть маршрут: иначе
     *    ровно та неполадка с роутера — пинг идёт, каналы мертвы до перезапуска движка. */
    out_set("lo", FAIL_DROP);
    state_write("active", "vl lo\n");
    tick(RULES_WITH, "blackhole default \n");
    check("blackhole при живом устройстве — маршрут возвращён",
          cmd_seen("ip route add default dev lo table 300"), 1);

    /* 2. Правило fwmark снято (так поступает apply_failed при on_fail=direct/zapret, и
     *    вернуть его было некому). Устройство живое, имя не менялось. */
    out_set("lo", FAIL_DROP);
    state_write("active", "vl lo\n");
    tick(RULES_WITHOUT, "default dev lo scope link\n");
    check("снятое правило fwmark — возвращено",
          cmd_seen("ip rule add fwmark 0x00100000 table 300"), 1);

    /* 3. Таблица пуста: ядро вычистило маршрут вместе с TUN умершего процесса. */
    out_set("lo", FAIL_DROP);
    state_write("active", "vl lo\n");
    tick(RULES_WITH, "");
    check("пустая таблица — маршрут возвращён",
          cmd_seen("ip route add default dev lo table 300"), 1);

    /* 4. Состояние в порядке — сторож не трогает НИЧЕГО. Иначе каждая минута означала бы
     *    flush таблицы живого выхода (то есть провал помеченного трафика на время
     *    перезаписи) и строку в журнале без новостей. */
    out_set("lo", FAIL_DROP);
    state_write("active", "vl lo\n");
    tick(RULES_WITH, "default dev lo scope link \n");
    check("целое состояние — маршрут не переписывается",
          cmd_seen("ip route add default dev lo table 300"), 0);
    check("целое состояние — правило не переписывается", rule_added, 0);
    check("целое состояние — таблица не сбрасывается",
          cmd_seen("ip route flush table 300"), 0);

    /* 5. Живых устройств нет (устройства с таким именем не существует), об отказе уже
     *    сообщали (active хранит «-»), но в таблице кто-то оставил маршрут на мёртвое
     *    устройство — например, клиент туннеля поднялся и привязал таблицу к себе, а
     *    сам туннель не отвечает. При on_fail=drop запрет обязан вернуться.
     *
     *    Метка перезапуска пишется заранее: без неё revive ждёт устройство десять
     *    секунд, и стенд стоял бы это время впустую — проверяется здесь не ожидание. */
    out_set("nodev0", FAIL_DROP);
    state_write("active", "vl -\n");
    {
        char stamp[32];
        snprintf(stamp, sizeof(stamp), "%ld\n", (long)time(NULL));
        state_write("restart-nodev0", stamp);
    }
    tick(RULES_WITH, "default dev nodev0 scope link\n");
    check("мёртвый выход с маршрутом — запрет возвращён",
          cmd_seen("ip route add blackhole default table 300"), 1);

    /* 6. То же, но состояние уже соответствует on_fail=drop: ни команд, ни строк. */
    out_set("nodev0", FAIL_DROP);
    state_write("active", "vl -\n");
    {
        char stamp[32];
        snprintf(stamp, sizeof(stamp), "%ld\n", (long)time(NULL));
        state_write("restart-nodev0", stamp);
    }
    tick(RULES_WITH, "blackhole default\n");
    check("мёртвый выход с запретом — ничего не делается",
          cmd_seen("ip route add blackhole default table 300"), 0);
    check("мёртвый выход с запретом — таблица не сбрасывается",
          cmd_seen("ip route flush table 300"), 0);

    /* 7. Привязка отказала (I-110). Устройство отвечает, имя сменилось — сторож зовёт
     *    bind_device, тот делает `ip route flush table 300` и следом `ip route add default
     *    dev lo table 300`, а он не проходит: устройство исчезло между проверкой и
     *    привязкой, таблица занята, нет прав. Таблица остаётся ПУСТОЙ, а пустая таблица —
     *    это не «нет пути», а «ищи дальше»: помеченный пакет проваливается в следующую
     *    таблицу и уходит НАПРЯМУЮ, то есть ровно туда, куда его не пускали. Хуже того,
     *    flush снял blackhole, который до этого поставил apply при on_fail=drop.
     *    Ровно это решение уже принято в apply_routing (steer.c) — здесь оно обязано
     *    совпадать. */
    out_set("lo", FAIL_DROP);
    state_write("active", "vl -\n");
    g_route_add_fails = 1;
    tick(RULES_WITH, "");
    g_route_add_fails = 0;
    check("отказ привязки при on_fail=drop — таблица не остаётся пустой",
          cmd_seen("ip route add blackhole default table 300"), 1);

    /* 8. Тот же отказ при on_fail=direct: запрет ставить НЕЛЬЗЯ — выход и объявлял, что
     *    при неудаче трафик идёт напрямую. Проверяется, что правка не подменила
     *    заявленный режим отказа заодно. */
    out_set("lo", FAIL_DIRECT);
    state_write("active", "vl -\n");
    g_route_add_fails = 1;
    tick(RULES_WITH, "");
    g_route_add_fails = 0;
    check("отказ привязки при on_fail=direct — запрет не ставится",
          cmd_seen("ip route add blackhole default table 300"), 0);

    /* 9. Привязка прошла — запрета быть не должно ни при каком on_fail. */
    out_set("lo", FAIL_DROP);
    state_write("active", "vl -\n");
    tick(RULES_WITH, "");
    check("успешная привязка — запрет не ставится",
          cmd_seen("ip route add blackhole default table 300"), 0);
    check("успешная привязка — маршрут поставлен",
          cmd_seen("ip route add default dev lo table 300"), 1);

    /* Уборка: файлы состояния и папка. */
    {
        char path[160];
        const char *names[] = { "active", "restart-nodev0", "restart-lo", NULL };
        for (int i = 0; names[i]; i++) {
            snprintf(path, sizeof(path), "%s/%s", g_dir, names[i]);
            unlink(path);
        }
        rmdir(g_dir);
    }

    /* ---- состояние прочитать не удалось --------------------------------------
     *
     * Самый дорогой промах сверки: если дамп правил пуст (нет `ip`, busybox не понял ключ,
     * отказал popen), то «разъехалось» будет ВСЕГДА — и сторож каждую минуту сносил бы
     * привязку живого выхода и поднимал заново, то есть сам устраивал бы провал трафика раз
     * в минуту. Пустой вывод `ip rule show` на живой коробке невозможен: там всегда лежат
     * три правила ядра. Поэтому пустота означает «спросить не получилось», и трогать ничего
     * нельзя. */
    {
        struct route_facts f = route_facts_of("", "", 0x1000000, 100);
        check("непрочитанное состояние: помечено как неизвестное", f.known, 0);
        struct route_facts g = route_facts_of("0:\tfrom all lookup local\n", "", 0x1000000, 100);
        check("пустая таблица при читаемых правилах: состояние известно", g.known, 1);
        check("пустая таблица при читаемых правилах: правила нашего нет", g.rule, 0);
        check("пустая таблица при читаемых правилах: таблица пуста", g.table, TBL_EMPTY);
    }

    if (g_fail) {
        fprintf(stderr, "failovermatch: провалено проверок: %d\n", g_fail);
        return 1;
    }

    printf("OK\n");
    return 0;
}
