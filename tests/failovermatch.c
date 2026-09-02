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

/* Ожидание подъёма подменено пустышкой. revive ждёт десятью секундными шагами, и настоящий
 * sleep стоил бы десять секунд на каждую проверку этой ветки, не добавляя к ней ничего:
 * устройства в стенде по ходу прохода не появляются и не исчезают. */
static int g_slept;
static unsigned test_sleep(unsigned n) { (void)n; g_slept++; return 0; }
#define sleep(n) test_sleep(n)

#include "../src/spec.h"

/* Mock globals */
size_t g_out_n = 0;
struct output g_out[MAX_OUTPUTS];
const char *g_state_dir = "/tmp";
void load_spec(const char *path) { (void)path; }
void registry_assign(void) {}

/* Ход подъёма выхода читается из файла в state_dir (src/spec.c). Здесь он задаётся прямо:
 * стенду нужен не разбор файла — его проверяет specmatch, — а поведение сторожа при каждом
 * из состояний. Особенно при «номер узла вне подписки»: ждать там нечего, и сторож обязан
 * это знать, а не обещать подъём. */
struct probe_status g_probe_stub;
struct probe_status probe_read(const char *out_name) { (void)out_name; return g_probe_stub; }

#include "../src/failover.c"

#undef popen
#undef pclose
#undef sleep

static int g_fail;

/* Позвать revive и забрать то, что он сказал. Приговор здесь — половина поведения: сторож не
 * умеет ничего починить у выхода, которым владеет наш же процесс, и всё, что у него есть, —
 * это слова в журнале. Проверять их надо ровно так же, как код возврата. */
static int revive_with_stderr(const struct output *o, const char *dev, char *buf, size_t n) {
    buf[0] = '\0';
    char tmpl[] = "/tmp/failovermatch-err.XXXXXX";
    int fd = mkstemp(tmpl);
    if (fd < 0) return -1;
    fflush(stderr);
    int saved = dup(fileno(stderr));
    dup2(fd, fileno(stderr));
    int rc = revive(o, dev, 0);
    fflush(stderr);
    dup2(saved, fileno(stderr));
    close(saved);
    lseek(fd, 0, SEEK_SET);
    ssize_t got = read(fd, buf, n - 1);
    if (got > 0) buf[got] = '\0';
    close(fd);
    unlink(tmpl);
    return rc;
}

static void check(const char *what, int got, int want) {
    if (got == want) return;
    fprintf(stderr, "failovermatch: %s: получено %d, ожидалось %d\n", what, got, want);
    g_fail++;
}

/* Дословный вывод `ip rule show` с живого роутера (10.8.1.87, OpenWrt 25.12, ядро 6.12):
 * правило выхода стоит между local и main, а метка и маска печатаются БЕЗ ведущих нулей —
 * мы задаём их как 0x00100000/0x0ff00000, ядро отвечает 0x100000/0xff00000. Форма взята
 * опытом, а не придумана: от неё зависит разбор. */
#define RULES_WITH \
    "0:\tfrom all lookup local\n" \
    "32764:\tfrom all fwmark 0x100000/0xff00000 lookup 300\n" \
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

    /* Маска ЧУЖАЯ — правило не наше: `fwmark 0x100000/0xff` поймает не тот трафик, и
     * согласиться с ним значило бы не поставить своё. */
    f = route_facts_of("32764:\tfrom all fwmark 0x100000/0xff lookup 300\n",
                       "default dev vl\n", 0x100000, 300);
    check("метка с чужой маской не своя", f.rule, 0);

    /* Прежняя форма — БЕЗ маски — тоже не наша, и это не придирка, а способ обновления.
     * Правило без маски осталось в ядре от версии до R-094; считать его своим значило бы
     * оставить его там навсегда, потому что сторож не трогает то, что считает верным. Не
     * считая — он пересоздаёт привязку, а `rule_drop` снимает обе формы, и через минуту
     * после обновления в ядре остаётся только правило с маской. */
    f = route_facts_of("32764:\tfrom all fwmark 0x100000 lookup 300\n",
                       "default dev vl\n", 0x100000, 300);
    check("прежняя форма без маски не своя", f.rule, 0);

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

/* Пул разнородных выходов: устройство создаёт и обслуживает выход-владелец (здесь
 * kind=xsteer — его проба не требует ни сети, ни root), а НАЗЫВАЕТ его в своём `devices`
 * другой выход, kind=interface, собирающий локацию подписки, wireguard и хаб в один список
 * с порядком предпочтения. Так пул собирает интерфейс splify2, и так его пишут руками.
 *
 * Пул стоит ПЕРВЫМ намеренно: revive не чаще раза в RESTART_COOLDOWN на устройство, и если
 * бы владелец шёл первым, он забирал бы попытку себе — проверка ниже проходила бы, ничего
 * не проверяя. */
static void out_set_pool(const char *dev) {
    memset(g_out, 0, sizeof(g_out));
    g_out_n = 2;

    snprintf(g_out[0].name, sizeof(g_out[0].name), "%s", "pool");
    g_out[0].kind = OUT_INTERFACE;
    g_out[0].on_fail = FAIL_DROP;
    snprintf(g_out[0].devices[0], sizeof(g_out[0].devices[0]), "%s", dev);
    g_out[0].devices_n = 1;
    g_out[0].mark = 0x200000;
    g_out[0].table = 301;

    snprintf(g_out[1].name, sizeof(g_out[1].name), "%s", "hub");
    g_out[1].kind = OUT_XSTEER;
    g_out[1].on_fail = FAIL_DROP;
    snprintf(g_out[1].device, sizeof(g_out[1].device), "%s", dev);
    snprintf(g_out[1].devices[0], sizeof(g_out[1].devices[0]), "%s", dev);
    g_out[1].devices_n = 1;
    g_out[1].mark = 0x100000;
    g_out[1].table = 300;
}

/* Пул из ДВУХ устройств одного выхода: первое — предпочтение, второе — запас. Здоровье
 * каждого задаётся стендом по тику через шов g_health_probe, поэтому ни /sys, ни сокеты не
 * нужны. Это ровно форма, на которой мелькал живой роутер: узел-предпочтение подхватывался
 * пробой на тик и снова падал. */
static int g_h_first = 1, g_h_second = 1;
static int hyst_health(const struct output *o, const char *dev) {
    (void)o;
    if (!strcmp(dev, "vpref"))  return g_h_first;
    if (!strcmp(dev, "vspare")) return g_h_second;
    return 0;
}
static void out_set_two(void) {
    memset(g_out, 0, sizeof(g_out));
    g_out_n = 1;
    snprintf(g_out[0].name, sizeof(g_out[0].name), "%s", "vl");
    g_out[0].kind = OUT_INTERFACE;
    g_out[0].on_fail = FAIL_DROP;
    snprintf(g_out[0].devices[0], sizeof(g_out[0].devices[0]), "%s", "vpref");
    snprintf(g_out[0].devices[1], sizeof(g_out[0].devices[1]), "%s", "vspare");
    g_out[0].devices_n = 2;
    g_out[0].mark = 0x100000;
    g_out[0].table = 300;
}
/* Что записано активным устройством после прохода. */
static void active_dev(char *buf, size_t n) { active_get("vl", buf, n); }

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

    /* 1a. Смена маршрута обязана СНЯТЬ установленные соединения этого выхода.
     *
     * Замер на живом роутере (10.8.1.87, OpenWrt 25.12): при включённой выгрузке потоков
     * пакеты установленного соединения идут мимо нашей цепочки разметки — она видит 2-7
     * пакетов вместо одиннадцати тысяч, — и смена маршрута такому соединению безразлична:
     * в одном прогоне из трёх поток продолжал идти на 613-666 Мбит/с через таблицу, где уже
     * лежал запрет. То есть on_fail=drop для установленных соединений не гарантия.
     *
     * Лечится тем же приёмом, что у mwan3: записи conntrack с нашей меткой снимаются, и
     * следующий пакет соединения проходит обычным путём — то есть заново получает решение.
     * Возможно это стало только с `ct mark set mark` в правиле: до него запись conntrack про
     * выход не знала ничего (mark=0), и снять «соединения этого выхода» было нельзя. */
    check("смена маршрута снимает соединения выхода",
          cmd_seen("conntrack -D --mark 1048576/267386880"), 1);

    /* 2. Правило fwmark снято (так поступает apply_failed при on_fail=direct/zapret, и
     *    вернуть его было некому). Устройство живое, имя не менялось. */
    out_set("lo", FAIL_DROP);
    state_write("active", "vl lo\n");
    tick(RULES_WITHOUT, "default dev lo scope link\n");
    check("снятое правило fwmark — возвращено",
          cmd_seen("ip rule add fwmark 0x00100000/0x0ff00000 table 300"), 1);
    /* И снимается прежняя форма тоже: иначе после обновления в ядре лежали бы два правила
     * на одну метку, и порядок между ними определялся бы приоритетом, а не замыслом. */
    check("прежняя форма без маски снимается",
          cmd_seen("ip rule del fwmark 0x00100000 table 300"), 1);

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

    /* Контроль к проверке 1a: на тике, где состояние целое и менять нечего, соединения
     * трогать НЕЛЬЗЯ. Снятие записи установленного соединения — это разрыв закачки для
     * человека; делать это раз в минуту «на всякий случай» хуже самой болезни. */
    out_set("lo", FAIL_DROP);
    state_write("active", "vl lo\n");
    tick(RULES_WITH, "default dev lo scope link\n");
    check("целое состояние — соединения не снимаются",
          cmd_seen("conntrack -D"), 0);

    /* 10. Мера здоровья принадлежит УСТРОЙСТВУ, а не виду выхода, который его назвал.
     *
     * Устройство туннеля, названное в `devices` выхода kind=interface, проверялось пробой
     * назвавшего — то есть ICMP. Через VLESS-туннель ICMP не проходит принципиально, и
     * живая локация в пуле объявлялась мёртвой на первом же проходе: трафик уходил к
     * следующему кандидату или, при on_fail=drop по умолчанию, в blackhole — на полностью
     * исправном туннеле и молча. Регресса этой правки не видно ни в одной другой проверке:
     * стенду настоящий пинг подменён моком, который всегда отвечает «дошло», поэтому здесь
     * проверяется не приговор, а то, что ICMP для такого устройства НЕ ЗАПРАШИВАЛСЯ вовсе. */
    out_set_pool("lo");
    state_write("active", "hub lo\n");
    tick(RULES_WITH, "default dev lo scope link\n");
    check("устройство туннеля в пуле не проверяется пингом", cmd_seen("ping"), 0);
    check("устройство туннеля в пуле не заводит правило пробы", cmd_seen("table 299"), 0);
    check("пул привязан к устройству владельца",
          cmd_seen("ip route add default dev lo table 301"), 1);
    check("живой пул не получает запрет",
          cmd_seen("ip route add blackhole default table 301"), 0);

    /* 11. То же для оживления. Устройство vless и xsteer создаёт наш процесс, netifd про
     *     него не знает, и ifdown/ifup по нему — «Interface … not found» раз в минуту и
     *     ничего больше. Решение по виду НАЗВАВШЕГО выхода приводило сюда ровно этот
     *     холостой цикл, от которого выход kind=vless уже избавлен. */
    out_set_pool("nodev1");
    state_write("active", "pool -\nhub -\n");
    tick(RULES_WITH, "blackhole default\n");
    check("мёртвое устройство туннеля в пуле не перезапускается через ifdown",
          cmd_seen("ifdown"), 0);
    check("мёртвый пул получает запрет",
          cmd_seen("ip route add blackhole default table 301"), 1);

    /* 12. Какое устройство выхода считать НЫНЕШНИМ вне процесса сторожа.
     *
     * Поле `device` объявлено активным устройством, но заполнял его только сторож и только
     * у себя внутри. apply, status и diag читают спеку своим процессом, и там в `device`
     * лежал первый кандидат — предпочтение, а не факт. Итог был виден у пула: сторож увёл
     * трафик на запасное устройство, а интерфейс рисовал основное с «up: false» и «выход
     * pool: устройства nodev0 нет», то есть поломку на работающем выходе; apply при этом
     * возвращал таблицу на неработающее устройство и при on_fail=drop ставил запрет.
     *
     * Проверяется здесь именно порядок ответа, потому что ошибиться можно в каждой из трёх
     * ступеней по отдельности. */
    {
        memset(g_out, 0, sizeof(g_out));
        g_out_n = 1;
        snprintf(g_out[0].name, sizeof(g_out[0].name), "%s", "pool");
        g_out[0].kind = OUT_INTERFACE;
        g_out[0].on_fail = FAIL_DROP;
        snprintf(g_out[0].devices[0], sizeof(g_out[0].devices[0]), "%s", "nodev0");
        snprintf(g_out[0].devices[1], sizeof(g_out[0].devices[1]), "%s", "lo");
        g_out[0].devices_n = 2;
        g_out[0].mark = 0x100000;
        g_out[0].table = 300;

        /* Запись сторожа названа кандидатом и устройство на месте — берётся она. */
        snprintf(g_out[0].device, sizeof(g_out[0].device), "%s", "nodev0");
        state_write("active", "pool lo\n");
        outputs_adopt_active();
        check("активное устройство берётся из записи сторожа",
              strcmp(g_out[0].device, "lo"), 0);

        /* Записи нет вовсе: сторож ещё не проходил. Первый СУЩЕСТВУЮЩИЙ кандидат — то же
         * самое, к чему привяжет таблицу apply, и рассказывать надо о нём. */
        {
            char path[160];
            snprintf(path, sizeof(path), "%s/active", g_dir);
            unlink(path);
        }
        snprintf(g_out[0].device, sizeof(g_out[0].device), "%s", "nodev0");
        outputs_adopt_active();
        check("без записи — первый существующий кандидат",
              strcmp(g_out[0].device, "lo"), 0);

        /* Запись устарела: названное устройство больше не кандидат этого выхода (человек
         * переписал список). Идти по ней значило бы привязать таблицу к устройству, которого
         * в настройке нет вовсе. */
        snprintf(g_out[0].device, sizeof(g_out[0].device), "%s", "nodev0");
        state_write("active", "pool lo0old\n");
        outputs_adopt_active();
        check("устаревшая запись не берётся",
              strcmp(g_out[0].device, "lo"), 0);

        /* Отказ выхода записан как «-»: активного устройства нет. Существующих кандидатов
         * тоже нет — оставляем как было, и apply честно доложит отказ, а при on_fail=drop
         * поставит запрет. Гадать тут нечем и незачем. */
        snprintf(g_out[0].devices[1], sizeof(g_out[0].devices[1]), "%s", "nodev1");
        snprintf(g_out[0].device, sizeof(g_out[0].device), "%s", "nodev0");
        state_write("active", "pool -\n");
        outputs_adopt_active();
        check("живых кандидатов нет — устройство не подменяется",
              strcmp(g_out[0].device, "nodev0"), 0);
    }

    /* Уборка: файлы состояния и папка. */
    {
        char path[160];
        const char *names[] = { "active", "restart-nodev0", "restart-nodev1",
                                "restart-lo", NULL };
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

    /* ---- сторож не обещает подъём, которого не будет ---------------------------
     *
     * Снято с живого роутера. У выхода стоял `node: 31`, а в подписке было двадцать девять
     * узлов, и сторож писал «должен подняться заново через procd; жду» каждые пять минут —
     * часами. Ждать там нечего: номер вне подписки, procd поднимает клиента, тот выходит с
     * тем же отказом, и так до правки числа человеком. Строка «жду» обещает работу, которой
     * не будет, и этим она хуже молчания: по ней человек ждёт вместе со сторожем.
     *
     * Проверяется и поведение, и слова. Поведение — по числу ожиданий: обычная ветка ждёт
     * десятью шагами, эта не ждёт вовсе. Слова — потому что весь смысл правки в них: приговор
     * обязан назвать оба числа, иначе он снова отправит человека не туда. */
    {
        struct output o = {0};
        snprintf(o.name, sizeof(o.name), "vl");
        o.kind = OUT_VLESS;
        o.on_fail = FAIL_DROP;
        g_rules = "";
        g_routes = "";

        /* Приговора нет — прежнее поведение: сказать, что молчит, и подождать procd. */
        char dir[] = "/tmp/failovermatch.XXXXXX";
        char *d = mkdtemp(dir);
        g_state_dir = d ? d : "/tmp";
        g_probe_stub = (struct probe_status){ PROBE_NONE, 0, 0 };
        g_slept = 0;
        char err[4096] = "";
        int rc = revive_with_stderr(&o, "vlA", err, sizeof(err));
        check("нет приговора: сторож ждёт procd", g_slept, 10);
        check("нет приговора: возврат 0", rc, 0);
        check("нет приговора: сказано, что ждём", strstr(err, "жду") != NULL, 1);

        /* Ни один узел не ответил — ждать по-прежнему осмысленно: узлы есть, следующая
         * попытка procd может застать один из них живым. */
        g_probe_stub = (struct probe_status){ PROBE_FAILED, 0, 29 };
        g_slept = 0;
        rc = revive_with_stderr(&o, "vlB", err, sizeof(err));
        check("узлы не ответили: сторож всё равно ждёт", g_slept, 10);

        /* А номер вне подписки не исправится сам никогда. */
        g_probe_stub = (struct probe_status){ PROBE_NO_SUCH_NODE, 31, 29 };
        g_slept = 0;
        rc = revive_with_stderr(&o, "vlC", err, sizeof(err));
        check("номер вне подписки: не ждём вовсе", g_slept, 0);
        check("номер вне подписки: возврат 0", rc, 0);
        check("номер вне подписки: «жду» не обещаем", strstr(err, "жду") == NULL, 1);
        check("номер вне подписки: назван выбранный номер", strstr(err, "31") != NULL, 1);
        check("номер вне подписки: названо число пригодных", strstr(err, "29") != NULL, 1);
        check("номер вне подписки: сказано, что сам не поднимется",
              strstr(err, "сам не поднимется") != NULL, 1);

        if (d) {
            char path[512];
            for (const char *dev = "vlA"; dev; dev = !strcmp(dev, "vlA") ? "vlB"
                                              : !strcmp(dev, "vlB") ? "vlC" : NULL) {
                snprintf(path, sizeof(path), "%s/restart-%s", d, dev);
                unlink(path);
            }
            rmdir(d);
        }
        g_state_dir = "/tmp";
    }

    /* ---- гистерезис возврата на предпочтительное устройство --------------------------
     *
     * Живой роутер: пул из двух устройств, предпочтение (vpref) — флаки-узел, подхватывается
     * пробой на один тик и снова падает. Без гистерезиса трафик прыгал vpref↔vspare каждую
     * минуту, каждый прыжок — до минуты мёртвого трафика. С STEER_FAILOVER_HYST=3 возврат на
     * vpref происходит лишь после трёх подряд здоровых тиков; уход с упавшего — сразу. */
    setenv("STEER_FAILOVER_HYST", "3", 1);
    failover_hyst_reset_for_test();
    g_health_probe = hyst_health;
    out_set_two();
    /* Свежий каталог состояния: предыдущий тест свой удалил и увёл g_state_dir в /tmp, а
     * state_write пишет в g_dir. Держим оба на одном каталоге. */
    snprintf(g_dir, sizeof(g_dir), "/tmp/failovermatch-hyst-XXXXXX");
    if (!mkdtemp(g_dir)) { perror("mkdtemp"); return 1; }
    g_state_dir = g_dir;
    {
        char dev[32];
        /* Старт: оба здоровы — берём предпочтение. */
        g_h_first = 1; g_h_second = 1;
        state_write("active", "vl - 0\n");
        tick(RULES_WITH, "default dev vpref \n");
        active_dev(dev, sizeof(dev));
        check("оба здоровы — трафик на предпочтении", !strcmp(dev, "vpref"), 1);

        /* Предпочтение упало — уходим на запас СРАЗУ, без задержки. */
        g_h_first = 0; g_h_second = 1;
        tick(RULES_WITH, "default dev vpref \n");
        active_dev(dev, sizeof(dev));
        check("предпочтение упало — уход на запас немедленный", !strcmp(dev, "vspare"), 1);

        /* Предпочтение мелькнуло здоровым один тик — НЕ возвращаемся (держим запас). */
        g_h_first = 1; g_h_second = 1;
        tick(RULES_WITH, "default dev vspare \n");
        active_dev(dev, sizeof(dev));
        check("предпочтение ожило на 1 тик — держим запас", !strcmp(dev, "vspare"), 1);

        /* Второй здоровый тик — всё ещё держим (порог 3). */
        tick(RULES_WITH, "default dev vspare \n");
        active_dev(dev, sizeof(dev));
        check("два тика здоровья — всё ещё запас", !strcmp(dev, "vspare"), 1);

        /* Третий подряд здоровый тик — возвращаемся на предпочтение. */
        tick(RULES_WITH, "default dev vspare \n");
        active_dev(dev, sizeof(dev));
        check("три тика подряд — возврат на предпочтение", !strcmp(dev, "vpref"), 1);

        /* Мелькание не копится: два здоровых, падение, снова два — возврата нет. */
        g_h_first = 0; g_h_second = 1;
        tick(RULES_WITH, "default dev vpref \n");   /* ушли на запас */
        g_h_first = 1;
        tick(RULES_WITH, "default dev vspare \n");   /* тик 1 */
        tick(RULES_WITH, "default dev vspare \n");   /* тик 2 */
        g_h_first = 0;
        tick(RULES_WITH, "default dev vspare \n");   /* провал — счётчик сброшен */
        g_h_first = 1;
        tick(RULES_WITH, "default dev vspare \n");   /* снова тик 1 */
        active_dev(dev, sizeof(dev));
        check("прерванный ряд не копится — по-прежнему запас", !strcmp(dev, "vspare"), 1);

        /* Порог 0 (STEER_FAILOVER_HYST=0) — прежнее поведение: возврат сразу. */
        setenv("STEER_FAILOVER_HYST", "0", 1);
        failover_hyst_reset_for_test();
        g_h_first = 1; g_h_second = 1;
        state_write("active", "vl vspare 0\n");
        tick(RULES_WITH, "default dev vspare \n");
        active_dev(dev, sizeof(dev));
        check("порог 0 — возврат наверх сразу", !strcmp(dev, "vpref"), 1);
    }
    g_health_probe = NULL;

    if (g_fail) {
        fprintf(stderr, "failovermatch: провалено проверок: %d\n", g_fail);
        return 1;
    }

    printf("OK\n");
    return 0;
}
