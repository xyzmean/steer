/* Подъём устройства туннеля: каждый отказ `ip` обязан быть назван.
 *
 * ЗАЧЕМ ОТДЕЛЬНЫМ СТЕНДОМ. tun_bring_up — последнее немое место на пути от «процесс
 * запущен» до «трафик идёт» (I-114). Три команды подряд, и ни у одной не смотрели код
 * возврата, притом что цена у них разная и ни одна не видна снаружи:
 *   - без адреса ядро считает маршрут на устройство непригодным для локально порождённых
 *     пакетов, то есть выход есть, а ходить по нему нечему;
 *   - без `up` через устройство не идёт вообще ничего;
 *   - без txqueuelen очередь остаётся ядерной в 500 пакетов против запрошенных 4096 — это
 *     не поломка, а молча потерянная скорость (замер в комментарии рядом с командой).
 * Регресс такой правки не виден ни в одной другой проверке: движок запускается, журнал
 * выглядит успешным, «настроено» и «работает» расходятся молча — ровно то, за чем этот
 * путь уже дважды правили (H-081 — имя устройства, H-084 — привязка таблицы).
 *
 * КАК ЭТО ПРОВЕРЯЕТСЯ БЕЗ РОУТЕРА. run_quiet подменён: он записывает команды вместо их
 * запуска и умеет отказать ровно на той, что назвал стенд (тот же приём, что в
 * tests/failovermatch.c). Наблюдаемое здесь — журнал: у подъёма устройства нет ни
 * возвращаемого значения, ни следующей команды, по которой можно судить со стороны, —
 * поэтому stderr на время вызова уводится в файл и читается целиком. Уровень строки
 * (`steer[warn]` против `steer[info]`) проверяется отдельно: у отказа очереди тон обязан
 * быть осведомляющий, иначе на системах без txqueuelen штатный запуск превратится в поток
 * предупреждений, и это научит не смотреть в журнал вовсе.
 *
 * Стенд включает src/ext/tunnel.c целиком: tun_bring_up статическая, и дотянуться до неё
 * иначе значило бы завести в движке подкоманду ради теста. Отсюда и mbedtls — цикл туннеля
 * тянет за собой TLS 1.3 и reality (поэтому стенд живёт в tests/ext-test.sh, а не в
 * `make test`). Ни сети, ни прав, ни устройства ему не нужно: вызывается ровно одна
 * функция, и все её сайд-эффекты проходят через подменённый run_quiet.
 */
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>

/* ---- подменённый запуск команд ------------------------------------------------ */

static char g_cmd[16][256];
static int  g_cmd_n;
/* Подстрока команды, которой велено отказать. Пустая — все проходят. */
static const char *g_fail_on = "";

int run_quiet(const char *const argv[]) {
    if (!argv || !argv[0]) return -1;
    char joined[256];
    size_t jn = 0;
    for (int i = 0; argv[i] && jn < sizeof(joined) - 2; i++)
        jn += (size_t)snprintf(joined + jn, sizeof(joined) - jn, i ? " %s" : "%s", argv[i]);
    if (g_cmd_n < (int)(sizeof(g_cmd) / sizeof(*g_cmd)))
        snprintf(g_cmd[g_cmd_n++], sizeof(g_cmd[0]), "%s", joined);
    if (g_fail_on[0] && strstr(joined, g_fail_on)) return 2;
    return 0;
}

#include "../src/spec.h"
/* Привязку таблицы делает failover.c; сюда он не входит — на этом стенде его не зовут. */
void bind_device(struct output *o, const char *dev) { (void)o; (void)dev; }

#include "../src/ext/tunnel.c"

/* ---- перехват журнала --------------------------------------------------------- */

static char g_logpath[] = "/tmp/devupmatch-log.XXXXXX";
static int  g_logfd = -1, g_saved_err = -1;
static char g_log[8192];

static void log_begin(void) {
    if (g_logfd < 0) {
        g_logfd = mkstemp(g_logpath);
        unlink(g_logpath);          /* файл нужен как буфер, а не как артефакт */
        g_saved_err = dup(2);
    }
    fflush(stderr);
    /* Обнулить НАДО и длину, и смещение: запись в подменённый stderr идёт по смещению
     * дескриптора, и без lseek следующий перехват начинался бы дырой из нулевых байтов —
     * то есть пустой строкой для strstr при непустом файле. */
    if (ftruncate(g_logfd, 0) != 0) { /* пусто и так */ }
    lseek(g_logfd, 0, SEEK_SET);
    dup2(g_logfd, 2);
}

static const char *log_end(void) {
    fflush(stderr);
    dup2(g_saved_err, 2);
    ssize_t n = pread(g_logfd, g_log, sizeof(g_log) - 1, 0);
    g_log[n > 0 ? n : 0] = '\0';
    return g_log;
}

/* ---- проверки ----------------------------------------------------------------- */

static int fails;

static void check(const char *what, long want, long got) {
    printf("%-66s %s\n", what, want == got ? "ok" : "ПРОВАЛ");
    if (want != got) {
        printf("     хочу: %ld\n     есть: %ld\n", want, got);
        fails++;
    }
}

/* Имя устройства НЕ содержит подстроки "up": ею стенд отличает `ip link set ... up` от
 * двух остальных команд, и имя вроде tun-devup ловило бы само себя. */
#define DEV   "steer-tst0"
#define TABLE 300

/* Поднять устройство при отказе указанной команды и вернуть журнал. */
static const char *bring_up_with(const char *fail_on) {
    g_cmd_n = 0;
    g_fail_on = fail_on;
    log_begin();
    tun_bring_up(DEV, TABLE);
    return log_end();
}

static int cmd_seen(const char *needle) {
    for (int i = 0; i < g_cmd_n; i++)
        if (strstr(g_cmd[i], needle)) return 1;
    return 0;
}

/* Сколько строк уровня в журнале. */
static int lines_with(const char *log, const char *level) {
    int n = 0;
    for (const char *p = log; (p = strstr(p, level)); p += strlen(level)) n++;
    return n;
}

int main(void) {
    printf("== подъём устройства туннеля: порядок команд не тронут ==\n");
    const char *log = bring_up_with("");
    check("команд ровно три", 3, g_cmd_n);
    check("адрес ставится из таблицы выхода (198.51.100.<1+N%200>/32)", 1,
          cmd_seen("ip addr replace 198.51.100." "101" "/32 dev " DEV));
    check("устройство поднимается", 1, cmd_seen("ip link set dev " DEV " up"));
    check("очередь передачи запрашивается в 4096", 1,
          cmd_seen("ip link set dev " DEV " txqueuelen 4096"));
    /* Страховка от перестарания: на исправном подъёме журнал молчит. Иначе штатный
     * запуск получил бы предупреждение, которого нечем объяснить. */
    check("на успешном подъёме предупреждений нет", 0, lines_with(log, "steer[warn]"));

    printf("\n== отказ каждой команды назван, и назван своим тоном ==\n");
    log = bring_up_with("addr replace");
    check("отказ адреса — предупреждение", 1, lines_with(log, "steer[warn]") > 0);
    check("в нём названо устройство", 1, strstr(log, DEV) != NULL);
    check("и сам адрес — по нему видно, что именно не встало", 1,
          strstr(log, "198.51.100.101") != NULL);
    check("остальные две команды всё равно выполнены", 1,
          cmd_seen("link set dev " DEV " up") && cmd_seen("txqueuelen"));

    log = bring_up_with(" up");
    check("отказ подъёма — предупреждение", 1, lines_with(log, "steer[warn]") > 0);
    check("в нём названо устройство", 1, strstr(log, DEV) != NULL);
    check("отказал именно `link set up`, адрес прошёл", 0, lines_with(log, "198.51.100.101"));

    log = bring_up_with("txqueuelen");
    check("отказ очереди назван", 1, lines_with(log, "steer[") > 0);
    check("но тоном осведомляющим, а не тревожным", 0, lines_with(log, "steer[warn]"));
    check("именно info", 1, lines_with(log, "steer[info]") > 0);
    check("в строке назван размер очереди, о котором просили", 1,
          strstr(log, "4096") != NULL);

    printf(fails ? "\nПРОВАЛОВ: %d\n" : "\nвсе проверки прошли\n", fails);
    return fails ? 1 : 0;
}
