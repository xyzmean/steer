/* steer failover — выбрать живое устройство для каждого выхода.
 *
 * Не демон. Один проход по вызову, состояние — в маршрутных таблицах ядра и в
 * реестре. Так же, как apply: движок остаётся компилятором, а «раз в минуту» —
 * дело того, кто его вызывает (init-скрипт ставит таймер).
 *
 * Порядок devices — приоритет. Первое здоровое устройство побеждает, поэтому
 * восстановление наверх происходит само: как только основной туннель ожил, он
 * снова оказывается первым здоровым, и следующий проход вернётся на него.
 *
 * Проверка НЕ трогает живой путь. Пинг уходит через отдельную таблицу с правилом
 * по адресу источника кандидата — иначе, чтобы проверить запасной туннель, пришлось
 * бы сначала переключиться на него, то есть уронить работающий ради вопроса
 * «работает ли другой».
 */
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/wait.h>
#include <fcntl.h>
#include <time.h>
#include "spec.h"

/* Таблица и приоритет правила для проб. Далеко от 300+, которые раздаёт реестр:
 * проба обязана быть невидимой для боевой маршрутизации. */
#define PROBE_TABLE 299
#define PROBE_PRIO  29999

/* Куда пинговать. Два адреса, потому что один может быть заблокирован именно в
 * этом туннеле, и тогда здоровый путь выглядел бы мёртвым. */
static const char *PROBE_TARGETS[] = { "1.1.1.1", "8.8.8.8", NULL };

int run_quiet(const char *const argv[]);   /* из steer.c */

/* Адрес источника устройства: без него правило пробы не к чему привязать, а само
 * отсутствие адреса уже означает, что устройство не готово нести трафик. */
static int device_src(const char *dev, char *out, size_t n) {
    char cmd[192];
    snprintf(cmd, sizeof(cmd), "ip -4 -o addr show %s 2>/dev/null", dev);
    FILE *pf = popen(cmd, "r");
    if (!pf) return 0;
    char line[256];
    int found = 0;
    while (!found && fgets(line, sizeof(line), pf)) {
        char ifname[32], addr[64];
        if (sscanf(line, "%*d: %31s inet %63s", ifname, addr) != 2) continue;
        char *slash = strchr(addr, '/');
        if (slash) *slash = '\0';
        snprintf(out, n, "%s", addr);
        found = 1;
    }
    pclose(pf);
    return found;
}

static int device_present(const char *dev) {
    char path[128];
    snprintf(path, sizeof(path), "/sys/class/net/%s/operstate", dev);
    FILE *f = fopen(path, "r");
    if (!f) return 0;
    char st[16] = "";
    int up = fgets(st, sizeof(st), f) && strncmp(st, "down", 4) != 0;
    fclose(f);
    return up;
}

/* Живо ли устройство на самом деле. operstate у туннеля почти всегда "unknown" и
 * остаётся таким, когда пир давно молчит, — поэтому решает пакет, дошедший до
 * настоящего адреса, а не то, что о себе сообщает интерфейс. */
static int device_healthy(const char *dev) {
    if (!device_present(dev)) return 0;
    char src[64];
    if (!device_src(dev, src, sizeof(src))) return 0;

    char tbl[16], prio[16];
    snprintf(tbl, sizeof(tbl), "%d", PROBE_TABLE);
    snprintf(prio, sizeof(prio), "%d", PROBE_PRIO);

    const char *del[] = { "ip", "-4", "rule", "del", "from", src, "table", tbl,
                          "priority", prio, NULL };
    run_quiet(del);
    const char *rt[] = { "ip", "-4", "route", "replace", "default", "dev", dev,
                         "table", tbl, NULL };
    run_quiet(rt);
    const char *add[] = { "ip", "-4", "rule", "add", "from", src, "table", tbl,
                          "priority", prio, NULL };
    run_quiet(add);

    int ok = 0;
    for (int i = 0; PROBE_TARGETS[i] && !ok; i++) {
        const char *p[] = { "ping", "-c", "1", "-W", "3", "-I", dev, "-q",
                            PROBE_TARGETS[i], NULL };
        ok = run_quiet(p) == 0;
    }

    /* Убрать за собой обязательно: оставленное правило пробы пережило бы этот
     * процесс и молча увело бы трафик источника в таблицу, которую никто больше
     * не наполняет. */
    run_quiet(del);
    const char *flush[] = { "ip", "-4", "route", "flush", "table", tbl, NULL };
    run_quiet(flush);
    return ok;
}

/* Куда направить таблицу выхода, когда живых устройств нет.
 *
 * drop   — blackhole: трафик канала останавливается заметно и никуда не утекает;
 * direct — правило снимается, трафик идёт как обычный (осознанный выбор);
 * zapret — то же, что direct, но нужен работающий обход DPI, иначе это просто
 *          direct под другим именем, о чём и сообщаем. */
static int zapret_running(void) {
    FILE *pf = popen("ps w 2>/dev/null", "r");
    if (!pf) return 0;
    char line[512];
    int found = 0;
    while (!found && fgets(line, sizeof(line), pf))
        if (strstr(line, "nfqws")) found = 1;
    pclose(pf);
    return found;
}

static void apply_failed(struct output *o) {
    char tbl[16], mark[24];
    snprintf(tbl, sizeof(tbl), "%d", o->table);
    snprintf(mark, sizeof(mark), "0x%08x", o->mark);
    const char *flush[] = { "ip", "route", "flush", "table", tbl, NULL };
    run_quiet(flush);

    if (o->on_fail == FAIL_DROP) {
        /* blackhole, а не отсутствие маршрута: без маршрута пакет с меткой
         * провалится в следующую таблицу и уйдёт напрямую — то есть ровно туда,
         * куда его не пускали. */
        const char *bh[] = { "ip", "route", "add", "blackhole", "default",
                             "table", tbl, NULL };
        run_quiet(bh);
        fprintf(stderr, "steer: выход %s: живых устройств нет, трафик остановлен "
                        "(on_fail=drop)\n", o->name);
        return;
    }

    /* direct и zapret: снимаем правило, чтобы помеченный трафик шёл обычным путём. */
    const char *rd[] = { "ip", "rule", "del", "fwmark", mark, "table", tbl, NULL };
    while (run_quiet(rd) == 0) ;

    if (o->on_fail == FAIL_ZAPRET && !zapret_running())
        fprintf(stderr, "steer: выход %s: живых устройств нет, трафик пущен напрямую, "
                        "но zapret не запущен — обхода DPI не будет\n", o->name);
    else
        fprintf(stderr, "steer: выход %s: живых устройств нет, трафик пущен напрямую "
                        "(on_fail=%s)\n", o->name,
                o->on_fail == FAIL_ZAPRET ? "zapret" : "direct");
}

/* Привязать таблицу выхода к устройству. Правило пересоздаётся, потому что режим
 * отказа мог его снять, а `ip rule add` дубликаты не проверяет. */
static void bind_device(struct output *o, const char *dev) {
    char tbl[16], mark[24];
    snprintf(tbl, sizeof(tbl), "%d", o->table);
    snprintf(mark, sizeof(mark), "0x%08x", o->mark);

    const char *rd[] = { "ip", "rule", "del", "fwmark", mark, "table", tbl, NULL };
    while (run_quiet(rd) == 0) ;
    const char *ra[] = { "ip", "rule", "add", "fwmark", mark, "table", tbl, NULL };
    run_quiet(ra);
    const char *flush[] = { "ip", "route", "flush", "table", tbl, NULL };
    run_quiet(flush);
    const char *rt[] = { "ip", "route", "add", "default", "dev", dev, "table", tbl, NULL };
    run_quiet(rt);
}

/* Что выбрано сейчас — чтобы не переписывать маршруты и не шуметь в лог, когда
 * ничего не изменилось. Файл в state_dir, рядом с реестром меток. */
static void active_path(char *buf, size_t n) {
    snprintf(buf, n, "%s/active", g_state_dir);
}

static void active_get(const char *out, char *dev, size_t n) {
    dev[0] = '\0';
    char path[256];
    active_path(path, sizeof(path));
    FILE *f = fopen(path, "r");
    if (!f) return;
    char name[32], d[32];
    while (fscanf(f, "%31s %31s\n", name, d) == 2)
        if (!strcmp(name, out)) snprintf(dev, n, "%s", d);
    fclose(f);
}

static void active_save(void) {
    char path[256];
    active_path(path, sizeof(path));
    FILE *f = fopen(path, "w");
    if (!f) return;
    for (size_t i = 0; i < g_out_n; i++)
        if (g_out[i].kind == OUT_INTERFACE)
            fprintf(f, "%s %s\n", g_out[i].name, g_out[i].device[0] ? g_out[i].device : "-");
    fclose(f);
}

/* Поднять залипший туннель.
 *
 * Обязательно ifdown+ifup, а не просто ifup: в netifd `ifup` на уже поднятом
 * интерфейсе — no-op, поэтому залипший туннель сам не оживёт НИКОГДА, и сторож
 * просидит в резерве даже после того, как сервер вернулся. Лечится этим то, что
 * иначе не лечится: netifd разрешает имя эндпоинта один раз при подъёме (переезд по
 * DDNS не подхватывается), сокет остаётся привязан к отмершему пути UDP/CGNAT, а
 * состояние proto-error само не снимается.
 *
 * Безопасно, потому что делается только с устройством, которое НЕ несёт трафик:
 * либо оно и так не отвечает, либо маршруты указывают на другое.
 *
 * Отдельная защита от циклов: перезапуск не чаще раза в NN секунд на устройство.
 * Мёртвый пир иначе получал бы ifdown/ifup каждую минуту, и туннель никогда не
 * успевал бы завершить рукопожатие. */
#define RESTART_COOLDOWN 300

static int restart_allowed(const char *dev) {
    char path[256];
    snprintf(path, sizeof(path), "%s/restart-%.32s", g_state_dir, dev);
    FILE *f = fopen(path, "r");
    long last = 0;
    if (f) { if (fscanf(f, "%ld", &last) != 1) last = 0; fclose(f); }
    long now = (long)time(NULL);
    if (last && now - last < RESTART_COOLDOWN) return 0;
    f = fopen(path, "w");
    if (f) { fprintf(f, "%ld\n", now); fclose(f); }
    return 1;
}

static int revive(const char *dev, int verbose) {
    if (!restart_allowed(dev)) {
        if (verbose)
            fprintf(stderr, "steer: %s: перезапуск был недавно, пропускаю\n", dev);
        return 0;
    }
    fprintf(stderr, "steer: %s: не отвечает — перезапускаю интерфейс\n", dev);
    const char *down[] = { "ifdown", dev, NULL };
    const char *up[] = { "ifup", dev, NULL };
    run_quiet(down);
    run_quiet(up);
    /* Рукопожатию нужно время: проверить сразу — значит объявить мёртвым то, что
     * ещё поднимается. Ждём короткими шагами, чтобы не держать проход дольше нужного. */
    for (int i = 0; i < 10; i++) {
        sleep(1);
        if (device_healthy(dev)) return 1;
    }
    return 0;
}

int cmd_failover(const char *spec, int verbose) {
    load_spec(spec);
    registry_assign();

    int changed = 0;
    for (size_t i = 0; i < g_out_n; i++) {
        struct output *o = &g_out[i];
        if (o->kind != OUT_INTERFACE) continue;

        char was[32];
        active_get(o->name, was, sizeof(was));

        const char *chosen = NULL;
        /* Сначала все по одному разу без перезапусков: если запасной здоров, поднимать
         * основной незачем — трафик уже пойдёт. Перезапуск дороже проверки и на
         * секунды роняет то, что перезапускают. */
        for (size_t k = 0; k < o->devices_n; k++) {
            if (device_healthy(o->devices[k])) { chosen = o->devices[k]; break; }
            if (verbose)
                fprintf(stderr, "steer: %s: %s не отвечает\n", o->name, o->devices[k]);
        }

        /* Ни одно не ответило — вот теперь можно тратить время на оживление. Порядок
         * тот же, поэтому основной туннель получает попытку первым. */
        if (!chosen)
            for (size_t k = 0; k < o->devices_n; k++)
                if (revive(o->devices[k], verbose)) { chosen = o->devices[k]; break; }

        if (chosen) {
            snprintf(o->device, sizeof(o->device), "%s", chosen);
            if (strcmp(was, chosen) != 0) {
                bind_device(o, chosen);
                printf("steer: выход %s -> %s%s\n", o->name, chosen,
                       was[0] && strcmp(was, "-") ? " (переключение)" : "");
                changed = 1;
            } else if (verbose) {
                fprintf(stderr, "steer: %s: %s работает\n", o->name, chosen);
            }
        } else {
            o->device[0] = '\0';
            if (strcmp(was, "-") != 0) {
                apply_failed(o);
                changed = 1;
            }
        }
    }
    active_save();
    if (!changed && verbose) fprintf(stderr, "steer: изменений нет\n");
    return 0;
}
