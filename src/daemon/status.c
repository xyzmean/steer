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


/* ---- status --------------------------------------------------------------- */
/* Counters come from the live chain, matched by the comment each rule carries —
 * which is why generation puts the channel name there. Without it the numbers
 * exist but belong to nobody. */

/* СНИМОК СОСТОЯНИЯ: зачем движок помнит свой последний ответ.
 *
 * Полный ответ стоит работы: разбор спеки, обход выходов с чтением /sys, чтение счётчиков
 * из живой цепочки nft. Замерено на стенде (mipsel 24kc, 880 МГц): 91 мс на вызов, из них
 * основное — запуск и разбор вывода nft. Пока на это смотрел только круг опроса раз в пять
 * секунд, цена была не видна; но ровно этот ответ нужен ПЕРВЫМ при открытии окна splify2, и
 * там он складывается со всем остальным, что страница спрашивает в тот же миг, — человек
 * ждёт на пустом экране.
 *
 * Поэтому движок пишет свой ответ рядом с остальным состоянием и умеет отдать запомненное
 * немедленно (`--fast`). Снимок обновляют двое: любой полный `status` (то есть каждый круг
 * опроса открытой страницы) и отдельный экземпляр procd раз в пять минут — чтобы на только
 * что открытой странице лежало не вчерашнее.
 *
 * ЧЕСТНОСТЬ ЗДЕСЬ ГЛАВНОЕ. Запомненный ответ отдаётся с двумя полями: `at` — когда его
 * собрали, `cached: true` — что это не измерение, а память. Без них интерфейс нарисовал бы
 * запомненное как живое, и «Работает» стояло бы на упавшем туннеле; в проекте это уже
 * стоило отдельного признака `stale` в самом интерфейсе, и повторять ту же ошибку на
 * ступень ниже незачем.
 *
 * Устаревший снимок при этом НЕ отвергается: смысл `--fast` в том, чтобы показать хоть
 * что-то сразу, а решение «это слишком старо, чтобы показывать» принимает тот, кто
 * спрашивает, — у него есть `at`. Снимка нет вовсе — команда считает всё честно, то есть
 * `--fast` никогда не отвечает пустотой.
 */
void status_snap_path(char *buf, size_t n) {
    snprintf(buf, n, "%s/status.json", g_state_dir);
}

/* Снимок больше этого не бывает: сотня выходов и сотня каналов — это единицы килобайт.
 * Предел стоит потому, что файл читается в буфер на стеке, а писать его мог не только
 * движок. */
#define STATUS_SNAP_MAX 262144

/* Отдать запомненное. 0 — отдали, -1 — снимка нет или он не похож на наш ответ.
 *
 * `cached` дописывается ПЕРЕД закрывающей скобкой, а не в начало: так порядок полей ответа
 * остаётся тем же, каким его видят все нынешние читатели, и `{"schema":1,...` по-прежнему
 * первое, что стоит в строке. */
static int status_from_snapshot(void) {
    char snap[256];
    status_snap_path(snap, sizeof snap);
    FILE *f = fopen(snap, "r");
    if (!f) return -1;
    static char buf[STATUS_SNAP_MAX];
    size_t n = fread(buf, 1, sizeof buf, f);
    int truncated = !feof(f);
    fclose(f);
    if (truncated) return -1;   /* не влез — значит это не наш снимок */
    while (n && (buf[n - 1] == '\n' || buf[n - 1] == ' ')) n--;
    /* Проверка формы, а не доверие имени файла: оборванная запись оставила бы обрубок,
     * и отдать его значило бы выдать половину JSON за ответ движка. */
    if (n < 3 || buf[0] != '{' || buf[n - 1] != '}') return -1;
    fwrite(buf, 1, n - 1, stdout);
    fputs(",\"cached\":true}\n", stdout);
    return 0;
}

/* Сам ответ. Поток параметром, потому что печатается он ДВАЖДЫ в разные места: в снимок на
 * диске и человеку (точнее, тому, кто позвал). Считать его два раза было бы вдвое дороже
 * ровно того, ради чего снимок и заведён. */
static void status_emit(const struct spec *sp, FILE *out) {
    /* УМЕНИЯ ДВИЖКА — перечнем имён и верхним уровнем.
     *
     * Зачем вообще. Незнакомый ключ спеки движок пропускает МОЛЧА (js_skip) — это и есть
     * совместимость вперёд внутри мажора, — поэтому управляющий слой, записавший новое поле
     * в движок постарше, получает применённую спеку и трафик не туда, куда просил. Узнать
     * поколение до записи он обязан сам, и до сих пор узнавал по косвенным признакам:
     * наличию `lan_devices` здесь и поля `nodes` у выхода kind=vless. Второй признак виден
     * ТОЛЬКО на роутере, где такой выход уже есть, — а смешанный пул нужнее всего там, где
     * его нет вовсе (xsteer плюс wireguard), и там же движок постарше молча уводит канал в
     * blackhole. Интерфейс поэтому вынужден был запрещать пул до первого применённого
     * выхода подписки (splify2, запуск 69).
     *
     * ПОЧЕМУ ИМЕНА, А НЕ НОМЕР ВЕРСИИ. Версию в дерево проставляет релизный workflow, а не
     * коммит: движок из main через два коммита после релиза называет то же число, что и
     * релиз (I-054). Сравнивать по нему — значит однажды объявить умеющим движок, который
     * не умеет. Имя умения печатает тот же код, который его и делает.
     *
     * ДОГОВОР О ПЕРЕЧНЕ. Поля нет вовсе — движок старше 1.3.0, и тогда судить о нём
     * по-прежнему нечем, кроме косвенных признаков. Набор имён может и расти, и сокращаться
     * между версиями: потребитель обязан терпеть незнакомые имена и не должен требовать
     * наличия какого-либо конкретного. */
    /* КОГДА СОБРАН ЭТОТ ОТВЕТ. Печатается всегда, а не только в снимке, и это не
     * избыточность: ответ движка теперь бывает запомненным, и различить измерение от памяти
     * по одному лишь `cached` было бы нечем — интерфейсу нужен возраст, чтобы сказать
     * человеку «данные такой-то давности», а не рисовать их живыми. У живого ответа возраст
     * нулевой, и это тот же контракт, а не особый случай. */
    fprintf(out, "{\"schema\":1,\"at\":%ld,"
                 "\"features\":[\"lan_devices\",\"nodes\",\"pool\",\"active_device\","
                 "\"status_cache\",\"xslink\",\"xsteer_state\",\"spec_schema2\",\"awg\","
                 "\"via\"]",
            (long)time(NULL));
    /* Локальные устройства — следом: интерфейс показывает, с чего забирается трафик, и
     * без этого поля ему пришлось бы читать спеку вторым источником, то есть однажды
     * показать не то, что применено. */
    fprintf(out, ",\"lan_devices\":[");
    for (size_t i = 0; i < sp->lan_dev_n; i++)
        fprintf(out, "%s\"%s\"", i ? "," : "", sp->lan_dev[i]);
    fprintf(out, "],\"outputs\":{");
    for (size_t i = 0; i < sp->out_n; i++) {
        char devpath[128];
        int up = 0;
        if (out_has_device(&sp->out[i])) {
            snprintf(devpath, sizeof(devpath), "/sys/class/net/%s/operstate", sp->out[i].device);
            FILE *df = fopen(devpath, "r");
            if (df) {
                char st[16] = "";
                if (fgets(st, sizeof(st), df)) up = strncmp(st, "down", 4) != 0;
                fclose(df);
            }
        }
        fprintf(out, "%s\"%s\":{\"kind\":\"%s\"", i ? "," : "", sp->out[i].name,
               kind_of(&sp->out[i])->name);
        /* Через какой выход идёт туннель этого выхода (`via`, см. «вложенные выходы» в
         * spec.h). Поля нет, когда туннель идёт напрямую, — как в спеке. Живость цели здесь не
         * повторяется: она видна у самой цели в этом же ответе, а второй источник того же
         * ответа однажды разошёлся бы с первым. */
        if (sp->out[i].via[0]) fprintf(out, ",\"via\":\"%s\"", sp->out[i].via);
        if (out_has_device(&sp->out[i])) {
            struct fwcheck c = fw_check(sp->out[i].device);
            fprintf(out, ",\"device\":\"%s\",\"up\":%s,\"mark\":\"0x%08x\",\"table\":%d"
                   ",\"in_firewall\":%s,\"nat\":%s",
                   sp->out[i].device, up ? "true" : "false", sp->out[i].mark, sp->out[i].table,
                   c.in_firewall ? "true" : "false", c.masqueraded ? "true" : "false");
            /* Кандидаты и режим отказа: без них failover не виден из интерфейса, и
             * человек не может понять, почему выход вдруг ведёт в другое устройство. */
            /* Ход подъёма — рядом с up, а не отдельным вызовом: интерфейс уже читает
             * status по кругу, и второй источник дал бы на экране два разных мгновения.
             * Поля нет вовсе, когда сказать нечего (устройство есть, файла нет, он устарел
             * или писавший процесс мёртв) — «не знаем» не должно читаться как «плохо». */
            if (!up) {
                /* Ход подъёма спрашивается у ВЛАДЕЛЬЦА устройства, а не у выхода, который
                 * его назвал: запись перебора узлов пишет клиент vless под своим именем, и
                 * пул, ждущий этот туннель, иначе отдавал бы «устройства нет» вместо
                 * «проверяю узлы, 3 из 26» — то же враньё, ради снятия которого перебор и
                 * стал виден (I-100). */
                struct probe_status pr =
                    probe_read(out_for_device(sp, &sp->out[i], sp->out[i].device)->name);
                if (pr.state == PROBE_RUNNING)
                    fprintf(out, ",\"probe\":{\"state\":\"probing\",\"node\":%d,\"total\":%d}",
                           pr.node, pr.total);
                else if (pr.state == PROBE_FAILED)
                    fprintf(out, ",\"probe\":{\"state\":\"failed\",\"total\":%d}", pr.total);
                /* Номер вне подписки — СВОЁ состояние, а не разновидность failed: интерфейс
                 * обязан уметь сказать «поправьте номер», а не «поменяйте подписку». Оба
                 * числа рядом, потому что порознь они ничего не значат. */
                else if (pr.state == PROBE_NO_SUCH_NODE)
                    fprintf(out, ",\"probe\":{\"state\":\"no_such_node\",\"node\":%d"
                                 ",\"total\":%d}", pr.node, pr.total);
            }
            fprintf(out, ",\"devices\":[");
            for (size_t d = 0; d < sp->out[i].devices_n; d++)
                fprintf(out, "%s\"%s\"", d ? "," : "", sp->out[i].devices[d]);
            fprintf(out, "],\"on_fail\":\"%s\"",
                   sp->out[i].on_fail == FAIL_DROP ? "drop" :
                   sp->out[i].on_fail == FAIL_ZAPRET ? "zapret" : "direct");
        }
        /* Свои поля вида (kind_ops.status): у vless — выбранные узлы подписки, у interface —
         * обфускация, у awg — рукопожатие и счётчики из ядра (все три — после on_fail, в объекте
         * выхода с устройством), у zapret — очередь, файл стратегии и живость обработчика. */
        {
            const struct kind_ops *k = kind_of(&sp->out[i]);
            if (k->status) k->status(out, sp, &sp->out[i]);
        }
        fprintf(out, "}");
    }
    fprintf(out, "},\"channels\":[");

    counters_load();
    for (size_t i = 0; i < g_grp_n; i++) {
        unsigned long up_p = 0, up_b = 0, dn_p = 0, dn_b = 0;
        int live = counter_find(g_grp[i].name, 0, &up_p, &up_b) == 0;
        int dn = counter_find(g_grp[i].name, 1, &dn_p, &dn_b) == 0;
        fprintf(out, "%s{\"name\":\"%s\",\"out\":\"%s\",\"kind\":\"%s\",\"live\":%s",
               i ? "," : "", g_grp[i].name, g_grp[i].out,
               g_grp[i].domains ? "domains" : "prefixes", live ? "true" : "false");
        if (live) fprintf(out, ",\"packets\":%lu,\"bytes\":%lu", up_p, up_b);
        /* Отдельными именами, а не вторым «bytes»: старое имя значило «наружу» и в таком
         * значении уже разошлось по установленным версиям splify2. Переопределить его
         * значило бы, что новый движок со старым интерфейсом молча показывает не то. */
        if (dn) fprintf(out, ",\"down_packets\":%lu,\"down_bytes\":%lu", dn_p, dn_b);
        fprintf(out, ",\"lists\":%zu,\"channels\":[", g_grp[i].files_n + g_grp[i].dfiles_n);
        for (size_t m = 0; m < g_grp[i].members_n; m++)
            fprintf(out, "%s\"%s\"", m ? "," : "", g_grp[i].members[m]);
        fprintf(out, "]}");
    }
    fprintf(out, "]}\n");
}

/* Полный ответ: посчитать, запомнить и напечатать.
 *
 * Снимок пишется через временный файл и rename, как и всё прочее состояние: оборванная
 * запись поверх прежнего снимка оставила бы обрубок, а `--fast` тогда отдавал бы половину
 * ответа. Не записалось (нет места, каталог только для чтения) — печатаем и молчим об этом:
 * снимок это УСКОРЕНИЕ, и терять из-за него сам ответ было бы обменом наоборот.
 *
 * Печатается ФАЙЛ, а не второй проход печати: обход выходов читает /sys, а счётчики — живую
 * цепочку nft, и второй проход дал бы в снимке и на экране два разных мгновения. */
int cmd_status(const char *spec, int fast) {
    static struct spec cfg;
    /* Запомненное — раньше разбора спеки: смысл `--fast` в том, чтобы не делать работу
     * вовсе. Спека при этом не читается, то есть негодная спека `--fast` не ломает — он
     * отвечает тем, что было применено, пока она была годной. */
    if (fast && status_from_snapshot() == 0) return 0;

    /* Правило 5, docs/architecture.md, раздел 2: err_die здесь довершает то, что раньше делал
     * die() изнутри load_spec/build_groups. */
    struct err e = {0};
    if (load_spec(spec, &cfg, &e) < 0) err_die(&e);
    if (registry_assign(&cfg, &e) < 0) err_die(&e);
    if (build_groups(&cfg, &e) < 0) err_die(&e);
    /* О том же устройстве, к которому apply привязал таблицу, — см. outputs_adopt_active.
     * Без этого пул, уведённый сторожем на запасное устройство, отдавался бы интерфейсу
     * основным устройством с `up: false`: рабочий выход, нарисованный сломанным. */
    outputs_adopt_active(&cfg);

    char snap[256], tmp[288];
    status_snap_path(snap, sizeof snap);
    snprintf(tmp, sizeof tmp, "%s.new", snap);
    mkdir(g_state_dir, 0755);
    FILE *f = fopen(tmp, "w");
    if (!f) { status_emit(&cfg, stdout); return 0; }
    status_emit(&cfg, f);
    if (fclose(f) != 0 || rename(tmp, snap) != 0) {
        unlink(tmp);
        status_emit(&cfg, stdout);
        return 0;
    }
    f = fopen(snap, "r");
    if (!f) { status_emit(&cfg, stdout); return 0; }
    char buf[8192];
    size_t n;
    while ((n = fread(buf, 1, sizeof buf, f)) > 0) fwrite(buf, 1, n, stdout);
    fclose(f);
    return 0;
}

