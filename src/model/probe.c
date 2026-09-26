#include <stdio.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>
#include <time.h>
#include "spec.h"
#include "probe.h"

/* ---- подъём выхода vless: ход перебора узлов --------------------------------------------
 *
 * Зачем это вообще есть и почему устаревание обезврежено двумя разными способами — в шапке
 * объявлений в spec.h. Здесь только формат и его разбор.
 *
 * Файл: одна строка «состояние узел всего pid время». Позиционно, а не ключами: строку читают
 * ровно два места в этом же дереве, а лишний разборщик на роутере — лишние байты. Лежит рядом
 * с реестром меток, в state_dir: на OpenWrt это tmpfs, поэтому перебор узлов не пишет во флеш
 * и не переживает перезагрузку — ровно то, чего от него и надо.
 */
#define PROBE_FAILED_TTL 120   /* «ни один не ответил» верно, пока свежо: procd пробует снова
                                * каждые пять секунд, значит запись старше двух минут означает,
                                * что никто больше не пробует. */

static void probe_path(char *buf, size_t n, const char *out_name) {
    snprintf(buf, n, "%s/probe-%.32s", steer_state_dir(), out_name);
}

void probe_report(const char *out_name, enum probe_state st, int node, int total) {
    char path[256];
    probe_path(path, sizeof(path), out_name);
    mkdir(steer_state_dir(), 0755);
    FILE *f = fopen(path, "w");
    if (!f) return;
    fprintf(f, "%s %d %d %ld %ld\n",
            st == PROBE_RUNNING ? "probing" : st == PROBE_NO_SUCH_NODE ? "nonode" : "failed",
            node, total, (long)getpid(), (long)time(NULL));
    fclose(f);
}

void probe_clear(const char *out_name) {
    char path[256];
    probe_path(path, sizeof(path), out_name);
    unlink(path);
}

struct probe_status probe_read(const char *out_name) {
    struct probe_status out = { PROBE_NONE, 0, 0 };
    char path[256];
    probe_path(path, sizeof(path), out_name);
    FILE *f = fopen(path, "r");
    if (!f) return out;
    char word[16] = "";
    int node = 0, total = 0;
    long pid = 0, at = 0;
    int got = fscanf(f, "%15s %d %d %ld %ld", word, &node, &total, &pid, &at);
    fclose(f);
    if (got != 5) return out;

    if (!strcmp(word, "probing")) {
        /* Верно, только пока жив написавший. Иначе перебор, прерванный на середине (движок
         * остановили, процесс убили), навсегда оставлял бы на экране «проверяю узлы» — то
         * есть обещание работы, которой никто не делает. */
        char proc[64];
        snprintf(proc, sizeof(proc), "/proc/%ld", pid);
        if (pid <= 0 || access(proc, F_OK) != 0) return out;
        out.state = PROBE_RUNNING;
        out.node = node;
        out.total = total;
        return out;
    }
    if (!strcmp(word, "failed") || !strcmp(word, "nonode")) {
        /* А это переживает смерть процесса намеренно: клиент выходит с кодом 1 именно потому,
         * что ни один узел не ответил, и приговор нужен ПОСЛЕ него. Живёт, пока свеж.
         *
         * `nonode` — то же по времени жизни и другое по смыслу: номер узла вне подписки.
         * Сохраняется ИМЕННО номер, который написал человек: без него приговор снова
         * превратился бы в «узлов нет», то есть во враньё про чужую подписку. */
        long now = (long)time(NULL);
        if (at <= 0 || now - at > PROBE_FAILED_TTL) return out;
        if (!strcmp(word, "nonode")) {
            out.state = PROBE_NO_SUCH_NODE;
            out.node = node;
        } else {
            out.state = PROBE_FAILED;
            out.node = 0;
        }
        out.total = total;
        return out;
    }
    /* Незнакомое слово читается как «не знаем», а не как отказ: запись мог оставить движок
     * другой версии (в /var она переживает подмену бинарника, но не перезагрузку), и жёлтая
     * метка на исправном выходе тут была бы хуже молчания. */
    return out;
}
