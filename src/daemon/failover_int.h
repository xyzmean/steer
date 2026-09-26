#ifndef STEER_FAILOVER_INT_H
#define STEER_FAILOVER_INT_H

/* Внутренний заголовок failover.c — по образцу dnsd_int.h (docs/architecture.md, раздел 4).
 * failover.c — один файл, а не несколько, но проверка сверки маршрутизации (tests/failovermatch.c)
 * читает её решение по кускам: разбор дампов ip rule/ip route — чистая функция, и ошибка в ней
 * не видна ни одной другой проверкой (см. шапку failover.c) — а линковать стенд с исходником
 * отдельным объектом (а не #include) можно только если у этих кусков есть объявление в
 * заголовке. "static" с них снят ровно поэтому — они по-прежнему не часть публичного API
 * движка (используются только внутри failover.c и в тесте), просто их имена стали видны
 * компоновщику. */

#include <stdint.h>
#include <stddef.h>
#include "spec.h"

/* ---- сверка фактической маршрутизации (route_facts_of) ---------------------------- */
enum tbl_state {
    TBL_EMPTY,        /* в таблице нет ничего похожего на default */
    TBL_BLACKHOLE,    /* запрет: blackhole/unreachable/prohibit default */
    TBL_DEV,          /* default через устройство */
    TBL_OTHER,        /* default есть, но устройство из него не вычитывается */
};

struct route_facts {
    /* known — удалось ли вообще прочитать состояние ядра.
     *
     * Это не перестраховка, а защита от худшего исхода всей затеи. Сверка отвечает на вопрос
     * «состояние разъехалось?», и если ответ построен на ПУСТОМ дампе, он всегда «да» — тогда
     * сторож каждую минуту сносил бы привязку живого выхода (`ip route flush table N`) и
     * поднимал заново, то есть сам делал бы короткий провал помеченного трафика раз в минуту и
     * заливал журнал.
     *
     * Признак «прочитать не удалось» — ПУСТОЙ вывод `ip rule show`. На живой коробке он пуст не
     * бывает никогда: там всегда лежат три правила ядра (0, 32766, 32767). Поэтому пустота
     * означает не «правил нет», а «спросить не получилось»: нет `ip`, busybox не понял ключ,
     * отказал popen. Проверять код возврата было бы хуже — busybox отдаёт ноль и на том, чего
     * не понял. */
    int known;
    int rule;             /* правило `fwmark <метка> table <таблица>` в ядре есть */
    enum tbl_state table;
    char dev[32];          /* устройство из default, когда table == TBL_DEV */
    int backstop;          /* запасной запрет (STEER_BACKSTOP_METRIC) на месте */
};

struct route_facts route_facts_of(const char *rules, const char *routes,
                                   uint32_t mark, int table);
int routing_live_ok(const struct route_facts *f, const char *dev);
int routing_failed_ok(const struct route_facts *f, enum on_fail of);

/* ---- лишние копии правила пробы/выхода (rule_copies_of) ---------------------------- */
#define RULE_COPIES_MAX 8
struct rule_copies {
    int known;                      /* дамп прочитан (пустым он на живой коробке не бывает) */
    int n;                          /* верных копий */
    unsigned long pref[RULE_COPIES_MAX];
    int wrong_n;                    /* копий на чужом приоритете */
    unsigned long wrong[RULE_COPIES_MAX];
    int legacy_n;                   /* прежняя форма без маски (см. rule_drop) */
    unsigned long legacy[RULE_COPIES_MAX];
};

struct rule_copies rule_copies_of(const char *rules, uint32_t mark, int table);

/* ---- прочее, что тест дёргает напрямую, в обход cmd_failover ----------------------- */
void active_get(const char *out, char *dev, size_t n);
int revive(const struct spec *sp, const struct output *o, const char *dev, int verbose);
void cleanup_probe_rule(void);
int device_healthy_for(const struct spec *sp, const struct output *o, const char *dev);
/* Швы здоровья/задержки: NULL в бою, стенд подставляет свою пробу — см. health_of в
 * failover.c. */
extern int (*g_health_probe)(const struct spec *, const struct output *, const char *);
extern int (*g_latency_probe)(const struct spec *, const struct output *, const char *);
/* Порог гистерезиса читает переменную окружения один раз и кэширует ответ — стенду нужно
 * менять её между проходами в одном процессе. */
void failover_hyst_reset_for_test(void);

/* Швы автомата прохода (failover.c, «ПРОХОД — КОНЕЧНЫЙ АВТОМАТ»). В бою все NULL; стенд
 * failovermatch ставит их, потому что ни ядра, ни сети, ни прав ему не дают:
 *   g_ip_show     — состояние ядра: table < 0 — правила (`ip -4 rule show`), иначе маршруты
 *                   таблицы (`ip -4 route show table N`), в out дословным текстом `ip`;
 *   g_icmp_probe  — проба ICMP устройства целиком (с правилом пробы): 1 — ответило;
 *   g_cmd_hook    — внешняя команда оживления (ifdown, ifup, ubus): «выполняется» сразу, код —
 *                   как у run_quiet;
 *   g_revive_step — длительность шага ожидания подъёма, мс (в бою — секунда): стенд считает
 *                   шаги и не ждёт их. */
extern int (*g_ip_show)(int table, char *out, size_t n);
extern int (*g_icmp_probe)(const char *dev);
extern int (*g_cmd_hook)(const char *const argv[]);
extern long (*g_revive_step)(void);

#endif
