/* Apply-сверка демона: новая спека сравнивается с применённой по частям (устройство и доводы —
 * в шапке recon.c). */
#ifndef STEER_RECON_H
#define STEER_RECON_H

#include <stddef.h>
#include <stdint.h>

#include "spec.h"

/* Выход в плане: то, что apply ставит в ядро для него, свёрнутое в подписи. */
struct recon_out {
    char name[32];
    unsigned mark;
    int table;
    int routed;                     /* у выхода есть устройство: правило и таблица */
    int awg;                        /* kind=awg: устройство настраивает apply */
    unsigned long long rsig;        /* подпись маршрутизации */
    unsigned long long wsig;        /* подпись того, что читает сторож */
};

/* План новой спеки — вывод `steer apply-plan`. */
struct recon_plan {
    int nftc;
    unsigned long long fp;          /* отпечаток текста набора правил */
    size_t ch_n, out_n;
    struct recon_out out[MAX_OUTPUTS];
    size_t n;
    struct { unsigned mark; int table; } stale[MAX_OUTPUTS];
    size_t stale_n;
};

/* Что демон знает о применённом. valid=0 — ничего: следующий apply применяет всё, как
 * подкоманда. */
struct recon_state {
    int valid;
    unsigned long long fp;
    uint64_t handle;                /* номер таблицы в ядре после нашего nft -f; 0 — ядро не даёт */
    struct recon_out out[MAX_OUTPUTS];
    size_t n;
    /* Подписи сторожа — отдельно от применённого: их сверка нужна и тогда, когда в ядро ничего
     * не шло. */
    int wvalid;
    struct { char name[32]; unsigned long long wsig; } w[MAX_OUTPUTS];
    size_t wn;
    int nftc;                       /* раскладка из первого плана; -1 — ещё не знаем */
};

/* Решение: что применять. */
struct recon_diff {
    int ruleset;
    char route[MAX_OUTPUTS][32];
    size_t route_n;
    struct { unsigned mark; int table; } drop[2 * MAX_OUTPUTS];
    size_t drop_n;
    int awg, masq;
    int watch;                      /* сторожу внеочередной проход */
};

void recon_init(struct recon_state *st);
/* Разобрать вывод плана. 0 — годный. */
int recon_plan_parse(const char *text, size_t n, struct recon_plan *p);
/* Решить по плану и применённому. Состояние ядра (таблица на месте, та же ли) спрашивается здесь. */
void recon_decide(const struct recon_state *st, const struct recon_plan *p, struct recon_diff *d);
/* Есть ли что применять в ядро (набор правил или маршрутизация). */
int recon_diff_any(const struct recon_diff *d);
/* argv для `steer apply-commit` по решению: буферы — в buf (n байт), av — не меньше 20 мест. */
void recon_commit_argv(const struct recon_diff *d, const char *exe, const char *spec,
                       const char *state_dir, int nftc, char *buf, size_t n, char **av);
/* Применение прошло: запомнить план как применённое (ruleset — ставился ли набор правил). */
void recon_applied(struct recon_state *st, const struct recon_plan *p, const struct recon_diff *d);
/* Подписи сторожа по плану: 1 — изменились (или прежних нет). Запоминает новые. */
int recon_watch_changed(struct recon_state *st, const struct recon_plan *p);
/* Применённое больше не известно (движок выключен, применение не прошло). */
void recon_forget(struct recon_state *st);

/* Номер таблицы inet ИМЯ в ядре (NFT_MSG_GETTABLE по netlink, без запуска nft): 0 — есть, номер
 * в *h (0 — ядро номеров таблиц не отдаёт, до Linux 4.16); 1 — таблицы нет; -1 — не спросить. */
int recon_table_handle(const char *name, uint64_t *h);

#endif
