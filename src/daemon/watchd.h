/* Сторож выходов в демоне (`steer daemon --watch`) — устройство и доводы в шапке watchd.c. */
#ifndef STEER_WATCHD_H
#define STEER_WATCHD_H

struct steerd;
struct watchd;

struct watchd_conf {
    int period_s;                /* период прохода в тишине, секунд */
    /* Включён ли движок (выключатель телефона). NULL — всегда. Выключен — проход не идёт:
     * демон работает и при выключенном движке, а трогать маршрутизацию тогда нельзя. */
    int (*enabled)(void);
    /* Идёт изменяющая команда (apply, reload): проход откладывается — он и apply пишут одни и те
     * же правила и таблицы. NULL — не спрашивать. */
    int (*busy)(void *arg);
    void *busy_arg;
};

/* Завести сторожа: первый проход — сразу, дальше по периоду и по событиям сети. Память выходов
 * — в d->outs. NULL — не вышло (причина в журнале). */
struct watchd *watchd_start(struct steerd *d, const struct watchd_conf *c);
/* Спека в памяти демона сменилась (apply, reload, SIGHUP): внеочередной проход. */
void watchd_spec_changed(struct watchd *w);
/* Демон уходит: идущему проходу — SIGTERM (он снимет правило пробы). */
void watchd_stop(struct watchd *w);

#endif
