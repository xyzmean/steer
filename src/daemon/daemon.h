#ifndef STEER_DAEMON_H
#define STEER_DAEMON_H

/* Общий заголовок ядра steer: объявления, которые до нарезки src/daemon/steer.c на модули
 * (docs/architecture.md) были видны друг другу просто потому, что жили в одном файле. Формы
 * ровно те же, только "static" снят там, где вызов теперь идёт из другого файла. */

#include <stddef.h>
#include <stdio.h>

struct spec;
struct groups;

/* Уровень в журнале — см. одноимённые макросы в failover.c и obfs.c. Метка подсистемы здесь
 * «apply»: строки с ней пишутся при компиляции и применении спеки. */
#define LOG_W "steer[warn] apply: "

struct fwcheck { int in_firewall, masqueraded; };

struct fwcheck fw_check(const char *device);
int report_mark_overlap(void);
/* Сброс кэша дампа ruleset (fwcheck.c) — только для tests/fwmatch.c: изображает свежий
 * процесс на каждую пробу, как в бою (короткоживущий CLI). */
void fwcheck_reset_cache(void);
/* Чем объяснять совпадение адреса — доменным списком, адресным или обоими (explain.c);
 * отдельной функцией ради стенда tests/fwmatch.c, см. её шапку там же. */
const char *explain_set_phrase(const char *addr, int has_files, int has_domains);
void report_traceroute_dep(const struct spec *sp);
void report_output_deps(const struct spec *sp);

/* Путь снимка состояния status — снимает apply.c, пишет и отдаёт status.c. */
void status_snap_path(char *buf, size_t n);

/* Проверка формы адреса/имени перед подстановкой в командную строку nft — общая для main.c
 * (разбор аргумента explain) и diag.c/explain.c. */
int addr_ok(const char *a);
int looks_like_name(const char *s);

/* Ответы status и explain — в поток, по спеке и группам, которые держит вызывающий: подкоманда
 * читает спеку сама, демон отдаёт свою из памяти (src/daemon/ctl.c). status_answer пишет и
 * снимок для --fast; status_fast — запомненный ответ (-1 — снимка нет). explain_emit
 * возвращает код подкоманды explain. */
void status_answer(const struct spec *sp, const struct groups *gr, FILE *out);
int status_fast(FILE *out);
int explain_emit(const struct spec *sp, const struct groups *gr, const char *what, FILE *out);

/* Соединения с меткой движка (дамп ctnetlink) — src/daemon/conns.c, тем же разговором с
 * ctnetlink, что у ctnl.c; журнал имён работающего резолвера отдаёт сам резолвер, dlog.c. Оба
 * печатают в поток: подкоманда — в stdout, демон — в память (src/daemon/ctl.c). */
int ctnl_conns_print(FILE *out);
int dlog_print(FILE *out);

int cmd_apply(const char *spec, int dry);
/* Служебные подкоманды демона для apply-сверки (apply.c, recon.c): план — проверки и отпечатки
 * частей без применения; применение — только названных частей. В справке их нет. */
int cmd_apply_plan(int argc, char **argv);
int cmd_apply_commit(int argc, char **argv);
int cmd_status(const char *spec, int fast);
int cmd_diag(const char *spec);
int cmd_down(void);
int cmd_supervise(const char *spec);
/* Поднимать ли резолвер (ответ needs-dnsd; supd.c) — им же решает супервизор демона (supd.c). */
int dnsd_wanted(void);
int cmd_explain(const char *spec, const char *what);
int failover_loop(const char *spec, int verbose, int period);
/* События сети для сторожа (watch.c): сокет netlink на RTMGRP_LINK и адреса IPv4/IPv6
 * (-1 — не открылся) и дочитать накопленное (1 — было хоть одно событие). Ими же пользуется
 * сторож демона (watchd.c). WATCH_SETTLE_S — сколько ждать после события до внеочередного
 * прохода: смена сети приходит пачкой, см. failover_loop. */
int watch_nl_open(void);
int watch_nl_drain(int fd);
#define WATCH_SETTLE_S 5
/* masquerade на телефоне сторож возвращает не на каждом проходе (watch.c, watch_masq_due). */
#define WATCH_MASQ_S 600
int watch_masq_due(long *last, int force);

int cmd_failover(const char *spec, int verbose);   /* failover.c */
void probe_rule_cleanup(void);   /* failover.c */

void iptables_masq_ensure(const struct spec *sp);   /* apply.c, plat()->iptables_masq */

#endif
