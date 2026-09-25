#ifndef STEER_DAEMON_H
#define STEER_DAEMON_H

/* Общий заголовок ядра steer: объявления, которые до нарезки src/daemon/steer.c на модули
 * (docs/architecture.md) были видны друг другу просто потому, что жили в одном файле. Формы
 * ровно те же, только "static" снят там, где вызов теперь идёт из другого файла. */

#include <stddef.h>

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
#ifndef STEER_ANDROID
void report_traceroute_dep(const struct spec *sp);
void report_output_deps(const struct spec *sp);
#endif

/* Путь снимка состояния status — снимает apply.c, пишет и отдаёт status.c. */
void status_snap_path(char *buf, size_t n);

/* Проверка формы адреса/имени перед подстановкой в командную строку nft — общая для main.c
 * (разбор аргумента explain) и diag.c/explain.c. */
int addr_ok(const char *a);
int looks_like_name(const char *s);

int cmd_apply(const char *spec, int dry);
int cmd_status(const char *spec, int fast);
int cmd_diag(const char *spec);
int cmd_down(void);
int cmd_supervise(const char *spec);
int cmd_explain(const char *spec, const char *what);
int failover_loop(const char *spec, int verbose, int period);

int cmd_failover(const char *spec, int verbose);   /* failover.c */
void probe_rule_cleanup(void);   /* failover.c */

#ifdef STEER_ANDROID
void android_masq_ensure(const struct spec *sp);
#endif

#endif
