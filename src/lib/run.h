#ifndef STEER_RUN_H
#define STEER_RUN_H

/* Запуск внешней команды с выброшенным выводом (src/lib/run.c). run_quiet экспортируется и
 * для failover.c, и для многих других файлов ядра — те держат собственное extern-объявление
 * (см. run.c) и не тронуты этим шагом; run.h нужен новым файлам ядра, разошедшимся со
 * steer.c при нарезке (apply.c, explain.c). */

int run(const char *const argv[]);
int run_quiet(const char *const argv[]);

#endif
