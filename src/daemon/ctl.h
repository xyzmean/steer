/* Управляющий сокет движка: демон (`steer daemon`, прежнее имя `steer ctl-serve`) и клиент для
 * отладки (`steer ctl`).
 *
 * Протокол, доводы и пределы описаны в шапке src/daemon/ctl.c и в docs/ctl.md; здесь только точки
 * входа. Обе команды разбирают свои аргументы сами (passthru в таблице cli.c): их флаги —
 * путь сокета, допущенные uid и домен — больше никому в движке не нужны, и заводить их в общую
 * таблицу флагов значило бы показывать в справке к apply то, что к ней не относится. */
#ifndef STEER_CTL_H
#define STEER_CTL_H

#include <stdio.h>

int ctl_serve_main(int argc, char **argv);
int ctl_client_main(int argc, char **argv);
void ctl_usage_flags(FILE *out);

#endif
