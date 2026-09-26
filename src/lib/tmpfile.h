#ifndef STEER_TMPFILE_H
#define STEER_TMPFILE_H
#include <stddef.h>

/* Шаблон временного файла для mkstemp: <tmp_dir платформы>/<stem>.XXXXXX. Каталог создаётся, если
 * его нет: на роутере /tmp есть всегда и mkdir ничего не делает, а на телефоне tmp внутри
 * /data/misc/steer появляется только при первом запуске — и первый apply без этой строки
 * отказал бы «cannot create a temporary ruleset». Определена в spec.c. */
void steer_tmp_template(char *dst, size_t n, const char *stem);

#endif
