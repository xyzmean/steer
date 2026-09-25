#include <stdio.h>
#include <stdlib.h>
#include "err.h"

/* Прежний немедленный отказ — оставлен для точек входа. Печатает ровно то же, что печатал
 * всегда: "steer: " + fmt%a + "\n" в stderr, потом exit(2). */
void die(const char *fmt, const char *a) {
    fprintf(stderr, "steer: ");
    fprintf(stderr, fmt, a);
    fputc('\n', stderr);
    exit(2);
}

/* Тот же текст, что собрал бы die(fmt, a) между "steer: " и "\n", — но в буфер, а не в stderr,
 * и без exit. snprintf, а не sprintf: буфер фиксирован (1024), и сообщение с длинной
 * подстановкой (например, путь из спеки) не должно переписать чужую память.
 *
 * noinline — НАРОЧНО, и не ради скорости. fmt здесь — параметр, не литерал, и сам по себе
 * анализу -Wformat-truncation не подлежит; но стенды, включающие исходники модели одним
 * #include (specmatch, dnsmatch, obfsmatch, awgmatch), собирают эту функцию в одной единице
 * трансляции с её вызывающими, и при инлайне компилятор протягивает КОНКРЕТНЫЙ литерал из
 * места вызова прямо в snprintf — тогда «выход %s: …» с непредсказуемым по длине именем
 * выхода выглядит как потенциальное усечение и попадает в предупреждение, хотя усечение здесь
 * ровно то поведение, ради которого snprintf (а не sprintf) и выбран. noinline держит границу
 * анализа там же, где raньше её держал fprintf(stderr, fmt, a) в die() — внутри одной функции,
 * которая просто передаёт fmt дальше, не зная его содержимого на этапе компиляции. */
__attribute__((noinline))
int err_set(struct err *e, const char *fmt, const char *a) {
    snprintf(e->msg, sizeof(e->msg), fmt, a);
    return -1;
}

void err_die(const struct err *e) {
    fprintf(stderr, "steer: %s\n", e->msg);
    exit(2);
}
