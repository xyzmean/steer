/* Общий каркас юнит-стендов: счётчики, check()/check_str()/check_mem()/check_hex() и единый
 * итог (docs/architecture.md, раздел 4: «юнит-стенды на модуль: модуль линкуется со стендом
 * сам, без #include чужого .c и setjmp»).
 *
 * ОТКУДА ЭТОТ ФАЙЛ. Проверялось, что тридцать пять стендов держат СВОЮ копию check() —
 * семнадцать из них с одной и той же подписью, и девять — с буквально одинаковым телом.
 * Разошлись остальные не зря: другая ширина колонки, другая формулировка отказа, другой
 * порядок аргументов, сравнение подстрокой вместо равенства — это не опечатка одного и того
 * же кода, а другая проверка под тем же именем. Поэтому в unit.h переехали ТОЛЬКО те check(),
 * которые совпадали побайтно; стенд, чей вариант отличается хоть чем-то, свою копию не отдаёт
 * — иначе FAIL-строка стала бы менее информативной для кого-то из них молча.
 *
 * ПРАВИЛО ДЛЯ НОВОГО СТЕНДА. Модуль, который стенд проверяет, — отдельный .c, слинкованный
 * Makefile'ом (MODEL_SRC/DNSD_SRC и другие списки, build/sources.mk), а не включённый текстом
 * через #include "../src/....c". #include чужого .c сваривает две единицы трансляции в одну:
 * static-имена одного файла тихо становятся видны другому (там, где стенд специально этим
 * пользуется — снятое static имя из внутреннего заголовка модуля, а не случайная видимость),
 * а настоящая сборка линкует их как отдельные объекты и может не найти неопределённую ссылку,
 * которую такой стенд не ловит вовсе — до релиза. Стенд подключает "unit.h", проверяет через
 * check()/check_str()/check_mem()/check_hex() и завершает main() строкой
 * `return unit_done("имя_стенда");`.
 *
 * Протокольные и туннельные стенды (каталоги src/proto, src/tunnel) unit.h использовать не
 * обязаны: там #include исходника — отдельный вопрос, вне этого шага. */
#ifndef STEER_TESTS_UNIT_H
#define STEER_TESTS_UNIT_H

#include <stdint.h>
#include <stdio.h>
#include <string.h>

static int unit_pass, unit_fail;

static inline void check(const char *what, long want, long got) {
    printf("%-62s %s\n", what, want == got ? "ok" : "ПРОВАЛ");
    if (want == got) { unit_pass++; return; }
    unit_fail++;
    printf("     хочу: %ld\n     есть:  %ld\n", want, got);
}

static inline void check_str(const char *what, const char *want, const char *got) {
    printf("%-62s %s\n", what, strcmp(want, got) == 0 ? "ok" : "ПРОВАЛ");
    if (strcmp(want, got) == 0) { unit_pass++; return; }
    unit_fail++;
    printf("     хочу: \"%s\"\n     есть:  \"%s\"\n", want, got);
}

static inline void check_mem(const char *what, const void *want, const void *got, size_t n) {
    int eq = memcmp(want, got, n) == 0;
    printf("%-62s %s\n", what, eq ? "ok" : "ПРОВАЛ");
    if (eq) { unit_pass++; return; }
    unit_fail++;
    printf("     хочу:");
    for (size_t i = 0; i < n; i++) printf(" %02x", ((const uint8_t *)want)[i]);
    printf("\n     есть: ");
    for (size_t i = 0; i < n; i++) printf(" %02x", ((const uint8_t *)got)[i]);
    printf("\n");
}

/* want — уже в виде hex-строки (нижним регистром, без разделителей), b/n — сырые байты. */
static inline void check_hex(const char *what, const char *want, const uint8_t *b, size_t n) {
    char got[160];
    for (size_t i = 0; i < n; i++) sprintf(got + i * 2, "%02x", b[i]);
    printf("%-62s %s\n", what, strcmp(want, got) == 0 ? "ok" : "ПРОВАЛ");
    if (strcmp(want, got) == 0) { unit_pass++; return; }
    unit_fail++;
    printf("     хочу: %s\n     есть:  %s\n", want, got);
}

static inline int unit_done(const char *name) {
    printf("\n%s: %d passed, %d failed\n", name, unit_pass, unit_fail);
    return unit_fail ? 1 : 0;
}

#endif
