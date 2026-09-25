/* Реестр видов выхода (kind.h).
 *
 * РЕЕСТР — ЭТО ТО, ЧТО ВОШЛО В СБОРКУ. Какие виды есть в бинарнике, решает профиль в
 * build/sources.mk: файл src/kinds/<вид>.c в профиле есть — вид есть. Реестр ссылается на
 * записи видов СЛАБО, поэтому файл вида, не вошедший в профиль, не ломает компоновку: его адрес
 * оказывается нулевым, и на его месте встаёт запись отказа — имя и одна строка `absent`. Так
 * отказ «kind vless требует пакет steer-extended» живёт в одном месте, и #ifdef для него не
 * нужен ни здесь, ни в разборе.
 *
 * Почему слабые ссылки, а не таблица, которую собирает сборка. Сгенерированный файл пришлось
 * бы порождать в трёх системах сборки (Makefile, сценарии образа, Soong в Android.bp), а у Soong
 * для этого нужен свой genrule — три копии одного знания, которые расходятся молча, то есть
 * ровно то, от чего избавлял единый манифест. Слабая ссылка — одно место и та же компоновка
 * объектов, которой собираются все пути (архивов .a здесь нет: при них слабая ссылка не
 * вытянула бы файл вида из архива, и вид пропал бы молча). Чтобы вид не выпал из профиля по
 * недосмотру, tests/buildmatch.sh сверяет: все файлы src/kinds, кроме видов расширенной части,
 * — в профиле base, а виды расширенной части — в extended и android.
 *
 * direct — единственный вид со СИЛЬНОЙ ссылкой: обнулённый выход читается как direct (kind_of
 * в spec.h), то есть без этой записи движок не значит ничего.
 *
 * Строки отказа базовых видов (interface, zapret, tgws, awg) в настоящей сборке недостижимы —
 * эти файлы входят в каждый профиль. Они нужны стендам, которые компонуют модель с частью видов,
 * и там отказ честнее падения. */
#include <string.h>

#include "spec.h"

extern const struct kind_ops kind_interface __attribute__((weak));
extern const struct kind_ops kind_vless __attribute__((weak));
extern const struct kind_ops kind_xsteer __attribute__((weak));
extern const struct kind_ops kind_zapret __attribute__((weak));
extern const struct kind_ops kind_tgws __attribute__((weak));
extern const struct kind_ops kind_awg __attribute__((weak));

/* Тексты — ровно те, что печатал разбор, пока отказ стоял в нём под #ifndef STEER_EXTENDED:
 * их сверяет снимок (tests/snapshot.sh), а подстроку «steer-extended» читает splify2 — по ней
 * он предлагает поставить полный пакет. Менять её нельзя. */
static const struct kind_ops no_interface = { .name = "interface", .absent = "kind interface в этой сборке нет" };
static const struct kind_ops no_vless     = { .name = "vless",  .absent = "kind vless требует пакет steer-extended" };
static const struct kind_ops no_xsteer    = { .name = "xsteer", .absent = "kind xsteer требует пакет steer-extended" };
static const struct kind_ops no_zapret    = { .name = "zapret", .absent = "kind zapret в этой сборке нет" };
static const struct kind_ops no_tgws      = { .name = "tgws",   .absent = "kind tgws в этой сборке нет" };
static const struct kind_ops no_awg       = { .name = "awg",    .absent = "kind awg в этой сборке нет" };

/* Порядок — прежний порядок видов (им же печатается справка о видах и идут проверки diag по
 * видам, см. cmd_diag). */
static const struct { const struct kind_ops *have, *none; } REG[] = {
    { &kind_direct,    NULL },
    { &kind_interface, &no_interface },
    { &kind_vless,     &no_vless },
    { &kind_xsteer,    &no_xsteer },
    { &kind_zapret,    &no_zapret },
    { &kind_tgws,      &no_tgws },
    { &kind_awg,       &no_awg },
};
#define REG_N (sizeof(REG) / sizeof(REG[0]))

size_t kind_count(void) { return REG_N; }

const struct kind_ops *kind_at(size_t i) {
    if (i >= REG_N) return NULL;
    return REG[i].have ? REG[i].have : REG[i].none;
}

const struct kind_ops *kind_by_name(const char *name) {
    for (size_t i = 0; i < REG_N; i++) {
        const struct kind_ops *k = kind_at(i);
        if (!strcmp(k->name, name)) return k;
    }
    return NULL;
}

void kind_sig_mix(unsigned long long *h, const void *p, size_t n) {
    const unsigned char *b = p;
    for (size_t i = 0; i < n; i++) { *h ^= b[i]; *h *= 1099511628211ULL; }
    *h ^= 0xff; *h *= 1099511628211ULL;   /* граница поля: «ab»+«c» не равно «a»+«bc» */
}
