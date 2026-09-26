/* Состояние демона steerd — то, что он держит в памяти между запросами.
 *
 * Шаг 2 устройства 1.8 (docs/architecture.md, «4а»): спека и группы, прочитанные при старте и
 * перечитанные после apply/reload, пути, с которыми демон запущен, и подписчики событий. Шаг 3
 * добавил память сторожа (outs); шаги 4-5 добавят таблицу детей и применённый ruleset — полями
 * этой же структуры, а не глобалами.
 *
 * ПОЧЕМУ СПЕКА В ПАМЯТИ ДАЁТ ТОТ ЖЕ ОТВЕТ, ЧТО ПОДКОМАНДА. `steer status` читает спеку заново
 * на каждый вызов; демон — при старте и после apply/reload. Спеку на диске меняет только сам
 * демон (apply через сокет) или человек руками — и тогда он говорит reload (или SIGHUP), как
 * говорил резолверу и супервизору. Всё, что меняется БЕЗ спеки (устройство, выбранное
 * сторожем, счётчики, реестр меток), status по-прежнему читает на каждый вызов.
 *
 * ПОДПИСЧИКИ. Событие — строка JSON {"v":1,"ev":"<имя>",…}\n, одна на событие. Кто её
 * доставляет и как (сокет, очередь с пределом, отключение медленного), знает подписчик сам —
 * здесь только список и рассылка. Новое событие (switched, helper-up, helper-down, node —
 * шаги 3-4) — это вызов steerd_emit в том месте, где оно случилось; ни механизм, ни
 * подписчиков трогать не нужно. */
#ifndef STEER_STATE_H
#define STEER_STATE_H

#include <stddef.h>

#include "spec.h"
#include "groups.h"

struct loop;
struct steerd_sub;
struct fo_store;
struct supd;
struct watchd;

/* Доставить подписчику готовую строку события (с '\n'). Подписчик вправе отписаться прямо
 * из этого вызова (steerd_sub_del самого себя) — рассылка к этому готова. */
typedef void (*steerd_sink)(struct steerd_sub *s, const char *line, size_t n);

struct steerd_sub {
    struct steerd_sub *next;
    steerd_sink push;
    void *arg;
};

struct steerd {
    struct loop *loop;
    const char *spec_path;
    const char *state_dir;           /* NULL — путь платформы */

    /* Спека и группы в памяти. have — спека прочитана хоть раз; иначе err — почему нет
     * (тот же текст, что напечатал бы `steer status`, — отдаётся вместо ответа). Группы
     * ссылаются на строки своей спеки, поэтому меняются только парой. */
    struct spec *sp;
    struct groups *gr;
    int have;
    char err[1024];
    char fp[17];                     /* отпечаток файла спеки: FNV-1a 64, шестнадцатерично */
    /* Рабочая копия спеки для ответа status: outputs_adopt_active переписывает устройство
     * выхода по выбору сторожа, и делать это с самой спекой значило бы однажды не вернуть
     * основное устройство, когда сторож вернулся на него. */
    struct spec *view;

    struct steerd_sub *subs;
    size_t subs_n;

    /* Память сторожа между проходами: активное устройство и серия, замеры задержки, время
     * последнего оживления (fostate.h). Заводит её сторож демона (watchd.c, `--watch`); без него
     * NULL, и status берёт выбор устройств из файла `active`, который пишет `failover --loop`. */
    struct fo_store *outs;

    /* Дети демона — помощники выходов и резолвер (helpers.h, supd.c, `--supervise`); без него
     * NULL, и помощников держат прежние супервизоры (procd, `steer supervise`). */
    struct supd *sup;

    /* Сторож демона (watchd.c, `--watch`); NULL — без него. Супервизор будит его на смене
     * состояния помощника: помощник упал или поднялся — внеочередной проход. */
    struct watchd *watch;
};

/* Выделить спеку и группы (они большие — в куче, не на стеке). 0 — готово. */
int steerd_init(struct steerd *d, struct loop *l, const char *spec_path, const char *state_dir);

/* Прочитать спеку с диска в память: load_spec, registry_assign, build_groups — как делает
 * `steer status`. Удалось — новая пара заменяет прежнюю, отпечаток обновлён, 0. Нет — прежняя
 * пара остаётся (демон продолжает отвечать по последней годной спеке), текст отказа — в
 * d->err, -1. Самая первая неудача (при старте) оставляет have=0. */
int steerd_load(struct steerd *d);

/* Подписчики. */
void steerd_sub_add(struct steerd *d, struct steerd_sub *s);
void steerd_sub_del(struct steerd *d, struct steerd_sub *s);

/* Разослать событие ev всем подписчикам. fields — остальные поля объекта, уже в JSON, с
 * запятой впереди (",\"spec\":\"…\""), или NULL. Строка собирается один раз. */
void steerd_emit(struct steerd *d, const char *ev, const char *fields);

/* Строку s — в JSON-строку (с кавычками) в buf; обрезается по размеру buf целым символом. */
void steerd_json_str(char *buf, size_t n, const char *s);

#endif
