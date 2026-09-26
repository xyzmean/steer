/* Состояние сторожа между проходами и события прохода — шов между логикой прохода (failover.c)
 * и тем, кто его крутит.
 *
 * ЗАЧЕМ ШОВ. Проход сторожа помнит между проходами четыре вещи: какое устройство несёт трафик
 * выхода и сколько тиков подряд ожило более предпочтительное (файл `active`), замеры задержки
 * (`latency`) и время последнего оживления каждого устройства (`restart-<устройство>`). Пока
 * сторожем был `steer failover` — один проход на процесс, — помнить было негде, кроме файлов
 * каталога состояния. Демон (шаг 3 устройства 1.8, docs/architecture.md, «4а») держит это в
 * памяти. Но до шага 6 на роутере и телефоне по-прежнему работают старые пути: procd и init
 * зовут `steer failover --loop`, а `steer status` подкомандой читает `active`. Поэтому проход
 * ОДИН — failover_pass, — а где лежит его память, решает тот, кто его зовёт:
 *
 *   `steer failover`, `--loop`, apply, status и diag подкомандой — fo_store_files: прежние
 *     файлы, байт в байт того же формата (его пишет и читает тот же код прохода);
 *   демон с `--watch` — хранилище в памяти (src/daemon/watchd.c).
 *
 * ХРАНИЛИЩЕ — ИМЕНОВАННЫЕ ТЕКСТЫ, а не поля. Запись — это ровно тот текст, что лежал бы в
 * файле с этим именем, и читает его тот же fscanf прохода, только из памяти (fmemopen). Так
 * «формат байт в байт тот же» — не обещание двух реализаций, а одна реализация: разбор и печать
 * не раздвоены, раздвоено только место. Имена: `active`, `latency`, `restart-<устройство>`.
 *
 * СОБЫТИЯ. Проход сообщает о переменах тому, кто его позвал: демон шлёт их подписчикам
 * управляющего сокета (switched, failed, revived — docs/ctl.md). У `steer failover` получателя
 * нет, и проход печатает то же, что печатал всегда. */
#ifndef STEER_FOSTATE_H
#define STEER_FOSTATE_H

#include <stdio.h>
#include <stddef.h>

#include "spec.h"

struct fo_store;
struct fo_store_ops {
    /* Открыть запись name на чтение. NULL — записи нет (как нет файла). */
    FILE *(*open_r)(struct fo_store *st, const char *name);
    /* Заменить запись целиком. Читатель видит либо прежний текст, либо новый. */
    void (*put)(struct fo_store *st, const char *name, const char *data, size_t n);
};
struct fo_store {
    const struct fo_store_ops *ops;
};

/* Файлы каталога состояния (steer_state_dir): прежний путь. */
extern struct fo_store fo_store_files;

/* События прохода. Строки живут до возврата из обратного вызова. */
enum fo_ev_kind {
    FO_EV_SWITCHED,   /* выход сменил устройство: from (NULL — не было), to, why */
    FO_EV_FAILED,     /* живых устройств нет, on_fail применён: from (NULL — не было), why */
    FO_EV_REVIVED,    /* сторож оживил устройство (перезапуск, перенастройка, ожидание), и оно ответило */
};
struct fo_event {
    enum fo_ev_kind kind;
    const char *out;
    const char *from, *to;
    /* switched: start — первый выбор (записи не было); recovered — выход был в отказе;
     *   spec — прежнее устройство больше не кандидат; down — прежнее не отвечает;
     *   preferred — более предпочтительное ожило и подтвердило здоровье (гистерезис);
     *   latency — выбор по замеру задержки.
     * failed: down — ни одно устройство не ответило; via — не работает выход, через который
     *   идёт этот. */
    const char *why;
    const char *on_fail;   /* режим отказа выхода: drop | direct | zapret */
};
typedef void (*fo_event_fn)(void *arg, const struct fo_event *e);

/* Один проход сторожа по спеке sp (разобранной, с метками реестра). sp меняется: device
 * каждого выхода — выбранное устройство. Память между проходами — st; ev (может быть NULL) —
 * получатель событий. Возврат — 0. */
int failover_pass(struct spec *sp, struct fo_store *st, int verbose, fo_event_fn ev, void *arg);

/* Перед проходом в отдельном процессе: снять правило пробы, оставшееся от прохода, убитого
 * SIGKILL, и снимать своё по SIGTERM/SIGINT (как `steer failover`). После прохода —
 * cleanup_probe_rule (то же объявление — в failover_int.h, для стенда). */
void failover_pass_guard(void);
void cleanup_probe_rule(void);

/* outputs_adopt_active (spec.h) по записи выбора из st, а не из файла. */
void outputs_adopt_active_st(struct spec *sp, struct fo_store *st);

#endif
