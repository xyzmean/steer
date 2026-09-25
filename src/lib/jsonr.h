#ifndef STEER_JSONR_H
#define STEER_JSONR_H
#include <stddef.h>
#include "err.h"

/* ---- a JSON reader small enough to audit ---------------------------------- */
/* Deliberately not a general parser: it walks the document the shape of the spec
 * demands and refuses anything else. A router config that compiles into firewall
 * rules should fail loudly on an unexpected shape rather than guess — which is the
 * same reason the spec is JSON and not YAML.
 *
 * Отказ — ЧЕРЕЗ struct err, а не die(): джейсон-ридер часть модели (правило 5, раздел 2
 * docs/architecture.md), и завершает процесс только вызывающий, который дошёл до точки
 * входа. Каждая функция, которая может отказать, возвращает -1 (или свой признак отказа —
 * str_list/keep возвращают указатель/размер) и, если сама знает текст сообщения, кладёт его
 * в e->msg; вызывающий либо пробрасывает уже готовое сообщение (err_prop), либо, если e->msg
 * пусто, формирует своё — так же, как раньше решал, каким текстом позвать die(). */
struct js { const char *p; };

void js_ws(struct js *j);
int js_lit(struct js *j, char c);
long js_hex4(const char *p);
size_t js_uesc(const char **pp, char out[4]);
int js_str(struct js *j, char *buf, size_t n, struct err *e);
int js_num(struct js *j, long *out, struct err *e);
int js_skip(struct js *j, struct err *e);
const char *keep(const char *s, struct err *e);
/* (size_t)-1 — отказ, текст уже в e->msg (переполнение элемента, предел списка или висящая
 * запятая — все три сами знают, что сказать). Иначе — как раньше: сколько строк прочитано,
 * включая мягкую остановку на первом нестроковом элементе (не отказ, см. определение). */
size_t str_list(struct js *j, const char **dst, size_t max, struct err *e);
int str_array(struct js *j, char dst[][64], size_t max, size_t *n, struct err *e);
int num_array(struct js *j, int *dst, size_t max, size_t *n, struct err *e);

#endif
