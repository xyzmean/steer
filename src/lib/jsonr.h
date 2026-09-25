#ifndef STEER_JSONR_H
#define STEER_JSONR_H
#include <stddef.h>

/* Отказ вызывающему: печатает и exit(2). Сама не здесь (пока в src/model/parse.c) — джейсон-ридер
 * о спеке не знает ничего, но громкий отказ на негодном тексте ему всё равно нужен. */
void die(const char *fmt, const char *a);

/* ---- a JSON reader small enough to audit ---------------------------------- */
/* Deliberately not a general parser: it walks the document the shape of the spec
 * demands and refuses anything else. A router config that compiles into firewall
 * rules should fail loudly on an unexpected shape rather than guess — which is the
 * same reason the spec is JSON and not YAML. */
struct js { const char *p; };

void js_ws(struct js *j);
int js_lit(struct js *j, char c);
long js_hex4(const char *p);
size_t js_uesc(const char **pp, char out[4]);
int js_str(struct js *j, char *buf, size_t n);
long js_num(struct js *j);
void js_skip(struct js *j);
const char *keep(const char *s);
size_t str_list(struct js *j, const char **dst, size_t max);
int str_array(struct js *j, char dst[][64], size_t max, size_t *n);
int num_array(struct js *j, int *dst, size_t max, size_t *n);

#endif
