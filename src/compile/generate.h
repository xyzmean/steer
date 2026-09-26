#ifndef STEER_GENERATE_H
#define STEER_GENERATE_H

/* Компиляция набора групп в набор правил nftables (src/compile/generate.c): дерево (ir.h),
 * раскладка старого ядра (legacy.h) и печать (print.c). */

#include <stdio.h>
#include "groups.h"
#include "ir.h"
#include "legacy.h"

/* Дерево современной раскладки по спеке sp и её группам gr. 0 — успех; -1 — отказ
 * (недостижимо на разобранной спеке, кроме нехватки памяти), текст в e->msg — правило 5,
 * docs/architecture.md, раздел 2. Спека и группы — параметрами, правило 6. */
int nft_build(struct nft_rs *rs, const struct spec *sp, const struct groups *gr, struct err *e);
/* Текст ruleset в f: nft_build, legacy_rewrite по g_nftc, nft_print. На отказе в f не
 * пишется ничего. */
int generate(const struct spec *sp, const struct groups *gr, FILE *f, struct err *e);

/* Построители видов выхода — будущий kind_ops.emit (docs/architecture.md, «Вид выхода»):
 * дописывают в дерево то, что нужно одному выходу своего вида. */
void nft_emit_zapret(struct nft_rs *rs, const struct spec *sp, const struct output *o);
void nft_emit_tgws(struct nft_rs *rs, const struct spec *sp, const struct output *o);
/* Каналы на само устройство (plat()->local_channels, src/platform/platform.h): цепочки на хуке
 * output. Код — здесь, у компилятора; платформа только говорит, бывают ли такие каналы. */
int nft_emit_output_mark(struct nft_rs *rs, const struct spec *sp, const struct groups *gr,
                         struct err *e);
void nft_emit_output_dns(struct nft_rs *rs, const struct spec *sp, const struct groups *gr);

void counters_load(void);
int counter_find(const char *name, int down, unsigned long *p, unsigned long *b);
void l4_describe(const struct l4match *m, char *dst, size_t n);

#endif
