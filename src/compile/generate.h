#ifndef STEER_GENERATE_H
#define STEER_GENERATE_H

/* Компиляция набора групп в текст правил nftables (src/compile/generate.c). */

#include <stdio.h>
#include "groups.h"

/* Раскладка набора правил этого запуска — флаги NFTC_* из nft_compat (spec.h). Ставит
 * cmd_apply перед генерацией; читают и apply.c (report_legacy_gaps), и diag.c, и explain.c —
 * подробно у объявления в generate.c. */
extern int g_nftc;
#define NFT_LEGACY (g_nftc & NFTC_LEGACY)

/* 0 — успех, текст ruleset записан в f; -1 — отказ (недостижимо на разобранной спеке, см.
 * определение), текст в e->msg — см. правило 5, docs/architecture.md, раздел 2. Читает
 * спеку sp — правило 6. */
int generate(const struct spec *sp, FILE *f, struct err *e);
void counters_load(void);
int counter_find(const char *name, int down, unsigned long *p, unsigned long *b);
void l4_describe(const struct l4match *m, char *dst, size_t n);
int legacy_has_ip(const struct spec *sp);
int legacy_has_ip6(void);
int legacy_may_have_static(const struct group *g);

#endif
