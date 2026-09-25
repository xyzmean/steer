#ifndef STEER_LEGACY_H
#define STEER_LEGACY_H

/* Раскладка набора правил для nftables старого ядра (Linux 4.9) — src/compile/legacy.c.
 * Чего там нет и почему — у NFTC_* в nftcompat.h. */

#include "spec.h"
#include "groups.h"
#include "ir.h"

/* Раскладка набора правил этого запуска — флаги NFTC_* из nft_compat. Ставит cmd_apply
 * перед генерацией; читают и apply.c (report_legacy_gaps), и diag.c, и explain.c — ноль
 * значит современное ядро. */
extern int g_nftc;
#define NFT_LEGACY (g_nftc & NFTC_LEGACY)

/* Переделать дерево современной раскладки (generate.c, nft_build) в раскладку старого ядра
 * по флагам nftc. Дерево без NFTC_LEGACY не трогается. 0 — успех, -1 — отказ памяти. */
int legacy_rewrite(struct nft_rs *rs, const struct spec *sp, int nftc, struct err *e);

/* Какие таблицы, кроме inet, есть в старой раскладке этого запуска (g_nftc). */
int legacy_has_ip(const struct spec *sp);
int legacy_has_ip6(void);
/* Может ли у доменной группы быть статическая половина набора («<имя>_n») в ядре — для
 * читателей ядра, diag и explain. */
int legacy_may_have_static(const struct group *g);

#endif
