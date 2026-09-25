#ifndef STEER_NFTQUERY_H
#define STEER_NFTQUERY_H

/* Мелкие запросы к живому ядру через nft/popen — общие для diag.c и explain.c
 * (src/daemon/nftquery.c). */

#include <stdint.h>

long set_count(const char *name);
int nft_has(const char *what);
int parse_prefix(const char *s, uint32_t *net, uint32_t *mask);
int ipv4_span(const char *t, uint32_t *lo, uint32_t *hi);

#endif
