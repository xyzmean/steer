#ifndef STEER_CTNL_H
#define STEER_CTNL_H
#include <stdint.h>
#include <sys/socket.h>
#include "dnsd_int.h"

/* Исходное назначение запроса из conntrack, и вывод `steer conns` — обе половины разговора
 * с ctnetlink резолвера. Типы адреса (union dnsd_sa, struct dnsd_local) свои для резолвера,
 * поэтому этот заголовок includes dnsd_int.h, а не только сетевые заголовки. */
int ct_origdst(const struct sockaddr_storage *cli, const struct dnsd_local *local,
               int lport, union dnsd_sa *out, uint32_t *mark, int *have_mark);

#endif
