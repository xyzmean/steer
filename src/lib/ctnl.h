#ifndef STEER_CTNL_H
#define STEER_CTNL_H
#include <stdint.h>
#include <linux/netlink.h>

/* Общий разговор с ctnetlink (src/lib/ctnl.c): разбор атрибутов netlink (ct_attr/ct_attr_in),
 * сокет дампа/удаления (ctnl_socket) и обход одного дампа conntrack с обработчиком записи
 * (ctnl_dump). Резолвер строит на этом исходное назначение запроса (src/dnsd/origdst.c:
 * ct_origdst, её объявление — в dnsd_int.h, типы адреса там свои для резолвера), сторож —
 * снятие соединений выхода при смене маршрута (ctnl_evict_mark, определена в ctnl.c рядом,
 * объявлена в spec.h), список `steer conns` — src/daemon/conns.c. Этот файл не знает ни про
 * резолвер, ни про демон: он — нижний общий слой, который читают оба, а не наоборот. */

#define CTNL_RCVBUF 32768   /* больше части дампа ядро не шлёт: netlink_dump режет по 32 КиБ */

const struct nlattr *ct_attr(const uint8_t *p, const uint8_t *end, int type);
const struct nlattr *ct_attr_in(const struct nlattr *in, int type);

int ctnl_socket(void);

typedef int (*ctnl_rec_fn)(const uint8_t *a, const uint8_t *end, uint8_t family, void *ctx);
int ctnl_dump(int dfd, uint8_t family, int filter, uint32_t val, uint32_t mask,
              uint32_t *seq, uint8_t *buf, ctnl_rec_fn fn, void *ctx);

uint32_t ct_mark_of(const uint8_t *a, const uint8_t *end);

#endif
