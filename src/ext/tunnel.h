/* Цикл туннеля: пакеты из TUN в потоки VLESS. Границы реализации — в tunnel.c. */
#ifndef STEER_TUNNEL_H
#define STEER_TUNNEL_H
#include "vless.h"

/* Больше MTU с запасом на заголовки VLESS и набивку Vision: кадр с длинной набивкой может
 * быть на 1400 байт больше самих данных. */
#define TUNNEL_BUF 8192

int tunnel_run(const char *dev, const struct vless_node *node);
#endif
