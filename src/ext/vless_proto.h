/* Протокол VLESS: заголовок запроса и разбор ответа. Подробности — в vless_proto.c. */
#ifndef STEER_VLESS_PROTO_H
#define STEER_VLESS_PROTO_H
#include <stdint.h>
#include <stddef.h>

#define VLESS_EAGAIN (-1)   /* данных пока мало, надо дочитать */
#define VLESS_EPROTO (-2)   /* ответ не по VLESS: скорее всего Reality нас не признал */

enum vless_cmd { VLESS_CMD_TCP = 1, VLESS_CMD_UDP = 2, VLESS_CMD_MUX = 3 };
enum { VLESS_ADDR_IPV4 = 1, VLESS_ADDR_DOMAIN = 2, VLESS_ADDR_IPV6 = 3 };

int vless_uuid_parse(const char *s, unsigned char out[16]);

/* flow — имя потока (xtls-rprx-vision) или NULL/"" для обычного VLESS. */
size_t vless_build_request(const unsigned char uuid[16], enum vless_cmd cmd,
                           const char *host, const unsigned char ip4[4],
                           uint16_t port, const char *flow,
                           unsigned char *out, size_t cap);

int vless_parse_response(const unsigned char *buf, size_t n, size_t *skip);

#endif
