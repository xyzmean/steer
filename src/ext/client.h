/* Соединение с узлом VLESS/Reality и проверка «нас признали». Подробности — в client.c. */
#ifndef STEER_CLIENT_H
#define STEER_CLIENT_H
#include "vless.h"
#include "reality.h"
#include "tls13.h"

#define VLESS_CONN_EDNS      (-30)
#define VLESS_CONN_ESOCK     (-31)
#define VLESS_CONN_ECONNECT  (-32)
#define VLESS_CONN_EIO       (-33)
#define VLESS_CONN_ECLOSED   (-34)
#define VLESS_CONN_EBADUUID  (-35)
/* Reality не признал ключ: TLS установлен, но отвечает маскировочный сайт. Отдельный код,
 * потому что это единственная ошибка, которая иначе выглядит как рабочий узел. */
#define VLESS_CONN_EREJECTED (-36)

struct vless_conn {
    int fd;
    int plain;                 /* security=none: TLS нет вовсе */
    struct reality_state rst;
    struct tls13 tls;
};

int vless_connect(const struct vless_node *node, struct vless_conn *conn, int timeout_s);
int vless_probe(const struct vless_node *node, int timeout_s, char *why, size_t why_n);
void vless_close(struct vless_conn *c);
const char *vless_strerror(int rc);

#endif
