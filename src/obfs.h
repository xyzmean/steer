/* WireGuard поверх поддельного TCP — внешний интерфейс обфускатора.
 *
 * Разделено на две части нарочно. Сборка и разбор сегмента — чистые функции без сокетов
 * и без времени, поэтому их можно проверить стендом (tests/obfsmatch.c) без сети и без
 * прав root. Циклы клиента и сервера сокетов требуют, и проверяются они уже на живом
 * стенде — см. tests/obfsmatch.c про границу.
 */
#ifndef STEER_OBFS_H
#define STEER_OBFS_H
#include <stdint.h>
#include <stddef.h>

struct obfs_seg {
    uint32_t saddr, daddr;      /* сетевой порядок */
    uint16_t sport, dport;      /* хостовый порядок */
    uint32_t seq, ack;          /* хостовый порядок */
    uint8_t flags;
    const uint8_t *payload;
    size_t plen;
};

/* Собрать сегмент в buf (нужно 60 + 1600 байт), вернуть его длину. */
size_t obfs_build(uint8_t *buf, uint32_t saddr, uint32_t daddr,
                  uint16_t sport, uint16_t dport, uint32_t seq, uint32_t ack,
                  uint8_t flags, int with_mss, const void *payload, size_t plen);

/* Разобрать пакет с IP-заголовка. 0 — разобрано, -1 — не наше или битое. */
int obfs_parse(const uint8_t *pkt, size_t n, struct obfs_seg *s);

/* Контрольная сумма TCP с псевдозаголовком; на готовом сегменте даёт 0. */
uint16_t obfs_tcp_csum(uint32_t saddr, uint32_t daddr, const void *seg, size_t len);

/* Куда сдвинуть ack, приняв сегмент. Только вперёд, с учётом переполнения uint32. */
uint32_t obfs_next_ack(uint32_t have, uint32_t seq, size_t plen);

/* «адрес:порт» → адрес и порт. 0 — разобрано. */
int obfs_split_hostport(const char *s, char *host, size_t hn, int *port);

/* Циклы. Возвращают ненулевой код: выход из них — всегда отказ, подъём заново — дело
 * procd (клиент) или systemd (сервер). */
int obfs_client(const char *out_name, const char *server, int server_port,
                const char *listen_addr, int listen_port);
int obfs_server(int listen_port, const char *forward, int forward_port);

#endif
