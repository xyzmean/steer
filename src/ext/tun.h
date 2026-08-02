/* TUN-устройство и разбор пакетов. Почему TUN, а не SOCKS — в tun.c. */
#ifndef STEER_TUN_H
#define STEER_TUN_H
#include <stdint.h>
#include <stddef.h>

#define TUN_ENODEV (-40)   /* нет /dev/net/tun — не установлен kmod-tun */
#define TUN_ESETUP (-41)

struct flow_key {
    uint32_t src, dst;      /* в сетевом порядке, как в пакете: так и уходят в tcp_build */
    /* Порты в ХОСТОВОМ порядке: ip_parse собирает их из байт вручную, то есть
     * преобразование уже сделано. Применять к ним ntohs — значит перевернуть дважды:
     * порт 80 превращался в 20480, соединение уходило не туда, и выглядело это как
     * «сервер не отвечает». Отсюда суффикс в имени — чтобы вопрос не возникал. */
    uint16_t sport, dport;
    uint8_t proto;
    uint8_t tcp_flags;
    uint32_t seq, ack;
};

/* Флаги TCP, которые нас интересуют. */
#define TCP_FIN 0x01
#define TCP_SYN 0x02
#define TCP_RST 0x04
#define TCP_PSH 0x08
#define TCP_ACK 0x10

int tun_open(const char *name);
int ip_parse(const unsigned char *p, size_t n, struct flow_key *k, size_t *payload_off);
size_t tcp_build(unsigned char *out, size_t cap,
                 uint32_t src, uint32_t dst, uint16_t sport, uint16_t dport,
                 uint32_t seq, uint32_t ack, unsigned char flags,
                 const unsigned char *data, size_t data_n, uint16_t window);
#endif
