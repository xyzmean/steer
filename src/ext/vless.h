/* Клиент VLESS/Reality для steer-extended.
 *
 * Отдельный пакет по той же логике, по которой в OpenWrt есть dnsmasq и dnsmasq-full:
 * базовому движку VLESS не нужен, а весит он вместе с TLS-стеком заметно больше самого
 * движка. Кто хочет — ставит extended, у кого туннели wireguard — не платит за это.
 *
 * Почему свой клиент, а не xray/sing-box: те бинарники — это клиент И сервер И два
 * десятка протоколов, 27–38 МБ. На роутере с 6.9 МБ overlay они не помещаются вовсе, а
 * нужен из них один клиентский путь.
 */
#ifndef STEER_VLESS_H
#define STEER_VLESS_H
#include <stdint.h>
#include <stddef.h>

/* Узел подписки. Строки, а не разобранные структуры: всё это едет в конфиг как есть, и
 * лишнее преобразование туда-обратно только добавило бы место для расхождения. */
struct vless_node {
    char name[128];        /* человеческое имя из #фрагмента, уже раскодированное */
    char host[128];
    uint16_t port;
    char uuid[64];
    char type[16];         /* tcp | grpc | xhttp */
    char security[16];     /* только reality имеет смысл */
    char sni[128];         /* маскировочный домен — он же SNI в ClientHello */
    char fp[16];           /* отпечаток браузера: chrome, firefox, qq… */
    char pbk[64];          /* публичный ключ сервера, base64url */
    char sid[32];          /* short id, hex */
    char flow[32];         /* xtls-rprx-vision или пусто */
    char path[128];        /* xhttp */
    char service[64];      /* grpc serviceName */
    char mode[16];         /* grpc: multi/gun; xhttp: auto/packet-up… */
    char skip_reason[64];  /* почему узел непригоден — чтобы это можно было показать */
};

size_t b64_decode(const char *in, size_t n, char *out, size_t out_n);

/* 0 — узел пригоден, 1 — пропущен (причина в skip_reason), -1 — не vless-ссылка. */
int vless_parse_url(const char *url, struct vless_node *n);

size_t vless_parse_sub(const char *text, struct vless_node *out, size_t max,
                       size_t *skipped, size_t *foreign);

#endif
