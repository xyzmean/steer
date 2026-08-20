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

/* Причины непригодности, сгруппированные по тексту причины.
 *
 * Группировка здесь, а не в интерфейсе: подписка, целиком собранная из узлов с
 * неподдержанным security, даёт 26 одинаковых строк, и гонять их по ubus ради того,
 * чтобы свернуть на экране, незачем. Отдельного кода причины нет намеренно — текст уже
 * содержит и класс («транспорт X не поддержан»), и само значение, а код был бы вторым
 * способом сказать то же самое, который со временем разойдётся с первым. */
#define VLESS_SKIP_REASONS 8

struct vless_skip {
    char reason[64];       /* та же строка, что легла бы в vless_node.skip_reason */
    char example[144];     /* имя ПЕРВОГО узла с этой причиной, иначе host:port.
                            * Длиннее name[128] намеренно: во второй форме сюда влезает
                            * host целиком плюс ":65535", а обрезанный хост в объяснении
                            * хуже, чем его отсутствие. */
    size_t count;
};

/* Итог разбора подписки: сколько узлов пригодно — возвращаемое значение, всё остальное
 * здесь, с объяснением. До запуска 45 отсюда наружу шли только два числа, и человек с
 * подпиской из одних tls-узлов видел «пригодно 0, пропущено 26» без причины, хотя
 * причина у движка была в руках (splicicd#16, вариант А). */
struct vless_sub_stats {
    size_t skipped;                              /* непригодных ссылок vless:// */
    size_t foreign;                              /* ссылок чужих протоколов */
    size_t reasons_n;                            /* сколько РАЗНЫХ причин собрано */
    size_t reasons_dropped;                      /* узлов, чья причина не влезла */
    struct vless_skip reasons[VLESS_SKIP_REASONS];
};

/* st допускает NULL: подъёму туннеля счётчики не нужны. */
size_t vless_parse_sub(const char *text, struct vless_node *out, size_t max,
                       struct vless_sub_stats *st);

#endif
