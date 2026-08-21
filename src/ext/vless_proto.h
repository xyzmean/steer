/* Протокол VLESS: заголовок запроса и разбор ответа. Подробности — в vless_proto.c. */
#ifndef STEER_VLESS_PROTO_H
#define STEER_VLESS_PROTO_H
#include <stdint.h>
#include <stddef.h>

#define VLESS_EAGAIN (-1)   /* данных пока мало, надо дочитать */
#define VLESS_EPROTO (-2)   /* ответ не по VLESS: скорее всего Reality нас не признал */

enum vless_cmd { VLESS_CMD_TCP = 1, VLESS_CMD_UDP = 2, VLESS_CMD_MUX = 3 };
enum { VLESS_ADDR_IPV4 = 1, VLESS_ADDR_DOMAIN = 2, VLESS_ADDR_IPV6 = 3 };

/* Форма идентификатора пользователя. Правило — из Xray (common/uuid/uuid.go,
 * ParseString), и оно про ДЛИНУ СТРОКИ, а не про то, похожа ли она на шестнадцатеричную.
 * Порядок здесь важен: строка из 15 шестнадцатеричных знаков у Xray ВЫВОДИТСЯ, а не
 * разбирается, и клиент, который решит иначе, отправит не те 16 байт — сервер такого
 * пользователя не найдёт и просто закроет соединение. */
enum {
    VLESS_UUID_HEX     =  1,   /* 32..36 знаков: шестнадцатеричный UUID, дефисы необязательны */
    VLESS_UUID_DERIVED =  2,   /* 1..30 знаков: UUID выводится из строки (sha1, версия 5) */
    VLESS_UUID_EMPTY   = -1,   /* пусто */
    VLESS_UUID_GAP     = -2,   /* ровно 31: для вывода длинно, для UUID коротко */
    VLESS_UUID_TOOLONG = -3,   /* длиннее 36 */
    VLESS_UUID_NOTHEX  = -4    /* длина как у UUID, но знаки не шестнадцатеричные */
};

/* Только классификация, без вычислений: нужна разбору подписки, чтобы непригодный узел
 * назвал причину человеческими словами и не попал в кандидаты. Текст причины живёт в
 * sub.c рядом с остальными — здесь только само правило. */
int vless_uuid_form(const char *s);

/* 16 байт идентификатора из текстовой формы. 0 — вышло, -1 — форма непригодна. */
int vless_uuid_parse(const char *s, unsigned char out[16]);

/* flow — имя потока (xtls-rprx-vision) или NULL/"" для обычного VLESS. */
size_t vless_build_request(const unsigned char uuid[16], enum vless_cmd cmd,
                           const char *host, const unsigned char ip4[4],
                           uint16_t port, const char *flow,
                           unsigned char *out, size_t cap);

int vless_parse_response(const unsigned char *buf, size_t n, size_t *skip);

#endif
