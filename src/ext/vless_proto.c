/* Протокол VLESS: заголовок запроса и разбор ответа.
 *
 * VLESS намеренно примитивен — в этом его смысл. Никакого своего шифрования и никаких
 * контрольных сумм: всё это уже сделал TLS снизу, и дублировать значило бы добавить
 * отличимый признак в поток, который должен выглядеть обычным HTTPS.
 *
 * Запрос:
 *   версия(1) | UUID(16) | длина_доп(1) | доп | команда(1) | порт(2) | тип_адреса(1) |
 *   адрес | данные...
 *
 * Ответ сервера — два байта (версия, длина_доп) плюс доп, дальше сразу данные.
 */
#define _GNU_SOURCE
#include <string.h>
#include <stdio.h>
#include <arpa/inet.h>

#include "vless_proto.h"

/* UUID из текстовой формы. Дефисы игнорируются: панели пишут и с ними, и без. */
int vless_uuid_parse(const char *s, unsigned char out[16]) {
    size_t o = 0;
    int hi = -1;
    for (const char *p = s; *p; p++) {
        if (*p == '-') continue;
        int v;
        if (*p >= '0' && *p <= '9') v = *p - '0';
        else if ((*p | 32) >= 'a' && (*p | 32) <= 'f') v = (*p | 32) - 'a' + 10;
        else return -1;
        if (hi < 0) hi = v;
        else {
            if (o >= 16) return -1;
            out[o++] = (unsigned char)((hi << 4) | v);
            hi = -1;
        }
    }
    return (o == 16 && hi < 0) ? 0 : -1;
}

/* Заголовок запроса. Адрес передаётся ИМЕНЕМ, когда оно известно: так разрешение имени
 * делает сервер, и запрос не утекает наружу через локальный DNS. Для трафика из TUN имени
 * нет — там уже адрес, и передаётся он как адрес. */
size_t vless_build_request(const unsigned char uuid[16], enum vless_cmd cmd,
                           const char *host, const unsigned char ip4[4],
                           uint16_t port, unsigned char *out, size_t cap) {
    size_t i = 0;
    if (cap < 24) return 0;
    out[i++] = 0;                       /* версия протокола */
    memcpy(out + i, uuid, 16); i += 16;
    out[i++] = 0;                       /* длина дополнительных данных: их нет */
    out[i++] = (unsigned char)cmd;
    out[i++] = (unsigned char)(port >> 8);
    out[i++] = (unsigned char)port;

    if (host && host[0]) {
        size_t hl = strlen(host);
        if (hl > 255 || i + 2 + hl > cap) return 0;
        out[i++] = VLESS_ADDR_DOMAIN;
        out[i++] = (unsigned char)hl;
        memcpy(out + i, host, hl); i += hl;
    } else {
        if (i + 5 > cap) return 0;
        out[i++] = VLESS_ADDR_IPV4;
        memcpy(out + i, ip4, 4); i += 4;
    }
    return i;
}

/* Ответ: версия + длина доп. Возвращает число байт, которые надо отбросить перед
 * данными, или отрицательное при неверном ответе.
 *
 * Неверный ответ здесь — важный сигнал: если Reality не признал нас, сервер проксирует
 * на настоящий сайт, и первым, что придёт, будет HTTP или TLS-мусор, а не VLESS. Значит
 * именно эта проверка и отличает «получилось» от «молча не получилось». */
int vless_parse_response(const unsigned char *buf, size_t n, size_t *skip) {
    if (n < 2) return VLESS_EAGAIN;
    if (buf[0] != 0) return VLESS_EPROTO;      /* не наша версия — почти наверняка чужой сайт */
    size_t extra = buf[1];
    if (n < 2 + extra) return VLESS_EAGAIN;
    *skip = 2 + extra;
    return 0;
}
