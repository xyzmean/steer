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

/* SHA-1 короткого сообщения — только для ВЫВОДА идентификатора (см. ниже).
 *
 * Почему своя реализация, а не mbedtls, которой линкуется вся расширенная сборка. Две
 * причины, и обе проверяемые:
 *
 *   1. SHA-1 в mbedtls этого проекта НЕ СОБИРАЕТСЯ. Библиотека компилируется с урезанной
 *      конфигурацией src/ext/steer_mbedtls_config.h, где включены SHA-256/384/512 и нет
 *      MBEDTLS_SHA1_C: вызов mbedtls_sha1 не скомпоновался бы, а включать в прошивку
 *      целый модуль ради одного вызова при overlay в 6,9 МБ незачем.
 *   2. vless_proto.c — арифметика формата, без библиотек, и именно поэтому его вместе с
 *      sub.c проверяет стенд из обычного `make test`, где mbedtls нет по построению
 *      (R-014). Утащив сюда криптобиблиотеку, мы вынесли бы проверку вывода
 *      идентификатора в релизную сборку, то есть туда, где её никто не гоняет.
 *
 * «Не пиши свою криптографию» здесь не нарушено по существу: SHA-1 работает не как
 * защита, а как ФИКСИРОВАННАЯ функция вывода — те же 16 байт обязан получить сервер, и
 * ошибка не «тихо перестаёт защищать», а сразу отбрасывает пользователя. Реализация
 * прибита к опубликованному вектору NIST («abc») в tests/submatch.c.
 *
 * Сообщение здесь ВСЕГДА короче блока: 16 нулевых байт плюс не больше 30 знаков строки,
 * то есть максимум 46 байт. Поэтому набивка укладывается в один блок 64 байта, и цикла по
 * блокам с накоплением состояния нет вовсе — самой частой ошибки в самодельных хэшах
 * (склейка блоков и перенос длины) здесь просто нет места. На большем — отказ. */
static int sha1_short(const unsigned char *msg, size_t n, unsigned char out[20]) {
    unsigned char b[64];
    uint32_t w[80], h[5] = { 0x67452301u, 0xEFCDAB89u, 0x98BADCFEu,
                             0x10325476u, 0xC3D2E1F0u };
    if (n > 55) return -1;              /* 55 = 64 - 1 байт набивки - 8 байт длины */
    memset(b, 0, sizeof(b));
    memcpy(b, msg, n);
    b[n] = 0x80;
    uint64_t bits = (uint64_t)n * 8;
    for (int i = 0; i < 8; i++) b[63 - i] = (unsigned char)(bits >> (8 * i));

    for (int i = 0; i < 16; i++)
        w[i] = (uint32_t)b[4 * i] << 24 | (uint32_t)b[4 * i + 1] << 16 |
               (uint32_t)b[4 * i + 2] << 8 | (uint32_t)b[4 * i + 3];
    for (int i = 16; i < 80; i++) {
        uint32_t v = w[i - 3] ^ w[i - 8] ^ w[i - 14] ^ w[i - 16];
        w[i] = (v << 1) | (v >> 31);
    }

    uint32_t a = h[0], bb = h[1], c = h[2], d = h[3], e = h[4];
    for (int i = 0; i < 80; i++) {
        uint32_t f, k;
        if (i < 20)      { f = (bb & c) | (~bb & d);              k = 0x5A827999u; }
        else if (i < 40) { f = bb ^ c ^ d;                        k = 0x6ED9EBA1u; }
        else if (i < 60) { f = (bb & c) | (bb & d) | (c & d);     k = 0x8F1BBCDCu; }
        else             { f = bb ^ c ^ d;                        k = 0xCA62C1D6u; }
        uint32_t t = ((a << 5) | (a >> 27)) + f + e + k + w[i];
        e = d; d = c; c = (bb << 30) | (bb >> 2); bb = a; a = t;
    }
    h[0] += a; h[1] += bb; h[2] += c; h[3] += d; h[4] += e;

    for (int i = 0; i < 5; i++) {
        out[4 * i]     = (unsigned char)(h[i] >> 24);
        out[4 * i + 1] = (unsigned char)(h[i] >> 16);
        out[4 * i + 2] = (unsigned char)(h[i] >> 8);
        out[4 * i + 3] = (unsigned char)h[i];
    }
    return 0;
}

static int hexval(char c) {
    if (c >= '0' && c <= '9') return c - '0';
    if ((c | 32) >= 'a' && (c | 32) <= 'f') return (c | 32) - 'a' + 10;
    return -1;
}

/* Группы 8-4-4-4-12, как в Xray: перед каждой группой допускается ОДИН дефис, внутри —
 * только шестнадцатеричные знаки. out допускает NULL: тогда идёт одна проверка.
 *
 * Хвост после последней группы Xray не смотрит вовсе — длину он уже ограничил 36 байтами,
 * и строка вида «32 знака hex плюс 4 любых» у него разбирается по первым 32. Здесь так же,
 * и это осознанно: строгость в эту сторону означала бы, что steer бракует ссылку, с
 * которой любой другой клиент подключается, — а расхождение с сервером она не создаёт,
 * потому что сервер нашу строку не видит. */
static int hex_groups(const char *s, size_t n, unsigned char *out) {
    static const size_t groups[5] = { 8, 4, 4, 4, 12 };
    size_t i = 0, o = 0;
    for (int g = 0; g < 5; g++) {
        if (i < n && s[i] == '-') i++;
        if (n - i < groups[g]) return -1;
        for (size_t k = 0; k < groups[g]; k += 2) {
            int hi = hexval(s[i + k]), lo = hexval(s[i + k + 1]);
            if (hi < 0 || lo < 0) return -1;
            if (out) out[o] = (unsigned char)((hi << 4) | lo);
            o++;
        }
        i += groups[g];
    }
    return 0;
}

/* Форма идентификатора — ПО ДЛИНЕ строки, как в Xray (common/uuid/uuid.go, ParseString).
 *
 * Так это и устроено у сервера: id из панели вроде «TMG_74317ba5f91» — законный VLESS, из
 * него UUID выводится хэшем, и оба конца обязаны вывести одинаково. Прежний разбор здесь
 * требовал строгий шестнадцатеричный текст, и такой узел не подключался вовсе: проба
 * отвечала «UUID неразборчив», а туннель ронял соединение без причины. */
int vless_uuid_form(const char *s) {
    size_t n = s ? strlen(s) : 0;
    if (n >= 32 && n <= 36)
        return hex_groups(s, n, NULL) == 0 ? VLESS_UUID_HEX : VLESS_UUID_NOTHEX;
    if (n == 0) return VLESS_UUID_EMPTY;
    if (n == 31) return VLESS_UUID_GAP;
    if (n > 36) return VLESS_UUID_TOOLONG;
    return VLESS_UUID_DERIVED;
}

/* 16 байт идентификатора. Ветка выбирается ОДНИМ правилом — тем, что выше: два
 * независимых решения о длине разъехались бы, и разъехались бы молча. */
int vless_uuid_parse(const char *s, unsigned char out[16]) {
    switch (vless_uuid_form(s)) {
    case VLESS_UUID_HEX:
        return hex_groups(s, strlen(s), out);
    case VLESS_UUID_DERIVED: {
        /* sha1(16 нулевых байт || строка), первые 16 байт; дальше версия 5 в старшей
         * половине байта 6 и вариант RFC 4122 в байте 8 — ровно как у Xray. Нулевые
         * байты впереди — это не соль, а пустой UUID, в который Xray хэширует строку
         * («h.Write(uuid[:])» до записи текста); без них вышли бы другие 16 байт. */
        size_t n = strlen(s);
        unsigned char msg[16 + 30], dg[20];
        memset(msg, 0, 16);
        memcpy(msg + 16, s, n);
        if (sha1_short(msg, 16 + n, dg) != 0) return -1;
        memcpy(out, dg, 16);
        out[6] = (unsigned char)((out[6] & 0x0f) | 0x50);
        out[8] = (unsigned char)((out[8] & 0x3f) | 0x80);
        return 0;
    }
    default:
        return -1;
    }
}

/* Заголовок запроса. Адрес передаётся ИМЕНЕМ, когда оно известно: так разрешение имени
 * делает сервер, и запрос не утекает наружу через локальный DNS. Для трафика из TUN имени
 * нет — там уже адрес, и передаётся он как адрес. */
size_t vless_build_request(const unsigned char uuid[16], enum vless_cmd cmd,
                           const char *host, const unsigned char ip4[4],
                           uint16_t port, const char *flow,
                           unsigned char *out, size_t cap) {
    size_t i = 0;
    if (cap < 24) return 0;
    out[i++] = 0;                       /* версия протокола */
    memcpy(out + i, uuid, 16); i += 16;

    /* Дополнительные данные. Для XTLS-Vision это protobuf-сообщение Addons со строкой
     * flow в поле 1 — схема из addons.proto Xray:
     *
     *   message Addons { string Flow = 1; bytes Seed = 2; }
     *
     * protobuf здесь кодируется вручную, потому что сообщение из одного строкового поля
     * — это три байта плюс само имя, и тащить генератор ради этого было бы несоразмерно:
     *   0x0A (поле 1, тип 2) | длина | байты строки
     *
     * Без этого сервер с flow=xtls-rprx-vision не отвечает вовсе: он ждёт Vision, а
     * получает обычный VLESS. Именно так и выглядела ошибка — «ответ 0 байт». */
    if (flow && flow[0]) {
        size_t fl = strlen(flow);
        if (fl > 120 || i + 3 + fl > cap) return 0;
        out[i++] = (unsigned char)(2 + fl);   /* длина protobuf-сообщения */
        out[i++] = 0x0A;                      /* поле 1, wire type 2 (строка) */
        out[i++] = (unsigned char)fl;
        memcpy(out + i, flow, fl); i += fl;
    } else {
        out[i++] = 0;                         /* дополнительных данных нет */
    }
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
