/* XTLS-Vision: кадры с набивкой поверх VLESS. Подробности формата — в vision.c. */
#ifndef STEER_VISION_H
#define STEER_VISION_H
#include <stddef.h>
#include <stdint.h>

#define VISION_CMD_CONTINUE 0
#define VISION_CMD_END      1
#define VISION_CMD_DIRECT   2

#define VISION_EAGAIN (-1)   /* самое начало потока пришло короче 21 байта */
#define VISION_EPROTO (-2)

struct vision {
    unsigned char uuid[16];
    /* UUID идёт только в первом кадре: он и есть признак начала потока, а повторять его
     * значило бы отдавать наблюдателю неизменную последовательность байт. */
    int need_uuid;
    /* Набивка закончилась и на ОТПРАВКУ. После кадра с командой end сервер перестаёт
     * ждать обёртку, и продолжать её ставить — значит вписывать пять байт заголовка
     * прямо в поток данных. На одном коротком запросе это незаметно (кадр всего один),
     * а на любой передаче побольше ломает выгрузку молча. */
    int sent_end;
    int recv_uuid_seen;      /* UUID в первом кадре от сервера уже снят */
    int recv_done;           /* набивка кончилась — дальше поток как есть */

    /* Разбор идёт ПОТОКОМ: кадр может приехать несколькими записями TLS, и требовать его
     * целиком значило бы либо держать буфер на 128 КБ на каждое соединение, либо терять
     * данные. Поэтому между вызовами переносятся только счётчики. */
    unsigned char rx_hdr[5];
    unsigned char rx_hdr_n;
    uint32_t rx_data_left;   /* сколько осталось от данных текущего кадра */
    uint32_t rx_pad_left;    /* сколько осталось от набивки текущего кадра */
    int rx_end_after;        /* у текущего кадра команда end или direct */

    unsigned long sent_frames;
};

void vision_init(struct vision *v, const unsigned char uuid[16]);
size_t vision_wrap(struct vision *v, const unsigned char *data, size_t n,
                   unsigned char *out, size_t cap);
int vision_unwrap(struct vision *v, const unsigned char *in, size_t n,
                  size_t *consumed, const unsigned char **payload, size_t *payload_n);
#endif
