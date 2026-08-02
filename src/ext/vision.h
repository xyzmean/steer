/* XTLS-Vision: кадры с набивкой поверх VLESS. Подробности формата — в vision.c. */
#ifndef STEER_VISION_H
#define STEER_VISION_H
#include <stddef.h>

#define VISION_CMD_CONTINUE 0
#define VISION_CMD_END      1
#define VISION_CMD_DIRECT   2

#define VISION_EAGAIN (-1)   /* кадр пришёл не целиком, надо дочитать */
#define VISION_EPROTO (-2)

struct vision {
    unsigned char uuid[16];
    /* UUID идёт только в первом кадре: он и есть признак начала потока, а повторять его
     * значило бы отдавать наблюдателю неизменную последовательность байт. */
    int need_uuid;
    int recv_done;           /* сервер прислал end — дальше поток без обёртки */
    unsigned long sent_frames;
};

void vision_init(struct vision *v, const unsigned char uuid[16]);
size_t vision_wrap(struct vision *v, const unsigned char *data, size_t n,
                   unsigned char *out, size_t cap);
int vision_unwrap(struct vision *v, const unsigned char *in, size_t n,
                  size_t *consumed, const unsigned char **payload, size_t *payload_n);
#endif
