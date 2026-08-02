/* Минимальный клиент HTTP/2 на один поток. Зачем и с какими границами — в h2.c. */
#ifndef STEER_H2_H
#define STEER_H2_H
#include <stdint.h>
#include <stddef.h>

#define H2_EIO      (-50)
#define H2_EPROTO   (-51)   /* кадр, которого здесь быть не может */
#define H2_ESTATUS  (-52)   /* сервер ответил не 200 */
#define H2_ERESET   (-53)   /* RST_STREAM или GOAWAY */
#define H2_ETOOBIG  (-54)
#define H2_EWINDOW  (-55)   /* окно закрыто, а отдать данные некуда */

/* Ввод-вывод под нами. Абстракция, а не прямой вызов tls13_*, потому что транспорт
 * бывает и без TLS (security=none), а HTTP/2 к этому безразличен. */
struct h2_io {
    void *ctx;
    int (*write)(void *ctx, const unsigned char *d, size_t n);
    int (*read)(void *ctx, unsigned char *d, size_t cap, size_t *got);
};

/* Состояние держится МАЛЕНЬКИМ сознательно: по одному такому на соединение VLESS, а их
 * до 64. Буфера на кадр здесь нет — записи читаются в общий буфер, а через вызовы
 * переносится только то, что нельзя разобрать сразу: обрывок заголовка кадра и счётчик
 * непрочитанного тела. 16 КБ на соединение × 64 — это мегабайт на коробке с 15. */
struct h2 {
    struct h2_io io;
    int started;
    int status;                 /* 200, 0 = ещё не знаем, -1 = не смогли разобрать */
    int done;                   /* END_STREAM от сервера */

    /* Обрывок заголовка кадра, не поместившийся в прошлую запись. */
    unsigned char pend[9];
    size_t pend_n;

    /* Текущий кадр: сколько тела осталось и что это за кадр. */
    uint32_t frame_left;
    unsigned char frame_type;
    unsigned char frame_flags;
    int frame_ours;             /* тело этого кадра адресовано нашему потоку */

    /* Тело служебного кадра собирается здесь: WINDOW_UPDATE, SETTINGS, PING и RST надо
     * увидеть ЦЕЛИКОМ, чтобы на них ответить, а границы записи TLS и кадра HTTP/2 не
     * совпадают. Все они короткие — 64 байта хватает на десяток настроек. */
    unsigned char ctl[64];
    unsigned char ctl_n;

    /* Управление потоком. Наше окно приёма пополняется по мере чтения; окно ОТПРАВКИ
     * принадлежит серверу, и переполнить его — значит получить RST_STREAM. */
    int32_t recv_credit;        /* сколько прочитано с последнего WINDOW_UPDATE */
    int32_t send_win;           /* окно потока, которое дал сервер */
    int32_t send_win_conn;      /* окно соединения */
};

/* Сколько места обязан дать вызывающий h2_read. В одной записи TLS приезжает до 16384
 * байт, и все они могут оказаться телом DATA — плюс перенесённый обрывок заголовка.
 * Меньший буфер означал бы H2_ETOOBIG на совершенно законном кадре. */
#define H2_MIN_READ_CAP (16384 + 16)

/* Открыть поток: преамбула, SETTINGS, HEADERS. content_type может быть NULL.
 * referer нужен xhttp (в нём едет набивка), gRPC его не посылает. */
int h2_start(struct h2 *h, const struct h2_io *io, const char *authority,
             const char *path, const char *content_type, const char *referer);

/* Отдать данные одним DATA-кадром (при необходимости несколькими). */
int h2_write(struct h2 *h, const unsigned char *d, size_t n);

/* Прочитать тело ответа. cap должен быть не меньше максимальной записи TLS: кадр целиком
 * влезает в запись, и тогда за один вызов отдаётся всё, что пришло. */
int h2_read(struct h2 *h, unsigned char *out, size_t cap, size_t *got);

const char *h2_strerror(int rc);

#endif
