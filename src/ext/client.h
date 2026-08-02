/* Соединение с узлом VLESS/Reality и проверка «нас признали». Подробности — в client.c. */
#ifndef STEER_CLIENT_H
#define STEER_CLIENT_H
#include "vless.h"
#include "reality.h"
#include "tls13.h"
#include "h2.h"

#define VLESS_CONN_EDNS      (-30)
#define VLESS_CONN_ESOCK     (-31)
#define VLESS_CONN_ECONNECT  (-32)
#define VLESS_CONN_EIO       (-33)
#define VLESS_CONN_ECLOSED   (-34)
#define VLESS_CONN_EBADUUID  (-35)
/* Reality не признал ключ: TLS установлен, но отвечает маскировочный сайт. Отдельный код,
 * потому что это единственная ошибка, которая иначе выглядит как рабочий узел. */
#define VLESS_CONN_EREJECTED (-36)
/* Транспорт требует HTTP/2, а сервер на него не согласился. Тоже отдельный код: всё
 * остальное при этом работает, данные просто не идут, и без имени этой ошибки узел
 * выглядит как «подключается и молчит». */
#define VLESS_CONN_ENOH2     (-37)
#define VLESS_CONN_EGRPC     (-38)   /* поток gRPC устроен не так, как мы умеем читать */

/* Как байты VLESS едут внутри соединения.
 *
 * Это не «разные протоколы», а разная упаковка одного и того же потока: сверху всегда
 * VLESS (и Vision, если узел его требует), снизу всегда TLS. Поэтому транспорт — поле
 * соединения, а не отдельный вид клиента. */
enum vless_transport { VT_RAW = 0, VT_GRPC, VT_XHTTP };

/* Разбор потока сообщений gRPC.
 *
 * Состояние нужно потому, что границы сообщения gRPC, кадра HTTP/2 и записи TLS не
 * совпадают ни в одном месте: одно сообщение может приехать тремя записями, а одна
 * запись — принести полтора сообщения. Держим счётчики, а не буфер: буфер на каждое из
 * 64 соединений стоил бы мегабайт, а счётчики — двадцать байт. */
struct grpc_de {
    unsigned char hdr[5];        /* признак сжатия(1) + длина(4) */
    unsigned char hdr_n;
    uint32_t msg_left;           /* сколько осталось от тела сообщения */
    unsigned char pb[8];         /* тег и длина поля protobuf */
    unsigned char pb_n;
    uint32_t field_left;         /* сколько осталось от поля bytes внутри сообщения */
};

struct vless_conn {
    int fd;
    int plain;                 /* security=none: TLS нет вовсе */
    struct reality_state rst;
    struct tls13 tls;
    enum vless_transport tr;
    struct h2 h2;              /* только для grpc и xhttp */
    struct grpc_de de;         /* только для grpc */
};

int vless_connect(const struct vless_node *node, struct vless_conn *conn, int timeout_s);
int vless_probe(const struct vless_node *node, int timeout_s, char *why, size_t why_n);

/* То же, но с замерами. Оба в миллисекундах, -1 если до этого шага не дошло:
 *
 *   handshake_ms — от начала TCP до готового транспорта (TCP + TLS + HTTP/2, если он есть).
 *                  Это цена ПОДКЛЮЧЕНИЯ к узлу, платится один раз;
 *   ttfb_ms      — от отправки запроса до первого байта ответа ОТ 1.1.1.1 через туннель.
 *                  Это то, что чувствуется как задержка, и то же самое, что показывает
 *                  curl своим временем до первого байта.
 *
 * Именно ttfb, а не ICMP: пинг через наш TUN не ходит вовсе (ICMP мы не пересылаем), и
 * «пинг» через туннель был бы не тем, что измеряют. Здесь измеряется ровно тот путь, по
 * которому пойдёт трафик. */
int vless_probe_timed(const struct vless_node *node, int timeout_s, char *why, size_t why_n,
                      int *handshake_ms, int *ttfb_ms);

/* Обмен данными в форме, которую требует транспорт узла. Вызывающий про транспорт не
 * знает — иначе о нём пришлось бы помнить и в туннеле, и в проверке, и в каждом новом
 * месте, а забытое место означало бы поток, который уходит не в той упаковке.
 *
 * vless_recv может вернуть 0 байт при коде 0: в записи мог приехать только служебный
 * кадр HTTP/2. Это «пока нечего отдать», а не конец потока — конец приходит кодом. */
int vless_send(struct vless_conn *c, const unsigned char *d, size_t n);
int vless_recv(struct vless_conn *c, unsigned char *d, size_t cap, size_t *got);

void vless_close(struct vless_conn *c);
const char *vless_strerror(int rc);

/* Сколько места обязан дать вызывающий vless_recv: транспорты поверх HTTP/2 отдают за
 * один раз до целой записи TLS. */
#define VLESS_MIN_RECV_CAP H2_MIN_READ_CAP

#endif
