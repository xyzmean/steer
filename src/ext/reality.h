/* Рукопожатие Reality: ClientHello, неотличимый от браузерного, с аутентификатором в
 * session_id. Подробное объяснение механики — в reality.c. */
#ifndef STEER_REALITY_H
#define STEER_REALITY_H
#include <stdint.h>
#include <stddef.h>

#define REALITY_EBADKEY (-2)   /* pbk или sid не разобрались */
#define REALITY_ECRYPTO (-3)   /* сбой примитива или источника случайности */
#define REALITY_ETOOBIG (-4)   /* Hello не влез в буфер */

struct reality_cfg {
    const char *sni;   /* маскировочный домен: он же SNI, он же соль для authkey */
    const char *pbk;   /* публичный ключ сервера, base64url */
    const char *sid;   /* short id, hex; может быть пустым */
    const char *fp;    /* отпечаток браузера — пока влияет только на набор расширений */
    /* Протокол для ALPN, или NULL — тогда расширения нет вовсе.
     *
     * NULL по умолчанию не из лени: Hello без ALPN проверен на живых узлах и работает, а
     * состав Hello — это то, по чему Reality отличает нас от постороннего. Добавлять
     * расширение туда, где оно не нужно, значит менять проверенное ради ничего. Оно нужно
     * ровно транспортам grpc и xhttp: они говорят по HTTP/2, и согласовать его можно
     * только здесь. */
    const char *alpn;
};

struct reality_state {
    unsigned char priv[32];        /* наш эфемерный приватный */
    unsigned char pub[32];         /* он же публичный — уезжает в key_share */
    unsigned char shared[32];      /* общий секрет с сервером */
    unsigned char session_id[32];  /* аутентификатор, он же legacy_session_id */
};

int reality_build_hello(const struct reality_cfg *cfg, struct reality_state *st,
                        unsigned char *out, size_t out_n, size_t *out_len);

#endif
