/* Записи TLS 1.3 для Reality. Почему не mbedtls_ssl_* — в tls13.c. */
#ifndef STEER_TLS13_H
#define STEER_TLS13_H
#include <stdint.h>
#include <stddef.h>
#include "mbedtls/sha256.h"

#define TLS13_MAX_REC   16640          /* максимум записи по RFC + запас на тег */
#define TLS13_MAX_PLAIN 16384

#define TLS13_EIO          (-10)
#define TLS13_ECLOSED      (-11)
#define TLS13_EBADREC      (-12)
#define TLS13_ETOOBIG      (-13)
#define TLS13_EAUTH        (-14)   /* AEAD не сошёлся: ключи разъехались с сервером */
#define TLS13_ECRYPTO      (-15)
#define TLS13_ENOKEYSHARE  (-16)   /* ServerHello без key_share — не TLS 1.3 */
#define TLS13_EBADSUITE    (-17)
#define TLS13_EFINISHED    (-18)   /* Finished не совпал: транскрипт или ключи неверны */
#define TLS13_ESTATE       (-19)

enum tls13_aead { TLS13_AEAD_AES128, TLS13_AEAD_AES256, TLS13_AEAD_CHACHA };

struct tls13_keys {
    enum tls13_aead aead;
    size_t key_n;
    unsigned char key[32];
    unsigned char iv[12];
};

struct tls13 {
    int fd;
    int ready;
    /* Что сервер выбрал в ALPN, из EncryptedExtensions. Пустая строка означает «не
     * присылал», то есть согласования не было.
     *
     * Нужно ради одной ошибки: транспорты grpc и xhttp требуют HTTP/2, и если сервер на
     * него не согласился, всё остальное работает, а данные не идут. Без этой строки
     * симптом — «узел подключается и молчит», и отличить его от закрытого порта нельзя. */
    char alpn[16];
    struct tls13_keys rd, wr;
    /* Счётчики записей. НЕ сбрасываются: сброс означал бы повтор nonce, то есть
     * полную потерю защиты AEAD. */
    uint64_t rd_seq, wr_seq;
    mbedtls_sha256_context tr;      /* транскрипт рукопожатия */
};

/* client_hello — байты, УЖЕ отправленные серверу (нужны для транскрипта);
 * shared_secret — общий секрет X25519 из reality.c. */
int tls13_handshake(struct tls13 *t, int fd,
                    const unsigned char *client_hello, size_t hello_n,
                    const unsigned char *shared_secret);

int tls13_write(struct tls13 *t, const unsigned char *data, size_t n);
int tls13_read(struct tls13 *t, unsigned char *out, size_t cap, size_t *got);

#endif
