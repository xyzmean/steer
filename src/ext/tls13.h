/* Записи TLS 1.3 для Reality. Почему не mbedtls_ssl_* — в tls13.c. */
#ifndef STEER_TLS13_H
#define STEER_TLS13_H
#include <stdint.h>
#include <stddef.h>
#include "mbedtls/sha256.h"
#include "mbedtls/gcm.h"
#include "mbedtls/chachapoly.h"

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
/* Записи целиком ещё нет в сокете. НЕ ошибка: чтение отказалось блокироваться, потому что
 * блокировка посреди записи останавливает не одно соединение, а весь цикл. */
#define TLS13_EAGAIN       (-20)

enum tls13_aead { TLS13_AEAD_AES128, TLS13_AEAD_AES256, TLS13_AEAD_CHACHA };

struct tls13_keys {
    enum tls13_aead aead;
    size_t key_n;
    unsigned char key[32];
    unsigned char iv[12];
    /* Контекст шифра, созданный ОДИН РАЗ на соединение.
     *
     * Раньше каждая запись делала init + setkey + free. Это не «лишний вызов»: у mbedtls
     * setkey для GCM выделяет контекст AES в куче, разворачивает расписание ключа и
     * генерирует таблицу GHASH — то есть постоянная работа на каждую запись независимо от
     * её размера. При мелких записях (а после перехода Vision на прямое копирование они
     * по 300 байт) это становится основной статьёй расхода.
     *
     * Заметить это по бенчмарку было нельзя: tests/crypto-bench.c ставит ключ один раз ВНЕ
     * измеряемого цикла, поэтому «800 Мбит/с» относились к коду, которого у нас не было. */
    int ctx_ready;
    mbedtls_gcm_context gcm;
    mbedtls_chachapoly_context chacha;
};

struct tls13 {
    int fd;
    int ready;
    /* Буфер чтения: берём у сокета всё, что есть, одним вызовом и собираем записи отсюда.
     *
     * Без него на каждую запись приходилось по несколько системных вызовов и ожидание её
     * дособирания — замерено 16 000 чтений в секунду по 600 байт и 80% времени цикла
     * внутри чтения. Записи в потоке бывают мелкими, и платить за каждую отдельно нельзя.
     *
     * Цена — 16 КБ на соединение (при 64 соединениях мегабайт). Это единственное место,
     * где мы согласились на буфер: он снимает и лишние вызовы, и ожидание, и оба костыля,
     * которые до него понадобились. */
    unsigned char rbuf[TLS13_MAX_REC + 8];
    size_t rbuf_n;      /* сколько байт лежит */
    size_t rbuf_off;    /* сколько из них уже разобрано */
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

/* Забрать байты, которые уже прочитаны у сокета, но ещё не разобраны как записи.
 *
 * Нужно ровно в одном случае: сервер перешёл на прямое копирование, и дальше в сокете уже
 * не наши записи. Часть этого сырого потока к тому моменту может лежать у нас в буфере —
 * прочитать сокет напрямую, не отдав её, значит потерять кусок и разъехаться с сервером.
 * Симптом был исчерпывающий: узлы с Vision отдавали ноль байт. */
size_t tls13_take_pending(struct tls13 *t, unsigned char *out, size_t cap);

int tls13_write(struct tls13 *t, const unsigned char *data, size_t n);
int tls13_read(struct tls13 *t, unsigned char *out, size_t cap, size_t *got);

/* Освободить контексты шифров. Обязательно на каждое закрытие: контекст AES внутри GCM
 * лежит в куче, а соединений за час работы туннеля проходят тысячи. */
void tls13_free(struct tls13 *t);

#endif
