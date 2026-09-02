/* Рукопожатие Reality: ClientHello, неотличимый от браузерного, с аутентификатором в
 * session_id. Подробное объяснение механики — в reality.c. */
#ifndef STEER_REALITY_H
#define STEER_REALITY_H
#include <stdint.h>
#include <stddef.h>

#define REALITY_EBADKEY (-2)   /* pbk или sid не разобрались */
#define REALITY_ECRYPTO (-3)   /* сбой примитива или источника случайности */
#define REALITY_ETOOBIG (-4)   /* Hello не влез в буфер */

/* X25519MLKEM768 — постквантовый обмен, который современный Chrome предлагает ПЕРВЫМ. Его ключ на
 * проводе занимает 1184 байта ML-KEM плюс 32 байта X25519. */
#define REALITY_GROUP_MLKEM 0x11EC
#define REALITY_MLKEM_SHARE 1216

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

/* Носитель чужого рукопожатия внутри того же ClientHello.
 *
 * ЗАЧЕМ ЭТО ЗДЕСЬ, А НЕ ОТДЕЛЬНЫМ СБОРЩИКОМ. Протоколу xsteer (см. xshake.c) нужен Hello
 * с обликом Chrome, но со своей полезной нагрузкой в двух полях: свой эфемерный ключ в
 * key_share, свой аутентификатор в session_id и запечатанный статический ключ в набивке
 * фальшивого ECH. Скопировать для этого сборщик Hello значило бы завести ВТОРОЕ место, где
 * живёт отпечаток браузера, — и однажды они разъедутся, причём симптомом будет не ошибка, а
 * сервер Reality, молча отвечающий маскировочным сайтом. Поэтому сборщик один, а различия
 * выражены тремя необязательными полями.
 *
 * Байты Hello при car == NULL не меняются ни на бит: это закреплено стендом
 * tests/hellofreeze.c, который сверяет их с заморозкой, снятой ДО появления носителя.
 *
 * Порядок вызова обратных функций не случаен и важен для обеих сторон: сначала fill_ech
 * (набивка входит в подписываемые байты), потом fill_sid (подписывает весь Hello с
 * обнулённым session_id). Тот же порядок повторяет хаб, разбирая полученное. */
struct reality_carrier {
    /* Готовая эфемерная пара вместо сгенерированной. Нужна потому, что xsteer выводит из
     * неё общий секрет ЕЩЁ ДО сборки Hello — чтобы было чем запечатать статический ключ. */
    const unsigned char *priv;      /* 32 байта, или NULL */
    const unsigned char *pub;       /* 32 байта, обязателен вместе с priv */
    /* Предлагать ли постквантовый обмен X25519MLKEM768 в key_share.
     *
     * Нужно xsteer и только ему. Сравнение с настоящим трафиком (стенд tests/xhttp-compare.sh в
     * репозитории xsteer) показало: у современного Chrome ClientHello занимает около 1760 байт и
     * уезжает ДВУМЯ сегментами — именно из-за постквантового ключа, который занимает 1216 байт. Наши
     * 537 байт в одном сегменте опознаются и по размеру, и по числу сегментов, и по составу
     * supported_groups: «Chrome, который не предлагает постквантовый обмен» — это Chrome позапрошлого
     * года.
     *
     * Клиент VLESS этого НЕ включает, и не по забывчивости: его Hello заморожен побайтово
     * (tests/hellofreeze.c) и сверен с живыми узлами Reality, а менять проверенное ради ничего в этом
     * файле запрещено его же шапкой. Байты при pq == 0 не меняются ни на бит. */
    int pq;
    /* Предлагать в ALPN ТОЛЬКО http/1.1 вместо обычной пары «h2, http/1.1».
     *
     * Нужно мосту Telegram (tgws) и только ему. Пара с h2 впереди — это то, что шлёт
     * браузер, и менять её по умолчанию нельзя; но точка веб-сокета за Cloudflare, увидев
     * h2, его и выбирает, а дальше наш апгрейд по HTTP/1.1 для неё мусор: снято пробой —
     * узел присылал преамбулу HTTP/2 до нашего запроса и закрывал соединение. Апгрейд
     * веб-сокета поверх HTTP/2 существует (RFC 8441), но это отдельный протокол ради того
     * же результата.
     *
     * Байты Hello при alpn_http11 == 0 не меняются ни на бит — это закреплено
     * tests/hellofreeze.c. */
    int alpn_http11;
    /* Заполнить набивку ECH (176 байт). NULL — оставить случайный шум, как у браузера без
     * настроенного ECH. */
    int (*fill_ech)(void *ctx, unsigned char *ech, size_t ech_n,
                    const unsigned char shared[32]);
    /* Заполнить 32 байта session_id вместо аутентификатора Reality. hs — сообщение
     * рукопожатия с УЖЕ ОБНУЛЁННЫМ session_id, то есть ровно те байты, которые вторая
     * сторона сможет восстановить у себя. */
    int (*fill_sid)(void *ctx, unsigned char sid[32],
                    const unsigned char *hs, size_t hs_n,
                    const unsigned char shared[32]);
    void *ctx;
};

int reality_build_hello_carry(const struct reality_cfg *cfg, struct reality_state *st,
                              const struct reality_carrier *car,
                              unsigned char *out, size_t out_n, size_t *out_len);

/* Примитивы этого файла наружу — для xsteer (src/ext/xshake.c). Объяснение, почему обёртки,
 * а не копии, стоит у их определений в reality.c. */
int xc_random(unsigned char *out, size_t n);
int xc_cpu_has_aes(void);
int xc_x25519_keypair(unsigned char priv[32], unsigned char pub[32]);
int xc_x25519_public(const unsigned char priv[32], unsigned char pub[32]);
/* Общий секрет X25519. Живёт здесь же и уже объявлена в tls13.c, но xsteer зовёт её тоже. */
int x25519_shared_ext(const unsigned char priv[32], const unsigned char peer[32],
                      unsigned char out[32]);

#endif
