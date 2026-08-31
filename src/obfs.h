/* WireGuard поверх поддельного TCP — внешний интерфейс обфускатора.
 *
 * Разделено на две части нарочно. Сборка и разбор сегмента — чистые функции без сокетов
 * и без времени, поэтому их можно проверить стендом (tests/obfsmatch.c) без сети и без
 * прав root. Циклы клиента и сервера сокетов требуют, и проверяются они уже на живом
 * стенде — см. tests/obfsmatch.c про границу.
 */
#ifndef STEER_OBFS_H
#define STEER_OBFS_H
#include <stdint.h>
#include <stddef.h>

struct obfs_seg {
    uint32_t saddr, daddr;      /* сетевой порядок */
    uint16_t sport, dport;      /* хостовый порядок */
    uint32_t seq, ack;          /* хостовый порядок */
    uint8_t flags;
    const uint8_t *payload;
    size_t plen;
};

/* Что кладём в опции SYN. Значение with_mss у obfs_build:
 *
 *   OBFS_OPT_NONE  — опций нет вовсе (обычный сегмент данных или голый ACK);
 *   OBFS_OPT_MSS   — только MSS. Так вёл себя обфускатор с самого начала;
 *   OBFS_OPT_SCALE — MSS и МАСШТАБ ОКНА.
 *
 * ЗАЧЕМ МАСШТАБ ОКНА, И ПОЧЕМУ ЭТО НЕ КОСМЕТИКА. Мы объявляем окно 65535 и никогда его не
 * обновляем — потока мы не контролируем, и это верно для нас самих. Но conntrack по дороге
 * ВЕРИТ этому окну и следит за ним: как только неподтверждённых данных в полёте становится
 * больше объявленного окна, он метит наши же сегменты недействительными, а штатное правило
 * fw4 «Prevent NAT leakage» (`oifname wan ct state invalid drop`) их выбрасывает, возвращая
 * нам EPERM.
 *
 * Измерено на живом роутере: канал 200 Мбит, процессор занят на 10%, а через туннель идёт
 * 10,2 Мбит/с — ровно 64 КиБ на круг задержки 50 мс. В журнале при этом «отправка не прошла
 * (Operation not permitted)», а в счётчике правила fw4 — 197 отброшенных пакетов. То есть
 * потолок ставило не железо и не шифр, а окно, которое мы сами объявили.
 *
 * С масштабом 7 то же поле означает 65535 × 128 = 8 МиБ, и потолок исчезает. Опция уходит
 * только в SYN и SYN-ACK, как и положено: в остальных сегментах её быть не должно. */
#define OBFS_OPT_NONE  0
#define OBFS_OPT_MSS   1
#define OBFS_OPT_SCALE 2
/* Тот самый множитель. Семь — потому что 65535 << 7 это восемь мегабайт: с запасом на любой
 * канал и любую задержку, и при этом ровно то значение, которое ставят настоящие стеки. */
#define OBFS_WSCALE 7

/* Собрать сегмент в buf (нужно 60 + 1600 байт), вернуть его длину. */
size_t obfs_build(uint8_t *buf, uint32_t saddr, uint32_t daddr,
                  uint16_t sport, uint16_t dport, uint32_t seq, uint32_t ack,
                  uint8_t flags, int with_mss, const void *payload, size_t plen);

/* Разобрать пакет с IP-заголовка. 0 — разобрано, -1 — не наше или битое. */
int obfs_parse(const uint8_t *pkt, size_t n, struct obfs_seg *s);

/* Контрольная сумма TCP с псевдозаголовком; на готовом сегменте даёт 0. */
uint16_t obfs_tcp_csum(uint32_t saddr, uint32_t daddr, const void *seg, size_t len);

/* Куда сдвинуть ack, приняв сегмент. Только вперёд, с учётом переполнения uint32. */
uint32_t obfs_next_ack(uint32_t have, uint32_t seq, size_t plen);

/* «адрес:порт» → адрес и порт. 0 — разобрано. */
int obfs_split_hostport(const char *s, char *host, size_t hn, int *port);

/* Циклы. Возвращают ненулевой код: выход из них — всегда отказ, подъём заново — дело
 * procd (клиент) или systemd (сервер). */
int obfs_client(const char *out_name, const char *server, int server_port,
                const char *listen_addr, int listen_port);
int obfs_server(int listen_port, const char *forward, int forward_port);

/* ---- сырой сокет, фильтры и правило против RST -----------------------------
 *
 * Объявлены наружу ради xsteer (src/ext/xsclient.c и xshub.c): он несёт свой протокол
 * поверх того же поддельного TCP и обязан пользоваться ЭТИМИ функциями, а не своими
 * копиями. Причина не в экономии строк: в этих четырёх функциях зашиты уроки, каждый из
 * которых куплен упавшим туннелем, и копия означала бы, что урок исправят в одном месте.
 *
 *   - obfs_raw_open: не ставит DF (при ошибке в MTU настройка деградирует фрагментацией,
 *     а не отваливается молча на больших пакетах) и подключается connect'ом, чтобы ядро
 *     само демультиплексировало ответы;
 *   - фильтры cBPF: сырой сокет получает КОПИЮ каждого локально доставляемого TCP, и без
 *     фильтра очередь переполняется, теряя настоящие сегменты (146 тысяч потерь на первом
 *     замере). Ставить фильтр надо ДО первого SYN: между socket() и настройкой очередь
 *     успевает набрать чужого;
 *   - obfs_guard_up: цепочка на приоритете raw, а не filter (иначе RST ядра успевает
 *     перевести запись conntrack в CLOSE, и штатное правило fw4 против утечек NAT
 *     выбрасывает наши же сегменты), и различение НАШЕГО RST от RST ядра по нулевому окну.
 *
 * kind — буква вида в имени цепочки: 'o' у обфускатора, 'x' у xsteer. Таблица одна на
 * оба (`inet steer_obfs`, имя историческое), а цепочки разные, иначе выход из одного
 * процесса снимал бы правило другого. */
int  obfs_raw_open(uint32_t daddr, uint32_t *saddr_out);
/* То же, но с ЗАДАННЫМ адресом источника: хаб обязан отвечать пиру с того адреса, на который пир
 * написал, а не с того, который ядро выберет для обратного маршрута. Подробности — у реализации. */
int  obfs_raw_open_from(uint32_t daddr, uint32_t saddr_want, uint32_t *saddr_out);
void obfs_filter_quad(int fd, uint32_t server_be, uint16_t sport, uint16_t dport);
void obfs_filter_port(int fd, uint16_t port);
/* Раскладка приёма по воркерам: только сегменты с (sport & mask) == id. Маска — степень
 * двойки минус один; при mask == 0 равносильно obfs_filter_port. */
void obfs_filter_port_shard(int fd, uint16_t port, uint16_t mask, uint16_t id);
void obfs_filter_none(int fd);
int  obfs_guard_up(char kind, const char *label, const char *peer_addr, int port,
                   int is_server);
void obfs_guard_down(void);

#endif
