#ifndef STEER_DNSD_INT_H
#define STEER_DNSD_INT_H

/* Общий внутренний заголовок резолвера: структуры и объявления, которые нужны нескольким
 * файлам src/dnsd (rules.c, wire.c, fakeip.c, table.c, dlog.c, proxy.c, main.c, origdst.c). До
 * пересборки всё это было статикой одного файла, dnsd.c; здесь — только то подмножество,
 * которое пересекает границу нового файла. Имена не менялись при переносе. */

#include <arpa/inet.h>
#include <ctype.h>
#include <errno.h>
#include <fcntl.h>
#include <fnmatch.h>
#include <limits.h>
#include <netinet/in.h>
#include <regex.h>
#include <signal.h>
#include <stdint.h>
#include "spec.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/epoll.h>
#include <sys/random.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <sys/types.h>
#include <sys/un.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

#include "sindex.h"

#define MAX_HOSTNAME 256

/* FAKEIP_ANSWER_TTL is independent of the real record's TTL — the fake IP
 * itself never needs to expire from the client's cache the way a real
 * record does (it's a stable, persistent allocation); this just needs to be
 * short enough that the client re-queries periodically, e.g. after a NAT-map
 * refresh. It is also the natural refresh cadence for everything derived
 * from the answer (the DNAT map, the route element): the client cannot act
 * on anything newer until its cached answer expires, so re-checking more
 * often than the TTL buys nothing — see the throttles that reference it. */
#define FAKEIP_ANSWER_TTL 60

/* Жалоба не чаще раза в WARN_EVERY_SEC на каждое место.
 *
 * Все три случая ниже (таблица ожиданий полна, апстрим не принял запрос, пул fake-IP
 * исчерпан) прежде происходили МОЛЧА, и это их главное свойство: снаружи они выглядят как
 * «DNS тормозит» или «сайт пошёл мимо туннеля», а в журнале нет ни строки. Молчать о них
 * нельзя, но и печатать на каждый пакет тоже — на всплеске это тысячи строк в syslog на
 * роутере с единственным ядром.
 *
 * static inline, а не extern: нужна нескольким файлам резолвера, а не одна копия на всех —
 * см. рационале у static inline в nlbuf.h. */
#define WARN_EVERY_SEC 10
static inline int warn_due(time_t *last, time_t now) {
    if (now - *last < WARN_EVERY_SEC) return 0;
    *last = now;
    return 1;
}

/* static inline по той же причине, что warn_due: нужна нескольким файлам резолвера. */
static inline void str_lower(char *s) {
    for (; *s; s++) *s = (char)tolower((unsigned char)*s);
}

#define DNS_TYPE_A     1
#define DNS_TYPE_AAAA  28
#define DNS_TYPE_SVCB  64
#define DNS_TYPE_HTTPS 65

struct answer_ip {
    uint32_t addr; /* network byte order */
    uint32_t ttl;
};

enum rule_type { RULE_EXACT, RULE_NAMESPACE, RULE_WILDCARD, RULE_REGEX };

struct rule {
    enum rule_type type;
    char *pattern;   /* lowercased source pattern, kept for EXACT/NAMESPACE/WILDCARD */
    regex_t re;      /* compiled only when type == RULE_REGEX */
    int re_valid;
};

/* Метки типа в индексе: одно и то же имя может быть задано и точным правилом, и доменным. */
#define RTAG_EXACT     1u
#define RTAG_NAMESPACE 2u

struct ruleset {
    struct rule *rules;
    size_t n;
    size_t cap;
    /* Точные и доменные правила — через индекс: их тысячи, и перебирать их на каждый запрос
     * незачем, имя проверяется по своим суффиксам (см. ruleset_match). */
    struct sindex idx;
    /* Шаблоны и регулярные выражения перебираются как раньше: по суффиксу их не найти, а
     * бывает их единицы на список. Отдельный массив номеров — чтобы перебор не шёл по всем
     * правилам ради этих единиц. */
    uint32_t *fancy;
    size_t fancy_n, fancy_cap;
};

/* Адрес сервера наверху в режиме origdst — IPv4 или IPv6 (см. g_origdst). Объединение, а не
 * sockaddr_storage: слотов MAX_PENDING, и 128 байт на слот ради 28 нужных незачем. */
union dnsd_sa { struct sockaddr sa; struct sockaddr_in v4; struct sockaddr_in6 v6; };

/* Адрес, на который пришёл запрос (режим origdst): по нему ищется запись conntrack, и с него
 * же уходит ответ клиенту (см. reply_client). af — AF_INET, AF_INET6 или 0 («не узнали»).
 * IPv4 у двойного стека приходит v4-mapped и хранится здесь как v4: и в conntrack, и в
 * ответе это IPv4-соединение, а не IPv6. */
struct dnsd_local { int af; struct in_addr v4; struct in6_addr v6; };

struct fakeip_entry {
    char *domain; /* lowercased, matches the ruleset's own lowercasing */
    uint32_t addr;      /* host byte order */
    uint32_t real_host; /* last-seen real backend, host order; 0 if unknown */
    /* В КАКИХ наборах доменных каналов сейчас лежит этот поддельный адрес — по биту
     * на канал (0 = ни в одном). Набор битов, а не один номер, и это разница по
     * существу: имя, названное в ДВУХ правилах сразу, обязано попасть в оба набора.
     *
     * Пока здесь стоял номер одного канала, поддельный адрес ложился в набор ПЕРВОГО
     * совпавшего правила и только туда. Для клиентов второго правила его в наборе не
     * было, значит ни одно правило их пакет не забирало, а адрес у них на руках был
     * поддельный — то есть домен переставал открываться совсем. Ровно это и пришло
     * обраткой: два правила на YouTube (одно на телевизор, другое на всю сеть), и
     * общее имя не работает ни там, ни там.
     *
     * Кто победит, когда наборов несколько, решает ПОРЯДОК ЦЕПОЧКИ — то есть порядок
     * правил, который человек видит и меняет стрелками. Это и есть «победитель —
     * который выше» (решение владельца), а не «нижнее правило отбрасываем».
     *
     * Бит на канал влезает точно: доменных каналов не больше MAX_CHANNELS = 64.
     *
     * NOT persisted to the state file: it is re-derived on (re)query and on the
     * rehydrate pass, so the 2-field/3-field formats on disk stay unchanged. The
     * whole reason this field exists is the fake-IP route fix: a fake IP used to
     * expire from its channel set (timeout = DNS TTL) while the conntrack session
     * it belonged to lived for minutes, and the packet then fell through to the
     * main route — i.e. the WAN — silently bypassing the tunnel. Now the fake IP
     * is a PERMANENT element of its channel set, exactly like it is permanent in
     * the DNAT map, so the path stays stable for the whole lifetime of the flow. */
    uint64_t sets;
    /* Дроссели горячего пути, оба — время последнего действия (0 = никогда).
     * Не сохраняются: после рестарта первый запрос всё сделает заново, это
     * и есть желаемое поведение.
     *
     * route_asserted — когда элемент канала последний раз переутверждался в
     * ядре. Переутверждение — страховка от fw4 reload, смывшего наборы, а не
     * рабочий путь: без дросселя каждый повторный запрос платил блокирующей
     * nf_tables-транзакцией (sendmsg + recv ack, до 100 мс под commit mutex)
     * за EEXIST, который ядро отвечало на уже стоящий элемент.
     *
     * refreshed — когда мы последний раз ходили за доменом к upstream ради
     * обновления DNAT-карты. Клиент не может переспросить раньше, чем истечёт
     * выданный ему TTL, поэтому фоновая сверка чаще FAKEIP_ANSWER_TTL не
     * узнаёт ничего нового, а стоит полного круга сокет-эполл-резолвер. */
    time_t route_asserted;
    time_t refreshed;
};

struct fakeip_table {
    struct fakeip_entry *entries;
    size_t n, cap;
};

/* struct tcpc — соединение по TCP; полное определение приватно для proxy.c. Здесь достаточно
 * неполного типа: origdst.c (ct_origdst) и dnsd_int.h сверяют только истинность указателя. */
struct tcpc;

/* One entry per channel that matches domains, in SPEC ORDER. */
struct dchan {
    char set[64];               /* the nft set the compiler generated for it */
    const char *rules_path[MAX_FILES];
    size_t rules_n;
    struct ruleset rules;
    int realip;                 /* put the real answers in the set, do not fake */
    /* Правило спеки, от имени которого набор показывается в журнале имён (dns-log), и его
     * выход: человеку нужно имя правила с экрана, а не имя набора nft. Набор бывает общим у
     * нескольких правил (тот же выход, те же клиенты и режим, см. dch_build), и тогда
     * называется первое ДОМЕННОЕ из них (с domains_files) — старшее по порядку, то есть то,
     * что человек видит выше. Адресное правило попадает в группу только ради гибридных
     * списков (dch_join_domain_group), и назвать его — значило бы приписать имя из доменного
     * списка соседа правилу «подсети Discord»; оно называется, лишь пока доменного в группе
     * нет. Выход у всех правил группы один — он входит в имя набора. */
    char chan[32];
    char out[32];
    int chan_dom;               /* chan — правило с domains_files */
};

/* ---------------------------------------------------------------------- */
/* глобалы, пересекающие границу файла (были static в одном dnsd.c)       */
/* ---------------------------------------------------------------------- */

/* fake-ip: таблица, файл состояния (fakeip.c) */
extern struct fakeip_table g_fakeip;
extern const char *g_fakeip_state_path;
extern int g_fakeip_dirty;
extern time_t g_fakeip_last_rewrite;
extern const char *g_fakeip_map;
/* Пул 198.18.0.0/15 (RFC 2544) — см. шапку fakeip.c. Индекс домен->запись и «следующий
 * свободный» — static в fakeip.c для всех, кроме tests/dnsmatch.c: стенду нужно сбрасывать
 * их между случаями, изображая свежий процесс. */
#define FAKEIP_POOL_BASE 0xC6120000u /* 198.18.0.0 */
#define FAKEIP_POOL_SIZE 131072u     /* 198.18.0.0 - 198.19.255.255 */
extern struct sindex g_fakeip_idx;
extern size_t g_fakeip_next;

/* каналы: таблица «канал → набор» (table.c) */
extern struct dchan g_dch[MAX_CHANNELS];
extern size_t g_dch_n;

/* proxy: адрес назначения из conntrack, метка соединения, контекст TCP (proxy.c) */
extern int g_origdst;
extern int g_ct_fd;
extern struct tcpc *g_tcp_cur;

/* журнал имён (dlog.c) */
extern int g_dlog_fd;

/* цикл событий (proxy.c) */
extern int g_epfd;

/* ---------------------------------------------------------------------- */
/* функции, пересекающие границу файла (были static в одном dnsd.c)       */
/* ---------------------------------------------------------------------- */

/* rules.c */
int ruleset_add(struct ruleset *rs, const char *raw);
void ruleset_free(struct ruleset *rs);
int ruleset_match(const struct ruleset *rs, const char *host);
int load_rules(const char *path, struct ruleset *rs);
int load_rules_into(const char *path, struct ruleset *rs);

/* wire.c */
int parse_query(const uint8_t *pkt, size_t len, char *out_qname,
                 size_t qname_len, uint16_t *out_qtype, size_t *out_qend);
int parse_response(const uint8_t *pkt, size_t len, char *out_qname,
                    size_t qname_len, uint16_t *out_qtype,
                    size_t *out_qend, struct answer_ip *ips,
                    int max_ips);
void make_response_flags(uint8_t *pkt);
size_t build_rewritten_response(const uint8_t *orig, size_t qend,
                                 uint8_t *out, size_t out_cap,
                                 int with_answer, uint32_t fake_addr_host);

/* fakeip.c */
long fakeip_find(const char *domain);
int fakeip_lookup_or_alloc(const char *domain_in, uint32_t *out_addr);
void fakeip_state_load(const char *path);
void fakeip_state_rewrite(void);
uint32_t fakeip_entry_get_real(const char *domain);
void fakeip_entry_set_real(const char *domain, uint32_t real_host);
void fakeip_route_set(const char *domain, uint64_t want);
size_t fakeip_rehydrate(int nk_open, size_t *routed_out);

/* table.c */
uint64_t dch_match_mask(const char *host);
int dch_first(uint64_t mask);
uint64_t dch_fakeip_only(uint64_t mask);
void dch_build(const struct spec *sp);
void dch_sig_write(void);

/* dlog.c */
void dlog_note(const char *qname, int hit);
void dlog_listen(void);
void dlog_close(void);
void dlog_serve(void);

/* proxy.c */
int run_proxy(int listen_port, int upstream_port);

/* proxy.c — таблица ожиданий: номер транзакции (слот+поколение) и отпечаток вопроса, чем
 * ответ апстрима сверяется со своим запросом. "static" снят только с этого подмножества —
 * tests/dnsmatch.c проверяет круг «собрать — разобрать» номера транзакции по ВСЕМ слотам и
 * ВСЕМ поколениям (правило 4, docs/architecture.md, раздел 4): обе стороны ломаются молча,
 * и добраться до них иначе, кроме добавления кода в движок ради теста, нельзя.
 *
 * ЧИСЛО СЛОТОВ — ЭТО ПРОПУСКНАЯ СПОСОБНОСТЬ ПРИ МЕДЛЕННОМ АПСТРИМЕ, а не «сколько бывает».
 * Ожидание живёт PENDING_TTL_SEC, значит таблица на N мест держит N/TTL запросов в секунду:
 * при 256 это 51 запрос/с. Пока резолвер наверху отвечает за миллисекунды, столько и не
 * нужно; но когда он начинает отвечать за секунды (DoH через туннель, а туннель просел),
 * таблица заполняется, и КАЖДЫЙ следующий запрос отбрасывается молча. Снаружи это выглядит
 * как «интернет тормозит через несколько часов работы»: клиент ждёт свой таймаут и
 * переспрашивает, а переспросы добивают ту же таблицу. 1024 места дают 204 запроса/с и
 * стоят ~180 КБ — на роутере, где свободно мегабайты, это дёшево.
 *
 * РАСКЛАДКА номера транзакции: младшие PENDING_IDX_BITS — номер слота, старшие — поколение.
 * Прежде было 8 и 8, и это ровно та арифметика, из-за которой защита от запоздавшего ответа
 * переставала работать именно под нагрузкой: слот переиспользуется примерно через
 * MAX_PENDING выдач, а поколение — байт, то есть при 256 слотах оно возвращалось к тому же
 * значению РОВНО тогда, когда слот шёл по второму кругу. Теперь поколения мало (6 бит), и
 * оно больше не единственная защита — главная проверка в том, что ответ обязан отвечать на
 * наш вопрос (см. question_fp). */
#define MAX_PENDING 1024
#define PENDING_IDX_BITS 10
#define PENDING_IDX_MASK ((1u << PENDING_IDX_BITS) - 1u)
#define PENDING_GEN_MASK (0xFFFFu >> PENDING_IDX_BITS)
#define PENDING_TTL_SEC 5

/* sockaddr_storage, not sockaddr_in: the listen socket is dual-stack, so a client can be
 * IPv6. See run_proxy's socket setup for why that matters. */
struct pending {
    /* Ни сокета, ни дескриптора: наверх ходит ОДИН постоянный сокет на весь процесс
     * (g_up_fd), а ответ к своему ожиданию привязывается переписанным номером транзакции —
     * см. pending_tag. Раньше на каждый пересланный запрос открывался свой сокет: socket +
     * connect + fcntl + send + epoll_ctl ADD на запрос и epoll_ctl DEL + close на ответ,
     * шесть системных вызовов и отдельная структура сокета в ядре — на пути КАЖДОГО запроса
     * из локальной сети. Замер: 19,1 мкс на запрос против 7,5. На mipsel, где системный
     * вызов дороже в разы, разница заметна на глаз при загрузке страницы (20-40 запросов). */
    /* Номер транзакции, с которым запрос пришёл ОТ КЛИЕНТА. Наверх уходит другой, наш, и в
     * ответе его надо вернуть на место: клиент сопоставляет ответ с запросом именно по нему. */
    uint16_t cli_id;
    /* Поколение слота: младший байт нашего номера транзакции — это индекс слота, а старший —
     * поколение. Без него запоздавший ответ на давно закрытое ожидание попал бы в чужой
     * слот, переиспользовавший тот же индекс. */
    uint8_t gen;
    /* Отпечаток вопроса и его длина — чем ответ сверяется с ожиданием (см. question_fp).
     * qfp == 0 значит «вопрос не разобрался», и тогда проверки нет: такой запрос пересылается
     * как есть и разбирается по полному пути. */
    uint16_t qfp;
    uint16_t qsec_end;
    int in_use;
    /* Клиенту уже ответили из быстрого пути: ответ upstream нужен только чтобы обновить
     * DNAT-карту и реальный адрес, отправлять его клиенту нельзя — второй ответ на тот же id
     * клиент в лучшем случае выбросит, а в худшем (другой адрес в A) примет за подмену. */
    int quiet;
    /* Результат матчинга, вычисленный на приёме запроса: -2 — вопрос не разобрался (ответ
     * пойдёт по полному пути), -1 — ни один канал не совпал, >=0 — номер канала. Ответ
     * upstream несёт то же имя вопроса, что и запрос, поэтому повторять разбор и матчинг в
     * ответе незачем — а для несовпавшего домена (подавляющее большинство трафика) это
     * снимает с ответа и parse_response, и проход по всем каналам. Действителен, только пока
     * rules_gen == g_rules_gen. */
    int hit;
    /* Полный набор совпавших каналов — тот же, что посчитал приём запроса (см.
     * dch_match_mask). Хранится рядом с `hit` по той же причине, по какой хранится `hit`:
     * ответ несёт то же имя, и второй проход по каналам ничего не узнаёт. */
    uint64_t sets;
    unsigned rules_gen;
    /* Запрос наверх по TCP (номер в g_tcpu) или -1 — по UDP. Ответ по TCP приходит на свой
     * сокет, и датаграмма с тем же номером транзакции на сокет UDP этому ожиданию не ответ
     * (см. dns over TCP, struct tcpu в proxy.c). */
    int tcp_up;
    struct sockaddr_storage client;
    socklen_t client_len;
    /* Куда ушёл запрос наверх — только в режиме --upstream-origdst (см. g_origdst): ответ
     * принимается лишь от этого адреса. В обычном режиме сокет connect'нут к петле, и
     * сравнивать нечего. */
    union dnsd_sa up;
    /* Режим origdst: сокет пула, которым ушёл запрос, номер транзакции наверх (случайный, см.
     * g_txmap) и адрес, на который пришёл запрос, — с него обязан уйти ответ клиенту. */
    int up_fd;
    uint16_t txid;
    struct dnsd_local local;
    int have_local;
    time_t expire;
};

extern struct pending g_pending[MAX_PENDING];
extern uint8_t g_gen_next;
uint8_t pending_next_gen(void);
uint16_t pending_tag(const struct pending *p);
uint16_t question_fp(const uint8_t *pkt, size_t qend);

/* origdst.c */
int ct_origdst(const struct sockaddr_storage *cli, const struct dnsd_local *local,
               int lport, union dnsd_sa *out, uint32_t *mark, int *have_mark);

#endif
