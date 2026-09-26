/* Наборы правил sing-box (`.srs`) как источник списка — читатель (см. шапку srs.c).
 *
 * Набор разбирается в два прохода. Первый (srs_open) проходит файл целиком, не выделяя памяти
 * под элементы, и строит КЛАУЗЫ — нормальную форму правил набора: у каждой одно назначение
 * (имена или подсети), сужение по протоколу и портам, ограничения по клиенту и приложению и,
 * если были, исключения. Второй (srs_walk) идёт по файлу снова и отдаёт элементы потоком —
 * каждый с номером своей клаузы, — поэтому набор на сотни тысяч элементов не держится в памяти,
 * если потребителю это не нужно.
 *
 * Что формат несёт, а мы не выражаем, отказом не становится: невыразимое ПРАВИЛО снимается
 * целиком (набор от этого только сужается), и про это одна строка — srs_skipped(). Отказ —
 * только испорченный файл (-1, текст в err).
 */
#ifndef STEER_SRS_H
#define STEER_SRS_H

#include <stddef.h>
#include <stdint.h>
#include "spec.h"

/* Вид доменного элемента — то, как его понимает sing-box, и одно-к-одному соответствие типам
 * правил резолвера (src/dnsd/rules.c):
 *   EXACT     domain              — только само имя              «=x.com»   RULE_EXACT
 *   SUFFIX    domain_suffix       — имя и его поддомены          «x.com»    RULE_NAMESPACE
 *   WILDCARD  domain_suffix «.x»  — буквальный суффикс строки    «*.x.com»  RULE_WILDCARD
 *   KEYWORD   domain_keyword      — подстрока                    «*слово*»  RULE_WILDCARD
 *   REGEX     domain_regex        — регулярное выражение         «re:…»     RULE_REGEX */
enum srs_dom { SRS_DOM_EXACT, SRS_DOM_SUFFIX, SRS_DOM_WILDCARD, SRS_DOM_KEYWORD, SRS_DOM_REGEX };

enum srs_ek { SRS_EL_DOMAIN = 1, SRS_EL_CIDR = 2 };

/* Один элемент набора. Указатели живут до возврата из обратного вызова. */
struct srs_elem {
    enum srs_ek kind;
    int excl;                   /* 1 — элемент ИСКЛЮЧЕНИЯ клаузы («… и не это»), не назначения */
    uint32_t clause;            /* номер клаузы (srs_clause) */
    enum srs_dom dom;           /* SRS_EL_DOMAIN */
    const char *str;            /* SRS_EL_DOMAIN: строка с нулём в конце, без метки вида */
    size_t len;
    int family;                 /* SRS_EL_CIDR: 4 или 6 */
    uint8_t addr[16];           /* SRS_EL_CIDR: адрес сети, network order */
    int plen;
};

/* Вид клаузы: про что её назначение. Правило sing-box с именами И подсетями даёт ДВЕ клаузы
 * с одним и тем же сужением: имена сопоставляет резолвер, подсети — набор nftables, и у
 * исключений то же разделение (см. srs.c, «Нормальная форма»). */
#define SRS_C_DOM   1u          /* назначение — имена */
#define SRS_C_CIDR  2u          /* назначение — подсети */
#define SRS_C_ALL   3u          /* назначения нет: весь трафик приложения (только с package_name) */

/* Флаги клаузы. */
#define SRS_F_V4     0x01u      /* есть подсети IPv4 назначения */
#define SRS_F_V6     0x02u      /* есть подсети IPv6 назначения */
#define SRS_F_XDOM   0x04u      /* есть исключения-имена */
#define SRS_F_XCIDR  0x08u      /* есть исключения-подсети */

#define SRS_MAX_SRC  64         /* подсетей source_ip_cidr в клаузе */
#define SRS_MAX_PKG  16         /* пакетов package_name в клаузе */

struct srs_pfx4 { uint32_t net; int plen; };      /* host order */

struct srs_clause {
    unsigned kind;              /* SRS_C_* */
    unsigned flags;             /* SRS_F_* */
    /* Сужение: протокол и порты назначения. Порты — отсортированы и слиты, чтобы одинаковые
     * множества сравнивались равными (l4match_same сравнивает по порядку). */
    struct l4match l4;
    /* Как сужение записано в наборе: протоколы и порты в порядке появления, повторы сняты. Нужно
     * только `srs-read` — его вывод обязан остаться прежним побайтно. */
    int net_tcp, net_udp;
    struct port_range raw[MAX_PORTS];
    unsigned char raw_range[MAX_PORTS];   /* 1 — записан как port_range, печатается «a-b» */
    size_t raw_n;
    /* source_ip_cidr — ограничение по клиенту (IPv4; IPv6-источники сняты с предупреждением).
     * Отдельной памятью и только у тех клауз, где есть: клауз бывает много, а этого — почти
     * никогда. */
    const struct srs_pfx4 *src;
    size_t src_n;
    /* package_name — ограничение по приложению (телефон). */
    const char *const *pkg;
    size_t pkg_n;
    /* Сколько элементов назначения: подсетей v4 (уже разложенных на префиксы), v6 и имён. */
    size_t n_v4, n_v6, n_dom;
    size_t n_xv4;               /* подсетей v4 в исключениях (набор <группа>_x) */
    uint32_t rule;              /* номер правила верхнего уровня, из которого клауза */
};

struct srs_set;

/* Первый проход. 0 — разобран (клаузы готовы), -1 — файл не наш или испорчен (err). Второе
 * открытие того же пути отдаёт тот же разбор из памяти процесса, пока файл не изменился
 * (размер, время, inode), — поэтому звать можно из каждого места, где нужно, не сговариваясь.
 * Открытый разбор отпускается srs_release: пока он не отпущен, указатели на него и его клаузы
 * живы, даже если файл сменился и кэш завёл новый. srs_cache_drop отпускает ссылки кэша. */
int srs_open(const char *path, const struct srs_set **out, struct err *e);
void srs_release(const struct srs_set *s);
void srs_cache_drop(void);

size_t srs_clause_n(const struct srs_set *s);
const struct srs_clause *srs_clause(const struct srs_set *s, size_t i);
const char *srs_path(const struct srs_set *s);
/* Что снято при чтении (невыразимое или неприменимое на этой платформе), одной фразой для
 * строки steer[warn]; NULL — ничего. */
const char *srs_skipped(const struct srs_set *s);
/* Есть ли хоть одна клауза вида kind / с флагом flag. */
int srs_any_kind(const struct srs_set *s, unsigned kind);
int srs_any_flag(const struct srs_set *s, unsigned flag);

/* Второй проход: элементы по порядку файла. want — SRS_EL_DOMAIN|SRS_EL_CIDR: чего не просили,
 * то пропускается без выделения памяти (дерево имён не строится вовсе). sel — битовая карта
 * клауз (бит i — клауза i) или NULL — все. cb возвращает 0, чтобы продолжать; не 0 — обход
 * прерывается и srs_walk возвращает это значение. -1 с текстом в err — файл испорчен или
 * изменился после первого прохода. */
typedef int (*srs_cb)(void *ctx, const struct srs_elem *el);
int srs_walk(const struct srs_set *s, unsigned want, const uint8_t *sel,
             srs_cb cb, void *ctx, struct err *e);

/* Похож ли файл на набор sing-box: подпись «SRS» в первых трёх байтах. Подпись, а не
 * расширение: файл списка человек называет как хочет, а подпись у формата одна. */
int srs_sniff(const char *path);

/* ---- сужение: операции, которые нужны и потребителям ---------------------------------- */

/* Пересечение сужений: 1 — непусто (результат в out), 0 — пусто (ни один пакет не подойдёт
 * обоим). Если результат совпадает с a как множество, в out кладётся a как есть — порядок,
 * написанный человеком, сохраняется (от него зависит имя набора, см. group_set_name). */
int l4_intersect(const struct l4match *a, const struct l4match *b, struct l4match *out);
/* Равны ли как множества (порядок портов не важен). */
int l4_same_set(const struct l4match *a, const struct l4match *b);

/* Разложение сужения на ящики «протокол × порты» для составного набора nftables
 * (ipv4_addr . inet_proto . inet_service): без сужения — один ящик 0-255 × 0-65535. */
struct l4box { unsigned char plo, phi; unsigned short lo, hi; };
#define L4BOX_MAX (2 * MAX_PORTS + 1)
size_t l4_boxes(const struct l4match *m, struct l4box *out);
/* Объединение нескольких сужений в НЕПЕРЕСЕКАЮЩИЕСЯ ящики: ядро не принимает в составной
 * набор пересекающиеся элементы (EEXIST), а одному адресу бывают нужны два сужения сразу. */
size_t l4_union_boxes(const struct l4match *const *ms, size_t n, struct l4box *out);
/* Текст ящика для nft: «17 . 50000-65535». */
void l4_box_text(const struct l4box *b, char *dst, size_t n);
/* Сужение текстом для таблицы резолвера: «-» (нет), «udp/50000-65535+19000-20000». */
void l4_to_text(const struct l4match *m, char *dst, size_t n);
int l4_from_text(const char *s, size_t len, struct l4match *m);

#endif
