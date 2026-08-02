/* Shared spec: both the compiler and the resolver read the SAME file.
 *
 * The resolver could have been handed its channels as command-line arguments by
 * the compiler, but then two programs would carry two ideas of what a channel is,
 * and a stale service definition would silently disagree with the config. One
 * parser, one source of truth — and they ship in one binary, so a version skew
 * between them is not expressible.
 */
#ifndef STEER_SPEC_H
#define STEER_SPEC_H
#include <stdint.h>
#include <stddef.h>

#define MAX_CHANNELS 64
#define MAX_OUTPUTS  16
#define MAX_FROM     16
/* Several lists can feed ONE channel. Enabling "youtube" and "google" must not force
 * two channels with two rules and two sets — they are one destination as far as
 * routing is concerned. Read as several files rather than concatenated into one by
 * the caller: on a box with 6MB of overlay, duplicating list bytes to express "and"
 * is a cost with nothing to show for it. */
#define MAX_FILES    16

enum out_kind { OUT_DIRECT, OUT_INTERFACE };

/* Что делать с трафиком выхода, когда ни одно его устройство не работает.
 *
 * Умолчание — DROP, и это не осторожность ради осторожности: канал заводят именно
 * для того, чтобы трафик НЕ шёл напрямую. Молча вернуть его на открытый путь в
 * момент поломки — значит нарушить единственное обещание выхода ровно тогда, когда
 * это опаснее всего, и человек об этом не узнает. Пусть лучше не работает заметно,
 * чем работает не туда незаметно. */
enum on_fail { FAIL_DROP, FAIL_DIRECT, FAIL_ZAPRET };

/* Устройства выхода в порядке предпочтения: первое здоровое побеждает. Список — это
 * приоритет, ровно как порядок каналов. */
#define MAX_DEVICES 8

struct output {
    char name[32];
    enum out_kind kind;
    /* Активное устройство — то, через которое трафик идёт СЕЙЧАС. Отдельно от списка
     * кандидатов, потому что failover меняет его, не трогая настройку. */
    char device[32];
    char devices[MAX_DEVICES][32];
    size_t devices_n;
    enum on_fail on_fail;
    uint32_t mark;      /* 0 for direct: claiming a packet needs no mark */
    int table;
};

struct channel {
    char name[32];
    char out[32];
    char prefixes_files[MAX_FILES][256];
    size_t prefixes_n;
    char domains_files[MAX_FILES][256];
    size_t domains_n;
    /* fake-IP (default) or real-IP for a domain channel. See dnsd.c: fake-IP is
     * precise per domain but makes every traceroute hop show the fake address,
     * because the kernel rewrites ICMP errors to look like they came from the
     * address the client addressed. real-IP keeps hops legible and loses precision
     * only where two domains share one backend address. */
    int realip;
    char from[MAX_FROM][64];
    size_t from_n;
    int any;
    /* Явное согласие на канал, который забирает весь трафик. Без него `any` без
     * списков отвергается: это почти всегда описка, а последствие — клиенты
     * теряют и роутер, и DNS, то есть чинить придётся с провода. */
    int allow_all;
};

extern struct output g_out[MAX_OUTPUTS];
extern size_t g_out_n;
extern struct channel g_ch[MAX_CHANNELS];
extern size_t g_ch_n;
extern char g_from_default[MAX_FROM][64];
extern size_t g_from_default_n;
extern char g_lan_device[32];
extern int g_traceroute_hops;
extern const char *g_state_dir;

/* The port `steer dnsd` listens on and the redirect points at. One constant, so
 * the two halves cannot disagree about where DNS is being steered. */
#define DNS_PORT 5300

void die(const char *fmt, const char *a);
void load_spec(const char *path);
void registry_assign(void);
struct output *out_by_name(const char *n);

#endif
