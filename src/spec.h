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

/* Вид выхода.
 *
 * vless — это тоже устройство: клиент поднимает TUN, и дальше всё остальное (метки,
 * таблицы, failover, каналы) работает с ним ровно как с wireguard. Отдельный вид нужен
 * только потому, что устройство надо СОЗДАТЬ и обслуживать процессом, тогда как
 * wireguard уже есть в системе к моменту apply.
 *
 * xsteer — свой протокол поверх поддельного TCP с конфигурацией в стиле wg (см.
 * docs/xsteer.md). Тоже отдельный ВИД, а не свойство существующего, и здесь оба довода
 * из struct out_obfs ниже переворачиваются. Первый: у obfs выход по смыслу остаётся тем
 * же интерфейсом, устройство уже есть, и старому движку достаточно не сломаться. У
 * xsteer устройства нет — его создаёт наш процесс, и спека, применённая базовой сборкой
 * «как интерфейс», дала бы правила, метки и таблицу, ведущую в устройство, которого
 * никто не создаст: человек увидел бы исправную конфигурацию, из которой не выходит ни
 * один пакет. Отказ парсером здесь не цена совместимости, а единственный честный ответ.
 * Второй: obfs не меняет того, чем выход является для остальной части движка, а xsteer
 * меняет, кто отвечает за жизнь устройства (наш процесс, а не netifd), — и это ровно то
 * различие, ради которого заводился OUT_VLESS.
 *
 * Значения добавляются В КОНЕЦ: в /var/lib/steer/registry лежат имя, метка и таблица, а
 * вид нигде не сериализуется, поэтому порядок можно не защищать — но и менять его без
 * нужды незачем. */
enum out_kind { OUT_DIRECT, OUT_INTERFACE, OUT_VLESS, OUT_XSTEER };

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

/* Обфускация транспорта выхода: WireGuard поверх поддельного TCP (см. obfs.c).
 *
 * Не отдельный вид выхода, а свойство существующего, и это не вкусовщина. Неизвестный
 * `kind` старый движок отвергает целиком (parse_outputs), то есть спека, записанная
 * новым интерфейсом, положила бы маршрутизацию на не обновлённом роутере; неизвестный
 * КЛЮЧ он пропускает (js_skip). Плюс по смыслу выход остаётся тем же интерфейсом —
 * меняется только то, чем его эндпоинт доставляется до сервера.
 *
 * Ключами WireGuard движок не владеет и владеть не должен: они живут в
 * /etc/config/network, а здесь лежит ровно то, что нужно обфускатору. */
struct out_obfs {
    int on;
    char server[64];        /* адрес сервера обфускации, только литерал (см. spec.c) */
    int server_port;
    /* Куда смотрит `Endpoint` пира WireGuard. По умолчанию 127.0.0.1: наружу этот порт
     * торчать не должен — трафик к нему уже расшифрован для WireGuard. */
    char listen[64];
    int listen_port;
};

struct output {
    char name[32];
    enum out_kind kind;
    /* Активное устройство — то, через которое трафик идёт СЕЙЧАС. Отдельно от списка
     * кандидатов, потому что failover меняет его, не трогая настройку. */
    char device[32];
    char devices[MAX_DEVICES][32];
    size_t devices_n;
    enum on_fail on_fail;
    /* Только для kind=vless: откуда брать узлы. Подписка, а не один узел, потому что
     * failover между узлами — то же самое, что между устройствами, и списком он и
     * выражается. Файл, а не URL: скачивание это дело управляющего слоя, движок читает
     * то, что ему положили — см. правило про списки в README. */
    char sub_file[256];
    /* Какой узел подписки использовать. -1 (по умолчанию) означает «первый рабочий»:
     * тогда выбор делает проверка при подъёме, а не человек, угадывающий номер. */
    int node_index;
    /* Только для kind=xsteer: путь к конфигурации в стиле wg. ПУТЬ, а не сами ключи, и
     * это принципиально: спеку читает и печатает целиком управляющий слой, она уходит в
     * status (его опрашивают раз в пять секунд), в diag и в резервную копию. Приватный
     * ключ в ней означал бы ключ, уже покинувший коробку. По умолчанию выводится из
     * имени выхода — держать два имени, которым позволено разойтись, незачем (то же
     * решение, что с device). */
    char xs_conf[256];
    struct out_obfs obfs;
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
    /** Выключенное правило: лежит в спеке, но в правила не превращается.
     *
     *  Нужно потому, что «отключу на вечер» — самая частая просьба, а единственным способом
     *  было удалить канал вместе с выбранными списками и собрать его заново. Интерфейс до
     *  этого поля обходился так: вынимал канал из спеки и держал у себя. Работало, но канал
     *  становился невидим движку — ни `status`, ни `explain` о нём не знали, и «почему сайт
     *  не идёт» приходилось объяснять тем, чего в спеке нет.
     *
     *  Умолчание — включён: спека, написанная до этого поля, обязана значить то же, что
     *  значила. Поэтому в JSON поле называется `enabled` и проверяется на `false`, а внутри
     *  хранится обратное — так поле, которого нет, даёт нуль и означает «работает». */
    int disabled;
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

/* Выход, у которого есть устройство и своя таблица маршрутизации. vless сюда входит:
 * его TUN — такое же устройство, и вся логика меток, маршрутов и проверок к нему
 * применима без изменений. Одна функция вместо повторения условия в пяти местах —
 * иначе добавление нового вида требовало бы найти их все, а забытое место означало бы
 * выход, который настроен, но не маршрутизируется. */
static inline int out_has_device(const struct output *o) {
    return o->kind == OUT_INTERFACE || o->kind == OUT_VLESS || o->kind == OUT_XSTEER;
}

/* Выход, устройство которого создаёт и обслуживает НАШ процесс, а не netifd.
 *
 * Отдельно от out_has_device, потому что из этого следуют другие вещи: ждать устройство
 * снаружи нельзя (его ещё нет), ifdown/ifup бесполезны (netifd про него не знает —
 * «Interface … not found», и на живом роутере это вечный холостой цикл в журнале), а
 * поднимает замену procd. */
static inline int out_engine_managed(const struct output *o) {
    return o->kind == OUT_VLESS || o->kind == OUT_XSTEER;
}

/* Выход, которому masquerade не нужен: наружу он ходит от своего имени.
 *
 * Причины у vless и xsteer РАЗНЫЕ, и объединять их формулировкой нельзя — только
 * следствием. У vless адреса клиентов границу не переходят вовсе: клиент завершает TCP у
 * себя и соединяется с сервером обычным сокетом. У xsteer они переходят, но переходят к
 * хабу внутри туннеля, где транслировать их нечем и не нужно; более того, NAT там ВРЕДЕН
 * — он скрывает, от какой пира пришёл пакет, и ломает обратный поиск по AllowedIPs.
 * Отсюда одна функция для решения и разные тексты в сообщениях. */
static inline int out_self_natting(const struct output *o) {
    return o->kind == OUT_VLESS || o->kind == OUT_XSTEER;
}

/* Имя вида для печати и разбор имени обратно. Обе — над ОДНОЙ таблицей в spec.c.
 *
 * Заведены потому, что знание «какие бывают виды» лежало в четырёх местах: тройной
 * тернарник в status, такой же в outputs, список в проверке --kind и список в тексте
 * справки. Тернарник печатал бы новый вид как «interface» — молча, — а половинчато
 * добавленный вид даёт либо пустой вывод при верном флаге, либо справку о том, чего
 * разбор не знает. Это ровно тот класс поломки, про который написано у registry_assign. */
const char *out_kind_name(enum out_kind k);
int out_kind_known(const char *s);

void die(const char *fmt, const char *a);
/* Годен ли идентификатор из спеки к подстановке в командную строку и в имя набора.
 * Проверяется парсером при загрузке — см. развёрнутое объяснение у определения. */
int name_ok(const char *s);
/* Годна ли ПОДПИСЬ (имя канала) к выводу в JSON и в текст ruleset. Мягче name_ok:
 * разрешает любой UTF-8, запрещает кавычку, обратную косую и управляющие символы. */
int label_ok(const char *s);

/* Имя набора nftables для группы каналов. Вычисляют двое — компилятор и резолвер, — и
 * функция общая именно поэтому: разойдись они в имени, резолвер наполнял бы набор,
 * которого нет. kind — "ip", "dom" или "all". Подробности у определения в spec.c. */
void group_set_name(char *dst, size_t n, const char *out, const char *kind,
                    const char (*from)[64], size_t from_n, int realip);
void load_spec(const char *path);
void registry_assign(void);
struct output *out_by_name(const char *n);

/* Привязать таблицу выхода к устройству: правило по метке и маршрут по умолчанию. Живёт в
 * failover.c, но нужна и клиенту VLESS: он привязывает своё устройство сам, потому что
 * только он знает момент, когда оно готово нести трафик. */
void bind_device(struct output *o, const char *dev);

#endif
