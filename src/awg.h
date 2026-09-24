/* Выход kind=awg: туннель AmneziaWG/WireGuard, которым движок управляет САМ, через модуль ядра.
 *
 * ЗАЧЕМ ОТДЕЛЬНЫЙ ВИД. До сих пор WireGuard в движке был только «чужим» устройством: выход
 * kind=interface называет интерфейс, который завёл кто-то другой (netifd на роутере), а движок
 * лишь метит трафик и ведёт таблицу в это устройство. На телефоне завести интерфейс некому:
 * netifd нет, а клиент WireGuard для Android — это VpnService, то есть ровно то, от чего
 * владелец отказался («маршрутизация ядра, Android ничего не замечает»: VpnService виден
 * ConnectivityService, рисует ключик в строке состояния и перехватывает весь трафик
 * телефона, а не каналы). Модуль ядра AmneziaWG (или обычный WireGuard) даёт туннель, который
 * живёт целиком в ядре: ни процесса, ни TUN, ни пробуждений процессора ради пересылки пакета.
 * Это и есть ответ на требование батареи — пакет в туннель шифрует ядро в том же проходе,
 * которым его отправило приложение.
 *
 * Отличие от kind=interface — КТО ОТВЕЧАЕТ ЗА ЖИЗНЬ УСТРОЙСТВА (тот же довод, что заводил
 * vless и xsteer): устройство создаёт и настраивает движок при apply, снимает при `steer down`
 * и при удалении выхода из спеки. Отличие от vless/xsteer — процесса нет вовсе: после apply
 * движку делать нечего, туннель работает без него.
 *
 * ФАЙЛ, А НЕ ПОЛЯ СПЕКИ. Ключи живут в файле формата awg-quick/wg-quick (путь — `conf` в
 * спеке), и спека секретов не несёт: её печатают status, diag и резервная копия (тот же
 * довод, что у xs_conf). Формат — ровно тот, что выдают Amnezia и обычные серверы WireGuard,
 * чтобы человек клал в движок файл, который у него уже есть, а не переписывал его руками.
 *
 * РЕАЛИЗАЦИЯ СВОЯ. embeddable-wg-library из wireguard-tools/amneziawg-tools — LGPL-2.1+, а
 * движок вшивается статически (роутер, образ Android); такой код в нём означал бы
 * обязательства, которых у проекта нет. Своя реализация — это разбор текста и сборка
 * нескольких сообщений netlink поверх построителя, который в движке уже есть (nlbuf.h).
 * Числа констант повторены из uapi-заголовков модуля (GPL-2.0 WITH Linux-syscall-note OR MIT —
 * интерфейс ядра, повторять его законно) — см. awg.c. */
#ifndef STEER_AWG_H
#define STEER_AWG_H
#include <stdint.h>
#include <stddef.h>
#include <stdio.h>
#include <string.h>
#include <strings.h>
#include <sys/socket.h>
#include <netinet/in.h>

struct output;

#define AWG_KEY_LEN   32
/* Пиров в одном файле. У клиента пир почти всегда один (сервер); несколько бывает у
 * сетки «каждый с каждым». Восемь — с запасом и с фиксированным бюджетом памяти. */
#define AWG_MAX_PEERS 8
/* Адресов интерфейса (Address): v4 и v6, иногда по нескольку. */
#define AWG_MAX_ADDRS 8
/* AllowedIPs ВСЕГО по всем пирам. Предел выведен из сообщения, а не из вкуса: вся настройка
 * пиров уходит ядру одним атрибутом WGDEVICE_A_PEERS, а длина атрибута netlink — 16 бит.
 * Запись AllowedIPs занимает до 40 байт (IPv6), 1024 записи — около 41 КБ, остальное — на
 * ключи и адреса. Файлы Amnezia с «раздельным туннелированием» приносят сотни подсетей в
 * AllowedIPs; у движка маршрутизацию решают каналы, и туннелю обычно нужен 0.0.0.0/0, но
 * отвергать чужой файл за длинный список незачем, пока он влезает. */
#define AWG_MAX_AIPS  1024
/* Длина одной строки I1..I5 (описание «имитирующего» пакета, `<b 0x…><r 16>…`). Шестнадцать
 * килобайт — несколько датаграмм в шестнадцатеричной записи; больше в одну датаграмму не
 * влезает всё равно. */
#define AWG_MAX_ISTR  16384

struct awg_prefix {
    uint8_t family;         /* AF_INET или AF_INET6 */
    uint8_t cidr;
    uint8_t addr[16];
};

struct awg_peer {
    uint8_t pub[AWG_KEY_LEN];
    int has_psk;            /* сам ключ — в struct awg_secrets */
    /* Endpoint как записан: имя или литерал и порт. Имя разрешается при apply, а не при
     * разборе: разбор зовёт и `--dry-run` интерфейса, и стенд, у которых сети может не быть. */
    char ep_host[256];
    uint16_t ep_port;
    int has_ep;
    struct sockaddr_storage ep;     /* заполняет awg_resolve */
    socklen_t ep_len;               /* 0 — не разрешён */
    size_t aip_first, aip_n;        /* срез conf->aips */
    /* PersistentKeepalive: диапазон секунд, упакованный как у модуля (lo | hi << 16).
     * 0 — выключен, и это умолчание НАРОЧНО: keepalive будит радио каждые N секунд, а
     * требование владельца — нормальный сон устройства. Включается только файлом. */
    uint32_t keepalive;
    int adv_sec, has_adv_sec;       /* AdvancedSecurity (флаг пира у AmneziaWG) */
};

/* Параметры AmneziaWG. Перечислениями, а не отдельными полями: у каждого есть «задан ли», и
 * сравнение двух настроек (нужно ли пересоздать устройство) проходит их циклом, а не
 * перечнем, который однажды забудет новое поле. */
enum { AWG_JC, AWG_JMIN, AWG_JMAX, AWG_S1, AWG_S2, AWG_S3, AWG_S4, AWG_U16_N };
/* Параметры AmneziaWG 3 со значением-диапазоном 16 бит, упакованным в u32 (lo | hi << 16). */
enum { AWG_CPA, AWG_REKEY_AFTER, AWG_REKEY_TIMEOUT, AWG_REJECT_AFTER, AWG_KA_TIMEOUT,
       AWG_MAX_HS, AWG_R16_N };
enum { AWG_RANDOM_TRAILERS, AWG_DISABLE_COOKIES, AWG_U8_N };

/* Всё из файла, КРОМЕ секретов. Разделение типом, а не дисциплиной (приём xsconf.h): всё,
 * что печатает, журналирует или сравнивает, принимает эту структуру и до ключа дотянуться
 * не может; ключи лежат в struct awg_secrets, попадают только в сообщение ядру и
 * затираются awg_secrets_wipe. */
struct awg_conf {
    struct awg_prefix addr[AWG_MAX_ADDRS];
    size_t addr_n;
    int mtu;                        /* 0 — не задан (движок ставит 1420, как wg-quick) */
    uint16_t listen_port;
    int has_listen_port;
    int dns_n;                      /* строк DNS: движок их не применяет — см. awg.c */
    unsigned ignored;               /* AWG_IGN_*: ключи wg-quick, которые движок не исполняет */
    uint16_t u16[AWG_U16_N];
    unsigned u16_has;
    uint64_t h[4];                  /* H1..H4: lo | hi << 32 */
    unsigned h_has;
    char *istr[5];                  /* I1..I5, NULL — нет */
    uint32_t r16[AWG_R16_N];
    unsigned r16_has;
    uint8_t u8v[AWG_U8_N];
    unsigned u8_has;
    int has_hpk;                    /* HeaderProtectionKey (сам ключ — в секретах) */
    struct awg_peer peer[AWG_MAX_PEERS];
    size_t peer_n;
    struct awg_prefix aips[AWG_MAX_AIPS];
    size_t aips_n;
};

#define AWG_IGN_TABLE    1u
#define AWG_IGN_FWMARK   2u
#define AWG_IGN_SCRIPTS  4u   /* PreUp/PostUp/PreDown/PostDown */
#define AWG_IGN_SAVE     8u

struct awg_secrets {
    uint8_t priv[AWG_KEY_LEN];
    int has_priv;
    uint8_t hpk[AWG_KEY_LEN];
    uint8_t psk[AWG_MAX_PEERS][AWG_KEY_LEN];
};

/* Разобрать текст файла. 0 — годен; -1 — нет, в err причина с номером строки. В причине НЕТ
 * значений — только имя параметра: значение может быть ключом, а текст ошибки уходит в
 * журнал и на экран. conf и secrets заполняются с нуля; после любого исхода conf надо
 * освободить awg_conf_free, secrets — затереть awg_secrets_wipe. */
int awg_conf_parse(const char *text, size_t n, struct awg_conf *c, struct awg_secrets *s,
                   char *err, size_t errn);
int awg_conf_load(const char *path, struct awg_conf *c, struct awg_secrets *s,
                  char *err, size_t errn);
void awg_conf_free(struct awg_conf *c);
void awg_secrets_wipe(struct awg_secrets *s);

/* Нужен ли модуль AmneziaWG: задан ли хоть один параметр, которого обычный WireGuard не
 * понимает (со значением, отличным от поведения WireGuard). 0 — файл годится и для
 * модуля wireguard. */
int awg_conf_needs_awg(const struct awg_conf *c);
/* Наименьшая версия семейства generic netlink «amneziawg», которая выражает все параметры
 * файла: 1 — J/S1/S2/H одним числом, 2 — S3/S4/I1..I5/диапазоны H, 3 — параметры AmneziaWG 3
 * и диапазон PersistentKeepalive. Для файла без параметров AmneziaWG — 1. Если параметр
 * файла требует более новой версии, чем у модуля, — это отказ: старое ядро молча отбросило
 * бы незнакомый атрибут, и туннель встал бы без обфускации, которую ждёт сервер. */
int awg_conf_min_version(const struct awg_conf *c, const char **why);

/* Сборка сообщения WG_CMD_SET_DEVICE. Выставлено наружу ради стенда awgmatch (побайтная
 * сверка атрибутов); движок зовёт её из awg_configure. is_awg — семейство «amneziawg» (иначе
 * «wireguard», и атрибутов AmneziaWG в сообщении нет вовсе), famver — его версия.
 * replace_peers — снять пиров, которых нет в файле (WGDEVICE_F_REPLACE_PEERS). Возврат — длина
 * сообщения или 0, если оно не влезло в cap. */
size_t awg_build_set(uint8_t *buf, size_t cap, uint16_t famid, int famver, int is_awg,
                     const char *ifname, const struct awg_conf *c,
                     const struct awg_secrets *s, uint32_t fwmark, int replace_peers,
                     uint32_t seq);
/* RTM_NEWLINK с IFLA_INFO_KIND: создать устройство. */
size_t awg_build_newlink(uint8_t *buf, size_t cap, const char *ifname, const char *kind,
                         int mtu, uint32_t seq);
/* CTRL_CMD_GETFAMILY по имени семейства. */
size_t awg_build_getfamily(uint8_t *buf, size_t cap, const char *name, uint32_t seq);

/* Метка сокета туннеля (WGDEVICE_A_FWMARK). via — имя выхода, через который должен идти UDP
 * туннеля, или NULL: тогда метка «мимо каналов движка». -1 — выхода via нет; 0 — годна, метка
 * в *mark. Подробности — у определения. */
int awg_sock_mark(const char *via, uint32_t *mark);

/* Годится ли файл для туннеля, который идёт через via: 0 — да; -1 — нет, причина в err (без
 * ключей). Сейчас одна причина — Endpoint с адресом IPv6: таблица выхода-цели и её ip rule
 * только для IPv4, и такой туннель ушёл бы мимо цели. Подробности — у определения. */
int awg_via_check(const struct awg_conf *c, const char *via, char *err, size_t n);

/* ---- то, что зовут apply, down, status и сторож ------------------------------------ */

/* Поднять и настроить устройства всех выходов kind=awg, снять устройства выходов, которых в
 * спеке больше нет. Возврат — сколько выходов не поднялось (о каждом — строка в журнале). */
int awg_apply_all(void);
/* Проверить файлы выходов kind=awg без касания ядра (apply --dry-run): ошибки — строками
 * steer[warn] в stderr. Возврат — сколько файлов негодны. */
int awg_check_all(void);
/* Снять все устройства, которые движок заводил (по реестру в каталоге состояния). */
void awg_down_all(void);
/* Здоровье устройства по свежести рукопожатия, без проб. 1 — живо или сказать нечего. */
int awg_healthy(const struct output *o, const char *dev);
/* Починка молчащего туннеля: заново разрешить Endpoint и перенастроить (создать, если
 * устройства нет). Возврат — как у awg_healthy после починки. */
int awg_revive(const struct output *o, const char *dev);
/* Поле "awg" у выхода в `steer status`: начинается с запятой. */
void awg_status_json(FILE *out, const struct output *o);

/* ---- имя устройства ----------------------------------------------------------------
 *
 * ИМЯ ВЫБИРАЕТ ДВИЖОК, И ОНО НЕ ДОЛЖНО ВЫДАВАТЬ ТУННЕЛЬ. Решение владельца: туннель на телефоне
 * не должен выделяться. Приложение без всяких прав видит имена интерфейсов с адресом
 * (getifaddrs → RTM_GETADDR, который платформа приложениям оставляет), и библиотеки «есть ли
 * VPN» решают ровно по имени: tun*, ppp*, wg*, ipsec*… Поэтому имя берётся из имени выхода —
 * так же, как у vless и xsteer (device по умолчанию — имя выхода, усечённое до 15 символов,
 * см. spec.c и tests/tunnamematch.c), — но если оно начинается с одного из этих слов, вместо
 * него берётся нейтральное «if» + восемь шестнадцатеричных знаков хэша имени выхода.
 * Детерминированно: одно имя выхода — одно устройство при каждом apply и на каждом
 * устройстве, иначе реестр и снятие по нему потеряли бы прежний интерфейс.
 *
 * Здесь, в заголовке, и static inline — потому что спрашивает об этом разбор спеки (spec.c),
 * а spec.c собирают стенды, у которых awg.c нет. */
static inline int awg_ifname_conspicuous(const char *s) {
    static const char *const bad[] = {
        "tun", "tap", "utun", "wg", "awg", "ppp", "pptp", "ipsec", "vpn", "l2tp",
        "wireguard", "amnezia",
    };
    for (size_t i = 0; i < sizeof bad / sizeof bad[0]; i++)
        if (!strncasecmp(s, bad[i], strlen(bad[i]))) return 1;
    return 0;
}

static inline void awg_default_ifname(const char *out_name, char *dst, size_t n) {
    if (strlen(out_name) <= 15 && !awg_ifname_conspicuous(out_name)) {
        snprintf(dst, n, "%s", out_name);
        return;
    }
    /* FNV-1a 32: короткий, без зависимостей, и его хватает — от хэша требуется только
     * различать выходы одной спеки, а не стойкость. */
    uint32_t h = 2166136261u;
    for (const char *p = out_name; *p; p++) { h ^= (uint8_t)*p; h *= 16777619u; }
    snprintf(dst, n, "if%08x", h);
}

#endif
