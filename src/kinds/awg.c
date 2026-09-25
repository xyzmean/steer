/* Выход kind=awg: туннель AmneziaWG/WireGuard в ядре, которым управляет движок.
 *
 * Зачем этот вид и почему файл, а не поля спеки, — в шапке awg.h. Здесь — как.
 *
 * ЖИЗНЕННЫЙ ЦИКЛ. apply (awg_apply_all) для каждого выхода: читает файл, разрешает имена
 * Endpoint, создаёт устройство, если его нет (RTM_NEWLINK с видом "amneziawg", при отсутствии
 * модуля и файле без обфускации — "wireguard"), настраивает его одним сообщением
 * WG_CMD_SET_DEVICE, ставит MTU, адреса и поднимает. Дальше таблицу выхода к устройству
 * привязывает apply_routing — тем же путём, что у kind=interface. Устройство, которое уже
 * есть, НЕ пересоздаётся: настройка ложится поверх, и живые сессии пиров, чьи ключи не
 * менялись, не рвутся (WireGuard не трогает сессию, если ключ, PSK и эндпоинт те же).
 * Пересоздание — только когда поверх нельзя: сменился вид (файл стал требовать AmneziaWG, а
 * устройство — wireguard) или из файла убран параметр AmneziaWG, у которого нет значения
 * «как не задан» (снять Jc или H1 поверх нельзя — модуль оставил бы прежнее).
 * `steer down` и удаление выхода из спеки снимают устройство по реестру в каталоге
 * состояния — как метки и таблицы у registry_assign.
 *
 * БАТАРЕЯ. После apply движок в жизни туннеля не участвует: ни процесса, ни таймеров.
 * Здоровье сторож судит по тому, что ядро и так знает, — свежести последнего рукопожатия и
 * счётчикам пира (WG_CMD_GET_DEVICE), без единого пакета от себя. PersistentKeepalive по
 * умолчанию выключен и включается только файлом: keepalive — это пробуждение радио каждые
 * N секунд.
 *
 * СЕКРЕТЫ. Приватный ключ, PSK и ключ защиты заголовка живут в struct awg_secrets и в буфере
 * сообщения ядру — и то и другое затирается сразу после отправки. Ответ WG_CMD_GET_DEVICE
 * ядро присылает С ПРИВАТНЫМ КЛЮЧОМ (у вызывающего есть CAP_NET_ADMIN), поэтому буфер приёма
 * затирается тоже. В status, журнал и сообщения об ошибках ключи не попадают: разбор
 * называет только имя параметра, никогда значение. */
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <ifaddrs.h>
#include <net/if.h>
#include <netdb.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <sys/types.h>
#include <time.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <linux/netlink.h>
#include <linux/rtnetlink.h>
#include <linux/genetlink.h>

#include "spec.h"
#include "awg.h"
#include "nlbuf.h"
#include "run.h"

#define LOG_W "steer[warn] awg: "
#define LOG_I "steer[info] awg: "

/* ---- интерфейс модуля: числа из uapi ------------------------------------------------
 *
 * Повторены из src/uapi/wireguard.h модуля amneziawg-linux-kernel-module (он же — uapi
 * WireGuard, дополненный в конце): GPL-2.0 WITH Linux-syscall-note OR MIT. Заголовок модуля в
 * системе не ставится (ни в sysroot musl, ни в NDK), поэтому числа здесь, со своими именами,
 * чтобы не столкнуться с <linux/wireguard.h>, если он где-то есть. Порядок — порядок enum в
 * uapi, и менять его нельзя: номер атрибута и есть интерфейс. */
#define AWG_GENL_NAME "amneziawg"
#define WG_GENL_NAME_ "wireguard"

enum { AWG_CMD_GET_DEVICE = 0, AWG_CMD_SET_DEVICE = 1 };
#define AWG_DEV_F_REPLACE_PEERS 1u
enum {
    AD_UNSPEC, AD_IFINDEX, AD_IFNAME, AD_PRIVATE_KEY, AD_PUBLIC_KEY, AD_FLAGS, AD_LISTEN_PORT,
    AD_FWMARK, AD_PEERS, AD_JC, AD_JMIN, AD_JMAX, AD_S1, AD_S2, AD_H1, AD_H2, AD_H3, AD_H4,
    AD_PEER, AD_S3, AD_S4, AD_I1, AD_I2, AD_I3, AD_I4, AD_I5, AD_HEADER_PROTECTION_KEY,
    AD_CONTENT_PADDING_ADDITION, AD_REKEY_AFTER_TIME, AD_REKEY_TIMEOUT, AD_REJECT_AFTER_TIME,
    AD_KEEPALIVE_TIMEOUT, AD_MAX_HANDSHAKE_ATTEMPTS, AD_RANDOM_TRAILERS, AD_DISABLE_COOKIES,
};
#define AWG_PEER_F_REPLACE_ALLOWEDIPS 2u
#define AWG_PEER_F_HAS_ADVANCED_SECURITY 8u
enum {
    AP_UNSPEC, AP_PUBLIC_KEY, AP_PRESHARED_KEY, AP_FLAGS, AP_ENDPOINT,
    AP_PERSISTENT_KEEPALIVE_INTERVAL, AP_LAST_HANDSHAKE_TIME, AP_RX_BYTES, AP_TX_BYTES,
    AP_ALLOWEDIPS, AP_PROTOCOL_VERSION, AP_ADVANCED_SECURITY,
};
enum { AA_UNSPEC, AA_FAMILY, AA_IPADDR, AA_CIDR_MASK };

/* Атрибуты AmneziaWG в порядке перечислений awg.h — чтобы сборка шла циклом. */
static const uint16_t U16_ATTR[AWG_U16_N] = { AD_JC, AD_JMIN, AD_JMAX, AD_S1, AD_S2, AD_S3, AD_S4 };
static const char *const U16_NAME[AWG_U16_N] = { "Jc", "Jmin", "Jmax", "S1", "S2", "S3", "S4" };
static const uint16_t R16_ATTR[AWG_R16_N] = {
    AD_CONTENT_PADDING_ADDITION, AD_REKEY_AFTER_TIME, AD_REKEY_TIMEOUT, AD_REJECT_AFTER_TIME,
    AD_KEEPALIVE_TIMEOUT, AD_MAX_HANDSHAKE_ATTEMPTS,
};
static const char *const R16_NAME[AWG_R16_N] = {
    "ContentPaddingAddition", "RekeyAfterTime", "RekeyTimeout", "RejectAfterTime",
    "KeepaliveTimeout", "MaxHandshakeAttempts",
};
static const uint16_t U8_ATTR[AWG_U8_N] = { AD_RANDOM_TRAILERS, AD_DISABLE_COOKIES };
static const char *const U8_NAME[AWG_U8_N] = { "RandomTrailers", "DisableCookies" };

/* Затирание, которое компилятор не выбросит: memset по памяти, которую дальше не читают,
 * оптимизатор вправе убрать, а здесь это ключи. */
static void wipe(void *p, size_t n) {
    volatile uint8_t *v = p;
    while (n--) *v++ = 0;
}

void awg_secrets_wipe(struct awg_secrets *s) {
    if (s) wipe(s, sizeof(*s));
}

void awg_conf_free(struct awg_conf *c) {
    if (!c) return;
    for (int i = 0; i < 5; i++) { free(c->istr[i]); c->istr[i] = NULL; }
}

/* ---- разбор файла ------------------------------------------------------------------- */

/* base64 ключа: ровно 44 знака, последний '=', 32 байта. Своя функция, а не общая из
 * расширенной сборки (xsconf.c): awg живёт в БАЗОВОМ движке, где ext нет. Строгость как у
 * wg: лишние биты в последнем знаке — отказ, иначе два разных текста давали бы один ключ,
 * и сверка «тот ли ключ» глазами обманывала бы. */
static int b64v(int ch) {
    if (ch >= 'A' && ch <= 'Z') return ch - 'A';
    if (ch >= 'a' && ch <= 'z') return ch - 'a' + 26;
    if (ch >= '0' && ch <= '9') return ch - '0' + 52;
    if (ch == '+') return 62;
    if (ch == '/') return 63;
    return -1;
}

static int key_from_b64(uint8_t out[AWG_KEY_LEN], const char *s) {
    if (strlen(s) != 44 || s[43] != '=') return -1;
    uint32_t acc = 0;
    size_t o = 0;
    for (int i = 0; i < 43; i++) {
        int v = b64v((unsigned char)s[i]);
        if (v < 0) return -1;
        acc = (acc << 6) | (uint32_t)v;
        if (i % 4 == 3) {
            out[o++] = (uint8_t)(acc >> 16);
            out[o++] = (uint8_t)(acc >> 8);
            out[o++] = (uint8_t)acc;
            acc = 0;
        }
    }
    /* Хвост: 3 знака = 18 бит, из них 16 — два последних байта, 2 младших обязаны быть 0. */
    if (acc & 3u) return -1;
    out[o++] = (uint8_t)(acc >> 10);
    out[o++] = (uint8_t)(acc >> 2);
    return o == AWG_KEY_LEN ? 0 : -1;
}

static char *trim(char *s) {
    while (*s == ' ' || *s == '\t' || *s == '\r') s++;
    size_t n = strlen(s);
    while (n && (s[n - 1] == ' ' || s[n - 1] == '\t' || s[n - 1] == '\r' || s[n - 1] == '\n'))
        s[--n] = '\0';
    return s;
}

/* Десятичное число в [lo, hi], вся строка. */
static int parse_num(const char *s, unsigned long lo, unsigned long hi, unsigned long *out) {
    if (!*s) return -1;
    for (const char *p = s; *p; p++) if (*p < '0' || *p > '9') return -1;
    if (strlen(s) > 10) return -1;
    unsigned long v = strtoul(s, NULL, 10);
    if (v < lo || v > hi) return -1;
    *out = v;
    return 0;
}

/* «N» или «N-M» с N ≤ M ≤ max. Так модуль записывает H1..H4 и параметры AmneziaWG 3. */
static int parse_range(const char *s, unsigned long max, unsigned long *lo, unsigned long *hi) {
    char buf[32];
    if (strlen(s) >= sizeof buf) return -1;
    snprintf(buf, sizeof buf, "%s", s);
    char *dash = strchr(buf, '-');
    if (dash) *dash = '\0';
    if (parse_num(trim(buf), 0, max, lo) != 0) return -1;
    if (!dash) { *hi = *lo; return 0; }
    if (parse_num(trim(dash + 1), 0, max, hi) != 0 || *hi < *lo) return -1;
    return 0;
}

static int parse_bool(const char *s, int *out) {
    if (!strcasecmp(s, "true") || !strcasecmp(s, "on") || !strcasecmp(s, "yes") || !strcmp(s, "1"))
        { *out = 1; return 0; }
    if (!strcasecmp(s, "false") || !strcasecmp(s, "off") || !strcasecmp(s, "no") || !strcmp(s, "0"))
        { *out = 0; return 0; }
    return -1;
}

/* «адрес[/префикс]». Без префикса — один хозяин (/32 или /128), как у wg-quick. */
static int parse_prefix(const char *s, struct awg_prefix *p) {
    char buf[64];
    if (strlen(s) >= sizeof buf) return -1;
    snprintf(buf, sizeof buf, "%s", s);
    char *sl = strchr(buf, '/');
    if (sl) *sl = '\0';
    memset(p, 0, sizeof(*p));
    if (inet_pton(AF_INET, buf, p->addr) == 1) { p->family = AF_INET; p->cidr = 32; }
    else if (inet_pton(AF_INET6, buf, p->addr) == 1) { p->family = AF_INET6; p->cidr = 128; }
    else return -1;
    if (sl) {
        unsigned long v;
        if (parse_num(sl + 1, 0, p->cidr, &v) != 0) return -1;
        p->cidr = (uint8_t)v;
    }
    return 0;
}

/* Endpoint: «хост:порт», «[v6]:порт». Литерал IPv6 без скобок — отказ: где кончается адрес и
 * начинается порт, в «fd00::1:51820» не решить, и любое угадывание однажды угадает не так. */
static int parse_endpoint(const char *s, struct awg_peer *pe) {
    char host[256];
    const char *port;
    if (*s == '[') {
        const char *rb = strchr(s, ']');
        if (!rb || rb[1] != ':' || (size_t)(rb - s - 1) >= sizeof host) return -1;
        memcpy(host, s + 1, (size_t)(rb - s - 1));
        host[rb - s - 1] = '\0';
        struct in6_addr a6;
        if (inet_pton(AF_INET6, host, &a6) != 1) return -1;
        port = rb + 2;
    } else {
        const char *c = strrchr(s, ':');
        if (!c || c == s || (size_t)(c - s) >= sizeof host) return -1;
        memcpy(host, s, (size_t)(c - s));
        host[c - s] = '\0';
        if (strchr(host, ':')) return -1;
        port = c + 1;
    }
    unsigned long v;
    if (parse_num(port, 1, 65535, &v) != 0) return -1;
    snprintf(pe->ep_host, sizeof pe->ep_host, "%s", host);
    pe->ep_port = (uint16_t)v;
    pe->has_ep = 1;
    return 0;
}

#define PERR(...) do { snprintf(err, errn, __VA_ARGS__); goto fail; } while (0)

int awg_conf_parse(const char *text, size_t n, struct awg_conf *c, struct awg_secrets *s,
                   char *err, size_t errn) {
    memset(c, 0, sizeof(*c));
    memset(s, 0, sizeof(*s));
    if (errn) err[0] = '\0';
    enum { SEC_NONE, SEC_IF, SEC_PEER } sec = SEC_NONE;
    int line_no = 0, seen_if = 0;
    struct awg_peer *pe = NULL;
    size_t pos = 0;
    /* Строка разбора — своя копия: файл читается целиком в буфер вызывающего, и резать его
     * нулями на месте значило бы портить чужой буфер. Размер строки ограничен — I1..I5 самые
     * длинные, и предел у них свой. */
    char *line = malloc(AWG_MAX_ISTR + 256);
    if (!line) { snprintf(err, errn, "нет памяти"); return -1; }

    while (pos < n) {
        size_t e = pos;
        while (e < n && text[e] != '\n') e++;
        line_no++;
        size_t len = e - pos;
        if (len >= AWG_MAX_ISTR + 256) PERR("строка %d длиннее допустимого", line_no);
        memcpy(line, text + pos, len);
        line[len] = '\0';
        pos = e + 1;
        /* Комментарий — от '#' до конца строки, как у wg. Внутри I1..I5 решётки не бывает
         * (там теги <b 0x…>, <r N>, <t>, <c>). */
        char *hash = strchr(line, '#');
        if (hash) *hash = '\0';
        char *l = trim(line);
        if (!*l) continue;
        if (*l == '[') {
            if (!strcasecmp(l, "[Interface]")) {
                if (seen_if) PERR("строка %d: второй раздел [Interface]", line_no);
                sec = SEC_IF; seen_if = 1;
            } else if (!strcasecmp(l, "[Peer]")) {
                if (c->peer_n >= AWG_MAX_PEERS) PERR("строка %d: пиров больше %d", line_no, AWG_MAX_PEERS);
                pe = &c->peer[c->peer_n++];
                pe->aip_first = c->aips_n;
                sec = SEC_PEER;
            } else PERR("строка %d: неизвестный раздел", line_no);
            continue;
        }
        char *eq = strchr(l, '=');
        if (!eq) PERR("строка %d: нет знака «=»", line_no);
        *eq = '\0';
        char *key = trim(l), *val = trim(eq + 1);
        if (!*key) PERR("строка %d: пустое имя параметра", line_no);
        /* Имя ключа попадает в сообщение об ошибке — и только оно. Длинное имя режем, чтобы
         * мусорная строка не превращала сообщение в простыню. */
        char kn[40];
        snprintf(kn, sizeof kn, "%.32s", key);
        if (sec == SEC_NONE) PERR("строка %d: параметр %s вне раздела", line_no, kn);
        unsigned long v, lo, hi;

        if (sec == SEC_IF) {
            if (!strcasecmp(key, "PrivateKey")) {
                if (key_from_b64(s->priv, val) != 0)
                    PERR("строка %d: PrivateKey — не ключ WireGuard (44 знака base64)", line_no);
                s->has_priv = 1;
            } else if (!strcasecmp(key, "Address")) {
                /* Через запятую и повторными строками — оба способа wg-quick. */
                for (char *t = strtok(val, ","); t; t = strtok(NULL, ",")) {
                    t = trim(t);
                    if (!*t) continue;
                    if (c->addr_n >= AWG_MAX_ADDRS) PERR("строка %d: адресов больше %d", line_no, AWG_MAX_ADDRS);
                    if (parse_prefix(t, &c->addr[c->addr_n]) != 0)
                        PERR("строка %d: Address — не адрес или адрес/префикс", line_no);
                    c->addr_n++;
                }
            } else if (!strcasecmp(key, "MTU")) {
                /* 1280 — меньше IPv6 не живёт, а адрес v6 внутри туннеля обычен. */
                if (parse_num(val, 1280, 65535, &v) != 0) PERR("строка %d: MTU — число от 1280 до 65535", line_no);
                c->mtu = (int)v;
            } else if (!strcasecmp(key, "ListenPort")) {
                if (parse_num(val, 0, 65535, &v) != 0) PERR("строка %d: ListenPort — число от 0 до 65535", line_no);
                c->listen_port = (uint16_t)v;
                c->has_listen_port = 1;
            } else if (!strcasecmp(key, "DNS")) {
                /* Не применяется: DNS телефона и клиентов раздачи — дело резолвера движка и
                 * каналов, а не туннеля, и wg-quick, переписывающий resolv.conf, здесь был бы
                 * вторым хозяином одного и того же. Считаем, чтобы предупредить. */
                c->dns_n++;
            } else if (!strcasecmp(key, "Table")) {
                c->ignored |= AWG_IGN_TABLE;
            } else if (!strcasecmp(key, "FwMark")) {
                c->ignored |= AWG_IGN_FWMARK;
            } else if (!strcasecmp(key, "PreUp") || !strcasecmp(key, "PostUp") ||
                       !strcasecmp(key, "PreDown") || !strcasecmp(key, "PostDown")) {
                c->ignored |= AWG_IGN_SCRIPTS;
            } else if (!strcasecmp(key, "SaveConfig")) {
                c->ignored |= AWG_IGN_SAVE;
            } else if (!strcasecmp(key, "H1") || !strcasecmp(key, "H2") ||
                       !strcasecmp(key, "H3") || !strcasecmp(key, "H4")) {
                int k = key[1] - '1';
                if (parse_range(val, 0xffffffffUL, &lo, &hi) != 0)
                    PERR("строка %d: %s — число или диапазон N-M до 4294967295", line_no, kn);
                c->h[k] = (uint64_t)lo | ((uint64_t)hi << 32);
                c->h_has |= 1u << k;
            } else if ((key[0] == 'I' || key[0] == 'i') && key[1] >= '1' && key[1] <= '5' && !key[2]) {
                int k = key[1] - '1';
                if (!*val) continue;    /* пустое значение — как отсутствие */
                if (strlen(val) >= AWG_MAX_ISTR) PERR("строка %d: %s длиннее допустимого", line_no, kn);
                free(c->istr[k]);
                c->istr[k] = strdup(val);
                if (!c->istr[k]) PERR("нет памяти");
            } else if (!strcasecmp(key, "HeaderProtectionKey")) {
                if (key_from_b64(s->hpk, val) != 0)
                    PERR("строка %d: HeaderProtectionKey — не ключ (44 знака base64)", line_no);
                c->has_hpk = 1;
            } else {
                int hit = 0;
                for (int k = 0; k < AWG_U16_N && !hit; k++)
                    if (!strcasecmp(key, U16_NAME[k])) {
                        if (parse_num(val, 0, 65535, &v) != 0)
                            PERR("строка %d: %s — число от 0 до 65535", line_no, kn);
                        c->u16[k] = (uint16_t)v; c->u16_has |= 1u << k; hit = 1;
                    }
                for (int k = 0; k < AWG_R16_N && !hit; k++)
                    if (!strcasecmp(key, R16_NAME[k])) {
                        if (parse_range(val, 65535, &lo, &hi) != 0)
                            PERR("строка %d: %s — число или диапазон N-M до 65535", line_no, kn);
                        c->r16[k] = (uint32_t)lo | ((uint32_t)hi << 16); c->r16_has |= 1u << k; hit = 1;
                    }
                for (int k = 0; k < AWG_U8_N && !hit; k++)
                    if (!strcasecmp(key, U8_NAME[k])) {
                        int b;
                        if (parse_bool(val, &b) != 0) PERR("строка %d: %s — true или false", line_no, kn);
                        c->u8v[k] = (uint8_t)b; c->u8_has |= 1u << k; hit = 1;
                    }
                if (!hit) PERR("строка %d: неизвестный параметр %s в [Interface]", line_no, kn);
            }
        } else {
            size_t pi = (size_t)(pe - c->peer);
            if (!strcasecmp(key, "PublicKey")) {
                if (key_from_b64(pe->pub, val) != 0)
                    PERR("строка %d: PublicKey — не ключ WireGuard (44 знака base64)", line_no);
                /* Ключ пира — не секрет и лежит в conf. Отдельного признака «задан» нет:
                 * нулевой ключ WireGuard недопустим, по нему и проверяется в конце разбора. */
            } else if (!strcasecmp(key, "PresharedKey")) {
                if (key_from_b64(s->psk[pi], val) != 0)
                    PERR("строка %d: PresharedKey — не ключ (44 знака base64)", line_no);
                pe->has_psk = 1;
            } else if (!strcasecmp(key, "Endpoint")) {
                if (parse_endpoint(val, pe) != 0)
                    PERR("строка %d: Endpoint — хост:порт или [IPv6]:порт", line_no);
            } else if (!strcasecmp(key, "AllowedIPs")) {
                /* Пир обязан владеть непрерывным срезом общего массива: AllowedIPs после
                 * следующего [Peer] сюда не попадает по построению (pe — последний пир). */
                for (char *t = strtok(val, ","); t; t = strtok(NULL, ",")) {
                    t = trim(t);
                    if (!*t) continue;
                    if (c->aips_n >= AWG_MAX_AIPS)
                        PERR("строка %d: AllowedIPs больше %d на файл", line_no, AWG_MAX_AIPS);
                    if (parse_prefix(t, &c->aips[c->aips_n]) != 0)
                        PERR("строка %d: AllowedIPs — адрес или адрес/префикс", line_no);
                    c->aips_n++;
                    pe->aip_n++;
                }
            } else if (!strcasecmp(key, "PersistentKeepalive")) {
                if (!strcasecmp(val, "off")) { lo = hi = 0; }
                else if (parse_range(val, 65535, &lo, &hi) != 0)
                    PERR("строка %d: PersistentKeepalive — секунды, диапазон N-M или off", line_no);
                pe->keepalive = (uint32_t)lo | ((uint32_t)hi << 16);
            } else if (!strcasecmp(key, "AdvancedSecurity")) {
                int b;
                if (parse_bool(val, &b) != 0) PERR("строка %d: AdvancedSecurity — true или false", line_no);
                pe->adv_sec = b; pe->has_adv_sec = 1;
            } else PERR("строка %d: неизвестный параметр %s в [Peer]", line_no, kn);
        }
    }

    if (!seen_if) PERR("нет раздела [Interface]");
    if (!s->has_priv) PERR("в [Interface] нет PrivateKey");
    if (!c->peer_n) PERR("нет ни одного [Peer]");
    static const uint8_t zero[AWG_KEY_LEN];
    for (size_t i = 0; i < c->peer_n; i++) {
        if (!memcmp(c->peer[i].pub, zero, AWG_KEY_LEN))
            PERR("у [Peer] №%zu нет PublicKey", i + 1);
        for (size_t k = 0; k < i; k++)
            if (!memcmp(c->peer[i].pub, c->peer[k].pub, AWG_KEY_LEN))
                PERR("PublicKey [Peer] №%zu повторяет №%zu", i + 1, k + 1);
    }
    /* Проверки, которые ядро делает само, но отвечает на них одним EINVAL без объяснения (а
     * причину пишет только в отладочный журнал ядра). Здесь их называют словами. */
    if ((c->u16_has & (1u << AWG_JMIN)) && (c->u16_has & (1u << AWG_JMAX)) &&
        c->u16[AWG_JMIN] > c->u16[AWG_JMAX])
        PERR("Jmin больше Jmax");
    for (int a = 0; a < 4; a++)
        for (int b = a + 1; b < 4; b++) {
            if (!((c->h_has >> a) & 1) || !((c->h_has >> b) & 1)) continue;
            uint32_t alo = (uint32_t)c->h[a], ahi = (uint32_t)(c->h[a] >> 32);
            uint32_t blo = (uint32_t)c->h[b], bhi = (uint32_t)(c->h[b] >> 32);
            if (alo <= bhi && blo <= ahi) PERR("H%d и H%d пересекаются — модуль их не примет", a + 1, b + 1);
        }
    free(line);
    return 0;
fail:
    free(line);
    awg_conf_free(c);
    awg_secrets_wipe(s);
    return -1;
}

int awg_conf_load(const char *path, struct awg_conf *c, struct awg_secrets *s,
                  char *err, size_t errn) {
    memset(c, 0, sizeof(*c));
    memset(s, 0, sizeof(*s));
    int fd = open(path, O_RDONLY | O_CLOEXEC);
    if (fd < 0) { snprintf(err, errn, "%s: %s", path, strerror(errno)); return -1; }
    struct stat st;
    /* Предел размера — от худшего законного файла: пять I по 16 КБ и тысяча AllowedIPs. */
    if (fstat(fd, &st) != 0 || st.st_size > 256 * 1024) {
        close(fd);
        snprintf(err, errn, "%s: файл слишком большой для конфигурации туннеля", path);
        return -1;
    }
    size_t cap = (size_t)st.st_size + 1, got = 0;
    char *buf = malloc(cap);
    if (!buf) { close(fd); snprintf(err, errn, "нет памяти"); return -1; }
    for (;;) {
        ssize_t r = read(fd, buf + got, cap - 1 - got);
        if (r < 0 && errno == EINTR) continue;
        if (r <= 0) break;
        got += (size_t)r;
        if (got >= cap - 1) break;
    }
    close(fd);
    buf[got] = '\0';
    int rc = awg_conf_parse(buf, got, c, s, err, errn);
    wipe(buf, cap);   /* в буфере был текст с приватным ключом */
    free(buf);
    return rc;
}

/* Задан ли H со значением, отличным от поведения WireGuard. Типы сообщений WireGuard — 1..4,
 * и H1=1, H2=2, H3=3, H4=4 одним числом — это обычный WireGuard, записанный явно (так
 * выглядят файлы Amnezia с выключенной обфускацией). */
static int h_nondefault(const struct awg_conf *c, int k) {
    if (!((c->h_has >> k) & 1)) return 0;
    return c->h[k] != (uint64_t)(k + 1) * 0x100000001ull;
}

int awg_conf_needs_awg(const struct awg_conf *c) {
    for (int k = 0; k < AWG_U16_N; k++)
        if (((c->u16_has >> k) & 1) && c->u16[k]) return 1;
    for (int k = 0; k < 4; k++)
        if (h_nondefault(c, k)) return 1;
    for (int k = 0; k < 5; k++)
        if (c->istr[k]) return 1;
    for (int k = 0; k < AWG_R16_N; k++)
        if (((c->r16_has >> k) & 1) && c->r16[k]) return 1;
    for (int k = 0; k < AWG_U8_N; k++)
        if (((c->u8_has >> k) & 1) && c->u8v[k]) return 1;
    if (c->has_hpk) return 1;
    for (size_t i = 0; i < c->peer_n; i++) {
        if (c->peer[i].has_adv_sec && c->peer[i].adv_sec) return 1;
        /* Диапазон keepalive — только у AmneziaWG 3; одно число понимает и WireGuard. */
        if ((c->peer[i].keepalive & 0xffff) != (c->peer[i].keepalive >> 16)) return 1;
    }
    return 0;
}

/* Версии семейства: см. объявление. Сверено с историей uapi модуля: версия 1 — J*, S1, S2,
 * H1..H4 одним u32 (2024); версия 2 — S3, S4, I1..I5 и H строкой «lo-hi» (2025, e939553);
 * версия 3 — параметры AmneziaWG 3, H как u64, keepalive диапазоном (2026, b6ca11f). */
int awg_conf_min_version(const struct awg_conf *c, const char **why) {
    const char *w = NULL;
    int v = 1;
    for (int k = 0; k < AWG_R16_N; k++)
        if ((c->r16_has >> k) & 1) { v = 3; w = R16_NAME[k]; }
    for (int k = 0; k < AWG_U8_N; k++)
        if ((c->u8_has >> k) & 1) { v = 3; w = U8_NAME[k]; }
    if (c->has_hpk) { v = 3; w = "HeaderProtectionKey"; }
    for (size_t i = 0; i < c->peer_n; i++)
        if ((c->peer[i].keepalive & 0xffff) != (c->peer[i].keepalive >> 16)) {
            v = 3; w = "диапазон PersistentKeepalive";
        }
    if (v < 2) {
        if (c->u16_has & ((1u << AWG_S3) | (1u << AWG_S4))) { v = 2; w = "S3/S4"; }
        for (int k = 0; k < 5; k++) if (c->istr[k]) { v = 2; w = "I1..I5"; }
        for (int k = 0; k < 4; k++)
            if (((c->h_has >> k) & 1) && (uint32_t)c->h[k] != (uint32_t)(c->h[k] >> 32)) {
                v = 2; w = "диапазон H1..H4";
            }
    }
    if (why) *why = w;
    return v;
}

/* Подпись параметров устройства, которые нельзя снять поверх (см. шапку): маска заданных и
 * значения. Ключа защиты заголовка здесь нет, есть только признак — сравнению нужен факт
 * «был/убран», а хэш ключа в файле состояния был бы ключом, покинувшим место хранения. */
struct awg_sig { unsigned u16_has, h_has, i_has, r16_has, u8_has, hpk; };

static struct awg_sig conf_sig(const struct awg_conf *c) {
    struct awg_sig g = { c->u16_has, c->h_has, 0, c->r16_has, c->u8_has, (unsigned)c->has_hpk };
    for (int k = 0; k < 5; k++) if (c->istr[k]) g.i_has |= 1u << k;
    return g;
}

/* ---- сообщения ------------------------------------------------------------------------ */

static struct nlmsghdr *msg_begin(struct nlbuf *b, void *mem, size_t cap, uint16_t type,
                                  uint16_t flags, uint32_t seq, const void *fam, size_t famlen) {
    nlbuf_init(b, mem, cap);
    size_t hl = NLMSG_ALIGN(sizeof(struct nlmsghdr)) + NLMSG_ALIGN(famlen);
    if (cap < hl) { b->overflow = 1; return NULL; }
    memset(mem, 0, hl);
    struct nlmsghdr *nh = mem;
    nh->nlmsg_type = type;
    nh->nlmsg_flags = flags;
    nh->nlmsg_seq = seq;
    memcpy((uint8_t *)mem + NLMSG_ALIGN(sizeof(struct nlmsghdr)), fam, famlen);
    b->p += hl;
    return nh;
}

static size_t msg_end(struct nlbuf *b, struct nlmsghdr *nh) {
    if (!nh || b->overflow) return 0;
    nh->nlmsg_len = (uint32_t)(b->p - b->base);
    return nh->nlmsg_len;
}

size_t awg_build_getfamily(uint8_t *buf, size_t cap, const char *name, uint32_t seq) {
    struct nlbuf b;
    struct genlmsghdr g = { .cmd = CTRL_CMD_GETFAMILY, .version = 1 };
    struct nlmsghdr *nh = msg_begin(&b, buf, cap, GENL_ID_CTRL, NLM_F_REQUEST, seq, &g, sizeof g);
    nlbuf_put_str(&b, CTRL_ATTR_FAMILY_NAME, name);
    return msg_end(&b, nh);
}

size_t awg_build_newlink(uint8_t *buf, size_t cap, const char *ifname, const char *kind,
                         int mtu, uint32_t seq) {
    struct nlbuf b;
    struct ifinfomsg ifi = { .ifi_family = AF_UNSPEC };
    struct nlmsghdr *nh = msg_begin(&b, buf, cap, RTM_NEWLINK,
                                    NLM_F_REQUEST | NLM_F_ACK | NLM_F_CREATE | NLM_F_EXCL,
                                    seq, &ifi, sizeof ifi);
    nlbuf_put_str(&b, IFLA_IFNAME, ifname);
    if (mtu > 0) nlbuf_put_u32(&b, IFLA_MTU, (uint32_t)mtu);
    struct nlattr *li = nlbuf_begin_nested(&b, IFLA_LINKINFO);
    nlbuf_put_str(&b, IFLA_INFO_KIND, kind);
    nlbuf_end_nested(&b, li);
    return msg_end(&b, nh);
}

/* H в той форме, которую ждёт версия семейства (так же поступает awg из amneziawg-tools):
 * 1 — u32 (диапазонов нет; сюда доходит только одно число, см. awg_conf_min_version),
 * 2 — строка «lo» или «lo-hi», 3 — u64 (lo | hi << 32). */
static void put_h(struct nlbuf *b, int famver, uint16_t attr, uint64_t h) {
    uint32_t lo = (uint32_t)h, hi = (uint32_t)(h >> 32);
    if (famver < 2) nlbuf_put_u32(b, attr, lo);
    else if (famver < 3) {
        char s[24];
        if (lo == hi) snprintf(s, sizeof s, "%u", lo);
        else snprintf(s, sizeof s, "%u-%u", lo, hi);
        nlbuf_put_str(b, attr, s);
    } else nlbuf_put_u64(b, attr, h);
}

size_t awg_build_set(uint8_t *buf, size_t cap, uint16_t famid, int famver, int is_awg,
                     const char *ifname, const struct awg_conf *c,
                     const struct awg_secrets *s, uint32_t fwmark, int replace_peers,
                     uint32_t seq) {
    struct nlbuf b;
    struct genlmsghdr g = { .cmd = AWG_CMD_SET_DEVICE, .version = (uint8_t)famver };
    struct nlmsghdr *nh = msg_begin(&b, buf, cap, famid, NLM_F_REQUEST | NLM_F_ACK, seq,
                                    &g, sizeof g);
    nlbuf_put_str(&b, AD_IFNAME, ifname);
    nlbuf_put_data(&b, AD_PRIVATE_KEY, s->priv, AWG_KEY_LEN);
    if (c->has_listen_port) nlbuf_put_u16(&b, AD_LISTEN_PORT, c->listen_port);
    /* Метка сокета — всегда, в том числе нулевая: иначе метка прежнего via осталась бы на
     * устройстве после того, как via убрали из спеки. */
    nlbuf_put_u32(&b, AD_FWMARK, fwmark);
    if (replace_peers) nlbuf_put_u32(&b, AD_FLAGS, AWG_DEV_F_REPLACE_PEERS);
    if (is_awg) {
        for (int k = 0; k < AWG_U16_N; k++)
            if ((c->u16_has >> k) & 1) nlbuf_put_u16(&b, U16_ATTR[k], c->u16[k]);
        static const uint16_t HA[4] = { AD_H1, AD_H2, AD_H3, AD_H4 };
        for (int k = 0; k < 4; k++)
            if ((c->h_has >> k) & 1) put_h(&b, famver, HA[k], c->h[k]);
        static const uint16_t IA[5] = { AD_I1, AD_I2, AD_I3, AD_I4, AD_I5 };
        for (int k = 0; k < 5; k++)
            if (c->istr[k]) nlbuf_put_str(&b, IA[k], c->istr[k]);
        if (c->has_hpk) nlbuf_put_data(&b, AD_HEADER_PROTECTION_KEY, s->hpk, AWG_KEY_LEN);
        for (int k = 0; k < AWG_R16_N; k++)
            if ((c->r16_has >> k) & 1) nlbuf_put_u32(&b, R16_ATTR[k], c->r16[k]);
        for (int k = 0; k < AWG_U8_N; k++)
            if ((c->u8_has >> k) & 1) nlbuf_put_u8(&b, U8_ATTR[k], c->u8v[k]);
    }
    struct nlattr *peers = nlbuf_begin_nested(&b, AD_PEERS);
    static const uint8_t zero[AWG_KEY_LEN];
    for (size_t i = 0; i < c->peer_n; i++) {
        const struct awg_peer *pe = &c->peer[i];
        struct nlattr *pn = nlbuf_begin_nested(&b, 0);
        nlbuf_put_data(&b, AP_PUBLIC_KEY, pe->pub, AWG_KEY_LEN);
        uint32_t fl = AWG_PEER_F_REPLACE_ALLOWEDIPS;
        if (is_awg && pe->has_adv_sec) fl |= AWG_PEER_F_HAS_ADVANCED_SECURITY;
        nlbuf_put_u32(&b, AP_FLAGS, fl);
        /* PSK — всегда: нулевой ключ значит «снять», и так PSK, убранный из файла, уходит и
         * с устройства. */
        nlbuf_put_data(&b, AP_PRESHARED_KEY, pe->has_psk ? s->psk[i] : zero, AWG_KEY_LEN);
        if (pe->ep_len) nlbuf_put_data(&b, AP_ENDPOINT, &pe->ep, pe->ep_len);
        /* keepalive — тоже всегда, нулём выключается. Ширина — по версии: у WireGuard и
         * AmneziaWG до третьей версии это u16 (одно число), у третьей — u32 с диапазоном. */
        if (is_awg && famver >= 3) nlbuf_put_u32(&b, AP_PERSISTENT_KEEPALIVE_INTERVAL, pe->keepalive);
        else nlbuf_put_u16(&b, AP_PERSISTENT_KEEPALIVE_INTERVAL, (uint16_t)(pe->keepalive & 0xffff));
        if (is_awg && pe->has_adv_sec && pe->adv_sec) nlbuf_put_flag(&b, AP_ADVANCED_SECURITY);
        struct nlattr *an = nlbuf_begin_nested(&b, AP_ALLOWEDIPS);
        for (size_t k = 0; k < pe->aip_n; k++) {
            const struct awg_prefix *p = &c->aips[pe->aip_first + k];
            struct nlattr *e = nlbuf_begin_nested(&b, 0);
            nlbuf_put_u16(&b, AA_FAMILY, p->family);
            nlbuf_put_data(&b, AA_IPADDR, p->addr, p->family == AF_INET ? 4 : 16);
            nlbuf_put_u8(&b, AA_CIDR_MASK, p->cidr);
            nlbuf_end_nested(&b, e);
        }
        nlbuf_end_nested(&b, an);
        nlbuf_end_nested(&b, pn);
    }
    nlbuf_end_nested(&b, peers);
    return msg_end(&b, nh);
}

/* ---- разговор с ядром -------------------------------------------------------------- */

static uint32_t g_seq;

static int nl_open(int proto) {
    int fd = socket(AF_NETLINK, SOCK_RAW | SOCK_CLOEXEC, proto);
    if (fd < 0) return -1;
    struct sockaddr_nl sa = { .nl_family = AF_NETLINK };
    if (bind(fd, (struct sockaddr *)&sa, sizeof(sa)) != 0) { close(fd); return -1; }
    /* Страховка от вечного recv при невозможном «ядро не ответило»; ядро отвечает внутри
     * того же системного вызова, и в работе таймаут не срабатывает. */
    struct timeval tv = { 2, 0 };
    setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
    return fd;
}

/* Отправить одно сообщение и прочитать ответ до подтверждения (или до NLMSG_DONE у дампа).
 * Каждое сообщение ответа, кроме служебных, отдаётся cb. Возврат — 0 или errno ядра. Буфер
 * приёма затирается перед возвратом: в ответе GET_DEVICE лежит приватный ключ. */
typedef void (*nl_cb)(const struct nlmsghdr *h, void *ctx);

static int nl_talk(int fd, void *msg, size_t len, nl_cb cb, void *ctx) {
    struct nlmsghdr *req = msg;
    int dump = (req->nlmsg_flags & NLM_F_DUMP) == NLM_F_DUMP;
    struct sockaddr_nl to = { .nl_family = AF_NETLINK };
    if (sendto(fd, msg, len, 0, (struct sockaddr *)&to, sizeof(to)) < 0) return errno;
    static uint8_t rbuf[65536];
    int rc = EIO, done = 0;
    while (!done) {
        ssize_t n = recv(fd, rbuf, sizeof rbuf, 0);
        if (n < 0) { if (errno == EINTR) continue; rc = errno; break; }
        for (struct nlmsghdr *h = (struct nlmsghdr *)rbuf; NLMSG_OK(h, (size_t)n);
             h = NLMSG_NEXT(h, n)) {
            if (h->nlmsg_seq != req->nlmsg_seq) continue;
            if (h->nlmsg_type == NLMSG_ERROR) {
                const struct nlmsgerr *e = NLMSG_DATA(h);
                rc = e->error ? -e->error : 0;
                done = 1;
                break;
            }
            if (h->nlmsg_type == NLMSG_DONE) { rc = 0; done = 1; break; }
            if (cb) cb(h, ctx);
            if (!dump && !(req->nlmsg_flags & NLM_F_ACK)) { rc = 0; done = 1; break; }
        }
    }
    wipe(rbuf, sizeof rbuf);
    return rc;
}

/* Разбор атрибутов в [p, p+len): table[type] = атрибут. Тип без флагов (вложенность у 4.9
 * иногда без NLA_F_NESTED). */
static void attrs_parse(const void *p, size_t len, const struct nlattr **tb, int max) {
    for (int i = 0; i <= max; i++) tb[i] = NULL;
    const uint8_t *q = p, *end = q + len;
    while (q + NLA_HDRLEN <= end) {
        const struct nlattr *a = (const struct nlattr *)q;
        if (a->nla_len < NLA_HDRLEN || q + a->nla_len > end) break;
        int t = a->nla_type & NLA_TYPE_MASK;
        if (t <= max) tb[t] = a;
        q += NLA_ALIGN(a->nla_len);
    }
}
#define NLA_DATA(a) ((const void *)((const uint8_t *)(a) + NLA_HDRLEN))
#define NLA_PLEN(a) ((size_t)((a)->nla_len - NLA_HDRLEN))

struct fam_ctx { uint16_t id; uint32_t ver; };

static void fam_cb(const struct nlmsghdr *h, void *ctx) {
    struct fam_ctx *f = ctx;
    const struct nlattr *tb[CTRL_ATTR_MAX + 1];
    size_t hl = NLMSG_ALIGN(sizeof(struct genlmsghdr));
    if (h->nlmsg_len < NLMSG_HDRLEN + hl) return;
    attrs_parse((const uint8_t *)NLMSG_DATA(h) + hl, h->nlmsg_len - NLMSG_HDRLEN - hl, tb, CTRL_ATTR_MAX);
    if (tb[CTRL_ATTR_FAMILY_ID] && NLA_PLEN(tb[CTRL_ATTR_FAMILY_ID]) >= 2)
        memcpy(&f->id, NLA_DATA(tb[CTRL_ATTR_FAMILY_ID]), 2);
    if (tb[CTRL_ATTR_VERSION] && NLA_PLEN(tb[CTRL_ATTR_VERSION]) >= 4)
        memcpy(&f->ver, NLA_DATA(tb[CTRL_ATTR_VERSION]), 4);
}

/* Номер и версия семейства generic netlink. 0 — нашлось. Спрашивание само подгружает модуль,
 * если ядро умеет (MODULE_ALIAS_GENL_FAMILY у wireguard и amneziawg). */
static int genl_family(const char *name, uint16_t *id, int *ver) {
    int fd = nl_open(NETLINK_GENERIC);
    if (fd < 0) return errno;
    uint8_t buf[128];
    size_t n = awg_build_getfamily(buf, sizeof buf, name, ++g_seq);
    struct fam_ctx f = { 0, 0 };
    int rc = nl_talk(fd, buf, n, fam_cb, &f);
    close(fd);
    if (rc == 0 && !f.id) rc = ENOENT;
    if (rc) return rc;
    *id = f.id;
    *ver = (int)f.ver;
    return 0;
}

struct link_ctx { char kind[32]; int index; };

static void link_cb(const struct nlmsghdr *h, void *ctx) {
    struct link_ctx *l = ctx;
    if (h->nlmsg_type != RTM_NEWLINK) return;
    const struct ifinfomsg *ifi = NLMSG_DATA(h);
    size_t hl = NLMSG_ALIGN(sizeof(*ifi));
    if (h->nlmsg_len < NLMSG_HDRLEN + hl) return;
    l->index = ifi->ifi_index;
    const struct nlattr *tb[IFLA_MAX + 1];
    attrs_parse((const uint8_t *)ifi + hl, h->nlmsg_len - NLMSG_HDRLEN - hl, tb, IFLA_MAX);
    if (!tb[IFLA_LINKINFO]) return;
    const struct nlattr *li[IFLA_INFO_MAX + 1];
    attrs_parse(NLA_DATA(tb[IFLA_LINKINFO]), NLA_PLEN(tb[IFLA_LINKINFO]), li, IFLA_INFO_MAX);
    if (li[IFLA_INFO_KIND]) {
        size_t k = NLA_PLEN(li[IFLA_INFO_KIND]);
        if (k >= sizeof l->kind) k = sizeof l->kind - 1;
        memcpy(l->kind, NLA_DATA(li[IFLA_INFO_KIND]), k);
        l->kind[k] = '\0';
    }
}

/* Есть ли устройство и какого вида. 0 — есть (kind может быть пустым у устройств без вида,
 * например eth0), ENODEV — нет. */
static int link_query(const char *ifname, char *kind, size_t kn, int *index) {
    int fd = nl_open(NETLINK_ROUTE);
    if (fd < 0) return errno;
    uint8_t buf[256];
    struct nlbuf b;
    struct ifinfomsg ifi = { .ifi_family = AF_UNSPEC };
    struct nlmsghdr *nh = msg_begin(&b, buf, sizeof buf, RTM_GETLINK, NLM_F_REQUEST | NLM_F_ACK,
                                    ++g_seq, &ifi, sizeof ifi);
    nlbuf_put_str(&b, IFLA_IFNAME, ifname);
    size_t n = msg_end(&b, nh);
    struct link_ctx l = { "", 0 };
    int rc = nl_talk(fd, buf, n, link_cb, &l);
    close(fd);
    if (rc == 0 && !l.index) rc = ENODEV;
    if (rc) return rc;
    if (kind) snprintf(kind, kn, "%s", l.kind);
    if (index) *index = l.index;
    return 0;
}

static int rtnl_simple(void *buf, size_t n) {
    int fd = nl_open(NETLINK_ROUTE);
    if (fd < 0) return errno;
    int rc = nl_talk(fd, buf, n, NULL, NULL);
    close(fd);
    return rc;
}

static int link_create(const char *ifname, const char *kind, int mtu) {
    uint8_t buf[256];
    size_t n = awg_build_newlink(buf, sizeof buf, ifname, kind, mtu, ++g_seq);
    return rtnl_simple(buf, n);
}

static int link_delete(const char *ifname) {
    uint8_t buf[128];
    struct nlbuf b;
    struct ifinfomsg ifi = { .ifi_family = AF_UNSPEC };
    struct nlmsghdr *nh = msg_begin(&b, buf, sizeof buf, RTM_DELLINK, NLM_F_REQUEST | NLM_F_ACK,
                                    ++g_seq, &ifi, sizeof ifi);
    nlbuf_put_str(&b, IFLA_IFNAME, ifname);
    return rtnl_simple(buf, msg_end(&b, nh));
}

/* MTU и подъём одним сообщением по номеру устройства. */
static int link_set_up(int index, int mtu) {
    uint8_t buf[128];
    struct nlbuf b;
    struct ifinfomsg ifi = { .ifi_family = AF_UNSPEC, .ifi_index = index,
                             .ifi_flags = IFF_UP, .ifi_change = IFF_UP };
    struct nlmsghdr *nh = msg_begin(&b, buf, sizeof buf, RTM_NEWLINK, NLM_F_REQUEST | NLM_F_ACK,
                                    ++g_seq, &ifi, sizeof ifi);
    if (mtu > 0) nlbuf_put_u32(&b, IFLA_MTU, (uint32_t)mtu);
    return rtnl_simple(buf, msg_end(&b, nh));
}

/* ---- состояние устройства из ядра (WG_CMD_GET_DEVICE) ------------------------------- */

struct awg_live_peer {
    uint8_t pub[AWG_KEY_LEN];
    int64_t hs;                     /* время последнего рукопожатия, секунды эпохи; 0 — не было */
    uint64_t rx, tx;
    struct sockaddr_storage ep;
    socklen_t ep_len;
};

struct awg_live {
    size_t peer_n;
    struct awg_live_peer peer[AWG_MAX_PEERS * 2];
    uint32_t fwmark;
};

static void live_peer(struct awg_live *L, const struct nlattr *pa) {
    const struct nlattr *tb[AP_ADVANCED_SECURITY + 1];
    attrs_parse(NLA_DATA(pa), NLA_PLEN(pa), tb, AP_ADVANCED_SECURITY);
    if (!tb[AP_PUBLIC_KEY] || NLA_PLEN(tb[AP_PUBLIC_KEY]) != AWG_KEY_LEN) return;
    struct awg_live_peer *p = NULL;
    /* Пир с длинным AllowedIPs приходит частями в нескольких сообщениях дампа — сводим по
     * ключу, иначе один пир посчитался бы дважды. */
    for (size_t i = 0; i < L->peer_n; i++)
        if (!memcmp(L->peer[i].pub, NLA_DATA(tb[AP_PUBLIC_KEY]), AWG_KEY_LEN)) p = &L->peer[i];
    if (!p) {
        if (L->peer_n >= sizeof L->peer / sizeof L->peer[0]) return;
        p = &L->peer[L->peer_n++];
        memset(p, 0, sizeof(*p));
        memcpy(p->pub, NLA_DATA(tb[AP_PUBLIC_KEY]), AWG_KEY_LEN);
    }
    if (tb[AP_LAST_HANDSHAKE_TIME]) {
        /* struct __kernel_timespec (два s64) у современных ядер; у 32-битных старых — два
         * s32. Берём секунды по длине атрибута. */
        size_t l = NLA_PLEN(tb[AP_LAST_HANDSHAKE_TIME]);
        if (l >= 16) { int64_t s; memcpy(&s, NLA_DATA(tb[AP_LAST_HANDSHAKE_TIME]), 8); p->hs = s; }
        else if (l >= 8) { int32_t s; memcpy(&s, NLA_DATA(tb[AP_LAST_HANDSHAKE_TIME]), 4); p->hs = s; }
    }
    if (tb[AP_RX_BYTES] && NLA_PLEN(tb[AP_RX_BYTES]) >= 8) memcpy(&p->rx, NLA_DATA(tb[AP_RX_BYTES]), 8);
    if (tb[AP_TX_BYTES] && NLA_PLEN(tb[AP_TX_BYTES]) >= 8) memcpy(&p->tx, NLA_DATA(tb[AP_TX_BYTES]), 8);
    if (tb[AP_ENDPOINT]) {
        size_t l = NLA_PLEN(tb[AP_ENDPOINT]);
        if (l > sizeof p->ep) l = sizeof p->ep;
        memcpy(&p->ep, NLA_DATA(tb[AP_ENDPOINT]), l);
        p->ep_len = (socklen_t)l;
    }
}

static void live_cb(const struct nlmsghdr *h, void *ctx) {
    struct awg_live *L = ctx;
    size_t hl = NLMSG_ALIGN(sizeof(struct genlmsghdr));
    if (h->nlmsg_len < NLMSG_HDRLEN + hl) return;
    const struct nlattr *tb[AD_DISABLE_COOKIES + 1];
    attrs_parse((const uint8_t *)NLMSG_DATA(h) + hl, h->nlmsg_len - NLMSG_HDRLEN - hl, tb,
                AD_DISABLE_COOKIES);
    if (tb[AD_FWMARK] && NLA_PLEN(tb[AD_FWMARK]) >= 4) memcpy(&L->fwmark, NLA_DATA(tb[AD_FWMARK]), 4);
    if (!tb[AD_PEERS]) return;
    const uint8_t *q = NLA_DATA(tb[AD_PEERS]), *end = q + NLA_PLEN(tb[AD_PEERS]);
    while (q + NLA_HDRLEN <= end) {
        const struct nlattr *a = (const struct nlattr *)q;
        if (a->nla_len < NLA_HDRLEN || q + a->nla_len > end) break;
        live_peer(L, a);
        q += NLA_ALIGN(a->nla_len);
    }
}

/* Вид устройства → семейство. Вид "amneziawg" и "wireguard" совпадают с именами семейств. */
static int live_read(const char *ifname, const char *kind, struct awg_live *L) {
    memset(L, 0, sizeof(*L));
    uint16_t id; int ver;
    int rc = genl_family(kind, &id, &ver);
    if (rc) return rc;
    int fd = nl_open(NETLINK_GENERIC);
    if (fd < 0) return errno;
    uint8_t buf[128];
    struct nlbuf b;
    struct genlmsghdr g = { .cmd = AWG_CMD_GET_DEVICE, .version = (uint8_t)ver };
    struct nlmsghdr *nh = msg_begin(&b, buf, sizeof buf, id, NLM_F_REQUEST | NLM_F_DUMP,
                                    ++g_seq, &g, sizeof g);
    nlbuf_put_str(&b, AD_IFNAME, ifname);
    rc = nl_talk(fd, buf, msg_end(&b, nh), live_cb, L);
    close(fd);
    return rc;
}

/* ---- метка сокета туннеля ------------------------------------------------------------ */

/* Через какой выход пускать UDP туннеля — поле `via` выхода (см. «вложенные выходы» в spec.h):
 * имя или NULL. Спрашивается одним местом, чтобы остальной код awg не знал, как поле хранится. */
static const char *awg_out_via(const struct output *o) {
    return o->via[0] ? o->via : NULL;
}

/* Метка сокета туннеля (WGDEVICE_A_FWMARK).
 *
 * С via — метка выхода via: ядро отправляет датаграммы туннеля с этой меткой (WireGuard
 * ставит skb->mark = fwmark устройства), правило движка `fwmark <метка via> lookup <таблица
 * via>` уводит их в устройство via — и туннель оказывается внутри другого туннеля.
 *
 * Без via — метка «мимо каналов движка»: STEER_SELF_MARK на телефоне, 0 на роутере. Почему
 * именно так — у out_underlay_mark в spec.h, и считает метку ОНА: у vless, xsteer, обфускатора и
 * awg одно правило, и держать его в двух местах значило бы однажды развести. Для awg к её доводам
 * добавляется одно: правила каналов на телефоне (self, uid:N) сокет туннеля не ловят и без метки —
 * сокет у WireGuard ядерный, без файла, и `meta skuid` на нём не совпадает, — но собственная метка
 * движка делает это свойством раскладки, а не удачей, и в `steer conns` такие записи не выдаются
 * за трафик приложений.
 *
 * Здесь остаётся только то, что out_underlay_mark не решает, — имя, которого нет: -1. Спека такое
 * отвергает (via_check), так что это страховка вызова в обход парсера (стенд awgmatch). Выход via
 * без метки (direct; или метка ещё не выдана) означает то же, что via нет. */
int awg_sock_mark(const struct spec *sp, const char *via, uint32_t *mark) {
    struct output t;
    memset(&t, 0, sizeof t);
    *mark = out_underlay_mark(sp, &t);
    if (!via || !*via) return 0;
    snprintf(t.via, sizeof t.via, "%s", via);
    if (!out_via(sp, &t)) return -1;
    *mark = out_underlay_mark(sp, &t);
    return 0;
}

/* ТУННЕЛЬ ЧЕРЕЗ via — ТОЛЬКО ПО IPv4, и это проверка, а не пожелание.
 *
 * Метка цели ведёт пакет в её таблицу через `ip rule fwmark …`, а и правило, и маршрут по
 * умолчанию в таблице выхода движок ставит только для IPv4 (`ip rule add` без семейства — это
 * IPv4). У датаграммы WireGuard к серверу по IPv6 с той же меткой в IPv6 нет ни правила, ни
 * таблицы — она идёт по обычным правилам системы, то есть НАПРЯМУЮ, мимо цели: ровно то, ради
 * чего via заводили (UDP к серверу режут, или сервер виден только из сети цели), молча не
 * происходит, а на телефоне это ещё и адрес человека у сервера мимо туннеля.
 *
 * Почему отказ, а не IPv6 для таблицы цели. Полноценный IPv6 — это `ip -6 rule` по той же метке,
 * маршрут в таблицу, запасной запрет, сверка и снятие в обоих семействах — во всём слое
 * маршрутизации (apply, сторож, down), и он менял бы судьбу и помеченного IPv6 приложений у
 * каждого выхода-цели, а не только туннеля. Остальные туннели через via этого не требуют вовсе:
 * клиенты vless, xsteer и обфускатор открывают сокеты только AF_INET (адрес узла, Endpoint и
 * сервер обфускации принимаются только как IPv4 или имя, разрешаемое в IPv4), так что их трафик
 * к серверу по IPv6 не уходит ни через цель, ни мимо. Единственный, кто мог так уйти, — awg:
 * адрес пира ядро берёт из настройки как есть. Поэтому здесь: литерал IPv6 при via — отказ с
 * понятной причиной (туннель не поднимается), имя при via разрешается только в IPv4
 * (resolve_peers), и тихой отправки мимо цели нет ни в одном случае. */
int awg_via_check(const struct awg_conf *c, const char *via, char *err, size_t n) {
    if (!via || !*via) return 0;
    for (size_t i = 0; i < c->peer_n; i++) {
        const struct awg_peer *pe = &c->peer[i];
        struct in6_addr a6;
        if (!pe->has_ep || inet_pton(AF_INET6, pe->ep_host, &a6) != 1) continue;
        snprintf(err, n, "Endpoint пира %zu — адрес IPv6 (%s), а туннель идёт через via %s: у "
                         "выхода-цели маршрут только для IPv4, и туннель ушёл бы мимо него — "
                         "напишите адрес IPv4 или имя с адресом IPv4; туннель не поднят",
                 i + 1, pe->ep_host, via);
        return -1;
    }
    return 0;
}

/* ---- адреса ----------------------------------------------------------------------------- */

static int prefix_of_mask(const struct sockaddr *m) {
    const uint8_t *p; size_t n;
    if (m->sa_family == AF_INET) { p = (const uint8_t *)&((const struct sockaddr_in *)m)->sin_addr; n = 4; }
    else { p = (const uint8_t *)&((const struct sockaddr_in6 *)m)->sin6_addr; n = 16; }
    int bits = 0;
    for (size_t i = 0; i < n; i++) for (int k = 7; k >= 0; k--) if (p[i] >> k & 1) bits++;
    return bits;
}

static void prefix_str(const struct awg_prefix *p, char *dst, size_t n) {
    char a[INET6_ADDRSTRLEN];
    inet_ntop(p->family, p->addr, a, sizeof a);
    snprintf(dst, n, "%s/%u", a, p->cidr);
}

/* Привести адреса устройства к файлу: недостающие добавить, лишние снять. Не «снять всё и
 * поставить заново»: повторный apply с тем же файлом не должен ни на миг оставлять устройство
 * без адреса. Через `ip`, как у kind=interface и у TUN клиентов (bind_device и соседи): одна
 * команда на адрес, раз в apply. IPv6 — с nodad: адрес на точке-точке без соседей, и
 * проверка дубликата только задержала бы его на секунду в состоянии tentative. */
static void addrs_sync(const char *dev, const struct awg_conf *c) {
    char have[32][64];
    size_t have_n = 0;
    struct ifaddrs *ifa0 = NULL;
    if (getifaddrs(&ifa0) == 0) {
        for (struct ifaddrs *i = ifa0; i && have_n < 32; i = i->ifa_next) {
            if (!i->ifa_addr || strcmp(i->ifa_name, dev)) continue;
            int fam = i->ifa_addr->sa_family;
            if (fam != AF_INET && fam != AF_INET6) continue;
            struct awg_prefix p = { .family = (uint8_t)fam };
            if (fam == AF_INET) memcpy(p.addr, &((struct sockaddr_in *)i->ifa_addr)->sin_addr, 4);
            else {
                const uint8_t *a6 = (const uint8_t *)&((struct sockaddr_in6 *)i->ifa_addr)->sin6_addr;
                if (a6[0] == 0xfe && (a6[1] & 0xc0) == 0x80) continue;   /* link-local — не наш */
                memcpy(p.addr, a6, 16);
            }
            p.cidr = (uint8_t)(i->ifa_netmask ? prefix_of_mask(i->ifa_netmask) : (fam == AF_INET ? 32 : 128));
            prefix_str(&p, have[have_n++], sizeof have[0]);
        }
        freeifaddrs(ifa0);
    }
    for (size_t k = 0; k < c->addr_n; k++) {
        char want[64];
        prefix_str(&c->addr[k], want, sizeof want);
        int found = 0;
        for (size_t h = 0; h < have_n; h++) if (!strcmp(have[h], want)) { found = 1; have[h][0] = '\0'; }
        if (found) continue;
        const char *v4[] = { "ip", "addr", "add", want, "dev", dev, NULL };
        const char *v6[] = { "ip", "-6", "addr", "add", want, "dev", dev, "nodad", NULL };
        if (run_quiet(c->addr[k].family == AF_INET ? v4 : v6) != 0)
            fprintf(stderr, LOG_W "%s: адрес %s не встал\n", dev, want);
    }
    for (size_t h = 0; h < have_n; h++) {
        if (!have[h][0]) continue;
        const char *del[] = { "ip", "addr", "del", have[h], "dev", dev, NULL };
        run_quiet(del);
    }
}

/* ---- разрешение Endpoint --------------------------------------------------------------- */

/* Имя — при apply, одной попыткой и без ожидания: apply не должен висеть на DNS, которого
 * при загрузке телефона ещё нет. Не разрешилось — пир ставится без эндпоинта, туннель
 * молчит, и сторож в revive разрешит заново (не чаще раза в пять минут на устройство).
 *
 * v4only — туннель идёт через via: имя разрешается только в IPv4. Иначе на сети с IPv6 (у
 * телефона это обычное дело) getaddrinfo по RFC 6724 отдал бы первым адрес IPv6, и туннель
 * ушёл бы мимо цели — см. awg_via_check. Имя без адреса IPv4 при via не разрешится вовсе, и
 * журнал говорит почему. */
static int resolve_peers(struct awg_conf *c, const char *dev, int loud, int v4only) {
    int bad = 0;
    for (size_t i = 0; i < c->peer_n; i++) {
        struct awg_peer *pe = &c->peer[i];
        pe->ep_len = 0;
        if (!pe->has_ep) continue;
        struct addrinfo hints = { .ai_family = v4only ? AF_INET : AF_UNSPEC,
                                  .ai_socktype = SOCK_DGRAM, .ai_protocol = IPPROTO_UDP };
        struct addrinfo *res = NULL;
        char port[8];
        snprintf(port, sizeof port, "%u", pe->ep_port);
        int rc = getaddrinfo(pe->ep_host, port, &hints, &res);
        if (rc != 0 || !res) {
            if (loud)
                fprintf(stderr, LOG_W "%s: Endpoint %s не разрешился%s (%s) — пир без адреса, "
                                "повторю при починке туннеля\n", dev, pe->ep_host,
                        v4only ? " в IPv4 (туннель через via идёт только по IPv4)" : "",
                        gai_strerror(rc));
            bad++;
            continue;
        }
        if (res->ai_addrlen <= sizeof pe->ep) {
            memcpy(&pe->ep, res->ai_addr, res->ai_addrlen);
            pe->ep_len = res->ai_addrlen;
        }
        freeaddrinfo(res);
    }
    return bad;
}

/* ---- реестр устройств и подпись параметров ------------------------------------------- */

#define REG_MAX (MAX_OUTPUTS * 2)

static void reg_path(char *buf, size_t n) { snprintf(buf, n, "%s/awg-devices", g_state_dir); }

static size_t reg_read(char dst[][IFNAMSIZ]) {
    char path[512];
    reg_path(path, sizeof path);
    FILE *f = fopen(path, "r");
    if (!f) return 0;
    size_t n = 0;
    char line[64];
    while (n < REG_MAX && fgets(line, sizeof line, f)) {
        char *t = trim(line);
        if (!*t || strlen(t) >= IFNAMSIZ || !name_ok(t)) continue;
        snprintf(dst[n++], IFNAMSIZ, "%s", t);
    }
    fclose(f);
    return n;
}

static void reg_write(char devs[][IFNAMSIZ], size_t n) {
    char path[512], tmp[544];
    reg_path(path, sizeof path);
    snprintf(tmp, sizeof tmp, "%s.new", path);
    mkdir(g_state_dir, 0755);
    FILE *f = fopen(tmp, "w");
    if (!f) return;
    for (size_t i = 0; i < n; i++) fprintf(f, "%s\n", devs[i]);
    if (fclose(f) != 0 || rename(tmp, path) != 0) unlink(tmp);
}

static void sig_path(const char *dev, char *buf, size_t n) {
    snprintf(buf, n, "%s/awg-%s.sig", g_state_dir, dev);
}

static int sig_read(const char *dev, struct awg_sig *g) {
    char p[512];
    sig_path(dev, p, sizeof p);
    FILE *f = fopen(p, "r");
    if (!f) return -1;
    int ok = fscanf(f, "%x %x %x %x %x %x", &g->u16_has, &g->h_has, &g->i_has, &g->r16_has,
                    &g->u8_has, &g->hpk) == 6;
    fclose(f);
    return ok ? 0 : -1;
}

/* Только при изменении: подпись пишется при каждой настройке устройства, в том числе при
 * починке сторожем (раз в пять минут у молчащего туннеля), а содержимое у неё меняется лишь с
 * файлом туннеля. Переписывать то же самое во флеш телефона незачем. */
static void sig_write(const char *dev, const struct awg_sig *g) {
    struct awg_sig old;
    if (sig_read(dev, &old) == 0 && old.u16_has == g->u16_has && old.h_has == g->h_has &&
        old.i_has == g->i_has && old.r16_has == g->r16_has && old.u8_has == g->u8_has &&
        old.hpk == g->hpk)
        return;
    char p[512];
    sig_path(dev, p, sizeof p);
    FILE *f = fopen(p, "w");
    if (!f) return;
    fprintf(f, "%x %x %x %x %x %x\n", g->u16_has, g->h_has, g->i_has, g->r16_has, g->u8_has, g->hpk);
    fclose(f);
}

/* Снимается ли что-то, что поверх не снять: бит, который был и пропал. */
static int sig_lost(const struct awg_sig *old, const struct awg_sig *now) {
    return (old->u16_has & ~now->u16_has) || (old->h_has & ~now->h_has) ||
           (old->i_has & ~now->i_has) || (old->r16_has & ~now->r16_has) ||
           (old->u8_has & ~now->u8_has) || (old->hpk && !now->hpk);
}

static int is_our_kind(const char *k) {
    return !strcmp(k, AWG_GENL_NAME) || !strcmp(k, WG_GENL_NAME_);
}

/* ---- замеры счётчиков для сторожа: в памяти круга или в файле ------------------------------
 *
 * ЗАЧЕМ ПАМЯТЬ. Приговор «туннель молчит» (см. «здоровье» ниже) сравнивает счётчики пира с
 * прошлым проходом сторожа, и прошлый замер надо где-то хранить между проходами. Раньше это был
 * файл <state>/awg-<устройство>.hs, и писался он КАЖДЫЙ проход — счётчики и время меняются
 * всегда. На телефоне каталог состояния — /data, то есть флеш, а проход — раз в минуту и по
 * каждому событию сети: это постоянные записи во флеш круглые сутки, против требования
 * владельца о батарее и сне (на роутере state — tmpfs, там это ничего не стоило).
 *
 * На телефоне сторож — `failover --loop`: один долгоживущий родитель и проход в дочернем
 * процессе (fork; почему так — у failover_loop в steer.c). Память родителя дочерний видит
 * копией, так что прошлые замеры он получает даром; новые отдаёт родителю через трубу одной
 * короткой записью (строк не больше, чем устройств). Проход, умерший на полпути (die() в
 * разборе спеки, SIGKILL), ничего не отдаёт — и родитель держит прежние замеры, а не пустые:
 * пустые означали бы «прошлого замера нет», и приговор отложился бы ещё на проход. Замеров в
 * файл круг не пишет вовсе; файл остаётся для одиночного прохода (круг procd на роутере), где
 * памяти между проходами нет. Сна это не касается: во сне проходов нет вовсе. */
struct hs_sample {
    char dev[IFNAMSIZ];
    unsigned long long tx, rx;
    long t;
    int v;
};
static struct hs_sample g_hs[REG_MAX];
static size_t g_hs_n;
static int g_hs_mem;

void awg_hs_memory(int on) { g_hs_mem = on; }

static int hs_get(const char *dev, struct hs_sample *out) {
    if (g_hs_mem) {
        for (size_t i = 0; i < g_hs_n; i++)
            if (!strcmp(g_hs[i].dev, dev)) { *out = g_hs[i]; return 0; }
        return -1;
    }
    char p[512];
    snprintf(p, sizeof p, "%s/awg-%s.hs", g_state_dir, dev);
    FILE *f = fopen(p, "r");
    if (!f) return -1;
    int ok = fscanf(f, "%llu %llu %ld %d", &out->tx, &out->rx, &out->t, &out->v) == 4;
    fclose(f);
    return ok ? 0 : -1;
}

static void hs_put(const char *dev, const struct hs_sample *s) {
    if (g_hs_mem) {
        size_t i = 0;
        while (i < g_hs_n && strcmp(g_hs[i].dev, dev)) i++;
        if (i == g_hs_n) {
            if (g_hs_n >= REG_MAX) return;
            g_hs_n++;
        }
        g_hs[i] = *s;
        snprintf(g_hs[i].dev, sizeof g_hs[i].dev, "%s", dev);
        return;
    }
    char p[512];
    snprintf(p, sizeof p, "%s/awg-%s.hs", g_state_dir, dev);
    FILE *f = fopen(p, "w");
    if (!f) return;
    fprintf(f, "%llu %llu %ld %d\n", s->tx, s->rx, s->t, s->v);
    fclose(f);
}

/* Сообщение в трубу: строка на замер и «end» в конце — по нему родитель узнаёт, что прочёл всё.
 * Одной записью: при нескольких десятках строк это меньше PIPE_BUF, и родитель не увидит
 * половину. */
void awg_hs_send(int fd) {
    char buf[REG_MAX * 96 + 8];
    size_t n = 0;
    for (size_t i = 0; i < g_hs_n; i++) {
        int w = snprintf(buf + n, sizeof buf - n, "%s %llu %llu %ld %d\n", g_hs[i].dev,
                         g_hs[i].tx, g_hs[i].rx, g_hs[i].t, g_hs[i].v);
        if (w < 0 || (size_t)w >= sizeof buf - n) return;
        n += (size_t)w;
    }
    if (n + 4 >= sizeof buf) return;
    memcpy(buf + n, "end\n", 4);
    n += 4;
    for (size_t off = 0; off < n; ) {
        ssize_t w = write(fd, buf + off, n - off);
        if (w < 0 && errno == EINTR) continue;
        if (w <= 0) return;
        off += (size_t)w;
    }
}

void awg_hs_recv(int fd) {
    char buf[REG_MAX * 96 + 8];
    size_t n = 0;
    for (;;) {
        if (n >= sizeof buf - 1) break;
        ssize_t r = read(fd, buf + n, sizeof buf - 1 - n);
        if (r < 0 && errno == EINTR) continue;
        if (r <= 0) break;
        n += (size_t)r;
    }
    buf[n] = '\0';
    if (n < 4 || strcmp(buf + n - 4, "end\n") != 0) return;   /* проход не договорил */
    struct hs_sample got[REG_MAX];
    size_t k = 0;
    for (char *save = NULL, *ln = strtok_r(buf, "\n", &save); ln; ln = strtok_r(NULL, "\n", &save)) {
        if (!strcmp(ln, "end") || k >= REG_MAX) break;
        struct hs_sample s;
        memset(&s, 0, sizeof s);
        char dev[64];
        if (sscanf(ln, "%63s %llu %llu %ld %d", dev, &s.tx, &s.rx, &s.t, &s.v) != 5) continue;
        if (strlen(dev) >= IFNAMSIZ) continue;
        snprintf(s.dev, sizeof s.dev, "%s", dev);
        got[k++] = s;
    }
    memcpy(g_hs, got, k * sizeof got[0]);
    g_hs_n = k;
}

static void dev_state_drop(const char *dev) {
    char p[512];
    sig_path(dev, p, sizeof p);
    unlink(p);
    snprintf(p, sizeof p, "%s/awg-%s.hs", g_state_dir, dev);
    unlink(p);
}

/* ---- настройка одного выхода ------------------------------------------------------------ */

/* Поднять и настроить устройство выхода. loud — apply (предупреждения о файле печатаются);
 * сторож зовёт тихо, чтобы раз в пять минут не повторять одно и то же. 0 — готово. */
static int awg_configure(const struct spec *sp, const struct output *o, int loud) {
    static struct awg_conf c;         /* ~20 КБ — не на стек телефона */
    struct awg_secrets s;
    char err[256];
    const char *dev = o->device;
    if (awg_conf_load(o->xs_conf, &c, &s, err, sizeof err) != 0) {
        fprintf(stderr, LOG_W "выход %s: %s\n", o->name, err);
        return -1;
    }
    int rc = -1;
    uint8_t *msg = NULL;
    size_t cap = 0;
    if (loud) {
        if (c.dns_n)
            fprintf(stderr, LOG_W "выход %s: DNS из файла не применяется — имена разрешает "
                            "резолвер движка по каналам\n", o->name);
        if (c.ignored & AWG_IGN_FWMARK)
            fprintf(stderr, LOG_W "выход %s: FwMark из файла не применяется — метку сокета "
                            "туннеля выбирает движок\n", o->name);
        if (c.ignored & AWG_IGN_TABLE)
            fprintf(stderr, LOG_W "выход %s: Table из файла не применяется — таблицу выхода "
                            "ведёт движок\n", o->name);
        if (c.ignored & AWG_IGN_SCRIPTS)
            fprintf(stderr, LOG_W "выход %s: PreUp/PostUp/PreDown/PostDown не исполняются\n",
                    o->name);
    }

    uint32_t fwmark;
    const char *via = awg_out_via(o);
    if (awg_sock_mark(sp, via, &fwmark) != 0) {
        fprintf(stderr, LOG_W "выход %s: via %s — такого выхода нет\n", o->name, via);
        goto out;
    }
    /* До создания устройства: туннель через via с сервером по IPv6 ушёл бы мимо цели, и
     * поднимать его нельзя вовсе (см. awg_via_check). Отказ всегда громкий — и при apply, и в
     * починке сторожа: это не шум, а причина, по которой туннель не работает. */
    {
        char verr[512];     /* текст длиннее обычной ошибки разбора: адрес и имя цели */
        if (awg_via_check(&c, via, verr, sizeof verr) != 0) {
            fprintf(stderr, LOG_W "выход %s: %s\n", o->name, verr);
            goto out;
        }
    }

    /* КАКОЙ МОДУЛЬ. AmneziaWG — всегда, когда он есть: он понимает и обычный WireGuard (файл
     * без параметров обфускации). Модуль wireguard — только запасной путь для такого файла.
     * Уже стоящее устройство решает первым: устройство wireguard с файлом без обфускации так и
     * остаётся wireguard (пересоздавать его ради смены модуля значило бы рвать работающий
     * туннель без всякой пользы), а с файлом, которому нужен AmneziaWG, — пересоздаётся. */
    int needs = awg_conf_needs_awg(&c);
    uint16_t famid = 0;
    int famver = 0, is_awg = 0;
    int have_awg = genl_family(AWG_GENL_NAME, &famid, &famver) == 0;
    char live_kind[32] = "";
    int index = 0;
    int lq = link_query(dev, live_kind, sizeof live_kind, &index);
    if (lq == 0 && !is_our_kind(live_kind)) {
        fprintf(stderr, LOG_W "выход %s: устройство %s уже есть, и это не туннель движка "
                        "(вид «%s») — не трогаю\n", o->name, dev, live_kind[0] ? live_kind : "?");
        goto out;
    }
    int recreate = 0;
    if (lq == 0 && !strcmp(live_kind, WG_GENL_NAME_) && !needs) is_awg = 0;
    else if (have_awg) {
        is_awg = 1;
        if (lq == 0 && strcmp(live_kind, AWG_GENL_NAME) != 0) recreate = 1;
    } else if (needs) {
        fprintf(stderr, LOG_W "выход %s: в ядре нет модуля AmneziaWG, а файл задаёт параметры "
                        "обфускации — обычный WireGuard их не понимает, туннель не поднят\n",
                o->name);
        goto out;
    } else {
        is_awg = 0;
        /* Устройство amneziawg при пропавшем модуле быть не может; если ядро всё же его
         * показывает — пересоздаём тем, что есть. */
        if (lq == 0 && strcmp(live_kind, WG_GENL_NAME_) != 0) recreate = 1;
    }
    if (is_awg) {
        const char *why = NULL;
        int need_ver = awg_conf_min_version(&c, &why);
        if (need_ver > famver) {
            fprintf(stderr, LOG_W "выход %s: модуль AmneziaWG в ядре старше файла: %s требует "
                            "версии интерфейса %d, у модуля %d — туннель не поднят\n",
                    o->name, why ? why : "параметр", need_ver, famver);
            goto out;
        }
    } else if (genl_family(WG_GENL_NAME_, &famid, &famver) != 0) {
        fprintf(stderr, LOG_W "выход %s: в ядре нет ни AmneziaWG, ни WireGuard — туннель "
                        "не поднят\n", o->name);
        goto out;
    }
    const char *kind = is_awg ? AWG_GENL_NAME : WG_GENL_NAME_;
    struct awg_sig now = conf_sig(&c), old;
    if (lq == 0 && !recreate && is_awg && sig_read(dev, &old) == 0 && sig_lost(&old, &now))
        recreate = 1;
    if (recreate) {
        if (loud)
            fprintf(stderr, LOG_I "выход %s: устройство %s поверх не перенастроить — "
                            "пересоздаю\n", o->name, dev);
        link_delete(dev);
        lq = ENODEV;
    }
    if (loud && !c.addr_n)
        fprintf(stderr, LOG_W "выход %s: в файле нет Address — у устройства не будет адреса, и "
                        "подменить им адрес источника будет нечем\n", o->name);
    int mtu = c.mtu ? c.mtu : 1420;
    int created = 0;
    if (lq != 0) {
        int e = link_create(dev, kind, mtu);
        if (e) {
            fprintf(stderr, LOG_W "выход %s: устройство %s не создано: %s\n", o->name, dev,
                    strerror(e));
            goto out;
        }
        created = 1;
        if (link_query(dev, NULL, 0, &index) != 0) goto out;
    }

    resolve_peers(&c, dev, loud, via != NULL);

    /* Пиры, которых в файле нет, снимаются флагом REPLACE_PEERS. Ставится он ТОЛЬКО когда
     * состав пиров действительно разошёлся: флаг снимает всех и ставит заново, то есть рвёт
     * живые сессии, а повторный apply с тем же файлом не должен рвать ничего. */
    int replace = 0;
    if (!created) {
        static struct awg_live L;
        if (live_read(dev, kind, &L) == 0) {
            if (L.peer_n != c.peer_n) replace = 1;
            for (size_t i = 0; i < L.peer_n && !replace; i++) {
                int f = 0;
                for (size_t k = 0; k < c.peer_n; k++)
                    if (!memcmp(L.peer[i].pub, c.peer[k].pub, AWG_KEY_LEN)) f = 1;
                if (!f) replace = 1;
            }
        } else replace = 1;
    }

    cap = 65536 + 5 * AWG_MAX_ISTR;
    msg = malloc(cap);
    if (!msg) goto out;
    size_t n = awg_build_set(msg, cap, famid, famver, is_awg, dev, &c, &s, fwmark, replace, ++g_seq);
    if (!n) {
        fprintf(stderr, LOG_W "выход %s: настройка не влезает в одно сообщение ядру\n", o->name);
        goto out;
    }
    int fd = nl_open(NETLINK_GENERIC);
    int e = fd < 0 ? errno : nl_talk(fd, msg, n, NULL, NULL);
    if (fd >= 0) close(fd);
    if (e) {
        fprintf(stderr, LOG_W "выход %s: ядро не приняло настройку %s: %s\n", o->name, dev,
                strerror(e));
        goto out;
    }
    e = link_set_up(index, mtu);
    if (e) fprintf(stderr, LOG_W "выход %s: %s не поднялось: %s\n", o->name, dev, strerror(e));
    addrs_sync(dev, &c);
    sig_write(dev, &now);
    if (loud)
        fprintf(stderr, LOG_I "выход %s: %s %s (%s%s)\n", o->name, dev,
                created ? "создано" : "перенастроено", kind,
                is_awg && needs ? ", с обфускацией" : "");
    rc = 0;
out:
    if (msg) { wipe(msg, cap); free(msg); }
    awg_secrets_wipe(&s);
    awg_conf_free(&c);
    return rc;
}

/* ---- apply и down ------------------------------------------------------------------------ */

int awg_apply_all(const struct spec *sp) {
    char reg[REG_MAX][IFNAMSIZ], keep[REG_MAX][IFNAMSIZ];
    size_t reg_n = reg_read(reg), keep_n = 0;
    int bad = 0;
    for (size_t i = 0; i < sp->out_n; i++) {
        const struct output *o = &sp->out[i];
        if (o->kind != OUT_AWG) continue;
        /* Два выхода на одно устройство настраивали бы его по очереди, и победил бы второй —
         * молча. Имена выводятся из имён выходов, так что это почти всегда явный `device`. */
        int dup = 0;
        for (size_t k = 0; k < i; k++)
            if (sp->out[k].kind == OUT_AWG && !strcmp(sp->out[k].device, o->device)) dup = 1;
        if (dup) {
            fprintf(stderr, LOG_W "выход %s: устройство %s уже занято другим выходом kind=awg\n",
                    o->name, o->device);
            bad++;
            continue;
        }
        if (awg_configure(sp, o, 1) != 0) bad++;
        /* В реестр — даже при отказе: устройство могло быть создано до отказа настройки, и
         * снять его потом должен кто-то. */
        if (keep_n < REG_MAX) snprintf(keep[keep_n++], IFNAMSIZ, "%s", o->device);
    }
    /* Выходы, которых в спеке больше нет: их устройства снимаются. Только наши по виду — имя
     * из реестра могло с тех пор достаться чужому устройству. */
    for (size_t r = 0; r < reg_n; r++) {
        int live = 0;
        for (size_t k = 0; k < keep_n; k++) if (!strcmp(reg[r], keep[k])) live = 1;
        if (live) continue;
        char kind[32] = "";
        if (link_query(reg[r], kind, sizeof kind, NULL) == 0 && is_our_kind(kind)) {
            link_delete(reg[r]);
            fprintf(stderr, LOG_I "устройство %s снято — его выхода больше нет\n", reg[r]);
        }
        dev_state_drop(reg[r]);
    }
    if (keep_n || reg_n) reg_write(keep, keep_n);
    return bad;
}

int awg_check_all(const struct spec *sp) {
    int bad = 0;
    for (size_t i = 0; i < sp->out_n; i++) {
        const struct output *o = &sp->out[i];
        if (o->kind != OUT_AWG) continue;
        static struct awg_conf c;
        struct awg_secrets s;
        char err[256];
        if (awg_conf_load(o->xs_conf, &c, &s, err, sizeof err) != 0) {
            fprintf(stderr, LOG_W "выход %s: %s\n", o->name, err);
            bad++;
            continue;
        }
        char verr[512];
        if (awg_via_check(&c, awg_out_via(o), verr, sizeof verr) != 0) {
            fprintf(stderr, LOG_W "выход %s: %s\n", o->name, verr);
            bad++;
        }
        awg_secrets_wipe(&s);
        awg_conf_free(&c);
    }
    return bad;
}

void awg_down_all(void) {
    char reg[REG_MAX][IFNAMSIZ];
    size_t n = reg_read(reg);
    for (size_t i = 0; i < n; i++) {
        char kind[32] = "";
        if (link_query(reg[i], kind, sizeof kind, NULL) == 0 && is_our_kind(kind))
            link_delete(reg[i]);
        dev_state_drop(reg[i]);
    }
    char path[512];
    reg_path(path, sizeof path);
    unlink(path);
}

/* ---- здоровье ------------------------------------------------------------------------------
 *
 * ПО РУКОПОЖАТИЮ, БЕЗ ПРОБ. Пока через туннель идёт трафик, WireGuard обновляет ключи не реже
 * чем раз в REKEY_AFTER_TIME (120 с), а через REJECT_AFTER_TIME (180 с) без нового рукопожатия
 * перестаёт шифровать вовсе. Значит рукопожатие моложе 180 с — туннель жив, и это видно без
 * единого пакета от нас.
 *
 * Старое рукопожатие само по себе НЕ приговор: туннель, по которому никто ничего не шлёт,
 * рукопожатий не делает, и так и должно быть — пробуждать радио ради проверки нельзя.
 * Приговор даёт сравнение счётчиков с прошлым проходом сторожа: если за это время мы что-то
 * отправили (tx вырос — это и данные, и попытки рукопожатия), а в ответ не пришло ни байта (rx
 * стоит), при старом рукопожатии — пир молчит. Прошлого замера нет или он моложе 15 с (две
 * попытки рукопожатия WireGuard идут с шагом 5 с) — прежний приговор, а при его отсутствии —
 * «живо»: сказать нечего, а ошибка в сторону «сломано» при on_fail=drop ставит запрет
 * работающему выходу.
 *
 * ЦЕНА этого выбора, и её надо знать. Упавший выход с on_fail=drop стоит на blackhole: трафик
 * в туннель не идёт, tx не растёт — и следующий проход видит «тишину», то есть «живо», и
 * возвращает маршрут. Если пир по-прежнему мёртв, трафик следующего прохода это покажет, и
 * выход снова уйдёт в отказ. То есть мёртвый туннель проверяется настоящим трафиком раз в два
 * прохода сторожа — это и есть проба, только из того, что человек и так шлёт, без
 * собственных пакетов и таймеров. Кому нужно быстрее — тот задаёт PersistentKeepalive. */
#define AWG_HS_FRESH 180
#define AWG_SAMPLE_MIN 15

static long boot_now(void) {
    struct timespec ts;
#ifdef CLOCK_BOOTTIME
    /* BOOTTIME, а не MONOTONIC: телефон спит, и сон между проходами тоже время — иначе
     * замер «15 секунд назад» после ночи сна значил бы «только что». */
    if (clock_gettime(CLOCK_BOOTTIME, &ts) == 0) return (long)ts.tv_sec;
#endif
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (long)ts.tv_sec;
}

static const char *live_kind_of(const char *dev, char *buf, size_t n) {
    if (link_query(dev, buf, n, NULL) != 0 || !is_our_kind(buf)) return NULL;
    return buf;
}

int awg_healthy(const struct output *o, const char *dev) {
    char kb[32];
    const char *kind = live_kind_of(dev, kb, sizeof kb);
    if (!kind) return 0;                /* устройства нет или оно не наше */
    static struct awg_live L;
    if (live_read(dev, kind, &L) != 0) return 1;   /* спросить не вышло — не приговор */
    int fresh_s = AWG_HS_FRESH;
    /* RejectAfterTime в файле (AmneziaWG 3) растягивает жизнь ключей — и порог вместе с ней. */
    {
        static struct awg_conf c;
        struct awg_secrets s;
        char err[128];
        if (o && awg_conf_load(o->xs_conf, &c, &s, err, sizeof err) == 0) {
            if ((c.r16_has >> AWG_REJECT_AFTER) & 1) {
                int ra = (int)(c.r16[AWG_REJECT_AFTER] >> 16);
                if (ra > fresh_s) fresh_s = ra;
            }
            awg_secrets_wipe(&s);
            awg_conf_free(&c);
        }
    }
    int64_t newest = 0;
    uint64_t rx = 0, tx = 0;
    for (size_t i = 0; i < L.peer_n; i++) {
        if (L.peer[i].hs > newest) newest = L.peer[i].hs;
        rx += L.peer[i].rx;
        tx += L.peer[i].tx;
    }
    long now = boot_now();
    /* Прошлый замер — из памяти круга или из файла (см. «замеры счётчиков для сторожа»). */
    struct hs_sample prev;
    unsigned long long ptx = 0, prx = 0;
    long pt = 0;
    int pv = -1;
    if (hs_get(dev, &prev) == 0) { ptx = prev.tx; prx = prev.rx; pt = prev.t; pv = prev.v; }
    int verdict;
    int64_t age = newest ? (int64_t)time(NULL) - newest : -1;
    if (newest && age >= 0 && age <= fresh_s) verdict = 1;
    else if (pv < 0 || tx < ptx || rx < prx) verdict = 1;          /* нет замера или счётчики сброшены */
    else if (now - pt < AWG_SAMPLE_MIN) return pv;                  /* рано судить — прежний приговор */
    else verdict = !(tx > ptx && rx == prx);
    struct hs_sample cur = { .tx = tx, .rx = rx, .t = now, .v = verdict };
    hs_put(dev, &cur);
    return verdict;
}

int awg_revive(const struct spec *sp, const struct output *o, const char *dev) {
    /* Устройства нет — это не «молчит», а «ещё не поднято»: так бывает при каждом включении
     * движка на телефоне, где сторож стартует раньше, чем выход успел создать устройство, и
     * после ручного `ip link del`. Предупреждение о молчащем пире в этом случае — ложная
     * тревога, которую человек видит в журнале приложения, поэтому причины разведены. */
    char kb[32];
    if (!live_kind_of(dev, kb, sizeof kb))
        fprintf(stderr, LOG_I "%s: устройства нет — поднимаю\n", dev);
    else
        fprintf(stderr, LOG_W "%s: туннель молчит — заново разрешаю Endpoint и перенастраиваю\n", dev);
    if (awg_configure(sp, o, 0) != 0) return 0;
    return awg_healthy(o, dev);
}

/* ---- status ------------------------------------------------------------------------------ */

static void ep_str(const struct sockaddr_storage *ss, socklen_t len, char *dst, size_t n) {
    char a[INET6_ADDRSTRLEN] = "";
    if (len >= sizeof(struct sockaddr_in) && ss->ss_family == AF_INET) {
        const struct sockaddr_in *s4 = (const void *)ss;
        inet_ntop(AF_INET, &s4->sin_addr, a, sizeof a);
        snprintf(dst, n, "%s:%u", a, ntohs(s4->sin_port));
    } else if (len >= sizeof(struct sockaddr_in6) && ss->ss_family == AF_INET6) {
        const struct sockaddr_in6 *s6 = (const void *)ss;
        inet_ntop(AF_INET6, &s6->sin6_addr, a, sizeof a);
        snprintf(dst, n, "[%s]:%u", a, ntohs(s6->sin6_port));
    } else dst[0] = '\0';
}

/* Состояние туннеля одним объектом рядом с device/up: status опрашивают раз в несколько
 * секунд, и это один разговор с ядром (дамп устройства) на выход — без проб и без файлов.
 * Итог по пирам сводится: самое свежее рукопожатие, суммы счётчиков, эндпоинт первого пира
 * (у клиента пир один — сервер). Ключей в выводе нет никаких, и публичных тоже: интерфейсу
 * они ни к чему, а лишнее поле в выводе, который уходит в резервные копии и отчёты, — лишнее. */
void awg_status_json(FILE *out, const struct output *o) {
    char kb[32];
    const char *kind = live_kind_of(o->device, kb, sizeof kb);
    static struct awg_live L;
    if (!kind || live_read(o->device, kind, &L) != 0) {
        fprintf(out, ",\"awg\":{\"live\":false}");
        return;
    }
    int64_t newest = 0;
    uint64_t rx = 0, tx = 0;
    for (size_t i = 0; i < L.peer_n; i++) {
        if (L.peer[i].hs > newest) newest = L.peer[i].hs;
        rx += L.peer[i].rx;
        tx += L.peer[i].tx;
    }
    fprintf(out, ",\"awg\":{\"live\":true,\"impl\":\"%s\",\"peers\":%zu", kind, L.peer_n);
    if (newest) {
        long long ago = (long long)time(NULL) - (long long)newest;
        if (ago < 0) ago = 0;
        fprintf(out, ",\"handshake_ago\":%lld", ago);
    } else fprintf(out, ",\"handshake_ago\":null");
    fprintf(out, ",\"rx\":%llu,\"tx\":%llu", (unsigned long long)rx, (unsigned long long)tx);
    char ep[80] = "";
    if (L.peer_n) ep_str(&L.peer[0].ep, L.peer[0].ep_len, ep, sizeof ep);
    if (ep[0]) fprintf(out, ",\"endpoint\":\"%s\"", ep);
    else fprintf(out, ",\"endpoint\":null");
    fprintf(out, "}");
}
