/* xsteer: разбор конфигурации в стиле WireGuard. Почему строго и почему без mbedtls —
 * в xsconf.h. */
#define _GNU_SOURCE
#include <arpa/inet.h>
#include <errno.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#include "xsconf.h"
#include "xswire.h"

/* ---- base64 для ключей, СТРОГО ---------------------------------------------
 *
 * Своя реализация, а не b64_decode из sub.c, и это не дублирование ради дублирования.
 * Тот декодер намеренно терпимый: он пропускает переводы строк, знаки '=' и любой мусор,
 * потому что читает подписку из интернета, где панели отдают что угодно. Для КЛЮЧА эта
 * терпимость означает ровно одно: строка «QUJD…» с выпавшим символом молча превращается в
 * ключ на 31 байт, и криптография оказывается слабее заявленной, причём заметить это
 * нельзя ничем. Поэтому здесь: ровно 44 символа, только стандартный алфавит, только один
 * '=' в конце, ровно 32 байта на выходе. */
static int b64v(unsigned char c) {
    if (c >= 'A' && c <= 'Z') return c - 'A';
    if (c >= 'a' && c <= 'z') return c - 'a' + 26;
    if (c >= '0' && c <= '9') return c - '0' + 52;
    if (c == '+') return 62;
    if (c == '/') return 63;
    return -1;
}

int xs_key_decode(const char *b64, uint8_t out[32]) {
    if (strlen(b64) != XS_KEY_B64) return -1;
    if (b64[XS_KEY_B64 - 1] != '=') return -1;
    uint32_t acc = 0;
    int bits = 0;
    size_t o = 0;
    for (int i = 0; i < XS_KEY_B64 - 1; i++) {
        int v = b64v((unsigned char)b64[i]);
        if (v < 0) return -1;
        acc = (acc << 6) | (uint32_t)v;
        bits += 6;
        if (bits >= 8) {
            bits -= 8;
            if (o >= 32) return -1;
            out[o++] = (uint8_t)((acc >> bits) & 0xFF);
        }
    }
    /* 43 символа дают 258 бит: два лишних обязаны быть нулевыми, иначе это не запись
     * 32 байт, а другая строка, случайно похожая на неё. Проверка дешёвая, а без неё у
     * одного ключа было бы четыре разных написания. */
    if (o != 32 || (acc & ((1u << bits) - 1)) != 0) return -1;
    return 0;
}

void xs_key_encode(const uint8_t key[32], char out[XS_KEY_B64 + 1]) {
    static const char A[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    int o = 0;
    for (int i = 0; i < 30; i += 3) {
        uint32_t v = ((uint32_t)key[i] << 16) | ((uint32_t)key[i + 1] << 8) | key[i + 2];
        out[o++] = A[(v >> 18) & 63];
        out[o++] = A[(v >> 12) & 63];
        out[o++] = A[(v >> 6) & 63];
        out[o++] = A[v & 63];
    }
    uint32_t v = ((uint32_t)key[30] << 16) | ((uint32_t)key[31] << 8);
    out[o++] = A[(v >> 18) & 63];
    out[o++] = A[(v >> 12) & 63];
    out[o++] = A[(v >> 6) & 63];
    out[o++] = '=';
    out[o] = '\0';
}

void xs_key_fp(const uint8_t pub[32], char out[12]) {
    char b[XS_KEY_B64 + 1];
    xs_key_encode(pub, b);
    memcpy(out, b, 8);
    out[8] = '\0';
}

void xs_conf_wipe(struct xs_secrets *s) {
    volatile uint8_t *p = s->priv;
    for (size_t i = 0; i < sizeof(s->priv); i++) p[i] = 0;
    s->has_priv = 0;
}

/* ---- разбор строк ---------------------------------------------------------- */

static int ieq(const char *a, const char *b) {
    for (; *a && *b; a++, b++)
        if ((*a | 32) != (*b | 32)) return 0;
    return *a == *b;
}

static char *trim(char *s) {
    while (*s == ' ' || *s == '\t') s++;
    char *e = s + strlen(s);
    while (e > s && (e[-1] == ' ' || e[-1] == '\t' || e[-1] == '\r')) *--e = '\0';
    return s;
}

/* Ключи wg, поведение которых движок не реализует. Отвергаются НАЗЫВАЯ замену: человек,
 * скопировавший конфигурацию из wg-quick, обязан узнать, что его PostUp не выполнится, —
 * иначе он будет ждать от туннеля того, чего тот не делает. */
static const struct { const char *key; const char *why; } REFUSED[] = {
    { "Table",        "таблицами маршрутизации владеет apply, см. spec.json" },
    { "FwMark",       "метками владеет движок (registry), задать их снаружи нельзя" },
    { "PreUp",        "движок не исполняет команды из конфигурации" },
    { "PostUp",       "движок не исполняет команды из конфигурации" },
    { "PreDown",      "движок не исполняет команды из конфигурации" },
    { "PostDown",     "движок не исполняет команды из конфигурации" },
    { "SaveConfig",   "движок конфигурацию не перезаписывает" },
    { "PresharedKey", "xsteer не использует предварительный ключ: принять его молча "
                      "значило бы сказать «настроено», не настроив ничего" },
};
#define REFUSED_N (sizeof(REFUSED) / sizeof(REFUSED[0]))

/* Известные ключи — для подсказки при опечатке. Тот же приём, что у «возможно, вы имели в
 * виду» в cli.c: опечатка в имени ключа не должна требовать чтения документации. */
static const char *KNOWN[] = {
    "PrivateKey", "Address", "MTU", "ListenPort", "SNI", "Device", "DNS",
    "Decoy", "DecoyDest", "DecoySNI",
    "PublicKey", "AllowedIPs", "Endpoint", "PersistentKeepalive",
};
#define KNOWN_N (sizeof(KNOWN) / sizeof(KNOWN[0]))

/* Не static: тем же расстоянием подсказывает по опечатке разбор ссылки (xslink.c). Своя копия
 * там означала бы две меры близости на один проект — и однажды разные подсказки на одну
 * опечатку. */
int xs_lev(const char *a, const char *b) {
    size_t la = strlen(a), lb = strlen(b);
    if (la > 32 || lb > 32) return 99;
    int prev[33], cur[33];
    for (size_t j = 0; j <= lb; j++) prev[j] = (int)j;
    for (size_t i = 1; i <= la; i++) {
        cur[0] = (int)i;
        for (size_t j = 1; j <= lb; j++) {
            int c = ((a[i - 1] | 32) == (b[j - 1] | 32)) ? 0 : 1;
            int m = prev[j] + 1;
            if (cur[j - 1] + 1 < m) m = cur[j - 1] + 1;
            if (prev[j - 1] + c < m) m = prev[j - 1] + c;
            cur[j] = m;
        }
        memcpy(prev, cur, sizeof(int) * (lb + 1));
    }
    return prev[lb];
}

static const char *did_you_mean(const char *key) {
    const char *best = NULL;
    int bd = 99;
    for (size_t i = 0; i < KNOWN_N; i++) {
        int d = xs_lev(key, KNOWN[i]);
        if (d < bd) { bd = d; best = KNOWN[i]; }
    }
    return bd <= 3 ? best : NULL;
}

/* Один префикс: «10.0.0.0/24» или «1.2.3.4» (то же, что /32). */
static int parse_pfx(const char *s, struct xs_allowed *a) {
    char buf[64];
    if (strlen(s) >= sizeof(buf)) return -1;
    snprintf(buf, sizeof(buf), "%s", s);
    int plen = 32;
    char *slash = strchr(buf, '/');
    if (slash) {
        *slash = '\0';
        char *end = NULL;
        long v = strtol(slash + 1, &end, 10);
        if (!end || *end || v < 0 || v > 32) return -1;
        plen = (int)v;
    }
    struct in_addr in;
    if (inet_pton(AF_INET, buf, &in) != 1) return -1;
    uint32_t net = ntohl(in.s_addr);
    uint32_t mask = plen ? (0xFFFFFFFFu << (32 - plen)) : 0;
    /* Хост-биты за маской обнуляются молча, как это делает и wg: «10.0.0.5/24» человек
     * пишет чаще, чем «10.0.0.0/24», и отвергать это значило бы придираться. */
    a->net = net & mask;
    a->mask = mask;
    a->plen = plen;
    return 0;
}

/* Одно имя прикрытия из DecoySNI.
 *
 * Приводится к НИЖНЕМУ РЕГИСТРУ и лишается завершающей точки прямо здесь, а не при сравнении:
 * сравнивать это имя предстоит с именем из чужого ClientHello, то есть на пути, куда попадает
 * кто угодно из интернета, и нормализовать там обе стороны значило бы делать лишнюю работу над
 * недоверенными байтами на каждом неопознанном соединении.
 *
 * Проверка строгая по той же причине, что и у остальных ключей: имя, принятое с мусором внутри,
 * не совпало бы ни с одним настоящим SNI никогда — то есть ключ выглядел бы настроенным и молча
 * не работал. 0 — записано, -1 — не годится, и тогда в why лежит причина. */
static int parse_decoy_name(const char *in, char *out, size_t outn, const char **why) {
    size_t n = strlen(in);
    /* Подстановка отвергается ОТДЕЛЬНОЙ причиной, а не общим «недопустимый символ»: человек,
     * написавший *.example.com, скопировал её из ключа --decoy-sni реализации на Go, где
     * подстановки есть, и обязан узнать, почему здесь их нет, а не гадать об опечатке. */
    if (strchr(in, '*')) {
        *why = "подстановки невозможны: имена разрешаются в адреса один раз при подъёме хаба, "
               "а имя из подстановки становится известно только в момент прихода прибора, то "
               "есть потребовало бы разрешения из цикла воркера";
        return -1;
    }
    if (n && in[n - 1] == '.') n--;          /* завершающая точка — законная форма FQDN */
    if (!n) { *why = "имя пустое"; return -1; }
    if (n >= outn) { *why = "длиннее буфера"; return -1; }
    if (in[0] == '.' || in[0] == '-' || in[n - 1] == '-') {
        *why = "имя не может начинаться с точки или дефиса и кончаться дефисом";
        return -1;
    }
    for (size_t i = 0; i < n; i++) {
        char ch = in[i];
        int ok = (ch >= 'a' && ch <= 'z') || (ch >= 'A' && ch <= 'Z') ||
                 (ch >= '0' && ch <= '9') || ch == '-' || ch == '.';
        if (!ok) { *why = "допустимы только буквы, цифры, дефис и точка"; return -1; }
        if (ch == '.' && i && in[i - 1] == '.') { *why = "две точки подряд"; return -1; }
        out[i] = (ch >= 'A' && ch <= 'Z') ? (char)(ch + 32) : ch;
    }
    out[n] = '\0';
    return 0;
}

#define FAIL(...) do { snprintf(err, errn, __VA_ARGS__); return -1; } while (0)

int xs_conf_parse(const char *text, size_t n, enum xs_role role,
                  struct xs_conf *c, struct xs_secrets *s, char *err, size_t errn) {
    memset(c, 0, sizeof(*c));
    memset(s, 0, sizeof(*s));
    if (n > XS_CONF_MAX) FAIL("файл больше %d КиБ", XS_CONF_MAX / 1024);

    int in_peer = -1;                 /* -1 — секции ещё не было; -2 — [Interface] */
    int have_addr = 0;
    int line_no = 0;
    const char *p = text;
    const char *end = text + n;

    while (p < end) {
        const char *nl = memchr(p, '\n', (size_t)(end - p));
        size_t len = nl ? (size_t)(nl - p) : (size_t)(end - p);
        /* Две тысячи, а не пятьсот: AllowedIPs едет ОДНОЙ строкой через запятую, и полный
         * туннель с исключениями — до шестидесяти четырёх префиксов (XS_ALLOWED_MAX) — это
         * под тысячу символов. С прежними 512 такая строка отвергалась как «слишком длинная»
         * ещё до подсчёта префиксов, то есть у самого частого сценария. */
        char raw[2048];
        if (len >= sizeof(raw)) FAIL("строка %d: слишком длинная", line_no + 1);
        memcpy(raw, p, len);
        raw[len] = '\0';
        p = nl ? nl + 1 : end;
        line_no++;

        char *line = trim(raw);
        if (!*line || *line == '#' || *line == ';') continue;

        if (*line == '[') {
            char *close = strchr(line, ']');
            if (!close) FAIL("строка %d: секция без закрывающей скобки", line_no);
            *close = '\0';
            char *name = trim(line + 1);
            if (ieq(name, "Interface")) in_peer = -2;
            else if (ieq(name, "Peer")) {
                if (c->peer_n >= XS_PEERS_MAX)
                    FAIL("строка %d: пиров больше %d", line_no, XS_PEERS_MAX);
                in_peer = (int)c->peer_n++;
            }
            /* Неизвестная секция — отказ, а не «все её ключи неизвестны»: иначе один
             * опечатанный заголовок породил бы десяток жалоб на ключи, и настоящая
             * причина утонула бы в них. */
            else FAIL("строка %d: неизвестная секция [%s] (нужна [Interface] или [Peer])",
                      line_no, name);
            continue;
        }

        char *eq = strchr(line, '=');
        if (!eq) FAIL("строка %d: нет знака равенства", line_no);
        *eq = '\0';
        char *key = trim(line);
        char *val = trim(eq + 1);
        if (!*key) FAIL("строка %d: пустое имя ключа", line_no);
        if (!*val) FAIL("строка %d: у ключа %s нет значения", line_no, key);
        if (in_peer == -1) FAIL("строка %d: ключ %s вне секции", line_no, key);

        for (size_t i = 0; i < REFUSED_N; i++)
            if (ieq(key, REFUSED[i].key))
                FAIL("строка %d: ключ %s не поддерживается — %s",
                     line_no, REFUSED[i].key, REFUSED[i].why);

        if (in_peer == -2) {                    /* [Interface] */
            if (ieq(key, "PrivateKey")) {
                if (xs_key_decode(val, s->priv) != 0)
                    FAIL("строка %d: PrivateKey должен быть 32 байта в base64 "
                         "(%d символа, как у wg genkey)", line_no, XS_KEY_B64);
                s->has_priv = 1;
            } else if (ieq(key, "Address")) {
                struct xs_allowed a;
                /* IPv6 отвергается ЯВНО. Маршрутизация в движке только про IPv4, и
                 * принять адрес значило бы обещать то, чего нет: туннель поднялся бы, а
                 * трафик не пошёл. */
                if (strchr(val, ':'))
                    FAIL("строка %d: Address только IPv4 — маршрутизация движка про IPv4",
                         line_no);
                if (parse_pfx(val, &a) != 0)
                    FAIL("строка %d: Address должен быть вида 10.0.0.2/24", line_no);
                struct in_addr in;
                char host[64];
                snprintf(host, sizeof(host), "%s", val);
                char *sl = strchr(host, '/');
                if (sl) *sl = '\0';
                if (inet_pton(AF_INET, host, &in) != 1)
                    FAIL("строка %d: Address не разобран", line_no);
                c->addr = ntohl(in.s_addr);
                c->addr_plen = a.plen;
                have_addr = 1;
            } else if (ieq(key, "MTU")) {
                long v = atol(val);
                if (v < 576 || v > XS_LINK_MAX)
                    FAIL("строка %d: MTU вне разумного (576..%d)", line_no, XS_LINK_MAX);
                c->mtu = (int)v;
            } else if (ieq(key, "ListenPort")) {
                long v = atol(val);
                if (v < 1 || v > 65535) FAIL("строка %d: ListenPort вне 1..65535", line_no);
                c->listen_port = (int)v;
            } else if (ieq(key, "SNI")) {
                if (strlen(val) >= sizeof(c->sni))
                    FAIL("строка %d: SNI длиннее %zu", line_no, sizeof(c->sni) - 1);
                snprintf(c->sni, sizeof(c->sni), "%s", val);
            } else if (ieq(key, "DNS")) {
                /* ПРИНИМАЕТСЯ, НО НЕ ПРИМЕНЯЕТСЯ, и это осознанный размен.
                 *
                 * Прежде ключ отвергал файл целиком. Отказ был честным (именами на роутере
                 * распоряжается dnsmasq, и трогать резолвер из туннеля здесь нельзя), но он
                 * ломал главное свойство формата, записанное в шапке этого файла и в conf.go
                 * реализации на Go: конфигурация носится между роутером и десктопом, и файл,
                 * принятый одной реализацией и отвергнутый другой, означает, что «настроено»
                 * зависит от того, куда его положили. Десктопный клиент DNS применяет, поэтому
                 * его файл обязан читаться и здесь.
                 *
                 * Молча проглотить тоже нельзя: человек, написавший DNS, ждёт, что запросы
                 * пойдут в туннель. Поэтому ключ запоминается счётчиком, а сказать о нём
                 * ОДИН РАЗ при подъёме — дело того, кто поднимает (xsclient.c): разбор здесь
                 * чистая функция и в журнал не пишет. */
                /* Разбираются АДРЕСА, а не строка целиком: в файле их пишут через запятую, и
                 * «DNS: 1 адр.» на строке из двух означало бы, что разбор понял её не так, как
                 * человек.
                 *
                 * КАЖДЫЙ ПРОВЕРЯЕТСЯ как литерал IPv4 — так же, как это делает половина на Go.
                 * Прежде здесь считались запятые и больше ничего, и «DNS = не-адрес» проходил
                 * тут и отвергался там: тот самый случай, когда «настроено» зависит от того,
                 * куда файл положили. */
                {
                    const char *q = val;
                    while (*q) {
                        while (*q == ' ' || *q == '\t' || *q == ',') q++;
                        if (!*q) break;
                        const char *e = q;
                        while (*e && *e != ',') e++;
                        size_t n2 = (size_t)(e - q);
                        while (n2 > 0 && (q[n2 - 1] == ' ' || q[n2 - 1] == '\t')) n2--;
                        if (n2 == 0) { q = e; continue; }
                        if (c->dns_n >= XS_DNS_MAX)
                            FAIL("строка %d: адресов DNS больше %d", line_no, XS_DNS_MAX);
                        if (n2 >= sizeof(c->dns[0]))
                            FAIL("строка %d: адрес DNS длиннее %zu знаков", line_no,
                                 sizeof(c->dns[0]) - 1);
                        char one[16];
                        memcpy(one, q, n2);
                        one[n2] = '\0';
                        struct in_addr din;
                        if (inet_pton(AF_INET, one, &din) != 1)
                            FAIL("строка %d: DNS «%s» — нужен адрес IPv4", line_no, one);
                        memcpy(c->dns[c->dns_n], one, n2 + 1);
                        c->dns_n++;
                        q = e;
                    }
                }
            } else if (ieq(key, "Decoy")) {
                /* Режим называется словом, а не числом: в журнале и в файле должно стоять то
                 * же слово, что в документации и в ключе --decoy реализации на Go. */
                if (ieq(val, "alert")) c->decoy = XS_DECOY_ALERT;
                else if (ieq(val, "silent")) c->decoy = XS_DECOY_SILENT;
                else if (ieq(val, "reset")) c->decoy = XS_DECOY_RESET;
                else if (ieq(val, "proxy")) c->decoy = XS_DECOY_PROXY;
                else FAIL("строка %d: Decoy: неизвестный режим %s (alert, silent, reset "
                          "или proxy)", line_no, val);
            } else if (ieq(key, "DecoyDest")) {
                /* Адрес сайта-прикрытия. Литерал IPv4 и порт — те же требования, что у
                 * Endpoint: соединяться с прикрытием приходится из цикла воркера, где нет ни
                 * одного блокирующего вызова, а разрешение имени им и было бы. */
                char *colon = strrchr(val, ':');
                if (!colon) FAIL("строка %d: DecoyDest должен быть вида адрес:порт", line_no);
                *colon = '\0';
                long port = atol(colon + 1);
                if (port < 1 || port > 65535)
                    FAIL("строка %d: DecoyDest: порт вне 1..65535", line_no);
                struct in_addr in;
                if (inet_pton(AF_INET, val, &in) != 1)
                    FAIL("строка %d: DecoyDest задаётся адресом, а не именем: разрешение "
                         "имени пошло бы через DNS из цикла, где нет блокирующих вызовов",
                         line_no);
                if (strlen(val) >= sizeof(c->decoy_dest))
                    FAIL("строка %d: DecoyDest длиннее буфера", line_no);
                snprintf(c->decoy_dest, sizeof(c->decoy_dest), "%s", val);
                c->decoy_port = (int)port;
            } else if (ieq(key, "DecoySNI")) {
                /* Имена прикрытия, которые хабу разрешено обслуживать: список через запятую,
                 * ровно как у AllowedIPs. Здесь имя ПРОВЕРЯЕТСЯ и нормализуется, а разрешается
                 * в адрес — один раз при подъёме хаба (xshub.c); почему так и почему подстановок
                 * нет, написано у поля decoy_sni в xsconf.h.
                 *
                 * Ключ называется так же, как --decoy-sni у реализации на Go: одно и то же
                 * свойство обязано называться одним словом в файле, в журнале и в документации
                 * обеих половин — тот же довод, что у Decoy выше. */
                char *save = val;
                while (*save) {
                    char *comma = strchr(save, ',');
                    if (comma) *comma = '\0';
                    char *item = trim(save);
                    if (*item) {
                        const char *why = "";
                        if (c->decoy_sni_n >= XS_DECOY_SNI_MAX)
                            FAIL("строка %d: DecoySNI: имён больше %d", line_no,
                                 XS_DECOY_SNI_MAX);
                        if (parse_decoy_name(item, c->decoy_sni[c->decoy_sni_n],
                                             XS_DECOY_SNI_LEN, &why) != 0)
                            FAIL("строка %d: DecoySNI: имя %s не годится — %s",
                                 line_no, item, why);
                        c->decoy_sni_n++;
                    }
                    if (!comma) break;
                    save = comma + 1;
                }
            } else if (ieq(key, "Device")) {
                /* Имя устройства ядра: те же ограничения, что у ip link — буквы, цифры и
                 * несколько знаков, короче IFNAMSIZ. Иначе `ip` откажет уже на подъёме, а
                 * там ошибку видно хуже, чем здесь с номером строки. */
                if (strlen(val) >= sizeof(c->device))
                    FAIL("строка %d: Device длиннее %zu", line_no, sizeof(c->device) - 1);
                for (const char *p = val; *p; p++)
                    if (!((*p >= 'a' && *p <= 'z') || (*p >= 'A' && *p <= 'Z') ||
                          (*p >= '0' && *p <= '9') || *p == '-' || *p == '_' || *p == '.'))
                        FAIL("строка %d: Device: недопустимый символ %c", line_no, *p);
                snprintf(c->device, sizeof(c->device), "%s", val);
            } else {
                const char *hint = did_you_mean(key);
                c->unknown_n++;
                if (hint) FAIL("строка %d: неизвестный ключ %s — возможно, %s",
                               line_no, key, hint);
                FAIL("строка %d: неизвестный ключ %s", line_no, key);
            }
            continue;
        }

        struct xs_peer *pe = &c->peer[in_peer];
        if (ieq(key, "PublicKey")) {
            if (xs_key_decode(val, pe->pub) != 0)
                FAIL("строка %d: PublicKey должен быть 32 байта в base64", line_no);
        } else if (ieq(key, "AllowedIPs")) {
            char *save = val;
            while (*save) {
                char *comma = strchr(save, ',');
                if (comma) *comma = '\0';
                char *item = trim(save);
                if (*item) {
                    if (pe->allowed_n >= XS_ALLOWED_MAX)
                        FAIL("строка %d: префиксов у пира больше %d",
                             line_no, XS_ALLOWED_MAX);
                    if (parse_pfx(item, &pe->allowed[pe->allowed_n]) != 0)
                        FAIL("строка %d: AllowedIPs: не разобран префикс %s", line_no, item);
                    pe->allowed_n++;
                }
                if (!comma) break;
                save = comma + 1;
            }
        } else if (ieq(key, "Endpoint")) {
            char *colon = strrchr(val, ':');
            if (!colon) FAIL("строка %d: Endpoint должен быть вида адрес:порт", line_no);
            *colon = '\0';
            long port = atol(colon + 1);
            if (port < 1 || port > 65535)
                FAIL("строка %d: Endpoint: порт вне 1..65535", line_no);
            struct in_addr in;
            if (inet_pton(AF_INET, val, &in) != 1)
                FAIL("строка %d: Endpoint задаётся адресом, а не именем: разрешение имени "
                     "пошло бы через DNS, который сам может идти в этот туннель", line_no);
            if (strlen(val) >= sizeof(pe->endpoint))
                FAIL("строка %d: Endpoint длиннее буфера", line_no);
            snprintf(pe->endpoint, sizeof(pe->endpoint), "%s", val);
            pe->endpoint_port = (int)port;
        } else if (ieq(key, "PersistentKeepalive")) {
            long v = atol(val);
            if (v < 0 || v > 3600)
                FAIL("строка %d: PersistentKeepalive вне 0..3600", line_no);
            pe->keepalive = (int)v;
            pe->keepalive_set = 1;
        } else {
            const char *hint = did_you_mean(key);
            c->unknown_n++;
            if (hint) FAIL("строка %d: неизвестный ключ %s — возможно, %s",
                           line_no, key, hint);
            FAIL("строка %d: неизвестный ключ %s", line_no, key);
        }
    }

    /* ---- проверки целого файла ---------------------------------------------
     *
     * Роль в файле не написана: её задаёт подкоманда, которая файл читает. Но разбор один
     * — иначе получились бы два представления об одной сущности, ровно то, от чего
     * предупреждает шапка spec.h, — поэтому требования проверяются здесь, по роли. */
    if (!s->has_priv) FAIL("нет PrivateKey в [Interface]");
    if (!have_addr) FAIL("нет Address в [Interface]");
    if (!c->peer_n) FAIL("нет ни одной секции [Peer]");

    for (size_t i = 0; i < c->peer_n; i++) {
        struct xs_peer *pe = &c->peer[i];
        int zero = 1;
        for (int k = 0; k < 32; k++) if (pe->pub[k]) { zero = 0; break; }
        if (zero) FAIL("пир %zu: нет PublicKey", i + 1);
        if (!pe->allowed_n) FAIL("пир %zu: нет AllowedIPs", i + 1);
        /* Один и тот же публичный ключ у двух пиров — это либо копипаста, либо попытка
         * завести двух пиров с одним ключом. И то и другое означает, что трафик достанется
         * непредсказуемому из них: хаб ищет пира по ключу. */
        for (size_t k = 0; k < i; k++)
            if (memcmp(pe->pub, c->peer[k].pub, 32) == 0)
                FAIL("пиры %zu и %zu: один и тот же PublicKey", k + 1, i + 1);
    }

    if (role == XS_ROLE_SPOKE) {
        if (c->listen_port)
            FAIL("ListenPort — это конфигурация хаба: пир никуда не слушает");
        /* Защита от зондирования — про слушающий порт, а пир никуда не слушает. Принять ключ
         * молча значило бы сказать «настроено», не настроив ничего. */
        if (c->decoy || c->decoy_port || c->decoy_sni_n)
            FAIL("Decoy — это конфигурация хаба: неопознанные приходят на слушающий порт, "
                 "а пир никуда не слушает");
        /* Две секции [Peer] у пира означали бы, что часть трафика идёт мимо хаба, а маршрут
         * пир↔пир через хаб — обещание топологии, а не деталь реализации. */
        if (c->peer_n != 1)
            FAIL("у пира ровно одна секция [Peer] — хаб; сети других пиров задаются их "
                 "префиксами в AllowedIPs этого пира");
        if (!c->peer[0].endpoint_port)
            FAIL("единственному пиру нужен Endpoint: соединение начинает пир, а не хаб");
        /* Умолчание wg — 25 секунд, и оно же здесь: пир за NAT обязан поддерживать
         * отображение живым, потому что дозвониться до него хаб не может. Подставляется
         * только когда ключа НЕ БЫЛО: явный ноль означает «выключено», и затирать его
         * умолчанием значило бы не сделать того, о чём попросили. */
        if (!c->peer[0].keepalive_set) c->peer[0].keepalive = 25;
    } else {
        if (!c->listen_port) FAIL("хабу нужен ListenPort");
        /* Режим proxy без адреса прикрытия — это не «работает вполсилы», а хаб, который на
         * каждого неопознанного пытается открыть соединение в никуда и отвечает оповещением,
         * то есть ровно то поведение, от которого настройка и уводит. Отказ здесь, а не в
         * бою: неверная настройка защиты, обнаруженная под зондированием, — защита, которой нет. */
        if (c->decoy == XS_DECOY_PROXY && !c->decoy_port)
            FAIL("Decoy = proxy требует DecoyDest — адрес сайта-прикрытия вида 1.2.3.4:443");
        /* Имена без режима proxy ничего не выбирают: отвечать оповещением, RST или молчанием
         * можно только одним способом, прикрытия в этих режимах нет вовсе. Принять список молча
         * значило бы сказать «настроено», не настроив ничего, — то же правило, что у
         * PresharedKey и у Decoy в конфигурации пира. */
        if (c->decoy_sni_n && c->decoy != XS_DECOY_PROXY)
            FAIL("DecoySNI имеет смысл только при Decoy = proxy: в остальных режимах "
                 "прикрытия нет вовсе и выбирать нечего");
        for (size_t i = 0; i < c->peer_n; i++)
            if (c->peer[i].endpoint_port)
                FAIL("пир %zu: Endpoint в конфигурации хаба бессмыслен — пира живут за "
                     "NAT и приходят сами", i + 1);
        /* Пересечение префиксов двух пиров ОТВЕРГАЕТСЯ, а не разрешается «последний
         * победил», как это делает wg. На хабе неоднозначность означает молчаливый увод
         * трафика к другой пиру, и найти такое по симптому нельзя: работает, но не туда. */
        for (size_t i = 0; i < c->peer_n; i++)
            for (size_t k = 0; k < i; k++)
                for (size_t a = 0; a < c->peer[i].allowed_n; a++)
                    for (size_t b = 0; b < c->peer[k].allowed_n; b++) {
                        struct xs_allowed *x = &c->peer[i].allowed[a];
                        struct xs_allowed *y = &c->peer[k].allowed[b];
                        uint32_t m = x->mask & y->mask;
                        if ((x->net & m) == (y->net & m))
                            FAIL("пиры %zu и %zu: AllowedIPs пересекаются — хаб не смог бы "
                                 "решить, кому отдать пакет", k + 1, i + 1);
                    }
    }
    return 0;
}

int xs_conf_load(const char *path, enum xs_role role,
                 struct xs_conf *c, struct xs_secrets *s, char *err, size_t errn) {
    /* lstat, а не stat: символьная ссылка отвергается до открытия. Нацеленная на
     * /etc/shadow, она положила бы его содержимое в текст ошибки разбора, то есть в
     * журнал и в diag. */
    struct stat st;
    if (lstat(path, &st) != 0) FAIL("%s: %s", path, strerror(errno));
    if (!S_ISREG(st.st_mode)) FAIL("%s: не обычный файл", path);
    /* Доступ «остальным» — ОТКАЗ, а не предупреждение. Приватный ключ, читаемый nobody
     * (под которым на OpenWrt живут dnsmasq и uhttpd), — это чужой пир в вашей звезде;
     * запустить туннель «пока так» значило бы согласиться с этим навсегда, а
     * предупреждение в журнале procd не читает никто. Команда даётся готовой. */
    if (st.st_mode & (S_IROTH | S_IWOTH | S_IXOTH))
        FAIL("%s: файл доступен всем — приватный ключ обязан быть закрыт: chmod 600 %s",
             path, path);
    if (st.st_size > XS_CONF_MAX) FAIL("%s: больше %d КиБ", path, XS_CONF_MAX / 1024);

    FILE *f = fopen(path, "r");
    if (!f) FAIL("%s: %s", path, strerror(errno));
    static char buf[XS_CONF_MAX + 1];
    size_t got = fread(buf, 1, XS_CONF_MAX, f);
    fclose(f);
    buf[got] = '\0';
    return xs_conf_parse(buf, got, role, c, s, err, errn);
}

void xs_conf_json(FILE *out, const struct xs_conf *c) {
    char addr[16];
    struct in_addr in;
    in.s_addr = htonl(c->addr);
    inet_ntop(AF_INET, &in, addr, sizeof(addr));
    fprintf(out, "{\"schema\":1,\"address\":\"%s/%d\",\"mtu\":%d,\"peers\":[",
            addr, c->addr_plen, c->mtu ? c->mtu : XS_MTU_DEF);
    for (size_t i = 0; i < c->peer_n; i++) {
        const struct xs_peer *pe = &c->peer[i];
        char fp[12];
        xs_key_fp(pe->pub, fp);
        fprintf(out, "%s{\"key\":\"%s\",\"keepalive\":%d,\"endpoint\":", i ? "," : "",
                fp, pe->keepalive);
        if (pe->endpoint_port) fprintf(out, "\"%s:%d\"", pe->endpoint, pe->endpoint_port);
        else fprintf(out, "null");
        fprintf(out, ",\"allowed\":[");
        for (size_t a = 0; a < pe->allowed_n; a++) {
            char net[16];
            in.s_addr = htonl(pe->allowed[a].net);
            inet_ntop(AF_INET, &in, net, sizeof(net));
            fprintf(out, "%s\"%s/%d\"", a ? "," : "", net, pe->allowed[a].plen);
        }
        fprintf(out, "]}");
    }
    fprintf(out, "]}");
}
