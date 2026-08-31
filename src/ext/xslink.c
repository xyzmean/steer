/* xsteer: разбор и печать ссылки xs://. Формат — в xslink.h и в docs/xsteer.md. */
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <arpa/inet.h>

#include "xslink.h"

#define LFAIL(...) do { if (err && errn) snprintf(err, errn, __VA_ARGS__); return -1; } while (0)

/* ---- процентная запись ------------------------------------------------------
 *
 * Своя, а не «взять готовую»: готовой в C нет, а требования здесь жёсткие. Обе стороны обязаны
 * понимать одну и ту же строку, поэтому набор незащищаемых знаков списан с реализации на Go
 * буква в букву (net/url, shouldEscape) — иначе имя с двоеточием, напечатанное одной половиной,
 * другая прочитала бы иначе. */
static int hexv(unsigned char c) {
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    return -1;
}

/* Раскрыть %XX. plus_space — читать '+' как пробел: так делает разбор СТРОКИ ЗАПРОСА (и Go, и
 * все браузеры), но не разбор фрагмента. Отсюда же следует, почему печать защищает '+': ключ,
 * записанный обычным base64, содержит '+', и без защиты он превратился бы в пробел. */
static int pct_decode(const char *s, size_t n, int plus_space, char *out, size_t outn) {
    size_t o = 0;
    for (size_t i = 0; i < n; i++) {
        unsigned char c = (unsigned char)s[i];
        if (c == '%') {
            if (i + 2 >= n) return -1;
            int h = hexv((unsigned char)s[i + 1]), l = hexv((unsigned char)s[i + 2]);
            if (h < 0 || l < 0) return -1;
            c = (unsigned char)((h << 4) | l);
            i += 2;
        } else if (c == '+' && plus_space) {
            c = ' ';
        }
        if (o + 1 >= outn) return -1;
        out[o++] = (char)c;
    }
    out[o] = '\0';
    return 0;
}

/* Защита ЗНАЧЕНИЯ в строке запроса. Защищается только то, что в строке запроса значимо: '&' и '='
 * разделяют пары, '#' начинает фрагмент, '%' начинает саму запись, '+' читается как пробел.
 * Остальное печатается как есть — и это осознанно: '/' в строке запроса законен (RFC 3986,
 * query = *(pchar / "/" / "?")), но обычные библиотеки печатают его как %2F, и префиксы
 * превращаются в 10.77.0.0%2F24. Ссылку проверяют ГЛАЗАМИ перед выдачей, и нечитаемая ссылка —
 * это ссылка, которую не проверят. */
static int q_esc(const char *v, char *out, size_t outn) {
    static const char SAFE[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"
                               "0123456789-._~/:,";
    size_t o = 0;
    for (const char *p = v; *p; p++) {
        if (strchr(SAFE, *p) && *p) {
            if (o + 1 >= outn) return -1;
            out[o++] = *p;
        } else {
            if (o + 3 >= outn) return -1;
            o += (size_t)snprintf(out + o, outn - o, "%%%02X", (unsigned char)*p);
        }
    }
    out[o] = '\0';
    return 0;
}

/* Защита ИМЕНИ во фрагменте. Набор — тот, что у url.PathEscape реализации на Go: не защищаются
 * буквы, цифры, «-._~» и «$&+:=@», защищается всё прочее, включая пробел, '/', ';', ',', '?' и
 * саму решётку. Имя бывает с пробелами и кириллицей, поэтому запись здесь нужна всегда. */
static int frag_esc(const char *v, char *out, size_t outn) {
    static const char SAFE[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"
                               "0123456789-._~$&+:=@";
    size_t o = 0;
    for (const char *p = v; *p; p++) {
        if (strchr(SAFE, *p) && *p) {
            if (o + 1 >= outn) return -1;
            out[o++] = *p;
        } else {
            if (o + 3 >= outn) return -1;
            o += (size_t)snprintf(out + o, outn - o, "%%%02X", (unsigned char)*p);
        }
    }
    out[o] = '\0';
    return 0;
}

/* ---- ключи в записи для ссылки ---------------------------------------------
 *
 * base64url БЕЗ набивки (43 знака, алфавит с '-' и '_'), потому что у обычного base64 есть '+' и
 * '/', а им в ссылке нужна процентная запись — и ссылка становится нечитаемой и ломается при
 * копировании через мессенджеры.
 *
 * На РАЗБОРЕ принимаются оба алфавита и набивка необязательна: человек будет вставлять ключ прямо
 * из wg-конфигурации, и отвергать такую вставку значило бы требовать от него ручного перевода. */
static int key_decode_url(const char *s, uint8_t out[32]) {
    char b[XS_KEY_B64 + 1];
    size_t n = strlen(s);
    while (n > 0 && s[n - 1] == '=') n--;
    if (n != XS_KEY_B64 - 1) return -1;
    for (size_t i = 0; i < n; i++)
        b[i] = s[i] == '-' ? '+' : s[i] == '_' ? '/' : s[i];
    b[n] = '=';
    b[n + 1] = '\0';
    return xs_key_decode(b, out);
}

static void key_encode_url(const uint8_t k[32], char out[XS_KEY_B64]) {
    char b[XS_KEY_B64 + 1];
    xs_key_encode(k, b);
    size_t n = strlen(b);
    while (n > 0 && b[n - 1] == '=') n--;
    for (size_t i = 0; i < n; i++)
        out[i] = b[i] == '+' ? '-' : b[i] == '/' ? '_' : b[i];
    out[n] = '\0';
}

/* Адрес IPv4 литералом. Имя пришлось бы разрешать через DNS, а он сам может быть направлен в
 * этот же туннель — то же правило и та же причина, что у Endpoint в файле. */
static int ipv4_lit(const char *s, struct in_addr *out) {
    return inet_pton(AF_INET, s, out) == 1 ? 0 : -1;
}

/* ---- разбор ----------------------------------------------------------------- */

/* Известные параметры — и для подсказки при опечатке, и для отказа по неизвестному. Отказ, а не
 * «запас на будущее»: опечатка в имени параметра, принятая молча, означает «настроено» без
 * настройки. */
static const char *LINK_KEYS[] = { "pk", "ip", "allowed", "sni", "mtu", "ka", "dns" };
#define LINK_KEYS_N (sizeof(LINK_KEYS) / sizeof(LINK_KEYS[0]))

static const char *link_did_you_mean(const char *key) {
    const char *best = NULL;
    int bd = 99;
    for (size_t i = 0; i < LINK_KEYS_N; i++) {
        int d = xs_lev(key, LINK_KEYS[i]);
        if (d < bd) { bd = d; best = LINK_KEYS[i]; }
    }
    return bd <= 2 ? best : NULL;
}

int xs_link_parse(const char *s, enum xs_role role, struct xs_conf *c, struct xs_secrets *sec,
                  char *name, size_t namen, char *err, size_t errn) {
    if (name && namen) name[0] = '\0';
    if (!s) LFAIL("ссылки нет");
    size_t len = strlen(s);
    if (len > XS_URI_MAX) LFAIL("ссылка длиннее %d КиБ", XS_URI_MAX / 1024);
    /* Пробелы и переводы строк по краям — обычное дело при копировании из сообщения. */
    while (len > 0 && (s[len - 1] == ' ' || s[len - 1] == '\t' || s[len - 1] == '\r' ||
                       s[len - 1] == '\n')) len--;
    while (len > 0 && (*s == ' ' || *s == '\t' || *s == '\r' || *s == '\n')) { s++; len--; }

    if (role == XS_ROLE_HUB)
        /* Ссылкой описывается ОДИН доступ: свой ключ, один хаб, свой адрес. Конфигурация хаба —
         * это список пиров, и уложить его в ссылку значило бы завести второй формат с другими
         * возможностями. Сказано прямо, чтобы «хаб по ссылке» не выглядел недоделкой. */
        LFAIL("ссылка описывает доступ ОДНОГО пира, а хабу нужен список пиров — "
             "хаб настраивается файлом");

    if (len < 5 || strncasecmp(s, "xs://", 5) != 0)
        LFAIL("ссылка не xs:// — она начинается с «xs://»");
    const char *p = s + 5, *end = s + len;

    /* Фрагмент отрезается ПЕРВОЙ решёткой: так же поступает разбор адреса в Go, и имя, в котором
     * решётка была, обязано приезжать записанным. */
    const char *frag = memchr(p, '#', (size_t)(end - p));
    if (frag) {
        char raw[XS_LINK_NAME_MAX * 3];
        size_t fn = (size_t)(end - frag - 1);
        if (fn >= sizeof(raw)) LFAIL("имя после решётки длиннее %d знаков", XS_LINK_NAME_MAX);
        char dec[XS_LINK_NAME_MAX];
        memcpy(raw, frag + 1, fn);
        raw[fn] = '\0';
        if (pct_decode(raw, fn, 0, dec, sizeof(dec)) != 0)
            LFAIL("имя после решётки: негодная процентная запись");
        if (name && namen) snprintf(name, namen, "%s", dec);
        end = frag;
    }

    const char *qs = memchr(p, '?', (size_t)(end - p));
    const char *auth_end = qs ? qs : end;

    /* Полномочие кончается ПЕРВОЙ косой чертой — так же, как в разборе адреса реализации на Go, и
     * это не мелочь: если ключ вставили обычным base64 (там бывает '/'), обе половины обязаны
     * отказать одинаково и назвать одну причину, а не одна «нет ключа», другая «лишний путь».
     * Одна косая черта в конце допустима: она пустой путь, а не путь. */
    const char *slash = memchr(p, '/', (size_t)(auth_end - p));
    if (slash) {
        size_t pn = (size_t)(auth_end - slash);
        int only_slashes = 1;
        for (size_t i = 0; i < pn; i++) if (slash[i] != '/') { only_slashes = 0; break; }
        if (!only_slashes) {
            char bad[64];
            snprintf(bad, sizeof(bad), "%.*s", (int)(pn > 40 ? 40 : pn), slash);
            LFAIL("в ссылке лишний путь «%s» — после порта идёт сразу ?", bad);
        }
        auth_end = slash;
    }

    /* Приватный ключ — до знака @. Ищем ПОСЛЕДНИЙ: в ключе '@' быть не может, а в неудачной
     * вставке — может, и тогда честнее отказать на ключе, чем на хосте. */
    const char *at = NULL;
    for (const char *q = p; q < auth_end; q++) if (*q == '@') at = q;
    if (!at || at == p)
        LFAIL("в ссылке нет приватного ключа: он идёт перед знаком @, "
             "как xs://<ключ>@<хост>:<порт>?...");
    char user[128];
    if ((size_t)(at - p) >= sizeof(user)) LFAIL("приватный ключ в ссылке слишком длинный");
    snprintf(user, sizeof(user), "%.*s", (int)(at - p), p);
    if (strchr(user, ':'))
        LFAIL("в ссылке двоеточие перед @ — приватный ключ идёт один, без пароля");
    uint8_t priv[32];
    if (key_decode_url(user, priv) != 0)
        LFAIL("приватный ключ в ссылке негоден: нужны 32 байта в base64 (43 знака без набивки)");

    /* Хост и порт. Двоеточие ПОСЛЕДНЕЕ: адрес IPv4 двоеточий не содержит, но так разбор
     * останется верным, если однажды появится литерал в скобках. */
    char hostport[80];
    if ((size_t)(auth_end - at - 1) >= sizeof(hostport))
        LFAIL("хост и порт в ссылке слишком длинные");
    snprintf(hostport, sizeof(hostport), "%.*s", (int)(auth_end - at - 1), at + 1);
    char *colon = strrchr(hostport, ':');
    if (!colon || colon == hostport)
        LFAIL("после @ нужен хост и порт (%s), как 1.2.3.4:443", hostport);
    *colon = '\0';
    struct in_addr hip;
    if (ipv4_lit(hostport, &hip) != 0)
        LFAIL("хост «%s» — нужен адрес IPv4 литералом: имя разрешает тот, кто пишет ссылку, "
             "иначе туннель может зависеть от DNS внутри себя", hostport);
    char *pend = NULL;
    long port = strtol(colon + 1, &pend, 10);
    if (!pend || *pend || pend == colon + 1 || port < 1 || port > 65535)
        LFAIL("порт «%s» — нужно число от 1 до 65535", colon + 1);

    /* ---- параметры ---- */
    char v_pk[128] = "", v_ip[64] = "", v_allowed[1024] = "", v_sni[256] = "";
    char v_mtu[32] = "", v_ka[32] = "", v_dns[512] = "";
    unsigned seen = 0;
    if (qs) {
        const char *q = qs + 1;
        while (q < end) {
            const char *amp = memchr(q, '&', (size_t)(end - q));
            const char *item_end = amp ? amp : end;
            if (item_end == q) { q = item_end + 1; continue; }
            const char *eq = memchr(q, '=', (size_t)(item_end - q));
            char key[64];
            if (!eq) {
                snprintf(key, sizeof(key), "%.*s",
                         (int)((size_t)(item_end - q) > 40 ? 40 : (size_t)(item_end - q)), q);
                LFAIL("у параметра %s нет значения", key);
            }
            if ((size_t)(eq - q) >= sizeof(key)) LFAIL("имя параметра в ссылке слишком длинное");
            snprintf(key, sizeof(key), "%.*s", (int)(eq - q), q);
            for (char *k = key; *k; k++) *k = (char)(*k >= 'A' && *k <= 'Z' ? *k + 32 : *k);

            char val[1200];
            if (pct_decode(eq + 1, (size_t)(item_end - eq - 1), 1, val, sizeof(val)) != 0)
                LFAIL("значение параметра %s: негодная процентная запись", key);
            /* Пробелы по краям значения — след копирования, а не смысл. */
            char *vb = val;
            while (*vb == ' ' || *vb == '\t') vb++;
            size_t vn = strlen(vb);
            while (vn > 0 && (vb[vn - 1] == ' ' || vb[vn - 1] == '\t')) vb[--vn] = '\0';
            if (!*vb) LFAIL("у параметра %s нет значения", key);

            size_t idx = LINK_KEYS_N;
            for (size_t i = 0; i < LINK_KEYS_N; i++)
                if (!strcmp(key, LINK_KEYS[i])) { idx = i; break; }
            if (idx == LINK_KEYS_N) {
                const char *hint = link_did_you_mean(key);
                if (hint)
                    LFAIL("неизвестный параметр %s — возможно, %s (есть pk, ip, allowed, sni, "
                         "mtu, ka, dns)", key, hint);
                LFAIL("неизвестный параметр %s (есть pk, ip, allowed, sni, mtu, ka, dns)", key);
            }
            /* Повтор — отказ: «последний победил» здесь означало бы, что смысл ссылки зависит от
             * того, как её склеили. */
            if (seen & (1u << idx))
                LFAIL("параметр %s задан дважды — какое значение верное, ссылка не говорит", key);
            seen |= 1u << idx;

            char *dst = NULL;
            size_t dstn = 0;
            switch (idx) {
                case 0: dst = v_pk;      dstn = sizeof(v_pk);      break;
                case 1: dst = v_ip;      dstn = sizeof(v_ip);      break;
                case 2: dst = v_allowed; dstn = sizeof(v_allowed); break;
                case 3: dst = v_sni;     dstn = sizeof(v_sni);     break;
                case 4: dst = v_mtu;     dstn = sizeof(v_mtu);     break;
                case 5: dst = v_ka;      dstn = sizeof(v_ka);      break;
                default: dst = v_dns;    dstn = sizeof(v_dns);     break;
            }
            size_t vl = strlen(vb);
            if (vl >= dstn) LFAIL("значение параметра %s слишком длинное", key);
            memcpy(dst, vb, vl + 1);
            if (!amp) break;
            q = amp + 1;
        }
    }

    if (!*v_pk) LFAIL("в ссылке нет pk — публичного ключа хаба");
    if (!*v_ip) LFAIL("в ссылке нет ip — адреса внутри туннеля");
    uint8_t pub[32];
    if (key_decode_url(v_pk, pub) != 0)
        LFAIL("pk (публичный ключ хаба) негоден: нужны 32 байта в base64");
    if (*v_ka) {
        char *ke = NULL;
        long ka = strtol(v_ka, &ke, 10);
        if (!ke || *ke || ka < 0 || ka > 65535)
            LFAIL("ka=«%s» — нужны секунды от 0 до 65535 (0 выключает)", v_ka);
    }
    if (*v_mtu) {
        char *me = NULL;
        (void)strtol(v_mtu, &me, 10);
        if (!me || *me) LFAIL("mtu=«%s» — нужно число", v_mtu);
    }

    /* AllowedIPs по умолчанию — СЕТЬ ИЗ ip, а не 0.0.0.0/0.
     *
     * Умолчание выбрано в безопасную сторону: полный туннель — решение человека, а не то, что
     * должно случаться от краткости ссылки. Сеть из ip — это «вижу свою звезду»; полный туннель
     * задаётся явным allowed=0.0.0.0/0. */
    if (!*v_allowed) {
        char ipbuf[64];
        snprintf(ipbuf, sizeof(ipbuf), "%s", v_ip);
        char *sl = strchr(ipbuf, '/');
        if (!sl) LFAIL("ip=«%s» — нужен адрес IPv4 с длиной префикса, например 10.77.0.2/24", v_ip);
        *sl = '\0';
        char *pe2 = NULL;
        long plen = strtol(sl + 1, &pe2, 10);
        struct in_addr a;
        if (!pe2 || *pe2 || plen < 0 || plen > 32 || ipv4_lit(ipbuf, &a) != 0)
            LFAIL("ip=«%s» — нужен адрес IPv4 с длиной префикса, например 10.77.0.2/24", v_ip);
        uint32_t host = ntohl(a.s_addr);
        uint32_t mask = plen == 0 ? 0 : 0xFFFFFFFFu << (32 - plen);
        uint32_t net = host & mask;
        snprintf(v_allowed, sizeof(v_allowed), "%u.%u.%u.%u/%ld",
                 (net >> 24) & 255, (net >> 16) & 255, (net >> 8) & 255, net & 255, plen);
    }

    /* ---- ссылка становится ФАЙЛОМ и проходит общий разбор ----
     *
     * Именно так, а не своей копией правил: иначе однажды появилось бы расхождение «ссылка
     * приняла то, что файл отвергает», и разница между двумя записями одного понятия стала бы
     * разницей в смысле. */
    char text[XS_CONF_MAX];
    char privb[XS_KEY_B64 + 1], pubb[XS_KEY_B64 + 1];
    xs_key_encode(priv, privb);
    xs_key_encode(pub, pubb);
    int o = snprintf(text, sizeof(text),
                     "[Interface]\nPrivateKey = %s\nAddress = %s\n", privb, v_ip);
    if (o < 0 || (size_t)o >= sizeof(text)) LFAIL("ссылка слишком длинная");
    if (*v_sni) o += snprintf(text + o, sizeof(text) - (size_t)o, "SNI = %s\n", v_sni);
    if (*v_mtu) o += snprintf(text + o, sizeof(text) - (size_t)o, "MTU = %s\n", v_mtu);
    if (*v_dns) o += snprintf(text + o, sizeof(text) - (size_t)o, "DNS = %s\n", v_dns);
    if (o < 0 || (size_t)o >= sizeof(text)) LFAIL("ссылка слишком длинная");
    o += snprintf(text + o, sizeof(text) - (size_t)o,
                  "\n[Peer]\nPublicKey = %s\nAllowedIPs = %s\nEndpoint = %s:%ld\n",
                  pubb, v_allowed, hostport, port);
    if (o < 0 || (size_t)o >= sizeof(text)) LFAIL("ссылка слишком длинная");
    if (*v_ka)
        o += snprintf(text + o, sizeof(text) - (size_t)o, "PersistentKeepalive = %s\n", v_ka);
    if (o < 0 || (size_t)o >= sizeof(text)) LFAIL("ссылка слишком длинная");

    char perr[320];
    if (xs_conf_parse(text, (size_t)o, role, c, sec, perr, sizeof(perr)) != 0) {
        /* Приватный ключ ушёл в текст — затираем его до возврата, каким бы ни был исход. */
        memset(text, 0, sizeof(text));
        memset(priv, 0, sizeof(priv));
        LFAIL("ссылка разобрана, но конфигурация из неё не проходит проверку: %s", perr);
    }
    memset(text, 0, sizeof(text));
    memset(priv, 0, sizeof(priv));
    return 0;
}

int xs_is_link(const char *s) {
    return s && strlen(s) > 5 && strncasecmp(s, "xs://", 5) == 0;
}

int xs_conf_load_any(const char *what, enum xs_role role, struct xs_conf *c,
                     struct xs_secrets *sec, char *name, size_t namen, int *was_link,
                     char *err, size_t errn) {
    if (name && namen) name[0] = '\0';
    if (was_link) *was_link = 0;
    if (!what) LFAIL("нужен путь к файлу, ссылка xs:// или «-»");
    if (!strcmp(what, "-")) {
        /* Читаем НА ОДИН БАЙТ БОЛЬШЕ предела: иначе «ровно предел» и «больше предела»
         * неразличимы, и вход длиннее допустимого молча обрезался бы до годного. */
        char buf[XS_URI_MAX + 1];
        size_t n = 0;
        while (n < sizeof(buf)) {
            size_t got = fread(buf + n, 1, sizeof(buf) - n, stdin);
            if (got == 0) break;
            n += got;
        }
        if (n >= sizeof(buf)) LFAIL("со стандартного ввода пришло больше %d КиБ", XS_URI_MAX / 1024);
        buf[n] = '\0';
        char *b = buf;
        while (*b == ' ' || *b == '\t' || *b == '\r' || *b == '\n') b++;
        if (xs_is_link(b)) {
            if (was_link) *was_link = 1;
            int rc = xs_link_parse(b, role, c, sec, name, namen, err, errn);
            memset(buf, 0, sizeof(buf));
            return rc;
        }
        int rc = xs_conf_parse(buf, strlen(buf), role, c, sec, err, errn);
        memset(buf, 0, sizeof(buf));
        return rc;
    }
    if (xs_is_link(what)) {
        if (was_link) *was_link = 1;
        return xs_link_parse(what, role, c, sec, name, namen, err, errn);
    }
    return xs_conf_load(what, role, c, sec, err, errn);
}

/* ---- печать ----------------------------------------------------------------- */

static int render_common(const struct xs_conf *c, const struct xs_secrets *sec,
                         char *err, size_t errn) {
    if (!c || !sec || !sec->has_priv) LFAIL("для ссылки нужен приватный ключ пира");
    if (c->listen_port)
        LFAIL("это конфигурация хаба (есть ListenPort) — ссылка описывает доступ одного пира");
    if (c->peer_n != 1)
        LFAIL("в ссылку укладывается ровно один пир — хаб, а секций [Peer] %zu", c->peer_n);
    if (!c->peer[0].endpoint_port)
        LFAIL("у хаба нет Endpoint — по такой ссылке подключаться некуда");
    return 0;
}

/* Префикс строкой. Хостовый порядок — как он и лежит в struct xs_allowed. */
static int pfx_str(uint32_t net, int plen, char *out, size_t outn) {
    return snprintf(out, outn, "%u.%u.%u.%u/%d",
                    (net >> 24) & 255, (net >> 16) & 255, (net >> 8) & 255, net & 255, plen);
}

int xs_link_render(const struct xs_conf *c, const struct xs_secrets *sec, const char *name,
                   char *out, size_t outn, char *err, size_t errn) {
    if (render_common(c, sec, err, errn) != 0) return -1;
    const struct xs_peer *pe = &c->peer[0];
    char privu[XS_KEY_B64], pubu[XS_KEY_B64];
    key_encode_url(sec->priv, privu);
    key_encode_url(pe->pub, pubu);

    char al[XS_ALLOWED_MAX * 20];
    size_t ao = 0;
    al[0] = '\0';
    for (size_t i = 0; i < pe->allowed_n; i++) {
        if (i) ao += (size_t)snprintf(al + ao, sizeof(al) - ao, ",");
        ao += (size_t)pfx_str(pe->allowed[i].net, pe->allowed[i].plen, al + ao, sizeof(al) - ao);
        if (ao >= sizeof(al)) LFAIL("префиксов в allowed больше, чем влезает в ссылку");
    }
    char ip[32];
    pfx_str(c->addr, c->addr_plen, ip, sizeof(ip));

    /* Порядок параметров СМЫСЛОВОЙ, а не алфавитный: главное — ключ хаба — идёт первым. Ссылку
     * читают глазами, и «pk» в середине означает, что её прочтут хуже. */
    int o = snprintf(out, outn, "xs://%s@%s:%d?pk=%s&ip=%s",
                     privu, pe->endpoint, pe->endpoint_port, pubu, ip);
    if (o < 0 || (size_t)o >= outn) LFAIL("ссылка не влезает в буфер");
    /* allowed печатается ВСЕГДА, даже когда совпадает с умолчанием: ссылка обязана значить одно
     * и то же независимо от того, каким умолчанием её прочтут. */
    char esc[XS_ALLOWED_MAX * 20 * 3];
    if (q_esc(al, esc, sizeof(esc)) != 0) LFAIL("allowed не влезает в ссылку");
    o += snprintf(out + o, outn - (size_t)o, "&allowed=%s", esc);
    if (o < 0 || (size_t)o >= outn) LFAIL("ссылка не влезает в буфер");
    if (c->sni[0]) {
        if (q_esc(c->sni, esc, sizeof(esc)) != 0) LFAIL("SNI не влезает в ссылку");
        o += snprintf(out + o, outn - (size_t)o, "&sni=%s", esc);
    }
    if (c->mtu) o += snprintf(out + o, outn - (size_t)o, "&mtu=%d", c->mtu);
    if (pe->keepalive_set || pe->keepalive) o += snprintf(out + o, outn - (size_t)o, "&ka=%d",
                                                         pe->keepalive);
    if (o < 0 || (size_t)o >= outn) LFAIL("ссылка не влезает в буфер");
    /* DNS печатается, хотя на роутере не применяется: ссылку переписывают дальше, и потерять в
     * ней то, что настроил оператор хаба, значило бы, что смысл ссылки зависит от того, через
     * сколько рук она прошла. Ровно ради этого значения и хранятся в struct xs_conf. */
    if (c->dns_n > 0) {
        char dl[XS_DNS_MAX * 17];
        size_t do_ = 0;
        dl[0] = '\0';
        for (int i = 0; i < c->dns_n; i++)
            do_ += (size_t)snprintf(dl + do_, sizeof(dl) - do_, "%s%s", i ? "," : "", c->dns[i]);
        if (q_esc(dl, esc, sizeof(esc)) != 0) LFAIL("DNS не влезает в ссылку");
        o += snprintf(out + o, outn - (size_t)o, "&dns=%s", esc);
        if (o < 0 || (size_t)o >= outn) LFAIL("ссылка не влезает в буфер");
    }
    if (name && *name) {
        if (frag_esc(name, esc, sizeof(esc)) != 0) LFAIL("имя не влезает в ссылку");
        o += snprintf(out + o, outn - (size_t)o, "#%s", esc);
        if (o < 0 || (size_t)o >= outn) LFAIL("ссылка не влезает в буфер");
    }
    return 0;
}

int xs_conf_render(const struct xs_conf *c, const struct xs_secrets *sec,
                   char *out, size_t outn, char *err, size_t errn) {
    if (render_common(c, sec, err, errn) != 0) return -1;
    const struct xs_peer *pe = &c->peer[0];
    char privb[XS_KEY_B64 + 1], pubb[XS_KEY_B64 + 1], ip[32];
    xs_key_encode(sec->priv, privb);
    xs_key_encode(pe->pub, pubb);
    pfx_str(c->addr, c->addr_plen, ip, sizeof(ip));
    int o = snprintf(out, outn, "[Interface]\nPrivateKey = %s\nAddress = %s\n", privb, ip);
    if (o < 0 || (size_t)o >= outn) LFAIL("конфигурация не влезает в буфер");
    if (c->sni[0]) o += snprintf(out + o, outn - (size_t)o, "SNI = %s\n", c->sni);
    if (c->mtu)    o += snprintf(out + o, outn - (size_t)o, "MTU = %d\n", c->mtu);
    for (int i = 0; i < c->dns_n; i++)
        o += snprintf(out + o, outn - (size_t)o, "%s%s%s", i ? ", " : "DNS = ", c->dns[i],
                      i + 1 == c->dns_n ? "\n" : "");
    if (o < 0 || (size_t)o >= outn) LFAIL("конфигурация не влезает в буфер");
    o += snprintf(out + o, outn - (size_t)o, "\n[Peer]\nPublicKey = %s\nAllowedIPs = ", pubb);
    if (o < 0 || (size_t)o >= outn) LFAIL("конфигурация не влезает в буфер");
    for (size_t i = 0; i < pe->allowed_n; i++) {
        if (i) o += snprintf(out + o, outn - (size_t)o, ", ");
        o += pfx_str(pe->allowed[i].net, pe->allowed[i].plen, out + o, outn - (size_t)o);
        if (o < 0 || (size_t)o >= outn) LFAIL("конфигурация не влезает в буфер");
    }
    o += snprintf(out + o, outn - (size_t)o, "\nEndpoint = %s:%d\n",
                  pe->endpoint, pe->endpoint_port);
    if (o < 0 || (size_t)o >= outn) LFAIL("конфигурация не влезает в буфер");
    if (pe->keepalive_set)
        o += snprintf(out + o, outn - (size_t)o, "PersistentKeepalive = %d\n", pe->keepalive);
    if (o < 0 || (size_t)o >= outn) LFAIL("конфигурация не влезает в буфер");
    return 0;
}
