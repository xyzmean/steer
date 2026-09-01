/* Разбор подписки: vless:// ссылки в список узлов.
 *
 * Подписка — это base64 от списка ссылок, по одной на строку. Ничего сложнее здесь нет,
 * и именно поэтому разбор живёт в steer, а не в клиенте: он не требует ни криптографии,
 * ни сети, проверяется текстом, и его результат нужен и интерфейсу (показать узлы), и
 * сторожу (выбрать живой).
 *
 * Чужие протоколы (hy2, ss, trojan) пропускаются молча, но считаются: подписка обычно
 * общая, и «в ней 26 узлов, а steer видит 17» должно объясняться цифрой, а не догадкой.
 */
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "vless.h"
/* Ради vless_uuid_form: пригодность идентификатора — такая же часть пригодности узла, как
 * транспорт и security, а правило, по которому он превращается в 16 байт, живёт в одном
 * месте — в vless_proto.c. Библиотек это не тянет. */
#include "vless_proto.h"

/* base64: только декодирование и только то, что встречается в подписках — с переводами
 * строк внутри и, возможно, без выравнивающих '='. URL-safe алфавит тоже принимается:
 * часть панелей отдаёт именно его. */
static int b64val(unsigned char c) {
    if (c >= 'A' && c <= 'Z') return c - 'A';
    if (c >= 'a' && c <= 'z') return c - 'a' + 26;
    if (c >= '0' && c <= '9') return c - '0' + 52;
    if (c == '+' || c == '-') return 62;
    if (c == '/' || c == '_') return 63;
    return -1;
}

size_t b64_decode(const char *in, size_t n, char *out, size_t out_n) {
    size_t o = 0;
    /* Накопитель БЕЗ знака и с маской: читаются из него только младшие bits+8 разрядов
     * (bits после уменьшения не больше 7), а старшие копились без нужды — на длинной
     * подписке int переполнялся, то есть разбор недоверенного текста упирался в
     * неопределённое поведение. UBSan на стенде подписки это и показывал:
     * «left shift of 496703836 by 6 places cannot be represented in type int». */
    unsigned acc = 0;
    int bits = 0;
    for (size_t i = 0; i < n; i++) {
        int v = b64val((unsigned char)in[i]);
        if (v < 0) continue;                  /* переводы строк, '=', мусор */
        acc = ((acc << 6) | (unsigned)v) & 0x3FFFu;   /* хватает 14 разрядов: 7 + 6 + 1 */
        bits += 6;
        if (bits >= 8) {
            bits -= 8;
            if (o + 1 < out_n) out[o++] = (char)((acc >> bits) & 0xFF);
        }
    }
    if (o < out_n) out[o] = '\0';
    return o;
}

/* Процентное декодирование на месте: имена узлов приходят как %F0%9F%8C%8D... и без
 * этого в интерфейсе выглядят мусором. */
/* Адрес, по которому собеседника не бывает в принципе.
 *
 * Только такие: не указан (0.0.0.0, ::), петля (127.0.0.0/8, ::1) и широковещательный.
 * Частные сети сюда НЕ входят — узел в 10.0.0.0/8 это законная настройка внутри своей сети
 * или поверх второго туннеля, и отбрасывать его значило бы решить за человека.
 *
 * Имя не разрешается: подписка приходит из интернета, и разрешение имён на этапе разбора
 * означало бы поход в сеть внутри парсера чужого текста. Строка сравнивается как строка —
 * заглушки панелей пишут адрес цифрами, а не именем.
 */
static int host_leads_nowhere(const char *h) {
    if (!h || !h[0]) return 1;
    if (!strcmp(h, "0.0.0.0") || !strcmp(h, "::") || !strcmp(h, "[::]")) return 1;
    if (!strcmp(h, "::1") || !strcmp(h, "[::1]")) return 1;
    if (!strcmp(h, "255.255.255.255")) return 1;
    /* 127.0.0.0/8 целиком: заглушки встречаются и как 127.0.0.1, и как 127.0.0.53. */
    if (!strncmp(h, "127.", 4)) {
        const char *p = h + 4;
        while (*p) { if ((*p < '0' || *p > '9') && *p != '.') return 0; p++; }
        return 1;
    }
    return 0;
}

static void pct_decode(char *s) {
    char *w = s;
    for (char *r = s; *r; r++) {
        if (*r == '%' && r[1] && r[2]) {
            int hi = r[1], lo = r[2];
            hi = hi <= '9' ? hi - '0' : (hi | 32) - 'a' + 10;
            lo = lo <= '9' ? lo - '0' : (lo | 32) - 'a' + 10;
            if (hi >= 0 && hi < 16 && lo >= 0 && lo < 16) {
                *w++ = (char)((hi << 4) | lo);
                r += 2;
                continue;
            }
        }
        *w++ = *r;
    }
    *w = '\0';
}

static void set_field(char *dst, size_t n, const char *src, size_t len) {
    if (len >= n) len = n - 1;
    memcpy(dst, src, len);
    dst[len] = '\0';
}

/* Снять с конца строки неполную последовательность UTF-8. Нужно там, где строку обрезал
 * буфер: обрезка идёт по байту, а буква вне ASCII занимает от двух байт, и граница
 * приходится на её середину. Одинокий ведущий байт — не «испорченная буква», а байт,
 * который ни один потребитель истолковать не может: JSON статуса печатает его как есть,
 * и разбирать этот JSON приходится уже интерфейсу. Терять последнюю букву честнее. */
static void utf8_trim_tail(char *s) {
    size_t n = strlen(s);
    if (!n) return;
    unsigned char last = (unsigned char)s[n - 1];
    if (last < 0x80) return;                       /* ASCII — рвать нечего */
    if ((last & 0xC0) != 0x80) { s[n - 1] = '\0'; return; }  /* ведущий байт без продолжения */

    /* Байт продолжения последним: отступить к ведущему и сверить длину. */
    size_t at = n - 1, cont = 1;
    while (at && ((unsigned char)s[at - 1] & 0xC0) == 0x80) { at--; cont++; }
    if (!at) { s[0] = '\0'; return; }              /* одни продолжения — мусор целиком */
    unsigned char lead = (unsigned char)s[at - 1];
    size_t need = (lead & 0xE0) == 0xC0 ? 1 :
                  (lead & 0xF0) == 0xE0 ? 2 :
                  (lead & 0xF8) == 0xF0 ? 3 : 0;
    if (need && cont == need) return;              /* последовательность целая */
    s[at - 1] = '\0';
}

/* Имя узла: единственное поле, куда подписка кладёт что угодно, включая UTF-8, и потому
 * единственное, где обрезка по байту буфера видна снаружи. Порядок важен: сначала снять
 * оборванную процентную форму (её оставила та же обрезка, декодировать её нечем), потом
 * раскодировать, потом снять оборванную последовательность UTF-8 — она могла появиться и
 * из процентной формы, и из сырых байт во фрагменте ссылки. */
static void set_name(char *dst, size_t n, const char *src) {
    size_t len = strlen(src);
    int cut = len >= n;
    set_field(dst, n, src, len);
    if (cut) {
        size_t l = strlen(dst);
        if (l >= 1 && dst[l - 1] == '%') dst[l - 1] = '\0';
        else if (l >= 2 && dst[l - 2] == '%') dst[l - 2] = '\0';
    }
    pct_decode(dst);
    utf8_trim_tail(dst);
}

/* Пригодность разобранного узла — общее правило для обоих путей разбора; тело ниже. */
static int node_usable(struct vless_node *n);

/* vless://UUID@host:port?params#name
 *
 * Возвращает 0, если ссылка разобрана и узел ПРИГОДЕН. Непригодный узел — это не ошибка
 * подписки: сервер может предлагать транспорт, которого клиент не умеет, и правильное
 * поведение — пропустить его, а не отказаться от всей подписки. */
int vless_parse_url(const char *url, struct vless_node *n) {
    memset(n, 0, sizeof(*n));
    if (strncmp(url, "vless://", 8) != 0) return -1;
    const char *p = url + 8;

    const char *at = strchr(p, '@');
    if (!at) return -1;
    set_field(n->uuid, sizeof(n->uuid), p, (size_t)(at - p));

    p = at + 1;
    const char *colon = strchr(p, ':');
    const char *qmark = strchr(p, '?');
    const char *hash = strchr(p, '#');
    if (!colon) return -1;
    set_field(n->host, sizeof(n->host), p, (size_t)(colon - p));
    n->port = (uint16_t)atoi(colon + 1);
    if (!n->port) return -1;

    /* Имя узла: за '#', и оно единственное, что может содержать что угодно. */
    if (hash) {
        set_name(n->name, sizeof(n->name), hash + 1);
    }

    /* Параметры. Значения по умолчанию — те, что подразумевает VLESS, когда поле
     * опущено: type=tcp и security=none встречаются именно так. */
    snprintf(n->type, sizeof(n->type), "tcp");
    if (qmark) {
        const char *end = hash && hash > qmark ? hash : qmark + strlen(qmark);
        const char *k = qmark + 1;
        while (k < end) {
            const char *amp = memchr(k, '&', (size_t)(end - k));
            const char *stop = amp ? amp : end;
            const char *eq = memchr(k, '=', (size_t)(stop - k));
            if (eq) {
                size_t klen = (size_t)(eq - k), vlen = (size_t)(stop - eq - 1);
                const char *v = eq + 1;
                if (!strncmp(k, "type", klen) && klen == 4) set_field(n->type, sizeof(n->type), v, vlen);
                else if (klen == 8 && !strncmp(k, "security", 8)) set_field(n->security, sizeof(n->security), v, vlen);
                else if (klen == 3 && !strncmp(k, "sni", 3)) set_field(n->sni, sizeof(n->sni), v, vlen);
                else if (klen == 2 && !strncmp(k, "fp", 2)) set_field(n->fp, sizeof(n->fp), v, vlen);
                else if (klen == 3 && !strncmp(k, "pbk", 3)) set_field(n->pbk, sizeof(n->pbk), v, vlen);
                else if (klen == 3 && !strncmp(k, "sid", 3)) set_field(n->sid, sizeof(n->sid), v, vlen);
                else if (klen == 4 && !strncmp(k, "flow", 4)) set_field(n->flow, sizeof(n->flow), v, vlen);
                else if (klen == 4 && !strncmp(k, "path", 4)) { set_field(n->path, sizeof(n->path), v, vlen); pct_decode(n->path); }
                else if (klen == 11 && !strncmp(k, "serviceName", 11)) { set_field(n->service, sizeof(n->service), v, vlen); pct_decode(n->service); }
                else if (klen == 4 && !strncmp(k, "mode", 4)) set_field(n->mode, sizeof(n->mode), v, vlen);
            }
            if (!amp) break;
            k = amp + 1;
        }
    }

    /* Пригодность. Проверяется здесь, а не при подключении, чтобы непригодный узел не
     * попал в список кандидатов и сторож не тратил на него попытки.
     *
     * security=none — это VLESS БЕЗ TLS, голый протокол по TCP. Он поддержан: шифровать
     * там нечего, а сам VLESS реализован целиком. Такой узел осмыслен внутри доверенной
     * сети или за уже защищённым каналом, и отбрасывать его вместе с неподдержанными
     * транспортами было бы ошибкой — причины у них разные. Пустое поле security означает
     * то же самое: в ссылке его просто опускают. */
    return node_usable(n);
}

/* Пригоден ли РАЗОБРАННЫЙ узел. 0 — да, 1 — нет, причина в n->skip_reason.
 *
 * Отдельной функцией, потому что путей разбора теперь два: ссылка vless:// и конфиг Xray в
 * подписке (см. parse_xray ниже). Правило пригодности у них обязано быть одно — иначе узел,
 * непригодный в одном виде, окажется пригодным в другом, и человек получит «узлов два,
 * туннель не работает, сказать нечего» ровно там, где мы этого и добивались избежать.
 *
 * Поля, которых во ссылке не было, к этому моменту уже заполнены умолчаниями: делает это
 * первая же строка. */
static int node_usable(struct vless_node *n) {
    if (!n->security[0]) snprintf(n->security, sizeof(n->security), "none");

    /* Идентификатор пользователя. Проверяется ЗДЕСЬ по той же причине, что и всё
     * остальное в этом блоке: непригодный узел не должен попасть в кандидаты.
     *
     * Пригодность здесь — это правило Xray (см. vless_uuid_form): либо шестнадцатеричный
     * UUID в 32-36 знаков, либо короткая строка до 30 знаков, из которой UUID выводится
     * хэшем. Панели выдают и то, и другое, и «TMG_74317ba5f91» — законный узел, а не
     * ошибка. Непригодны ровно три случая, и стать 16 байтами они не могут никак:
     * пустая строка, ровно 31 знак (для вывода длинно, для UUID коротко) и длиннее
     * UUID; отдельно — строка нужной длины с посторонним знаком внутри.
     *
     * До этой проверки такой узел считался пригодным, доходил до подключения и молчал:
     * проба отвечала «UUID неразборчив», а туннель ронял соединение без причины. */
    switch (vless_uuid_form(n->uuid)) {
    case VLESS_UUID_EMPTY:
        snprintf(n->skip_reason, sizeof(n->skip_reason), "идентификатор пуст");
        return 1;
    case VLESS_UUID_GAP:
        snprintf(n->skip_reason, sizeof(n->skip_reason),
                 "идентификатор: 31 знак, нужен UUID");
        return 1;
    case VLESS_UUID_TOOLONG:
        snprintf(n->skip_reason, sizeof(n->skip_reason), "идентификатор длиннее UUID");
        return 1;
    case VLESS_UUID_NOTHEX:
        snprintf(n->skip_reason, sizeof(n->skip_reason), "UUID с недопустимым знаком");
        return 1;
    default:
        break;
    }

    if (strcmp(n->security, "reality") != 0 && strcmp(n->security, "none") != 0) {
        /* tls и xtls остаются непригодными по-настоящему: для них нужна проверка
         * настоящей цепочки сертификатов, то есть корневое хранилище на роутере —
         * а это отдельная работа и отдельный вес. */
        snprintf(n->skip_reason, sizeof(n->skip_reason), "security=%s не поддержан",
                 n->security);
        return 1;
    }
    if (!strcmp(n->security, "reality") && (!n->pbk[0] || !n->sni[0])) {
        snprintf(n->skip_reason, sizeof(n->skip_reason), "reality без pbk или sni");
        return 1;
    }
    if (strcmp(n->type, "tcp") != 0 && strcmp(n->type, "grpc") != 0 &&
        strcmp(n->type, "xhttp") != 0) {
        snprintf(n->skip_reason, sizeof(n->skip_reason), "транспорт %s не поддержан", n->type);
        return 1;
    }

    /* Узел, который никуда не ведёт. Отдельная причина, а не «не подключился»: панели,
     * привязывающие подписку к устройствам, отвечают клиенту без идентификатора не отказом,
     * а ЗАГЛУШКОЙ — законными ссылками vless:// на `0.0.0.0:1`, где сообщение человеку
     * спрятано в ИМЯ узла («📱 Неправильный клиент», «🔌 Лимит устройств достигнут»).
     *
     * Разбор такую ссылку принимает целиком, и правильно: по форме она безупречна. Но
     * пригодной она быть не может — по этому адресу не существует собеседника, и connect
     * либо уйдёт в свой же роутер (0.0.0.0 ядро трактует как локальный), либо в чужую сеть.
     * Раньше такой узел попадал в кандидаты, тратил попытки сторожа и давал ровно тот вид
     * отказа, которого в этом коде нет больше нигде: «узлов два, туннель не работает,
     * сказать нечего».
     *
     * Названная причина при этом ДОНОСИТ сообщение панели: skip_reason уезжает в интерфейс
     * вместе с примером, а примером служит имя узла — то есть человек читает «узел ведёт в
     * 0.0.0.0 — например „Неправильный клиент“» и понимает, что дело в панели, а не в
     * роутере.
     *
     * Проверяются только адреса, у которых собеседника не бывает В ПРИНЦИПЕ: не указан
     * (0.0.0.0, ::), локальная петля (127.0.0.0/8, ::1) и широковещательный. Частные сети
     * НЕ проверяются: узел в 10.0.0.0/8 — законная и рабочая настройка внутри своей сети или
     * поверх второго туннеля. */
    if (host_leads_nowhere(n->host)) {
        /* Длина держится в пределах skip_reason (64 байта, а буква кириллицы это два):
         * обрезка причины по границе буфера разрубила бы букву посередине, и в JSON уехала
         * бы недобитая последовательность — ровно то, чем ломался вывод стенда в I-029. */
        snprintf(n->skip_reason, sizeof(n->skip_reason), "%.20s: отвечать некому", n->host);
        return 1;
    }

    /* Режим xhttp, которого мы не умеем, называется ЗДЕСЬ, а не выясняется при
     * подключении: непригодный узел не должен попадать в кандидаты и тратить попытки.
     *
     * Поддержан stream-one: один запрос POST, тело запроса — поток наверх, тело ответа —
     * вниз. Его же выбирает и сам Xray при reality с mode=auto, поэтому «auto» пригоден.
     * packet-up и stream-up требуют второго запроса и нумерации кусков — заметно больше
     * кода ради того же результата с худшей задержкой. */
    if (!strcmp(n->type, "xhttp") && n->mode[0] &&
        strcmp(n->mode, "auto") != 0 && strcmp(n->mode, "stream-one") != 0) {
        snprintf(n->skip_reason, sizeof(n->skip_reason),
                 "xhttp mode=%s: нужен auto или stream-one", n->mode);
        return 1;
    }
    return 0;
    return 0;
}

/* Отнести непригодный узел к его причине. Единственное место, где растёт skipped:
 * счётчик и объяснение обязаны сходиться, а два независимых инкремента — это ровно тот
 * случай, когда «пропущено 26» и «причин на 24 узла» уезжают друг от друга молча. */
static void skip_note(struct vless_sub_stats *st, const struct vless_node *n,
                      const char *reason) {
    if (!st) return;
    st->skipped++;
    for (size_t i = 0; i < st->reasons_n; i++) {
        if (!strcmp(st->reasons[i].reason, reason)) { st->reasons[i].count++; return; }
    }
    if (st->reasons_n >= VLESS_SKIP_REASONS) { st->reasons_dropped++; return; }
    struct vless_skip *s = &st->reasons[st->reasons_n++];
    snprintf(s->reason, sizeof(s->reason), "%s", reason);
    /* Пример — чтобы причину можно было привязать к узлу в подписке. Имя есть не
     * всегда: во ссылке без '#' его нет вовсе, а у неразобранной ссылки может не быть
     * и host — тогда пример остаётся пустым, и это честнее выдуманного «узел 3». */
    if (n && n->name[0]) snprintf(s->example, sizeof(s->example), "%s", n->name);
    else if (n && n->host[0]) snprintf(s->example, sizeof(s->example), "%s:%u",
                                      n->host, n->port);
    s->count = 1;
}

/* ---- подписка в виде конфига Xray -------------------------------------------
 *
 * ЗАЧЕМ ЭТО ВООБЩЕ ЕСТЬ. Панели с привязкой к устройствам выбирают формат ответа по
 * User-Agent, и списка ссылок vless:// среди вариантов может не быть НИ ОДНОГО. Замерено на
 * живой подписке: незнакомому клиенту (steer, curl, sing-box, Nekoray) отдаётся заглушка из
 * ссылок ss:// на localhost:1234 с именами «Неправильный клиент» и «Подключись через Happ»;
 * Happ, v2rayNG и Streisand получают конфиг Xray в JSON; Clash — свой YAML; SFI — конфиг
 * sing-box. То есть подписка, у которой узлы совершенно исправны (проверено пробой: восемь
 * из девяти отвечают), для движка выглядела как «ни одного пригодного узла».
 *
 * Притворяться чужим клиентом — не выход, и не из принципа: JSON приезжает и Happ-у, значит
 * читать его пришлось бы всё равно. Поэтому читаем.
 *
 * ЧТО ИМЕННО ЧИТАЕТСЯ. Массив конфигов `[{...},{...}]` или один конфиг `{...}`; в каждом
 * берутся `outbounds`, а из них — те, у которых `protocol` равен `vless`. Всё остальное
 * (dns, routing, inbounds, freedom, blackhole) пропускается: это настройки клиента, к
 * которому подписка обращается, а не описание узла.
 *
 * Разборщик свой и намеренно маленький — как и в spec.c, он не общий парсер JSON, а обход
 * ровно той формы, которую ждём. Переиспользовать тот из spec.c нельзя: он статический, а
 * стенд подписки (tests/submatch.c) компилируется в одиночку, без spec.c и без mbedtls, и
 * это его главное свойство — чужой текст из интернета проверяется без сети и без docker.
 */
struct sj { const char *p; };

static void sj_ws(struct sj *j) {
    while (*j->p == ' ' || *j->p == '\t' || *j->p == '\n' || *j->p == '\r') j->p++;
}

/* Строка в buf. Экранирование понимается ровно настолько, чтобы \" не оборвала строку: имена
 * узлов приходят из панели и содержат что угодно, а \uXXXX в них не встречается — панели
 * пишут UTF-8 как есть. Непонятая последовательность попадает в buf буквально, и это лучше,
 * чем отказ: имя — единственное поле, которому позволено быть любым. */
static int sj_str(struct sj *j, char *buf, size_t n) {
    sj_ws(j);
    if (*j->p != '"') return -1;
    j->p++;
    size_t i = 0;
    while (*j->p && *j->p != '"') {
        if (*j->p == '\\' && j->p[1]) j->p++;
        if (i + 1 < n) buf[i++] = *j->p;
        j->p++;
    }
    if (*j->p != '"') return -1;
    j->p++;
    if (n) buf[i] = '\0';
    return 0;
}

/* Пропустить одно значение любого типа. Нужен там же, где в spec.c: чтобы незнакомый ключ
 * не толковался молча, а именно пропускался. */
static void sj_skip(struct sj *j) {
    sj_ws(j);
    if (*j->p == '"') { char t[8]; sj_str(j, t, sizeof(t)); return; }
    if (*j->p == '{' || *j->p == '[') {
        char open = *j->p, close = open == '{' ? '}' : ']';
        int depth = 0;
        do {
            if (*j->p == '"') { char t[8]; sj_str(j, t, sizeof(t)); continue; }
            if (*j->p == open) depth++;
            else if (*j->p == close) depth--;
            j->p++;
        } while (*j->p && depth > 0);
        return;
    }
    while (*j->p && *j->p != ',' && *j->p != '}' && *j->p != ']') j->p++;
}

/* Войти в объект и отдавать его ключи по одному. 0 — ключ в key, 1 — объект кончился,
 * -1 — это не объект. Значение читает вызывающий; не прочитал — обязан позвать sj_skip. */
static int sj_obj_key(struct sj *j, int *first, char *key, size_t key_n) {
    sj_ws(j);
    if (*first) {
        if (*j->p != '{') return -1;
        j->p++;
        *first = 0;
    } else {
        sj_ws(j);
        if (*j->p == ',') j->p++;
    }
    sj_ws(j);
    if (*j->p == '}') { j->p++; return 1; }
    if (sj_str(j, key, key_n) != 0) return -1;
    sj_ws(j);
    if (*j->p != ':') return -1;
    j->p++;
    return 0;
}

/* Тот же приём для массива: 0 — элемент начинается здесь, 1 — массив кончился. */
static int sj_arr_next(struct sj *j, int *first) {
    sj_ws(j);
    if (*first) {
        if (*j->p != '[') return -1;
        j->p++;
        *first = 0;
    } else {
        sj_ws(j);
        if (*j->p == ',') j->p++;
    }
    sj_ws(j);
    if (*j->p == ']') { j->p++; return 1; }
    return 0;
}

/* streamSettings: транспорт, security и всё, что зависит от них. */
static void xray_stream(struct sj *j, struct vless_node *n) {
    int first = 1;
    char k[64];
    while (sj_obj_key(j, &first, k, sizeof(k)) == 0) {
        if (!strcmp(k, "network")) sj_str(j, n->type, sizeof(n->type));
        else if (!strcmp(k, "security")) sj_str(j, n->security, sizeof(n->security));
        else if (!strcmp(k, "realitySettings") || !strcmp(k, "tlsSettings")) {
            /* Оба объекта несут serverName и fingerprint; publicKey и shortId бывают только
             * у reality. Разбирать их одним куском можно потому, что имена полей не спорят:
             * узел объявляет ровно один из двух. */
            int f2 = 1;
            char k2[64];
            while (sj_obj_key(j, &f2, k2, sizeof(k2)) == 0) {
                if (!strcmp(k2, "serverName")) sj_str(j, n->sni, sizeof(n->sni));
                else if (!strcmp(k2, "fingerprint")) sj_str(j, n->fp, sizeof(n->fp));
                else if (!strcmp(k2, "publicKey")) sj_str(j, n->pbk, sizeof(n->pbk));
                else if (!strcmp(k2, "shortId")) sj_str(j, n->sid, sizeof(n->sid));
                else sj_skip(j);
            }
        } else if (!strcmp(k, "grpcSettings")) {
            int f2 = 1;
            char k2[64];
            while (sj_obj_key(j, &f2, k2, sizeof(k2)) == 0) {
                if (!strcmp(k2, "serviceName")) sj_str(j, n->service, sizeof(n->service));
                else sj_skip(j);
            }
        } else if (!strcmp(k, "xhttpSettings") || !strcmp(k, "splithttpSettings")) {
            /* splithttpSettings — прежнее имя того же транспорта; панели с ним ещё живут. */
            int f2 = 1;
            char k2[64];
            while (sj_obj_key(j, &f2, k2, sizeof(k2)) == 0) {
                if (!strcmp(k2, "path")) sj_str(j, n->path, sizeof(n->path));
                else if (!strcmp(k2, "mode")) sj_str(j, n->mode, sizeof(n->mode));
                else sj_skip(j);
            }
        } else sj_skip(j);
    }
}

/* settings исходящего vless: vnext[0] — адрес, порт и первый пользователь.
 *
 * Именно первый и только он: подписка описывает узел для ОДНОГО человека, и второго
 * пользователя в ней не бывает. Появится — возьмём первого и не станем притворяться, что
 * умеем больше. */
static void xray_settings(struct sj *j, struct vless_node *n) {
    int first = 1;
    char k[64];
    while (sj_obj_key(j, &first, k, sizeof(k)) == 0) {
        if (strcmp(k, "vnext") != 0) { sj_skip(j); continue; }
        int fa = 1, taken = 0;
        while (sj_arr_next(j, &fa) == 0) {
            if (taken) { sj_skip(j); continue; }
            taken = 1;
            int fo = 1;
            char k2[64];
            while (sj_obj_key(j, &fo, k2, sizeof(k2)) == 0) {
                if (!strcmp(k2, "address")) sj_str(j, n->host, sizeof(n->host));
                else if (!strcmp(k2, "port")) {
                    sj_ws(j);
                    char num[16];
                    size_t i = 0;
                    while (*j->p >= '0' && *j->p <= '9' && i + 1 < sizeof(num))
                        num[i++] = *j->p++;
                    num[i] = '\0';
                    n->port = (uint16_t)atoi(num);
                } else if (!strcmp(k2, "users")) {
                    int fu = 1, u_taken = 0;
                    while (sj_arr_next(j, &fu) == 0) {
                        if (u_taken) { sj_skip(j); continue; }
                        u_taken = 1;
                        int fu2 = 1;
                        char k3[64];
                        while (sj_obj_key(j, &fu2, k3, sizeof(k3)) == 0) {
                            if (!strcmp(k3, "id")) sj_str(j, n->uuid, sizeof(n->uuid));
                            else if (!strcmp(k3, "flow")) sj_str(j, n->flow, sizeof(n->flow));
                            else sj_skip(j);
                        }
                    }
                } else sj_skip(j);
            }
        }
    }
}

/* Один outbound. 1 — это узел vless и он записан в n, 0 — не наш. */
static int xray_outbound(struct sj *j, struct vless_node *n) {
    memset(n, 0, sizeof(*n));
    int first = 1, is_vless = 0;
    char k[64], proto[32] = "";
    /* Порядок ключей в JSON не задан, поэтому protocol может оказаться ПОСЛЕ settings.
     * Значит читаем всё, а решаем в конце: разбор чужого исходящего в свободные поля никому
     * не вредит, потому что узел всё равно не будет взят. */
    while (sj_obj_key(j, &first, k, sizeof(k)) == 0) {
        if (!strcmp(k, "protocol")) sj_str(j, proto, sizeof(proto));
        /* tag из конфигурации Xray обрезается тем же байтовым пределом, что и имя из
         * фрагмента ссылки, — и рвётся так же. */
        else if (!strcmp(k, "tag")) { sj_str(j, n->name, sizeof(n->name)); utf8_trim_tail(n->name); }
        else if (!strcmp(k, "settings")) xray_settings(j, n);
        else if (!strcmp(k, "streamSettings")) xray_stream(j, n);
        else sj_skip(j);
    }
    is_vless = !strcmp(proto, "vless");
    return is_vless;
}

/* Конфиг целиком: массив конфигов или один. Возвращает число ПРИГОДНЫХ узлов. */
static size_t parse_xray(const char *text, struct vless_node *out, size_t max,
                         struct vless_sub_stats *st) {
    struct sj j = { text };
    size_t n = 0;
    sj_ws(&j);
    /* Один конфиг заворачивается в массив из одного: дальше путь общий. */
    int wrapped = (*j.p == '{');
    int fa = 1;
    if (wrapped) fa = 0;                    /* массива нет — сразу разбираем объект */
    for (;;) {
        if (!wrapped) {
            int r = sj_arr_next(&j, &fa);
            if (r != 0) break;
        }
        /* Тело одного конфига: нужен только outbounds. */
        int fc = 1;
        char k[64];
        int seen_ob = 0;
        while (sj_obj_key(&j, &fc, k, sizeof(k)) == 0) {
            if (strcmp(k, "outbounds") != 0) { sj_skip(&j); continue; }
            seen_ob = 1;
            int fo = 1;
            while (sj_arr_next(&j, &fo) == 0) {
                struct vless_node node;
                const char *before = j.p;
                if (!xray_outbound(&j, &node)) continue;
                if (j.p == before) break;               /* разбор не двинулся — уходим */
                if (n >= max) {
                    /* Мест больше нет. Считаем как пропущенный, а не теряем молча: то же
                     * обещание, что у списка ссылок — арифметика обязана сходиться. */
                    skip_note(st, &node, "узлов больше, чем помещается");
                    continue;
                }
                if (node_usable(&node) == 0) out[n++] = node;
                else skip_note(st, &node, node.skip_reason);
            }
        }
        (void)seen_ob;
        if (wrapped) break;
    }
    return n;
}

/* Разобрать текст подписки (уже декодированный из base64) в массив узлов.
 * Возвращает число ПРИГОДНЫХ; остальное — в st (может быть NULL). */
size_t vless_parse_sub(const char *text, struct vless_node *out, size_t max,
                       struct vless_sub_stats *st) {
    size_t n = 0;
    if (st) memset(st, 0, sizeof(*st));
    const char *p = text;
    /* Форма определяется ПЕРВЫМ непробельным знаком, а не поиском подстроки: '[' или '{'
     * бывает только у JSON, а список ссылок с них не начинается никогда. Прежнее правило в
     * tunnel.c искало «://» и на конфиге Xray срабатывало случайно — там «https://» лежит
     * внутри настроек DNS. Случайность в распознавании чужого формата — это отказ, который
     * появится ровно тогда, когда панель уберёт одну строчку из своего конфига. */
    while (*p == ' ' || *p == '\t' || *p == '\n' || *p == '\r') p++;
    if (*p == '[' || *p == '{') return parse_xray(p, out, max, st);
    while (*p && n < max) {
        while (*p == '\n' || *p == '\r' || *p == ' ' || *p == '\t') p++;
        if (!*p) break;
        /* Конец ссылки — перевод строки ИЛИ начало следующей схемы. Подписки часто
         * приходят без завершающего перевода, а некоторые панели склеивают ссылки без
         * разделителя вовсе; при разборе только по переводу последняя ссылка тогда
         * склеивалась со следующей и терялась молча. */
        const char *e = p;
        while (*e && *e != '\n' && *e != '\r') {
            if (e > p && !strncmp(e, "://", 3)) {
                /* Отступаем к началу схемы — по ИМЕНИ СХЕМЫ, а не по алфавиту.
                 *
                 * Отступ по алфавиту («пока слева буквы и цифры») съедал хвост имени
                 * узла: в «...#onevless://b@...» он уходил до самого '#', граница
                 * ставилась перед «onevless», и вторая ссылка начиналась со лишних
                 * букв — то есть переставала быть vless-ссылкой и уходила в чужие
                 * протоколы. На склеенной подписке так терялся КАЖДЫЙ второй узел,
                 * а первому обнулялось имя. Условие срабатывало почти всегда: имена
                 * узлов кончаются буквой или цифрой чаще, чем нет.
                 *
                 * Список отсортирован по УБЫВАНИЮ длины, и берётся первое совпадение —
                 * то есть самое длинное. Короткое имя схемы обязано проигрывать
                 * длинному, иначе граница встаёт внутри чужого слова: «ss» совпадает
                 * с хвостом самого «vless», и разбор рубил бы каждую ссылку по её же
                 * собственной схеме. По той же причине после самого длинного совпадения
                 * к более коротким не переходим: если оно указывает на начало ЭТОЙ
                 * ссылки, делить нечего.
                 *
                 * Имя узла, оканчивающееся именем схемы («...#Express» перед «ss://»),
                 * разделится верно: сравниваются ровно байты перед «://». */
                static const char *const schemes[] = {
                    "hysteria2", "wireguard", "hysteria", "trojan", "vmess",
                    "vless", "tuic", "hy2", "ssr", "ss"
                };
                const char *s2 = NULL;
                for (size_t si = 0; si < sizeof(schemes) / sizeof(*schemes); si++) {
                    size_t sl = strlen(schemes[si]);
                    if ((size_t)(e - p) < sl) continue;
                    if (strncmp(e - sl, schemes[si], sl) != 0) continue;
                    /* Строго больше: равенство означает схему САМОЙ этой ссылки. */
                    if ((size_t)(e - p) > sl) s2 = e - sl;
                    break;
                }
                if (s2) { e = s2; break; }
            }
            e++;
        }

        char line[2048];
        size_t len = (size_t)(e - p);
        if (len >= sizeof(line)) {
            /* Ссылка длиннее буфера. Считается непригодной, а не пропадает: см. ниже —
             * счётчики обязаны сходиться с числом ссылок в тексте. */
            if (!strncmp(p, "vless://", 8))
                skip_note(st, NULL, "ссылка длиннее 2048 байт");
        } else {
            memcpy(line, p, len);
            line[len] = '\0';
            if (!strncmp(line, "vless://", 8)) {
                struct vless_node node;
                int rc = vless_parse_url(line, &node);
                /* rc == 0 — узел взят; иначе НЕ ВЗЯТ, и для счётчика это одно и то
                 * же — узел, которого человек в списке не увидит, — а для объяснения
                 * разное: у «транспорт не поддержан» (1) причина уже названа разбором,
                 * у «ссылку не разобрали» (-1) её приходится называть здесь, потому
                 * что разбор бросил ссылку раньше, чем добрался до пригодности.
                 * Раньше -1 не считался нигде, и ссылка исчезала бесследно —
                 * так пропадал, например, узел с IPv6-литералом в host: первое
                 * двоеточие оказывается внутри скобок, порт читается как 0, разбор
                 * возвращает -1. Заголовок этого файла обещает обратное: «в ней 26
                 * узлов, а steer видит 17» должно объясняться цифрой. */
                if (rc == 0) out[n++] = node;
                else skip_note(st, &node, rc > 0 ? node.skip_reason
                                                 : "ссылка не разобрана");
            } else if (strstr(line, "://") && st) {
                /* hy2, ss, trojan и прочее. Считаем, но не трогаем: подписка общая, а
                 * «26 узлов в подписке, 17 у steer» должно объясняться числом. */
                st->foreign++;
            }
        }
        p = e;
    }
    return n;
}

/* Привести прочитанный файл подписки к тексту, который понимает vless_parse_sub.
 *
 * Три вида, и различаются они первым непробельным знаком, а не догадкой:
 *   '[' или '{'  — конфиг Xray в JSON, отдаётся как есть;
 *   есть «://»   — список ссылок, отдаётся как есть;
 *   иначе        — base64, раскодируется в dec.
 *
 * Раньше это решение жило в tunnel.c одной строкой `if (!strstr(raw, "://"))`, и на конфиге
 * Xray оно срабатывало ПО СЛУЧАЙНОСТИ: «://» там есть внутри настроек DNS. Здесь оно потому,
 * что здесь его можно проверить стендом — tunnel.c требует и сети, и TUN, и mbedtls.
 *
 * Возвращает raw или dec; ни то, ни другое не освобождается — буферы вызывающего. */
const char *vless_sub_text(const char *raw, size_t raw_n, char *dec, size_t dec_n) {
    const char *p = raw;
    while (*p == ' ' || *p == '\t' || *p == '\n' || *p == '\r') p++;
    if (*p == '[' || *p == '{') return raw;
    if (strstr(raw, "://")) return raw;
    b64_decode(raw, raw_n, dec, dec_n);
    return dec;
}
