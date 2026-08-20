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
    int acc = 0, bits = 0;
    for (size_t i = 0; i < n; i++) {
        int v = b64val((unsigned char)in[i]);
        if (v < 0) continue;                  /* переводы строк, '=', мусор */
        acc = (acc << 6) | v;
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
        set_field(n->name, sizeof(n->name), hash + 1, strlen(hash + 1));
        pct_decode(n->name);
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
    if (!n->security[0]) snprintf(n->security, sizeof(n->security), "none");

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

/* Разобрать текст подписки (уже декодированный из base64) в массив узлов.
 * Возвращает число ПРИГОДНЫХ; остальное — в st (может быть NULL). */
size_t vless_parse_sub(const char *text, struct vless_node *out, size_t max,
                       struct vless_sub_stats *st) {
    size_t n = 0;
    if (st) memset(st, 0, sizeof(*st));
    const char *p = text;
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
