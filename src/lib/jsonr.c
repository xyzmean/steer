#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "jsonr.h"

/* ---- a JSON reader small enough to audit ---------------------------------- */
/* Deliberately not a general parser: it walks the document the shape of the spec
 * demands and refuses anything else. A router config that compiles into firewall
 * rules should fail loudly on an unexpected shape rather than guess — which is the
 * same reason the spec is JSON and not YAML. */

void js_ws(struct js *j) {
    while (*j->p == ' ' || *j->p == '\t' || *j->p == '\n' || *j->p == '\r') j->p++;
}
int js_lit(struct js *j, char c) {
    js_ws(j);
    if (*j->p != c) return -1;
    j->p++;
    return 0;
}
/* Четыре шестнадцатеричные цифры после \u. -1 — если их нет. */
long js_hex4(const char *p) {
    long v = 0;
    for (int k = 0; k < 4; k++) {
        char c = p[k];
        int d = c >= '0' && c <= '9' ? c - '0' :
                c >= 'a' && c <= 'f' ? c - 'a' + 10 :
                c >= 'A' && c <= 'F' ? c - 'A' + 10 : -1;
        if (d < 0) return -1;
        v = v * 16 + d;
    }
    return v;
}

/* \uXXXX в UTF-8 (I-315). Раньше экранирование читалось как «следующий знак как есть», и
 * «a"b» становилось «au0022b»: JSON вправе так записать любой знак, а сериализатор,
 * экранирующий не-ASCII, так пишет любую кириллицу. Возвращает число записанных байт и
 * сдвигает *pp за разобранное; 0 — не раскодировано, и тогда строка читается как прежде
 * (буква «u» и дальше как есть), с предупреждением. Не раскодируются управляющие знаки —
 * в имени, пути или адресе им смысла нет, а грузилась такая спека и до правки, — одинокие
 * суррогаты и недописанное \u. */
size_t js_uesc(const char **pp, char out[4]) {
    const char *p = *pp;                              /* указывает на 'u' */
    long cp = js_hex4(p + 1);
    size_t used = 5;
    if (cp >= 0xD800 && cp <= 0xDBFF && p[5] == '\\' && p[6] == 'u') {
        long lo = js_hex4(p + 7);
        if (lo >= 0xDC00 && lo <= 0xDFFF) { cp = 0x10000 + ((cp - 0xD800) << 10) + (lo - 0xDC00); used = 11; }
    }
    if (cp < 0x20 || (cp >= 0xD800 && cp <= 0xDFFF)) {
        fprintf(stderr, "steer[warn] spec: \\%.5s в строке не раскодирован и прочитан как есть — "
                "запишите вместо него сам знак\n", p);
        return 0;
    }
    size_t k;
    if (cp < 0x80) { out[0] = (char)cp; k = 1; }
    else if (cp < 0x800) { out[0] = (char)(0xC0 | (cp >> 6)); out[1] = (char)(0x80 | (cp & 0x3F)); k = 2; }
    else if (cp < 0x10000) {
        out[0] = (char)(0xE0 | (cp >> 12)); out[1] = (char)(0x80 | ((cp >> 6) & 0x3F));
        out[2] = (char)(0x80 | (cp & 0x3F)); k = 3;
    } else {
        out[0] = (char)(0xF0 | (cp >> 18)); out[1] = (char)(0x80 | ((cp >> 12) & 0x3F));
        out[2] = (char)(0x80 | ((cp >> 6) & 0x3F)); out[3] = (char)(0x80 | (cp & 0x3F)); k = 4;
    }
    *pp = p + used;
    return k;
}

/* Возврат: 0 — разобрано. -1 с пустым e->msg — это не строка (не начинается с кавычки, или
 * файл оборван внутри строки): такую же -1 функция возвращала и раньше, и вызывающий решает
 * сам, отказ это или мягкая остановка (см. str_list). -1 с непустым e->msg — строка длиннее
 * допустимого: раньше на этом сразу звал die(), теперь сообщение готово и вызывающий обязан
 * его пробросить, а не придумывать своё (см. err_prop). */
int js_str(struct js *j, char *buf, size_t n, struct err *e) {
    js_ws(j);
    if (*j->p != '"') return -1;
    j->p++;
    size_t i = 0;
    while (*j->p && *j->p != '"') {
        if (*j->p == '\\' && j->p[1] == 'u') {
            char u[4];
            const char *q = j->p + 1;
            size_t k = js_uesc(&q, u);
            if (k) {
                /* Длиннее буфера — отказ, а не молчаливая обрезка: имя выхода из 36 знаков
                 * принималось как 31-значное, а имя устройства длиннее IFNAMSIZ ядро всё
                 * равно не возьмёт — и узнать об этом было нечем. */
                if (i + k >= n)
                    return err_set(e, "spec: строка длиннее допустимого (имя, путь или ключ)", NULL);
                memcpy(buf + i, u, k);
                i += k;
                j->p = q;
                continue;
            }
        }
        if (*j->p == '\\' && j->p[1]) j->p++;
        if (i + 1 >= n)
            return err_set(e, "spec: строка длиннее допустимого (имя, путь или ключ)", NULL);
        buf[i++] = *j->p;
        j->p++;
    }
    if (*j->p != '"') return -1;
    j->p++;
    buf[i] = '\0';
    return 0;
}

/* Единственный вид отказа — «не число» (не продвинулся ни на байт), и раньше он всегда звал
 * die() с этим же текстом, независимо от места вызова. Сообщение поэтому ставится здесь же —
 * вызывающему нечего добавить, только пробросить -1. */
int js_num(struct js *j, long *out, struct err *e) {
    js_ws(j);
    char *end = NULL;
    long v = strtol(j->p, &end, 10);
    /* Не число (например, число в кавычках) — отказ. strtol молча давал 0 и не двигал
     * указатель: `"node":"3"` выбирал узел 0 вместо третьего, `"stream_port":"443"` — порт 0,
     * а строка «3» затем читалась как следующий ключ. */
    if (end == j->p) return err_set(e, "spec: здесь ожидалось число без кавычек", NULL);
    j->p = end;
    *out = v;
    return 0;
}
/* Skips one value of any type, so unknown keys are tolerated (forward compat
 * within a schema major) without being silently interpreted.
 *
 * 0 — пропущено (в том числе когда строка внутри значения не раскодировалась синтаксически —
 * то же мягкое поведение, что было раньше, никто эту причину не проверял). -1 с сообщением в
 * e->msg — строка внутри значения длиннее допустимого; раньше это был die() прямо отсюда. */
int js_skip(struct js *j, struct err *e) {
    js_ws(j);
    if (*j->p == '"') {
        char t[512];
        if (js_str(j, t, sizeof(t), e) != 0 && e->msg[0]) return -1;
        return 0;
    }
    if (*j->p == '{' || *j->p == '[') {
        char open = *j->p, close = open == '{' ? '}' : ']';
        int depth = 0;
        do {
            if (*j->p == '"') {
                char t[512];
                if (js_str(j, t, sizeof(t), e) != 0 && e->msg[0]) return -1;
                continue;
            }
            if (*j->p == open) depth++;
            else if (*j->p == close) depth--;
            j->p++;
        } while (*j->p && depth > 0);
        return 0;
    }
    while (*j->p && *j->p != ',' && *j->p != '}' && *j->p != ']') j->p++;
    return 0;
}

/* Копия строки на всю жизнь процесса. Спека разбирается один раз, а живёт разобранной до
 * конца работы — освобождать эти строки некому и незачем; отказ malloc здесь равносилен
 * «спеку не прочитать», поэтому громкий (в струкруте, а не в stderr — см. правило 5). NULL —
 * отказ, e->msg уже заполнен. */
const char *keep(const char *s, struct err *e) {
    size_t n = strlen(s) + 1;
    char *p = malloc(n);
    if (!p) { err_set(e, "out of memory reading the spec", NULL); return NULL; }
    memcpy(p, s, n);
    return p;
}

/* Списки путей. От str_array отличается тем, что хранит УКАЗАТЕЛИ, а не буферы: путей в
 * правиле теперь до шестидесяти четырёх, и массив фиксированных буферов по 256 байт стоил бы
 * 32 КБ на правило.
 *
 * (size_t)-1 — отказ, текст в e->msg: переполнение элемента (js_str), предел списка или
 * висящая запятая. Иначе — количество прочитанных строк, и здесь есть МЯГКАЯ остановка: первый
 * нестроковый элемент не отказ, а конец списка (см. комментарий у вызова в parse_outputs про
 * devices) — так было и раньше, js_str там просто возвращал -1 без die. */
size_t str_list(struct js *j, const char **dst, size_t max, struct err *e) {
    if (js_lit(j, '[') != 0) return 0;
    size_t n = 0;
    js_ws(j);
    if (*j->p == ']') { j->p++; return 0; }
    for (;;) {
        char t[256];
        if (js_str(j, t, sizeof(t), e) != 0) return e->msg[0] ? (size_t)-1 : n;
        if (n >= max) {
            err_set(e, "too many entries in list", NULL);
            return (size_t)-1;
        }
        const char *kept = keep(t, e);
        if (!kept) return (size_t)-1;
        dst[n++] = kept;
        js_ws(j);
        if (*j->p == ',') {
            /* Висящая запятая (`[...,]`) — громкий отказ, а не продвижение к ']' и риск
             * зависания вызывающего цикла на несъеденной скобке. */
            j->p++;
            js_ws(j);
            if (*j->p == ']') {
                err_set(e, "list: trailing comma (expected a string)", NULL);
                return (size_t)-1;
            }
            continue;
        }
        break;
    }
    js_lit(j, ']');
    return n;
}

int str_array(struct js *j, char dst[][64], size_t max, size_t *n, struct err *e) {
    if (js_lit(j, '[') != 0) return -1;
    *n = 0;
    js_ws(j);
    if (*j->p == ']') { j->p++; return 0; }
    for (;;) {
        char t[64];
        /* -1 без сообщения здесь возможен (не строка) — тот же случай, что у str_list, и
         * решает вызывающий: у lan_devices это отказ своим текстом (err_prop), у from_default
         * — мягкое «не разобрал, оставляю как есть», как было и раньше. */
        if (js_str(j, t, sizeof(t), e) != 0) return -1;
        if (*n >= max) return err_set(e, "too many entries in array", NULL);
        snprintf(dst[(*n)++], 64, "%s", t);
        js_ws(j);
        if (*j->p == ',') {
            /* См. str_list: висящая запятая → громкий отказ, а не продвижение к ']' и риск
             * зависания вызывающего цикла на несъеденной скобке. */
            j->p++;
            js_ws(j);
            if (*j->p == ']') return err_set(e, "array: trailing comma (expected a string)", NULL);
            continue;
        }
        break;
    }
    return js_lit(j, ']');
}

/* Массив целых. Отдельно от str_array, потому что js_num на не-числе НЕ ПРОДВИГАЕТ указатель,
 * а теперь ещё и всегда возвращает готовое сообщение — тут добавить вызывающему нечего.
 * Проверка сделана здесь, у единственного места, где числа читаются массивом. */
int num_array(struct js *j, int *dst, size_t max, size_t *n, struct err *e) {
    if (js_lit(j, '[') != 0) return -1;
    *n = 0;
    js_ws(j);
    if (*j->p == ']') { j->p++; return 0; }
    for (;;) {
        long v = 0;
        if (js_num(j, &v, e) != 0) return -1;    /* не число: строка, объект, мусор — e->msg уже готов */
        if (*n >= max) return err_set(e, "too many entries in array", NULL);
        if (v < 0 || v > 100000) return -1;      /* вне диапазона — мягкий отказ, решает вызывающий */
        dst[(*n)++] = (int)v;
        js_ws(j);
        if (*j->p == ',') {
            /* См. str_list: висящая запятая → громкий отказ. */
            j->p++;
            js_ws(j);
            if (*j->p == ']') return err_set(e, "array: trailing comma (expected a number)", NULL);
            continue;
        }
        break;
    }
    return js_lit(j, ']');
}
