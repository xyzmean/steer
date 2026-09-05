/* Скачивание подписки и обработка того, что ответила панель.
 *
 * ЗАЧЕМ ЭТО В ДВИЖКЕ, А НЕ В ИНТЕРФЕЙСЕ.
 *
 * Раньше всё это жило в объекте ubus splify2 на shell: заголовки запроса с идентификатором
 * устройства, разбор ответных заголовков, base64 названия подписки, арифметика остатка
 * трафика, повтор за другим форматом. И каждый шаг там упирался в то, чего у оболочки нет.
 *
 * Считать идентификатор устройства приходилось внешними `sha256sum`/`md5sum` — на роутере
 * из отчётов теста нет ни `base64`, ни `openssl`, а busybox собран без них, поэтому
 * название подписки декодировалось СВОЕЙ реализацией base64 на awk. Движок при этом
 * разбирает base64 в C уже давно (sub.c) и SHA-256 у него в руках (mbedtls) — то есть
 * оболочка держала вторые реализации того, что рядом было готово, и держала их там, где
 * проверить их нечем.
 *
 * Сколько в подписке ПРИГОДНЫХ узлов оболочка тоже не могла узнать сама: она спрашивала
 * движок отдельным запуском (`steer vless-nodes`) и вытаскивала число регулярным
 * выражением из его JSON. А это число нужно ровно затем, чтобы решить, не отдала ли панель
 * заглушку и не попросить ли у неё другой формат, — то есть решение принималось по
 * пересказу ответа, полученного из третьего процесса.
 *
 * Здесь всё это в одном месте и на своём уровне: подписка скачивается, её заголовки
 * разбираются, узлы считаются той же функцией, которой их читает подъём туннеля
 * (vless_parse_sub), и повтор за другим форматом решается по настоящему числу.
 *
 * ЧТО ОСТАЛОСЬ ИНТЕРФЕЙСУ и осталось нарочно: какая подписка сейчас выбрана, где лежат её
 * файлы, что записано в uci (ссылка, вид источника, название), сколько выходов на неё
 * ссылается. Это учёт настройки управляющего слоя, а не работа с подпиской: движку про uci
 * знать нечего, и он про него ничего и не знает.
 *
 * ПОЧЕМУ БАЙТЫ ВСЁ ЕЩЁ ТАСКАЕТ СИСТЕМНЫЙ КАЧАЛЬЩИК (curl или uclient-fetch), а не движок
 * сам. Подписка живёт на https, а у нас нет клиента https общего назначения: свой стек TLS
 * 1.3 (tls13.c) написан под Reality и проверяет сервер общим секретом X25519, а не цепочкой
 * сертификатов; mbedtls собирается урезанной конфигурацией, где X.509 и модуль SSL
 * выключены совсем. Включить их — это плюс сотни килобайт в прошивку и хранилище корневых
 * сертификатов на роутере, где overlay 6,9 МБ, ради работы, которую системный качальщик
 * уже делает и уже делал в оболочке. Поэтому байты по-прежнему таскает он, но ЗАПУСКАЕТ его
 * движок, без оболочки и без подстановки строк: аргументы уезжают массивом в execvp.
 */
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <limits.h>
#include <time.h>
#include <unistd.h>
#include <dirent.h>
#include <sys/stat.h>

#include "vless.h"
#include "subfetch.h"
#include "../hwid.h"

/* Уровень в журнале — как в остальных файлах движка. Метка подсистемы «sub»: всё здесь
 * пишется при работе с подпиской. */
#define LOG_W "steer[warn] sub: "

/* Запуск внешней команды с заглушенным выводом — тот же, которым движок зовёт nft и ip.
 * Второй такой же помощник означал бы два места, где решается, куда девать вывод. */
int run_quiet(const char *const argv[]);   /* из steer.c */

/* Швы для стенда. На роутере ветка `:-` не выбирается никогда: движок запускают из procd и
 * из объекта rpcd, а те дают чистое окружение. Тот же приём, что у STEER_TUN_STATS и
 * STEER_EXPLAIN_TRACE. */
/* env_or переехал в src/hwid.c вместе с идентификатором: там три шва стенда, здесь два, и
 * две копии одной трёхстрочной функции — это два места, где решается, что считать пустым
 * значением переменной окружения. Имя `env_or` оставлено локальным псевдонимом, чтобы не
 * переписывать вызовы, которых к нему больше, чем строк в нём самом. */
#define env_or steer_env_or

/* ---- идентификатор устройства и описание системы ------------------------------------
 *
 * ПЕРЕЕХАЛИ В src/hwid.c. Здесь они завелись потому, что читатель был один — заголовок
 * `x-hwid` для панели подписки, а панель бывает только в расширенной сборке. Читателей
 * стало двое, и второй (телеметрия) обязан работать на роутере, где расширенной сборки нет.
 * Значение при переезде не изменилось ни на шаг — иначе каждый заведённый в панели роутер
 * стал бы новым устройством; это сторожит стенд hwidmatch, сверяя результат с `sha256sum`.
 *
 * Здесь остались только читатели: hwid() для заголовка и dev_os()/dev_model() для тех
 * заголовков, которыми панель описывает устройство человеку. */

/* ---- разбор ответных заголовков ---------------------------------------------------- */

/* Последнее значение заголовка с этим именем; регистр имени не важен.
 *
 * ПОСЛЕДНЕЕ, а не первое: за перенаправлением приезжает второй блок заголовков, и заголовки
 * подписки лежат именно в нём — в первом стоит только 30x и Location. Прежний код в
 * оболочке брал `tail -1` по той же причине.
 *
 * 0 — заголовка не было; `out` тогда не тронут. */
static int hdr_get(const char *hdrs, const char *name, char *out, size_t n) {
    if (!hdrs) return 0;
    size_t nl = strlen(name);
    int found = 0;
    for (const char *p = hdrs; *p; ) {
        const char *eol = strchr(p, '\n');
        size_t len = eol ? (size_t)(eol - p) : strlen(p);
        if (len > nl && p[nl] == ':' && !strncasecmp(p, name, nl)) {
            const char *v = p + nl + 1;
            size_t vl = len - nl - 1;
            while (vl && (*v == ' ' || *v == '\t')) { v++; vl--; }
            while (vl && (v[vl - 1] == ' ' || v[vl - 1] == '\t' || v[vl - 1] == '\r')) vl--;
            if (vl >= n) vl = n - 1;
            memcpy(out, v, vl);
            out[vl] = 0;
            found = 1;
        }
        if (!eol) break;
        p = eol + 1;
    }
    return found;
}

/* Одно поле заголовка `subscription-userinfo`. Только цифры: панель отдаёт байты и
 * unix-время, и всё остальное здесь — либо мусор, либо чужое соглашение, которое мы не
 * читаем. 0 — поля нет или в нём не число. */
static int ui_field(const char *val, const char *field, unsigned long long *out) {
    size_t fl = strlen(field);
    for (const char *p = val; *p; ) {
        while (*p == ' ' || *p == '\t' || *p == ';' || *p == ',') p++;
        if (!*p) break;
        const char *s = p;
        while (*p && *p != ';' && *p != ',') p++;
        const char *eq = memchr(s, '=', (size_t)(p - s));
        if (!eq || (size_t)(eq - s) != fl || strncasecmp(s, field, fl)) continue;
        const char *d = eq + 1;
        while (d < p && (*d == ' ' || *d == '\t')) d++;
        if (d >= p || *d < '0' || *d > '9') return 0;
        unsigned long long acc = 0;
        while (d < p && *d >= '0' && *d <= '9') {
            unsigned digit = (unsigned)(*d++ - '0');
            /* Переполнение — это «числу верить нельзя», а не «число большое»: панель с
             * битым заголовком иначе показала бы человеку остаток, которого нет. */
            if (acc > (ULLONG_MAX - digit) / 10) return 0;
            acc = acc * 10 + digit;
        }
        *out = acc;
        return 1;
    }
    return 0;
}

/* Название подписки, как его назвала САМА панель.
 *
 * Панели отдают его заголовком `profile-title` — обычно в base64 с приставкой `base64:`
 * (так делают Marzban, Remnawave, 3x-ui), реже открытым текстом. Есть и запасной путь:
 * `content-disposition: attachment; filename="Riot VPN"`. Это то же имя, что человек видит
 * в своём клиенте, и брать его оттуда честнее, чем просить придумать своё: две подписки от
 * одного продавца иначе называются «sub2» и «sub3».
 *
 * base64 раскодируется ТОЙ ЖЕ функцией, которой движок читает саму подписку (sub.c): в
 * оболочке ради этой одной строки жила своя реализация base64 на awk — на роутере нет ни
 * `base64`, ни `openssl`. */
static void sub_title(const char *hdrs, char *out, size_t n) {
    out[0] = 0;
    char raw[512] = "";
    if (!hdr_get(hdrs, "profile-title", raw, sizeof raw) || !raw[0]) {
        char cd[512] = "";
        raw[0] = 0;
        if (hdr_get(hdrs, "content-disposition", cd, sizeof cd)) {
            const char *f = strcasestr(cd, "filename=");
            if (f) {
                f += 9;
                if (*f == '"') f++;
                size_t i = 0;
                while (f[i] && f[i] != '"' && f[i] != ';' && i + 1 < sizeof raw) i++;
                memcpy(raw, f, i);
                raw[i] = 0;
            }
        }
    }
    if (!raw[0]) return;
    if (!strncasecmp(raw, "base64:", 7)) {
        char dec[512];
        size_t got = b64_decode(raw + 7, strlen(raw + 7), dec, sizeof dec - 1);
        if (got) { dec[got] = 0; snprintf(raw, sizeof raw, "%s", dec); }
    }
    /* Управляющие символы и кавычки вон: строка уедет в uci и в JSON. Кириллицу здесь, в
     * отличие от заголовков ЗАПРОСА, оставляем — это название для человека, и панели зовут
     * подписки по-русски сплошь. */
    size_t o = 0;
    for (const unsigned char *p = (const unsigned char *)raw; *p; p++) {
        if (*p < ' ' || *p == '"' || *p == '\\') continue;
        if (o + 1 >= n || o >= 48) break;
        out[o++] = (char)*p;
    }
    /* Обрезка по границе кодовой точки: половина буквы в названии выглядит как поломка
     * панели, а не как длинное имя.
     *
     * Убирается только НЕПОЛНАЯ последовательность, а не всякая последняя: панели зовут
     * подписки по-русски сплошь, и «Россия», обрезанная до «Росси» на ровном месте, была бы
     * той же поломкой, от которой это и защищает. Поэтому сначала находим начало последней
     * последовательности, потом смотрим по ведущему байту, сколько ей нужно байт, и убираем
     * её целиком только если нужного числа не набралось. */
    size_t k = o;
    while (k && ((unsigned char)out[k - 1] & 0xC0) == 0x80) k--;
    if (k) {
        unsigned char lead = (unsigned char)out[k - 1];
        size_t need = 1;
        if ((lead & 0xE0) == 0xC0) need = 2;
        else if ((lead & 0xF0) == 0xE0) need = 3;
        else if ((lead & 0xF8) == 0xF0) need = 4;
        if (k - 1 + need > o) o = k - 1;
    }
    out[o] = 0;
}

/* Что панель сказала про устройство. NULL — сказать нечего. */
static const char *device_warn(const char *hdrs, int hwid_sent) {
    char v[256];
    if (hdr_get(hdrs, "x-hwid-not-supported", v, sizeof v))
        return "панель не увидела идентификатора устройства и отдала заглушку вместо узлов";
    if (hdr_get(hdrs, "x-hwid-limit", v, sizeof v))
        return "панель считает, что устройств уже больше, чем позволено подпиской: "
               "освободите слот у поставщика";
    if (!hwid_sent)
        return "идентификатор устройства не ушёл (нечем послать заголовок): "
               "если панель требует HWID, вместо узлов приедет заглушка";
    return NULL;
}

/* ---- остаток трафика --------------------------------------------------------------
 *
 * `subscription-userinfo: upload=…; download=…; total=…; expire=…` — соглашение панелей
 * (Marzban, 3x-ui, Remnawave и родня), то же, что читают мобильные клиенты. В теле подписки
 * этих чисел нет вовсе, а вставленные руками ссылки vless:// не несут их тем более: узнать
 * остаток можно только в момент запроса, поэтому он и запоминается рядом с подпиской.
 *
 * ФОРМАТ ФАЙЛА НЕ МЕНЯЕТСЯ, и это не мелочь: тот же файл читает splify2, собирая ответ
 * методов sub_info и sub_list, и он же перечислен в keep.d движка — то есть лежит на уже
 * установленных роутерах. Имена ключей здесь — контракт между движком и интерфейсом.
 */
struct ui_nums {
    int has_up, has_down, has_total, has_exp;
    unsigned long long up, down, total, expire;
};

struct quota {
    int have;                    /* файл прочитан и в нём есть числа */
    struct ui_nums n;
    long long at;                /* когда спросили */
    long long at0;               /* первое наблюдение периода */
    int has_at0;
    unsigned long long used0;
};

static int quota_read(const char *path, struct quota *q) {
    memset(q, 0, sizeof *q);
    FILE *f = fopen(path, "r");
    if (!f) return 0;
    char line[128];
    while (fgets(line, sizeof line, f)) {
        char *eq = strchr(line, '=');
        if (!eq) continue;
        *eq = 0;
        char *v = eq + 1;
        size_t l = strlen(v);
        while (l && (v[l - 1] == '\n' || v[l - 1] == '\r')) v[--l] = 0;
        /* Пустое значение — «панель этого не сообщила», и это не то же, что нуль: «осталось
         * 0 из 0» на экране человек читает как исчерпанную подписку. */
        if (!*v) continue;
        if (!strcmp(line, "upload"))        { q->n.has_up = 1;    q->n.up = strtoull(v, NULL, 10); }
        else if (!strcmp(line, "download")) { q->n.has_down = 1;  q->n.down = strtoull(v, NULL, 10); }
        else if (!strcmp(line, "total"))    { q->n.has_total = 1; q->n.total = strtoull(v, NULL, 10); }
        else if (!strcmp(line, "expire"))   { q->n.has_exp = 1;   q->n.expire = strtoull(v, NULL, 10); }
        else if (!strcmp(line, "at"))       { q->at = strtoll(v, NULL, 10); }
        else if (!strcmp(line, "at0"))      { q->has_at0 = 1; q->at0 = strtoll(v, NULL, 10); }
        else if (!strcmp(line, "used0"))    { q->used0 = strtoull(v, NULL, 10); }
    }
    fclose(f);
    q->have = q->n.has_total || q->n.has_exp;
    return q->have;
}

/* Число, которого может не быть: пустая строка вместо нуля — см. quota_read. */
static void put_num(FILE *f, const char *key, int has, unsigned long long v) {
    if (has) fprintf(f, "%s=%llu\n", key, v);
    else fprintf(f, "%s=\n", key);
}

/* Запомнить остаток из ответа панели. Возвращает 1, только если заголовок был И в нём было
 * что читать.
 *
 * Заголовка не было — прежний файл СНИМАЕТСЯ, и это не уборка. Числа от прежней подписки
 * выглядят свежими и ничем не отличимы от правды: «осталось 68 ГБ» на подписке, о которой
 * панель молчит, — худший из трёх исходов, хуже честного «панель не сообщает остаток».
 *
 * `keep` — «спросили не до конца»: так зовёт ПРОБА заголовков (HEAD), после которой при
 * неудаче будет обычная загрузка. Снимать прежние числа она права не имеет, и это не
 * осторожность: вместе с ними снимается точка отсчёта периода, а с ней — измеренный темп
 * расхода, который набирается сутками. Замерено на живом роутере: панель отвечала на HEAD
 * отказом, проба снимала файл, загрузка вслед записывала его заново — и «в среднем в сутки»
 * начинало считаться с нуля при каждом открытии обзора. */
static int quota_save(const char *path, const char *hdrs, int keep, struct quota *out) {
    memset(out, 0, sizeof *out);
    char v[512];
    if (!hdr_get(hdrs, "subscription-userinfo", v, sizeof v)) {
        /* Заголовков не получено ВОВСЕ (uclient-fetch их не отдаёт) — это `keep`: мы не
         * спрашивали, а не получили отказ. Разница между «панель молчит» и «нам нечем
         * спросить» здесь и хранится. */
        if (!keep) unlink(path);
        quota_read(path, out);
        return 0;
    }
    struct ui_nums n;
    memset(&n, 0, sizeof n);
    n.has_up    = ui_field(v, "upload", &n.up);
    n.has_down  = ui_field(v, "download", &n.down);
    n.has_total = ui_field(v, "total", &n.total);
    n.has_exp   = ui_field(v, "expire", &n.expire);
    /* Ни объёма, ни срока — читать нечего: заголовок есть, а смысла в нём нет. Считаем это
     * молчанием панели, иначе обзор нарисовал бы полосу «осталось 0 из 0». */
    if (!n.has_total && !n.has_exp) {
        if (!keep) unlink(path);
        quota_read(path, out);
        return 0;
    }

    /* Начало периода. Панель его НЕ сообщает — она называет только конец («expire») и
     * накопленный расход, — а без начала нельзя посчитать средний расход в сутки: делить
     * накопленное не на что. Гадать длину периода (тридцать дней и подобное) нельзя: на
     * подписке на девяносто дней «в среднем в сутки» вышло бы втрое завышенным, и обзор
     * обещал бы, что трафик кончится, когда он не кончится.
     *
     * Поэтому запоминается ПЕРВОЕ наблюдение периода: время и расход на тот момент. Дальше
     * темп считается по двум наблюдениям — это измерение, а не догадка.
     *
     * Период считается новым, когда сменился срок, или когда расход УМЕНЬШИЛСЯ (панель
     * обнулила счётчик), или когда сменился объём — то есть тариф. */
    long long now = (long long)time(NULL);
    unsigned long long used = n.up + n.down;
    struct quota prev;
    long long at0 = now;
    unsigned long long used0 = used;
    if (quota_read(path, &prev) && prev.has_at0 &&
        prev.n.has_exp == n.has_exp && prev.n.expire == n.expire &&
        prev.n.has_total == n.has_total && prev.n.total == n.total &&
        used >= prev.n.up + prev.n.down) {
        at0 = prev.at0;
        used0 = prev.used0;
    }

    char tmp[512];
    snprintf(tmp, sizeof tmp, "%s.tmp", path);
    FILE *f = fopen(tmp, "w");
    if (!f) {
        fprintf(stderr, LOG_W "остаток трафика не записался: %s\n", tmp);
        return 0;
    }
    put_num(f, "upload", n.has_up, n.up);
    put_num(f, "download", n.has_down, n.down);
    put_num(f, "total", n.has_total, n.total);
    put_num(f, "expire", n.has_exp, n.expire);
    /* Когда спросили. Без этого обзор не может сказать «обновлено 12 минут назад», а mtime
     * файла для этого не годится: файл переписывается и когда числа не изменились. */
    fprintf(f, "at=%lld\n", now);
    fprintf(f, "at0=%lld\n", at0);
    fprintf(f, "used0=%llu\n", used0);
    if (fclose(f) != 0 || rename(tmp, path) != 0) {
        unlink(tmp);
        fprintf(stderr, LOG_W "остаток трафика не записался: %s\n", path);
        return 0;
    }
    out->have = 1;
    out->n = n;
    out->at = now;
    out->at0 = at0;
    out->has_at0 = 1;
    out->used0 = used0;
    return 1;
}

/* ---- печать ответа ---------------------------------------------------------------- */

/* Строка JSON с экранированием. Имена подписок и ссылки приходят снаружи — кавычка в них
 * ломала бы весь ответ, а не только своё поле. */
static void json_str(const char *s) {
    putchar('"');
    for (const unsigned char *p = (const unsigned char *)(s ? s : ""); *p; p++) {
        if (*p == '"' || *p == '\\') { putchar('\\'); putchar(*p); }
        else if (*p < 0x20) printf("\\u%04x", *p);
        else putchar(*p);
    }
    putchar('"');
}

/* Остаток трафика в ответ. Поля — те же, что отдавал splify2 из этого же файла, чтобы
 * интерфейс видел один вид ответа независимо от того, кто его собрал.
 *
 * Байты — СТРОКАМИ. 200 ГБ это 2·10^11, а тот же ответ проходит через jshn в splify2, где
 * целое 32-битное: подписка на 200 ГБ приехала бы обрезанным числом, и обзор показал бы
 * остаток, которого нет.
 *
 * Темп расхода здесь не считается нарочно: делить и предсказывать — работа интерфейса, а
 * второе место, где то же число считается иначе, разойдётся с первым. Отдаётся точка
 * отсчёта, по которой он считается. */
static void quota_json(const struct quota *q) {
    if (!q->have) return;
    printf(",\"quota\":{\"up\":");
    if (q->n.has_up) printf("\"%llu\"", q->n.up); else printf("\"\"");
    printf(",\"down\":");
    if (q->n.has_down) printf("\"%llu\"", q->n.down); else printf("\"\"");
    printf(",\"total\":");
    if (q->n.has_total) printf("\"%llu\"", q->n.total); else printf("\"\"");
    printf(",\"expire\":%llu,\"at\":%lld,\"since\":%lld,\"since_used\":\"%llu\"}",
           q->n.has_exp ? q->n.expire : 0ULL, q->at, q->at0, q->used0);
}

/* ---- скачивание ------------------------------------------------------------------- */

/* Есть ли такая команда. Тем же обходом PATH, что делает `command -v`: различать «качальщика
 * нет» и «качальщик отказал» обязательно — первое означает «нечем послать заголовок», и об
 * этом человеку говорится отдельно. */
static int have(const char *name) {
    const char *path = env_or("PATH", "/usr/sbin:/usr/bin:/sbin:/bin");
    for (const char *p = path; *p; ) {
        const char *e = strchr(p, ':');
        size_t l = e ? (size_t)(e - p) : strlen(p);
        if (l) {
            char full[512];
            snprintf(full, sizeof full, "%.*s/%s", (int)l, p, name);
            if (access(full, X_OK) == 0) return 1;
        }
        if (!e) break;
        p = e + 1;
    }
    return 0;
}

#define FETCH_TIMEOUT "60"
#define HEAD_TIMEOUT  "20"

/* Один заход к панели.
 *
 * body — куда тело (NULL при HEAD); hdr_path — куда заголовки ответа (NULL — они не нужны
 * или качальщик их не умеет). *hwid_sent — ушёл ли идентификатор устройства.
 *
 * Заголовки умеют посылать curl и busybox wget; uclient-fetch, которым `wget` на OpenWrt
 * бывает по факту, не умеет вовсе. Поэтому попытка с заголовками, а при отказе — попытка
 * без них, и об этом ГОВОРИТСЯ: подписка, скачанная без HWID, может оказаться заглушкой.
 *
 * ЗАГОЛОВКИ ОТВЕТА читает только curl (-D): у busybox wget их дампить нечем. Тогда ни
 * названия подписки, ни остатка трафика мы не узнаём — и это честно отличается от «панель
 * промолчала» (см. quota_save и его `keep`). */
static int http_get(const char *url, const char *body, const char *hdr_path,
                    const char *id, int head, int *hwid_sent) {
    char os[80], model[80];
    steer_dev_os(os, sizeof os);
    steer_dev_model(model, sizeof model);
    char h_id[128], h_os[128], h_ver[128], h_model[128];
    snprintf(h_id, sizeof h_id, "x-hwid: %s", id ? id : "");
    snprintf(h_os, sizeof h_os, "x-device-os: %s", os);
    snprintf(h_ver, sizeof h_ver, "x-ver-os: %s", os);
    snprintf(h_model, sizeof h_model, "x-device-model: %s", model);

    *hwid_sent = 0;
    /* Два прохода: первый с заголовками устройства, второй без. При пустом id первый
     * пропускается — посылать «x-hwid: » значило бы назвать себя пустым именем. */
    for (int with_id = (id && *id) ? 1 : 0; ; with_id--) {
        const char *a[32];
        int i = 0;
        if (have("curl")) {
            a[i++] = "curl";
            a[i++] = head ? "-fsSI" : "-fsSL";
            a[i++] = "--max-time"; a[i++] = head ? HEAD_TIMEOUT : FETCH_TIMEOUT;
            if (hdr_path) { a[i++] = "-D"; a[i++] = hdr_path; }
            a[i++] = "-o"; a[i++] = body ? body : "/dev/null";
            if (with_id) {
                a[i++] = "-H"; a[i++] = h_id;
                a[i++] = "-H"; a[i++] = h_os;
                a[i++] = "-H"; a[i++] = h_ver;
                a[i++] = "-H"; a[i++] = h_model;
            }
        } else if (!head && have("wget")) {
            /* busybox wget: заголовки посылать умеет, дампить ответные — нет. HEAD у него
             * тоже нет, поэтому проба заголовков сюда не приходит вовсе. */
            a[i++] = "wget";
            a[i++] = "-q";
            a[i++] = "-O"; a[i++] = body ? body : "/dev/null";
            a[i++] = "--timeout=" FETCH_TIMEOUT;
            if (with_id) {
                a[i++] = "--header"; a[i++] = h_id;
                a[i++] = "--header"; a[i++] = h_os;
                a[i++] = "--header"; a[i++] = h_ver;
                a[i++] = "--header"; a[i++] = h_model;
            }
        } else if (!head && have("uclient-fetch")) {
            if (with_id) continue;   /* заголовков не умеет — сразу второй проход */
            a[i++] = "uclient-fetch";
            a[i++] = "-q";
            a[i++] = "-T"; a[i++] = FETCH_TIMEOUT;
            a[i++] = "-O"; a[i++] = body ? body : "/dev/null";
        } else {
            return 0;   /* качать нечем */
        }
        a[i++] = url;
        a[i] = NULL;
        if (run_quiet(a) == 0) {
            *hwid_sent = with_id;
            return 1;
        }
        if (!with_id) return 0;
    }
}

/* Заголовки ответа в память, без '\r'. Пустая строка, если файла нет: разница между «нет
 * заголовков» и «в заголовках ничего нет» здесь не нужна — оба означают «панель ничего не
 * сказала». */
static void hdrs_load(const char *path, char *out, size_t n) {
    out[0] = 0;
    if (!path) return;
    FILE *f = fopen(path, "r");
    if (!f) return;
    size_t got = fread(out, 1, n - 1, f);
    fclose(f);
    size_t o = 0;
    for (size_t i = 0; i < got; i++) if (out[i] != '\r') out[o++] = out[i];
    out[o] = 0;
}

/* ---- сколько в файле ПРИГОДНЫХ узлов ----------------------------------------------
 *
 * Той же функцией, которой узлы читает подъём туннеля. Это и есть смысл переноса: в
 * оболочке число добывалось запуском `steer vless-nodes` и регулярным выражением по его
 * JSON — то есть решение «не заглушка ли это» принималось по пересказу нашего же ответа,
 * полученного из третьего процесса.
 *
 * Буфера — в куче, а не статикой: команда живёт один вызов, а статика легла бы в BSS того
 * же бинарника, который работает демоном туннеля. Полмегабайта постоянно занятой памяти на
 * коробке с 64 МБ ради разового вызова — плохой обмен. */
#define SUB_BUF 262144
#define SUB_MAX_NODES 128

static size_t usable_nodes(const char *path, struct vless_sub_stats *st) {
    memset(st, 0, sizeof *st);
    FILE *f = fopen(path, "r");
    if (!f) return 0;
    char *raw = malloc(SUB_BUF), *dec = malloc(SUB_BUF);
    struct vless_node *nodes = malloc(sizeof(struct vless_node) * SUB_MAX_NODES);
    size_t cnt = 0;
    if (raw && dec && nodes) {
        size_t n = fread(raw, 1, SUB_BUF - 1, f);
        raw[n] = 0;
        const char *text = vless_sub_text(raw, n, dec, SUB_BUF);
        cnt = vless_parse_sub(text, nodes, SUB_MAX_NODES, st);
    }
    fclose(f);
    free(raw); free(dec); free(nodes);
    return cnt;
}

static long file_bytes(const char *path) {
    struct stat s;
    return stat(path, &s) == 0 ? (long)s.st_size : 0;
}

static int url_ok(const char *url) {
    return url && (!strncmp(url, "http://", 7) || !strncmp(url, "https://", 8));
}

/* Путь остатка трафика по пути подписки. Правило то же, каким его выводит splify2, — и
 * оно ЗДЕСЬ ради того, чтобы вызывающий мог его не повторять; свой путь он всё равно может
 * назвать явно. */
static void info_for(const char *out_path, char *buf, size_t n) {
    size_t l = strlen(out_path);
    if (l > 4 && !strcmp(out_path + l - 4, ".txt"))
        snprintf(buf, n, "%.*s.userinfo", (int)(l - 4), out_path);
    else
        snprintf(buf, n, "%s.userinfo", out_path);
}

/* ---- sub-fetch -------------------------------------------------------------------- */

int cmd_sub_fetch(const char *url, const char *out_path, const char *info_path) {
    if (!url_ok(url)) {
        fprintf(stderr, "steer: нужна ссылка на подписку (http:// или https://)\n");
        return 2;
    }
    if (!out_path || !*out_path) {
        fprintf(stderr, "steer: не сказано, куда положить подписку (--out)\n");
        return 2;
    }
    char info[512];
    if (info_path && *info_path) snprintf(info, sizeof info, "%s", info_path);
    else info_for(out_path, info, sizeof info);

    char id[64] = "";
    int have_id = steer_hwid(id, sizeof id);

    char tmp[512], hdrp[512];
    snprintf(tmp, sizeof tmp, "%s.tmp", out_path);
    snprintf(hdrp, sizeof hdrp, "%s.hdr", out_path);
    unlink(tmp); unlink(hdrp);

    int sent = 0;
    if (!http_get(url, tmp, hdrp, have_id ? id : NULL, 0, &sent)) {
        unlink(tmp); unlink(hdrp);
        printf("{\"ok\":false,\"error\":\"подписка не скачалась\",\"url\":");
        json_str(url);
        printf(",\"hwid\":");
        json_str(have_id ? id : "");
        printf("}\n");
        return 1;
    }
    if (file_bytes(tmp) <= 0) {
        unlink(tmp); unlink(hdrp);
        printf("{\"ok\":false,\"error\":\"панель отдала пустой ответ\",\"url\":");
        json_str(url);
        printf("}\n");
        return 1;
    }

    static char hdrs[16384];
    hdrs_load(hdrp, hdrs, sizeof hdrs);

    struct vless_sub_stats st;
    size_t usable = usable_nodes(tmp, &st);

    /* ПОВТОР ЗА ДРУГИМ ФОРМАТОМ.
     *
     * Панели с привязкой к устройствам выбирают формат ответа по клиенту, и списка ссылок
     * vless:// среди вариантов может не быть ни одного. Замерено на живой подписке:
     * незнакомому клиенту (curl, а значит и нам) отдаётся заглушка из ссылок ss:// на
     * localhost:1234 с именами «Неправильный клиент» и «Подключись через Happ»; Happ,
     * v2rayNG и Streisand получают конфиг Xray в JSON; Clash — свой YAML. Узлы при этом
     * совершенно исправны: восемь из девяти отвечают на пробу. То есть подписка выглядела
     * как «ни одного рабочего узла» не потому, что узлов нет, а потому, что нам их не дали.
     *
     * Притворяться чужим клиентом мы не станем, и не из принципа: JSON приезжает и Happ-у,
     * значит читать его пришлось бы всё равно, и движок его читает (sub.c, parse_xray).
     * Осталось попросить: у панелей этого семейства JSON лежит по тому же адресу с
     * суффиксом /json, и никакого User-Agent для него не нужно.
     *
     * Условие повтора — «НИ ОДНОГО пригодного узла». Не «мало узлов» и не «есть чужие
     * протоколы»: подписка, в которой рядом с vless лежат hy2 и ss, законна и трогать её
     * незачем. */
    const char *eff = url;
    char jurl[1024];
    if (!usable) {
        size_t l = strlen(url);
        int already = (l >= 5 && !strcmp(url + l - 5, "/json")) ||
                      (l >= 6 && !strcmp(url + l - 6, "/json/"));
        if (!already) {
            snprintf(jurl, sizeof jurl, "%.*s/json",
                     (int)(l && url[l - 1] == '/' ? l - 1 : l), url);
            char tmp2[512], hdr2[512];
            snprintf(tmp2, sizeof tmp2, "%s.json.tmp", out_path);
            snprintf(hdr2, sizeof hdr2, "%s.json.hdr", out_path);
            int sent2 = 0;
            if (http_get(jurl, tmp2, hdr2, have_id ? id : NULL, 0, &sent2)) {
                struct vless_sub_stats st2;
                size_t u2 = usable_nodes(tmp2, &st2);
                if (u2 > 0) {
                    /* Помогло — дальше работаем с этим ответом целиком: и файл, и его
                     * заголовки, и ссылка, по которой обновлять в следующий раз. */
                    rename(tmp2, tmp);
                    rename(hdr2, hdrp);
                    hdrs_load(hdrp, hdrs, sizeof hdrs);
                    usable = u2;
                    st = st2;
                    sent = sent2;
                    eff = jurl;
                }
            }
            unlink(tmp2); unlink(hdr2);
        }
    }

    /* Перенос через rename, а не запись поверх: оборванная запись поверх рабочей подписки
     * оставила бы туннель с половиной узлов. Временный файл лежит РЯДОМ с целью, а не в
     * /tmp: между файловыми системами busybox копирует, и обрыв оставил бы ровно тот
     * обрубок, от которого rename и должен спасти. */
    if (rename(tmp, out_path) != 0) {
        unlink(tmp); unlink(hdrp);
        printf("{\"ok\":false,\"error\":\"подписка не записалась — кончилось место?\"}\n");
        return 1;
    }

    struct quota q;
    quota_save(info, hdrs, 0, &q);

    char title[64];
    sub_title(hdrs, title, sizeof title);
    const char *warn = device_warn(hdrs, sent);

    printf("{\"ok\":true,\"url\":");
    json_str(eff);
    printf(",\"path\":");
    json_str(out_path);
    printf(",\"bytes\":%ld,\"usable\":%zu,\"skipped\":%zu,\"foreign\":%zu",
           file_bytes(out_path), usable, st.skipped, st.foreign);
    printf(",\"title\":");
    json_str(title);
    printf(",\"hwid\":");
    json_str(have_id ? id : "");
    printf(",\"hwid_sent\":%s", sent ? "true" : "false");
    /* Сказанное панелью про устройство — в ответе, а не в журнале: человек нажал кнопку и
     * должен узнать там же, что скачалась заглушка, а не гадать позже по туннелю, который
     * «настроен и не работает». */
    if (warn) { printf(",\"warn\":"); json_str(warn); }
    quota_json(&q);
    printf("}\n");
    unlink(hdrp);
    return 0;
}

/* ---- sub-quota -------------------------------------------------------------------- */

int cmd_sub_quota(const char *url, const char *info_path) {
    if (!url_ok(url)) {
        fprintf(stderr, "steer: нужна ссылка на подписку (http:// или https://)\n");
        return 2;
    }
    if (!info_path || !*info_path) {
        fprintf(stderr, "steer: не сказано, где лежит остаток трафика (--info)\n");
        return 2;
    }
    char id[64] = "";
    int have_id = steer_hwid(id, sizeof id);

    static char hdrs[16384];
    struct quota q;
    memset(&q, 0, sizeof q);
    int asked = 0;

    /* HEAD там, где есть curl: тело нам не нужно, а подписка на десятки узлов — это десятки
     * килобайт на каждое открытие обзора, и качать их ради двух чисел незачем. Часть панелей
     * на HEAD отвечает отказом (405) — тогда обычная загрузка, но в ВЫБРОСНЫЙ файл: сама
     * подписка не меняется, поэтому и перечитывать клиента незачем. */
    if (have("curl")) {
        char hdrp[512];
        snprintf(hdrp, sizeof hdrp, "%s.head", info_path);
        unlink(hdrp);
        int sent = 0;
        if (http_get(url, NULL, hdrp, have_id ? id : NULL, 1, &sent)) {
            hdrs_load(hdrp, hdrs, sizeof hdrs);
            unlink(hdrp);
            asked = 1;
            /* keep: если чисел в ответе нет, ниже будет обычная загрузка, и она же решит,
             * снимать ли прежние. Проба такого права не имеет — см. quota_save. */
            if (quota_save(info_path, hdrs, 1, &q)) {
                printf("{\"ok\":true,\"asked\":true");
                quota_json(&q);
                printf("}\n");
                return 0;
            }
        }
        unlink(hdrp);
    }

    char probe[512];
    snprintf(probe, sizeof probe, "%s.probe", info_path);
    char hdrp[512];
    snprintf(hdrp, sizeof hdrp, "%s.probe.hdr", info_path);
    unlink(probe); unlink(hdrp);
    int sent = 0;
    if (http_get(url, probe, hdrp, have_id ? id : NULL, 0, &sent)) {
        asked = 1;
        hdrs_load(hdrp, hdrs, sizeof hdrs);
        quota_save(info_path, hdrs, 0, &q);
    }
    unlink(probe); unlink(hdrp);

    printf("{\"ok\":true,\"asked\":%s", asked ? "true" : "false");
    if (!asked) {
        printf(",\"why\":");
        json_str("панель не ответила");
    } else if (!q.have) {
        /* Две разные причины одним полем намеренно: интерфейс в обоих случаях говорит одно
         * и то же («панель не сообщает остаток»), а различить их можно в журнале. */
        printf(",\"why\":");
        json_str("панель не сообщила остаток трафика");
    }
    quota_json(&q);
    printf("}\n");
    return 0;
}

/* ---- sub-hwid ---------------------------------------------------------------------
 *
 * Подкоманда переехала в src/hwid.c вместе с самим идентификатором: она обязана отвечать и
 * в базовой сборке, где этого файла нет вовсе. */
