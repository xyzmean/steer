/* Обвязка командной строки: таблица команд, справка по ней и разбор аргументов.
 * Зачем таблица, а не текст в main() — см. src/cli.h. */
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>

#include "cli.h"

/* Версию подставляет сборка (-DSTEER_VERSION) из файла VERSION. Умолчание нужно
 * потому, что исходники движка компилируют ещё и стенды из tests/: им до версии дела
 * нет, а падать на неопределённом макросе они не должны. */
#ifndef STEER_VERSION
#define STEER_VERSION "dev"
#endif

/* Ревизия сборки: `git describe` от сборочного скрипта (-DSTEER_REV). Нужна потому, что
 * версия пакета одна на всё время между релизами: движок из релиза 0.9.6 и движок,
 * собранный из main через два коммита после него, оба называли себя «0.9.6-r1», и на
 * стенде два РАЗНЫХ бинарника отчитывались одинаково (R-045/I-054). Ревизия различает их,
 * не задевая ни имя пакета, ни версию пакета: интерфейс версию берёт от менеджера
 * пакетов, и его сравнение остаётся тем же.
 *
 * Умолчание честное: в docker-сборке каталога .git может не быть вовсе, и «неизвестна»
 * лучше, чем подставленное число, которое ничему не соответствует. */
#ifndef STEER_REV
#define STEER_REV "неизвестна"
#endif

#if defined(STEER_SERVER)
#define STEER_BUILD "серверная сборка, хаб xsteer"
#elif defined(STEER_EXTENDED)
#define STEER_BUILD "расширенная сборка, VLESS/Reality"
#else
#define STEER_BUILD "базовая сборка"
#endif

/* ---- флаги ----------------------------------------------------------------
 * Описание флага живёт в одном месте на всю программу: команды ссылаются на него
 * именем. Иначе одинаковый --spec объяснялся бы девять раз и девятью способами. */
struct cli_flag {
    const char *name;
    const char *alias;  /* короткая форма или NULL */
    const char *value;  /* имя значения в справке; NULL — флаг без значения */
    const char *help;
};

static const struct cli_flag FLAGS[] = {
    {"--spec",      NULL, "ФАЙЛ",       "спека каналов (по умолчанию /etc/steer/spec.json)"},
    {"--state-dir", NULL, "КАТАЛОГ",    "каталог состояния (по умолчанию /var/lib/steer)"},
    {"--dry-run",   NULL, NULL,         "напечатать готовый ruleset и ничего не применять"},
    {"--verbose",   "-v", NULL,         "рассказывать по шагам, что проверяется"},
    {"--kind",      NULL, "ВИД",        "только выходы этого вида: interface, vless, xsteer, direct"},
    {"--obfs",      NULL, NULL,         "только выходы, у которых настроена обфускация"},
    {"--devices",   NULL, NULL,         "печатать имена устройств, а не имена выходов"},
    {"--node",      NULL, "N",          "номер узла подписки, с нуля; -1 — первый рабочий (по умолчанию)"},
    {"--timeout",   NULL, "СЕК",        "сколько ждать ответа узла (по умолчанию 5)"},
    {"--listen",    NULL, "ПОРТ",       "порт поддельного TCP, который слушает сервер"},
    {"--forward",   NULL, "АДРЕС:ПОРТ", "куда отдавать распакованные датаграммы"},
    {"--config",    NULL, "ФАЙЛ",       "конфигурация xsteer в стиле wg "
                                        "(по умолчанию /etc/steer/xsteer/hub.conf)"},
    {"--device",    NULL, "ИМЯ",        "готовое устройство TUN: им владеет netifd, "
                                        "движок только открывает его"},
    {"--stream",     NULL, NULL,        "вести записи по НАСТОЯЩЕМУ TCP вместо поддельного: "
                                        "без сырого сокета и без правила против RST"},
    {"--no-stream",  NULL, NULL,        "выключить режим потока там, где он задан спекой"},
    {"--stream-port", NULL, "ПОРТ",     "порт хаба для режима потока (по умолчанию порт из "
                                        "Endpoint)"},
};
static const size_t FLAGS_N = sizeof FLAGS / sizeof FLAGS[0];

/* ---- команды --------------------------------------------------------------
 * Порядок строк — это порядок в справке; разделы идут подряд, заголовок печатается
 * при смене группы. */
static const struct cli_cmd CMDS[] = {
{"apply", "Маршрутизация", "",
 "скомпилировать спеку в правила nftables и таблицы маршрутизации",
 "Разворачивает списки в наборы nftables и ставит всё одной транзакцией: применяется\n"
 "либо весь набор каналов, либо ничего. Правила живут в своей таблице inet steer,\n"
 "поэтому перезагрузка fw4 их не трогает, а удаление сводится к удалению таблицы.",
 "--spec --state-dir --dry-run", 0, 0, 0, 0, 0},

{"failover", "Маршрутизация", "",
 "выбрать живое устройство для каждого выхода",
 "Обходит устройства выхода в порядке приоритета и записывает в состояние первое\n"
 "живое. Запускается по кругу из init-скрипта, поэтому печатает только изменения —\n"
 "с -v рассказывает и про проверки, которые ничего не поменяли.",
 "--spec --state-dir --verbose", 0, 0, 0, 0, 0},

{"dnsd", "Маршрутизация", "",
 "резолвер для каналов, заданных доменами",
 "Отвечает на запросы LAN и раскладывает домены по наборам того канала, которому они\n"
 "принадлежат: режим fakeip выдаёт адрес из служебного диапазона, realip — настоящий\n"
 "ответ апстрима. Работает на переднем плане, процессом управляет procd.",
 "", 0, 1, 0, 0, 0},

{"status", "Диагностика", "",
 "применённое состояние движка, JSON",
 "Печатает то, что стоит на роутере прямо сейчас: выходы, выбранные устройства,\n"
 "каналы и размеры наборов. Читается глазами и разбирается программой.",
 "--spec --state-dir", 0, 0, 0, 0, 0},

{"diag", "Диагностика", "",
 "проверки состояния, JSON; код 1 при поломке",
 "Сверяет спеку с тем, что действительно стоит в системе: таблица на месте, наборы\n"
 "не пустые, устройства подняты, резолвер запущен, маскарад настроен. Код возврата 1\n"
 "означает «сломано» — на него опирается контроль в splify2, поэтому вывод и код\n"
 "стоит считать интерфейсом, а не текстом для чтения.",
 "--spec --state-dir", 0, 0, 0, 0, 0},

{"explain", "Диагностика", "<адрес|имя>",
 "какой канал и какой выход достанутся адресу",
 "Отвечает на вопрос «почему этот сайт идёт не туда»: называет первый канал,\n"
 "который поймает адрес или имя, и выход, куда трафик уйдёт. Аргумент проверяется\n"
 "по форме до того, как попадёт в вызов nft.",
 "--spec --state-dir", 1, 0, 0, 0, 0},

{"outputs", "Диагностика", "",
 "перечислить выходы, по одному в строке",
 "Нужен init-скрипту: он спрашивает движок, для каких выходов поднимать процессы.\n"
 "Спрашивать движок надёжнее, чем искать ключ в спеке grep-ом, — переименование поля\n"
 "ломает grep молча, а вместе с ним и запуск.",
 "--spec --state-dir --kind --obfs --devices", 0, 0, 0, 0, 0},

{"needs-dnsd", "Диагностика", "",
 "код 0, если в спеке есть доменные каналы",
 "Ничего не печатает, отвечает кодом возврата: 0 — резолвер нужен, 1 — нет.\n"
 "Тоже для init-скрипта и по той же причине, что outputs.",
 "--spec --state-dir", 0, 0, 0, 0, 0},

{"vless", "VLESS", "<выход>",
 "поднять TUN и клиент для выхода kind=vless",
 "Поднимает TUN-интерфейс и клиент VLESS/Reality для названного выхода. Несёт и TCP,\n"
 "и UDP, поэтому через такой выход работают QUIC, WireGuard/WARP и игровой трафик.\n"
 "Работает на переднем плане, процессом управляет procd.",
 "--spec --state-dir", 1, 0, 1, 0, 0},

{"vless-nodes", "VLESS", "<выход>",
 "узлы подписки этого выхода, JSON",
 "Печатает разобранную подписку в порядке файла: по объекту на узел. Номер узла в\n"
 "этом списке — то, что ждёт --node у vless-probe.",
 "--spec --state-dir", 1, 0, 1, 0, 0},

{"vless-probe", "VLESS", "<выход>",
 "проверить узел подписки и замерить задержку",
 "Подключается к узлу и печатает результат с задержкой. Без --node проверяется тот\n"
 "узел, который выбрал бы подъём выхода, — то есть первый рабочий: так проверка\n"
 "отвечает на вопрос «что будет, если применить», а не на вопрос про конкретный узел.",
 "--spec --state-dir --node --timeout", 1, 0, 1, 0, 0},

{"obfs", "Обфускация", "<выход>",
 "WireGuard поверх поддельного TCP, клиентская половина",
 "Принимает локальный UDP от WireGuard и несёт его до сервера потоком, который\n"
 "выглядит обычным TCP-соединением. Адрес сервера и порты берутся из спеки, из\n"
 "настроек obfs у названного выхода.",
 "--spec --state-dir", 1, 0, 0, 0, 0},

{"obfs-server", "Обфускация", "",
 "серверная половина обфускации, для VPS",
 "Слушает порт поддельного TCP и пересылает распакованные датаграммы локальному\n"
 "WireGuard. Спека не нужна и не читается: на VPS нет ни выходов, ни каналов — есть\n"
 "порт, который слушать, и адрес, которому пересылать.",
 "--listen --forward", 0, 0, 0, 0, 0},

{"xsteer", "Звезда xsteer", "[<выход>]",
 "поднять клиент xsteer: для выхода спеки или для готового устройства",
 "С именем выхода: читает конфигурацию в стиле wg (по умолчанию\n"
 "/etc/steer/xsteer/<выход>.conf), сам создаёт TUN и сам привязывает к нему таблицу\n"
 "маршрутизации выхода. Так его поднимает procd для выхода kind=xsteer.\n"
 "\n"
 "Без имени выхода: спека не читается вовсе, нужны --config и --device. Устройством в\n"
 "этом режиме владеет netifd: он даёт адрес, MTU и зону firewall, а движок только\n"
 "открывает готовое устройство и несёт трафик. Обработчик протокола для netifd и\n"
 "страница настройки едут в пакете luci-app-splify2 — это часть интерфейса, не движка.\n"
 "Тогда в спеке этот туннель описывается как обычный kind: interface — как wireguard.\n"
 "\n"
 "В обоих режимах поток до хаба выглядит обычным TLS на :443. Работает на переднем\n"
 "плане: процессом управляет procd или netifd.\n"
 "\n"
 "Транспорт по умолчанию — ПОДДЕЛЬНЫЙ TCP: сырой сокет плюс правило nft против RST\n"
 "собственного ядра, зато потери наружу остаются потерями и не превращаются в задержку\n"
 "для внутреннего TCP. Где сырой сокет недоступен (провайдер его режет, контейнер без\n"
 "CAP_NET_RAW) или где хаб держит только режим потока, помогает --stream: записи те же\n"
 "и облик тот же, но едут по обычному соединению TCP, которое открывает ядро. Тогда же\n"
 "включается смена ключей эпохами — каждые 64 МиБ и без разрыва туннеля.\n"
 "\n"
 "Оговорка по существу: режим потока СЛУШАЕТ пока только хаб реализации на Go\n"
 "(xsteer hub --stream-port). Наш собственный хаб (steer xsteer-hub) ждёт поддельный TCP,\n"
 "и --stream к нему не подключится — перенос слушающей половины ещё не сделан.",
 "--spec --state-dir --config --device --stream --no-stream --stream-port", 0, 0, 1, 0, 1},

{"xsteer-peers", "Звезда xsteer", "<выход>",
 "пиры выхода, рукопожатия и счётчики, JSON",
 "Отвечает на вопрос «почему пир A не видит пира B»: пиры из конфигурации, их\n"
 "AllowedIPs, возраст последнего рукопожатия и объёмы. Секретов не печатает никогда —\n"
 "приватный ключ до печати не доходит по построению.",
 "--spec --state-dir --config", 1, 0, 1, 0, 0},

{"xsteer-check", "Звезда xsteer", "",
 "проверить конфигурацию, ничего не поднимая",
 "Читает конфигурацию в стиле wg и печатает, ЧТО в ней понято: роль, адрес, MTU, пиры и их\n"
 "AllowedIPs. Так видно самые частые ошибки, которые разбор пропускает по праву — маску /32\n"
 "вместо /24, забытый Endpoint, MTU, который человек считал заданным. Негодный файл вызывает\n"
 "объяснение с номером строки в stderr и код возврата 2. Нужна прослойке netifd: она проверяет\n"
 "настройки ДО создания устройства, чтобы человек увидел причину, а не интерфейс,\n"
 "который «поднялся и молчит». Роль (пир или хаб) выводится из самой конфигурации:\n"
 "есть ListenPort — это хаб, есть Endpoint у единственной секции [Peer] — это пир.",
 "--config", 0, 0, 1, 0, 0},

{"xsteer-key", "Звезда xsteer", "",
 "напечатать новую пару ключей base64",
 "Печатает две строки в том виде, в каком они кладутся в конфигурацию. Ничего не\n"
 "записывает: куда положить приватную половину — решение человека, а не движка.\n"
 "При нехватке энтропии отказывается, а не выдумывает ключ: предсказуемый ключ хуже\n"
 "отсутствующего, и заметить его нельзя ничем.",
 "", 0, 0, 1, 0, 0},

{"xsteer-hub", "Звезда xsteer", "",
 "хаб полной звезды, для VPS",
 "Слушает порт и разводит трафик между пирами по их AllowedIPs, поэтому пир видит\n"
 "пир через хаб. Спека не нужна и не читается: на VPS нет ни выходов, ни каналов —\n"
 "есть конфигурация звезды и порт.",
 "--config --state-dir", 0, 0, 1, 1, 0},

{"fit", "Списки", "[ФАЙЛ]",
 "подогнать список префиксов под память роутера",
 "Ужимает список до заданного числа элементов набора, объединяя соседние префиксы по\n"
 "плотности. Без --budget только склеивает то, что склеивается без потерь. Читает\n"
 "stdin, если файл не назван; результат идёт в stdout, отчёт о цене — в stderr.\n"
 "Код возврата 1 означает «не влезло»: без --truncate список выходит целиком и\n"
 "честно помечается fits:false, потому что тихая дыра хуже честного отказа.",
 "", 0, 1, 0, 0, 0},
};
static const size_t CMDS_N = sizeof CMDS / sizeof CMDS[0];

/* ---- мелочи ---------------------------------------------------------------- */

/* Тот же префикс и тот же код возврата, что у die() в spec.c, но с настоящим
 * форматом: сообщения разбора аргументов почти всегда про два значения сразу
 * («команда X не знает флаг Y»), а die() умеет подставить только одну строку. */
static void cli_die(const char *fmt, ...) {
    va_list ap;
    fputs("steer: ", stderr);
    va_start(ap, fmt);
    vfprintf(stderr, fmt, ap);
    va_end(ap);
    fputc('\n', stderr);
    exit(2);
}

static const struct cli_flag *flag_find(const char *name) {
    for (size_t i = 0; i < FLAGS_N; i++)
        if (!strcmp(FLAGS[i].name, name) ||
            (FLAGS[i].alias && !strcmp(FLAGS[i].alias, name)))
            return &FLAGS[i];
    return NULL;
}

/* Список флагов команды — строка имён через пробел. Сравнение потокенно, а не
 * strstr-ом: подстрока нашла бы «--listen» внутри «--listen-port». */
static int flag_listed(const char *list, const char *name) {
    size_t n = strlen(name);
    for (const char *p = list; *p; ) {
        while (*p == ' ') p++;
        const char *s = p;
        while (*p && *p != ' ') p++;
        if ((size_t)(p - s) == n && !strncmp(s, name, n)) return 1;
    }
    return 0;
}

const struct cli_cmd *cli_lookup(const char *name) {
    for (size_t i = 0; i < CMDS_N; i++)
        if (!strcmp(CMDS[i].name, name)) return &CMDS[i];
    return NULL;
}

int cli_wants_help(int argc, char **argv) {
    for (int i = 0; i < argc; i++)
        if (!strcmp(argv[i], "--help") || !strcmp(argv[i], "-h")) return 1;
    return 0;
}

/* ---- справка --------------------------------------------------------------- */

/* Синопсис собирается из тех же данных, что и разбор: если у команды появился флаг,
 * он появляется и в строке использования, и наоборот. */
static void print_synopsis(FILE *out, const struct cli_cmd *c) {
    fprintf(out, "  steer %s", c->name);
    if (c->args[0]) fprintf(out, " %s", c->args);
    if (c->passthru) {
        fputs(" [флаги]", out);
    } else {
        for (const char *p = c->flags; *p; ) {
            while (*p == ' ') p++;
            const char *s = p;
            while (*p && *p != ' ') p++;
            if (p == s) break;
            char name[32];
            size_t n = (size_t)(p - s);
            if (n >= sizeof name) continue;
            memcpy(name, s, n);
            name[n] = 0;
            const struct cli_flag *f = flag_find(name);
            if (!f) continue;
            if (f->value) fprintf(out, " [%s %s]", f->name, f->value);
            else fprintf(out, " [%s]", f->name);
        }
    }
    fputc('\n', out);
}

/* Выравнивание колонки — руками, а не через %-24s. printf считает БАЙТЫ, а кириллица
 * в UTF-8 занимает по два на букву: «--state-dir КАТАЛОГ» printf принимает за 26
 * символов вместо 19, и колонка описаний расползается ровно на тех строках, где имя
 * значения написано по-русски. Считаются начальные байты кодовых точек. */
static void pad_to(FILE *out, const char *s, int width) {
    int n = 0;
    for (const unsigned char *p = (const unsigned char *)s; *p; p++)
        if ((*p & 0xC0) != 0x80) n++;
    fputs(s, out);
    while (n++ < width) fputc(' ', out);
}

static void print_flags(FILE *out, const char *list) {
    for (size_t i = 0; i < FLAGS_N; i++) {
        if (!flag_listed(list, FLAGS[i].name)) continue;
        char left[48];
        if (FLAGS[i].alias)
            snprintf(left, sizeof left, "%s, %s%s%s", FLAGS[i].alias, FLAGS[i].name,
                     FLAGS[i].value ? " " : "", FLAGS[i].value ? FLAGS[i].value : "");
        else
            snprintf(left, sizeof left, "%s%s%s", FLAGS[i].name,
                     FLAGS[i].value ? " " : "", FLAGS[i].value ? FLAGS[i].value : "");
        fputs("  ", out);
        pad_to(out, left, 24);
        fprintf(out, " %s\n", FLAGS[i].help);
    }
}

static void help_all(FILE *out) {
    fprintf(out, "steer %s — движок маршрутизации по правилам для OpenWrt\n\n", STEER_VERSION);
    fputs("Использование:\n"
          "  steer <команда> [аргументы] [флаги]\n", out);
    const char *group = NULL;
    for (size_t i = 0; i < CMDS_N; i++) {
        if (!group || strcmp(group, CMDS[i].group)) {
            group = CMDS[i].group;
            fprintf(out, "\n%s:\n", group);
        }
        fprintf(out, "  %-13s %s", CMDS[i].name, CMDS[i].brief);
#ifndef STEER_EXTENDED
        /* Команда названа даже там, где её нет. «Неизвестная команда» на steer vless
         * заставила бы искать опечатку вместо того, чтобы поставить нужный пакет. */
        if (CMDS[i].ext && !CMDS[i].srv) fputs(" [steer-extended]", out);
        /* Хаб — не «другой пакет для роутера», а другой артефакт: архив для VPS. Маркер
         * поэтому свой, иначе человека послали бы ставить steer-extended туда, где он не
         * поможет. */
        if (CMDS[i].srv) fputs(" [steer-hub]", out);
#endif
        fputc('\n', out);
    }
    fputs("\nСправка и версия:\n"
          "  help [команда]  подробности: что делает команда и какие у неё флаги\n"
          "  version         версия движка и вариант сборки\n"
          "\n"
          "Подробности по команде: steer help apply   (то же самое: steer apply --help)\n", out);
#ifndef STEER_EXTENDED
    fputs("\nЭто базовая сборка: команды, помеченные [steer-extended], откажутся работать.\n"
          "VLESS/Reality есть в пакете steer-extended — он ставится вместо этого и умеет всё то же.\n"
          "Помеченное [steer-hub] живёт в архиве для VPS: на роутере хабу делать нечего.\n", out);
#endif
}

static void help_cmd(FILE *out, const struct cli_cmd *c) {
    fprintf(out, "steer %s — %s\n\n", c->name, c->brief);
    fputs("Использование:\n", out);
    print_synopsis(out, c);
    if (c->detail) fprintf(out, "\n%s\n", c->detail);
    if (!c->passthru && c->flags[0]) {
        fputs("\nФлаги:\n", out);
        print_flags(out, c->flags);
    }
#ifndef STEER_EXTENDED
    if (c->srv)
        fputs("\nВ этой сборке команды нет: хаб ставится на VPS из архива steer-hub.\n", out);
    else if (c->ext)
        fputs("\nВ этой сборке команды нет: нужен пакет steer-extended.\n", out);
#endif
}

void cli_help(FILE *out, const struct cli_cmd *cmd) {
    if (cmd) help_cmd(out, cmd);
    else help_all(out);
}

void cli_usage_short(FILE *out) {
    fputs("steer: нужна команда\n"
          "использование: steer <команда> [аргументы] [флаги]\n"
          "список команд: steer help\n", out);
}

void cli_version(FILE *out) {
    fprintf(out, "steer %s (%s, ревизия %s)\n", STEER_VERSION, STEER_BUILD, STEER_REV);
}

/* ---- подсказка по опечатке -------------------------------------------------- */

/* Расстояние Левенштейна, обычная построчная динамика. Имён команд полтора десятка и
 * они короткие, так что дешевле некуда, а «steer aply» без подсказки стоит человеку
 * захода в README. */
static int edit_dist(const char *a, const char *b) {
    size_t la = strlen(a), lb = strlen(b);
    if (la > 32 || lb > 32) return 99;
    int prev[33], cur[33];
    for (size_t j = 0; j <= lb; j++) prev[j] = (int)j;
    for (size_t i = 1; i <= la; i++) {
        cur[0] = (int)i;
        for (size_t j = 1; j <= lb; j++) {
            int sub = prev[j - 1] + (a[i - 1] != b[j - 1]);
            int del = prev[j] + 1, ins = cur[j - 1] + 1;
            int m = sub < del ? sub : del;
            cur[j] = m < ins ? m : ins;
        }
        memcpy(prev, cur, (lb + 1) * sizeof *prev);
    }
    return prev[lb];
}

void cli_unknown(const char *name) {
    const char *best = NULL;
    int bestd = 99;
    for (size_t i = 0; i < CMDS_N; i++) {
        int d = edit_dist(name, CMDS[i].name);
        if (d < bestd) { bestd = d; best = CMDS[i].name; }
    }
    fprintf(stderr, "steer: нет такой команды: %s\n", name);
    /* Порог по трети длины имени: иначе «steer foo» уверенно советовал бы «fit»,
     * а неверная подсказка хуже, чем никакой. */
    if (best && bestd <= 2 && (size_t)bestd * 3 <= strlen(best) + 2)
        fprintf(stderr, "       возможно, имелось в виду: steer %s\n", best);
    fputs("       список команд: steer help\n", stderr);
    exit(2);
}

/* ---- разбор ----------------------------------------------------------------- */

static int cli_int(const char *flag, const char *s, int lo, int hi) {
    char *end;
    long v = strtol(s, &end, 10);
    if (!*s || *end || v < lo || v > hi)
        cli_die("%s: нужно целое от %d до %d, а не «%s»", flag, lo, hi, s);
    return (int)v;
}

void cli_parse(const struct cli_cmd *cmd, int argc, char **argv, int from,
               struct cli_args *out) {
    memset(out, 0, sizeof *out);
    out->spec = "/etc/steer/spec.json";
    /* Умолчание по узлу — «до первого рабочего»: то же решение, что принимает подъём
     * выхода, поэтому проверка отвечает на вопрос «что будет, если применить». */
    out->node = -1;
    out->timeout = 5;

    for (int i = from; i < argc; i++) {
        const char *a = argv[i];
        if (a[0] != '-' || !a[1]) {
            /* Позиционный. Раньше сюда молча падало ВСЁ неопознанное, включая
             * опечатки во флагах, — см. комментарий в cli.h. */
            /* Предел — npos_max, если он задан, иначе npos: команда без необязательных
             * позиционных ведёт себя ровно как раньше. */
            int pmax = cmd->npos_max ? cmd->npos_max : cmd->npos;
            if (out->npos >= pmax || out->npos >= CLI_MAXPOS) {
                if (pmax == 0)
                    cli_die("команда %s не принимает аргументов, а получила «%s»",
                            cmd->name, a);
                cli_die("команда %s принимает один аргумент %s, а получила ещё и «%s»",
                        cmd->name, cmd->args, a);
            }
            out->pos[out->npos++] = a;
            continue;
        }
        const struct cli_flag *f = flag_find(a);
        if (!f)
            cli_die("неизвестный флаг: %s (подсказка: steer %s --help)", a, cmd->name);
        if (!flag_listed(cmd->flags, f->name))
            cli_die("команда %s не понимает флаг %s (подсказка: steer %s --help)",
                    cmd->name, a, cmd->name);
        const char *val = NULL;
        if (f->value) {
            /* Значение, похожее на флаг, — почти всегда потерянное значение, а не путь
             * с именем «--dry-run». Молча съесть его значило бы применить правила
             * вместо показа: ровно то, ради чего человек и писал --dry-run. */
            if (i + 1 >= argc || flag_find(argv[i + 1]))
                cli_die("флаг %s остался без значения (%s)", f->name, f->value);
            val = argv[++i];
        }
        if      (!strcmp(f->name, "--spec"))       out->spec = val;
        else if (!strcmp(f->name, "--state-dir"))  out->state_dir = val;
        else if (!strcmp(f->name, "--kind"))       out->kind = val;
        else if (!strcmp(f->name, "--forward"))    out->forward = val;
        else if (!strcmp(f->name, "--config"))     out->config = val;
        else if (!strcmp(f->name, "--device"))     out->device = val;
        else if (!strcmp(f->name, "--dry-run"))    out->dry_run = 1;
        else if (!strcmp(f->name, "--verbose"))    out->verbose = 1;
        else if (!strcmp(f->name, "--obfs"))       out->obfs = 1;
        else if (!strcmp(f->name, "--devices"))    out->devices = 1;
        /* Нижняя граница -1, а не 0: это часовой «первый рабочий», то же умолчание, и
         * splify2 передаёт его явно (`vless-probe --node -1`). Диапазон с нуля молча
         * сломал бы проверку выхода в интерфейсе. */
        else if (!strcmp(f->name, "--node"))       out->node = cli_int(f->name, val, -1, 65535);
        else if (!strcmp(f->name, "--timeout"))    out->timeout = cli_int(f->name, val, 1, 3600);
        else if (!strcmp(f->name, "--listen"))     out->listen = cli_int(f->name, val, 1, 65535);
        else if (!strcmp(f->name, "--stream"))     out->stream = 1;
        else if (!strcmp(f->name, "--no-stream"))  out->stream = -1;
        /* Порт подразумевает режим: назвать порт потока и остаться на поддельном TCP человек
         * не может хотеть, а молча проигнорировать ключ — это «настроил и не работает». */
        else if (!strcmp(f->name, "--stream-port")) {
            out->stream_port = cli_int(f->name, val, 1, 65535);
            if (out->stream >= 0) out->stream = 1;
        }
    }

    if (out->npos < cmd->npos)
        cli_die("команде %s нужен аргумент %s (подсказка: steer %s --help)",
                cmd->name, cmd->args, cmd->name);
}
