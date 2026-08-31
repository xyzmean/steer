/* Скачивание и обработка подписки: то, что раньше жило в оболочке и не проверялось ничем.
 *
 * ЗАЧЕМ ЭТОТ СТЕНД. Работа с подпиской целиком состоит из чужих данных: заголовки ответа
 * пишет панель, MAC приходит от ядра, название подписки приезжает в base64, остаток трафика
 * — числами, которым никто не гарантировал формат. И каждая ошибка здесь молчаливая по
 * построению:
 *
 *   * ИДЕНТИФИКАТОР УСТРОЙСТВА. Изменился на один шаг — и каждый уже заведённый роутер стал
 *     для панели новым устройством. Человек теряет слот и не понимает, почему; подписка при
 *     этом «скачивается», просто вместо узлов приезжает заглушка. Поэтому проверяется не
 *     значение хеша (его считает mbedtls), а ВСЯ РЕЦЕПТУРА: какая строка хешируется, сколько
 *     знаков берётся, какая приставка, какой порт выбирается из нескольких.
 *
 *   * ТОЧКА ОТСЧЁТА ПЕРИОДА. Панель сообщает только конец срока и накопленный расход, а
 *     «в среднем в сутки» считается по двум наблюдениям. Сбросить точку отсчёта не вовремя —
 *     значит показать человеку темп расхода, набранный за минуту, и обещать, что трафик
 *     кончится завтра.
 *
 *   * ПОВТОР ЗА ДРУГИМ ФОРМАТОМ. Панели выбирают формат ответа по клиенту, и списка ссылок
 *     vless:// среди вариантов может не быть ни одного. Не попросив JSON, движок объявляет
 *     исправную подписку пустой.
 *
 * КАК ЭТО ПРОВЕРЯЕТСЯ БЕЗ СЕТИ И БЕЗ MBEDTLS. Файл включает исходник (тот же приём, что в
 * submatch.c и dnsmatch.c), подставляет свой `mbedtls_sha256` и свой `run_quiet`, а вместо
 * curl в PATH кладёт скрипт-заглушку, который пишет заранее заданные заголовки и тело.
 *
 * ПОЧЕМУ ЗАГЛУШКА ХЕША, А НЕ НАСТОЯЩИЙ SHA-256. Проверять надо не сам хеш — это работа
 * библиотеки, — а то, ЧТО в него уходит и что из него берётся. Заглушка запоминает
 * поданную строку, поэтому рецептура проверяется целиком и точнее, чем сравнением с
 * заранее посчитанным числом: сравнение с числом молчит о том, откуда это число взялось.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <fcntl.h>

/* ---- заглушки, без которых стенд не собрать ---------------------------------------- */

/* Что последний раз хешировали. Ради этого заглушка и существует: рецептура HWID
 * проверяется по ВХОДУ хеша, а не по его результату. */
static char g_sha_in[256];
static size_t g_sha_in_n;

/* Поддельный SHA-256: детерминированный, зависит от входа (иначе «разный MAC — разный
 * идентификатор» проверялось бы ни на чём), и легко предсказуемый на стороне проверки. */
int mbedtls_sha256(const unsigned char *input, size_t ilen, unsigned char *output, int is224);
int mbedtls_sha256(const unsigned char *input, size_t ilen, unsigned char *output, int is224) {
    (void)is224;
    g_sha_in_n = ilen < sizeof g_sha_in - 1 ? ilen : sizeof g_sha_in - 1;
    memcpy(g_sha_in, input, g_sha_in_n);
    g_sha_in[g_sha_in_n] = 0;
    unsigned acc = 0x1234;
    for (size_t i = 0; i < ilen; i++) acc = acc * 31 + input[i];
    for (int i = 0; i < 32; i++) {
        acc = acc * 1103515245u + 12345u;
        output[i] = (unsigned char)(acc >> 16);
    }
    return 0;
}

/* Тот же запуск, что в steer.c: заглушка curl обязана запускаться по-настоящему, иначе
 * ветка скачивания осталась бы непроверенной вовсе. */
int run_quiet(const char *const argv[]);
int run_quiet(const char *const argv[]) {
    pid_t p = fork();
    if (p < 0) return -1;
    if (p == 0) {
        int devnull = open("/dev/null", O_WRONLY);
        if (devnull >= 0) { dup2(devnull, 1); dup2(devnull, 2); close(devnull); }
        execvp(argv[0], (char *const *)argv);
        _exit(127);
    }
    int st = 0;
    waitpid(p, &st, 0);
    return WIFEXITED(st) ? WEXITSTATUS(st) : -1;
}

#include "../src/ext/subfetch.c"
/* base64 названия подписки и разбор узлов — из sub.c, той же функцией, которой их читает
 * подъём туннеля. Исходник включается тем же приёмом; mbedtls он не требует. */
#include "../src/ext/sub.c"
#include "../src/ext/vless_proto.c"

static int g_pass, g_fail;

static void ck(const char *what, const char *want, const char *got) {
    if (want && got && !strcmp(want, got)) { g_pass++; return; }
    g_fail++;
    printf("FAIL %s\n  ожидалось: %s\n  получено:  %s\n", what,
           want ? want : "(null)", got ? got : "(null)");
}

static void ck_num(const char *what, long long want, long long got) {
    char a[32], b[32];
    snprintf(a, sizeof a, "%lld", want);
    snprintf(b, sizeof b, "%lld", got);
    ck(what, a, b);
}

static void ck_true(const char *what, int cond) {
    ck(what, "да", cond ? "да" : "нет");
}

/* ---- песочница --------------------------------------------------------------------- */

static char T[256];

static void wr(const char *path, const char *text) {
    FILE *f = fopen(path, "w");
    if (!f) { printf("FAIL не открылся %s\n", path); g_fail++; return; }
    fputs(text, f);
    fclose(f);
}

static char *rd(const char *path) {
    static char buf[8192];
    buf[0] = 0;
    FILE *f = fopen(path, "r");
    if (!f) return buf;
    size_t n = fread(buf, 1, sizeof buf - 1, f);
    buf[n] = 0;
    fclose(f);
    return buf;
}

static void mkiface(const char *name, const char *mac, int physical) {
    char p[512];
    snprintf(p, sizeof p, "%s/sys/%s", T, name);
    mkdir(p, 0755);
    snprintf(p, sizeof p, "%s/sys/%s/address", T, name);
    char v[64];
    snprintf(v, sizeof v, "%s\n", mac);
    wr(p, v);
    if (physical) {
        snprintf(p, sizeof p, "%s/sys/%s/device", T, name);
        wr(p, "");
    }
}

static void rmiface(const char *name) {
    char p[512];
    snprintf(p, sizeof p, "%s/sys/%s/address", T, name); unlink(p);
    snprintf(p, sizeof p, "%s/sys/%s/device", T, name);  unlink(p);
    snprintf(p, sizeof p, "%s/sys/%s", T, name);         rmdir(p);
}

/* Перехват stdout: ответы команд — это JSON в stdout, и проверять их надо целиком. */
static int g_stdout_saved = -1;
static char *cap(int (*fn)(void)) {
    char path[512];
    snprintf(path, sizeof path, "%s/out.json", T);
    fflush(stdout);
    g_stdout_saved = dup(1);
    int fd = open(path, O_WRONLY | O_CREAT | O_TRUNC, 0644);
    dup2(fd, 1);
    close(fd);
    fn();
    fflush(stdout);
    dup2(g_stdout_saved, 1);
    close(g_stdout_saved);
    return rd(path);
}

/* Есть ли подстрока — самый прямой способ спросить про поле JSON, не заводя разборщик
 * JSON в стенде движка. */
static int has(const char *hay, const char *needle) { return strstr(hay, needle) != NULL; }

/* ---- проверки: идентификатор устройства -------------------------------------------- */

static void t_hwid(void) {
    char id[64];

    /* Один физический порт. Проверяется ВХОД хеша: строка без завершающего перевода строки
     * — ровно то, что делал `printf 'splify2:%s'` в оболочке. Один лишний байт здесь меняет
     * идентификатор у всех установленных роутеров сразу. */
    mkiface("eth0", "C4:41:1E:DD:EE:01", 1);
    ck_true("один порт: идентификатор посчитан", hwid(id, sizeof id));
    ck("хешируется ровно «splify2:<mac>»", "splify2:c4:41:1e:dd:ee:01", g_sha_in);
    ck_num("и ни байтом больше", 25, (long long)g_sha_in_n);
    ck_true("приставка на месте", !strncmp(id, "splify2-", 8));
    ck_num("двадцать знаков хеша, не больше", 28, (long long)strlen(id));

    /* MAC приводится к нижнему регистру: sysfs отдаёт его так, но не всякий драйвер. */
    ck_true("в идентификаторе только строчные шестнадцатеричные",
            strspn(id + 8, "0123456789abcdef") == 20);

    /* Порядок портов ЖЁСТКИЙ. Без него идентификатор менялся бы от порядка обхода каталога,
     * то есть от перезагрузки к перезагрузке. */
    mkiface("wan", "c4:41:1e:dd:ee:03", 1);
    mkiface("lan1", "c4:41:1e:dd:ee:02", 1);
    hwid(id, sizeof id);
    ck("eth* выигрывает у lan* и wan*", "splify2:c4:41:1e:dd:ee:01", g_sha_in);
    rmiface("eth0");
    hwid(id, sizeof id);
    ck("без eth* берётся lan*", "splify2:c4:41:1e:dd:ee:02", g_sha_in);
    rmiface("lan1");
    hwid(id, sizeof id);
    ck("без lan* берётся wan*", "splify2:c4:41:1e:dd:ee:03", g_sha_in);
    rmiface("wan");

    /* Виртуальный интерфейс не порт: у моста, туннеля и wifi-ap ссылки на устройство нет, а
     * их MAC меняется вместе с настройкой. */
    mkiface("br-lan", "c4:41:1e:dd:ee:10", 0);
    mkiface("zz9", "c4:41:1e:dd:ee:11", 1);
    hwid(id, sizeof id);
    ck("мост без device пропущен", "splify2:c4:41:1e:dd:ee:11", g_sha_in);
    rmiface("br-lan");
    rmiface("zz9");

    /* «Назначен локально» — адрес, который выдумало ядро: после перезагрузки он другой.
     * Признак — вторая шестнадцатеричная цифра из 2,3,6,7,a,b,e,f. */
    mkiface("eth0", "02:41:1e:dd:ee:20", 1);
    ck_true("локально назначенный адрес не годится", !hwid(id, sizeof id));
    rmiface("eth0");
    mkiface("eth0", "ae:41:1e:dd:ee:21", 1);
    ck_true("и в форме «ae:» тоже", !hwid(id, sizeof id));
    rmiface("eth0");

    /* Нули и широковещательный адрес — не идентификаторы, а признак того, что драйвер ещё
     * не дал настоящего. */
    mkiface("eth0", "00:00:00:00:00:00", 1);
    ck_true("нулевой адрес не годится", !hwid(id, sizeof id));
    rmiface("eth0");
    mkiface("eth0", "ff:ff:ff:ff:ff:ff", 1);
    ck_true("широковещательный не годится", !hwid(id, sizeof id));
    rmiface("eth0");

    /* Ни одного годного порта — пустой ответ, а не выдуманный идентификатор: заголовок тогда
     * не уходит вовсе, и об этом говорится отдельным словом. */
    char *out = cap(cmd_sub_hwid);
    ck_true("без портов ответ пустой, а не выдуманный", has(out, "\"hwid\":\"\""));
}

/* ---- проверки: заголовки ответа ---------------------------------------------------- */

static void t_headers(void) {
    char v[256];

    /* ПОСЛЕДНИЙ блок заголовков, а не первый: за перенаправлением приезжает второй, и
     * заголовки подписки лежат именно в нём — в первом только 30x и Location. */
    const char *two =
        "HTTP/1.1 302 Found\n"
        "Location: https://panel.example/sub\n"
        "profile-title: старое\n"
        "\n"
        "HTTP/1.1 200 OK\n"
        "Profile-Title: новое\n";
    v[0] = 0;
    hdr_get(two, "profile-title", v, sizeof v);
    ck("за перенаправлением берётся последний блок", "новое", v);

    /* Регистр имени заголовка не значит ничего: панели пишут их как хотят. */
    v[0] = 0;
    ck_true("имя заголовка регистронезависимо",
            hdr_get("X-HWID-Limit: 3\n", "x-hwid-limit", v, sizeof v));
    ck("значение обрезано от пробелов", "3", v);

    v[0] = 0;
    ck_true("чужого заголовка нет", !hdr_get("a: 1\n", "b", v, sizeof v));

    /* Имя, совпадающее с началом другого, не должно ловиться: `x-hwid` и
     * `x-hwid-not-supported` — разные вещи, и путать их значит объявить заглушкой исправный
     * ответ. */
    v[0] = 0;
    ck_true("частичное совпадение имени не считается",
            !hdr_get("x-hwid-not-supported: 1\n", "x-hwid", v, sizeof v));
}

static void t_ui_field(void) {
    unsigned long long n = 0;
    const char *ui = "upload=100; download=200; total=300; expire=1900000000";
    ck_true("upload прочитан", ui_field(ui, "upload", &n)); ck_num("upload", 100, (long long)n);
    ck_true("download прочитан", ui_field(ui, "download", &n)); ck_num("download", 200, (long long)n);
    ck_true("total прочитан", ui_field(ui, "total", &n)); ck_num("total", 300, (long long)n);
    ck_true("expire прочитан", ui_field(ui, "expire", &n)); ck_num("expire", 1900000000, (long long)n);
    ck_true("чужого поля нет", !ui_field(ui, "quota", &n));

    /* Только цифры. Панель отдаёт байты и unix-время; «unlimited» — чужое соглашение,
     * которое мы не читаем, и принять его за число значило бы показать остаток, которого
     * нет. */
    ck_true("не-число не считается числом", !ui_field("total=unlimited", "total", &n));
    /* Переполнение — это «числу верить нельзя», а не «число большое». */
    ck_true("переполнение отвергается",
            !ui_field("total=99999999999999999999999", "total", &n));
    /* Имя поля целиком, а не по началу: `total` и `totals` — разные поля. */
    ck_true("имя поля сверяется целиком", !ui_field("totals=5", "total", &n));
}

static void t_title(void) {
    char t[64];

    /* base64 с приставкой — так отдают Marzban, Remnawave и 3x-ui. Раскодируется той же
     * функцией, которой движок читает саму подписку; в оболочке ради этой одной строки
     * жила своя реализация base64 на awk. */
    sub_title("profile-title: base64:0KDQvtGB0YHQuNGP\n", t, sizeof t);
    ck("название из base64", "Россия", t);

    sub_title("profile-title: Riot VPN\n", t, sizeof t);
    ck("название открытым текстом", "Riot VPN", t);

    /* Запасной путь: часть панелей называет подписку только так. */
    sub_title("content-disposition: attachment; filename=\"Riot VPN\"\n", t, sizeof t);
    ck("название из content-disposition", "Riot VPN", t);

    /* Кавычки и управляющие символы вон: строка уедет в uci и в JSON. */
    sub_title("profile-title: a\"b\\c\n", t, sizeof t);
    ck("кавычки и обратный слэш убраны", "abc", t);

    sub_title("x-other: 1\n", t, sizeof t);
    ck("панель промолчала — названия нет", "", t);

    /* Обрезка по границе кодовой точки: половина буквы выглядит как поломка панели, а не как
     * длинное имя. Строка ниже длиннее предела в 48 байт ровно на середине буквы. */
    sub_title("profile-title: "
              "ААААААААААААААААААААААААААААААА\n", t, sizeof t);
    ck_true("обрезано по границе буквы", strlen(t) % 2 == 0);
    ck_true("и не длиннее предела", strlen(t) <= 48);
}

static void t_warn(void) {
    const char *w;
    w = device_warn("x-hwid-not-supported: 1\n", 1);
    ck_true("панель не увидела идентификатора — сказано", w && strstr(w, "заглушку"));
    w = device_warn("x-hwid-limit: 3\n", 1);
    ck_true("лимит устройств — сказано", w && strstr(w, "слот"));
    w = device_warn("", 0);
    ck_true("идентификатор не ушёл — сказано", w && strstr(w, "не ушёл"));
    w = device_warn("", 1);
    ck_true("сказать нечего — молчим", w == NULL);
}

/* ---- проверки: остаток трафика и точка отсчёта -------------------------------------- */

static void t_quota(void) {
    char info[512];
    snprintf(info, sizeof info, "%s/sub.userinfo", T);
    unlink(info);
    struct quota q;

    const char *h1 = "subscription-userinfo: upload=10; download=20; total=1000; expire=1900000000\n";
    ck_true("числа панели запомнены", quota_save(info, h1, 0, &q));
    ck_num("расход на момент первого наблюдения", 30, (long long)q.used0);
    long long at0 = q.at0;
    ck_true("точка отсчёта поставлена", q.has_at0 && at0 > 0);

    /* Тот же период: расход вырос, срок и объём те же. Точка отсчёта ОБЯЗАНА уцелеть —
     * иначе измеренный темп расхода, который набирается сутками, обнулялся бы при каждом
     * открытии обзора. */
    const char *h2 = "subscription-userinfo: upload=40; download=60; total=1000; expire=1900000000\n";
    quota_save(info, h2, 0, &q);
    ck_num("точка отсчёта уцелела", at0, q.at0);
    ck_num("и расход в ней прежний", 30, (long long)q.used0);

    /* Сменился срок — новый период. */
    const char *h3 = "subscription-userinfo: upload=40; download=60; total=1000; expire=1950000000\n";
    quota_save(info, h3, 0, &q);
    ck_num("смена срока начинает период заново", 100, (long long)q.used0);

    /* Сменился объём — сменился тариф, значит период тоже новый. */
    quota_save(info, h2, 0, &q);
    at0 = q.at0;
    const char *h4 = "subscription-userinfo: upload=40; download=60; total=2000; expire=1900000000\n";
    quota_save(info, h4, 0, &q);
    ck_num("смена объёма начинает период заново", 100, (long long)q.used0);

    /* Расход УМЕНЬШИЛСЯ — панель обнулила счётчик. Считать это тем же периодом значило бы
     * получить отрицательный темп расхода. */
    quota_save(info, h4, 0, &q);
    const char *h5 = "subscription-userinfo: upload=1; download=1; total=2000; expire=1900000000\n";
    quota_save(info, h5, 0, &q);
    ck_num("обнулённый счётчик начинает период заново", 2, (long long)q.used0);

    /* Заголовка нет — прежние числа СНИМАЮТСЯ. «Осталось 68 ГБ» на подписке, о которой
     * панель молчит, ничем не отличимо от правды и потому хуже честного незнания. */
    ck_true("панель промолчала — это не удача", !quota_save(info, "x: 1\n", 0, &q));
    ck("и файл снят", "", rd(info));

    /* А `keep` — это «спросили не до конца»: так зовёт проба заголовков, после которой при
     * неудаче будет обычная загрузка. Снимать прежние числа она права не имеет. */
    quota_save(info, h1, 0, &q);
    quota_save(info, "x: 1\n", 1, &q);
    ck_true("проба чужие числа не снимает", strstr(rd(info), "total=1000") != NULL);

    /* Заголовок есть, а смысла в нём нет: без объёма и без срока обзор нарисовал бы полосу
     * «осталось 0 из 0». Считаем это молчанием панели. */
    ck_true("заголовок без объёма и срока — молчание",
            !quota_save(info, "subscription-userinfo: upload=1; download=2\n", 0, &q));

    /* Пустое значение в файле — «панель этого не сообщала», и это не нуль: подписка без
     * ограничения объёма не должна выглядеть исчерпанной. */
    const char *h6 = "subscription-userinfo: upload=5; download=5; expire=1900000000\n";
    quota_save(info, h6, 0, &q);
    ck_true("объёма нет — в файле пусто, а не нуль", strstr(rd(info), "total=\n") != NULL);
    struct quota back;
    quota_read(info, &back);
    ck_true("и при чтении объём остаётся неназванным", !back.n.has_total);
    unlink(info);
}

/* ---- проверки: скачивание целиком, через поддельный curl ---------------------------- */

/* Поддельный curl. Ведёт себя как настоящий в том, что нам важно: понимает -D и -o, а тело
 * и заголовки берёт из файлов песочницы по имени запрошенного адреса. Так проверяется вся
 * дорожка команды, включая повтор за другим форматом. */
static void make_fake_curl(void) {
    char p[512];
    snprintf(p, sizeof p, "%s/bin", T);
    mkdir(p, 0755);
    snprintf(p, sizeof p, "%s/bin/curl", T);
    wr(p,
       "#!/bin/sh\n"
       "# Заглушка curl для стенда: тело и заголовки берутся из файлов песочницы.\n"
       "hdr=''; out=''; url=''; head=0\n"
       "while [ $# -gt 0 ]; do\n"
       "    case \"$1\" in\n"
       "        -D) hdr=\"$2\"; shift 2 ;;\n"
       "        -o) out=\"$2\"; shift 2 ;;\n"
       "        -H) shift 2 ;;\n"
       "        --max-time) shift 2 ;;\n"
       "        -fsSI) head=1; shift ;;\n"
       "        -fsSL) shift ;;\n"
       "        *) url=\"$1\"; shift ;;\n"
       "    esac\n"
       "done\n"
       "case \"$url\" in\n"
       "    */json) key=json ;;\n"
       "    *) key=main ;;\n"
       "esac\n"
       "[ -f \"$SANDBOX/rc.$key\" ] && exit \"$(cat \"$SANDBOX/rc.$key\")\"\n"
       "[ -n \"$hdr\" ] && [ -f \"$SANDBOX/hdr.$key\" ] && cp \"$SANDBOX/hdr.$key\" \"$hdr\"\n"
       "if [ \"$head\" = 0 ] && [ -n \"$out\" ]; then\n"
       "    [ -f \"$SANDBOX/body.$key\" ] || exit 1\n"
       "    cp \"$SANDBOX/body.$key\" \"$out\"\n"
       "fi\n"
       "exit 0\n");
    chmod(p, 0755);
    char path[1024];
    snprintf(path, sizeof path, "%s/bin:%s", T, getenv("PATH") ? getenv("PATH") : "/bin");
    setenv("PATH", path, 1);
    setenv("SANDBOX", T, 1);
}

static void fixture(const char *key, const char *what, const char *text) {
    char p[512];
    snprintf(p, sizeof p, "%s/%s.%s", T, what, key);
    if (!text) { unlink(p); return; }
    wr(p, text);
}

static char g_url[512], g_out[512], g_info[512];
static int g_rc;
static int call_fetch(void) { return g_rc = cmd_sub_fetch(g_url, g_out, g_info); }
static int call_quota(void) { return g_rc = cmd_sub_quota(g_url, g_info); }

static void t_fetch(void) {
    make_fake_curl();
    mkiface("eth0", "c4:41:1e:dd:ee:01", 1);
    snprintf(g_out, sizeof g_out, "%s/sub.txt", T);
    snprintf(g_info, sizeof g_info, "%s/sub.userinfo", T);
    snprintf(g_url, sizeof g_url, "https://panel.example/sub");
    unlink(g_out); unlink(g_info);

    const char *LINKS =
        "vless://11111111-2222-3333-4444-555555555555@1.2.3.4:443?"
        "type=tcp&security=reality&sni=a.example&pbk=Zm9vYmFyZm9vYmFyZm9vYmFyZm9vYmFyZm9vYmFyMDA&"
        "sid=ab12&flow=xtls-rprx-vision#\xd0\x9d\xd0\xbe\xd0\xb4\n";

    /* Обычная удача: тело на месте, заголовки прочитаны, узлы посчитаны той же функцией,
     * которой их читает подъём туннеля. */
    fixture("main", "body", LINKS);
    fixture("main", "hdr",
            "HTTP/1.1 200 OK\r\n"
            "profile-title: base64:0KDQvtGB0YHQuNGP\r\n"
            "subscription-userinfo: upload=1; download=2; total=1000; expire=1900000000\r\n");
    fixture("main", "rc", NULL);
    char *out = cap(call_fetch);
    ck_true("подписка скачана", has(out, "\"ok\":true"));
    ck_true("узел посчитан пригодным", has(out, "\"usable\":1"));
    ck_true("название взято у панели", has(out, "\"title\":\"Россия\""));
    ck_true("остаток трафика в том же ответе", has(out, "\"total\":\"1000\""));
    ck_true("идентификатор устройства назван", has(out, "\"hwid\":\"splify2-"));
    ck_true("и он ушёл в запрос", has(out, "\"hwid_sent\":true"));
    ck_true("файл узлов на месте", strstr(rd(g_out), "vless://") != NULL);
    ck_true("остаток записан рядом", strstr(rd(g_info), "total=1000") != NULL);

    /* Временные файлы убраны. Оставленный `.hdr` — это заголовки панели, лежащие в /etc
     * навсегда; оставленный `.tmp` — половина подписки, которую следующий запуск примет за
     * целую. */
    char p[640];
    snprintf(p, sizeof p, "%s.tmp", g_out);
    ck_true("временный файл убран", access(p, F_OK) != 0);
    snprintf(p, sizeof p, "%s.hdr", g_out);
    ck_true("заголовки не остались на диске", access(p, F_OK) != 0);

    /* ПОВТОР ЗА ДРУГИМ ФОРМАТОМ. Панель отдала заглушку — ссылки чужого протокола на
     * localhost, — то есть пригодных узлов нет ни одного. Тогда тот же адрес спрашивается с
     * суффиксом /json, и в ответе стоит именно та ссылка, по которой обновлять дальше. */
    fixture("main", "body", "ss://YWVzOnB3ZA==@127.0.0.1:1234#Неправильный клиент\n");
    fixture("json", "body",
            "{\"outbounds\":[{\"protocol\":\"vless\",\"settings\":{\"vnext\":[{"
            "\"address\":\"5.6.7.8\",\"port\":443,\"users\":[{"
            "\"id\":\"11111111-2222-3333-4444-555555555555\",\"flow\":\"xtls-rprx-vision\"}]}]},"
            "\"streamSettings\":{\"network\":\"tcp\",\"security\":\"reality\","
            "\"realitySettings\":{\"serverName\":\"a.example\","
            "\"publicKey\":\"Zm9vYmFyZm9vYmFyZm9vYmFyZm9vYmFyZm9vYmFyMDA\",\"shortId\":\"ab12\"}}}]}");
    fixture("json", "hdr", "HTTP/1.1 200 OK\r\nprofile-title: JSON\r\n");
    out = cap(call_fetch);
    ck_true("заглушка распознана и формат перезапрошен", has(out, "\"usable\":1"));
    ck_true("в ответе ссылка на /json", has(out, "/sub/json"));
    ck_true("и заголовки взяты от НЕГО", has(out, "\"title\":\"JSON\""));
    ck_true("файл — тот, что приехал вторым", strstr(rd(g_out), "outbounds") != NULL);

    /* Повтор не делается, если уже просили JSON: второй такой же запрос ничего не добавит, а
     * адрес вида «…/json/json» панель не знает вовсе. */
    snprintf(g_url, sizeof g_url, "https://panel.example/sub/json");
    fixture("json", "body", "ss://YWVzOnB3ZA==@127.0.0.1:1234#нет\n");
    out = cap(call_fetch);
    ck_true("у /json второго повтора нет", has(out, "\"usable\":0"));
    ck_true("и ссылка в ответе прежняя", has(out, "\"url\":\"https://panel.example/sub/json\""));

    /* Отказ панели НЕ ТРОГАЕТ прежнюю подписку: туннель работает по тому, что скачано, и
     * подменять рабочие узлы пустотой из-за упавшей сети нельзя. */
    snprintf(g_url, sizeof g_url, "https://panel.example/sub");
    wr(g_out, "vless://прежнее\n");
    fixture("main", "rc", "22");
    fixture("json", "rc", "22");
    out = cap(call_fetch);
    ck_true("отказ назван отказом", has(out, "\"ok\":false"));
    ck_true("прежняя подписка не тронута", strstr(rd(g_out), "прежнее") != NULL);
    fixture("main", "rc", NULL);
    fixture("json", "rc", NULL);

    /* Пустой ответ — тоже отказ, а не «скачали пустую подписку»: пустой файл узлов означает
     * туннель, который никуда не поднимется, причём молча. */
    fixture("main", "body", "");
    out = cap(call_fetch);
    ck_true("пустой ответ панели — отказ", has(out, "\"ok\":false"));
    ck_true("и прежняя подписка снова не тронута", strstr(rd(g_out), "прежнее") != NULL);

    /* Не ссылка — отказ до всякой работы: подставлять «https://» за человека значило бы
     * скачать не то, что он назвал. */
    snprintf(g_url, sizeof g_url, "panel.example/sub");
    /* Отказ уходит в stderr — там же, где движок отвечает всякому, кто позвал его неверно.
     * Строка в выводе стенда поэтому ожидаема и не означает провала. */
    cap(call_fetch);
    ck_num("адрес без схемы отвергается", 2, g_rc);

    /* Путь остатка трафика выводится из пути подписки тем же правилом, каким его выводит
     * splify2: иначе два файла разъехались бы по каталогам при переопределённом пути. */
    char derived[512];
    info_for("/etc/steer/sub.txt", derived, sizeof derived);
    ck("остаток лежит рядом с подпиской", "/etc/steer/sub.userinfo", derived);
    info_for("/etc/steer/subs/second", derived, sizeof derived);
    ck("а без «.txt» — просто рядом", "/etc/steer/subs/second.userinfo", derived);
}

static void t_quota_cmd(void) {
    snprintf(g_url, sizeof g_url, "https://panel.example/sub");
    snprintf(g_info, sizeof g_info, "%s/sub.userinfo", T);
    unlink(g_info);

    /* Проба заголовков телом не платит: HEAD отдаёт только заголовки, и подписка на десятки
     * узлов ради двух чисел не качается. */
    fixture("main", "hdr",
            "HTTP/1.1 200 OK\r\n"
            "subscription-userinfo: upload=7; download=3; total=500; expire=1900000000\r\n");
    fixture("main", "body", NULL);
    char *out = cap(call_quota);
    ck_true("остаток спрошен", has(out, "\"asked\":true"));
    ck_true("и получен", has(out, "\"total\":\"500\""));
    ck_true("подписка при этом не качалась", strstr(rd(g_info), "total=500") != NULL);

    /* Панель промолчала — это НЕ отказ команды: человек ничего не сделал не так, и код
     * возврата обязан остаться нулевым, иначе интерфейс покажет ошибку на исправной
     * настройке. */
    fixture("main", "hdr", "HTTP/1.1 200 OK\r\n");
    fixture("main", "body", "vless://x\n");
    out = cap(call_quota);
    ck_num("молчание панели — не отказ команды", 0, g_rc);
    ck_true("и об этом сказано словами", has(out, "не сообщила остаток"));

    /* Выбросные файлы пробы убраны: они лежат рядом с настройками, и оставленное тело
     * подписки следующий разбор мог бы принять за саму подписку. */
    char p[640];
    snprintf(p, sizeof p, "%s.probe", g_info);
    ck_true("выбросное тело убрано", access(p, F_OK) != 0);
    snprintf(p, sizeof p, "%s.head", g_info);
    ck_true("заголовки пробы убраны", access(p, F_OK) != 0);
}

/* ---- проверки: заголовки об устройстве ---------------------------------------------
 *
 * ЗАЧЕМ ЭТО ПРОВЕРЯТЬ. Значение уезжает в HTTP-заголовок, а модель роутера приходит из файла,
 * который пишет не наш код: перевод строки внутри значения — это вставка ЧУЖОГО заголовка в
 * запрос.
 *
 * И вторая причина, историческая. В оболочке чистка была написана как `tr -cd '[:print:]'`, и
 * это работает у coreutils, но НЕ у busybox: тот классов не знает и разбирает «[:print:]» как
 * обычный набор символов — то есть оставляет от строки только буквы, из которых составлено имя
 * класса. На роутере «TP-Link Archer C6U v1» превращалось в «inrr», а «OpenWrt 25.12.5» — в
 * «pnrt», и именно это уезжало в панель. Человек видел в списке устройств бессмыслицу и не мог
 * найти среди телефонов свой роутер — ровно то, ради чего эти заголовки и посылаются.
 *
 * Стенд на машине разработчика этого не замечал: на GNU tr обе строки проходят целиком.
 * Здесь такой ловушки нет по построению — байты сравниваются напрямую. */
static void t_device_hdrs(void) {
    char v[80];
    char p[512];

    dev_os(v, sizeof v);
    ck("версия системы не искажается чисткой", "OpenWrt 25.12.5", v);
    dev_model(v, sizeof v);
    ck("модель не искажается чисткой", "Xiaomi AX3000T", v);

    /* Кириллица выбрасывается намеренно: в заголовке HTTP она приезжает панели байтами UTF-8
     * и показывается там мусором, поэтому лучше её отсутствие. */
    snprintf(p, sizeof p, "%s/model", T);
    wr(p, "тестAX3000T\n");
    dev_model(v, sizeof v);
    ck("кириллица в модели выбрасывается", "AX3000T", v);

    /* И то, ради чего чистка вообще существует: перевод строки внутри значения — это вставка
     * чужого заголовка в запрос. Здесь защиты две, и вторая строже первой: файл читается
     * ПОСТРОЧНО, поэтому всё после перевода строки не доходит до чистки вовсе. В оболочке так
     * не было — там значение бралось целиком через `cat`, и защитой была одна чистка. */
    wr(p, "aaa\nX-Evil: 1\n");
    dev_model(v, sizeof v);
    ck("после перевода строки в заголовок не попадает ничего", "aaa", v);
    /* И сама чистка на месте: строка без перевода, но с управляющим символом. */
    wr(p, "aaa\rX-Evil: 1\n");
    dev_model(v, sizeof v);
    ck("возврат каретки из значения убран", "aaaX-Evil: 1", v);

    /* Файла нет — честное умолчание, а не пустой заголовок: пустое значение панель показала бы
     * как устройство без имени. */
    unlink(p);
    dev_model(v, sizeof v);
    ck("без файла модели — честное умолчание", "router", v);
    wr(p, "Xiaomi AX3000T\n");

    /* Длина ограничена: заголовок — не место для страницы текста. */
    snprintf(p, sizeof p, "%s/model", T);
    wr(p, "0123456789012345678901234567890123456789"
          "0123456789012345678901234567890123456789\n");
    dev_model(v, sizeof v);
    ck_num("значение обрезано по пределу", 64, (long long)strlen(v));
    wr(p, "Xiaomi AX3000T\n");

    /* Версия системы читается из файла в кавычках — так её и пишет OpenWrt. */
    snprintf(p, sizeof p, "%s/openwrt_release", T);
    wr(p, "DISTRIB_ID='OpenWrt'\nDISTRIB_RELEASE=\"24.10.0\"\n");
    dev_os(v, sizeof v);
    ck("кавычки вокруг версии — часть формата, а не значение", "OpenWrt 24.10.0", v);
    unlink(p);
    dev_os(v, sizeof v);
    ck("без файла версии — просто OpenWrt", "OpenWrt", v);
    wr(p, "DISTRIB_RELEASE='25.12.5'\n");
}

/* ---- проверки: несколько подписок --------------------------------------------------
 *
 * Подписок на роутере бывает несколько: у человека две панели, и локации из обеих он
 * складывает в один пул. Движок про этот учёт ничего не знает и знать не должен — ему
 * называют пути, — но именно поэтому пути обязаны соблюдаться БУКВАЛЬНО. Ошибка здесь
 * молчаливая в худшем виде: остаток второй панели, записанный поверх остатка первой,
 * выглядит как правда, а узлы, скачанные в чужой файл, уводят трафик к другому поставщику. */
static void t_multi(void) {
    char out2[512], info2[512], derived[512];
    snprintf(out2, sizeof out2, "%s/subs-green.txt", T);
    snprintf(info2, sizeof info2, "%s/subs-green.userinfo", T);
    /* Путь остатка, который движок ВЫВЕЛ БЫ сам, — и он не должен быть использован, когда
     * названный путь другой. */
    info_for(out2, derived, sizeof derived);
    snprintf(info2, sizeof info2, "%s/elsewhere.userinfo", T);
    ck_true("выведенный и названный пути различаются", strcmp(derived, info2) != 0);

    fixture("main", "body", "vless://11111111-2222-3333-4444-555555555555@1.2.3.4:443?"
            "type=tcp&security=reality&sni=a.example&"
            "pbk=Zm9vYmFyZm9vYmFyZm9vYmFyZm9vYmFyZm9vYmFyMDA&sid=ab12#\xd0\x9d\n");
    fixture("main", "hdr",
            "HTTP/1.1 200 OK\r\n"
            "subscription-userinfo: upload=1; download=1; total=9; expire=1900000000\r\n");
    unlink(out2); unlink(info2); unlink(derived);

    snprintf(g_url, sizeof g_url, "https://second.invalid/sub");
    snprintf(g_out, sizeof g_out, "%s", out2);
    snprintf(g_info, sizeof g_info, "%s", info2);
    cap(call_fetch);
    ck_true("подписка легла по названному пути", strstr(rd(out2), "vless://") != NULL);
    ck_true("остаток лёг по НАЗВАННОМУ пути", strstr(rd(info2), "total=9") != NULL);
    ck_true("а по выведенному не появился", access(derived, F_OK) != 0);

    /* Первая подписка при этом не тронута: у неё свои файлы, и работа со второй в них не
     * заглядывает. */
    char first[512], firstinfo[512];
    snprintf(first, sizeof first, "%s/sub.txt", T);
    snprintf(firstinfo, sizeof firstinfo, "%s/sub.userinfo", T);
    wr(first, "vless://первая\n");
    wr(firstinfo, "total=111\n");
    cap(call_fetch);
    ck_true("файл первой подписки не тронут", strstr(rd(first), "первая") != NULL);
    ck_true("и её остаток тоже", strstr(rd(firstinfo), "total=111") != NULL);
}

int main(void) {
    snprintf(T, sizeof T, "/tmp/subfetchmatch.%d", (int)getpid());
    mkdir(T, 0755);
    char p[512];
    snprintf(p, sizeof p, "%s/sys", T);
    mkdir(p, 0755);
    setenv("STEER_SYSNET", p, 1);
    snprintf(p, sizeof p, "%s/openwrt_release", T);
    wr(p, "DISTRIB_RELEASE='25.12.5'\n");
    setenv("STEER_OPENWRT_RELEASE", p, 1);
    snprintf(p, sizeof p, "%s/model", T);
    wr(p, "Xiaomi AX3000T\n");
    setenv("STEER_SYSINFO_MODEL", p, 1);

    t_hwid();
    t_headers();
    t_ui_field();
    t_title();
    t_warn();
    t_quota();
    t_fetch();
    t_quota_cmd();
    t_device_hdrs();
    t_multi();

    /* Песочница убирается снаружи скриптом стендов: оставленный каталог после ПРОВАЛА
     * помогает понять, что именно записалось. */
    printf("\n%d проверок пройдено", g_pass);
    if (g_fail) { printf(", %d ПРОВАЛЕНО\n", g_fail); return 1; }
    printf("\nвсе проверки прошли\n");
    return 0;
}
