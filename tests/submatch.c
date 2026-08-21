/* Разбор подписки: что именно steer видит в ссылках vless:// и как считает то, чего не взял.
 *
 * Зачем отдельным тестом. sub.c — единственное место, где в движок попадает чужой текст
 * из интернета: подписка приходит с панели, формат её никто не гарантирует, а результат
 * разбора расходится сразу двум потребителям — интерфейсу (показать список узлов) и
 * сторожу (выбрать живой). Ошибка здесь не выглядит как сбой: узел просто не появляется
 * в списке, и человек ищет причину в панели, в подписке, в сети — где угодно, кроме
 * парсера, который его молча не понял.
 *
 * Поэтому проверяется не «разбирает ли валидную ссылку», а арифметика: заголовок sub.c
 * обещает, что расхождение «26 узлов в подписке, 17 у steer» объясняется ЧИСЛОМ, а не
 * догадкой. Значит usable + skipped + foreign обязано сходиться с числом ссылок в тексте
 * при любом их виде, включая те, которые парсер не осилил.
 *
 * Файл включает исходник (#include "../src/ext/sub.c") — тот же приём, что в dnsmatch.c
 * и specmatch.c: он даёт доступ к статике и не требует ни сети, ни mbedtls, ни docker,
 * которых у make test нет (см. R-014). */
#include <stdio.h>
#include <string.h>

#include "../src/ext/sub.c"
/* Вывод UUID живёт в vless_proto.c, а проверка пригодности — в sub.c, и стенду нужны
 * оба: ссылка из панели обязана и пройти проверку пригодности, и дать те самые 16 байт,
 * которые уедут в заголовок запроса. Исходник включается тем же приёмом, что и sub.c —
 * mbedtls он не требует (см. заголовок vless_proto.c), поэтому стенд остаётся в обычном
 * make test. */
#include "../src/ext/vless_proto.c"

static int g_pass, g_fail;

/* UUID в каноническую запись: сравнивать 16 байт глазами в отчёте стенда нельзя. */
static const char *uuid_str(const unsigned char u[16]) {
    static char s[37];
    snprintf(s, sizeof(s),
             "%02x%02x%02x%02x-%02x%02x-%02x%02x-%02x%02x-%02x%02x%02x%02x%02x%02x",
             u[0], u[1], u[2], u[3], u[4], u[5], u[6], u[7],
             u[8], u[9], u[10], u[11], u[12], u[13], u[14], u[15]);
    return s;
}

static void check(const char *name, const char *expected, const char *actual) {
    if (!strcmp(expected, actual)) {
        g_pass++;
        printf("%-56s ok\n", name);
    } else {
        g_fail++;
        printf("FAIL %s\n  ожидалось: %s\n  получено:  %s\n", name, expected, actual);
    }
}

static void check_n(const char *name, long expected, long actual) {
    char e[32], a[32];
    snprintf(e, sizeof(e), "%ld", expected);
    snprintf(a, sizeof(a), "%ld", actual);
    check(name, e, a);
}

int main(void) {
    /* ---- base64: то, чем подписки реально приходят ------------------------- */
    {
        char out[64];
        /* Без выравнивающих '=' и с переводом строки посередине: и то, и другое
         * встречается у панелей, и оба должны раскодироваться, а не обрезаться. */
        size_t n = b64_decode("dmxlc3M6\nLy9h", 13, out, sizeof(out));
        check("base64 без padding и с переводом строки", "vless://a", out);
        check_n("base64: длина результата", 9, (long)n);

        /* URL-safe алфавит: '-' вместо '+', '_' вместо '/'. */
        n = b64_decode("Pz8_", 4, out, sizeof(out));
        check("base64 URL-safe: _ читается как /", "??\?", out);
        check_n("base64 URL-safe: длина", 3, (long)n);
    }

    /* ---- одна ссылка: поля попадают туда, куда обещано --------------------- */
    {
        struct vless_node n;
        int rc = vless_parse_url(
            "vless://11111111-2222-3333-4444-555555555555@example.com:8443"
            "?security=reality&sni=www.microsoft.com&pbk=ABCDEF&sid=aa11&fp=chrome"
            "&type=tcp&flow=xtls-rprx-vision#%D0%A3%D0%B7%D0%B5%D0%BB", &n);
        check_n("reality-ссылка: узел пригоден", 0, rc);
        check("reality: host", "example.com", n.host);
        check_n("reality: port", 8443, (long)n.port);
        check("reality: uuid", "11111111-2222-3333-4444-555555555555", n.uuid);
        check("reality: sni", "www.microsoft.com", n.sni);
        check("reality: flow", "xtls-rprx-vision", n.flow);
        /* Имя приходит процентно-закодированным: без раскодирования интерфейс
         * показывает %D0%A3... вместо имени. */
        check("имя раскодировано из процентной формы", "Узел", n.name);
    }

    /* ---- непригодные узлы: пропущены с причиной, а не выброшены ------------ */
    {
        struct vless_node n;
        check_n("security=tls: пропущен",
                1, vless_parse_url("vless://u@h:443?security=tls#x", &n));
        check("security=tls: причина названа", "security=tls не поддержан", n.skip_reason);

        check_n("reality без pbk: пропущен",
                1, vless_parse_url("vless://u@h:443?security=reality&sni=a.com#x", &n));
        check("reality без pbk: причина названа", "reality без pbk или sni", n.skip_reason);

        check_n("транспорт ws: пропущен",
                1, vless_parse_url("vless://u@h:443?security=none&type=ws#x", &n));
        check("транспорт ws: причина названа", "транспорт ws не поддержан", n.skip_reason);

        /* security опущен вовсе — это VLESS без TLS, он поддержан (см. sub.c). */
        check_n("security опущен: узел пригоден",
                0, vless_parse_url("vless://u@h:443#x", &n));
        check("security опущен: поле заполнено умолчанием", "none", n.security);
        check("тип по умолчанию tcp", "tcp", n.type);
    }

    /* ---- склеенные ссылки: панель может не поставить разделитель (I-028) ----
     *
     * Отступ к началу следующей ссылки шёл «пока слева буквы и цифры» и съедал хвост
     * имени: в «#onevless://…» граница вставала перед «onevless», вторая ссылка
     * переставала начинаться с vless:// и уходила в чужие протоколы. Терялся каждый
     * второй узел, а первому обнулялось имя. */
    {
        struct vless_node nodes[8];
        struct vless_sub_stats st;
        size_t n = vless_parse_sub("vless://a@h1:443#one" "vless://b@h2:443#two",
                                   nodes, 8, &st);
        check_n("две склеенные ссылки разобраны как две", 2, (long)n);
        check("первая: имя не съело вторую", "one", nodes[0].name);
        check("вторая: хост свой", "h2", nodes[1].host);
        check_n("склеенные: чужих протоколов нет", 0, (long)st.foreign);
    }
    {
        /* Имя без '#'-хвоста: граница обязана встать по схеме, не по цифрам порта. */
        struct vless_node nodes[8];
        struct vless_sub_stats st;
        size_t n = vless_parse_sub("vless://a@h1:443" "vless://b@h2:8443",
                                   nodes, 8, &st);
        check_n("склейка без имён: две ссылки", 2, (long)n);
        check_n("первой не откусили порт", 443, (long)nodes[0].port);
        check_n("второй достался свой порт", 8443, (long)nodes[1].port);
    }
    {
        /* Имя, оканчивающееся именем схемы, — граница всё равно по байтам перед '://'. */
        struct vless_node nodes[8];
        struct vless_sub_stats st;
        size_t n = vless_parse_sub("vless://a@h1:443#Express" "ss://b@h2:443#other",
                                   nodes, 8, &st);
        check_n("имя кончается на имя схемы: узел один", 1, (long)n);
        check("имя не обрезано", "Express", nodes[0].name);
        check_n("следующая ссылка учтена как чужая", 1, (long)st.foreign);
    }

    /* ---- арифметика подписки (I-027) --------------------------------------
     *
     * Заголовок sub.c обещает: «в ней 26 узлов, а steer видит 17» должно объясняться
     * цифрой. Значит ни одна ссылка не имеет права исчезнуть, не попав ни в один
     * счётчик. До правки исчезали две: IPv6-литерал в host (первое двоеточие
     * оказывается внутри скобок, порт читается как 0) и ссылка с портом 0. Обе
     * возвращают -1, а -1 не считался нигде — узел пропадал из подписки бесследно. */
    {
        struct vless_node nodes[16];
        struct vless_sub_stats st;
        const char *sub =
            "vless://a@1.2.3.4:443?security=reality&pbk=K&sni=x.com#ok\n"
            "vless://b@[2001:db8::1]:443?security=reality&pbk=K&sni=x.com#ipv6\n"
            "vless://c@5.6.7.8:0?security=reality&pbk=K&sni=x.com#zero-port\n"
            "vless://d@9.9.9.9:443?security=tls#tls\n"
            "hy2://e@10.0.0.1:443#foreign\n";
        size_t n = vless_parse_sub(sub, nodes, 16, &st);
        check_n("пригодных узлов", 1, (long)n);
        check_n("чужих протоколов", 1, (long)st.foreign);
        /* Четыре ссылки vless: одна взята, три нет — и все три обязаны быть в счётчике. */
        check_n("непригодных ссылок vless учтено", 3, (long)st.skipped);
        check_n("сумма сходится с числом ссылок в тексте",
                5, (long)(n + st.skipped + st.foreign));
    }

    /* Ссылка длиннее буфера строки тоже исчезала бесследно: ветка длины отбрасывала
     * её раньше разбора. Считается как непригодная — она и есть непригодная. */
    {
        struct vless_node nodes[4];
        struct vless_sub_stats st;
        char big[4096];
        int k = snprintf(big, sizeof(big), "vless://u@h:443?sni=");
        memset(big + k, 'x', 2200);
        big[k + 2200] = '\0';
        size_t n = vless_parse_sub(big, nodes, 4, &st);
        check_n("слишком длинная ссылка: не взята", 0, (long)n);
        check_n("слишком длинная ссылка: учтена как непригодная", 1, (long)st.skipped);
        check("слишком длинная ссылка: причина названа", "ссылка длиннее 2048 байт",
              st.reasons[0].reason);
    }

    /* ---- причины непригодности: сгруппированы и сходятся (splicicd#16) -----
     *
     * Движок знал причину и не говорил её: skip_reason читал только этот стенд, а
     * cmd_vless_nodes печатал «пригодно 0, пропущено 26». Человек с подпиской из
     * tls-узлов делал единственный возможный вывод — «не подключается».
     *
     * Проверяется не наличие поля, а два свойства, на которых оно живёт: причины
     * СХОДЯТСЯ (сумма count равна skipped — иначе часть узлов пропала бы уже в
     * объяснении) и СХЛОПЫВАЮТСЯ по тексту (три tls-узла — одна строка со счётчиком,
     * а не три одинаковых). */
    {
        struct vless_node nodes[16];
        struct vless_sub_stats st;
        const char *sub =
            "vless://a@1.1.1.1:443?security=tls#Первый\n"
            "vless://b@2.2.2.2:443?security=tls#Второй\n"
            "vless://c@3.3.3.3:443?security=tls#Третий\n"
            "vless://d@4.4.4.4:443?type=ws&security=none#Вебсокет\n"
            "vless://e@[2001:db8::1]:443?security=none#IPv6\n"
            "vless://f@6.6.6.6:443?security=reality&pbk=K&sni=x.com#Годный\n";
        size_t n = vless_parse_sub(sub, nodes, 16, &st);
        check_n("причины: пригоден один узел", 1, (long)n);
        check_n("причины: непригодных пять", 5, (long)st.skipped);
        check_n("причины: разных причин три", 3, (long)st.reasons_n);
        check_n("причины: ничего не потерялось", 0, (long)st.reasons_dropped);

        size_t sum = 0;
        for (size_t i = 0; i < st.reasons_n; i++) sum += st.reasons[i].count;
        check_n("причины: сумма сходится со skipped", (long)st.skipped, (long)sum);

        /* Порядок — по первому появлению, поэтому он предсказуем и его можно
         * проверять: иначе стенд молчал бы о том, что причины перепутались. */
        check("первая причина: security=tls", "security=tls не поддержан",
              st.reasons[0].reason);
        check_n("tls схлопнут в одну строку со счётчиком 3", 3, (long)st.reasons[0].count);
        check("tls: пример — имя первого узла", "Первый", st.reasons[0].example);
        check("вторая причина: транспорт ws", "транспорт ws не поддержан",
              st.reasons[1].reason);
        check("ws: пример — имя своего узла", "Вебсокет", st.reasons[1].example);
        /* IPv6-литерал разбор не осиливает и до проверки пригодности не доходит —
         * причину называет уже сам обход подписки, иначе ссылка снова стала бы
         * «пропущено на единицу больше» без объяснения. */
        check("третья причина: ссылка не разобрана", "ссылка не разобрана",
              st.reasons[2].reason);
    }

    /* Причин больше, чем ведёр: девятая обязана попасть в reasons_dropped, а не
     * потеряться. Сумма count плюс dropped по-прежнему равна skipped — на этом
     * свойстве держится доверие к числу «пропущено N». */
    {
        struct vless_node nodes[16];
        struct vless_sub_stats st;
        char sub[1024];
        size_t off = 0;
        for (int i = 1; i <= 9; i++)
            off += (size_t)snprintf(sub + off, sizeof(sub) - off,
                                    "vless://u@h%d:443?security=s%d#n%d\n", i, i, i);
        size_t n = vless_parse_sub(sub, nodes, 16, &st);
        check_n("переполнение: пригодных нет", 0, (long)n);
        check_n("переполнение: непригодных девять", 9, (long)st.skipped);
        check_n("переполнение: причин влезло восемь", VLESS_SKIP_REASONS,
                (long)st.reasons_n);
        check_n("переполнение: девятая учтена отдельно", 1, (long)st.reasons_dropped);
        size_t sum = st.reasons_dropped;
        for (size_t i = 0; i < st.reasons_n; i++) sum += st.reasons[i].count;
        check_n("переполнение: сумма всё равно сходится", (long)st.skipped, (long)sum);
    }

    /* ---- идентификатор пользователя: правило XRAY, а не «строгий hex» ------
     *
     * Панели выдают узлы, у которых id — короткое имя вроде «TMG_74317ba5f91», и это
     * законный VLESS: Xray в common/uuid/uuid.go смотрит на ДЛИНУ строки. 32-36 знаков
     * разбираются как шестнадцатеричный UUID (дефисы необязательны), 1-30 знаков —
     * ВЫВОДЯТСЯ: sha1(16 нулевых байт || строка), первые 16 байт, версия 5 и вариант
     * в байтах 6 и 8. Ровно 31, длиннее 36 и пустая строка — отказ.
     *
     * До правки движок требовал строгий hex, и такой узел проходил проверку пригодности
     * (то есть попадал в кандидаты и тратил попытки сторожа), а падал молча уже на
     * подключении: «UUID неразборчив» в пробе и conn_drop без причины в туннеле. */
    {
        struct vless_node n;
        int rc = vless_parse_url(
            "vless://TMG_74317ba5f91@203.0.113.7:443?type=xhttp&encryption=none"
            "&path=%2FdRh-l74-MZE3z&host=amazon.com&mode=auto&security=reality"
            "&fp=firefox&pbk=KEY&sni=amazon.com&sid=9392&spx=%2F"
            "#TMG_74317ba5f91-%D0%93%D0%B5%D1%80%D0%BC%D0%B0%D0%BD%D0%B8%D1%8F", &n);
        check_n("ссылка панели с коротким id: узел пригоден", 0, rc);
        check("ссылка панели: id взят как есть", "TMG_74317ba5f91", n.uuid);

        unsigned char u[16] = { 0 };
        check_n("короткий id разобран", 0, vless_uuid_parse(n.uuid, u));
        /* Вектор посчитан независимо от этого кода — питоном по алгоритму Xray. */
        check("короткий id даёт UUID версии 5",
              "dd4748e6-1f48-5b36-bbc6-656b42ccfd75", uuid_str(u));
    }

    /* SHA-1 прибит к опубликованному вектору. Реализация в vless_proto.c своя (mbedtls
     * этого проекта собирается без SHA-1 — см. комментарий там), и без этой проверки
     * ошибка в ней выглядела бы как «сервер не признаёт пользователя»: 16 байт уходят
     * не те, а сказать об этом некому. */
    {
        unsigned char d[20];
        char hex[41];
        check_n("sha1: сообщение длиной с блок отвергнуто", -1,
                sha1_short((const unsigned char *)"", 56, d));
        check_n("sha1(\"abc\") посчитан", 0, sha1_short((const unsigned char *)"abc", 3, d));
        for (int i = 0; i < 20; i++) snprintf(hex + 2 * i, 3, "%02x", d[i]);
        check("sha1(\"abc\") — вектор NIST",
              "a9993e364706816aba3e25717850c26c9cd0d89d", hex);
    }

    /* Обычный UUID: с дефисами и без — одни и те же 16 байт. Оба написания встречаются
     * в подписках, и разойтись они не имеют права. */
    {
        unsigned char a[16] = { 0 }, b[16] = { 0 };
        check_n("UUID 36 знаков с дефисами разобран", 0,
                vless_uuid_parse("11111111-2222-3333-4444-555555555555", a));
        check_n("UUID 32 знака без дефисов разобран", 0,
                vless_uuid_parse("11111111222233334444555555555555", b));
        check("UUID с дефисами: те же байты", "11111111-2222-3333-4444-555555555555",
              uuid_str(a));
        check_n("UUID без дефисов даёт то же", 0, memcmp(a, b, 16));
        /* Заглавные знаки Xray принимает (hex.Decode), значит принимаем и мы. */
        unsigned char c[16] = { 0 };
        check_n("UUID заглавными разобран", 0,
                vless_uuid_parse("AABBCCDD-EEFF-0011-2233-445566778899", c));
        check("UUID заглавными: байты те же", "aabbccdd-eeff-0011-2233-445566778899",
              uuid_str(c));
    }

    /* Границы длины — то, из-за чего правило нельзя писать как «сначала hex, потом
     * вывод»: 32 и 36 разбираются, 30 выводится, 31 и 37 отвергаются, и всё это
     * решается ДЛИНОЙ строки, а не тем, похожа ли она на шестнадцатеричную. */
    {
        unsigned char u[16] = { 0 };
        char s30[31], s31[32], s37[38];
        memset(s30, 'a', 30); s30[30] = '\0';
        memset(s31, 'a', 31); s31[31] = '\0';
        memset(s37, 'a', 37); s37[37] = '\0';

        check_n("30 знаков: форма — вывод", VLESS_UUID_DERIVED, vless_uuid_form(s30));
        check_n("30 знаков: UUID выведен", 0, vless_uuid_parse(s30, u));
        /* Вектор посчитан питоном по алгоритму Xray, а не этим кодом. */
        check("30 знаков: вывод совпал", "d20a3bd4-9d58-52e0-8caa-820ca42d1ad0",
              uuid_str(u));

        check_n("31 знак: форма — щель", VLESS_UUID_GAP, vless_uuid_form(s31));
        check_n("31 знак: разбора нет", -1, vless_uuid_parse(s31, u));

        check_n("37 знаков: форма — слишком длинно", VLESS_UUID_TOOLONG,
                vless_uuid_form(s37));
        check_n("37 знаков: разбора нет", -1, vless_uuid_parse(s37, u));

        check_n("32 знака hex: форма — UUID", VLESS_UUID_HEX,
                vless_uuid_form("0123456789abcdef0123456789abcdef"));
        check_n("36 знаков с дефисами: форма — UUID", VLESS_UUID_HEX,
                vless_uuid_form("01234567-89ab-cdef-0123-456789abcdef"));

        check_n("пусто: форма — пусто", VLESS_UUID_EMPTY, vless_uuid_form(""));
        check_n("пусто: разбора нет", -1, vless_uuid_parse("", u));

        /* Длина как у UUID, но знак посторонний: у Xray это ошибка hex.Decode, и
         * коротким именем такая строка стать уже не может — она слишком длинная. */
        check_n("32 знака с посторонним: форма — не hex", VLESS_UUID_NOTHEX,
                vless_uuid_form("0123456789abcdef0123456789abcdeZ"));
        check_n("32 знака с посторонним: разбора нет", -1,
                vless_uuid_parse("0123456789abcdef0123456789abcdeZ", u));
        /* Дефис допускается ТОЛЬКО между группами: внутри группы это посторонний знак. */
        check_n("дефис внутри группы: не hex", VLESS_UUID_NOTHEX,
                vless_uuid_form("0123-456789ab-cdef-0123-456789abcdef"));
    }

    /* Длина 31 — щель между двумя формами: для вывода слишком длинно, для UUID коротко.
     * Знаки при этом шестнадцатеричные, то есть отказ идёт именно по ДЛИНЕ, как у Xray. */
    {
        struct vless_node n;
        check_n("id из 31 знака: узел пропущен", 1,
                vless_parse_url("vless://0123456789abcdef0123456789abcde@h:443"
                                "?security=none#x", &n));
        check("id из 31 знака: причина названа", "идентификатор: 31 знак, нужен UUID",
              n.skip_reason);
    }

    /* Остальные непригодные формы — каждая со своей причиной: причина уезжает в
     * интерфейс, и «узел пропущен» без неё уже разбиралось в splicicd#16. */
    {
        struct vless_node n;
        char url[128];
        check_n("пустой id: узел пропущен", 1,
                vless_parse_url("vless://@h:443?security=none#x", &n));
        check("пустой id: причина названа", "идентификатор пуст", n.skip_reason);

        char long_id[40];
        memset(long_id, 'a', 37); long_id[37] = '\0';
        snprintf(url, sizeof(url), "vless://%s@h:443?security=none#x", long_id);
        check_n("id длиннее UUID: узел пропущен", 1, vless_parse_url(url, &n));
        check("id длиннее UUID: причина названа", "идентификатор длиннее UUID",
              n.skip_reason);

        check_n("id длины UUID с посторонним знаком: пропущен", 1,
                vless_parse_url("vless://0123456789abcdef0123456789abcdeZ@h:443"
                                "?security=none#x", &n));
        check("id с посторонним знаком: причина названа", "UUID с недопустимым знаком",
              n.skip_reason);
    }

    /* Подписка целиком: пригодные узлы с обоими видами id взяты, непригодный по id
     * учтён и объяснён. Арифметика та же, на которой стоит весь этот стенд — ни одна
     * ссылка не имеет права исчезнуть, не попав ни в один счётчик. */
    {
        struct vless_node nodes[16];
        struct vless_sub_stats st;
        const char *sub =
            "vless://TMG_74317ba5f91@1.2.3.4:443?security=reality&pbk=K&sni=x.com#Короткий\n"
            "vless://11111111-2222-3333-4444-555555555555@5.6.7.8:443"
            "?security=reality&pbk=K&sni=x.com#UUID\n"
            "vless://0123456789abcdef0123456789abcde@9.9.9.9:443"
            "?security=reality&pbk=K&sni=x.com#Щель\n";
        size_t n = vless_parse_sub(sub, nodes, 16, &st);
        check_n("подписка: пригодны оба вида id", 2, (long)n);
        check("подписка: короткий id сохранён", "TMG_74317ba5f91", nodes[0].uuid);
        check_n("подписка: непригоден один", 1, (long)st.skipped);
        check("подписка: причина непригодного названа",
              "идентификатор: 31 знак, нужен UUID", st.reasons[0].reason);
        check("подписка: пример — имя своего узла", "Щель", st.reasons[0].example);
        check_n("подписка: сумма сходится", 3, (long)(n + st.skipped + st.foreign));
    }

    printf("\n%d проверок пройдено", g_pass);
    if (g_fail) {
        printf(", %d ПРОВАЛЕНО\n", g_fail);
        return 1;
    }
    printf("\nвсе проверки прошли\n");
    return 0;
}
