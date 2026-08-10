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

static int g_pass, g_fail;

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
        size_t skipped = 0, foreign = 0;
        size_t n = vless_parse_sub("vless://a@h1:443#one" "vless://b@h2:443#two",
                                   nodes, 8, &skipped, &foreign);
        check_n("две склеенные ссылки разобраны как две", 2, (long)n);
        check("первая: имя не съело вторую", "one", nodes[0].name);
        check("вторая: хост свой", "h2", nodes[1].host);
        check_n("склеенные: чужих протоколов нет", 0, (long)foreign);
    }
    {
        /* Имя без '#'-хвоста: граница обязана встать по схеме, не по цифрам порта. */
        struct vless_node nodes[8];
        size_t skipped = 0, foreign = 0;
        size_t n = vless_parse_sub("vless://a@h1:443" "vless://b@h2:8443",
                                   nodes, 8, &skipped, &foreign);
        check_n("склейка без имён: две ссылки", 2, (long)n);
        check_n("первой не откусили порт", 443, (long)nodes[0].port);
        check_n("второй достался свой порт", 8443, (long)nodes[1].port);
    }
    {
        /* Имя, оканчивающееся именем схемы, — граница всё равно по байтам перед '://'. */
        struct vless_node nodes[8];
        size_t skipped = 0, foreign = 0;
        size_t n = vless_parse_sub("vless://a@h1:443#Express" "ss://b@h2:443#other",
                                   nodes, 8, &skipped, &foreign);
        check_n("имя кончается на имя схемы: узел один", 1, (long)n);
        check("имя не обрезано", "Express", nodes[0].name);
        check_n("следующая ссылка учтена как чужая", 1, (long)foreign);
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
        size_t skipped = 0, foreign = 0;
        const char *sub =
            "vless://a@1.2.3.4:443?security=reality&pbk=K&sni=x.com#ok\n"
            "vless://b@[2001:db8::1]:443?security=reality&pbk=K&sni=x.com#ipv6\n"
            "vless://c@5.6.7.8:0?security=reality&pbk=K&sni=x.com#zero-port\n"
            "vless://d@9.9.9.9:443?security=tls#tls\n"
            "hy2://e@10.0.0.1:443#foreign\n";
        size_t n = vless_parse_sub(sub, nodes, 16, &skipped, &foreign);
        check_n("пригодных узлов", 1, (long)n);
        check_n("чужих протоколов", 1, (long)foreign);
        /* Четыре ссылки vless: одна взята, три нет — и все три обязаны быть в счётчике. */
        check_n("непригодных ссылок vless учтено", 3, (long)skipped);
        check_n("сумма сходится с числом ссылок в тексте",
                5, (long)(n + skipped + foreign));
    }

    /* Ссылка длиннее буфера строки тоже исчезала бесследно: ветка длины отбрасывала
     * её раньше разбора. Считается как непригодная — она и есть непригодная. */
    {
        struct vless_node nodes[4];
        size_t skipped = 0, foreign = 0;
        char big[4096];
        int k = snprintf(big, sizeof(big), "vless://u@h:443?sni=");
        memset(big + k, 'x', 2200);
        big[k + 2200] = '\0';
        size_t n = vless_parse_sub(big, nodes, 4, &skipped, &foreign);
        check_n("слишком длинная ссылка: не взята", 0, (long)n);
        check_n("слишком длинная ссылка: учтена как непригодная", 1, (long)skipped);
    }

    printf("\n%d проверок пройдено", g_pass);
    if (g_fail) {
        printf(", %d ПРОВАЛЕНО\n", g_fail);
        return 1;
    }
    printf("\nвсе проверки прошли\n");
    return 0;
}
