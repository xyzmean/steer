/* Подбор доменного правила: проверка семантики, а не скорости.
 *
 * Зачем отдельным тестом. Подбор переписан с перебора на индекс по суффиксам имени, и это
 * ровно тот случай, когда ошибка не видна снаружи: канал просто перестаёт совпадать, трафик
 * идёт открытым путём, и в логе ничего нет. «Работает» и «правильно» здесь расходятся молча,
 * поэтому проверяются граничные случаи, а не пара примеров:
 *
 *   - доменное правило совпадает с самим именем и с поддоменами, но НЕ с чужим именем,
 *     которое лишь заканчивается теми же буквами (notyoutube.com против youtube.com);
 *   - точное правило совпадает только с самим именем;
 *   - совпадение на границе точки, а не по символам: «ube.com» не совпадает с «youtube.com»;
 *   - шаблоны и регулярные выражения работают по-прежнему — они по суффиксу не находятся и
 *     идут отдельным перебором;
 *   - одно и то же имя, заданное и точным, и доменным правилом, работает как доменное: в
 *     индексе это один ключ с двумя метками, и потеря метки была бы невидима.
 *
 * Включаются ИСХОДНИКИ резолвера, в порядке исходного файла: подбор — статическая функция
 * внутри него, и вызывать её иначе можно было бы только через новую подкоманду, то есть
 * добавив в движок код ради теста. */
#include "../src/lib/sindex.c"
#include "../src/lib/nftnl.c"
#include "../src/lib/jsonw.c"
#include "../src/lib/ctnl.c"
#include "../src/dnsd/rules.c"
#include "../src/dnsd/wire.c"
#include "../src/dnsd/fakeip.c"
#include "../src/dnsd/table.c"
#include "../src/dnsd/dlog.c"
#include "../src/dnsd/proxy.c"
#include "../src/dnsd/main.c"
#include <sys/stat.h>

static int fails;

static void check(const char *what, int want, int got) {
    printf("%-58s %s\n", what, want == got ? "ok" : "ПРОВАЛ");
    if (want != got) fails++;
}

/* Набор из строк списка — в том же виде, в каком их читает load_rules_into. */
static void build(struct ruleset *rs, const char *const *lines) {
    memset(rs, 0, sizeof(*rs));
    for (size_t i = 0; lines[i]; i++) {
        char buf[512];
        snprintf(buf, sizeof(buf), "%s", lines[i]);
        ruleset_add(rs, buf);
    }
}

int main(void) {
    {
        static const char *const lines[] = { "youtube.com", "=exact.example", NULL };
        struct ruleset rs;
        build(&rs, lines);

        check("доменное: само имя", 1, ruleset_match(&rs, "youtube.com"));
        check("доменное: поддомен", 1, ruleset_match(&rs, "www.youtube.com"));
        check("доменное: глубокий поддомен", 1, ruleset_match(&rs, "a.b.c.youtube.com"));
        check("доменное: РЕГИСТР не важен", 1, ruleset_match(&rs, "WWW.YouTube.COM"));
        check("доменное: чужое имя с тем же хвостом", 0, ruleset_match(&rs, "notyoutube.com"));
        check("доменное: совпадение только по границе точки", 0, ruleset_match(&rs, "ube.com"));
        check("доменное: другой домен", 0, ruleset_match(&rs, "example.org"));
        check("доменное: имя короче шаблона", 0, ruleset_match(&rs, "com"));

        check("точное: само имя", 1, ruleset_match(&rs, "exact.example"));
        check("точное: поддомен НЕ совпадает", 0, ruleset_match(&rs, "www.exact.example"));

        ruleset_free(&rs);
    }
    {
        /* Правило в записи FQDN, с завершающей точкой. Имя вопроса из пакета собирается без
         * неё, и `foo.org.` не совпадало ни с чем — правило молча не действовало. */
        static const char *const lines[] = { "fqdn.example.", "=exactdot.example.",
                                             "*.wilddot.example.", ".", "*.", NULL };
        struct ruleset rs;
        build(&rs, lines);
        check("завершающая точка: доменное, само имя", 1, ruleset_match(&rs, "fqdn.example"));
        check("завершающая точка: доменное, поддомен", 1, ruleset_match(&rs, "www.fqdn.example"));
        check("завершающая точка: точное", 1, ruleset_match(&rs, "exactdot.example"));
        check("завершающая точка: шаблон", 1, ruleset_match(&rs, "a.wilddot.example"));
        check("`.` и `*.` — не правило «всё»", 0, ruleset_match(&rs, "other.test"));
        check("`.` и `*.` правилами не становятся", 3, (int)rs.n);
        ruleset_free(&rs);
    }
    {
        /* Одно имя двумя правилами: в индексе это один ключ, и метки обязаны сложиться. */
        static const char *const lines[] = { "=both.test", "both.test", NULL };
        struct ruleset rs;
        build(&rs, lines);
        check("точное и доменное на одном имени: само имя", 1, ruleset_match(&rs, "both.test"));
        check("точное и доменное на одном имени: поддомен", 1, ruleset_match(&rs, "x.both.test"));
        ruleset_free(&rs);
    }
    {
        static const char *const lines[] = { "*.cdn.example", "re:^ads[0-9]+\\.", NULL };
        struct ruleset rs;
        build(&rs, lines);
        check("шаблон: совпадает", 1, ruleset_match(&rs, "img.cdn.example"));
        check("шаблон: не совпадает", 0, ruleset_match(&rs, "cdn.example.org"));
        check("регулярное: совпадает", 1, ruleset_match(&rs, "ads12.example.com"));
        check("регулярное: не совпадает", 0, ruleset_match(&rs, "adsx.example.com"));
        ruleset_free(&rs);
    }
    {
        /* Много правил: проверяем, что индекс находит и первое, и последнее, и не находит
         * того, чего нет. Перерастание таблицы (256 слотов по умолчанию) здесь тоже
         * происходит — на нём ломается неверный перехэш. */
        struct ruleset rs;
        memset(&rs, 0, sizeof(rs));
        char buf[64];
        for (int i = 0; i < 5000; i++) {
            snprintf(buf, sizeof(buf), "d%d.example", i);
            ruleset_add(&rs, buf);
        }
        check("много правил: первое", 1, ruleset_match(&rs, "d0.example"));
        check("много правил: последнее", 1, ruleset_match(&rs, "d4999.example"));
        check("много правил: поддомен последнего", 1, ruleset_match(&rs, "w.d4999.example"));
        check("много правил: отсутствующее", 0, ruleset_match(&rs, "d5000.example"));
        ruleset_free(&rs);
    }
    {
        /* Таблица fake-IP на том же индексе: адрес обязан быть постоянным для домена и
         * разным для разных доменов. Совпадение адресов означало бы, что один домен уводит
         * трафик на сайт другого. */
        uint32_t a = 0, b = 0, again = 0;
        check("fake-IP: выдан", 0, fakeip_lookup_or_alloc("one.test", &a));
        check("fake-IP: другому домену другой", 0, fakeip_lookup_or_alloc("two.test", &b));
        check("fake-IP: адреса не совпадают", 1, a != b);
        check("fake-IP: повторный запрос — тот же адрес", 0,
              fakeip_lookup_or_alloc("one.test", &again));
        check("fake-IP: адрес постоянен", 1, again == a);
        fakeip_entry_set_real("one.test", 0x01020304u);
        check("fake-IP: реальный адрес запомнен", 1,
              fakeip_entry_get_real("one.test") == 0x01020304u);
        check("fake-IP: у другого домена своего нет", 1, fakeip_entry_get_real("two.test") == 0);
    }
    {
        /* Подавление HTTPS (65) и SVCB (64) на совпавшем домене. Проверяется не
         * константа, а форма ответа: клиент должен получить NODATA — тот же вопрос,
         * ноль записей — и ни одной подсказки ipv4hint из настоящего ответа. Иначе
         * браузер идёт по реальному адресу мимо туннеля и ждёт таймаута, что и
         * выглядит как задержка на первом открытии сайта.
         *
         * Ответ собирается руками: заголовок, вопрос «www.test HTTPS IN», затем
         * запись с ipv4hint. build_rewritten_response обязан обрезать всё после
         * вопроса. */
        uint8_t resp[64];
        size_t n = 0;
        resp[n++] = 0x12; resp[n++] = 0x34;          /* id */
        resp[n++] = 0x81; resp[n++] = 0x80;          /* QR + RD + RA */
        resp[n++] = 0x00; resp[n++] = 0x01;          /* qdcount = 1 */
        resp[n++] = 0x00; resp[n++] = 0x01;          /* ancount = 1 */
        resp[n++] = 0x00; resp[n++] = 0x00;          /* nscount */
        resp[n++] = 0x00; resp[n++] = 0x00;          /* arcount */
        resp[n++] = 3; memcpy(resp + n, "www", 3);  n += 3;
        resp[n++] = 4; memcpy(resp + n, "test", 4); n += 4;
        resp[n++] = 0;                               /* конец имени */
        resp[n++] = 0x00; resp[n++] = DNS_TYPE_HTTPS;
        resp[n++] = 0x00; resp[n++] = 0x01;          /* class IN */
        size_t qend = n;
        resp[n++] = 0xC0; resp[n++] = 0x0C;          /* ответ: указатель на вопрос */
        resp[n++] = 0x00; resp[n++] = DNS_TYPE_HTTPS;
        resp[n++] = 0x00; resp[n++] = 0x01;
        resp[n++] = 0x00; resp[n++] = 0x00; resp[n++] = 0x00; resp[n++] = 0x3C;
        resp[n++] = 0x00; resp[n++] = 0x0B;          /* rdlength */
        resp[n++] = 0x00; resp[n++] = 0x01;          /* priority 1 */
        resp[n++] = 0x00;                            /* target = . */
        resp[n++] = 0x00; resp[n++] = 0x04;          /* key 4 = ipv4hint */
        resp[n++] = 0x00; resp[n++] = 0x04;
        resp[n++] = 1; resp[n++] = 2; resp[n++] = 3; resp[n++] = 4;

        uint8_t out[512];
        size_t len = build_rewritten_response(resp, qend, out, sizeof(out), 0, 0);
        check("HTTPS: ответ обрезан по конец вопроса", (int)qend, (int)len);
        check("HTTPS: ancount обнулён", 0, out[7]);
        check("HTTPS: вопрос сохранён (qdcount)", 1, out[5]);
        check("HTTPS: тип вопроса не подменён", DNS_TYPE_HTTPS, out[qend - 3]);
        check("HTTPS: id ответа тот же", 0x1234, (out[0] << 8) | out[1]);
        check("HTTPS: ipv4hint 1.2.3.4 клиенту не ушёл", 0,
              memcmp(out + qend - 4, "\x01\x02\x03\x04", 4) == 0);
        check("SVCB разбирается тем же путём, что HTTPS", 1,
              DNS_TYPE_SVCB == 64 && DNS_TYPE_HTTPS == 65);
    }

    {
        /* Быстрый путь: разбор ЗАПРОСА и ответ, собранный из него.
         *
         * Задержка fake-ip держалась на том, что каждый запрос ждал круга до
         * upstream — даже когда ответ от него не зависел. Здесь проверяются оба
         * условия, на которых быстрый путь стоит: parse_query читает вопрос и
         * отвергает не-вопросы, а ответ из запроса несёт правильные флаги —
         * QR (иначе клиент выбросит пакет как чужой запрос) и RA, без AA/TC. */
        uint8_t q[64];
        size_t n = 0;
        q[n++] = 0xAB; q[n++] = 0xCD;               /* id */
        q[n++] = 0x01; q[n++] = 0x00;               /* RD, это запрос */
        q[n++] = 0x00; q[n++] = 0x01;               /* qdcount = 1 */
        q[n++] = 0x00; q[n++] = 0x00;
        q[n++] = 0x00; q[n++] = 0x00;
        q[n++] = 0x00; q[n++] = 0x00;
        q[n++] = 3; memcpy(q + n, "www", 3);  n += 3;
        q[n++] = 4; memcpy(q + n, "test", 4); n += 4;
        q[n++] = 0;
        q[n++] = 0x00; q[n++] = 0x01;               /* тип A */
        q[n++] = 0x00; q[n++] = 0x01;               /* class IN */

        char name[MAX_HOSTNAME];
        uint16_t qtype = 0;
        size_t qend = 0;
        check("запрос: разобран", 0, parse_query(q, n, name, sizeof(name), &qtype, &qend));
        check("запрос: имя", 0, strcmp(name, "www.test"));
        check("запрос: тип A", DNS_TYPE_A, qtype);
        check("запрос: конец вопроса", (int)n, (int)qend);

        /* Ответ (QR=1) быстрый путь обязан отвергнуть: он для запросов. */
        uint8_t r[64];
        memcpy(r, q, n);
        r[2] |= 0x80;
        check("ответ вместо запроса: отвергнут", -1,
              parse_query(r, n, name, sizeof(name), &qtype, &qend));

        /* NODATA из запроса: та же форма, что из ответа, плюс флаги ответа. */
        uint8_t out[512];
        size_t len = build_rewritten_response(q, qend, out, sizeof(out), 0, 0);
        make_response_flags(out);
        check("ответ из запроса: длина — конец вопроса", (int)qend, (int)len);
        check("ответ из запроса: QR выставлен", 0x80, out[2] & 0x80);
        check("ответ из запроса: RD перенесён", 0x01, out[2] & 0x01);
        check("ответ из запроса: AA/TC не выдуманы", 0, out[2] & 0x06);
        check("ответ из запроса: RA выставлен, RCODE ноль", 0x80, out[3]);
        check("ответ из запроса: id клиента", 0xABCD, (out[0] << 8) | out[1]);

        /* A с подстановкой: fake-IP уходит в ответ из запроса тем же
         * build_rewritten_response, что и раньше из ответа. */
        len = build_rewritten_response(q, qend, out, sizeof(out), 1, 0xC6120005u);
        make_response_flags(out);
        check("A из запроса: ancount = 1", 1, out[7]);
        check("A из запроса: fake-IP в rdata", 0,
              memcmp(out + len - 4, "\xC6\x12\x00\x05", 4));
    }

    {
        /* Долгий путь к файлу состояния fake-IP. Путь задаётся снаружи (--state-file,
         * --state-dir), то есть его длину выбирает не движок, а буфер под имя временного
         * файла был размером в имя ХОСТА (MAX_HOSTNAME, 256). «%s.tmp» в него молча не
         * влезал, и обрезка приходилась на произвольное место пути — в том числе ровно на
         * границу компонента, и тогда обрезанное имя оказывалось существующим КАТАЛОГОМ:
         * fopen падал с EISDIR, функция молча возвращалась, и таблица fake-IP не
         * сохранялась вовсе. Следствие видно только после перезапуска — весь DNAT
         * собирается заново, а прежние адреса у клиентов в кеше уже другие.
         *
         * Стенд ставит длину каталога ровно 255: тогда обрезка «%s.tmp» до 255 символов
         * даёт сам каталог. Проверяется наблюдаемое следствие — файл состояния после
         * rewrite обязан существовать и содержать записанную пару. */
        char dir[512];
        snprintf(dir, sizeof(dir), "/tmp/dnsmatch-long.XXXXXX");
        if (!mkdtemp(dir)) { perror("mkdtemp"); return 1; }
        size_t at = strlen(dir);
        /* Два уровня по 115 символов добирают путь каталога до 255 (25 + 115 + 115). */
        for (int lvl = 0; lvl < 2; lvl++) {
            at += (size_t)snprintf(dir + at, sizeof(dir) - at, "/%0114d", lvl);
            if (mkdir(dir, 0755) != 0 && errno != EEXIST) { perror("mkdir"); return 1; }
        }
        check("долгий путь: каталог ровно на границе буфера", 255, (int)strlen(dir));
        char path[768];
        snprintf(path, sizeof(path), "%s/fakeip.state", dir);

        memset(&g_fakeip, 0, sizeof(g_fakeip));
        g_fakeip_next = 0;
        uint32_t addr = 0;
        g_fakeip_state_path = NULL;             /* без append: пишет только rewrite */
        check("долгий путь: адрес выдан", 0, fakeip_lookup_or_alloc("long.test", &addr));
        g_fakeip_state_path = path;
        fakeip_state_rewrite();

        FILE *rf = fopen(path, "r");
        check("долгий путь: файл состояния создан", 1, rf != NULL);
        if (rf) {
            char line[512] = {0};
            char *got = fgets(line, sizeof(line), rf);
            check("долгий путь: строка прочитана", 1, got != NULL);
            check("долгий путь: домен на месте", 1, strstr(line, "long.test") != NULL);
            fclose(rf);
        }
        g_fakeip_state_path = NULL;
        memset(&g_fakeip, 0, sizeof(g_fakeip));
        g_fakeip_next = 0;
    }

    /* ---- ГИБРИДНЫЙ СПИСОК: адреса и имена в одном файле -------------------------
     *
     * Проверяется не ruleset_add, а load_rules_into — то есть путь ЧТЕНИЯ ФАЙЛА, потому
     * что именно там теперь стоит разделение: адресные строки этого же файла берёт
     * компилятор набора правил, доменные — резолвер. Через ruleset_add напрямую разделения
     * не видно вовсе, и стенд был бы зелёным при любом поведении читателя.
     *
     * Список ровно тот, который назвал владелец: адрес, имя, подсеть. Плюс диапазон —
     * его выдаёт `steer fit`, и он тоже адрес. */
    {
        char path[] = "/tmp/dnsmatch-hybrid.XXXXXX";
        int fd = mkstemp(path);
        check("гибрид: файл создан", 1, fd >= 0);
        if (fd >= 0) {
            FILE *w = fdopen(fd, "w");
            fputs("1.1.1.1\n"
                  "youtube.com\n"
                  "8.8.8.0/24\n"
                  "10.0.0.1-10.0.0.9\n"
                  "# комментарий\n"
                  "=exact.example\n"
                  "*.wild.example\n", w);
            fclose(w);

            struct ruleset rs;
            memset(&rs, 0, sizeof(rs));
            check("гибрид: файл прочитан", 0, load_rules_into(path, &rs));
            /* Доменных правил ровно три: суффикс, точное, шаблон. Адресные четыре строки
             * в резолвер не попали — иначе их было бы семь, и каждая адресная стала бы
             * правилом RULE_NAMESPACE для имени вроде «8.8.8.0/24». */
            check("гибрид: доменных правил ровно три", 3, (int)rs.n);
            check("гибрид: имя ловится", 1, ruleset_match(&rs, "youtube.com"));
            check("гибрид: поддомен имени ловится", 1, ruleset_match(&rs, "www.youtube.com"));
            check("гибрид: точное ловится", 1, ruleset_match(&rs, "exact.example"));
            check("гибрид: поддомен точного НЕ ловится", 0,
                  ruleset_match(&rs, "sub.exact.example"));
            check("гибрид: шаблон ловится", 1, ruleset_match(&rs, "a.wild.example"));
            check("гибрид: адрес не стал доменным правилом", 0,
                  ruleset_match(&rs, "8.8.8.0/24"));
            check("гибрид: чужое имя не ловится", 0, ruleset_match(&rs, "example.org"));

            /* Классификатор отдельно: он общий на двух читателей, и его ответы — это
             * граница между ними. Ошибка здесь означает строку, которую не взял никто. */
            check("классификатор: 1.1.1.1 адрес", 1, spec_line_is_addr("1.1.1.1"));
            check("классификатор: 8.8.8.0/24 адрес", 1, spec_line_is_addr("8.8.8.0/24"));
            check("классификатор: диапазон адрес", 1,
                  spec_line_is_addr("10.0.0.1-10.0.0.9"));
            check("классификатор: youtube.com не адрес", 0, spec_line_is_addr("youtube.com"));
            check("классификатор: имя с дефисом не адрес", 0,
                  spec_line_is_addr("my-site.example"));
            check("классификатор: IPv6 не адрес", 0, spec_line_is_addr("2606:4700::/32"));
            unlink(path);
        }
    }

    /* ---- ОДНО ИМЯ В НЕСКОЛЬКИХ ПРАВИЛАХ ------------------------------------------
     *
     * Правило на телевизор и правило на всю сеть законно называют один и тот же YouTube.
     * Пока резолвер клал поддельный адрес в набор ПЕРВОГО совпавшего канала, у клиентов
     * второго на руках оказывался адрес, которого нет ни в одном правиле, — и домен
     * переставал открываться у всех сразу. Проверяется поэтому не «нашёлся ли канал», а
     * СКОЛЬКО их нашлось и кто из них строит ответ. */
    {
        static const char *const yt[] = { "youtube.com", NULL };
        g_dch_n = 2;
        memset(g_dch, 0, sizeof(g_dch[0]) * 2);
        snprintf(g_dch[0].set, sizeof(g_dch[0].set), "%s", "tv_dom");
        snprintf(g_dch[1].set, sizeof(g_dch[1].set), "%s", "all_dom");
        build(&g_dch[0].rules, yt);
        build(&g_dch[1].rules, yt);

        check("пересечение: совпали ОБА канала", 3, (int)dch_match_mask("youtube.com"));
        check("пересечение: поддомен — тоже оба", 3, (int)dch_match_mask("www.youtube.com"));
        check("пересечение: ответ строит верхний", 0, dch_first(dch_match_mask("youtube.com")));
        check("пересечение: чужое имя — ни один", 0, (int)dch_match_mask("example.org"));
        check("пересечение: пустой набор — канала нет", -1, dch_first(0));

        /* Канал реального адреса поддельного к себе не берёт: в его наборе лежат
         * настоящие адреса из ответа, а поддельного клиент в этом режиме не получает. */
        g_dch[1].realip = 1;
        check("пересечение: realip не берёт поддельный адрес", 1,
              (int)dch_fakeip_only(dch_match_mask("youtube.com")));

        ruleset_free(&g_dch[0].rules);
        ruleset_free(&g_dch[1].rules);
        g_dch_n = 0;
    }

    /* ---- ВЫКЛЮЧЕННОЕ ПРАВИЛО РЕЗОЛВЕР НЕ БЕРЁТ -----------------------------------
     *
     * «Выключено» обязано значить «не действует». Компилятор набора выключенный канал
     * пропускал, а резолвер — нет, и получалось хуже, чем «действует»: имя разрешалось в
     * поддельный адрес, набора для которого в ядре нет вовсе. Снаружи это выглядело как
     * сломанный выключатель — «отключить правило не помогает, надо удалить».
     *
     * Проверяется через dch_build на настоящей спеке: пропуск живёт именно там. */
    {
        char lst[] = "/tmp/dnsmatch-off-list.XXXXXX";
        int lf = mkstemp(lst);
        check("выключенное: список создан", 1, lf >= 0);
        if (lf >= 0) {
            FILE *w = fdopen(lf, "w");
            fputs("youtube.com\n", w);
            fclose(w);

            char sp[] = "/tmp/dnsmatch-off-spec.XXXXXX";
            int sf = mkstemp(sp);
            if (sf >= 0) {
                FILE *ws = fdopen(sf, "w");
                fprintf(ws,
                        "{\"schema\":1,"
                        "\"outputs\":{\"vl\":{\"kind\":\"interface\",\"device\":\"lo\"}},"
                        "\"channels\":["
                        "{\"name\":\"off\",\"enabled\":false,"
                        "\"match\":{\"domains_files\":[\"%s\"]},\"out\":\"vl\"}"
                        "]}\n", lst);
                fclose(ws);

                load_spec(sp);
                dch_build();
                check("выключенное: канала у резолвера нет", 0, (int)g_dch_n);
                unlink(sp);
            }
            unlink(lst);
        }
    }

    /* ---- fake-IP: пул, регистр, восстановление, флаги, срок элемента ------------- */
    {
        char dir[] = "/tmp/dnsmatch-fk.XXXXXX";
        if (!mkdtemp(dir)) { perror("mkdtemp"); return 2; }
        char path[768];
        snprintf(path, sizeof(path), "%s/state", dir);

        /* Срок элемента набора канала: TTL 0 — не «навечно». */
        check("срок элемента: TTL 0 даёт 1 с, не постоянный элемент", 1, (int)set_ttl_clamp(0));
        check("срок элемента: сутки — потолок", 86400, (int)set_ttl_clamp(86401));
        check("срок элемента: обычный TTL как есть", 300, (int)set_ttl_clamp(300));

        /* Адрес вне пула в файле состояния — брак строки, а не исчерпанный пул. */
        FILE *f = fopen(path, "w");
        fputs("bad.test\t203.0.113.5\n", f);
        fclose(f);
        memset(&g_fakeip, 0, sizeof(g_fakeip));
        memset(&g_fakeip_idx, 0, sizeof(g_fakeip_idx));
        g_fakeip_next = 0;
        g_fakeip_state_path = NULL;
        fakeip_state_load(path);
        check("адрес вне пула в состоянии не загружен", 0, (int)g_fakeip.n);
        uint32_t addr = 0;
        check("после такой строки пул не исчерпан", 0, fakeip_lookup_or_alloc("new.test", &addr));
        check("и адрес выдан из пула", 1, addr >= FAKEIP_POOL_BASE && addr < FAKEIP_POOL_BASE + FAKEIP_POOL_SIZE);

        /* Регистр: ключ таблицы строчный независимо от вызывающего. */
        uint32_t a1 = 0, a2 = 0;
        fakeip_lookup_or_alloc("X.TEST", &a1);
        fakeip_lookup_or_alloc("x.test", &a2);
        check("X.TEST и x.test — один адрес", 1, a1 != 0 && a1 == a2);

        /* Восстановление без ядра: третье поле НЕ становится real_host. */
        f = fopen(path, "w");
        fputs("known.test\t198.18.0.7\t93.184.216.34\n", f);
        fclose(f);
        memset(&g_fakeip, 0, sizeof(g_fakeip));
        memset(&g_fakeip_idx, 0, sizeof(g_fakeip_idx));
        g_fakeip_next = 0;
        fakeip_state_load(path);
        check("трёхполевая строка загружена", 1, (int)g_fakeip.n);
        size_t routed = 99;
        size_t restored = fakeip_rehydrate(-1, &routed);
        check("без netlink ничего не восстановлено", 0, (int)restored);
        check("и real_host сброшен — быстрый путь закрыт", 0, g_fakeip.n ? (int)(g_fakeip.entries[0].real_host != 0) : -1);
        check("маршруты без ядра не утверждались", 0, (int)routed);
        memset(&g_fakeip, 0, sizeof(g_fakeip));
        memset(&g_fakeip_idx, 0, sizeof(g_fakeip_idx));
        g_fakeip_next = 0;
        unlink(path);
        rmdir(dir);

        /* Флаги синтетического ответа из ответа upstream: TC и AD не наследуются. */
        uint8_t up[64] = { 0x12, 0x34, 0x83, 0xA0, 0, 1, 0, 0, 0, 0, 0, 0,
                           1, 'a', 0, 0, 1, 0, 1 };
        size_t qend = 12 + 3 + 4;
        uint8_t out[512];
        size_t len = build_rewritten_response(up, qend, out, sizeof(out), 1, 0xC6120005u);
        check("ответ из upstream собран", 1, len > 0);
        check("TC снят", 0, out[2] & 0x02);
        check("AD снят", 0, out[3] & 0x20);
        check("QR стоит", 0x80, out[2] & 0x80);
    }

    /* ---- ожидания: номер транзакции и отпечаток вопроса ----------------------------
     *
     * Два свойства, на которых держится «ответ попал к тому, кто спрашивал». Оба прежде
     * не проверялись ничем, и оба ломаются ТИХО: клиент получает чужой адрес, а в журнале
     * ни строки.
     *
     * 1. Номер транзакции составной: младшие биты — слот, старшие — поколение. Раскладка
     *    менялась (было 8+8, стало 10+6), и круг «собрать — разобрать» обязан сходиться
     *    для КАЖДОГО слота, иначе ответ уедет в чужое ожидание.
     * 2. Отпечаток вопроса: поколение шестибитное и когда-нибудь повторится, поэтому
     *    настоящая защита — в том, что ответ несёт тот же вопрос, что мы задали. */
    {
        int bad_round = 0;
        for (int i = 0; i < MAX_PENDING; i++) {
            for (unsigned g = 0; g < 4; g++) {
                g_pending[i].gen = (uint8_t)(g * 17);
                uint16_t tag = pending_tag(&g_pending[i]);
                if ((tag & PENDING_IDX_MASK) != (unsigned)i) bad_round++;
                if (((tag >> PENDING_IDX_BITS) & PENDING_GEN_MASK) !=
                    (g_pending[i].gen & PENDING_GEN_MASK)) bad_round++;
            }
        }
        check("номер транзакции: слот и поколение разбираются обратно у всех мест",
              0, bad_round);
        check("мест в таблице ожиданий хватает медленному резолверу", 1,
              MAX_PENDING / PENDING_TTL_SEC >= 200);
        memset(g_pending, 0, sizeof(g_pending));

        /* А ТЕПЕРЬ ГЛАВНОЕ, чего круг выше поймать не мог: он сравнивал обе стороны уже
         * усечёнными, а на приёме сравнивается ЦЕЛОЕ поле p->gen с шестью битами из
         * номера. Пока поколение писалось в слот целым байтом, всякое значение от 64 и
         * выше не совпадало ни с чем: ответ сверху отбрасывался молча, клиент ждал
         * таймаута и спрашивал заново — те самые «5-7 секунд на резолв» на живом
         * роутере, где счётчик поколений уходит за 64 за первую же сотню запросов.
         *
         * Поэтому проверка идёт по ВСЕМУ кругу счётчика и повторяет обе стороны
         * дословно: слева — присваивание из handle_client_query, справа — сравнение из
         * handle_upstream_response. */
        int bad_gen = 0;
        g_gen_next = 0;
        for (int round = 0; round < 256; round++) {
            struct pending *p = &g_pending[round % MAX_PENDING];
            p->gen = pending_next_gen();
            uint16_t tag = pending_tag(p);
            if (p->gen != (uint8_t)((tag >> PENDING_IDX_BITS) & PENDING_GEN_MASK))
                bad_gen++;
        }
        check("поколение слота переживает весь круг счётчика (0..255)", 0, bad_gen);
        g_gen_next = 0;
        memset(g_pending, 0, sizeof(g_pending));

        /* Два РАЗНЫХ вопроса в одном слоте с одним поколением — ровно тот случай, ради
         * которого отпечаток и заведён: по номеру транзакции они неразличимы. */
        uint8_t q1[64] = { 0x12, 0x34, 0x01, 0x00, 0, 1, 0, 0, 0, 0, 0, 0,
                           3, 'w', 'w', 'w', 2, 'y', 'a', 0, 0, 1, 0, 1 };
        uint8_t q2[64] = { 0x12, 0x34, 0x01, 0x00, 0, 1, 0, 0, 0, 0, 0, 0,
                           3, 'w', 'w', 'w', 2, 'v', 'k', 0, 0, 1, 0, 1 };
        size_t qe = 12 + 8 + 4;
        uint16_t f1 = question_fp(q1, qe), f2 = question_fp(q2, qe);
        check("отпечаток вопроса: разные имена — разные отпечатки", 1, f1 != f2);
        check("отпечаток вопроса: одинаковые байты — один отпечаток", 1,
              f1 == question_fp(q1, qe));
        check("отпечаток вопроса: ненулевой (ноль значит «вопроса нет»)", 1, f1 != 0);

        /* Тип записи — часть вопроса: A и AAAA к одному имени это разные вопросы, и
         * перепутать их ответы значит отдать клиенту адрес не того семейства. */
        uint8_t q3[64];
        memcpy(q3, q1, sizeof(q3));
        q3[qe - 3] = 28;                        /* QTYPE A -> AAAA */
        check("отпечаток вопроса: тип записи учитывается", 1, question_fp(q3, qe) != f1);
    }

    printf("\n%s\n", fails ? "ЕСТЬ ПРОВАЛЫ" : "все проверки прошли");
    return fails ? 1 : 0;
}
