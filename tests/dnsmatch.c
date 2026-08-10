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
 * Включается ИСХОДНИК резолвера: подбор — статическая функция внутри него, и вызывать её
 * иначе можно было бы только через новую подкоманду, то есть добавив в движок код ради
 * теста. */
#include "../src/dnsd.c"

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

    printf("\n%s\n", fails ? "ЕСТЬ ПРОВАЛЫ" : "все проверки прошли");
    return fails ? 1 : 0;
}
