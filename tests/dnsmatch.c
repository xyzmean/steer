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
        /* Проверка типов DNS и подавления HTTPS/SVCB */
        check("DNS_TYPE_HTTPS == 65", 65, DNS_TYPE_HTTPS);
        check("DNS_TYPE_SVCB == 64", 64, DNS_TYPE_SVCB);
        uint8_t dummy[12] = {0};
        uint8_t out[512];
        size_t len = build_rewritten_response(dummy, 12, out, sizeof(out), 0, 0);
        check("build_rewritten_response NODATA len == 12", 12, len);
        check("build_rewritten_response NODATA ancount == 0", 0, out[7]);
    }

    printf("\n%s\n", fails ? "ЕСТЬ ПРОВАЛЫ" : "все проверки прошли");
    return fails ? 1 : 0;
}
