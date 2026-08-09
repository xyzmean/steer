/* Конфигурационный парсер: проверка семантики, а не скорости.
 *
 * Зачем отдельным тестом. Парсер spec.c — точка входа всей системы: прочитанный им
 * конфиг расходится по двум независимым потребителям (компилятору nftables-правил в
 * steer.c и резолверу в dnsd.c), которые читают ОДНИ те же глобалы. Ошибка здесь не
 * видна снаружи как сбой — правила встают, резолвер поднимается, но каждый работает
 * со своим пониманием конфигурации, и понять «почему трафик идёт не туда» потом
 * нечем. Поэтому проверяются граничные случаи, а не пара примеров:
 *
 *   - валидная спека заполняет g_out[]/g_ch[] ровно тем, что в ней написано;
 *   - пустые каналы законны (состояние «настроен, но ничего не направляет») и не
 *     должны отвергаться — иначе первичная настройка запирается наглухо;
 *   - выключенный канал остаётся в g_ch[], но не режет применение спеки проверками;
 *   - каждая конфигурация, «которая отрежет доступ к роутеру» или которая не имеет
 *     смысла (несуществующий выход, смешанные MAC/IP, дубликат устройства в failover,
 *     «any без списков в туннель»), обязана вызвать die() и exit(2) — молчаливое
 *     применение такой спеки и есть тот класс бага, ради которого die существует.
 *
 * die() в spec.c зовёт exit(2) напрямую, и перехватить его через подкоманду движка
 * нельзя — пришлось бы добавить в движок код ради теста. Поэтому тест включает ИСХОДНИК
 * парсера (#include "../src/spec.c") и перехватывает exit через setjmp/longjmp поверх
 * макроса: die() остаётся noreturn-функцией (longjmp не возвращается), а тест видит
 * код завершения, не порождая дочерних процессов. Тот же приём, что в dnsmatch.c для
 * доступа к статике, плюс jmp_buf для контроля «должен отказаться». Сообщение die()
 * уходит в stderr и видно в выводе make test — перехватывать его ради тишины не нужно,
 * поведение проверяется по коду возврата. */
#include <setjmp.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>

static jmp_buf g_jmp;
static int g_exit_code;          /* код, с которым die/exit пытались завершить тест */

/* Перехват exit: die() в spec.c вызывает exit(2) последним выражением. Подменяя exit
 * макросом ДО подключения spec.c, мы заменяем этот вызов на longjmp, не возвращаясь.
 * Компилятор по-прежнему считает die() noreturn-путём (longjmp не возвращается), так
 * что -Wall не выдаёт ложных предупреждений о падении сквозь конец функции. */
#define exit(code) (g_exit_code = (code), longjmp(g_jmp, 1))

#include "../src/spec.c"

#undef exit

static int fails;

static void check(const char *what, int want, int got) {
    printf("%-62s %s\n", what, want == got ? "ok" : "ПРОВАЛ");
    if (want != got) fails++;
}

/* Сравнение строк как «да/нет»: удобно для проверок «поле заполнено ожидаемо», где
 * интересен сам факт совпадения, а не длина. */
static void check_str(const char *what, const char *want, const char *got) {
    printf("%-62s %s\n", what, strcmp(want, got) == 0 ? "ok" : "ПРОВАЛ");
    if (strcmp(want, got) != 0) {
        printf("     хочу: \"%s\"\n     есть:  \"%s\"\n", want, got);
        fails++;
    }
}

/* Полный сброс глобалов парсера. g_out_n/g_ch_n нарастают между вызовами load_spec
 * (g_out[g_out_n++] = o), и без сброса второй тест увидит выходы первого. g_lan_device
 * возвращается к умолчанию «br-lan», g_traceroute_hops — к 0. g_state_dir оставляем
 * как есть: registry_assign в этих тестах не вызывается. */
static void reset_globals(void) {
    g_out_n = 0;
    g_ch_n = 0;
    g_from_default_n = 0;
    memset(g_out, 0, sizeof(g_out));
    memset(g_ch, 0, sizeof(g_ch));
    memset(g_from_default, 0, sizeof(g_from_default));
    strcpy(g_lan_device, "br-lan");
    g_traceroute_hops = 0;
}

/* Записать спеку во временный файл и скормить load_spec. Возвращает 0, если load_spec
 * завершилась нормально, или код exit, если отказала через die(). from_default задаём
 * явно во всех спеках: иначе load_spec зовёт popen("ip ..."), которого в окружении
 * теста нет, и автоопределение LAN молча оставляет g_from_default_n == 0.
 *
 * Сообщение die() пишется в stderr напрямую; мы его не перехватываем намеренно.
 * Поведение проверяется по коду возврата, а гонять stderr через pipe ради тишины —
 * лишний платформозависимый код (pipe/dup2) ради косметики. При провале конкретный
 * текст виден в выводе make test и сам по себе помогает разобраться. */
static int load_from_str(const char *spec) {
    reset_globals();
    g_exit_code = -1;
    /* Относительное имя во временной директории ОС: работает и на Linux (/tmp), и в
     * любой другой среде сборки. PID гарантирует уникальность, unlink — очистку.
     * Файл обязателен: load_spec читает путь, а не буфер. */
    char tmp[256];
    const char *td = getenv("TMPDIR");
    if (!td) td = "/tmp";
    snprintf(tmp, sizeof(tmp), "%s/specmatch.%d.json", td, (int)getpid());
    FILE *f = fopen(tmp, "w");
    if (f) { fputs(spec, f); fclose(f); }

    int rc;
    if (setjmp(g_jmp) == 0) {
        load_spec(tmp);
        rc = 0;                     /* нормальное завершение */
    } else {
        rc = g_exit_code;           /* вышли через die/exit */
    }
    unlink(tmp);
    return rc;
}

/* Удобные конструкторы спек: from_default вынесен в обёртку, чтобы каждый тест-случай
 * оставался читаемым и описывал только то, что проверяет.
 * SPEC — для литеральных спек: подставляет body и закрывает объект.
 * SPEC_OPEN — для динамически собираемых (sprintf в цикле): только префикс, закрытие
 *   делает сам тест. Иначе SPEC("") оставлял бы хвостовую '}', и дописанный после неё
 *   "outputs" парсер не видел. */
#define SPEC(body) \
    "{\"schema\":1,\"from_default\":[\"192.168.1.0/24\"]," body "}"
#define SPEC_OPEN \
    "{\"schema\":1,\"from_default\":[\"192.168.1.0/24\"],"

int main(void) {
    {
        /* Минимальная валидная спека: один прямой выход, один доменный канал.
         * Заполняет g_out_n=1, g_ch_n=1; выход — OUT_DIRECT, канал смотрит на «direct». */
        const char *s = SPEC(
            "\"outputs\":{\"direct\":{\"kind\":\"direct\"}},"
            "\"channels\":[{\"name\":\"yt\",\"out\":\"direct\","
            "\"match\":{\"domains_file\":\"/tmp/yt.lst\"}}]}");
        check("минимальная спека: load_spec не отказывает", 0, load_from_str(s));
        check("минимальная спека: один выход", 1, (int)g_out_n);
        check("минимальная спека: один канал", 1, (int)g_ch_n);
        check_str("минимальная спека: имя выхода", "direct", g_out[0].name);
        check("минимальная спека: kind direct", OUT_DIRECT, g_out[0].kind);
        check_str("минимальная спека: имя канала", "yt", g_ch[0].name);
        check_str("минимальная спека: канал → direct", "direct", g_ch[0].out);
        check("минимальная спека: domains_n", 1, (int)g_ch[0].domains_n);
        check_str("минимальная спека: domains_file", "/tmp/yt.lst", g_ch[0].domains_files[0]);
    }
    {
        /* Выходы без каналов законны: steer настроен, но ничего не направляет. Это
         * правильное начальное состояние, и отказ на нём запирал бы первичную
         * настройку (см. комментарий в load_spec, строки 366-372). */
        const char *s = SPEC("\"outputs\":{\"direct\":{\"kind\":\"direct\"}}");
        check("только outputs, без channels: не отказывает", 0, load_from_str(s));
        check("только outputs: один выход", 1, (int)g_out_n);
        check("только outputs: ноль каналов", 0, (int)g_ch_n);
    }
    {
        /* Пустая секция channels: [] — то же состояние, что и отсутствие секции. */
        const char *s = SPEC("\"outputs\":{\"direct\":{\"kind\":\"direct\"}},\"channels\":[]");
        check("channels: [] — не отказывает", 0, load_from_str(s));
        check("channels: [] — ноль каналов", 0, (int)g_ch_n);
    }
    {
        /* Interface-выход с устройством и failover-списком devices. Проверяем, что
         * оба поля (device и devices[]) заполняются и согласованы: задан devices —
         * device выводится из первого; проверка дубликатов проходит. */
        const char *s = SPEC(
            "\"outputs\":{\"wg\":{\"kind\":\"interface\","
            "\"devices\":[\"wg0\",\"wg1\"]}},"
            "\"channels\":[{\"name\":\"all\",\"out\":\"wg\","
            "\"match\":{\"prefixes_file\":\"/tmp/all.lst\"}}]}");
        check("interface с devices: не отказывает", 0, load_from_str(s));
        check("interface: devices_n=2", 2, (int)g_out[0].devices_n);
        check_str("interface: device выведен из devices[0]", "wg0", g_out[0].device);
    }
    {
        /* Выключенный канал остаётся в g_ch[], но проходит проверку «matches nothing»,
         * потому что проверка отключённых пропускается (строки 416). Без этого
         * выключить сломанное правило было бы нельзя — только удалить. */
        const char *s = SPEC(
            "\"outputs\":{\"direct\":{\"kind\":\"direct\"}},"
            "\"channels\":[{\"name\":\"off\",\"out\":\"direct\",\"enabled\":false,"
            "\"match\":{\"any\":true}}]}");
        check("выключенный any-канал: не отказывает", 0, load_from_str(s));
        check("выключенный канал: в g_ch[]", 1, (int)g_ch_n);
        check("выключенный канал: disabled=1", 1, g_ch[0].disabled);
    }
    {
        /* ---- невалидные спеки: каждая обязана die()/exit(2) ---- */

        /* schema != 1: весь смысл поля — отказаться от неизвестного major, а не угадывать. */
        check("schema=2: отказ", 2, load_from_str("{\"schema\":2,\"outputs\":{},\"channels\":[]}"));
        check("schema отсутствует: отказ", 2,
              load_from_str("{\"outputs\":{},\"channels\":[]}"));

        /* Канал → несуществующий выход: правило применяется, но ведёт в никуда. */
        check("канал → несуществующий выход: отказ", 2,
              load_from_str(SPEC("\"outputs\":{\"direct\":{\"kind\":\"direct\"}},"
                                 "\"channels\":[{\"name\":\"x\",\"out\":\"nope\","
                                 "\"match\":{\"domains_file\":\"/tmp/x.lst\"}}]}")));

        /* Смешанные MAC/IP в from: nft не умеет «или» внутри правила. */
        check("смешанные MAC/IP в from: отказ", 2,
              load_from_str(SPEC("\"outputs\":{\"wg\":{\"kind\":\"interface\",\"device\":\"wg0\"}},"
                                 "\"channels\":[{\"name\":\"m\",\"out\":\"wg\","
                                 "\"from\":[\"192.168.1.5\",\"aa:bb:cc:dd:ee:ff\"],"
                                 "\"match\":{\"domains_file\":\"/tmp/m.lst\"}}]}")));

        /* Дубликат устройства в failover-списке: второй кандидат идентичен первому,
         * failover бессмысленен. */
        check("дубликат устройства в devices: отказ", 2,
              load_from_str(SPEC("\"outputs\":{\"wg\":{\"kind\":\"interface\","
                                 "\"devices\":[\"wg0\",\"wg0\"]}},"
                                 "\"channels\":[{\"name\":\"c\",\"out\":\"wg\","
                                 "\"match\":{\"domains_file\":\"/tmp/c.lst\"}}]}")));

        /* any-канал в туннель (interface/vless) без allow_all уводит ВЕСЬ трафик
         * клиентов, включая доступ к роутеру и DNS. Требует явного согласия. */
        check("any в туннель без allow_all: отказ", 2,
              load_from_str(SPEC("\"outputs\":{\"wg\":{\"kind\":\"interface\",\"device\":\"wg0\"}},"
                                 "\"channels\":[{\"name\":\"a\",\"out\":\"wg\","
                                 "\"match\":{\"any\":true}}]}")));

        /* Тот же any-канал, но с allow_all=true внутри match — законная осознанная
         * конфигурация. allow_all живёт в match, рядом с any (строки 262-263 в spec.c). */
        check("any в туннель с allow_all: разрешён", 0,
              load_from_str(SPEC("\"outputs\":{\"wg\":{\"kind\":\"interface\",\"device\":\"wg0\"}},"
                                 "\"channels\":[{\"name\":\"a\",\"out\":\"wg\","
                                 "\"match\":{\"any\":true,\"allow_all\":true}}]}")));

        /* Неизвестный kind выхода: угадывать, что имел в виду человек, опаснее, чем
         * отказать. */
        check("неизвестный kind: отказ", 2,
              load_from_str(SPEC("\"outputs\":{\"x\":{\"kind\":\"magic\"}}")));

        /* Неизвестное on_fail: drop/direct/zapret — закрытое множество. */
        check("неизвестный on_fail: отказ", 2,
              load_from_str(SPEC("\"outputs\":{\"wg\":{\"kind\":\"interface\",\"device\":\"wg0\","
                                 "\"on_fail\":\"teleport\"}}")));

        /* Канал без name: его невозможно сослаться, объяснить, отлаживать. */
        check("канал без name: отказ", 2,
              load_from_str(SPEC("\"outputs\":{\"direct\":{\"kind\":\"direct\"}},"
                                 "\"channels\":[{\"out\":\"direct\","
                                 "\"match\":{\"domains_file\":\"/tmp/x.lst\"}}]}")));

        /* Канал без out: правило без назначения. */
        check("канал без out: отказ", 2,
              load_from_str(SPEC("\"outputs\":{\"direct\":{\"kind\":\"direct\"}},"
                                 "\"channels\":[{\"name\":\"x\","
                                 "\"match\":{\"domains_file\":\"/tmp/x.lst\"}}]}")));

        /* Канал, который ничего не матчит: нет ни списков, ни any. Правило без
         * смысла — отказываем громко, а не молча создаём пустой набор. */
        check("канал matches nothing: отказ", 2,
              load_from_str(SPEC("\"outputs\":{\"direct\":{\"kind\":\"direct\"}},"
                                 "\"channels\":[{\"name\":\"x\",\"out\":\"direct\","
                                 "\"match\":{}}]}")));

        /* Слишком много выходов: MAX_OUTPUTS=16 — жёсткий предел (метки/таблицы). */
        {
            char big[8192];
            char *p = big;
            p += sprintf(p, "%s\"outputs\":{", SPEC_OPEN);
            for (int i = 0; i < 17; i++)
                p += sprintf(p, "\"o%d\":{\"kind\":\"direct\"},", i);
            p += sprintf(p, "\"last\":{\"kind\":\"direct\"}}}");
            check("больше MAX_OUTPUTS выходов: отказ", 2, load_from_str(big));
        }

        /* Слишком много каналов: MAX_CHANNELS=64. */
        {
            char big[16384];
            char *p = big;
            p += sprintf(p, "%s\"outputs\":{\"direct\":{\"kind\":\"direct\"}},\"channels\":[",
                         SPEC_OPEN);
            for (int i = 0; i < 65; i++)
                p += sprintf(p, "{\"name\":\"c%d\",\"out\":\"direct\","
                               "\"match\":{\"domains_file\":\"/tmp/c.lst\"}},", i);
            p += sprintf(p, "{\"name\":\"last\",\"out\":\"direct\","
                           "\"match\":{\"domains_file\":\"/tmp/c.lst\"}}]}");
            check("больше MAX_CHANNELS каналов: отказ", 2, load_from_str(big));
        }
    }
    {
        /* Пограничный случай: ровно MAX_FILES (16) domains_files принимается.
         * Это НЕ тест на I-001 (переполнение 17+) — он будет добавлен отдельно как
         * красный тест к хотфиксу. Здесь проверяем, что граница «16 ещё работает». */
        char big[16384];
        char *p = big;
        p += sprintf(p, "%s\"outputs\":{\"direct\":{\"kind\":\"direct\"}},"
                        "\"channels\":[{\"name\":\"many\",\"out\":\"direct\",\"match\":{"
                        "\"domains_files\":[", SPEC_OPEN);
        for (int i = 0; i < 16; i++) {
            p += sprintf(p, "\"/tmp/d%d.lst\"", i);
            if (i < 15) p += sprintf(p, ",");
        }
        p += sprintf(p, "]}}]}");
        check("ровно 16 domains_files: принимается", 0, load_from_str(big));
        check("ровно 16 domains_files: domains_n=16", 16, (int)g_ch[0].domains_n);
    }
    {
        /* I-001: Больше MAX_FILES domains_files вызывает отказ, а не тихое обрезание */
        char big[16384];
        char *p = big;
        p += sprintf(p, "%s\"outputs\":{\"direct\":{\"kind\":\"direct\"}},"
                        "\"channels\":[{\"name\":\"many\",\"out\":\"direct\",\"match\":{"
                        "\"domains_files\":[", SPEC_OPEN);
        for (int i = 0; i < 17; i++) {
            p += sprintf(p, "\"/tmp/d%d.lst\"", i);
            if (i < 16) p += sprintf(p, ",");
        }
        p += sprintf(p, "]}}]}");
        check("больше 16 domains_files: отказ (I-001)", 2, load_from_str(big));
    }
    {
        /* I-001: Больше MAX_FROM from вызывает отказ */
        char big[16384];
        char *p = big;
        p += sprintf(p, "%s\"outputs\":{\"direct\":{\"kind\":\"direct\"}},"
                        "\"channels\":[{\"name\":\"many\",\"out\":\"direct\","
                        "\"from\":[", SPEC_OPEN);
        for (int i = 0; i < 17; i++) {
            p += sprintf(p, "\"10.0.0.%d\"", i);
            if (i < 16) p += sprintf(p, ",");
        }
        p += sprintf(p, "],\"match\":{\"any\":true,\"allow_all\":true}}]}");
        check("больше 16 from: отказ (I-001)", 2, load_from_str(big));
    }
    {
        /* I-002: Спека больше 256 КБ вызывает отказ */
        char *huge = malloc(262200);
        if (huge) {
            memset(huge, ' ', 262199);
            huge[262199] = '\0';
            char *p = huge;
            p += sprintf(p, "%s\"outputs\":{\"direct\":{\"kind\":\"direct\"}},\"channels\":[]", SPEC_OPEN);
            *p = ' ';
            huge[262198] = '}';
            check("спека больше 256 КБ: отказ (I-002)", 2, load_from_str(huge));
            free(huge);
        }
    }
    {
        /* I-006: Trailing comma в domains_files (путь str_list). Раньше str_list на
         * `[...,]` после последнего элемента делал continue, js_str видел ']' (не '"'),
         * возвращал -1 → return n ДО js_lit(']'), закрывающая скобка оставалась
         * несъеденной, и вызывающий цикл parse_channels while(*j.p != '}') крутился на
         * ']' вечно (100% CPU, зависание демона steer apply). Должен быть die()/exit(2). */
        const char *s = SPEC(
            "\"outputs\":{\"direct\":{\"kind\":\"direct\"}},"
            "\"channels\":[{\"name\":\"t\",\"out\":\"direct\","
            "\"match\":{\"domains_files\":[\"/tmp/a.lst\",]}}]}");
        check("trailing comma в domains_files: отказ (I-006)", 2, load_from_str(s));
    }
    {
        /* I-006: тот же дефект в str_array — путь `from`. str_array, как и str_list,
         * выходил через break до js_lit(']'), и оставшаяся ']' могла увести вызывающий
         * цикл в бесконечное вращение (js_str для ключа возвращает -1, возврат не
         * проверяется, j->p не двигается). */
        const char *s = SPEC(
            "\"outputs\":{\"wg\":{\"kind\":\"interface\",\"device\":\"wg0\"}},"
            "\"channels\":[{\"name\":\"t\",\"out\":\"wg\","
            "\"from\":[\"10.0.0.1\",],"
            "\"match\":{\"domains_file\":\"/tmp/a.lst\"}}]}");
        check("trailing comma в from: отказ (I-006)", 2, load_from_str(s));
    }
    {
        /* I-006: тот же дефект в inline-парсере devices внутри parse_outputs. Цикл
         * `else for(;;)` после `,` делает continue, js_str видит ']', break — и не
         * доходит до js_lit(']'). Оставшаяся ']' ломает parse_outputs аналогично. */
        const char *s = SPEC(
            "\"outputs\":{\"wg\":{\"kind\":\"interface\","
            "\"devices\":[\"wg0\",]}},"
            "\"channels\":[{\"name\":\"t\",\"out\":\"wg\","
            "\"match\":{\"domains_file\":\"/tmp/a.lst\"}}]}");
        check("trailing comma в devices: отказ (I-006)", 2, load_from_str(s));
    }

    printf("\n%s\n", fails ? "ЕСТЬ ПРОВАЛЫ" : "все проверки прошли");
    return fails ? 1 : 0;
}
