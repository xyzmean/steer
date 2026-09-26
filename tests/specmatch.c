/* Конфигурационный парсер: проверка семантики, а не скорости.
 *
 * Зачем отдельным тестом. Парсер spec.c — точка входа всей системы: прочитанный им
 * конфиг расходится по двум независимым потребителям (компилятору nftables-правил в
 * steer.c и резолверу в dnsd.c), которые читают ОДНИ те же глобалы. Ошибка здесь не
 * видна снаружи как сбой — правила встают, резолвер поднимается, но каждый работает
 * со своим пониманием конфигурации, и понять «почему трафик идёт не туда» потом
 * нечем. Поэтому проверяются граничные случаи, а не пара примеров:
 *
 *   - валидная спека заполняет g_spec.out[]/g_spec.ch[] ровно тем, что в ней написано;
 *   - пустые каналы законны (состояние «настроен, но ничего не направляет») и не
 *     должны отвергаться — иначе первичная настройка запирается наглухо;
 *   - выключенный канал остаётся в g_spec.ch[], но не режет применение спеки проверками;
 *   - каждая конфигурация, «которая отрежет доступ к роутеру» или которая не имеет
 *     смысла (несуществующий выход, смешанные MAC/IP, дубликат устройства в failover,
 *     «any без списков в туннель»), обязана вызвать die() и exit(2) — молчаливое
 *     применение такой спеки и есть тот класс бага, ради которого die существует.
 *
 * load_spec() ошибку ВОЗВРАЩАЕТ, а не завершает процесс сама (правило 5, docs/architecture.md,
 * раздел 2) — код 2 ниже не результат перехваченного exit(), а то же число, каким точка входа
 * (err_die) отвечает на -1 от load_spec. Перехватывать здесь больше нечего: стенд линкуется с
 * парсером отдельным объектом (MODEL_SRC, Makefile) и читает код возврата load_spec напрямую.
 * Текст отказа кладётся в struct err, а не идёт в stderr сам — в этом стенде он не
 * проверяется (проверяется код), а сверяет его текст снимок apply --dry-run (tests/snapshot.sh),
 * который гоняет настоящий бинарник. */
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <sys/stat.h>
#include <time.h>
#include <unistd.h>

#include "spec.h"

/* awg.c (вид awg) зовёт run_quiet из lib/run.c; стенду разбора он не нужен — ядро здесь не
 * трогают. */
int run_quiet(const char *const argv[]);
int run_quiet(const char *const argv[]) { (void)argv; return 0; }

static int fails;

/* Спека — значение, а не глобалы (правило 6, docs/architecture.md, раздел 2): один экземпляр
 * на весь стенд, заполняется load_spec/load_from_str заново перед каждым случаем. */
static struct spec g_spec;

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

/* Полный сброс глобалов парсера. g_spec.out_n/g_spec.ch_n нарастают между вызовами load_spec
 * (g_spec.out[g_spec.out_n++] = o), и без сброса второй тест увидит выходы первого. Список локальных
 * устройств возвращается к умолчанию «один br-lan», g_spec.traceroute_hops — к 0. g_state_dir
 * оставляем как есть: registry_assign в этих тестах не вызывается. */
static void reset_globals(void) {
    memset(&g_spec, 0, sizeof(g_spec));
    strcpy(g_spec.lan_dev[0], "br-lan");
    g_spec.lan_dev_n = 1;
}

/* Записать спеку во временный файл и скормить load_spec. Возвращает 0, если load_spec
 * завершилась нормально, или код exit, если отказала через die(). from_default задаём
 * явно во всех спеках: иначе load_spec зовёт popen("ip ..."), которого в окружении
 * теста нет, и автоопределение LAN молча оставляет g_spec.from_default_n == 0.
 *
 * Текст отказа load_spec кладёт в struct err, а не в stderr сам — этот стенд его не печатает
 * и не проверяет (проверяется код), ровно как раньше не перехватывалось и не проверялось
 * сообщение die(). При провале конкретный текст, если он нужен для разбора, видно на
 * снимке apply --dry-run (tests/snapshot.sh). Код 2 — то же число, каким точка входа отвечает
 * на -1 от load_spec (err_die), а 0 — успешный разбор. */
static int load_from_str(const char *spec) {
    reset_globals();
    /* Относительное имя во временной директории ОС: работает и на Linux (/tmp), и в
     * любой другой среде сборки. PID гарантирует уникальность, unlink — очистку.
     * Файл обязателен: load_spec читает путь, а не буфер. */
    char tmp[256];
    const char *td = getenv("TMPDIR");
    if (!td) td = "/tmp";
    snprintf(tmp, sizeof(tmp), "%s/specmatch.%d.json", td, (int)getpid());
    FILE *f = fopen(tmp, "w");
    if (f) { fputs(spec, f); fclose(f); }

    struct err e = {0};
    int rc = load_spec(tmp, &g_spec, &e) < 0 ? 2 : 0;
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
/* То же, но schema 2: измерение «протокол и порты» разрешено только там. Отдельным
 * макросом, а не подстановкой числа в SPEC, чтобы в каждом случае было видно, про какую
 * версию он: половина проверок ниже как раз про то, что версии не путаются. */
#define SPEC2(body) \
    "{\"schema\":2,\"from_default\":[\"192.168.1.0/24\"]," body "}"

int main(void) {
    /* Общий на все проверки ниже: registry_assign и прямые вызовы js_str не проверяют этот
     * стенд на отказ (тесты правила 5 — про load_spec, см. load_from_str), им нужен просто
     * struct err, чтобы позвать функцию новой сигнатуры. */
    struct err e = {0};
    {
        /* Минимальная валидная спека: один прямой выход, один доменный канал.
         * Заполняет g_spec.out_n=1, g_spec.ch_n=1; выход — OUT_DIRECT, канал смотрит на «direct». */
        const char *s = SPEC(
            "\"outputs\":{\"direct\":{\"kind\":\"direct\"}},"
            "\"channels\":[{\"name\":\"yt\",\"out\":\"direct\","
            "\"match\":{\"domains_file\":\"/tmp/yt.lst\"}}]}");
        check("минимальная спека: load_spec не отказывает", 0, load_from_str(s));
        check("минимальная спека: один выход", 1, (int)g_spec.out_n);
        check("минимальная спека: один канал", 1, (int)g_spec.ch_n);
        check_str("минимальная спека: имя выхода", "direct", g_spec.out[0].name);
        check("минимальная спека: kind direct", 1, kind_of(&g_spec.out[0]) == OUT_DIRECT);
        check_str("минимальная спека: имя канала", "yt", g_spec.ch[0].name);
        check_str("минимальная спека: канал → direct", "direct", g_spec.ch[0].out);
        check("минимальная спека: domains_n", 1, (int)g_spec.ch[0].domains_n);
        check_str("минимальная спека: domains_file", "/tmp/yt.lst", g_spec.ch[0].domains_files[0]);
    }
    {
        /* Выходы без каналов законны: steer настроен, но ничего не направляет. Это
         * правильное начальное состояние, и отказ на нём запирал бы первичную
         * настройку (см. комментарий в load_spec, строки 366-372). */
        const char *s = SPEC("\"outputs\":{\"direct\":{\"kind\":\"direct\"}}");
        check("только outputs, без channels: не отказывает", 0, load_from_str(s));
        check("только outputs: один выход", 1, (int)g_spec.out_n);
        check("только outputs: ноль каналов", 0, (int)g_spec.ch_n);
    }
    {
        /* Пустая секция channels: [] — то же состояние, что и отсутствие секции. */
        const char *s = SPEC("\"outputs\":{\"direct\":{\"kind\":\"direct\"}},\"channels\":[]");
        check("channels: [] — не отказывает", 0, load_from_str(s));
        check("channels: [] — ноль каналов", 0, (int)g_spec.ch_n);
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
        check("interface: devices_n=2", 2, (int)g_spec.out[0].devices_n);
        check_str("interface: device выведен из devices[0]", "wg0", g_spec.out[0].device);
    }
    {
        /* Выключенный канал остаётся в g_spec.ch[], но проходит проверку «matches nothing»,
         * потому что проверка отключённых пропускается (строки 416). Без этого
         * выключить сломанное правило было бы нельзя — только удалить. */
        const char *s = SPEC(
            "\"outputs\":{\"direct\":{\"kind\":\"direct\"}},"
            "\"channels\":[{\"name\":\"off\",\"out\":\"direct\",\"enabled\":false,"
            "\"match\":{\"any\":true}}]}");
        check("выключенный any-канал: не отказывает", 0, load_from_str(s));
        check("выключенный канал: в g_spec.ch[]", 1, (int)g_spec.ch_n);
        check("выключенный канал: disabled=1", 1, g_spec.ch[0].disabled);
    }
    {
        /* ---- schema 2: протокол и порты назначения ---------------------------------
         *
         * ПОЧЕМУ ВЕРСИЯ, А НЕ ПРОСТО НОВЫЙ КЛЮЧ. Неизвестный ключ парсер пропускает
         * (js_skip), и для всего, что совпадение РАСШИРЯЕТ, это верно: не понял — ничего не
         * потерял. Порты совпадение СУЖАЮТ: канал Discord это 104.16.0.0/12 (Cloudflare)
         * плюс udp 50000-65535, и пропущенный ключ означал бы «сузить забыли», то есть весь
         * TCP к Cloudflare молча в туннель. Отсюда major: движок постарше обязан отвергнуть
         * спеку ЦЕЛИКОМ, а не понять её наполовину.
         */
        check("schema=2: принимается", 0,
              load_from_str("{\"schema\":2,\"outputs\":{},\"channels\":[]}"));

        /* Discord как он есть: подсети плюс протокол плюс два диапазона. */
        check("proto и ports разбираются", 0,
              load_from_str(SPEC2("\"outputs\":{\"wg\":{\"kind\":\"interface\",\"device\":\"wg0\"}},"
                                  "\"channels\":[{\"name\":\"dc\",\"out\":\"wg\",\"match\":{"
                                  "\"prefixes_file\":\"/tmp/dc.lst\",\"proto\":\"udp\","
                                  "\"ports\":[\"50000-65535\",\"19000-20000\"]}}]}")));
        check("proto udp", CH_PROTO_UDP, g_spec.ch[0].l4.proto);
        check("диапазонов два", 2, (int)g_spec.ch[0].l4.ports_n);
        check("первый диапазон: начало", 50000, g_spec.ch[0].l4.ports[0].lo);
        check("первый диапазон: конец", 65535, g_spec.ch[0].l4.ports[0].hi);
        check("второй диапазон: начало", 19000, g_spec.ch[0].l4.ports[1].lo);
        check("второй диапазон: конец", 20000, g_spec.ch[0].l4.ports[1].hi);

        /* Одиночный порт — это диапазон из одного: одна форма во внутреннем виде избавляет
         * и разбор, и генератор от ветки «а это порт или диапазон». */
        check("одиночный порт принимается", 0,
              load_from_str(SPEC2("\"outputs\":{\"wg\":{\"kind\":\"interface\",\"device\":\"wg0\"}},"
                                  "\"channels\":[{\"name\":\"p\",\"out\":\"wg\",\"match\":{"
                                  "\"prefixes_file\":\"/tmp/p.lst\",\"ports\":[\"443\"]}}]}")));
        check("одиночный порт: lo == hi", 1,
              g_spec.ch[0].l4.ports[0].lo == 443 && g_spec.ch[0].l4.ports[0].hi == 443);
        /* Протокол не назван — сужения по протоколу нет, и это не то же самое, что «оба
         * протокола вместо всех»: генератор допишет `meta l4proto { tcp, udp }` только как
         * носитель для чтения порта (см. emit_l4 в steer.c). */
        check("порты без proto: протокол не выдуман", CH_PROTO_ANY, g_spec.ch[0].l4.proto);

        /* `both` — это ЗАПИСАННОЕ умолчание, а не третье поведение. */
        check("proto both принимается", 0,
              load_from_str(SPEC2("\"outputs\":{\"wg\":{\"kind\":\"interface\",\"device\":\"wg0\"}},"
                                  "\"channels\":[{\"name\":\"p\",\"out\":\"wg\",\"match\":{"
                                  "\"prefixes_file\":\"/tmp/p.lst\",\"proto\":\"both\"}}]}")));
        check("proto both значит «не критерий»", CH_PROTO_ANY, g_spec.ch[0].l4.proto);
        /* ...но ключ схемы 2 при этом ЗАПИСАН, и в спеке schema 1 он обязан быть отказом:
         * иначе «both» проходил бы там, где «udp» отвергается, а человек читал бы это как
         * «порты в первой схеме работают». */
        check("proto both в схеме 1: отказ", 2,
              load_from_str(SPEC("\"outputs\":{\"wg\":{\"kind\":\"interface\",\"device\":\"wg0\"}},"
                                 "\"channels\":[{\"name\":\"p\",\"out\":\"wg\",\"match\":{"
                                 "\"prefixes_file\":\"/tmp/p.lst\",\"proto\":\"both\"}}]}")));

        /* Спека schema 1 с полями схемы 2 — отказ, а НЕ молчаливый пропуск. Молчаливый
         * пропуск и есть та беда, от которой заведена версия: человек считает, что сузил. */
        check("ports в схеме 1: отказ", 2,
              load_from_str(SPEC("\"outputs\":{\"wg\":{\"kind\":\"interface\",\"device\":\"wg0\"}},"
                                 "\"channels\":[{\"name\":\"p\",\"out\":\"wg\",\"match\":{"
                                 "\"prefixes_file\":\"/tmp/p.lst\",\"ports\":[\"443\"]}}]}")));
        check("proto в схеме 1: отказ", 2,
              load_from_str(SPEC("\"outputs\":{\"wg\":{\"kind\":\"interface\",\"device\":\"wg0\"}},"
                                 "\"channels\":[{\"name\":\"p\",\"out\":\"wg\",\"match\":{"
                                 "\"prefixes_file\":\"/tmp/p.lst\",\"proto\":\"udp\"}}]}")));
        /* Отказ касается и ВЫКЛЮЧЕННОГО канала, в отличие от прочих проверок канала. Там
         * исключение сделано затем, чтобы сломанное правило можно было выключить, а не
         * только удалить; здесь чинить надо не правило, а число схемы у всей спеки. */
        check("ports в схеме 1 у выключенного канала: тоже отказ", 2,
              load_from_str(SPEC("\"outputs\":{\"wg\":{\"kind\":\"interface\",\"device\":\"wg0\"}},"
                                 "\"channels\":[{\"name\":\"p\",\"out\":\"wg\",\"enabled\":false,"
                                 "\"match\":{\"prefixes_file\":\"/tmp/p.lst\","
                                 "\"ports\":[\"443\"]}}]}")));

        /* Порты БЕЗ списка адресов — недописанная настройка, а не «канал ловит по портам»:
         * правило без `ip daddr` накрыло бы весь трафик клиентов на этих портах. Прежний
         * отказ обязан остаться в силе — новые поля источником совпадения не являются. */
        check("одни порты, без списков: matches nothing", 2,
              load_from_str(SPEC2("\"outputs\":{\"wg\":{\"kind\":\"interface\",\"device\":\"wg0\"}},"
                                  "\"channels\":[{\"name\":\"p\",\"out\":\"wg\",\"match\":{"
                                  "\"proto\":\"udp\",\"ports\":[\"443\"]}}]}")));

        /* Негодные записи — громкий отказ. Не педантизм: `nft -f` отвергает набор правил
         * ЦЕЛИКОМ на одном плохом элементе, и тогда на роутере остаются прежние правила, а
         * человек видит, что его выбор не подействовал, без намёка на причину. */
#define PORTS(v) SPEC2("\"outputs\":{\"wg\":{\"kind\":\"interface\",\"device\":\"wg0\"}}," \
                       "\"channels\":[{\"name\":\"p\",\"out\":\"wg\",\"match\":{" \
                       "\"prefixes_file\":\"/tmp/p.lst\",\"ports\":" v "}}]}")
        check("порт 0: отказ", 2, load_from_str(PORTS("[\"0\"]")));
        check("порт 65536: отказ", 2, load_from_str(PORTS("[\"65536\"]")));
        check("перевёрнутый диапазон: отказ", 2, load_from_str(PORTS("[\"9-1\"]")));
        check("не число: отказ", 2, load_from_str(PORTS("[\"abc\"]")));
        check("хвост после диапазона: отказ", 2, load_from_str(PORTS("[\"1-2-3\"]")));
        /* Двоеточие — форма sing-box (`port_range 50000:65535`). У нас диапазон пишется
         * тире, как у адресов (`10.0.9.0-10.0.9.5`), и принять чужую форму молча значило бы
         * иметь два синтаксиса, из которых один нигде не описан. */
        check("двоеточие вместо тире: отказ", 2, load_from_str(PORTS("[\"50000:65535\"]")));
        check("пустая строка: отказ", 2, load_from_str(PORTS("[\"\"]")));
        check("пробел внутри: отказ", 2, load_from_str(PORTS("[\"443 \"]")));
        check("число вместо строки: отказ", 2, load_from_str(PORTS("[443]")));
        check("не массив: отказ", 2, load_from_str(PORTS("\"443\"")));
        check("висящая запятая: отказ", 2, load_from_str(PORTS("[\"443\",]")));
        /* Повтор и пересечение — тоже отказ, и по той же причине, что негодная запись: nft
         * не принимает множество с накладывающимися интервалами. Проверка наша потому, что
         * его сообщение приходит после того, как применение уже началось. */
        check("повтор диапазона: отказ", 2, load_from_str(PORTS("[\"443\",\"443\"]")));
        check("пересечение: отказ", 2, load_from_str(PORTS("[\"1-100\",\"50-60\"]")));
        check("вложение: отказ", 2, load_from_str(PORTS("[\"1-100\",\"40-50\"]")));
        check("соседние диапазоны: принимаются", 0, load_from_str(PORTS("[\"1-100\",\"101-200\"]")));
        check("неизвестный proto: отказ", 2,
              load_from_str(SPEC2("\"outputs\":{\"wg\":{\"kind\":\"interface\",\"device\":\"wg0\"}},"
                                  "\"channels\":[{\"name\":\"p\",\"out\":\"wg\",\"match\":{"
                                  "\"prefixes_file\":\"/tmp/p.lst\",\"proto\":\"sctp\"}}]}")));
        /* Пустой массив — это «портов не задано», а не отказ: так интерфейс, у которого
         * поле портов не заполнено, пишет его без особого случая. */
        check("пустой массив портов: принимается", 0, load_from_str(PORTS("[]")));
        check("пустой массив: ноль диапазонов", 0, (int)g_spec.ch[0].l4.ports_n);

        /* Границы предела. Числа берутся из MAX_PORTS, а не вписаны: следующий, кто его
         * подвинет, не должен править ещё и стенд. */
        {
            char big[4096], *q = big;
            q += sprintf(q, "%s\"outputs\":{\"wg\":{\"kind\":\"interface\",\"device\":\"wg0\"}},"
                            "\"channels\":[{\"name\":\"p\",\"out\":\"wg\",\"match\":{"
                            "\"prefixes_file\":\"/tmp/p.lst\",\"ports\":[",
                         "{\"schema\":2,\"from_default\":[\"192.168.1.0/24\"],");
            for (size_t i = 0; i < MAX_PORTS; i++)
                q += sprintf(q, "%s\"%zu\"", i ? "," : "", 1000 + i * 2);
            q += sprintf(q, "]}}]}");
            check("ровно MAX_PORTS диапазонов: принимается", 0, load_from_str(big));
            check("ровно MAX_PORTS: сосчитаны все", (int)MAX_PORTS, (int)g_spec.ch[0].l4.ports_n);
        }
        {
            char big[4096], *q = big;
            q += sprintf(q, "%s\"outputs\":{\"wg\":{\"kind\":\"interface\",\"device\":\"wg0\"}},"
                            "\"channels\":[{\"name\":\"p\",\"out\":\"wg\",\"match\":{"
                            "\"prefixes_file\":\"/tmp/p.lst\",\"ports\":[",
                         "{\"schema\":2,\"from_default\":[\"192.168.1.0/24\"],");
            for (size_t i = 0; i <= MAX_PORTS; i++)
                q += sprintf(q, "%s\"%zu\"", i ? "," : "", 1000 + i * 2);
            q += sprintf(q, "]}}]}");
            /* На один больше — отказ, а не тихое обрезание: обрезанный перечень портов это
             * канал ШИРЕ написанного, то есть та же беда, что у обрезанного списка файлов. */
            check("больше MAX_PORTS диапазонов: отказ", 2, load_from_str(big));
        }
#undef PORTS

        /* ---- имя набора расходится вместе с сужением -------------------------------
         *
         * Ядро сливает одноимённые наборы МОЛЧА, поэтому два канала одного выхода с разными
         * портами обязаны получить разные имена — иначе они поделят один набор адресов, и
         * ограничение по портам либо распространится на чужие адреса, либо пропадёт. Та же
         * беда и то же лечение, что у списка клиентов (см. from_disc в spec.c).
         *
         * Имя вычисляется ОБЩЕЙ функцией: её же зовёт резолвер, решая, в какой набор класть
         * адрес разрешённого домена. Поэтому проверяется она, а не текст правил. */
        check("два сужения в одной спеке: принимается", 0,
              load_from_str(SPEC2("\"outputs\":{\"wg\":{\"kind\":\"interface\",\"device\":\"wg0\"}},"
                                  "\"channels\":["
                                  "{\"name\":\"yt\",\"out\":\"wg\",\"match\":{"
                                  "\"prefixes_file\":\"/tmp/yt.lst\"}},"
                                  "{\"name\":\"dc\",\"out\":\"wg\",\"match\":{"
                                  "\"prefixes_file\":\"/tmp/dc.lst\",\"proto\":\"udp\","
                                  "\"ports\":[\"50000-65535\"]}}]}")));
        {
            char n0[64], n1[64];
            group_set_name(&g_spec, n0, sizeof(n0), "wg", "ip", g_spec.from_default, g_spec.from_default_n, 0,
                           &g_spec.ch[0].l4);
            group_set_name(&g_spec, n1, sizeof(n1), "wg", "ip", g_spec.from_default, g_spec.from_default_n, 0,
                           &g_spec.ch[1].l4);
            /* Канал без сужения обязан сохранить ПРЕЖНЕЕ имя: на установленных роутерах от
             * имени набора зависит перенос счётчиков, и переименование стоило бы обнулённых
             * объёмов у каждого канала при обновлении движка. */
            check_str("канал без сужения: имя прежнее", "wg_ip", n0);
            check("канал с сужением: имя другое", 1, strcmp(n0, n1) != 0);
            /* Предел длины имени набора у nftables на старых ядрах — 32 символа. */
            check("имя с сужением укладывается в 32 символа", 1, (int)strlen(n1) < 32);
        }
    }
    {
        /* ---- невалидные спеки: каждая обязана die()/exit(2) ---- */

        /* Неизвестный major — отказ; весь смысл поля в этом, а не в угадывании. Двойка
         * теперь ЗНАКОМА (протокол и порты у канала), поэтому граница проверяется тройкой:
         * стеречь надо отказ на незнакомом числе, а не конкретное число. */
        check("schema=3: отказ", 2, load_from_str("{\"schema\":3,\"outputs\":{},\"channels\":[]}"));
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
        /* Пограничный случай: ровно MAX_FILES списков принимается.
         *
         * Предел вырос с шестнадцати до шестидесяти четырёх: в каталоге splify2 под сорок
         * записей, и «отправить в туннель всё» упиралось в `too many entries in list` уже на
         * восьмом сервисе. Числа здесь взяты из MAX_FILES, а не вписаны: следующий, кто его
         * подвинет, не должен править ещё и стенд, чтобы тот остался про границу. */
        char big[65536];
        char *p = big;
        p += sprintf(p, "%s\"outputs\":{\"direct\":{\"kind\":\"direct\"}},"
                        "\"channels\":[{\"name\":\"many\",\"out\":\"direct\",\"match\":{"
                        "\"domains_files\":[", SPEC_OPEN);
        for (size_t i = 0; i < MAX_FILES; i++) {
            p += sprintf(p, "\"/tmp/d%zu.lst\"", i);
            if (i + 1 < MAX_FILES) p += sprintf(p, ",");
        }
        p += sprintf(p, "]}}]}");
        check("ровно MAX_FILES domains_files: принимается", 0, load_from_str(big));
        check("ровно MAX_FILES domains_files: сосчитаны все", (int)MAX_FILES, (int)g_spec.ch[0].domains_n);
    }
    {
        /* I-001: на один больше — отказ, а не тихое обрезание. Тихое обрезание здесь хуже
         * отказа вдвойне: канал остался бы, а часть списков молча выпала — и узкое правило
         * стало бы шире, чем человек написал. */
        char big[65536];
        char *p = big;
        p += sprintf(p, "%s\"outputs\":{\"direct\":{\"kind\":\"direct\"}},"
                        "\"channels\":[{\"name\":\"many\",\"out\":\"direct\",\"match\":{"
                        "\"domains_files\":[", SPEC_OPEN);
        for (size_t i = 0; i <= MAX_FILES; i++) {
            p += sprintf(p, "\"/tmp/d%zu.lst\"", i);
            if (i < MAX_FILES) p += sprintf(p, ",");
        }
        p += sprintf(p, "]}}]}");
        check("больше MAX_FILES domains_files: отказ (I-001)", 2, load_from_str(big));
    }
    {
        /* I-001: Больше MAX_FROM from вызывает отказ */
        char big[16384];
        char *p = big;
        p += sprintf(p, "%s\"outputs\":{\"direct\":{\"kind\":\"direct\"}},"
                        "\"channels\":[{\"name\":\"many\",\"out\":\"direct\","
                        "\"from\":[", SPEC_OPEN);
        /* Предел берётся из MAX_FROM, а не числом: он уже менялся (16 -> 32), и
         * записанное руками число превращает проверку предела в проверку прошлого. */
        for (int i = 0; i < MAX_FROM + 1; i++) {
            p += sprintf(p, "\"10.0.0.%d\"", i);
            if (i < MAX_FROM) p += sprintf(p, ",");
        }
        p += sprintf(p, "],\"match\":{\"any\":true,\"allow_all\":true}}]}");
        check("больше MAX_FROM from: отказ (I-001)", 2, load_from_str(big));
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

    /* ---- obfs: WireGuard поверх поддельного TCP ---------------------------------
     *
     * Проверяется ровно то, что молчаливо ломает туннель: принятое, но неполное
     * описание обфускации выглядит как настроенный выход, из которого не выходит ни
     * одного пакета. Поэтому каждый пропуск — отказ, а не умолчание. */
    {
        const char *s = SPEC(
            "\"outputs\":{\"wg\":{\"kind\":\"interface\",\"device\":\"wg0\","
            "\"obfs\":{\"mode\":\"wg-over-tcp\",\"server\":\"203.0.113.10:4567\","
            "\"listen\":\"127.0.0.1:51820\"}}},"
            "\"channels\":[]}");
        check("obfs: спека принята", 0, load_from_str(s));
        check("obfs: признак включён", 1, g_spec.out[0].iface.obfs.on);
        check_str("obfs: адрес сервера", "203.0.113.10", g_spec.out[0].iface.obfs.server);
        check("obfs: порт сервера", 4567, g_spec.out[0].iface.obfs.server_port);
        check_str("obfs: локальный адрес", "127.0.0.1", g_spec.out[0].iface.obfs.listen);
        check("obfs: локальный порт", 51820, g_spec.out[0].iface.obfs.listen_port);
    }
    {
        /* Умолчание по режиму: спека без mode обязана значить сегодняшний
         * единственный режим, иначе добавление второго сломало бы уже написанные. */
        const char *s = SPEC(
            "\"outputs\":{\"wg\":{\"kind\":\"interface\",\"device\":\"wg0\","
            "\"obfs\":{\"server\":\"203.0.113.10:4567\",\"listen\":\"127.0.0.1:51820\"}}},"
            "\"channels\":[]}");
        check("obfs: без mode — тот же режим", 0, load_from_str(s));
        check("obfs: без mode — признак включён", 1, g_spec.out[0].iface.obfs.on);
    }
    {
        const char *s = SPEC(
            "\"outputs\":{\"wg\":{\"kind\":\"interface\",\"device\":\"wg0\","
            "\"obfs\":{\"mode\":\"udp2raw\",\"server\":\"203.0.113.10:4567\","
            "\"listen\":\"127.0.0.1:51820\"}}},"
            "\"channels\":[]}");
        check("obfs: неизвестный mode — отказ", 2, load_from_str(s));
    }
    {
        const char *s = SPEC(
            "\"outputs\":{\"wg\":{\"kind\":\"interface\",\"device\":\"wg0\","
            "\"obfs\":{\"server\":\"203.0.113.10\",\"listen\":\"127.0.0.1:51820\"}}},"
            "\"channels\":[]}");
        check("obfs: server без порта — отказ", 2, load_from_str(s));
    }
    {
        /* Имя вместо адреса: разрешать его пришлось бы через DNS, который может идти
         * в тот самый туннель, который поднимается через этот самый сервер. */
        const char *s = SPEC(
            "\"outputs\":{\"wg\":{\"kind\":\"interface\",\"device\":\"wg0\","
            "\"obfs\":{\"server\":\"vpn.example.com:4567\",\"listen\":\"127.0.0.1:51820\"}}},"
            "\"channels\":[]}");
        check("obfs: имя вместо адреса — отказ", 2, load_from_str(s));
    }
    {
        const char *s = SPEC(
            "\"outputs\":{\"wg\":{\"kind\":\"interface\",\"device\":\"wg0\","
            "\"obfs\":{\"server\":\"203.0.113.10:4567\"}}},"
            "\"channels\":[]}");
        check("obfs: без listen — отказ", 2, load_from_str(s));
    }
    {
        /* У direct транспорта нет вовсе, обфусцировать нечего. Принять поле молча
         * значило бы сказать «настроено», не настроив ничего. */
        const char *s = SPEC(
            "\"outputs\":{\"direct\":{\"kind\":\"direct\","
            "\"obfs\":{\"server\":\"203.0.113.10:4567\",\"listen\":\"127.0.0.1:51820\"}}},"
            "\"channels\":[]}");
        check("obfs: на kind=direct — отказ", 2, load_from_str(s));
    }
    {
        /* Спека без obfs обязана оставлять признак выключенным: поле, которого нет,
         * не должно означать «включено» ни при какой раскладке памяти. */
        const char *s = SPEC(
            "\"outputs\":{\"wg\":{\"kind\":\"interface\",\"device\":\"wg0\"}},"
            "\"channels\":[]}");
        check("без obfs: спека принята", 0, load_from_str(s));
        check("без obfs: признак выключен", 0, g_spec.out[0].iface.obfs.on);
    }

    /* ---- kind=zapret: выход без устройства, но с меткой -------------------------
     *
     * Проверяется в ОБЕИХ сборках, в отличие от vless и xsteer: обход DPI делает чужой
     * процесс (nfqws), криптографии движка тут не нужно, и отказывать базовой сборке было
     * бы отказом без причины. */
    {
        const char *s = SPEC(
            "\"outputs\":{\"yt\":{\"kind\":\"zapret\"}},"
            "\"channels\":[]}");
        check("zapret: спека принята", 0, load_from_str(s));
        check("zapret: вид zapret", 1, kind_of(&g_spec.out[0]) == OUT_ZAPRET);
        /* Главное различие этого вида: устройства нет, а метка есть. Пока условие было
         * одно на две надобности, такой выход получил бы правило канала и не получил
         * метки — то есть в очередь не попал бы ни один пакет. */
        check("zapret: устройства нет", 0, out_has_device(&g_spec.out[0]));
        check("zapret: метка нужна", 1, out_needs_mark(&g_spec.out[0]));
        check("zapret: устройство не названо", 0, g_spec.out[0].device[0]);
        check_str("zapret: opts_file по умолчанию из имени выхода",
                  "/etc/steer/zapret/yt.opts", g_spec.out[0].zp.opts);
        /* Умолчание on_fail общее для всех выходов — drop, и здесь оно значит «нет обхода
         * — нет трафика», то есть очередь без bypass. */
        check("zapret: on_fail по умолчанию drop", FAIL_DROP, g_spec.out[0].on_fail);
    }
    {
        const char *s = SPEC(
            "\"outputs\":{\"yt\":{\"kind\":\"zapret\",\"opts_file\":\"/etc/y.opts\"}},"
            "\"channels\":[]}");
        check("zapret: явный opts_file принят", 0, load_from_str(s));
        check_str("zapret: явный opts_file сохранён", "/etc/y.opts", g_spec.out[0].zp.opts);
    }
    {
        /* Относительный путь «работал бы из шелла» и не работал бы у службы: процесс
         * запускает procd со своим рабочим каталогом. Тот же барьер, что у conf у xsteer. */
        const char *s = SPEC(
            "\"outputs\":{\"yt\":{\"kind\":\"zapret\",\"opts_file\":\"y.opts\"}},"
            "\"channels\":[]}");
        check("zapret: относительный opts_file — отказ", 2, load_from_str(s));
    }
    {
        /* Названное устройство — почти наверняка описка при копировании выхода-туннеля.
         * Принять его молча значило бы обещать маршрутизацию, которой не будет. */
        const char *s = SPEC(
            "\"outputs\":{\"yt\":{\"kind\":\"zapret\",\"device\":\"wg0\"}},"
            "\"channels\":[]}");
        check("zapret: device — отказ", 2, load_from_str(s));
    }
    {
        /* «При отказе обхода включить обход» — круг, который ничего не значит. */
        const char *s = SPEC(
            "\"outputs\":{\"yt\":{\"kind\":\"zapret\",\"on_fail\":\"zapret\"}},"
            "\"channels\":[]}");
        check("zapret: on_fail zapret у себя же — отказ", 2, load_from_str(s));
    }
    {
        /* Поле, принятое молча у чужого вида выхода, — это «настроено», сказанное о том,
         * что не настроено. Тот же довод, что у obfs и stream. */
        const char *s = SPEC(
            "\"outputs\":{\"wg\":{\"kind\":\"interface\",\"device\":\"wg0\","
            "\"opts_file\":\"/etc/y.opts\"}},"
            "\"channels\":[]}");
        check("opts_file у kind=interface — отказ", 2, load_from_str(s));
    }
    {
        /* Номер очереди выводится из метки, а не задаётся человеком: второй источник
         * правды о том, какой процесс какой трафик разбирает, разошёлся бы молча.
         * Проверяется именно ВЫВОД: первый недирект-выход получает младший бит. */
        const char *s = SPEC(
            "\"outputs\":{\"a\":{\"kind\":\"zapret\"},\"b\":{\"kind\":\"zapret\"}},"
            "\"channels\":[]}");
        check("zapret: две очереди, спека принята", 0, load_from_str(s));
        g_spec.out[0].mark = STEER_MARK_BASE;
        g_spec.out[1].mark = STEER_MARK_BASE << 1;
        check("zapret: очередь первого выхода", ZAPRET_QUEUE_BASE,
              out_zapret_queue(&g_spec.out[0]));
        check("zapret: очередь второго выхода", ZAPRET_QUEUE_BASE + 1,
              out_zapret_queue(&g_spec.out[1]));
    }

    /* ---- виды выходов, существующие только в расширенной сборке ------------------
     *
     * Этот же файл собирается ДВАЖДЫ: build/specmatch без STEER_EXTENDED и
     * build/specmatch-ext с ним. Иначе положительные случаи kind=vless и kind=xsteer
     * недостижимы вовсе — базовая сборка отвергает такую спеку парсером, — и до
     * появления второго бинарника vless не был проверен здесь ни одной строкой.
     * Прецедент тот же, что у build/diagsim: один исходник, два бинарника. */
    {
        const char *s = SPEC(
            "\"outputs\":{\"vpn\":{\"kind\":\"xsteer\"}},"
            "\"channels\":[]}");
#ifdef STEER_EXTENDED
        check("xsteer: спека принята", 0, load_from_str(s));
        check("xsteer: вид xsteer", 1, kind_of(&g_spec.out[0]) == OUT_XSTEER);
        /* Устройство и путь к конфигурации выводятся из имени выхода: держать их
         * отдельными полями значило бы позволить двум именам разойтись. */
        check_str("xsteer: устройство из имени выхода", "vpn", g_spec.out[0].device);
        check("xsteer: один кандидат в devices", 1, (int)g_spec.out[0].devices_n);
        check_str("xsteer: conf по умолчанию", "/etc/steer/xsteer/vpn.conf", g_spec.out[0].xs.conf);
        check("xsteer: считается выходом с устройством", 1, out_has_device(&g_spec.out[0]));
        check("xsteer: устройство создаёт наш процесс", 1, out_engine_managed(&g_spec.out[0]));
        check("xsteer: masquerade не нужен", 1, out_self_natting(&g_spec.out[0]));
#else
        /* Базовая сборка обязана отказать ПАРСЕРОМ, а не при подъёме: иначе правила и
         * метки встают, устройства не создаёт никто, и человек видит рабочую с виду
         * конфигурацию, из которой не выходит ни один пакет. */
        check("xsteer: базовая сборка отвергает вид", 2, load_from_str(s));
#endif
    }
    {
        /* То же обещание для vless — до второго бинарника оно не проверялось нигде. */
        const char *s = SPEC(
            "\"outputs\":{\"vpn\":{\"kind\":\"vless\",\"sub_file\":\"/tmp/sub.txt\"}},"
            "\"channels\":[]}");
#ifdef STEER_EXTENDED
        check("vless: спека принята", 0, load_from_str(s));
        check("vless: вид vless", 1, kind_of(&g_spec.out[0]) == OUT_VLESS);
        check("vless: устройство создаёт наш процесс", 1, out_engine_managed(&g_spec.out[0]));
#else
        check("vless: базовая сборка отвергает вид", 2, load_from_str(s));
#endif
    }

    /* ---- выбор узлов подписки: список кандидатов, а не один номер ---------------------
     *
     * У выхода kind=vless был ровно один `node`, и выбрать три локации из двадцати шести
     * было нечем: либо зашитый номер, либо -1 «первый рабочий среди всех». Просьба
     * интерфейса — то же самое, что `devices` у kind=interface, только кандидаты называются
     * номерами узлов, поэтому и форма та же: `nodes` списком, `node` — сокращение для одного,
     * пустой список — прежнее умолчание.
     *
     * Проверяется здесь и разбор, и ЗНАЧЕНИЕ поля (out_node_list): порядок перебора решает,
     * через какую страну пойдёт трафик, а стенда на подъём туннеля нет — он требует и
     * mbedtls, и сети. Функции живут в src/kinds/vless.c, то есть только в расширенной сборке. */
#ifdef STEER_EXTENDED
    {
        /* Развёртка выбора в порядок перебора. Собирается прямо в структуре: это чистая
         * функция от поля спеки и размера подписки, спека для неё не нужна. */
        struct output o = {0};
        int dst[16];
        check("nodes пуст: перебирается вся подписка", 4,
              (int)out_node_list(&o, 4, dst, 16));
        check("nodes пуст: порядок подписки", 1, dst[0] == 0 && dst[3] == 3);

        o.vless.nodes_n = 3;
        o.vless.nodes[0] = 6; o.vless.nodes[1] = 7; o.vless.nodes[2] = 12;
        check("выбор из трёх: кандидатов трое", 3, (int)out_node_list(&o, 26, dst, 16));
        check("выбор из трёх: порядок предпочтения сохранён", 1,
              dst[0] == 6 && dst[1] == 7 && dst[2] == 12);
        /* Подписка обновилась и стала короче: устаревший номер пропускается, а не выключает
         * локации, которые на месте. */
        check("номер вне подписки пропущен", 2, (int)out_node_list(&o, 8, dst, 16));
        check("после пропуска остались выбранные", 1, dst[0] == 6 && dst[1] == 7);
        /* А вот когда за пределы уехали ВСЕ, перебирать вместо выбранного что попало нельзя:
         * это увело бы трафик в локацию, которую человек не выбирал, и молча. Ноль здесь —
         * приговор для клиента, а не «значит, перебираем всё». */
        check("выбор целиком вне подписки — кандидатов нет", 0,
              (int)out_node_list(&o, 3, dst, 16));
    }
    /* ---- нужен ли перебор: кто назвал узел, а не сколько кандидатов осталось ----------
     *
     * Клиент vless пропускал проверку узла, когда кандидат оставался один, — а один он
     * остаётся и без всякого выбора человека: подписка из единственного узла, или из трёх
     * выбранных уцелел один после её обновления. Туннель поднимался на непроверенном узле, и
     * вместо приговора «ни один узел подписки не отвечает» человек получал обратно то самое
     * «устройства нет», ради снятия которого перебор и стал виден (I-100). */
    {
        struct output o = {0};
        check("подписка из одного узла: узел никем не назван", 0, out_node_named(&o));
        o.vless.nodes_n = 3; o.vless.nodes[0] = 6; o.vless.nodes[1] = 7; o.vless.nodes[2] = 12;
        check("из трёх выбранных уцелел один: выбор всё равно не именной", 0,
              out_node_named(&o));
        o.vless.nodes_n = 1; o.vless.nodes[0] = 4;
        check("номер написан в спеке: узел назван", 1, out_node_named(&o));
    }
#endif
    {
        /* Выбор узлов есть только у подписки. У kind=interface кандидаты — устройства, и
         * принять здесь `nodes` молча значило бы сказать «настроено», не настроив ничего. */
        const char *s = SPEC(
            "\"outputs\":{\"wg\":{\"kind\":\"interface\",\"device\":\"wg0\","
            "\"nodes\":[1,2]}},"
            "\"channels\":[]}");
        check("nodes на kind=interface — отказ", 2, load_from_str(s));
    }
#ifdef STEER_EXTENDED
    {
        const char *s = SPEC(
            "\"outputs\":{\"vpn\":{\"kind\":\"vless\",\"sub_file\":\"/tmp/sub.txt\","
            "\"nodes\":[6,7,12]}},"
            "\"channels\":[]}");
        check("nodes: спека принята", 0, load_from_str(s));
        check("nodes: кандидатов трое", 3, (int)g_spec.out[0].vless.nodes_n);
        check("nodes: порядок как написан", 1,
              g_spec.out[0].vless.nodes[0] == 6 && g_spec.out[0].vless.nodes[1] == 7 && g_spec.out[0].vless.nodes[2] == 12);
    }
    {
        /* Одиночная форма — сокращение для списка из одного, дальше по коду путь один. */
        const char *s = SPEC(
            "\"outputs\":{\"vpn\":{\"kind\":\"vless\",\"sub_file\":\"/tmp/sub.txt\","
            "\"node\":4}},"
            "\"channels\":[]}");
        check("node: спека принята", 0, load_from_str(s));
        check("node: один кандидат", 1, (int)g_spec.out[0].vless.nodes_n);
        check("node: номер сохранён", 4, g_spec.out[0].vless.nodes[0]);
    }
    {
        /* Прежнее «первый рабочий» записывается пустым списком: спека, написанная до
         * появления перечня, обязана значить ровно то, что значила. */
        const char *s = SPEC(
            "\"outputs\":{\"vpn\":{\"kind\":\"vless\",\"sub_file\":\"/tmp/sub.txt\","
            "\"node\":-1}},"
            "\"channels\":[]}");
        check("node -1: спека принята", 0, load_from_str(s));
        check("node -1: кандидатов не выбрано", 0, (int)g_spec.out[0].vless.nodes_n);
    }
    {
        const char *s = SPEC(
            "\"outputs\":{\"vpn\":{\"kind\":\"vless\",\"sub_file\":\"/tmp/sub.txt\"}},"
            "\"channels\":[]}");
        check("без node: спека принята", 0, load_from_str(s));
        check("без node: кандидатов не выбрано", 0, (int)g_spec.out[0].vless.nodes_n);
    }
    {
        /* Пустой список — та же «вся подписка», а не «узлов нет»: отказывать на нём значило бы
         * запретить интерфейсу писать поле всегда, в том числе когда человек ничего не выбрал. */
        const char *s = SPEC(
            "\"outputs\":{\"vpn\":{\"kind\":\"vless\",\"sub_file\":\"/tmp/sub.txt\","
            "\"nodes\":[]}},"
            "\"channels\":[]}");
        check("nodes пустой список принят", 0, load_from_str(s));
        check("nodes пустой список: кандидатов не выбрано", 0, (int)g_spec.out[0].vless.nodes_n);
    }
    {
        /* Обе формы сразу — отказ, ровно как lan_device вместе с lan_devices: взять одну молча
         * значило бы, что половина написанного человеком не действует. */
        const char *s = SPEC(
            "\"outputs\":{\"vpn\":{\"kind\":\"vless\",\"sub_file\":\"/tmp/sub.txt\","
            "\"node\":4,\"nodes\":[6,7]}},"
            "\"channels\":[]}");
        check("node вместе с nodes — отказ", 2, load_from_str(s));
    }
    {
        /* Дубликат делает перебор бессмысленным так же, как дубликат устройства в devices. */
        const char *s = SPEC(
            "\"outputs\":{\"vpn\":{\"kind\":\"vless\",\"sub_file\":\"/tmp/sub.txt\","
            "\"nodes\":[6,7,6]}},"
            "\"channels\":[]}");
        check("узел в nodes дважды — отказ", 2, load_from_str(s));
    }
    {
        /* Список строится из MAX_NODE_SEL: предел уже менялся (8 -> 16), и перечисление
         * номеров руками проверяло бы прежний предел, а не нынешний. */
        char many[512];
        int mn = snprintf(many, sizeof(many),
                          "%s\"outputs\":{\"vpn\":{\"kind\":\"vless\","
                          "\"sub_file\":\"/tmp/sub.txt\",\"nodes\":[", SPEC_OPEN);
        for (int i = 0; i < MAX_NODE_SEL + 1; i++)
            mn += snprintf(many + mn, sizeof(many) - (size_t)mn, "%s%d", i ? "," : "", i);
        snprintf(many + mn, sizeof(many) - (size_t)mn, "]}},\"channels\":[]}");
        check("nodes длиннее предела — отказ", 2, load_from_str(many));
    }
    {
        /* Отрицательный номер здесь не «первый рабочий»: в списке кандидатов он не значит
         * ничего, а прочитанный молча дал бы пропущенного кандидата. */
        const char *s = SPEC(
            "\"outputs\":{\"vpn\":{\"kind\":\"vless\",\"sub_file\":\"/tmp/sub.txt\","
            "\"nodes\":[6,-1]}},"
            "\"channels\":[]}");
        check("отрицательный номер в nodes — отказ", 2, load_from_str(s));
    }
    {
        /* Номер строкой: js_num на не-числе не продвигает указатель, и цикл без этой проверки
         * встал бы навсегда — то же семейство, что trailing comma в str_list. */
        const char *s = SPEC(
            "\"outputs\":{\"vpn\":{\"kind\":\"vless\",\"sub_file\":\"/tmp/sub.txt\","
            "\"nodes\":[\"6\"]}},"
            "\"channels\":[]}");
        check("номер строкой в nodes — отказ", 2, load_from_str(s));
    }
    {
        const char *s = SPEC(
            "\"outputs\":{\"vpn\":{\"kind\":\"vless\",\"sub_file\":\"/tmp/sub.txt\","
            "\"nodes\":[6,]}},"
            "\"channels\":[]}");
        check("хвостовая запятая в nodes — отказ", 2, load_from_str(s));
    }
#endif
#ifdef STEER_EXTENDED
    {
        /* Явный conf побеждает умолчание, но обязан быть абсолютным: процесс запускает
         * procd со своим рабочим каталогом, и относительный путь «работал бы из шелла». */
        const char *s = SPEC(
            "\"outputs\":{\"vpn\":{\"kind\":\"xsteer\",\"conf\":\"/etc/hub.conf\"}},"
            "\"channels\":[]}");
        check("xsteer: явный conf принят", 0, load_from_str(s));
        check_str("xsteer: явный conf сохранён", "/etc/hub.conf", g_spec.out[0].xs.conf);
    }
    {
        const char *s = SPEC(
            "\"outputs\":{\"vpn\":{\"kind\":\"xsteer\",\"conf\":\"hub.conf\"}},"
            "\"channels\":[]}");
        check("xsteer: относительный conf — отказ", 2, load_from_str(s));
    }
    {
        /* У xsteer свой транспорт и своя маскировка внутри движка: obfs здесь означал бы
         * обфускацию поверх обфускации, то есть «настроено», не настроив ничего. */
        const char *s = SPEC(
            "\"outputs\":{\"vpn\":{\"kind\":\"xsteer\","
            "\"obfs\":{\"server\":\"203.0.113.10:4567\",\"listen\":\"127.0.0.1:51820\"}}},"
            "\"channels\":[]}");
        check("xsteer: obfs — отказ", 2, load_from_str(s));
    }
    {
        /* Проверки, знавшие про один вид выхода с устройством, молча пропускали второй.
         * Эти две — ровно они: выход в локальный мост и any без allow_all. */
        const char *s = SPEC(
            "\"lan_device\":\"br-lan\","
            "\"outputs\":{\"vpn\":{\"kind\":\"xsteer\",\"device\":\"br-lan\"}},"
            "\"channels\":[]}");
        check("xsteer: устройство = lan_device — отказ", 2, load_from_str(s));
    }
    {
        const char *s = SPEC(
            "\"outputs\":{\"vpn\":{\"kind\":\"xsteer\"}},"
            "\"channels\":[{\"name\":\"всё\",\"out\":\"vpn\",\"match\":{\"any\":true}}]}");
        check("xsteer: any без allow_all — отказ", 2, load_from_str(s));
    }
#endif
    {
        /* Неизвестный вид отвергается целиком — и это желаемое поведение, а не цена:
         * спека, записанная более новым интерфейсом, не должна применяться наполовину. */
        const char *s = SPEC(
            "\"outputs\":{\"vpn\":{\"kind\":\"xsteerr\"}},"
            "\"channels\":[]}");
        check("неизвестный kind — отказ", 2, load_from_str(s));
        /* Реестр знает вид и тогда, когда его нет в сборке (запись отказа): `--kind xsteer` в
         * базовой сборке — пустой список, а не «нет такого вида». */
        check("kind_by_name: xsteer известен", 1, kind_by_name("xsteer") != NULL);
        check("kind_by_name: опечатка неизвестна", 1, kind_by_name("xsteerr") == NULL);
        check_str("kind_by_name: имя xsteer", "xsteer", kind_by_name("xsteer")->name);
        check_str("kind_of: имя interface", "interface", kind_of(&(struct output){ .kind = OUT_INTERFACE })->name);
    }

    /* ---- имена таблиц маршрутизации объявляются системе ------------------------
     *
     * Номер таблицы (300) в `ip rule show` и в `ip route show table` не говорит ничего:
     * какой это выход, надо помнить. iproute2 умеет имена через /etc/iproute2/rt_tables.d, и
     * с ними диагностика становится обычной. Проверяется здесь и содержимое, и то, что файл
     * НЕ перезаписывается без нужды: registry_assign зовут все подкоманды, включая status,
     * который интерфейс опрашивает каждые пять секунд. */
    {
        char sdir[] = "/tmp/specmatch-state-XXXXXX";
        char rdir[] = "/tmp/specmatch-rt-XXXXXX";
        if (!mkdtemp(sdir) || !mkdtemp(rdir)) { perror("mkdtemp"); return 1; }
        const char *saved_state = steer_state_dir(), *saved_rt = steer_rt_tables_dir();
        steer_set_state_dir(sdir);
        steer_set_rt_tables_dir(rdir);

        reset_globals();
        const char *s2 = SPEC(
            "\"outputs\":{\"direct\":{\"kind\":\"direct\"},"
            "\"vpn\":{\"kind\":\"interface\",\"device\":\"wg0\"},"
            "\"alt\":{\"kind\":\"interface\",\"device\":\"wg1\"}},"
            "\"channels\":[]}");
        check("спека с двумя туннелями загрузилась", 0, load_from_str(s2));
        registry_assign(&g_spec, &e);

        char path[512];
        snprintf(path, sizeof(path), "%s/steer.conf", rdir);
        char have[512] = {0};
        FILE *f = fopen(path, "r");
        size_t hn = f ? fread(have, 1, sizeof(have) - 1, f) : 0;
        if (f) fclose(f);
        have[hn] = 0;
        check("имена таблиц записаны", 1, hn > 0);
        /* Прямой выход в файл не попадает: таблицы у него нет. Приставка обязательна —
         * пространство имён таблиц общее на всю коробку. */
        check("имя первого выхода на месте", 1, strstr(have, "steer_vpn") != NULL);
        check("имя второго выхода на месте", 1, strstr(have, "steer_alt") != NULL);
        check("прямой выход не назван", 0, strstr(have, "steer_direct") != NULL);
        check("номер таблицы рядом с именем", 1, strstr(have, "300 steer_") != NULL);

        /* Повторный вызов при том же составе выходов файл трогать не должен. */
        struct stat st1, st2;
        stat(path, &st1);
        registry_assign(&g_spec, &e);
        stat(path, &st2);
        check("повторный вызов файл не перезаписывает",
              1, st1.st_mtime == st2.st_mtime && st1.st_size == st2.st_size);

        /* Выход исчез из спеки — исчезает и его имя: файл собирается целиком, а не
         * дописывается, иначе имена мёртвых выходов копились бы вечно. */
        reset_globals();
        const char *s3 = SPEC(
            "\"outputs\":{\"vpn\":{\"kind\":\"interface\",\"device\":\"wg0\"}},"
            "\"channels\":[]}");
        check("спека с одним туннелем загрузилась", 0, load_from_str(s3));
        registry_assign(&g_spec, &e);
        memset(have, 0, sizeof(have));
        f = fopen(path, "r");
        hn = f ? fread(have, 1, sizeof(have) - 1, f) : 0;
        if (f) fclose(f);
        have[hn] = 0;
        check("имя исчезнувшего выхода убрано", 0, strstr(have, "steer_alt") != NULL);
        check("имя оставшегося выхода на месте", 1, strstr(have, "steer_vpn") != NULL);

        unlink(path);
        rmdir(rdir);
        snprintf(path, sizeof(path), "%s/registry", sdir);
        unlink(path);
        rmdir(sdir);
        steer_set_state_dir(saved_state);
        steer_set_rt_tables_dir(saved_rt);
    }

    /* ---- мест под метку столько же, сколько выходов ----------------------------
     *
     * Выход получал БИТ (метка `база << номер`), и восемь бит поля значили восемь
     * помеченных выходов — при том что объявить их разрешено шестнадцать. Девятый падал с
     * «out of mark bits», и обойти это расширением поля нельзя: слева от нашего диапазона
     * бит 28 у мини-сборки, 29 и 30 у zapret, 16-23 у Tailscale и pbr. Поэтому выходу
     * выдаётся ЗНАЧЕНИЕ в том же поле, и проверяется здесь именно это: все шестнадцать
     * получают метку, и ни метка, ни таблица, ни очередь ни у кого не повторяются. */
    {
        char sdir[] = "/tmp/specmatch-slots-XXXXXX";
        char rdir[] = "/tmp/specmatch-slotsrt-XXXXXX";
        if (!mkdtemp(sdir) || !mkdtemp(rdir)) { perror("mkdtemp"); return 1; }
        const char *saved_state = steer_state_dir(), *saved_rt = steer_rt_tables_dir();
        steer_set_state_dir(sdir);
        steer_set_rt_tables_dir(rdir);

        reset_globals();
        char many[4096];
        int mn = snprintf(many, sizeof(many), "%s\"outputs\":{", SPEC_OPEN);
        for (int i = 0; i < MAX_OUTPUTS; i++)
            mn += snprintf(many + mn, sizeof(many) - (size_t)mn,
                           "%s\"o%d\":{\"kind\":\"interface\",\"device\":\"wg%d\"}",
                           i ? "," : "", i, i);
        snprintf(many + mn, sizeof(many) - (size_t)mn, "},\"channels\":[]}");
        check("спека на все MAX_OUTPUTS туннелей загрузилась", 0, load_from_str(many));
        registry_assign(&g_spec, &e);

        int no_mark = 0, off_mask = 0, dup_mark = 0, dup_table = 0, dup_queue = 0;
        int bad_table = 0;
        for (size_t i = 0; i < g_spec.out_n; i++) {
            if (!g_spec.out[i].mark) { no_mark++; continue; }
            if (g_spec.out[i].mark & ~STEER_MARK_MASK) off_mask++;
            if (g_spec.out[i].table < 300 || g_spec.out[i].table > 300 + MAX_OUTPUTS - 1) bad_table++;
            for (size_t j = 0; j < i; j++) {
                if (g_spec.out[j].mark == g_spec.out[i].mark) dup_mark++;
                if (g_spec.out[j].table == g_spec.out[i].table) dup_table++;
                if (out_zapret_queue(&g_spec.out[j]) == out_zapret_queue(&g_spec.out[i])) dup_queue++;
            }
        }
        check("метку получили все MAX_OUTPUTS выходов", 0, no_mark);
        check("метка каждого внутри маски контракта", 0, off_mask);
        check("метки не повторяются", 0, dup_mark);
        check("номера таблиц не повторяются", 0, dup_table);
        check("номера таблиц в своём ряду (300..315)", 0, bad_table);
        check("номера очередей обхода не повторяются", 0, dup_queue);

        /* РЕЕСТР С ПРЕЖНЕЙ СБОРКИ. Там метки одинокими битами, и старший из них — база,
         * умноженная на 128, — новой раздачей не выдаётся никому. Выход обязан сохранить
         * и метку, и таблицу: метка уже стоит в пакетах и в правиле маршрутизации, а
         * перетасовка на обновлении означала бы трафик, ушедший по чужому пути. */
        char rpath[512];
        snprintf(rpath, sizeof(rpath), "%s/registry", sdir);
        FILE *rf = fopen(rpath, "w");
        if (rf) {
            fprintf(rf, "old %08x %d\n", STEER_MARK_BASE << 7, 300 + 7);
            fclose(rf);
        }
        reset_globals();
        const char *s4 = SPEC(
            "\"outputs\":{\"old\":{\"kind\":\"interface\",\"device\":\"wg0\"},"
            "\"fresh\":{\"kind\":\"interface\",\"device\":\"wg1\"}},"
            "\"channels\":[]}");
        check("спека со старым и новым выходом загрузилась", 0, load_from_str(s4));
        registry_assign(&g_spec, &e);
        unsigned old_mark = 0, fresh_mark = 0;
        int old_table = 0, fresh_table = 0;
        for (size_t i = 0; i < g_spec.out_n; i++) {
            if (!strcmp(g_spec.out[i].name, "old")) {
                old_mark = g_spec.out[i].mark; old_table = g_spec.out[i].table;
            } else if (!strcmp(g_spec.out[i].name, "fresh")) {
                fresh_mark = g_spec.out[i].mark; fresh_table = g_spec.out[i].table;
            }
        }
        check("старая метка из реестра сохранена как есть", STEER_MARK_BASE << 7, old_mark);
        check("старая таблица из реестра сохранена", 307, old_table);
        check("новый выход метку получил", 1, fresh_mark != 0);
        check("новый выход не занял чужую метку", 1, fresh_mark != old_mark);
        check("новый выход не занял чужую таблицу", 1, fresh_table != old_table);

        unlink(rpath);
        snprintf(rpath, sizeof(rpath), "%s/steer.conf", rdir);
        unlink(rpath);
        rmdir(rdir);
        rmdir(sdir);
        steer_set_state_dir(saved_state);
        steer_set_rt_tables_dir(saved_rt);
    }

    /* ---- ход подъёма выхода: запись и чтение ------------------------------------------
     *
     * Три состояния, и различать их обязательно: у них РАЗНОЕ лечение. «Перебор идёт» —
     * ждать; «ни один не ответил» — менять узел или подписку; «номер вне подписки» —
     * поправить одно число. Последнее до этой правки писалось той же записью, что «узлов в
     * подписке нет вовсе», и диагностика говорила «в подписке нет пригодных узлов» на
     * подписке из двадцати девяти живых узлов. Снято с живого роутера.
     *
     * Проверяется круг целиком — запись, чтение, устаревание, — потому что состояние живёт
     * в файле и читает его ДРУГОЙ процесс: клиент пишет, а status, diag и сторож читают. */
    {
        char sdir[] = "/tmp/specmatch-probe.XXXXXX";
        char *d = mkdtemp(sdir);
        const char *saved = steer_state_dir();
        if (d) steer_set_state_dir(d);

        /* Ничего не писали — «не знаем», а не отказ. Пустое место не должно красить
         * исправный выход в жёлтое. */
        struct probe_status pr = probe_read("nowhere");
        check("файла нет — не знаем", PROBE_NONE, pr.state);

        /* Номер вне подписки: оба числа обязаны дойти до читателя. Порознь они не значат
         * ничего — «31» без «29» не объясняет, почему это ошибка. */
        probe_report("vl", PROBE_NO_SUCH_NODE, 31, 29);
        pr = probe_read("vl");
        check("номер вне подписки: состояние своё", PROBE_NO_SUCH_NODE, pr.state);
        check("номер вне подписки: номер человека сохранён", 31, pr.node);
        check("номер вне подписки: число пригодных сохранено", 29, pr.total);

        /* «Ни один не ответил» — другое состояние, и номер там не значит ничего. */
        probe_report("vl", PROBE_FAILED, 0, 26);
        pr = probe_read("vl");
        check("перебор кончился ничем: состояние failed", PROBE_FAILED, pr.state);
        check("перебор кончился ничем: номера нет", 0, pr.node);
        check("перебор кончился ничем: пригодных 26", 26, pr.total);

        /* Пустая подписка — тот же failed, но с нулём: различие в total, и оно значимо. */
        probe_report("vl", PROBE_FAILED, 0, 0);
        pr = probe_read("vl");
        check("пустая подписка: failed с нулём", PROBE_FAILED, pr.state);
        check("пустая подписка: пригодных ноль", 0, pr.total);

        /* Перебор идёт — верно, только пока жив написавший. Своё же pid жив, значит верно. */
        probe_report("vl", PROBE_RUNNING, 3, 26);
        pr = probe_read("vl");
        check("перебор идёт: состояние probing", PROBE_RUNNING, pr.state);
        check("перебор идёт: номер узла", 3, pr.node);

        /* Запись снимается — снова «не знаем». Устройство поднялось, объяснять нечего. */
        probe_clear("vl");
        check("запись снята — не знаем", PROBE_NONE, probe_read("vl").state);

        /* Незнакомое слово читается как «не знаем», а не как отказ: запись мог оставить
         * движок другой версии, и жёлтая метка на исправном выходе тут хуже молчания. */
        {
            char path[512];
            snprintf(path, sizeof(path), "%s/probe-vl", steer_state_dir());
            FILE *f = fopen(path, "w");
            if (f) { fprintf(f, "чтотонеизвестное 1 2 %ld %ld\n",
                             (long)getpid(), (long)time(NULL)); fclose(f); }
            check("незнакомое состояние — не знаем", PROBE_NONE, probe_read("vl").state);
            unlink(path);
        }
        /* Устаревшая запись тоже «не знаем»: procd давно перестал пробовать. */
        {
            char path[512];
            snprintf(path, sizeof(path), "%s/probe-vl", steer_state_dir());
            FILE *f = fopen(path, "w");
            if (f) { fprintf(f, "nonode 31 29 %ld %ld\n",
                             (long)getpid(), (long)time(NULL) - 3600); fclose(f); }
            check("устаревшая запись — не знаем", PROBE_NONE, probe_read("vl").state);
            unlink(path);
        }

        if (d) { rmdir(d); }
        steer_set_state_dir(saved);
    }

    {
        /* ---- кого общий обход DPI трогать не должен --------------------------------
         *
         * Проверяется САМА ФУНКЦИЯ, и по ВСЕЙ таблице видов, а не пара примеров. Причина в
         * том, из-за чего правка и понадобилась: знание «кому ставить чужой бит» было
         * `case`-ом по kind на месте, и вид выхода, добавленный позже (tgws), в него не
         * попал — молча, потому что правила при этом выглядят исправно. Стенд, знающий про
         * два вида, повторил бы ту же ошибку; стенд, идущий по реестру видов, покраснеет на
         * следующем добавленном виде, если его забудут рассудить.
         *
         * Ожидание сформулировано ОТРИЦАНИЕМ («все, кроме direct»), а не перечнем: перечень
         * здесь был бы второй копией самой функции, и сверять копию с копией бессмысленно.
         * Утверждение проверки — про СМЫСЛ: единственный вид, чей трафик отдаётся общему
         * обходу, это прямой канал, потому что для этого его и заводят. */
        for (size_t i = 0; i < kind_count(); i++) {
            /* Вид вне сборки (запись отказа) свойств не имеет — рассуждать о нём нечего. */
            if (kind_at(i)->absent) continue;
            struct output o = {0};
            o.kind = kind_at(i);
            char what[96];
            int want = kind_at(i) != OUT_DIRECT;
            snprintf(what, sizeof(what), "обход DPI не трогает выход kind=%s: %s",
                     kind_at(i)->name, want ? "да" : "нет (прямой канал)");
            check(what, want, out_skips_zapret(&o));
        }
        /* И отдельной строкой то, ради чего перечень выше: direct — единственное
         * исключение. Считаем исключения, а не перечисляем виды: появись второе, оно обязано
         * появиться вместе с решением, а не тихо. */
        {
            int exceptions = 0;
            for (size_t i = 0; i < kind_count(); i++) {
                if (kind_at(i)->absent) continue;
                struct output o = {0};
                o.kind = kind_at(i);
                if (!out_skips_zapret(&o)) exceptions++;
            }
            check("исключение ровно одно", 1, exceptions);
        }
    }

    /* ---- брак, который принимался молча ------------------------------------
     *
     * Каждый случай ниже — спека, которую парсер брал как целую, хотя она либо оборвана,
     * либо противоречива, либо записана не тем типом. Комментарий load_spec обещает громкий
     * отказ на битой спеке; отказ был только при обрыве внутри строки. */
    {
        /* Обрыв после последнего канала: нет `]}`. Так выглядит файл после отключения питания
         * посреди записи — половина спеки применялась без единой жалобы. */
        check("обрыв: нет закрывающих скобок — отказ", 2, load_from_str(
            "{\"schema\":1,\"from_default\":[\"192.168.1.0/24\"],"
            "\"outputs\":{\"direct\":{\"kind\":\"direct\"}},"
            "\"channels\":[{\"name\":\"yt\",\"out\":\"direct\","
            "\"match\":{\"domains_file\":\"/tmp/yt.lst\"}}"));
        check("обрыв: outputs без закрывающей скобки — отказ", 2, load_from_str(
            "{\"schema\":1,\"from_default\":[\"192.168.1.0/24\"],"
            "\"outputs\":{\"direct\":{\"kind\":\"direct\"}"));
        /* Два выхода с одним именем: реестр раздаёт две метки, init поднимает два процесса на
         * одно имя, out_by_name всегда берёт первый — как у devices/nodes, это отказ. */
        check("два выхода с одним именем — отказ", 2, load_from_str(SPEC(
            "\"outputs\":{\"vpn\":{\"kind\":\"direct\"},\"vpn\":{\"kind\":\"direct\"}},"
            "\"channels\":[]")));
        /* Число, записанное строкой: strtol молча даёт 0 и не двигает указатель. Для node это
         * значило «узел 0» вместо выбранного человеком. */
        check("node строкой — отказ", 2, load_from_str(SPEC(
            "\"outputs\":{\"vl\":{\"kind\":\"vless\",\"sub_file\":\"/tmp/s\",\"node\":\"3\"}},"
            "\"channels\":[]")));
        check("schema строкой — отказ", 2, load_from_str(
            "{\"schema\":\"1\",\"from_default\":[\"192.168.1.0/24\"],"
            "\"outputs\":{\"direct\":{\"kind\":\"direct\"}},\"channels\":[]}"));
        /* Единственное рядом с множественным у списков канала — как у device/devices: отказ, а
         * не молчаливая победа того, что прочитано позже. */
        check("prefixes_file рядом с prefixes_files — отказ", 2, load_from_str(SPEC(
            "\"outputs\":{\"direct\":{\"kind\":\"direct\"}},"
            "\"channels\":[{\"name\":\"a\",\"out\":\"direct\",\"match\":{"
            "\"prefixes_files\":[\"/tmp/a\",\"/tmp/b\"],\"prefixes_file\":\"/tmp/c\"}}]")));
        /* Имя длиннее буфера резалось молча до 31 байта: для device это ещё и больше IFNAMSIZ. */
        check("имя выхода длиннее 31 байта — отказ", 2, load_from_str(SPEC(
            "\"outputs\":{\"abcdefghijklmnopqrstuvwxyz0123456789\":{\"kind\":\"direct\"}},"
            "\"channels\":[]")));
    }

    /* ---- \uXXXX в строках спеки (I-315) ------------------------------------------
     *
     * Экранирование \u читалось как «следующий знак как есть»: «a\u0022b» давало
     * «au0022b». JSON вправе так записать любой знак, а кириллицу в имени канала так пишет
     * любой сериализатор, экранирующий не-ASCII. Проверяется сам js_str: вопрос не в том,
     * куда строка идёт дальше, а в том, что из неё прочитано. Управляющий знак и
     * недописанное \u не раскодируются — остаются как прочитались прежде, с
     * предупреждением: такая спека грузилась и до правки. */
    {
        char b[64];
        struct js j;
        j.p = "\"a\\u0022b\"";
        check("\\u0022 читается кавычкой", 0, js_str(&j, b, sizeof b, &e));
        check_str("\\u0022 читается кавычкой: значение", "a\"b", b);
        j.p = "\"\\u0431\\u0443\"";
        js_str(&j, b, sizeof b, &e);
        check_str("\\u0431\\u0443 — кириллица в UTF-8", "\xd0\xb1\xd1\x83", b);
        j.p = "\"\\ud83d\\ude00\"";
        js_str(&j, b, sizeof b, &e);
        check_str("суррогатная пара — один знак в четыре байта", "\xf0\x9f\x98\x80", b);
        j.p = "\"x\\u000ay\"";
        js_str(&j, b, sizeof b, &e);
        check_str("управляющий \\u000a — как прежде, не раскодирован", "xu000ay", b);
        j.p = "\"x\\u00zy\"";
        js_str(&j, b, sizeof b, &e);
        check_str("недописанное \\u — как прежде", "xu00zy", b);
        j.p = "\"a\\\"b\\\\c\"";
        js_str(&j, b, sizeof b, &e);
        check_str("\\\" и \\\\ — как прежде", "a\"b\\c", b);
    }

    /* ---- enabled: 0 и 1 наравне с false и true (I-315) ------------------------------
     *
     * enabled проверялся по первой букве 'f', а any рядом — по 't' и '1'. jshn у OpenWrt
     * пишет логическое значение то словом, то единицей (см. any в spec.c), и «enabled»:0 —
     * канал, выключенный человеком, — включался. Непонятное значение по-прежнему оставляет
     * канал включённым, с предупреждением. */
    {
        static const struct { const char *v; int disabled; } ev[] = {
            { "false", 1 }, { "true", 0 }, { "0", 1 }, { "1", 0 }, { "null", 0 },
        };
        for (size_t k = 0; k < sizeof ev / sizeof *ev; k++) {
            char s[512], what[96];
            snprintf(s, sizeof s, SPEC(
                "\"outputs\":{\"direct\":{\"kind\":\"direct\"}},"
                "\"channels\":[{\"name\":\"c\",\"out\":\"direct\",\"enabled\":%s,"
                "\"match\":{\"domains_file\":\"/tmp/x.lst\"}}]"), ev[k].v);
            snprintf(what, sizeof what, "enabled:%s — грузится", ev[k].v);
            check(what, 0, load_from_str(s));
            snprintf(what, sizeof what, "enabled:%s — disabled=%d", ev[k].v, ev[k].disabled);
            check(what, ev[k].disabled, g_spec.ch_n ? g_spec.ch[0].disabled : -1);
        }
    }

    /* ---- ключ без двоеточия (I-315) ------------------------------------------------
     *
     * В четырёх циклах объектов возврат js_lit(':') не проверялся, и {"kind" "direct"}
     * читался как {"kind":"direct"}. Это не JSON: интерфейс такую спеку не разберёт, а
     * движок молча принимал. Каждое из четырёх мест — отдельный случай. */
    {
        check("ключ верхнего уровня без ':' — отказ", 2, load_from_str(
            "{\"schema\" 1,\"from_default\":[\"192.168.1.0/24\"],"
            "\"outputs\":{\"direct\":{\"kind\":\"direct\"}},\"channels\":[]}"));
        check("ключ выхода без ':' — отказ", 2, load_from_str(SPEC(
            "\"outputs\":{\"direct\":{\"kind\" \"direct\"}},\"channels\":[]")));
        check("ключ канала без ':' — отказ", 2, load_from_str(SPEC(
            "\"outputs\":{\"direct\":{\"kind\":\"direct\"}},"
            "\"channels\":[{\"name\" \"c\",\"out\":\"direct\","
            "\"match\":{\"domains_file\":\"/tmp/x.lst\"}}]")));
        check("ключ obfs без ':' — отказ", 2, load_from_str(SPEC(
            "\"outputs\":{\"wg\":{\"kind\":\"interface\",\"device\":\"wg0\","
            "\"obfs\":{\"server\" \"203.0.113.10:4567\",\"listen\":\"127.0.0.1:51820\"}}},"
            "\"channels\":[]")));
        check("те же спеки с ':' грузятся", 0, load_from_str(SPEC(
            "\"outputs\":{\"wg\":{\"kind\":\"interface\",\"device\":\"wg0\","
            "\"obfs\":{\"server\":\"203.0.113.10:4567\",\"listen\":\"127.0.0.1:51820\"}}},"
            "\"channels\":[{\"name\":\"c\",\"out\":\"wg\","
            "\"match\":{\"domains_file\":\"/tmp/x.lst\"}}]")));
    }

    /* ---- пустая строка в «кому» (I-315) --------------------------------------------
     *
     * from:[""] принимался, а в правило уходил как «ip saddr {  }», и nft отвергал всё
     * применение синтаксической ошибкой. Такой from пишет сам интерфейс splify2 («только эти
     * устройства» без единого устройства), поэтому у канала это предупреждение, а не отказ:
     * пустые строки выбрасываются, а канал, у которого не осталось никого, не применяется —
     * и НЕ превращается в правило на всю сеть. from_default:[""] не пишет никто, там отказ. */
    {
        check("from:[\"\"] у канала — грузится", 0, load_from_str(SPEC(
            "\"outputs\":{\"direct\":{\"kind\":\"direct\"}},"
            "\"channels\":[{\"name\":\"c\",\"out\":\"direct\",\"from\":[\"\"],"
            "\"match\":{\"domains_file\":\"/tmp/x.lst\"}},"
            "{\"name\":\"d\",\"out\":\"direct\","
            "\"match\":{\"domains_file\":\"/tmp/y.lst\"}}]")));
        check("и этот канал не применяется", 1, g_spec.ch_n ? g_spec.ch[0].disabled : -1);
        check("а соседний канал — применяется", 0, g_spec.ch_n > 1 ? g_spec.ch[1].disabled : -1);
        check("пустая строка рядом с адресом — грузится", 0, load_from_str(SPEC(
            "\"outputs\":{\"direct\":{\"kind\":\"direct\"}},"
            "\"channels\":[{\"name\":\"c\",\"out\":\"direct\","
            "\"from\":[\"192.168.1.5\",\"\"],"
            "\"match\":{\"domains_file\":\"/tmp/x.lst\"}}]")));
        check("и пустая выброшена, адрес остался", 1, g_spec.ch_n ? (int)g_spec.ch[0].from_n : -1);
        check_str("и это тот адрес", "192.168.1.5", g_spec.ch_n ? g_spec.ch[0].from[0] : "");
        check("и канал применяется", 0, g_spec.ch_n ? g_spec.ch[0].disabled : -1);
        check("from:[\"\"] у выключенного канала — грузится", 0, load_from_str(SPEC(
            "\"outputs\":{\"direct\":{\"kind\":\"direct\"}},"
            "\"channels\":[{\"name\":\"c\",\"out\":\"direct\",\"from\":[\"\"],"
            "\"enabled\":false,\"match\":{\"domains_file\":\"/tmp/x.lst\"}}]")));
        check("from_default:[\"\"] у канала без from — отказ", 2, load_from_str(
            "{\"schema\":1,\"from_default\":[\"\"],"
            "\"outputs\":{\"direct\":{\"kind\":\"direct\"}},"
            "\"channels\":[{\"name\":\"c\",\"out\":\"direct\","
            "\"match\":{\"domains_file\":\"/tmp/x.lst\"}}]}"));
    }

    /* ---- вложенные выходы: via ---------------------------------------------------------
     *
     * Каждый отказ здесь — конфигурация, которая иначе применилась бы и молча повела туннель не
     * туда: мимо выхода-цели напрямую (цели нет, у цели нет устройства, у выхода нет своего
     * сокета, чтобы его пометить) или в круг, где не встаёт ни один туннель. Выходы в базовой
     * сборке — interface с obfs: это единственный вид со своим сокетом наверх, который она знает;
     * vless и xsteer — в расширенной. OBFS(dev) — описание обфускатора с устройством dev. */
#define OBFS(dev) "{\"kind\":\"interface\",\"device\":\"" dev "\"," \
                  "\"obfs\":{\"server\":\"203.0.113.10:4567\",\"listen\":\"127.0.0.1:51820\"}"
    {
        check("via: interface с obfs через interface — принята", 0, load_from_str(SPEC(
            "\"outputs\":{\"a\":" OBFS("wg0") ",\"via\":\"b\"},"
            "\"b\":{\"kind\":\"interface\",\"device\":\"wg1\"}},\"channels\":[]}")));
        check_str("via: поле заполнено", "b", g_spec.out_n ? g_spec.out[0].via : "");
        check("via: out_via находит цель", 1, g_spec.out_n == 2 && out_via(&g_spec, &g_spec.out[0]) == &g_spec.out[1]);
        check("via: у цели via нет", 1, g_spec.out_n == 2 && out_via(&g_spec, &g_spec.out[1]) == NULL);
        /* Метка туннеля — метка цели; без via — «мимо каналов» (на роутере ноль). Метки здесь
         * ставятся руками: registry_assign в этом стенде не зовётся. */
        g_spec.out[0].mark = 0x00100000;
        g_spec.out[1].mark = 0x00200000;
        check("via: метка туннеля — метка цели", 0x00200000, (int)out_underlay_mark(&g_spec, &g_spec.out[0]));
        check("via: без via — метки нет", 0, (int)out_underlay_mark(&g_spec, &g_spec.out[1]));
        check("via: глубина 1 и 0", 1, out_via_depth(&g_spec, &g_spec.out[0]) == 1 && out_via_depth(&g_spec, &g_spec.out[1]) == 0);
    }
    check("via: цель ниже в спеке — принята", 0, load_from_str(SPEC(
        "\"outputs\":{\"b\":{\"kind\":\"interface\",\"device\":\"wg1\"},"
        "\"a\":" OBFS("wg0") ",\"via\":\"b\"}},\"channels\":[]}")));
    check("via: пустая строка — как без via", 0, load_from_str(SPEC(
        "\"outputs\":{\"a\":" OBFS("wg0") ",\"via\":\"\"}},\"channels\":[]}")));
    check("via: пустая строка — поле пустое", 1, g_spec.out_n == 1 && !out_via(&g_spec, &g_spec.out[0]));
    check("via: негодное имя — отказ", 2, load_from_str(SPEC(
        "\"outputs\":{\"a\":" OBFS("wg0") ",\"via\":\"b c\"}},\"channels\":[]}")));
    check("via: несуществующий выход — отказ", 2, load_from_str(SPEC(
        "\"outputs\":{\"a\":" OBFS("wg0") ",\"via\":\"nope\"}},\"channels\":[]}")));
    check("via: на самого себя — отказ", 2, load_from_str(SPEC(
        "\"outputs\":{\"a\":" OBFS("wg0") ",\"via\":\"a\"}},\"channels\":[]}")));
    check("via: у обычного interface (сокет не наш) — отказ", 2, load_from_str(SPEC(
        "\"outputs\":{\"a\":{\"kind\":\"interface\",\"device\":\"wg0\",\"via\":\"b\"},"
        "\"b\":{\"kind\":\"interface\",\"device\":\"wg1\"}},\"channels\":[]}")));
    check("via: у direct — отказ", 2, load_from_str(SPEC(
        "\"outputs\":{\"a\":{\"kind\":\"direct\",\"via\":\"b\"},"
        "\"b\":{\"kind\":\"interface\",\"device\":\"wg1\"}},\"channels\":[]}")));
    check("via: на direct — отказ", 2, load_from_str(SPEC(
        "\"outputs\":{\"a\":" OBFS("wg0") ",\"via\":\"d\"},"
        "\"d\":{\"kind\":\"direct\"}},\"channels\":[]}")));
    check("via: на zapret — отказ", 2, load_from_str(SPEC(
        "\"outputs\":{\"a\":" OBFS("wg0") ",\"via\":\"z\"},"
        "\"z\":{\"kind\":\"zapret\"}},\"channels\":[]}")));
    check("via: на tgws — отказ", 2, load_from_str(SPEC(
        "\"outputs\":{\"a\":" OBFS("wg0") ",\"via\":\"t\"},"
        "\"t\":{\"kind\":\"tgws\",\"domain\":\"example.com\"}},\"channels\":[]}")));
    check("via: круг a → b → a — отказ", 2, load_from_str(SPEC(
        "\"outputs\":{\"a\":" OBFS("wg0") ",\"via\":\"b\"},"
        "\"b\":" OBFS("wg1") ",\"via\":\"a\"}},\"channels\":[]}")));
    check("via: круг a → b → c → b — отказ", 2, load_from_str(SPEC(
        "\"outputs\":{\"a\":" OBFS("wg0") ",\"via\":\"b\"},"
        "\"b\":" OBFS("wg1") ",\"via\":\"c\"},"
        "\"c\":" OBFS("wg2") ",\"via\":\"b\"}},\"channels\":[]}")));
    {
        check("via: цепочка из трёх выходов — принята", 0, load_from_str(SPEC(
            "\"outputs\":{\"a\":" OBFS("wg0") ",\"via\":\"b\"},"
            "\"b\":" OBFS("wg1") ",\"via\":\"c\"},"
            "\"c\":{\"kind\":\"interface\",\"device\":\"wg2\"}},\"channels\":[]}")));
        check("via: глубина цепочки из трёх — 2", 2, g_spec.out_n == 3 ? out_via_depth(&g_spec, &g_spec.out[0]) : -1);
        g_spec.out[0].mark = 0x00100000; g_spec.out[1].mark = 0x00200000; g_spec.out[2].mark = 0x00300000;
        /* Каждый слой метит СВОЙ сокет меткой СВОЕЙ цели — не конца цепочки: пакет a едет в
         * устройство b, а уже соединение b — в устройство c. */
        check("via: слой a метится меткой b", 0x00200000, (int)out_underlay_mark(&g_spec, &g_spec.out[0]));
        check("via: слой b метится меткой c", 0x00300000, (int)out_underlay_mark(&g_spec, &g_spec.out[1]));
    }
    check("via: три перехода — принята", 0, load_from_str(SPEC(
        "\"outputs\":{\"a\":" OBFS("wg0") ",\"via\":\"b\"},"
        "\"b\":" OBFS("wg1") ",\"via\":\"c\"},"
        "\"c\":" OBFS("wg2") ",\"via\":\"d\"},"
        "\"d\":{\"kind\":\"interface\",\"device\":\"wg3\"}},\"channels\":[]}")));
    check("via: четыре перехода — отказ", 2, load_from_str(SPEC(
        "\"outputs\":{\"a\":" OBFS("wg0") ",\"via\":\"b\"},"
        "\"b\":" OBFS("wg1") ",\"via\":\"c\"},"
        "\"c\":" OBFS("wg2") ",\"via\":\"d\"},"
        "\"d\":" OBFS("wg3") ",\"via\":\"e\"},"
        "\"e\":{\"kind\":\"interface\",\"device\":\"wg4\"}},\"channels\":[]}")));
    /* Круг через пул: цель — interface, среди устройств которого устройство самого выхода.
     * Пока сторож держит пул на первом устройстве, всё работает; стоит ему переключиться — и
     * туннель пошёл бы внутрь себя. Отказ — сразу, а не в тот момент. */
    check("via: пул цели с устройством самого выхода — отказ", 2, load_from_str(SPEC(
        "\"outputs\":{\"a\":" OBFS("wg0") ",\"via\":\"p\"},"
        "\"p\":{\"kind\":\"interface\",\"devices\":[\"wg1\",\"wg0\"]}},\"channels\":[]}")));
    check("via: пул цели без него — принята", 0, load_from_str(SPEC(
        "\"outputs\":{\"a\":" OBFS("wg0") ",\"via\":\"p\"},"
        "\"p\":{\"kind\":\"interface\",\"devices\":[\"wg1\",\"wg2\"]}},\"channels\":[]}")));
    /* kind=awg — в обе стороны: его UDP метит движок (WGDEVICE_A_FWMARK), и у него устройство с
     * таблицей, то есть он годится и во внутренние, и в цели. */
    {
        check("via: awg через interface — принята", 0, load_from_str(SPEC(
            "\"outputs\":{\"a\":{\"kind\":\"awg\",\"via\":\"w\"},"
            "\"w\":{\"kind\":\"interface\",\"device\":\"wg0\"}},\"channels\":[]}")));
        check("via: awg умеет via", 1, g_spec.out_n == 2 && out_via_capable(&g_spec.out[0]));
        check("via: interface с obfs через awg — принята", 0, load_from_str(SPEC(
            "\"outputs\":{\"o\":" OBFS("wg0") ",\"via\":\"a\"},"
            "\"a\":{\"kind\":\"awg\"}},\"channels\":[]}")));
        check("via: awg ↔ awg по кругу — отказ", 2, load_from_str(SPEC(
            "\"outputs\":{\"a\":{\"kind\":\"awg\",\"via\":\"b\"},"
            "\"b\":{\"kind\":\"awg\",\"via\":\"a\"}},\"channels\":[]}")));
    }
#ifdef STEER_EXTENDED
    {
        check("via: awg через vless (пример владельца) — принята", 0, load_from_str(SPEC(
            "\"outputs\":{\"a\":{\"kind\":\"awg\",\"via\":\"v\"},"
            "\"v\":{\"kind\":\"vless\",\"sub_file\":\"/tmp/s\"}},\"channels\":[]}")));
        /* Пример владельца наоборот и прямо: VLESS через интерфейс; xsteer через VLESS. */
        check("via: vless через interface — принята", 0, load_from_str(SPEC(
            "\"outputs\":{\"v\":{\"kind\":\"vless\",\"sub_file\":\"/tmp/s\",\"via\":\"w\"},"
            "\"w\":{\"kind\":\"interface\",\"device\":\"wg0\"}},\"channels\":[]}")));
        check("via: vless через interface — цель найдена", 1,
              g_spec.out_n == 2 && out_via(&g_spec, &g_spec.out[0]) == &g_spec.out[1]);
        check("via: xsteer через vless — принята", 0, load_from_str(SPEC(
            "\"outputs\":{\"x\":{\"kind\":\"xsteer\",\"via\":\"v\"},"
            "\"v\":{\"kind\":\"vless\",\"sub_file\":\"/tmp/s\"}},\"channels\":[]}")));
        check("via: vless ↔ xsteer по кругу — отказ", 2, load_from_str(SPEC(
            "\"outputs\":{\"x\":{\"kind\":\"xsteer\",\"via\":\"v\"},"
            "\"v\":{\"kind\":\"vless\",\"sub_file\":\"/tmp/s\",\"via\":\"x\"}},\"channels\":[]}")));
        /* Круг, которого в полях via не видно: v идёт через пул p, в пуле — устройство x, а x
         * сам идёт через v. Сторож переключит пул на x — и туннели завернутся друг в друга. */
        check("via: круг через устройство пула — отказ", 2, load_from_str(SPEC(
            "\"outputs\":{\"v\":{\"kind\":\"vless\",\"sub_file\":\"/tmp/s\",\"via\":\"p\"},"
            "\"p\":{\"kind\":\"interface\",\"devices\":[\"wg0\",\"x\"]},"
            "\"x\":{\"kind\":\"xsteer\",\"via\":\"v\"}},\"channels\":[]}")));
        check("via: пул с чужим туннелем без круга — принята", 0, load_from_str(SPEC(
            "\"outputs\":{\"v\":{\"kind\":\"vless\",\"sub_file\":\"/tmp/s\",\"via\":\"p\"},"
            "\"p\":{\"kind\":\"interface\",\"devices\":[\"wg0\",\"x\"]},"
            "\"x\":{\"kind\":\"xsteer\"}},\"channels\":[]}")));
    }
#endif
#undef OBFS

    printf("\n%s\n", fails ? "ЕСТЬ ПРОВАЛЫ" : "все проверки прошли");
    return fails ? 1 : 0;
}
