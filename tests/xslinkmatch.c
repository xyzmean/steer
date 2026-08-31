/* Ссылка xs://: разбор, печать и то, что обе половины понимают ОДНУ строку.
 *
 * ЗАЧЕМ ЭТОТ СТЕНД. Ссылку выдаёт одна сторона звезды, а принимает другая, и половины написаны на
 * разных языках. Расхождение здесь не падает и не видно: ссылка «принялась», а туннель молчит,
 * потому что маска оказалась другой или keepalive включился сам. Поэтому проверяется не «разбор не
 * упал», а РАВЕНСТВО: тот же файл и та же ссылка обязаны дать одну конфигурацию, а печать —
 * побайтово ту же строку, что печатает половина на Go (векторы ниже сняты с её стенда
 * xsteer/conf/link_test.go).
 *
 * Сборка без mbedtls: разбор ссылки арифметики на кривой не касается.
 */
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#include "../src/ext/xsconf.c"
#include "../src/ext/xslink.c"

static int fails;
#define OK(what, cond) do { \
    printf("%-58s %s\n", (what), (cond) ? "ok" : "ПРОВАЛ"); \
    if (!(cond)) fails++; \
} while (0)

/* Те же ключи, что в стенде половины на Go, — чтобы векторы можно было сверять глазами. */
static const char *PRIV_B64 = "6Gtidge6FqhO/0LhrAWpRiyYaKdLZF/gib/HePLC9GU=";
static const char *PUB_B64  = "QYkH5bWOsEOCgIMldHPATSG7yvNyJ8st7o/HMelWKxs=";
/* Они же в записи для ссылки. Значения проверяются, а не подразумеваются: несовпадение алфавита
 * здесь означало бы, что половины печатают разные ссылки на один ключ. */
static const char *PRIV_URL = "6Gtidge6FqhO_0LhrAWpRiyYaKdLZF_gib_HePLC9GU";
static const char *PUB_URL  = "QYkH5bWOsEOCgIMldHPATSG7yvNyJ8st7o_HMelWKxs";

static void t_key_alphabets(void) {
    uint8_t want[32], got[32];
    if (xs_key_decode(PRIV_B64, want) != 0) { printf("ключ не разобрался вовсе\n"); fails++; return; }
    char nopad[64];
    snprintf(nopad, sizeof(nopad), "%.43s", PRIV_B64);
    const char *forms[] = { PRIV_URL, PRIV_B64, nopad };
    int all = 1;
    for (size_t i = 0; i < 3; i++) {
        if (key_decode_url(forms[i], got) != 0 || memcmp(got, want, 32) != 0) all = 0;
    }
    OK("ключ в ссылке: оба алфавита и без набивки", all);
    /* Мусор той же длины — отказ: у одного ключа не должно быть нескольких написаний. */
    const char *bad[] = { "", "x", "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
                          "!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!" };
    int rejected = 1;
    for (size_t i = 0; i < 4; i++) if (key_decode_url(bad[i], got) == 0) rejected = 0;
    OK("ключ в ссылке: мусор отвергнут", rejected);
    /* И печать: она обязана дать ровно ту запись, которую печатает половина на Go. */
    char url[XS_KEY_B64];
    key_encode_url(want, url);
    OK("ключ в ссылке: печать совпала с половиной на Go", strcmp(url, PRIV_URL) == 0);
}

/* Главное свойство: ссылка и файл описывают ОДНУ конфигурацию. Проверяется равенство результата,
 * а не «разобралось»: иначе два представления разошлись бы по мелочам — умолчание keepalive,
 * длина маски, порядок префиксов, — и «настроено» зависело бы от того, чем настраивали. */
static void t_link_equals_file(void) {
    char file[1024];
    snprintf(file, sizeof(file),
             "[Interface]\nPrivateKey = %s\nAddress    = 10.77.0.2/24\n"
             "SNI        = www.microsoft.com\n\n"
             "[Peer]\nPublicKey  = %s\nAllowedIPs = 10.77.0.0/24, 192.168.9.0/24\n"
             "Endpoint   = 203.0.113.7:443\nPersistentKeepalive = 25\n", PRIV_B64, PUB_B64);
    struct xs_conf cf, cl;
    struct xs_secrets sf, sl;
    char err[320] = "";
    if (xs_conf_parse(file, strlen(file), XS_ROLE_SPOKE, &cf, &sf, err, sizeof(err)) != 0) {
        printf("файл не разобрался: %s\n", err);
        fails++;
        return;
    }
    char link[1024];
    snprintf(link, sizeof(link),
             "xs://%s@203.0.113.7:443?pk=%s&ip=10.77.0.2/24"
             "&allowed=10.77.0.0/24,192.168.9.0/24&sni=www.microsoft.com&ka=25#дом",
             PRIV_URL, PUB_URL);
    char name[XS_LINK_NAME_MAX] = "";
    if (xs_link_parse(link, XS_ROLE_SPOKE, &cl, &sl, name, sizeof(name), err, sizeof(err)) != 0) {
        printf("ссылка не разобралась: %s\n", err);
        fails++;
        return;
    }
    OK("имя из фрагмента раскрыто", strcmp(name, "дом") == 0);
    OK("приватный ключ тот же", memcmp(sf.priv, sl.priv, 32) == 0 && sl.has_priv);
    OK("интерфейс тот же (адрес, маска, SNI, MTU)",
       cf.addr == cl.addr && cf.addr_plen == cl.addr_plen &&
       !strcmp(cf.sni, cl.sni) && cf.mtu == cl.mtu);
    int peers_same = cl.peer_n == 1 && cf.peer_n == 1 &&
                     !memcmp(cf.peer[0].pub, cl.peer[0].pub, 32) &&
                     !strcmp(cf.peer[0].endpoint, cl.peer[0].endpoint) &&
                     cf.peer[0].endpoint_port == cl.peer[0].endpoint_port &&
                     cf.peer[0].keepalive == cl.peer[0].keepalive &&
                     cf.peer[0].keepalive_set == cl.peer[0].keepalive_set &&
                     cf.peer[0].allowed_n == cl.peer[0].allowed_n;
    for (size_t i = 0; peers_same && i < cf.peer[0].allowed_n; i++)
        peers_same = cf.peer[0].allowed[i].net == cl.peer[0].allowed[i].net &&
                     cf.peer[0].allowed[i].plen == cl.peer[0].allowed[i].plen;
    OK("пир тот же (ключ, точка, префиксы, keepalive)", peers_same);
    xs_conf_wipe(&sf);
    xs_conf_wipe(&sl);
}

/* Круг: файл → ссылка → конфигурация → ссылка. Второй круг обязан дать ПОБАЙТОВО ту же строку,
 * иначе ссылка перестаёт быть способом передать доступ — она становится способом передать
 * что-то похожее. */
static void t_round_trip(void) {
    char file[1024];
    snprintf(file, sizeof(file),
             "[Interface]\nPrivateKey = %s\nAddress    = 10.77.0.5/24\nMTU        = 1400\n"
             "DNS        = 10.77.0.1\n\n"
             "[Peer]\nPublicKey  = %s\nAllowedIPs = 0.0.0.0/0\n"
             "Endpoint   = 198.51.100.9:8443\nPersistentKeepalive = 0\n", PRIV_B64, PUB_B64);
    struct xs_conf c, c2;
    struct xs_secrets s, s2;
    char err[320] = "";
    if (xs_conf_parse(file, strlen(file), XS_ROLE_SPOKE, &c, &s, err, sizeof(err)) != 0) {
        printf("файл не разобрался: %s\n", err);
        fails++;
        return;
    }
    char link[1024] = "", link2[1024] = "";
    if (xs_link_render(&c, &s, "узел один", link, sizeof(link), err, sizeof(err)) != 0) {
        printf("печать ссылки: %s\n", err);
        fails++;
        return;
    }
    /* Вектор снят с половины на Go: порядок параметров смысловой (pk первым), '/' в префиксах не
     * защищается, имя во фрагменте — процентной записью. */
    char want[1024];
    snprintf(want, sizeof(want),
             "xs://%s@198.51.100.9:8443?pk=%s&ip=10.77.0.5/24&allowed=0.0.0.0/0&mtu=1400&ka=0"
             "&dns=10.77.0.1"
             "#%%D1%%83%%D0%%B7%%D0%%B5%%D0%%BB%%20%%D0%%BE%%D0%%B4%%D0%%B8%%D0%%BD",
             PRIV_URL, PUB_URL);
    if (strcmp(link, want) != 0) printf("  напечатано: %s\n  ожидалось:  %s\n", link, want);
    OK("печать ссылки совпала с вектором половины на Go", strcmp(link, want) == 0);

    char name[XS_LINK_NAME_MAX] = "";
    if (xs_link_parse(link, XS_ROLE_SPOKE, &c2, &s2, name, sizeof(name), err, sizeof(err)) != 0) {
        printf("обратный разбор: %s\n", err);
        fails++;
        return;
    }
    OK("имя пережило круг", strcmp(name, "узел один") == 0);
    /* PersistentKeepalive = 0 ОБЯЗАН пережить круг: ноль означает «выключено», а потеря признака
     * превратила бы его в умолчание — то есть выключенный keepalive включился бы сам. */
    OK("ka=0 пережил круг (ноль это «выключено», а не «умолчание»)",
       c2.peer[0].keepalive == 0 && c2.peer[0].keepalive_set);
    OK("MTU и DNS пережили круг",
       c2.mtu == 1400 && c2.dns_n == 1 && !strcmp(c2.dns[0], "10.77.0.1"));
    OK("полный туннель пережил круг", c2.peer[0].allowed_n == 1 && c2.peer[0].allowed[0].plen == 0);
    if (xs_link_render(&c2, &s2, name, link2, sizeof(link2), err, sizeof(err)) != 0) {
        printf("вторая печать: %s\n", err);
        fails++;
    } else {
        if (strcmp(link, link2) != 0) printf("  1: %s\n  2: %s\n", link, link2);
        OK("второй круг дал побайтово ту же ссылку", strcmp(link, link2) == 0);
    }
    /* Файл из ссылки — вторая половина пары: присланную ссылку часто надо положить в /etc. */
    char text[XS_CONF_MAX];
    struct xs_conf c3;
    struct xs_secrets s3;
    if (xs_conf_render(&c2, &s2, text, sizeof(text), err, sizeof(err)) != 0) {
        printf("печать файла: %s\n", err);
        fails++;
    } else if (xs_conf_parse(text, strlen(text), XS_ROLE_SPOKE, &c3, &s3, err, sizeof(err)) != 0) {
        printf("файл из ссылки не разобрался: %s\n%s", err, text);
        fails++;
    } else {
        OK("файл, напечатанный из ссылки, разбирается в то же",
           c3.addr == c2.addr && c3.mtu == c2.mtu &&
           c3.peer[0].keepalive_set == c2.peer[0].keepalive_set &&
           !memcmp(c3.peer[0].pub, c2.peer[0].pub, 32));
        xs_conf_wipe(&s3);
    }
    xs_conf_wipe(&s);
    xs_conf_wipe(&s2);
}

/* Умолчание allowed — СЕТЬ ИЗ ip, а не полный туннель. Выбор в безопасную сторону: полный
 * туннель это воля человека, а не то, что случается от краткости ссылки. */
static void t_default_allowed(void) {
    char link[512];
    snprintf(link, sizeof(link), "xs://%s@203.0.113.7:443?pk=%s&ip=10.77.0.2/24",
             PRIV_URL, PUB_URL);
    struct xs_conf c;
    struct xs_secrets s;
    char err[320] = "";
    if (xs_link_parse(link, XS_ROLE_SPOKE, &c, &s, NULL, 0, err, sizeof(err)) != 0) {
        printf("ссылка без allowed: %s\n", err);
        fails++;
        return;
    }
    OK("без allowed берётся сеть из ip, а не 0.0.0.0/0",
       c.peer[0].allowed_n == 1 && c.peer[0].allowed[0].plen == 24 &&
       c.peer[0].allowed[0].net == ((10u << 24) | (77u << 16)));
    xs_conf_wipe(&s);
}

/* Разбор строгий, как у файла: каждая из этих ссылок обязана быть отвергнута С ОБЪЯСНЕНИЕМ.
 * Принятая молча опечатка означает «настроено» без настройки. */
static void t_rejects(void) {
    char base[512];
    snprintf(base, sizeof(base), "xs://%s@203.0.113.7:443?pk=%s&ip=10.77.0.2/24",
             PRIV_URL, PUB_URL);
    struct { const char *name, *link, *want; } cases[] = {
        { "чужая схема", "vless://x@203.0.113.7:443?pk=a&ip=10.0.0.1/24", "не xs" },
        { "нет ключа", "xs://203.0.113.7:443?pk=x", "приватного ключа" },
        { "короткий ключ", "xs://abc@203.0.113.7:443?pk=x&ip=10.0.0.1/24", "приватный ключ" },
        { "нет pk", NULL, "нет pk" },
        { "нет ip", NULL, "нет ip" },
        { "опечатка в параметре", NULL, "неизвестный параметр" },
        { "повтор параметра", NULL, "дважды" },
        { "имя вместо адреса", NULL, "IPv4" },
        { "порт вне предела", NULL, "порт" },
        { "адрес IPv6 внутри", NULL, "IPv4" },
        { "лишний путь", NULL, "лишний путь" },
        { "двоеточие перед @", NULL, "без пароля" },
    };
    char b[12][640];
    snprintf(b[3], sizeof(b[3]), "xs://%s@203.0.113.7:443?ip=10.77.0.2/24", PRIV_URL);
    snprintf(b[4], sizeof(b[4]), "xs://%s@203.0.113.7:443?pk=%s", PRIV_URL, PUB_URL);
    snprintf(b[5], sizeof(b[5]), "%s&snii=a", base);
    snprintf(b[6], sizeof(b[6]), "%s&sni=a&sni=b", base);
    snprintf(b[7], sizeof(b[7]), "xs://%s@example.com:443?pk=%s&ip=10.0.0.1/24",
             PRIV_URL, PUB_URL);
    snprintf(b[8], sizeof(b[8]), "xs://%s@203.0.113.7:99999?pk=%s&ip=10.0.0.1/24",
             PRIV_URL, PUB_URL);
    snprintf(b[9], sizeof(b[9]), "xs://%s@203.0.113.7:443?pk=%s&ip=fd00::1/64",
             PRIV_URL, PUB_URL);
    snprintf(b[10], sizeof(b[10]), "xs://%s@203.0.113.7:443/hello?pk=%s&ip=10.0.0.1/24",
             PRIV_URL, PUB_URL);
    snprintf(b[11], sizeof(b[11]), "xs://%s:pass@203.0.113.7:443?pk=%s&ip=10.0.0.1/24",
             PRIV_URL, PUB_URL);
    for (size_t i = 3; i < 12; i++) cases[i].link = b[i];

    for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); i++) {
        struct xs_conf c;
        struct xs_secrets s;
        char err[320] = "";
        int rc = xs_link_parse(cases[i].link, XS_ROLE_SPOKE, &c, &s, NULL, 0, err, sizeof(err));
        char what[96];
        snprintf(what, sizeof(what), "отвергнуто с объяснением: %s", cases[i].name);
        int good = rc != 0 && strstr(err, cases[i].want) != NULL;
        if (!good) printf("  %s: rc=%d err=%s\n", cases[i].name, rc, err);
        OK(what, good);
        if (rc == 0) xs_conf_wipe(&s);
    }
    /* Роль хаба отвергается ОБЪЯСНЕНИЕМ, а не общей ошибкой разбора: человек должен узнать, что
     * хаб настраивается файлом, а не что «ссылка неверна». */
    struct xs_conf c;
    struct xs_secrets s;
    char err[320] = "";
    int rc = xs_link_parse(base, XS_ROLE_HUB, &c, &s, NULL, 0, err, sizeof(err));
    OK("роль хаба: сказано, что хаб настраивается файлом",
       rc != 0 && strstr(err, "хаб настраивается файлом") != NULL);
    /* И печать хабовой конфигурации ссылкой — тоже отказ, а не ссылка «на первого пира». */
    char hub[1024];
    snprintf(hub, sizeof(hub),
             "[Interface]\nPrivateKey = %s\nAddress = 10.77.0.1/24\nListenPort = 443\n\n"
             "[Peer]\nPublicKey = %s\nAllowedIPs = 10.77.0.2/32\n", PRIV_B64, PUB_B64);
    struct xs_conf hc;
    struct xs_secrets hs;
    if (xs_conf_parse(hub, strlen(hub), XS_ROLE_HUB, &hc, &hs, err, sizeof(err)) != 0) {
        printf("конфигурация хаба не разобралась: %s\n", err);
        fails++;
    } else {
        char link[512];
        rc = xs_link_render(&hc, &hs, NULL, link, sizeof(link), err, sizeof(err));
        OK("печать: конфигурацию хаба ссылкой не выдать", rc != 0 && strstr(err, "хаб") != NULL);
        xs_conf_wipe(&hs);
    }
}

/* Ссылка из недоверенного источника: обрезки, мусор и очень длинные значения не должны ни падать,
 * ни уходить за буфер. Проверяется тем же приёмом, что и разбор Hello, — обрезкой по всем длинам.
 * Стенд имеет смысл только под санитайзерами, поэтому он молчалив: важен не вывод, а то, что
 * прогон дошёл до конца. */
static void t_fuzz_truncations(void) {
    char link[1024];
    snprintf(link, sizeof(link),
             "xs://%s@203.0.113.7:443?pk=%s&ip=10.77.0.2/24&allowed=10.77.0.0/24,192.168.9.0/24"
             "&sni=www.microsoft.com&mtu=1400&ka=25&dns=10.77.0.1#дом",
             PRIV_URL, PUB_URL);
    size_t n = strlen(link);
    for (size_t cut = 0; cut <= n; cut++) {
        char buf[1024];
        snprintf(buf, sizeof(buf), "%.*s", (int)cut, link);
        struct xs_conf c;
        struct xs_secrets s;
        char err[320];
        if (xs_link_parse(buf, XS_ROLE_SPOKE, &c, &s, NULL, 0, err, sizeof(err)) == 0)
            xs_conf_wipe(&s);
    }
    /* И порча каждого байта по очереди — на тех же основаниях. */
    for (size_t i = 0; i < n; i++) {
        char buf[1024];
        snprintf(buf, sizeof(buf), "%s", link);
        buf[i] = (char)0xFF;
        struct xs_conf c;
        struct xs_secrets s;
        char err[320];
        if (xs_link_parse(buf, XS_ROLE_SPOKE, &c, &s, NULL, 0, err, sizeof(err)) == 0)
            xs_conf_wipe(&s);
    }
    /* Незакрытая процентная запись и пустые пары — частые следы копирования. */
    const char *odd[] = { "xs://k@1.2.3.4:443?pk=%", "xs://k@1.2.3.4:443?pk=%A",
                          "xs://k@1.2.3.4:443?&&&", "xs://", "xs://@", "xs://@:",
                          "xs://k@1.2.3.4:443?=v", "xs://k@1.2.3.4:443?pk", "xs://k@1.2.3.4:0?pk=a" };
    for (size_t i = 0; i < sizeof(odd) / sizeof(odd[0]); i++) {
        struct xs_conf c;
        struct xs_secrets s;
        char err[320];
        if (xs_link_parse(odd[i], XS_ROLE_SPOKE, &c, &s, NULL, 0, err, sizeof(err)) == 0)
            xs_conf_wipe(&s);
    }
    OK("обрезки, порча байтов и незакрытая запись не роняют разбор", 1);
}

int main(void) {
    t_key_alphabets();
    t_link_equals_file();
    t_round_trip();
    t_default_allowed();
    t_rejects();
    t_fuzz_truncations();
    printf(fails ? "\nПРОВАЛОВ: %d\n" : "\nвсё сошлось\n", fails);
    return fails ? 1 : 0;
}
