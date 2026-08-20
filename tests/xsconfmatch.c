/* Разбор конфигурации xsteer: единственное место, куда в движок попадает текст, который
 * человек написал руками.
 *
 * Зачем отдельным стендом. Разбор здесь СТРОГИЙ, и каждая его строгость — про конкретную
 * тихую поломку: опечатка в AllowedIPs уводит половину маршрутов; ключ, усечённый на
 * символ, ослабляет криптографию; `PostUp`, принятый молча, обещает исполнение команды,
 * которого не будет; пересекающиеся префиксы двух пиров на хабе означают «работает, но не
 * туда». Ни одно из этого не видно из журнала, поэтому проверяется здесь, литералами.
 *
 * Отдельно проверяется УТЕЧКА: вывод xs_conf_json не содержит приватного ключа ни в одном
 * виде. Обещание «секретов в status и diag нет» держится на том, что xs_conf_json не имеет
 * доступа к struct xs_secrets по построению, — и вот проверка, что это так и осталось.
 *
 * Ни сети, ни прав root, ни mbedtls: xsconf.c намеренно без библиотеки (это же требуется
 * для build/diagsim), поэтому стенд включает исходник напрямую и входит в обычный
 * make test. */
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#include "../src/ext/xsconf.c"

static int fails;

static void check(const char *what, long want, long got) {
    printf("%-62s %s\n", what, want == got ? "ok" : "ПРОВАЛ");
    if (want != got) {
        printf("     хочу: %ld\n     есть:  %ld\n", want, got);
        fails++;
    }
}

static void check_str(const char *what, const char *want, const char *got) {
    printf("%-62s %s\n", what, strcmp(want, got) == 0 ? "ok" : "ПРОВАЛ");
    if (strcmp(want, got) != 0) {
        printf("     хочу: \"%s\"\n     есть:  \"%s\"\n", want, got);
        fails++;
    }
}

/* Настоящие 44-символьные ключи: base64 от 32 байт. Берутся из xs_key_encode, чтобы стенд
 * не зависел от того, что кто-то правильно набрал их руками. */
static char KEY_A[XS_KEY_B64 + 1], KEY_B[XS_KEY_B64 + 1], KEY_C[XS_KEY_B64 + 1];

static struct xs_conf g_c;
static struct xs_secrets g_s;
static char g_err[256];

static int parse(const char *text, enum xs_role role) {
    g_err[0] = '\0';
    return xs_conf_parse(text, strlen(text), role, &g_c, &g_s, g_err, sizeof(g_err));
}

/* Отказ проверяется не только кодом, но и тем, что объяснение НЕ ПУСТОЕ: отказ без текста
 * означает «не работает, и почему — неизвестно», то есть худший вид отказа. */
static void refuses(const char *what, const char *text, enum xs_role role) {
    int rc = parse(text, role);
    int ok = rc == -1 && g_err[0] != '\0';
    printf("%-62s %s\n", what, ok ? "ok" : "ПРОВАЛ");
    if (!ok) {
        printf("     код: %d, объяснение: \"%s\"\n", rc, g_err);
        fails++;
    }
}

int main(void) {
    uint8_t ka[32], kb[32], kc[32];
    for (int i = 0; i < 32; i++) { ka[i] = (uint8_t)(i + 1); kb[i] = (uint8_t)(200 - i); kc[i] = (uint8_t)(i * 7 + 3); }
    xs_key_encode(ka, KEY_A);
    xs_key_encode(kb, KEY_B);
    xs_key_encode(kc, KEY_C);

    /* ---- base64 ключей: строго --------------------------------------------- */
    {
        uint8_t out[32];
        check("ключ: 44 символа — длина строки", XS_KEY_B64, (long)strlen(KEY_A));
        check("ключ: круг encode → decode", 0, xs_key_decode(KEY_A, out));
        check("ключ: круг даёт те же байты", 0, memcmp(out, ka, 32));
        char bad[XS_KEY_B64 + 2];
        snprintf(bad, sizeof(bad), "%s", KEY_A);
        bad[XS_KEY_B64 - 1] = 'A';            /* '=' заменён символом */
        check("ключ: без выравнивающего '=' — отказ", -1, xs_key_decode(bad, out));
        snprintf(bad, sizeof(bad), "%.43s", KEY_A);
        check("ключ: 43 символа — отказ", -1, xs_key_decode(bad, out));
        snprintf(bad, sizeof(bad), "%s=", KEY_A);
        check("ключ: 45 символов — отказ", -1, xs_key_decode(bad, out));
        snprintf(bad, sizeof(bad), "%s", KEY_A);
        bad[3] = '!';
        check("ключ: чужой символ — отказ", -1, xs_key_decode(bad, out));
        snprintf(bad, sizeof(bad), "%s", KEY_A);
        bad[3] = '-';                          /* url-safe алфавит: не наш */
        check("ключ: url-safe алфавит — отказ", -1, xs_key_decode(bad, out));
        /* 43-й символ несёт два лишних бита: они обязаны быть нулевыми, иначе у одного
         * ключа было бы четыре разных написания. */
        snprintf(bad, sizeof(bad), "%s", KEY_A);
        bad[XS_KEY_B64 - 2] = (char)(bad[XS_KEY_B64 - 2] == 'A' ? 'B' : 'A');
        int rc = xs_key_decode(bad, out);
        check("ключ: лишние биты в хвосте — отказ или те же байты",
              1, rc == -1 || memcmp(out, ka, 32) == 0);
        char fp[12];
        xs_key_fp(ka, fp);
        check("отпечаток: восемь символов", 8, (long)strlen(fp));
        check("отпечаток: начало base64 ключа", 0, memcmp(fp, KEY_A, 8));
    }

    /* ---- канонический файл пира ------------------------------------------- */
    {
        char t[1024];
        snprintf(t, sizeof(t),
                 "# пир\n"
                 "[Interface]\n"
                 "PrivateKey = %s\n"
                 "Address    = 10.77.0.2/24\n"
                 "SNI        = www.example.com\n"
                 "\n"
                 "[Peer]\n"
                 "PublicKey  = %s\n"
                 "AllowedIPs = 10.77.0.0/24, 192.168.88.0/24\n"
                 "Endpoint   = 203.0.113.10:443\n"
                 "PersistentKeepalive = 15\n", KEY_A, KEY_B);
        check("пир: файл принят", 0, parse(t, XS_ROLE_SPOKE));
        check("пир: приватный ключ прочитан", 1, g_s.has_priv);
        check("пир: приватный ключ тот самый", 0, memcmp(g_s.priv, ka, 32));
        check("пир: адрес", 0x0A4D0002u, (long)g_c.addr);
        check("пир: длина префикса", 24, g_c.addr_plen);
        check_str("пир: SNI", "www.example.com", g_c.sni);
        check("пир: один пир", 1, (long)g_c.peer_n);
        check("пир: публичный ключ пира", 0, memcmp(g_c.peer[0].pub, kb, 32));
        check("пир: два префикса", 2, (long)g_c.peer[0].allowed_n);
        check("пир: первый префикс", 0x0A4D0000u, (long)g_c.peer[0].allowed[0].net);
        check("пир: второй префикс", 0xC0A85800u, (long)g_c.peer[0].allowed[1].net);
        check_str("пир: адрес хаба", "203.0.113.10", g_c.peer[0].endpoint);
        check("пир: порт хаба", 443, g_c.peer[0].endpoint_port);
        check("пир: keepalive из файла", 15, g_c.peer[0].keepalive);
        check("пир: не слушает", 0, g_c.listen_port);
        check("пир: неизвестных ключей нет", 0, g_c.unknown_n);
        check("пир: MTU не задан — вывести из канала", 0, g_c.mtu);
    }
    {
        /* Ни один секрет не должен попасть в вывод. Проверяется буквально: печатаем JSON и
         * ищем в нём base64 приватного ключа и любой его восьмисимвольный кусок. */
        char t[1024];
        snprintf(t, sizeof(t),
                 "[Interface]\nPrivateKey=%s\nAddress=10.77.0.2/24\n"
                 "[Peer]\nPublicKey=%s\nAllowedIPs=0.0.0.0/0\nEndpoint=203.0.113.10:443\n",
                 KEY_A, KEY_B);
        check("утечка: файл принят", 0, parse(t, XS_ROLE_SPOKE));
        char buf[4096];
        FILE *f = fmemopen(buf, sizeof(buf), "w");
        xs_conf_json(f, &g_c);
        fclose(f);
        check("утечка: приватного ключа в JSON нет", 0, strstr(buf, KEY_A) != NULL);
        char part[9];
        memcpy(part, KEY_A, 8);
        part[8] = '\0';
        check("утечка: даже его начала в JSON нет", 0, strstr(buf, part) != NULL);
        check("утечка: отпечаток публичного ключа есть", 1, strstr(buf, "\"key\":") != NULL);
        /* Затирание: после wipe в структуре не должно остаться ни одного байта ключа. */
        xs_conf_wipe(&g_s);
        int nz = 0;
        for (int i = 0; i < 32; i++) if (g_s.priv[i]) nz++;
        check("затирание: приватный ключ обнулён", 0, nz);
        check("затирание: признак снят", 0, g_s.has_priv);
    }

    /* ---- терпимость к тому, как люди пишут файлы --------------------------- */
    {
        /* CRLF: конфигурацию правят и в Windows, и через веб-панели. Отвергать её за
         * перевод строки значило бы отвергать правильный файл. */
        char t[512];
        snprintf(t, sizeof(t),
                 "[Interface]\r\nprivatekey=%s\r\nADDRESS = 10.0.0.2/32\r\n\r\n"
                 "[peer]\r\nPUBLICKEY=%s\r\nallowedips = 10.0.0.0/24 , 10.1.0.0/16\r\n"
                 "endpoint=198.51.100.1:8443\r\n", KEY_A, KEY_B);
        check("CRLF и любой регистр ключей: принято", 0, parse(t, XS_ROLE_SPOKE));
        check("CRLF: адрес разобран", 0x0A000002u, (long)g_c.addr);
        check("пробелы вокруг запятых: два префикса", 2, (long)g_c.peer[0].allowed_n);
        check("keepalive не задан — умолчание wg", 25, g_c.peer[0].keepalive);
    }
    {
        /* Хост-биты за маской обнуляются молча — так же, как это делает wg: «10.0.0.5/24»
         * человек пишет чаще, чем «10.0.0.0/24». */
        char t[512];
        snprintf(t, sizeof(t),
                 "[Interface]\nPrivateKey=%s\nAddress=10.0.0.2\n"
                 "[Peer]\nPublicKey=%s\nAllowedIPs=10.9.9.9/24\nEndpoint=1.2.3.4:443\n",
                 KEY_A, KEY_B);
        check("префикс с хост-битами: принят", 0, parse(t, XS_ROLE_SPOKE));
        check("префикс с хост-битами: обнулены", 0x0A090900u, (long)g_c.peer[0].allowed[0].net);
        check("Address без префикса — это /32", 32, g_c.addr_plen);
    }
    {
        char t[512];
        snprintf(t, sizeof(t),
                 "; точка с запятой тоже комментарий\n"
                 "[Interface]\nPrivateKey=%s\nAddress=10.0.0.2/24\nMTU=1380\n"
                 "[Peer]\nPublicKey=%s\nAllowedIPs=0.0.0.0/0\nEndpoint=1.2.3.4:443\n"
                 "PersistentKeepalive=0\n", KEY_A, KEY_B);
        check("комментарии и MTU: принято", 0, parse(t, XS_ROLE_SPOKE));
        check("MTU из файла", 1380, g_c.mtu);
        /* Ноль означает «выключено» и обязан выжить: умолчание применяется только когда
         * ключа нет вовсе, иначе выключить keepalive было бы нечем. */
        check("keepalive = 0 остаётся нулём", 0, g_c.peer[0].keepalive);
    }

    /* ---- хаб ---------------------------------------------------------------- */
    {
        char t[1024];
        snprintf(t, sizeof(t),
                 "[Interface]\nPrivateKey=%s\nAddress=10.77.0.1/24\nListenPort=443\n"
                 "Device=xshubc0\n"
                 "[Peer]\nPublicKey=%s\nAllowedIPs=10.77.0.2/32, 192.168.88.0/24\n"
                 "[Peer]\nPublicKey=%s\nAllowedIPs=10.77.0.3/32, 192.168.99.0/24\n",
                 KEY_A, KEY_B, KEY_C);
        check("хаб: файл принят", 0, parse(t, XS_ROLE_HUB));
        check("хаб: два пира", 2, (long)g_c.peer_n);
        check("хаб: слушает", 443, g_c.listen_port);
        check_str("хаб: имя устройства из Device", "xshubc0", g_c.device);
        check("хаб: у пиров нет endpoint", 0, g_c.peer[0].endpoint_port);
        check("хаб: keepalive не подставляется", 0, g_c.peer[0].keepalive);
        check("хаб: неизвестных ключей нет", 0, g_c.unknown_n);
    }
    {
        /* Device без значения по умолчанию пуст — хаб возьмёт xshub0. И мусорное имя отвергается
         * здесь, а не на подъёме `ip link`, где ошибку видно хуже. */
        char t[1024];
        snprintf(t, sizeof(t),
                 "[Interface]\nPrivateKey=%s\nAddress=10.77.0.1/24\nListenPort=443\nDevice=bad name\n"
                 "[Peer]\nPublicKey=%s\nAllowedIPs=10.77.0.2/32\n", KEY_A, KEY_B);
        refuses("отказ: Device с пробелом", t, XS_ROLE_HUB);
    }

    /* ---- защита от зондирования: режим и адрес прикрытия ---------------------
     *
     * Ключи хаба, и проверяется у них главное: режим называется словом, адрес прикрытия — это
     * литерал IPv4 с портом (имя пришлось бы разрешать через DNS из цикла, где нет ни одного
     * блокирующего вызова), режим proxy без адреса отвергается ДО подъёма, а у пира этих ключей
     * нет вовсе — неопознанные приходят на слушающий порт, а пир никуда не слушает.
     *
     * Отказ до подъёма здесь не придирчивость: неверная настройка защиты, обнаруженная под
     * зондированием, — это защита, которой нет. */
    {
        char t[1024];
#define HUB_HEAD "[Interface]\nPrivateKey=%s\nAddress=10.77.0.1/24\nListenPort=443\n"
#define HUB_PEER "[Peer]\nPublicKey=%s\nAllowedIPs=10.77.0.2/32\n"
        snprintf(t, sizeof(t), HUB_HEAD HUB_PEER, KEY_A, KEY_B);
        check("без ключа Decoy: режим — прежнее поведение", 0, parse(t, XS_ROLE_HUB));
        check("и это оповещение TLS", (long)XS_DECOY_ALERT, (long)g_c.decoy);
        check("адреса прикрытия нет", 0, g_c.decoy_port);

        snprintf(t, sizeof(t), HUB_HEAD "Decoy=silent\n" HUB_PEER, KEY_A, KEY_B);
        check("Decoy = silent принят", 0, parse(t, XS_ROLE_HUB));
        check("режим silent", (long)XS_DECOY_SILENT, (long)g_c.decoy);
        snprintf(t, sizeof(t), HUB_HEAD "decoy = RESET\n" HUB_PEER, KEY_A, KEY_B);
        check("Decoy = reset принят в любом регистре", 0, parse(t, XS_ROLE_HUB));
        check("режим reset", (long)XS_DECOY_RESET, (long)g_c.decoy);

        snprintf(t, sizeof(t), HUB_HEAD "Decoy=proxy\nDecoyDest=93.184.216.34:443\n" HUB_PEER,
                 KEY_A, KEY_B);
        check("Decoy = proxy с адресом принят", 0, parse(t, XS_ROLE_HUB));
        check("режим proxy", (long)XS_DECOY_PROXY, (long)g_c.decoy);
        check_str("адрес прикрытия", "93.184.216.34", g_c.decoy_dest);
        check("порт прикрытия", 443, g_c.decoy_port);
        check("неизвестных ключей не появилось", 0, g_c.unknown_n);

        snprintf(t, sizeof(t), HUB_HEAD "Decoy=proxy\n" HUB_PEER, KEY_A, KEY_B);
        refuses("отказ: proxy без DecoyDest", t, XS_ROLE_HUB);
        snprintf(t, sizeof(t), HUB_HEAD "Decoy=quiet\n" HUB_PEER, KEY_A, KEY_B);
        refuses("отказ: неизвестный режим", t, XS_ROLE_HUB);
        snprintf(t, sizeof(t),
                 HUB_HEAD "Decoy=proxy\nDecoyDest=www.example.com:443\n" HUB_PEER, KEY_A, KEY_B);
        refuses("отказ: прикрытие именем, а не адресом", t, XS_ROLE_HUB);
        snprintf(t, sizeof(t), HUB_HEAD "Decoy=proxy\nDecoyDest=93.184.216.34\n" HUB_PEER,
                 KEY_A, KEY_B);
        refuses("отказ: прикрытие без порта", t, XS_ROLE_HUB);
        snprintf(t, sizeof(t), HUB_HEAD "Decoy=proxy\nDecoyDest=93.184.216.34:0\n" HUB_PEER,
                 KEY_A, KEY_B);
        refuses("отказ: порт прикрытия вне диапазона", t, XS_ROLE_HUB);
        snprintf(t, sizeof(t),
                 "[Interface]\nPrivateKey=%s\nAddress=10.0.0.2/24\nDecoy=silent\n"
                 "[Peer]\nPublicKey=%s\nAllowedIPs=0.0.0.0/0\nEndpoint=1.2.3.4:443\n",
                 KEY_A, KEY_B);
        refuses("отказ: Decoy в конфигурации пира", t, XS_ROLE_SPOKE);

        /* ---- имена прикрытия (DecoySNI, R-070) -------------------------------
         *
         * Список имён, по которым прибор сам выбирает прикрытие: без него подлинный сертификат
         * получает только тот, кто спросил имя нашего DecoyDest, а всякий другой видит
         * расхождение «просил A — получил сертификат B». Разрешаются имена ОДИН РАЗ при
         * подъёме хаба, поэтому здесь проверяется ровно то, что можно проверить по тексту:
         * имя нормализовано (нижний регистр, без завершающей точки — сравнивать его предстоит
         * с чужим SNI, и нормализовать обе стороны на каждом неопознанном было бы лишней
         * работой над недоверенными байтами) и заведомо негодное отвергнуто ДО подъёма.
         *
         * Отдельно — подстановка: она отвергается СВОЕЙ причиной, потому что человек пишет её
         * не по опечатке, а копируя ключ --decoy-sni реализации на Go, где подстановки есть. */
        snprintf(t, sizeof(t),
                 HUB_HEAD "Decoy=proxy\nDecoyDest=93.184.216.34:443\n"
                 "DecoySNI = WWW.Example.COM. , cdn.example.net\n" HUB_PEER, KEY_A, KEY_B);
        check("DecoySNI: список принят", 0, parse(t, XS_ROLE_HUB));
        check("DecoySNI: посчитаны оба имени, а не строка", 2, (long)g_c.decoy_sni_n);
        check_str("DecoySNI: имя приведено к нижнему регистру и без точки в конце",
                  "www.example.com", g_c.decoy_sni[0]);
        check_str("DecoySNI: второе имя на месте", "cdn.example.net", g_c.decoy_sni[1]);
        check("DecoySNI: постоянное прикрытие никуда не делось", 443, g_c.decoy_port);

        snprintf(t, sizeof(t),
                 HUB_HEAD "Decoy=proxy\nDecoyDest=93.184.216.34:443\n"
                 "DecoySNI=*.example.com\n" HUB_PEER, KEY_A, KEY_B);
        refuses("отказ: подстановка в DecoySNI", t, XS_ROLE_HUB);
        check("и отказ назвал именно подстановку", 1,
              strstr(g_err, "одстановк") != NULL);

        snprintf(t, sizeof(t),
                 HUB_HEAD "Decoy=proxy\nDecoyDest=93.184.216.34:443\n"
                 "DecoySNI=www.example.com/../etc\n" HUB_PEER, KEY_A, KEY_B);
        refuses("отказ: в имени посторонние символы", t, XS_ROLE_HUB);
        snprintf(t, sizeof(t),
                 HUB_HEAD "Decoy=proxy\nDecoyDest=93.184.216.34:443\n"
                 "DecoySNI=www..example.com\n" HUB_PEER, KEY_A, KEY_B);
        refuses("отказ: две точки подряд", t, XS_ROLE_HUB);
        snprintf(t, sizeof(t),
                 HUB_HEAD "Decoy=proxy\nDecoyDest=93.184.216.34:443\n"
                 "DecoySNI=.example.com\n" HUB_PEER, KEY_A, KEY_B);
        refuses("отказ: имя с точки — это подстановка формы Go", t, XS_ROLE_HUB);
        {
            /* Имя длиннее буфера ОТВЕРГАЕТСЯ, а не обрезается: обрезанное не совпало бы ни с
             * одним настоящим SNI никогда, то есть ключ выглядел бы настроенным и молчал. */
            char longname[XS_DECOY_SNI_LEN + 16];
            memset(longname, 'a', sizeof(longname) - 1);
            longname[sizeof(longname) - 1] = '\0';
            snprintf(t, sizeof(t),
                     HUB_HEAD "Decoy=proxy\nDecoyDest=93.184.216.34:443\nDecoySNI=%s\n"
                     HUB_PEER, KEY_A, longname, KEY_B);
            refuses("отказ: имя длиннее буфера", t, XS_ROLE_HUB);
        }
        {
            char names[512] = "";
            for (int i = 0; i <= XS_DECOY_SNI_MAX; i++) {
                char one[32];
                snprintf(one, sizeof(one), "%sn%d.example.com", i ? "," : "", i);
                strncat(names, one, sizeof(names) - strlen(names) - 1);
            }
            snprintf(t, sizeof(t),
                     HUB_HEAD "Decoy=proxy\nDecoyDest=93.184.216.34:443\nDecoySNI=%s\n"
                     HUB_PEER, KEY_A, names, KEY_B);
            refuses("отказ: имён больше предела", t, XS_ROLE_HUB);
        }

        snprintf(t, sizeof(t),
                 HUB_HEAD "Decoy=alert\nDecoySNI=www.example.com\n" HUB_PEER, KEY_A, KEY_B);
        refuses("отказ: DecoySNI без режима proxy", t, XS_ROLE_HUB);
        snprintf(t, sizeof(t),
                 "[Interface]\nPrivateKey=%s\nAddress=10.0.0.2/24\n"
                 "DecoySNI=www.example.com\n"
                 "[Peer]\nPublicKey=%s\nAllowedIPs=0.0.0.0/0\nEndpoint=1.2.3.4:443\n",
                 KEY_A, KEY_B);
        refuses("отказ: DecoySNI в конфигурации пира", t, XS_ROLE_SPOKE);
    }

    /* ---- DNS: принимается, но не применяется --------------------------------
     *
     * Ключ отвергать нельзя, и это не мелочь: конфигурация носится между роутером и
     * десктопом, а десктопный клиент DNS применяет. Файл, принятый одной реализацией и
     * отвергнутый другой, означает, что «настроено» зависит от того, куда его положили.
     * Применить его здесь тоже нельзя (именами распоряжается dnsmasq), поэтому разбор
     * СЧИТАЕТ адреса, а сказать о них один раз — дело того, кто поднимает туннель. */
    {
        char t[1024];
        snprintf(t, sizeof(t),
                 "[Interface]\nPrivateKey=%s\nAddress=10.0.0.2/24\nDNS=1.1.1.1, 8.8.8.8\n"
                 "[Peer]\nPublicKey=%s\nAllowedIPs=0.0.0.0/0\nEndpoint=1.2.3.4:443\n",
                 KEY_A, KEY_B);
        check("DNS: файл принят, а не отвергнут", 0, parse(t, XS_ROLE_SPOKE));
        check("DNS: посчитаны оба адреса, а не строка", 2, g_c.dns_n);
        check("DNS: неизвестных ключей не появилось", 0, g_c.unknown_n);
        snprintf(t, sizeof(t),
                 "[Interface]\nPrivateKey=%s\nAddress=10.0.0.2/24\n"
                 "[Peer]\nPublicKey=%s\nAllowedIPs=0.0.0.0/0\nEndpoint=1.2.3.4:443\n",
                 KEY_A, KEY_B);
        check("DNS: без ключа счётчик нулевой", 0, parse(t, XS_ROLE_SPOKE));
        check("DNS: и равен нулю", 0, g_c.dns_n);
    }

    /* ---- отказы ------------------------------------------------------------- */
    {
        char t[1024];
#define SPOKE_HEAD "[Interface]\nPrivateKey=%s\nAddress=10.0.0.2/24\n"
#define PEER_OK    "[Peer]\nPublicKey=%s\nAllowedIPs=0.0.0.0/0\nEndpoint=1.2.3.4:443\n"

        snprintf(t, sizeof(t), SPOKE_HEAD "Table=off\n" PEER_OK, KEY_A, KEY_B);
        refuses("отказ: Table (таблицами владеет apply)", t, XS_ROLE_SPOKE);
        snprintf(t, sizeof(t), SPOKE_HEAD "FwMark=0x100\n" PEER_OK, KEY_A, KEY_B);
        refuses("отказ: FwMark (метками владеет движок)", t, XS_ROLE_SPOKE);
        snprintf(t, sizeof(t), SPOKE_HEAD "PostUp=iptables -A FORWARD -j ACCEPT\n" PEER_OK,
                 KEY_A, KEY_B);
        refuses("отказ: PostUp (движок не исполняет команды из файла)", t, XS_ROLE_SPOKE);
        snprintf(t, sizeof(t), SPOKE_HEAD "SaveConfig=true\n" PEER_OK, KEY_A, KEY_B);
        refuses("отказ: SaveConfig", t, XS_ROLE_SPOKE);
        snprintf(t, sizeof(t), SPOKE_HEAD PEER_OK "PresharedKey=%s\n", KEY_A, KEY_B, KEY_C);
        refuses("отказ: PresharedKey (не используется криптографией)", t, XS_ROLE_SPOKE);

        snprintf(t, sizeof(t), SPOKE_HEAD PEER_OK, KEY_A, KEY_B);
        char *p = strstr(t, "AllowedIPs");
        memcpy(p, "AllowdIPs ", 10);            /* опечатка: пропущена буква */
        refuses("отказ: опечатка в имени ключа", t, XS_ROLE_SPOKE);
        check("отказ: опечатка получает подсказку", 1, strstr(g_err, "AllowedIPs") != NULL);

        snprintf(t, sizeof(t), "[Interfce]\nPrivateKey=%s\n", KEY_A);
        refuses("отказ: неизвестная секция", t, XS_ROLE_SPOKE);
        snprintf(t, sizeof(t), "PrivateKey=%s\n", KEY_A);
        refuses("отказ: ключ вне секции", t, XS_ROLE_SPOKE);
        snprintf(t, sizeof(t), "[Interface\nPrivateKey=%s\n", KEY_A);
        refuses("отказ: секция без закрывающей скобки", t, XS_ROLE_SPOKE);
        snprintf(t, sizeof(t), "[Interface]\nPrivateKey\n");
        refuses("отказ: строка без знака равенства", t, XS_ROLE_SPOKE);
        snprintf(t, sizeof(t), "[Interface]\nPrivateKey=\n");
        refuses("отказ: ключ без значения", t, XS_ROLE_SPOKE);

        snprintf(t, sizeof(t), "[Interface]\nPrivateKey=%.43s\nAddress=10.0.0.2/24\n" PEER_OK,
                 KEY_A, KEY_B);
        refuses("отказ: PrivateKey на символ короче", t, XS_ROLE_SPOKE);
        snprintf(t, sizeof(t), "[Interface]\nAddress=10.0.0.2/24\n" PEER_OK, KEY_B);
        refuses("отказ: нет PrivateKey", t, XS_ROLE_SPOKE);
        snprintf(t, sizeof(t), "[Interface]\nPrivateKey=%s\n" PEER_OK, KEY_A, KEY_B);
        refuses("отказ: нет Address", t, XS_ROLE_SPOKE);
        snprintf(t, sizeof(t), SPOKE_HEAD, KEY_A);
        refuses("отказ: нет ни одного пира", t, XS_ROLE_SPOKE);

        snprintf(t, sizeof(t), "[Interface]\nPrivateKey=%s\nAddress=fd00::2/64\n" PEER_OK,
                 KEY_A, KEY_B);
        refuses("отказ: IPv6 в Address назван прямо", t, XS_ROLE_SPOKE);
        snprintf(t, sizeof(t), "[Interface]\nPrivateKey=%s\nAddress=10.0.0.2/33\n" PEER_OK,
                 KEY_A, KEY_B);
        refuses("отказ: длина префикса больше 32", t, XS_ROLE_SPOKE);
        snprintf(t, sizeof(t), SPOKE_HEAD "MTU=64\n" PEER_OK, KEY_A, KEY_B);
        refuses("отказ: MTU вне разумного", t, XS_ROLE_SPOKE);

        snprintf(t, sizeof(t), SPOKE_HEAD
                 "[Peer]\nPublicKey=%s\nAllowedIPs=0.0.0.0/0\nEndpoint=hub.example.com:443\n",
                 KEY_A, KEY_B);
        refuses("отказ: Endpoint именем, а не адресом", t, XS_ROLE_SPOKE);
        check("отказ: причина названа (DNS через этот же туннель)", 1,
              strstr(g_err, "DNS") != NULL);
        snprintf(t, sizeof(t), SPOKE_HEAD
                 "[Peer]\nPublicKey=%s\nAllowedIPs=0.0.0.0/0\nEndpoint=1.2.3.4\n",
                 KEY_A, KEY_B);
        refuses("отказ: Endpoint без порта", t, XS_ROLE_SPOKE);
        snprintf(t, sizeof(t), SPOKE_HEAD
                 "[Peer]\nPublicKey=%s\nAllowedIPs=0.0.0.0/0\nEndpoint=1.2.3.4:0\n",
                 KEY_A, KEY_B);
        refuses("отказ: Endpoint с портом 0", t, XS_ROLE_SPOKE);
        snprintf(t, sizeof(t), SPOKE_HEAD
                 "[Peer]\nPublicKey=%s\nAllowedIPs=10.0.0.0/8,мусор\nEndpoint=1.2.3.4:443\n",
                 KEY_A, KEY_B);
        refuses("отказ: неразбираемый префикс в AllowedIPs", t, XS_ROLE_SPOKE);
        snprintf(t, sizeof(t), SPOKE_HEAD
                 "[Peer]\nPublicKey=%s\nEndpoint=1.2.3.4:443\n", KEY_A, KEY_B);
        refuses("отказ: пир без AllowedIPs", t, XS_ROLE_SPOKE);
        snprintf(t, sizeof(t), SPOKE_HEAD
                 "[Peer]\nAllowedIPs=0.0.0.0/0\nEndpoint=1.2.3.4:443\n", KEY_A);
        refuses("отказ: пир без PublicKey", t, XS_ROLE_SPOKE);

        /* Роль решает подкоманда, но требования проверяются здесь. */
        snprintf(t, sizeof(t), SPOKE_HEAD "ListenPort=443\n" PEER_OK, KEY_A, KEY_B);
        refuses("отказ: ListenPort у пира", t, XS_ROLE_SPOKE);
        snprintf(t, sizeof(t), SPOKE_HEAD PEER_OK
                 "[Peer]\nPublicKey=%s\nAllowedIPs=10.5.0.0/16\nEndpoint=5.6.7.8:443\n",
                 KEY_A, KEY_B, KEY_C);
        refuses("отказ: у пира два пира", t, XS_ROLE_SPOKE);
        snprintf(t, sizeof(t), SPOKE_HEAD "[Peer]\nPublicKey=%s\nAllowedIPs=0.0.0.0/0\n",
                 KEY_A, KEY_B);
        refuses("отказ: у пира пира нет Endpoint", t, XS_ROLE_SPOKE);
        snprintf(t, sizeof(t), "[Interface]\nPrivateKey=%s\nAddress=10.0.0.1/24\n"
                 "[Peer]\nPublicKey=%s\nAllowedIPs=10.0.0.2/32\n", KEY_A, KEY_B);
        refuses("отказ: хаб без ListenPort", t, XS_ROLE_HUB);
        snprintf(t, sizeof(t), "[Interface]\nPrivateKey=%s\nAddress=10.0.0.1/24\n"
                 "ListenPort=443\n" PEER_OK, KEY_A, KEY_B);
        refuses("отказ: Endpoint в конфигурации хаба", t, XS_ROLE_HUB);

        /* Самая ценная проверка хаба: пересечение префиксов означало бы, что пакет
         * достаётся непредсказуемой пиру, а симптом — «работает, но не туда». */
        snprintf(t, sizeof(t), "[Interface]\nPrivateKey=%s\nAddress=10.0.0.1/24\n"
                 "ListenPort=443\n"
                 "[Peer]\nPublicKey=%s\nAllowedIPs=10.9.0.0/16\n"
                 "[Peer]\nPublicKey=%s\nAllowedIPs=10.9.5.0/24\n", KEY_A, KEY_B, KEY_C);
        refuses("отказ: AllowedIPs двух пиров пересекаются", t, XS_ROLE_HUB);
        check("отказ: названы оба пира", 1,
              strstr(g_err, "1") != NULL && strstr(g_err, "2") != NULL);
        snprintf(t, sizeof(t), "[Interface]\nPrivateKey=%s\nAddress=10.0.0.1/24\n"
                 "ListenPort=443\n"
                 "[Peer]\nPublicKey=%s\nAllowedIPs=10.9.0.0/16\n"
                 "[Peer]\nPublicKey=%s\nAllowedIPs=10.9.0.0/16\n", KEY_A, KEY_B, KEY_B);
        refuses("отказ: один PublicKey у двух пиров", t, XS_ROLE_HUB);
    }
    {
        /* Переполнения — отказ, а не отбрасывание лишнего: пир или префикс, молча не
         * попавший в таблицу, это «настроено и не работает». */
        char t[8192];
        int o = snprintf(t, sizeof(t), "[Interface]\nPrivateKey=%s\nAddress=10.0.0.2/24\n"
                         "[Peer]\nPublicKey=%s\nEndpoint=1.2.3.4:443\nAllowedIPs=", KEY_A, KEY_B);
        for (int i = 0; i <= XS_ALLOWED_MAX; i++)
            o += snprintf(t + o, sizeof(t) - (size_t)o, "%s10.%d.0.0/16", i ? "," : "", i);
        snprintf(t + o, sizeof(t) - (size_t)o, "\n");
        refuses("отказ: префиксов больше предела", t, XS_ROLE_SPOKE);
    }
    {
        /* А ПРЕДЕЛА хватает: полный туннель с исключениями — это одна длинная строка на
         * несколько десятков префиксов, и раньше её резал не счётчик, а буфер строки в 512
         * байт. Здесь сорок префиксов одной строкой (под семьсот символов) обязаны пройти. */
        char t[8192];
        int o = snprintf(t, sizeof(t), "[Interface]\nPrivateKey=%s\nAddress=10.0.0.2/24\n"
                         "[Peer]\nPublicKey=%s\nEndpoint=1.2.3.4:443\nAllowedIPs=", KEY_A, KEY_B);
        for (int i = 0; i < 40; i++)
            o += snprintf(t + o, sizeof(t) - (size_t)o, "%s%d.0.0.0/8", i ? "," : "", i + 1);
        snprintf(t + o, sizeof(t) - (size_t)o, "\n");
        check("длинный список исключений принят", 0, parse(t, XS_ROLE_SPOKE));
        check("длинный список: все сорок префиксов на месте", 40, (long)g_c.peer[0].allowed_n);
    }
    {
        char t[16384];
        int o = snprintf(t, sizeof(t), "[Interface]\nPrivateKey=%s\nAddress=10.0.0.1/24\n"
                         "ListenPort=443\n", KEY_A);
        for (int i = 0; i <= XS_PEERS_MAX; i++) {
            uint8_t k[32];
            char b[XS_KEY_B64 + 1];
            memset(k, 0, sizeof(k));
            k[0] = (uint8_t)(i + 1);
            k[1] = (uint8_t)(i + 2);
            xs_key_encode(k, b);
            o += snprintf(t + o, sizeof(t) - (size_t)o,
                          "[Peer]\nPublicKey=%s\nAllowedIPs=10.%d.0.0/16\n", b, i + 20);
        }
        refuses("отказ: пиров больше предела", t, XS_ROLE_HUB);
    }
    {
        /* Файл больше предела отвергается целиком, а не читается частично: половина
         * конфигурации это конфигурация, которой никто не писал. */
        static char big[XS_CONF_MAX + 64];
        memset(big, '\n', sizeof(big) - 1);
        big[sizeof(big) - 1] = '\0';
        refuses("отказ: файл больше предела", big, XS_ROLE_SPOKE);
    }

    printf("\n%s\n", fails ? "ЕСТЬ ПРОВАЛЫ" : "все проверки прошли");
    return fails ? 1 : 0;
}
