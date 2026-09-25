#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <errno.h>
#include <unistd.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <linux/netlink.h>
#include <linux/rtnetlink.h>
#include <poll.h>
#include <signal.h>
#include <fcntl.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/time.h>
#include <time.h>

#include "spec.h"
#include "awg.h"
#include "hwid.h"
#include "obfs.h"
#include "cli.h"
#include "srs.h"
#include "ctl.h"
#include "generate.h"
#include "daemon.h"

/* КАРТА ПОДМЕНЫ fake→real ЗАСЕВАЕТСЯ ПРЯМО В НАБОРЕ ПРАВИЛ — из файла состояния резолвера
 * (<state-dir>/fakeip.state, строки «домен\tподдельный\tнастоящий»), а не остаётся пустой до
 * перезапуска dnsd.
 *
 * ЗАЧЕМ. apply пересобирает таблицу целиком, и карта на мгновение исчезала вместе с ней; dnsd
 * восстанавливал её только при своём перезапуске, секундой позже. Запрос, пришедший в это окно,
 * не мог добавить подмену (карты нет), и dnsd по правилу fail-open отдавал клиенту НАСТОЯЩИЙ
 * адрес: сайт, который человек велел вести в туннель, уходил напрямую, а клиент запоминал этот
 * адрес на весь TTL записи. Снято с живого роутера: после «Применить» посреди просмотра YouTube
 * узел googlevideo остался в состоянии без настоящего адреса, а ролики не открывались до
 * перезапуска браузера — уже при исправном туннеле. С засеянной картой окна нет: пакеты к
 * поддельным адресам переводятся тем же набором правил, который их и метит.
 *
 * Только строки с настоящим адресом: без него подменять нечего, и dnsd такую запись тоже не
 * восстанавливает. Повтор поддельного адреса пропускается — nft отвергает набор с двойным
 * ключом целиком, а в файле повторы законны (первая раздача побеждает, как у dnsd). Файла нет —
 * карта пустая, как и раньше: так на роутере, где резолвер ещё ничего не раздал. */
static void emit_fakeip_elements(FILE *f) {
    char path[512];
    if (snprintf(path, sizeof(path), "%s/fakeip.state", g_state_dir) >= (int)sizeof(path)) return;
    FILE *s = fopen(path, "r");
    if (!s) return;
    static uint8_t seen[131072 / 8];       /* 198.18.0.0/15 — бит на адрес */
    memset(seen, 0, sizeof(seen));
    char line[1024];
    int n = 0;
    while (fgets(line, sizeof(line), s)) {
        char *t1 = strchr(line, '\t');
        if (!t1) continue;
        char *fake = t1 + 1;
        char *t2 = strchr(fake, '\t');
        if (!t2) continue;
        *t2 = '\0';
        char *real = t2 + 1;
        char *end = real + strcspn(real, "\t\r\n");
        *end = '\0';
        struct in_addr a, b;
        if (inet_aton(fake, &a) == 0 || inet_aton(real, &b) == 0 || b.s_addr == 0) continue;
        uint32_t fh = ntohl(a.s_addr);
        if ((fh & 0xfffe0000u) != 0xc6120000u) continue;   /* вне 198.18.0.0/15 — не наше */
        uint32_t idx = fh - 0xc6120000u;
        if (seen[idx >> 3] & (uint8_t)(1u << (idx & 7))) continue;
        seen[idx >> 3] |= (uint8_t)(1u << (idx & 7));
        /* В набор едет РАЗОБРАННЫЙ адрес, а не байты строки. inet_aton принимает не только
         * точечную запись: «0xc6120009», «3323068425» и «198.18.9» — то же самое 198.18.0.9,
         * и проверку диапазона выше такая строка проходит честно. А nft такого ключа не
         * понимает и отвергает набор ЦЕЛИКОМ (`nft -f` атомарен) — то есть одна нетипичная
         * строка в файле состояния оставила бы роутер вообще без правил: ни маршрутизации,
         * ни подмены, ни меток. Раз адрес уже разобран, печатать надо его, а не то, из чего
         * он разобран.
         *
         * Два своих буфера, а не inet_ntoa дважды: inet_ntoa отдаёт статический буфер, и
         * второй вызов в том же fprintf перезаписал бы результат первого. */
        char fs[INET_ADDRSTRLEN], rs[INET_ADDRSTRLEN];
        if (!inet_ntop(AF_INET, &a, fs, sizeof(fs)) ||
            !inet_ntop(AF_INET, &b, rs, sizeof(rs))) continue;
        fprintf(f, n ? ",\n            %s : %s" : "        elements = { %s : %s", fs, rs);
        n++;
    }
    if (n) fprintf(f, " }\n");
    fclose(s);
}


/* «Кто» одной или двумя проверками.
 *
 * Адреса и MAC-и уходят РАЗНЫМИ выражениями, объединёнными по И... нет — по ИЛИ быть не может:
 * nft не умеет «или» внутри правила. Поэтому смешивать их в одном правиле нельзя, и это
 * проверяется при загрузке спеки: правило либо про адреса, либо про MAC-и. Молча взять только
 * половину значило бы, что часть устройств правило не касается, и понять это было бы нечем. */
static void emit_who(FILE *f, const struct group *g, int reverse) {
    if (!g->from_n) return;
    int mac = is_mac(g->from[0]);
    if (mac) fprintf(f, "ether %s { ", reverse ? "daddr" : "saddr");
    else fprintf(f, "ip %s { ", reverse ? "daddr" : "saddr");
    for (size_t i = 0; i < g->from_n; i++) fprintf(f, "%s%s", i ? ", " : "", g->from[i]);
    fprintf(f, " } ");
}

/* «Кто» по устройству: клиенты, которых мы узнаём по интерфейсу, а не по адресу.
 *
 * ИМЕНЕМ (`iifname`), А НЕ НОМЕРОМ (`iif`). Разница не косметическая: `iif` ядро разрешает
 * в индекс в момент ЗАГРУЗКИ правила и на отсутствующем устройстве отказывает всей
 * транзакции. А tailscale0 и zt* появляются позже сети и пропадают при перезапуске своего
 * демона — то есть на `iif` перезагрузка роутера оставляла бы человека вообще без правил.
 * `iifname` сверяется по имени в момент прохода пакета: правило спокойно грузится на
 * отсутствующее устройство и начинает работать само, когда оно поднимется.
 *
 * Один элемент печатается без фигурных скобок: так вывод `--dry-run` у обычной
 * конфигурации остаётся тем же текстом, что и раньше, и nft печатает его так же. */
static void emit_ifs(FILE *f, int reverse) {
    const char *kw = reverse ? "oifname" : "iifname";
    if (g_lan_dev_n == 1) { fprintf(f, "%s \"%s\" ", kw, g_lan_dev[0]); return; }
    fprintf(f, "%s { ", kw);
    for (size_t i = 0; i < g_lan_dev_n; i++)
        fprintf(f, "%s\"%s\"", i ? ", " : "", g_lan_dev[i]);
    fprintf(f, " } ");
}

/* «Кто» у правила группы. Способ ровно один, и это принципиально: адреса ИЛИ устройства, а
 * не то и другое сразу.
 *
 * ПОЧЕМУ НЕ ОБА. Соблазн был — добавлять правило по устройствам вдобавок к адресному, чтобы
 * перечень интерфейсов действовал всегда. Но `from_default` пишут в спеке, чтобы клиентов
 * ОГРАНИЧИТЬ: гостевая подсеть на том же мосту нарочно остаётся за пределами списка. Второе
 * правило по `iifname "br-lan"` молча забрало бы и её — то есть добавление интерфейса меняло
 * бы смысл давно написанной строки. Поэтому явный `from_default` значит ровно то, что
 * написано, а противоречие «клиенты описаны и подсетями, и несколькими устройствами»
 * отвергается при загрузке спеки (см. load_spec), а не разрешается движком на свой вкус. */
static void emit_from(FILE *f, const struct group *g) {
    if (g->from_n) emit_who(f, g, 0); else emit_ifs(f, 0);
}

/* То же «кто», но на встречном пути: там наш клиент — это ПОЛУЧАТЕЛЬ. */
static void emit_to(FILE *f, const struct group *g) {
    if (g->from_n) emit_who(f, g, 1); else emit_ifs(f, 1);
}


#ifdef STEER_ANDROID
/* ---- DNS приложений телефона — к резолверу движка -------------------------------------
 *
 * Доменный канал на сам телефон видит только те имена, что спросили через наш резолвер. DNS
 * приложений делает DnsResolver (netd) — сокетом, который он приписывает UID приложения, — к
 * серверам текущей сети; правило ниже заворачивает эти запросы к нам, а резолвер переспрашивает
 * тот же сервер (dnsd --upstream-origdst: адрес берётся из conntrack).
 *
 * ВСЕ приложения, а не только приложения каналов. У DnsResolver общий кэш на сеть: заверни мы
 * только своих, настоящий адрес, полученный чужим приложением первым, достался бы из кэша и
 * своему — мимо набора канала, то есть мимо туннеля. Кроме root: это сам резолвер (его запрос
 * наверх иначе завернулся бы по кругу) и прочие демоны.
 *
 * И перевод поддельных адресов для соединений самого телефона — тот же, что prerouting_dnat
 * делает для раздачи: поддельный адрес из кэша DnsResolver получает любое приложение, и у
 * приложения вне канала соединение должно уйти напрямую к настоящему адресу, а не в никуда.
 *
 * И UDP, и TCP: по TCP приходят переспросы после усечённого ответа (TC=1) и запросы приложений,
 * которые ходят по TCP сразу, — без заворота имя, спрошенное так, прошло бы мимо канала, и
 * соединение ушло бы по настоящему адресу. Резолвер слушает TCP на том же порту и переспрашивает
 * тот же сервер тоже по TCP (см. «DNS по TCP» в dnsd.c).
 *
 * ОБА СЕМЕЙСТВА. Запрос по IPv6 (сервер сети из RDNSS, в том числе link-local) заворачивается
 * так же: резолвер ищет исходное назначение и в AF_INET6 и переспрашивает тот же IPv6-сервер
 * (см. g_origdst в dnsd.c). В современной раскладке это одно правило в inet, в старой — по
 * цепочке nat output в ip и ip6 (emit_local_dns_redirect); на старом ядре без nat в ip6
 * (NFTC_IP6NAT) IPv6-половины нет — там такого правила не поставить, и apply об этом говорит. */

/* Само правило заворота — одно на всех раскладках и семействах (по правилу на протокол).
 *
 * Всех, кроме собственного запроса резолвера наверх (STEER_SELF_MARK) и собственного трафика
 * туннелей (без via — тот же STEER_SELF_MARK, с via — STEER_TUNNEL_BIT, см. ниже): DnsResolver
 * шлёт запросы приложений от root, поэтому по UID отличить нельзя. Метка «сам движок» у переспроса по TCP та же, что по UDP
 * (tcpu_open в dnsd.c).
 *
 * `ct mark set mark` — чтобы резолвер узнал метку сети исходного запроса: на 4.9 принятому сокету
 * метку датаграммы не узнать (SO_RCVMARK — с 5.19), а запись conntrack резолвер и так читает
 * целиком (подробно — у g_up_mark в dnsd.c). У TCP это та же запись conntrack, что ищет резолвер
 * по соединению, и цепочка nat видит её первый пакет (SYN) — метку сокета приложения. Копируется
 * метка ЦЕЛИКОМ, и это не расходится с тем, как метку соединения пишет сам движок: разметка
 * каналов (output_mark, раньше по приоритету) тоже делает `ct mark set mark` целиком
 * (out_needs_ctmark верно для всякого выхода канала телефона: tgws там спека отвергает), то есть к
 * этому правилу пакет приходит с той же меткой, что уже лежит в ct mark, и перезапись ничего не
 * меняет. У запроса, который канал не пометил, ct mark получает fwmark netd — поле движка там
 * нулевое, и читателям ct mark движка (сравнения `ct mark and МАСКА == метка`) это ничего не
 * значит. Смешать метку пакета со старой ct mark (`ct mark and … or mark`) на 4.9 нельзя вовсе:
 * там нет bitwise двух регистров. Цепочка nat видит только первый пакет соединения — ровно тот
 * момент, когда метку и надо запомнить. */
/* Туннели через via — тоже мимо заворота. Сокет наверх такого туннеля несёт метку ЦЕЛИ, а не
 * «сам движок», и у сервера на 53-м порту (UDP или TCP — их и выбирают, чтобы пройти там, где
 * режут остальное) заворот забрал бы соединение туннеля к нашему резолверу: туннель не встал бы
 * вовсе. Пропуск — по биту STEER_TUNNEL_BIT, который такой сокет несёт рядом с меткой цели (почему
 * бит, а не UID помощника, — у определения в spec.h). Условие пишется только в спеке с via: у
 * остальных текст правил остаётся прежним побайтно, а бита там не ставит никто. */
static void emit_local_dns_redirect(FILE *f) {
    char tun[64] = "";
    if (has_via())
        snprintf(tun, sizeof(tun), "meta mark and 0x%08x == 0x00000000 ", STEER_TUNNEL_BIT);
    fprintf(f, "        meta mark and 0x%08x != 0x%08x %sudp dport 53 ct mark set mark counter "
               "redirect to :%d comment \"steer-dns-local\"\n",
            STEER_MARK_MASK, STEER_SELF_MARK, tun, DNS_PORT);
    fprintf(f, "        meta mark and 0x%08x != 0x%08x %stcp dport 53 ct mark set mark counter "
               "redirect to :%d comment \"steer-dns-local-tcp\"\n",
            STEER_MARK_MASK, STEER_SELF_MARK, tun, DNS_PORT);
}

static void emit_local_dns(FILE *f, const char *dnat_kw) {
    emit_local_dns_redirect(f);
    if (has_fakeip())
        fprintf(f, "        ip daddr 198.18.0.0/15 counter %s to ip daddr map @fakeip "
                   "comment \"steer-fakeip-local\"\n", dnat_kw);
}

/* «Кто» у группы на сам телефон: владелец сокета. "self" — все приложения (UID от
 * STEER_APP_UID_MIN; почему не демоны — у from_is_local); "uid:N[-M]" — перечисленные. У
 * пакета без сокета (RST и ICMP, которые ядро шлёт само) владельца нет, и skuid не совпадает
 * ни с чем — такие пакеты идут обычным путём.
 *
 * `ct direction original` — только соединения, которые приложение ОТКРЫЛО само. Ответы на
 * входящие (беспроводной adb, сервер в приложении) обязаны уйти тем же путём, каким пришёл
 * запрос, а не в туннель. */
static void emit_local_who(FILE *f, const struct group *g) {
    if (!strcmp(g->from[0], "self")) {
        fprintf(f, "meta skuid >= %u ct direction original ", STEER_APP_UID_MIN);
        return;
    }
    int one = g->from_n == 1 && !strchr(g->from[0], '-');
    fprintf(f, one ? "meta skuid " : "meta skuid { ");
    for (size_t i = 0; i < g->from_n; i++) {
        unsigned lo, hi;
        if (from_uid_range(g->from[i], &lo, &hi) != 0)
            die("группа %s: негодный UID", g->name);   /* спека это уже отвергла */
        if (lo == hi) fprintf(f, "%s%u", i ? ", " : "", lo);
        else fprintf(f, "%s%u-%u", i ? ", " : "", lo, hi);
    }
    fprintf(f, one ? " ct direction original " : " } ct direction original ");
}

#endif


/* «Чем и куда именно»: сужение канала по протоколу и портам назначения (схема 2).
 *
 * ПОЧЕМУ `meta l4proto` ПЛЮС `th dport`, А НЕ `tcp dport`/`udp dport`. Две причины, и
 * первая решающая.
 *
 * Первая: nft не умеет «или» внутри правила. Слово `tcp dport` само тянет за собой
 * зависимость «протокол tcp», поэтому «и TCP, и UDP на этих портах» им не записать — пришлось
 * бы ставить ДВА правила на один канал. А правило у канала одно не для красоты: на нём висит
 * счётчик (второе правило разделило бы объёмы канала на две половины, и ни одна не была бы
 * ответом на «сколько ушло»), и на нём же держится «первое совпадение выигрывает» — порядок,
 * который человек читает прямо по спеке. `meta l4proto { tcp, udp }` — это МНОЖЕСТВО, а не
 * «или», и оно укладывается в то же одно правило.
 *
 * Вторая: одна форма и для одного протокола, и для двух. Ветка «а если протокол один,
 * печатаем по-другому» — это второй путь, по которому пойдёт ровно половина каналов, и
 * расходиться этим двум путям негде, кроме опыта на живом роутере.
 *
 * И ЭТО НЕ КОМПРОМИСС: разницы с «правильной» формой нет никакой. Проверено загрузкой в
 * ядро (nftables 1.0.9): `meta l4proto udp th dport { … }` ядро печатает обратно как
 * `udp dport { … }`, а `meta l4proto tcp th dport 1-1024` — как `tcp dport 1-1024`. То
 * есть специальная форма и есть наша, просто записанная короче, — а множество из двух
 * протоколов ядро оставляет как написано, потому что короче его не записать.
 *
 * ЗАЧЕМ ПРОТОКОЛ ОБЯЗАТЕЛЕН ПЕРЕД ПОРТОМ. `th` — это смещение в транспортном заголовке, и
 * никакой проверки протокола в нём нет. У icmp, esp, gre по этому смещению лежат чужие байты,
 * и `th dport 50000-65535` совпал бы на них — то есть канал забирал бы пакеты, у которых
 * портов не бывает вовсе. Поэтому при заданных портах протокол пинится ВСЕГДА, и когда
 * человек его не назвал — множеством `{ tcp, udp }`, которое здесь работает носителем для
 * чтения порта, а не сужением по протоколу.
 *
 * СЕМЕЙСТВА АДРЕСОВ. Таблица `inet` несёт и IPv4, и IPv6; `meta l4proto` и `th` смотрят на
 * транспортный уровень и одинаково верны для обоих — в отличие от `ip saddr`, которому нужен
 * близнец `ip6 saddr` (см. emit_ifs и правило DNS). Пометки семейства здесь поэтому нет.
 *
 * ПОРЯДОК В ПРАВИЛЕ: сужение стоит ПЕРЕД поиском по набору адресов. Сравнение одного байта
 * протокола дешевле поиска в наборе на 19 тысяч префиксов, и для канала «только UDP» оно
 * отбрасывает весь TCP роутера до поиска, а не после. На пакет это один и тот же путь, но
 * пакетов, которым канал не подходит, всегда больше.
 *
 * reverse — встречный путь: там наш клиент получатель, а порт сервера ИСХОДЯЩИЙ. */
static void emit_l4(FILE *f, const struct l4match *m, int reverse) {
    if (l4match_empty(m)) return;
    if (m->proto == CH_PROTO_TCP)      fprintf(f, "meta l4proto tcp ");
    else if (m->proto == CH_PROTO_UDP) fprintf(f, "meta l4proto udp ");
    else                               fprintf(f, "meta l4proto { tcp, udp } ");
    if (!m->ports_n) return;
    fprintf(f, "th %s ", reverse ? "sport" : "dport");
    /* Один диапазон печатается без фигурных скобок — ровно как одно устройство в emit_ifs, и
     * по той же причине: так это печатает сам nft, и вывод `--dry-run` совпадает с тем, что
     * человек потом увидит в `nft list`. */
    int one = m->ports_n == 1;
    if (!one) fprintf(f, "{ ");
    for (size_t i = 0; i < m->ports_n; i++) {
        if (i) fprintf(f, ", ");
        if (m->ports[i].lo == m->ports[i].hi) fprintf(f, "%u", m->ports[i].lo);
        else fprintf(f, "%u-%u", m->ports[i].lo, m->ports[i].hi);
    }
    fprintf(f, one ? " " : " } ");
}

/* Сужение словами, для explain. Отдельно от emit_l4, потому что там формат nftables, а
 * здесь фраза человеку; печатать в ответ человеку синтаксис ядра значило бы объяснять
 * настройку языком, которого он не выбирал.
 *
 * Дописывается КУСКАМИ С ПРОВЕРКОЙ МЕСТА, а не сложением возвратов snprintf, и это не
 * педантизм: snprintf возвращает длину, которая ПОЛУЧИЛАСЬ БЫ, а не записанную. Сложение
 * таких возвратов уводит смещение за буфер, и следующий `n - k` уходит в подпол size_t,
 * превращая ограничение длины в «сколько угодно». Шестнадцать диапазонов по «50000-65535» —
 * это 217 байт, то есть предел MAX_PORTS переполняет любой разумный буфер, и случай не
 * гипотетический. Не влезло — обрываем на границе куска: обрезанный перечень портов в
 * ПОЯСНЕНИИ безобиден, порванная память — нет. */
void l4_describe(const struct l4match *m, char *dst, size_t n) {
    if (!n) return;
    size_t k = 0;
    dst[0] = '\0';
    char piece[32];
    snprintf(piece, sizeof(piece), "%s",
             m->proto == CH_PROTO_TCP ? "tcp" :
             m->proto == CH_PROTO_UDP ? "udp" : "tcp и udp");
    for (size_t i = 0; i <= m->ports_n; i++) {
        if (i) {
            if (m->ports[i - 1].lo == m->ports[i - 1].hi)
                snprintf(piece, sizeof(piece), "%s%u", i > 1 ? ", " : " ",
                         m->ports[i - 1].lo);
            else
                snprintf(piece, sizeof(piece), "%s%u-%u", i > 1 ? ", " : " ",
                         m->ports[i - 1].lo, m->ports[i - 1].hi);
        }
        size_t len = strlen(piece);
        if (k + len + 1 > n) return;
        memcpy(dst + k, piece, len);
        k += len;
        dst[k] = '\0';
    }
}

/* Elements come straight from the list files: the fitter (steer-aggregate) has
 * already decided what fits, and re-parsing them here would only add a second place
 * for the two to disagree. */

static size_t emit_elements(FILE *f, const char *path, size_t already) {
    FILE *in = fopen(path, "r");
    /* Не die: читаемость всех файлов уже проверена (check_address_lists), и попасть сюда
     * можно только гонкой — список удалили между проверкой и генерацией. Ронять из-за неё
     * весь набор правил незачем: пропадут адреса одного списка, и про это будет сказано. */
    if (!in) {
        fprintf(stderr, LOG_W "%s: список исчез во время сборки набора правил\n", path);
        return 0;
    }
    /* 512, а не 128: строка длиннее просто обрезалась бы посередине, и в набор уехал бы
     * обломок адреса — то есть тихо не тот адрес. */
    char line[512];
    size_t n = already;
    while (fgets(line, sizeof(line), in)) {
        char *nl = strpbrk(line, "\r\n");
        if (nl) *nl = '\0';
        char *p = line;
        while (*p == ' ' || *p == '\t') p++;
        if (!*p || *p == '#' || *p == ';') continue;
        /* Не-адреса пропускаем молча: про них уже сказал check_address_lists, а nft на
         * них отвергает ВЕСЬ набор, а не одну строку. */
        if (!spec_line_is_addr(p)) continue;
        /* fputs, а не fprintf: на списке в сотни тысяч элементов разбор
         * форматной строки на каждый — это заметная доля времени apply. */
        if (n) fputs(", ", f);
        fputs(p, f);
        n++;
    }
    fclose(in);
    return n - already;
}

/* ---- перенос счётчиков через apply ------------------------------------------
 *
 * `apply` заменяет таблицу новой одной транзакцией, а счётчики живут в правилах —
 * значит каждый apply обнулял их. Само по себе это выглядело безобидно, но обновление списков
 * из splify2 вызывает apply по расписанию, раз в сутки в пять утра. То есть объёмы в
 * интерфейсе всегда были «с пяти утра», нигде об этом не сказано, и вопрос «сколько ушло за
 * сутки» ответа не имел. Замер: 4 090 141 байт до apply, 0 после.
 *
 * Поэтому перед генерацией читаем то, что накопилось, и вписываем в новые правила: nft
 * принимает `counter packets N bytes M` на входе — ровно в том виде, в каком сам печатает.
 *
 * Переносим ПО ИМЕНИ КАНАЛА, а не по номеру правила: правила перетасовываются при любой
 * правке спеки, и перенос по позиции приписал бы чужой трафик. Канал, которого в новой спеке
 * нет, свой счётчик теряет — это и правильно, его больше не существует.
 */
#define CTR_MAX MAX_CHANNELS
struct ctr { char name[32]; unsigned long pkts, bytes; };
static struct ctr g_ctr_up[CTR_MAX], g_ctr_down[CTR_MAX];
static size_t g_ctr_up_n, g_ctr_down_n;

/* Разбор вывода nft — ОДИН на apply и status. Раздельные разошлись бы в понимании одного и
 * того же текста, а расхождение здесь означало бы, что перенесённое и показанное — разные
 * числа. */
void counters_load(void) {
    g_ctr_up_n = g_ctr_down_n = 0;
    /* Обе цепочки за один вызов: раздельные popen дали бы счётчики, снятые в разные моменты,
     * и «отдано больше, чем скачано» на глазах у человека объяснялось бы не маршрутизацией,
     * а нашей ленью. */
    /* Таблица — своя у каждой сборки (nft_table): у мини-сборки моста это inet stgws, и с
     * жёстким «inet steer» её счётчики через apply не переносились. */
    char cmd[256];
    snprintf(cmd, sizeof(cmd),
             "nft -a list chain inet %s prerouting_mark 2>/dev/null; "
             "nft -a list chain inet %s postrouting_down 2>/dev/null", nft_table(), nft_table());
    FILE *nft = popen(cmd, "r");
    if (!nft) return;
    char line[1024];
    while (fgets(line, sizeof(line), nft)) {
        /* Встречный вид проверяется первым: «steer:» нашлось бы и внутри «steer-down:». */
        int down = 0;
        char *c = strstr(line, "comment \"steer-down:");
        if (c) { c += strlen("comment \"steer-down:"); down = 1; }
        else {
            c = strstr(line, "comment \"steer:");
            if (!c) continue;
            c += strlen("comment \"steer:");
        }
        char *e = strchr(c, '"');
        if (!e) continue;
        *e = '\0';
        unsigned long p = 0, b = 0;
        char *pc = strstr(line, "packets ");
        if (pc) sscanf(pc, "packets %lu bytes %lu", &p, &b);
        struct ctr *arr = down ? g_ctr_down : g_ctr_up;
        size_t *n = down ? &g_ctr_down_n : &g_ctr_up_n;
        /* Одно имя — одно число. В современной раскладке имена в цепочке уникальны и эта
         * ветка не срабатывает; в старой у доменной группы с префиксами правил два (по одному
         * на половину набора, см. generate), и объём канала — их сумма. */
        size_t k = 0;
        while (k < *n && strcmp(arr[k].name, c) != 0) k++;
        if (k < *n) {
            arr[k].pkts += p;
            arr[k].bytes += b;
            continue;
        }
        if (*n < CTR_MAX) {
            snprintf(arr[*n].name, sizeof(arr[*n].name), "%s", c);
            arr[*n].pkts = p;
            arr[*n].bytes = b;
            (*n)++;
        }
    }
    pclose(nft);
}

/* Найти прежнее значение. -1 — канала в ядре не было (первый apply или новый канал). */
int counter_find(const char *name, int down, unsigned long *p, unsigned long *b) {
    const struct ctr *arr = down ? g_ctr_down : g_ctr_up;
    size_t n = down ? g_ctr_down_n : g_ctr_up_n;
    for (size_t i = 0; i < n; i++)
        if (!strcmp(arr[i].name, name)) { *p = arr[i].pkts; *b = arr[i].bytes; return 0; }
    return -1;
}

/* `counter` с прежним значением, если оно есть. Нули печатаем коротким `counter`: так вывод
 * `--dry-run` на чистой машине остаётся тем же текстом, что и раньше. */
static void emit_counter(FILE *f, const char *name, int down) {
    unsigned long p = 0, b = 0;
    if (counter_find(name, down, &p, &b) == 0 && (p || b))
        fprintf(f, "counter packets %lu bytes %lu ", p, b);
    else
        fprintf(f, "counter ");
}

/* РАСКЛАДКА НАБОРА ПРАВИЛ ЭТОГО ЗАПУСКА — флаги NFTC_* из nft_compat (spec.h). Ставит cmd_apply
 * перед генерацией; ноль — современное ядро, и тогда текст печатается ровно тот же, что до
 * появления старой раскладки, байт в байт: ветки legacy стоят рядом с прежними строками, а то,
 * что печатают обе раскладки, перенесено в функции дословно. На этом держатся все стенды
 * компилятора и то, что роутеры после обновления получают тот же набор правил.
 *
 * Что меняется в старой раскладке — коротко; доводы у каждого места ниже:
 *   - таблиц становится две-три: `inet` (наборы, разметка, счётчики, очереди — всё, что
 *     filter), `ip` (карта fakeip и ОДНА цепочка nat на prerouting) и `ip6` (заворот DNS по
 *     IPv6, если ядро умеет nat в ip6). Наборы между таблицами не видны, поэтому карта fakeip
 *     живёт там же, где правило dnat, — в ip;
 *   - доменный набор делится надвое: интервальный без сроков (<имя>_n, префиксы из списков) и
 *     hash со сроками (<имя>, туда пишет резолвер); правило канала повторяется на каждую
 *     половину;
 *   - notrack — только если ядро его знает (NFTC_NOTRACK), `exthdr … exists` — заменён. */
int g_nftc;
#define NFT_LEGACY (g_nftc & NFTC_LEGACY)

/* Есть ли у доменной группы статическая половина в старой раскладке: адресные строки в её
 * списках. Та же проверка, что решает про строку elements в современном наборе. */
static int legacy_has_static(const struct group *g) {
    return NFT_LEGACY && g->domains && g->files_n && g->addrs;
}

/* То же для читателей ядра — diag и explain. Они списков не разбирают (addrs считает только
 * check_address_lists в apply), поэтому спрашивают вторую половину у всякой доменной группы с
 * адресными списками; нет её в ядре — ответ «набора нет», и он просто не прибавляется. */
int legacy_may_have_static(const struct group *g) {
    return NFT_LEGACY && g->domains && g->files_n;
}

/* Интервальный набор с элементами из адресных списков группы — статическая половина доменного
 * набора в старой раскладке. Тот же текст, что у адресного набора в generate. */
static void emit_static_set(FILE *f, const struct group *g, const char *name) {
    fprintf(f, "    set %s {\n        type ipv4_addr\n"
               "        flags interval\n        auto-merge\n", name);
    if (g->files_n && g->addrs) {
        fprintf(f, "        elements = { ");
        size_t written = 0;
        for (size_t k = 0; k < g->files_n; k++)
            written += emit_elements(f, g->files[k], written);
        fprintf(f, " }\n");
    }
    fprintf(f, "    }\n");
}

/* Цепочка для traceroute_hops — объяснение у места вызова в generate. Функцией, потому что
 * печатают её две раскладки. */
static void emit_traceroute_raw(FILE *f) {
    fprintf(f, "    chain prerouting_raw {\n"
               "        type filter hook prerouting priority raw; policy accept;\n"
               "        meta l4proto icmp icmp type time-exceeded counter notrack "
               "comment \"steer:traceroute-hops\"\n"
               "    }\n");
}

/* Правила перехвата Telegram — объяснение у цепочки tgws_redirect в generate. Функцией по
 * той же причине: в старой раскладке они живут в общей цепочке nat таблицы ip. */
static void emit_tgws_rules(FILE *f) {
    for (size_t i = 0; i < g_out_n; i++) {
        struct output *o = &g_out[i];
        if (o->kind != OUT_TGWS) continue;
        fprintf(f, "        meta mark and 0x%08x == 0x%08x tcp dport { 443, 80, 5222 } "
                   "counter redirect to :%d comment \"steer:tgws:%s\"\n",
                STEER_MARK_MASK, o->mark, out_tgws_port(o), o->name);
    }
}

/* Какие таблицы, кроме inet, есть в старой раскладке. Спрашивают двое — генератор и шапка
 * файла в cmd_apply (добавить-и-удалить каждую таблицу раскладки одной транзакцией), — и
 * ответ у них обязан совпадать, иначе `delete table` встретил бы таблицу, которой файл не
 * создаёт, или наоборот. */
int legacy_has_ip(void) {
    if (!NFT_LEGACY) return 0;
    if (has_tgws()) return 1;
#ifdef STEER_TGWS
    return 0;
#else
    return 1;                       /* заворот DNS стоит всегда — см. prerouting_dns */
#endif
}

int legacy_has_ip6(void) {
#ifdef STEER_TGWS
    return 0;
#else
    return NFT_LEGACY && (g_nftc & NFTC_IP6NAT);
#endif
}

#ifdef STEER_ANDROID
/* ---- каналы на сам телефон: разметка на выходе ------------------------------------
 *
 * Тот же приём, что prerouting_mark для раздачи, но на хуке output: «первое совпадение
 * решает», одно правило на группу (два — на две половины доменного набора старой раскладки),
 * метка — наши биты с маской, метка соединения — как там.
 *
 * Тип цепочки зависит от раскладки. В современной (ядро с nat в inet) это route прямо в
 * inet, где и наборы: смена метки в ней сама заставляет ядро искать маршрут заново. В старой
 * route в inet нет, поэтому здесь filter, а к метке добавляется STEER_REROUTE_BIT — его
 * снимает цепочка route в таблице ip (generate_legacy_tail), и маршрут пересматривается там
 * (подробно — у STEER_REROUTE_BIT в spec.h).
 *
 * IPv6. Наборы каналов — IPv4, и правило с набором IPv6 не касается. Но у группы «весь
 * трафик» набора нет, и её IPv6 ушёл бы мимо туннеля: маршруты выхода движок ставит только
 * для IPv4. Поэтому такой группе IPv6 отвечается отказом — приложения переходят на IPv4 (так
 * устроен выбор адреса у любого клиента с двумя стеками), и ничего не утекает напрямую. */
static void emit_output_mark(FILE *f) {
    fprintf(f, "\n    chain output_mark {\n"
               "        type %s hook output priority mangle + 1; policy accept;\n",
            NFT_LEGACY ? "filter" : "route");
    for (size_t i = 0; i < g_grp_n; i++) {
        struct group *g = &g_grp[i];
        if (!group_is_local(g)) continue;
        struct output *o = out_by_name(g->out);
        if (!o) die("channel group %s points at a missing output", g->name);
        if (g->all && out_needs_mark(o)) {
            /* С тем же сужением по протоколу и портам, что и канал: канал «UDP 50000-65535»
             * не вправе отнимать у приложения весь IPv6. Своя сеть (петля, link-local, ULA,
             * мультикаст) — не наружу и не мимо туннеля, её не трогаем. */
            fprintf(f, "        ");
            emit_local_who(f, g);
            fprintf(f, "meta nfproto ipv6 ");
            emit_l4(f, g->l4, 0);
            fprintf(f, "oifname != \"lo\" ip6 daddr != { fe80::/10, fc00::/7, ff00::/8 } "
                       "counter reject comment \"steer-v6:%s\"\n", g->name);
        }
        int halves = legacy_has_static(g) ? 2 : 1;
        for (int h = 0; h < halves; h++) {
            char sn[80];
            const char *set = g->name;
            if (halves == 2 && h == 0) { nft_static_set_name(sn, sizeof(sn), g->name); set = sn; }
            fprintf(f, "        ");
            emit_local_who(f, g);
            /* «Весь трафик» — это интернет, а не своя сеть: принтер, NAS и Chromecast в Wi-Fi
             * через туннель не видны. Только IPv4 — IPv6 такой группы отвергнут строкой выше. */
            if (g->all)
                fprintf(f, "meta nfproto ipv4 ip daddr != { 10.0.0.0/8, 127.0.0.0/8, "
                           "169.254.0.0/16, 172.16.0.0/12, 192.168.0.0/16, 224.0.0.0/4, "
                           "255.255.255.255 } ");
            emit_l4(f, g->l4, 0);
            if (g->files_n || g->domains || g->emptied) fprintf(f, "ip daddr @%s ", set);
            /* Бит перемаршрутизации ставится ПОСЛЕ метки соединения: в conntrack ему не место,
             * он живёт на пакете до цепочки route в таблице ip. */
            if (out_needs_mark(o))
            {
                fprintf(f, "meta mark set mark and 0x%08x or 0x%08x %s",
                        ~STEER_MARK_MASK, o->mark,
                        out_needs_ctmark(o) ? "ct mark set mark " : "");
                if (NFT_LEGACY) fprintf(f, "meta mark set mark or 0x%08x ", STEER_REROUTE_BIT);
            }
            if (h == 0) emit_counter(f, g->name, 0);
            else fprintf(f, "counter ");
            fprintf(f, "return comment \"steer:%s\"\n", g->name);
        }
    }
    fprintf(f, "    }\n");
}

#endif

/* ХВОСТ НАБОРА ПРАВИЛ В СТАРОЙ РАСКЛАДКЕ: закрыть inet и собрать nat в ip/ip6.
 *
 * ПОЧЕМУ ОДНА ЦЕПОЧКА NAT, а не три, как в современной раскладке (prerouting_dns,
 * prerouting_dnat, tgws_redirect). До 4.18 каждая базовая цепочка nat — отдельный хук, и
 * первый из них, где ни одно правило не совпало, ставит новому соединению «пустую»
 * трансляцию (nf_nat_alloc_null_binding в nf_nat_ipv4_fn); остальные хуки видят
 * nf_nat_initialized и своих правил уже не проверяют. Три цепочки на 4.9 значили бы, что для
 * запроса DNS работает только первая, а для поддельного адреса — ни одна, если первой стоит
 * цепочка DNS. В одной цепочке правила проверяются по очереди и первое совпавшее ставит
 * трансляцию — ровно то, что делают три цепочки на современном ядре (там после первой
 * состоявшейся трансляции остальные цепочки тоже пропускаются). Порядок правил повторяет
 * порядок цепочек: DNS и fakeip на dstnat в порядке регистрации, мост на dstnat + 1.
 *
 * ПОЧЕМУ dstnat - 1. Тот же механизм «пустой трансляции» действует между нами и таблицей
 * nat iptables: её хук на том же приоритете -100 зарегистрирован раньше (при загрузке), и
 * при равном приоритете идёт первым. На Android iptables nat есть всегда (netd держит там
 * правила раздачи интернета), то есть на -100 наша цепочка не увидела бы ни одного нового
 * соединения: ни заворота DNS, ни fakeip. На -101 первыми идём мы. Цена — обратная: для
 * соединения, которое не забрали мы, «пустую» трансляцию назначения ставим уже мы, и правила
 * PREROUTING в iptables nat до него не доходят. У netd там только пустая цепочка oem_nat_pre,
 * раздача интернета живёт в POSTROUTING, которого мы не касаемся; на прочих старых системах
 * с пробросами портов в iptables apply об этом предупреждает (report_legacy_gaps).
 *
 * Карта fakeip — в той же таблице ip, что и правило dnat: наборы между таблицами не видны.
 * Синтаксис `dnat to` без слова ip: в таблице одного семейства семейство и так известно.
 *
 * ПОЧЕМУ ПУСТАЯ ЦЕПОЧКА postrouting_nat. До 4.18 ядро переписывает адреса только в тех хуках,
 * где зарегистрирована хоть одна цепочка nat, — и обратную трансляцию ответов тоже. Ответ на
 * заворот DNS или на dnat по карте fakeip уходит клиенту через POSTROUTING, и там его адрес
 * источника обязан вернуться к тому, куда клиент спрашивал (1.1.1.1, поддельный 198.18.x.x).
 * Без цепочки на этом хуке ответ ушёл бы с настоящим адресом, и клиент его отбросил бы как
 * чужой. Снято на стенде tools/vm49: правила prerouting срабатывают (счётчики по единице), а
 * SYN-ACK приходит от 10.99.0.1:8080 вместо 198.18.0.0:8080 — пока цепочки нет. На Android её
 * роль и так выполнял бы хук nat iptables, но полагаться на чужую таблицу незачем.
 * Приоритет srcnat + 1, то есть ПОСЛЕ nat iptables (100): пустая цепочка тоже ставит
 * соединению «пустую» трансляцию источника, и окажись она первой — MASQUERADE раздачи
 * интернета у netd больше не сработал бы.
 *
 * ip6 — только заворот DNS, и только если ядро умеет nat в ip6 (NFTC_IP6NAT): без этого вся
 * транзакция отверглась бы из-за одной таблицы. Пустая цепочка postrouting — там же и по той
 * же причине. */
static void generate_legacy_tail(FILE *f) {
    if (has_domains() && g_traceroute_hops && (g_nftc & NFTC_NOTRACK)) emit_traceroute_raw(f);
    fprintf(f, "}\n");
    int fakeip = has_domains() && has_fakeip();
    if (legacy_has_ip()) {
        fprintf(f, "table ip %s {\n", nft_table());
        if (fakeip) {
            fprintf(f, "    map fakeip {\n        type ipv4_addr : ipv4_addr;\n");
            emit_fakeip_elements(f);
            fprintf(f, "    }\n");
        }
        fprintf(f, "    chain prerouting_nat {\n"
                   "        type nat hook prerouting priority dstnat - 1; policy accept;\n");
#ifndef STEER_TGWS
        /* IPv4-половина prerouting_dns: подсети клиентов по адресу, а без подсетей — по
         * устройству. Устройственное правило при заданных подсетях в современной раскладке
         * помечено `meta nfproto ipv6` — здесь оно уезжает в таблицу ip6. */
        for (size_t i = 0; i < g_from_default_n; i++)
            fprintf(f, "        ip saddr %s udp dport 53 counter redirect to :%d\n",
                    g_from_default[i], DNS_PORT);
        if (!g_from_default_n) {
            fprintf(f, "        ");
            emit_ifs(f, 0);
            fprintf(f, "udp dport 53 counter redirect to :%d\n", DNS_PORT);
        }
        /* TCP/53 рядом с UDP/53 — почему, сказано у prerouting_dns в generate. */
        for (size_t i = 0; i < g_from_default_n; i++)
            fprintf(f, "        ip saddr %s tcp dport 53 counter redirect to :%d\n",
                    g_from_default[i], DNS_PORT);
        if (!g_from_default_n) {
            fprintf(f, "        ");
            emit_ifs(f, 0);
            fprintf(f, "tcp dport 53 counter redirect to :%d\n", DNS_PORT);
        }
#endif
        if (fakeip)
            fprintf(f, "        ip daddr 198.18.0.0/15 counter dnat to ip daddr map @fakeip\n");
        emit_tgws_rules(f);
        fprintf(f, "    }\n");
#ifdef STEER_ANDROID
        if (has_local_domains()) {
            fprintf(f, "    chain output_nat {\n"
                       "        type nat hook output priority dstnat - 1; policy accept;\n");
            emit_local_dns(f, "dnat");
            fprintf(f, "    }\n");
        }
        /* Снятие бита перемаршрутизации — см. STEER_REROUTE_BIT в spec.h. mangle + 2: сразу
         * после разметки (output_mark в inet, mangle + 1) и до nat на выходе. */
        if (has_local())
            fprintf(f, "    chain output_reroute {\n"
                       "        type route hook output priority mangle + 2; policy accept;\n"
                       "        meta mark and 0x%08x == 0x%08x meta mark set mark and 0x%08x "
                       "counter comment \"steer-reroute\"\n"
                       "    }\n", STEER_REROUTE_BIT, STEER_REROUTE_BIT, ~STEER_REROUTE_BIT);
#endif
        fprintf(f, "    chain postrouting_nat {\n"
                   "        type nat hook postrouting priority srcnat + 1; policy accept;\n"
                   "    }\n}\n");
    }
    if (legacy_has_ip6()) {
        fprintf(f, "table ip6 %s {\n"
                   "    chain prerouting_nat {\n"
                   "        type nat hook prerouting priority dstnat - 1; policy accept;\n"
                   "        ", nft_table());
        emit_ifs(f, 0);
        fprintf(f, "udp dport 53 counter redirect to :%d\n", DNS_PORT);
        fprintf(f, "        ");
        emit_ifs(f, 0);
        fprintf(f, "tcp dport 53 counter redirect to :%d\n", DNS_PORT);
        fprintf(f, "    }\n");
#ifdef STEER_ANDROID
        /* IPv6-половина заворота DNS приложений (см. emit_local_dns): та же цепочка, что в
         * таблице ip, без fakeip — поддельные адреса только IPv4. */
        if (has_local_domains()) {
            fprintf(f, "    chain output_nat {\n"
                       "        type nat hook output priority dstnat - 1; policy accept;\n");
            emit_local_dns_redirect(f);
            fprintf(f, "    }\n");
        }
#endif
        fprintf(f, "    chain postrouting_nat {\n"
                   "        type nat hook postrouting priority srcnat + 1; policy accept;\n"
                   "    }\n}\n");
    }
}

void generate(FILE *f) {
    fprintf(f, "table inet %s {\n", nft_table());
    for (size_t i = 0; i < g_grp_n; i++) {
        struct group *g = &g_grp[i];
        /* `any`-группе набор не нужен; опустевшей — нужен, иначе её правило потеряет
         * `ip daddr` и станет безусловным (см. поле `emptied`). */
        if (!g->files_n && !g->domains && !g->emptied) continue;
        if (g->domains && NFT_LEGACY) {
            /* СТАРОЕ ЯДРО: интервальный набор со сроками не грузится (у nft_set_rbtree в 4.9
             * нет NFT_SET_TIMEOUT), а одному набору здесь нужно и то и другое — префиксы из
             * списков навсегда и адреса резолвера на TTL. Поэтому набора два.
             *
             * Динамический — hash со сроками, и он сохраняет ИМЯ ГРУППЫ: резолвер вычисляет
             * имя той же group_set_name и пишет туда не зная про раскладку ничего, кроме
             * одного — что интервальной пары там больше нет (см. nft_add_element в dnsd.c).
             * auto-merge здесь не нужен и не принимается: сливать в hash нечего.
             *
             * Статический — интервальный, с суффиксом _n, и только когда в списках группы
             * есть адресные строки: пустой интервальный набор на каждый доменный канал был бы
             * лишним поиском на каждом пакете. */
            fprintf(f, "    set %s {\n        type ipv4_addr\n        flags timeout\n    }\n",
                    g->name);
            if (legacy_has_static(g)) {
                char sn[80];
                nft_static_set_name(sn, sizeof(sn), g->name);
                emit_static_set(f, g, sn);
            }
            continue;
        }
        if (g->domains) {
            /* timeout — из-за резолвера: он кладёт адреса с TTL ответа, и адрес, который CDN
             * перестал отдавать, истекает сам, а не копится вечно.
             *
             * Адресные списки в ТОЙ ЖЕ группе печатаются элементами без timeout, то есть
             * остаются навсегда. Что набор держит и те, и другие — проверено на живом nft, а
             * не выведено: элемент без своего timeout в наборе с этим флагом постоянный. Это
             * и позволяет одному правилу быть про сервис, а не про вид списка. */
            fprintf(f, "    set %s {\n        type ipv4_addr\n"
                       "        flags interval,timeout\n        auto-merge\n", g->name);
            if (g->files_n && g->addrs) {
                fprintf(f, "        elements = { ");
                size_t written = 0;
                for (size_t k = 0; k < g->files_n; k++)
                    written += emit_elements(f, g->files[k], written);
                fprintf(f, " }\n");
            }
            fprintf(f, "    }\n");
        } else {
            /* auto-merge because several lists in one group WILL overlap — an address
             * list and a service list cover the same hosting — and folding duplicates
             * in the kernel is cheaper than rewriting the text. */
            fprintf(f, "    set %s {\n        type ipv4_addr\n"
                       "        flags interval\n        auto-merge\n", g->name);
            /* Пустой набор объявляется БЕЗ строки elements: `elements = {  }` nft не примет,
             * а объявление без элементов — обычное дело (так же начинают жизнь доменные
             * наборы, которые наполняет резолвер). */
            if (g->files_n && g->addrs) {
                fprintf(f, "        elements = { ");
                size_t written = 0;
                for (size_t k = 0; k < g->files_n; k++)
                    written += emit_elements(f, g->files[k], written);
                fprintf(f, " }\n");
            }
            fprintf(f, "    }\n");
        }
    }

    /* mangle + 1: the mark must exist before the routing decision, and staying one
     * step after mangle leaves room for anything that legitimately wants to run first. */
    fprintf(f, "    chain prerouting_mark {\n"
               "        type filter hook prerouting priority mangle + 1; policy accept;\n");
    for (size_t i = 0; i < g_grp_n; i++) {
        struct group *g = &g_grp[i];
        struct output *o = out_by_name(g->out);
        if (!o) die("channel group %s points at a missing output", g->name);
        /* Каналы на сам телефон — на хуке output, см. emit_output_mark. */
        if (group_is_local(g)) continue;
        /* ПРАВИЛ У ГРУППЫ ОБЫЧНО ОДНО, в старой раскладке у доменной группы с префиксами — два:
         * по правилу на каждую половину набора (см. generate выше). nft не умеет «или» внутри
         * правила, а объединить интервальный набор с hash-набором нечем. Оба правила
         * одинаковы во всём, кроме набора, и оба кончаются return — первое совпавшее решает,
         * как и раньше. Комментарий у них ОДИН И ТОТ ЖЕ: счётчики читаются по нему, и
         * counters_load складывает правила с одним именем — объём канала остаётся одним
         * числом. Перенесённое значение ложится в первое правило, второе начинает с нуля:
         * сумма от этого не меняется. */
        int halves = legacy_has_static(g) ? 2 : 1;
        for (int h = 0; h < halves; h++) {
            char sn[80];
            const char *set = g->name;
            if (halves == 2 && h == 0) { nft_static_set_name(sn, sizeof(sn), g->name); set = sn; }
            fprintf(f, "        ");
            emit_from(f, g);
            emit_l4(f, g->l4, 0);
            if (g->files_n || g->domains || g->emptied) fprintf(f, "ip daddr @%s ", set);
            /* НАШИ биты, а не всё слово: `mark and ~маска or метка`. Перезапись стирала метку
             * mwan3/pbr/sqm молча, а их перезапись — нашу, и тогда помеченный пакет уходил по
             * таблице main, минуя запрет on_fail=drop (I-135). Диапазон объявлен в spec.h и в
             * контракте. Ядро при выводе канонизирует выражение (оно само выставляет в маске
             * бит, который следующий `or` всё равно поднимает) — на поведение это не влияет,
             * проверено на живом роутере. */
            if (out_needs_mark(o))
                /* Метка ПАКЕТА решает маршрут, метка СОЕДИНЕНИЯ позволяет с этим соединением
                 * потом что-то сделать. Без второй запись conntrack про выход не знает ничего
                 * (mark=0 в дампе), и «сними соединения этого выхода» выразить нечем — а это
                 * единственный способ пересмотреть маршрут уже установленного соединения.
                 *
                 * Понадобилось это из-за выгрузки потоков: замер на роутере показал, что при
                 * flow_offloading=1 наша цепочка видит 2-7 пакетов соединения вместо
                 * одиннадцати тысяч, то есть после установления маршрут больше не
                 * пересматривается — и запрет on_fail=drop до такого соединения не доходит
                 * (R-096). Тот же приём и по той же причине использует mwan3. */
                /* Ко всем выходам, КРОМЕ kind=direct, к нашей метке добавляется чужой бит —
                 * тот, которым системный zapret узнаёт «этот пакет не мой» (ZAPRET_SKIP_MARK,
                 * см. spec.h; кому именно и почему — out_skips_zapret там же).
                 *
                 * У kind=zapret без него трафик разбирали бы двое: сначала общий обход своей
                 * стратегией, потом наш экземпляр своей, — и вышло бы не то, что выбрал
                 * человек, ни в одном из двух смыслов. У туннельных выходов причина другая и
                 * не менее веская: обход стал бы рассинхронизировать ВНЕШНИЕ пакеты туннеля,
                 * до полезной нагрузки не добираясь вовсе.
                 *
                 * Ставится ЗДЕСЬ, в prerouting, потому что цепочки zapret висят на
                 * postrouting: позже было бы поздно. */
                /* Метка СОЕДИНЕНИЯ ставится не всем: она живёт в conntrack и переживает
                 * снятие правил, поэтому у выходов, которым она не нужна, её нет вовсе — см.
                 * out_needs_ctmark в spec.h и что из-за неё случалось после удаления tgws. */
                fprintf(f, "meta mark set mark and 0x%08x or 0x%08x %s",
                        ~STEER_MARK_MASK,
                        out_skips_zapret(o) ? (o->mark | ZAPRET_SKIP_MARK) : o->mark,
                        out_needs_ctmark(o) ? "ct mark set mark " : "");
            /* `return` and not `accept`: it ends OUR chain, letting the rest of the
             * firewall proceed, while making the first matching group the winner. */
            if (h == 0) emit_counter(f, g->name, 0);
            else fprintf(f, "counter ");
            fprintf(f, "return comment \"steer:%s\"\n", g->name);
        }
    }
    fprintf(f, "    }\n");

#ifdef STEER_ANDROID
    if (has_local()) emit_output_mark(f);
#endif

    /* ВЫХОД УПАЛ И ПУЩЕН НАПРЯМУЮ — бит «не для zapret» снимается. Правило разметки выше
     * ставит его безусловно, а при on_fail=direct/zapret упавший выход отдаёт трафик
     * таблице main, то есть открытому пути; там пакет обязан быть обычным трафиком роутера
     * и для общего обхода тоже. Какие выходы сейчас в таком состоянии, знает сторож: он
     * держит их метки в наборе. Зачем именно так — у out_failopen_capable в spec.h.
     *
     * mangle + 2 — сразу после разметки (mangle + 1), то есть задолго до цепочек zapret на
     * postrouting. Счётчик — чтобы по дампу было видно, что правило действительно брало
     * пакеты, а не только стояло. */
    int failopen = 0;
    for (size_t i = 0; i < g_out_n; i++)
        if (out_failopen_capable(&g_out[i])) failopen = 1;
    if (failopen)
        fprintf(f, "\n    set %s {\n        type mark\n    }\n"
                   "    chain prerouting_failopen {\n"
                   "        type filter hook prerouting priority mangle + 2; policy accept;\n"
                   "        meta mark and 0x%08x @%s meta mark set mark and 0x%08x counter "
                   "comment \"steer-failopen\"\n"
                   "    }\n",
                FAILOPEN_SET, STEER_MARK_MASK, FAILOPEN_SET, ~ZAPRET_SKIP_MARK);

    /* Встречный путь — только чтобы его было ЧЕМ ПОСЧИТАТЬ. Метку здесь не ставим и
     * решений не принимаем: маршрут ответным пакетам не нужен, их ведёт conntrack.
     *
     * Зачем вообще. Счётчик в prerouting_mark стоит на правиле, ставящем метку, а метка
     * ставится по пути «из локальной сети наружу»: скачанное под `ip saddr <сеть>` не
     * подпадает и в него не попадает никогда. На живом роутере это выглядело как 4,3 МБ при
     * скачанных 223 МБ — человек видел одни подтверждения и не мог понять, куда ушёл
     * трафик. Объём по устройству выхода отвечал на «сколько всего», но не «сколько по
     * этому каналу».
     *
     * ПОЧЕМУ POSTROUTING, а не prerouting. Тут я ошибся и был поправлен опытом
     * (build/natorder.sh), поэтому вывод записан числами. Для доменного канала в наборе
     * лежат fake-IP, и у ответного пакета адрес источника обязан быть переведён обратно в
     * fake-IP, чтобы совпасть с набором. Этот обратный перевод — манипуляция ИСТОЧНИКОМ, а
     * она делается в postrouting: в prerouting в saddr стоит настоящий адрес сервера, каким
     * бы приоритет ни был. Опыт: мегабайт через fake-IP дал в prerouting (и на месте метки,
     * и после dstnat) ровно нуль, а в postrouting — 42 пакета и 1 050 973 байта.
     *
     * Адресному каналу postrouting тоже годится: там адрес источника настоящий с обеих
     * сторон и переводить его нечего — тот же мегабайт, те же 42 пакета. Поэтому одна
     * цепочка покрывает оба вида, и разделять их не нужно.
     *
     * Правило `counter` без вердикта: цепочка ничего не решает, policy accept, и на пути
     * скачивания это один поиск по набору на пакет. */
    fprintf(f, "\n    chain postrouting_down {\n"
               "        type filter hook postrouting priority srcnat + 10; policy accept;\n");
    for (size_t i = 0; i < g_grp_n; i++) {
        struct group *g = &g_grp[i];
        /* Скачанное каналом на сам телефон этой цепочкой не считается: получатель у него —
         * сокет телефона, и пакет идёт через input, а не через postrouting. */
        if (group_is_local(g)) continue;
        /* Две половины доменного набора в старой раскладке — два правила с одним
         * комментарием, как в prerouting_mark и по той же причине. */
        int halves = legacy_has_static(g) ? 2 : 1;
        for (int h = 0; h < halves; h++) {
            char sn[80];
            const char *set = g->name;
            if (halves == 2 && h == 0) { nft_static_set_name(sn, sizeof(sn), g->name); set = sn; }
            fprintf(f, "        ");
            emit_to(f, g);
            /* Зеркало сужения: без него счётчик скачанного считал бы и тот трафик, который
             * правило разметки не берёт, — то есть врал бы ровно на ту величину, ради которой
             * порты и заведены. Тот же довод, что у emit_to рядом. */
            emit_l4(f, g->l4, 1);
            if (g->files_n || g->domains) fprintf(f, "ip saddr @%s ", set);
            if (h == 0) emit_counter(f, g->name, 1);
            else fprintf(f, "counter ");
            fprintf(f, "comment \"steer-down:%s\"\n", g->name);
        }
    }
    fprintf(f, "    }\n");

    /* ---- выходы kind=zapret: помеченный трафик уходит в свой nfqws ----------------
     *
     * ЗДЕСЬ И БОЛЬШЕ НИГДЕ движок соприкасается с обходом DPI. Никаких стратегий он не
     * знает, ключей nfqws не разбирает и процесс отсюда не запускает: его дело — сказать
     * ядру, какой помеченный трафик в какую очередь отдать, и это ровно то же самое, что
     * он делает метками и таблицами для туннелей.
     *
     * Всё, что ниже, СВЕРЕНО С ЖИВЫМ НАБОРОМ ПРАВИЛ zapret, а не выведено из документации:
     * пакет remittor/zapret-openwrt v72.20260307 поставлен на роутер 10.8.1.87 (OpenWrt
     * 25.12.5, nftables 1.1.6), и `nft list table inet zapret` показал вот что.
     *
     *   chain postnat_hook { type filter hook postrouting priority srcnat + 1;
     *       meta mark & 0x40000000 == 0x00000000 jump postnat }
     *   chain postnat { oifname @wanif tcp dport {...} ct original packets 1-9
     *       ip daddr != @nozapret meta mark set meta mark | 0x20000000
     *       ct mark set ct mark | 0x40000000 queue flags bypass to 200 }
     *   chain predefrag { type filter hook output priority -401;
     *       meta mark & 0x40000000 != 0x00000000 jump predefrag_nfqws }
     *   chain predefrag_nfqws { meta mark & 0x20000000 != 0x00000000 notrack ... }
     *
     * Из этого следуют ТРИ решения, и ни одно из них не про вкус.
     *
     * ПРИОРИТЕТ srcnat + 2, а не mangle. Сначала здесь стояло `mangle + 10` (то есть -140),
     * и это было неверно дважды. Во-первых, mangle идёт ДО трансляции адресов, а nfqws
     * обязан видеть пакет таким, каким тот уйдёт с роутера: у zapret на OpenWrt для этого
     * есть отдельный режим POSTNAT, включённый по умолчанию, и его цепочка висит на
     * srcnat + 1 именно поэтому. Чинить ClientHello с адресом источника из локальной сети —
     * значит чинить пакет, которого в сети не будет. Во-вторых, до нашей цепочки должна
     * успеть отработать цепочка zapret: она увидит нашу метку, пропустит наш трафик, и
     * пакет дойдёт сюда нетронутым. Обратный порядок дал бы два обхода на одном пакете.
     *
     * ЧУЖИЕ БИТЫ МЕТКИ. На исходный пакет мы ставим 0x40000000 (это делает prerouting_mark
     * выше) — по нему postnat_hook говорит «не мой» и трафик выхода мимо общего обхода
     * проходит целиком. Свой обработчик поднимается с --dpi-desync-fwmark=0x60000000, то
     * есть его собственные пакеты (подделки, повторы, куски разрезанного) несут ОБА бита:
     * 0x40000000 уводит их и от общего обхода, и в predefrag_nfqws — там их снимают с учёта
     * conntrack, без чего ядро отбросило бы их как INVALID; 0x20000000 выводит их из НАШЕЙ
     * очереди первым правилом ниже. Разные биты у исходного и у порождённого — единственный
     * способ различить их здесь: у обоих есть 0x40000000, и один бит на двоих означал бы
     * либо круг (свой пакет снова в свою очередь), либо неразобранный исходный.
     *
     * ПРЕДЕЛ ПАКЕТОВ. `ct original packets 1-N` — не осторожность, а цена: без него в
     * userspace уезжает КАЖДЫЙ пакет соединения, то есть весь поток видео проходит через
     * копирование в nfqws и обратно на 880 МГц. Обходу нужны только первые пакеты — там
     * лежат SYN, ClientHello и QUIC Initial; zapret по той же причине ставит свой предел
     * (NFQWS_TCP_PKT_OUT, по умолчанию 9), и число здесь взято его же.
     *
     * BYPASS ВЫРАЖАЕТ on_fail, и выражает его САМО ЯДРО, без сторожа и без опроса:
     *   on_fail=direct — `bypass`: нет процесса на очереди, пакет идёт дальше как обычный;
     *   on_fail=drop   — без `bypass`: нет процесса — пакет отбрасывается.
     * Умолчание общее для всех выходов — drop, и здесь оно значит то же, что везде: канал
     * заводят ради обхода, и молча вернуть трафик на открытый путь в момент, когда обход
     * умер, — значит нарушить единственное обещание выхода ровно тогда, когда это важнее
     * всего. Оговорка у `bypass` одна и её стоит знать: он срабатывает и на ПЕРЕПОЛНЕНИИ
     * очереди, а не только на отсутствии процесса. */
    if (has_zapret()) {
        fprintf(f, "\n    chain zapret_queue {\n"
                   "        type filter hook postrouting priority srcnat + 2; policy accept;\n");
        fprintf(f, "        meta mark and 0x%08x == 0x%08x counter return "
                   "comment \"steer:zapret-own\"\n", ZAPRET_MINE_BIT, ZAPRET_MINE_BIT);
        /* БИТ 0x40000000 СНИМАЕТСЯ С ПАКЕТА ПЕРЕД ОЧЕРЕДЬЮ, и без этого выход не работал
         * вовсе. nfqws считает своим порождённым любой пакет, у которого с его
         * --dpi-desync-fwmark есть хоть один общий бит, и пропускает такой без обработки
         * («ignoring generated packet» в его отладке). Наш обработчик поднят с 0x60000000,
         * бит 0x40000000 в него входит — а на исходном пакете он стоит с prerouting, чтобы
         * общий обход сказал «не мой». Пока бит доезжал до очереди, обработчик не трогал
         * НИ ОДНОГО пакета: снято с роутера владельца — YouTube через выход 3 из 37 при
         * любой стратегии, со снятым битом 33 из 37. Снимать здесь безопасно: цепочка
         * общего обхода (srcnat + 1) уже позади, дальше бит никому не нужен, а свои восемь
         * бит метки (маршрут) целы. */
        /* ВЫХОД УЗНАЁТСЯ ПО МЕТКЕ СОЕДИНЕНИЯ (ct mark), А НЕ ПАКЕТА. Обе ставятся одним
         * правилом в prerouting и до маршрутизации совпадают, но между маршрутизацией и этой
         * цепочкой лежит хук forward — и там метку пакета переписывают чужие. Tailscale на
         * каждом пакете с tailscale0 делает `meta mark set mark and 0xff00ffff xor 0x40000`:
         * биты 16-23 стираются, а наши восемь бит начинаются с двадцатого, то есть у первых
         * четырёх выходов метка до очереди не доезжала вовсе. Снаружи это выглядело как
         * «добавил tailscale0 в клиенты — с телефона обход не работает, из LAN работает»:
         * правило стоит, счётчик нулевой, обработчик жив. Метку соединения никто из соседей
         * не трогает — она наша по назначению, тот же довод, что у conntrack_evict. Цепочка
         * ответов (zapret_queue_in) по ct mark работала и прежде. */
        for (size_t i = 0; i < g_out_n; i++) {
            struct output *o = &g_out[i];
            if (o->kind != OUT_ZAPRET) continue;
            fprintf(f, "        ct mark and 0x%08x == 0x%08x ct original packets 1-%d "
                       "meta mark set mark and 0x%08x counter queue num %d%s "
                       "comment \"steer:zapret:%s\"\n",
                    STEER_MARK_MASK, o->mark, ZAPRET_FIRST_PACKETS, ~ZAPRET_SKIP_MARK,
                    out_zapret_queue(o), o->on_fail == FAIL_DROP ? "" : " bypass", o->name);
        }
        fprintf(f, "    }\n");
        /* Ответные пакеты — SYN-ACK и два за ним — тоже в очередь, как у zapret
         * (`ct reply packets 1-3`): по ним nfqws узнаёт TTL сервера для autottl и состояние
         * соединения; без них стратегии с autottl работали бы вслепую. Соединение узнаётся по
         * ct mark — он ставится вместе с меткой в prerouting и несёт номер выхода. Всегда с
         * bypass: ответ терять нельзя ни при каком on_fail, исходные пакеты и так решают
         * судьбу соединения. */
        fprintf(f, "\n    chain zapret_queue_in {\n"
                   "        type filter hook prerouting priority mangle; policy accept;\n");
        for (size_t i = 0; i < g_out_n; i++) {
            struct output *o = &g_out[i];
            if (o->kind != OUT_ZAPRET) continue;
            fprintf(f, "        ct mark and 0x%08x == 0x%08x ct reply packets 1-3 "
                       "counter queue num %d bypass comment \"steer:zapret-reply:%s\"\n",
                    STEER_MARK_MASK, o->mark, out_zapret_queue(o), o->name);
        }
        fprintf(f, "    }\n");
        /* СВОЯ predefrag, а не расчёт на цепочку zapret. Порождённые обработчиком пакеты
         * (подделки, повторы, куски разрезанного) для conntrack — мусор: чужие номера
         * последовательности, дубли, части без начала. Учтённые, они становятся INVALID, и
         * fw4 их отбрасывает — обход молча не работает, хотя обработчик жив и очередь
         * считает пакеты. Снятие с учёта (notrack) делает predefrag_nfqws системного
         * zapret, и до сих пор мы на неё и рассчитывали: у порождённых пакетов поднят
         * 0x40000000, её условие. Но эта цепочка живёт в таблице СЛУЖБЫ zapret и исчезает
         * вместе с ней — а выключить общий обход и оставить обход только одному выходу
         * (например, YouTube) — ровно то, ради чего выход kind=zapret и заводят. Снято с
         * живого роутера владельца: общий обход выключен, выход стоит, стратегия рабочая,
         * очередь считает пакеты — YouTube не открывается; проверка стратегий при этом даёт
         * числа, равные «без обхода», по той же причине.
         *
         * Правила — те же четыре, что у zapret (postnat-метка, два вида фрагментов,
         * данные без ACK), и на том же приоритете -401 — до conntrack. Две одинаковые
         * цепочки при работающем общем обходе не мешают друг другу: notrack дважды — это
         * notrack. */
        /* СТАРОЕ ЯДРО БЕЗ notrack — цепочки нет вовсе. На ядре телефона выражения нет
         * (nft_ct.c в 4.9 его не знает), и строка с ним отвергла бы всю транзакцию. Цена
         * названа при apply (report_legacy_gaps): порождённые обработчиком пакеты остаются на
         * учёте conntrack. Очередь при этом работает — это другие цепочки выше. */
        if (!NFT_LEGACY || (g_nftc & NFTC_NOTRACK))
        fprintf(f, "\n    chain zapret_predefrag {\n"
                   "        type filter hook output priority -401; policy accept;\n"
                   "        meta mark and 0x%08x != 0x00000000 jump zapret_predefrag_nfqws "
                   "comment \"steer:zapret-notrack\"\n"
                   "    }\n"
                   "    chain zapret_predefrag_nfqws {\n"
                   /* ПРАВИЛА ТРИ, А НЕ ЧЕТЫРЕ: правила zapret про «postnat traffic» здесь быть
                    * не должно, и это не упрощение, а починка отказа, из-за которого выход
                    * kind=zapret не работал ни у кого, кто выбрал стратегию.
                    *
                    * У zapret бит 0x20000000 (DESYNC_MARK_POSTNAT) значит «пакет взят из
                    * цепочки ПОСЛЕ трансляции адресов», и ставит его само правило очереди. У
                    * нас этот бит значит другое — «пакет нашего обработчика» (ZAPRET_MINE_BIT,
                    * см. spec.h): без него порождённый пакет вернулся бы в нашу же очередь.
                    * Правило мы взяли у zapret вместе с его смыслом бита, и получилось, что
                    * снимаются с учёта ВСЕ пакеты нашего nfqws.
                    *
                    * Цена этого — весь канал. Снятый учёт означает, что к пакету не
                    * применяется трансляция адресов; а nfqws строит свои копии из ИСХОДНОГО
                    * кортежа соединения, то есть с адресом клиента из локальной сети. Такие
                    * копии уходят в интернет с частным адресом источника, сервер их не
                    * узнаёт, и соединение виснет до таймаута.
                    *
                    * Снято на стенде в QEMU с настоящим клиентом за LAN. Рукопожатие уходит
                    * верно (10.77.0.2 -> сервер, сервер отвечает), а каждый пакет данных —
                    * «192.168.1.2 -> сервер», шесть копий подряд (--dpi-desync-repeats=6).
                    * Клиент получает таймаут, 5 проб из 5. Тот же nfqws и та же стратегия на
                    * ВЕСЬ роутер службой zapret работают: HTTP 200 за 20-113 мс, 4 из 4, —
                    * значит дело не в стенде и не в обходе, а в этом правиле. Проверено
                    * счётчиками, что до очереди пакет доезжает уже оттранслированным (38 из
                    * 38 с адресом WAN), то есть исправлять надо именно обратный путь.
                    *
                    * Остальные три правила остаются: фрагменты и данные без ACK для conntrack
                    * действительно мусор, и учтённые они стали бы INVALID. */
                   "        ip frag-off and 0x1fff != 0x0 notrack comment \"ipfrag\"\n"
                   /* `exthdr frag exists` на 4.9 НЕ отвергается, а ПОДМЕНЯЕТСЯ: флага «есть
                    * ли заголовок» там нет, ядро выбрасывает незнакомый атрибут и грузит
                    * сравнение поля frag nexthdr с единицей (снято на стенде tools/vm49).
                    * Замена `frag frag-off >= 0` значит то же самое на любом ядре: выражение
                    * exthdr без флага ищет заголовок фрагмента в цепочке заголовков и при
                    * его отсутствии правило не совпадает, а сравнение `>= 0` верно всегда.
                    * Проверено там же сырыми пакетами: совпадает и [ipv6][frag], и
                    * [ipv6][hop-by-hop][frag], и не совпадает с пакетом без фрагмента. */
                   "        %s notrack comment \"ipfrag\"\n"
                   "        tcp flags ! syn,rst,ack notrack comment \"datanoack\"\n"
                   "    }\n", ZAPRET_SKIP_MARK,
                NFT_LEGACY ? "frag frag-off >= 0" : "exthdr frag exists");
    }

    /* Всё, что ниже, — nat и то, что стоит рядом с ним. В старой раскладке оно устроено
     * иначе целиком (другие таблицы, одна цепочка nat), и смешивать две раскладки строками
     * через одну значило бы читать каждую строку дважды. Поэтому отдельная функция. */
    if (NFT_LEGACY) { generate_legacy_tail(f); return; }

    /* ---- перехват Telegram у выходов kind=tgws ------------------------------------
     *
     * ПЕРЕХВАТ, А НЕ МАРШРУТ. Приложению ничего не настраивают: соединение с дата-центром
     * заворачивается на мост здесь же, в ядре, а он уводит его веб-сокетом (см. длинное
     * объяснение у TGWS_PORT_BASE в spec.h).
     *
     * ПРИОРИТЕТ dstnat + 1, и оба слова важны. Метку канала ставит prerouting на
     * `mangle + 1` (то есть -149), а трансляция адресов идёт на -100 — значит к моменту
     * этой цепочки метка на пакете уже есть и по ней можно узнать выход. Плюс единица —
     * чтобы пропустить вперёд свою же цепочку fakeip: доменное правило сначала должно
     * вернуть настоящий адрес, и только потом мы решаем, наш ли он.
     *
     * ТОЛЬКО PREROUTING, то есть только трафик клиентов сети. Трафик самого роутера сюда
     * не попадает нарочно: перехватывать собственные соединения движка (обновление
     * списков, проверки) значило бы заворачивать в мост то, что к Telegram отношения не
     * имеет, а разделять их было бы нечем.
     *
     * ПОРТЫ — те, на которых Telegram держит MTProto: 443 и 80 (обычные), 5222 (запасной у
     * старых клиентов). UDP здесь нет: голос звонков в веб-сокет не заворачивается (см.
     * spec.h), и пусть идёт своим путём.
     *
     * redirect, а не dnat на петлю: redirect подставляет адрес того интерфейса, откуда
     * пришёл пакет, и обратный путь ядро собирает само. Исходный адрес назначения мост
     * узнаёт у ядра через SO_ORIGINAL_DST — из него же выводится номер дата-центра. */
    if (has_tgws()) {
        fprintf(f, "\n    chain tgws_redirect {\n"
                   "        type nat hook prerouting priority dstnat + 1; policy accept;\n");
        emit_tgws_rules(f);
        fprintf(f, "    }\n");
    }

    /* ПЕРЕНАПРАВЛЕНИЕ DNS СТОИТ ВСЕГДА, а не только при доменных каналах.
     *
     * Раньше оно появлялось и исчезало вместе с has_domains(), и это была переменная,
     * от которой зависели три вещи в разных местах: сам резолвер (needs-dnsd в
     * init-скрипте), это правило и ключ force_dns у https-dns-proxy в splify2. Две
     * последние обязаны меняться вместе — два перенаправления порта 53 в одной точке
     * nat prerouting выигрывает то, которое зарегистрировалось раньше, а проигравший
     * молчит: домены перестают маршрутизироваться, сайты при этом открываются.
     *
     * Пока «нужен ли резолвер» выводилось из спеки, синхронизировать их успевал метод
     * apply управляющего слоя. С гибридными списками (домен и подсеть в одном файле)
     * доменность стала бы зависеть от СОДЕРЖИМОГО файла — то есть могла бы перевернуться
     * ночным обновлением списков, которое зовёт `steer apply` напрямую, минуя метод и
     * его синхронизацию. Решение владельца: резолвер держим всегда, и тогда переворачивать
     * нечего — force_dns навсегда 0, а гонки не существует.
     *
     * Цена названа вслух: у роутера без единого доменного канала DNS всё равно идёт через
     * наш резолвер. Взамен уходит целый класс отказов «доменность изменилась, а что-то не
     * пересинхронизировалось».
     *
     * Форм у правила две, и выбирает между ними то же, что выбирает «кто» у каналов.
     * Заданы подсети — забираем IPv4 по адресу, а IPv6 по устройству, потому что
     * стабильного `ip6 saddr` у локального префикса нет. Подсетей нет — забираем по
     * устройству ОБА семейства одним правилом. */
    /* НО НЕ В МИНИ-СБОРКЕ, И ЭТО НЕ ЭКОНОМИЯ, А ИСПРАВЛЕНИЕ ОТКАЗА.
     *
     * Микропакет tgws поднимает ровно мост (см. его init-скрипт: procd получает только
     * экземпляры `tgws`), резолвера в нём не поднимает никто и спека у него адресная —
     * канал по prefixes_files, ни одного имени. А правило ставилось всё равно, потому что
     * решение «резолвер держим всегда» принималось для полного движка, где init поднимает
     * dnsd безусловно.
     *
     * Получалось так: пакет встаёт, подбор домена заканчивается через минуту, apply
     * ставит таблицу — и весь DNS локальной сети заворачивается на порт 5300, где никто
     * не слушает. У сети пропадает разрешение имён целиком, а Telegram продолжает
     * работать, потому что его клиент ходит к дата-центрам по вшитым адресам и DNS не
     * спрашивает. Снаружи это выглядит как «поставил прокси, через минуту помер
     * интернет, помогло только удаление и ребут» — ребут помогает потому, что правила
     * nft не сохраняются между загрузками. Ровно это сообщение и пришло от человека, и
     * воспроизведено в openwrt/rootfs:x86-64-24.10.6.
     *
     * Инвариант поэтому привязан к сборке, а не к спеке и не к настройке: правило
     * существует там и только там, где существует поднимающий резолвер. Настройкой этот
     * выбор делать нельзя — разошедшиеся правило и процесс это ровно тот отказ, который
     * здесь и починен.
     */
#ifndef STEER_TGWS
    fprintf(f, "    chain prerouting_dns {\n"
               "        type nat hook prerouting priority dstnat; policy accept;\n");
    for (size_t i = 0; i < g_from_default_n; i++)
        fprintf(f, "        ip saddr %s udp dport 53 counter redirect to :%d\n",
                g_from_default[i], DNS_PORT);
    fprintf(f, "        ");
    if (g_from_default_n) fprintf(f, "meta nfproto ipv6 ");
    emit_ifs(f, 0);
    fprintf(f, "udp dport 53 counter redirect to :%d\n", DNS_PORT);
    /* TCP/53 рядом с UDP/53. Резолвер слушает TCP на том же порту (dnsd.c, «DNS по TCP»), а без
     * заворота доменный канал слеп ко всему, что спрошено по TCP: к переспросу после усечённого
     * ответа (TC=1) и к клиентам, которые ходят по TCP сразу. Имя, спрошенное так, не получает
     * fakeip и не попадает в набор, и соединение уходит по настоящему адресу мимо выхода.
     * Замерено на живом роутере с steer 1.5.8: Windows-клиент за несколько минут задал 22
     * вопроса по TCP к IPv6-адресу роутера — все мимо резолвера, прямо в dnsmasq. */
    for (size_t i = 0; i < g_from_default_n; i++)
        fprintf(f, "        ip saddr %s tcp dport 53 counter redirect to :%d\n",
                g_from_default[i], DNS_PORT);
    fprintf(f, "        ");
    if (g_from_default_n) fprintf(f, "meta nfproto ipv6 ");
    emit_ifs(f, 0);
    fprintf(f, "tcp dport 53 counter redirect to :%d\n", DNS_PORT);
    fprintf(f, "    }\n");
#endif

    /* Остальное по-прежнему по факту доменных каналов: карта fakeip и цепочка dstnat
     * стоят per-packet, и держать их пустыми на роутере без доменов незачем. Это гейт
     * по СТОИМОСТИ, а не по смыслу, и переворачиваться он может свободно — ни один
     * чужой ключ от него не зависит. */
    if (has_domains()) {
        if (has_fakeip()) {
            fprintf(f, "\n    map fakeip {\n        type ipv4_addr : ipv4_addr;\n");
            emit_fakeip_elements(f);
            fprintf(f, "    }\n");
            /* Счётчик здесь обязателен, и это не единообразие с соседями. Правило
             * отвечает на единственный вопрос, который встаёт, когда «домены не
             * работают»: доехал ли поддельный адрес до роутера вообще. Без счётчика
             * «клиент не прислал» и «прислал, а мы не развернули» различаются только
             * tcpdump'ом на роутере, а первое — обычное дело у клиента из mesh-VPN
             * (Tailscale, ZeroTier): 198.18.0.0/15 уходит в туннель, только если роутер
             * объявил этот диапазон маршрутом, и по умолчанию он его не объявляет. Из
             * локальной сети вопрос не встаёт вовсе — там роутер и есть шлюз. */
            fprintf(f, "    chain prerouting_dnat {\n"
                       "        type nat hook prerouting priority dstnat; policy accept;\n"
                       "        ip daddr 198.18.0.0/15 counter dnat ip to ip daddr map @fakeip\n"
                       "    }\n");
        }
#ifdef STEER_ANDROID
        if (has_local_domains()) {
            fprintf(f, "    chain output_dns {\n"
                       "        type nat hook output priority dstnat; policy accept;\n");
            emit_local_dns(f, "dnat ip");
            fprintf(f, "    }\n");
        }
#endif
        /* Make traceroute show the REAL intermediate routers while the destination
         * stays the fake address.
         *
         * ONLY WORKS WHEN THE OUTPUT DOES NOT MASQUERADE — measured: with NAT on, 13
         * errors hit this rule, 0 reached the accept for untracked traffic, and every
         * hop after the first became an asterisk. With NAT the error is addressed to
         * the ROUTER, so only conntrack knows which client it belongs to; untracking
         * removes exactly that knowledge. Tracking is the delivery mechanism and being
         * tracked is what rewrites the source — one does not come without the other.
         *
         * Scope is just time-exceeded (type 11): dest-unreachable must stay tracked or
         * path-MTU discovery breaks, which trades a cosmetic win for broken transfers. */
        if (g_traceroute_hops) emit_traceroute_raw(f);
        /* The resolver only sees what is steered to it. IPv6 as well as IPv4: the
         * router advertises itself as an IPv6 resolver by default and clients prefer
         * that server, so an IPv4-only redirect catches almost nothing — measured on a
         * real client, 15 of its DNS packets went over IPv6 against 20 over IPv4.
         * TCP/53 is redirected alongside UDP/53 (prerouting_dns above): the daemon
         * listens on TCP too (dnsd.c, «DNS по TCP»).
         */
    }
    fprintf(f, "}\n");
}

