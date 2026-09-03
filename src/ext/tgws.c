/* Мост Telegram → WebSocket: приложение не настраивают, соединение перехватывают.
 *
 * ЗАЧЕМ. Telegram ходит в свои дата-центры по TCP на их адреса, и режут именно это. У
 * веб-клиента есть второй путь: тот же MTProto, завёрнутый в WebSocket поверх TLS к точке
 * `/apiws`. Сама по себе она стоит на адресах Telegram и от блокировки не спасает — спасает
 * то, что её можно поставить ЗА CLOUDFLARE: домен с записью `kwsN.<домен>` и включённым
 * проксированием отвечает адресами Cloudflare, блокировать которые дорого. Готовые прокси
 * (tg-ws-proxy и родня) так и устроены, но требуют вписать адрес и секрет В КАЖДОМ КЛИЕНТЕ.
 * Здесь то же самое делается прозрачно: правило nat заворачивает соединение на этот мост, а
 * он уводит его веб-сокетом.
 *
 * ПОЧЕМУ ЧУЖОЙ ПРОКСИ СЮДА НЕ ПОСТАВИТЬ. Он ждёт рукопожатие MTPROXY: там есть секрет, и из
 * него же берётся номер дата-центра. Приложение, идущее в дата-центр напрямую, шлёт другое
 * рукопожатие — без секрета, и номера в нём нет вовсе. Завернуть одно в другое нечем, кроме
 * как разобрав его самим, — этим мост и занимается.
 *
 * ПОЧЕМУ ПОТОК ИДЁТ НАСКВОЗЬ. Обфускация MTProto ключей не согласовывает: клиент шлёт 64
 * случайных байта, и ключ с вектором — это байты [8..40] и [40..56] прямо из них, без
 * секрета (секрет подмешивается только у MTProxy — core.telegram.org/mtproto/
 * mtproto-transports). Точка `apiws` ждёт ровно такой же пакет. Значит расшифровывать и
 * перешифровывать поток не нужно вовсе: отдаём 64 байта клиента первым бинарным кадром и
 * дальше переливаем байты. Прикладной слой всё равно закрыт auth_key, и читать его нечем.
 *
 * ЧТО ВСЁ-ТАКИ ПРАВИТСЯ — ВОСЕМЬ БАЙТ ХВОСТА. В [56..64] лежат метка транспорта и номер ДЦ
 * (signed LE, отрицательный — медийный). У прямого соединения номера там нет — случайные
 * байты, — а точке `apiws` он нужен. Мы его вписываем: считаем гамму теми же сырыми ключами
 * и переXORиваем хвост. Ключи от этого не меняются: они выводятся из [8..56], которых мы не
 * трогаем, — поэтому остаток потока остаётся верным и расшифруется у дата-центра.
 *
 * ОТКУДА НОМЕР ДЦ. Из адреса назначения (SO_ORIGINAL_DST), потому что в рукопожатии его нет.
 * Таблица ниже, её можно дополнить файлом. НЕИЗВЕСТНЫЙ АДРЕС НЕ ПЕРЕХВАТЫВАЕТСЯ: соединение
 * просто переливается на исходный адрес как было. Увести соединение не в тот дата-центр —
 * значит сломать то, что работало, а промолчать об этом нечем: клиент получил бы ответы
 * чужого ДЦ и решил бы, что его выкинули.
 *
 * СЕРТИФИКАТ НЕ ПРОВЕРЯЕТСЯ, и это осознанно. В сборке нет ни X.509, ни PK, ни цепочек
 * доверия (см. шапку steer_mbedtls_config.h), а внутри едет MTProto, у которого своя
 * сквозная аутентификация: ключ согласуется по DH и подписан ключами Telegram, зашитыми в
 * приложение. Посредник во внешнем TLS не прочитает и не подделает ни одного сообщения —
 * ему остаётся только оборвать соединение, что он и так может. Эталонные реализации (в том
 * числе питоновская, с которой писали tg-ws-proxy) поступают так же.
 *
 * ЗВОНКИ СЮДА НЕ ПОПАДАЮТ. Голос идёт по UDP (P2P или через рефлекторы), MTProto участвует
 * только в установке. Перехват здесь только TCP — завернуть UDP в этот веб-сокет нечем.
 *
 * ПОТОК НА СОЕДИНЕНИЕ. Их единицы (клиент держит одно-два на дата-центр), и каждое почти всё
 * время спит. Городить здесь общий цикл epoll, как в туннеле, значило бы платить сложностью
 * за то, чего нет: там сотни соединений и путь данных, здесь — десяток и переливание. */

#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <pthread.h>
#include <signal.h>
#include <time.h>
#include <netdb.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <sys/socket.h>
#include <linux/netfilter_ipv4.h>

#include <mbedtls/aes.h>

#include "tgws.h"
#include "tls13.h"
#include "reality.h"
#include "../spec.h"

#define LOG_I "steer[info] tgws: "
#define LOG_W "steer[warn] tgws: "

#define HS_LEN        64        /* длина рукопожатия обфускации */
#define TAG_POS       56        /* метка транспорта */
#define DC_POS        60        /* номер ДЦ, signed LE */
#define BUF_N         16384     /* столько за раз переливаем в каждую сторону */
/* Место, которое обязано быть свободно перед чтением из TLS.
 *
 * tls13_read отдаёт запись ЦЕЛИКОМ и отказывает (TLS13_ETOOBIG), если она не влезла, — то
 * есть «мало места» здесь не «прочитаем остаток потом», а потерянная запись и разъехавшийся
 * поток. Запись TLS 1.3 — до 16 КБ полезной нагрузки, поэтому свободного места всегда
 * держим больше. Поймано пробой против openssl s_server: ответ в 3 КБ не влезал в буфер на
 * 2 КБ, и ошибка выглядела как «сервер отказал». */
#define TLS_REC_MAX   17408
/* Предел одновременных соединений. Был 64 — «больше клиент не открывает», — и на живом
 * роутере кончился за секунду: перехват берёт ВСЁ, что идёт на адреса Telegram по 80 и 443,
 * а это не только MTProto, но и веб-клиент со своей пачкой соединений, и каждое из них,
 * даже пропускаемое насквозь, занимает слот. Отказ при этом выглядит для человека как
 * «Telegram не работает», причём молча. 192 — потому что стек потока выделяется лениво:
 * место под них резервируется в адресном пространстве, а не в памяти. */
#define MAX_CONNS     192
#define UP_TIMEOUT_S  10

/* Домен точек веб-сокета. Прямой (web.telegram.org) НЕ работает у нас по двум причинам
 * сразу, и обе выяснились пробой против настоящего Telegram, а не по документации:
 *
 *   1) kwsN.web.telegram.org отвечает ТОЛЬКО TLS 1.2 (сертификат GoDaddy, ECDHE-RSA-
 *      AES128-GCM-SHA256), а наш клиент — строго TLS 1.3 и другим быть не должен: он же
 *      носит облик Chrome, а Chrome к 1.2 здесь не опускается;
 *   2) адреса у него телеграмовские — то есть ровно те, которые и режут. Гнать перехват
 *      туда значило бы менять один заблокированный путь на другой.
 *
 * Работает путь через домен, стоящий за Cloudflare: `kwsN.<домен>` с записью на веб-точку
 * Telegram и включённым проксированием. Такой домен отвечает TLS 1.3, а его адреса —
 * адреса Cloudflare, блокировать которые дорого. Домен задаётся выходу в спеке (`domain`),
 * потому что он ЧУЖОЙ: это либо домен самого владельца роутера, либо тот, который кто-то
 * держит для сообщества, и зашивать его в движок значило бы решать за человека, чьим
 * каналом он пользуется. */
#define TGWS_DOMAIN_DEFAULT "web.telegram.org"

/* ---- таблица дата-центров ---------------------------------------------------------
 *
 * Адреса встроены в клиенты Telegram и меняются редко. Медийные ДЦ обслуживают загрузку
 * файлов и объявляются отрицательным номером — у них своя точка `kwsN-1`.
 *
 * Таблицу можно дополнить файлом (STEER_TGWS_DCMAP, по умолчанию /etc/steer/tgws-dc.conf):
 * строки вида `149.154.167.220 2` или `149.154.164.250 4 media`. Файл, а не только сборка,
 * потому что список чужой: Telegram может добавить адрес, и чинить это перевыпуском пакета
 * — заведомо медленнее, чем строкой в конфигурации. */
/* Запись таблицы — АДРЕС ИЛИ ПОДСЕТЬ. Только поимённых адресов не хватило: Telegram держит
 * за одним дата-центром весь /24 и раздаёт клиентам разные адреса из него, поэтому мост,
 * знающий девять адресов, видел живого клиента и говорил «не наш дата-центр». Совпадение
 * ищется по самой длинной маске: подсеть задаёт общее правило, отдельный адрес — исключение
 * из него (в 149.154.167.0/24 живёт второй ДЦ, но .91 и .92 — четвёртый). */
struct dc_ent { uint32_t ip; uint32_t mask; short dc; short media; };
static struct dc_ent g_dc[128];
static size_t g_dc_n;

/* Подсети — из объявлений Telegram, отдельные адреса — исключения внутри них. Медийные ДЦ
 * (флаг media) обслуживают загрузку файлов и имеют свою точку kwsN-1. */
static const struct { const char *ip; short dc; short media; } DC_BUILTIN[] = {
    { "149.154.175.0/24",  1, 0 },
    { "149.154.167.0/24",  2, 0 },
    { "149.154.161.0/24",  2, 0 },
    { "149.154.162.0/24",  2, 0 },
    { "149.154.171.0/24",  5, 0 },
    { "91.108.56.0/22",    5, 0 },
    { "91.108.4.0/22",     4, 0 },
    { "91.108.8.0/22",     2, 0 },
    { "91.108.12.0/22",    1, 0 },
    { "91.108.16.0/22",    3, 0 },
    { "91.108.20.0/22",    4, 0 },
    { "91.105.192.0/23",   2, 0 },
    { "185.76.151.0/24",   2, 0 },
    { "95.161.64.0/20",    2, 0 },
    /* Исключения поимённо: они перекрывают подсеть выше, потому что маска длиннее. */
    { "149.154.175.50",  1, 0 },
    { "149.154.175.53",  1, 0 },
    { "149.154.175.100", 3, 0 },
    { "149.154.175.115", 3, 0 },
    { "149.154.167.50",  2, 0 },
    { "149.154.167.51",  2, 0 },
    /* Медийные точки клиента. Они обслуживают файлы и картинки, у них своя точка kwsN-1, и
     * отправленное на обычную точку того же ДЦ соединение авторизуется, а файлы не отдаёт —
     * снаружи это ровно «переписка идёт, медиа не грузится». Адреса сверены с картой
     * дата-центров Telegram (getProxyConfig: -2 и -4 живут в 149.154.161.x и 149.154.165.x). */
    { "149.154.167.151", 2, 1 },
    { "149.154.167.222", 2, 1 },
    { "149.154.161.184", 2, 1 },
    { "149.154.164.0/24", 4, 1 },
    { "149.154.165.0/24", 4, 1 },
    { "149.154.166.0/24", 4, 1 },
    { "149.154.167.91",  4, 0 },
    { "149.154.167.92",  4, 0 },
    { "149.154.164.250", 4, 1 },
    { "149.154.166.120", 4, 1 },
    { "149.154.171.5",   5, 0 },
    { "91.108.56.130",   5, 0 },
    { "91.108.56.140",   5, 1 },
};

/* Принимает и `1.2.3.4`, и `1.2.3.0/24`. Повторная запись с той же маской заменяет прежнюю:
 * файл дополняет встроенную таблицу, а не спорит с ней. */
static void dc_add(const char *ip, short dc, short media) {
    struct in_addr a;
    char buf[64];
    unsigned bits = 32;
    const char *slash = strchr(ip, '/');

    if (g_dc_n >= sizeof(g_dc) / sizeof(g_dc[0])) return;
    if (slash) {
        size_t n = (size_t)(slash - ip);
        if (n >= sizeof(buf)) return;
        memcpy(buf, ip, n);
        buf[n] = '\0';
        bits = (unsigned)atoi(slash + 1);
        if (bits > 32) return;
        ip = buf;
    }
    if (inet_pton(AF_INET, ip, &a) != 1) return;

    uint32_t mask = bits ? htonl(0xffffffffu << (32 - bits)) : 0;
    uint32_t net = a.s_addr & mask;
    for (size_t i = 0; i < g_dc_n; i++)
        if (g_dc[i].ip == net && g_dc[i].mask == mask) {
            g_dc[i].dc = dc; g_dc[i].media = media; return;
        }
    g_dc[g_dc_n].ip = net;
    g_dc[g_dc_n].mask = mask;
    g_dc[g_dc_n].dc = dc;
    g_dc[g_dc_n].media = media;
    g_dc_n++;
}

static void dc_table_init(void) {
    g_dc_n = 0;
    for (size_t i = 0; i < sizeof(DC_BUILTIN) / sizeof(DC_BUILTIN[0]); i++)
        dc_add(DC_BUILTIN[i].ip, DC_BUILTIN[i].dc, DC_BUILTIN[i].media);

    const char *path = getenv("STEER_TGWS_DCMAP");
    if (!path) path = "/etc/steer/tgws-dc.conf";
    FILE *f = fopen(path, "r");
    if (!f) return;
    char line[128];
    size_t added = 0;
    while (fgets(line, sizeof(line), f)) {
        char ip[64], flag[16];
        int dc;
        flag[0] = '\0';
        if (line[0] == '#') continue;
        int n = sscanf(line, "%63s %d %15s", ip, &dc, flag);
        if (n < 2 || dc < 1 || dc > 9) continue;
        dc_add(ip, (short)dc, (short)(!strcmp(flag, "media")));
        added++;
    }
    fclose(f);
    if (added) fprintf(stderr, LOG_I "адресов ДЦ из %s: %zu\n", path, added);
}

/* Запасные домены. Точки общественные и чужие: 503 от Cloudflare приходит и на исправном
 * домене — просто потому, что за ним сейчас слишком много народу. Пропускать соединение
 * насквозь в такой момент значит отдать его в блокировку, а клиент ответит на это тем, что
 * переподключится через секунду, и так по кругу; снаружи это видно как
 * «подключается-отключается раз в 2-3 секунды».
 *
 * Список — файлом, а не в спеке: домены живут и умирают чаще, чем настройка роутера, и
 * обновляет его тот же набор данных, что и списки (у brb это data/tgws-domains.lst). */
#define MAX_ALT 8
static char g_alt[MAX_ALT][128];
static size_t g_alt_n;

/* Домен, только что ответивший 503, на минуту уходит в конец очереди.
 *
 * Без этого каждое новое соединение снова начинает с него: 503 у Cloudflare держится
 * секундами, а платит за это КАЖДОЕ соединение — лишним рукопожатием TLS и лишним запросом
 * перед тем, как уйти на запасной. Отсюда редкие, но заметные подвисания.
 *
 * Помечается домен, а не точка: 503 отдаёт край Cloudflare, и если он отказывает по kws2,
 * то с большой вероятностью откажет и по kws4 того же домена. */
#define ALT_COOLDOWN_S 60
static time_t g_bad[1 + MAX_ALT];

static int dom_ok_now(size_t i, time_t now) { return g_bad[i] <= now; }

static void alt_init(void) {
    const char *path = getenv("STEER_TGWS_DOMAINS");
    if (!path) path = "/etc/steer/tgws-domains.lst";
    FILE *f = fopen(path, "r");
    if (!f) return;
    char line[160];
    while (g_alt_n < MAX_ALT && fgets(line, sizeof(line), f)) {
        char *p = line;
        while (*p == ' ' || *p == '\t') p++;
        p[strcspn(p, " \t\r\n")] = '\0';
        if (!*p || *p == '#') continue;
        snprintf(g_alt[g_alt_n], sizeof(g_alt[0]), "%s", p);
        g_alt_n++;
    }
    fclose(f);
    if (g_alt_n) fprintf(stderr, LOG_I "запасных доменов: %zu\n", g_alt_n);
}

/* Домен точек. Из спеки, а её может не быть (проба спеку не читает) — тогда из окружения,
 * иначе прямой. */
static char g_domain[128];
static void domain_init(const char *from_spec) {
    const char *env = getenv("STEER_TGWS_DOMAIN");
    const char *d = (from_spec && *from_spec) ? from_spec : (env && *env ? env : TGWS_DOMAIN_DEFAULT);
    snprintf(g_domain, sizeof(g_domain), "%s", d);
}

/* Имена точек ДЦ в порядке предпочтения: у медийного впереди `kwsN-1`, у обычного `kwsN`.
 * Их всегда два, и второй не запасной «на всякий случай»: медийную запись публикует не
 * каждый домен-посредник (проверено — у общественных её нет), и без отката медийные
 * дата-центры просто не работали бы. */
/* Имя точки: kwsN у обычного дата-центра, kwsN-1 у медийного.
 *
 * ВТОРЫМ КАНДИДАТОМ ИДЁТ ТОЧКА ДРУГОГО ВИДА, и это не небрежность. У самого Telegram записи
 * kwsN-1 есть, а у общественных доменов за Cloudflare их не завёл никто: из двадцати доменов
 * пула kws2-1 не отвечает ни один. Идти в таком случае напрямую нельзя — адреса медийных ДЦ
 * блокируют так же, как и остальные, — а ключ авторизации у медийного и обычного ДЦ с одним
 * номером общий, и файлы обычная точка отдаёт. Поэтому: сначала своя точка, потом соседняя,
 * и только если молчат обе — насквозь. */
static void tgws_hosts_at(const char *domain, int dc, int media, char out[2][160]) {
    snprintf(out[0], 160, "kws%d%s.%s", dc, media ? "-1" : "", domain);
    snprintf(out[1], 160, "kws%d%s.%s", dc, media ? "" : "-1", domain);
}

static void tgws_hosts(int dc, int media, char out[2][160]) {
    tgws_hosts_at(g_domain, dc, media, out);
}

/* Номер ДЦ по адресу назначения. 0 — адрес неизвестен, перехватывать нельзя. */
/* Самая длинная подходящая маска. Порядок записей в таблице при этом не важен — важно
 * только, насколько запись точна. */
static short dc_of(uint32_t ip, short *media) {
    short dc = 0;
    uint32_t best = 0;
    int have = 0;
    for (size_t i = 0; i < g_dc_n; i++) {
        if ((ip & g_dc[i].mask) != g_dc[i].ip) continue;
        uint32_t m = ntohl(g_dc[i].mask);
        if (have && m <= best) continue;
        best = m; have = 1;
        dc = g_dc[i].dc;
        *media = g_dc[i].media;
    }
    return dc;
}

/* ---- обфускация MTProto ------------------------------------------------------------ */

/* Гамма AES-256-CTR с начала потока: ключ [8..40], вектор [40..56] прямо из рукопожатия.
 * Сырые, без SHA-256 и без секрета, — так делает клиент, идущий в дата-центр напрямую, и
 * так же ждёт точка apiws. */
static int hs_keystream(const unsigned char hs[HS_LEN], unsigned char out[HS_LEN]) {
    mbedtls_aes_context aes;
    unsigned char nonce[16], sb[16], zeros[HS_LEN];
    size_t nc = 0;
    int rc;

    mbedtls_aes_init(&aes);
    memcpy(nonce, hs + 40, 16);
    memset(zeros, 0, sizeof(zeros));
    rc = mbedtls_aes_setkey_enc(&aes, hs + 8, 256);
    if (rc == 0) rc = mbedtls_aes_crypt_ctr(&aes, HS_LEN, &nc, nonce, sb, zeros, out);
    mbedtls_aes_free(&aes);
    return rc;
}

/* Разобрать рукопожатие и вписать в него номер ДЦ.
 *
 * Возвращает 1, если это MTProto (метка транспорта опознана) и хвост поправлен; 0 — если
 * нет: тогда соединение переливается на исходный адрес без перехвата. Метка нужна не ради
 * порядка — по ней отличается настоящий клиент от постороннего, случайно попавшего под
 * правило: перехватить чужое и увести в Telegram значило бы сломать чужое соединение. */
static int hs_patch_dc(unsigned char hs[HS_LEN], short dc, short media, unsigned char *tag) {
    unsigned char ks[HS_LEN];
    if (hs_keystream(hs, ks) != 0) return 0;

    unsigned char t[4];
    for (int i = 0; i < 4; i++) t[i] = hs[TAG_POS + i] ^ ks[TAG_POS + i];
    if (!((t[0] == 0xef && t[1] == 0xef && t[2] == 0xef && t[3] == 0xef) ||
          (t[0] == 0xee && t[1] == 0xee && t[2] == 0xee && t[3] == 0xee) ||
          (t[0] == 0xdd && t[1] == 0xdd && t[2] == 0xdd && t[3] == 0xdd)))
        return 0;
    *tag = t[0];

    int16_t idx = media ? (int16_t)-dc : (int16_t)dc;
    unsigned char d[2] = { (unsigned char)(idx & 0xff), (unsigned char)((idx >> 8) & 0xff) };
    hs[DC_POS + 0] = d[0] ^ ks[DC_POS + 0];
    hs[DC_POS + 1] = d[1] ^ ks[DC_POS + 1];
    return 1;
}

/* Собрать init так, как его строит клиент: ключ и вектор — сырые байты пакета, в хвосте
 * метка транспорта и номер ДЦ. Нужно ТОЛЬКО пробе: у моста init приходит от клиента готовым.
 * Запрещённые начала — те же, что отвергает Telegram (приняв их за HTTP или TLS). */
static int hs_build(unsigned char hs[HS_LEN], unsigned char tag, short dc, short media) {
    static const unsigned char BAD4[][4] = {
        { 'H','E','A','D' }, { 'P','O','S','T' }, { 'G','E','T',' ' },
        { 0xee,0xee,0xee,0xee }, { 0xdd,0xdd,0xdd,0xdd }, { 0x16,0x03,0x01,0x02 },
    };
    for (int tries = 0; tries < 64; tries++) {
        if (xc_random(hs, HS_LEN) != 0) return -1;
        if (hs[0] == 0xef) continue;
        int bad = 0;
        for (size_t i = 0; i < sizeof(BAD4) / sizeof(BAD4[0]); i++)
            if (!memcmp(hs, BAD4[i], 4)) bad = 1;
        if (bad) continue;
        if (!hs[4] && !hs[5] && !hs[6] && !hs[7]) continue;

        unsigned char ks[HS_LEN];
        if (hs_keystream(hs, ks) != 0) return -1;
        int16_t idx = media ? (int16_t)-dc : (int16_t)dc;
        unsigned char tail[8] = { tag, tag, tag, tag,
                                  (unsigned char)(idx & 0xff), (unsigned char)((idx >> 8) & 0xff),
                                  0, 0 };
        if (xc_random(tail + 6, 2) != 0) return -1;
        for (int i = 0; i < 8; i++) hs[TAG_POS + i] = tail[i] ^ ks[TAG_POS + i];
        return 0;
    }
    return -1;
}

/* ---- транспорт: TLS либо голый сокет ----------------------------------------------
 *
 * Голый нужен стенду: поднимать в нём настоящий TLS означало бы проверять чужую библиотеку
 * вместо своего моста. Включается STEER_TGWS_PLAIN=1 и в бою не встречается. */
/* Код последней неудачи TLS — только для сообщений: без него «не поднялось» неотличимо от
 * «узел молчит», а это разные причины с разными действиями. */
static int g_tls_rc;

struct upstream {
    int fd;
    struct tls13 tls;
    int tls_on;
};

static int up_write(struct upstream *u, const unsigned char *p, size_t n) {
    if (u->tls_on) return tls13_write(&u->tls, p, n) == 0 ? (int)n : -1;
    size_t off = 0;
    while (off < n) {
        ssize_t w = send(u->fd, p + off, n - off, MSG_NOSIGNAL);
        if (w <= 0) { if (errno == EINTR) continue; return -1; }
        off += (size_t)w;
    }
    return (int)n;
}

/* Возвращает число байт, 0 — «пока нечего, приходи снова», -1 — конец или отказ.
 *
 * TLS13_EAGAIN здесь ОБЯЗАН отличаться от отказа, и это не мелочь: он значит «целой записи в
 * сокете ещё нет», а не поломку. Первая версия считала его отказом — и апгрейд веб-сокета
 * падал на живой точке, которая отвечала 101 (проверено вручную через openssl): ответ просто
 * не успевал прийти целиком к первому чтению. */
static int up_read(struct upstream *u, unsigned char *p, size_t cap) {
    if (u->tls_on) {
        size_t got = 0;
        int rc = tls13_read(&u->tls, p, cap, &got);
        if (rc == TLS13_EAGAIN) return 0;
        if (rc != 0) { g_tls_rc = rc; return -1; }
        return (int)got;
    }
    ssize_t r = recv(u->fd, p, cap, 0);
    if (r < 0 && (errno == EAGAIN || errno == EWOULDBLOCK || errno == EINTR)) return 0;
    return r > 0 ? (int)r : -1;
}

/* ---- WebSocket (RFC 6455), ровно столько, сколько нужно ---------------------------
 *
 * Нужны только бинарные кадры в обе стороны, ping/pong и close. Расширений (permessage-
 * deflate) не запрашиваем: сжимать нечего — внутри шифрованный поток, — а согласование
 * добавило бы состояние на ровном месте. */

static void b64(const unsigned char *in, size_t n, char *out) {
    static const char A[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    size_t i = 0, o = 0;
    for (; i + 2 < n; i += 3) {
        out[o++] = A[in[i] >> 2];
        out[o++] = A[((in[i] & 3) << 4) | (in[i + 1] >> 4)];
        out[o++] = A[((in[i + 1] & 15) << 2) | (in[i + 2] >> 6)];
        out[o++] = A[in[i + 2] & 63];
    }
    if (i < n) {
        out[o++] = A[in[i] >> 2];
        if (i + 1 < n) {
            out[o++] = A[((in[i] & 3) << 4) | (in[i + 1] >> 4)];
            out[o++] = A[(in[i + 1] & 15) << 2];
        } else {
            out[o++] = A[(in[i] & 3) << 4];
            out[o++] = '=';
        }
        out[o++] = '=';
    }
    out[o] = '\0';
}

/* Рукопожатие HTTP: Upgrade к /apiws.
 *
 * Заголовки — те же, что шлёт веб-клиент Telegram (Origin и подпротокол `binary`): точка
 * `apiws` их ждёт, а нам заодно незачем выглядеть иначе, чем браузер, который к ней и ходит.
 *
 * Ответ читаем до пустой строки и сверяем только «101». Sec-WebSocket-Accept не проверяем
 * нарочно: он защищает от кэширующего посредника, принявшего апгрейд за обычный ответ, а у
 * нас поверх TLS посредника нет, и SHA-1 ради одной проверки в сборку тянуть незачем. */
static int ws_upgrade(struct upstream *u, const char *host) {
    unsigned char nonce[16];
    char key[32], req[512];
    /* Ответ читается в буфер под целую запись TLS: см. TLS_REC_MAX. В куче, а не на стеке, —
     * поток моста живёт со стеком в 128 КБ, и 17 КБ на кадр установления там лишние. */
    char *resp = malloc(TLS_REC_MAX + 1);
    if (!resp) return -1;
#define WS_UP_FAIL(...) do { fprintf(stderr, __VA_ARGS__); free(resp); return -1; } while (0)

    if (xc_random(nonce, sizeof(nonce)) != 0) return -1;
    b64(nonce, sizeof(nonce), key);

    int n = snprintf(req, sizeof(req),
                     "GET /apiws HTTP/1.1\r\n"
                     "Host: %s\r\n"
                     "Upgrade: websocket\r\n"
                     "Connection: Upgrade\r\n"
                     "Sec-WebSocket-Key: %s\r\n"
                     "Sec-WebSocket-Version: 13\r\n"
                     "Sec-WebSocket-Protocol: binary\r\n"
                     "Origin: https://web.telegram.org\r\n"
                     "User-Agent: Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 "
                     "(KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36\r\n"
                     "\r\n", host, key);
    if (n <= 0) WS_UP_FAIL(LOG_W "запрос не собрался\n");
    if (up_write(u, (unsigned char *)req, (size_t)n) < 0) WS_UP_FAIL(LOG_W "запрос не ушёл\n");

    size_t got = 0;
    for (int round = 0; round < 200; round++) {
        if (TLS_REC_MAX - got < 1) WS_UP_FAIL(LOG_W "ответ на апгрейд не влез\n");
        int r = up_read(u, (unsigned char *)resp + got, TLS_REC_MAX - got);
        if (r < 0) WS_UP_FAIL(LOG_W "чтение ответа отказало (код %d)\n", g_tls_rc);
        if (r == 0) {
            /* Записи ещё нет — ждём событие на сокете, а не крутим цикл: у моста это путь
             * установления, и занимать им процессор роутера незачем. */
            struct pollfd p = { .fd = u->fd, .events = POLLIN, .revents = 0 };
            if (!(u->tls_on && tls13_has_record(&u->tls)) && poll(&p, 1, 100) < 0)
                WS_UP_FAIL(LOG_W "ожидание ответа прервано\n");
            continue;
        }
        got += (size_t)r;
        resp[got] = '\0';
        if (strstr(resp, "\r\n\r\n")) break;
    }
    if (!strstr(resp, "\r\n\r\n"))
        WS_UP_FAIL(LOG_W "ответа на апгрейд нет (получено %zu байт)\n", got);
    if (strncmp(resp, "HTTP/1.1 101", 12) != 0) {
        char *e = strchr(resp, '\r');
        if (e) *e = '\0';
        WS_UP_FAIL(LOG_W "%s: апгрейд отклонён (%s)\n", host, resp);
    }
    free(resp);
#undef WS_UP_FAIL
    /* Тело после заголовков быть не должно: сервер отвечает 101 и молчит до первого кадра.
     * Если что-то пришло, это уже кадры — но их приход раньше нашего init означал бы, что
     * мы говорим не с той точкой, и разбирать это нечем. */
    return 0;
}

/* Кадр от клиента ОБЯЗАН быть замаскирован (RFC 6455 §5.3) — сервер рвёт соединение иначе. */
static int ws_send(struct upstream *u, const unsigned char *p, size_t n) {
    unsigned char hdr[14];
    size_t h = 0;
    unsigned char mask[4];

    if (xc_random(mask, 4) != 0) return -1;
    hdr[h++] = 0x82;                                  /* FIN + binary */
    if (n < 126) hdr[h++] = (unsigned char)(0x80 | n);
    else if (n < 65536) {
        hdr[h++] = 0x80 | 126;
        hdr[h++] = (unsigned char)(n >> 8);
        hdr[h++] = (unsigned char)(n & 0xff);
    } else {
        hdr[h++] = 0x80 | 127;
        for (int i = 7; i >= 0; i--) hdr[h++] = (unsigned char)((uint64_t)n >> (i * 8));
    }
    memcpy(hdr + h, mask, 4);
    h += 4;

    /* Заголовок и тело — ОДНОЙ записью. Раздельно это две записи TLS и два сегмента TCP на
     * каждый кадр: лишний круг на пустом месте там, где кадры мелкие и частые (а переписка
     * такая и есть). */
    unsigned char buf[BUF_N + sizeof(hdr)];
    size_t off = 0;
    while (off < n || (off == 0 && n == 0)) {
        size_t part = n - off;
        if (part > BUF_N) part = BUF_N;
        size_t at = 0;
        if (off == 0) { memcpy(buf, hdr, h); at = h; }
        for (size_t i = 0; i < part; i++) buf[at + i] = p[off + i] ^ mask[(off + i) & 3];
        if (up_write(u, buf, at + part) < 0) return -1;
        off += part;
        if (n == 0) break;
    }
    return 0;
}

/* Приём кадров: накапливаем, пока не соберётся заголовок и тело.
 *
 * Свой буфер, а не чтение по байту: TLS отдаёт запись целиком, и в ней бывает несколько
 * кадров — читая по одному, второй оставляли бы ждать события, которого может не быть. */
struct ws_rx {
    /* Кадр веб-сокета плюс запас под целую запись TLS: читать в остаток меньше записи
     * нельзя (см. TLS_REC_MAX). */
    unsigned char buf[BUF_N * 2 + TLS_REC_MAX];
    size_t n;
    /* Тело кадра, которое ещё не дошло до клиента. Кадр НЕ обязан помещаться в буфер
     * целиком — см. пояснение у ws_head. */
    size_t pend;
    int    pend_op;
};

/* Разбор ЗАГОЛОВКА кадра, без требования, чтобы тело уже пришло целиком.
 *
 * ПОЧЕМУ ТЕЛО НЕ СОБИРАЕТСЯ В БУФЕР. Раньше кадр, не влезший в буфер (около 50 КБ), считался
 * ошибкой и обрывал соединение. Переписка в такие кадры не попадает никогда, а кусок файла —
 * всегда: клиент просит их по 128 КБ и по 512 КБ. Снаружи это выглядело ровно так, как
 * рассказал владелец: «подключается-отключается раз в 2-3 секунды, медиа не грузится».
 * Собирать такой кадр целиком незачем и нечем — за ним поток, а не сообщение: тело
 * переливается по мере прихода, а буфер держит только заголовок и то, что уже прочитано.
 *
 * 1 — заголовок разобран, 0 — нужно ещё читать, -1 — ошибка. */
static int ws_head(struct ws_rx *rx, size_t *need, size_t *plen, int *opcode) {
    if (rx->n < 2) return 0;
    unsigned char b1 = rx->buf[1];
    size_t hn = 2, n = b1 & 0x7f;
    if (b1 & 0x80) return -1;                         /* сервер маскировать не должен */
    if (n == 126) {
        if (rx->n < 4) return 0;
        n = ((size_t)rx->buf[2] << 8) | rx->buf[3];
        hn = 4;
    } else if (n == 127) {
        if (rx->n < 10) return 0;
        n = 0;
        for (int i = 0; i < 8; i++) n = (n << 8) | rx->buf[2 + i];
        hn = 10;
    }
    *opcode = rx->buf[0] & 0x0f;
    /* Управляющий кадр по RFC 6455 §5.5 не длиннее 125 байт и не дробится — его ждём
     * целиком, иначе отвечать нечем. */
    if (*opcode & 0x8) {
        if (n > 125) return -1;
        if (rx->n < hn + n) return 0;
    }
    *need = hn;
    *plen = n;
    return 1;
}

static void ws_consume(struct ws_rx *rx, size_t used) {
    memmove(rx->buf, rx->buf + used, rx->n - used);
    rx->n -= used;
}

/* ---- соединение с точкой apiws ---------------------------------------------------- */

static int tcp_connect(const char *host, const char *port, int timeout_s) {
    struct addrinfo hints, *res = NULL, *it;
    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_INET;                        /* IPv6 к ДЦ пока не перехватываем */
    hints.ai_socktype = SOCK_STREAM;
    if (getaddrinfo(host, port, &hints, &res) != 0) return -1;

    int fd = -1;
    for (it = res; it; it = it->ai_next) {
        fd = socket(it->ai_family, SOCK_STREAM, 0);
        if (fd < 0) continue;
        struct timeval tv = { .tv_sec = timeout_s, .tv_usec = 0 };
        setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
        setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));
        if (connect(fd, it->ai_addr, it->ai_addrlen) == 0) break;
        close(fd);
        fd = -1;
    }
    freeaddrinfo(res);
    if (fd >= 0) {
        int one = 1;
        setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, &one, sizeof(one));
    }
    return fd;
}

/* TLS 1.3 с обликом Chrome. Hello собирает reality.c — тот же, что у клиента VLESS, и это
 * не переиспользование ради экономии: отпечаток браузера должен жить в одном месте, иначе
 * две копии однажды разъедутся, а симптомом будет не ошибка, а молчаливая блокировка.
 *
 * session_id заполняется случайными байтами через носитель: аутентификатор Reality здесь не
 * нужен и не имеет смысла — мы говорим с настоящим Cloudflare, а не с сервером Reality. */
static int sid_random(void *ctx, unsigned char sid[32], const unsigned char *hs, size_t hs_n,
                      const unsigned char shared[32]) {
    (void)ctx; (void)hs; (void)hs_n; (void)shared;
    return xc_random(sid, 32);
}

static int tls_start(struct upstream *u, const char *sni) {
    unsigned char priv[32], pub[32], hello[4096];
    size_t hello_n = 0;
    /* Постоянный ключ «сервера» не используется (см. sid_random), но сборщику Hello он нужен
     * как вход. Подставляем ОДНОРАЗОВЫЙ, но настоящий: случайные 32 байта — не обязательно
     * точка на кривой, и умножение на них отвергается (проверено: REALITY_ECRYPTO). Секрет,
     * посчитанный с ним, никуда не идёт — session_id заполняет sid_random. */
    unsigned char throwaway[32], fake_pbk[32];
    char pbk_b64[64];
    if (xc_x25519_keypair(throwaway, fake_pbk) != 0) { g_tls_rc = -103; return -1; }
    b64(fake_pbk, sizeof(fake_pbk), pbk_b64);
    for (char *p = pbk_b64; *p; p++) {                /* base64url, как ждёт reality.c */
        if (*p == '+') *p = '-';
        else if (*p == '/') *p = '_';
        else if (*p == '=') { *p = '\0'; break; }
    }

    if (xc_x25519_keypair(priv, pub) != 0) { g_tls_rc = -101; return -1; }
    struct reality_cfg cfg = { .sni = sni, .pbk = pbk_b64, .sid = "", .fp = "chrome",
                               .alpn = "http/1.1" };
    struct reality_state st;
    /* ALPN только http/1.1: с обычной парой Cloudflare выбирает h2, и апгрейд по HTTP/1.1
     * для неё мусор (см. поле alpn_http11 в reality.h — там же, как это выяснилось). */
    struct reality_carrier car = { .priv = priv, .pub = pub, .fill_sid = sid_random,
                                   .alpn_http11 = 1 };
    int hrc = reality_build_hello_carry(&cfg, &st, &car, hello, sizeof(hello), &hello_n);
    if (hrc != 0) { g_tls_rc = -200 + hrc; return -1; }
    if (up_write(u, hello, hello_n) < 0) { g_tls_rc = -102; return -1; }
    memset(&u->tls, 0, sizeof(u->tls));
    g_tls_rc = tls13_handshake(&u->tls, u->fd, hello, hello_n, priv);
    if (g_tls_rc != 0) return -1;
    u->tls_on = 1;
    return 0;
}

/* ---- переливание -------------------------------------------------------------------
 *
 * Обе стороны в одном цикле poll: отдельный поток на направление стоил бы второго стека и
 * согласования закрытия ради ровно той же работы. */
static void pump(int cfd, struct upstream *u) {
    struct ws_rx rx;
    unsigned char buf[BUF_N];
    rx.n = 0;
    rx.pend = 0;
    rx.pend_op = 0;

    for (;;) {
        struct pollfd p[2];
        p[0].fd = cfd;   p[0].events = POLLIN;  p[0].revents = 0;
        p[1].fd = u->fd; p[1].events = POLLIN;  p[1].revents = 0;
        /* Записи TLS могут уже лежать у нас в буфере — тогда ждать события на сокете
         * нельзя, иначе хвост ответа простоит до таймаута клиента (та же ловушка, что
         * закрыта в tls13_has_record). */
        int wait = (u->tls_on && tls13_has_record(&u->tls)) ? 0 : 60000;
        if (poll(p, 2, wait) < 0) {
            if (errno == EINTR) continue;
            return;
        }

        if (p[0].revents & POLLIN) {
            ssize_t r = recv(cfd, buf, sizeof(buf), 0);
            if (r <= 0) return;
            if (ws_send(u, buf, (size_t)r) < 0) return;
        }

        if ((p[1].revents & POLLIN) || wait == 0) {
            /* Места всегда хватает: разбор ниже опустошает буфер до заголовка следующего
             * кадра, а тело через него только протекает. */
            if (sizeof(rx.buf) - rx.n >= TLS_REC_MAX) {
                int r = up_read(u, rx.buf + rx.n, sizeof(rx.buf) - rx.n);
                if (r < 0) return;
                if (r > 0) rx.n += (size_t)r;
            }
            for (;;) {
                /* Хвост предыдущего кадра идёт вперёд заголовков: пока он не дошёл до
                 * клиента, следующего кадра в потоке нет. */
                if (rx.pend) {
                    size_t take = rx.n < rx.pend ? rx.n : rx.pend;
                    if (!take) break;
                    if (rx.pend_op == 0x1 || rx.pend_op == 0x2 || rx.pend_op == 0x0) {
                        size_t off = 0;
                        while (off < take) {
                            ssize_t w = send(cfd, rx.buf + off, take - off, MSG_NOSIGNAL);
                            if (w <= 0) { if (errno == EINTR) continue; return; }
                            off += (size_t)w;
                        }
                    }
                    ws_consume(&rx, take);
                    rx.pend -= take;
                    continue;
                }

                size_t need, len;
                int op;
                int h = ws_head(&rx, &need, &len, &op);
                if (h == 0) break;
                if (h < 0) return;
                if (op == 0x8) return;                /* close */
                if (op == 0x9) {                      /* ping — отвечаем тем же телом */
                    unsigned char pong[128];
                    size_t pn = len > sizeof(pong) ? sizeof(pong) : len;
                    memcpy(pong, rx.buf + need, pn);
                    ws_consume(&rx, need + len);
                    /* pong — управляющий кадр, но маскировка та же; тело копируем заранее,
                     * потому что ws_consume сдвигает буфер под ним. */
                    unsigned char hdr[6];
                    hdr[0] = 0x8a;
                    hdr[1] = (unsigned char)(0x80 | pn);
                    unsigned char mask[4];
                    if (xc_random(mask, 4) != 0) return;
                    memcpy(hdr + 2, mask, 4);
                    if (up_write(u, hdr, 6) < 0) return;
                    for (size_t i = 0; i < pn; i++) pong[i] ^= mask[i & 3];
                    if (pn && up_write(u, pong, pn) < 0) return;
                    continue;
                }
                if (op & 0x8) { ws_consume(&rx, need + len); continue; }  /* прочее управление */

                ws_consume(&rx, need);
                rx.pend = len;
                rx.pend_op = op;
            }
        }
        if ((p[0].revents | p[1].revents) & (POLLERR | POLLHUP)) {
            if (!rx.n) return;
        }
    }
}

/* Переливание без перехвата: соединение уходит туда, куда шло. Так обрабатывается всё, чего
 * мост не понял, — неизвестный адрес ДЦ, не-MTProto, недоступная точка apiws. Молча рвать
 * такое нельзя: под правило попадает трафик человека, и «Telegram не работает» из-за нашей
 * осторожности ничем не лучше блокировки. */
static void relay_direct(int cfd, const struct sockaddr_in *dst,
                         const unsigned char *pre, size_t pre_n) {
    int fd = socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0) return;
    struct timeval tv = { .tv_sec = UP_TIMEOUT_S, .tv_usec = 0 };
    setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
    setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));
    if (connect(fd, (const struct sockaddr *)dst, sizeof(*dst)) != 0) { close(fd); return; }
    if (pre_n) {
        size_t off = 0;
        while (off < pre_n) {
            ssize_t w = send(fd, pre + off, pre_n - off, MSG_NOSIGNAL);
            if (w <= 0) { close(fd); return; }
            off += (size_t)w;
        }
    }
    unsigned char buf[BUF_N];
    for (;;) {
        struct pollfd p[2];
        p[0].fd = cfd; p[0].events = POLLIN; p[0].revents = 0;
        p[1].fd = fd;  p[1].events = POLLIN; p[1].revents = 0;
        if (poll(p, 2, 60000) <= 0) break;
        for (int i = 0; i < 2; i++) {
            if (!(p[i].revents & POLLIN)) continue;
            int from = i ? fd : cfd, to = i ? cfd : fd;
            ssize_t r = recv(from, buf, sizeof(buf), 0);
            if (r <= 0) goto out;
            size_t off = 0;
            while (off < (size_t)r) {
                ssize_t w = send(to, buf + off, (size_t)r - off, MSG_NOSIGNAL);
                if (w <= 0) goto out;
                off += (size_t)w;
            }
        }
        if ((p[0].revents | p[1].revents) & (POLLERR | POLLHUP)) break;
    }
out:
    close(fd);
}

/* ---- одно соединение ---------------------------------------------------------------- */

struct job { int fd; };
static volatile int g_live;
static pthread_mutex_t g_mu = PTHREAD_MUTEX_INITIALIZER;

static void *serve(void *arg) {
    struct job *j = arg;
    int cfd = j->fd;
    free(j);

    struct sockaddr_in dst;
    socklen_t dl = sizeof(dst);
    unsigned char hs[HS_LEN];
    size_t got = 0;
    short media = 0, dc = 0;
    unsigned char tag = 0;

    /* Куда клиент шёл на самом деле. Правило redirect подменило адрес, а исходный ядро
     * помнит — без него номер дата-центра взять неоткуда. */
    if (getsockopt(cfd, SOL_IP, SO_ORIGINAL_DST, &dst, &dl) != 0) {
        fprintf(stderr, LOG_W "исходный адрес не узнать (%s) — соединение закрыто\n",
                strerror(errno));
        goto done;
    }

    struct timeval tv = { .tv_sec = UP_TIMEOUT_S, .tv_usec = 0 };
    setsockopt(cfd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
    setsockopt(cfd, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));
    /* Без этого Nagle придерживает хвост каждой порции до подтверждения предыдущей, а
     * задержанное подтверждение на той стороне добавляет к этому до двухсот миллисекунд.
     * Соединению вверх NODELAY ставится в tcp_connect с самого начала, а вот принятому от
     * клиента не ставился, и платил за это ровно тот трафик, который через мост идёт:
     * снаружи это «часть картинки пришла, потом пауза на пару секунд, потом остальное». */
    { int one = 1; setsockopt(cfd, IPPROTO_TCP, TCP_NODELAY, &one, sizeof(one)); }

    while (got < HS_LEN) {
        ssize_t r = recv(cfd, hs + got, HS_LEN - got, 0);
        if (r <= 0) goto done;
        got += (size_t)r;
    }

    char dsts[INET_ADDRSTRLEN] = "?";
    inet_ntop(AF_INET, &dst.sin_addr, dsts, sizeof(dsts));
    dc = dc_of(dst.sin_addr.s_addr, &media);
    if (!dc) {
        fprintf(stderr, LOG_I "%s: не наш дата-центр — пропускаю как есть\n", dsts);
        relay_direct(cfd, &dst, hs, got);
        goto done;
    }
    if (!hs_patch_dc(hs, dc, media, &tag)) {
        fprintf(stderr, LOG_I "%s: это не MTProto — пропускаю как есть\n", dsts);
        relay_direct(cfd, &dst, hs, got);
        goto done;
    }

    /* Куда идём. Имя точки — kwsN[-1].<домен>, оно же SNI и Host; АДРЕС подключения обычно
     * тот же, но стенду его задают отдельно (там поднят свой сервер на петле). */
    char cand[2][160];
    const char *port = "443";
    const char *ep = getenv("STEER_TGWS_ENDPOINT");
    char epbuf[160];
    /* Домены по порядку: свой, потом запасные. Больше трёх не пробуем — человек ждёт
     * соединения, а не полного обхода списка. */
    const char *doms[1 + MAX_ALT];
    size_t didx[1 + MAX_ALT];
    size_t dom_n = 0;
    time_t now = time(NULL);
    /* Два прохода: сначала домены без свежего отказа, потом остальные. Так очередь
     * переупорядочивается, но ни один домен из неё не выпадает — «все в отказе» это
     * состояние сети, а не повод не пробовать. */
    for (int pass = 0; pass < 2 && dom_n < 3; pass++) {
        if ((pass == 0) == (dom_ok_now(0, now) != 0)) { doms[dom_n] = g_domain; didx[dom_n++] = 0; }
        for (size_t i = 0; i < g_alt_n && dom_n < 3; i++) {
            if (!strcmp(g_alt[i], g_domain)) continue;
            if ((pass == 0) != (dom_ok_now(i + 1, now) != 0)) continue;
            doms[dom_n] = g_alt[i]; didx[dom_n++] = i + 1;
        }
    }
    tgws_hosts(dc, media, cand);
    if (ep) {
        snprintf(epbuf, sizeof(epbuf), "%s", ep);
        char *c = strchr(epbuf, ':');
        if (c) { *c = '\0'; port = c + 1; }
    }

    struct upstream u;
    int ok = 0;
    const char *sni = cand[0];
    for (size_t d = 0; d < dom_n && !ok; d++) {
        if (d || doms[0] != g_domain) tgws_hosts_at(doms[d], dc, media, cand);
        for (int i = 0; i < 2 && !ok; i++) {
            sni = cand[i];
            memset(&u, 0, sizeof(u));
            u.fd = tcp_connect(ep ? epbuf : sni, port, UP_TIMEOUT_S);
            if (u.fd < 0) continue;
            if (!getenv("STEER_TGWS_PLAIN") && tls_start(&u, sni) != 0) {
                fprintf(stderr, LOG_W "%s: TLS не поднялся (код %d)\n", sni, g_tls_rc);
                close(u.fd);
                continue;
            }
            if (ws_upgrade(&u, sni) != 0 || ws_send(&u, hs, HS_LEN) < 0) {
                if (u.tls_on) tls13_free(&u.tls);
                close(u.fd);
                continue;
            }
            ok = 1;
        }
        if (!ok) g_bad[didx[d]] = time(NULL) + ALT_COOLDOWN_S;
    }
    if (!ok) {
        /* Пропустить насквозь — единственный честный ответ. Точки нет, а отправить
         * соединение в чужую значит сломать его наверняка; напрямую же оно сломано только
         * там, где провайдер этот адрес и правда режет. */
        fprintf(stderr, LOG_W "%s: точка ДЦ%d%s недоступна — пропускаю как есть\n",
                cand[0], dc, media ? "m" : "");
        relay_direct(cfd, &dst, hs, got);
        goto done;
    }

    fprintf(stderr, LOG_I "%s -> ДЦ%d%s через %s (транспорт 0x%02x)\n",
            dsts, dc, media ? "m" : "", sni, tag);
    pump(cfd, &u);
    if (u.tls_on) tls13_free(&u.tls);
    close(u.fd);

done:
    close(cfd);
    pthread_mutex_lock(&g_mu);
    g_live--;
    pthread_mutex_unlock(&g_mu);
    return NULL;
}

/* ---- проверка пути до Telegram -------------------------------------------------------
 *
 * ЗАЧЕМ ОТДЕЛЬНАЯ КОМАНДА. Стенд (tests/run-tgws.sh) закрывает половину пути — перехват,
 * разбор рукопожатия, кадры веб-сокета, — но точку `apiws` он подделывает, а TLS в нём
 * выключен. Вторая половина проверяется только против настоящего Telegram, и на роутере это
 * единственный способ отличить «мост цел, узел закрыт» от «мост сломан». Без такой команды
 * ответом на «Telegram не работает» было бы гадание.
 *
 * ЧТО СЧИТАЕТСЯ ОТВЕТОМ. Не 101 на апгрейд — его отдаст и посторонний веб-сервер, — а
 * настоящий обмен MTProto: посылаем незашифрованный req_pq_multi и ждём resPQ. Это первое
 * сообщение любого клиента Telegram, и ответить на него может только дата-центр.
 *
 * ЗДЕСЬ, В ОТЛИЧИЕ ОТ МОСТА, ПОТОК ШИФРУЕТСЯ НАМИ. Мост переливает чужой поток и ключей не
 * касается; пробе шифровать нечем, кроме как самой: она сама себе клиент. Ключи по той же
 * схеме — свои из [8..56] init, чужие из [8..56] ПЕРЕВЁРНУТОГО init. */

struct obf {
    mbedtls_aes_context enc, dec;
    unsigned char nce[16], ncd[16], sbe[16], sbd[16];
    size_t oe, od;
};

static int obf_init(struct obf *o, const unsigned char hs[HS_LEN]) {
    unsigned char rev[HS_LEN];
    for (int i = 0; i < HS_LEN; i++) rev[i] = hs[HS_LEN - 1 - i];
    mbedtls_aes_init(&o->enc);
    mbedtls_aes_init(&o->dec);
    memcpy(o->nce, hs + 40, 16);
    memcpy(o->ncd, rev + 40, 16);
    o->oe = o->od = 0;
    if (mbedtls_aes_setkey_enc(&o->enc, hs + 8, 256) != 0) return -1;
    if (mbedtls_aes_setkey_enc(&o->dec, rev + 8, 256) != 0) return -1;
    /* Промотать 64 байта гаммы надо ТОЛЬКО шифрующему направлению: их съел наш собственный
     * init, который ушёл в сеть. Поток сервера к нам начинается с нуля — он нам никакого
     * init не слал. Промотав оба, получаешь расшифровку со сдвигом: снято пробой против
     * настоящего Telegram — ответ приходил, но выглядел шумом. */
    unsigned char skip[HS_LEN], zero[HS_LEN];
    memset(zero, 0, sizeof(zero));
    if (mbedtls_aes_crypt_ctr(&o->enc, HS_LEN, &o->oe, o->nce, o->sbe, zero, skip) != 0)
        return -1;
    return 0;
}

static void obf_free(struct obf *o) {
    mbedtls_aes_free(&o->enc);
    mbedtls_aes_free(&o->dec);
}

/* Транспорт intermediate (0xee): четыре байта длины, дальше тело. Взят он, а не padded, ровно
 * потому, что набивки в нём нет — пробе нечего проверять в наполнителе. */
static int probe_send(struct upstream *u, struct obf *o,
                      const unsigned char *body, size_t n) {
    unsigned char pkt[256], enc[256];
    if (n + 4 > sizeof(pkt)) return -1;
    pkt[0] = (unsigned char)(n & 0xff);
    pkt[1] = (unsigned char)((n >> 8) & 0xff);
    pkt[2] = (unsigned char)((n >> 16) & 0xff);
    pkt[3] = (unsigned char)((n >> 24) & 0xff);
    memcpy(pkt + 4, body, n);
    if (mbedtls_aes_crypt_ctr(&o->enc, n + 4, &o->oe, o->nce, o->sbe, pkt, enc) != 0)
        return -1;
    return ws_send(u, enc, n + 4);
}

int cmd_tgws_probe(int dc, int media) {
    if (dc < 1 || dc > 9) { fprintf(stderr, LOG_W "номер ДЦ: 1..5\n"); return 2; }
    domain_init(NULL);

    char cand[2][160], host[160];
    const char *port = "443";
    const char *ep = getenv("STEER_TGWS_ENDPOINT");
    tgws_hosts(dc, media, cand);
    const char *sni = cand[0];

    struct upstream u;
    memset(&u, 0, sizeof(u));
    u.fd = -1;
    for (int i = 0; i < 2 && u.fd < 0; i++) {
        sni = cand[i];
        if (ep) {
            snprintf(host, sizeof(host), "%s", ep);
            char *c = strchr(host, ':');
            if (c) { *c = '\0'; port = c + 1; }
        } else {
            snprintf(host, sizeof(host), "%s", sni);
        }
        printf("точка:      %s:%s\n", host, port);
        u.fd = tcp_connect(host, port, UP_TIMEOUT_S);
        if (u.fd < 0) printf("            не соединиться (%s)\n", strerror(errno));
        if (ep) break;
    }
    if (u.fd < 0) { printf("итог:       ни одна точка не отвечает\n"); return 1; }
    printf("соединение: есть\n");

    if (!getenv("STEER_TGWS_PLAIN")) {
        if (tls_start(&u, sni) != 0) {
            printf("итог:       TLS не поднялся (код %d)\n", g_tls_rc);
            close(u.fd);
            return 1;
        }
        printf("TLS 1.3:    есть (SNI %s, сертификат не проверяется — см. tgws.c)\n", sni);
    }
    /* Разведочный режим: TLS подняли и молчим. Нужен ровно для одного вопроса — приходит ли
     * отказ узла ДО нашего запроса; ответ на него разделяет «не нравится рукопожатие» и «не
     * нравится запрос», а это разные починки. */
    if (getenv("STEER_TGWS_NOREQ")) {
        unsigned char probe_buf[4096];
        for (int i = 0; i < 20; i++) {
            int r = up_read(&u, probe_buf, sizeof(probe_buf));
            if (r < 0) { printf("после TLS: узел закрыл сам (код %d)\n", g_tls_rc); break; }
            if (r > 0) { printf("после TLS: узел прислал %d байт до запроса\n", r); break; }
            struct pollfd pp = { .fd = u.fd, .events = POLLIN, .revents = 0 };
            if (poll(&pp, 1, 100) < 0) break;
        }
        printf("итог:       разведка закончена\n");
        if (u.tls_on) tls13_free(&u.tls);
        close(u.fd);
        return 0;
    }
    if (ws_upgrade(&u, sni) != 0) {
        printf("итог:       апгрейд WebSocket отклонён\n");
        if (u.tls_on) tls13_free(&u.tls);
        close(u.fd);
        return 1;
    }
    printf("WebSocket:  апгрейд принят (/apiws)\n");

    unsigned char hs[HS_LEN];
    struct obf o;
    if (hs_build(hs, 0xee, (short)dc, (short)media) != 0 || obf_init(&o, hs) != 0) {
        printf("итог:       не собрать рукопожатие\n");
        goto bad;
    }
    if (ws_send(&u, hs, HS_LEN) < 0) { printf("итог:       init не ушёл\n"); goto bad; }

    /* req_pq_multi#be7e8ef1 nonce:int128 — первое сообщение любого клиента, шлётся без
     * шифрования прикладного слоя: auth_key_id = 0, дальше идентификатор сообщения, длина и
     * тело. Идентификатор — время в старших 32 битах, кратный четырём (так требует протокол
     * от клиента). */
    unsigned char body[40], nonce[16];
    if (xc_random(nonce, sizeof(nonce)) != 0) goto bad;
    memset(body, 0, 8);                                  /* auth_key_id = 0 */
    uint64_t mid = ((uint64_t)time(NULL) << 32) & ~3ull;
    for (int i = 0; i < 8; i++) body[8 + i] = (unsigned char)(mid >> (8 * i));
    body[16] = 20; body[17] = 0; body[18] = 0; body[19] = 0;   /* длина тела */
    body[20] = 0xf1; body[21] = 0x8e; body[22] = 0x7e; body[23] = 0xbe;  /* req_pq_multi */
    memcpy(body + 24, nonce, 16);
    if (probe_send(&u, &o, body, 40) < 0) { printf("итог:       запрос не ушёл\n"); goto bad; }
    printf("req_pq_multi: отправлен\n");

    struct ws_rx rx;
    rx.n = 0;
    for (int round = 0; round < 40; round++) {
        struct pollfd p = { .fd = u.fd, .events = POLLIN, .revents = 0 };
        int wait = (u.tls_on && tls13_has_record(&u.tls)) ? 0 : 500;
        if (wait && poll(&p, 1, wait) <= 0) continue;
        if (sizeof(rx.buf) - rx.n < TLS_REC_MAX) break;
        int r = up_read(&u, rx.buf + rx.n, sizeof(rx.buf) - rx.n);
        if (r < 0) break;
        if (r == 0) continue;
        rx.n += (size_t)r;
        for (;;) {
            unsigned char *pl;
            size_t need, len;
            int op;
            /* Пробе хватает кадра целиком: resPQ — четыре с небольшим десятка байт. */
            if (ws_head(&rx, &need, &len, &op) != 1) break;
            if (rx.n < need + len) break;
            size_t used = need + len;
            pl = rx.buf + need;
            if (op == 0x2 && len > 8) {
                unsigned char dec[512];
                size_t n = len > sizeof(dec) ? sizeof(dec) : len;
                if (mbedtls_aes_crypt_ctr(&o.dec, n, &o.od, o.ncd, o.sbd, pl, dec) != 0) goto bad;
                /* resPQ#05162463 — первые четыре байта ТЕЛА, а тело начинается за заголовком:
                 * 4 байта длины транспорта + 8 auth_key_id + 8 message_id + 4 длины тела =
                 * 24. Смещение снято с живого ответа, а не выведено из документации. */
                if (n >= 28 && dec[24] == 0x63 && dec[25] == 0x24 && dec[26] == 0x16 &&
                    dec[27] == 0x05) {
                    printf("ответ:      resPQ, %zu байт\n", n);
                    printf("итог:       дата-центр %d%s отвечает через веб-сокет\n",
                           dc, media ? " (медийный)" : "");
                    obf_free(&o);
                    if (u.tls_on) tls13_free(&u.tls);
                    close(u.fd);
                    return 0;
                }
                printf("ответ:      %zu байт, но это не resPQ; начало:", n);
                for (size_t k = 0; k < (n < 28 ? n : 28); k++) printf(" %02x", dec[k]);
                printf("\n");
                goto bad;
            }
            ws_consume(&rx, used);
        }
    }
    printf("итог:       ответа нет (точка молчит)\n");
bad:
    obf_free(&o);
    if (u.tls_on) tls13_free(&u.tls);
    close(u.fd);
    return 1;
}

/* ---- служба ------------------------------------------------------------------------- */

int cmd_tgws(const char *spec, const char *name) {
    if (!name || !*name) { fprintf(stderr, LOG_W "нужно имя выхода\n"); return 2; }
    load_spec(spec);
    registry_assign();

    const struct output *o = NULL;
    for (size_t i = 0; i < g_out_n; i++)
        if (!strcmp(g_out[i].name, name)) { o = &g_out[i]; break; }
    if (!o) { fprintf(stderr, LOG_W "нет выхода %s\n", name); return 2; }
    if (o->kind != OUT_TGWS) {
        fprintf(stderr, LOG_W "выход %s не kind=tgws\n", name);
        return 2;
    }

    dc_table_init();
    domain_init(o->tg_domain);
    alt_init();
    int port = out_tgws_port(o);

    int srv = socket(AF_INET, SOCK_STREAM, 0);
    if (srv < 0) { perror("socket"); return 1; }
    int one = 1;
    setsockopt(srv, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one));
    struct sockaddr_in a;
    memset(&a, 0, sizeof(a));
    a.sin_family = AF_INET;
    a.sin_addr.s_addr = htonl(INADDR_ANY);
    a.sin_port = htons((uint16_t)port);
    if (bind(srv, (struct sockaddr *)&a, sizeof(a)) != 0) {
        fprintf(stderr, LOG_W "порт %d занят (%s)\n", port, strerror(errno));
        close(srv);
        return 1;
    }
    if (listen(srv, 32) != 0) { perror("listen"); close(srv); return 1; }

    fprintf(stderr, LOG_I "%s: жду перехваченные соединения на :%d, домен %s, адресов ДЦ %zu\n",
            name, port, g_domain, g_dc_n);

    signal(SIGPIPE, SIG_IGN);
    for (;;) {
        int fd = accept(srv, NULL, NULL);
        if (fd < 0) {
            if (errno == EINTR) continue;
            break;
        }
        pthread_mutex_lock(&g_mu);
        int live = g_live;
        if (live < MAX_CONNS) g_live++;
        pthread_mutex_unlock(&g_mu);
        if (live >= MAX_CONNS) {
            fprintf(stderr, LOG_W "разом больше %d соединений — отказ\n", MAX_CONNS);
            close(fd);
            continue;
        }
        struct job *j = malloc(sizeof(*j));
        if (!j) { close(fd); continue; }
        j->fd = fd;
        pthread_t t;
        pthread_attr_t at;
        pthread_attr_init(&at);
        pthread_attr_setdetachstate(&at, PTHREAD_CREATE_DETACHED);
        /* 128 КБ вместо восьми мегабайт по умолчанию: на роутере с 64 МБ памяти
         * шестьдесят четыре потока по умолчанию — это полтора гигабайта адресов. */
        pthread_attr_setstacksize(&at, 128 * 1024);
        if (pthread_create(&t, &at, serve, j) != 0) {
            pthread_mutex_lock(&g_mu);
            g_live--;
            pthread_mutex_unlock(&g_mu);
            close(fd);
            free(j);
        }
        pthread_attr_destroy(&at);
    }
    close(srv);
    return 0;
}
