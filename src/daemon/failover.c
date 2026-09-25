/* steer failover — выбрать живое устройство для каждого выхода.
 *
 * Не демон. Один проход по вызову, состояние — в маршрутных таблицах ядра и в
 * реестре. Так же, как apply: движок остаётся компилятором, а «раз в минуту» —
 * дело того, кто его вызывает (init-скрипт ставит таймер).
 *
 * Порядок devices — приоритет. Первое здоровое устройство побеждает, поэтому
 * восстановление наверх происходит само: как только основной туннель ожил, он
 * снова оказывается первым здоровым, и следующий проход вернётся на него.
 *
 * Проверка НЕ трогает живой путь. Пинг уходит через отдельную таблицу с правилом
 * по адресу источника кандидата — иначе, чтобы проверить запасной туннель, пришлось
 * бы сначала переключиться на него, то есть уронить работающий ради вопроса
 * «работает ли другой».
 *
 * Проход не только выбирает устройство, но и СВЕРЯЕТ фактическую маршрутизацию выхода с
 * тем, какой она должна быть, — правило fwmark и содержимое таблицы. Состояние здесь
 * самовосстанавливающееся, а не поправляемое по событию, и почему именно так — подробно
 * в комментарии «сверка фактического состояния маршрутизации» ниже.
 */
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/wait.h>
#include <fcntl.h>
#include <time.h>
#include <errno.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <arpa/inet.h>
#include <poll.h>
#include <net/if.h>
#include <ifaddrs.h>
#include <signal.h>
#include <sys/stat.h>
#include "spec.h"
#include "awg.h"
#include "run.h"

/* Уровень в журнале приписывается КАЖДОЙ строке — это контракт, по которому управляющий
 * слой (splify2) раскрашивает журнал, и он разбирает именно префикс, а не текст. Базовый
 * движок его не ставил вовсе, хотя контракт обещал: интерфейс из-за этого подписывал все
 * свежие строки про переключение устройств как «от более старого движка». */
#define LOG_W "steer[warn] failover: "
#define LOG_I "steer[info] failover: "

/* Таблица и приоритет правила для проб. Далеко от 300+, которые раздаёт реестр:
 * проба обязана быть невидимой для боевой маршрутизации. */
#define PROBE_TABLE 299
/* Приоритет правила пробы — из spec.h (STEER_PROBE_PREF): на Android он обязан стоять ниже
 * лестницы правил netd, на роутере остаётся прежним 29999. */
#define PROBE_PRIO  STEER_PROBE_PREF

/* Куда пинговать. Два адреса, потому что один может быть заблокирован именно в
 * этом туннеле, и тогда здоровый путь выглядел бы мёртвым. */
static const char *PROBE_TARGETS[] = { "1.1.1.1", "8.8.8.8", NULL };

/* Чтение вывода команды — определено ниже, у сверки состояния; нужно и привязке таблицы. */
static void ip_show(const char *cmd, char *out, size_t n);

/* Адрес источника устройства: без него правило пробы не к чему привязать, а само
 * отсутствие адреса уже означает, что устройство не готово нести трафик. */
static int device_src(const char *dev, char *out, size_t n) {
    struct ifaddrs *ifaddr, *ifa;
    int found = 0;

    if (getifaddrs(&ifaddr) == -1) return 0;

    for (ifa = ifaddr; ifa != NULL && !found; ifa = ifa->ifa_next) {
        if (ifa->ifa_addr == NULL) continue;
        if (ifa->ifa_addr->sa_family == AF_INET && strcmp(ifa->ifa_name, dev) == 0) {
            struct sockaddr_in *s4 = (struct sockaddr_in *)ifa->ifa_addr;
            if (inet_ntop(AF_INET, &s4->sin_addr, out, n) != NULL) {
                found = 1;
            }
        }
    }
    freeifaddrs(ifaddr);
    return found;
}

static int device_present(const char *dev) {
    char path[128];
    snprintf(path, sizeof(path), "/sys/class/net/%s/operstate", dev);
    FILE *f = fopen(path, "r");
    if (!f) return 0;
    char st[16] = "";
    int up = fgets(st, sizeof(st), f) && strncmp(st, "down", 4) != 0;
    fclose(f);
    return up;
}

/* Доступен ли внешний адрес ПО TCP через данное устройство.
 *
 * Зачем отдельная проверка, а не device_healthy: VLESS-туннель пропускает ТОЛЬКО TCP
 * (клиент завершает TCP у себя и соединяется с сервером обычным сокетом — ICMP сквозь
 * него не идёт принципиально). device_healthy пингует ICMP, и для выхода kind=vless
 * отвечал «мёртв» на полностью рабочем туннеле: на живом роутере это выглядело как
 * вечное «vl: не отвечает — перезапускаю интерфейс» в журнале и гоняло ifdown/ifup
 * по устройству, которым netifd вовсе не управляет.
 *
 * SO_BINDTODEVICE привязывает сокет именно к этому устройству, не полагаясь на метки и
 * таблицы маршрутизации: проба обязана идти тем путём, который мы проверяем. Неблокирующий
 * connect с poll — чтобы на чёрной дыре не стоять дольше таймаута. */
/* ЧЕТВЁРТЫЙ АРГУМЕНТ — задержка в миллисекундах, необязателен (NULL — не мерить).
 *
 * Мера берётся ЗДЕСЬ, а не рядом с вызовом: интересует время до установления соединения, а
 * не время работы функции. На неудачном кандидате разница между ними — целый таймаут.
 *
 * CLOCK_MONOTONIC, а не время суток: подводка часов ntpd на только что поднявшемся роутере —
 * обычное дело, и замер по стенным часам дал бы отрицательную задержку. */
static int tcp_reachable(const char *dev, const char *host, int port, int timeout_s,
                         int *out_ms) {
    if (out_ms) *out_ms = -1;
    struct timespec t0;
    clock_gettime(CLOCK_MONOTONIC, &t0);
    struct in_addr a;
    if (inet_aton(host, &a) == 0) return 0;
    int fd = socket(AF_INET, SOCK_STREAM | SOCK_NONBLOCK | SOCK_CLOEXEC, 0);
    if (fd < 0) return 0;
    if (setsockopt(fd, SOL_SOCKET, SO_BINDTODEVICE, dev, strlen(dev) + 1) != 0) {
        close(fd);
        return 0;
    }
    struct sockaddr_in sa = { .sin_family = AF_INET, .sin_port = htons((uint16_t)port),
                              .sin_addr = a };
    int ok = 0;
    int rc = connect(fd, (struct sockaddr *)&sa, sizeof(sa));
    if (rc == 0) ok = 1;                          /* соединилось мгновенно — обычно сосед по L2 */
    else if (errno == EINPROGRESS) {
        struct pollfd pw = { .fd = fd, .events = POLLOUT, .revents = 0 };
        if (poll(&pw, 1, timeout_s * 1000) > 0) {
            int err = 0; socklen_t el = sizeof(err);
            if (getsockopt(fd, SOL_SOCKET, SO_ERROR, &err, &el) == 0 && err == 0)
                ok = 1;
        }
    }
    close(fd);
    if (ok && out_ms) {
        struct timespec t1;
        clock_gettime(CLOCK_MONOTONIC, &t1);
        long ms = (t1.tv_sec - t0.tv_sec) * 1000 + (t1.tv_nsec - t0.tv_nsec) / 1000000;
        if (ms < 0) ms = 0;
        if (ms > 1000000) ms = 1000000;
        *out_ms = (int)ms;
    }
    return ok;
}

/* Живо ли устройство на самом деле. operstate у туннеля почти всегда "unknown" и
 * остаётся таким, когда пир давно молчит, — поэтому решает пакет, дошедший до
 * настоящего адреса, а не то, что о себе сообщает интерфейс. */
static int device_healthy(const char *dev) {
    if (!device_present(dev)) return 0;
    char src[64];
    if (!device_src(dev, src, sizeof(src))) return 0;

    char tbl[16], prio[16];
    snprintf(tbl, sizeof(tbl), "%d", PROBE_TABLE);
    snprintf(prio, sizeof(prio), "%d", PROBE_PRIO);

    const char *del[] = { "ip", "-4", "rule", "del", "from", src, "table", tbl,
                          "priority", prio, NULL };
    run_quiet(del);
    const char *rt[] = { "ip", "-4", "route", "replace", "default", "dev", dev,
                         "table", tbl, NULL };
    run_quiet(rt);
    const char *add[] = { "ip", "-4", "rule", "add", "from", src, "table", tbl,
                          "priority", prio, NULL };
    run_quiet(add);

    int ok = 0;
    for (int i = 0; PROBE_TARGETS[i] && !ok; i++) {
        const char *p[] = { "ping", "-c", "1", "-W", "3", "-I", dev, "-q",
                            PROBE_TARGETS[i], NULL };
        ok = run_quiet(p) == 0;
    }

    /* Убрать за собой обязательно: оставленное правило пробы пережило бы этот
     * процесс и молча увело бы трафик источника в таблицу, которую никто больше
     * не наполняет. */
    run_quiet(del);
    const char *flush[] = { "ip", "-4", "route", "flush", "table", tbl, NULL };
    run_quiet(flush);
    return ok;
}

/* УСТРОЙСТВО XSTEER, ПОДНЯТОЕ NETIFD: как его узнать и что о нём известно.
 *
 * Один и тот же туннель бывает поднят двумя способами, и только один из них виден спеке.
 * Выход `kind: xsteer` поднимает сам движок — там всё понятно по виду выхода. Но splify2
 * поднимает туннель ИНАЧЕ: обычным интерфейсом netifd с proto xsteer
 * (splify2/files/lib/netifd/proto/xsteer.sh), и в спеке такой туннель значится просто
 * именем устройства в пуле выхода `kind: interface`. Слова «xsteer» в спеке при этом нет
 * нигде, и решение по `o->kind` до него не доходит.
 *
 * Чем это кончалось на живом роутере (10.8.1.1): интерфейс `xs0`, устройство `xs-xs0`,
 * `ping 8.8.8.8 -I xs-xs0` идёт, а выход, в пуле которого это устройство стоит первым, на
 * него не переключается. Сторож судил исправный туннель пингом наружу — той самой пробой,
 * которая для xsteer запрещена (см. device_healthy_for: хаб полной звезды имеет право
 * маршрутизировать только между пирами), — а «чинил» его `ifdown` по имени УСТРОЙСТВА,
 * которого netifd не знает вовсе: интерфейс зовётся xs0, устройство — xs-xs0, и ответ на
 * это один, «Interface not found».
 *
 * ПРИЗНАК — ФАЙЛ СОСТОЯНИЯ, а не имя. Клиент пишет <state_dir>/xsteer-<устройство>.json
 * (src/proto/xsteer/xsclient.c, state_write), и шапка там прямо говорит, что файл этот — для
 * сторожа. Файл есть — значит устройство создал наш процесс, каким бы способом его ни
 * подняли. Приставка «xs-» в признак не годится: имя устройства задаёт настройка
 * (device_name), а «xs-<интерфейс>» — всего лишь её умолчание. Тот же признак, тем же
 * путём и по тому же файлу, читает splify2 в методе xsteer_state.
 *
 * Выход `kind: xsteer` сюда не попадает и не должен: у него файл назван по имени ВЫХОДА, а
 * не устройства, и приговор ему выносится раньше, по виду. */
#define XS_STATE_STALE 30

/* 1 — файл состояния этого устройства есть. `up` получает «хотя бы одно соединение с хабом
 * живо», `fresh` — писался ли файл недавно. Оба указателя необязательны.
 *
 * Разбор — поиском подстроки, а не разбором JSON, и это не лень: файл пишет одна функция в
 * этом же дереве, одной строкой и без вложенности, а поле `up` в ней ровно одно. Тащить
 * сюда разборщик ради двух слов значило бы завести вторую схему того же файла. */
static int xs_state_read(const char *dev, int *up, int *fresh) {
    char path[320];
    snprintf(path, sizeof(path), "%s/xsteer-%.40s.json", g_state_dir, dev);
    struct stat sb;
    if (stat(path, &sb) != 0) return 0;
    if (fresh) *fresh = (long)(time(NULL) - sb.st_mtime) <= XS_STATE_STALE;
    if (up) {
        *up = 0;
        FILE *f = fopen(path, "r");
        if (f) {
            char line[1024] = "";
            if (fgets(line, sizeof(line), f)) *up = strstr(line, "\"up\":true") != NULL;
            fclose(f);
        }
    }
    return 1;
}

/* Живо ли устройство. Выход передаётся, но решает не он: чем проверять, определяет вид
 * ВЛАДЕЛЬЦА устройства (см. device_owner ниже), и только у устройства без владельца это
 * совпадает с видом выхода, который его назвал.
 *
 * Для kind=interface (wireguard, openvpn и т.п.)
 * ICMP годится: ядро проксирует его вместе с TCP/UDP. Для kind=vless ICMP НЕ проходит
 * вовсе — туннель завершает TCP у себя и наружу соединяется сокетом, поэтому пинг к
 * внешнему адресу через VLESS-устройство всегда теряется. Та же самая «не отвечает» на
 * рабочем туннеле, что и с masquerade для traceroute, только по отношению к ICMP целиком.
 *
 * Поэтому VLESS проверяем TCP-рукопожатием к знакомому адресату: это ровно то, что туннель
 * и пропускает, и ровно то, что делает реальный трафик. Два кандидата — на случай, когда
 * один адрес недоступен именно в этом туннеле (та же причина, что у PROBE_TARGETS). */
#define TCP_PROBE_PORT 80
#define TCP_PROBE_TIMEOUT 4

/* Шов замера — симметрично шву здоровья и по той же причине: стенду нужно задавать
 * задержки кандидатов, не поднимая сокетов. В бою указатель NULL и меряет device_latency. */
static int (*g_latency_probe)(const struct output *, const char *);

/* ЗАДЕРЖКА КАНДИДАТА в миллисекундах, -1 — не измерилась.
 *
 * Меряется соединением TCP через само устройство (SO_BINDTODEVICE) к PROBE_TARGETS — тем же
 * механизмом, которым уже проверяется здоровье выхода kind=vless. Не ping'ом: тот идёт через
 * временное правило ip rule, и время его установки и снятия перекрыло бы измеряемое. И не
 * своим протоколом: время до установления соединения — ровно то, что меряет urltest у
 * sing-box запросом на generate_204.
 *
 * Берётся ЛУЧШИЙ из целей, а не первый ответивший: цели в разных сетях, и «первая ответила
 * за 300 мс» на канале, где вторая отвечает за 20, — это не задержка канала.
 *
 * xsteer не меряется НИКОГДА, и это то же решение, что у его здоровья: PROBE_TARGETS — это
 * проверка интернета У ХАБА, а хаб полной звезды имеет право маршрутизировать только между
 * пирами. Замер дал бы -1 на исправном туннеле, то есть выбросил бы его из сравнения.
 * Возврат -1 честнее: вызывающий на нём откатывается к порядку. */
static int device_latency(const struct output *o, const char *dev) {
    if (g_latency_probe) return g_latency_probe(o, dev);
    if (!device_present(dev)) return -1;
    o = out_for_device(o, dev);
    /* И тот же туннель, поднятый netifd, — по тому же доводу: мерить его нечем, а число
     * из пробы наружу означало бы не задержку туннеля, а наличие интернета у хаба. */
    if (o->kind == OUT_XSTEER || xs_state_read(dev, NULL, NULL)) return -1;
    int best = -1;
    for (int i = 0; PROBE_TARGETS[i]; i++) {
        int ms = -1;
        if (tcp_reachable(dev, PROBE_TARGETS[i], TCP_PROBE_PORT, TCP_PROBE_TIMEOUT, &ms) &&
            ms >= 0 && (best < 0 || ms < best))
            best = ms;
    }
    return best;
}

/* Владелец устройства. Объяснение — у объявления в spec.h; там же сказано, почему функция
 * объявлена рядом со спекой, а живёт здесь (тот же случай, что bind_device). */
const struct output *device_owner(const char *dev) {
    for (size_t i = 0; i < g_out_n; i++) {
        const struct output *c = &g_out[i];
        if (!out_engine_managed(c)) continue;
        if (!strcmp(c->device, dev)) return c;
        for (size_t k = 0; k < c->devices_n; k++)
            if (!strcmp(c->devices[k], dev)) return c;
    }
    return NULL;
}

const struct output *out_for_device(const struct output *o, const char *dev) {
    const struct output *owner = device_owner(dev);
    return owner ? owner : o;
}

static int device_healthy_for(const struct output *o, const char *dev);
/* Проба здоровья вызывается через указатель, а не напрямую, ровно ради одного: стенд
 * гистерезиса задаёт здоровье устройств по тику, не создавая интерфейсов в /sys и не открывая
 * сокетов. В бою указатель НИКОГДА не меняется и всегда ссылается на device_healthy_for —
 * ветка предсказуемая, той же природы, что швы путей для стендов в остальном коде. */
static int (*g_health_probe)(const struct output *, const char *);
static int health_of(const struct output *o, const char *dev) {
    return g_health_probe ? g_health_probe(o, dev) : device_healthy_for(o, dev);
}

static int device_healthy_for(const struct output *o, const char *dev) {
    if (!device_present(dev)) return 0;
    /* Мера здоровья принадлежит УСТРОЙСТВУ, а не виду выхода, который его назвал: у
     * устройства с владельцем спрашиваем так, как спросил бы владелец. Для выхода,
     * владеющего своим устройством сам, это тот же ответ, что и раньше. */
    o = out_for_device(o, dev);
    /* xsteer НЕ проверяется ни PROBE_TARGETS, ни пробой TCP, и это не недоделка.
     *
     * PROBE_TARGETS — публичные адреса, то есть проверка интернета У ХАБА. Хаб полной
     * звезды имеет право маршрутизировать только между пирами: у такого выхода
     * AllowedIPs это, скажем, 10.0.0.0/8, и пинг 1.1.1.1 через его устройство теряется на
     * полностью исправном туннеле. При on_fail=drop (умолчании) сторож поставил бы
     * blackhole работающему выходу — то есть сам сломал бы то, что охраняет. Проба TCP,
     * как у vless, проверила бы ровно то же самое и с тем же итогом.
     *
     * Правильная мера здоровья здесь — возраст последнего рукопожатия с хабом, и её
     * источник (файл состояния, который пишет сам процесс) появляется вместе с клиентом.
     * До тех пор приговор даёт наличие устройства: устройство создаёт наш процесс, и
     * пропало оно — значит процесса нет. Это не полная проверка, но она никогда не врёт в
     * сторону «сломано», а именно эта сторона здесь дорого стоит. */
    if (o->kind == OUT_XSTEER) return 1;
    /* Туннель в ядре, заведённый движком (kind=awg): мера — свежесть рукопожатия и счётчики
     * пира, которые ядро и так ведёт, без единого пакета от нас. Ни ping, ни проба TCP: и то и
     * другое будило бы радио телефона ради вопроса, на который ответ уже лежит в ядре, — см.
     * «здоровье» в src/kinds/awg.c, там же почему старое рукопожатие само по себе не приговор. */
    if (o->kind == OUT_AWG) return awg_healthy(o, dev);
    /* Тот же туннель, поднятый netifd (см. xs_state_read выше). Спека про него знает только
     * имя устройства, а про рукопожатие с хабом знает его собственный клиент — и пишет это в
     * свой файл. Приговор отдаётся файлу целиком: пинг наружу здесь запрещён ровно по той же
     * причине, что и у выхода kind=xsteer.
     *
     * Устаревший файл (писавшего процесса нет) возвращает нас к наличию устройства — оно
     * проверено выше и сюда мы попали только потому, что устройство есть. Врать в сторону
     * «сломано» здесь дороже всего: при on_fail=drop это blackhole работающему выходу. А
     * умерший клиент устройства за собой не оставляет — netifd сносит его следом, и это
     * видно в журнале роутера строкой «Network device 'xs-xs0' link is down». */
    {
        int up = 0, fresh = 0;
        if (xs_state_read(dev, &up, &fresh)) return fresh ? up : 1;
    }
    if (o->kind == OUT_VLESS) {
        for (int i = 0; PROBE_TARGETS[i]; i++)
            if (tcp_reachable(dev, PROBE_TARGETS[i], TCP_PROBE_PORT, TCP_PROBE_TIMEOUT, NULL))
                return 1;
        return 0;
    }
    return device_healthy(dev);
}

/* Куда направить таблицу выхода, когда живых устройств нет.
 *
 * drop   — blackhole: трафик канала останавливается заметно и никуда не утекает;
 * direct — правило снимается, трафик идёт как обычный (осознанный выбор);
 * zapret — то же, что direct, но нужен работающий обход DPI, иначе это просто
 *          direct под другим именем, о чём и сообщаем. */
#include <dirent.h>
#include <ctype.h>

/* Есть ли в системе процесс, командная строка которого содержит NEEDLE.
 *
 * Вынесено из zapret_running, потому что тот же обход /proc понадобился второму
 * спрашивающему — выходу kind=zapret, которому нужен не «работает ли обход вообще», а
 * «жив ли обработчик МОЕЙ очереди». Два обхода /proc с двумя копиями разбора cmdline
 * разошлись бы на первой же правке (буфер, замена нулей, пропуск не-цифр).
 *
 * Почему вообще /proc, а не вопрос ядру: списка «кто слушает очередь nfqueue N» ядро не
 * отдаёт ни через netlink, ни через /proc/net/netfilter/nfnetlink_queue (там номер очереди
 * и pid, но только для очередей, через которые уже прошёл пакет, — то есть у поднятого и
 * ещё не нагруженного обработчика запись отсутствует). Командная строка с --qnum=N
 * отвечает на тот же вопрос и отвечает всегда. */
static int cmdline_find(const char *needle, int digit_end);
static int cmdline_has(const char *needle) { return cmdline_find(needle, 0); }

/* NEEDLE в командной строке какого-нибудь процесса. digit_end — требовать, чтобы сразу за
 * NEEDLE не стояла цифра: так «--qnum=830» перестаёт находиться в «--qnum=8300». */
static int cmdline_find(const char *needle, int digit_end) {
    DIR *d = opendir("/proc");
    if (!d) return 0;
    struct dirent *dir;
    int found = 0;
    char path[300];
    char buf[512];

    while ((dir = readdir(d)) != NULL && !found) {
        if (!isdigit(dir->d_name[0])) continue;
        snprintf(path, sizeof(path), "/proc/%s/cmdline", dir->d_name);
        int fd = open(path, O_RDONLY | O_CLOEXEC);
        if (fd >= 0) {
            ssize_t n = read(fd, buf, sizeof(buf) - 1);
            if (n > 0) {
                buf[n] = '\0';
                for (ssize_t i = 0; i < n; i++) {
                    if (buf[i] == '\0') buf[i] = ' ';
                }
                for (const char *q = strstr(buf, needle); q; q = strstr(q + 1, needle)) {
                    char after = q[strlen(needle)];
                    if (digit_end && after >= '0' && after <= '9') continue;
                    found = 1;
                    break;
                }
            }
            close(fd);
        }
    }
    closedir(d);
    return found;
}

static int zapret_running(void) { return cmdline_has("nfqws"); }

/* Жив ли обработчик ИМЕННО ЭТОЙ очереди.
 *
 * Ищется «--qnum=N» целиком, вместе с ключом, и это не педантизм: подстрока «8300» нашлась
 * бы и в чужом пути, и в номере другой очереди (83001), а ответ «выход работает» о мёртвом
 * обходе — худший из возможных, потому что трафик при этом уходит и выглядит ушедшим. */
int nfqws_on_queue(int queue) {
    char needle[32];
    snprintf(needle, sizeof(needle), "--qnum=%d", queue);
    return cmdline_find(needle, 1);
}

/* ---- правило маршрутизации выхода: одно место на четыре вызывающих ---------------
 *
 * Зачем функциями, а не строками на месте: команд четыре пары (apply, уборка мёртвых
 * правил, отказ выхода, привязка устройства), и добавление маски строками означало бы
 * четыре шанса забыть её в одном месте. Почему маска вообще — в spec.h у STEER_MARK_MASK.
 */
void rule_add(unsigned mark, int table) {
    char m[32], t[16];
    snprintf(m, sizeof(m), "0x%08x/0x%08x", mark, STEER_MARK_MASK);
    snprintf(t, sizeof(t), "%d", table);
    /* Приоритет — только если сборка его задаёт (STEER_RULE_PREF, spec.h): на роутере его нет,
     * и команда остаётся прежней до последнего слова. rule_drop приоритета не называет и
     * снимает правило при любом. */
    if (STEER_RULE_PREF) {
        char pr[16];
        snprintf(pr, sizeof(pr), "%d", STEER_RULE_PREF);
        const char *addp[] = { "ip", "rule", "add", "fwmark", m, "table", t,
                               "priority", pr, NULL };
        run_quiet(addp);
        return;
    }
    const char *add[] = { "ip", "rule", "add", "fwmark", m, "table", t, NULL };
    run_quiet(add);
}

/* Снять установленные соединения ЭТОГО выхода.
 *
 * ЗАЧЕМ. Пакеты установленного соединения могут не доходить до нашей цепочки вовсе — так
 * работает выгрузка потоков (flow_offloading в firewall4): после установления соединение
 * идёт быстрым путём с ingress, то есть РАНЬШЕ prerouting. Замерено на живом роутере
 * (10.8.1.87, OpenWrt 25.12, ядро 6.12): цепочка разметки видит 2-7 пакетов вместо
 * одиннадцати тысяч, а поток после подмены таблицы на запрет в одном прогоне из трёх
 * продолжал идти на 613-666 Мбит/с. То есть смена устройства выхода и запрет on_fail=drop
 * для УЖЕ установленных соединений не срабатывают, а выключить выгрузку целиком дорого:
 * тот же замер дал 287-329 Мбит/с против 613-666.
 *
 * КАК. Снятие записи conntrack убирает и её выгрузку: следующий пакет соединения идёт
 * обычным путём, проходит нашу цепочку и получает решение заново. Отбор строго по НАШЕЙ
 * метке с НАШЕЙ маской — то есть по выходу; чужие соединения не трогаются. Возможно это
 * стало только с `ct mark set mark` в правиле (см. generate в steer.c). Тем же приёмом и по
 * той же причине пользуется mwan3.
 *
 * ЧЕМ. Сначала сам движок, через ctnetlink (ctnl_evict_mark в dnsd.c): дамп записей с нашей
 * меткой и снятие каждой по её кортежу. Так на ЛЮБОЙ сборке, а не только на Android, где
 * инструмента conntrack в образе нет вовсе: один путь на всех проверяется каждым стендом, а
 * два пути, выбранных по сборке, расходились бы молча. И это дешевле — ни fork, ни exec, ни
 * разбора аргументов: сторож на телефоне работает на батарее.
 *
 * Внешний `conntrack -D --mark` остаётся запасным — на случай, когда ctnetlink недоступен:
 * на роутере без модуля nf_conntrack_netlink (в OpenWrt это отдельный kmod) сокет открывается,
 * а подсистема conntrack в нём не отвечает. Если нет и инструмента — предупреждаем ОДИН раз за
 * процесс и работаем как раньше: маршрутизация верна для новых соединений, а установленные
 * доживают свой век. Делать зависимость обязательной незачем: на роутере без выгрузки потоков
 * и без долгих соединений разница незаметна. */
void conntrack_evict(unsigned mark) {
    static int warned;
    if (ctnl_evict_mark(mark, STEER_MARK_MASK) >= 0) return;
    char sel[48];
    /* Десятичными, а не 0x: проверено на живом роутере — `conntrack -D --mark 1048576/267386880`
     * снимает записи, и это та форма, которая там сработала. */
    snprintf(sel, sizeof(sel), "%u/%u", mark, (unsigned)STEER_MARK_MASK);
    const char *del[] = { "conntrack", "-D", "--mark", sel, NULL };
    if (run_quiet(del) == 0) return;
    /* Ненулевой код возврата означает и «инструмента нет», и «нечего было снимать» — второе
     * обычное дело, поэтому жалуемся только если инструмента действительно нет. */
    const char *probe[] = { "conntrack", "--version", NULL };
    if (run_quiet(probe) == 0 || warned) return;
    warned = 1;
    fprintf(stderr, LOG_W "снять соединения выхода нечем: ядро не отвечает по ctnetlink (нет "
                    "модуля nf_conntrack_netlink?), инструмента conntrack тоже нет. Смена "
                    "маршрута выхода не снимает уже установленные соединения: с включённой "
                    "выгрузкой потоков (flow_offloading) они продолжат идти прежним путём — "
                    "поставьте пакет conntrack\n");
}

void rule_drop(unsigned mark, int table) {
    char m[32], legacy[24], t[16];
    snprintf(m, sizeof(m), "0x%08x/0x%08x", mark, STEER_MARK_MASK);
    snprintf(legacy, sizeof(legacy), "0x%08x", mark);
    snprintf(t, sizeof(t), "%d", table);
    /* В цикле, потому что `ip rule add` дубликаты не проверяет и копий может быть
     * несколько; до отказа — он и означает «больше таких нет». */
    const char *del[] = { "ip", "rule", "del", "fwmark", m, "table", t, NULL };
    while (run_quiet(del) == 0) ;
    /* Прежняя форма БЕЗ маски: она осталась в ядре от версии до R-094. Снять её обязан
     * тот же вызов — иначе на одну метку легли бы два правила, и какое из них поймает
     * пакет, решал бы приоритет, а не замысел. Через несколько версий строку можно
     * убрать; пока роутеры обновляются, она и есть весь механизм перехода. */
    const char *dell[] = { "ip", "rule", "del", "fwmark", legacy, "table", t, NULL };
    while (run_quiet(dell) == 0) ;
}

/* ---- таблица и правило выхода БЕЗ МГНОВЕНИЯ ПУСТОТЫ -----------------------------------
 *
 * ЧТО БЫЛО. Привязка выхода к устройству (bind_device, apply_routing, отказ drop в
 * apply_failed) делала `rule_drop` → `rule_add` и `ip route flush table N` → `ip route add
 * default dev X table N`. Каждая пара — это два запуска ip, то есть миллисекунды, и в эти
 * миллисекунды у помеченного трафика не было ни правила, ни маршрута в таблице. А нет правила
 * или пуста таблица — значит «ищи дальше»: пакет с меткой выхода уходит по таблице main, то
 * есть НАПРЯМУЮ, мимо туннеля. На стенде так утекло рукопожатие WireGuard, а при on_fail=drop
 * утекает ровно то, что человек запретил пускать мимо туннеля. Перепривязка случается не раз в
 * жизни: смена устройства пула, каждый apply, каждая починка разъехавшейся маршрутизации,
 * подъём TUN помощником.
 *
 * КАК ТЕПЕРЬ. Маршрут меняется одной командой `ip route replace` — ядро подменяет запись на
 * месте (и тип тоже: blackhole на устройство и обратно, проверено на 6.8 и 4.9), поэтому
 * таблица не бывает пустой ни на миг; всё лишнее, что в ней было, снимается ПОСЛЕ. Правило не
 * снимается вовсе, если оно уже стоит: недостающее добавляется, а лишние копии и прежние формы
 * (без маски, не на своём приоритете) снимаются после того, как верная копия есть. Одинаковые
 * правила в ядре ничего не решают друг за друга, так что «сначала добавить, потом снять» —
 * это и есть «ровно одна копия без мгновения, когда нет ни одной».
 *
 * Что нужно прочитать для этого — `ip -4 rule show` и `ip -4 route show table N` — сторож и
 * так читает на сверке; здесь это одно чтение на привязку, а привязка случается по событию. */

/* Сколько в ядре копий НАШЕГО правила: метка и маска наши, таблица наша (номер или имя, как у
 * route_facts_of — имя из rt_tables.d разрешить нечем, а метку с нашей маской ставим только
 * мы), на телефоне — и приоритет наш. pref[] — приоритеты найденных копий, чтобы лишние
 * снимались точно, по приоритету, а не «первая попавшаяся». wrong[] — наше правило на чужом
 * приоритете: осталось от сборки, где приоритет выбирало ядро. Чистая функция — стенд
 * failovermatch. */
#define RULE_COPIES_MAX 8
struct rule_copies {
    int known;                      /* дамп прочитан (пустым он на живой коробке не бывает) */
    int n;                          /* верных копий */
    unsigned long pref[RULE_COPIES_MAX];
    int wrong_n;                    /* копий на чужом приоритете */
    unsigned long wrong[RULE_COPIES_MAX];
    int legacy_n;                   /* прежняя форма без маски (см. rule_drop) */
    unsigned long legacy[RULE_COPIES_MAX];
};

static struct rule_copies rule_copies_of(const char *rules, uint32_t mark, int table) {
    struct rule_copies c;
    memset(&c, 0, sizeof c);
    c.known = rules && rules[0] != '\0';
    if (!c.known) return c;
    char want_tbl[16];
    snprintf(want_tbl, sizeof(want_tbl), "%d", table);
    for (const char *ln = rules; ln && *ln; ) {
        const char *end = strchr(ln, '\n');
        size_t len = end ? (size_t)(end - ln) : strlen(ln);
        char line[512];
        size_t n = len < sizeof(line) - 1 ? len : sizeof(line) - 1;
        memcpy(line, ln, n);
        line[n] = '\0';
        ln = end ? end + 1 : NULL;

        char *stop = NULL;
        unsigned long pref = strtoul(line, &stop, 10);
        if (!stop || *stop != ':') continue;
        const char *fm = strstr(line, "fwmark ");
        if (!fm) continue;
        unsigned long got = strtoul(fm + 7, &stop, 16);
        if (!stop || (uint32_t)got != mark) continue;
        /* Без маски — прежняя форма (ядро печатает маску 0xffffffff никак). Её снимают, но не
         * считают верной копией — см. rule_ensure. */
        int legacy = *stop != '/';
        if (!legacy && (uint32_t)strtoul(stop + 1, NULL, 16) != STEER_MARK_MASK) continue;
        const char *lk = strstr(line, "lookup ");
        if (!lk) continue;
        const char *t = lk + 7;
        size_t tl = strcspn(t, " \t");
        int numeric = tl > 0;
        for (size_t i = 0; i < tl; i++)
            if (!isdigit((unsigned char)t[i])) numeric = 0;
        if (numeric && (tl != strlen(want_tbl) || strncmp(t, want_tbl, tl) != 0)) continue;
        if (legacy) {
            if (c.legacy_n < RULE_COPIES_MAX) c.legacy[c.legacy_n++] = pref;
            continue;
        }
        if (STEER_RULE_PREF && pref != (unsigned long)STEER_RULE_PREF) {
            if (c.wrong_n < RULE_COPIES_MAX) c.wrong[c.wrong_n++] = pref;
            continue;
        }
        if (c.n < RULE_COPIES_MAX) c.pref[c.n] = pref;
        c.n++;
    }
    return c;
}

/* Снять одну копию правила на данном приоритете. С приоритетом, а не «любую»: без него ядро
 * сняло бы первую попавшуюся, и это могла бы оказаться как раз та, что должна остаться. */
static void rule_del_at(unsigned mark, int table, unsigned long pref) {
    char m[32], t[16], p[24];
    snprintf(m, sizeof(m), "0x%08x/0x%08x", mark, STEER_MARK_MASK);
    snprintf(t, sizeof(t), "%d", table);
    snprintf(p, sizeof(p), "%lu", pref);
    const char *del[] = { "ip", "rule", "del", "fwmark", m, "table", t, "priority", p, NULL };
    run_quiet(del);
}

void rule_ensure(unsigned mark, int table) {
    /* Статический и с запасом — по той же причине, что в route_facts_read: это ВСЕ правила
     * коробки, и обрезанный дамп значил бы «нашего нет» и лишнюю копию. */
    static char rules[16384];
    ip_show("ip -4 rule show 2>/dev/null", rules, sizeof(rules));
    struct rule_copies c = rule_copies_of(rules, mark, table);
    /* Прочитать не вышло (нет ip, отказал popen) — добавляем, ничего не снимая: лишняя копия
     * того же правила ничего не меняет в маршрутизации, а снятие вслепую могло бы оставить
     * метку без правила — то есть ту самую утечку, ради которой всё это. */
    if (!c.known || c.n == 0) rule_add(mark, table);
    /* Верная копия есть (или только что добавлена) — теперь можно убирать лишнее. */
    for (int k = 1; k < c.n && k < RULE_COPIES_MAX; k++) rule_del_at(mark, table, c.pref[k]);
    for (int k = 0; k < c.wrong_n; k++) rule_del_at(mark, table, c.wrong[k]);
    /* Прежняя форма без маски — см. rule_drop. Снимается после того, как форма с маской есть, и
     * ТОЛЬКО с явной маской 0xffffffff (так её хранит ядро) и приоритетом. `ip rule del fwmark X
     * table T` без маски на ядре 4.9 (телефон) снимает ЛЮБОЕ правило с меткой X — и с нашей
     * маской тоже: маска там сравнивается, только если её назвали. rule_drop это не задевало
     * (он снимает обе формы по замыслу), а здесь сняло бы только что поставленное верное правило
     * — то есть метка осталась бы без правила, а трафик ушёл бы напрямую; поймал стенд legacy49
     * на ядре 4.9. Не прочитав дамп, прежнюю форму не трогаем вовсе. */
    char legacy[40], t[16], p[24];
    snprintf(legacy, sizeof(legacy), "0x%08x/0xffffffff", mark);
    snprintf(t, sizeof(t), "%d", table);
    for (int k = 0; k < c.legacy_n; k++) {
        snprintf(p, sizeof(p), "%lu", c.legacy[k]);
        const char *dell[] = { "ip", "rule", "del", "fwmark", legacy, "table", t,
                               "priority", p, NULL };
        run_quiet(dell);
    }
}

/* Одна строка `ip -4 route show table N`, разобранная на то, чем её можно снять точно: тип
 * (пусто — обычный unicast), назначение, устройство, метрика. */
struct rt_line {
    char type[16];
    char dst[64];
    char dev[32];
    unsigned long metric;
};

static int rt_line_parse(const char *line, struct rt_line *r) {
    static const char *const types[] = { "blackhole", "unreachable", "prohibit", "throw",
                                         "local", "broadcast", "multicast", "anycast", "nat",
                                         "unicast", NULL };
    memset(r, 0, sizeof *r);
    char buf[512];
    snprintf(buf, sizeof(buf), "%s", line);
    char *save = NULL;
    char *tok = strtok_r(buf, " \t", &save);
    if (!tok) return 0;
    for (int i = 0; types[i]; i++)
        if (!strcmp(tok, types[i])) {
            snprintf(r->type, sizeof(r->type), "%s", tok);
            tok = strtok_r(NULL, " \t", &save);
            break;
        }
    if (!tok) return 0;
    snprintf(r->dst, sizeof(r->dst), "%s", tok);
    while ((tok = strtok_r(NULL, " \t", &save)) != NULL) {
        int is_dev = !strcmp(tok, "dev"), is_metric = !strcmp(tok, "metric");
        if (!is_dev && !is_metric) continue;
        char *v = strtok_r(NULL, " \t", &save);
        if (!v) break;
        if (is_dev) snprintf(r->dev, sizeof(r->dev), "%s", v);
        else r->metric = strtoul(v, NULL, 10);
    }
    return 1;
}

/* Снять из таблицы всё, кроме одного маршрута по умолчанию — того, что только что поставлен
 * заменой (в dev, а при dev == NULL — запрет), — и запасного запрета, если он положен
 * (backstop; см. STEER_BACKSTOP_METRIC в spec.h). Снимается каждая запись по её ключу (тип,
 * назначение, устройство, метрика): «сбросить таблицу и поставить заново» здесь и есть то
 * окно, от которого эта функция избавляет. */
static void table_prune(int table, const char *dev, int backstop) {
    static char routes[8192];
    char cmd[64], t[16];
    snprintf(cmd, sizeof(cmd), "ip -4 route show table %d 2>/dev/null", table);
    snprintf(t, sizeof(t), "%d", table);
    ip_show(cmd, routes, sizeof(routes));
    int kept = 0;
    for (const char *ln = routes; ln && *ln; ) {
        const char *end = strchr(ln, '\n');
        size_t len = end ? (size_t)(end - ln) : strlen(ln);
        char line[512];
        size_t n = len < sizeof(line) - 1 ? len : sizeof(line) - 1;
        memcpy(line, ln, n);
        line[n] = '\0';
        ln = end ? end + 1 : NULL;

        struct rt_line r;
        if (!rt_line_parse(line, &r)) continue;
        int is_main = !strcmp(r.dst, "default") && r.metric == 0 &&
                      (dev ? (!r.type[0] || !strcmp(r.type, "unicast")) && !strcmp(r.dev, dev)
                           : !strcmp(r.type, "blackhole"));
        if (is_main && !kept) { kept = 1; continue; }
        int is_backstop = !strcmp(r.dst, "default") && !strcmp(r.type, "blackhole") &&
                          r.metric == STEER_BACKSTOP_METRIC;
        if (is_backstop && backstop) { backstop = 0; continue; }
        char m[24];
        snprintf(m, sizeof(m), "%lu", r.metric);
        const char *argv[16];
        int k = 0;
        argv[k++] = "ip"; argv[k++] = "route"; argv[k++] = "del";
        if (r.type[0]) argv[k++] = r.type;
        argv[k++] = r.dst;
        if (r.dev[0]) { argv[k++] = "dev"; argv[k++] = r.dev; }
        if (r.metric) { argv[k++] = "metric"; argv[k++] = m; }
        argv[k++] = "table"; argv[k++] = t;
        argv[k] = NULL;
        run_quiet(argv);
    }
}

/* Поставить запасной запрет (см. STEER_BACKSTOP_METRIC в spec.h). Заменой: стоящий такой же
 * она не дублирует. */
static void backstop_set(int table) {
    char t[16], m[16];
    snprintf(t, sizeof(t), "%d", table);
    snprintf(m, sizeof(m), "%d", STEER_BACKSTOP_METRIC);
    const char *bs[] = { "ip", "route", "replace", "blackhole", "default", "metric", m,
                         "table", t, NULL };
    run_quiet(bs);
}

int table_bind(const struct output *o, const char *dev) {
    char t[16];
    snprintf(t, sizeof(t), "%d", o->table);
    /* Запасной запрет — ПЕРВЫМ: с этого мгновения исчезновение устройства (помощник умер, awg
     * пересоздаётся) оставляет в таблице запрет, а не пустоту. */
    int backstop = o->on_fail == FAIL_DROP;
    if (backstop) backstop_set(o->table);
    const char *to_dev[] = { "ip", "route", "replace", "default", "dev", dev, "table", t, NULL };
    const char *to_bh[] = { "ip", "route", "replace", "blackhole", "default", "table", t, NULL };
    int rc = run_quiet(dev ? to_dev : to_bh);
    if (rc != 0) return rc;
    /* Без on_fail=drop запасной запрет снимается здесь же: режим мог смениться с drop, а
     * пустая таблица у direct/zapret — обещанное «напрямую», а не утечка. */
    table_prune(o->table, dev, backstop);
    return 0;
}

/* Пущен ли выход напрямую — отметка в наборе FAILOPEN_SET нашей таблицы. Зачем она и почему
 * так, а не иначе, — у out_failopen_capable в spec.h: пока метка выхода в наборе, цепочка
 * prerouting_failopen снимает с его пакетов бит ZAPRET_SKIP_MARK, и трафик упавшего выхода
 * идёт как обычный трафик роутера — через общий обход, если тот запущен.
 *
 * Молча: `add` существующего элемента nft принимает, а отказ `delete` отсутствующего — обычное
 * дело (выход и не был отмечен). Набора нет, если в спеке нет ни одного выхода, которому он
 * нужен, — тогда отказывает любая из двух команд, и это тоже ничего не значит. */
void failopen_mark(const struct output *o, int on) {
    if (!o->mark || !out_has_device(o) || !out_skips_zapret(o)) return;
    if (on && !out_failopen_capable(o)) on = 0;   /* on_fail=drop: напрямую не пускаем */
    char el[32];
    snprintf(el, sizeof(el), "{ 0x%08x }", o->mark);
    const char *cmd[] = { "nft", on ? "add" : "delete", "element", "inet", nft_table(),
                          FAILOPEN_SET, el, NULL };
    run_quiet(cmd);
}

/* announce=0 — то же самое приведение состояния в порядок, но без объявления отказа:
 * сторож зовёт apply_failed не только когда выход ТОЛЬКО ЧТО отказал, но и когда отказ
 * длится, а состояние в ядре с тех пор разъехалось (см. сверку ниже). Строку «живых
 * устройств нет» в этом случае печатает вызывающий, и печатает вместе с причиной
 * расхождения — иначе журнал раз в минуту повторял бы одно и то же без новостей. */
static void apply_failed(struct output *o, int announce) {
    char tbl[16];
    snprintf(tbl, sizeof(tbl), "%d", o->table);

    if (o->on_fail == FAIL_DROP) {
        /* blackhole, а не отсутствие маршрута: без маршрута пакет с меткой
         * провалится в следующую таблицу и уйдёт напрямую — то есть ровно туда,
         * куда его не пускали.
         *
         * Заменой, а не «сбросить таблицу и добавить запрет»: между сбросом и добавлением
         * таблица пуста, и помеченный пакет в это мгновение уходил напрямую — ровно то, от
         * чего запрет и ставится (см. «без мгновения пустоты» у table_bind). */
        table_bind(o, NULL);
        /* Правило — и здесь: без него blackhole лежит в таблице, которую никто не
         * спрашивает, и помеченный пакет провалится дальше и уйдёт напрямую — то самое, от
         * чего on_fail=drop и защищает. А снять правило было кому: прежний отказ мог
         * случиться в режиме direct/zapret (ниже), и режим меняют в интерфейсе, не
         * перезапуская ничего. Стоящее правило не снимается (rule_ensure): снять и поставить
         * заново значило бы на миг открыть тот же путь напрямую. */
        rule_ensure(o->mark, o->table);
        /* Режим мог смениться с direct/zapret на drop, пока выход лежал: отметка «пущен
         * напрямую» от прежнего отказа здесь больше не правда. */
        failopen_mark(o, 0);
        /* Запрет поставлен — теперь он обязан касаться и уже установленных соединений,
         * иначе on_fail=drop это обещание только для новых. */
        conntrack_evict(o->mark);
        if (announce)
            fprintf(stderr, LOG_W "выход %s: живых устройств нет, трафик остановлен "
                            "(on_fail=drop)\n", o->name);
        return;
    }

    /* direct и zapret: снимаем правило, чтобы помеченный трафик шёл обычным путём, — и
     * обычным он обязан стать целиком, то есть и для общего обхода DPI: отметка в наборе
     * снимает с него бит «не для zapret» (см. out_failopen_capable в spec.h). Отметка — ДО
     * снятия соединений: следующий пакет каждого из них пройдёт разметку заново и должен
     * застать её уже на месте. Таблица сбрасывается — здесь пустота и есть обещанное: трафик
     * выхода идёт напрямую, и порядок двух команд этого не меняет. */
    rule_drop(o->mark, o->table);
    const char *flush[] = { "ip", "route", "flush", "table", tbl, NULL };
    run_quiet(flush);
    failopen_mark(o, 1);
    conntrack_evict(o->mark);

    if (!announce) return;
    if (o->on_fail == FAIL_ZAPRET && !zapret_running())
        fprintf(stderr, LOG_W "выход %s: живых устройств нет, трафик пущен напрямую, "
                        "но zapret не запущен — обхода DPI не будет\n", o->name);
    else
        fprintf(stderr, LOG_W "выход %s: живых устройств нет, трафик пущен напрямую "
                        "(on_fail=%s)\n", o->name,
                o->on_fail == FAIL_ZAPRET ? "zapret" : "direct");
}

/* Привязать таблицу выхода к устройству. Правило проверяется и при нужде возвращается,
 * потому что режим отказа мог его снять.
 *
 * Не static: этим же пользуется клиент VLESS, когда поднял своё устройство. Он —
 * единственный, кто знает момент, когда TUN готов нести трафик, и ждать этого момента
 * снаружи невозможно: procd запускает экземпляр только после того, как init-скрипт
 * закончил работу, то есть уже после apply. Одна функция вместо второй копии тех же
 * команд — иначе привязка «от клиента» и «от сторожа» разъехались бы.
 *
 * Порядок — сначала маршрут, потом правило, и ни одного снятия до того, как новое стоит (см.
 * «без мгновения пустоты» у table_bind). Маршрут первым: если правила не было (прежний отказ
 * в режиме direct), то появившееся правило должно сразу найти в таблице устройство, а не
 * пустоту. */
void bind_device(struct output *o, const char *dev) {
    char tbl[16];
    snprintf(tbl, sizeof(tbl), "%d", o->table);

    /* Выход снова несёт трафик сам — бит «не для zapret» его пакетам опять нужен. Снимается
     * до привязки и до снятия соединений по той же причине, по какой в apply_failed
     * ставится до них. При отказе привязки ниже отметка возвращается. */
    failopen_mark(o, 0);
    int rc = table_bind(o, dev);
    rule_ensure(o->mark, o->table);
    /* Соединения снимаются ЗДЕСЬ, а не в сторожевом проходе целиком: bind_device зовут,
     * когда маршрут выхода действительно меняется (первая привязка, смена устройства,
     * расхождение состояния), а не каждую минуту. Снимать записи на здоровом тике значило бы
     * рвать людям закачки раз в минуту без всякой причины. */
    conntrack_evict(o->mark);
    if (rc != 0) {
        /* Замена не прошла: устройство исчезло между проверкой и привязкой (свой же процесс
         * туннеля умер), нет прав. В таблице осталось то, что было, — прежнее устройство,
         * запрет или ничего, — и оставлять это на волю случая нельзя: пустая таблица — это не
         * «нет маршрута», а «ищи дальше», то есть напрямую, куда пакет не пускали. То же
         * решение принято в apply_routing (steer.c) и в apply_failed выше; здесь оно обязано
         * совпадать, иначе один и тот же случай означает в трёх местах разное. */
        fprintf(stderr, LOG_W "выход %s: не удалось привязать таблицу %s к %s — "
                        "устройство ещё живо?\n", o->name, tbl, dev);
        if (o->on_fail == FAIL_DROP) {
            table_bind(o, NULL);
            fprintf(stderr, LOG_W "выход %s: трафик остановлен до успешной привязки "
                            "(on_fail=drop)\n", o->name);
        } else {
            /* direct/zapret: пустая таблица уводит пакет в main, то есть напрямую, — пусть
             * и идёт как обычный, через общий обход. Сброс — потому что замена не прошла и в
             * таблице могло остаться прежнее (мёртвое) устройство. */
            const char *flush[] = { "ip", "route", "flush", "table", tbl, NULL };
            run_quiet(flush);
            failopen_mark(o, 1);
        }
    }
}

/* ---- сверка фактического состояния маршрутизации -----------------------------
 *
 * Зачем это вообще есть. На живом роутере наблюдалось так: выход kind=vless сторож
 * объявляет не отвечающим, интерфейс поднимается заново и действительно поднимается,
 * пинг через устройство идёт, splify2 показывает выход живым — а ВСЕ каналы и маршруты,
 * которые через этот выход ходили, молчат. Перезапуск движка возвращает всё мгновенно.
 * Это описание не оборванного туннеля, а разъехавшейся ПОЛИТИЧЕСКОЙ маршрутизации: у
 * выхода своя таблица и своя метка, помеченный трафик ходит через `ip rule fwmark`, и
 * пинг с роутера в эту таблицу не заглядывает вовсе — потому «пинг есть» и «каналы
 * мертвы» спокойно живут вместе.
 *
 * Причина была в том, что состояние правилось ТОЛЬКО ПО СОБЫТИЮ «сменилось устройство»:
 * при was == chosen проход не проверял ничего. Сломать состояние при неизменном имени
 * устройства может как минимум четыре обычных вещи:
 *   - apply_failed при on_fail=drop ставит в таблицу `blackhole default`. Устройство
 *     потом оживает под тем же именем (процесс туннеля поднимает procd) — и запрет
 *     остаётся лежать до перезапуска движка;
 *   - apply, не найдя устройства, ставит тот же blackhole (см. apply_routing в steer.c);
 *   - apply_failed при on_fail=direct/zapret СНИМАЕТ правило fwmark, а возвращал его
 *     только bind_device по событию смены устройства;
 *   - процесс туннеля умер вместе со своим TUN — ядро вычистило из таблицы маршрут,
 *     ссылавшийся на исчезнувшее устройство, и таблица осталась ПУСТОЙ. Пустая таблица
 *     означает не «нет пути», а «ищи дальше»: помеченный пакет уходит напрямую, то есть
 *     ровно туда, куда его не пускали. Для человека это те же «сервисы не работают» —
 *     прямым путём они как раз и заблокированы.
 * Плюс гонка, которая не нуждается ни в одной поломке снаружи: клиент vless привязывает
 * таблицу к своему устройству сам, в момент готовности TUN (см. bind_device выше), и
 * если тик сторожа в это время уже ждал в revive, его apply_failed ложится ПОВЕРХ
 * только что сделанной живой привязки.
 *
 * Почему проба здоровья этого не замечает. И `ping -I dev`, и проба TCP с
 * SO_BINDTODEVICE не несут нашей метки, поэтому таблицу выхода не спрашивают; больше
 * того, при заданном устройстве ядро, не найдя маршрута, считает адресата «за этим
 * устройством» и всё равно отправляет пакет. То есть проба принципиально не видит того
 * состояния, за которое сторож отвечает, и врать в сторону «всё хорошо» будет всегда.
 *
 * Отсюда решение: проверять ФАКТ, а не помнить событие. Раз в тик читаются `ip rule
 * show` и `ip route show table N` выхода, и если действительность разошлась с тем, что
 * должно быть, она приводится в порядок тем же bind_device (или тем же apply_failed).
 * Два коротких чтения на выход раз в минуту не стоят ничего рядом с туннелем, который
 * иначе лежит до перезапуска движка. Перезапуск движка лечением НЕ является: он лечит
 * следствие, и лечит его ровно тем, что переписывает эти же правила заново.
 *
 * Про cleanup_stale_routing (steer.c): там устройство выхода нарочно не проверяется, и
 * это решение остаётся в силе. Оно про ДРУГОЙ вопрос — «жива ли метка», и ответ «правило
 * снять нельзя только потому, что TUN ещё не поднялся» здесь ничем не задет: сверка
 * ниже правило не снимает, а возвращает. */

enum tbl_state {
    TBL_EMPTY,        /* в таблице нет ничего похожего на default */
    TBL_BLACKHOLE,    /* запрет: blackhole/unreachable/prohibit default */
    TBL_DEV,          /* default через устройство */
    TBL_OTHER,        /* default есть, но устройство из него не вычитывается */
};

struct route_facts {
    /* known — удалось ли вообще прочитать состояние ядра.
     *
     * Это не перестраховка, а защита от худшего исхода всей затеи. Сверка отвечает на вопрос
     * «состояние разъехалось?», и если ответ построен на ПУСТОМ дампе, он всегда «да» — тогда
     * сторож каждую минуту сносил бы привязку живого выхода (`ip route flush table N`) и
     * поднимал заново, то есть сам делал бы короткий провал помеченного трафика раз в минуту и
     * заливал журнал. Ровно этот класс беды в этом файле уже описан выше про ifdown/ifup.
     *
     * Признак «прочитать не удалось» — ПУСТОЙ вывод `ip rule show`. На живой коробке он пуст не
     * бывает никогда: там всегда лежат три правила ядра (0, 32766, 32767). Поэтому пустота
     * означает не «правил нет», а «спросить не получилось»: нет `ip`, busybox не понял ключ,
     * отказал popen. Проверять код возврата было бы хуже — busybox отдаёт ноль и на том, чего
     * не понял. */
    int known;
    int rule;             /* правило `fwmark <метка> table <таблица>` в ядре есть */
    enum tbl_state table;
    char dev[32];         /* устройство из default, когда table == TBL_DEV */
    int backstop;         /* запасной запрет (STEER_BACKSTOP_METRIC) на месте */
};

/* Разбор дословного вывода `ip rule show` и `ip route show table N`.
 *
 * Чистая функция, без единого вызова ip: иначе решение «состояние разъехалось» нельзя
 * было бы закрыть стендом, а ошибка именно здесь ничего не сломает заметно — она просто
 * оставит туннель мёртвым до перезапуска движка, то есть вернёт ту самую неполадку.
 * Стенд: tests/failovermatch.c. */
static struct route_facts route_facts_of(const char *rules, const char *routes,
                                         uint32_t mark, int table) {
    struct route_facts f;
    f.known = rules && rules[0] != '\0';
    f.rule = 0;
    f.table = TBL_EMPTY;
    f.dev[0] = '\0';
    f.backstop = 0;
    if (!f.known) return f;

    char want_tbl[16];
    snprintf(want_tbl, sizeof(want_tbl), "%d", table);

    for (const char *ln = rules; ln && *ln; ) {
        const char *end = strchr(ln, '\n');
        size_t len = end ? (size_t)(end - ln) : strlen(ln);
        char line[512];
        size_t n = len < sizeof(line) - 1 ? len : sizeof(line) - 1;
        memcpy(line, ln, n);
        line[n] = '\0';
        ln = end ? end + 1 : NULL;

        const char *fm = strstr(line, "fwmark ");
        if (!fm) continue;
        char *stop = NULL;
        unsigned long got = strtoul(fm + 7, &stop, 16);
        if (!stop) continue;
        /* Маска обязана быть НАШЕЙ, и это проверка в обе стороны.
         *
         * Чужая маска (`fwmark 0x100000/0xff`) поймает не тот трафик: согласиться с таким
         * правилом значило бы не поставить своё. Отсутствие маски — тоже не наше, хотя
         * раньше было единственной нашей формой: правило без маски осталось в ядре от
         * версии до R-094, и если считать его верным, сторож не тронет его никогда, то
         * есть обновление не доедет. Считая его чужим, сторож пересоздаёт привязку, а
         * rule_drop снимает обе формы — и через минуту после обновления в ядре остаётся
         * только правило с маской.
         *
         * Ядро печатает маску без ведущих нулей (`0x100000/0xff00000`) — форма проверена
         * на живом роутере, см. RULES_WITH в tests/failovermatch.c. */
        if (*stop != '/') continue;
        char *mstop = NULL;
        unsigned long msk = strtoul(stop + 1, &mstop, 16);
        if ((uint32_t)msk != STEER_MARK_MASK) continue;
        if ((uint32_t)got != mark) continue;
        /* Куда правило смотрит. Номер таблицы iproute2 печатает как есть, но может
         * напечатать и ИМЯ, если оно заведено в /etc/iproute2/rt_tables кем-то ещё.
         * Имя здесь не разрешить, и в этом случае правило считается нашим: метка уже
         * наша, а ставит её только наш набор правил. Другой ЧИСЛОВОЙ номер — наоборот,
         * повод правило пересоздать. */
        const char *lk = strstr(line, "lookup ");
        if (lk) {
            const char *t = lk + 7;
            size_t tl = strcspn(t, " \t");
            int numeric = tl > 0;
            for (size_t i = 0; i < tl; i++)
                if (!isdigit((unsigned char)t[i])) numeric = 0;
            if (numeric && (tl != strlen(want_tbl) || strncmp(t, want_tbl, tl) != 0))
                continue;
        }
        f.rule = 1;
    }

    for (const char *ln = routes; ln && *ln; ) {
        const char *end = strchr(ln, '\n');
        size_t len = end ? (size_t)(end - ln) : strlen(ln);
        char line[512];
        size_t n = len < sizeof(line) - 1 ? len : sizeof(line) - 1;
        memcpy(line, ln, n);
        line[n] = '\0';
        ln = end ? end + 1 : NULL;

        const char *p = line;
        while (*p == ' ' || *p == '\t') p++;
        /* Интересует только запись про default: адресные маршруты в таблице выхода
         * никому не мешают (их кладёт, например, `ip addr` на само устройство). */
        int blocked = !strncmp(p, "blackhole ", 10) || !strncmp(p, "unreachable ", 12) ||
                      !strncmp(p, "prohibit ", 9);
        if (blocked) {
            if (!strstr(p, "default")) continue;
            /* Запасной запрет — не «запрет в таблице»: он лежит у живого выхода всегда (см.
             * STEER_BACKSTOP_METRIC в spec.h), и счесть его запретом значило бы объявлять
             * разъехавшейся каждую исправную таблицу. */
            {
                char bm[32];
                snprintf(bm, sizeof(bm), " metric %d", STEER_BACKSTOP_METRIC);
                const char *mp = strstr(p, bm);
                if (mp && (mp[strlen(bm)] == '\0' || mp[strlen(bm)] == ' ' ||
                           mp[strlen(bm)] == '\t')) {
                    f.backstop = 1;
                    continue;
                }
            }
            f.table = TBL_BLACKHOLE;
            f.dev[0] = '\0';
            continue;
        }
        if (strncmp(p, "default", 7) != 0) continue;
        const char *d = strstr(p, " dev ");
        if (!d) { f.table = TBL_OTHER; continue; }
        d += 5;
        size_t dl = strcspn(d, " \t");
        if (dl == 0 || dl >= sizeof(f.dev)) { f.table = TBL_OTHER; continue; }
        memcpy(f.dev, d, dl);
        f.dev[dl] = '\0';
        f.table = TBL_DEV;
    }
    return f;
}

/* Годится ли фактическое состояние для «выход живёт через dev». */
static int routing_live_ok(const struct route_facts *f, const char *dev) {
    return f->rule && f->table == TBL_DEV && strcmp(f->dev, dev) == 0;
}

/* Годится ли фактическое состояние для «живых устройств нет» при данном режиме отказа.
 * drop требует и правила, и запрета в таблице: запрет без правила — это утечка напрямую
 * (таблицу никто не спрашивает), правило без запрета — трафик в мёртвый туннель. */
static int routing_failed_ok(const struct route_facts *f, enum on_fail of) {
    /* Запрет — основной или только запасной: второе остаётся, когда ядро вычистило маршрут
     * исчезнувшего устройства, и трафик при нём стоит ровно так же. */
    if (of == FAIL_DROP)
        return f->rule && (f->table == TBL_BLACKHOLE || (f->table == TBL_EMPTY && f->backstop));
    return !f->rule;
}

/* Чем разошлось состояние при отказе. Отдельно от facts_why, потому что при отказе
 * «правило есть» бывает не бедой, а самой бедой: в режимах direct и zapret оно ОБЯЗАНО
 * быть снято, и сказать про такую таблицу «пуста — трафик уходил напрямую» значило бы
 * назвать бедой обещанное поведение. */
static const char *failed_why(const struct route_facts *f, enum on_fail of) {
    if (of != FAIL_DROP)
        return f->rule ? "правило fwmark на месте, хотя трафик обещан прямым путём"
                       : "правило fwmark снято";
    if (!f->rule) return "правила fwmark нет — помеченный трафик уходил напрямую";
    if (f->table == TBL_BLACKHOLE) return "запрет на месте";
    if (f->table == TBL_DEV) return "в таблице default на устройство, которое не отвечает";
    return "в таблице нет запрета — помеченный трафик уходил напрямую";
}

/* Чем именно разошлось — для журнала. Человек по этой строке отличает «правило снесли»
 * от «в таблице остался запрет», а это разные причины с разной историей. */
static const char *facts_why(const struct route_facts *f, const char *dev) {
    static char buf[128];
    if (!f->rule) return "правила fwmark нет";
    switch (f->table) {
    case TBL_EMPTY:
        return f->backstop ? "маршрута в устройство нет — трафик стоял на запасном запрете"
                           : "таблица пуста — помеченный трафик уходил напрямую";
    case TBL_BLACKHOLE:
        return "в таблице остался запрет (blackhole)";
    case TBL_OTHER:
        return "default в таблице без устройства";
    case TBL_DEV:
        if (dev && strcmp(f->dev, dev)) {
            snprintf(buf, sizeof(buf), "default ведёт на %s, а не на %s", f->dev, dev);
            return buf;
        }
        snprintf(buf, sizeof(buf), "в таблице default на %s", f->dev);
        return buf;
    }
    return "состояние не разобрано";
}

/* Прочитать вывод команды. popen, а не run_quiet: тому вывод нужен выброшенным, а нам —
 * прочитанным. Подменяется стендом ровно так же, как в tests/fwmatch.c. */
static void ip_show(const char *cmd, char *out, size_t n) {
    out[0] = '\0';
    FILE *p = popen(cmd, "r");
    if (!p) return;
    size_t got = fread(out, 1, n - 1, p);
    out[got] = '\0';
    pclose(p);
}

static struct route_facts route_facts_read(const struct output *o) {
    /* Статические, и с запасом. Вывод `ip rule show` — это ВСЕ правила коробки, а не
     * только наши: рядом живут mwan3, fw4 и чужие туннели, у которых правил бывают
     * десятки. Обрезанный дамп означал бы «нашего правила нет» и пересоздание живой
     * привязки каждую минуту — то есть короткий провал помеченного трафика на ровном
     * месте. Статические, потому что процесс короткоживущий и делить с этим стек незачем. */
    static char rules[16384], routes[8192];
    char cmd[64];
    ip_show("ip -4 rule show 2>/dev/null", rules, sizeof(rules));
    snprintf(cmd, sizeof(cmd), "ip -4 route show table %d 2>/dev/null", o->table);
    ip_show(cmd, routes, sizeof(routes));
    return route_facts_of(rules, routes, o->mark, o->table);
}

/* Что выбрано сейчас — чтобы не переписывать маршруты и не шуметь в лог, когда
 * ничего не изменилось. Файл в state_dir, рядом с реестром меток. */
static void active_path(char *buf, size_t n) {
    snprintf(buf, n, "%s/active", g_state_dir);
}

/* Гистерезис возврата: сколько тиков подряд более предпочтительное устройство обязано быть
 * здоровым, прежде чем пул вернётся к нему с запасного. Возврат наверх «мгновенно, как только
 * ожил» на живом роутере обернулся мельканием: узел-предпочтение №0 подхватывался пробой раз в
 * минуту, трафик прыгал на него и через минуту падал обратно — и так по кругу, каждый прыжок
 * это до минуты мёртвого трафика. УХОД с мёртвого устройства при этом мгновенен и гистерезисом
 * не задерживается: держать трафик на упавшем туннеле нельзя. 0 — прежнее поведение (без
 * задержки). Читается один раз: процесс короткоживущий. */
static int g_hyst_cache = -2;
static int failover_hyst(void) {
    if (g_hyst_cache == -2) {
        const char *e = getenv("STEER_FAILOVER_HYST");
        g_hyst_cache = e ? atoi(e) : 3;
        if (g_hyst_cache < 0) g_hyst_cache = 0;
    }
    return g_hyst_cache;
}
/* Стенду нужно менять порог между проходами; в бою процесс короткоживущий и это не зовётся. */
static void failover_hyst_reset_for_test(void) __attribute__((unused));
static void failover_hyst_reset_for_test(void) { g_hyst_cache = -2; }

/* Счётчик подряд-здоровых тиков более предпочтительного устройства — рядом с активным, третьим
 * полем в том же файле. Все читатели файла обязаны СЪЕДАТЬ три поля, иначе оставшийся на строке
 * счётчик уедет в имя следующего выхода. Старый файл без счётчика читается как ноль. */
static int g_streak[MAX_OUTPUTS];

/* ---- состояние замеров задержки -----------------------------------------------------
 *
 * ОТДЕЛЬНЫМ ФАЙЛОМ, а не четвёртым полем в `active`. Тот читается fscanf по трём полям, и у
 * него уже есть оговорка про запись без третьего поля; четвёртое означало бы правку формата,
 * который пишут и читают в трёх местах. Отдельный файл вдобавок необязателен сам по себе:
 * нет его — значит не мерили, и это законное начальное состояние.
 *
 * Строка: `выход устройство мс отметка`. Отметка — CLOCK_MONOTONIC в секундах, то есть время
 * с загрузки: по стенным часам сравнивать нельзя, ntpd на только что поднявшемся роутере
 * подводит их на годы, и любой замер выглядел бы свежим или древним. Цена — перезагрузка
 * обнуляет отсчёт и первый тик после неё меряет заново, что и правильно. */
#define LAT_TOLERANCE_MS 50
#define LAT_INTERVAL_S   180

static void lat_path(char *buf, size_t n) {
    snprintf(buf, n, "%s/latency", g_state_dir);
}

static long mono_now(void) {
    struct timespec t;
    clock_gettime(CLOCK_MONOTONIC, &t);
    return (long)t.tv_sec;
}

static int lat_get(const char *out, const char *dev, int *ms, long *age) {
    char path[256];
    lat_path(path, sizeof(path));
    FILE *f = fopen(path, "r");
    if (!f) return 0;
    char o[32], d[32];
    int v = 0; long at = 0, found = 0;
    while (fscanf(f, "%31s %31s %d %ld", o, d, &v, &at) == 4)
        if (!strcmp(o, out) && !strcmp(d, dev)) { *ms = v; *age = mono_now() - at; found = 1; }
    fclose(f);
    return (int)found;
}

/* Записать замеры выхода, оставив записи остальных на месте. Через временный файл и rename:
 * обрыв на середине оставил бы половину строк, а половина замеров ХУЖЕ их отсутствия — по
 * ней сторож переключился бы на кандидата, чей замер уцелел. */
static void lat_put(const char *out, char devs[][32], int *ms, size_t n) {
    char path[256], tmp[288];
    lat_path(path, sizeof(path));
    snprintf(tmp, sizeof(tmp), "%s.tmp", path);
    FILE *old = fopen(path, "r");
    FILE *f = fopen(tmp, "w");
    if (!f) { if (old) fclose(old); return; }
    if (old) {
        char o[32], d[32];
        int v; long at;
        while (fscanf(old, "%31s %31s %d %ld", o, d, &v, &at) == 4)
            if (strcmp(o, out) != 0) fprintf(f, "%s %s %d %ld\n", o, d, v, at);
        fclose(old);
    }
    long now = mono_now();
    for (size_t k = 0; k < n; k++)
        if (ms[k] >= 0) fprintf(f, "%s %s %d %ld\n", out, devs[k], ms[k], now);
    fclose(f);
    if (rename(tmp, path) != 0) unlink(tmp);
}

static int active_streak_get(const char *out) {
    char path[256];
    active_path(path, sizeof(path));
    FILE *f = fopen(path, "r");
    if (!f) return 0;
    char name[32], d[32];
    int st = 0, val = 0;
    while (fscanf(f, "%31s %31s %d", name, d, &st) >= 2) {
        if (!strcmp(name, out)) val = st;
        st = 0;   /* следующая запись без третьего поля не должна унаследовать этот */
    }
    fclose(f);
    return val;
}

static void active_get(const char *out, char *dev, size_t n) {
    dev[0] = '\0';
    char path[256];
    active_path(path, sizeof(path));
    FILE *f = fopen(path, "r");
    if (!f) return;
    char name[32], d[32];
    int st = 0;
    while (fscanf(f, "%31s %31s %d", name, d, &st) >= 2) {
        if (!strcmp(name, out)) snprintf(dev, n, "%s", d);
        st = 0;
    }
    fclose(f);
}

/* Записать выбор прохода — ТОЛЬКО если он отличается от записанного.
 *
 * Файл пишется в конце каждого прохода, а проход на телефоне — раз в минуту и по каждому
 * событию сети. Каталог состояния там — /data, то есть флеш, и безусловная запись означала бы
 * запись во флеш каждую минуту круглые сутки ради одного и того же текста: выбор устройства
 * меняется редко (переключение, отказ, счётчик гистерезиса при возврате). Требование владельца —
 * батарея и сон — это исключает. Сравнивается будущий текст целиком, как у реестра меток
 * (registry_assign в spec.c): чтение не пишет ничего.
 *
 * Через временный файл и rename: status и apply читают этот файл в любой момент, и половина
 * строк означала бы для них «сторож не проходил» у половины выходов. */
static void active_save(void) {
    char want[MAX_OUTPUTS * 80 + 1];
    size_t wn = 0;
    for (size_t i = 0; i < g_out_n; i++) {
        if (!out_has_device(&g_out[i])) continue;
        int w = snprintf(want + wn, sizeof(want) - wn, "%s %s %d\n", g_out[i].name,
                         g_out[i].device[0] ? g_out[i].device : "-", g_streak[i]);
        if (w < 0 || (size_t)w >= sizeof(want) - wn) break;
        wn += (size_t)w;
    }
    char path[256], tmp[288];
    active_path(path, sizeof(path));
    FILE *f = fopen(path, "r");
    if (f) {
        char have[sizeof(want) + 1];
        size_t hn = fread(have, 1, sizeof(have), f);
        fclose(f);
        if (hn == wn && memcmp(have, want, wn) == 0) return;
    }
    snprintf(tmp, sizeof(tmp), "%s.tmp", path);
    f = fopen(tmp, "w");
    if (!f) return;
    fwrite(want, 1, wn, f);
    if (fclose(f) != 0 || rename(tmp, path) != 0) unlink(tmp);
}

/* Взять устройство, которое НЕСЁТ ТРАФИК СЕЙЧАС, а не первое по списку кандидатов.
 *
 * Поле `device` объявлено активным устройством выхода (см. struct output в spec.h), но
 * заполнял его до сих пор один сторож и только внутри своего процесса. Всякая другая
 * команда читает спеку заново, а там `device` — это ПЕРВЫЙ кандидат, то есть
 * предпочтение, а не факт. На выходе с одним устройством разницы нет, и её не было
 * видно; у пула она видна сразу: сторож увёл трафик на запасное устройство, а `status`
 * показывает основное с `up: false`, `diag` говорит «устройства нет», и на исправно
 * работающем пуле интерфейс рисует поломку. Тем же промахом болел приговор про
 * masquerade, ради которого владелец устройства и заводился: `out_for_device` спрашивали
 * про устройство, которое трафик не несёт (I-160).
 *
 * Порядок ответа, и он один на всех спрашивающих:
 *   1) запись сторожа, если названное ею устройство всё ещё кандидат этого выхода и всё
 *      ещё есть на роутере, — это и есть факт, добытый пробами;
 *   2) иначе первый существующий кандидат — записи нет (сторож ещё не проходил) или она
 *      устарела, но связывать таблицу с устройством, которого нет, незачем, когда рядом
 *      есть существующее;
 *   3) иначе оставляем как было: не из чего выбирать, и apply честно доложит отказ, а
 *      при on_fail=drop поставит запрет.
 *
 * Одна функция на apply и на отчёты не ради краткости: apply ПРИВЯЗЫВАЕТ таблицу к тому,
 * что вернули здесь, а status и diag рассказывают о том же самом. Разойдись они — и
 * интерфейс снова показывал бы не то, что применено. */
void outputs_adopt_active(void) {
    for (size_t i = 0; i < g_out_n; i++) {
        struct output *o = &g_out[i];
        if (!out_has_device(o)) continue;

        char rec[32];
        active_get(o->name, rec, sizeof(rec));   /* читает три поля — см. active_get */
        const char *pick = NULL;
        if (rec[0] && strcmp(rec, "-") != 0 && device_present(rec))
            for (size_t k = 0; k < o->devices_n && !pick; k++)
                if (!strcmp(o->devices[k], rec)) pick = o->devices[k];
        for (size_t k = 0; k < o->devices_n && !pick; k++)
            if (device_present(o->devices[k])) pick = o->devices[k];
        if (pick) snprintf(o->device, sizeof(o->device), "%s", pick);
    }
}

/* Поднять залипший туннель.
 *
 * Обязательно ifdown+ifup, а не просто ifup: в netifd `ifup` на уже поднятом
 * интерфейсе — no-op, поэтому залипший туннель сам не оживёт НИКОГДА, и сторож
 * просидит в резерве даже после того, как сервер вернулся. Лечится этим то, что
 * иначе не лечится: netifd разрешает имя эндпоинта один раз при подъёме (переезд по
 * DDNS не подхватывается), сокет остаётся привязан к отмершему пути UDP/CGNAT, а
 * состояние proto-error само не снимается.
 *
 * Безопасно, потому что делается только с устройством, которое НЕ несёт трафик:
 * либо оно и так не отвечает, либо маршруты указывают на другое.
 *
 * Отдельная защита от циклов: перезапуск не чаще раза в NN секунд на устройство.
 * Мёртвый пир иначе получал бы ifdown/ifup каждую минуту, и туннель никогда не
 * успевал бы завершить рукопожатие. */
#define RESTART_COOLDOWN 300

static int restart_allowed(const char *dev) {
    char path[256];
    snprintf(path, sizeof(path), "%s/restart-%.32s", g_state_dir, dev);
    FILE *f = fopen(path, "r");
    long last = 0;
    if (f) { if (fscanf(f, "%ld", &last) != 1) last = 0; fclose(f); }
    long now = (long)time(NULL);
    if (last && now - last < RESTART_COOLDOWN) return 0;
    f = fopen(path, "w");
    if (f) { fprintf(f, "%ld\n", now); fclose(f); }
    return 1;
}

static int revive(const struct output *o, const char *dev, int verbose) {
    if (!restart_allowed(dev)) {
        if (verbose)
            fprintf(stderr, LOG_I "%s: перезапуск был недавно, пропускаю\n", dev);
        return 0;
    }

    /* Устройство xsteer, поднятое netifd: клиент наш, а интерфейс — его, и зовётся интерфейс
     * НЕ так, как устройство (xs0 против xs-xs0). `ifdown xs-xs0` netifd отвечает «Interface
     * not found», то есть сторож писал бы в журнал отказ вместо починки. Чинить здесь нечего
     * и не нам: упавшего клиента поднимает заново netifd, как любой обработчик протокола, и
     * дело сторожа то же, что и с нашими собственными процессами, — сказать и подождать. */
    if (xs_state_read(dev, NULL, NULL)) {
        fprintf(stderr, LOG_W "%s: не отвечает — клиента туннеля поднимет заново служба "
                        "сети; жду\n", dev);
        for (int i = 0; i < 10; i++) {
            sleep(1);
            if (device_healthy_for(o, dev)) return 1;
        }
        return 0;
    }

    /* Устройство vless и xsteer создаёт НАШ процесс, а не netifd. ifdown/ifup здесь
     * бесполезны — netifd про это устройство не знает («Interface vl not found») — и на
     * живом роутере это выглядело как вечный холостой цикл перезапусков в журнале.
     * Падение процесса ловит procd (init-скрипт ставит respawn), и подъём заново выбирает
     * рабочий узел (vless) или заново здоровается с хабом (xsteer) сам. У сторожа здесь
     * одна задача: сообщить, что туннель молчит, и подождать — кому именно ждать, тот
     * поднимется сам.
     *
     * Вопрос задаётся УСТРОЙСТВУ, а не выходу, который его назвал, по той же причине, что и
     * проба здоровья (см. device_owner): в пуле разнородных туннелей устройство vless
     * названо выходом kind=interface, и решение по виду НАЗВАВШЕГО дало бы здесь ifdown/ifup
     * по устройству, которым netifd не управляет, — «Interface … not found» раз в минуту и
     * ничего больше. */
    /* Туннель kind=awg чинится не ожиданием: процесса, который поднял бы его заново, нет —
     * устройство живёт в ядре. Лечится то же, что у netifd лечит ifdown/ifup: имя Endpoint
     * разрешается заново (переезд сервера по DNS), настройка ложится заново, а пропавшее
     * устройство создаётся. Частоту уже ограничил restart_allowed выше. */
    {
        const struct output *aw = out_for_device(o, dev);
        if (aw->kind == OUT_AWG) return awg_revive(aw, dev);
    }
    if (out_engine_managed(o) || device_owner(dev)) {
        /* СНАЧАЛА спрашиваем, не известна ли уже причина, по которой ждать бессмысленно.
         *
         * Снято с живого роутера: у выхода с `node: 31` при двадцати девяти узлах в подписке
         * сторож писал «должен подняться заново через procd; жду» раз в пять минут — часами.
         * Ждать там нечего: номер вне подписки, procd поднимает клиента, тот выходит с тем же
         * отказом, и так до правки числа человеком. Строка «жду» обещает работу, которой не
         * будет, и этим она хуже молчания: по ней человек ждёт вместе со сторожем.
         *
         * Причину знает сам клиент и уже записал её (probe_report), поэтому здесь её не
         * выводят заново, а читают. Спрашивается у ВЛАДЕЛЬЦА устройства — по той же причине,
         * что и проба здоровья: в пуле разнородных туннелей запись пишет клиент под своим
         * именем, а не выход, который его назвал. */
        const struct output *pr_own = device_owner(dev);
        struct probe_status pr = probe_read(pr_own ? pr_own->name : o->name);
        if (pr.state == PROBE_NO_SUCH_NODE) {
            fprintf(stderr, LOG_W "%s: выбран узел %d, а пригодных в подписке %d — сам не "
                            "поднимется, поправьте номер узла\n", dev, pr.node, pr.total);
            return 0;
        }
        fprintf(stderr, LOG_W "%s: не отвечает — процесс туннеля должен подняться "
                        "заново через procd; жду\n", dev);
        for (int i = 0; i < 10; i++) {
            sleep(1);
            if (device_healthy_for(o, dev)) return 1;
        }
        return 0;
    }

#ifdef STEER_ANDROID
    /* На телефоне нет ни netifd (ifdown/ifup), ни procd с ubus: интерфейс туннеля поднимает
     * тот, кто его завёл, — приложение VPN или наш же процесс, и перезапускать его отсюда
     * нечем. Дело сторожа то же, что у выходов, чьё устройство заводит движок: сказать и
     * подождать, не оживёт ли. */
    fprintf(stderr, LOG_W "%s: не отвечает — жду, не поднимется ли\n", dev);
    for (int i = 0; i < 10; i++) {
        sleep(1);
        if (device_healthy_for(o, dev)) return 1;
    }
    return 0;
#endif
    fprintf(stderr, LOG_W "%s: не отвечает — перезапускаю интерфейс\n", dev);
    /* Сначала обфускатор, потом интерфейс, и порядок здесь — не вкусовщина.
     *
     * У выхода с obfs датаграммы WireGuard идут не в сеть, а в свой процесс, и если
     * молчит он, то поднимать заново интерфейс бессмысленно: рукопожатие уйдёт в тот же
     * тупик. Обфускатор умеет чинить себя сам (тишина при активной отправке — признак
     * мёртвого пути), но узнаёт об этом только по факту отправки, а пока туннель лежит,
     * отправлять нечего. Отсюда явный сигнал: procd поднимет процесс заново, и уже
     * после этого ifdown/ifup даст WireGuard свежую попытку.
     *
     * Через ubus, а не kill: экземпляром владеет procd, и он же обязан поднять замену.
     * Отказ игнорируем — выход мог быть настроен без obfs, и это норма. */
    if (o->obfs.on) {
        /* С запасом: имя выхода до 24 символов плюс обрамление JSON — иначе
         * -Wformat-truncation справедливо ругается, а сборка здесь обязана быть без
         * предупреждений (I-007). */
        char inst[96];
        snprintf(inst, sizeof(inst), "{\"name\":\"steer\",\"instance\":\"obfs_%.24s\","
                                     "\"signal\":15}", o->name);
        const char *sig[] = { "ubus", "call", "service", "signal", inst, NULL };
        run_quiet(sig);
        sleep(1);
    }
    const char *down[] = { "ifdown", dev, NULL };
    const char *up[] = { "ifup", dev, NULL };
    run_quiet(down);
    run_quiet(up);
    /* Рукопожатию нужно время: проверить сразу — значит объявить мёртвым то, что
     * ещё поднимается. Ждём короткими шагами, чтобы не держать проход дольше нужного. */
    for (int i = 0; i < 10; i++) {
        sleep(1);
        if (device_healthy_for(o, dev)) return 1;
    }
    return 0;
}

static void cleanup_probe_rule(void) {
    char prio[16];
    snprintf(prio, sizeof(prio), "%d", PROBE_PRIO);
    const char *del[] = { "ip", "-4", "rule", "del", "priority", prio, NULL };
    run_quiet(del);
}

/* То же для `steer down`: правило пробы — все копии, и таблица пробы. Проход, убитый SIGKILL
 * (init Android гасит сервис так), не успевает ни того, ни другого. */
void probe_rule_cleanup(void) {
    char prio[16], tbl[16];
    snprintf(prio, sizeof(prio), "%d", PROBE_PRIO);
    snprintf(tbl, sizeof(tbl), "%d", PROBE_TABLE);
    const char *del[] = { "ip", "-4", "rule", "del", "priority", prio, NULL };
    for (int i = 0; i < 16 && run_quiet(del) == 0; i++) {}
    const char *flush[] = { "ip", "route", "flush", "table", tbl, NULL };
    run_quiet(flush);
}

static void sig_cleanup(int sig) {
    cleanup_probe_rule();
    _exit(128 + sig);
}

int cmd_failover(const char *spec, int verbose) {
    atexit(cleanup_probe_rule);
    signal(SIGINT, sig_cleanup);
    signal(SIGTERM, sig_cleanup);
    /* Снять probe-rule, оставшийся от ПРЕЖНЕГО прохода, прежде чем ставить свой.
     * atexit и обработчики выше закрывают обычное завершение, но не SIGKILL и не
     * OOM-killer (I-022): после жёсткого убийства правило жило в ядре до ручной
     * чистки. Уборка в начале прохода восстанавливает состояние независимо от
     * того, как умер предыдущий процесс, и идемпотентна — нет правила, нет дела. */
    cleanup_probe_rule();

    /* Правило 5, docs/architecture.md, раздел 2: err_die здесь довершает то, что раньше делал
     * die() изнутри load_spec/registry_assign — «конец одного прохода», как и сказано в шапке
     * watch.c, только теперь через явную проверку возврата, а не exit() из глубины разбора. */
    struct err e = {0};
    if (load_spec(spec, &e) < 0) err_die(&e);
    if (registry_assign(&e) < 0) err_die(&e);

    int changed = 0;
    /* ПОРЯДОК ОБХОДА — ПО ЗАВИСИМОСТЯМ `via`, а не по спеке.
     *
     * Выход, чей туннель идёт через другой выход (см. «вложенные выходы» в spec.h), жив только
     * пока жива его цель: соединение внутреннего туннеля с сервером едет в устройство цели. Ответ
     * «цель жива» сторож и так получает в этом же проходе — нужно лишь спросить цель ПЕРВОЙ.
     * Поэтому сначала выходы без via, затем те, чья цель без via, и так до MAX_VIA_DEPTH: спека
     * круги и цепочки длиннее не пропускает (via_check в spec.c), так что каждый выход получает
     * место ровно один раз. Порядок внутри одного слоя — прежний, спековый: у спек без via обход
     * тот же, что был, до последнего прохода.
     *
     * Ни проб, ни таймеров ради этого не заводится — требование батареи на телефоне: зависимость
     * читается из уже известного ответа, а пробы внутреннего выхода при лежащей цели и вовсе не
     * делаются (см. via_down ниже). */
    size_t ord[MAX_OUTPUTS];
    size_t ord_n = 0;
    for (int depth = 0; depth <= MAX_VIA_DEPTH; depth++)
        for (size_t i = 0; i < g_out_n; i++)
            if (out_via_depth(&g_out[i]) == depth) ord[ord_n++] = i;
    /* Кто в ЭТОМ проходе нашёл живое устройство. */
    int alive[MAX_OUTPUTS] = {0};
    for (size_t oi = 0; oi < ord_n; oi++) {
        size_t i = ord[oi];
        struct output *o = &g_out[i];
        if (!out_has_device(o)) continue;

        /* Цель via лежит — внутренний выход нерабочий, что бы ни говорила его собственная проба.
         * Проба тут и соврать может: устройство vless или xsteer остаётся на месте, пока жив
         * процесс, а до сервера его соединение через мёртвую цель не доедет. И пробовать, и
         * оживлять его бесполезно — поэтому ни того, ни другого, сразу ветка отказа с ЕГО
         * on_fail: каналы внутреннего выхода получают то, что человек для них выбрал. */
        const struct output *via = out_via(o);
        int via_down = via && !alive[via - g_out];

        char was[32];
        active_get(o->name, was, sizeof(was));
        /* Где в списке предпочтения стоит несущее трафик сейчас. -1 — записи нет или её
         * устройство больше не кандидат: тогда гистерезису не за что держаться, берём
         * лучшее здоровое сразу. */
        int cur = -1;
        for (size_t k = 0; k < o->devices_n; k++)
            if (!strcmp(o->devices[k], was)) { cur = (int)k; break; }

        /* Первое здоровое по предпочтению. Пробуем по порядку и ОСТАНАВЛИВАЕМСЯ на нём —
         * пробить пробой каждое устройство значило бы платить таймаут за каждый мёртвый
         * запас на каждом тике. Здоровье устройств 0..first_h тем самым известно. */
        int first_h = -1;
        for (size_t k = 0; k < o->devices_n && !via_down; k++) {
            if (health_of(o, o->devices[k])) { first_h = (int)k; break; }
            if (verbose)
                fprintf(stderr, LOG_W "%s: %s не отвечает\n", o->name, o->devices[k]);
        }

        const char *chosen = NULL;
        int streak = active_streak_get(o->name);
        int new_streak = 0;

        /* ---- ВЫБОР ПО ЗАМЕРУ, если выход этого просит --------------------------------
         *
         * Работает НЕ на каждом тике, и это главное в устройстве. Выше сторож нарочно
         * останавливается на первом здоровом: пробить пробой каждого мёртвого запаса стоит
         * таймаут, и на восьми кандидатах это двадцать секунд на тик. Замер же требует
         * опросить ВСЕХ — иначе сравнивать не с чем. Поэтому у него свой, длинный интервал
         * (умолчание 180 с против тика в 60), а между замерами выход ведёт себя как прежде,
         * то есть по порядку предпочтения.
         *
         * Допуск (умолчание 50 мс) — гистерезис в единицах самого замера. Без него сторож
         * менял бы устройство на каждом дрожании в пару миллисекунд, а смена устройства
         * здесь это смена выходного адреса и обрыв соединений через прежнее.
         *
         * Оба числа взяты у sing-box (interval 3m, tolerance 50), где эта задача решена
         * давно и проверена на несравнимо большем числе установок, чем наша.
         *
         * Порядок предпочтения человека НЕ отменяется, а становится решающим при равенстве:
         * кандидат, чей замер не хуже лучшего на допуск, считается равным, и из таких
         * берётся самый предпочтительный. Иначе включение режима означало бы «мой список
         * больше ничего не значит». */
        if (o->prefer_latency && first_h >= 0 && o->devices_n > 1) {
            int tol = o->lat_tolerance_ms > 0 ? o->lat_tolerance_ms : LAT_TOLERANCE_MS;
            long iv  = o->lat_interval_s  > 0 ? o->lat_interval_s  : LAT_INTERVAL_S;
            int ms[MAX_DEVICES];
            int have = 0, stale = 0;
            for (size_t k = 0; k < o->devices_n; k++) {
                long age = 0;
                ms[k] = -1;
                if (lat_get(o->name, o->devices[k], &ms[k], &age)) {
                    if (age > iv || age < 0) stale = 1;
                } else stale = 1;
            }
            if (stale) {
                /* Меряем ВСЕХ, включая тех, что ниже first_h: смысл режима ровно в том,
                 * чтобы узнать про них. */
                for (size_t k = 0; k < o->devices_n; k++)
                    ms[k] = device_latency(o, o->devices[k]);
                lat_put(o->name, o->devices, ms, o->devices_n);
            }
            for (size_t k = 0; k < o->devices_n; k++) if (ms[k] >= 0) have++;
            if (have > 0) {
                int best = -1;
                for (size_t k = 0; k < o->devices_n; k++)
                    if (ms[k] >= 0 && (best < 0 || ms[k] < best)) best = ms[k];
                int pick = -1;
                for (size_t k = 0; k < o->devices_n; k++)
                    if (ms[k] >= 0 && ms[k] - best <= tol) { pick = (int)k; break; }
                if (pick >= 0) {
                    /* Уходить с ЖИВОГО текущего только если выигрыш больше допуска. Мёртвое
                     * текущее уступает сразу: здоровье старше замера. */
                    if (cur >= 0 && cur != pick && ms[cur] >= 0 &&
                        health_of(o, o->devices[cur]) && ms[cur] - ms[pick] <= tol)
                        pick = cur;
                    if (!health_of(o, o->devices[pick])) pick = -1;
                }
                if (pick >= 0) {
                    chosen = o->devices[pick];
                    if (verbose)
                        fprintf(stderr, LOG_I "%s: по замеру выбран %s (%d мс, лучший %d, "
                                        "допуск %d)\n",
                                o->name, o->devices[pick], ms[pick], best, tol);
                }
            } else if (verbose) {
                /* Ни один замер не удался — режим молча становится прежним. Сказать надо:
                 * иначе человек думает, что выбор идёт по задержке, а он идёт по списку.
                 * Так бывает у выхода kind=xsteer, который не меряется никогда. */
                fprintf(stderr, LOG_W "%s: задержку измерить не удалось ни у одного "
                                "устройства — выбираю по порядку\n", o->name);
            }
        }

        if (!chosen && first_h >= 0) {
            if (cur > first_h) {
                /* Трафик сейчас на менее предпочтительном устройстве, а более
                 * предпочтительное ожило. Уходить с текущего, если оно ещё живо, спешить
                 * нельзя — это и есть мелькание. Держим его, пока верхнее не подтвердит
                 * здоровье STEER_FAILOVER_HYST тиков подряд. Мёртвое текущее — сразу вниз. */
                int hyst = failover_hyst();
                if (health_of(o, o->devices[cur])) {
                    int s = streak + 1;
                    if (hyst > 0 && s < hyst) { chosen = o->devices[cur]; new_streak = s; }
                    else chosen = o->devices[first_h];
                } else {
                    chosen = o->devices[first_h];
                }
            } else {
                /* first_h == cur (несём лучшее доступное) либо cur < first_h (текущее
                 * мертво — first_h это уход вниз): в обоих случаях берём first_h без
                 * задержки, счётчик сбрасываем. */
                chosen = o->devices[first_h];
            }
        }

        /* Ни одно не ответило — вот теперь можно тратить время на оживление. Порядок
         * тот же, поэтому основной туннель получает попытку первым. */
        if (!chosen && !via_down)
            for (size_t k = 0; k < o->devices_n; k++)
                if (revive(o, o->devices[k], verbose)) { chosen = o->devices[k]; break; }
        g_streak[i] = new_streak;
        alive[i] = chosen != NULL;
        /* Причину назвать надо: иначе «живых устройств нет» стоит у выхода, чьё устройство на
         * месте и чья проба, спроси её, ответила бы «да». Строка — на переходе в отказ (как и
         * объявление apply_failed) или при -v, а не на каждом проходе. */
        if (via_down && (verbose || strcmp(was, "-") != 0))
            fprintf(stderr, LOG_W "выход %s: идёт через %s, а тот не работает — выход "
                            "считается нерабочим\n", o->name, via->name);

        if (chosen) {
            snprintf(o->device, sizeof(o->device), "%s", chosen);
            if (strcmp(was, chosen) != 0) {
                bind_device(o, chosen);
                printf("steer: выход %s -> %s%s\n", o->name, chosen,
                       was[0] && strcmp(was, "-") ? " (переключение)" : "");
                changed = 1;
            } else {
                /* Имя устройства то же — и это НЕ значит, что маршрутизация цела.
                 * Спрашиваем ядро, а не свою память: см. «сверка фактического
                 * состояния» выше, там же почему пинг при этом идёт. */
                struct route_facts f = route_facts_read(o);
                if (!f.known) {
                    /* Состояние прочитать не удалось. Оставляем как есть: переписать живую
                     * привязку по незнанию хуже, чем не заметить поломку — та лечится
                     * следующим проходом, а провал трафика уже случится. Строка на проход
                     * при -v: молча гадать тоже нельзя. */
                    if (verbose)
                        fprintf(stderr, LOG_W "%s: состояние маршрутизации не прочитать "
                                        "(нет ip?) — ничего не меняю\n", o->name);
                } else if (!routing_live_ok(&f, chosen)) {
                    fprintf(stderr, LOG_W "выход %s: %s отвечает, но маршрутизация "
                                    "разъехалась (%s) — возвращаю маршрут\n",
                            o->name, chosen, facts_why(&f, chosen));
                    bind_device(o, chosen);
                    changed = 1;
                } else {
                    /* Маршрутизация цела, но у выхода с drop пропал запасной запрет (его снял
                     * кто-то снаружи, или таблицу ставил движок до этой версии). Возвращается
                     * одной командой, без перепривязки: соединения рвать не из-за чего. */
                    if (o->on_fail == FAIL_DROP && !f.backstop) backstop_set(o->table);
                    if (verbose) fprintf(stderr, LOG_I "%s: %s работает\n", o->name, chosen);
                }
            }
        } else {
            o->device[0] = '\0';
            /* Тоже по факту, а не по записи в active. Запись «-» говорит лишь о том, что
             * об отказе уже сообщали, а не о том, что заявленный on_fail всё ещё стоит в
             * ядре: клиент туннеля мог с тех пор подняться и привязать таблицу к
             * устройству, которое не отвечает, — тогда трафик уходит в мёртвый туннель
             * вместо остановки, обещанной on_fail=drop. */
            if (strcmp(was, "-") != 0) {
                apply_failed(o, 1);         /* отказ только что случился — объявляем */
                changed = 1;
            } else {
                struct route_facts f = route_facts_read(o);
                if (!f.known) {
                    /* То же, что в живой ветке: по незнанию не трогаем. Здесь цена ошибки
                     * даже выше — apply_failed при on_fail=drop останавливает трафик, и
                     * сделать это «на всякий случай» значило бы уронить работающий выход. */
                    if (verbose)
                        fprintf(stderr, LOG_W "%s: состояние маршрутизации не прочитать "
                                        "(нет ip?) — ничего не меняю\n", o->name);
                } else if (!routing_failed_ok(&f, o->on_fail)) {
                    fprintf(stderr, LOG_W "выход %s: живых устройств по-прежнему нет, а "
                                    "маршрутизация разъехалась (%s) — возвращаю "
                                    "on_fail=%s\n",
                            o->name, failed_why(&f, o->on_fail),
                            o->on_fail == FAIL_DROP ? "drop" :
                            o->on_fail == FAIL_ZAPRET ? "zapret" : "direct");
                    apply_failed(o, 0);
                    changed = 1;
                }
            }
        }
    }
    active_save();
    if (!changed && verbose) fprintf(stderr, LOG_I "изменений нет\n");
    return 0;
}
