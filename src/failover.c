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
#include "spec.h"

/* Уровень в журнале приписывается КАЖДОЙ строке — это контракт, по которому управляющий
 * слой (splify2) раскрашивает журнал, и он разбирает именно префикс, а не текст. Базовый
 * движок его не ставил вовсе, хотя контракт обещал: интерфейс из-за этого подписывал все
 * свежие строки про переключение устройств как «от более старого движка». */
#define LOG_W "steer[warn] failover: "
#define LOG_I "steer[info] failover: "

/* Таблица и приоритет правила для проб. Далеко от 300+, которые раздаёт реестр:
 * проба обязана быть невидимой для боевой маршрутизации. */
#define PROBE_TABLE 299
#define PROBE_PRIO  29999

/* Куда пинговать. Два адреса, потому что один может быть заблокирован именно в
 * этом туннеле, и тогда здоровый путь выглядел бы мёртвым. */
static const char *PROBE_TARGETS[] = { "1.1.1.1", "8.8.8.8", NULL };

int run_quiet(const char *const argv[]);   /* из steer.c */

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
static int tcp_reachable(const char *dev, const char *host, int port, int timeout_s) {
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

/* Живо ли устройство ДЛЯ КОНКРЕТНОГО ВЫХОДА.
 *
 * Вид выхода решает, чем проверять. Для kind=interface (wireguard, openvpn и т.п.)
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

static int device_healthy_for(const struct output *o, const char *dev) {
    if (!device_present(dev)) return 0;
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
    if (o->kind == OUT_VLESS) {
        for (int i = 0; PROBE_TARGETS[i]; i++)
            if (tcp_reachable(dev, PROBE_TARGETS[i], TCP_PROBE_PORT, TCP_PROBE_TIMEOUT))
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

static int zapret_running(void) {
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
                if (strstr(buf, "nfqws")) found = 1;
            }
            close(fd);
        }
    }
    closedir(d);
    return found;
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
    const char *add[] = { "ip", "rule", "add", "fwmark", m, "table", t, NULL };
    run_quiet(add);
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

/* announce=0 — то же самое приведение состояния в порядок, но без объявления отказа:
 * сторож зовёт apply_failed не только когда выход ТОЛЬКО ЧТО отказал, но и когда отказ
 * длится, а состояние в ядре с тех пор разъехалось (см. сверку ниже). Строку «живых
 * устройств нет» в этом случае печатает вызывающий, и печатает вместе с причиной
 * расхождения — иначе журнал раз в минуту повторял бы одно и то же без новостей. */
static void apply_failed(struct output *o, int announce) {
    char tbl[16];
    snprintf(tbl, sizeof(tbl), "%d", o->table);
    const char *flush[] = { "ip", "route", "flush", "table", tbl, NULL };
    run_quiet(flush);

    if (o->on_fail == FAIL_DROP) {
        /* blackhole, а не отсутствие маршрута: без маршрута пакет с меткой
         * провалится в следующую таблицу и уйдёт напрямую — то есть ровно туда,
         * куда его не пускали. */
        const char *bh[] = { "ip", "route", "add", "blackhole", "default",
                             "table", tbl, NULL };
        run_quiet(bh);
        /* Правило пересоздаётся и здесь. Без него blackhole лежит в таблице, которую
         * никто не спрашивает: помеченный пакет провалится дальше и уйдёт напрямую —
         * то самое, от чего on_fail=drop и защищает. А снять правило было кому:
         * прежний отказ мог случиться в режиме direct/zapret (ниже), и режим меняют
         * в интерфейсе, не перезапуская ничего. */
        rule_drop(o->mark, o->table);
        rule_add(o->mark, o->table);
        if (announce)
            fprintf(stderr, LOG_W "выход %s: живых устройств нет, трафик остановлен "
                            "(on_fail=drop)\n", o->name);
        return;
    }

    /* direct и zapret: снимаем правило, чтобы помеченный трафик шёл обычным путём. */
    rule_drop(o->mark, o->table);

    if (!announce) return;
    if (o->on_fail == FAIL_ZAPRET && !zapret_running())
        fprintf(stderr, LOG_W "выход %s: живых устройств нет, трафик пущен напрямую, "
                        "но zapret не запущен — обхода DPI не будет\n", o->name);
    else
        fprintf(stderr, LOG_W "выход %s: живых устройств нет, трафик пущен напрямую "
                        "(on_fail=%s)\n", o->name,
                o->on_fail == FAIL_ZAPRET ? "zapret" : "direct");
}

/* Привязать таблицу выхода к устройству. Правило пересоздаётся, потому что режим
 * отказа мог его снять, а `ip rule add` дубликаты не проверяет.
 *
 * Не static: этим же пользуется клиент VLESS, когда поднял своё устройство. Он —
 * единственный, кто знает момент, когда TUN готов нести трафик, и ждать этого момента
 * снаружи невозможно: procd запускает экземпляр только после того, как init-скрипт
 * закончил работу, то есть уже после apply. Одна функция вместо второй копии тех же
 * трёх команд — иначе привязка «от клиента» и «от сторожа» разъехались бы. */
void bind_device(struct output *o, const char *dev) {
    char tbl[16];
    snprintf(tbl, sizeof(tbl), "%d", o->table);

    rule_drop(o->mark, o->table);
    rule_add(o->mark, o->table);
    const char *flush[] = { "ip", "route", "flush", "table", tbl, NULL };
    run_quiet(flush);
    const char *rt[] = { "ip", "route", "add", "default", "dev", dev, "table", tbl, NULL };
    if (run_quiet(rt) != 0) {
        /* Отказ здесь оставляет таблицу ПУСТОЙ, а пустая таблица — это не «нет
         * маршрута», а «ищи дальше»: помеченный пакет провалится в следующую таблицу и
         * уйдёт напрямую, то есть ровно туда, куда его не пускали. Причём flush выше
         * только что снял blackhole, который apply поставил при on_fail=drop, — молча
         * исчезает не маршрут, а сама защита. То же решение уже принято в apply_routing
         * (steer.c) и в apply_failed выше; здесь оно обязано совпадать, иначе один и тот
         * же порядок команд означает в трёх местах разное.
         *
         * Достижимо и после H-081: устройство исчезло между проверкой и привязкой (свой
         * же процесс туннеля умер), таблица занята чужим маршрутом, нет прав. */
        fprintf(stderr, LOG_W "выход %s: не удалось привязать таблицу %s к %s — "
                        "устройство ещё живо?\n", o->name, tbl, dev);
        if (o->on_fail == FAIL_DROP) {
            const char *bh[] = { "ip", "route", "add", "blackhole", "default",
                                 "table", tbl, NULL };
            run_quiet(bh);
            fprintf(stderr, LOG_W "выход %s: трафик остановлен до успешной привязки "
                            "(on_fail=drop)\n", o->name);
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
    if (of == FAIL_DROP) return f->rule && f->table == TBL_BLACKHOLE;
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
        return "таблица пуста — помеченный трафик уходил напрямую";
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

static void active_get(const char *out, char *dev, size_t n) {
    dev[0] = '\0';
    char path[256];
    active_path(path, sizeof(path));
    FILE *f = fopen(path, "r");
    if (!f) return;
    char name[32], d[32];
    while (fscanf(f, "%31s %31s\n", name, d) == 2)
        if (!strcmp(name, out)) snprintf(dev, n, "%s", d);
    fclose(f);
}

static void active_save(void) {
    char path[256];
    active_path(path, sizeof(path));
    FILE *f = fopen(path, "w");
    if (!f) return;
    for (size_t i = 0; i < g_out_n; i++)
        if (out_has_device(&g_out[i]))
            fprintf(f, "%s %s\n", g_out[i].name, g_out[i].device[0] ? g_out[i].device : "-");
    fclose(f);
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

    /* Устройство vless и xsteer создаёт НАШ процесс, а не netifd. ifdown/ifup здесь
     * бесполезны — netifd про это устройство не знает («Interface vl not found») — и на
     * живом роутере это выглядело как вечный холостой цикл перезапусков в журнале.
     * Падение процесса ловит procd (init-скрипт ставит respawn), и подъём заново выбирает
     * рабочий узел (vless) или заново здоровается с хабом (xsteer) сам. У сторожа здесь
     * одна задача: сообщить, что туннель молчит, и подождать — кому именно ждать, тот
     * поднимется сам. */
    if (out_engine_managed(o)) {
        fprintf(stderr, LOG_W "%s: не отвечает — процесс туннеля должен подняться "
                        "заново через procd; жду\n", dev);
        for (int i = 0; i < 10; i++) {
            sleep(1);
            if (device_healthy_for(o, dev)) return 1;
        }
        return 0;
    }

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

    load_spec(spec);
    registry_assign();

    int changed = 0;
    for (size_t i = 0; i < g_out_n; i++) {
        struct output *o = &g_out[i];
        if (!out_has_device(o)) continue;

        char was[32];
        active_get(o->name, was, sizeof(was));

        const char *chosen = NULL;
        /* Сначала все по одному разу без перезапусков: если запасной здоров, поднимать
         * основной незачем — трафик уже пойдёт. Перезапуск дороже проверки и на
         * секунды роняет то, что перезапускают. */
        for (size_t k = 0; k < o->devices_n; k++) {
            if (device_healthy_for(o, o->devices[k])) { chosen = o->devices[k]; break; }
            if (verbose)
                fprintf(stderr, LOG_W "%s: %s не отвечает\n", o->name, o->devices[k]);
        }

        /* Ни одно не ответило — вот теперь можно тратить время на оживление. Порядок
         * тот же, поэтому основной туннель получает попытку первым. */
        if (!chosen)
            for (size_t k = 0; k < o->devices_n; k++)
                if (revive(o, o->devices[k], verbose)) { chosen = o->devices[k]; break; }

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
                } else if (verbose) {
                    fprintf(stderr, LOG_I "%s: %s работает\n", o->name, chosen);
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
