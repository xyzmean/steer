/* steer failover — выбрать живое устройство для каждого выхода.
 *
 * Один проход по вызову (failover_pass), состояние — в маршрутных таблицах ядра, в
 * реестре и в памяти сторожа между проходами (active, latency, restart-*). «Раз в минуту» —
 * дело того, кто проход зовёт: init-скрипт кругом `steer failover`, `failover --loop`
 * (watch.c) или демон с --watch (watchd.c). Где лежит память между проходами — файлы или
 * память демона, — решает тот же вызывающий, см. fostate.h.
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
#include <sys/epoll.h>
#include <ctype.h>
#include <linux/netlink.h>
#include <linux/rtnetlink.h>
#include "spec.h"
#include "awg.h"
#include "run.h"
#include "rtnl.h"
#include "loop.h"
#include "foprobe.h"
#include "gaiw.h"
#include "failover_int.h"
#include "fostate.h"

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

/* Чтение правил и таблицы — определено ниже, у сверки состояния; нужно и привязке таблицы. */
static void rules_show(char *out, size_t n);
static void routes_show(int table, char *out, size_t n);

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

/* ПРОБА TCP — доступен ли внешний адрес ПО TCP через данное устройство.
 *
 * Зачем отдельная проверка, а не ICMP: VLESS-туннель пропускает ТОЛЬКО TCP (клиент завершает
 * TCP у себя и соединяется с сервером обычным сокетом — ICMP сквозь него не идёт
 * принципиально). Проба ICMP отвечала «мёртв» на полностью рабочем туннеле kind=vless: на
 * живом роутере это выглядело как вечное «vl: не отвечает — перезапускаю интерфейс» в журнале
 * и гоняло ifdown/ifup по устройству, которым netifd вовсе не управляет.
 *
 * SO_BINDTODEVICE привязывает сокет именно к этому устройству, не полагаясь на метки и таблицы
 * маршрутизации: проба обязана идти тем путём, который мы проверяем. Соединение неблокирующее и
 * ждётся циклом событий со сроком (foprobe_tcp в foprobe.c) — на чёрной дыре проба стоит не
 * дольше срока и не держит при этом ни цикл демона, ни процесс.
 *
 * Задержка меряется там же, от начала соединения до установления: интересует время до
 * установления соединения, а не время работы функции (на неудачном кандидате разница между
 * ними — целый срок). CLOCK_MONOTONIC, а не время суток: подводка часов ntpd на только что
 * поднявшемся роутере — обычное дело, и замер по стенным часам дал бы отрицательную задержку.
 *
 * ПРОБА ICMP — живо ли устройство на самом деле. operstate у туннеля почти всегда "unknown" и
 * остаётся таким, когда пир давно молчит, — поэтому решает пакет, дошедший до настоящего
 * адреса, а не то, что о себе сообщает интерфейс. Нет адреса IPv4 у устройства — оно не готово
 * нести трафик, и проба отвечает «нет» сразу.
 *
 * Эхо-запрос шлёт сам процесс (foprobe_icmp: сырой сокет, ping-сокет, внешний ping — последним
 * откатом), с сокета, привязанного к устройству (SO_BINDTODEVICE) и к его адресу. И при этом
 * на время пробы по-прежнему ставится правило `from <адрес устройства> lookup 299` с
 * `default dev <устройство>` в таблице 299 — теперь сообщениями rtnetlink, без запуска `ip`.
 * SO_BINDTODEVICE его НЕ заменяет полностью, и вот почему. Привязка к устройству решает только
 * путь ТУДА: поиск маршрута с заданным устройством пропускает маршруты через другие устройства,
 * а не найдя ничего, считает адресата «за этим устройством». Путь ОБРАТНО она не решает: ответ
 * приходит с устройства туннеля от 1.1.1.1, и при строгой проверке обратного пути (rp_filter=1)
 * ядро спрашивает, ведёт ли маршрут к 1.1.1.1 с нашего адреса туда же, откуда пришёл пакет. По
 * таблице main он ведёт в WAN — ответ выбрасывается, и живой запасной туннель выглядел бы
 * мёртвым. Правило по адресу источника отвечает на этот вопрос «да, через устройство пробы», и
 * отвечает только для адреса самого устройства: живой путь им не задет. Так проверка НЕ трогает
 * живой путь — чтобы проверить запасной туннель, не нужно на него переключаться.
 *
 * Убрать правило обязательно: оставленное, оно пережило бы пробу и молча увело бы трафик
 * источника в таблицу, которую никто больше не наполняет. Снимается оно в конце пробы, при
 * отмене прохода (демон уходит) и — от прохода, убитого SIGKILL, — при старте сторожа
 * (cleanup_probe_rule). */

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
    snprintf(path, sizeof(path), "%s/xsteer-%.40s.json", steer_state_dir(), dev);
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

/* ---- источник здоровья помощника: файлы (fostate.h) ----------------------------------------
 *
 * Прежний путь, байт в байт те же вопросы: ход перебора узлов — запись probe-<выход>, которую
 * пишет клиент vless (probe_report); туннель xsteer, поднятый netifd, — его файл состояния;
 * оживление обфускатора — сигналом экземпляру procd (у прохода, restart здесь нет). Из записи
 * перебора проходу нужно то же, что и раньше: «идёт перебор» и «номера нет в подписке».
 * «Ни один узел не ответил» (PROBE_FAILED) проход не читал и не читает: устройства в этом случае
 * нет, и приговор ему выносит наличие устройства. */
static int files_state(struct fo_hsrc *s, const char *out, struct fo_hstate *h) {
    (void)s;
    struct probe_status pr = probe_read(out);
    h->node = pr.node;
    h->total = pr.total;
    if (pr.state == PROBE_RUNNING) { h->st = FO_HS_PROBING; return 0; }
    if (pr.state == PROBE_NO_SUCH_NODE) { h->st = FO_HS_NONODE; return 0; }
    h->st = FO_HS_UNKNOWN;
    return -1;
}

static int files_xsdev(struct fo_hsrc *s, const char *dev, int *up, int *fresh) {
    (void)s;
    return xs_state_read(dev, up, fresh);
}

static const struct fo_hsrc_ops files_hops = {
    files_state, files_xsdev, NULL, "процесс туннеля должен подняться заново через procd",
};
struct fo_hsrc fo_hsrc_files = { &files_hops };

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
 * задержки кандидатов, не поднимая сокетов. В бою указатель NULL и меряет device_latency.
 * Объявление (extern) — в failover_int.h: его присваивает tests/failovermatch.c. */
int (*g_latency_probe)(const struct spec *, const struct output *, const char *);

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
 * Вид, которому такой замер не годится, отвечает сам (kind_ops.latency): xsteer не меряется
 * НИКОГДА — см. kinds/xsteer.c. */
/* Сама проба — hp_start (замер) ниже, в автомате прохода. */

/* Владелец устройства. Объяснение — у объявления в spec.h; там же сказано, почему функция
 * объявлена рядом со спекой, а живёт здесь (тот же случай, что bind_device). */
const struct output *device_owner(const struct spec *sp, const char *dev) {
    for (size_t i = 0; i < sp->out_n; i++) {
        const struct output *c = &sp->out[i];
        if (!out_engine_managed(c)) continue;
        if (!strcmp(c->device, dev)) return c;
        for (size_t k = 0; k < c->devices_n; k++)
            if (!strcmp(c->devices[k], dev)) return c;
    }
    return NULL;
}

const struct output *out_for_device(const struct spec *sp, const struct output *o, const char *dev) {
    const struct output *owner = device_owner(sp, dev);
    return owner ? owner : o;
}

/* Проба здоровья вызывается через указатель, а не напрямую, ровно ради одного: стенд
 * гистерезиса задаёт здоровье устройств по тику, не создавая интерфейсов в /sys и не открывая
 * сокетов. В бою указатель НИКОГДА не меняется и равен NULL — тогда спрашивается устройство
 * (hp_start ниже); ветка предсказуемая, той же природы, что швы путей для стендов в остальном
 * коде. Объявление (extern) — в failover_int.h: его присваивает tests/failovermatch.c.
 *
 * Мера здоровья принадлежит УСТРОЙСТВУ, а не виду выхода, который его назвал: у устройства с
 * владельцем спрашиваем так, как спросил бы владелец (out_for_device). Своя мера у вида
 * владельца (kind_ops.health): xsteer — наличие устройства (пинг наружу через хаб полной звезды
 * теряется на исправном туннеле, kinds/xsteer.c), awg — свежесть рукопожатия и счётчики пира в
 * ядре (kinds/awg.c). Туннель xsteer, поднятый netifd, судится своим файлом состояния (см.
 * xs_state_read выше): спека про него знает только имя устройства, а про рукопожатие с хабом
 * знает его собственный клиент. Устаревший файл (писавшего процесса нет) возвращает нас к
 * наличию устройства: врать в сторону «сломано» здесь дороже всего — при on_fail=drop это
 * blackhole работающему выходу. Туннель, который завершает TCP у себя (vless), — пробой TCP;
 * остальное — пробой ICMP. */
int (*g_health_probe)(const struct spec *, const struct output *, const char *);

/* Работает ли обход (zapret_running) и жив ли обработчик очереди (nfqws_on_queue) — вопросы к
 * процессам nfqws, они в kinds/zapret.c. */

/* Куда направить таблицу выхода, когда живых устройств нет.
 *
 * drop   — blackhole: трафик канала останавливается заметно и никуда не утекает;
 * direct — правило снимается, трафик идёт как обычный (осознанный выбор);
 * zapret — то же, что direct, но нужен работающий обход DPI, иначе это просто
 *          direct под другим именем, о чём и сообщаем. */

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
/* struct rule_copies и RULE_COPIES_MAX — в failover_int.h: их читает и стенд failovermatch. */
struct rule_copies rule_copies_of(const char *rules, uint32_t mark, int table) {
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
    rules_show(rules, sizeof(rules));
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
    char t[16];
    snprintf(t, sizeof(t), "%d", table);
    routes_show(table, routes, sizeof(routes));
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

/* enum tbl_state и struct route_facts (known — удалось ли вообще прочитать состояние ядра;
 * это не перестраховка, а защита от худшего исхода всей затеи — см. failover_int.h) — в
 * failover_int.h: их читает и стенд failovermatch.
 *
 * Разбор дословного вывода `ip rule show` и `ip route show table N`.
 *
 * Чистая функция, без единого вызова ip: иначе решение «состояние разъехалось» нельзя
 * было бы закрыть стендом, а ошибка именно здесь ничего не сломает заметно — она просто
 * оставит туннель мёртвым до перезапуска движка, то есть вернёт ту самую неполадку.
 * Стенд: tests/failovermatch.c. */
struct route_facts route_facts_of(const char *rules, const char *routes,
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
int routing_live_ok(const struct route_facts *f, const char *dev) {
    return f->rule && f->table == TBL_DEV && strcmp(f->dev, dev) == 0;
}

/* Годится ли фактическое состояние для «живых устройств нет» при данном режиме отказа.
 * drop требует и правила, и запрета в таблице: запрет без правила — это утечка напрямую
 * (таблицу никто не спрашивает), правило без запрета — трафик в мёртвый туннель. */
int routing_failed_ok(const struct route_facts *f, enum on_fail of) {
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

/* Прочитать состояние ядра: правила (`ip -4 rule show`) и таблицу (`ip -4 route show table N`)
 * — сообщениями rtnetlink, напечатанными в той же форме (src/lib/rtnl.h: почему текстом и в
 * чём отличие от iproute2). Раньше это был popen `ip`: два процесса на выход на каждом проходе,
 * а сторож в демоне работает без процессов на проход. Не прочиталось — пустой текст, то есть
 * «состояние не известно», и сверка ничего не трогает (см. route_facts.known).
 *
 * Шов g_ip_show — для стенда failovermatch: ему ядро не дают, и он отвечает дословными дампами
 * `ip` с живого роутера (table < 0 — правила). В бою NULL. */
int (*g_ip_show)(int table, char *out, size_t n);

static void rules_show(char *out, size_t n) {
    out[0] = '\0';
    if (g_ip_show) { g_ip_show(-1, out, n); return; }
    rtnl_rules_text(out, n);
}

static void routes_show(int table, char *out, size_t n) {
    out[0] = '\0';
    if (g_ip_show) { g_ip_show(table, out, n); return; }
    rtnl_routes_text(table, out, n);
}

static struct route_facts route_facts_read(const struct output *o) {
    /* Статические, и с запасом. Вывод `ip rule show` — это ВСЕ правила коробки, а не
     * только наши: рядом живут mwan3, fw4 и чужие туннели, у которых правил бывают
     * десятки. Обрезанный дамп означал бы «нашего правила нет» и пересоздание живой
     * привязки каждую минуту — то есть короткий провал помеченного трафика на ровном
     * месте. Статические: буферы большие, а проход однопоточный (в демоне — на цикле событий,
     * по одному шагу за раз), и делить с ними стек незачем. */
    static char rules[16384], routes[8192];
    rules_show(rules, sizeof(rules));
    routes_show(o->table, routes, sizeof(routes));
    return route_facts_of(rules, routes, o->mark, o->table);
}

/* ---- хранилище состояния сторожа: файлы каталога состояния ---------------------------
 *
 * Шов и почему он — в fostate.h. Здесь прежний путь: запись — файл <state_dir>/<имя>.
 * Замена — через временный файл и rename: status и apply читают `active` в любой момент, и
 * половина строк означала бы для них «сторож не проходил» у половины выходов; половина
 * замеров `latency` хуже их отсутствия (по ней сторож переключился бы на кандидата, чей замер
 * уцелел). */
static FILE *files_open_r(struct fo_store *st, const char *name) {
    (void)st;
    char path[320];
    snprintf(path, sizeof(path), "%s/%s", steer_state_dir(), name);
    return fopen(path, "r");
}

static void files_put(struct fo_store *st, const char *name, const char *data, size_t n) {
    (void)st;
    char path[320], tmp[336];
    snprintf(path, sizeof(path), "%s/%s", steer_state_dir(), name);
    snprintf(tmp, sizeof(tmp), "%s.tmp", path);
    FILE *f = fopen(tmp, "w");
    if (!f) return;
    size_t w = n ? fwrite(data, 1, n, f) : 0;
    if (fclose(f) != 0 || w != n || rename(tmp, path) != 0) unlink(tmp);
}

static const struct fo_store_ops files_ops = { files_open_r, files_put };
struct fo_store fo_store_files = { &files_ops };

/* Гистерезис возврата: сколько тиков подряд более предпочтительное устройство обязано быть
 * здоровым, прежде чем пул вернётся к нему с запасного. Возврат наверх «мгновенно, как только
 * ожил» на живом роутере обернулся мельканием: узел-предпочтение №0 подхватывался пробой раз в
 * минуту, трафик прыгал на него и через минуту падал обратно — и так по кругу, каждый прыжок
 * это до минуты мёртвого трафика. УХОД с мёртвого устройства при этом мгновенен и гистерезисом
 * не задерживается: держать трафик на упавшем туннеле нельзя. 0 — прежнее поведение (без
 * задержки). Читается один раз: окружение процесса за его жизнь не меняется. */
static int g_hyst_cache = -2;
static int failover_hyst(void) {
    if (g_hyst_cache == -2) {
        const char *e = getenv("STEER_FAILOVER_HYST");
        g_hyst_cache = e ? atoi(e) : 3;
        if (g_hyst_cache < 0) g_hyst_cache = 0;
    }
    return g_hyst_cache;
}
/* Стенду нужно менять порог между проходами одного процесса; в бою это не зовётся.
 * Объявление — в failover_int.h. */
void failover_hyst_reset_for_test(void) { g_hyst_cache = -2; }

/* Счётчик подряд-здоровых тиков более предпочтительного устройства — рядом с активным, третьим
 * полем в том же файле. Все читатели файла обязаны СЪЕДАТЬ три поля, иначе оставшийся на строке
 * счётчик уедет в имя следующего выхода. Старый файл без счётчика читается как ноль. Серия
 * прохода — массив по выходам спеки у failover_pass, в хранилище она уходит с active_save. */

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

static long mono_now(void) {
    struct timespec t;
    clock_gettime(CLOCK_MONOTONIC, &t);
    return (long)t.tv_sec;
}

static int lat_get(struct fo_store *st, const char *out, const char *dev, int *ms, long *age) {
    FILE *f = st->ops->open_r(st, "latency");
    if (!f) return 0;
    char o[32], d[32];
    int v = 0; long at = 0, found = 0;
    while (fscanf(f, "%31s %31s %d %ld", o, d, &v, &at) == 4)
        if (!strcmp(o, out) && !strcmp(d, dev)) { *ms = v; *age = mono_now() - at; found = 1; }
    fclose(f);
    return (int)found;
}

/* Записать замеры выхода, оставив записи остальных на месте. Заменой целиком (у файлов —
 * временный файл и rename, см. files_put): обрыв на середине оставил бы половину строк. */
static void lat_put(struct fo_store *st, const char *out, char devs[][32], int *ms, size_t n) {
    char *buf = NULL;
    size_t bn = 0;
    FILE *old = st->ops->open_r(st, "latency");
    FILE *f = open_memstream(&buf, &bn);
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
    if (fclose(f) == 0) st->ops->put(st, "latency", buf, bn);
    free(buf);
}

static int active_streak_get(struct fo_store *st, const char *out) {
    FILE *f = st->ops->open_r(st, "active");
    if (!f) return 0;
    char name[32], d[32];
    int sk = 0, val = 0;
    while (fscanf(f, "%31s %31s %d", name, d, &sk) >= 2) {
        if (!strcmp(name, out)) val = sk;
        sk = 0;   /* следующая запись без третьего поля не должна унаследовать этот */
    }
    fclose(f);
    return val;
}

static void active_get_st(struct fo_store *st, const char *out, char *dev, size_t n) {
    dev[0] = '\0';
    FILE *f = st->ops->open_r(st, "active");
    if (!f) return;
    char name[32], d[32];
    int sk = 0;
    while (fscanf(f, "%31s %31s %d", name, d, &sk) >= 2) {
        if (!strcmp(name, out)) snprintf(dev, n, "%s", d);
        sk = 0;
    }
    fclose(f);
}

void active_get(const char *out, char *dev, size_t n) {
    active_get_st(&fo_store_files, out, dev, n);
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
 * Заменой целиком (у файлов — через временный файл и rename, см. files_put): status и apply
 * читают этот файл в любой момент. */
static void active_save(struct fo_store *st, const struct spec *sp, const int *streak) {
    char want[MAX_OUTPUTS * 80 + 1];
    size_t wn = 0;
    for (size_t i = 0; i < sp->out_n; i++) {
        if (!out_has_device(&sp->out[i])) continue;
        int w = snprintf(want + wn, sizeof(want) - wn, "%s %s %d\n", sp->out[i].name,
                         sp->out[i].device[0] ? sp->out[i].device : "-", streak[i]);
        if (w < 0 || (size_t)w >= sizeof(want) - wn) break;
        wn += (size_t)w;
    }
    FILE *f = st->ops->open_r(st, "active");
    if (f) {
        char have[sizeof(want) + 1];
        size_t hn = fread(have, 1, sizeof(have), f);
        fclose(f);
        if (hn == wn && memcmp(have, want, wn) == 0) return;
    }
    st->ops->put(st, "active", want, wn);
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
void outputs_adopt_active(struct spec *sp) {
    outputs_adopt_active_st(sp, &fo_store_files);
}

void outputs_adopt_active_st(struct spec *sp, struct fo_store *st) {
    for (size_t i = 0; i < sp->out_n; i++) {
        struct output *o = &sp->out[i];
        if (!out_has_device(o)) continue;

        char rec[32];
        active_get_st(st, o->name, rec, sizeof(rec));   /* читает три поля — см. active_get */
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

static int restart_allowed(struct fo_store *st, const char *dev) {
    char name[48];
    snprintf(name, sizeof(name), "restart-%.32s", dev);
    FILE *f = st->ops->open_r(st, name);
    long last = 0;
    if (f) { if (fscanf(f, "%ld", &last) != 1) last = 0; fclose(f); }
    long now = (long)time(NULL);
    if (last && now - last < RESTART_COOLDOWN) return 0;
    char txt[32];
    int tn = snprintf(txt, sizeof(txt), "%ld\n", now);
    if (tn > 0) st->ops->put(st, name, txt, (size_t)tn);
    return 1;
}

void cleanup_probe_rule(void) {
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

void failover_pass_guard(void) {
    signal(SIGINT, sig_cleanup);
    signal(SIGTERM, sig_cleanup);
    /* Снять probe-rule, оставшийся от ПРЕЖНЕГО прохода, прежде чем ставить свой.
     * Обработчики выше и отмена прохода закрывают обычное завершение, но не SIGKILL и не
     * OOM-killer (I-022): после жёсткого убийства правило жило в ядре до ручной
     * чистки. Уборка при старте сторожа восстанавливает состояние независимо от
     * того, как умер предыдущий процесс, и идемпотентна — нет правила, нет дела. */
    cleanup_probe_rule();
}

static const char *on_fail_name(enum on_fail of) {
    return of == FAIL_DROP ? "drop" : of == FAIL_ZAPRET ? "zapret" : "direct";
}

/* Сказать получателю о перемене, если он есть. */
static void fo_emit(fo_event_fn ev, void *arg, enum fo_ev_kind kind, const struct output *o,
                    const char *from, const char *to, const char *why) {
    if (!ev) return;
    struct fo_event e = { kind, o->name, from, to, why, on_fail_name(o->on_fail) };
    ev(arg, &e);
}

/* ==== ПРОХОД — КОНЕЧНЫЙ АВТОМАТ НА ЦИКЛЕ СОБЫТИЙ ===========================================
 *
 * Решение владельца: сторож в демоне работает без fork на проход (docs/architecture.md, «4а»).
 * Всё, чего проход ждёт, — пробы устройств, внешние команды оживления, подъём устройства,
 * разрешение имени Endpoint, — он ждёт не синхронно, а шагом автомата: начал ожидание,
 * вернул управление циклу, а по готовности дескриптора, срабатыванию таймера или выходу
 * ребёнка продолжил с того места, где остановился. Цикл при этом свободен: демон отвечает на
 * status и apply посреди пробы, которая ждёт свои три секунды.
 *
 * ЛОГИКА ОДНА. Автомат — это прежний проход, разложенный по шагам, а не второй проход рядом с
 * ним: порядок обхода по via, «первый живой по предпочтению», гистерезис возврата, выбор по
 * замеру с допуском, оживление по порядку, сверка маршрутизации и on_fail — те же решения в том
 * же порядке, с теми же пробами (и тем же их числом: проба, которой прежний код не делал из-за
 * короткого замыкания условия, не делается и здесь). Состояния ниже названы по местам прежнего
 * кода, где он ждал. Им же пользуются все, кто проход зовёт:
 *   - демон с --watch (watchd.c) — на своём цикле, fo_pass_start;
 *   - `steer failover --loop` (watch.c) — на своём цикле, тоже fo_pass_start: fork на проход
 *     ушёл и оттуда;
 *   - `steer failover` — failover_pass: заводит цикл, крутит его до конца прохода и выходит.
 *
 * Что по-прежнему синхронно: действия над ядром в конце шага выхода — привязка таблицы
 * (`ip route replace`, `ip rule`), снятие соединений, отметка в наборе nft. Это доли
 * миллисекунды у ядра и случаются только при перемене (привязка, отказ, починка разъехавшегося
 * состояния), а не на каждом проходе; откладывать их значило бы откладывать решения прохода
 * до его конца. Сверка же, которая идёт на каждом проходе, читает ядро сообщениями rtnetlink
 * без процессов (rules_show, routes_show выше). Итог: проход по исправной спеке не запускает
 * ни одного процесса; процесс появляется только на ДЕЙСТВИЕ — ifdown/ifup, сигнал помощнику
 * через ubus, перепривязку, — или на пробу там, где проба ICMP из процесса запрещена (foprobe.h).
 *
 * ОЖИДАНИЕ ПОДЪЁМА при оживлении — десять шагов по секунде, как и было, но шаг — это таймер
 * цикла, а не sleep; и событие netlink о самом устройстве (появилось, поднялось, получило
 * адрес) проверяет его сразу, не дожидаясь конца шага. Такая внеочередная проверка шагом не
 * считается — предел ожидания прежний, — и за шаг она одна: пачка событий от одного ifup не
 * превращается в пачку проб. */

#define ICMP_PROBE_TIMEOUT_MS 3000                     /* как у прежнего `ping -W 3` */
#define TCP_PROBE_TIMEOUT_MS  (TCP_PROBE_TIMEOUT * 1000)
#define REVIVE_WAIT_STEPS 10
#define REVIVE_STEP_MS 1000
/* Предел внешней команды оживления (ifdown, ifup, ubus): не ответила — SIGKILL её группе.
 * Раньше предел был один на весь проход (десять минут у ребёнка демона); теперь зависнуть
 * может только команда, а не проход. */
#define CMD_MAX_MS 60000

/* Швы для стенда failovermatch (объявления — в failover_int.h). В бою все NULL. */
int (*g_icmp_probe)(const char *dev);
int (*g_cmd_hook)(const char *const argv[]);
long (*g_revive_step)(void);

enum fo_state {
    S_START, S_OUT, S_SCAN, S_SCAN_R, S_LAT, S_LAT_M, S_LAT_M_R, S_LAT_C, S_LAT_CUR_R,
    S_LAT_PICK, S_LAT_PICK_R, S_HYST, S_HYST_R, S_REV0, S_REV, S_REV_R, S_FIN, S_END,
    S_PROBE_ONLY, S_PROBE_ONLY_R, S_REVIVE_ONLY, S_REVIVE_ONLY_R,
    RV_START, RV_UBUS_R, RV_PAUSE, RV_DOWN, RV_DOWN_R, RV_UP_R, RV_WAIT_INIT, RV_WAIT_ARM,
    RV_WAITING, RV_WAIT_PROBE, RV_WAIT_R, RV_EV_PROBE, RV_EV_R, RV_KIND, RV_KIND_GO,
};

/* Вид пробы: здоровье через шов стенда (в проходе), здоровье устройства без шва (ожидание
 * подъёма при оживлении — так было и раньше: там спрашивалось само устройство), замер. */
enum { HP_HEALTH, HP_HEALTH_REAL, HP_LATENCY };

struct fo_run {
    struct loop *l;
    struct spec *sp;
    struct fo_store *st;
    struct fo_hsrc *hs;               /* источник здоровья помощников (fostate.h) */
    int verbose;
    fo_event_fn ev;
    void *ev_arg;
    fo_done_fn done;
    void *done_arg;
    struct loop_timer *kick;          /* первый шаг — оборотом цикла, а не изнутри fo_pass_start */
    enum fo_state s;
    int res;                          /* итог последнего ожидания */

    /* ---- проход (прежние локальные переменные failover_pass) ---- */
    int changed;
    int streak_new[MAX_OUTPUTS];
    int alive[MAX_OUTPUTS];           /* кто в ЭТОМ проходе нашёл живое устройство */
    size_t ord[MAX_OUTPUTS], ord_n, oi;
    size_t i;
    struct output *o;
    const struct output *via;
    int via_down;
    char was[32];
    int cur, first_h;
    size_t k;
    const char *chosen;
    int streak, new_streak, by_latency, cur_dead;
    int tol;
    long iv;
    int ms[MAX_DEVICES];
    int best, pick;

    /* ---- идущая проба ---- */
    struct {
        int kind;
        char dev[32];
        int ti, best, rule;
        char src[64];
        struct foprobe *p;
    } hp;

    /* ---- идущее оживление ---- */
    struct {
        enum fo_state ret;
        const struct output *o;
        const struct output *ow;
        char dev[32];
        int i, extra, timer_fired;
        struct loop_timer *tm;
        int nl;
        struct fospawn *sp;
        struct gaiw *gw;
        struct kind_name names[KIND_NAMES_MAX];
        size_t nn;
    } rv;
};

static void fo_step(struct fo_run *r);

/* ---- проба --------------------------------------------------------------------------------- */

/* Правило пробы — см. шапку «ПРОБА ICMP» выше, почему оно остаётся при SO_BINDTODEVICE. */
static void probe_rule_set(struct fo_run *r) {
    struct in_addr src;
    if (inet_aton(r->hp.src, &src) == 0) return;
    rtnl_rule_from(0, src, PROBE_TABLE, PROBE_PRIO);
    unsigned idx = if_nametoindex(r->hp.dev);
    if (idx) rtnl_route_default_dev(PROBE_TABLE, (int)idx);
    rtnl_rule_from(1, src, PROBE_TABLE, PROBE_PRIO);
    r->hp.rule = 1;
}

static void probe_rule_clear(struct fo_run *r) {
    if (!r->hp.rule) return;
    struct in_addr src;
    if (inet_aton(r->hp.src, &src) != 0) rtnl_rule_from(0, src, PROBE_TABLE, PROBE_PRIO);
    rtnl_table_flush(PROBE_TABLE);
    r->hp.rule = 0;
}

/* Итог TCP-цели: 1 — решено (здоровье нашло живую цель). Замер спрашивает все цели и берёт
 * ЛУЧШУЮ, а не первую ответившую: цели в разных сетях, и «первая ответила за 300 мс» на
 * канале, где вторая отвечает за 20, — это не задержка канала. */
static int hp_tcp_take(struct fo_run *r, int ok, int ms) {
    if (r->hp.kind == HP_LATENCY) {
        if (ok && ms >= 0 && (r->hp.best < 0 || ms < r->hp.best)) r->hp.best = ms;
        return 0;
    }
    if (ok) { r->res = 1; return 1; }
    return 0;
}

static void hp_tcp_cb(void *arg, int ok, int ms);

/* 1 — проба идёт; 0 — кончилась, итог в r->res. */
static int hp_tcp_next(struct fo_run *r) {
    for (; PROBE_TARGETS[r->hp.ti]; r->hp.ti++) {
        int ok = 0, ms = -1;
        r->hp.p = foprobe_tcp(r->l, r->hp.dev, PROBE_TARGETS[r->hp.ti], TCP_PROBE_PORT,
                              TCP_PROBE_TIMEOUT_MS, hp_tcp_cb, r, &ok, &ms);
        if (r->hp.p) return 1;
        if (hp_tcp_take(r, ok, ms)) return 0;
    }
    r->res = r->hp.kind == HP_LATENCY ? r->hp.best : 0;
    return 0;
}

static void hp_tcp_cb(void *arg, int ok, int ms) {
    struct fo_run *r = arg;
    r->hp.p = NULL;
    if (!hp_tcp_take(r, ok, ms)) {
        r->hp.ti++;
        if (hp_tcp_next(r)) return;
    }
    fo_step(r);
}

static void hp_icmp_cb(void *arg, int ok, int ms);

static int hp_icmp_next(struct fo_run *r) {
    for (; PROBE_TARGETS[r->hp.ti]; r->hp.ti++) {
        int ok = 0;
        r->hp.p = foprobe_icmp(r->l, r->hp.dev, r->hp.src, PROBE_TARGETS[r->hp.ti],
                               ICMP_PROBE_TIMEOUT_MS, hp_icmp_cb, r, &ok);
        if (r->hp.p) return 1;
        if (ok) break;
    }
    r->res = PROBE_TARGETS[r->hp.ti] != NULL;
    probe_rule_clear(r);
    return 0;
}

static void hp_icmp_cb(void *arg, int ok, int ms) {
    (void)ms;
    struct fo_run *r = arg;
    r->hp.p = NULL;
    if (ok) {
        r->res = 1;
        probe_rule_clear(r);
    } else {
        r->hp.ti++;
        if (hp_icmp_next(r)) return;
    }
    fo_step(r);
}

/* Спросить устройство dev выхода o. Состояние, в котором продолжить, вызывающий ставит ДО
 * вызова. 1 — проба идёт (вызывающий возвращает управление циклу, продолжение — из обратного
 * вызова); 0 — ответ уже есть, в r->res (здоровье 1/0, замер — мс или -1). */
static int hp_start(struct fo_run *r, int kind, const struct output *o, const char *dev) {
    const struct spec *sp = r->sp;
    r->hp.kind = kind;
    snprintf(r->hp.dev, sizeof(r->hp.dev), "%s", dev);
    r->hp.ti = 0;
    r->hp.best = -1;
    if (kind == HP_HEALTH && g_health_probe) { r->res = g_health_probe(sp, o, dev); return 0; }
    if (kind == HP_LATENCY) {
        if (g_latency_probe) { r->res = g_latency_probe(sp, o, dev); return 0; }
        r->res = -1;
        if (!device_present(dev)) return 0;
        o = out_for_device(sp, o, dev);
        const struct kind_ops *k = kind_of(o);
        if (k->latency) { r->res = k->latency(sp, o, dev); return 0; }
        /* И туннель xsteer, поднятый netifd, — по тому же доводу, что у вида xsteer: мерить его
         * нечем, а число из пробы наружу означало бы не задержку туннеля, а наличие интернета у
         * хаба. */
        if (r->hs->ops->xsdev(r->hs, dev, NULL, NULL)) return 0;
        return hp_tcp_next(r);
    }
    r->res = 0;
    if (!device_present(dev)) return 0;
    o = out_for_device(sp, o, dev);
    /* Устройство создаёт наш процесс — сначала спросить о нём источник здоровья (fostate.h):
     * «не поднят» — приговор без пробы, «поднят» — дальше прежняя мера устройства. */
    if (out_engine_managed(o)) {
        struct fo_hstate h;
        if (r->hs->ops->state(r->hs, o->name, &h) == 0 && h.st != FO_HS_UNKNOWN &&
            h.st != FO_HS_UP)
            return 0;
    }
    const struct kind_ops *k = kind_of(o);
    if (k->health) { r->res = k->health(sp, o, dev); return 0; }
    {
        int up = 0, fresh = 0;
        if (r->hs->ops->xsdev(r->hs, dev, &up, &fresh)) { r->res = fresh ? up : 1; return 0; }
    }
    if (out_has_cap(o, KC_TCP_PROBE)) return hp_tcp_next(r);
    if (g_icmp_probe) { r->res = g_icmp_probe(dev); return 0; }
    if (!device_src(dev, r->hp.src, sizeof(r->hp.src))) return 0;
    probe_rule_set(r);
    return hp_icmp_next(r);
}

/* ---- внешняя команда оживления --------------------------------------------------------------- */

static void cmd_cb(void *arg, int rc) {
    struct fo_run *r = arg;
    r->rv.sp = NULL;
    r->res = rc;
    fo_step(r);
}

/* 1 — команда идёт; 0 — кончилась (итог в r->res). Шов g_cmd_hook — стенду: команда
 * «выполняется» его журналом и кончается сразу. */
static int cmd_start(struct fo_run *r, const char *const argv[]) {
    if (g_cmd_hook) { r->res = g_cmd_hook(argv); return 0; }
    int rc = -1;
    r->rv.sp = fospawn_start(r->l, argv, CMD_MAX_MS, cmd_cb, r, &rc);
    if (r->rv.sp) return 1;
    r->res = rc;
    return 0;
}

/* ---- оживление: таймер шага и события netlink --------------------------------------------- */

static void rv_arm(struct fo_run *r) {
    long ms = g_revive_step ? g_revive_step() : REVIVE_STEP_MS;
    loop_timer_set(r->rv.tm, ms);
}

static void rv_timer(struct loop *l, struct loop_timer *t, void *arg) {
    (void)l; (void)t;
    struct fo_run *r = arg;
    switch (r->s) {
    case RV_PAUSE:                    /* пауза после сигнала помощнику */
        r->s = RV_DOWN;
        fo_step(r);
        return;
    case RV_WAITING:                  /* шаг ожидания кончился — проба */
        r->rv.i++;
        r->s = RV_WAIT_PROBE;
        fo_step(r);
        return;
    case RV_EV_R:                     /* шаг кончился посреди внеочередной пробы */
        r->rv.timer_fired = 1;
        return;
    default:
        return;
    }
}

static void rv_nl_close(struct fo_run *r) {
    if (r->rv.nl < 0) return;
    loop_fd_del(r->l, r->rv.nl);
    close(r->rv.nl);
    r->rv.nl = -1;
}

/* Событие о самом устройстве оживления (по номеру: у только что созданного он уже есть на
 * момент события) — внеочередная проба, одна за шаг. */
static void rv_nl(struct loop *l, int fd, uint32_t ev, void *arg) {
    (void)l; (void)ev;
    struct fo_run *r = arg;
    unsigned idx = if_nametoindex(r->rv.dev);
    int mine = 0;
    char buf[8192];
    ssize_t n;
    while ((n = recv(fd, buf, sizeof(buf), 0)) > 0 || (n < 0 && errno == ENOBUFS)) {
        if (n < 0) { mine = 1; continue; }   /* события потеряны — могли быть и наши */
        int left = (int)n;
        for (struct nlmsghdr *h = (struct nlmsghdr *)buf; NLMSG_OK(h, (unsigned)left);
             h = NLMSG_NEXT(h, left)) {
            if (h->nlmsg_type == RTM_NEWLINK &&
                h->nlmsg_len >= NLMSG_LENGTH(sizeof(struct ifinfomsg))) {
                const struct ifinfomsg *ifi = NLMSG_DATA(h);
                if (idx && (unsigned)ifi->ifi_index == idx) mine = 1;
            } else if (h->nlmsg_type == RTM_NEWADDR &&
                       h->nlmsg_len >= NLMSG_LENGTH(sizeof(struct ifaddrmsg))) {
                const struct ifaddrmsg *ifa = NLMSG_DATA(h);
                if (idx && ifa->ifa_index == idx) mine = 1;
            }
        }
    }
    if (mine && r->s == RV_WAITING && !r->rv.extra) {
        r->rv.extra = 1;
        r->s = RV_EV_PROBE;
        fo_step(r);
    }
}

static void rv_nl_open(struct fo_run *r) {
    int fd = socket(AF_NETLINK, SOCK_RAW | SOCK_CLOEXEC | SOCK_NONBLOCK, NETLINK_ROUTE);
    if (fd < 0) return;
    struct sockaddr_nl a;
    memset(&a, 0, sizeof(a));
    a.nl_family = AF_NETLINK;
    a.nl_groups = RTMGRP_LINK | RTMGRP_IPV4_IFADDR;
    if (bind(fd, (struct sockaddr *)&a, sizeof(a)) != 0 ||
        loop_fd_add(r->l, fd, EPOLLIN, rv_nl, r) != 0) {
        close(fd);
        return;
    }
    r->rv.nl = fd;
}

/* Начать оживление устройства dev выхода o; итог (1 — ожило) — в r->res в состоянии ret. */
static void rv_begin(struct fo_run *r, const struct output *o, const char *dev, enum fo_state ret) {
    r->rv.ret = ret;
    r->rv.o = o;
    r->rv.ow = NULL;
    if (dev != r->rv.dev) snprintf(r->rv.dev, sizeof(r->rv.dev), "%s", dev);
    r->rv.i = r->rv.extra = r->rv.timer_fired = 0;
    r->rv.nn = 0;
    r->s = RV_START;
}

static void rv_done(struct fo_run *r, int res) {
    rv_nl_close(r);
    loop_timer_stop(r->rv.tm);
    r->res = res;
    r->s = r->rv.ret;
}

static void rv_gai_cb(void *arg, const struct kind_name *names, size_t n) {
    struct fo_run *r = arg;
    r->rv.gw = NULL;
    if (n > KIND_NAMES_MAX) n = KIND_NAMES_MAX;
    memcpy(r->rv.names, names, n * sizeof(names[0]));
    r->rv.nn = n;
    fo_step(r);
}

/* ---- заведение и уход ----------------------------------------------------------------------- */

static void run_kick(struct loop *l, struct loop_timer *t, void *arg) {
    (void)l; (void)t;
    fo_step(arg);
}

static struct fo_run *run_new(struct loop *l, struct spec *sp, struct fo_store *st, int verbose,
                              fo_event_fn ev, void *ev_arg, fo_done_fn done, void *done_arg) {
    struct fo_run *r = calloc(1, sizeof(*r));
    if (!r) return NULL;
    r->l = l;
    r->sp = sp;
    r->st = st;
    r->hs = &fo_hsrc_files;
    r->verbose = verbose;
    r->ev = ev;
    r->ev_arg = ev_arg;
    r->done = done;
    r->done_arg = done_arg;
    r->rv.nl = -1;
    r->kick = loop_timer_new(l, run_kick, r);
    r->rv.tm = loop_timer_new(l, rv_timer, r);
    if (!r->kick || !r->rv.tm) {
        loop_timer_free(r->kick);
        loop_timer_free(r->rv.tm);
        free(r);
        return NULL;
    }
    return r;
}

static void run_free(struct fo_run *r) {
    if (r->hp.p) foprobe_cancel(r->hp.p);
    probe_rule_clear(r);
    if (r->rv.sp) fospawn_cancel(r->rv.sp);
    if (r->rv.gw) gaiw_cancel(r->rv.gw);
    rv_nl_close(r);
    loop_timer_free(r->rv.tm);
    loop_timer_free(r->kick);
    free(r);
}

static void run_end(struct fo_run *r, int res) {
    fo_done_fn done = r->done;
    void *arg = r->done_arg;
    run_free(r);
    if (done) done(arg, res);
}

struct fo_run *fo_pass_start(struct loop *l, struct spec *sp, struct fo_store *st, int verbose,
                             fo_event_fn ev, void *ev_arg, fo_done_fn done, void *done_arg) {
    struct fo_run *r = run_new(l, sp, st, verbose, ev, ev_arg, done, done_arg);
    if (!r) return NULL;
    r->s = S_START;
    loop_timer_set(r->kick, 0);
    return r;
}

void fo_pass_abort(struct fo_run *r) {
    if (r) run_free(r);
}

void fo_pass_helpers(struct fo_run *r, struct fo_hsrc *hs) {
    if (r) r->hs = hs ? hs : &fo_hsrc_files;
}

/* ---- шаг выхода: действия после решения (прежний хвост тела цикла failover_pass) ----------- */

static void out_finish(struct fo_run *r) {
    struct output *o = r->o;
    const char *chosen = r->chosen;
    const char *was = r->was;
    r->streak_new[r->i] = r->new_streak;
    r->alive[r->i] = chosen != NULL;
    /* Причину назвать надо: иначе «живых устройств нет» стоит у выхода, чьё устройство на
     * месте и чья проба, спроси её, ответила бы «да». Строка — на переходе в отказ (как и
     * объявление apply_failed) или при -v, а не на каждом проходе. */
    if (r->via_down && (r->verbose || strcmp(was, "-") != 0))
        fprintf(stderr, LOG_W "выход %s: идёт через %s, а тот не работает — выход "
                        "считается нерабочим\n", o->name, r->via->name);

    if (chosen) {
        snprintf(o->device, sizeof(o->device), "%s", chosen);
        if (strcmp(was, chosen) != 0) {
            bind_device(o, chosen);
            printf("steer: выход %s -> %s%s\n", o->name, chosen,
                   was[0] && strcmp(was, "-") ? " (переключение)" : "");
            r->changed = 1;
            const char *why = !was[0] ? "start" : !strcmp(was, "-") ? "recovered"
                            : r->cur < 0 ? "spec" : r->by_latency ? "latency"
                            : r->cur_dead ? "down" : "preferred";
            fo_emit(r->ev, r->ev_arg, FO_EV_SWITCHED, o,
                    was[0] && strcmp(was, "-") ? was : NULL, chosen, why);
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
                if (r->verbose)
                    fprintf(stderr, LOG_W "%s: состояние маршрутизации не прочитать "
                                    "— ничего не меняю\n", o->name);
            } else if (!routing_live_ok(&f, chosen)) {
                fprintf(stderr, LOG_W "выход %s: %s отвечает, но маршрутизация "
                                "разъехалась (%s) — возвращаю маршрут\n",
                        o->name, chosen, facts_why(&f, chosen));
                bind_device(o, chosen);
                r->changed = 1;
            } else {
                /* Маршрутизация цела, но у выхода с drop пропал запасной запрет (его снял
                 * кто-то снаружи, или таблицу ставил движок до этой версии). Возвращается
                 * одной командой, без перепривязки: соединения рвать не из-за чего. */
                if (o->on_fail == FAIL_DROP && !f.backstop) backstop_set(o->table);
                if (r->verbose) fprintf(stderr, LOG_I "%s: %s работает\n", o->name, chosen);
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
            r->changed = 1;
            fo_emit(r->ev, r->ev_arg, FO_EV_FAILED, o, was[0] ? was : NULL, NULL,
                    r->via_down ? "via" : "down");
        } else {
            struct route_facts f = route_facts_read(o);
            if (!f.known) {
                /* То же, что в живой ветке: по незнанию не трогаем. Здесь цена ошибки
                 * даже выше — apply_failed при on_fail=drop останавливает трафик, и
                 * сделать это «на всякий случай» значило бы уронить работающий выход. */
                if (r->verbose)
                    fprintf(stderr, LOG_W "%s: состояние маршрутизации не прочитать "
                                    "— ничего не меняю\n", o->name);
            } else if (!routing_failed_ok(&f, o->on_fail)) {
                fprintf(stderr, LOG_W "выход %s: живых устройств по-прежнему нет, а "
                                "маршрутизация разъехалась (%s) — возвращаю "
                                "on_fail=%s\n",
                        o->name, failed_why(&f, o->on_fail), on_fail_name(o->on_fail));
                apply_failed(o, 0);
                r->changed = 1;
            }
        }
    }
}

/* ---- автомат ------------------------------------------------------------------------------ */

/* Крутить автомат, пока шаги отвечают сразу; вернуться, как только начато ожидание (его
 * обратный вызов позовёт fo_step снова) или проход кончился (run_end освободил r). */
static void fo_step(struct fo_run *r) {
    struct spec *sp = r->sp;
    for (;;) {
        struct output *o = r->o;
        switch (r->s) {

        /* ---- проход ---- */
        case S_START:
            /* ПОРЯДОК ОБХОДА — ПО ЗАВИСИМОСТЯМ `via`, а не по спеке.
             *
             * Выход, чей туннель идёт через другой выход (см. «вложенные выходы» в spec.h),
             * жив только пока жива его цель: соединение внутреннего туннеля с сервером едет в
             * устройство цели. Ответ «цель жива» сторож и так получает в этом же проходе —
             * нужно лишь спросить цель ПЕРВОЙ. Поэтому сначала выходы без via, затем те, чья
             * цель без via, и так до MAX_VIA_DEPTH: спека круги и цепочки длиннее не
             * пропускает (via_check в spec.c), так что каждый выход получает место ровно один
             * раз. Порядок внутри одного слоя — прежний, спековый: у спек без via обход тот
             * же, что был, до последнего прохода.
             *
             * Ни проб, ни таймеров ради этого не заводится — требование батареи на телефоне:
             * зависимость читается из уже известного ответа, а пробы внутреннего выхода при
             * лежащей цели и вовсе не делаются (см. via_down ниже). */
            r->ord_n = 0;
            for (int depth = 0; depth <= MAX_VIA_DEPTH; depth++)
                for (size_t i = 0; i < sp->out_n; i++)
                    if (out_via_depth(sp, &sp->out[i]) == depth) r->ord[r->ord_n++] = i;
            r->oi = 0;
            r->s = S_OUT;
            continue;

        case S_OUT:
            if (r->oi >= r->ord_n) { r->s = S_END; continue; }
            r->i = r->ord[r->oi];
            r->o = o = &sp->out[r->i];
            if (!out_has_device(o)) { r->oi++; continue; }
            /* Цель via лежит — внутренний выход нерабочий, что бы ни говорила его собственная
             * проба. Проба тут и соврать может: устройство vless или xsteer остаётся на месте,
             * пока жив процесс, а до сервера его соединение через мёртвую цель не доедет. И
             * пробовать, и оживлять его бесполезно — поэтому ни того, ни другого, сразу ветка
             * отказа с ЕГО on_fail: каналы внутреннего выхода получают то, что человек для
             * них выбрал. */
            r->via = out_via(sp, o);
            r->via_down = r->via && !r->alive[r->via - sp->out];
            active_get_st(r->st, o->name, r->was, sizeof(r->was));
            /* Где в списке предпочтения стоит несущее трафик сейчас. -1 — записи нет или её
             * устройство больше не кандидат: тогда гистерезису не за что держаться, берём
             * лучшее здоровое сразу. */
            r->cur = -1;
            for (size_t k = 0; k < o->devices_n; k++)
                if (!strcmp(o->devices[k], r->was)) { r->cur = (int)k; break; }
            r->first_h = -1;
            r->k = 0;
            r->s = S_SCAN;
            continue;

        case S_SCAN:
            /* Первое здоровое по предпочтению. Пробуем по порядку и ОСТАНАВЛИВАЕМСЯ на нём —
             * пробить пробой каждое устройство значило бы платить таймаут за каждый мёртвый
             * запас на каждом тике. Здоровье устройств 0..first_h тем самым известно. */
            if (r->k >= o->devices_n || r->via_down) { r->s = S_LAT; continue; }
            r->s = S_SCAN_R;
            if (hp_start(r, HP_HEALTH, o, o->devices[r->k])) return;
            continue;

        case S_SCAN_R:
            if (r->res) { r->first_h = (int)r->k; r->s = S_LAT; continue; }
            if (r->verbose)
                fprintf(stderr, LOG_W "%s: %s не отвечает\n", o->name, o->devices[r->k]);
            r->k++;
            r->s = S_SCAN;
            continue;

        case S_LAT:
            r->chosen = NULL;
            r->streak = active_streak_get(r->st, o->name);
            r->new_streak = 0;
            /* Для события switched: чем выбор объяснить. Устройства 0..first_h пробой уже
             * спрошены, поэтому «текущее мертво» при cur < first_h известно без новой пробы. */
            r->by_latency = 0;
            r->cur_dead = r->cur >= 0 && r->first_h >= 0 && r->cur < r->first_h;
            /* ---- ВЫБОР ПО ЗАМЕРУ, если выход этого просит ----------------------------
             *
             * Работает НЕ на каждом тике, и это главное в устройстве. Выше сторож нарочно
             * останавливается на первом здоровом: пробить пробой каждого мёртвого запаса
             * стоит таймаут, и на восьми кандидатах это двадцать секунд на тик. Замер же
             * требует опросить ВСЕХ — иначе сравнивать не с чем. Поэтому у него свой, длинный
             * интервал (умолчание 180 с против тика в 60), а между замерами выход ведёт себя
             * как прежде, то есть по порядку предпочтения.
             *
             * Допуск (умолчание 50 мс) — гистерезис в единицах самого замера. Без него сторож
             * менял бы устройство на каждом дрожании в пару миллисекунд, а смена устройства
             * здесь это смена выходного адреса и обрыв соединений через прежнее.
             *
             * Оба числа взяты у sing-box (interval 3m, tolerance 50), где эта задача решена
             * давно и проверена на несравнимо большем числе установок, чем наша.
             *
             * Порядок предпочтения человека НЕ отменяется, а становится решающим при
             * равенстве: кандидат, чей замер не хуже лучшего на допуск, считается равным, и
             * из таких берётся самый предпочтительный. Иначе включение режима означало бы
             * «мой список больше ничего не значит». */
            if (o->prefer_latency && r->first_h >= 0 && o->devices_n > 1) {
                r->tol = o->lat_tolerance_ms > 0 ? o->lat_tolerance_ms : LAT_TOLERANCE_MS;
                r->iv  = o->lat_interval_s  > 0 ? o->lat_interval_s  : LAT_INTERVAL_S;
                int stale = 0;
                for (size_t k = 0; k < o->devices_n; k++) {
                    long age = 0;
                    r->ms[k] = -1;
                    if (lat_get(r->st, o->name, o->devices[k], &r->ms[k], &age)) {
                        if (age > r->iv || age < 0) stale = 1;
                    } else stale = 1;
                }
                /* Меряем ВСЕХ, включая тех, что ниже first_h: смысл режима ровно в том, чтобы
                 * узнать про них. */
                r->k = 0;
                r->s = stale ? S_LAT_M : S_LAT_C;
                continue;
            }
            r->s = S_HYST;
            continue;

        case S_LAT_M:
            if (r->k >= o->devices_n) {
                lat_put(r->st, o->name, o->devices, r->ms, o->devices_n);
                r->s = S_LAT_C;
                continue;
            }
            r->s = S_LAT_M_R;
            if (hp_start(r, HP_LATENCY, o, o->devices[r->k])) return;
            continue;

        case S_LAT_M_R:
            r->ms[r->k] = r->res;
            r->k++;
            r->s = S_LAT_M;
            continue;

        case S_LAT_C: {
            int have = 0;
            for (size_t k = 0; k < o->devices_n; k++) if (r->ms[k] >= 0) have++;
            if (have == 0) {
                /* Ни один замер не удался — режим молча становится прежним. Сказать надо:
                 * иначе человек думает, что выбор идёт по задержке, а он идёт по списку.
                 * Так бывает у выхода kind=xsteer, который не меряется никогда. */
                if (r->verbose)
                    fprintf(stderr, LOG_W "%s: задержку измерить не удалось ни у одного "
                                    "устройства — выбираю по порядку\n", o->name);
                r->s = S_HYST;
                continue;
            }
            int best = -1;
            for (size_t k = 0; k < o->devices_n; k++)
                if (r->ms[k] >= 0 && (best < 0 || r->ms[k] < best)) best = r->ms[k];
            int pick = -1;
            for (size_t k = 0; k < o->devices_n; k++)
                if (r->ms[k] >= 0 && r->ms[k] - best <= r->tol) { pick = (int)k; break; }
            r->best = best;
            r->pick = pick;
            if (pick < 0) { r->s = S_HYST; continue; }
            /* Уходить с ЖИВОГО текущего только если выигрыш больше допуска. Мёртвое текущее
             * уступает сразу: здоровье старше замера. */
            if (r->cur >= 0 && r->cur != pick && r->ms[r->cur] >= 0) {
                r->s = S_LAT_CUR_R;
                if (hp_start(r, HP_HEALTH, o, o->devices[r->cur])) return;
                continue;
            }
            r->s = S_LAT_PICK;
            continue;
        }

        case S_LAT_CUR_R:
            if (r->res && r->ms[r->cur] - r->ms[r->pick] <= r->tol) r->pick = r->cur;
            r->s = S_LAT_PICK;
            continue;

        case S_LAT_PICK:
            r->s = S_LAT_PICK_R;
            if (hp_start(r, HP_HEALTH, o, o->devices[r->pick])) return;
            continue;

        case S_LAT_PICK_R:
            if (r->res) {
                r->chosen = o->devices[r->pick];
                r->by_latency = 1;
                if (r->verbose)
                    fprintf(stderr, LOG_I "%s: по замеру выбран %s (%d мс, лучший %d, "
                                    "допуск %d)\n",
                            o->name, o->devices[r->pick], r->ms[r->pick], r->best, r->tol);
            }
            r->s = S_HYST;
            continue;

        case S_HYST:
            if (!r->chosen && r->first_h >= 0) {
                if (r->cur > r->first_h) {
                    /* Трафик сейчас на менее предпочтительном устройстве, а более
                     * предпочтительное ожило. Уходить с текущего, если оно ещё живо, спешить
                     * нельзя — это и есть мелькание. Держим его, пока верхнее не подтвердит
                     * здоровье STEER_FAILOVER_HYST тиков подряд. Мёртвое текущее — сразу вниз. */
                    r->s = S_HYST_R;
                    if (hp_start(r, HP_HEALTH, o, o->devices[r->cur])) return;
                    continue;
                }
                /* first_h == cur (несём лучшее доступное) либо cur < first_h (текущее мертво —
                 * first_h это уход вниз): в обоих случаях берём first_h без задержки, счётчик
                 * сбрасываем. */
                r->chosen = o->devices[r->first_h];
            }
            r->s = S_REV0;
            continue;

        case S_HYST_R: {
            int hyst = failover_hyst();
            if (r->res) {
                int s = r->streak + 1;
                if (hyst > 0 && s < hyst) { r->chosen = o->devices[r->cur]; r->new_streak = s; }
                else r->chosen = o->devices[r->first_h];
            } else {
                r->chosen = o->devices[r->first_h];
                r->cur_dead = 1;
            }
            r->s = S_REV0;
            continue;
        }

        case S_REV0:
            /* Ни одно не ответило — вот теперь можно тратить время на оживление. Порядок
             * тот же, поэтому основной туннель получает попытку первым. */
            if (!r->chosen && !r->via_down) {
                if (r->cur >= 0) r->cur_dead = 1;   /* ни одно не ответило — и текущее тоже */
                r->k = 0;
                r->s = S_REV;
                continue;
            }
            r->s = S_FIN;
            continue;

        case S_REV:
            if (r->k >= o->devices_n) { r->s = S_FIN; continue; }
            rv_begin(r, o, o->devices[r->k], S_REV_R);
            continue;

        case S_REV_R:
            if (r->res) {
                r->chosen = o->devices[r->k];
                fo_emit(r->ev, r->ev_arg, FO_EV_REVIVED, o, NULL, r->chosen, NULL);
                r->s = S_FIN;
                continue;
            }
            r->k++;
            r->s = S_REV;
            continue;

        case S_FIN:
            out_finish(r);
            r->oi++;
            r->s = S_OUT;
            continue;

        case S_END:
            active_save(r->st, sp, r->streak_new);
            if (!r->changed && r->verbose) fprintf(stderr, LOG_I "изменений нет\n");
            /* Строки о переключении — в stdout: у долгоживущего процесса он буферизован, а
             * читают его журнал сервиса и стенды — сразу после прохода. */
            fflush(stdout);
            run_end(r, 0);
            return;

        /* ---- одна проба или одно оживление (синхронные обёртки для стенда) ---- */
        case S_PROBE_ONLY:
            r->s = S_PROBE_ONLY_R;
            if (hp_start(r, HP_HEALTH_REAL, r->rv.o, r->rv.dev)) return;
            continue;
        case S_PROBE_ONLY_R:
            run_end(r, r->res);
            return;
        case S_REVIVE_ONLY:
            rv_begin(r, r->rv.o, r->rv.dev, S_REVIVE_ONLY_R);
            continue;
        case S_REVIVE_ONLY_R:
            run_end(r, r->res);
            return;

        /* ---- оживление устройства r->rv.dev выхода r->rv.o ---- */
        case RV_START: {
            const struct output *ro = r->rv.o;
            const char *dev = r->rv.dev;
            if (!restart_allowed(r->st, dev)) {
                if (r->verbose)
                    fprintf(stderr, LOG_I "%s: перезапуск был недавно, пропускаю\n", dev);
                rv_done(r, 0);
                continue;
            }
            /* Устройство xsteer, поднятое netifd: клиент наш, а интерфейс — его, и зовётся
             * интерфейс НЕ так, как устройство (xs0 против xs-xs0). `ifdown xs-xs0` netifd
             * отвечает «Interface not found», то есть сторож писал бы в журнал отказ вместо
             * починки. Чинить здесь нечего и не нам: упавшего клиента поднимает заново netifd,
             * как любой обработчик протокола, и дело сторожа то же, что и с нашими собственными
             * процессами, — сказать и подождать.
             *
             * Устройство, о чьём помощнике источнику здоровья есть что сказать, сюда не
             * попадает: файл состояния по имени устройства мог остаться от прежнего запуска
             * клиента выхода kind=xsteer (он назван по имени выхода, а имя устройства у такого
             * выхода по умолчанию — то же). */
            const struct output *ow = out_for_device(sp, ro, dev);
            struct fo_hstate hst = { FO_HS_UNKNOWN, 0, 0 };
            int hknown = out_engine_managed(ow) && r->hs->ops->state(r->hs, ow->name, &hst) == 0;
            if (!hknown && r->hs->ops->xsdev(r->hs, dev, NULL, NULL)) {
                fprintf(stderr, LOG_W "%s: не отвечает — клиента туннеля поднимет заново "
                                "служба сети; жду\n", dev);
                r->s = RV_WAIT_INIT;
                continue;
            }
            /* Устройство vless и xsteer создаёт НАШ процесс, а не netifd. ifdown/ifup здесь
             * бесполезны — netifd про это устройство не знает («Interface vl not found») — и
             * на живом роутере это выглядело как вечный холостой цикл перезапусков в журнале.
             * Падение процесса ловит procd (init-скрипт ставит respawn), и подъём заново
             * выбирает рабочий узел (vless) или заново здоровается с хабом (xsteer) сам. У
             * сторожа здесь одна задача: сообщить, что туннель молчит, и подождать — кому
             * именно ждать, тот поднимется сам.
             *
             * Вопрос задаётся УСТРОЙСТВУ, а не выходу, который его назвал, по той же причине,
             * что и проба здоровья (см. device_owner): в пуле разнородных туннелей устройство
             * vless названо выходом kind=interface, и решение по виду НАЗВАВШЕГО дало бы здесь
             * ifdown/ifup по устройству, которым netifd не управляет, — «Interface … not
             * found» раз в минуту и ничего больше.
             *
             * Вид, который чинит своё устройство сам (kind_ops.revive), — у ВЛАДЕЛЬЦА
             * устройства. Туннель kind=awg чинится не ожиданием: процесса, который поднял бы
             * его заново, нет — устройство живёт в ядре. Лечится то же, что у netifd лечит
             * ifdown/ifup: имя Endpoint разрешается заново (переезд сервера по DNS), настройка
             * ложится заново, а пропавшее устройство создаётся. Частоту уже ограничил
             * restart_allowed выше. */
            if (kind_of(ow)->revive) {
                r->rv.ow = ow;
                r->s = RV_KIND;
                continue;
            }
            if (out_engine_managed(ro) || device_owner(sp, dev)) {
                /* СНАЧАЛА спрашиваем, не известна ли уже причина, по которой ждать
                 * бессмысленно.
                 *
                 * Снято с живого роутера: у выхода с `node: 31` при двадцати девяти узлах в
                 * подписке сторож писал «должен подняться заново через procd; жду» раз в пять
                 * минут — часами. Ждать там нечего: номер вне подписки, procd поднимает
                 * клиента, тот выходит с тем же отказом, и так до правки числа человеком.
                 * Строка «жду» обещает работу, которой не будет, и этим она хуже молчания: по
                 * ней человек ждёт вместе со сторожем.
                 *
                 * Причину знает сам клиент и уже записал её (probe_report), поэтому здесь её
                 * не выводят заново, а читают. Спрашивается у ВЛАДЕЛЬЦА устройства — по той же
                 * причине, что и проба здоровья: в пуле разнородных туннелей запись пишет
                 * клиент под своим именем, а не выход, который его назвал. Откуда причина —
                 * из записи клиента или из памяти демона, — решает источник здоровья
                 * (fostate.h); сам вывод один. */
                if (hknown && hst.st == FO_HS_NONODE) {
                    fprintf(stderr, LOG_W "%s: выбран узел %d, а пригодных в подписке %d — сам "
                                    "не поднимется, поправьте номер узла\n", dev, hst.node,
                            hst.total);
                    rv_done(r, 0);
                    continue;
                }
                fprintf(stderr, LOG_W "%s: не отвечает — %s; жду\n", dev, r->hs->ops->respawn);
                r->s = RV_WAIT_INIT;
                continue;
            }
            /* Без netifd (телефон: ни ifdown/ifup, ни procd с ubus) интерфейс туннеля поднимает
             * тот, кто его завёл, — приложение VPN или наш же процесс, и перезапускать его
             * отсюда нечем. Дело сторожа то же, что у выходов, чьё устройство заводит движок:
             * сказать и подождать, не оживёт ли. */
            if (!plat()->netifd) {
                fprintf(stderr, LOG_W "%s: не отвечает — жду, не поднимется ли\n", dev);
                r->s = RV_WAIT_INIT;
                continue;
            }
            fprintf(stderr, LOG_W "%s: не отвечает — перезапускаю интерфейс\n", dev);
            /* Сначала помощник выхода (обфускатор), потом интерфейс, и порядок здесь — не
             * вкусовщина.
             *
             * У выхода с obfs датаграммы WireGuard идут не в сеть, а в свой процесс, и если
             * молчит он, то поднимать заново интерфейс бессмысленно: рукопожатие уйдёт в тот
             * же тупик. Обфускатор умеет чинить себя сам (тишина при активной отправке —
             * признак мёртвого пути), но узнаёт об этом только по факту отправки, а пока
             * туннель лежит, отправлять нечего. Отсюда явный сигнал: procd поднимет процесс
             * заново, и уже после этого ifdown/ifup даст WireGuard свежую попытку.
             *
             * Через ubus, а не kill: экземпляром владеет procd, и он же обязан поднять замену
             * (экземпляр зовётся «<помощник>_<выход>», как его заводит init-скрипт). Отказ
             * игнорируем. Помощника спрашиваем у вида: сюда доходит только устройство netifd,
             * то есть interface, а у него помощник — ровно обфускатор, когда obfs настроен. */
            struct kind_helper hp = { .sig = KIND_SIG_INIT };
            const struct kind_ops *hk = kind_of(ro);
            /* Помощник — ребёнок демона (--supervise): перезапускает его сам демон, без ubus
             * и procd (источник здоровья, fostate.h). Пауза на подъём и ifdown/ifup — те же. */
            int have_hp = hk->helper && hk->helper(sp, ro, &hp) == 0;
            if (have_hp && r->hs->ops->restart &&
                r->hs->ops->restart(r->hs, ro->name, hp.cmd) == 0) {
                r->s = RV_UBUS_R;
                continue;
            }
            if (have_hp) {
                /* С запасом: имя выхода до 24 символов плюс обрамление JSON — иначе
                 * -Wformat-truncation справедливо ругается, а сборка здесь обязана быть без
                 * предупреждений (I-007). */
                char inst[112];
                snprintf(inst, sizeof(inst), "{\"name\":\"steer\",\"instance\":\"%.7s_%.24s\","
                                             "\"signal\":15}", hp.cmd, ro->name);
                const char *sig[] = { "ubus", "call", "service", "signal", inst, NULL };
                r->s = RV_UBUS_R;
                if (cmd_start(r, sig)) return;
                continue;
            }
            r->s = RV_DOWN;
            continue;
        }

        case RV_UBUS_R:
            /* Секунда процессу помощника на подъём — таймером, а не sleep. */
            r->s = RV_PAUSE;
            rv_arm(r);
            return;

        case RV_PAUSE:
            return;                   /* ждём таймер (rv_timer) */

        case RV_DOWN: {
            const char *down[] = { "ifdown", r->rv.dev, NULL };
            r->s = RV_DOWN_R;
            if (cmd_start(r, down)) return;
            continue;
        }

        case RV_DOWN_R: {
            const char *up[] = { "ifup", r->rv.dev, NULL };
            r->s = RV_UP_R;
            if (cmd_start(r, up)) return;
            continue;
        }

        case RV_UP_R:
            /* Рукопожатию нужно время: проверить сразу — значит объявить мёртвым то, что ещё
             * поднимается. Ждём короткими шагами, чтобы не держать проход дольше нужного. */
            r->s = RV_WAIT_INIT;
            continue;

        case RV_WAIT_INIT:
            r->rv.i = 0;
            rv_nl_open(r);
            r->s = RV_WAIT_ARM;
            continue;

        case RV_WAIT_ARM:
            if (r->rv.i >= REVIVE_WAIT_STEPS) { rv_done(r, 0); continue; }
            r->rv.extra = 0;
            r->rv.timer_fired = 0;
            r->s = RV_WAITING;
            rv_arm(r);
            return;

        case RV_WAITING:
            return;                   /* ждём таймер шага или событие об устройстве */

        case RV_WAIT_PROBE:
            r->s = RV_WAIT_R;
            if (hp_start(r, HP_HEALTH_REAL, r->rv.o, r->rv.dev)) return;
            continue;

        case RV_WAIT_R:
            if (r->res) { rv_done(r, 1); continue; }
            r->s = RV_WAIT_ARM;
            continue;

        case RV_EV_PROBE:
            r->s = RV_EV_R;
            if (hp_start(r, HP_HEALTH_REAL, r->rv.o, r->rv.dev)) return;
            continue;

        case RV_EV_R:
            if (r->res) { rv_done(r, 1); continue; }
            if (r->rv.timer_fired) {
                r->rv.timer_fired = 0;
                r->rv.i++;
                r->s = RV_WAIT_PROBE;
                continue;
            }
            r->s = RV_WAITING;        /* таймер шага по-прежнему заведён */
            return;

        case RV_KIND: {
            /* Имена, которые починка вида разрешила бы getaddrinfo, — рабочим потоком
             * (gaiw.h), чтобы DNS не остановил цикл. */
            const struct kind_ops *k = kind_of(r->rv.ow);
            r->rv.nn = k->revive_names ? k->revive_names(sp, r->rv.ow, r->rv.names,
                                                         KIND_NAMES_MAX) : 0;
            r->s = RV_KIND_GO;
            if (r->rv.nn) {
                r->rv.gw = gaiw_start(r->l, r->rv.names, r->rv.nn, rv_gai_cb, r);
                if (r->rv.gw) return;
            }
            continue;
        }

        case RV_KIND_GO: {
            const struct kind_ops *k = kind_of(r->rv.ow);
            int ok = k->revive(sp, r->rv.ow, r->rv.dev, k->revive_names ? r->rv.names : NULL,
                               r->rv.nn);
            rv_done(r, ok);
            continue;
        }
        }
        return;
    }
}

/* ---- синхронно: свой цикл, прогон до конца ------------------------------------------------ */

struct fo_sync {
    struct loop *l;
    struct fo_run *r;
    int res;
};

static void sync_done(void *arg, int res) {
    struct fo_sync *s = arg;
    s->res = res;
    s->r = NULL;
    loop_stop(s->l, 0);
}

/* SIGTERM/SIGINT посреди прохода `steer failover`: снять правило пробы и выйти — то же, что
 * делал обработчик sig_cleanup, пока сигналы не шли через цикл. */
static void sync_sig(struct loop *l, int sig, void *arg) {
    (void)l;
    struct fo_sync *s = arg;
    if (s->r) fo_pass_abort(s->r);
    cleanup_probe_rule();
    _exit(128 + sig);
}

static int run_sync(enum fo_state first, struct spec *sp, struct fo_store *st, int verbose,
                    fo_event_fn ev, void *ev_arg, const struct output *o, const char *dev,
                    int fail) {
    /* loop_new блокирует сигналы цикла в процессе — вернуть маску, как была: вне прохода
     * `steer failover` живёт с обработчиками failover_pass_guard. */
    sigset_t old;
    sigprocmask(SIG_SETMASK, NULL, &old);
    struct loop *l = loop_new();
    if (!l) {
        fprintf(stderr, LOG_W "цикл событий не завёлся: %s\n", strerror(errno));
        sigprocmask(SIG_SETMASK, &old, NULL);
        return fail;
    }
    struct fo_sync s = { l, NULL, fail };
    loop_signal(l, SIGTERM, sync_sig, &s);
    loop_signal(l, SIGINT, sync_sig, &s);
    struct fo_run *r = run_new(l, sp, st, verbose, ev, ev_arg, sync_done, &s);
    if (r) {
        s.r = r;
        r->s = first;
        r->rv.o = o;
        if (dev) snprintf(r->rv.dev, sizeof(r->rv.dev), "%s", dev);
        loop_timer_set(r->kick, 0);
        loop_run(l);
        if (s.r) fo_pass_abort(s.r);
    }
    loop_free(l);
    sigprocmask(SIG_SETMASK, &old, NULL);
    return s.res;
}

int failover_pass(struct spec *sp, struct fo_store *st, int verbose, fo_event_fn ev, void *arg) {
    run_sync(S_START, sp, st, verbose, ev, arg, NULL, NULL, 0);
    return 0;
}

int device_healthy_for(const struct spec *sp, const struct output *o, const char *dev) {
    return run_sync(S_PROBE_ONLY, (struct spec *)sp, &fo_store_files, 0, NULL, NULL, o, dev, 0);
}

int revive(const struct spec *sp, const struct output *o, const char *dev, int verbose) {
    return run_sync(S_REVIVE_ONLY, (struct spec *)sp, &fo_store_files, verbose, NULL, NULL, o,
                    dev, 0);
}

int cmd_failover(const char *spec, int verbose) {
    /* Спека — значение, а не глобалы (правило 6): свой экземпляр у точки входа. */
    static struct spec cfg;
    atexit(cleanup_probe_rule);
    failover_pass_guard();

    /* Правило 5, docs/architecture.md, раздел 2: err_die здесь довершает то, что раньше делал
     * die() изнутри load_spec/registry_assign — «конец одного прохода», только через явную
     * проверку возврата, а не exit() из глубины разбора. */
    struct err e = {0};
    if (load_spec(spec, &cfg, &e) < 0) err_die(&e);
    if (registry_assign(&cfg, &e) < 0) err_die(&e);
    return failover_pass(&cfg, &fo_store_files, verbose, NULL, NULL);
}
