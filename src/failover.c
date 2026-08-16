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

static void apply_failed(struct output *o) {
    char tbl[16], mark[24];
    snprintf(tbl, sizeof(tbl), "%d", o->table);
    snprintf(mark, sizeof(mark), "0x%08x", o->mark);
    const char *flush[] = { "ip", "route", "flush", "table", tbl, NULL };
    run_quiet(flush);

    if (o->on_fail == FAIL_DROP) {
        /* blackhole, а не отсутствие маршрута: без маршрута пакет с меткой
         * провалится в следующую таблицу и уйдёт напрямую — то есть ровно туда,
         * куда его не пускали. */
        const char *bh[] = { "ip", "route", "add", "blackhole", "default",
                             "table", tbl, NULL };
        run_quiet(bh);
        fprintf(stderr, LOG_W "выход %s: живых устройств нет, трафик остановлен "
                        "(on_fail=drop)\n", o->name);
        return;
    }

    /* direct и zapret: снимаем правило, чтобы помеченный трафик шёл обычным путём. */
    const char *rd[] = { "ip", "rule", "del", "fwmark", mark, "table", tbl, NULL };
    while (run_quiet(rd) == 0) ;

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
    char tbl[16], mark[24];
    snprintf(tbl, sizeof(tbl), "%d", o->table);
    snprintf(mark, sizeof(mark), "0x%08x", o->mark);

    const char *rd[] = { "ip", "rule", "del", "fwmark", mark, "table", tbl, NULL };
    while (run_quiet(rd) == 0) ;
    const char *ra[] = { "ip", "rule", "add", "fwmark", mark, "table", tbl, NULL };
    run_quiet(ra);
    const char *flush[] = { "ip", "route", "flush", "table", tbl, NULL };
    run_quiet(flush);
    const char *rt[] = { "ip", "route", "add", "default", "dev", dev, "table", tbl, NULL };
    run_quiet(rt);
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

    /* VLESS-устройство создаёт процесс «steer vless», а НЕ netifd. ifdown/ifup здесь
     * бесполезны — netifd про это устройство не знает («Interface vl not found») — и на
     * живом роутере это выглядело как вечный холостой цикл перезапусков в журнале.
     * Падение процесса vless ловит procd (init-скрипт ставит respawn), и подъём заново
     * выбирает рабочий узел сам. У сторожа для vless одна задача: сообщить, что туннель
     * молчит, и подождать — кому именно ждать, тот поднимется сам. */
    if (o->kind == OUT_VLESS) {
        fprintf(stderr, LOG_W "%s: не отвечает по TCP — VLESS-процесс должен подняться "
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
            } else if (verbose) {
                fprintf(stderr, LOG_I "%s: %s работает\n", o->name, chosen);
            }
        } else {
            o->device[0] = '\0';
            if (strcmp(was, "-") != 0) {
                apply_failed(o);
                changed = 1;
            }
        }
    }
    active_save();
    if (!changed && verbose) fprintf(stderr, LOG_I "изменений нет\n");
    return 0;
}
