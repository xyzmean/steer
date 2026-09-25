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
#include "daemon.h"

/* ---- what an interface output depends on, and does not own ----------------- */
/* steer does not touch the firewall. It has no business rewriting someone's zones
 * or adding masquerade rules — that is the operator's configuration, and a routing
 * engine silently editing it is how two tools start fighting over one ruleset.
 *
 * But an interface output cannot work without it: packets leaving a tunnel with LAN
 * source addresses never come back, so the route looks applied, the channel counter
 * even rises, and every site behind it simply hangs. That failure is invisible from
 * inside steer's own state — which is exactly why it must be REPORTED.
 *
 * Both checks are textual and deliberately conservative: a false "looks fine" is
 * worse than a false warning, so anything unrecognised reads as missing. */


/* Is DEVICE named here as a whole token? Substring matching is not good enough in
 * either direction: looking for it quoted missed fw4 entirely (see below), while a
 * bare substring would let "warp" answer for "warp0". */
static int names_device(const char *hay, const char *device) {
    size_t n = strlen(device);
    for (const char *p = strstr(hay, device); p; p = strstr(p + 1, device)) {
        char before = p == hay ? ' ' : p[-1];
        char after = p[n];
        int lb = (before >= 'a' && before <= 'z') || (before >= 'A' && before <= 'Z')
                 || (before >= '0' && before <= '9');
        int la = (after >= 'a' && after <= 'z') || (after >= 'A' && after <= 'Z')
                 || (after >= '0' && after <= '9');
        if (!lb && !la) return 1;
    }
    return 0;
}

/* Имя цепочки — первое слово: и в заголовке (`chain srcnat_vpn {`), и в переходе
 * (`jump srcnat_vpn comment ...`) оно стоит первым и кончается пробелом или скобкой. */
static void chain_token(const char *s, char *out, size_t cap) {
    size_t i = 0;
    while (*s == ' ' || *s == '\t') s++;
    while (i + 1 < cap && s[i] && s[i] != ' ' && s[i] != '\t' && s[i] != '\n'
           && s[i] != '{' && s[i] != ';')
        out[i] = s[i], i++;
    out[i] = 0;
}

#define FWC_CHAINS 16
static void remember_chain(char tab[FWC_CHAINS][64], size_t *n, const char *name) {
    if (!*name || *n >= FWC_CHAINS) return;
    for (size_t i = 0; i < *n; i++)
        if (!strcmp(tab[i], name)) return;
    snprintf(tab[(*n)++], 64, "%s", name);
}

/* Один дамп набора правил на процесс.
 *
 * fw_check дёргается по разу на выход, report_traceroute_dep добавляет свой
 * дамп — то есть status (а его интерфейс опрашивает каждые пять секунд) и apply
 * платили sh+nft и полный обход ruleset ядром по два-пять раз за запуск, на
 * одни и те же данные. На слабом роутере это был главный фоновый расход CPU
 * всей системы. Кэш корректен ровно потому, что все читатели работают ПОСЛЕ
 * любых изменений набора правил в этом же процессе: в apply отчёты идут после
 * `nft -f`, а status/diag ruleset не трогают. Дамп по-прежнему --terse (см.
 * комментарий в fw_check), так что в памяти он занимает килобайты, а живёт до
 * конца короткоживущего CLI-процесса. */
/* Кэш всегда либо NULL, либо получен malloc'ом: tests/fwmatch.c сбрасывает его
 * между пробами обычным free(), изображая свежий процесс на каждую пробу. */
static char *g_ruleset_dump;

static const char *ruleset_dump(void) {
    if (g_ruleset_dump) return g_ruleset_dump;
    size_t cap = 65536, n = 0;
    char *buf = malloc(cap);
    if (!buf) return ""; /* не кэшируем — следующий вызов попробует снова */
    FILE *f = popen("nft -t list ruleset 2>/dev/null || "
                    "nft list ruleset 2>/dev/null", "r");
    if (!f) { buf[0] = '\0'; return g_ruleset_dump = buf; }
    for (;;) {
        if (n + 4096 + 1 > cap) {
            char *nb = realloc(buf, cap *= 2);
            if (!nb) break; /* сколько влезло — с тем и работаем */
            buf = nb;
        }
        size_t r = fread(buf + n, 1, 4096, f);
        if (!r) break;
        n += r;
    }
    pclose(f);
    buf[n] = '\0';
    return g_ruleset_dump = buf;
}

/* Следующая «строка» кэша с семантикой fgets: длинная строка выдаётся кусками
 * по cap-1 — читатели ниже написаны в этих терминах. Возвращает позицию
 * продолжения или NULL в конце. */
static const char *dump_line(const char *p, char *line, size_t cap) {
    if (!p || !*p) return NULL;
    size_t len = 0;
    while (len < cap - 1 && p[len] && p[len] != '\n') len++;
    if (len < cap - 1 && p[len] == '\n') len++;
    memcpy(line, p, len);
    line[len] = '\0';
    return p + len;
}

struct fwcheck fw_check(const char *device) {
    struct fwcheck r = { 0, 0 };
    /* Зона может называться не так, как устройство, и тогда оба признака ниже молчат:
     * fw4 пишет имя ЗОНЫ и в имя цепочки (`srcnat_vpn`), и в комментарий правила
     * ("Masquerade IPv4 vpn traffic"), а устройство называет ТОЛЬКО на переходе в эту
     * цепочку: `oifname "warp0" jump srcnat_vpn`. Снято с fw4 25.12: при зоне с именем,
     * отличным от имени устройства, во всём наборе нет ни одной строки, где устройство
     * стояло бы рядом со словом masquerade, — и выход получал «нет masquerade» при
     * включённом masq (splicicd#8). Поэтому цепочка, в которую устройство уходит по oif,
     * засчитывается вместе со своим содержимым. Порядок строк не предполагается: дамп
     * может назвать цепочку и до перехода, и после, поэтому оба множества собираются за
     * один проход и пересекаются в конце. */
    char dev_chain[FWC_CHAINS][64], masq_chain[FWC_CHAINS][64];
    size_t dev_chain_n = 0, masq_chain_n = 0;
    /* --terse: без содержимого наборов. Проверка смотрит на имена устройств в правилах
     * и цепочках, а элементы наборов ей не нужны — при этом их бывают десятки тысяч, и
     * полный дамп на слабом роутере стоил секунды НА КАЖДЫЙ ВЫЗОВ. Флаг есть в nft
     * с 0.9.4 (OpenWrt 21+); на случай древней сборки — откат к полному дампу,
     * медленно, но не слепо. Сам дамп берётся из ruleset_dump() — один на процесс. */
    const char *pos = ruleset_dump();
    char line[2048];
    char chain[128] = "";
    int in_steer = 0;
    while ((pos = dump_line(pos, line, sizeof(line))) != NULL) {
        /* Our own table mentions the device too; it proves nothing about NAT. */
        {
            char want[80];
            snprintf(want, sizeof(want), "table inet %s", nft_table());
            if (strstr(line, want)) in_steer = 1;
            else if (!strncmp(line, "table ", 6)) in_steer = 0;
        }
        if (in_steer) continue;

        const char *c = strstr(line, "chain ");
        if (c) snprintf(chain, sizeof(chain), "%s", c + 6);

        if (names_device(line, device)) r.in_firewall = 1;
        /* fw4 does NOT name the device on the masquerade rule: it emits
         * `chain srcnat_warp0 { meta nfproto ipv4 masquerade comment "...warp0..." }`
         * and matches the device on the jump into that chain. Checking only the rule
         * line reported "no NAT" on a router whose NAT was working fine — a false
         * alarm that sent me diagnosing the wrong thing. So the enclosing chain name
         * counts as evidence too. */
        /* Переход, на котором названо устройство: `oifname "warp0" jump srcnat_vpn`.
         * Требование oif намеренное — masquerade живёт на выходе, и переход по входящему
         * устройству (dstnat) про NAT наружу не говорит ничего. */
        const char *j = strstr(line, "jump ");
        if (j && strstr(line, "oif") && names_device(line, device)) {
            char t[64];
            chain_token(j + 5, t, sizeof t);
            remember_chain(dev_chain, &dev_chain_n, t);
        }
        if (strstr(line, "masquerade") || strstr(line, "snat")) {
            if (names_device(line, device) || names_device(chain, device)) r.masqueraded = 1;
            else {
                char t[64];
                chain_token(chain, t, sizeof t);
                remember_chain(masq_chain, &masq_chain_n, t);
            }
        }
    }
    for (size_t i = 0; i < dev_chain_n && !r.masqueraded; i++)
        for (size_t k = 0; k < masq_chain_n; k++)
            if (!strcmp(dev_chain[i], masq_chain[k])) { r.masqueraded = 1; break; }
    return r;
}

#ifndef STEER_ANDROID   /* на телефоне не зовётся — см. конец cmd_apply */
void report_traceroute_dep(void) {
    if (!g_traceroute_hops) return;
    /* Say the useless case out loud rather than leaving the operator to discover it
     * as a column of asterisks. */
    for (size_t i = 0; i < g_out_n; i++) {
        if (!out_has_device(&g_out[i])) continue;
        if (fw_check(g_out[i].device).masqueraded) {
            fprintf(stderr, LOG_W "traceroute_hops cannot work for output %s: %s "
                            "masquerades, so ICMP errors come addressed to the router "
                            "and only conntrack can route them to the client — "
                            "untracking them drops the hops entirely\n",
                    g_out[i].name, g_out[i].device);
            return;
        }
    }
    /* Тот же кэшированный дамп, что в fw_check: ищется правило, а не элементы. */
    const char *pos = ruleset_dump();
    int ok = 0;
    char line[2048];
    while ((pos = dump_line(pos, line, sizeof(line))) != NULL)
        if (strstr(line, "untracked") && strstr(line, "accept")) ok = 1;
    if (!ok)
        fprintf(stderr, LOG_W "traceroute_hops is on but no rule accepting untracked "
                        "packets was found — ICMP time-exceeded will be dropped by the "
                        "firewall and hops will show as asterisks. Needed once, in the "
                        "firewall (not here): accept ct state untracked icmp type "
                        "time-exceeded towards %s\n", g_lan_dev[0]);
}
#endif

/* ЧУЖИЕ ПРАВИЛА НА БИТАХ 16-23 — предупреждение, а не отказ.
 *
 * Поле метки движка — биты 20-27 (STEER_MARK_MASK, контракт). Tailscale и pbr держат свою
 * метку маской 0x00ff0000, то есть битами 16-23, и на битах 20-23 два поля ПЕРЕСЕКАЮТСЯ —
 * подробно у STEER_MARK_MASK в spec.h. Раскладку не меняем: это контракт, и сдвиг поля
 * означал бы новые метки у всех выходов на всех роутерах. Зато говорим, когда соседство
 * действительно есть, — иначе его последствия выглядят как «канал иногда идёт мимо выхода»
 * без единой строки в журнале.
 *
 * Признак — число в выражении с меткой в ЧУЖОЙ таблице: 0x00ff0000 (маска поля 16-23) или
 * 0xff00ffff (она же, дополнением: «стереть биты 16-23»). Так их печатает nft и для
 * Tailscale (снято с роутера: `meta mark set mark and 0xff00ffff xor 0x40000`), и для
 * всякого, кто метит по той же схеме. Разбираются числа, а не строка: ведущие нули nft то
 * печатает, то нет.
 *
 * Не отказ, потому что соседство законно и чаще всего безвредно: Tailscale переписывает
 * метку в хуке forward, то есть ПОСЛЕ решения о маршруте, и ip rule выхода его не замечает;
 * единственный наш читатель метки после forward — очередь kind=zapret — узнаёт выход по
 * метке соединения. Отказ применить спеку на роутере с Tailscale снял бы маршрутизацию у
 * людей, у которых всё работает. Вредные случаи — чужое правило, которое метит ТОТ ЖЕ пакет
 * в prerouting после нас (стирает наши биты — пакет уходит по main, мимо выхода и мимо
 * запрета on_fail=drop), или до нас (мы стираем его биты 20-23 — его политика на этом
 * пакете перестаёт совпадать), — по дампу не отличить, поэтому о них говорится словами.
 *
 * Возвращает, о скольких таблицах сказано: стенд fwmatch проверяет признак на дампах. */
int report_mark_overlap(void) {
    /* Поле целиком выше бита 23 (мини-сборка моста живёт в бите 28) — с масками 16-23 оно не
     * пересекается, и говорить не о чем. */
    if (STEER_MARK_LOBIT > 23) return 0;
    const char *pos = ruleset_dump();
    char line[2048], table[96] = "", said[8][96];
    int n_said = 0;
    while ((pos = dump_line(pos, line, sizeof(line))) != NULL) {
        const char *p = line;
        while (*p == ' ' || *p == '\t') p++;
        if (!strncmp(p, "table ", 6)) {
            snprintf(table, sizeof(table), "%s", p + 6);
            char *b = strchr(table, '{');
            if (b) *b = '\0';
            for (size_t k = strlen(table); k && table[k - 1] == ' '; k--) table[k - 1] = '\0';
            continue;
        }
        if (!*table || !strstr(p, "mark")) continue;
        /* Своя таблица — «семейство имя», имя вторым словом. */
        const char *tn = strchr(table, ' ');
        if (tn && !strcmp(tn + 1, nft_table())) continue;
        int hit = 0;
        for (const char *q = p; (q = strstr(q, "0x")) != NULL; q += 2) {
            unsigned long v = strtoul(q, NULL, 16);
            if (v == 0x00ff0000ul || v == 0xff00fffful) { hit = 1; break; }
        }
        if (!hit) continue;
        int dup = 0;
        for (int k = 0; k < n_said; k++) if (!strcmp(said[k], table)) dup = 1;
        if (dup || n_said >= 8) continue;
        snprintf(said[n_said++], sizeof(said[0]), "%s", table);
        /* Биты — из базы и ширины поля (STEER_MARK_LOBIT/HIBIT), а не строкой: у сборки под
         * Android поле 22-27, и пересекается оно с 16-23 на двух битах, а не на четырёх. */
        fprintf(stderr, LOG_W "таблица %s метит пакеты маской 0x00ff0000 (биты 16-23, так "
                        "работают Tailscale и pbr), а поле движка — биты %d-%d: на битах "
                        "%d-23 метки пересекаются. Если её правило метит тот же пакет в "
                        "prerouting после нас, трафик канала уйдёт мимо выхода; если до нас — "
                        "перестанет действовать её политика на этом пакете\n", table,
                STEER_MARK_LOBIT, STEER_MARK_HIBIT, STEER_MARK_LOBIT);
    }
    return n_said;
}

#ifndef STEER_ANDROID   /* на телефоне не зовётся — см. конец cmd_apply */
void report_output_deps(void) {
    for (size_t i = 0; i < g_out_n; i++) {
        if (!out_has_device(&g_out[i])) continue;
        struct fwcheck c = fw_check(g_out[i].device);
        if (!c.in_firewall)
            fprintf(stderr, LOG_W "output %s: %s is not mentioned by the firewall at all — "
                            "traffic steered there will not come back until it is in a zone\n",
                    g_out[i].name, g_out[i].device);
        /* Выходу vless NAT не нужен, и предупреждать о нём — значит посылать человека
         * настраивать то, чему нечего транслировать: клиент завершает TCP у себя и
         * соединяется с сервером обычным сокетом, поэтому адрес клиента наружу не уезжает
         * вовсе. Предупреждение «нет masquerade» здесь было ложной тревогой, а ложная
         * тревога дороже отсутствующей: по ней настраивают лишнее и перестают верить
         * настоящим. Про зону предупреждать всё равно надо — без неё fw4 не пропускает
         * транзит, и это проверено с настоящего клиента.
         *
         * У xsteer тот же итог по другой причине: адреса клиентов границу переходят, но
         * переходят к хабу внутри туннеля, где транслировать их нечем. Там NAT не просто
         * не нужен, а вреден — он скрывает, от какой пира пришёл пакет, и ломает
         * обратный поиск по AllowedIPs. Условие поэтому одно (out_self_natting), а
         * объяснения в diag разные: см. ветку про masquerade в cmd_diag.
         *
         * Спрашивается ВЛАДЕЛЕЦ устройства, а не выход, который его назвал (out_for_device):
         * в пуле kind=interface активным может быть устройство VLESS-туннеля, и вопрос «нужен
         * ли ему masquerade» решает то, чем устройство является, а не то, кто его перечислил.
         * Иначе — постоянная жалоба на исправной настройке. */
        else if (out_self_natting(out_for_device(&g_out[i], g_out[i].device))) {
            /* нечего проверять */
        }
        else if (!c.masqueraded)
            fprintf(stderr, LOG_W "output %s: no masquerade/snat rule found for %s — "
                            "if that path needs NAT, packets leave with LAN addresses and "
                            "the channel goes quiet while its counter still rises\n",
                    g_out[i].name, g_out[i].device);
    }
}
#endif

