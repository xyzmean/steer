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
#include "nftquery.h"
#include "generate.h"

/* Сколько элементов в наборе по мнению ядра. -1 — набора нет.
 *
 * Имя проверяется по составу, а не просто обрезается: оно уходит в командную строку через
 * popen. Имя набора собирается из имени выхода, а то приходит из спеки — то есть снаружи.
 * В этом файле такую дыру уже находили однажды, в explain, где адрес подставлялся в
 * system(); повторять не будем. */
long set_count(const char *name) {
    for (const char *q = name; *q; q++)
        if (!((*q >= 'a' && *q <= 'z') || (*q >= 'A' && *q <= 'Z') ||
              (*q >= '0' && *q <= '9') || *q == '_' || *q == '-' || *q == '.'))
            return -1;
    char cmd[256];
    snprintf(cmd, sizeof(cmd), "nft list set inet %s %.64s 2>/dev/null", nft_table(), name);
    FILE *p = popen(cmd, "r");
    if (!p) return -1;
    long n = -1;
    char line[4096];
    int seen = 0;
    while (fgets(line, sizeof(line), p)) {
        seen = 1;
        char *e = strstr(line, "elements = {");
        if (!e) continue;
        n = 0;
        /* Считаем запятые, а не разбираем элементы: их бывают десятки тысяч, и разбор
         * ради одного числа значил бы держать в памяти весь список второй раз. */
        for (char *q = e; *q; q++) if (*q == ',') n++;
        /* Элементов на одну больше, чем запятых; продолжение приезжает следующими
         * строками, поэтому дальше просто добавляем. */
        n++;
        while (fgets(line, sizeof(line), p)) {
            for (char *q = line; *q; q++) if (*q == ',') n++;
            if (strchr(line, '}')) break;
        }
        break;
    }
    pclose(p);
    if (!seen) return -1;
    return n < 0 ? 0 : n;
}

int nft_has(const char *what) {
    char cmd[512];
    /* --terse: ищутся цепочки, элементы наборов не нужны — а их дамп на большом
     * наборе стоит дороже всех остальных проверок diag вместе взятых. */
    /* В старой раскладке nat живёт в таблице ip (generate_legacy_tail), и искать заворот DNS
     * только в inet значило бы объявить его пропавшим на исправном телефоне. */
    if (NFT_LEGACY)
        snprintf(cmd, sizeof(cmd),
                 "{ nft -t list table inet %s 2>/dev/null || "
                 "nft list table inet %s 2>/dev/null; "
                 "nft -t list table ip %s 2>/dev/null || "
                 "nft list table ip %s 2>/dev/null; } | grep -qF '%s'",
                 nft_table(), nft_table(), nft_table(), nft_table(), what);
    else
        snprintf(cmd, sizeof(cmd),
                 "{ nft -t list table inet %s 2>/dev/null || "
                 "nft list table inet %s 2>/dev/null; } | grep -qF '%s'",
                 nft_table(), nft_table(), what);
    return system(cmd) == 0;
}

/* "A.B.C.D[/N]" → сеть и маска. 0, если строка не префикс.
 *
 * Сдвиг на 32 — неопределённое поведение, поэтому нулевая длина считается отдельно, а не
 * выводится из общей формулы: /0 в списке встречается («весь интернет в туннель»), и на
 * нём же общая формула и сломалась бы. */
int parse_prefix(const char *s, uint32_t *net, uint32_t *mask) {
    unsigned a, b, c, d, len = 32;
    int n = sscanf(s, "%u.%u.%u.%u/%u", &a, &b, &c, &d, &len);
    if (n < 4 || a > 255 || b > 255 || c > 255 || d > 255 || len > 32) return 0;
    *mask = len ? ~0u << (32 - len) : 0;
    *net = (((uint32_t)a << 24) | ((uint32_t)b << 16) | ((uint32_t)c << 8) | d) & *mask;
    return 1;
}

/* Asks the KERNEL, channel by channel in spec order, instead of re-reading the
 * list files: the answer has to describe what the box will actually do, including
 * the case where a set failed to load. This is the one answer raw nft cannot give. */
/* Адрес или префикс IPv4 в диапазон [lo, hi]. 0 — не адрес. Диапазон «a-b» — тоже: так nft
 * печатает интервалы, не укладывающиеся в один префикс. */
int ipv4_span(const char *t, uint32_t *lo, uint32_t *hi) {
    char buf[40];
    size_t n = strlen(t);
    if (!n || n >= sizeof(buf)) return 0;
    memcpy(buf, t, n + 1);
    char *dash = strchr(buf, '-');
    if (dash) {
        *dash = '\0';
        struct in_addr a, b;
        if (inet_pton(AF_INET, buf, &a) != 1 || inet_pton(AF_INET, dash + 1, &b) != 1) return 0;
        *lo = ntohl(a.s_addr);
        *hi = ntohl(b.s_addr);
        return *lo <= *hi;
    }
    char *sl = strchr(buf, '/');
    int len = 32;
    if (sl) {
        *sl = '\0';
        char *e;
        long v = strtol(sl + 1, &e, 10);
        if (*e || v < 0 || v > 32) return 0;
        len = (int)v;
    }
    struct in_addr a;
    if (inet_pton(AF_INET, buf, &a) != 1) return 0;
    uint32_t m = len ? 0xffffffffu << (32 - len) : 0;
    *lo = ntohl(a.s_addr) & m;
    *hi = *lo | ~m;
    return 1;
}
