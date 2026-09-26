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
#include "groups.h"
#include "generate.h"
#include "run.h"
#include "nftquery.h"


/* Чем именно объяснять совпадение: адресным списком, доменным или обоими.
 *
 * ЗАЧЕМ ФУНКЦИЯ, А НЕ ТЕРНАРНИК НА МЕСТЕ. Фраза выводилась из ИМЕНИ набора: у группы с
 * доменами она всегда была «domain set». Но группа, у которой есть и адресный список, и
 * доменный, держит оба в ОДНОМ наборе — так его находит резолвер (см. build_groups), — и
 * адрес из АДРЕСНОГО списка объяснялся как совпадение по домену. Человек, выясняющий,
 * почему 142.250.1.1 идёт в туннель, получал ответ про DNS, которого там не было. Снято с
 * живого роутера: канал с обоими списками, адрес из youtube.lst, ответ «domain set».
 *
 * Теперь фраза отвечает на «откуда этот адрес взялся в наборе»:
 *
 *   fake-IP            — его выдал резолвер, значит имя нашлось в доменном списке;
 *   есть оба списка    — по настоящему адресу различить нельзя (в режиме realip резолвер
 *                        кладёт в набор настоящие адреса), и честнее назвать оба, чем
 *                        угадать один;
 *   один вид списка    — ответ тот же, что был.
 *
 * Отдельной функцией — чтобы это проверялось стендом: разбор ответа ядра для проверки
 * требует живого nft, а выбор фразы — нет. */
const char *explain_set_phrase(const char *addr, int has_files, int has_domains) {
    int fake = addr && (strncmp(addr, "198.18.", 7) == 0 || strncmp(addr, "198.19.", 7) == 0);
    if (fake) return "domain set";
    if (has_files && has_domains) return "address+domain set";
    return has_domains ? "domain set" : "address set";
}

/* ---- explain по имени --------------------------------------------------------
 *
 * Спрашиваем НАШ резолвер, а не getaddrinfo. Разница принципиальная: getaddrinfo пойдёт к
 * системному dnsmasq и вернёт настоящий адрес сервера, а доменные каналы работают на fake-IP —
 * том адресе, который выдал бы клиенту именно steer. То есть по системному ответу нельзя
 * сказать, попадёт ли имя в набор: набор заполнен fake-адресами.
 *
 * Поэтому запрос уходит прямо в dnsd на 127.0.0.1:DNS_PORT. Заодно это проверка самого
 * резолвера: не ответил — значит и клиентам он не отвечает, и это первое, что надо знать.
 *
 * Свой запрос из четырёх десятков строк, а не библиотека: тут нужен ровно один тип записи и
 * ровно один сервер, а тянуть resolver-библиотеку в статический бинарь для роутера — это
 * килобайты за то, что укладывается в один буфер.
 */
static int dns_ask(const char *name, char *out, size_t out_n) {
    unsigned char q[512];
    size_t n = 0;
    q[n++] = 0x12; q[n++] = 0x34;                 /* id — постоянный: один запрос за процесс */
    q[n++] = 0x01; q[n++] = 0x00;                 /* стандартный запрос, рекурсия желательна */
    q[n++] = 0x00; q[n++] = 0x01;                 /* вопросов 1 */
    q[n++] = 0x00; q[n++] = 0x00;                 /* ответов 0 */
    q[n++] = 0x00; q[n++] = 0x00;
    q[n++] = 0x00; q[n++] = 0x00;
    /* Имя метками. Пустая метка (две точки подряд) сделала бы запрос неразбираемым. */
    const char *p = name;
    while (*p) {
        const char *dot = strchr(p, '.');
        size_t len = dot ? (size_t)(dot - p) : strlen(p);
        if (!len || len > 63 || n + len + 1 >= sizeof(q) - 5) return -1;
        q[n++] = (unsigned char)len;
        memcpy(q + n, p, len);
        n += len;
        if (!dot) break;
        p = dot + 1;
    }
    q[n++] = 0x00;
    q[n++] = 0x00; q[n++] = 0x01;                 /* тип A */
    q[n++] = 0x00; q[n++] = 0x01;                 /* класс IN */

    int fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (fd < 0) return -1;
    struct timeval tv = { .tv_sec = 2, .tv_usec = 0 };
    setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof tv);
    struct sockaddr_in a = { .sin_family = AF_INET, .sin_port = htons(DNS_PORT) };
    a.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    /* connect, а не sendto: у присоединённого сокета ICMP «порт закрыт» приходит ошибкой
     * recv сразу, и незапущенный резолвер — ответ немедленно, а не через две секунды срока.
     * explain исполняет и демон (src/daemon/ctl.c), в своём цикле, и две секунды впустую — это
     * две секунды, когда он не отвечает никому. */
    if (connect(fd, (struct sockaddr *)&a, sizeof a) != 0 || send(fd, q, n, 0) < 0) {
        close(fd);
        return -1;
    }

    unsigned char r[1024];
    ssize_t rn = recv(fd, r, sizeof r, 0);
    close(fd);
    if (rn < 12) return -1;
    unsigned ancount = ((unsigned)r[6] << 8) | r[7];
    if (!ancount) return -2;                       /* ответ есть, адреса нет — NODATA */
    /* Пропускаем раздел вопроса. */
    size_t i = 12;
    while (i < (size_t)rn && r[i]) {
        if ((r[i] & 0xC0) == 0xC0) { i += 2; break; }
        i += r[i] + 1;
    }
    if (i < (size_t)rn && !r[i]) i++;
    i += 4;
    /* Первый ответ типа A. CNAME пропускаем: dnsd их не выдаёт, но чужой ответ может. */
    for (unsigned k = 0; k < ancount && i + 12 <= (size_t)rn; k++) {
        if ((r[i] & 0xC0) == 0xC0) i += 2;
        else { while (i < (size_t)rn && r[i]) i += r[i] + 1; i++; }
        if (i + 10 > (size_t)rn) return -1;
        unsigned type = ((unsigned)r[i] << 8) | r[i + 1];
        unsigned rdlen = ((unsigned)r[i + 8] << 8) | r[i + 9];
        i += 10;
        if (type == 1 && rdlen == 4 && i + 4 <= (size_t)rn) {
            snprintf(out, out_n, "%u.%u.%u.%u", r[i], r[i + 1], r[i + 2], r[i + 3]);
            return 0;
        }
        i += rdlen;
    }
    return -2;
}

/* Похоже ли на имя, а не на адрес. Заодно единственная проверка перед подстановкой в
 * командную строку nft: адрес проверяет addr_ok, имя — этот набор символов. */
int looks_like_name(const char *s) {
    size_t n = 0;
    int alpha = 0;
    for (const char *p = s; *p; p++, n++) {
        if ((*p >= 'a' && *p <= 'z') || (*p >= 'A' && *p <= 'Z')) { alpha = 1; continue; }
        if ((*p >= '0' && *p <= '9') || *p == '.' || *p == '-' || *p == '_') continue;
        return 0;
    }
    return alpha && n > 0 && n < 254;
}



/* Лежит ли адрес (или весь префикс) в наборе — по его дампу, без `nft get element`.
 *
 * Нужна ядру 4.9: NFT_MSG_GETSETELEM там отвечает только на дамп, а на запрос одного элемента
 * — -EOPNOTSUPP (одиночный get появился в 4.15). Без этой ветки explain на телефоне отвечал бы
 * «ни один канал не забирает» про каждый адрес, в том числе про те, что прямо в списке.
 *
 * Разбирается не формат nft целиком, а слова из цифр, точек, дробей и дефисов после
 * «elements = {»: адрес, префикс, диапазон. Прочее (timeout 1h, expires 59m) адресом не
 * читается и пропускается само. */
static int set_scan(const char *set, const char *addr) {
    for (const char *q = set; *q; q++)
        if (!((*q >= 'a' && *q <= 'z') || (*q >= 'A' && *q <= 'Z') ||
              (*q >= '0' && *q <= '9') || *q == '_' || *q == '-'))
            return 0;
    uint32_t qlo, qhi;
    if (!ipv4_span(addr, &qlo, &qhi)) return 0;
    char cmd[256];
    snprintf(cmd, sizeof(cmd), "nft list set inet %s %.64s 2>/dev/null", nft_table(), set);
    FILE *p = popen(cmd, "r");
    if (!p) return 0;
    int in = 0, hit = 0, c;
    char tok[40];
    size_t tn = 0;
    const char *key = "elements = {";
    size_t kpos = 0;
    while (!hit && (c = fgetc(p)) != EOF) {
        if (!in) {
            kpos = (c == key[kpos]) ? kpos + 1 : (c == key[0] ? 1 : 0);
            if (!key[kpos]) in = 1;
            continue;
        }
        if ((c >= '0' && c <= '9') || c == '.' || c == '/' || c == '-') {
            if (tn + 1 < sizeof(tok)) tok[tn++] = (char)c;
            continue;
        }
        if (tn) {
            tok[tn] = '\0';
            tn = 0;
            uint32_t lo, hi;
            if (ipv4_span(tok, &lo, &hi) && lo <= qlo && qhi <= hi) hit = 1;
        }
        if (c == '}') in = 0;
    }
    pclose(p);
    return hit;
}

/* Есть ли адрес в наборе: одиночным `nft get element`, а на старом ядре, где его нет, —
 * разбором дампа (set_scan). На современном ядре путь прежний, один запуск nft. */
static int set_lookup(const char *set, const char *elem, const char *addr) {
    const char *q[] = { "nft", "get", "element", "inet", nft_table(), set, elem, NULL };
    if (run(q) == 0) return 1;
    return NFT_LEGACY && set_scan(set, addr);
}

int cmd_explain(const char *spec, const char *what) {
    static struct spec cfg;
    static struct groups gr;
    /* Правило 5, docs/architecture.md, раздел 2: err_die здесь довершает то, что раньше делал
     * die() изнутри load_spec/build_groups. */
    struct err e = {0};
    if (load_spec(spec, &cfg, &e) < 0) err_die(&e);
    if (registry_assign(&cfg, &e) < 0) err_die(&e);
    if (build_groups(&cfg, &gr, &e) < 0) err_die(&e);
    return explain_emit(&cfg, &gr, what, stdout);
}

/* Сам ответ — в поток out, по спеке и группам вызывающего: подкоманда читает спеку сама,
 * демон отдаёт свою из памяти. Код — тот, с которым кончается подкоманда. */
int explain_emit(const struct spec *cfg, const struct groups *gr, const char *what, FILE *out) {
    g_nftc = nft_compat();

    /* Имя сначала превращаем в адрес — и печатаем, во что именно. Без этой строки человек
     * видел бы вердикт по адресу, которого не спрашивал, и не мог бы понять, тот ли это
     * адрес: у доменного канала он fake, и с настоящим адресом сайта не совпадает вовсе. */
    char resolved[32];
    const char *addr = what;
    if (looks_like_name(what)) {
        int rc = dns_ask(what, resolved, sizeof resolved);
        if (rc == -1) {
            /* Два разных случая, и путать их нельзя. Нет доменных правил — резолвер и не
             * должен работать, а «не отвечает» звучало бы как поломка. Есть — тогда молчание
             * резолвера и есть поломка, причём для всех клиентов сразу. */
            if (!has_domains(gr))
                fprintf(out, "%s -> в настройке нет ни одного правила по доменам, поэтому резолвер "
                       "steer не запущен: имена он не разбирает, спрашивайте адресом\n", what);
            else
                fprintf(out, "%s -> резолвер steer не ответил на 127.0.0.1:%d — доменные правила "
                       "сейчас не работают ни для кого\n", what, DNS_PORT);
            return 1;
        }
        if (rc == -2) {
            fprintf(out, "%s -> резолвер ответил, но адреса не дал: имени нет либо оно не в "
                   "доменных списках, а вышестоящий сервер его не знает\n", what);
            return 0;
        }
        int fake = strncmp(resolved, "198.18.", 7) == 0 || strncmp(resolved, "198.19.", 7) == 0;
        fprintf(out, "%s -> %s (%s)\n", what, resolved,
               fake ? "fake-IP, выдан steer — значит имя в доменном списке"
                    : "настоящий адрес — имя ни в одном доменном списке не нашлось");
        addr = resolved;
    }
    for (size_t i = 0; i < gr->n; i++) {
        int hit = !gr->g[i].files_n && !gr->g[i].domains;   /* an `any` group */
        /* Domain channels own a set too — it is just filled by the resolver. Asking
         * only the prefix channels made explain answer "no channel matches" for
         * every fake IP, i.e. exactly the addresses a user is most likely to ask
         * about. Same oversight the generator had one commit earlier. */
        if (!hit) {
            char setname[72], elem[64];
            /* Which sets were consulted, in order — the difference between "no
             * channel matches" meaning "not listed" and meaning "explain never
             * looked". */
            if (getenv("STEER_EXPLAIN_TRACE"))
                fprintf(stderr, "checking %.63s\n", gr->g[i].name);
            snprintf(setname, sizeof(setname), "%.63s", gr->g[i].name);
            snprintf(elem, sizeof(elem), "{ %s }", addr);
            hit = set_lookup(setname, elem, addr);
            /* Старая раскладка: у доменной группы вторая половина набора, с префиксами. */
            if (!hit && legacy_may_have_static(&gr->g[i])) {
                nft_static_set_name(setname, sizeof(setname), gr->g[i].name);
                hit = set_lookup(setname, elem, addr);
            }
        }
        if (!hit) continue;
        const struct output *o = out_by_name(cfg, gr->g[i].out);
        /* Не бывает: build_groups сверил каждый канал с выходами. Но исполняет это и демон, и
         * die() здесь завершил бы его целиком — поэтому отказ возвращается. */
        if (!o) {
            fprintf(stderr, "steer: group %s points at a missing output\n", gr->g[i].name);
            return 2;
        }
        fprintf(out, "%s -> %s \"%s\" -> output \"%s\"", addr,
               explain_set_phrase(addr, gr->g[i].files_n > 0, gr->g[i].domains),
               gr->g[i].name, o->name);
        if (out_has_device(o))
            fprintf(out, " -> dev %s (mark 0x%08x, table %d)\n", o->device, o->mark, o->table);
        else
            fprintf(out, " -> direct\n");
        /* Канал бывает СУЖЕН по протоколу и портам, а спрошен был адрес. Адрес в наборе
         * лежит — но «идёт туда» верно не для всего его трафика, и промолчать значило бы
         * ответить правдой наполовину: человек, выясняющий, почему TCP к 104.16.0.1 идёт
         * напрямую, получил бы подтверждение, что канал его забирает. Отдельной строкой,
         * чтобы первая осталась той же, что была, — её читают и глазами, и разбором. */
        if (!l4match_empty(gr->g[i].l4)) {
            /* С запасом на предел MAX_PORTS: шестнадцать диапазонов вида «50000-65535» с
             * разделителями — это 217 байт, и обрезанное пояснение было бы хуже полного. */
            char d[256];
            l4_describe(gr->g[i].l4, d, sizeof(d));
            fprintf(out, "      канал сужен: только %s — остальной трафик к этому адресу "
                   "идёт мимо канала\n", d);
        }
        return 0;
    }
    fprintf(out, "%s -> no channel matches -> direct (steer does not touch it)\n", addr);
    return 0;
}
