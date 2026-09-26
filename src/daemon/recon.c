/* Apply-сверка демона (docs/architecture.md, «4а», шаг 5): apply и reload сравнивают новую спеку
 * с применённой по частям и трогают только то, что изменилось.
 *
 * ЧАСТИ И КАК ОНИ СРАВНИВАЮТСЯ.
 *   Набор правил — отпечаток (FNV-1a 64) текста, который печатает generate по дереву, без
 *     счётчиков: план их из ядра не читает, поэтому текст зависит только от спеки, списков и
 *     раскладки. Совпал с отпечатком последнего нашего nft -f, и таблица в ядре — та самая (номер
 *     таблицы, NFT_MSG_GETTABLE по netlink, без запуска nft) — nft не зовётся вовсе: ни
 *     транзакции, ни сброса наборов, которые наполняет резолвер, ни пересчёта счётчиков. Не
 *     совпал — одной транзакцией, как у подкоманды (ruleset_load в apply.c: «добавить — удалить —
 *     новая таблица», счётчики переносятся), отказ ядра — прежний откат спеки.
 *   Маршрутизация — подпись по выходу: вид, метка, таблица, on_fail, пул устройств, файл awg
 *     (out_route_sig в apply.c). Привязываются заново только выходы с новой подписью и новые;
 *     правило и таблица убранного выхода (или прежняя метка выхода, которому реестр дал другую)
 *     снимаются, как у cleanup_stale_routing, если метку не несёт никто из оставшихся.
 *   Помощники — сверка подписей в супервизоре (helpers_merge через supd_spec_changed): apply
 *     зовёт её, а не перезапуск всех.
 *   Таблица резолвера — пишется в трубу, только если изменился её текст или файлы списков, на
 *     которые она ссылается (supd.c, tab_send).
 *   Сторож — внеочередной проход, только если изменились выходы: подпись сторожа (маршрут, via,
 *     выбор по задержке) или помощники.
 *
 * ЧТО ДЕМОН ЗНАЕТ О ПРИМЕНЁННОМ. Только то, что применил сам (struct recon_state). После старта
 * демона — ничего, и первый apply или reload применяет всё, как подкоманда: спеку до него мог
 * ставить init (`steer apply`), и верить, что в ядре именно она, демону не на чем. Применённое
 * забывается, когда движок выключен (правила снимает init, включённый движок их ставит init же) и
 * когда применение не прошло целиком. Чужое вмешательство в ядро — `steer down`, `steer apply` из
 * init — меняет номер таблицы или убирает её, и сверка видит это по netlink: тогда тоже всё
 * заново. На ядре до 4.16 номера таблиц нет, и там видно только «таблица есть или нет»; init
 * телефона ставит ту же сохранённую спеку, что держит демон, так что разойтись им не на чем.
 *
 * ГДЕ ИДЁТ РАБОТА. Компиляция — не в процессе демона, а ребёнком на команду: `steer apply-plan`
 * (проверки dry-run и отпечатки частей) и, если есть что применять, `steer apply-commit` (только
 * названные части). Процесс на apply, а не на проход — это допустимо и здесь лучше потока:
 *   - компиляция больших списков — секунды процессора и десятки мегабайт памяти пиком; в ребёнке
 *     цикл демона свободен (status отвечает сразу), а память возвращается системе с его выходом,
 *     и куча демона, который живёт месяцами, не растёт пиками;
 *   - компилятор держит глобальное состояние (g_nftc, перенесённые счётчики, реестр меток), и
 *     status демона читает те же счётчики в процессе — поток-рабочий делил бы их без замков;
 *   - сбой компилятора (die на битом списке, зависание nft) задевает только ребёнка, как и
 *     прежде, а срок команды убивает его группу целиком.
 * Прежний путь делал то же двумя детьми — dry-run и apply, то есть компилировал дважды на каждый
 * apply; сейчас на неизменной спеке компиляция одна (план), а nft и ip не запускаются вовсе. План
 * внешних процессов не зовёт: раскладку набора правил (проба ядра через nft) демон узнаёт у
 * первого плана и дальше передаёт готовой. nft -f и ip — в apply-commit, ребёнке демона, чей
 * выход приходит через loop_child.
 *
 * Подкоманда `steer apply` (init.d, rpcd, init телефона) не меняется: она проходит все шаги
 * подряд, тем же кодом (apply.c). */
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <endian.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <linux/netlink.h>
#include <linux/netfilter.h>
#include <linux/netfilter/nfnetlink.h>
#include <linux/netfilter/nf_tables.h>

#include "recon.h"

void recon_init(struct recon_state *st) {
    memset(st, 0, sizeof(*st));
    st->nftc = -1;
}

void recon_forget(struct recon_state *st) {
    st->valid = 0;
    st->n = 0;
}

int recon_plan_parse(const char *text, size_t n, struct recon_plan *p) {
    memset(p, 0, sizeof(*p));
    p->nftc = -1;
    int have_fp = 0;
    const char *end = text + n;
    for (const char *ln = text; ln < end; ) {
        const char *e = memchr(ln, '\n', (size_t)(end - ln));
        size_t len = e ? (size_t)(e - ln) : (size_t)(end - ln);
        char line[256];
        if (len >= sizeof(line)) len = sizeof(line) - 1;
        memcpy(line, ln, len);
        line[len] = '\0';
        ln = e ? e + 1 : end;
        if (!strncmp(line, "nftc ", 5)) {
            p->nftc = atoi(line + 5);
        } else if (!strncmp(line, "ruleset ", 8)) {
            p->fp = strtoull(line + 8, NULL, 16);
            have_fp = 1;
        } else if (!strncmp(line, "counts ", 7)) {
            if (sscanf(line + 7, "%zu %zu", &p->ch_n, &p->out_n) != 2) return -1;
        } else if (!strncmp(line, "out ", 4)) {
            if (p->n >= MAX_OUTPUTS) return -1;
            struct recon_out *o = &p->out[p->n];
            if (sscanf(line + 4, "%31s %x %d %d %d %llx %llx", o->name, &o->mark, &o->table,
                       &o->routed, &o->awg, &o->rsig, &o->wsig) != 7)
                return -1;
            p->n++;
        } else if (!strncmp(line, "stale ", 6)) {
            if (p->stale_n >= MAX_OUTPUTS) continue;
            if (sscanf(line + 6, "%x %d", &p->stale[p->stale_n].mark,
                       &p->stale[p->stale_n].table) == 2)
                p->stale_n++;
        }
    }
    return have_fp && p->nftc >= 0 ? 0 : -1;
}

static const struct recon_out *out_find(const struct recon_out *v, size_t n, const char *name) {
    for (size_t i = 0; i < n; i++)
        if (!strcmp(v[i].name, name)) return &v[i];
    return NULL;
}

static void drop_add(struct recon_diff *d, const struct recon_plan *p, unsigned mark, int table) {
    if (!mark) return;
    for (size_t i = 0; i < p->n; i++)
        if (p->out[i].mark == mark) return;      /* метку несёт выход новой спеки */
    for (size_t i = 0; i < d->drop_n; i++)
        if (d->drop[i].mark == mark && d->drop[i].table == table) return;
    if (d->drop_n >= sizeof(d->drop) / sizeof(d->drop[0])) return;
    d->drop[d->drop_n].mark = mark;
    d->drop[d->drop_n].table = table;
    d->drop_n++;
}

void recon_decide(const struct recon_state *st, const struct recon_plan *p, struct recon_diff *d) {
    memset(d, 0, sizeof(*d));
    int full = !st->valid;
    if (!full) {
        uint64_t h = 0;
        int rc = recon_table_handle(nft_table(), &h);
        /* Таблицы нет или она не та, что ставили мы, — в ядре побывал кто-то ещё (`steer down`,
         * `steer apply` из init): что там теперь стоит, не знаем — всё заново. */
        if (rc != 0 || h != st->handle) full = 1;
    }
    d->ruleset = full || st->fp != p->fp;
    for (size_t i = 0; i < p->n; i++) {
        const struct recon_out *o = &p->out[i];
        if (!o->routed) continue;
        const struct recon_out *was = full ? NULL : out_find(st->out, st->n, o->name);
        if (was && was->routed && was->rsig == o->rsig) continue;
        snprintf(d->route[d->route_n++], sizeof(d->route[0]), "%s", o->name);
        if (o->awg) d->awg = 1;
    }
    for (size_t i = 0; i < p->stale_n; i++) drop_add(d, p, p->stale[i].mark, p->stale[i].table);
    if (st->valid)
        for (size_t i = 0; i < st->n; i++) {
            const struct recon_out *was = &st->out[i];
            const struct recon_out *now = out_find(p->out, p->n, was->name);
            if (now && now->mark == was->mark && now->table == was->table) continue;
            drop_add(d, p, was->mark, was->table);
            if (was->awg && (!now || !now->awg)) d->awg = 1;
        }
    if (full) d->awg = d->masq = 1;
    else d->masq = d->route_n || d->drop_n;
}

int recon_diff_any(const struct recon_diff *d) {
    return d->ruleset || d->route_n || d->drop_n || d->awg;
}

void recon_commit_argv(const struct recon_diff *d, const char *exe, const char *spec,
                       const char *state_dir, int nftc, char *buf, size_t n, char **av) {
    size_t k = 0, off = 0;
    av[k++] = (char *)exe;
    av[k++] = "apply-commit";
    av[k++] = "--spec";
    av[k++] = (char *)spec;
    if (state_dir) { av[k++] = "--state-dir"; av[k++] = (char *)state_dir; }
    if (nftc >= 0) {
        int w = snprintf(buf + off, n - off, "%d", nftc);
        av[k++] = "--nftc";
        av[k++] = buf + off;
        off += (size_t)w + 1;
    }
    if (d->ruleset) av[k++] = "--ruleset";
    if (d->awg) av[k++] = "--awg";
    if (d->masq) av[k++] = "--masq";
    if (d->route_n && off < n) {
        char *s = buf + off;
        size_t l = 0;
        for (size_t i = 0; i < d->route_n && off + l + 40 < n; i++)
            l += (size_t)snprintf(s + l, n - off - l, "%s%s", i ? "," : "", d->route[i]);
        av[k++] = "--route";
        av[k++] = s;
        off += l + 1;
    }
    if (d->drop_n && off < n) {
        char *s = buf + off;
        size_t l = 0;
        for (size_t i = 0; i < d->drop_n && off + l + 40 < n; i++)
            l += (size_t)snprintf(s + l, n - off - l, "%s%x:%d", i ? "," : "", d->drop[i].mark,
                                  d->drop[i].table);
        av[k++] = "--drop";
        av[k++] = s;
        off += l + 1;
    }
    av[k] = NULL;
}

void recon_applied(struct recon_state *st, const struct recon_plan *p, const struct recon_diff *d) {
    if (d->ruleset || !st->valid) {
        uint64_t h = 0;
        /* Номер нашей новой таблицы — чтобы следующий раз узнать, не подменил ли её кто. Не
         * спросилось — применённое не запоминаем: следующий apply применит набор заново. */
        if (recon_table_handle(nft_table(), &h) != 0) { recon_forget(st); return; }
        st->handle = h;
    }
    st->valid = 1;
    st->fp = p->fp;
    memcpy(st->out, p->out, p->n * sizeof(p->out[0]));
    st->n = p->n;
}

int recon_watch_changed(struct recon_state *st, const struct recon_plan *p) {
    int changed = !st->wvalid || st->wn != p->n;
    for (size_t i = 0; i < p->n && !changed; i++) {
        size_t k = 0;
        while (k < st->wn && strcmp(st->w[k].name, p->out[i].name)) k++;
        if (k == st->wn || st->w[k].wsig != p->out[i].wsig) changed = 1;
    }
    for (size_t i = 0; i < p->n; i++) {
        snprintf(st->w[i].name, sizeof(st->w[i].name), "%s", p->out[i].name);
        st->w[i].wsig = p->out[i].wsig;
    }
    st->wn = p->n;
    st->wvalid = 1;
    return changed;
}

/* ---- номер таблицы по netlink ------------------------------------------------------------------
 *
 * Один запрос NFT_MSG_GETTABLE с именем таблицы: ответ несёт NFTA_TABLE_HANDLE — номер, который
 * ядро выдаёт каждой новой таблице из общего счётчика (с Linux 4.16). Наш nft -f удаляет таблицу
 * и создаёт её заново, то есть после каждого применения номер новый, а резолвер, который кладёт в
 * наборы адреса, номер не меняет. Запуска nft это не стоит: сверка неизменной спеки не зовёт ни
 * одного процесса. Срок ответа — секунда: ядро отвечает сразу, а зависнуть циклу демона на
 * сокете нельзя. */
#ifndef NFTA_TABLE_HANDLE
#define NFTA_TABLE_HANDLE 4
#endif

int recon_table_handle(const char *name, uint64_t *h) {
    *h = 0;
    int fd = socket(AF_NETLINK, SOCK_RAW | SOCK_CLOEXEC, NETLINK_NETFILTER);
    if (fd < 0) return -1;
    struct timeval tv = { 1, 0 };
    setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
    struct sockaddr_nl sa = { .nl_family = AF_NETLINK };
    union { struct nlmsghdr nh; char b[256]; } req;
    memset(&req, 0, sizeof(req));
    size_t nl = strlen(name) + 1;
    struct nfgenmsg *g = (struct nfgenmsg *)NLMSG_DATA(&req.nh);
    g->nfgen_family = NFPROTO_INET;
    g->version = NFNETLINK_V0;
    struct nlattr *a = (struct nlattr *)((char *)g + NLMSG_ALIGN(sizeof(*g)));
    a->nla_type = NFTA_TABLE_NAME;
    a->nla_len = (uint16_t)(NLA_HDRLEN + nl);
    memcpy((char *)a + NLA_HDRLEN, name, nl);
    req.nh.nlmsg_len = (uint32_t)(NLMSG_HDRLEN + NLMSG_ALIGN(sizeof(*g)) + NLA_ALIGN(a->nla_len));
    req.nh.nlmsg_type = (NFNL_SUBSYS_NFTABLES << 8) | NFT_MSG_GETTABLE;
    req.nh.nlmsg_flags = NLM_F_REQUEST | NLM_F_ACK;
    req.nh.nlmsg_seq = 1;
    if (sendto(fd, &req, req.nh.nlmsg_len, 0, (struct sockaddr *)&sa, sizeof(sa)) < 0) {
        close(fd);
        return -1;
    }
    int rc = -1, done = 0;
    char buf[8192];
    while (!done) {
        ssize_t m = recv(fd, buf, sizeof(buf), 0);
        if (m < 0 && errno == EINTR) continue;
        if (m <= 0) break;
        for (struct nlmsghdr *nh = (struct nlmsghdr *)buf; NLMSG_OK(nh, (size_t)m);
             nh = NLMSG_NEXT(nh, m)) {
            if (nh->nlmsg_type == NLMSG_ERROR) {
                const struct nlmsgerr *er = NLMSG_DATA(nh);
                if (er->error == -ENOENT) rc = 1;
                else if (er->error != 0) rc = -1;
                done = 1;
                break;
            }
            if (nh->nlmsg_type == NLMSG_DONE) { done = 1; break; }
            if ((nh->nlmsg_type & 0xff) != NFT_MSG_NEWTABLE) continue;
            rc = 0;
            const char *p = (const char *)NLMSG_DATA(nh) + NLMSG_ALIGN(sizeof(struct nfgenmsg));
            const char *e = (const char *)nh + nh->nlmsg_len;
            while (p + NLA_HDRLEN <= e) {
                const struct nlattr *at = (const struct nlattr *)p;
                if (at->nla_len < NLA_HDRLEN || p + at->nla_len > e) break;
                if ((at->nla_type & NLA_TYPE_MASK) == NFTA_TABLE_HANDLE &&
                    at->nla_len >= NLA_HDRLEN + 8) {
                    uint64_t v;
                    memcpy(&v, p + NLA_HDRLEN, 8);
                    *h = be64toh(v);
                }
                p += NLA_ALIGN(at->nla_len);
            }
        }
    }
    close(fd);
    return rc;
}
