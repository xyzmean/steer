/* `steer srs-read` — набор правил sing-box нашим синтаксисом списка, через тот же читатель,
 * которым набор читают компилятор и резолвер (src/model/srs.c, там же — формат и соответствие
 * видов элементов нашему синтаксису).
 *
 * Вывод прежний до байта (стенд tests/srsmatch.sh): домены и подсети — в порядке файла, по
 * строке на элемент; сужение — третьим потоком, ОДНО на весь набор (протоколы и порты всех
 * правил вместе), в виде `proto=` и `ports=`, готовом к переносу в канал.
 *
 * ПОЧЕМУ СУЖЕНИЕ ОТДЕЛЬНЫМ ПОТОКОМ, а не строкой в списке. Список читают dnsd и компилятор
 * набора правил, и обоим `proto=udp` — мусор: первый сочтёт это доменным правилом, второй
 * пропустит как не-адрес. Сужение принадлежит каналу, а не списку.
 *
 * ЧЕГО ТРИ ФАЙЛА НЕ ВЫРАЖАЮТ (и отвергается кодом 2): исключения («x.com, но не y.x.com»),
 * ограничение по клиенту (source_ip_cidr) и по приложению (package_name). Канал с `srs_files`
 * выражает и это — поэтому, а не ради команды, набор теперь подключается к каналу сам. */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

#include "srs.h"
#include "srsread.h"

#define MAX_META_PORTS 32
#define META_PORT_LEN  16

struct out {
    FILE *dom, *pfx;
    int saw_v6;
};

static int print_elem(void *ctx, const struct srs_elem *el) {
    struct out *o = ctx;
    if (el->kind == SRS_EL_DOMAIN) {
        switch (el->dom) {
        case SRS_DOM_SUFFIX:   fprintf(o->dom, "%s\n", el->str); break;   /* имя и поддомены */
        case SRS_DOM_WILDCARD: fprintf(o->dom, "*%s\n", el->str); break;  /* буквальный суффикс */
        case SRS_DOM_EXACT:    fprintf(o->dom, "=%s\n", el->str); break;  /* только само имя */
        case SRS_DOM_KEYWORD:  fprintf(o->dom, "*%s*\n", el->str); break;
        case SRS_DOM_REGEX:    fprintf(o->dom, "re:%s\n", el->str); break;
        }
        return 0;
    }
    if (el->family == 6) {
        /* IPv6 в наших наборах правил пока не участвует, а молча выбросить его нельзя —
         * иначе список выглядел бы прочитанным целиком. */
        o->saw_v6 = 1;
        return 0;
    }
    fprintf(o->pfx, "%u.%u.%u.%u/%d\n", el->addr[0], el->addr[1], el->addr[2], el->addr[3],
            el->plen);
    return 0;
}

static int srs_dump_set(const struct srs_set *s, const char *path, FILE *dom, FILE *pfx,
                        FILE *meta);

static int srs_dump_to(const char *path, FILE *dom, FILE *pfx, FILE *meta) {
    const struct srs_set *s;
    struct err e = {0};
    if (srs_open(path, &s, &e) != 0) {
        fprintf(stderr, "steer: %s\n", e.msg);
        return 1;
    }
    int rc = srs_dump_set(s, path, dom, pfx, meta);
    srs_release(s);
    return rc;
}

static int srs_dump_set(const struct srs_set *s, const char *path, FILE *dom, FILE *pfx,
                        FILE *meta) {
    struct err e = {0};
    /* Что тремя файлами не выражается — решается до печати: половина набора — не набор. */
    const char *why = NULL;
    int tcp = 0, udp = 0;
    char ports[MAX_META_PORTS][META_PORT_LEN];
    size_t ports_n = 0;
    int ports_over = 0;
    for (size_t i = 0; i < srs_clause_n(s) && !why; i++) {
        const struct srs_clause *c = srs_clause(s, i);
        if (c->flags & (SRS_F_XDOM | SRS_F_XCIDR))
            why = "правило-исключение: списком исключения не выражаются (подключите набор к "
                  "каналу ключом srs_files)";
        else if (c->src_n)
            why = "source_ip_cidr: набор описывает клиентов, а не назначение (подключите набор "
                  "к каналу ключом srs_files)";
        else if (c->pkg_n)
            why = "package_name: набор описывает приложения (подключите набор к каналу ключом "
                  "srs_files)";
        tcp |= c->net_tcp;
        udp |= c->net_udp;
        /* Повторы отбрасываются: у sing-box один и тот же диапазон встречается в двух
         * элементах, а nft на дубле в множестве отвергает весь набор правил. */
        for (size_t k = 0; k < c->raw_n && !ports_over; k++) {
            char b[META_PORT_LEN];
            if (c->raw_range[k] || c->raw[k].lo != c->raw[k].hi)
                snprintf(b, sizeof(b), "%u-%u", c->raw[k].lo, c->raw[k].hi);
            else
                snprintf(b, sizeof(b), "%u", c->raw[k].lo);
            size_t j = 0;
            while (j < ports_n && strcmp(ports[j], b) != 0) j++;
            if (j < ports_n) continue;
            if (ports_n >= MAX_META_PORTS) { ports_over = 1; break; }
            snprintf(ports[ports_n++], META_PORT_LEN, "%s", b);
        }
    }
    if (!why && ports_over) why = "портов в наборе больше, чем канал может сузить";
    if (why) {
        fprintf(stderr, "steer: srs: набор понят, но не выразим списком — %s\n", why);
        return 2;
    }
    /* Сужение есть, а печатать его некуда — это ОТКАЗ, а не мелочь. Отдать подсети Cloudflare
     * без «только udp 50000-65535» значит увести в туннель весь TCP к 104.16.0.0/12, и
     * вызывающий об этом даже не узнает. */
    if (!meta && (tcp || udp || ports_n)) {
        fprintf(stderr, "steer: srs: набор сужен по протоколу или портам — нужен --meta-out, "
                        "иначе сужение потеряется, а подсети уедут в туннель целиком\n");
        return 2;
    }
    struct out o = { dom, pfx, 0 };
    int rc = srs_walk(s, SRS_EL_DOMAIN | SRS_EL_CIDR, NULL, print_elem, &o, &e);
    if (rc != 0) {
        fprintf(stderr, "steer: %s\n", e.msg);
        return 1;
    }
    /* Уровень обязателен: разбор УДАЛСЯ, значит это строка журнала во время работы, а не
     * отказ вызывающему (контракт docs/contract-v1.md §5). */
    if (srs_skipped(s))
        fprintf(stderr, "steer[warn] srs: %s: %s\n", path, srs_skipped(s));
    if (o.saw_v6)
        fprintf(stderr, "steer[warn] srs: в наборе есть подсети IPv6 — они пропущены, "
                        "правила работают по IPv4\n");
    if (meta) {
        if (tcp && udp) fprintf(meta, "proto=both\n");
        else if (tcp)   fprintf(meta, "proto=tcp\n");
        else if (udp)   fprintf(meta, "proto=udp\n");
        if (ports_n) {
            fprintf(meta, "ports=");
            for (size_t i = 0; i < ports_n; i++) fprintf(meta, "%s%s", i ? "," : "", ports[i]);
            fprintf(meta, "\n");
        }
    }
    return 0;
}

/* Открыть все выходы, разобрать, закрыть. Выходы открываются ДО разбора: файл, который не
 * удалось создать, надо назвать раньше, чем половина набора уехала в другой. */
int srs_dump(const char *path, const char *dom_path, const char *pfx_path,
             const char *meta_path) {
    FILE *dom = stdout, *pfx = stdout, *meta = NULL;
    if (dom_path && !(dom = fopen(dom_path, "w"))) {
        fprintf(stderr, "steer: srs: не создался %s\n", dom_path);
        return 1;
    }
    if (pfx_path && !(pfx = fopen(pfx_path, "w"))) {
        fprintf(stderr, "steer: srs: не создался %s\n", pfx_path);
        if (dom != stdout) fclose(dom);
        return 1;
    }
    if (meta_path && !(meta = fopen(meta_path, "w"))) {
        fprintf(stderr, "steer: srs: не создался %s\n", meta_path);
        if (dom != stdout) fclose(dom);
        if (pfx != stdout && pfx != dom) fclose(pfx);
        return 1;
    }
    int rc = srs_dump_to(path, dom, pfx, meta);
    /* Закрытие проверяется: на полном overlay ошибка приходит именно здесь, при сбросе буфера. */
    if (dom != stdout && fclose(dom) != 0) {
        fprintf(stderr, "steer: srs: %s не записался до конца\n", dom_path);
        rc = rc ? rc : 1;
    }
    if (pfx != stdout && pfx != dom && fclose(pfx) != 0) {
        fprintf(stderr, "steer: srs: %s не записался до конца\n", pfx_path);
        rc = rc ? rc : 1;
    }
    if (meta && fclose(meta) != 0) {
        fprintf(stderr, "steer: srs: %s не записался до конца\n", meta_path);
        rc = rc ? rc : 1;
    }
    return rc;
}
