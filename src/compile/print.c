/* Печать дерева набора правил (ir.h) в текст nftables — один печатник на обе раскладки.
 *
 * Печатник знает только синтаксис nft и раскладку текста: отступы в четыре пробела, пустые
 * строки там, где их поставил строитель (obj->gap), «dnat ip to» в inet и «dnat to» в
 * таблице одного семейства. Что стоит в ядре, решают генератор (generate.c) и раскладка
 * старого ядра (legacy.c). Текст обязан совпадать с тем, что печатал прежний генератор, до
 * байта: на этом держится снимок tests/golden/ruleset. */
#define _GNU_SOURCE
#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <arpa/inet.h>
#include <netinet/in.h>

#include "spec.h"
#include "ir.h"

#define LOG_W "steer[warn] apply: "

/* Elements come straight from the list files: the fitter (steer-aggregate) has
 * already decided what fits, and re-parsing them here would only add a second place
 * for the two to disagree. */
static size_t emit_elements(FILE *f, const char *path, size_t already) {
    FILE *in = fopen(path, "r");
    /* Не die: читаемость всех файлов уже проверена (check_address_lists), и попасть сюда
     * можно только гонкой — список удалили между проверкой и генерацией. Ронять из-за неё
     * весь набор правил незачем: пропадут адреса одного списка, и про это будет сказано. */
    if (!in) {
        fprintf(stderr, LOG_W "%s: список исчез во время сборки набора правил\n", path);
        return 0;
    }
    /* 512, а не 128: строка длиннее просто обрезалась бы посередине, и в набор уехал бы
     * обломок адреса — то есть тихо не тот адрес. */
    char line[512];
    size_t n = already;
    while (fgets(line, sizeof(line), in)) {
        char *nl = strpbrk(line, "\r\n");
        if (nl) *nl = '\0';
        char *p = line;
        while (*p == ' ' || *p == '\t') p++;
        if (!*p || *p == '#' || *p == ';') continue;
        /* Не-адреса пропускаем молча: про них уже сказал check_address_lists, а nft на
         * них отвергает ВЕСЬ набор, а не одну строку. */
        if (!spec_line_is_addr(p)) continue;
        /* fputs, а не fprintf: на списке в сотни тысяч элементов разбор
         * форматной строки на каждый — это заметная доля времени apply. */
        if (n) fputs(", ", f);
        fputs(p, f);
        n++;
    }
    fclose(in);
    return n - already;
}

/* КАРТА ПОДМЕНЫ fake→real ЗАСЕВАЕТСЯ ПРЯМО В НАБОРЕ ПРАВИЛ — из файла состояния резолвера
 * (<state-dir>/fakeip.state, строки «домен\tподдельный\tнастоящий»), а не остаётся пустой до
 * перезапуска dnsd.
 *
 * ЗАЧЕМ. apply пересобирает таблицу целиком, и карта на мгновение исчезала вместе с ней; dnsd
 * восстанавливал её только при своём перезапуске, секундой позже. Запрос, пришедший в это окно,
 * не мог добавить подмену (карты нет), и dnsd по правилу fail-open отдавал клиенту НАСТОЯЩИЙ
 * адрес: сайт, который человек велел вести в туннель, уходил напрямую, а клиент запоминал этот
 * адрес на весь TTL записи. Снято с живого роутера: после «Применить» посреди просмотра YouTube
 * узел googlevideo остался в состоянии без настоящего адреса, а ролики не открывались до
 * перезапуска браузера — уже при исправном туннеле. С засеянной картой окна нет: пакеты к
 * поддельным адресам переводятся тем же набором правил, который их и метит.
 *
 * Только строки с настоящим адресом: без него подменять нечего, и dnsd такую запись тоже не
 * восстанавливает. Повтор поддельного адреса пропускается — nft отвергает набор с двойным
 * ключом целиком, а в файле повторы законны (первая раздача побеждает, как у dnsd). Файла нет —
 * карта пустая, как и раньше: так на роутере, где резолвер ещё ничего не раздал. */
static void emit_fakeip_elements(FILE *f, const char *path) {
    FILE *s = fopen(path, "r");
    if (!s) return;
    static uint8_t seen[131072 / 8];       /* 198.18.0.0/15 — бит на адрес */
    memset(seen, 0, sizeof(seen));
    char line[1024];
    int n = 0;
    while (fgets(line, sizeof(line), s)) {
        char *t1 = strchr(line, '\t');
        if (!t1) continue;
        char *fake = t1 + 1;
        char *t2 = strchr(fake, '\t');
        if (!t2) continue;
        *t2 = '\0';
        char *real = t2 + 1;
        char *end = real + strcspn(real, "\t\r\n");
        *end = '\0';
        struct in_addr a, b;
        if (inet_aton(fake, &a) == 0 || inet_aton(real, &b) == 0 || b.s_addr == 0) continue;
        uint32_t fh = ntohl(a.s_addr);
        if ((fh & 0xfffe0000u) != 0xc6120000u) continue;   /* вне 198.18.0.0/15 — не наше */
        uint32_t idx = fh - 0xc6120000u;
        if (seen[idx >> 3] & (uint8_t)(1u << (idx & 7))) continue;
        seen[idx >> 3] |= (uint8_t)(1u << (idx & 7));
        /* В набор едет РАЗОБРАННЫЙ адрес, а не байты строки. inet_aton принимает не только
         * точечную запись: «0xc6120009», «3323068425» и «198.18.9» — то же самое 198.18.0.9,
         * и проверку диапазона выше такая строка проходит честно. А nft такого ключа не
         * понимает и отвергает набор ЦЕЛИКОМ (`nft -f` атомарен) — то есть одна нетипичная
         * строка в файле состояния оставила бы роутер вообще без правил: ни маршрутизации,
         * ни подмены, ни меток. Раз адрес уже разобран, печатать надо его, а не то, из чего
         * он разобран.
         *
         * Два своих буфера, а не inet_ntoa дважды: inet_ntoa отдаёт статический буфер, и
         * второй вызов в том же fprintf перезаписал бы результат первого. */
        char fs[INET_ADDRSTRLEN], rs[INET_ADDRSTRLEN];
        if (!inet_ntop(AF_INET, &a, fs, sizeof(fs)) ||
            !inet_ntop(AF_INET, &b, rs, sizeof(rs))) continue;
        fprintf(f, n ? ",\n            %s : %s" : "        elements = { %s : %s", fs, rs);
        n++;
    }
    if (n) fprintf(f, " }\n");
    fclose(s);
}

/* Элементы набора. Источник fakeip.state печатается своей раскладкой (пары по строке, и
 * строки elements нет вовсе, если пар нет); остальные — одной строкой через запятую.
 *
 * Строка elements у адресных источников печатается, даже если в файлах не нашлось ни одной
 * адресной строки: строитель кладёт файлы в набор, только когда check_address_lists насчитал
 * в них адреса, и пустым набор здесь выйдет лишь гонкой (список исчез после проверки) —
 * ровно как у прежнего генератора. */
static void print_elements(FILE *f, const struct nft_set *s) {
    int list = 0;
    for (const struct nft_elsrc *e = s->els; e; e = e->next) {
        if (e->k == NFT_EL_FAKEIP_STATE) emit_fakeip_elements(f, e->s);
        else list = 1;
    }
    if (!list) return;
    fprintf(f, "        elements = { ");
    size_t written = 0;
    for (const struct nft_elsrc *e = s->els; e; e = e->next) {
        if (e->k == NFT_EL_ADDR_FILE) written += emit_elements(f, e->s, written);
        else if (e->k == NFT_EL_VALUE) {
            if (written++) fputs(", ", f);
            fputs(e->s, f);
        }
    }
    fprintf(f, " }\n");
}

static void print_set(FILE *f, const struct nft_set *s) {
    fprintf(f, "%s    %s %s {\n", s->o.gap ? "\n" : "", s->data ? "map" : "set", s->o.name);
    if (s->data) fprintf(f, "        type %s : %s;\n", s->key, s->data);
    else fprintf(f, "        type %s\n", s->key);
    if (s->flags) {
        fprintf(f, "        flags ");
        const char *sep = "";
        if (s->flags & NFT_SET_INTERVAL) { fprintf(f, "%sinterval", sep); sep = ","; }
        if (s->flags & NFT_SET_TIMEOUT) fprintf(f, "%stimeout", sep);
        fprintf(f, "\n");
    }
    if (s->auto_merge) fprintf(f, "        auto-merge\n");
    print_elements(f, s);
    fprintf(f, "    }\n");
}

static void print_expr(FILE *f, const struct nft_table *t, const struct nft_rule *r,
                       const struct nft_expr *x) {
    switch (x->k) {
    case NFT_X_RAW:
    case NFT_X_MARKSET:
    case NFT_X_NOTRACK:
    case NFT_X_FRAG6:
        fputs(x->text, f);
        break;
    case NFT_X_FAMILY:
        fprintf(f, "meta nfproto ipv%d", x->fam);
        break;
    case NFT_X_SETREF:
        fprintf(f, "%s @%s", x->text, x->arg);
        break;
    case NFT_X_COUNTER:
        /* Нули — коротким `counter`: так вывод `--dry-run` на чистой машине остаётся тем же
         * текстом, что и раньше. */
        if (r->pkts || r->bytes) fprintf(f, "counter packets %lu bytes %lu", r->pkts, r->bytes);
        else fputs("counter", f);
        break;
    case NFT_X_DNAT:
        /* В таблице одного семейства семейство и так известно, и слово ip после dnat там
         * лишнее; в inet без него nft не знает, адрес какого семейства подставлять. */
        fprintf(f, "dnat %sto %s map @%s", t->fam == NFT_FAM_INET ? "ip " : "", x->text, x->arg);
        break;
    case NFT_X_JUMP:
        fprintf(f, "jump %s", x->arg);
        break;
    }
}

static void print_rule(FILE *f, const struct nft_table *t, const struct nft_rule *r) {
    fputs("        ", f);
    int first = 1;
    for (const struct nft_expr *x = r->x; x; x = x->next) {
        /* «meta nfproto ipvN» в таблице ip/ip6 ничего не сужает — семейство задала таблица. */
        if (x->k == NFT_X_FAMILY && t->fam != NFT_FAM_INET) continue;
        if (!first) fputc(' ', f);
        print_expr(f, t, r, x);
        first = 0;
    }
    if (r->comment) fprintf(f, "%scomment \"%s\"", first ? "" : " ", r->comment);
    fputc('\n', f);
}

static void print_chain(FILE *f, const struct nft_table *t, const struct nft_chain *c) {
    fprintf(f, "%s    chain %s {\n", c->o.gap ? "\n" : "", c->o.name);
    if (c->type) {
        char prio[48];
        ir_prio_str(c, prio, sizeof(prio));
        fprintf(f, "        type %s hook %s priority %s; policy %s;\n",
                c->type, c->hook, prio, c->policy ? c->policy : "accept");
    }
    for (const struct nft_rule *r = c->rules; r; r = r->next) print_rule(f, t, r);
    fprintf(f, "    }\n");
}

static const char *fam_name(enum nft_family fam) {
    switch (fam) {
    case NFT_FAM_IP: return "ip";
    case NFT_FAM_IP6: return "ip6";
    case NFT_FAM_INET: break;
    }
    return "inet";
}

void nft_print(const struct nft_rs *rs, FILE *f) {
    for (const struct nft_table *t = rs->tables; t; t = t->next) {
        fprintf(f, "table %s %s {\n", fam_name(t->fam), t->name);
        for (struct nft_obj *o = t->objs; o; o = o->next) {
            if (o->k == NFT_OBJ_SET) print_set(f, (const struct nft_set *)o);
            else print_chain(f, t, (const struct nft_chain *)o);
        }
        fprintf(f, "}\n");
    }
}
