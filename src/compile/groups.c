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
#include "groups.h"
#include "daemon.h"

/* Дописать адресный список в группу, растя вектор вдвое. Отказ памяти здесь — это «правила
 * не собрать», поэтому громкий (в struct err, а не в stderr — см. правило 5, раздел 2
 * docs/architecture.md): тихо потерянный список превратил бы узкий канал в широкий. */
static int group_add_file(struct group *g, const char *path, struct err *e) {
    if (g->files_n == g->files_cap) {
        size_t cap = g->files_cap ? g->files_cap * 2 : 8;
        const char **p = realloc(g->files, cap * sizeof(*p));
        if (!p) return err_set(e, "out of memory building channel groups", NULL);
        g->files = p;
        g->files_cap = cap;
    }
    g->files[g->files_n++] = path;
    return 0;
}

void groups_free(struct groups *gr) {
    for (size_t i = 0; i < gr->n; i++) free(gr->g[i].files);
    gr->n = 0;
}

static int same_from(const struct spec *sp, const struct channel *c, const struct group *g) {
    const char (*cf)[64] = c->from_n ? c->from : sp->from_default;
    size_t cn = c->from_n ? c->from_n : sp->from_default_n;
    if (cn != g->from_n) return 0;
    for (size_t i = 0; i < cn; i++)
        if (strcmp(cf[i], g->from[i]) != 0) return 0;
    return 1;
}

/* Built once per run: the first channel of a group fixes its place, so "first match wins"
 * still reads off the spec.
 *
 * ПРОХОДОВ ДВА, И ПЕРВЫЙ — ПРАВИЛА НА УСТРОЙСТВО. Порядок совпадения в цепочке и есть
 * приоритет: правило заканчивается `return`, поэтому побеждает первое совпавшее. Пока
 * порядок читался только со спеки, правило «этот телефон не маршрутизируем» работало ровно
 * до тех пор, пока человек держал его выше глобальных: стоило добавить новое глобальное и
 * поставить его первым — и исключение для телефона перестало действовать, молча.
 *
 * Владелец потребовал обратного: правило на устройство старше глобального ВСЕГДА. Значит
 * приоритет обязан быть свойством правила, а не порядка в списке, — и обеспечивается он
 * здесь, а не просьбой к человеку не переставлять строки.
 *
 * Внутри каждой из двух групп порядок спеки сохраняется: два правила на разные устройства
 * или два глобальных по-прежнему читаются сверху вниз, как и раньше. */
int build_groups(const struct spec *sp, struct groups *gr, struct err *e) {
    /* Прежние векторы файлов не теряются: повторный разбор в том же значении их отдаёт. */
    groups_free(gr);
    for (int pass = 0; pass < 2; pass++)
    for (size_t i = 0; i < sp->ch_n; i++) {
        const struct channel *c = &sp->ch[i];
        /* Первый проход берёт только правила на устройство, второй — только остальные. */
        if ((pass == 0) != (c->dev_scope != 0)) continue;
        /* Выключенное правило не превращается ни в набор, ни в правило — то есть его нет в
         * ядре так же, как если бы его не было в спеке. Именно этого от выключателя и ждут:
         * «выключено» обязано значить «не действует», а не «действует тише». */
        if (c->disabled) continue;
        int domains = c->domains_n > 0;
        /* Канал, забирающий ВЕСЬ трафик: у него нет набора вовсе. */
        int all = c->any && !c->prefixes_n && !c->domains_n;
        size_t k = 0;
        for (; k < gr->n; k++) {
            struct group *g = &gr->g[k];
            if (strcmp(g->out, c->out) != 0) continue;
            /* «Весь трафик» и «трафик из списка» — РАЗНЫЕ группы, даже когда выход и
             * клиенты совпадают. Слияние их было молчаливой потерей: правило группы
             * получало имя _ip и начинало проверять набор, то есть канал «весь трафик
             * этой сети в туннель» превращался в «только адреса из списка», и об этом не
             * сообщалось ни отказом, ни в status, ни в diag. */
            if (g->all != all) continue;
            /* Вид больше НЕ разделяет группы: адресное и доменное правило одного сервиса,
             * ведущие в один outbound для одних клиентов, — это одно правило и один набор.
             * Разделение по виду было следствием запрета смешивать, а не требованием ядра. */
            if (domains && g->domains && g->realip != c->realip) continue;
            if (!same_from(sp, c, g)) continue;
            /* СУЖЕНИЕ ПО ПРОТОКОЛУ И ПОРТАМ РАЗДЕЛЯЕТ ГРУППЫ так же, как выход и клиенты.
             *
             * Слить их было бы молчаливой потерей смысла в обе стороны сразу: набор у группы
             * один, правило одно, и ограничение либо распространилось бы на чужие адреса
             * (сузили то, чего человек не просил), либо пропало бы вовсе — а «пропало»
             * означает весь TCP к Cloudflare в туннель, потому что канал Discord это
             * 104.16.0.0/12 плюс udp 50000-65535. Об этом не сообщил бы ни отказ, ни status,
             * ни diag: правила выглядят применёнными. Та же болезнь, от которой выше
             * разделены группы `all` и списочные. */
            if (!l4match_same(g->l4, &c->l4)) continue;
            break;
        }
        if (k == gr->n) {
            struct group *g = &gr->g[gr->n++];
            memset(g, 0, sizeof(*g));
            g->out = c->out;
            g->domains = 0;
            g->all = all;
            g->realip = c->realip;
            g->from = c->from_n ? c->from : sp->from_default;
            g->from_n = c->from_n ? c->from_n : sp->from_default_n;
            g->l4 = &c->l4;
            /* Имя ставим предварительно, окончательное — ниже: домены могут прийти вторым
             * правилом, и тогда набор обязан называться _dom, иначе резолвер его не найдёт
             * (он вычисляет имя сам, той же функцией group_set_name). */
            group_set_name(sp, g->name, sizeof(g->name), g->out, all ? "all" : domains ? "dom" : "ip",
                           g->from, g->from_n, g->realip, g->l4);
        }
        struct group *g = &gr->g[k];
        /* Домены только помечаем: их файлы читает резолвер. Режим берём у первого доменного
         * правила в группе — у адресного его нет вовсе, и брать оттуда нечего. */
        if (domains) {
            if (!g->domains) g->realip = c->realip;
            g->domains = 1;
            g->dfiles_n += c->domains_n;
        }
        for (size_t f = 0; f < c->prefixes_n; f++)
            if (group_add_file(g, c->prefixes_files[f], e) != 0) return -1;
        if (g->members_n < MAX_CHANNELS) g->members[g->members_n++] = c->name;
    }
    /* Окончательные имена. Группа с доменами — всегда _dom, потому что имя набора резолвер
     * вычисляет тем же правилом и по-другому его не найдёт. Группы `any` не трогаем: у них
     * набора нет вовсе. */
    for (size_t i = 0; i < gr->n; i++) {
        struct group *g = &gr->g[i];
        if (!g->files_n && !g->domains) continue;
        group_set_name(sp, g->name, sizeof(g->name), g->out, g->domains ? "dom" : "ip",
                       g->from, g->from_n, g->realip, g->l4);
    }
    /* Страховка, а не проверка входа: имя обязано быть уникальным по построению, и если
     * оно всё-таки повторилось — значит различитель не различил (например, два имени
     * выхода совпали после обрезки до 18 символов). Молчать здесь нельзя: именно молчание
     * и было прежней бедой — ядро сливает одноимённые наборы, и трафик уходит не туда без
     * единой строки. Лучше громкий отказ применить спеку, чем тихая ошибка маршрутизации. */
    for (size_t i = 0; i < gr->n; i++)
        for (size_t k = i + 1; k < gr->n; k++)
            if (!strcmp(gr->g[i].name, gr->g[k].name))
                return err_set(e, "два разных набора каналов получили одно имя %s — "
                    "укоротите или разведите имена выходов", gr->g[i].name);
    return 0;
}

int has_domains(const struct groups *gr) {
    for (size_t i = 0; i < gr->n; i++) if (gr->g[i].domains) return 1;
    return 0;
}

/* Есть ли хоть один выход kind=zapret. Отдельной функцией по той же причине, что
 * has_domains: цепочка очередей пишется только когда ей есть что писать, а пустая базовая
 * цепочка в postrouting — это лишний проход по правилам на КАЖДОМ пакете роутера. */
int has_zapret(const struct spec *sp) {
    for (size_t i = 0; i < sp->out_n; i++)
        if (sp->out[i].kind == OUT_ZAPRET) return 1;
    return 0;
}

/* Есть ли хоть один выход kind=tgws. Тот же довод, что у has_zapret: цепочка перехвата
 * пишется, только когда ей есть что перехватывать. */
int has_tgws(const struct spec *sp) {
    for (size_t i = 0; i < sp->out_n; i++)
        if (sp->out[i].kind == OUT_TGWS) return 1;
    return 0;
}


int has_fakeip(const struct groups *gr) {
    for (size_t i = 0; i < gr->n; i++)
        if (gr->g[i].domains && !gr->g[i].realip) return 1;
    return 0;
}

/* Адрес это или MAC. Различаем по двоеточию: у IPv4 его нет, у MAC их пять.
 *
 * Зачем MAC вообще. «Только этот телевизор» — обычная просьба, а адрес у него меняется: DHCP
 * выдаёт другой после перезагрузки, и правило начинает касаться не того устройства. MAC
 * привязан к железу и живёт, пока живёт устройство.
 *
 * Чего он НЕ умеет: MAC виден только у соседа по L2. За вторым роутером или повторителем в
 * пакете будет MAC этого роутера, а не устройства, и правило накроет всех, кто за ним. Это
 * свойство сети, а не наша недоделка, но сказать об этом обязаны — в интерфейсе есть подсказка. */
int is_mac(const char *s) {
    int colons = 0;
    for (const char *p = s; *p; p++) {
        if (*p == ':') { colons++; continue; }
        if (!((*p >= '0' && *p <= '9') || (*p >= 'a' && *p <= 'f') || (*p >= 'A' && *p <= 'F')))
            return 0;
    }
    return colons == 5;
}


/* Группа каналов на сам телефон, а не на клиентов раздачи (см. from_is_local в spec.h).
 * Смешанных групп не бывает: спека отвергает «кому» из себя и клиентов сразу. */
int group_is_local(const struct group *g) {
    return g->from_n && from_is_local(g->from[0]);
}

int has_local(const struct groups *gr) {
    for (size_t i = 0; i < gr->n; i++) if (group_is_local(&gr->g[i])) return 1;
    return 0;
}

/* Есть ли доменный канал на сам телефон. Тогда DNS приложений заворачивается к резолверу —
 * см. nft_emit_output_dns в generate.c. */
int has_local_domains(const struct groups *gr) {
    for (size_t i = 0; i < gr->n; i++)
        if (group_is_local(&gr->g[i]) && gr->g[i].domains) return 1;
    return 0;
}

/* Есть ли в спеке туннель через via — тогда его сокет несёт STEER_TUNNEL_BIT, и заворот DNS
 * обязан его пропускать (см. local_dns_redirect в generate.c). */
int has_via(const struct spec *sp) {
    for (size_t i = 0; i < sp->out_n; i++) if (sp->out[i].via[0]) return 1;
    return 0;
}

/* Похожа ли строка на адрес или префикс IPv4. Только форма, без проверки диапазонов:
 * нам надо отличить «1.2.3.0/24» от «amazon.com», а не проверять корректность маски —
 * второе сделает nft, и его сообщение об одном плохом элементе понятно. */
/* Одна половина: «A.B.C.D» или «A.B.C.D/N». Точную проверку значений делает nft — здесь
 * различается ФОРМА, чтобы отделить адресный список от доменного. */
/* Прочитать список и посчитать, сколько строк в нём НЕ адреса.
 *
 * Отдельным проходом, до генерации: сообщение об ошибке должно появиться раньше, чем
 * мы начнём собирать набор, и раньше, чем что-либо будет применено. */
static int count_list(const char *path, size_t *total, size_t *bad,
                      char *first_bad, size_t first_bad_n, size_t *first_bad_line,
                      struct err *e) {
    FILE *in = fopen(path, "r");
    /* Отказ здесь — почти всегда гонка: readability уже проверена вызывающим мгновением
     * раньше (см. check_address_lists), и попасть сюда можно только если список исчез
     * между той проверкой и этим чтением. Редкость причины не повод оставить die() — правило
     * 5 касается любого пути, даже маловероятного. */
    if (!in) return err_set(e, "%s: cannot read a channel's list", path);
    char line[512];
    size_t lineno = 0;
    *total = *bad = 0;
    if (first_bad_n) first_bad[0] = '\0';
    while (fgets(line, sizeof(line), in)) {
        lineno++;
        char *nl = strpbrk(line, "\r\n");
        if (nl) *nl = '\0';
        char *p = line;
        while (*p == ' ' || *p == '\t') p++;
        if (!*p || *p == '#' || *p == ';') continue;
        (*total)++;
        if (spec_line_is_addr(p)) continue;
        if (!(*bad)++ && first_bad_n) {
            /* Точность в формате, а не только размер буфера: строка из файла бывает
             * длиннее образца, и обрезать её надо явно, а не «как получится». */
            snprintf(first_bad, first_bad_n, "%.100s", p);
            if (first_bad_line) *first_bad_line = lineno;
        }
    }
    fclose(in);
    return 0;
}

/* Проверить списки адресных каналов ДО того, как что-то применится.
 *
 * Зачем это здесь, а не «пусть nft разберётся». nft разбирается плохо: один доменный
 * список, подключённый как адресный, даёт «syntax error, unexpected string» с указанием
 * на середину строки в восемь тысяч символов — и отвергает НАБОР ЦЕЛИКОМ, то есть вся
 * маршрутизация остаётся на прежних правилах, а человек видит, что его выбор не подействовал,
 * без единого намёка на причину. Так и случилось: список «Хостинги и CDN» у издателя лежит
 * в адресных категориях и обещает 5444 подсети, а внутри 250 доменов и ни одного адреса.
 *
 * Поэтому разделяем два случая, и это не педантизм:
 *   весь список не адреса  — это НЕ ТОТ список, отказываемся и говорим, что делать;
 *   несколько строк плохие — это мусор в файле, предупреждаем и пропускаем их, потому что
 *                            ронять канал из 19 тысяч префиксов из-за одной строки хуже. */
int check_address_lists(struct groups *gr, struct err *e) {
    for (size_t i = 0; i < gr->n; i++) {
        struct group *g = &gr->g[i];
        /* Непрочитанный файл выбрасывается из группы ЗДЕСЬ, до подсчёта и до генерации:
         * дальше по коду его отсутствие уже не отличить от «списка не было», а разница
         * важна — про пропажу надо сказать. Причина почти всегда одна: обновление образа
         * сохранило спеку (она в keep.d) и не сохранило каталог списков — он там не
         * объявлен намеренно, это решение владельца (splicicd#6). */
        for (size_t k = 0; k < g->files_n; ) {
            FILE *probe = fopen(g->files[k], "r");
            if (probe) { fclose(probe); k++; continue; }
            fprintf(stderr, LOG_W "%s: список канала не читается (%s) — его адреса в набор "
                            "не попадут\n", g->files[k], strerror(errno));
            for (size_t m = k + 1; m < g->files_n; m++) g->files[m - 1] = g->files[m];
            g->files_n--;
        }
        if (!g->files_n && !g->domains && !g->all) {
            /* Ни одного читаемого адресного списка, доменов нет. Канал остаётся пустым —
             * почему именно так, сказано у поля `emptied`. */
            g->emptied = 1;
            fprintf(stderr, LOG_W "канал «%s»: ни один из его списков не читается — правило "
                            "остаётся, но не совпадает ни с чем\n",
                    g->members_n ? g->members[0] : g->name);
        }
        /* Раньше здесь стоял пропуск доменных групп целиком. Теперь у группы могут быть и
         * адресные файлы: пропускать её значило бы не заметить пустой или сломанный список. */
        for (size_t k = 0; k < g->files_n; k++) {
            size_t total = 0, bad = 0, bad_line = 0;
            char sample[128];
            if (count_list(g->files[k], &total, &bad, sample, sizeof(sample), &bad_line, e) != 0)
                return -1;
            g->addrs += total - bad;
            if (!total) {
                fprintf(stderr, LOG_W "%s: список пуст — канал «%s» ничего не поймает\n",
                        g->files[k], g->members_n ? g->members[0] : g->name);
                continue;
            }
            /* РАНЬШЕ ЗДЕСЬ БЫЛ ОТКАЗ, и он был прав. Список без единого адреса,
             * подключённый адресным ключом, означал канал, который не поймает ничего:
             * компилятор брал из файла только адреса, а доменные строки не брал никто.
             * Отказ с указанием файла и первой строки был единственным способом это
             * назвать — nft на таком списке отвергает НАБОР ЦЕЛИКОМ с указанием на
             * середину строки в восемь тысяч символов.
             *
             * С гибридными списками это перестало быть ошибкой: доменные строки из этого
             * же файла теперь берёт резолвер (load_rules_into в dnsd.c), и список из одних
             * имён просто работает — как доменный. Тот самый список «Хостинги и CDN» у
             * издателя, из-за которого отказ и появился (лежит в адресных категориях,
             * внутри 250 имён и ни одного адреса), заработал сам собой.
             *
             * Строка всё равно печатается, и с уровнем: канал, у которого в наборе нет ни
             * одного адреса, — это законное, но НЕОЖИДАННОЕ состояние, и человек, который
             * выбирал «подсети», должен узнать, что получил маршрутизацию по именам. */
            if (bad == total) {
                char who[128];
                if (g->members_n > 1)
                    snprintf(who, sizeof(who), "%.60s (и ещё %zu в том же наборе)",
                             g->members[0], g->members_n - 1);
                else
                    snprintf(who, sizeof(who), "%.60s",
                             g->members_n ? g->members[0] : g->name);
                /* По именам канал работает, только когда у его группы есть доменный набор,
                 * то есть рядом стоит канал с доменными списками того же выхода, тех же
                 * клиентов и того же сужения (build_groups; резолвер повторяет это же
                 * решение в dch_join_domain_group). Без такого соседа имена из файла не
                 * берёт никто, и обещать «будет работать» значило бы соврать. */
                if (g->domains)
                    fprintf(stderr, LOG_W "%s: адресов нет вовсе, только имена (%zu) — канал "
                                    "«%s» будет работать по именам через резолвер. Первая "
                                    "строка: «%s»\n",
                            g->files[k], total, who, sample);
                else
                    fprintf(stderr, LOG_W "%s: адресов нет вовсе, только имена (%zu) — канал "
                                    "«%s» ничего не поймает: имена резолвер берёт у каналов с "
                                    "доменными списками, а у этого их нет. Подключите файл "
                                    "доменным списком (domains_files). Первая строка: «%s»\n",
                            g->files[k], total, who, sample);
                continue;
            }
            if (bad)
                fprintf(stderr, LOG_W "%s: строк не-адресов %zu из %zu, пропускаю их "
                                "(первая — %zu: «%s»)\n",
                        g->files[k], bad, total, bad_line, sample);
        }
    }
    return 0;
}

