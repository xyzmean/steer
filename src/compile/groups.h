#ifndef STEER_GROUPS_H
#define STEER_GROUPS_H

/* Группы каналов: слияние правил, которые ведут в один и тот же выход и совпадают на всём,
 * что важно ядру (см. комментарий у struct group ниже, в src/compile/groups.c). Отдельный
 * заголовок — потому что поля struct group читают и generate.c (компиляция в текст правил),
 * и apply.c/status.c/diag.c/explain.c (объём, число списков, объяснение совпадения). */

#include <stddef.h>
#include "spec.h"
#include "srsplan.h"

/* ---- coalescing: one interface, at most two sets ---------------------------
 *
 * Channels are how a configuration is WRITTEN — a list, who it applies to, where it
 * goes. They are not how it has to be EXECUTED. Emitting one set and one rule per
 * channel means a box with a dozen enabled lists walks a dozen rules for every
 * packet and holds a dozen sets, when all of them lead to the same tunnel.
 *
 * So channels that agree on everything that matters to the kernel — the output, the
 * kind of list, the clients, and (for domains) the resolver mode — are merged into
 * one set and one rule. With one tunnel and every list enabled that is 2 sets and 2
 * rules instead of a dozen each: addresses and domains, because those two reach a
 * set by different routes and cannot share one.
 *
 * Expressiveness is not lost, only deduplicated: a channel that differs in `from` or
 * mode still gets its own group, so "only the TV, only this list" remains sayable.
 */
struct group {
    char name[64];              /* <output>_ip | <output>_dom, and the set name */
    const char *out;
    int domains;                /* addresses otherwise */
    /* Группа «весь трафик»: набора у неё нет, правило безусловное. Признак входит в ключ
     * слияния — см. build_groups, почему такую группу нельзя объединять со списочной. */
    int all;
    int realip;
    const char (*from)[64];
    size_t from_n;
    /* Сужение по протоколу и портам — УКАЗАТЕЛЬ на сужение первого канала группы, ровно как
     * `from` указывает на его список клиентов. Каналы группы по этому признаку совпадают
     * (он входит в ключ слияния), а спека разобранной живёт до конца процесса, так что
     * копировать 68 байт в каждую группу незачем. NULL быть не может: у канала без сужения
     * структура просто пустая, и l4match_empty отвечает про неё то же самое. */
    const struct l4match *l4;
    /* ТОЛЬКО адресные файлы: их элементы уходят в набор при компиляции. Доменные читает
     * резолвер сам, из спеки, поэтому здесь их держать незачем — а держали, и из-за этого
     * группа не могла быть смешанной. */
    /* Адресные списки группы. Вектор, а не массив на MAX_CHANNELS*MAX_FILES: с пределом в
     * шестьдесят четыре файла на правило такой массив стоил бы 32 КБ на группу и два
     * мегабайта на все — при том, что обычная группа держит один-два файла. */
    const char **files;
    size_t files_n, files_cap;
    /* Сколько доменных списков в группе. Нужно только чтобы сказать это человеку в status:
     * набор у них общий, а вот «сколько списков» он спрашивает про правило. */
    size_t dfiles_n;
    /* Все адресные списки группы оказались непрочитанными — набор и правило остаются, но
     * набор пуст.
     *
     * Почему не выбросить группу совсем: правило без `ip daddr @набор` это «весь трафик
     * этих клиентов в туннель», то есть пропавший список молча превратил бы узкий канал в
     * полный туннель. Почему не оставить как было (die на первом непрочитанном файле):
     * тогда не появляется НИ ОДНОГО правила, и напрямую идёт весь роутер, включая каналы,
     * чьи списки на месте (I-136). Пустой набор — единственный вариант, при котором
     * пропавший список уносит ровно свои адреса и ничего больше. */
    int emptied;
    /* Сколько АДРЕСНЫХ строк во всех файлах группы — считает check_address_lists. Ноль при
     * непустом files_n бывает законно (файл из одних имён, см. там же), и тогда набор
     * объявляется без строки elements: `elements = {  }` nft не принимает и отвергает весь
     * набор правил — то есть один такой список снимал бы маршрутизацию целиком. */
    size_t addrs;
    /* Which channels fed it — reported so a counter still has names behind it. */
    const char *members[MAX_CHANNELS];
    size_t members_n;

    /* ---- наборы sing-box (srs_files, раскладка — src/model/srsplan.c) ---------------------
     *
     * srs — клаузы наборов, попавшие в группу (указатели в раскладку, которую держит struct
     * groups): их подсети v4 компилятор кладёт в набор сам, потоком, имена берёт резолвер.
     * srs_addrs — сколько подсетей v4 из них (как addrs у списков). */
    const struct srs_psel **srs;
    size_t srs_n, srs_cap;
    size_t srs_addrs;
    /* Составной набор (ipv4_addr . inet_proto . inet_service): у списка канала смешанное
     * сужение, и у каждого элемента оно своё — правило одно, без x_l4. files_l4 — сужение, с
     * которым идут адреса каждого файла files (параллельно files). */
    int composite;
    const struct l4match **files_l4;
    /* Доп. группа канала — клаузы набора с условиями, которых у канала нет: номер в имени
     * (0 — обычная группа), второе «ip saddr» (source_ip_cidr), исключения-подсети — набор
     * «<имя>_x». */
    unsigned extra;
    const struct srs_pfx4 *xsrc;
    size_t xsrc_n;
    int xcidr;
};

/* Есть ли в группе подсети v4 из наборов sing-box (без подсчёта — по разметке клауз). */
static inline int group_srs_v4(const struct group *g) {
    for (size_t i = 0; i < g->srs_n; i++) if (g->srs[i]->has_v4) return 1;
    return 0;
}

/* Есть ли у группы набор адресов (правило с поиском в нём), а не «весь трафик». */
static inline int group_has_set(const struct group *g) {
    return g->files_n || g->srs_n || g->domains || g->emptied;
}


/* Группы одного разбора спеки — результат build_groups. До 1.7 они лежали в глобале
 * g_grp/g_grp_n, и любой, кто читал группы (генератор, status, diag, explain), читал то, что
 * оставил последний build_groups в процессе, — долг из раздела 5 docs/architecture.md. Теперь
 * это значение: точка входа держит свой экземпляр (static — он около 45 КБ) и передаёт его
 * параметром, как struct spec. Векторы files выделены в куче — groups_free их отдаёт;
 * build_groups сам отдаёт прежние, поэтому экземпляр до первого вызова обязан быть нулевым
 * (static или `= {0}`). */
struct groups {
    struct group g[MAX_CHANNELS];
    size_t n;
    /* Раскладки каналов с наборами sing-box: группы указывают в них (l4, srs), поэтому они
     * живут столько же, сколько группы, и отдаются groups_free. */
    struct srs_plan plans[MAX_CHANNELS];
    size_t plans_n;
};

/* build_groups/check_address_lists возвращают код ошибки, а не завершают процесс — правило 5,
 * docs/architecture.md, раздел 2. 0 — успех; -1 — отказ, текст в e->msg. Читают спеку sp — правило 6. */
int build_groups(const struct spec *sp, struct groups *gr, struct err *e);
void groups_free(struct groups *gr);
int has_domains(const struct groups *gr);
/* Есть ли в спеке выход zapret/tgws — вопросы к видам (kind.h: zapret_present, tgws_present),
 * не к группам; здесь не живут (общий код кроме src/kinds вид не сравнивает). */
int has_fakeip(const struct groups *gr);
int is_mac(const char *s);
int group_is_local(const struct group *g);
int check_address_lists(struct groups *gr, struct err *e);

int has_local(const struct groups *gr);
int has_local_domains(const struct groups *gr);
int has_via(const struct spec *sp);

#endif
