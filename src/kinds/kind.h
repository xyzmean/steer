/* ВИД ВЫХОДА — МОДУЛЬ (docs/architecture.md, раздел 2, правило 1).
 *
 * Всё, что знает о виде, лежит в src/kinds/<вид>.c и отдаётся остальному движку одной таблицей
 * struct kind_ops. Общий код спрашивает вид — его свойства (caps) и его функции, — а не
 * сравнивает, какой он. Сравнение `kind == …` в общем коде означало бы, что новый вид требует
 * найти все такие места, а забытое место — это выход, который настроен и молча не работает
 * (ровно этот класс поломки описан у предикатов out_* в spec.h). Стенд tests/buildmatch.sh
 * ловит такие сравнения вне src/kinds.
 *
 * Любая функция таблицы может быть NULL — «виду здесь сказать нечего», — и общий код это
 * проверяет явно, а не зовёт пустышки.
 *
 * РЕЕСТР собирается из того, что вошло в сборку (kind.c): запись вида, файла которого в профиле
 * нет (build/sources.mk), отвечает одной строкой отказа — `absent`. Так «kind vless требует пакет
 * steer-extended» говорится из одного места, а не из #ifdef в разборе. */
#ifndef STEER_KIND_H
#define STEER_KIND_H
#include <stdio.h>
#include <stddef.h>

struct output;
struct spec;
struct err;
struct out_keys;
struct out_obfs;
struct vless_cfg;
struct xsteer_cfg;
struct tgws_cfg;
/* Дерево ruleset генератора. Объявлено ради поля emit ниже; определит его перевод src/compile на
 * промежуточное дерево (docs/architecture.md, «Слои и каталоги», compile/ir.c). */
struct nft_rs;

/* Свойства вида — то, о чём спрашивает общий код. Были предикатами со списком видов внутри
 * (out_has_device и соседи в spec.h); предикаты остались тонкими обёртками над этими битами,
 * а смысл каждого бита записан у своего предиката. */
enum kind_cap {
    KC_DEVICE       = 1 << 0,   /* своё устройство и таблица маршрутизации (out_has_device) */
    KC_MARK         = 1 << 1,   /* своя метка пакета (out_needs_mark) */
    KC_CTMARK       = 1 << 2,   /* метка соединения (out_needs_ctmark) */
    KC_ENGINE_OWNED = 1 << 3,   /* устройство заводит наш процесс, а не netifd (out_engine_managed) */
    KC_SELF_NAT     = 1 << 4,   /* masquerade не нужен (out_self_natting) */
    KC_OVER         = 1 << 5,   /* свой сокет наверх — `via` имеет смысл (out_via_capable) */
    KC_SKIP_ZAPRET  = 1 << 6,   /* общий обход DPI трафик не трогает (out_skips_zapret) */
    /* Здоровье устройства — рукопожатием TCP через него, а не ICMP: туннель завершает TCP у
     * себя, и пинг наружу через его устройство не проходит никогда (failover.c). */
    KC_TCP_PROBE    = 1 << 7,
    /* UDP идёт к узлу своим потоком на каждую пару адрес-порт, то есть у каждого DNS-запроса
     * своё рукопожатие (заметка «resolver» в diag.c). */
    KC_FLOW_UDP     = 1 << 8,
    /* Выход несёт IPv6: трафик v6 можно отдавать в него так же, как v4. Пока только разметка —
     * маршрутизации v6 в движке нет, и бит никем не читается; поведение появится в 1.9 вместе
     * со спекой v2 (docs/architecture.md, «IPv6 — в 1.9»). Поставлен тем видам, у которых v6
     * есть по устройству выхода: интерфейс и awg — устройства ядра с обоими семействами,
     * zapret трафик никуда не уводит, а только разбирает. VLESS — после проверки v6 в стеке
     * src/tunnel, xsteer и tgws — по их протоколам; direct маршрута не меняет вовсе. */
    KC_IPV6         = 1 << 9,
};

/* Ключи спеки, которые принадлежат виду. Разбирает их parse.c — для всех видов, в том числе не
 * вошедших в сборку: иначе базовая сборка перестала бы отвечать прежними отказами на ключ
 * расширенного вида у чужого выхода («stream есть только у kind=xsteer»). Бит говорит, чей ключ:
 * у выхода другого вида такой ключ — отказ. `conf` и `sub_file` сюда не входят: у чужого вида
 * они и прежде молча ничего не делали, и отказ на них сломал бы работавшие спеки. */
enum kind_key {
    KK_OBFS   = 1 << 0,
    KK_STREAM = 1 << 1,
    KK_OPTS   = 1 << 2,
    KK_DOMAIN = 1 << 3,
    KK_NODES  = 1 << 4,
};

/* Помощник выхода — процесс, который поднимает супервизор (supervise.c). cmd — подкоманда движка
 * («vless», «xsteer», «obfs», «tgws»), sig — подпись того, что помощник читает из спеки при
 * старте: супервизор кладёт в неё начальное значение FNV, вид подмешивает свои поля
 * (kind_sig_mix), общий код — цель `via`. */
struct kind_helper {
    char cmd[8];
    unsigned long long sig;
};

/* Куда вид отдаёт свои проверки diag: id, приговор (ok/note/warn/fail), что смотрели, что делать. */
typedef void kind_diag_fn(const char *id, const char *verdict, const char *what, const char *why);

struct kind_ops {
    const char *name;           /* как пишется в спеке */
    unsigned caps;              /* enum kind_cap */
    unsigned keys;              /* enum kind_key */
    /* Не NULL — вида в этой сборке нет, и разбор отвечает ровно этой строкой (после
     * «outputs.<имя>: »). У такой записи остальные поля пусты. */
    const char *absent;

    /* Свойства, которые зависят не только от вида, но и от настройки выхода (interface с obfs
     * умеет via). Складываются с caps. */
    unsigned (*caps_of)(const struct output *);

    /* ---- тексты, которые общий код печатает о виде ---- */
    /* Как назвать вид в отказе «via есть только у…», если выход этого вида via не умеет;
     * NULL — просто name. */
    const char *novia;
    /* Почему masquerade не нужен (у вида с KC_SELF_NAT) — причины у видов РАЗНЫЕ, см.
     * out_self_natting в spec.h. */
    const char *selfnat_why;
    /* Не NULL — выход работает только для клиентов раздачи, а для трафика самого устройства его
     * нет; строка — почему. */
    const char *lan_only;

    /* ---- спека ---- */
    /* Свои ключи и умолчания: k — что спека написала в ключах видов, выход уже с общими полями.
     * 0 — годится; -1 — отказ, текст в e. */
    int (*parse)(struct output *o, const struct out_keys *k, struct err *e);
    /* Проверка после разбора и общих проверок выхода (владельцы ключей) — то, что зависит от
     * общих полей (on_fail). sp — спека с выходами, разобранными до этого. */
    int (*check)(const struct spec *sp, const struct output *o, struct err *e);

    /* ---- правила ---- */
    /* Свои правила nft: дописывает в дерево (compile/ir.h) то, что нужно ОДНОМУ выходу этого
     * вида. Цепочки, общие для всех выходов вида (например, zapret_queue — своя очередь на
     * каждый выход, но цепочка одна), заводит первый вызов на пустом дереве — тот же приём,
     * что у build_group_sets и соседей. NULL — виду в дереве сказать нечего (direct, group и
     * виды с устройством: их правила пишет общий код по caps, а не per-kind emit).
     *
     * Порядок вызовов — kind_emit_all (kind.c): по ВИДАМ, в порядке реестра (kind_at), а
     * внутри вида — по выходам в порядке спеки. Так текст ruleset не зависит от того, в каком
     * порядке человек перечислил выходы разных видов: все правила одного вида ложатся в дерево
     * подряд, одним блоком, как было при отдельных построителях nft_emit_zapret/nft_emit_tgws
     * (docs/architecture.md, «Вид выхода»). Тот же приём и с тем же доводом уже применяется в
     * kind_ops.diag (daemon/diag.c). */
    void (*emit)(struct nft_rs *rs, const struct spec *sp, const struct output *o);

    /* ---- сторож (failover.c) ---- */
    /* Мера здоровья устройства, владелец которого — выход этого вида. NULL — общая проба
     * (ICMP или TCP по KC_TCP_PROBE). 1 — живо, 0 — нет. */
    int (*health)(const struct spec *sp, const struct output *o, const char *dev);
    /* Починка молчащего устройства. NULL — общий путь (ждать свой процесс, ifdown/ifup). */
    int (*revive)(const struct spec *sp, const struct output *o, const char *dev);
    /* Замер задержки. NULL — общий замер соединением TCP; мс или -1. */
    int (*latency)(const struct spec *sp, const struct output *o, const char *dev);

    /* ---- наблюдаемость ---- */
    /* Свои поля в объекте выхода `steer status`: фрагмент JSON, начинающийся с запятой. */
    void (*status)(FILE *out, const struct spec *sp, const struct output *o);
    /* Свои проверки `steer diag`. */
    void (*diag)(kind_diag_fn *put, const struct spec *sp, const struct output *o);

    /* ---- помощник ---- */
    /* 0 — выходу нужен помощник, h заполнен; -1 — не нужен. */
    int (*helper)(const struct spec *sp, const struct output *o, struct kind_helper *h);
};

/* ---- реестр (kind.c) ---- */
/* Запись вида по имени из спеки, в том числе вида вне сборки (у неё absent); NULL — такого вида
 * нет вовсе. */
const struct kind_ops *kind_by_name(const char *name);
/* Все виды по порядку реестра: direct, interface, vless, xsteer, zapret, tgws, awg. */
size_t kind_count(void);
const struct kind_ops *kind_at(size_t i);
/* Шаг FNV-1a подписи помощника (с границей поля: «ab»+«c» не равно «a»+«bc»). */
void kind_sig_mix(unsigned long long *h, const void *p, size_t n);
#define KIND_SIG_INIT 14695981039346656037ULL

/* Дописать в дерево rs правила всех видов, у которых есть emit: по видам в порядке реестра,
 * внутри вида — по выходам в порядке спеки (см. kind_ops.emit выше). Одна точка входа вместо
 * ручного прохода по видам в generate.c — новый вид с emit не требует правки компилятора. */
void kind_emit_all(struct nft_rs *rs, const struct spec *sp);

/* Записи видов. Определены в src/kinds/<вид>.c; реестр ссылается на них слабо (kind.c), поэтому
 * вид, файла которого нет в сборке, у реестра есть — записью отказа. */
extern const struct kind_ops kind_direct, kind_interface, kind_vless, kind_xsteer, kind_zapret,
                             kind_tgws, kind_awg;

/* Вид обнулённого выхода (kind == NULL; так их собирают стенды) — direct, как у нулевого
 * значения прежнего перечня видов. Читает его kind_of в spec.h. */
#define KIND_ZERO (&kind_direct)

/* ПРЕЖНИЕ ИМЕНА ВИДОВ — только для стендов (tests/specmatch.c, tests/failovermatch.c), которым
 * нужно собрать выход конкретного вида, не читая спеку: `g_spec.out[0].kind = OUT_XSTEER`.
 * Общий код вида не сравнивает — он спрашивает kind_of(o)->caps или конкретную функцию вида
 * (zapret_present, out_tgws и соседи ниже). Вне src/kinds и стендов эти имена ловит
 * tests/buildmatch.sh. */
#define OUT_DIRECT    (&kind_direct)
#define OUT_INTERFACE (&kind_interface)
#define OUT_VLESS     (&kind_vless)
#define OUT_XSTEER    (&kind_xsteer)
#define OUT_ZAPRET    (&kind_zapret)
#define OUT_TGWS      (&kind_tgws)
#define OUT_AWG       (&kind_awg)

/* ---- вопросы к отдельным видам ------------------------------------------------------------
 *
 * Помощнику вида (клиенту vless, xsteer, мосту tgws) нужна настройка своего выхода, и спросить
 * её он должен у вида: «это мой выход?» — NULL, если выход другого вида. */

/* interface: обфускация транспорта или NULL, если её нет (или выход не interface). */
const struct out_obfs *iface_obfs(const struct output *o);

/* vless */
const struct vless_cfg *out_vless(const struct output *o);
/* Развернуть выбор узлов выхода в порядок перебора при подписке из `usable` пригодных узлов.
 * Пишет в dst номера кандидатов по предпочтению и возвращает, сколько написал.
 *
 * Живёт рядом с разбором выхода, а не в клиенте vless: это ЗНАЧЕНИЕ поля `nodes`, а не деталь
 * подъёма туннеля, и проверить его стендом надо там, где стенд не требует ни mbedtls, ни
 * сети. Клиент и `vless-probe` зовут одну и ту же функцию — иначе диагностика показывала бы
 * перебор, отличный от настоящего.
 *
 * Номер вне подписки ПРОПУСКАЕТСЯ, а не роняет выход: подписка обновляется, узлов в ней
 * становится меньше, и устаревший номер не повод выключить локации, которые на месте.
 * Возврат 0 при непустом `nodes` означает, что не осталось ни одного, — вот это уже отказ,
 * потому что перебирать вместо выбранного что попало значит увести трафик в локацию,
 * которую человек не выбирал. */
size_t out_node_list(const struct output *o, size_t usable, int *dst, size_t max);
/* Назван ли узел ЧЕЛОВЕКОМ — то есть выбирать не из чего и перебор не нужен.
 *
 * Отдельным вопросом, а не длиной списка кандидатов, потому что это разные вещи. Кандидат
 * остаётся один и тогда, когда его никто не называл: в подписке единственный узел, или из
 * трёх выбранных в ней уцелел один. Клиент решал по длине — и на подписке из одного узла
 * переставал его проверять вовсе: туннель поднимался на молчащем узле, а вместо «ни один
 * узел подписки не отвечает» человек снова видел «устройства нет» (I-100, ради снятия
 * которого перебор и стал виден).
 *
 * Пропускать проверку можно ровно в одном случае — номер написан в спеке: там человек уже
 * решил, и сообщать ему «выбран единственный выбранный» нечего. */
int out_node_named(const struct output *o);

/* xsteer */
const struct xsteer_cfg *out_xsteer(const struct output *o);

/* zapret */
/* Жив ли обработчик очереди nfqueue с этим номером — то есть работает ли выход kind=zapret. */
int nfqws_on_queue(int queue);
/* Работает ли системный обход (любой nfqws) — нужен on_fail=zapret у выходов с устройством. */
int zapret_running(void);
/* `steer zapret-instances`: что поднимать init-скрипту. Код — как у команды. */
int zapret_instances(const struct spec *sp);
/* Есть ли в спеке хоть один выход kind=zapret — общему коду (apply.c) это нужно знать про
 * ядро: без notrack порождённые обработчиком пакеты остаются на учёте conntrack, а без
 * kmod-nft-queue правило очереди не встанет вовсе. Раньше жила в compile/groups.c как
 * has_zapret и сравнивала kind напрямую; здесь то же самое — вопрос вида, а не общего кода. */
int zapret_present(const struct spec *sp);

/* tgws */
const struct tgws_cfg *out_tgws(const struct output *o);
/* `steer tgws-instances`: что поднимать init-скрипту. Код — как у команды. */
int tgws_instances(const struct spec *sp);
/* Есть ли в спеке хоть один выход kind=tgws — нужно раскладке старого ядра (legacy.c): в ней
 * заводится своя таблица `ip`, только когда моста есть куда перехватывать. Тот же довод и та
 * же замена, что у zapret_present. */
int tgws_present(const struct spec *sp);

#endif
