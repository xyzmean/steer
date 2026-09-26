/* Платформа, на которой запущен движок: роутер OpenWrt или телефон Android.
 *
 * Решение владельца (docs/architecture.md, раздел 2, правило 2): «Платформа — модуль,
 * выбираемый при запуске. Отличия телефона от роутера лежат в platform/android.c и
 * platform/openwrt.c за одной таблицей struct platform_ops. Один бинарник сам определяет, где
 * он запущен, а --platform переопределяет выбор для стендов. #ifdef STEER_ANDROID в общем коде
 * нет.»
 *
 * ЧТО ЗДЕСЬ, А ЧТО У СЛОЁВ. Платформа — самый нижний слой после lib: её спрашивают разбор спеки
 * (zapret и каналы на само устройство), реестр (поле метки), компилятор, демон, резолвер и
 * протоколы. Поэтому таблица держит ДАННЫЕ и ПРИЗНАКИ — пути, раскладку меток, «есть ли fw4»,
 * «оживляет ли сторож интерфейсы через netifd», — а код, который по признаку работает
 * (цепочки output для каналов на телефон, masquerade правилом iptables, метка сети netd у
 * резолвера), живёт у своего слоя и спрашивает признак. Положи мы построители цепочек сюда,
 * платформа зависела бы от компилятора, а стенды модели, которые её линкуют, — от всего
 * движка.
 *
 * ПРИЗНАКИ НАЗВАНЫ ПО СВОЙСТВУ, а не по имени платформы: общий код спрашивает «есть ли fw4», а
 * не «не Android ли это». Третья платформа (настольный Linux без fw4) тогда — ещё одна
 * таблица, а не развилка на три ветки в каждом месте.
 *
 * ВЫБОР (platform.c, plat()): --platform или STEER_PLATFORM, затем умолчание сборки
 * (-DSTEER_DEFAULT_PLATFORM=android у цели build/steer-android и в Android.bp — они ведут себя
 * как прежде, где бы ни запустились), затем признаки среды (Android — /system/build.prop или
 * ANDROID_ROOT, OpenWrt — /etc/openwrt_release), и если ничего не узнано — openwrt. Код обеих
 * платформ есть в любом бинарнике. */
#ifndef STEER_PLATFORM_H
#define STEER_PLATFORM_H
#include <stddef.h>
#include <stdint.h>

struct platform_ops {
    const char *name;                 /* как пишется в --platform и STEER_PLATFORM */
    int (*detect)(void);              /* 1 — похоже, что запущены здесь; NULL — не узнаётся */

    /* ---- пути (почему корни одним местом — в шапке openwrt.c) -------------------------- */
    const char *etc_dir;              /* спека, списки, файлы выходов, сокет управления */
    const char *state_dir;            /* реестр, fake-ip, пробы; --state-dir переопределяет */
    const char *tmp_dir;              /* времянки набора правил и проб */
    const char *lists_dir;            /* куда put-file кладёт файлы приложения */
    const char *spec_path;            /* спека по умолчанию */
    const char *ctl_sock;             /* сокет управления (ctl-serve) */
    const char *rt_tables_d;          /* имена таблиц для iproute2; NULL — не ведутся */
    const char *tun_dev;              /* узел TUN */
    const char *tun_hint;             /* что сказать, когда узла нет */
    const char *const *ca_dirs;       /* системное хранилище корней, NULL-конец; NULL — нет */

    /* ---- раскладка метки (подробно — marks.h) ------------------------------------------- */
    uint32_t mark_base;               /* младший бит поля метки движка */
    unsigned mark_bits;               /* ширина поля */
    uint32_t mark_mask;               /* маска поля — PLAT_MARK_MASK(база, ширина) */
    unsigned rule_pref;               /* приоритет ip rule выходов; 0 — не передавать pref */
    unsigned probe_pref;              /* приоритет правила пробы сторожа */
    uint32_t reroute_bit;             /* бит перемаршрутизации в старой раскладке; 0 — нет */
    uint32_t self_mark;               /* метка собственного трафика движка; 0 — не метится */
    uint32_t tunnel_bit;              /* бит собственного трафика туннеля через via; 0 — нет */
    unsigned app_uid_min;             /* первый UID приложений (канал «self») */

    /* ---- что на платформе есть ---------------------------------------------------------- */
    unsigned local_channels : 1;      /* каналы на само устройство: from self / uid:N */
    unsigned zapret : 1;              /* kind zapret и on_fail zapret */
    unsigned fw4 : 1;                 /* firewall4: проверки зоны и masquerade после apply */
    unsigned netifd : 1;              /* сторож оживляет интерфейс ifdown/ifup и procd */
    unsigned iptables_masq : 1;       /* masquerade выходов — правилом nat iptables движка */
    unsigned lan_bridge : 1;          /* раздача через мост Linux (diag про br_netfilter) */
    unsigned warn_iptables_nat : 1;   /* старое ядро: предупреждать о живом nat iptables */
    const char *ctl_allow_domain;     /* SELinux-домен клиента сокета; NULL — проверки нет */
    /* Таблица «пакет → UID» (package_name из наборов sing-box, src/model/srsplan.c); NULL —
     * приложений на платформе нет, и правило набора про приложение не выражается. */
    const char *packages_list;

    /* ---- устройство для заголовков подписки (src/tools/hwid.c) --------------------------- */
    const char *os_release;           /* файл версии системы; NULL — только имя os_name */
    const char *os_name;              /* имя системы */
    const char *model_path;           /* где ядро или система называет модель */
    const char *model_fallback;       /* модель, если не названа */
};

/* Маска поля выводится из базы и ширины, а не пишется третьим числом: три записанных руками
 * числа разошлись бы при первом изменении любого из них (marks.h). Полем, а не выражением у
 * каждого читателя, — маску спрашивают в каждом правиле, и считать её заново незачем. */
#define PLAT_MARK_MASK(base, bits) ((((1u << (bits)) - 1u)) * (base))

extern const struct platform_ops plat_openwrt, plat_android;

/* Выбранная платформа. Выбор делается при первом вызове и дальше не меняется. */
const struct platform_ops *plat(void);
/* Платформа по имени или NULL. */
const struct platform_ops *plat_by_name(const char *name);
/* Выбрать явно (--platform): 0 — выбрана, -1 — нет такой. Имя уходит и в окружение
 * (STEER_PLATFORM), чтобы процессы, которые движок запускает сам (dnsd, помощники выходов),
 * работали на той же платформе. */
int plat_select(const char *name);
/* Имена всех платформ через запятую — для сообщений об ошибке. */
const char *plat_names(void);

/* Каталог состояния этого запуска: --state-dir, если задан, иначе путь платформы. */
const char *steer_state_dir(void);
void steer_set_state_dir(const char *dir);        /* NULL — вернуть путь платформы */
/* Каталог имён таблиц iproute2; NULL — платформа их не ведёт. Сеттер — шов стендов. */
const char *steer_rt_tables_dir(void);
void steer_set_rt_tables_dir(const char *dir);    /* NULL — вернуть путь платформы */
/* "<etc_dir>/<name>" в buf; возвращает buf. */
const char *plat_etc_path(char *buf, size_t n, const char *name);

#endif
