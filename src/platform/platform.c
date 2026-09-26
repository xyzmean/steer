/* Выбор платформы при запуске и пути, которые зависят от неё (см. platform.h).
 *
 * ПОРЯДОК ВЫБОРА. Явное (--platform, STEER_PLATFORM) — всегда первым: стенду нужно собрать
 * ruleset телефона на своей машине тем же бинарником. Затем умолчание сборки
 * (-DSTEER_DEFAULT_PLATFORM=android): прошивка и цель build/steer-android обязаны вести себя
 * как телефон, где бы их ни запустили, — стенды гоняют Android-сборку на обычном Linux и в
 * виртуальной машине, где признаков Android нет, а /etc/openwrt_release может и быть. Затем
 * признаки среды, и последним — роутер: с него движок начинался, и сборка без умолчания на
 * машине разработчика собирает ruleset роутера, как собирала всегда. */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "platform.h"

/* Прежний ключ сборки телефона. Код его больше не читает, и сборка с ним молча стала бы
 * бинарником без умолчания — на машине без признаков Android (стенды на обычном Linux) это
 * роутер. Громкий отказ дешевле. */
#ifdef STEER_ANDROID
#error "-DSTEER_ANDROID снят: платформа выбирается при запуске, умолчание — -DSTEER_DEFAULT_PLATFORM=android"
#endif

static const struct platform_ops *const PLATFORMS[] = { &plat_openwrt, &plat_android };
#define PLATFORMS_N (sizeof PLATFORMS / sizeof PLATFORMS[0])

#define PLAT_STR_(x) #x
#define PLAT_STR(x) PLAT_STR_(x)

static const struct platform_ops *g_plat;

const struct platform_ops *plat_by_name(const char *name) {
    for (size_t i = 0; name && i < PLATFORMS_N; i++)
        if (!strcmp(PLATFORMS[i]->name, name)) return PLATFORMS[i];
    return NULL;
}

const char *plat_names(void) {
    static char buf[64];
    if (!buf[0])
        for (size_t i = 0; i < PLATFORMS_N; i++)
            snprintf(buf + strlen(buf), sizeof buf - strlen(buf), "%s%s", i ? ", " : "",
                     PLATFORMS[i]->name);
    return buf;
}

static const struct platform_ops *plat_choose(void) {
    const char *e = getenv("STEER_PLATFORM");
    if (e && *e) {
        const struct platform_ops *p = plat_by_name(e);
        if (p) return p;
        fprintf(stderr, "steer[warn] STEER_PLATFORM=%s: такой платформы нет (есть %s), "
                        "выбираю по среде\n", e, plat_names());
    }
#ifdef STEER_DEFAULT_PLATFORM
    {
        const struct platform_ops *p = plat_by_name(PLAT_STR(STEER_DEFAULT_PLATFORM));
        if (p) return p;
    }
#endif
    /* Признаки: сначала Android — его признаки однозначны, а роутер и так умолчание. */
    for (size_t i = PLATFORMS_N; i-- > 0;)
        if (PLATFORMS[i]->detect && PLATFORMS[i]->detect()) return PLATFORMS[i];
    return &plat_openwrt;
}

const struct platform_ops *plat(void) {
    if (!g_plat) g_plat = plat_choose();
    return g_plat;
}

int plat_select(const char *name) {
    const struct platform_ops *p = plat_by_name(name);
    if (!p) return -1;
    g_plat = p;
    setenv("STEER_PLATFORM", p->name, 1);
    return 0;
}

/* ---- пути с переопределением ------------------------------------------------------------
 *
 * Каталог состояния и каталог имён таблиц — пути платформы, но у обоих есть шов: у первого
 * --state-dir (движок, dnsd, ctl-serve передают его своим детям), у второго — стенды, которым
 * нужно писать в свой каталог, а не в системный. Переопределение хранится отдельно от
 * таблицы: таблица платформы — константа, одна на процесс. */
static const char *g_state_override, *g_rt_override;

const char *steer_state_dir(void) {
    return g_state_override ? g_state_override : plat()->state_dir;
}

void steer_set_state_dir(const char *dir) { g_state_override = dir; }

const char *steer_rt_tables_dir(void) {
    return g_rt_override ? g_rt_override : plat()->rt_tables_d;
}

void steer_set_rt_tables_dir(const char *dir) { g_rt_override = dir; }

const char *plat_etc_path(char *buf, size_t n, const char *name) {
    snprintf(buf, n, "%s/%s", plat()->etc_dir, name);
    return buf;
}
