/* Канал с наборами sing-box (`srs_files`): на какие группы он ложится (см. srsplan.c).
 *
 * Раскладку спрашивают двое, и ответ у них обязан совпадать: компилятор (build_groups — какие
 * наборы и правила) и резолвер (dch_build — в какой набор класть адрес имени и с каким
 * сужением). Поэтому решение — одна функция здесь, а не два повтора в двух слоях. */
#ifndef STEER_SRSPLAN_H
#define STEER_SRSPLAN_H

#include <stddef.h>
#include <stdint.h>
#include "spec.h"
#include "srs.h"

enum { SP_PLAIN = 0, SP_COMPOSITE = 1, SP_EXTRA = 2 };

/* Предел элементов составного набора: больше — канал делится по сужению (почему — srsplan.c). */
#define SRS_MIXED_MAX 16384

/* Клаузы одного файла, попавшие в часть. */
struct srs_psel {
    const char *path;
    const struct srs_set *set;
    uint8_t *sel;               /* бит на клаузу */
    struct l4match *eff;        /* сужение каждой клаузы с учётом сужения канала (по номеру) */
    size_t ncl;
    int has_dom, has_v4;
};

struct srs_part {
    int kind;                   /* SP_* */
    struct l4match l4;          /* PLAIN, EXTRA: сужение группы; COMPOSITE — у каждого элемента своё */
    int own;                    /* собственные списки канала (prefixes/domains_files) — здесь */
    int has_dom;                /* есть имена: клаузы имён или свои domains_files */
    int has_v4;                 /* есть подсети v4 из наборов */
    size_t n_v4;                /* сколько их (для проверки размера набора) */
    /* EXTRA: условия, которых нет у канала, — отдельной группой со своим правилом. */
    unsigned id;                /* номер в имени группы: номер канала * 100 + k */
    int all;                    /* назначения нет: весь трафик приложения */
    int xcidr;                  /* исключения-подсети: набор <группа>_x и «ip daddr != @…» */
    const struct srs_pfx4 *src;
    size_t src_n;
    char (*uid)[64];            /* приложения как «uid:N» — тем же видом, что from канала */
    size_t uid_n;
    struct srs_psel *sel;
    size_t sel_n;
};

struct srs_plan {
    struct srs_part *p;
    size_t n;
    const struct srs_set *held[MAX_FILES];   /* открытые разборы — отпускаются srs_plan_free */
    size_t held_n;
    char warn[1024];            /* что снято при раскладке — печатает apply (check_address_lists) */
};

/* Разложить канал c. concat — примет ли ядро составной набор: 1, 0 (смешанное сужение делится
 * по группам) или -1 — спросить, когда понадобится (srs_concat_override, иначе nft_concat_ok).
 * 0 — готово; -1 — отказ спеке (err): сужение канала и набора не пересекаются. Непрочитанный файл отказом не считается — он снимается с предупреждением, как
 * непрочитанный адресный список. */
int srs_plan_channel(const struct spec *sp, const struct channel *c, int concat,
                     struct srs_plan *out, struct err *e);
void srs_plan_free(struct srs_plan *pl);
/* Ответ «примет ли ядро составной набор» для всего процесса: -1 — спрашивать ядро (умолчание),
 * 0 или 1 — задан (стенды, раскладка, выбранная вызывающим). */
extern int srs_concat_override;

/* Сужения клауз канала (с учётом сужения канала) в порядке файлов и клауз — для нумерации
 * сужений в именах наборов (group_set_name): cb зовётся на каждое непустое. */
void srs_chan_l4_each(const struct channel *c, void (*cb)(void *ctx, const struct l4match *m),
                      void *ctx);

#endif
