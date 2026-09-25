#include <stdio.h>
#include <sys/stat.h>
#include "paths.h"
#include "tmpfile.h"

/* ---- временные файлы и проба nftables ------------------------------------------------ */

void steer_tmp_template(char *dst, size_t n, const char *stem) {
    /* Ошибку mkdir не смотрим: каталог чаще всего уже есть (EEXIST), а если создать его
     * нельзя, об этом внятнее скажет сам mkstemp у вызывающего. */
    mkdir(STEER_TMP_DIR, 0700);
    snprintf(dst, n, "%s/%s.XXXXXX", STEER_TMP_DIR, stem);
}
