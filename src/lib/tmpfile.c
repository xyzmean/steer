#include <stdio.h>
#include <sys/stat.h>
#include "platform.h"
#include "tmpfile.h"

/* ---- временные файлы и проба nftables ------------------------------------------------ */

void steer_tmp_template(char *dst, size_t n, const char *stem) {
    /* Ошибку mkdir не смотрим: каталог чаще всего уже есть (EEXIST), а если создать его
     * нельзя, об этом внятнее скажет сам mkstemp у вызывающего. */
    mkdir(plat()->tmp_dir, 0700);
    snprintf(dst, n, "%s/%s.XXXXXX", plat()->tmp_dir, stem);
}
