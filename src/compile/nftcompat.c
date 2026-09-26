#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/wait.h>
#include "spec.h"
#include "tmpfile.h"
#include "nftcompat.h"

/* Примет ли ядро этот текст: `nft -c -f` над временным файлом. 1 — принял, 0 — отверг,
 * -1 — спросить не удалось (нет nft, нет прав, не создать файл).
 *
 * Свой fork, а не run_quiet из steer.c: пробу зовёт и резолвер, а стенд dnsmatch собирает
 * его вместе с этим файлом без steer.c. Вывод nft гасится — отказ здесь ожидаем и не ошибка. */
static int nft_check_text(const char *text) {
    char tmp[256];
    steer_tmp_template(tmp, sizeof(tmp), "steer-nprobe");
    int fd = mkstemp(tmp);
    if (fd < 0) return -1;
    size_t len = strlen(text);
    int ok = write(fd, text, len) == (ssize_t)len;
    close(fd);
    if (!ok) { unlink(tmp); return -1; }
    pid_t p = fork();
    if (p < 0) { unlink(tmp); return -1; }
    if (p == 0) {
        int devnull = open("/dev/null", O_WRONLY);
        if (devnull >= 0) { dup2(devnull, 1); dup2(devnull, 2); close(devnull); }
        execlp("nft", "nft", "-c", "-f", tmp, (char *)NULL);
        _exit(127);
    }
    int st = 0;
    waitpid(p, &st, 0);
    unlink(tmp);
    if (!WIFEXITED(st) || WEXITSTATUS(st) == 127) return -1;
    return WEXITSTATUS(st) == 0;
}

/* Пробная таблица с одной цепочкой nat в семействе fam. Своё имя (<таблица>_nprobe): `nft -c`
 * ничего не создаёт, но с чужой живой таблицей того же имени проверялось бы её содержимое.
 * Приоритет числом, а не словом dstnat: символьные имена приоритетов знает nft с 0.9.1, и на
 * совсем старой сборке проба отказала бы разбором, а не ядром, — ответ был бы про nft, а не
 * про то, что спрашивается. */
static int nft_nat_probe(const char *fam) {
    char text[256];
    snprintf(text, sizeof(text),
             "table %s %s_nprobe {\n"
             "    chain c {\n"
             "        type nat hook prerouting priority -100; policy accept;\n"
             "    }\n"
             "}\n", fam, nft_table());
    return nft_check_text(text);
}

/* Что из необязательного старое ядро всё-таки умеет. Спрашивается только в старой раскладке:
 * у современного ядра есть всё.
 *
 * notrack — ОТДЕЛЬНОЙ пробой, а не выводом из версии. В upstream выражение появилось в 4.10, и
 * в ядре телефона (LineageOS lineage-22.2, net/netfilter/nft_ct.c) его нет — файл совпадает с
 * v4.9 с точностью до стабильных исправлений. А Debian в своё 4.9 его перенёс: на стенде
 * tools/vm49 (4.9.320 из stretch) nft_ct.ko несёт alias nft-expr-notrack, и `notrack` грузится.
 * Номер версии здесь не ответ — ответ даёт только ядро. */
static int nft_legacy_extras(void) {
    int r = 0;
    if (nft_nat_probe("ip6") == 1) r |= NFTC_IP6NAT;
    char text[256];
    snprintf(text, sizeof(text),
             "table inet %s_nprobe {\n"
             "    chain c {\n"
             "        type filter hook output priority -300; policy accept;\n"
             "        meta mark 0x00000001 notrack\n"
             "    }\n"
             "}\n", nft_table());
    if (nft_check_text(text) == 1) r |= NFTC_NOTRACK;
    return r;
}

/* Раскладка набора правил — объяснение у объявления в spec.h. Здесь только порядок решения.
 *
 * СНАЧАЛА inet. Принял — ядро современное, и дальше спрашивать нечего: всё, чего нет в 4.9,
 * появилось раньше nat в inet (5.2). Не смогли спросить (нет nft — ответ -1; нет прав, как у
 * стенда под обычным пользователем, — отказ и на inet, и на ip) — тоже современная раскладка:
 * так движок работал всегда, и если ядро её не примет, отказ apply назовёт это сам, а не
 * гадание.
 *
 * Отверг — спрашиваем ip. Принял ip при отказе inet — это и есть старое ядро: nat есть, но не
 * в inet. Отверг и ip — у ядра нет nat вовсе (не собран, не загружен), и раскладка его не
 * вернёт: остаёмся на современной, чтобы отказ был тем же, что и до этой проверки.
 *
 * ip6 спрашивается ОТДЕЛЬНО и только в старой раскладке. На телефоне nat для IPv6
 * (NF_NAT_IPV6) в конфиге ядра LineageOS (mi845_defconfig) не включён, и таблица ip6 с цепочкой nat в том же
 * файле отвергла бы всю транзакцию — то есть вместе с заворотом DNS по IPv6 пропало бы всё. */
int nft_compat(void) {
    static int cached = -1;
    if (cached >= 0) return cached;
    const char *e = getenv("STEER_NFT_COMPAT");
    int r = 0;
    if (e && !strcmp(e, "modern")) {
        r = 0;
    } else if (e && !strcmp(e, "legacy-min")) {
        r = NFTC_LEGACY;
    } else if (e && !strcmp(e, "legacy")) {
        r = NFTC_LEGACY | nft_legacy_extras();
    } else {
        if (e && *e)
            fprintf(stderr, "steer[warn] STEER_NFT_COMPAT=%.32s не понят (modern, legacy, "
                            "legacy-min) — раскладка правил выбирается пробой ядра\n", e);
        if (nft_nat_probe("inet") == 0 && nft_nat_probe("ip") == 1)
            r = NFTC_LEGACY | nft_legacy_extras();
    }
    cached = r;
    return r;
}

/* Составной интервальный набор (ipv4_addr . inet_proto . inet_service, flags interval,timeout):
 * примет ли его ядро. Нужен только каналам, у списка которых сужение СМЕШАННОЕ (набор .srs, где
 * часть подсетей — «udp 50000-65535», часть — без сужения, см. src/model/srsplan.c): такой
 * список ложится в ядро одним набором и одним правилом. Интервалы в составном ключе (pipapo)
 * есть с Linux 5.6; на старой раскладке (4.9) их нет заведомо, а на 5.2-5.5 раскладка
 * современная, но набор не примется — поэтому для современной спрашивается ядро, пробной
 * таблицей через `nft -c`. Нет — канал делится на группы по сужению, как раньше делились
 * каналы с разными портами.
 *
 * Спрашивается лениво — только когда такой канал есть, — и один раз на процесс. STEER_NFT_CONCAT
 * (0 или 1) переопределяет ответ для стендов; STEER_NFT_COMPAT=modern без него значит «да»
 * (стенды генератора ядра не спрашивают вовсе), legacy и legacy-min — «нет». */
int nft_concat_ok(void) {
    static int cached = -1;
    if (cached >= 0) return cached;
    const char *o = getenv("STEER_NFT_CONCAT");
    if (o && (!strcmp(o, "0") || !strcmp(o, "1"))) return cached = o[0] == '1';
    if (nft_compat() & NFTC_LEGACY) return cached = 0;
    const char *e = getenv("STEER_NFT_COMPAT");
    if (e && !strcmp(e, "modern")) return cached = 1;
    char text[512];
    snprintf(text, sizeof(text),
             "table inet %s_nprobe {\n"
             "    set s {\n"
             "        type ipv4_addr . inet_proto . inet_service\n"
             "        flags interval,timeout\n"
             "        elements = { 192.0.2.0/24 . 0-255 . 0-65535 }\n"
             "    }\n"
             "}\n", nft_table());
    return cached = nft_check_text(text) == 1;
}
