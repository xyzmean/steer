#!/bin/sh
# Расширенная половина движка, собранная ТУЛЧЕЙНОМ OpenWrt SDK, а не zig.
#
# ЗАЧЕМ ВТОРОЙ СПОСОБ СБОРКИ. Замер на живом роутере (mt7621, mipsel_24kc, tests/xsbench.c,
# нагрузка 1439 байт, одна и та же mbedtls 3.6.2, оба прогона по два раза):
#
#     zig 0.13.0, -O2            полный путь пакета 83 878 нс   AEAD 81 118 нс
#     SDK gcc 14.3.0, -O2        полный путь пакета 66 766 нс   AEAD 63 763 нс   (−20%)
#     SDK gcc 14.3.0, -Os        полный путь пакета 176 061 нс  AEAD 166 673 нс
#
# То есть GCC выпускает для ChaCha20-Poly1305 на MIPS32 код на пятую часть быстрее, чем LLVM, и
# ни -O3, ни -funroll-loops у zig этого не закрывают (проверено: 83 900 и 84 110 нс). На живом
# туннеле того же роутера, три прогона вперемежку: хаб → клиент 58,4 / 58,6 / 56,2 Мбит/с у SDK
# против 52,0 / 54,0 / 53,5 у zig — то есть около +8% устойчиво; на отдаче разброс стенда
# (36,3..48,7 у zig) перекрывает разницу, и про неё сказать нечего.
#
# Последняя строка таблицы — про умолчание OpenWrt: -Os стоит здесь ВДВОЕ дороже -O2 на шифре и в
# ТРИНАДЦАТЬ раз на контрольной сумме (36 890 нс против 2 826). Пакет, собранный обычным путём
# OpenWrt, был бы вдвое медленнее того, что мы выкладываем.
#
# ПО ВЕСУ РАЗМЕНА ТОЖЕ НЕТ, и это стоит сказать отдельно: расширенная половина выходит 574 552 байта
# против 687 980 у zig (−16,5%), хаб — 461 264 против 546 236 (−15,6%), пакет .apk — 288 050 против
# 314 863 (−8,5%). Сто тринадцать килобайт на overlay в 6,9 МБ не косметика.
#
# Здесь же ответ, почему LTO указан явно: zig включает его САМ (с -flto и без него размер один и тот
# же, 687 980), а gcc — нет, и без ключа сборка выходит на 15 КБ толще.
#
# ЧЕМ ПЛАТИМ ЗА SDK. Один zig на 45 МБ покрывает все ISA; SDK — это по 230 МБ на каждую цель.
# Поэтому этот скрипт не заменяет build-ext.sh, а стоит рядом: им собирается то, где выигрыш
# измерен (MIPS), а остальное по-прежнему zig. Решение о том, что выкладывать, остаётся за
# человеком — здесь только воспроизводимый рецепт.
#
#     sh build/build-ext-sdk.sh <каталог SDK> <mbedtls-3.6.2> <router|server> <выход> [версия] [ревизия]
set -eu

SDK="${1:?нужен каталог распакованного OpenWrt SDK}"
MBED="${2:?нужен каталог исходников mbedtls}"
ROLE="${3:?нужна роль: router или server}"
OUT="${4:?нужен путь выходного файла}"
VERSION="${5:-0.0.0}"
REV="${6:-неизвестна}"

SRC=$(cd "$(dirname "$0")/.." && pwd)
TC=$(echo "$SDK"/staging_dir/toolchain-*)
[ -d "$TC/bin" ] || { echo "в $SDK нет staging_dir/toolchain-*/bin"; exit 2; }
# STAGING_DIR обязателен: без него gcc из SDK предупреждает на каждом файле и ищет заголовки не там.
export STAGING_DIR="$SDK/staging_dir"
export PATH="$TC/bin:$PATH"
CC=$(ls "$TC"/bin/*-openwrt-linux-gcc | head -1)
[ -x "$CC" ] || { echo "не нашёл gcc в $TC/bin"; exit 2; }

# -O2, а не -Os: см. таблицу в шапке. Флаги процессора берутся те же, что у OpenWrt для этой цели
# (include/target.mk: CPU_CFLAGS_24kc).
OPT="-O2 -mips32r2 -mtune=24kc -flto"
CFG='-DMBEDTLS_CONFIG_FILE="steer_mbedtls_config.h"'
WORK="/tmp/mb-sdk-$(basename "$TC")"
mkdir -p "$WORK"

# mbedtls компилируется ЦЕЛИКОМ: линковщик возьмёт только используемое. Причина та же, что в
# build-ext.sh — ручной отбор модулей превращается в игру «кто кого тянет».
if [ ! -f "$WORK/.done" ]; then
    echo "собираю mbedtls тулчейном SDK ($OPT)"
    for f in "$MBED"/library/*.c; do
        m=$(basename "$f" .c)
        case "$m" in net_sockets|debug|timing) continue ;; esac
        # shellcheck disable=SC2086
        "$CC" $OPT -w -c -I"$MBED/include" -I"$SRC/src/ext" $CFG "$f" -o "$WORK/$m.o" 2>/dev/null || true
    done
    touch "$WORK/.done"
fi

XS_COMMON="$SRC/src/ext/xswire.c $SRC/src/ext/xsconf.c $SRC/src/ext/xsroute.c \
           $SRC/src/ext/chello.c $SRC/src/ext/xshake.c $SRC/src/ext/xsconn.c \
           $SRC/src/ext/xsstream.c $SRC/src/ext/xsepoch.c \
           $SRC/src/ext/tls13.c $SRC/src/ext/reality.c $SRC/src/ext/tun.c $SRC/src/ext/h2.c \
           $SRC/src/ext/xsadmin.c"
EXT_ROUTER="$SRC/src/ext/sub.c $SRC/src/ext/vless_proto.c $SRC/src/ext/vision.c \
            $SRC/src/ext/client.c $SRC/src/ext/tunnel.c $SRC/src/ext/rtx.c \
            $SRC/src/ext/xsclient.c $SRC/src/ext/subfetch.c"

case "$ROLE" in
  router) EXT="$XS_COMMON $EXT_ROUTER"; ROLEDEF="-DSTEER_EXTENDED" ;;
  server) EXT="$XS_COMMON $SRC/src/ext/xshub.c"; ROLEDEF="-DSTEER_SERVER" ;;
  *) echo "неизвестная роль: $ROLE (router|server)" >&2; exit 2 ;;
esac

# -latomic обязателен, и это находка того же замера. На 32-битной цели атомарная операция над
# 64-битным словом не выражается одной командой, и gcc зовёт libatomic; zig подставлял эти вызовы
# сам, поэтому раньше отсутствие ключа никого не смущало. Заодно из-за этого метки времени, которые
# читает чужой поток, стали тридцатидвухбитными (см. xsh_ms в xshub.c): 64-битная атомарная запись
# на КАЖДЫЙ подтверждённый кадр — это захват глобального замка на пакет.
# shellcheck disable=SC2086
"$CC" $OPT -w -static -s \
    -I"$MBED/include" -I"$SRC/src/ext" $CFG $ROLEDEF \
    -DSTEER_VERSION="\"$VERSION\"" -DSTEER_REV="\"$REV\"" \
    -o "$OUT" \
    "$SRC"/src/steer.c "$SRC"/src/spec.c "$SRC"/src/dnsd.c "$SRC"/src/failover.c \
    "$SRC"/src/aggregate.c "$SRC"/src/obfs.c "$SRC"/src/cli.c \
    $EXT "$WORK"/*.o -lpthread -latomic

printf '%s: %s байт\n' "$OUT" "$(stat -c %s "$OUT")"
