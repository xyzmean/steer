#!/bin/sh
# Расширенная половина движка, связанная с libmbedcrypto САМОГО УСТРОЙСТВА.
#
# ЗАЧЕМ. На стоковом образе OpenWrt mbedtls уже лежит: её тянет libustream-mbedtls, а с ним
# uclient-fetch, wpad и LuCI по https. Своя копия внутри бинарника — это второй экземпляр того же
# кода в overlay, который у mt7621 равен 6,9 МБ. Замер на роутере (mipsel_24kc, 25.12.5,
# libmbedtls21-3.6.6):
#
#     расширенная половина, статика, своя mbedtls      574 552 байта
#     расширенная половина, библиотека роутера         319 940 байт   (−44,3%)
#     хаб,                  статика, своя mbedtls      461 248 байт
#     хаб,                  библиотека роутера         213 828 байт   (−53,6%)
#
# ЦЕНА ПО СКОРОСТИ В ПРЕДЕЛАХ ПРОЦЕНТА, и это было неочевидно: OpenWrt собирает свои пакеты с -Os,
# а -Os на этом шифре стоит вдвое (166 673 нс против 63 763 у -O2). Но пакет mbedtls исключение —
# его Makefile ВЫБРАСЫВАЕТ -O% из TARGET_CFLAGS (строка `TARGET_CFLAGS := $(filter-out -O%,...)`) и
# отдаёт выбор CMake, а тот в сборке Release ставит -O2 (include/cmake.mk отдаёт
# -DCMAKE_BUILD_TYPE=Release, а CMakeLists.txt самой mbedtls — CMAKE_C_FLAGS_RELEASE "-O2").
# Поэтому библиотека роутера идёт вровень с нашей.
#
# Замер на роутере, tests/xsbench.c, «только AEAD», три прогона ПО ОДНОМУ (это важно, см. ниже),
# среднее в наносекундах на пакет 1439 байт:
#
#     своя mbedtls, статика                        ChaCha 63 726   AES 646 358
#     своя mbedtls, .so                            ChaCha 64 469   AES 648 945
#     своя mbedtls, .so + THREADING_C              ChaCha 64 350   AES 648 772
#     библиотека роутера                           ChaCha 64 355   AES 648 322
#
# То есть ни разделяемое связывание само по себе, ни -fPIC (645 354 против 648 523 на AES —
# статически слинкованные объекты с -fPIC и без), ни включённая в OpenWrt поддержка потоков ничего
# не стоят. Разница между своей копией и чужой — около 1% на ChaCha и 0,3% на AES, то есть на уровне
# шума стенда.
#
# ПРО «ПО ОДНОМУ» — это не педантизм, а цена уже совершённой ошибки. Первые замеры показали у
# библиотеки роутера AES 748 517 и 816 660 нс (то есть −16..26%), и под это уже была придумана
# правдоподобная механика — PIC, таблицы AES, GOT. Оказалось, что на роутере в это время шёл второй
# замер: два процесса на двух ядрах, и числа доходили до 1 330 248 нс, чего быть не может вовсе.
# Правило простое: на этом роутере одновременно идёт РОВНО ОДИН замер, иначе меряется раскладка по
# ядрам, а не сборка.
#
# ЧЕМ ПЛАТИМ. Бинарник перестаёт быть одним файлом на несколько выпусков OpenWrt: он привязан и к
# рантайму (musl), и к ABI библиотеки (SONAME libmbedcrypto.so.16 — это пакет libmbedtls21; в
# 23.05 там mbedtls 2.28 с другим SONAME, и такой бинарник просто не запустится). Имя пакета,
# который эту библиотеку приносит, тоже привязано к ABI: на 25.12.5 это libmbedtls21, и именно его
# должен требовать .apk. Поэтому нативная сборка — это способ собрать ПАКЕТ под конкретный выпуск,
# где зависимость объявлена и apk её проверяет, а не способ выложить файл «положи и запусти». Файл
# по-прежнему собирается статикой (build-ext-sdk.sh), и это осознанное разделение, а не недоделка.
#
# И ГЛАВНАЯ ОГОВОРКА. Раскладка публичных структур mbedtls зависит от макросов конфигурации, а
# конфигурацию здесь выбирает OpenWrt. Расхождение не ловится линковщиком — оно портит память в
# работе. Поэтому нативная сборка выкладывается только на тот выпуск, где на самом устройстве
# ответил «всё сошлось» стенд tests/nativembed.c. Он же объясняет, почему сверить версии нельзя:
# MBEDTLS_VERSION_C в сборке OpenWrt выключен.
#
#     sh build/build-ext-native.sh <каталог SDK> <mbedtls тех же ВЕРСИЙ, что на устройстве> \
#                                  <router|server> <выход> [версия] [ревизия] [soname]
set -eu

SDK="${1:?нужен каталог распакованного OpenWrt SDK}"
MBED="${2:?нужен каталог исходников mbedtls той же версии, что на устройстве}"
ROLE="${3:?нужна роль: router или server}"
OUT="${4:?нужен путь выходного файла}"
VERSION="${5:-0.0.0}"
REV="${6:-неизвестна}"
SONAME="${7:-libmbedcrypto.so.16}"

SRC=$(cd "$(dirname "$0")/.." && pwd)
TC=$(echo "$SDK"/staging_dir/toolchain-*)
[ -d "$TC/bin" ] || { echo "в $SDK нет staging_dir/toolchain-*/bin"; exit 2; }
export STAGING_DIR="$SDK/staging_dir"
export PATH="$TC/bin:$PATH"
CC=$(ls "$TC"/bin/*-openwrt-linux-gcc | head -1)
[ -x "$CC" ] || { echo "не нашёл gcc в $TC/bin"; exit 2; }

OPT="-O2 -mips32r2 -mtune=24kc -flto"
WORK="/tmp/mb-native-$(basename "$TC")"
mkdir -p "$WORK"

# КОНФИГУРАЦИЯ ЗДЕСЬ СТОКОВАЯ, без steer_mbedtls_config.h: заголовки обязаны описывать ту
# библиотеку, с которой пойдёт работа, а её собрали со стоковой. Своя урезанная конфигурация дала бы
# другую раскладку структур — то самое расхождение, ради которого существует tests/nativembed.c.
#
# ЛИНКОВАТЬСЯ ПРЯМО С ФАЙЛОМ РОУТЕРА НЕЛЬЗЯ: у выложенной OpenWrt библиотеки срезаны заголовки
# секций (`readelf -S` показывает ноль), а без них ld не видит .dynsym как секцию и отказывается
# принимать файл как разделяемую библиотеку. Поэтому из тех же исходников собирается ТЕНЕВАЯ .so с
# тем же SONAME: она нужна только на связывание, на устройство не попадает, и в NEEDED окажется
# именно то имя, которое там лежит.
if [ ! -f "$WORK/.so-done" ]; then
    # БЕЗ -flto и с -fPIC: с объектами LTO линковщик пересобирает код на этапе -shared и падает на
    # R_MIPS_26 («recompile with -fPIC»), а OpenWrt свою mbedtls всё равно собирает с no-lto — так
    # теневая копия ещё и ближе к настоящей.
    SOOPT="-O2 -mips32r2 -mtune=24kc -fPIC"
    echo "собираю теневую $SONAME для связывания ($SOOPT)"
    for f in "$MBED"/library/*.c; do
        m=$(basename "$f" .c)
        case "$m" in net_sockets|debug|timing|ssl_*|x509*|pkcs7) continue ;; esac
        # shellcheck disable=SC2086
        "$CC" $SOOPT -w -c -I"$MBED/include" "$f" -o "$WORK/$m.o" 2>/dev/null || true
    done
    # shellcheck disable=SC2086
    "$CC" $SOOPT -shared -Wl,-soname,"$SONAME" -o "$WORK/$SONAME" "$WORK"/*.o -lpthread
    ln -sf "$SONAME" "$WORK/libmbedcrypto.so"
    touch "$WORK/.so-done"
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

# shellcheck disable=SC2086
"$CC" $OPT -w -s \
    -I"$MBED/include" -I"$SRC/src/ext" $ROLEDEF \
    -DSTEER_VERSION="\"$VERSION\"" -DSTEER_REV="\"$REV\"" \
    -o "$OUT" \
    "$SRC"/src/steer.c "$SRC"/src/spec.c "$SRC"/src/dnsd.c "$SRC"/src/failover.c \
    "$SRC"/src/aggregate.c "$SRC"/src/obfs.c "$SRC"/src/cli.c \
    $EXT -L"$WORK" -lmbedcrypto -lpthread

printf '%s: %s байт\n' "$OUT" "$(stat -c %s "$OUT")"
printf 'зависимости: '
"$TC"/bin/*-readelf -d "$OUT" 2>/dev/null | sed -n 's/.*NEEDED.*\[\(.*\)\]/\1/p' | tr '\n' ' '
echo
echo "ПЕРЕД ВЫКЛАДКОЙ: собрать и прогнать на устройстве tests/nativembed.c (см. его шапку)."
