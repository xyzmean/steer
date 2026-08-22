#!/bin/sh
# Собрать замер AEAD под цель в трёх вариантах конфигурации mbedtls.
#
# Три, а не один, потому что вопрос стоит именно так: что даёт включение инструкций AES,
# что даёт большая таблица GHASH, и не оказывается ли ChaCha20 быстрее обоих. Ответ
# зависит от железа, и на Cortex-A53 он не тот же, что на x86.
set -eu
TARGET="${1:-aarch64-linux-musl}"
MCPU="${2:-cortex_a53}"
OUT="${3:-/src/build/bench}"

MBED_INC=/opt/mbedtls/include
EXT_INC=/src/src/ext

build() {  # СУФФИКС ДОП_ФЛАГИ
    suffix="$1"; extra="$2"
    work="/tmp/bench-$suffix"
    mkdir -p "$work"
    cd "$work"
    for f in /opt/mbedtls/library/*.c; do
        m=$(basename "$f" .c)
        case "$m" in net_sockets|debug|timing) continue ;; esac
        # shellcheck disable=SC2086
        zig cc -target "$TARGET" -mcpu="$MCPU" -O2 -c \
            -I"$MBED_INC" -I"$EXT_INC" \
            -DMBEDTLS_CONFIG_FILE='"steer_mbedtls_config.h"' $extra \
            "$f" -o "$m.o" 2>/dev/null || true
    done
    # shellcheck disable=SC2086
    zig cc -target "$TARGET" -mcpu="$MCPU" -static -O2 \
        -I"$MBED_INC" -I"$EXT_INC" \
        -DMBEDTLS_CONFIG_FILE='"steer_mbedtls_config.h"' $extra \
        -o "$OUT-$suffix" /src/tests/crypto-bench.c "$work"/*.o
}

# Ускорение теперь включается самой конфигурацией (см. steer_mbedtls_config.h), поэтому
# «без ускорения» задаётся его ОТКЛЮЧЕНИЕМ, а не включением: иначе первый вариант перестал
# бы быть базой сравнения и три числа означали бы одно и то же.
# Замерено на x86_64: большая таблица GHASH не даёт ничего (331,9 против 328,5 МБ/с) —
# при аппаратном AES библиотека считает GHASH инструкциями и таблицу не открывает. Вариант
# оставлен, чтобы это можно было перепроверить на другом железе, а не поверить на слово.
build plain "-DSTEER_NO_AES_ACCEL"
build aesce ""
build aesce-big "-DMBEDTLS_GCM_LARGE_TABLE"

# Разложение выбранного шифра на составляющие — отдельным бинарником и одним вариантом
# конфигурации: он отвечает не «какой шифр», а «что внутри дорого», и три сборки ему ни к
# чему. Нужен там, где потолок ставит ChaCha20: на MT7621 замерено 26,1 МБ/с у потока шифра
# против 60,6 у Poly1305, то есть ускорять имело бы смысл первое, а не второе.
work=/tmp/bench-split
mkdir -p "$work"
cd "$work"
for f in /opt/mbedtls/library/*.c; do
    m=$(basename "$f" .c)
    case "$m" in net_sockets|debug|timing) continue ;; esac
    zig cc -target "$TARGET" -mcpu="$MCPU" -O2 -c \
        -I"$MBED_INC" -I"$EXT_INC" \
        -DMBEDTLS_CONFIG_FILE='"steer_mbedtls_config.h"' \
        "$f" -o "$m.o" 2>/dev/null || true
done
zig cc -target "$TARGET" -mcpu="$MCPU" -static -O2 \
    -I"$MBED_INC" -I"$EXT_INC" \
    -DMBEDTLS_CONFIG_FILE='"steer_mbedtls_config.h"' \
    -o "$OUT-split" /src/tests/aead-split.c "$work"/*.o

ls -la "$OUT"-*
