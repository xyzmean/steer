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
            -DMBEDTLS_CONFIG_FILE='"mbedtls_config.h"' $extra \
            "$f" -o "$m.o" 2>/dev/null || true
    done
    # shellcheck disable=SC2086
    zig cc -target "$TARGET" -mcpu="$MCPU" -static -O2 \
        -I"$MBED_INC" -I"$EXT_INC" \
        -DMBEDTLS_CONFIG_FILE='"mbedtls_config.h"' $extra \
        -o "$OUT-$suffix" /src/tests/crypto-bench.c "$work"/*.o
}

build plain ""
build aesce "-DMBEDTLS_AESCE_C"
build aesce-big "-DMBEDTLS_AESCE_C -DMBEDTLS_GCM_LARGE_TABLE"
ls -la "$OUT"-*
