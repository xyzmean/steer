#!/bin/sh
# Собирает расширенный бинарник (движок + клиент VLESS/Reality) под одну архитектуру.
#
# Вынесено из build.sh отдельным файлом, а не оставлено строкой в `docker run -c`: там всё
# это жило внутри двойных кавычек с экранированием, и флаги -I терялись при подстановке —
# ошибка выглядела как «mbedtls/sha256.h не найден», то есть будто заголовков нет в образе.
# Скрипт в файле читается буквально, и подобный класс ошибок в нём невозможен.
set -eu

TARGET="$1"
MCPU="${2:-}"
OUT="$3"

MBED_INC=/opt/mbedtls/include
EXT_INC=/src/src/ext
CFG='-DMBEDTLS_CONFIG_FILE="mbedtls_config.h"'

WORK="/tmp/mb-$(echo "$TARGET$MCPU" | tr -c 'a-zA-Z0-9' '_')"
mkdir -p "$WORK"
cd "$WORK"

# mbedtls компилируется ЦЕЛИКОМ: линковщик возьмёт только используемое, а ручной отбор
# модулей превращается в игру «кто кого тянет» — проверено на rsa_alt_helpers, который
# исключался шаблоном *_alt* и ломал сборку неочевидным образом.
if [ ! -f .done ]; then
    for f in /opt/mbedtls/library/*.c; do
        m=$(basename "$f" .c)
        case "$m" in net_sockets|debug|timing) continue ;; esac
        # shellcheck disable=SC2086
        zig cc -target "$TARGET" ${MCPU:+-mcpu=$MCPU} -Os -c \
            -I"$MBED_INC" -I"$EXT_INC" $CFG "$f" -o "$m.o" 2>/dev/null || true
    done
    touch .done
fi

# shellcheck disable=SC2086
zig cc -target "$TARGET" ${MCPU:+-mcpu=$MCPU} -static -Os \
    -I"$MBED_INC" -I"$EXT_INC" $CFG -DSTEER_EXTENDED \
    -o "$OUT" \
    /src/src/steer.c /src/src/spec.c /src/src/dnsd.c /src/src/failover.c \
    /src/src/aggregate.c \
    /src/src/ext/sub.c /src/src/ext/reality.c /src/src/ext/tls13.c \
    /src/src/ext/vless_proto.c /src/src/ext/vision.c /src/src/ext/client.c \
    /src/src/ext/tun.c /src/src/ext/tunnel.c /src/src/ext/h2.c \
    "$WORK"/*.o
