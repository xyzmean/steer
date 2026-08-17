#!/bin/sh
# Собирает расширенный бинарник под одну архитектуру — в одной из двух РОЛЕЙ.
#
# Роли появились вместе со звездой xsteer, и не ради удобства. Хабу нужна криптография, то
# есть mbedtls, то есть расширенная сборка; а на роутере хабу делать нечего — подкоманды,
# поднимающей слушателя на публичном порту, там быть не должно. Отсюда две роли:
#
#   router (по умолчанию) — движок, клиент VLESS/Reality и клиент xsteer. Едет в пакет.
#   server                — движок, хаб xsteer. Едет в архив для VPS.
#
# Гейт стоит на СПИСКАХ ФАЙЛОВ, а не внутри их тел, и это важно: цель ext-syntax в Makefile
# гоняет -fsyntax-only по маске src/ext/*.c, и файл, целиком спрятанный под #ifdef, проходил
# бы проверку «пустым» — то есть ровно тот откат, ради которого ext-syntax и появилась.
# Поэтому цикл спицы живёт в xsclient.c, цикл хаба в xshub.c, а различаются только списки.
#
# Вынесено из build.sh отдельным файлом, а не оставлено строкой в `docker run -c`: там всё
# это жило внутри двойных кавычек с экранированием, и флаги -I терялись при подстановке —
# ошибка выглядела как «mbedtls/sha256.h не найден», то есть будто заголовков нет в образе.
# Скрипт в файле читается буквально, и подобный класс ошибок в нём невозможен.
#
# Пути к исходникам ниже АБСОЛЮТНЫЕ, и это не стиль: сборка делает cd в каталог mbedtls
# (см. WORK), после чего относительный путь не находится — ошибка выглядела как
# «FileNotFound: src/ext/tls13.c», то есть будто файла нет вовсе.
set -eu

TARGET="$1"
MCPU="${2:-}"
OUT="$3"
# Версия приходит четвёртым аргументом, а не читается из VERSION: скрипт работает внутри
# контейнера после cd в каталог mbedtls, и относительный путь к файлу оттуда не находится.
# Умолчание нужно ради ручного запуска с тремя аргументами.
VERSION="${4:-dev}"
# Роль: router (умолчание) или server. Пятым аргументом, чтобы прежние вызовы с четырьмя
# аргументами продолжали значить то же, что значили.
ROLE="${5:-router}"

MBED_INC=/opt/mbedtls/include
EXT_INC=/src/src/ext
# Имя файла НЕ mbedtls_config.h, и это не вкусовщина.
#
# build_info.h делает `#include MBEDTLS_CONFIG_FILE` кавычками, а кавычки ищутся сначала
# рядом с включающим файлом — то есть в /opt/mbedtls/include/mbedtls/, где лежит
# mbedtls_config.h самой библиотеки. Наш файл с тем же именем не выигрывал у него НИКОГДА:
# mbedtls собиралась с ПОЛНОЙ конфигурацией по умолчанию, со своим TLS-стеком, DTLS, RSA,
# X.509 и таблицами OID, а весь src/ext/mbedtls_config.h был мёртвым текстом.
#
# Обнаружилось по строкам «id-ce-certificatePolicies» в готовом бинарнике: их там быть не
# могло, X509 в нашей конфигурации выключен. Цена молчаливая — 240 КБ флеша на overlay в
# 6,9 МБ.
CFG='-DMBEDTLS_CONFIG_FILE="steer_mbedtls_config.h"'

WORK="/tmp/mb-$(echo "$TARGET$MCPU" | tr -c 'a-zA-Z0-9' '_')"
mkdir -p "$WORK"
cd "$WORK"

# Оптимизация: -O2, а не -Os, и только для этой половины сборки.
#
# Через AEAD проходит ВЕСЬ трафик туннеля, и потолок шифрования — это потолок скорости. -Os
# на крипто экономит десятки килобайт и стоит десятков процентов пропускной способности:
# обмен, который для базового движка выгоден (там размер решает, влезет ли пакет), а здесь
# ровно наоборот. Базовый пакет собирается с -Os по-прежнему, см. build.sh.
OPT=-O2

# mbedtls компилируется ЦЕЛИКОМ: линковщик возьмёт только используемое, а ручной отбор
# модулей превращается в игру «кто кого тянет» — проверено на rsa_alt_helpers, который
# исключался шаблоном *_alt* и ломал сборку неочевидным образом.
if [ ! -f .done ]; then
    for f in /opt/mbedtls/library/*.c; do
        m=$(basename "$f" .c)
        case "$m" in net_sockets|debug|timing) continue ;; esac
        # shellcheck disable=SC2086
        zig cc -target "$TARGET" ${MCPU:+-mcpu=$MCPU} $OPT -c \
            -I"$MBED_INC" -I"$EXT_INC" $CFG "$f" -o "$m.o" 2>/dev/null || true
    done
    touch .done
fi

# shellcheck disable=SC2086
# -s обязателен: zig cc при -Os убирает отладочную информацию сам, при -O2 — оставляет,
# и бинарник разом вырастает с 540 КБ до 4,9 МБ. На overlay в 6,9 МБ это разница между
# «пакет ставится» и «места нет», причём отладочная информация на роутере не нужна никому.
# Общее для обеих ролей: формат кадра, конфигурация, маршрутизация, рукопожатие, соединение
# и то, на чём они стоят (TLS-записи, примитивы Reality, TUN). Расходиться на проводе этим
# половинам негде — кода формата ровно один экземпляр, и это ровно та гарантия, которая
# заменила прежнюю «один бинарник на две стороны» (см. server/README.md).
XS_COMMON="/src/src/ext/xswire.c /src/src/ext/xsconf.c /src/src/ext/xsroute.c \
           /src/src/ext/chello.c /src/src/ext/xshake.c /src/src/ext/xsconn.c \
           /src/src/ext/tls13.c /src/src/ext/reality.c /src/src/ext/tun.c /src/src/ext/h2.c \\
           /src/src/ext/xsadmin.c"
EXT_ROUTER="/src/src/ext/sub.c /src/src/ext/vless_proto.c /src/src/ext/vision.c \
            /src/src/ext/client.c /src/src/ext/tunnel.c /src/src/ext/rtx.c \
            /src/src/ext/xsclient.c"
EXT_SERVER="/src/src/ext/xshub.c"

case "$ROLE" in
  router) EXT="$XS_COMMON $EXT_ROUTER"; ROLEDEF="-DSTEER_EXTENDED" ;;
  # У серверной сборки STEER_EXTENDED НЕ определён нарочно: на VPS нет ни спеки, ни выходов,
  # ни каналов, и клиентские подкоманды там обязаны отказывать штатной заглушкой, а не
  # ссылаться на код, которого в этой сборке нет.
  server) EXT="$XS_COMMON $EXT_SERVER"; ROLEDEF="-DSTEER_SERVER" ;;
  *) echo "неизвестная роль: $ROLE (router|server)" >&2; exit 2 ;;
esac

# shellcheck disable=SC2086
zig cc -target "$TARGET" ${MCPU:+-mcpu=$MCPU} -static $OPT -s \
    -I"$MBED_INC" -I"$EXT_INC" $CFG $ROLEDEF -DSTEER_VERSION="\"$VERSION\"" \
    -o "$OUT" \
    /src/src/steer.c /src/src/spec.c /src/src/dnsd.c /src/src/failover.c \
    /src/src/aggregate.c /src/src/obfs.c /src/src/cli.c \
    $EXT \
    "$WORK"/*.o
