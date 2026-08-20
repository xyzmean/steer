#!/bin/sh
# Прогон стендов src/ext, которым нужен НАСТОЯЩИЙ mbedtls, а не заглушки из tests/stub:
#
#   tests/xsloop.c     — рукопожатие Noise IK целиком: сборка ClientHello, ответ хаба,
#                        подтверждение, отказ по аутентификации, затирание состояния.
#   tests/spokematch.c — освобождение транспортных ключей при неудачном рукопожатии;
#                        собирается под AddressSanitizer, потому что утекает именно
#                        контекст шифра в куче (I-067).
#   tests/hubmatch.c   — арифметика записи в хабе: правило набора кадров в пачку против
#                        объявленной строки воркера (I-070). Включает src/ext/xshub.c, отсюда
#                        и mbedtls: цикл хаба тянет за собой reality.c и TLS 1.3.
#
# В обычный `make test` они НЕ входят: там mbedtls нет по построению (R-014, см. ext-syntax),
# а роутерная сборка src/ext идёт только docker'ом через build.sh. Из-за этого первые два стенда
# до запуска 42 не прогонялись НИ РАЗУ — и первый же прогон дал I-066 (xsloop был красным с
# 18 августа) и I-067 (утечка 576 байт на попытку). Эта цель закрывает разрыв: проверяемость
# src/ext хоть где-то, кроме релизной сборки (R-058).
#
# Библиотека ищется в таком порядке, первое найденное выигрывает:
#   1) STEER_MBEDTLS — install-префикс (include/ + lib/) или дерево исходников (include/ +
#      library/libmbedcrypto.a);
#   2) pkg-config --exists mbedcrypto;
#   3) системные пути (/usr/include, /usr/local/include).
# Не нашлась — ГРОМКИЙ пропуск (echo + выход 0), а не падение и не молчание: молчаливый
# пропуск читается как «прошло», ровно как молчаливо пропущенный ui-harness в splify2.
#
# В РЕЛИЗЕ этот же файл зовётся ВНУТРИ образа сборщика, где mbedtls та самая, которой собирается
# расширенный пакет: обвязка — build/ext-test-image.sh, шаг — в .github/workflows/release.yml
# (R-063). Оттуда приходят STEER_MBEDTLS и CC="zig cc".
#
# ВЕРСИЯ. src/ext/reality.c писан под mbedtls 3.x и пользуется макросом MBEDTLS_PRIVATE:
# в 2.x его нет, поэтому нужна заглушка -D'MBEDTLS_PRIVATE(x)=x'; в 3.x доступ к приватным
# полям открывает -DMBEDTLS_ALLOW_PRIVATE_ACCESS. Флаг выбирается по мажорной версии. Прогон
# ПЕЧАТАЕТ версию, на которой шёл: зелёное на 2.28 НЕ равно зелёному в релизе — там docker
# собирает 3.x, и стенд, зелёный на 2.28 и красный на 3.x, был бы хуже отсутствующего
# (R-058, поле risks).
set -e

CC=${CC:-cc}
BUILD=${BUILD:-build}
mkdir -p "$BUILD"

MBED_INC=""
MBED_LIB=""
VH=""

# 1) STEER_MBEDTLS
if [ -n "$STEER_MBEDTLS" ] && [ -f "$STEER_MBEDTLS/include/mbedtls/version.h" ]; then
	MBED_INC="-I$STEER_MBEDTLS/include"
	VH="$STEER_MBEDTLS/include/mbedtls/version.h"
	if [ -f "$STEER_MBEDTLS/library/libmbedcrypto.a" ]; then
		MBED_LIB="$STEER_MBEDTLS/library/libmbedcrypto.a"
	else
		MBED_LIB="-L$STEER_MBEDTLS/lib -lmbedcrypto"
	fi
fi

# 2) pkg-config
if [ -z "$MBED_LIB" ] && command -v pkg-config >/dev/null 2>&1 && \
   pkg-config --exists mbedcrypto 2>/dev/null; then
	MBED_INC=$(pkg-config --cflags mbedcrypto)
	MBED_LIB=$(pkg-config --libs mbedcrypto)
fi

# 3) системные пути
if [ -z "$MBED_LIB" ]; then
	for d in /usr/include /usr/local/include; do
		if [ -f "$d/mbedtls/version.h" ]; then
			MBED_LIB="-lmbedcrypto"
			VH="$d/mbedtls/version.h"
			break
		fi
	done
fi

# Не нашли — громкий пропуск, не падение.
if [ -z "$MBED_LIB" ]; then
	echo "ext-test: mbedtls не найден — ПРОПУСК (это не падение)."
	echo "ext-test:   Debian/Ubuntu: apt-get install libmbedtls-dev"
	echo "ext-test:   либо STEER_MBEDTLS=/путь (install-префикс или дерево исходников)."
	echo "ext-test: под этими стендами лежат I-066 и I-067 — без прогона они не видны."
	exit 0
fi

# Версия из version.h (если pkg-config дал только флаги, ищем заголовок в системных путях).
if [ -z "$VH" ]; then
	for d in /usr/include /usr/local/include; do
		[ -f "$d/mbedtls/version.h" ] && VH="$d/mbedtls/version.h" && break
	done
fi
MBED_VER=""
[ -n "$VH" ] && MBED_VER=$(sed -n 's/.*MBEDTLS_VERSION_STRING  *"\([^"]*\)".*/\1/p' "$VH" | head -1)
MBED_MAJOR=$(printf '%s' "$MBED_VER" | cut -d. -f1)

if [ "$MBED_MAJOR" = "3" ]; then
	PRIV="-DMBEDTLS_ALLOW_PRIVATE_ACCESS"
else
	PRIV="-DMBEDTLS_PRIVATE(x)=x"
fi

echo "ext-test: mbedtls ${MBED_VER:-неизвестной версии}, флаг доступа: $PRIV"
echo "ext-test: ВНИМАНИЕ — релиз собирается docker'ом с mbedtls 3.x; зелёное здесь"
echo "ext-test:            не равно зелёному в релизе (R-058)."

# xsloop — рукопожатие целиком.
echo "ext-test: собираю и прогоняю xsloop..."
$CC -O2 -w -Isrc $MBED_INC "$PRIV" -o "$BUILD/xsloop" tests/xsloop.c \
	src/ext/xshake.c src/ext/chello.c src/ext/xswire.c src/ext/reality.c \
	src/ext/tls13.c src/ext/h2.c $MBED_LIB
"$BUILD/xsloop"

# spokematch — освобождение ключей при неудаче, под AddressSanitizer.
#
# Доступен ли санитайзер — проверяется ПРОБОЙ, а не догадкой по имени компилятора. В образе
# сборщика (zig cc, musl) рантайма ASan нет вовсе, а на musl нет и LeakSanitizer — то есть ровно
# того, на чём стоит этот стенд (I-067, утечка контекста шифра). Собрать там без санитайзера
# МОЛЧА значило бы получить зелёный стенд, который больше не проверяет то, ради чего написан,
# — поэтому пропуск громкий, как и пропуск по ненайденной библиотеке.
#
# Проба выделяет и ОСВОБОЖДАЕТ память: программа с утечкой была бы отвергнута самим ASan там,
# где он работает, и проба выключала бы его на ровном месте.
ASAN="-fsanitize=address"
probe="$BUILD/asan-probe"
mkdir -p "$BUILD"
printf '#include <stdlib.h>\nint main(void){char*p=malloc(16);p[0]=1;free(p);return 0;}\n' \
	> "$probe.c"
if $CC -O0 $ASAN -o "$probe" "$probe.c" >/dev/null 2>&1 && "$probe" >/dev/null 2>&1; then
	:
else
	echo "ext-test: ВНИМАНИЕ — AddressSanitizer здесь не работает (нет рантайма либо нет"
	echo "ext-test:            LeakSanitizer, как на musl). spokematch собирается БЕЗ него:"
	echo "ext-test:            проверки в нём прогонятся, утечка (I-067) — НЕТ."
	ASAN=""
fi
rm -f "$probe" "$probe.c"

echo "ext-test: собираю и прогоняю spokematch (ASan: ${ASAN:-нет})..."
$CC -O1 -g -w -Isrc $ASAN $MBED_INC "$PRIV" -o "$BUILD/spokematch" \
	tests/spokematch.c \
	src/ext/xsconn.c src/ext/xswire.c src/ext/xsepoch.c src/ext/xsroute.c \
	src/ext/xsconf.c src/ext/xsstream.c src/ext/xshake.c src/ext/chello.c \
	src/ext/reality.c src/ext/tls13.c src/ext/h2.c src/ext/tun.c src/obfs.c \
	src/spec.c $MBED_LIB -lpthread
"$BUILD/spokematch"

# hubmatch — согласие правила набора пачки с размером строки воркера.
echo "ext-test: собираю и прогоняю hubmatch..."
$CC -O2 -w -Isrc $MBED_INC "$PRIV" -o "$BUILD/hubmatch" tests/hubmatch.c \
	src/ext/xsconn.c src/ext/xswire.c src/ext/xsepoch.c src/ext/xsroute.c \
	src/ext/xsconf.c src/ext/xsstream.c src/ext/xshake.c src/ext/chello.c \
	src/ext/reality.c src/ext/tls13.c src/ext/h2.c src/ext/tun.c src/obfs.c \
	src/spec.c $MBED_LIB -lpthread
"$BUILD/hubmatch"

echo "ext-test: все стенды прошли на mbedtls ${MBED_VER:-?}"
