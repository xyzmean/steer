#!/bin/sh
# Прогон стендов src/ext ВНУТРИ образа сборщика — там, где mbedtls та самая.
#
# Зачем отдельный скрипт. Стенды xsloop, spokematch и hubmatch требуют НАСТОЯЩЕЙ mbedtls
# (tests/ext-test.sh, там же объяснено почему), и до сих пор прогонялись только руками, на
# той версии, что стоит у человека, — 2.28. Расширенный пакет при этом собирается docker'ом
# с 3.6.2 из build/Dockerfile: зелёное на 2.28 не равно зелёному в релизе, и стенд, зелёный
# на 2.28 и красный на 3.x, был бы хуже отсутствующего (R-058, R-063). Значит прогонять их
# надо там же, где собирается ext, а не на runner'е с чужой версией.
#
# Логика здесь, а не строкой в `docker run -c`: там всё это жило бы внутри двойных кавычек с
# экранированием, и на этом класс ошибок уже стоил сборки — флаги -I терялись при подстановке,
# а выглядело как «mbedtls/sha256.h не найден» (см. шапку build/build-ext.sh).
#
# ЧТО СОБИРАЕТСЯ И ЧЕМ. В образе лежат только ИСХОДНИКИ mbedtls (готовых .a там нет намеренно
# — см. Dockerfile), поэтому библиотека собирается здесь под хост-цель тем же zig, которым
# собирается релиз. Конфигурация при этом БЕРЁТСЯ ПО УМОЛЧАНИЮ, а не steer_mbedtls_config.h,
# и это не небрежность: стенды компилируются без -DMBEDTLS_CONFIG_FILE, и библиотека, собранная
# с другой конфигурацией, дала бы расхождение в раскладке структур — то есть самый тихий вид
# поломки, какой тут возможен. Проверяется версия библиотеки, а не её конфигурация.
#
# AddressSanitizer в этом окружении недоступен (zig не везёт с собой его рантайм, а на musl нет
# и LeakSanitizer). tests/ext-test.sh это проверяет пробой и говорит об этом ГРОМКО, собирая
# spokematch без санитайзера: функциональная половина стенда прогоняется, утечка — нет.
set -eu

MB=${MBEDTLS_DIR:-/opt/mbedtls}
SRC=${SRC:-/src}
OBJ=$SRC/build/mbedtls-host
LIB=$SRC/build/libmbed-host.a
# Префикс в том виде, в каком его ждёт tests/ext-test.sh: include/ рядом с lib/.
PREFIX=/tmp/mbedtls-host

if [ ! -f "$MB/include/mbedtls/version.h" ]; then
	echo "ext-test-image: в образе нет исходников mbedtls ($MB) — прогон невозможен" >&2
	exit 2
fi
command -v zig >/dev/null 2>&1 || {
	echo "ext-test-image: в образе нет zig — это не образ сборщика steer" >&2; exit 2; }

echo "ext-test-image: mbedtls из образа: $(sed -n 's/.*MBEDTLS_VERSION_STRING  *"\([^"]*\)".*/\1/p' \
	"$MB/include/mbedtls/version.h" | head -1)"

if [ ! -f "$LIB" ]; then
	mkdir -p "$OBJ"
	cd "$MB/library"
	# Тот же список исключений, что в build/build-ext.sh: сокеты, отладочная печать и
	# таймеры библиотеке здесь не нужны и тянут за собой платформенные вызовы.
	ok=0 bad=0
	for f in *.c; do
		case "$f" in net_sockets.c|debug.c|timing.c) continue ;; esac
		if zig cc -O1 -w -I../include -c "$f" -o "$OBJ/${f%.c}.o" 2>/dev/null; then
			ok=$((ok + 1))
		else
			bad=$((bad + 1))
		fi
	done
	# Число печатается, а не проверяется на ноль: линковщик берёт только нужное, и отдельный
	# не собравшийся модуль сам скажет о себе неопределённой ссылкой при сборке стенда. Молчать
	# об этом нельзя — иначе «стенд не собрался» читалось бы как ошибка в стенде.
	echo "ext-test-image: объектов mbedtls собрано $ok, не собралось $bad"
	# ar здесь zig'овый: busybox ar умеет только распаковывать, создавать архив им нельзя.
	zig ar rcs "$LIB" "$OBJ"/*.o
fi

mkdir -p "$PREFIX/lib"
ln -sfn "$MB/include" "$PREFIX/include"
cp "$LIB" "$PREFIX/lib/libmbedcrypto.a"

cd "$SRC"
STEER_MBEDTLS="$PREFIX" CC="zig cc" BUILD="${BUILD:-build}" exec sh tests/ext-test.sh
