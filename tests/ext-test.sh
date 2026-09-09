#!/bin/sh
# Прогон стендов src/ext, которым нужен НАСТОЯЩИЙ mbedtls, а не заглушки из tests/stub:
#
#   tests/xsloop.c     — рукопожатие Noise IK целиком: сборка ClientHello, ответ хаба,
#                        подтверждение, отказ по аутентификации, затирание состояния.
#   tests/spokematch.c — освобождение транспортных ключей при неудачном рукопожатии;
#                        собирается под AddressSanitizer, потому что утекает именно
#                        контекст шифра в куче (I-067).
#   tests/vlessmatch.c — ветви отказа vless_connect: код возврата, дескрипторы и куча на
#                        каждом «нет». Собирается под AddressSanitizer по той же причине,
#                        что spokematch: утекают контексты AES/GCM в куче (R-114). Сюда же
#                        входит серверная половина TLS 1.3 — та, которой в проекте не было
#                        вовсе, и без которой до серверного Finished не доходил ни один стенд.
#   tests/hubmatch.c   — арифметика записи в хабе: правило набора кадров в пачку против
#                        объявленной строки воркера (I-070). Включает src/ext/xshub.c, отсюда
#                        и mbedtls: цикл хаба тянет за собой reality.c и TLS 1.3.
#   tests/devupmatch.c — подъём устройства туннеля: каждый отказ `ip` обязан быть назван, и
#                        назван своим тоном (I-114). Включает src/ext/tunnel.c — оттуда та же
#                        зависимость от mbedtls.
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

# ---- разбор X.509: отдельная библиотека там, где она отдельная -----------------
# certverify.c зовёт mbedtls_x509_crt_* — единственное место в src/ext, где нужен разбор
# сертификатов, и появилось оно вместе с security=tls. В образе сборщика вся библиотека
# сложена в один libmbedcrypto.a (build/ext-test-image.sh: объекты всех модулей в один
# архив), и добавлять там нечего. В системной mbedtls она разделена на три —
# crypto, x509, tls, — и стенды падали на неопределённых mbedtls_x509_crt_init.
#
# ПРОБА, А НЕ ДОГАДКА: тот же приём, что ниже у AddressSanitizer, и по той же причине. Путь
# к библиотеке приходит четырьмя разными способами (см. выше), и «-lmbedx509 всегда»
# сломало бы ровно образ сборщика, где такой библиотеки не существует.
x509p="$BUILD/x509-probe"
printf '%s\n' '#include "mbedtls/x509_crt.h"' \
	'int main(void){mbedtls_x509_crt c;mbedtls_x509_crt_init(&c);mbedtls_x509_crt_free(&c);return 0;}' \
	> "$x509p.c"
# shellcheck disable=SC2086
if ! $CC -O0 -w $MBED_INC "$PRIV" -o "$x509p" "$x509p.c" $MBED_LIB >/dev/null 2>&1; then
	# shellcheck disable=SC2086
	if $CC -O0 -w $MBED_INC "$PRIV" -o "$x509p" "$x509p.c" -lmbedx509 $MBED_LIB >/dev/null 2>&1; then
		MBED_LIB="-lmbedx509 $MBED_LIB"
		echo "ext-test: разбор X.509 — отдельной библиотекой (-lmbedx509)"
	else
		# Громкий пропуск, как и при ненайденной библиотеке: без X.509 не компонуется ни
		# один стенд, потому что tls13.c зовёт certverify.c во всех сборках.
		echo "ext-test: в этой mbedtls нет разбора X.509 — ПРОПУСК (это не падение)."
		echo "ext-test:   Debian/Ubuntu: apt-get install libmbedtls-dev (в нём libmbedx509)."
		rm -f "$x509p" "$x509p.c"
		exit 0
	fi
fi
rm -f "$x509p" "$x509p.c"

# xsloop — рукопожатие целиком.
echo "ext-test: собираю и прогоняю xsloop..."
$CC -O2 -w -Isrc $MBED_INC "$PRIV" -o "$BUILD/xsloop" tests/xsloop.c \
	src/ext/xshake.c src/ext/chello.c src/ext/xswire.c src/ext/reality.c \
	src/ext/tls13.c src/ext/certverify.c src/ext/h2.c $MBED_LIB
"$BUILD/xsloop"

# spokematch — освобождение ключей при неудаче, под AddressSanitizer.
#
# Доступен ли санитайзер — проверяется ПРОБОЙ, а не догадкой по имени компилятора. В образе
# сборщика (zig cc, musl) рантайма ASan нет вовсе, а на musl нет и LeakSanitizer — то есть ровно
# того, на чём стоит этот стенд (I-067, утечка контекста шифра). Собрать там без санитайзера
# МОЛЧА значило бы получить зелёный стенд, который больше не проверяет то, ради чего написан,
# — поэтому пропуск громкий, как и пропуск по ненайденной библиотеке.
#
# ПРОБ ДВЕ, И ВТОРАЯ ПОЯВИЛАСЬ ПОТОМУ, ЧТО ПЕРВОЙ НЕ ХВАТАЛО (I-232). Первая ничего не теряет
# и обязана пройти: так видно, что рантайм есть и программа с ним ЗАПУСКАЕТСЯ. Вторая теряет
# 64 байта нарочно и обязана ПРОВАЛИТЬСЯ: так видно, что утечки ищутся. Без второй проба
# отвечала на вопрос «есть ли рантайм», а комментарий над ней обещал ответ и про отсутствие
# LeakSanitizer — обещание, которого код не исполнял: программа без утечки проходит и там, где
# утечек не ищут вовсе. Проверено: `ASAN_OPTIONS=detect_leaks=0 ./build/spokematch` печатал
# «все проверки прошли», то есть барьер под I-067 снимался переменной окружения молча.
ASAN="-fsanitize=address"
probe="$BUILD/asan-probe"
mkdir -p "$BUILD"
printf '#include <stdlib.h>\nint main(void){char*p=malloc(16);p[0]=1;free(p);return 0;}\n' \
	> "$probe.c"
printf '#include <stdlib.h>\nint main(void){char*p=malloc(64);p[0]=1;return 0;}\n' \
	> "$probe-leak.c"
asan_why=""
if ! $CC -O0 $ASAN -o "$probe" "$probe.c" >/dev/null 2>&1 || ! "$probe" >/dev/null 2>&1; then
	asan_why="рантайма нет либо программа с ним не запускается"
elif ! $CC -O0 $ASAN -o "$probe-leak" "$probe-leak.c" >/dev/null 2>&1; then
	asan_why="проба на утечку не собралась"
elif "$probe-leak" >/dev/null 2>&1; then
	# Вышла с нулём, потеряв 64 байта: рантайм есть, а утечек он не ищет.
	asan_why="утечки не ищутся (нет LeakSanitizer, как на musl, либо detect_leaks=0)"
fi
if [ -n "$asan_why" ]; then
	echo "ext-test: ВНИМАНИЕ — AddressSanitizer здесь не годится: $asan_why."
	echo "ext-test:            spokematch и vlessmatch собираются БЕЗ него: проверки в них"
	echo "ext-test:            прогонятся, утечки (I-067, R-114) — НЕТ."
	ASAN=""
fi
rm -f "$probe" "$probe.c" "$probe-leak" "$probe-leak.c"

echo "ext-test: собираю и прогоняю spokematch (ASan: ${ASAN:-нет})..."
# xslink.c в списке ОБЯЗАТЕЛЕН: командная строка клиента принимает и ссылку xs://, и файл
# одним xs_conf_load_any, и живёт эта функция там. Без неё сборка стенда падает на компоновке,
# то есть весь ext-test не доходит даже до первой проверки — а именно в нём и живёт ASan.
$CC -O1 -g -w -Isrc $ASAN $MBED_INC "$PRIV" -o "$BUILD/spokematch" \
	tests/spokematch.c \
	src/ext/xsconn.c src/ext/xswire.c src/ext/xsepoch.c src/ext/xsroute.c \
	src/ext/xsconf.c src/ext/xslink.c src/ext/xsstream.c src/ext/xshake.c src/ext/chello.c \
	src/ext/reality.c src/ext/tls13.c src/ext/certverify.c src/ext/h2.c src/ext/tun.c src/obfs.c \
	src/spec.c $MBED_LIB -lpthread
"$BUILD/spokematch"

# vlessmatch — ветви отказа vless_connect, под тем же AddressSanitizer.
#
# ASAN здесь уже определён пробой выше: второй экземпляр этой пробы разошёлся бы с первым,
# ровно как разошлись бы два определения mbedtls. Если санитайзера нет, стенд об этом
# ГОВОРИТ САМ (последние строки его вывода) — проверки кодов возврата и дескрипторов
# прогонятся, куча нет.
#
# Список исходников повторяет devupmatch без client.c: сам client.c стенд ВКЛЮЧАЕТ (шов
# установления TCP статический, см. заголовок стенда), и вторая его копия при компоновке
# дала бы дубли символов.
# ---- выпуск X.509: нужен vlessmatch для случаев security=tls -------------------
# Стенд выпускает свою пару «корень + лист» на месте (R-118): иначе проверка сервера не
# может ПРОЙТИ, а через удавшуюся проверку достижима ветвь VLESS_CONN_ENOH2 — та, ради
# которой в клиенте появился vless_close. Для выпуска нужен MBEDTLS_X509_CRT_WRITE_C, и
# он есть не в каждой сборке: в урезанной конфигурации роутера его нет вовсе.
#
# Проба, а не догадка — тот же приём, что у разбора X.509 выше и у AddressSanitizer ниже.
# Не нашлось — стенд собирается БЕЗ этих случаев и ГОВОРИТ об этом сам последними строками
# вывода: молчаливый пропуск читался бы как «прошло» (I-232).
X509W=""
x509wp="$BUILD/x509write-probe"
printf '%s\n' '#include "mbedtls/x509_crt.h"' \
	'int main(void){mbedtls_x509write_cert c;mbedtls_x509write_crt_init(&c);' \
	'mbedtls_x509write_crt_free(&c);return 0;}' > "$x509wp.c"
# shellcheck disable=SC2086
if $CC -O0 -w $MBED_INC "$PRIV" -o "$x509wp" "$x509wp.c" $MBED_LIB >/dev/null 2>&1; then
	X509W="-DSTEER_HAVE_X509WRITE"
	echo "ext-test: выпуск X.509 есть — случаи security=tls в vlessmatch включены"
else
	echo "ext-test: ВНИМАНИЕ — в этой mbedtls нет выпуска X.509 (MBEDTLS_X509_CRT_WRITE_C):"
	echo "ext-test:            случаи security=tls в vlessmatch будут ПРОПУЩЕНЫ (R-118)."
fi
rm -f "$x509wp" "$x509wp.c"

echo "ext-test: собираю и прогоняю vlessmatch (ASan: ${ASAN:-нет})..."
$CC -O1 -g -w -Isrc $ASAN $MBED_INC "$PRIV" $X509W -o "$BUILD/vlessmatch" tests/vlessmatch.c \
	src/ext/vless_proto.c src/ext/vision.c src/ext/tls13.c src/ext/certverify.c \
	src/ext/reality.c src/ext/h2.c src/ext/tun.c src/ext/rtx.c src/ext/sub.c \
	src/spec.c $MBED_LIB -lpthread
"$BUILD/vlessmatch"

# hubmatch — согласие правила набора пачки с размером строки воркера.
echo "ext-test: собираю и прогоняю hubmatch..."
$CC -O2 -w -Isrc $MBED_INC "$PRIV" -o "$BUILD/hubmatch" tests/hubmatch.c \
	src/ext/xsconn.c src/ext/xswire.c src/ext/xsepoch.c src/ext/xsroute.c \
	src/ext/xsconf.c src/ext/xslink.c src/ext/xsstream.c src/ext/xshake.c src/ext/chello.c \
	src/ext/reality.c src/ext/tls13.c src/ext/certverify.c src/ext/h2.c src/ext/tun.c src/obfs.c \
	src/spec.c $MBED_LIB -lpthread
"$BUILD/hubmatch"

# devupmatch — подъём устройства туннеля называет свои отказы (I-114).
echo "ext-test: собираю и прогоняю devupmatch..."
$CC -O2 -w -Isrc $MBED_INC "$PRIV" -o "$BUILD/devupmatch" tests/devupmatch.c \
	src/ext/client.c src/ext/vless_proto.c src/ext/vision.c src/ext/tls13.c src/ext/certverify.c \
	src/ext/reality.c src/ext/h2.c src/ext/tun.c src/ext/rtx.c src/ext/sub.c \
	src/spec.c $MBED_LIB -lpthread
"$BUILD/devupmatch"

# probe — активное зондирование настоящим openssl s_client. Здесь, а не отдельной целью
# Makefile: определение mbedtls уже сделано выше, а второй экземпляр этого определения
# разошёлся бы с первым. Стенд требует root и сетевых пространств и без них ГРОМКО
# пропускается, поэтому в ext-test он безопасен.
#
# Бинарник СЕРВЕРНЫЙ (-DSTEER_SERVER): хаб живёт только в нём, у роутерной сборки подкоманда
# xsteer-hub — штатная заглушка «ставится из архива steer-hub». Список исходников повторяет
# серверную половину из build/build-ext.sh; расходиться им негде — оба списка про один бинарник,
# и стенд упадёт на неразрешённом имени, если половины разъедутся.
#
# И РАЗОШЛИСЬ. `src/srs.c` появился в движке 5 сентября, в этот список его не внесли, и с того
# дня `make ext-test` не собирался вовсе — падал на `undefined reference to srs_dump`. Комментарий
# выше при этом обещал обратное: «расходиться им негде». Обещание держалось на том, что кто-то
# запустит цель, а её не запускали: она требует настоящей mbedtls и потому не входит в `make
# test`. Урок ровно про это: барьер, который нужно ЗАПУСТИТЬ РУКАМИ, не барьер.
echo "ext-test: собираю серверный бинарник для стенда зондирования..."
$CC -O1 -w -Isrc $MBED_INC "$PRIV" -DSTEER_SERVER -o "$BUILD/steer-hub-native" \
	src/steer.c src/spec.c src/dnsd.c src/failover.c src/aggregate.c src/obfs.c src/cli.c \
	src/srs.c src/puff.c src/hwid.c \
	src/ext/xswire.c src/ext/xsconf.c src/ext/xslink.c src/ext/xsroute.c src/ext/chello.c src/ext/xshake.c \
	src/ext/xsconn.c src/ext/xsstream.c src/ext/xsepoch.c src/ext/tls13.c src/ext/certverify.c src/ext/reality.c \
	src/ext/tun.c src/ext/h2.c src/ext/xsadmin.c src/ext/xshub.c \
	$MBED_LIB -lpthread
echo "ext-test: прогоняю probe (зондирование порта хаба)..."
BUILD="$BUILD" sh tests/probe.sh

echo "ext-test: все стенды прошли на mbedtls ${MBED_VER:-?}"
