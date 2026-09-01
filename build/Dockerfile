# Кросс-компилятор для steer: musl-статика под все архитектуры OpenWrt плюс исходники
# mbedtls для VLESS/Reality.
#
# Почему zig, а не набор тулчейнов: движку нужен статический musl-бинарник, и Debian'ов
# cross-gcc здесь не годится дважды — статический glibc это ~800 КБ на 35 КБ программы
# при 7 МБ флеша, а его mipsel-цель собрана под HARD FLOAT, тогда как OpenWrt mipsel_24kc
# работает на soft-float: такой бинарник умирает с SIGILL на Mi Router 4C, то есть пакет
# ставится, а демон не может запуститься ни разу. Один zig на 45 МБ покрывает все ISA.
#
# Почему mbedtls ИСХОДНИКАМИ, а не пакетом:
#
# Reality — это TLS 1.3 с X25519, HKDF, ChaCha20-Poly1305 и AES-GCM. Писать это самому
# было бы худшим решением в проекте: ошибка в криптографии не ломается заметно, она
# тихо перестаёт защищать, а проверить это на роутере нельзя. mbedtls 3.6.6 уже стоит в
# OpenWrt (libmbedcrypto, 463 КБ) — но в системе только рантайм, без заголовков, и
# собирать надо под каждую архитектуру. Поэтому исходники едут в образ и компилируются
# тем же zig, что и остальное: у бинарника СВОЯ mbedtls, и что именно оказалось на
# роутере, его не касается вовсе — версии здесь не совпадают, они не связаны.
FROM alpine:3.20

ARG ZIG_VERSION=0.13.0
ARG ZIG_SHA256=d45312e61ebcc48032b77bc4cf7fd6915c11fa16e4aad116b66c9468211230ea

# ВЕРСИЯ mbedtls И ЧЕМ ОНА ОБОСНОВАНА.
#
# Прежде здесь стояло «та же ветка, что в OpenWrt 25.12 — чтобы поведение TLS на роутере и в
# сборке совпадало». Это описывало механизм, которого нет: собранное этим образом идёт СТАТИКОЙ
# и несёт свою mbedtls целиком (см. build.sh, pkg_deps — у такого бинарника нет даже записи
# DT_NEEDED на libmbedcrypto). Системная библиотека роутера в него не входит, совпадать там
# нечему, и сверять версии не с чем. Версию устройства учитывает ДРУГАЯ сборка —
# build/build-ext-native.sh, — и она получает исходники аргументом, а не отсюда.
#
# Настоящее обоснование числа: 3.6.x — ветка долгой поддержки, и внутри неё раскладка публичных
# структур и API не меняются, то есть src/ext/steer_mbedtls_config.h и вызовы остаются годными.
# Само число — то, на котором собрано и замерено то, что лежит в релизе; двигать его стоит
# осознанно, потому что это патчи TLS-библиотеки, а не косметика.
ARG MBEDTLS_VERSION=3.6.2
# Контрольная сумма опубликована апстримом рядом с тарболом
# (mbedtls-3.6.2-sha256sum.txt в том же выпуске). Проверять её обязательно и по той же
# причине, по какой проверяется тарбол zig: без сверки в образ приезжает то, что отдал сервер
# в момент сборки. Здесь цена выше, чем у компилятора, — это ровно та половина, где живут
# X25519, HKDF, ChaCha20-Poly1305 и AES-GCM для Reality, и подмена в ней не ломается заметно,
# она тихо перестаёт защищать. Проверялся компилятор, не проверялась криптография.
ARG MBEDTLS_SHA256=8b54fb9bcf4d5a7078028e0520acddefb7900b3e66fec7f7175bb5b7d85ccdca

RUN apk add --no-cache curl xz \
 && curl -fsSL -o /tmp/zig.tar.xz \
      "https://ziglang.org/download/${ZIG_VERSION}/zig-linux-x86_64-${ZIG_VERSION}.tar.xz" \
 && echo "${ZIG_SHA256}  /tmp/zig.tar.xz" | sha256sum -c - \
 && mkdir -p /opt && tar xf /tmp/zig.tar.xz -C /opt \
 && ln -s "/opt/zig-linux-x86_64-${ZIG_VERSION}/zig" /usr/local/bin/zig \
 && rm /tmp/zig.tar.xz \
 && zig version

# Только исходники: собирать их будет вызывающий, под нужную цель. Готовых .a в образе
# нет намеренно — иначе пришлось бы держать по копии на каждую из шести архитектур и
# следить, чтобы они не разъехались с тем, чем компилируется steer.
RUN curl -fsSL -o /tmp/mbedtls.tar.bz2 \
      "https://github.com/Mbed-TLS/mbedtls/releases/download/mbedtls-${MBEDTLS_VERSION}/mbedtls-${MBEDTLS_VERSION}.tar.bz2" \
 && echo "${MBEDTLS_SHA256}  /tmp/mbedtls.tar.bz2" | sha256sum -c - \
 && mkdir -p /opt/mbedtls \
 && tar xf /tmp/mbedtls.tar.bz2 -C /opt/mbedtls --strip-components=1 \
 && rm /tmp/mbedtls.tar.bz2 \
 && ls /opt/mbedtls/include/mbedtls/ssl.h

ENV MBEDTLS_DIR=/opt/mbedtls
WORKDIR /src
ENTRYPOINT ["/usr/local/bin/zig"]
