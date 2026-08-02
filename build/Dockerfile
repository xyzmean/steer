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
# тем же zig, что и остальное: одна версия у сборки и у цели, никаких сюрпризов от того,
# что на роутере оказалась другая.
FROM alpine:3.20

ARG ZIG_VERSION=0.13.0
ARG ZIG_SHA256=d45312e61ebcc48032b77bc4cf7fd6915c11fa16e4aad116b66c9468211230ea
# Та же ветка, что в OpenWrt 25.12 — чтобы поведение TLS на роутере и в сборке совпадало.
ARG MBEDTLS_VERSION=3.6.2

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
 && mkdir -p /opt/mbedtls \
 && tar xf /tmp/mbedtls.tar.bz2 -C /opt/mbedtls --strip-components=1 \
 && rm /tmp/mbedtls.tar.bz2 \
 && ls /opt/mbedtls/include/mbedtls/ssl.h

ENV MBEDTLS_DIR=/opt/mbedtls
WORKDIR /src
ENTRYPOINT ["/usr/local/bin/zig"]
