#!/bin/sh
# Builds one static musl binary per OpenWrt architecture and packages it.
#
# Same zig cross-toolchain splify uses: a static binary means no libc version to
# match against the router's, and one build serves every OpenWrt release for that
# ISA.
set -eu

VERSION="$(cat VERSION 2>/dev/null || echo 0.1.0)"
OUT=out
# Свой образ, а не образ сборщика splify: в том нет исходников mbedtls, и расширенная
# сборка в нём падает на «mbedtls/sha256.h не найден», тогда как базовая проходит.
# Незаметная поломка: `./build.sh` печатает архитектуры, пакеты появляются, и только
# extended молча отсутствует.
IMAGE="${STEER_BUILDER_IMAGE:-steer-builder:mbedtls}"

# Собрать образ, если его нет. Иначе первая же сборка на чужой машине упирается в
# «Unable to find image», и человек ищет, откуда его взять, — а он описан прямо здесь,
# в build/Dockerfile.
if ! docker image inspect "$IMAGE" >/dev/null 2>&1; then
    echo "образ $IMAGE отсутствует — собираю из build/Dockerfile"
    docker build -t "$IMAGE" build/ || { echo "не удалось собрать образ"; exit 1; }
fi

# id:target:mcpu — the ISAs OpenWrt actually ships. Package arch names below map
# several OpenWrt targets onto one ISA build, which is why the two lists differ.
# Два варианта одного движка, как dnsmasq и dnsmasq-full: базовый и с клиентом
# VLESS/Reality. Базовому VLESS не нужен, а весит он вместе с TLS-стеком больше самого
# движка — и на 4C с 6.9 МБ overlay это решает, влезет ли пакет.
#
# Собираются из ОДНИХ исходников: extended это те же файлы плюс src/ext и mbedtls.
# Разные бинарники из разного набора файлов означали бы два места, где чинить одну ошибку.
BASE_SRC="src/steer.c src/spec.c src/dnsd.c src/failover.c src/aggregate.c"
# Абсолютные пути внутри контейнера: расширенная сборка компилирует mbedtls из отдельного
# каталога и делает cd туда, так что относительные пути к исходникам не находятся —
# ошибка выглядела как «FileNotFound: src/ext/tls13.c», то есть будто файла нет вовсе.
BASE_SRC_ABS="/src/src/steer.c /src/src/spec.c /src/src/dnsd.c /src/src/failover.c /src/src/aggregate.c"
EXT_SRC_ABS="/src/src/ext/sub.c /src/src/ext/reality.c /src/src/ext/tls13.c /src/src/ext/vless_proto.c /src/src/ext/vision.c /src/src/ext/client.c /src/src/ext/tun.c /src/src/ext/tunnel.c /src/src/ext/h2.c /src/src/ext/rtx.c"

ISAS="
mipsel_24kc:mipsel-linux-musl:mips32r2+soft_float
mips_24kc:mips-linux-musl:mips32r2+soft_float
aarch64_cortex-a53:aarch64-linux-musl:cortex_a53
aarch64_generic:aarch64-linux-musl:baseline
arm_cortex-a7_neon-vfpv4:arm-linux-musleabihf:cortex_a7
x86_64:x86_64-linux-musl:baseline
"

mkdir -p "$OUT" build/pkg

echo "steer $VERSION"
for spec in $ISAS; do
    arch=${spec%%:*}; rest=${spec#*:}
    target=${rest%%:*}; mcpu=${rest#*:}
    printf '  %-26s ' "$arch"
    if docker run --rm -v "$PWD:/src" -w /src "$IMAGE" \
            cc -target "$target" -mcpu="$mcpu" -static -Os -Wall -Wextra \
               -o "build/steer-$arch" $BASE_SRC \
               2>"build/$arch.err"; then
        echo "$(stat -c %s "build/steer-$arch") bytes"
    else
        # Старый бинарник обязан исчезнуть: иначе упаковка молча положит в пакет
        # сборку от прошлого раза, и ошибка компиляции превратится в «версия
        # обновилась, а поведение прежнее» — самый дорогой вид тихого сбоя.
        rm -f "build/steer-$arch"
        echo "FAILED — $(grep -m1 error "build/$arch.err" || head -1 "build/$arch.err")"
        continue
    fi

    # Расширенный вариант: те же исходники плюс VLESS и mbedtls. Логика в отдельном
    # скрипте — см. build/build-ext.sh, там объяснено почему.
    printf '  %-26s ' "$arch (extended)"
    if docker run --rm -v "$PWD:/src" -w /src --entrypoint sh "$IMAGE" \
            /src/build/build-ext.sh "$target" "$mcpu" "/src/build/steer-ext-$arch" \
            2>"build/$arch-ext.err"; then
        echo "$(stat -c %s "build/steer-ext-$arch") bytes"
    else
        rm -f "build/steer-ext-$arch"
        echo "FAILED — $(grep -m1 error "build/$arch-ext.err" || head -1 "build/$arch-ext.err")"
    fi

    root="build/pkg/$arch"
    rm -rf "$root"
    mkdir -p "$root/usr/sbin" "$root/etc/init.d" "$root/etc/steer/lists"
    cp "build/steer-$arch" "$root/usr/sbin/steer"
    cp files/etc/init.d/steer "$root/etc/init.d/steer"
    chmod 0755 "$root/usr/sbin/steer" "$root/etc/init.d/steer"

    # OUTSIDE the package root: anything inside it ships as a FILE, so a
    # .post-install written there arrives on the router as /.post-install and
    # collides with every other package doing the same — apk refused the install of a
    # second package with "trying to overwrite .post-install owned by steer". The
    # script belongs to --script, not to the payload.
    mkdir -p build/scripts
    cat > build/scripts/post-install <<'EOF'
#!/bin/sh
[ -n "${IPKG_INSTROOT}" ] && exit 0
/etc/init.d/steer enable 2>/dev/null
[ -f /etc/steer/spec.json ] && /etc/init.d/steer restart 2>/dev/null
exit 0
EOF
    cat > build/scripts/pre-deinstall <<'EOF'
#!/bin/sh
[ -n "${IPKG_INSTROOT}" ] && exit 0
/etc/init.d/steer stop 2>/dev/null
/etc/init.d/steer disable 2>/dev/null
exit 0
EOF
    chmod +x build/scripts/post-install build/scripts/pre-deinstall

    # Расширенный пакет: то же имя команды, поэтому provides/conflicts с базовым —
    # установленные вместе они спорили бы за /usr/sbin/steer, и какой победит зависело бы
    # от порядка установки.
    if [ -f "build/steer-ext-$arch" ]; then
        eroot="build/pkg/$arch-ext"
        rm -rf "$eroot"
        mkdir -p "$eroot/usr/sbin" "$eroot/etc/init.d" "$eroot/etc/steer/lists"
        cp "build/steer-ext-$arch" "$eroot/usr/sbin/steer"
        cp files/etc/init.d/steer "$eroot/etc/init.d/steer"
        chmod 0755 "$eroot/usr/sbin/steer" "$eroot/etc/init.d/steer"
        docker run --rm -v "$PWD":/w -w /w alpine:latest sh -c \
            "apk add --no-cache apk-tools >/dev/null 2>&1; apk mkpkg \
               --info name:steer-extended --info version:$VERSION-r1 \
               --info description:'steer + клиент VLESS/Reality (как dnsmasq-full)' \
               --info arch:$arch --info depends:'nftables ip-full kmod-tun' \
               --info provides:steer --info replaces:steer \
               --script post-install:build/scripts/post-install \
               --script pre-deinstall:build/scripts/pre-deinstall \
               -F $eroot -o $OUT/steer-extended-$VERSION-1_$arch.apk" >/dev/null 2>&1 \
            || echo "    (упаковка extended для $arch не удалась)"
    fi

    docker run --rm -v "$PWD":/w -w /w alpine:latest sh -c \
        "apk add --no-cache apk-tools >/dev/null 2>&1; apk mkpkg \
           --info name:steer --info version:$VERSION-r1 \
           --info description:'policy routing engine: channels in, nftables out' \
           --info arch:$arch --info depends:'nftables ip-full' \
           --script post-install:build/scripts/post-install \
           --script pre-deinstall:build/scripts/pre-deinstall \
           -F $root -o $OUT/steer-$VERSION-1_$arch.apk" >/dev/null 2>&1 \
        || echo "    (apk packaging failed for $arch)"
done

echo "packages:"
ls -1 "$OUT" 2>/dev/null | sed 's/^/  /'
