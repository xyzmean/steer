#!/bin/sh
# Builds one static musl binary per OpenWrt architecture and packages it.
#
# Same zig cross-toolchain splify uses: a static binary means no libc version to
# match against the router's, and one build serves every OpenWrt release for that
# ISA. The image is the splify-dnsd builder — reused rather than duplicated.
set -eu

VERSION="$(cat VERSION 2>/dev/null || echo 0.1.0)"
OUT=out
IMAGE="${STEER_BUILDER_IMAGE:-splify-dnsd-builder:zig-0.13.0}"

# id:target:mcpu — the ISAs OpenWrt actually ships. Package arch names below map
# several OpenWrt targets onto one ISA build, which is why the two lists differ.
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
               -o "build/steer-$arch" src/steer.c src/spec.c src/dnsd.c src/failover.c \
               src/aggregate.c \
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
