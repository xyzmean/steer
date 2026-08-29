#!/bin/sh
# Builds one static musl binary per OpenWrt architecture and packages it.
#
# Same zig cross-toolchain splify uses: a static binary means no libc version to
# match against the router's, and one build serves every OpenWrt release for that
# ISA.
set -eu

VERSION="$(cat VERSION 2>/dev/null || echo 0.1.0)"

# В VERSION только цифры и точки. Этой строкой собираются имя файла пакета
# (`steer-extended-26.9-1_<арх>.apk`), версия для apk/opkg и тег релиза — пробелу и буквам там
# места нет ни в одном из трёх мест. Заодно её читает интерфейс splify2 через менеджер пакетов и
# сравнивает с релизами; версия с буквами в этом сравнении оказалась бы несравнимой.
#
# Кодовое имя выпуска («26.9 Andromeda») живёт в ЗАГОЛОВКЕ релиза на GitHub: оттуда его читает
# splify2 и показывает человеку. В имени пакета ему места нет.
#
# Число составляющих НЕ проверяется: «26.9» — такая же законная версия, как «1.2.0», и требовать
# три части значило бы отвергать собственный выпуск.
case "$VERSION" in
    ''|*[!0-9.]*)
        echo "в VERSION только цифры и точки, а там: «$VERSION»" >&2
        echo "кодовое имя выпуска задаётся заголовком релиза на GitHub, а не файлом VERSION" >&2
        exit 1 ;;
esac
# Ревизия сборки: чем этот бинарник отличается от релиза с тем же номером версии. Версия
# между релизами не меняется, поэтому релизный движок и движок из main через два коммита
# после него назывались одним числом, и на стенде два РАЗНЫХ бинарника отчитывались как
# «0.9.6-r1» (R-045/I-054). Печатает её `steer --version`; имена пакетов и версия пакета не
# затронуты намеренно — интерфейс версию берёт от менеджера пакетов.
#
# Считается ЗДЕСЬ, а не внутри docker: в образе нет ни git, ни каталога .git — смонтирован
# только рабочий каталог, — и describe там вернул бы пустоту при любом состоянии дерева.
#
# Без `--dirty`, в отличие от Makefile: релизный workflow сам записывает номер в VERSION
# ПЕРЕД сборкой и коммитит его после (см. .github/workflows/release.yml), поэтому дерево во
# время релизной сборки грязное всегда, и флаг помечал бы «-dirty» каждый релиз — то есть
# перестал бы что-либо значить.
REV="$(git describe --tags --always 2>/dev/null || true)"
[ -n "$REV" ] || REV="неизвестна"
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
BASE_SRC="src/steer.c src/spec.c src/dnsd.c src/failover.c src/aggregate.c src/obfs.c src/cli.c"
# Список файлов расширенной сборки живёт в build/build-ext.sh и только там: он запускается
# отдельным процессом с тремя аргументами, ничего отсюда не наследует, и вторая копия списка
# здесь молча расходилась бы с первой. Что списки не разошлись с самим каталогом src/ext,
# проверяет tests/buildmatch.sh.

ISAS="
mipsel_24kc:mipsel-linux-musl:mips32r2+soft_float
mips_24kc:mips-linux-musl:mips32r2+soft_float
aarch64_cortex-a53:aarch64-linux-musl:cortex_a53
aarch64_generic:aarch64-linux-musl:baseline
arm_cortex-a7_neon-vfpv4:arm-linux-musleabihf:cortex_a7
x86_64:x86_64-linux-musl:baseline
"

mkdir -p "$OUT" build/pkg

# ---- две упаковки одного пакета: apk и opkg ----------------------------------
#
# OpenWrt перешёл на apk в 24.10, но 23.05 и 22.03 живут на роутерах и будут жить: на
# 4/32 их никто не обновит, а именно там движок и нужнее всего. Собирать пакет только в
# новом формате значит отрезать половину устройств, ради которых он написан.
#
# Оба формата делаются из ОДНОГО дерева файлов ($root / $eroot), а не из двух: разные
# деревья означали бы пакет, который на одном формате работает, а на другом нет, и
# заметить это можно было бы только на роутере. Отличаются они только метаданными.
#
# ipkg-build — родной скрипт OpenWrt, тот же, что собирает пакеты в их SDK. Берётся из
# сети один раз и кладётся в build/ (см. .gitignore): переписывать его своими руками
# значило бы получить .ipk, который opkg принимает не везде, — ровно та ошибка, на
# которой в splify обжигались с po2lmo.
IPKG=build/ipkg-build
if [ ! -x "$IPKG" ]; then
    echo "качаю ipkg-build из OpenWrt"
    # ДВА ИСТОЧНИКА, а не один, и по той же причине, по которой пакеты выкладываются в
    # ветку dist (splify2#15): `raw.githubusercontent.com` у части провайдеров закрыт
    # целиком, а хосты самого GitHub — другая сеть и работают. `api.github.com` с
    # заголовком `Accept: application/vnd.github.raw` отдаёт тот же файл байтами, никуда не
    # перенаправляя. Это машина сборщика, а не роутер, но человек с закрытым доменом не мог
    # собрать пакеты вовсе, и сообщение об этом ничем не отличалось от «сеть отвалилась».
    RAW=https://raw.githubusercontent.com/openwrt/openwrt/master/scripts/ipkg-build
    API='https://api.github.com/repos/openwrt/openwrt/contents/scripts/ipkg-build?ref=master'
    ACCEPT='Accept: application/vnd.github.raw'
    # curl или wget: на машине сборщика бывает любой из двух, а требовать конкретный
    # значит уронить сборку там, где всё для неё есть.
    if command -v curl >/dev/null 2>&1; then
        curl -fsSL "$RAW" -o "$IPKG" ||
        curl -fsSL -H "$ACCEPT" "$API" -o "$IPKG" ||
            { echo "не удалось скачать ipkg-build ни из $RAW, ни из $API"; exit 1; }
    elif command -v wget >/dev/null 2>&1; then
        wget -qO "$IPKG" "$RAW" ||
        wget -qO "$IPKG" --header="$ACCEPT" "$API" ||
            { echo "не удалось скачать ipkg-build ни из $RAW, ни из $API"; exit 1; }
    else
        echo "нужен curl или wget, чтобы взять ipkg-build"; exit 1
    fi
    chmod +x "$IPKG"
fi

# mk_ipk КОРЕНЬ ИМЯ АРХ ЗАВИСИМОСТИ ОПИСАНИЕ [ДОПОЛНИТЕЛЬНЫЕ ПОЛЯ CONTROL]
#
# Каталог CONTROL создаётся ВНУТРИ дерева пакета, поэтому зовётся строго ПОСЛЕ apk mkpkg
# по тому же дереву: иначе служебные файлы уехали бы в полезную нагрузку apk.
mk_ipk() {
    ipk_root="$1"; ipk_name="$2"; ipk_arch="$3"; ipk_dep="$4"; ipk_desc="$5"; ipk_extra="${6:-}"
    mkdir -p "$ipk_root/CONTROL"
    {
        echo "Package: $ipk_name"
        echo "Version: $VERSION-1"
        echo "Depends: $ipk_dep"
        echo "Architecture: $ipk_arch"
        echo "Maintainer: xyzmean"
        echo "Section: net"
        [ -n "$ipk_extra" ] && printf '%s\n' "$ipk_extra"
        echo "Description: $ipk_desc"
    } > "$ipk_root/CONTROL/control"
    cp build/scripts/post-install "$ipk_root/CONTROL/postinst"
    cp build/scripts/pre-deinstall "$ipk_root/CONTROL/prerm"
    chmod 0755 "$ipk_root/CONTROL/postinst" "$ipk_root/CONTROL/prerm"
    # Без -o/-g: нынешний ipkg-build их не понимает (они были в старых версиях), а
    # молчаливый отказ здесь означал бы релиз без половины пакетов.
    if "$PWD/$IPKG" "$ipk_root" "$PWD/$OUT" >/dev/null 2>&1; then
        # ipkg-build называет файл через подчёркивания; приводим к тому же виду, что у
        # apk, чтобы в релизе оба формата одного пакета лежали рядом и читались одинаково.
        mv "$OUT/${ipk_name}_${VERSION}-1_${ipk_arch}.ipk" \
           "$OUT/${ipk_name}-${VERSION}-1_${ipk_arch}.ipk" 2>/dev/null || true
    else
        echo "    (ipk packaging failed for $ipk_name $ipk_arch)"
    fi
    rm -rf "$ipk_root/CONTROL"
}

echo "steer $VERSION"
for spec in $ISAS; do
    arch=${spec%%:*}; rest=${spec#*:}
    target=${rest%%:*}; mcpu=${rest#*:}
    printf '  %-26s ' "$arch"
    if docker run --rm -v "$PWD:/src" -w /src "$IMAGE" \
            cc -target "$target" -mcpu="$mcpu" -static -Os -Wall -Wextra \
               -DSTEER_VERSION="\"$VERSION\"" -DSTEER_REV="\"$REV\"" \
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
            "$VERSION" router "$REV" \
            2>"build/$arch-ext.err"; then
        echo "$(stat -c %s "build/steer-ext-$arch") bytes"
    else
        rm -f "build/steer-ext-$arch"
        echo "FAILED — $(grep -m1 error "build/$arch-ext.err" || head -1 "build/$arch-ext.err")"
    fi

    root="build/pkg/$arch"
    rm -rf "$root"
    mkdir -p "$root/usr/sbin" "$root/etc/init.d" "$root/etc/steer/lists" \
             "$root/lib/upgrade/keep.d" "$root/etc/hotplug.d/iface"
    cp "build/steer-$arch" "$root/usr/sbin/steer"
    cp files/etc/init.d/steer "$root/etc/init.d/steer"
    # Реакция на события сети: подъём и падение интерфейса доходят до сторожа сразу, а не
    # через минуту опроса. Файл невелик, но без него правка I-137 существует только в дереве.
    cp files/etc/hotplug.d/iface/95-steer "$root/etc/hotplug.d/iface/95-steer"
    # Настройки объявляются системе, иначе их не существует для sysupgrade и для «Создать
    # архив» в LuCI: список файлов там собирается из /etc/sysupgrade.conf и
    # /lib/upgrade/keep.d/*, и всё, чего в нём нет, обновление прошивки «с сохранением
    # настроек» просто теряет — молча (I-037: на стенде sysupgrade -l не знал ни spec.json,
    # ни sub.txt, то есть переживал обновление только URL подписки в /etc/config, без узлов).
    # Файл кладётся В ПОЛЕЗНУЮ НАГРУЗКУ, а не в скрипт установки: он обязан исчезнуть вместе
    # с пакетом и принадлежать ему, как init-скрипт.
    cp files/lib/upgrade/keep.d/steer "$root/lib/upgrade/keep.d/steer"
    chmod 0755 "$root/usr/sbin/steer" "$root/etc/init.d/steer" \
               "$root/etc/hotplug.d/iface/95-steer"
    chmod 0644 "$root/lib/upgrade/keep.d/steer"

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

    # Расширенный пакет: то же имя команды, поэтому объявляется заменой базового —
    # установленные вместе они спорили бы за /usr/sbin/steer, и какой победит зависело бы
    # от порядка установки. В apk это provides + replaces (третьего поля там нет), в opkg
    # к ним добавляется Conflicts — см. mk_ipk.
    if [ -f "build/steer-ext-$arch" ]; then
        eroot="build/pkg/$arch-ext"
        rm -rf "$eroot"
        mkdir -p "$eroot/usr/sbin" "$eroot/etc/init.d" "$eroot/etc/steer/lists" \
                 "$eroot/lib/upgrade/keep.d" "$eroot/etc/hotplug.d/iface"
        cp "build/steer-ext-$arch" "$eroot/usr/sbin/steer"
        cp files/etc/init.d/steer "$eroot/etc/init.d/steer"
        cp files/etc/hotplug.d/iface/95-steer "$eroot/etc/hotplug.d/iface/95-steer"
        # Тот же файл, что и в базовом пакете: расширенный ставится ВМЕСТО базового
        # (provides/replaces), и без своей копии keep.d замена пакета молча снимала бы
        # объявление настроек — то есть возвращала бы I-037 на ровно том пакете, который
        # ставит большинство.
        cp files/lib/upgrade/keep.d/steer "$eroot/lib/upgrade/keep.d/steer"
        chmod 0755 "$eroot/usr/sbin/steer" "$eroot/etc/init.d/steer" \
                   "$eroot/etc/hotplug.d/iface/95-steer"
        chmod 0644 "$eroot/lib/upgrade/keep.d/steer"
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
        # Тот же пакет в формате opkg. Три поля сразу: в opkg это ровно тот набор,
        # которым выражается «ставится ВМЕСТО», и без Conflicts два пакета уживались бы
        # в базе, споря за /usr/sbin/steer. Отдельной переменной, а не строкой в вызове:
        # многострочный литерал посреди аргументов читается плохо и его проверяет стенд.
        EXT_FIELDS='Provides: steer
Replaces: steer
Conflicts: steer'
        mk_ipk "$eroot" steer-extended "$arch" "nftables, ip-full, kmod-tun" \
            "steer + клиент VLESS/Reality (как dnsmasq-full)" "$EXT_FIELDS"
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
    mk_ipk "$root" steer "$arch" "nftables, ip-full" \
        "policy routing engine: channels in, nftables out"
done

# ---- серверная половина обфускации: архив для VPS -----------------------------
#
# steer obfs-server живёт не на роутере, а на VPS рядом с WireGuard, и пакетом OpenWrt
# туда не поставишь: там обычный Linux с systemd. До сих пор единственным путём была
# сборка из исходников (server/install.sh), то есть на голой VPS установка начиналась с
# apt install build-essential ради одного файла — и упиралась в него же на образах, где
# компилятора нет и ставить его нельзя.
#
# Архив содержит ровно то, что нужно на той стороне: статический бинарник, установщик и
# краткую справку. Бинарник тот же самый, что уезжает в пакет для роутера той же
# архитектуры, — отдельной сборки для сервера нет и быть не должно: два бинарника из
# разных сборок означали бы две обфускации, расходящиеся в мелочах на проводе.
#
# Архитектуры только те, на которых VPS реально бывают. Собирать архив под mips значило
# бы предлагать людям то, чего не существует.
echo "серверная половина:"
for arch in x86_64 aarch64_generic; do
    bin="build/steer-$arch"
    if [ ! -f "$bin" ]; then
        printf '  %-26s пропуск (движок не собрался)\n' "$arch"
        continue
    fi
    # Имя внутри архива — привычное человеку, а не имя цели OpenWrt: на VPS про
    # aarch64_generic никто не знает, там знают uname -m.
    case "$arch" in
        x86_64)           uarch=x86_64 ;;
        aarch64_generic)  uarch=aarch64 ;;
        *)                uarch=$arch ;;
    esac
    stage="build/obfs-$uarch"
    rm -rf "$stage"
    mkdir -p "$stage"
    cp "$bin" "$stage/steer"
    cp server/install.sh "$stage/install.sh"
    [ -f server/README.md ] && cp server/README.md "$stage/README.md"
    chmod 0755 "$stage/steer" "$stage/install.sh"
    tar -C build -czf "$OUT/steer-obfs-$VERSION-$uarch.tar.gz" "obfs-$uarch"
    printf '  %-26s %s bytes\n' "$uarch" "$(stat -c %s "$OUT/steer-obfs-$VERSION-$uarch.tar.gz")"
done

# ---- хаб xsteer: архив для VPS -----------------------------------------------
#
# Клиент xsteer живёт на роутере (роль router, уже собран выше в extended), а хаб звезды —
# на VPS. Хабу нужна подкоманда xsteer-hub, поднимающая слушателя на публичном порту, и
# ради безопасности её нет в сборке для роутера: это отдельная РОЛЬ server сборки ext
# (см. build/build-ext.sh — там объяснено, почему гейт стоит на списках файлов).
#
# Отсюда отдельный бинарник steer-hub и отдельный архив: смешивать его с обфускацией из
# steer-obfs нельзя — там другая половина и другой протокол. Архитектуры те же, что у VPS
# вообще (см. серверную половину выше): собирать хаб под mips значило бы предлагать
# несуществующее.
#
# Имя архива БЕЗ версии — steer-hub-$uarch.tar.gz: установщик server/xs_install.sh тянет его
# по фиксированному пути releases/latest/download/steer-hub-$arch.tar.gz, где имя не должно
# зависеть от версии. Внутри — бинарник, установщик и справка: распаковал и запустил, даже
# без сети (xs_install.sh берёт steer-hub рядом с собой, если он есть).
echo "хаб xsteer:"
for arch in x86_64 aarch64_generic; do
    # Цель и mcpu берём из того же ISAS, что и основную сборку: одна таблица архитектур,
    # чтобы хаб и движок не разошлись в флагах компилятора.
    spec=""
    for s in $ISAS; do [ "${s%%:*}" = "$arch" ] && spec="$s" && break; done
    if [ -z "$spec" ]; then
        printf '  %-26s пропуск (нет в ISAS)\n' "$arch"
        continue
    fi
    rest=${spec#*:}; target=${rest%%:*}; mcpu=${rest#*:}
    case "$arch" in
        x86_64)           uarch=x86_64 ;;
        aarch64_generic)  uarch=aarch64 ;;
        *)                uarch=$arch ;;
    esac
    printf '  %-26s ' "$uarch"
    if docker run --rm -v "$PWD:/src" -w /src --entrypoint sh "$IMAGE" \
            /src/build/build-ext.sh "$target" "$mcpu" "/src/build/steer-hub-$arch" \
            "$VERSION" server "$REV" \
            2>"build/$arch-hub.err"; then
        :
    else
        rm -f "build/steer-hub-$arch"
        echo "FAILED — $(grep -m1 error "build/$arch-hub.err" || head -1 "build/$arch-hub.err")"
        continue
    fi
    stage="build/hub-$uarch"
    rm -rf "$stage"
    mkdir -p "$stage"
    cp "build/steer-hub-$arch" "$stage/steer-hub"
    cp server/xs_install.sh "$stage/xs_install.sh"
    [ -f server/README.md ] && cp server/README.md "$stage/README.md"
    chmod 0755 "$stage/steer-hub" "$stage/xs_install.sh"
    tar -C "$stage" -czf "$OUT/steer-hub-$uarch.tar.gz" .
    printf '%s bytes\n' "$(stat -c %s "$OUT/steer-hub-$uarch.tar.gz")"
done

echo "packages:"
ls -1 "$OUT" 2>/dev/null | sed 's/^/  /'
