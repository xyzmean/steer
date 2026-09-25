#!/bin/sh
# Снимок генератора: полный текст ruleset каждого `apply --dry-run`, который делают стенды.
#
# Зачем. Пересборка ядра (docs/architecture.md, выпуски 1.6-1.7) переносит генератор по
# модулям и переводит его на промежуточное дерево, и всё это время ruleset обязан оставаться
# ТЕМ ЖЕ до байта. Стенды генератора (gen.sh, androidmatch.sh, tgwsmark.sh) такого не
# обещают: они ищут в выводе нужные строки (`grep -c`), и переставленная цепочка, лишнее
# правило или пропавший набор проходят их молча, если искомая строка на месте. Снимок
# сравнивает текст целиком.
#
# Как. Стенды не трогаются: вместо бинарника им подставляется обёртка, которая пропускает
# все вызовы насквозь, а вывод `apply --dry-run` дополнительно складывает в файл. Имя файла —
# стенд, бинарник и порядковый номер вызова, поэтому новый вызов в середине стенда сдвигает
# номера следующих: такая правка стенда означает перезапись снимка, и это видно в diff.
#
# В заголовке каждого файла — аргументы, код выхода, переменные STEER_* и stderr: по ним
# понятно, какой случай разошёлся, без поиска по стенду. stderr входит в снимок нарочно:
# половина вызовов — отказы с кодом 2, и их текст (и строки steer[warn]) — такая же часть
# поведения, как ruleset. Временный каталог стенда заменён на TMP.
#
#   sh tests/snapshot.sh          сверить с tests/golden/ruleset (так зовёт make test)
#   sh tests/snapshot.sh record   записать снимок заново — только когда ruleset меняется
#                                 намеренно, и в том же коммите, что и изменение
set -u
MODE="${1:-check}"
GOLDEN="tests/golden/ruleset"
STEER_BIN="${STEER:-./build/steer}"
ANDROID_BIN="${ANDROID:-./build/steer-android}"
TGWSSIM_BIN="${TGWSSIM:-./build/tgwssim}"
for b in "$STEER_BIN" "$ANDROID_BIN" "$TGWSSIM_BIN"; do
    [ -x "$b" ] || { echo "snapshot: не собран $b (make)"; exit 2; }
done

abs() { echo "$(cd "$(dirname "$1")" && pwd)/$(basename "$1")"; }

tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT
out="$tmp/out"
mkdir -p "$out" "$tmp/wrap"

# Обёртка на каждый бинарник. Метка (router, android, tgws) входит в имя файла снимка.
wrap() {
    real="$(abs "$1")"
    cat > "$tmp/wrap/$2" <<EOF
#!/bin/sh
real='$real'
tag="\${SNAP_STAGE}-$2"
dry=0
if [ "\${1:-}" = apply ]; then
    for a in "\$@"; do [ "\$a" = --dry-run ] && dry=1; done
fi
[ \$dry = 1 ] || exec "\$real" "\$@"
cnt="$out/.n-\$tag"
n=\$(cat "\$cnt" 2>/dev/null || echo 0); n=\$((n + 1)); echo \$n > "\$cnt"
buf="$out/.buf.\$\$"
"\$real" "\$@" > "\$buf" 2> "\$buf.err"
rc=\$?
{
    printf '# args: %s\n' "\$*"
    printf '# exit: %s\n' "\$rc"
    env | grep '^STEER_' | LC_ALL=C sort | sed 's/^/# env: /'
    sed 's/^/# stderr: /' "\$buf.err"
    cat "\$buf"
} | sed -E 's#/[A-Za-z0-9_./-]*/tmp\.[A-Za-z0-9]+#TMP#g' > "$out/\$(printf '%s-%03d.nft' "\$tag" "\$n")"
cat "\$buf"
cat "\$buf.err" >&2
rm -f "\$buf" "\$buf.err"
exit \$rc
EOF
    chmod +x "$tmp/wrap/$2"
}
wrap "$STEER_BIN" router
wrap "$ANDROID_BIN" android
wrap "$TGWSSIM_BIN" tgws

# Стенды гоняются молча: свои pass/fail они печатают в make test сами. Упавший стенд
# обрывается раньше и оставляет меньше файлов — это покажет сверка ниже.
SNAP_STAGE=gen STEER="$tmp/wrap/router" sh tests/gen.sh >/dev/null 2>&1
SNAP_STAGE=androidmatch ANDROID="$tmp/wrap/android" sh tests/androidmatch.sh >/dev/null 2>&1
SNAP_STAGE=tgwsmark STEER="$tmp/wrap/router" TGWSSIM="$tmp/wrap/tgws" \
    sh tests/tgwsmark.sh >/dev/null 2>&1
rm -f "$out"/.n-*

n="$(ls "$out" | wc -l | tr -d ' ')"
if [ "$MODE" = record ]; then
    rm -rf "$GOLDEN"
    mkdir -p "$GOLDEN"
    cp "$out"/*.nft "$GOLDEN"/
    echo "snapshot: записано $n снимков в $GOLDEN"
    exit 0
fi

[ -d "$GOLDEN" ] || { echo "snapshot: нет $GOLDEN — sh tests/snapshot.sh record"; exit 2; }
if diff -r -u "$GOLDEN" "$out" > "$tmp/diff"; then
    echo "snapshot: $n снимков совпали"
    exit 0
fi
echo "snapshot: ruleset разошёлся со снимком ($GOLDEN):"
head -n 80 "$tmp/diff"
[ "$(wc -l < "$tmp/diff")" -gt 80 ] && echo "... (diff длиннее, полностью: diff -r $GOLDEN <вывод>)"
echo "если изменение намеренное: sh tests/snapshot.sh record — в том же коммите"
exit 1
