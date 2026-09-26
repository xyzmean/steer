#!/bin/sh
# Платформа выбирается при запуске (src/platform, docs/architecture.md, раздел 2, правило 2).
#
# Зачем. build/steer-android отличается от build/steer только умолчанием выбора
# (-DSTEER_DEFAULT_PLATFORM=android), код обеих платформ собран в оба. Значит обычный бинарник,
# которому платформу назвали явно — переменной STEER_PLATFORM или флагом --platform, — обязан
# вести себя ровно как сборка под эту платформу: тот же набор правил, те же строки в stderr, тот
# же код выхода. Иначе «выбор при запуске» — это два разных движка под одним именем, и стенд,
# собравший ruleset телефона обычным бинарником, проверял бы не то, что ставится на телефон.
#
# Как. Стенды генератора не переписываются: androidmatch.sh и gen.sh гоняются целиком, а
# вместо бинарника им подставляется сверяющая обёртка. Она зовёт эталон (сборку платформы) и
# проверяемого (другую сборку с явной платформой — и переменной, и флагом) с теми же
# аргументами и сравнивает stdout, stderr и код выхода. Каталог состояния у каждого прогона
# один и тот же, но перед проверяемым он возвращается в то состояние, в каком его застал
# эталон: реестр меток, дописанный первым прогоном, иначе менял бы второй. Дальше идёт
# состояние эталона — стенд видит то, что видел бы без обёртки.
#
# Сравниваются команды, которые не читают stdin и ничего не ставят в систему (apply --dry-run,
# help, needs-dnsd, dnsd-sig, *-instances, explain); остальные уходят в эталон насквозь.
set -u
ROUTER="${STEER:-./build/steer}"
ANDROID="${ANDROID:-./build/steer-android}"
for b in "$ROUTER" "$ANDROID"; do [ -x "$b" ] || { echo "not built: $b (make test)"; exit 2; }; done

pass=0 fail=0
check() {
    if [ "$2" = "$3" ]; then pass=$((pass + 1)); else
        fail=$((fail + 1))
        printf 'FAIL %s\n  expected: %s\n  actual:   %s\n' "$1" "$2" "$3"
    fi
}
abs() { echo "$(cd "$(dirname "$1")" && pwd)/$(basename "$1")"; }
tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT

# Обёртка: CMP_REAL — эталон, CMP_OTHER — проверяемый, CMP_PLAT — платформа, которую ему
# называют; итог каждого вызова — строка в CMP_LOG.
cat > "$tmp/cmp" <<'EOW'
#!/bin/sh
case "${1:-}" in
    apply|help|needs-dnsd|dnsd-sig|zapret-instances|tgws-instances|explain) ;;
    *) exec "$CMP_REAL" "$@" ;;
esac
d="$CMP_DIR/call.$$"
mkdir -p "$d"
st="" prev=""
for a in "$@"; do [ "$prev" = --state-dir ] && st="$a"; prev="$a"; done
[ -n "$st" ] && [ -d "$st" ] && cp -a "$st" "$d/pre"
"$CMP_REAL" "$@" >"$d/r.out" 2>"$d/r.err"; rc=$?
echo "$rc" >> "$d/r.out"
if [ -n "$st" ]; then rm -rf "$d/post"; [ -d "$st" ] && mv "$st" "$d/post"; fi
same=1
for how in env flag; do
    if [ -n "$st" ]; then rm -rf "$st"; [ -d "$d/pre" ] && cp -a "$d/pre" "$st"; fi
    if [ $how = env ]; then STEER_PLATFORM="$CMP_PLAT" "$CMP_OTHER" "$@" >"$d/o.out" 2>"$d/o.err"
    else "$CMP_OTHER" --platform "$CMP_PLAT" "$@" >"$d/o.out" 2>"$d/o.err"; fi
    echo "$?" >> "$d/o.out"
    cmp -s "$d/r.out" "$d/o.out" && cmp -s "$d/r.err" "$d/o.err" || { same=0; echo "DIFF($how) $*" >> "$CMP_LOG"; }
done
[ $same = 1 ] && echo "ok $*" >> "$CMP_LOG"
if [ -n "$st" ]; then rm -rf "$st"; [ -d "$d/post" ] && mv "$d/post" "$st"; fi
sed '$d' "$d/r.out"
cat "$d/r.err" >&2
rm -rf "$d"
exit "$rc"
EOW
chmod +x "$tmp/cmp"

# run СТЕНД ЭТАЛОН ПРОВЕРЯЕМЫЙ ПЛАТФОРМА ПЕРЕМЕННАЯ-БИНАРНИКА
run() {
    log="$tmp/$1.log"
    : > "$log"
    env "$5=$tmp/cmp" CMP_REAL="$(abs "$2")" CMP_OTHER="$(abs "$3")" CMP_PLAT="$4" \
        CMP_DIR="$tmp" CMP_LOG="$log" sh "tests/$1.sh" >/dev/null 2>&1
    check "$1: стенд прошёл и через обёртку" "0" "$?"
    check "$1: вызовов сверено больше десятка" "1" "$([ "$(grep -c '^ok ' "$log")" -gt 10 ] && echo 1 || echo 0)"
    check "$1: $3 с платформой $4 — как $2" "" "$(grep '^DIFF' "$log" | head -5)"
}
run androidmatch "$ANDROID" "$ROUTER" android ANDROID
run gen "$ROUTER" "$ANDROID" openwrt STEER

# Флаг — в любом месте строки, до команды тоже; неизвестное имя — отказ с перечнем известных.
check "--platform до команды — то же, что после" "$("$ROUTER" help apply --platform android 2>&1)" \
    "$("$ROUTER" --platform android help apply 2>&1)"
check "справка платформы телефона — его пути" "1" \
    "$("$ROUTER" --platform android help apply 2>&1 | grep -c '/data/misc/steer/spec.json')"
"$ROUTER" --platform nope help >/dev/null 2>"$tmp/p.err"
check "--platform с неизвестным именем — отказ" "2" "$?"
check "  и названы известные" "1" "$(grep -c 'openwrt, android' "$tmp/p.err")"
"$ROUTER" help --platform >/dev/null 2>"$tmp/p.err"
check "--platform без значения — отказ" "2" "$?"
# Выбор уходит в окружение детей (dnsd, помощники выходов): plat_select ставит STEER_PLATFORM.
check "общая справка называет выбранную платформу" "1" \
    "$("$ROUTER" --platform android help 2>&1 | grep -c '^Платформа: android')"
check "без выбора на машине стенда — роутер" "1" \
    "$(env -u STEER_PLATFORM -u ANDROID_ROOT "$ROUTER" help 2>&1 | grep -c '^Платформа: openwrt')"

printf '\nplatmatch: %s passed, %s failed\n' "$pass" "$fail"
[ "$fail" -eq 0 ]
