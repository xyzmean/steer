#!/bin/sh
# apply и настоящий nft: замена таблицы одной транзакцией и набор «пущен напрямую».
#
# Остальные стенды компилятора смотрят на текст --dry-run, а здесь нужно именно ядро: текст
# не скажет, примет ли nft файл целиком и что останется в ядре, если не примет.
#
# Что проверяется.
#  1. apply на машине без таблицы проходит: файл начинается с `table inet steer` (добавить,
#     если нет) и `delete table inet steer`, и без первой строки удаление отказало бы — а с
#     ним весь файл.
#  2. Повторный apply проходит, и отдельного `nft delete table` при этом не зовётся: прежде
#     таблица удалялась одним запуском nft, а новая грузилась другим, и между ними DNS
#     клиентов шёл мимо резолвера. Запуски nft считает обёртка в PATH.
#  3. Отвергнутый набор оставляет в ядре ПРЕЖНЮЮ таблицу, а не пустоту.
#  4. Выход с on_fail=direct без устройства: apply ставит его метку в набор failopen, то есть
#     его трафик, ушедший напрямую, общий обход снова видит как свой.
#
# Нужны root (сетевое пространство и nf_tables), nft и ip. Без них стенд пропускается, а не
# проваливается — как dnsnft.sh.
set -u
BIN="${STEER:-./build/steer}"
BIN="$(cd "$(dirname "$BIN")" && pwd)/$(basename "$BIN")"
[ -x "$BIN" ] || { echo "not built: $BIN (make)"; exit 2; }
command -v nft >/dev/null 2>&1 || { echo "applynft: nft нет — пропускаю"; exit 0; }
command -v ip >/dev/null 2>&1 || { echo "applynft: ip нет — пропускаю"; exit 0; }
if [ "${APPLYNFT_INNER:-}" != 1 ]; then
    [ "$(id -u)" = 0 ] || { echo "applynft: нужен root — пропускаю"; exit 0; }
    unshare -n true 2>/dev/null || { echo "applynft: unshare -n недоступен — пропускаю"; exit 0; }
    APPLYNFT_INNER=1 STEER="$BIN" exec unshare -n sh "$0" "$@"
fi

ip link set lo up
nft add table inet applynft_probe 2>/dev/null || { echo "applynft: nf_tables недоступен — пропускаю"; exit 0; }
nft delete table inet applynft_probe

tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT
pass=0 fail=0
check() {
    if [ "$2" = "$3" ]; then pass=$((pass + 1)); else
        fail=$((fail + 1))
        printf 'FAIL %s\n  expected: %s\n  actual:   %s\n' "$1" "$2" "$3"
    fi
}

# Обёртка: пишет каждый запуск nft строкой и передаёт настоящему.
real_nft="$(command -v nft)"
mkdir -p "$tmp/bin"
cat > "$tmp/bin/nft" <<EOF
#!/bin/sh
printf '%s\n' "\$*" >> "$tmp/nft.log"
exec "$real_nft" "\$@"
EOF
chmod +x "$tmp/bin/nft"
PATH="$tmp/bin:$PATH"; export PATH

printf '203.0.113.0/24\n' > "$tmp/a.lst"
cat > "$tmp/spec.json" <<EOF
{ "schema": 2,
  "from_default": ["192.168.1.0/24"],
  "outputs": { "vpn": { "kind": "interface", "device": "applynft0", "on_fail": "direct" } },
  "channels": [ { "name": "a", "match": { "prefixes_file": "$tmp/a.lst" }, "out": "vpn" } ] }
EOF
S="--spec $tmp/spec.json --state-dir $tmp/state"

"$BIN" apply $S >/dev/null 2>&1
check "первый apply (таблицы нет) проходит" "0" "$?"
check "набор канала в ядре" "1" "$(nft list set inet steer vpn_ip 2>/dev/null | grep -c '203.0.113.0/24')"

: > "$tmp/nft.log"
"$BIN" apply $S >/dev/null 2>&1
check "повторный apply проходит" "0" "$?"
check "таблица не удаляется отдельным запуском nft" "0" "$(grep -c '^delete table' "$tmp/nft.log")"
check "набор канала на месте" "1" "$(nft list set inet steer vpn_ip 2>/dev/null | grep -c '203.0.113.0/24')"

# Форму строка проходит, а адресом не является: её отвергает ядро, и отвергает весь файл.
printf '999.1.1.1\n' > "$tmp/a.lst"
err="$("$BIN" apply $S 2>&1 >/dev/null)"
check "отвергнутый набор — отказ" "1" "$?"
check "и прежняя таблица стоит" "1" "$(nft list set inet steer vpn_ip 2>/dev/null | grep -c '203.0.113.0/24')"
# apply оставляет отвергнутый файл для разбора и называет его — здесь он не нужен.
kept="$(printf '%s\n' "$err" | sed -n 's/.*(kept: \(.*\))$/\1/p')"
[ -n "$kept" ] && rm -f "$kept"
printf '203.0.113.0/24\n' > "$tmp/a.lst"

"$BIN" apply $S >/dev/null 2>&1
check "выход без устройства при on_fail=direct отмечен «пущен напрямую»" "1" \
    "$(nft list set inet steer failopen 2>/dev/null | grep -c 'elements = { 0x00100000 }')"
check "цепочка снятия бита стоит" "1" \
    "$(nft list chain inet steer prerouting_failopen 2>/dev/null | grep -c '@failopen')"

printf '\napplynft: %s passed, %s failed\n' "$pass" "$fail"
[ "$fail" -eq 0 ]
