#!/bin/sh
# Сборка под Android (-DSTEER_ANDROID): поле метки, пути по умолчанию и раскладка правил.
#
# Проверяется то, что сборка меняет, и ничего сверх: остальное у неё общее с роутерной и
# проверено её стендами. Раскладка nft к сборке не привязана (её выбирает проба ядра, см.
# nft_compat в src/spec.h), поэтому здесь она задаётся явно — и современная, и старая: обе
# обязаны собираться с полем метки телефона.
#
# Что проверяется.
#  1. Поле метки — биты 22-27: маска 0x0fc00000, запись `mark and 0xf03fffff`, и ни одного
#     следа роутерного поля 0x0ff00000 — в бит 20 и 21 пишет netd.
#  2. Пути по умолчанию — /data/misc/steer: /etc и /var на телефоне только для чтения.
#  3. Старая раскладка (legacy-min — ровно ядро телефона) собирается и с этим полем.
#  4. zapret на телефоне нет: бит пропуска zapret (0x40000000, в битах vendor netd) не ставится,
#     цепочки failopen, которая существует ради него, нет, а kind/on_fail zapret — отказ спеки.
set -u
BIN="${ANDROID:-./build/steer-android}"
[ -x "$BIN" ] || { echo "not built: $BIN (make test)"; exit 2; }

pass=0 fail=0
tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT
check() {
    if [ "$2" = "$3" ]; then pass=$((pass + 1)); else
        fail=$((fail + 1))
        printf 'FAIL %s\n  expected: %s\n  actual:   %s\n' "$1" "$2" "$3"
    fi
}

printf '203.0.113.0/24\n' > "$tmp/a.lst"
printf 'example.com\n' > "$tmp/d.lst"
cat > "$tmp/spec.json" <<EOF2
{ "schema": 2, "lan_devices": ["rndis0"],
  "outputs": { "direct": { "kind": "direct" },
               "vpn": { "kind": "interface", "device": "wg0", "on_fail": "direct" } },
  "channels": [ { "name": "a", "match": { "prefixes_file": "$tmp/a.lst" }, "out": "vpn" },
                { "name": "d", "match": { "domains_files": ["$tmp/d.lst"] }, "out": "vpn" } ] }
EOF2
S="--spec $tmp/spec.json --state-dir $tmp/state"

out="$(STEER_NFT_COMPAT=modern "$BIN" apply --dry-run $S 2>/dev/null)"
check "современная раскладка собирается" "0" "$?"
check "метка пишется в биты 22-27, без бита zapret" "1" \
    "$(printf '%s\n' "$out" | grep -c 'meta mark set mark and 0xf03fffff or 0x00400000')"
check "бита zapret 0x40000000 нет нигде" "0" "$(printf '%s\n' "$out" | grep -ci '0x4[0-9a-f]\{7\}')"
check "набора и цепочки failopen нет" "0" "$(printf '%s\n' "$out" | grep -c 'failopen')"
check "роутерного поля нет нигде" "0" "$(printf '%s\n' "$out" | grep -c '0x0ff00000\|0xf00fffff')"

help="$("$BIN" help apply 2>&1)"
check "спека по умолчанию — /data/misc/steer/spec.json" "1" \
    "$(printf '%s\n' "$help" | grep -c '/data/misc/steer/spec.json')"
check "состояние по умолчанию — /data/misc/steer/state" "1" \
    "$(printf '%s\n' "$help" | grep -c '/data/misc/steer/state')"
check "и ни слова про /etc/steer" "0" "$(printf '%s\n' "$help" | grep -c '/etc/steer')"

lout="$(STEER_NFT_COMPAT=legacy-min "$BIN" apply --dry-run $S 2>/dev/null)"
check "старая раскладка собирается" "0" "$?"
check "старая раскладка: nat в таблице ip" "1" "$(printf '%s\n' "$lout" | grep -c '^table ip steer {')"
# Правил два: адресный и доменный каналы слились в одну группу, и в старой раскладке у неё
# по правилу на каждую половину набора.
check "старая раскладка: метка та же" "2" \
    "$(printf '%s\n' "$lout" | grep -c 'meta mark set mark and 0xf03fffff or 0x00400000')"

sed 's/"kind": "direct" }/"kind": "zapret" }/' "$tmp/spec.json" > "$tmp/z.json"
"$BIN" apply --dry-run --spec "$tmp/z.json" --state-dir "$tmp/state" >/dev/null 2>"$tmp/z.err"
check "kind zapret — отказ спеки" "2" "$?"
check "  и причина названа" "1" "$(grep -c 'в сборке под Android zapret нет' "$tmp/z.err")"
sed 's/"on_fail": "direct"/"on_fail": "zapret"/' "$tmp/spec.json" > "$tmp/zf.json"
"$BIN" apply --dry-run --spec "$tmp/zf.json" --state-dir "$tmp/state" >/dev/null 2>"$tmp/zf.err"
check "on_fail zapret — отказ спеки" "2" "$?"

printf '\nandroidmatch: %s passed, %s failed\n' "$pass" "$fail"
[ "$fail" -eq 0 ]
