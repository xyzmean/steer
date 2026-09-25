#!/bin/sh
# apply и резолвер в раскладке для старого ядра (STEER_NFT_COMPAT=legacy) на настоящем nft.
#
# Раскладка нужна ядру 4.9 (телефон, см. nft_compat в src/model/spec.h), а здесь ядро свежее — и это
# не делает стенд бесполезным. Свежее ядро принимает всё, что принимает 4.9, поэтому стенд
# проверяет то, чего текст --dry-run не скажет: что три таблицы встают ОДНОЙ транзакцией и
# заменяются ею же, что резолвер пишет в hash-набор и в карту таблицы ip, а не туда, где их
# больше нет, что счётчик канала из двух правил читается одним числом и что возврат на
# современную раскладку снимает таблицы старой. Примет ли всё это само ядро 4.9 — вопрос
# стенда tools/vm49 в хабе, он запускается отдельно.
#
# Что проверяется.
#  1. apply проходит; в inet нет ни одной цепочки nat, nat живёт в ip (и ip6), карта fakeip —
#     в ip; доменный набор — hash со сроками, его префиксы — во второй половине _n.
#  2. Повторный apply проходит и не зовёт отдельного `nft delete table`.
#  3. Резолвер кладёт поддельный адрес в карту `ip steer fakeip` и одиночным элементом в
#     hash-набор канала; режим realip кладёт настоящий адрес со сроком.
#  4. Два правила одной группы — один счётчик: status складывает их, apply переносит сумму.
#  5. diag видит заворот DNS в таблице ip и считает адреса обеих половин набора; explain
#     находит адрес в половине _n.
#  6. legacy-min: без ip6, без notrack — и apply говорит, чего не будет.
#  7. Современная раскладка после старой снимает таблицы ip и ip6 той же транзакцией.
#
# Нужны root, nft, ip и python3; без них стенд пропускается, как applynft.sh и dnsnft.sh.
set -u
BIN="${STEER:-./build/steer}"
BIN="$(cd "$(dirname "$BIN")" && pwd)/$(basename "$BIN")"
[ -x "$BIN" ] || { echo "not built: $BIN (make)"; exit 2; }
command -v nft >/dev/null 2>&1 || { echo "applynft-legacy: nft нет — пропускаю"; exit 0; }
command -v ip >/dev/null 2>&1 || { echo "applynft-legacy: ip нет — пропускаю"; exit 0; }
command -v python3 >/dev/null 2>&1 || { echo "applynft-legacy: python3 нет — пропускаю"; exit 0; }
if [ "${APPLYNFT_INNER:-}" != 1 ]; then
    [ "$(id -u)" = 0 ] || { echo "applynft-legacy: нужен root — пропускаю"; exit 0; }
    unshare -n true 2>/dev/null || { echo "applynft-legacy: unshare -n недоступен — пропускаю"; exit 0; }
    APPLYNFT_INNER=1 STEER="$BIN" exec unshare -n sh "$0" "$@"
fi

ip link set lo up
nft add table inet applynft_probe 2>/dev/null || { echo "applynft-legacy: nf_tables недоступен — пропускаю"; exit 0; }
nft delete table inet applynft_probe

tmp="$(mktemp -d)"
trap 'kill ${DPID:-0} ${UPID:-0} 2>/dev/null; rm -rf "$tmp"' EXIT
pass=0 fail=0
check() {
    if [ "$2" = "$3" ]; then pass=$((pass + 1)); else
        fail=$((fail + 1))
        printf 'FAIL %s\n  expected: %s\n  actual:   %s\n' "$1" "$2" "$3"
    fi
}

real_nft="$(command -v nft)"
mkdir -p "$tmp/bin"
cat > "$tmp/bin/nft" <<EOF
#!/bin/sh
printf '%s\n' "\$*" >> "$tmp/nft.log"
exec "$real_nft" "\$@"
EOF
chmod +x "$tmp/bin/nft"
PATH="$tmp/bin:$PATH"; export PATH
STEER_NFT_COMPAT=legacy; export STEER_NFT_COMPAT

LPORT=15410
UPORT=15463
printf '203.0.113.0/24\n' > "$tmp/a.lst"
printf 'example.com\n' > "$tmp/d.lst"
# Адресный список доменного канала: его префикс уходит в статическую половину набора.
printf '198.51.100.0/24\n' > "$tmp/p.lst"
printf 'real.io\n' > "$tmp/r.lst"
cat > "$tmp/spec.json" <<EOF
{ "schema": 2,
  "from_default": ["127.0.0.0/8"],
  "outputs": { "vpn": { "kind": "interface", "device": "applynft0", "on_fail": "direct" },
               "geo": { "kind": "interface", "device": "applynft1", "on_fail": "direct" } },
  "channels": [ { "name": "a", "match": { "prefixes_file": "$tmp/a.lst" }, "out": "vpn" },
                { "name": "d", "match": { "domains_files": ["$tmp/d.lst"],
                                          "prefixes_files": ["$tmp/p.lst"] }, "out": "vpn" },
                { "name": "r", "match": { "domains_files": ["$tmp/r.lst"], "mode": "realip" },
                  "out": "geo" } ] }
EOF
S="--spec $tmp/spec.json --state-dir $tmp/state"

# --- 1. Раскладка -----------------------------------------------------------------------------
"$BIN" apply $S >/dev/null 2>"$tmp/err1"
check "apply в старой раскладке проходит" "0" "$?"
check "apply называет раскладку" "1" "$(grep -c 'nftables старого ядра' "$tmp/err1")"
check "в inet нет цепочек nat" "0" "$(nft list table inet steer | grep -c 'type nat')"
check "nat — одна цепочка в ip" "1" "$(nft list table ip steer | grep -c 'type nat hook prerouting')"
check "заворот DNS в ip" "1" "$(nft list chain ip steer prerouting_nat | grep -c 'udp dport 53 .*redirect to :5300')"
check "заворот DNS по TCP в ip" "1" "$(nft list chain ip steer prerouting_nat | grep -c 'tcp dport 53 .*redirect to :5300')"
check "dnat по карте в той же цепочке" "1" \
    "$(nft list chain ip steer prerouting_nat | grep -c 'dnat to ip daddr map @fakeip')"
check "заворот DNS по IPv6 в ip6" "1" \
    "$(nft list chain ip6 steer prerouting_nat 2>/dev/null | grep -c 'udp dport 53 .*redirect to :5300')"
check "заворот DNS по IPv6 и TCP в ip6" "1" \
    "$(nft list chain ip6 steer prerouting_nat 2>/dev/null | grep -c 'tcp dport 53 .*redirect to :5300')"
check "доменный набор — со сроками и без interval" "1" \
    "$(nft list set inet steer vpn_dom | grep -c 'flags timeout')"
check "префикс доменного канала — в половине _n" "1" \
    "$(nft list set inet steer vpn_dom_n | grep -c '198.51.100.0/24')"
check "правил разметки у доменной группы два" "2" \
    "$(nft list chain inet steer prerouting_mark | grep -c 'comment "steer:vpn_dom"')"

# --- 2. Повторный apply ---------------------------------------------------------------------
: > "$tmp/nft.log"
"$BIN" apply $S >/dev/null 2>&1
check "повторный apply проходит" "0" "$?"
check "таблицы не удаляются отдельным запуском nft" "0" "$(grep -c '^delete table' "$tmp/nft.log")"
check "и таблица ip на месте" "1" "$(nft list tables | grep -c '^table ip steer$')"

# --- 3. Резолвер ------------------------------------------------------------------------------
cat > "$tmp/upstream.py" <<'PY'
import socket, sys
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
s.bind(("127.0.0.1", int(sys.argv[1])))
while True:
    data, addr = s.recvfrom(2048)
    qend = 12
    while data[qend]: qend += 1 + data[qend]
    qend += 5
    ip = bytes([203, 0, 113, 77])
    hdr = data[:2] + b'\x81\x80' + data[4:6] + b'\x00\x01\x00\x00\x00\x00'
    ans = b'\xc0\x0c\x00\x01\x00\x01\x00\x00\x00\x3c\x00\x04' + ip
    s.sendto(hdr + data[12:qend] + ans, addr)
PY
cat > "$tmp/client.py" <<'PY'
import socket, struct, sys
port, name = int(sys.argv[1]), sys.argv[2]
q = struct.pack('>HHHHHH', 0x4242, 0x0100, 1, 0, 0, 0)
for l in name.split('.'): q += bytes([len(l)]) + l.encode()
q += b'\x00' + struct.pack('>HH', 1, 1)
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM); s.settimeout(3)
s.sendto(q, ('127.0.0.1', port))
try:
    d, _ = s.recvfrom(2048)
except socket.timeout:
    print("timeout"); sys.exit()
print(".".join(str(b) for b in d[-4:]))
PY
python3 "$tmp/upstream.py" "$UPORT" & UPID=$!
sleep 0.5
"$BIN" dnsd $S --listen-port "$LPORT" --upstream-port "$UPORT" > "$tmp/dlog" 2>&1 & DPID=$!
sleep 1
fake="$(python3 "$tmp/client.py" "$LPORT" example.com)"
sleep 0.5
check "резолвер отдал поддельный адрес" "198.18" "$(echo "$fake" | cut -d. -f1-2)"
check "карта fakeip в таблице ip получила элемент" "1" \
    "$(nft list map ip steer fakeip | grep -c "$fake : 203.0.113.77")"
check "hash-набор канала получил поддельный адрес" "1" \
    "$(nft list set inet steer vpn_dom | grep -c "$fake")"
python3 "$tmp/client.py" "$LPORT" real.io >/dev/null
sleep 0.5
check "realip: настоящий адрес в наборе со сроком" "1" \
    "$(nft list set inet steer geo_dom_c0r | grep -c '203.0.113.77 timeout')"
kill "$DPID" 2>/dev/null; wait "$DPID" 2>/dev/null
[ "$fail" -gt 0 ] && { echo "--- dnsd"; tail -n 20 "$tmp/dlog"; }

# --- 4. Счётчик из двух правил ----------------------------------------------------------------
# Значения ставятся самим ядром: правило заменяется своим же текстом с другим счётчиком.
setctr() {   # номер-правила-группы пакетов байтов
    line="$(nft -a list chain inet steer prerouting_mark | grep 'comment "steer:vpn_dom"' | sed -n "$1p")"
    h="$(printf '%s\n' "$line" | sed -n 's/.*# handle \([0-9]*\).*/\1/p')"
    body="$(printf '%s\n' "$line" | sed -e 's/ # handle.*//' -e "s/counter packets [0-9]* bytes [0-9]*/counter packets $2 bytes $3/")"
    printf 'replace rule inet steer prerouting_mark handle %s %s\n' "$h" "$body" > "$tmp/r.nft"
    "$real_nft" -f "$tmp/r.nft"
}
setctr 1 5 500
setctr 2 7 700
st="$("$BIN" status $S 2>/dev/null)"
check "status складывает два правила группы" "1" \
    "$(printf '%s' "$st" | grep -c '"name":"vpn_dom","out":"vpn","kind":"domains","live":true,"packets":12,"bytes":1200')"
"$BIN" apply $S >/dev/null 2>&1
st="$("$BIN" status $S 2>/dev/null)"
check "apply переносит сумму" "1" \
    "$(printf '%s' "$st" | grep -c '"name":"vpn_dom","out":"vpn","kind":"domains","live":true,"packets":12,"bytes":1200')"

# --- 5. diag ----------------------------------------------------------------------------------
dg="$("$BIN" diag $S 2>/dev/null)"
check "diag видит заворот DNS в таблице ip" "1" \
    "$(printf '%s' "$dg" | grep -c '"id":"dns_redirect","verdict":"ok"')"
check "diag считает обе половины набора" "1" \
    "$(printf '%s' "$dg" | grep -c 'канал vpn_dom: адресов в ядре 2"')"

ex="$("$BIN" explain 198.51.100.9 $S 2>/dev/null)"
check "explain находит адрес во второй половине набора" "1" \
    "$(printf '%s\n' "$ex" | grep -c '"vpn_dom" -> output "vpn"')"

# --- 6. legacy-min ----------------------------------------------------------------------------
STEER_NFT_COMPAT=legacy-min "$BIN" apply $S >/dev/null 2>"$tmp/err6"
check "legacy-min: apply проходит" "0" "$?"
check "legacy-min: таблицы ip6 нет" "0" "$(nft list tables | grep -c '^table ip6 steer$')"
check "legacy-min: сказано про IPv6 и DNS" "1" "$(grep -c 'nat для IPv6' "$tmp/err6")"

# --- 7. Назад на современную раскладку --------------------------------------------------------
STEER_NFT_COMPAT=legacy "$BIN" apply $S >/dev/null 2>&1
: > "$tmp/nft.log"
STEER_NFT_COMPAT=modern "$BIN" apply $S >/dev/null 2>&1
check "современная раскладка после старой проходит" "0" "$?"
check "таблицы ip не осталось" "0" "$(nft list tables | grep -c '^table ip steer$')"
check "таблицы ip6 не осталось" "0" "$(nft list tables | grep -c '^table ip6 steer$')"
check "nat снова в inet" "1" "$(nft list table inet steer | grep -c 'chain prerouting_dns')"
check "и без отдельного delete table" "0" "$(grep -c '^delete table' "$tmp/nft.log")"

printf '\napplynft-legacy: %s passed, %s failed\n' "$pass" "$fail"
[ "$fail" -eq 0 ]
