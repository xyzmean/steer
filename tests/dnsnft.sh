#!/bin/sh
# Резолвер и ядро: DNAT-карта fakeip через настоящий netlink, в отдельном сетевом пространстве.
#
# Всё прочее в резолвере проверяется без ядра, а путь «ответ апстрима -> элемент карты» — нет,
# и именно в нём жили две ошибки, которые снаружи выглядят одинаково: клиент с поддельным
# адресом идёт без подмены. Поэтому здесь поднимается настоящий dnsd в `unshare -n`, с таблицей
# `inet steer` и картой `fakeip` такими, какими их ждёт резолвер, поддельным апстримом на петле
# и `nft monitor` рядом — он считает, сколькими транзакциями ядро приняло переезд домена.
#
# Что проверяется.
#  1. Переезд (апстрим ответил другим адресом) — ОДНА транзакция: удаление старого значения и
#     добавление нового идут одним батчем. Двумя транзакциями между ними есть поколение ядра,
#     в котором поддельного адреса в карте нет, а при отказе второй — карта теряет элемент
#     насовсем, хотя резолвер продолжает раздавать этот адрес из быстрого пути.
#  2. После переезда в карте новый адрес.
#  3. Элемент удалён снаружи (перезагрузка fw4 снесла карту), затем переезд: удаление отвечает
#     ENOENT, батч откатывается целиком — и резолвер обязан повторить одно добавление.
#  4. Ядро отвергло добавление нового значения — прежнее отображение остаётся в карте (батч
#     откатывается целиком), а не пропадает вместе с удалением.
#  5. HUP при исчезнувшем файле правил не оставляет канал без правил, а вернувшийся файл
#     следующим HUP подхватывается.
#
# Нужны root (сетевое пространство и nf_tables), nft и python3. Без них стенд пропускается,
# а не проваливается: остальной набор обязан проходить на голой машине.
set -u
BIN="${STEER:-./build/steer}"
BIN="$(cd "$(dirname "$BIN")" && pwd)/$(basename "$BIN")"
[ -x "$BIN" ] || { echo "not built: $BIN (make)"; exit 2; }
command -v python3 >/dev/null 2>&1 || { echo "dnsnft: python3 нет — пропускаю"; exit 0; }
command -v nft >/dev/null 2>&1 || { echo "dnsnft: nft нет — пропускаю"; exit 0; }
if [ "${DNSNFT_INNER:-}" != 1 ]; then
    [ "$(id -u)" = 0 ] || { echo "dnsnft: нужен root — пропускаю"; exit 0; }
    unshare -n true 2>/dev/null || { echo "dnsnft: unshare -n недоступен — пропускаю"; exit 0; }
    DNSNFT_INNER=1 STEER="$BIN" exec unshare -n sh "$0" "$@"
fi

ip link set lo up
nft add table inet steer 2>/dev/null || { echo "dnsnft: nf_tables недоступен — пропускаю"; exit 0; }
nft add map inet steer fakeip '{ type ipv4_addr : ipv4_addr; }'

tmp="$(mktemp -d)"
trap 'kill ${DPID:-0} ${UPID:-0} ${MPID:-0} 2>/dev/null; rm -rf "$tmp"' EXIT

LPORT=15310
UPORT=15363

# Апстрим отвечает на A тем адресом, что лежит в файле сейчас: переезд домена — это запись
# в файл между запросами.
cat > "$tmp/upstream.py" <<'PY'
import socket, sys
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
s.bind(("127.0.0.1", int(sys.argv[1])))
while True:
    data, addr = s.recvfrom(2048)
    qend = 12
    while data[qend]: qend += 1 + data[qend]
    qend += 5
    ip = bytes(int(x) for x in open(sys.argv[2]).read().split("."))
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
rc = d[3] & 0x0f
if rc: print("rcode%d" % rc)
elif struct.unpack('>H', d[6:8])[0] == 0: print("empty")
else: print(".".join(str(b) for b in d[-4:]))
PY

printf 'example.com\nmoved.net\nfail.io\nstay.org\n' > "$tmp/d.lst"
printf '{"schema":1,"from_default":["127.0.0.0/8"],'\
'"outputs":{"direct":{"kind":"direct"},"vpn":{"kind":"interface","device":"lo"}},'\
'"channels":[{"name":"c","match":{"domains_files":["%s/d.lst"],"mode":"fakeip"},"out":"vpn"}]}' \
    "$tmp" > "$tmp/spec.json"

echo 203.0.113.1 > "$tmp/ip"
python3 "$tmp/upstream.py" "$UPORT" "$tmp/ip" & UPID=$!
nft monitor > "$tmp/mon" 2>&1 & MPID=$!
sleep 1
"$BIN" dnsd --spec "$tmp/spec.json" --state-dir "$tmp/state" \
    --listen-port "$LPORT" --upstream-port "$UPORT" > "$tmp/log" 2>&1 & DPID=$!
sleep 1
kill -0 "$DPID" 2>/dev/null || { echo "FAIL резолвер не поднялся:"; cat "$tmp/log"; exit 1; }

pass=0 fail=0
check() {
    if [ "$2" = "$3" ]; then pass=$((pass + 1)); printf 'ok   %s\n' "$1"; else
        fail=$((fail + 1))
        printf 'FAIL %s\n  ожидалось: %s\n  получено:  %s\n' "$1" "$2" "$3"
    fi
}
ask() { python3 "$tmp/client.py" "$LPORT" "$1"; }
# Значение карты для поддельного адреса: пусто, если элемента нет.
mapval() { nft get element inet steer fakeip "{ $1 }" 2>/dev/null |
           sed -n 's/.*elements = { [0-9.]* : \([0-9.]*\).*/\1/p'; }
gens() { grep -c 'new generation' "$tmp/mon"; }
# Переезд идёт из быстрого пути: клиенту сразу уходит поддельный адрес, а карту обновляет
# фоновый ответ апстрима. Его и ждём.
settle() { sleep 0.5; }

# Каждый сценарий — своё имя. Быстрый путь ходит наверх за свежестью карты не чаще раза в
# FAKEIP_ANSWER_TTL (60 с), и первый такой поход случается на ВТОРОМ запросе имени: первый
# идёт наверх обычным путём и ставит карту, второй отвечает поддельным сразу и обновляет карту
# фоновым ответом. То есть на имя в стенде ровно один переезд.
first() {   # имя адрес -> поддельный адрес; карта должна встать с этим адресом
    echo "$2" > "$tmp/ip"
    f="$(ask "$1")"
    settle
    check "$1: первый ответ — поддельный адрес" "198.18" "$(echo "$f" | cut -d. -f1-2)"
    check "$1: в карте первый адрес" "$2" "$(mapval "$f")"
}
move() {    # имя новый-адрес: переезд через быстрый путь
    echo "$2" > "$tmp/ip"
    ask "$1" >/dev/null
    settle
}

# --- 1-2. Переезд ---------------------------------------------------------------------------
first example.com 203.0.113.1
fake="$f"
g0="$(gens)"
move example.com 203.0.113.2
g1="$(gens)"
check "переезд — одна транзакция ядра" "1" "$((g1 - g0))"
check "после переезда в карте новый адрес" "203.0.113.2" "$(mapval "$fake")"

# --- 3. Элемент удалён снаружи, затем переезд ------------------------------------------------
first moved.net 203.0.113.11
fake="$f"
nft delete element inet steer fakeip "{ $fake }"
move moved.net 203.0.113.12
check "после внешнего удаления переезд восстановил элемент" "203.0.113.12" "$(mapval "$fake")"

# --- 4. Добавление отвергнуто — прежнее отображение остаётся ---------------------------------
# Карта того же имени, но со значением IPv6: удаление по ключу проходит, а добавление
# четырёхбайтного значения ядро отвергает. Двумя транзакциями удаление успевало
# зафиксироваться и элемент пропадал; одним батчем откатывается всё, и прежнее значение цело.
first fail.io 203.0.113.21
fake="$f"
nft delete map inet steer fakeip
nft add map inet steer fakeip '{ type ipv4_addr : ipv6_addr; }'
nft add element inet steer fakeip "{ $fake : 2001:db8::21 }"
move fail.io 203.0.113.22
check "отказ добавления не снёс прежний элемент" "1" \
    "$(nft list map inet steer fakeip | grep -c "$fake : 2001:db8::21")"
nft delete map inet steer fakeip
nft add map inet steer fakeip '{ type ipv4_addr : ipv4_addr; }'

# --- 5. HUP при исчезнувшем файле правил ----------------------------------------------------
mv "$tmp/d.lst" "$tmp/d.lst.gone"
kill -HUP "$DPID"
sleep 0.5
stay="$(ask stay.org)"
check "HUP без файла правил: домен из прежних правил всё ещё подменяется" "198.18" \
    "$(echo "$stay" | cut -d. -f1-2)"
# Файл вернулся с новым именем — следующий HUP его берёт: подмена не застыла на старом.
{ cat "$tmp/d.lst.gone"; echo new.dev; } > "$tmp/d.lst"
rm -f "$tmp/d.lst.gone"
kill -HUP "$DPID"
sleep 0.5
check "HUP с вернувшимся файлом берёт новые правила" "198.18" \
    "$(ask new.dev | cut -d. -f1-2)"

kill "$DPID" 2>/dev/null; wait "$DPID" 2>/dev/null
if [ "$fail" -gt 0 ]; then
    echo "--- nft monitor"; cat "$tmp/mon"; echo "--- dnsd"; tail -n 20 "$tmp/log"
fi
printf '\n%d проверок пройдено' "$pass"
if [ "$fail" -gt 0 ]; then printf ', %d ПРОВАЛЕНО\n' "$fail"; exit 1; fi
printf '\nвсе проверки прошли\n'
