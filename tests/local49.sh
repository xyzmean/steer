#!/bin/sh
# Каналы на сам телефон (from: self / uid:N) — на НАСТОЯЩЕМ ядре: куда уходит собственный
# трафик устройства и с каким адресом источника.
#
# Запускается на стенде tools/vm49 хаба splicicd (ядро 4.9 — старая раскладка, та, что у
# телефона) и так же годится для сетевого пространства на свежем ядре (современная раскладка:
# цепочка route прямо в inet). Бинарники — Android-сборка движка и помощник:
#
#   K=/root/vm49/sysroot/kinc
#   musl-gcc -static -idirafter $K -O2 -DSTEER_ANDROID -o /tmp/steer <исходники как в Makefile>
#   musl-gcc -static -idirafter $K -O2 -o /tmp/local49-tool tests/local49-tool.c
#   tools/vm49/vm49.sh run steer/tests/local49.sh /tmp/steer /tmp/local49-tool
#
# Что проверяется. Приложение из канала по UID уходит в устройство своего выхода, а другое
# приложение к тому же адресу — обычным путём; канал сторожевого вида для раздачи сам телефон не
# задевает; «self» берёт всех, кроме root; канал «весь трафик» приложения — всё его IPv4;
# адрес источника в туннеле — адрес устройства туннеля (masquerade), а не адрес Wi-Fi; down
# снимает цепочки выхода. Устройства — постоянные TUN (local49-tool mk), «сеть» — up0 с
# маршрутом по умолчанию, туннели — wg9 и wg8.
set -u
pass=0 fail=0
check() {
    if [ "$2" = "$3" ]; then pass=$((pass + 1)); echo "ok   $1"; else
        fail=$((fail + 1)); printf 'FAIL %s\n  expected: %s\n  actual:   %s\n' "$1" "$2" "$3"
    fi
}
uname -r
W=${WORK:-/work}
mkdir -p /data/misc/steer/state /data/misc/steer/tmp /tmp/st
local49-tool mk up0 10.66.0.1/24 && ip route add default dev up0
local49-tool mk wg9 10.77.0.1/24
local49-tool mk wg8 10.78.0.1/24
printf '203.0.113.0/24\n' > $W/p.lst
printf '198.51.100.0/24\n' > $W/q.lst
cat > $W/local.json <<J
{ "schema": 2, "lan_devices": ["rndis0"],
  "outputs": { "vpn": { "kind": "interface", "device": "wg9", "on_fail": "drop" },
               "vpn2": { "kind": "interface", "device": "wg8", "on_fail": "direct" } },
  "channels": [
    { "name": "app", "from": ["uid:10123"], "match": { "prefixes_files": ["$W/p.lst"] }, "out": "vpn" },
    { "name": "all", "from": ["self"], "match": { "prefixes_files": ["$W/q.lst"] }, "out": "vpn2" },
    { "name": "full", "from": ["uid:10500-10510"], "match": { "any": true, "allow_all": true }, "out": "vpn" },
    { "name": "lan", "match": { "prefixes_files": ["$W/p.lst"] }, "out": "vpn2" } ] }
J
S="--spec $W/local.json --state-dir /tmp/st"
steer apply $S 2>&1 | grep -v 'masquerade\|not mentioned\|IPv6'
check "apply с каналами на сам телефон" "0" "$(steer apply $S >/dev/null 2>&1; echo $?)"
nft list ruleset | grep -A8 'chain output_' | grep -v '^--'
ip rule show | grep fwmark

# probe UID АДРЕС ПОРТ — через какое устройство ушёл SYN: «wg9 SRC», «wg8 SRC», «up0 SRC».
probe() {
    for d in up0 wg9 wg8; do local49-tool watch $d 900 > /tmp/w.$d & done
    sleep 0.3
    local49-tool conn "$1" "$2" "$3"
    wait
    for d in up0 wg9 wg8; do
        sed -n "s/^syn \([0-9.]*\) -> $2:$3$/$d \1/p" /tmp/w.$d
    done | head -1
}

echo "=== 1. приложение из канала по UID"
check "uid 10123 к 203.0.113.9 — в туннель wg9 с адресом туннеля" "wg9 10.77.0.1" "$(probe 10123 203.0.113.9 443)"
echo "=== 2. другое приложение к тому же адресу"
check "uid 10124 к 203.0.113.9 — обычным путём (канал раздачи lan телефон не задевает)" \
    "up0 10.66.0.1" "$(probe 10124 203.0.113.9 443)"
echo "=== 3. self — все, кроме root"
check "uid 10124 к 198.51.100.9 — в wg8" "wg8 10.78.0.1" "$(probe 10124 198.51.100.9 443)"
check "uid 1000 (system) к 198.51.100.9 — в wg8" "wg8 10.78.0.1" "$(probe 1000 198.51.100.9 443)"
check "root к 198.51.100.9 — обычным путём" "up0 10.66.0.1" "$(probe 0 198.51.100.9 443)"
echo "=== 4. весь трафик приложения (диапазон UID)"
check "uid 10505 к 192.0.2.7 — в wg9" "wg9 10.77.0.1" "$(probe 10505 192.0.2.7 80)"
check "uid 10511 к 192.0.2.7 — вне диапазона, обычным путём" "up0 10.66.0.1" "$(probe 10511 192.0.2.7 80)"
check "первое совпадение сверху: uid 10505 к 198.51.100.9 — канал all выше full" \
    "wg8 10.78.0.1" "$(probe 10505 198.51.100.9 443)"
echo "=== 5. down"
steer down --state-dir /tmp/st
check "после down цепочек выхода нет" "0" "$(nft list ruleset | grep -c 'output_mark\|output_reroute')"
check "после down uid 10123 — обычным путём" "up0 10.66.0.1" "$(probe 10123 203.0.113.9 443)"

printf '\nlocal49: %s passed, %s failed\n' "$pass" "$fail"
[ "$fail" -eq 0 ]
