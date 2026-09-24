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
#   musl-gcc -static -idirafter $K -O2 -o /tmp/dnstool tests/legacy49-dnstool.c
#   iptables-legacy статически (musl), под именем iptables — см. ANDROID_AGENT_TASK.md §4
#   tools/vm49/vm49.sh run steer/tests/local49.sh /tmp/steer /tmp/local49-tool /tmp/dnstool /tmp/iptables
#
# Что проверяется. Приложение из канала по UID уходит в устройство своего выхода, а другое
# приложение к тому же адресу — обычным путём; канал сторожевого вида для раздачи сам телефон не
# задевает; «self» берёт всех, кроме root; канал «весь трафик» приложения — всё его IPv4;
# адрес источника в туннеле — адрес устройства туннеля (masquerade), а не адрес Wi-Fi; DNS
# приложений заворачивается к резолверу движка, а тот переспрашивает сервер, к которому шёл
# запрос (адрес из conntrack), и соединение к поддельному адресу уходит к настоящему; то же
# по TCP/53 — заворот, доменный канал, переспрос того же сервера по TCP, конвейер; down
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
# Как netd: NAT раздачи в iptables на восходящий интерфейс. На ядре 4.9 первая сработавшая
# регистрация nat решает судьбу соединения, поэтому masquerade движка обязан жить в той же
# таблице iptables, а не цепочкой nft рядом (см. android_masq_sync в steer.c).
iptables -t nat -A POSTROUTING -o up0 -j MASQUERADE
printf '203.0.113.0/24\n' > $W/p.lst
printf '198.51.100.0/24\n' > $W/q.lst
printf 'example.com\n' > $W/d.lst
cat > $W/local.json <<J
{ "schema": 2, "lan_devices": ["rndis0"],
  "outputs": { "vpn": { "kind": "interface", "device": "wg9", "on_fail": "drop" },
               "vpn2": { "kind": "interface", "device": "wg8", "on_fail": "direct" } },
  "channels": [
    { "name": "app", "from": ["uid:10123"], "match": { "prefixes_files": ["$W/p.lst"] }, "out": "vpn" },
    { "name": "all", "from": ["self"], "match": { "prefixes_files": ["$W/q.lst"] }, "out": "vpn2" },
    { "name": "full", "from": ["uid:10500-10510"], "match": { "any": true, "allow_all": true }, "out": "vpn" },
    { "name": "lan", "match": { "prefixes_files": ["$W/p.lst"] }, "out": "vpn2" },
    { "name": "dom", "from": ["uid:10123"], "match": { "domains_files": ["$W/d.lst"] }, "out": "vpn" } ] }
J
printf 'example.com\n' > $W/d.lst
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

# probe2 UID АДРЕС ПОРТ НАСТОЯЩИЙ — то же, но SYN ищется к НАСТОЯЩЕМУ адресу: соединение к
# поддельному переводится на выходе (nat output) раньше, чем пакет покинет устройство.
probe2() {
    for d in up0 wg9 wg8; do local49-tool watch $d 900 > /tmp/w.$d & done
    sleep 0.3
    local49-tool conn "$1" "$2" "$3"
    wait
    for d in up0 wg9 wg8; do
        sed -n "s/^syn \([0-9.]*\) -> $4:$3$/$d \1/p" /tmp/w.$d
    done | head -1
}

echo "=== 1. приложение из канала по UID"
check "uid 10123 к 203.0.113.9 — в туннель wg9 с адресом туннеля" "wg9 10.77.0.1" "$(probe 10123 203.0.113.9 443)"
echo "=== 2. другое приложение к тому же адресу"
check "uid 10124 к 203.0.113.9 — обычным путём (канал раздачи lan телефон не задевает)" \
    "up0 10.66.0.1" "$(probe 10124 203.0.113.9 443)"
echo "=== 3. self — все, кроме root"
check "uid 10124 к 198.51.100.9 — в wg8" "wg8 10.78.0.1" "$(probe 10124 198.51.100.9 443)"
check "uid 1000 (system) к 198.51.100.9 — обычным путём: self — это приложения" \
    "up0 10.66.0.1" "$(probe 1000 198.51.100.9 443)"
check "root к 198.51.100.9 — обычным путём" "up0 10.66.0.1" "$(probe 0 198.51.100.9 443)"
echo "=== 4. весь трафик приложения (диапазон UID)"
check "uid 10505 к 192.0.2.7 — в wg9" "wg9 10.77.0.1" "$(probe 10505 192.0.2.7 80)"
check "uid 10511 к 192.0.2.7 — вне диапазона, обычным путём" "up0 10.66.0.1" "$(probe 10511 192.0.2.7 80)"
check "uid 10505 к своей сети 192.168.5.5 — не в туннель" "up0 10.66.0.1" "$(probe 10505 192.168.5.5 80)"
check "первое совпадение сверху: uid 10505 к 198.51.100.9 — канал all выше full" \
    "wg8 10.78.0.1" "$(probe 10505 198.51.100.9 443)"
echo "=== 5. DNS приложений: к резолверу движка и дальше — к тому серверу, к которому шли"
# «Сеть» раздаёт DNS с 10.66.0.53 и на любое имя отвечает 203.0.113.77 — настоящим адресом;
# по TCP — 192.0.2.78: так видно, что резолвер движка спросил наверх тоже по TCP. Адрес — вне
# списков каналов по префиксам (203.0.113.0/24 у канала app): в туннель соединение к нему уводит
# только поддельный адрес, то есть только ответ резолвера движка.
# Резолвер движка поднят в режиме origdst: переспрашивает тот сервер, к которому шёл запрос.
modprobe nf_conntrack_netlink 2>/dev/null
ip addr add 10.66.0.53/32 dev up0
dnstool serve 53 203.0.113.77 10.66.0.53 192.0.2.78 & UP=$!
steer dnsd $S --listen-port 5300 --upstream-origdst > /tmp/dnsd.log 2>&1 & DP=$!
sleep 1
fake="$(local49-tool dns 10123 10.66.0.53 example.com)"
check "имя канала у приложения — поддельный адрес" "198.18" "$(echo "$fake" | cut -d. -f1-2)"
check "чужое имя у другого приложения — ответ того самого сервера сети (с его адреса)" \
    "203.0.113.77" "$(local49-tool dns 10124 10.66.0.53 other.example)"
check "имя канала у ДРУГОГО приложения — тоже поддельный (общий кэш DnsResolver)" "198.18" \
    "$(local49-tool dns 10124 10.66.0.53 example.com | cut -d. -f1-2)"
check "запрос root (так шлёт DnsResolver) заворачивается тоже" "198.18" \
    "$(local49-tool dns 0 10.66.0.53 example.com | cut -d. -f1-2)"
check "приложение канала к поддельному адресу — в туннель, к настоящему адресу" \
    "wg9 10.77.0.1" "$(probe2 10123 "$fake" 443 203.0.113.77)"
check "другое приложение к тому же поддельному — напрямую к настоящему" \
    "up0 10.66.0.1" "$(probe2 10124 "$fake" 443 203.0.113.77)"
echo "=== 5б. DNS приложений по TCP/53"
# Новое имя канала по TCP: без заворота ответил бы сам сервер сети (адрес 10.66.0.53 — свой,
# и запрос дошёл бы до него напрямую) настоящим адресом, а не поддельным.
tfake="$(local49-tool dnstcp 10123 10.66.0.53 tcp.example.com)"
check "TCP: имя канала у приложения — поддельный адрес" "198.18" "$(echo "$tfake" | cut -d. -f1-2)"
check "TCP: соединение к нему — в туннель, к адресу из ответа сервера по TCP" \
    "wg9 10.77.0.1" "$(probe2 10123 "$tfake" 443 192.0.2.78)"
check "TCP: чужое имя — ответ того самого сервера сети, спрошенного по TCP" \
    "192.0.2.78" "$(local49-tool dnstcp 10124 10.66.0.53 other.tcp.example)"
check "TCP: запрос root заворачивается тоже" "198.18" \
    "$(local49-tool dnstcp 0 10.66.0.53 root.example.com | cut -d. -f1-2)"
check "TCP: конвейер из двух запросов в одном соединении — оба ответа" "198.18 192.0.2.78" \
    "$(local49-tool dnstcp 10124 10.66.0.53 pipe.example.com pipe.other.example | \
       sed '1s/^\(198\.18\)\..*/\1/' | tr '\n' ' ' | sed 's/ $//')"
check "TCP: повтор имени канала — тот же поддельный адрес" "$tfake" \
    "$(local49-tool dnstcp 10124 10.66.0.53 tcp.example.com)"
kill $DP $UP 2>/dev/null
grep -v 'realip' /tmp/dnsd.log | head -3

echo "=== 6. down"
steer down --state-dir /tmp/st
check "после down цепочек выхода нет" "0" "$(nft list ruleset | grep -c 'output_mark\|output_reroute')"
check "после down uid 10123 — обычным путём" "up0 10.66.0.1" "$(probe 10123 203.0.113.9 443)"
check "после down masquerade движка в iptables снят, правило netd на месте" "1" \
    "$(iptables -t nat -S POSTROUTING | grep -c MASQUERADE)"

printf '\nlocal49: %s passed, %s failed\n' "$pass" "$fail"
[ "$fail" -eq 0 ]
