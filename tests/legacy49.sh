#!/bin/sh
# steer в раскладке для старого ядра — на НАСТОЯЩЕМ Linux 4.9: загрузка, подмены, резолвер, nat.
#
# Запускается не из `make test`, а на стенде tools/vm49 хаба splicicd (QEMU с ядром 4.9 из
# Debian stretch, initramfs со свежим nft). Бинарники — статические, собранные musl-gcc с
# заголовками ядра стенда:
#
#   K=/root/vm49/sysroot/kinc
#   musl-gcc -static -idirafter $K -O2 -o /tmp/steer src/*.c   # набор файлов — как в Makefile
#   musl-gcc -static -idirafter $K -O2 -o /tmp/dnstool tests/legacy49-dnstool.c
#   musl-gcc -static -idirafter $K -O2 -o /tmp/tuntool tests/legacy49-tuntool.c
#   tools/vm49/vm49.sh run steer/tests/legacy49.sh /tmp/steer /tmp/dnstool /tmp/tuntool
#
# Код выхода 0 — всё прошло, 1 — есть провалы. В конце печатается `nft list
# ruleset` полной спеки: его стоит сравнить с тем же на свежем ядре, потому что 4.9 молча
# выбрасывает незнакомые атрибуты netlink и может загрузить ДРУГОЕ правило без ошибки.
#
# Что проверяется: проба ядра выбирает старую раскладку сама; полная спека (домены, zapret,
# мост Telegram, failopen, сужение по портам, MAC, traceroute_hops) грузится; legacy-min
# (ровно то, что умеет ядро телефона) грузится и переключается той же транзакцией; explain
# работает без `nft get element`; клиент, вошедший через TUN как из LAN, получает от резолвера
# поддельный адрес через заворот DNS, доходит по dnat из карты и перехватывается мостом — всё
# одной цепочкой nat. И контроль: две цепочки nat на одном хуке, как в современной раскладке,
# на 4.9 не работают (dnat второй цепочки не срабатывает) — ради этого цепочка одна.
set -u
pass=0 fail=0
check() {
    if [ "$2" = "$3" ]; then pass=$((pass + 1)); echo "ok   $1"; else
        fail=$((fail + 1)); printf 'FAIL %s\n  expected: %s\n  actual:   %s\n' "$1" "$2" "$3"
    fi
}
steer --version
uname -r
printf '203.0.113.0/24\n' > /work/a.lst
printf 'example.com\n' > /work/d.lst
printf '198.51.100.0/24\n' > /work/p.lst
printf '104.16.0.0/12\n' > /work/dc.lst
cat > /work/full.json <<'J'
{ "schema": 2, "traceroute_hops": true, "from_default": ["10.99.0.0/24"],
  "outputs": { "direct": { "kind": "direct" },
    "vpn": { "kind": "interface", "device": "applynft0", "on_fail": "direct" },
    "vpn2": { "kind": "interface", "device": "applynft1" },
    "yt": { "kind": "zapret" }, "dis": { "kind": "zapret", "on_fail": "direct" },
    "tg": { "kind": "tgws", "domain": "ex.co.uk" } },
  "channels": [
    { "name": "tv", "from": ["a4:83:e7:2c:11:0f"], "match": { "any": true, "allow_all": true }, "out": "vpn2" },
    { "name": "blk", "match": { "prefixes_file": "/work/a.lst" }, "out": "vpn" },
    { "name": "dom", "match": { "domains_files": ["/work/d.lst"], "prefixes_files": ["/work/p.lst"] }, "out": "vpn" },
    { "name": "rip", "match": { "domains_files": ["/work/d.lst"], "mode": "realip" }, "out": "vpn2" },
    { "name": "disc", "match": { "prefixes_files": ["/work/dc.lst"], "proto": "udp", "ports": ["50000-65535", "19000-20000"] }, "out": "vpn" },
    { "name": "z", "match": { "prefixes_file": "/work/a.lst" }, "out": "yt" },
    { "name": "z2", "match": { "domains_files": ["/work/d.lst"] }, "out": "dis" },
    { "name": "t", "match": { "prefixes_files": ["/work/dc.lst"] }, "out": "tg" } ] }
J
S="--spec /work/full.json --state-dir /tmp/st"

echo "=== 1. проба ядра без подсказки"
steer apply $S --dry-run > /tmp/dry.nft 2>/tmp/dry.err; echo "dry-run код $?"
cat /tmp/dry.err | grep -v 'realip уходит'
check "проба выбрала старую раскладку" "1" "$(grep -c 'nftables старого ядра' /tmp/dry.err)"
check "таблица ip в тексте" "1" "$(grep -c '^table ip steer {' /tmp/dry.nft)"
check "таблица ip6 в тексте (nat в ip6 у этого ядра есть)" "1" "$(grep -c '^table ip6 steer {' /tmp/dry.nft)"
check "notrack у этого ядра есть — predefrag на месте" "1" "$(grep -c 'chain zapret_predefrag {' /tmp/dry.nft)"

echo "=== 2. apply полной спеки"
steer apply $S 2>&1 | grep -v 'realip уходит\|no masquerade\|not mentioned\|traceroute_hops\|untracked'; rc=$?
check "apply полной спеки" "0" "$(steer apply $S >/dev/null 2>&1; echo $?)"
nft list ruleset > /tmp/live.nft
check "в ядре нет подмены frag: frag frag-off >= 0" "1" "$(grep -c 'frag frag-off >= 0 notrack' /tmp/live.nft)"
check "в ядре нет exthdr frag exists / nexthdr icmp" "0" "$(grep -c 'nexthdr icmp\|unknown-exthdr' /tmp/live.nft)"

echo "=== 3. legacy-min (как ядро телефона: без notrack и nat в ip6)"
STEER_NFT_COMPAT=legacy-min steer apply $S >/dev/null 2>/tmp/min.err
check "legacy-min apply" "0" "$?"
check "legacy-min: predefrag нет" "0" "$(nft list ruleset | grep -c zapret_predefrag)"
check "legacy-min: таблицы ip6 нет (удалена той же транзакцией)" "0" "$(nft list tables | grep -c 'ip6 steer')"
grep 'notrack\|IPv6' /tmp/min.err
steer apply $S >/dev/null 2>&1
check "обратно в полную старую раскладку" "1" "$(nft list tables | grep -c 'ip6 steer')"

echo "=== 4. explain без nft get element"
cat > /work/ex.json <<'J'
{ "schema": 2, "from_default": ["10.99.0.0/24"],
  "outputs": { "vpn": { "kind": "interface", "device": "applynft0", "on_fail": "direct" } },
  "channels": [ { "name": "blk", "match": { "prefixes_file": "/work/a.lst" }, "out": "vpn" },
    { "name": "dom", "match": { "domains_files": ["/work/d.lst"], "prefixes_files": ["/work/p.lst"] }, "out": "vpn" } ] }
J
E="--spec /work/ex.json --state-dir /tmp/ex"
steer apply $E >/dev/null 2>&1; echo "apply код $?"
nft get element inet steer vpn_dom_n '{ 198.51.100.9 }' >/dev/null 2>&1; echo "nft get element код $?"
steer explain 198.51.100.9 $E 2>&1 | head -3
check "explain нашёл адрес в половине _n" "1" "$(steer explain 198.51.100.9 $E 2>/dev/null | grep -c '"vpn_dom" -> output "vpn"')"
check "explain нашёл адрес второго списка той же группы" "1" "$(steer explain 203.0.113.9 $E 2>/dev/null | grep -c '"vpn_dom" -> output "vpn"')"
check "explain не нашёл чужой адрес" "0" "$(steer explain 192.0.2.1 $E 2>/dev/null | grep -c 'output')"

echo "=== 5. резолвер и nat: клиент входит через TUN, как из LAN"
printf 'example.com\n' > /work/d2.lst
cat > /work/fn.json <<'J'
{ "schema": 2, "from_default": ["10.99.0.0/24"],
  "outputs": { "vpn": { "kind": "interface", "device": "applynft0", "on_fail": "direct" },
               "tg": { "kind": "tgws", "domain": "ex.co.uk" } },
  "channels": [ { "name": "d", "match": { "domains_files": ["/work/d2.lst"] }, "out": "vpn" },
                { "name": "t", "match": { "prefixes_files": ["/work/dc.lst"] }, "out": "tg" } ] }
J
F="--spec /work/fn.json --state-dir /tmp/fn"
steer apply $F >/dev/null 2>&1; echo "apply код $?"
dnstool serve 15363 10.99.0.1 & UP=$!
steer dnsd $F --listen-port 5300 --upstream-port 15363 >/tmp/dnsd.log 2>&1 & DP=$!
sleep 1
ans="$(tuntool dns example.com)"
echo "ответ клиенту на запрос к 1.1.1.1:53: $ans"
fake="$(echo "$ans" | cut -d' ' -f1)"
check "запрос DNS клиента завёрнут на резолвер" "198.18" "$(echo "$fake" | cut -d. -f1-2)"
check "карта fakeip в таблице ip получила элемент" "1" "$(nft list map ip steer fakeip | grep -c "$fake : 10.99.0.1")"
check "hash-набор канала получил поддельный адрес" "1" "$(nft list set inet steer vpn_dom | grep -c "elements = { $fake")"
nc -l -p 8080 >/dev/null 2>&1 & NC=$!
sleep 0.3
syn="$(tuntool syn "$fake" 8080)"
echo "SYN на $fake:8080: $syn"
check "SYN на поддельный адрес доехал по dnat из карты (ответ от него же)" "synack от $fake:8080" "$syn"
kill $NC 2>/dev/null
# Мост Telegram — третье правило той же цепочки: помеченный SYN на 443 к адресу ДЦ уходит на
# порт моста (8480 + место выхода). Слушатель на порту моста отвечает SYN-ACK.
port="$(nft list chain ip steer prerouting_nat | sed -n 's/.*redirect to :\(84[0-9][0-9]\).*/\1/p')"
nc -l -p "$port" >/dev/null 2>&1 & NC=$!
sleep 0.3
syn="$(tuntool syn 104.16.0.1 443)"
echo "SYN на 104.16.0.1:443 (порт моста $port): $syn"
check "перехват моста срабатывает после правил DNS и fakeip" "synack от 104.16.0.1:443" "$syn"
kill $NC 2>/dev/null
nft list chain ip steer prerouting_nat
grep -v 'realip' /tmp/dnsd.log | head -5

echo "=== 6. контроль: три цепочки nat на одном хуке, как в современной раскладке"
nft delete table ip steer
cat > /tmp/three.nft <<T
table ip three {
    map fakeip {
        type ipv4_addr : ipv4_addr
        elements = { $fake : 10.99.0.1 }
    }
    chain prerouting_dns {
        type nat hook prerouting priority -100; policy accept;
        ip saddr 10.99.0.0/24 udp dport 53 counter redirect to :5300
    }
    chain prerouting_dnat {
        type nat hook prerouting priority -100; policy accept;
        ip daddr 198.18.0.0/15 counter dnat to ip daddr map @fakeip
    }
}
T
nft -f /tmp/three.nft; echo "загрузка кода $?"
nc -l -p 8080 >/dev/null 2>&1 & NC=$!
sleep 0.3
syn="$(tuntool syn "$fake" 8080 40002)"
echo "три цепочки: SYN на $fake:8080 -> $syn"
nft list table ip three | grep counter
kill $NC $DP $UP 2>/dev/null
nft delete table ip three

echo "=== ruleset полной спеки (для сверки с тем же текстом на свежем ядре)"
echo "---BEGIN---"
cat /tmp/live.nft
echo "---END---"
printf '\nlegacy49: %s passed, %s failed\n' "$pass" "$fail"
[ "$fail" -eq 0 ]
