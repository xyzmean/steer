#!/bin/sh
# Выход kind=awg на НАСТОЯЩЕМ ядре 4.9 с модулем AmneziaWG: движок поднимает туннель по спеке,
# трафик канала от клиента раздачи уходит в него, status и сторож видят рукопожатие, смена
# файла перенастраивает устройство (поверх или пересозданием, когда поверх нельзя), down его
# снимает.
#
# Зачем стенд, если есть tests/awgns.sh. Там ядро машины разработки и обычный WireGuard (модуля
# AmneziaWG на ней нет). Здесь — ядро телефона по версии (4.9) и тот же исходник модуля
# AmneziaWG, что встроен в ядро телефона (CONFIG_AMNEZIAWG=y, см. /root/vm49/awg/README): только
# так проверяются атрибуты обфускации в той форме, которую ждёт версия 3 семейства, и
# раскладка правил для 4.9 рядом с устройством, которое заводит движок.
#
# Пир — в своём пространстве, настроен утилитой `awg` (amneziawg-tools, независимая реализация
# протокола настройки). Клиент раздачи — в третьем пространстве, 192.168.1.2; канал уводит его
# трафик к 198.51.100.0/24 (адрес за пиром) в выход. masquerade здесь не нужен нарочно: пир
# пускает и 192.168.1.0/24 (его AllowedIPs), так что проверяется маршрутизация и туннель, а не
# трансляция (её ставит iptables, которого в образе стенда нет, — это стенд local49).
#
# Запуск на стенде tools/vm49 хаба splicicd (сборка — как у ctnl49, плюс src/awg.c):
#
#   K=/root/vm49/sysroot/kinc
#   musl-gcc -static -idirafter $K -O2 -DSTEER_ANDROID -o OUT/steer <исходники как в Makefile>
#   A=/root/vm49/awg
#   tools/vm49/vm49.sh run steer/tests/awg49e.sh OUT/steer $A/awg $A/amneziawg.ko \
#       $A/udp_tunnel.ko $A/ip6_udp_tunnel.ko $A/awg49-veth [$A/wireguard.ko $A/wg]
#
# С wireguard.ko и wg сценарий в конце выгружает AmneziaWG и проверяет запасной путь: файл без
# обфускации поднимается модулем wireguard, файл с обфускацией получает внятный отказ.
#
# Роутерную сборку (без -DSTEER_ANDROID) — тем же сценарием: метка сокета туннеля у неё 0, у
# Android-сборки — STEER_SELF_MARK (0x0fc00000); сценарий узнаёт сборку по полю метки выхода.
set -u
pass=0 fail=0
check() {
    if [ "$2" = "$3" ]; then pass=$((pass + 1)); echo "ok   $1"; else
        fail=$((fail + 1)); printf 'FAIL %s\n  expected: %s\n  actual:   %s\n' "$1" "$2" "$3"
    fi
}
uname -r
mkdir -p /data/misc/steer/state /data/misc/steer/tmp /var/lib/steer /tmp/awg
T=/tmp/awg
for m in udp_tunnel ip6_udp_tunnel amneziawg; do
    [ -f "$m.ko" ] && { insmod "$m.ko" || { echo "не загрузился $m.ko"; exit 1; }; }
done
echo 1 > /proc/sys/net/ipv4/ip_forward

# ---- пространства: p — пир, c — клиент раздачи ------------------------------------------
ip netns add p && ip netns add c || { echo "нет сетевых пространств"; exit 1; }
awg49-veth ep0 ep1 && awg49-veth ec0 ec1 || { echo "не создалась пара veth"; exit 1; }
ip link set ep1 netns p; ip link set ec1 netns c
ip addr add 192.0.2.1/24 dev ep0; ip link set ep0 up
ip addr add 192.168.1.1/24 dev ec0; ip link set ec0 up
ip -n p link set lo up; ip -n p addr add 192.0.2.2/24 dev ep1; ip -n p link set ep1 up
ip -n c link set lo up; ip -n c addr add 192.168.1.2/24 dev ec1; ip -n c link set ec1 up
ip -n c route add default via 192.168.1.1
ip -n p addr add 198.51.100.1/32 dev lo

KO=$(awg genkey); PO=$(printf '%s\n' "$KO" | awg pubkey)
KP=$(awg genkey); PP=$(printf '%s\n' "$KP" | awg pubkey)
OBFS="Jc = 4
Jmin = 40
Jmax = 70
S1 = 15
S2 = 18
S3 = 20
S4 = 8
H1 = 100000-100100
H2 = 200000-200100
H3 = 300000
H4 = 400000-400100
I1 = <b 0xdeadbeefcafe0102><r 16>"
{
    printf '[Interface]\nPrivateKey = %s\nListenPort = 51820\n%s\n' "$KP" "$OBFS"
    printf '[Peer]\nPublicKey = %s\nAllowedIPs = 10.77.0.0/24, 192.168.1.0/24\n' "$PO"
} > $T/peer.conf
ip -n p link add wgp type amneziawg
ip netns exec p awg setconf wgp $T/peer.conf || echo "awg setconf пира не прошёл"
ip -n p addr add 10.77.0.1/24 dev wgp
ip -n p link set wgp up
ip -n p route add 192.168.1.0/24 dev wgp
# На входе пира — счётчик пакетов с типом ОБЫЧНОГО WireGuard (первые 4 байта UDP-нагрузки
# 01..04 00 00 00): у туннеля с H1..H4 их быть не должно ни одного.
ip netns exec p nft -f - <<EOF
table inet cnt {
    chain in {
        type filter hook input priority 0;
        udp dport 51820 counter comment "all"
        udp dport 51820 @th,64,32 0x01000000 counter comment "std"
        udp dport 51820 @th,64,32 0x04000000 counter comment "std"
    }
}
EOF
cnt() { ip netns exec p nft list chain inet cnt in | sed -n "s/.*counter packets \([0-9]*\) bytes.*comment \"$1\".*/\1/p" | awk '{n+=$1} END {print n+0}'; }

mkconf() {   # $1 — параметры AmneziaWG, $2 — прочее в [Interface]
    {
        printf '[Interface]\nPrivateKey = %s\nAddress = 10.77.0.2/24\n%s\n%s\n' "$KO" "$1" "${2:-}"
        printf '[Peer]\nPublicKey = %s\nEndpoint = 192.0.2.2:51820\nAllowedIPs = 0.0.0.0/0\n' "$PP"
    } > $T/nl.conf
}
printf '198.51.100.0/24\n' > $T/a.lst
cat > $T/spec.json <<EOF
{ "schema": 2, "from_default": ["192.168.1.0/24"],
  "outputs": { "nl": { "kind": "awg", "conf": "$T/nl.conf", "on_fail": "drop" } },
  "channels": [ { "name": "a", "match": { "prefixes_file": "$T/a.lst" }, "out": "nl" } ] }
EOF
S="--spec $T/spec.json"
st() { steer status $S 2>/dev/null; }
field() { st | grep -o "\"$1\":[^,}]*" | head -1 | cut -d: -f2- | tr -d '"'; }
cping() { ip netns exec c ping -c "${1:-3}" -W 2 -q 198.51.100.1 >$T/ping.out 2>&1; r=$?; [ $r = 0 ] || cat $T/ping.out; return $r; }

# ---- 1. apply ------------------------------------------------------------------------------
mkconf "$OBFS"
steer apply $S >$T/apply.out 2>&1
check "apply проходит" "0" "$?"
grep -E 'awg|warn' $T/apply.out | sed 's/^/     /'
check "устройство nl вида amneziawg" "1" "$(ip -d link show nl 2>/dev/null | grep -c amneziawg)"
check "параметры обфускации на устройстве (awg showconf)" "1" \
      "$(awg showconf nl 2>/dev/null | grep -c '^H1 = 100000-100100$')"
check "I1 на устройстве" "1" "$(awg showconf nl 2>/dev/null | grep -c '^I1 = <b 0xdeadbeefcafe0102><r 16>$')"
check "приватный ключ — из файла" "$KO" "$(awg show nl private-key 2>/dev/null)"
# awg печатает выключенный keepalive нулём (у него это диапазон), wg — словом off.
ka="$(awg show nl persistent-keepalive | cut -f2)"
check "keepalive выключен (батарея)" "1" "$(case "$ka" in 0|off) echo 1;; *) echo "$ka";; esac)"
mark="$(st | grep -o '"mark":"0x[0-9a-f]*"' | head -1 | cut -d'"' -f4)"
# Сборку узнаём по метке единственного выхода: у Android-сборки поле с бита 22 (первая метка
# 0x00400000), у роутерной — с бита 20 (0x00100000).
if [ "$((mark % 0x00400000))" = 0 ]; then
    want_fw=0xfc00000     # Android-сборка: STEER_SELF_MARK
else
    want_fw=off           # роутерная: свой трафик роутера не метится
fi
check "метка сокета туннеля без via ($want_fw)" "$want_fw" "$(awg show nl fwmark)"
check "status: impl" "amneziawg" "$(field impl)"
check "в status ключа нет" "0" "$(st | grep -c "$(printf '%s' "$KO" | cut -c1-20)")"

# ---- 2. трафик канала уходит в туннель -------------------------------------------------
cping 3
check "клиент раздачи → 198.51.100.1 через туннель" "0" "$?"
check "рукопожатие у пира" "1" "$(ip netns exec p awg show wgp latest-handshakes | awk '{print ($2>0)}')"
check "на входе пира ноль пакетов обычного WireGuard" "0" "$(cnt std)"
check "а пакеты туннеля были" "1" "$([ "$(cnt all)" -gt 0 ] && echo 1)"
ago="$(field handshake_ago)"
check "status: рукопожатие (секунд назад — число)" "1" "$(printf '%s' "$ago" | grep -cE '^[0-9]+$')"
check "status: endpoint" "192.0.2.2:51820" "$(field endpoint)"

# ---- 3. сторож -------------------------------------------------------------------------
steer failover $S >$T/fo.out 2>&1
check "сторож: маршрут выхода на месте" "1" "$(ip route show table all | grep -c '^default dev nl table')"
check "сторож: без blackhole" "0" "$(ip route show table all | grep -c 'blackhole')"

# ---- 4. смена файла поверх --------------------------------------------------------------
idx="$(cat /sys/class/net/nl/ifindex)"
mkconf "$OBFS" "MTU = 1380
ListenPort = 51999"
steer apply $S >/dev/null 2>&1
check "перенастроено без пересоздания (тот же ifindex)" "$idx" "$(cat /sys/class/net/nl/ifindex)"
check "ListenPort из нового файла" "51999" "$(awg show nl listen-port)"
check "MTU из нового файла" "1" "$(ip link show nl | grep -c 'mtu 1380')"
cping 2
check "трафик после перенастройки" "0" "$?"

# ---- 5. убран параметр, который поверх не снять — пересоздание --------------------------
OBFS2=$(printf '%s\n' "$OBFS" | grep -v '^I1')
mkconf "$OBFS2"
{   # пир тоже без I1 — сигнатурные пакеты шлёт только инициатор, но держим стороны одинаковыми
    printf '[Interface]\nPrivateKey = %s\nListenPort = 51820\n%s\n' "$KP" "$OBFS2"
    printf '[Peer]\nPublicKey = %s\nAllowedIPs = 10.77.0.0/24, 192.168.1.0/24\n' "$PO"
} > $T/peer.conf
ip netns exec p awg setconf wgp $T/peer.conf
steer apply $S >$T/apply2.out 2>&1
check "убран I1 — устройство пересоздано" "1" "$([ "$(cat /sys/class/net/nl/ifindex)" != "$idx" ] && echo 1)"
check "I1 на устройстве больше нет" "0" "$(awg showconf nl 2>/dev/null | grep -c '^I1')"
cping 3
check "трафик после пересоздания" "0" "$?"

# ---- 5a. via: UDP туннеля — через выход-интерфейс ---------------------------------------
# Второй путь к пиру — ux0, устройство выхода kind=interface. Endpoint — адрес на петле пира,
# до которого без метки маршрута нет: дойти туда UDP туннеля может только меткой выхода ux,
# через его таблицу и ux0 (см. «вложенные выходы» в spec.h). На ядре 4.9 это проверяет, что
# WireGuard ставит метку устройства на свои датаграммы и ip rule движка их уводит.
awg49-veth ux0 ux1 || echo "не создалась пара veth ux"
ip link set ux1 netns p
ip addr add 10.78.0.1/24 dev ux0; ip link set ux0 up
ip -n p addr add 10.78.0.2/24 dev ux1; ip -n p link set ux1 up
ip -n p addr add 203.0.113.9/32 dev lo
ip -n p addr add 1.1.1.1/32 dev lo      # адрес пробы сторожа — за ux0, иначе ux «мёртв» всегда
mkconf "$OBFS2"
sed -i 's/^Endpoint = .*/Endpoint = 203.0.113.9:51820/' $T/nl.conf
cat > $T/spec.json <<EOF
{ "schema": 2, "from_default": ["192.168.1.0/24"],
  "outputs": { "ux": { "kind": "interface", "device": "ux0", "on_fail": "drop" },
               "nl": { "kind": "awg", "conf": "$T/nl.conf", "device": "nl", "via": "ux",
                       "on_fail": "drop" } },
  "channels": [ { "name": "a", "match": { "prefixes_file": "$T/a.lst" }, "out": "nl" } ] }
EOF
steer apply $S >$T/apply5.out 2>&1
check "via: apply проходит" "0" "$?"
omark() { st | grep -o "\"$1\":{[^}]*" | grep -o '"mark":"0x[0-9a-f]*"' | cut -d'"' -f4; }
check "via: метка сокета туннеля — метка выхода ux" "$(printf '0x%x' "$(($(omark ux)))")" \
      "$(awg show nl fwmark)"
cping 3
check "via: клиент раздачи → 198.51.100.1 через awg, awg — через ux" "0" "$?"
check "via: пир видит нас с адреса ux0" "10.78.0.1" \
      "$(ip netns exec p awg show wgp endpoints | cut -f2 | cut -d: -f1)"
nlt="$(st | grep -o '"nl":{[^}]*' | grep -o '"table":[0-9]*' | cut -d: -f2)"
steer failover $S >$T/fo5.out 2>&1
check "via: ux жив — nl в работе" "1" "$(ip route show table "$nlt" | grep -c 'default dev nl')"
ip link set ux0 down
steer failover $S >$T/fo5.out 2>&1
check "via: ux лёг — nl объявлен нерабочим" "1" "$(grep -c 'выход nl: идёт через ux' $T/fo5.out)"
check "via: у nl blackhole" "1" "$(ip route show table "$nlt" | grep -c blackhole)"
ip link set ux0 up
steer failover $S >$T/fo5.out 2>&1
check "via: ux ожил — nl вернулся" "1" "$(ip route show table "$nlt" | grep -c 'default dev nl')"
cping 3
check "via: трафик после возврата ux" "0" "$?"
# Дальше — прежняя спека без via: часть 7 проверяет свои вещи, и via ей ни к чему.
cat > $T/spec.json <<EOF
{ "schema": 2, "from_default": ["192.168.1.0/24"],
  "outputs": { "nl": { "kind": "awg", "conf": "$T/nl.conf", "on_fail": "drop" } },
  "channels": [ { "name": "a", "match": { "prefixes_file": "$T/a.lst" }, "out": "nl" } ] }
EOF

# ---- 6. down ---------------------------------------------------------------------------
steer down >/dev/null 2>&1
check "down: устройство снято" "0" "$(ip link show nl 2>/dev/null | grep -c 'nl:')"
check "down: пир не тронут" "1" "$(ip -n p link show wgp | grep -c wgp)"

# ---- 7. без модуля AmneziaWG: запасной wireguard и внятный отказ ------------------------
# Только если переданы wireguard.ko и wg (WireGuard из дерева ядра телефона, собранный под ядро
# стенда). AmneziaWG выгружается — так выглядит ядро, где его нет.
if [ -f wireguard.ko ] && [ -x wg ]; then
    ip -n p link del wgp
    rmmod amneziawg && insmod wireguard.ko || echo "смена модулей не прошла"
    grep -E '^(amneziawg|wireguard) ' /proc/modules | cut -d' ' -f1 | sed 's/^/     модуль: /'
    {
        printf '[Interface]\nPrivateKey = %s\nListenPort = 51820\n' "$KP"
        printf '[Peer]\nPublicKey = %s\nAllowedIPs = 10.77.0.0/24, 192.168.1.0/24\n' "$PO"
    } > $T/peer.conf
    ip -n p link add wgq type wireguard
    ip netns exec p wg setconf wgq $T/peer.conf
    ip -n p addr add 10.77.0.1/24 dev wgq
    ip -n p link set wgq up
    ip -n p route replace 192.168.1.0/24 dev wgq
    mkconf "H1 = 1
H2 = 2
H3 = 3
H4 = 4"
    steer apply $S >$T/apply3.out 2>&1
    check "без AmneziaWG: файл без обфускации поднят модулем wireguard" "1" \
          "$(ip -d link show nl 2>/dev/null | grep -c ' wireguard ')"
    check "status: impl wireguard" "wireguard" "$(field impl)"
    cping 3
    check "без AmneziaWG: трафик канала через wireguard" "0" "$?"
    mkconf "$OBFS"
    sed -i 's/"nl"/"nl2"/; s/"out": "nl"/"out": "nl2"/' $T/spec.json
    steer apply $S >$T/apply4.out 2>&1
    check "обфускация без модуля — отказ назван" "1" "$(grep -c 'нет модуля AmneziaWG' $T/apply4.out)"
    check "устройство nl2 не создано" "0" "$(ip link show nl2 2>/dev/null | grep -c nl2)"
    check "устройство убранного выхода nl снято" "0" "$(ip link show nl 2>/dev/null | grep -c 'nl:')"
    steer down >/dev/null 2>&1
fi

dmesg | grep -E 'BUG|WARNING|Oops' | head -5
check "в журнале ядра нет BUG/WARNING/Oops" "0" "$(dmesg | grep -cE 'BUG|WARNING|Oops')"
echo "awg49e: $pass passed, $fail failed"
[ "$fail" -eq 0 ]
