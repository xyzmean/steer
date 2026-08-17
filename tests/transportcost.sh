#!/bin/sh
# Чем платит транспорт: сырой сокет против TUN. Что именно меряется и чего этот стенд НЕ
# решает — в шапке tests/transportcost.c.
#
# Зачем он есть. Вопрос «а с TUN было бы быстрее» возникает каждый раз, когда кто-то видит
# сырой сокет, и без чисел на него отвечают верой. Числа получаются за минуту, а вера живёт
# годами.
#
# Требует root (пространства имён и сырые сокеты) и /dev/net/tun. В make test не входит.
#
#     sudo sh tests/transportcost.sh
set -u
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
BIN=build/transportcost
NSA=tc-a
NSB=tc-b

cd "$ROOT" || exit 2
[ "$(id -u)" = 0 ] || { echo "нужен root"; exit 2; }
[ -c /dev/net/tun ] || { echo "нет /dev/net/tun"; exit 2; }

cleanup() {
    ip netns del $NSA 2>/dev/null
    ip netns del $NSB 2>/dev/null
}
trap cleanup EXIT INT TERM
cleanup

cc -O2 -Wall -Wextra -o "$BIN" tests/transportcost.c || exit 1

ip netns add $NSA
ip netns add $NSB
ip link add tca0 netns $NSA type veth peer name tcb0 netns $NSB
ip netns exec $NSA sh -c "ip addr add 10.90.0.1/24 dev tca0; ip link set tca0 up; ip link set lo up"
ip netns exec $NSB sh -c "ip addr add 10.90.0.2/24 dev tcb0; ip link set tcb0 up; ip link set lo up"

echo "== отправка: пакет обязан реально уйти соседу"
before=$(ip netns exec $NSB cat /sys/class/net/tcb0/statistics/rx_packets)
ip netns exec $NSA "./$BIN" tx 10.90.0.2
after=$(ip netns exec $NSB cat /sys/class/net/tcb0/statistics/rx_packets)
# Без этой сверки любой из способов может оказаться быстрым просто потому, что его пакеты
# отбрасываются на первом же шаге. Ровно так и вышло при первом прогоне: у TUN был неверный
# заголовок, ядро считало IpInHdrErrors, а стенд показывал «TUN вдвое быстрее».
echo "   дошло до соседа: $((after - before)) пакетов (ожидается 4 прогона по 300000)"

echo
echo "== приём: счёт процессора всей системы на 200000 пакетов"
cpu() { awk '/^cpu /{print $2+$3+$4+$6+$7+$8}' /proc/stat; }
rxrun() {
    ip netns exec $NSA sh -c "nft flush ruleset 2>/dev/null; ip link del rxt0 2>/dev/null;
                              conntrack -F 2>/dev/null; true"
    timeout 40 ip netns exec $NSA "./$BIN" "$1" 200000 ${2:-} > /tmp/tc.$1.out 2>&1 &
    rp=$!
    sleep 1
    a=$(cpu)
    timeout 30 ip netns exec $NSB "./$BIN" send 10.90.0.1 200000 >/dev/null 2>&1
    wait $rp 2>/dev/null
    b=$(cpu)
    printf '   %-18s %s\n' "$1${2:+ x$2}" "$(cat /tmp/tc.$1.out)"
    printf '   %-18s система %s тиков = %s мкс/пакет\n' "" "$((b - a))" \
        "$(awk -v t="$((b - a))" 'BEGIN{printf "%.1f", t*10000/200000}')"
}
rxrun raw 1
rxrun tun
rxrun pkt 1
rxrun pkt 4
