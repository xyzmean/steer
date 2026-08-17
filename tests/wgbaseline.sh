#!/bin/sh
# Эталон для xsteer: ядерный WireGuard на ТОЙ ЖЕ машине, тем же iperf3, через тот же veth.
#
# Зачем это в репозитории. В этом проекте правило: замер без указания железа замером не
# считается. Сравнивать userspace-туннель с числами из интернета бессмысленно — там другое
# ядро, другой процессор и другой размер пакета. Здесь оба конца на одной машине, и разница
# в числах относится к туннелю, а не к обстановке.
#
# Три числа, и каждое нужно:
#   - veth без туннеля: потолок самого стенда. Выше него не прыгнет ничто, и если туннель
#     упирается в него, значит мерится уже не туннель.
#   - WireGuard во все ядра: то, с чем сравнивают пользователи.
#   - WireGuard на одном ядре: то, что происходит на роутере, где ядро одно. Именно это
#     число сопоставимо с однопоточным прогоном tests/xsbench.c.
#
# Требует root (пространства имён), модуль wireguard, wg, iperf3. Прибирает за собой при
# любом выходе: оставленные пространства имён мешают следующему замеру.
#
#     sudo sh tests/wgbaseline.sh [секунд_на_замер]
set -e
# Права на создаваемые файлы: iperf3 и wg genkey пишут через перенаправление, то есть по
# текущей umask, и без этой строки приватный ключ на мгновение оказывается доступен всем.
# Стенд — не место для привычек, которые потом переезжают в рабочие скрипты.
umask 077

NSA=xsbench-a
NSB=xsbench-b
SECS="${1:-10}"
KEYDIR=

for t in wg ip iperf3; do
    command -v "$t" >/dev/null || { echo "нет $t — замер невозможен"; exit 2; }
done
[ "$(id -u)" = 0 ] || { echo "нужен root: замер делает пространства имён"; exit 2; }

cleanup() {
    ip netns del $NSA 2>/dev/null || true
    ip netns del $NSB 2>/dev/null || true
    if [ -n "$KEYDIR" ]; then rm -rf "$KEYDIR"; fi
    # Возврат нуля обязателен: функция зовётся при живом set -e, и «ложь» от последней
    # проверки означала бы выход из скрипта на собственной уборке. Первая версия так и
    # делала — молча выходила, ничего не измерив.
    return 0
}
trap cleanup EXIT INT TERM
cleanup

# Ключи в каталоге с правами 0700, а не в /tmp по фиксированному имени: приватный ключ,
# доступный кому угодно, — это привычка, которая однажды переедет из стенда в рабочий скрипт.
KEYDIR="$(mktemp -d)"
chmod 700 "$KEYDIR"

ip netns add $NSA
ip netns add $NSB
ip link add veth-a netns $NSA type veth peer name veth-b netns $NSB
ip -n $NSA addr add 10.200.0.1/24 dev veth-a
ip -n $NSB addr add 10.200.0.2/24 dev veth-b
for ns in $NSA $NSB; do ip -n $ns link set lo up; done
ip -n $NSA link set veth-a up
ip -n $NSB link set veth-b up

run_iperf() {   # $1 — адрес, $2 — префикс taskset или пусто
    ip netns exec $NSB iperf3 -s -1 -D --logfile "$KEYDIR/iperf.log" >/dev/null 2>&1
    sleep 0.4
    # shellcheck disable=SC2086
    ip netns exec $NSA $2 iperf3 -c "$1" -t "$SECS" -f m 2>/dev/null \
        | awk '/receiver/ {printf "  %8.2f Гбит/с  (%s)\n", $7/1000, "'"$3"'"}'
    sleep 0.3
}

echo "потолок стенда (veth, MTU 1500, без туннеля):"
run_iperf 10.200.0.2 "" "выше этого не прыгнет ничто"

wg genkey > "$KEYDIR/a.key"
wg genkey > "$KEYDIR/b.key"
chmod 600 "$KEYDIR/a.key" "$KEYDIR/b.key"
PA=$(wg pubkey < "$KEYDIR/a.key")
PB=$(wg pubkey < "$KEYDIR/b.key")

for ns in $NSA $NSB; do ip -n $ns link add wg0 type wireguard; done
ip netns exec $NSA wg set wg0 private-key "$KEYDIR/a.key" listen-port 51820 \
    peer "$PB" allowed-ips 10.201.0.2/32 endpoint 10.200.0.2:51821
ip netns exec $NSB wg set wg0 private-key "$KEYDIR/b.key" listen-port 51821 \
    peer "$PA" allowed-ips 10.201.0.1/32 endpoint 10.200.0.1:51820
ip -n $NSA addr add 10.201.0.1/24 dev wg0
ip -n $NSB addr add 10.201.0.2/24 dev wg0
# MTU туннеля WireGuard: канал минус 60 (20 IP + 8 UDP + 32 WireGuard). У xsteer здесь
# будет 1439 — минус 61, то есть на байт больше накладных и на 11 байт меньше, чем у
# WireGuard поверх поддельного TCP (см. src/ext/xswire.h).
for ns in $NSA $NSB; do ip -n $ns link set wg0 mtu 1440 up; done

sleep 0.5
ip netns exec $NSA ping -c 2 -W 2 10.201.0.2 >/dev/null 2>&1 \
    || { echo "туннель WireGuard не поднялся"; exit 1; }

echo "ядерный WireGuard (ChaCha20-Poly1305, MTU 1440):"
run_iperf 10.201.0.2 "" "все ядра"
run_iperf 10.201.0.2 "taskset -c 2" "одно ядро — как на роутере"

echo
echo "сопоставимо с однопоточным прогоном tests/xsbench.c (шифрование + расшифровка):"
echo "  там оба конца тоже в одном процессе на одном ядре."
