#!/bin/sh
# Прогон ЦЕЛОГО туннеля на локальном стенде: без узла подписки и без интернета.
#
# Что здесь проверяется и почему только так. Синтез TCP, повторная передача и раскладка
# соединений по потокам живут только на настоящем трафике — модульным тестом их не достать.
# Пока трафик брался у узла подписки, каждая проверка зависела от чужого сервера: «не
# восстановилось после потерь» было не отличить от «узел лёг», и дважды именно на этом всё и
# остановилось.
#
# Стенд: своё сетевое пространство, в нём поддельный сервер VLESS на 127.0.0.1 (tests/
# fake-vless.py), поднятый steer туннель и wget как клиент. Потери вносятся правилом nft на
# ВХОДЕ с устройства туннеля — то есть теряются ровно те пакеты, которые синтезировали мы.
#
# Использование: tests/run-tunnel.sh [потери_в_процентах] [потоков]
set -eu
cd "$(dirname "$0")/.."

LOSS="${1:-0}"
STREAMS="${2:-1}"
# Восемь мегабайт, а не двадцать: стенд проверяет ВОССТАНОВЛЕНИЕ, а не скорость, и
# двадцать здесь ехали бы долго по причине, к туннелю не относящейся. Клиент на стенде
# локальный, поэтому наш сегмент в 18 КБ приходит ему ОДНИМ сегментом, а не тринадцатью, и
# его ядро придерживает подтверждение отложенным таймером. На настоящей сети сегмент
# нарезается, подтверждения идут густо, и этого замедления нет.
MB=8
BIN="${STEER:-./build/steer-ext-check}"
[ -x "$BIN" ] || { echo "нет бинарника: $BIN (собери extended)"; exit 2; }

NS=steer-tunnel
UUID=8f7d3b1a-2c4e-4f60-9a81-b5d7e6c30124
PORT=10800
WORK="$(mktemp -d)"

cleanup() {
    [ -n "${SRV_PID:-}" ] && kill "$SRV_PID" 2>/dev/null || true
    [ -n "${TUN_PID:-}" ] && kill "$TUN_PID" 2>/dev/null || true
    ip netns pids "$NS" 2>/dev/null | xargs -r kill 2>/dev/null || true
    ip netns delete "$NS" 2>/dev/null || true
    rm -rf "$WORK"
}
trap cleanup EXIT INT TERM

printf '%s\n' "vless://$UUID@127.0.0.1:$PORT?security=none&type=tcp#local" > "$WORK/sub.txt"
cat > "$WORK/spec.json" <<SPEC
{"schema":1,
 "outputs":{"vl":{"name":"vl","kind":"vless","sub_file":"$WORK/sub.txt","node":0}},
 "channels":[]}
SPEC

ip netns delete "$NS" 2>/dev/null || true
ip netns add "$NS"
ip netns exec "$NS" ip link set lo up

# Сервер и туннель — внутри пространства: сервер слушает на 127.0.0.1, туннель туда и ходит.
ip netns exec "$NS" python3 tests/fake-vless.py --port "$PORT" --uuid "$UUID" --mb "$MB" \
    > "$WORK/srv.log" 2>&1 &
SRV_PID=$!
sleep 1

ip netns exec "$NS" env STEER_TUN_STATS=1 "$BIN" vless vl \
    --spec "$WORK/spec.json" --state-dir "$WORK/state" > "$WORK/tun.log" 2>&1 &
TUN_PID=$!

# Ждём появления устройства, а не спим наугад: подъём занимает разное время.
for _ in $(seq 50); do
    ip netns exec "$NS" ip link show vl >/dev/null 2>&1 && break
    sleep 0.2
done
if ! ip netns exec "$NS" ip link show vl >/dev/null 2>&1; then
    echo "устройство vl не поднялось:"; sed 's/^/  /' "$WORK/tun.log"; exit 1
fi
sed -n 's/^/  /p' "$WORK/tun.log" | grep -iE "разгрузк|потоков" || true

# Куда угодно, кроме localhost: адрес поддельному серверу не важен, важно попасть в туннель.
TARGET=203.0.113.7
ip netns exec "$NS" ip route replace "$TARGET/32" dev vl

if [ "$LOSS" != 0 ]; then
    ip netns exec "$NS" nft add table inet loss
    ip netns exec "$NS" nft add chain inet loss input \
        '{ type filter hook input priority -300; policy accept; }'
    ip netns exec "$NS" nft add rule inet loss input iifname vl \
        numgen random mod 100 lt "$LOSS" counter drop
fi

# Ждём ТОЛЬКО закачки. Голый `wait` ждал бы ещё сервер и туннель — а они не завершаются
# никогда, и прогон висел до внешнего таймаута, выглядя как зависший туннель.
#
# Скачиваем В ФАЙЛ и сверяем размер: «код возврата 0» без проверки длины однажды уже
# показал 3200 Мбит/с за ноль секунд, то есть измерил не то.
s=$(date +%s.%N)
pids=""
i=1; while [ "$i" -le "$STREAMS" ]; do
    ( ip netns exec "$NS" wget -q -O "$WORK/dl.$i" -T 120 "http://$TARGET/x" || true ) &
    pids="$pids $!"
    i=$((i+1))
done
for pid in $pids; do wait "$pid" || true; done
e=$(date +%s.%N)

want=$((MB * 1024 * 1024))
ok=0; i=1
while [ "$i" -le "$STREAMS" ]; do
    got=$(wc -c < "$WORK/dl.$i" 2>/dev/null || echo 0)
    if [ "$got" = "$want" ]; then ok=$((ok+1)); else echo "    поток $i: $got из $want байт"; fi
    i=$((i+1))
done
dropped=0
[ "$LOSS" != 0 ] && dropped=$(ip netns exec "$NS" nft list table inet loss 2>/dev/null |
    sed -n 's/.*packets \([0-9]*\).*/\1/p' | head -1)

echo "  повторов у туннеля:"
grep -o 'повторов [0-9]*/с ([0-9.]* КБ/с)' "$WORK/tun.log" 2>/dev/null |
    grep -v 'повторов 0/с' | sort -u | tail -2 | sed 's/^/    /' || true
# Какие потоки реально работали: «стало быстрее» и «всё село в одну очередь» в остальных
# числах выглядят одинаково.
busy=$(grep -o '^tun-stats\[[0-9]\]' "$WORK/tun.log" 2>/dev/null | sort -u | tr -d 'tun-satsm[]' | tr '\n' ' ')
work=$(grep '^tun-stats' "$WORK/tun.log" 2>/dev/null | grep -v ' 0.0 МБ/с ' |
    grep -o '^tun-stats\[[0-9]\]' | sort -u | wc -l)
echo "  потоков с трафиком: $work (всего отчитывалось: $busy)"

awk -v s="$s" -v e="$e" -v ok="$ok" -v n="$STREAMS" -v mb="$MB" -v l="$LOSS" -v d="${dropped:-0}" 'BEGIN{
  t=e-s
  printf "  потери %s%%, потоков %s: дошло %d/%d за %.1f с", l, n, ok, n, t
  if (ok==n) printf " = %.0f Мбит/с", n*mb*8/t
  printf ", отброшено %s\n", d
  exit (ok==n ? 0 : 1)}'
