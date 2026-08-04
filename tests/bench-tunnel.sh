#!/bin/sh
# Сколько ПРОЦЕССОРА стоит мегабайт через туннель — и как эта цена зависит от числа
# открытых, но молчащих соединений.
#
# Зачем отдельно от run-tunnel.sh. Тот проверяет, что туннель работает и восстанавливается
# после потерь, и мерит время закачки. На быстрой машине время закачки упирается в сеть
# стенда, а не в нас, и «стало быстрее на роутере» по нему не видно вовсе.
#
# Здесь мерится другое: секунды процессора на мегабайт. Эта величина от скорости стенда не
# зависит и переносится на роутер напрямую — если на мегабайт уходит вдвое меньше такта,
# значит на том же ядре пройдёт вдвое больше мегабайт.
#
# Второй параметр — число молчащих соединений. Именно он воспроизводит слабое место:
# браузер держит соединения живыми между запросами, и каждый виток цикла платил за КАЖДОЕ
# из них, качает оно что-нибудь или нет.
#
# Использование: tests/bench-tunnel.sh [МБ] [молчащих_соединений] [потоков]
set -eu
cd "$(dirname "$0")/.."

MB="${1:-32}"
IDLE="${2:-0}"
STREAMS="${3:-1}"
BIN="${STEER:-./build/steer-ext-check}"
[ -x "$BIN" ] || { echo "нет бинарника: $BIN"; exit 2; }

NS=steer-bench
UUID=8f7d3b1a-2c4e-4f60-9a81-b5d7e6c30124
PORT=10800
WORK="$(mktemp -d)"

cleanup() {
    [ -n "${IDLE_PID:-}" ] && kill "$IDLE_PID" 2>/dev/null || true
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

ip netns exec "$NS" python3 tests/fake-vless.py --port "$PORT" --uuid "$UUID" --mb "$MB" \
    > "$WORK/srv.log" 2>&1 &
SRV_PID=$!
sleep 1

# ОДНО ядро и ОДИН поток: на роутере их столько и есть, а на восьми ядрах разница между
# «цикл дорогой» и «цикл дешёвый» размазывается по свободным ядрам и не видна.
ip netns exec "$NS" taskset -c 0 env STEER_TUN_THREADS=1 "$BIN" vless vl \
    --spec "$WORK/spec.json" --state-dir "$WORK/state" > "$WORK/tun.log" 2>&1 &
TUN_PID=$!

for _ in $(seq 50); do
    ip netns exec "$NS" ip link show vl >/dev/null 2>&1 && break
    sleep 0.2
done
ip netns exec "$NS" ip link show vl >/dev/null 2>&1 || {
    echo "устройство vl не поднялось:"; sed 's/^/  /' "$WORK/tun.log"; exit 1; }

TARGET=203.0.113.7
ip netns exec "$NS" ip route replace "$TARGET/32" dev vl

# Молчащие соединения: открыть и держать. Порт 9 — тот, на котором поддельный сервер
# сознательно молчит (см. fake-vless.py).
if [ "$IDLE" -gt 0 ]; then
    ip netns exec "$NS" python3 - "$TARGET" "$IDLE" > "$WORK/idle.log" 2>&1 <<'PY' &
import socket, sys, time
host, n = sys.argv[1], int(sys.argv[2])
socks = []
for _ in range(n):
    s = socket.socket()
    s.settimeout(10)
    try:
        s.connect((host, 9))
        socks.append(s)
    except OSError as e:
        print("не открылось на %d: %r" % (len(socks), e))
        break
print("держу %d" % len(socks), flush=True)
time.sleep(3600)
PY
    IDLE_PID=$!
    # Ждём, пока они действительно откроются: рукопожатие идёт через пул, и мерить
    # раньше — значит мерить установку, а не цикл.
    for _ in $(seq 100); do
        grep -q '^держу' "$WORK/idle.log" 2>/dev/null && break
        sleep 0.2
    done
    sleep 1
    held=$(sed -n 's/^держу //p' "$WORK/idle.log")
    echo "  молчащих соединений: ${held:-0} из $IDLE"
fi

# Процессорное время процесса — из /proc: utime+stime всех его потоков, в тиках.
cpu_ticks() { awk '{print $14 + $15}' "/proc/$TUN_PID/stat" 2>/dev/null || echo 0; }
HZ=$(getconf CLK_TCK)

t0=$(cpu_ticks)
s=$(date +%s.%N)
pids=""
i=1; while [ "$i" -le "$STREAMS" ]; do
    ( ip netns exec "$NS" wget -q -O "$WORK/dl.$i" -T 180 "http://$TARGET/x" || true ) &
    pids="$pids $!"
    i=$((i+1))
done
for pid in $pids; do wait "$pid" || true; done
e=$(date +%s.%N)
t1=$(cpu_ticks)

want=$((MB * 1024 * 1024))
ok=0; i=1
while [ "$i" -le "$STREAMS" ]; do
    got=$(wc -c < "$WORK/dl.$i" 2>/dev/null || echo 0)
    if [ "$got" = "$want" ]; then ok=$((ok+1)); else echo "    поток $i: $got из $want байт"; fi
    i=$((i+1))
done

awk -v t0="$t0" -v t1="$t1" -v hz="$HZ" -v s="$s" -v e="$e" -v mb="$MB" \
    -v n="$STREAMS" -v ok="$ok" -v idle="$IDLE" 'BEGIN{
  cpu=(t1-t0)/hz; wall=e-s; total=mb*n
  printf "  молчащих %-4d потоков %d: дошло %d/%d, %.1f МБ за %.2f с = %.0f Мбит/с",
         idle, n, ok, n, total, wall, total*8/wall
  printf " | процессор %.2f с = %.1f мс/МБ\n", cpu, cpu*1000/total
  exit (ok==n ? 0 : 1)}'
