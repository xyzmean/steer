#!/bin/sh
# I-319: клиент закрывает свою половину (FIN), не дождавшись ответа, — nc -q0, HTTP/1.0,
# любой half-close после запроса. Часто FIN едет В ОДНОМ СЕГМЕНТЕ с хвостом запроса.
#
# Туннель обязан: отдать хвост серверу, подтвердить его вместе с FIN (ack = seq+данные+1) и
# донести клиенту ответ, пришедший уже после его FIN. Сервер стенда (fake-vless.py, порт 7)
# отвечает только на дочитанную строку, так что потерянный хвост виден как пустой ответ.
#
# Три случая, потому что это три разные дорожки в handle_packet:
#   ready    — FIN с данными одним сегментом, поток к узлу уже готов;
#   early    — то же сразу после рукопожатия, пока поток к узлу ещё открывается;
#   separate — данные и FIN разными сегментами;
#   silent   — сервер (порт 9) не отвечает и не закрывает: соединение обязано закрыться
#              само за CLOSE_DRAIN_MS, а не висеть до уборки по простою.
# Что FIN и данные действительно шли одним сегментом, считает правило nft на выходе в vl.
#
# Использование: tests/run-tunnel-fin.sh   (нужен root: своё сетевое пространство)
#   STEER=<бинарник>      по умолчанию ./build/steer-ext-check
#   TRACE=1               журнал разбора пакетов туннеля (печатается при провале)
#   STEER_PRELOAD=<.so>   подгрузить в движок библиотеку — для сборки на glibc, где потокам
#                         установщика не хватает стека под __thread-буферы (см. отчёт I-319)
set -eu
cd "$(dirname "$0")/.."

BIN="${STEER:-./build/steer-ext-check}"
[ -x "$BIN" ] || { echo "нет бинарника: $BIN (собери extended)"; exit 2; }

NS=steer-tunfin
UUID=8f7d3b1a-2c4e-4f60-9a81-b5d7e6c30124
PORT=10800
NODE=10.66.0.1
TARGET=203.0.113.7
WORK="$(mktemp -d)"

cleanup() {
    [ -n "${SRV_PID:-}" ] && kill "$SRV_PID" 2>/dev/null || true
    [ -n "${TUN_PID:-}" ] && kill "$TUN_PID" 2>/dev/null || true
    ip netns pids "$NS" 2>/dev/null | xargs -r kill 2>/dev/null || true
    ip netns delete "$NS" 2>/dev/null || true
    rm -rf "$WORK"
}
trap cleanup EXIT INT TERM

printf '%s\n' "vless://$UUID@$NODE:$PORT?security=none&type=tcp#local" > "$WORK/sub.txt"
cat > "$WORK/spec.json" <<SPEC
{"schema":1,
 "outputs":{"vl":{"name":"vl","kind":"vless","sub_file":"$WORK/sub.txt","node":0}},
 "channels":[]}
SPEC

ip netns delete "$NS" 2>/dev/null || true
ip netns add "$NS"
ip netns exec "$NS" ip link set lo up
ip netns exec "$NS" ip link add stand type dummy
ip netns exec "$NS" ip addr add "$NODE/32" dev stand
ip netns exec "$NS" ip link set stand up

ip netns exec "$NS" python3 tests/fake-vless.py --port "$PORT" --uuid "$UUID" --mb 1 --bind "$NODE" \
    > "$WORK/srv.log" 2>&1 &
SRV_PID=$!
sleep 1

# Без запасных сессий: иначе и «early» получает готовый поток и дорожка «пока поток
# открывается» не проверяется вовсе.
ip netns exec "$NS" env STEER_TUN_SPARES=0 ${TRACE:+STEER_TUN_TRACE=1} \
    ${STEER_PRELOAD:+LD_PRELOAD=$STEER_PRELOAD} "$BIN" vless vl --spec "$WORK/spec.json" --state-dir "$WORK/state" \
    > "$WORK/tun.log" 2>&1 &
TUN_PID=$!
for _ in $(seq 50); do
    ip netns exec "$NS" ip link show vl >/dev/null 2>&1 && break
    sleep 0.2
done
ip netns exec "$NS" ip link show vl >/dev/null 2>&1 ||
    { echo "устройство vl не поднялось:"; sed 's/^/  /' "$WORK/tun.log"; exit 1; }
ip netns exec "$NS" ip route replace "$TARGET/32" dev vl

# Сегменты клиента с FIN и данными: ip-длина больше голого заголовка с опциями (20+32).
ip netns exec "$NS" nft add table inet fin
ip netns exec "$NS" nft add chain inet fin out '{ type filter hook output priority 0; policy accept; }'
ip netns exec "$NS" nft add rule inet fin out oifname vl 'tcp flags & fin == fin' ip length gt 64 counter

fail=0
for mode in ready early separate silent; do
    before=$(ip netns exec "$NS" nft list chain inet fin out | sed -n 's/.*packets \([0-9]*\).*/\1/p')
    got=$(ip netns exec "$NS" python3 - "$TARGET" "$mode" <<'PY'
import socket, sys, time
host, mode = sys.argv[1], sys.argv[2]
line = b"i319-" + mode.encode() + b"-" + b"x" * 3000 + b"\n"
s = socket.create_connection((host, 9 if mode == "silent" else 7), timeout=10)
if mode != "early":
    time.sleep(0.5)                      # поток к узлу успевает открыться
if mode == "separate":
    s.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
    s.sendall(line)
    time.sleep(0.3)
else:
    # CORK: ядро склеивает хвост данных и FIN в один сегмент.
    s.setsockopt(socket.IPPROTO_TCP, socket.TCP_CORK, 1)
    s.sendall(line)
s.shutdown(socket.SHUT_WR)
buf = b""
try:
    while True:
        c = s.recv(65536)
        if not c:
            break
        buf += c
except OSError as e:
    print("ошибка: %r" % e, file=sys.stderr)
    buf = None
ok = buf == (b"" if mode == "silent" else b"ECHO " + line)
print("ok" if ok else "нет конца потока за 10 с" if buf is None else
      "получено %d байт вместо %d" % (len(buf), len(line) + 5))
PY
)
    after=$(ip netns exec "$NS" nft list chain inet fin out | sed -n 's/.*packets \([0-9]*\).*/\1/p')
    merged=$((after - before))
    echo "  $mode: $got (сегментов FIN+данные: $merged)"
    [ "$got" = ok ] || fail=1
    if [ "$mode" != separate ] && [ "$mode" != silent ] && [ "$merged" = 0 ]; then
        echo "  $mode: FIN не склеился с данными — случай не воспроизведён"; fail=1
    fi
done

if [ "$fail" != 0 ]; then
    echo "журнал туннеля:"; tail -${TAIL:-20} "$WORK/tun.log" | sed 's/^/  /'
    echo "журнал сервера:"; tail -20 "$WORK/srv.log" | sed 's/^/  /'
    echo "run-tunnel-fin: ПРОВАЛ"; exit 1
fi
echo "run-tunnel-fin: ok"
