#!/bin/sh
# Прогон туннеля через НАСТОЯЩИЙ Reality-сервер — свой, с известными ключами.
#
# Зачем, если уже есть tests/run-tunnel.sh. Тот стенд поднимает поддельный сервер без TLS и
# проверяет цикл туннеля: синтез TCP, повторную передачу, потоки. Reality, Vision и VLESS он
# не проверяет вовсе — а именно там ломалось так, что снаружи выглядело как «узел умер».
#
# Здесь другая половина: сервер настоящий (sing-box), с настоящим Reality и Vision, и он
# ПИШЕТ В ЛОГ, что именно ему не понравилось. Это оказалось единственным способом отличить
# «нас не признали» от «признали, но мы не поняли ответ»: у Reality нет отрицательного
# ответа, непризнанного клиента он молча проксирует на маскировочный сайт, и оба случая
# снаружи одинаковы.
#
# Стороны РАЗВЕДЕНЫ по сетевым пространствам, и это обязательно. Первая версия держала всё на
# хосте, маршрут до цели через туннель применялся и к самому серверу, и его исходящее
# соединение уходило обратно в туннель — стенд ловил свою же петлю и выглядел как отказ
# Reality.
#
# Нужен sing-box. Путь задаётся переменной SINGBOX, по умолчанию ./build/sing-box.
set -eu
cd "$(dirname "$0")/.."

SB="${SINGBOX:-./build/sing-box}"
BIN="${STEER:-./build/steer-ext-check}"
MASK="${MASK:-prod.vkimages.io}"          # маскировочный домен: обязан уметь TLS 1.3 и h2
TARGET="${TARGET:-205.234.175.175}"       # куда просим сходить через туннель
TPATH="${TPATH:-/1mb.test}"
THOST="${THOST:-cachefly.cachefly.net}"

[ -x "$SB" ] || { echo "нет sing-box: $SB (SINGBOX=путь)"; exit 2; }
[ -x "$BIN" ] || { echo "нет бинарника: $BIN"; exit 2; }

NS=steer-reality
W="$(mktemp -d)"
cleanup() {
    [ -n "${SRV:-}" ] && kill "$SRV" 2>/dev/null || true
    ip netns pids "$NS" 2>/dev/null | xargs -r kill 2>/dev/null || true
    ip netns delete "$NS" 2>/dev/null || true
    ip link delete veth-h 2>/dev/null || true
    rm -rf "$W"
}
trap cleanup EXIT INT TERM

ip netns delete "$NS" 2>/dev/null || true
ip link delete veth-h 2>/dev/null || true
ip netns add "$NS"
ip netns exec "$NS" ip link set lo up
ip link add veth-h type veth peer name veth-c
ip addr add 10.90.0.1/24 dev veth-h && ip link set veth-h up
ip link set veth-c netns "$NS"
ip netns exec "$NS" ip addr add 10.90.0.2/24 dev veth-c
ip netns exec "$NS" ip link set veth-c up

"$SB" generate reality-keypair > "$W/rk.txt"
PRIV=$(awk '/PrivateKey/{print $2}' "$W/rk.txt")
PUB=$(awk '/PublicKey/{print $2}' "$W/rk.txt")
UUID=$("$SB" generate uuid)
SID=0123456789abcdef

cat > "$W/server.json" <<CFG
{"log":{"level":"trace","timestamp":true},
 "inbounds":[{"type":"vless","tag":"in","listen":"10.90.0.1","listen_port":18443,
   "users":[{"uuid":"$UUID","flow":"xtls-rprx-vision"}],
   "tls":{"enabled":true,"server_name":"$MASK",
     "reality":{"enabled":true,
       "handshake":{"server":"$MASK","server_port":443},
       "private_key":"$PRIV","short_id":["$SID"]}}}],
 "outbounds":[{"type":"direct","tag":"out"}]}
CFG

printf '%s\n' "vless://$UUID@10.90.0.1:18443?encryption=none&flow=xtls-rprx-vision&type=tcp&security=reality&sni=$MASK&pbk=$PUB&sid=$SID&fp=chrome#local" > "$W/sub.txt"
cat > "$W/spec.json" <<SPEC
{"schema":1,
 "outputs":{"vl":{"name":"vl","kind":"vless","sub_file":"$W/sub.txt","node":0}},
 "channels":[]}
SPEC

"$SB" run -c "$W/server.json" > "$W/srv.log" 2>&1 &
SRV=$!
sleep 2
grep -q "tcp server started" "$W/srv.log" || { echo "сервер не поднялся:"; tail -5 "$W/srv.log"; exit 1; }

ip netns exec "$NS" env STEER_TUN_STATS=1 "$BIN" vless vl \
    --spec "$W/spec.json" --state-dir "$W/state" > "$W/tun.log" 2>&1 &
for _ in $(seq 40); do
    ip netns exec "$NS" ip link show vl >/dev/null 2>&1 && break
    sleep 0.2
done
ip netns exec "$NS" ip link show vl >/dev/null 2>&1 || { echo "vl не поднялся:"; tail -5 "$W/tun.log"; exit 1; }
ip netns exec "$NS" ip route replace "$TARGET/32" dev vl

echo "  маскировка $MASK, цель $TARGET"
ip netns exec "$NS" curl -s -o "$W/dl.bin" \
    -w "  через туннель: код %{http_code}, %{size_download} байт, %{speed_download} Б/с\n" \
    --max-time 30 -H "Host: $THOST" "http://$TARGET$TPATH" || echo "  через туннель: НЕ ВЫШЛО"

echo "  сервер:"
grep -iE "inbound connection to|Xtls|ERROR|isHandshakeComplete" "$W/srv.log" |
    tail -5 | sed 's/.*\] //; s/^/    /' | cut -c1-150
