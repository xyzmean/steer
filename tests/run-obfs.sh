#!/bin/sh
# Обфускатор (поддельный TCP) живьём: клиент и сервер в двух сетевых пространствах.
#
# Зачем отдельно от tests/obfsmatch.c. Тот проверяет чистую часть — сборку и разбор сегмента,
# суммы, движение ack. Циклов клиента и сервера в нём нет: им нужны сырые сокеты, то есть root
# и сеть. Здесь проверяется ровно то, что юнитом не поймать:
#
#   а. сервер с двумя адресами на одном интерфейсе отвечает С ТОГО, на который писал клиент
#      (I-312): SYN-ACK и RST на данные без сессии. Ответ с другого адреса клиентский фильтр
#      (obfs_filter_quad) отбрасывает в ядре — туннель молчит без единой строки в журнале. У RST
#      вдобавок сумма считалась от одного адреса, а ядро подставляло другой. Запись на
#      первичный адрес — контроль: ответ с первичного;
#   б. сквозной обмен: `steer obfs` → `steer obfs-server` на втором адресе → UDP-эхо, ответ
#      обязан вернуться;
#   в. пауза перед переподключением (I-313): сервер без слушателя, ядро рвёт RST каждый SYN.
#      Без паузы клиент слал десятки тысяч SYN в секунду; с паузой 250 мс…5 с за три секунды
#      их четыре.
#
# Не входит в `make test`: нужен root и `ip netns`. Без них стенд пропускается, а не падает.
#
# Использование: tests/run-obfs.sh
#   STEER=путь/к/steer (по умолчанию build/steer)
#   STEER_PRELOAD=библиотека для LD_PRELOAD движка — на glibc статический TLS движка не влезает
#   в малые стеки потоков, и живой движок может встать на создании потока.
set -u
cd "$(dirname "$0")/.."

BIN="${STEER:-build/steer}"
PRE="${STEER_PRELOAD:-}"

skip() { echo "пропущено: $1"; exit 0; }
[ "$(id -u)" = 0 ] || skip "нужен root"
command -v ip >/dev/null 2>&1 || skip "нет ip"
command -v python3 >/dev/null 2>&1 || skip "нет python3"
[ -x "$BIN" ] || { echo "нет бинарника: $BIN (make)"; exit 2; }

S=obfs-s$$
C=obfs-c$$
WORK="$(mktemp -d)"
PIDS=""

cleanup() {
    for p in $PIDS; do kill "$p" 2>/dev/null; done
    wait 2>/dev/null
    for n in "$S" "$C"; do
        ip netns exec "$n" nft delete table inet steer_obfs 2>/dev/null
        ip netns delete "$n" 2>/dev/null
    done
    rm -rf "$WORK"
}
trap cleanup EXIT INT TERM
ip netns add "$S" 2>/dev/null || skip "ip netns недоступен"
ip netns add "$C" || exit 2

fails=0
verdict() {   # $1 — что проверяли, $2 — 0/1
    if [ "$2" = 0 ]; then printf '%-66s ok\n' "$1"
    else printf '%-66s ПРОВАЛ\n' "$1"; fails=$((fails + 1)); fi
}

run_steer() {   # в пространстве $1, журнал $2, дальше аргументы движка
    ns=$1; log=$2; shift 2
    if [ -n "$PRE" ]; then
        ip netns exec "$ns" env LD_PRELOAD="$PRE" "$BIN" "$@" >"$log" 2>&1 &
    else
        ip netns exec "$ns" "$BIN" "$@" >"$log" 2>&1 &
    fi
    PIDS="$PIDS $!"
    LAST=$!
}

ip link add obfs-a$$ type veth peer name obfs-b$$ || exit 2
ip link set obfs-a$$ netns "$S"
ip link set obfs-b$$ netns "$C"
ip -n "$S" addr add 10.99.0.1/24 dev obfs-a$$
ip -n "$S" addr add 10.99.0.3/24 dev obfs-a$$
ip -n "$C" addr add 10.99.0.2/24 dev obfs-b$$
for n in "$S" "$C"; do ip -n "$n" link set lo up; done
ip -n "$S" link set obfs-a$$ up
ip -n "$C" link set obfs-b$$ up

# ---- а. адрес ответа -------------------------------------------------------------------
# Зонд — питон с сырым сокетом: SYN на порт сервера (заводит сессию) и голый ACK с другого
# порта (сессии нет — сервер обязан ответить RST). Ответы ловит тот же сокет; сумма
# сверяется по адресам, пришедшим в заголовке IP.
cat >"$WORK/probe.py" <<'PY'
import socket, struct, sys, time
cli, dst = sys.argv[1], sys.argv[2]
def csum(b):
    if len(b) % 2: b += b'\0'
    s = sum(struct.unpack('!%dH' % (len(b) // 2), b))
    s = (s >> 16) + (s & 0xffff); s += s >> 16
    return (~s) & 0xffff
def seg(src, dst, sp, dp, seq, ack, fl):
    h = struct.pack('!HHIIBBHHH', sp, dp, seq, ack, 5 << 4, fl, 65535, 0, 0)
    ph = socket.inet_aton(src) + socket.inet_aton(dst) + struct.pack('!BBH', 0, 6, len(h))
    c = csum(ph + h)
    return h[:16] + struct.pack('!H', c) + h[18:]
s = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_TCP)
s.settimeout(0.2)
s.sendto(seg(cli, dst, 40001, 4443, 1000, 0, 0x02), (dst, 0))
s.sendto(seg(cli, dst, 40002, 4443, 5000, 7, 0x10), (dst, 0))
got = {}
end = time.time() + 1.5
while time.time() < end and len(got) < 2:
    try: p = s.recv(4096)
    except socket.timeout: continue
    ihl = (p[0] & 15) * 4
    src, pdst = socket.inet_ntoa(p[12:16]), p[16:20]
    sp, dp = struct.unpack('!HH', p[ihl:ihl + 4])
    if sp != 4443 or dp not in (40001, 40002): continue
    tcp = p[ihl:]
    ph = p[12:16] + pdst + struct.pack('!BBH', 0, 6, len(tcp))
    kind = 'synack' if dp == 40001 else 'rst'
    got[kind] = '%s %s' % (src, 'correct' if csum(ph + tcp) == 0 else 'incorrect')
for k in ('synack', 'rst'):
    print(k, got.get(k, 'нет'))
PY

run_steer "$S" "$WORK/srv.log" obfs-server --listen 4443 --forward 127.0.0.1:51821
sleep 0.5
for dst in 10.99.0.3 10.99.0.1; do
    ip netns exec "$C" python3 "$WORK/probe.py" 10.99.0.2 "$dst" >"$WORK/probe.out"
    sa=$(sed -n 's/^synack //p' "$WORK/probe.out")
    rs=$(sed -n 's/^rst //p' "$WORK/probe.out")
    [ "$sa" = "$dst correct" ]; verdict "а. SYN-ACK на $dst: с $dst, сумма верна (есть: $sa)" $?
    [ "$rs" = "$dst correct" ]; verdict "а. RST без сессии на $dst: с $dst, сумма верна (есть: $rs)" $?
done

# ---- б. сквозной обмен на втором адресе ------------------------------------------------
ip netns exec "$S" python3 -c '
import socket
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM); s.bind(("127.0.0.1", 51821))
while True:
    d, a = s.recvfrom(2000); s.sendto(b"echo:" + d, a)' &
PIDS="$PIDS $!"
cat >"$WORK/spec2.json" <<'J'
{"schema":1,"from_default":["192.168.1.0/24"],"outputs":{"wg":{"kind":"interface","device":"wg0","obfs":{"mode":"wg-over-tcp","server":"10.99.0.3:4443","listen":"127.0.0.1:51820"}}},"channels":[]}
J
run_steer "$C" "$WORK/cli2.log" obfs wg --spec "$WORK/spec2.json"
CLI2=$LAST
sleep 1
ans=$(ip netns exec "$C" python3 -c '
import socket
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM); s.settimeout(2)
s.sendto(b"ping", ("127.0.0.1", 51820))
try: print(s.recvfrom(2000)[0].decode())
except Exception: print("нет")')
[ "$ans" = "echo:ping" ]; verdict "б. obfs → obfs-server на 10.99.0.3 → эхо: ответ пришёл (есть: $ans)" $?
kill "$CLI2" 2>/dev/null
ip netns exec "$C" nft delete table inet steer_obfs 2>/dev/null

# ---- в. пауза перед переподключением ---------------------------------------------------
# Порт 4444 никто не слушает: ядро сервера отвечает RST на каждый SYN. SYN считает сырой
# сокет в пространстве сервера.
cat >"$WORK/spec3.json" <<'J'
{"schema":1,"from_default":["192.168.1.0/24"],"outputs":{"wr":{"kind":"interface","device":"wg0","obfs":{"mode":"wg-over-tcp","server":"10.99.0.1:4444","listen":"127.0.0.1:51830"}}},"channels":[]}
J
ip netns exec "$S" python3 -c '
import socket, struct, time
s = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_TCP); s.settimeout(0.1)
n = 0; end = time.time() + 3.5
while time.time() < end:
    try: p = s.recv(4096)
    except socket.timeout: continue
    ihl = (p[0] & 15) * 4
    dp, fl = struct.unpack("!H", p[ihl + 2:ihl + 4])[0], p[ihl + 13]
    if dp == 4444 and fl & 0x02: n += 1
print(n)' >"$WORK/syn.out" &
CNT=$!
sleep 0.3
run_steer "$C" "$WORK/cli3.log" obfs wr --spec "$WORK/spec3.json"
CLI3=$LAST
sleep 3
kill "$CLI3" 2>/dev/null
wait "$CNT" 2>/dev/null
syn=$(cat "$WORK/syn.out")
[ -n "$syn" ] && [ "$syn" -ge 1 ] && [ "$syn" -le 10 ]
verdict "в. RST на каждый SYN: за 3 с от 1 до 10 SYN (есть: $syn)" $?

if [ "$fails" -ne 0 ]; then echo "провалов: $fails"; exit 1; fi
echo "все проверки прошли"
exit 0
