#!/bin/sh
# UDP через туннель на локальном стенде: без узла подписки и без интернета.
#
# Зачем отдельно от run-tunnel.sh. Тот проверяет TCP: синтез соединения, повторную передачу,
# восстановление после потерь. У UDP ничего этого нет — и ровно поэтому ошибки у него другие,
# а стенд нужен свой. Проверяется здесь то, что может молча испортиться:
#
#   1. границы датаграмм. VLESS несёт их потоком с двухбайтовой длиной, и запись TLS про эти
#      границы не знает: датаграмма приезжает двумя записями, а одна запись приносит полторы.
#      Ошибка в сборке выглядит как «работает, но иногда данные не те» — поэтому сверяется
#      СОДЕРЖИМОЕ каждого ответа, а не только их число;
#   2. размеры на границах: 1 байт, ровно в MTU, и больше MTU — последнее уходит клиенту
#      фрагментами, и собрать их обратно должен его стек;
#   3. поток на пару адрес-порт: две разные цели одновременно не должны перепутаться;
#   4. отсутствие ICMP-отказа. Прежде туннель отвечал на UDP «порт недостижим», и если такой
#      ответ вернётся, клиент будет считать, что порта нет, — то есть QUIC не заработает
#      даже при исправном переносе датаграмм.
#
# Стенд: своё сетевое пространство, поддельный сервер VLESS (tests/fake-vless.py) с эхом на
# команде 2, поднятый steer туннель и питон как клиент UDP.
#
# Использование: tests/run-udp.sh
set -eu
cd "$(dirname "$0")/.."

BIN="${STEER:-./build/steer-ext-check}"
[ -x "$BIN" ] || { echo "нет бинарника: $BIN (собери extended)"; exit 2; }

NS=steer-udp
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

ip netns exec "$NS" python3 tests/fake-vless.py --port "$PORT" --uuid "$UUID" --mb 1 \
    > "$WORK/srv.log" 2>&1 &
SRV_PID=$!
sleep 1

ip netns exec "$NS" env STEER_TUN_STATS=1 "$BIN" vless vl \
    --spec "$WORK/spec.json" --state-dir "$WORK/state" > "$WORK/tun.log" 2>&1 &
TUN_PID=$!

for _ in $(seq 50); do
    ip netns exec "$NS" ip link show vl >/dev/null 2>&1 && break
    sleep 0.2
done
if ! ip netns exec "$NS" ip link show vl >/dev/null 2>&1; then
    echo "устройство vl не поднялось:"; sed 's/^/  /' "$WORK/tun.log"; exit 1
fi

# Куда угодно, кроме localhost: поддельному серверу адрес безразличен, важно попасть в туннель.
ip netns exec "$NS" ip route replace 203.0.113.0/24 dev vl

# Клиент внутри пространства: своим сокетом UDP, потому что ни один готовый инструмент не
# умеет сказать «пришла ли ответная датаграмма ЦЕЛОЙ и той же». ICMP слушаем сырым сокетом —
# отказ «порт недостижим» здесь означал бы, что UDP не поддержан, и это надо ЗАМЕТИТЬ, а не
# получить в виде таймаута.
rc=0
ip netns exec "$NS" python3 - > "$WORK/out.txt" 2>&1 <<'PY' || rc=$?
import socket, struct, sys, time

TARGET_A, TARGET_B = "203.0.113.7", "203.0.113.9"
fails = []

def check(name, ok, detail=""):
    print("%-46s %s%s" % (name, "ok" if ok else "ПРОВАЛ", ("  " + detail) if detail else ""))
    if not ok:
        fails.append(name)

icmp = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP)
icmp.setblocking(False)

def drain(sock):
    """Выгрести всё, что уже пришло.

    Обязательно между проверками: эхо от предыдущей проверки, пришедшее с опозданием, иначе
    достаётся следующей и она сравнивает не то. Один раз этот стенд уже соврал именно так —
    «другой порт: свой поток ПРОВАЛ» при исправном туннеле.
    """
    n = 0
    while True:
        try:
            sock.recvfrom(65535)
            n += 1
        except BlockingIOError:
            return n


def echo(sock, host, port, payload, timeout=6.0):
    """Отправить датаграмму и вернуть ответ (или None по таймауту)."""
    drain(sock)
    sock.sendto(payload, (host, port))
    end = time.time() + timeout
    while time.time() < end:
        try:
            data, _ = sock.recvfrom(65535)
            return data
        except BlockingIOError:
            time.sleep(0.02)
    return None

s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
s.setblocking(False)
s.bind(("", 0))

# 1. Обычная датаграмма. Первая заодно проверяет весь путь установки: рукопожатие с узлом
#    идёт уже после того, как датаграмма попала в буфер ранних данных.
p = b"quic-ish-initial-" + bytes(range(200))
r = echo(s, TARGET_A, 443, p)
check("датаграмма 217 байт вернулась той же", r == p,
      "" if r == p else "получено %r" % (None if r is None else len(r)))

# 2. Размеры на границах. Один байт — минимум; 1472 — ровно MTU (1500 - 20 - 8); 3000 —
#    больше MTU В ОБЕ СТОРОНЫ: наверх датаграмма приходит от клиента уже фрагментами и
#    собирается туннелем, обратно она же уходит фрагментами и собирается стеком клиента.
#    Одна проверка закрывает и сборку, и нарезку — эхо не сойдётся, если сломано любое.
for n in (1, 1472, 3000):
    p = bytes((i * 37 + n) % 251 for i in range(n))
    r = echo(s, TARGET_A, 443, p)
    check("датаграмма %d байт вернулась той же" % n, r == p,
          "" if r == p else "получено %s" % (None if r is None else len(r)))

# 3. Пачка подряд: границы не должны склеиться. Ответы могут прийти в любом порядке —
#    сверяем как множество, потому что порядок UDP не обещает никто.
drain(s)
sent = [bytes([i]) * (100 + i) for i in range(8)]
for p in sent:
    s.sendto(p, (TARGET_A, 443))
got, end = [], time.time() + 8
while len(got) < len(sent) and time.time() < end:
    try:
        got.append(s.recvfrom(65535)[0])
    except BlockingIOError:
        time.sleep(0.02)
check("пачка из 8: все вернулись целыми", sorted(got) == sorted(sent),
      "получено %d из %d" % (len(got), len(sent)))

# 4. Два адресата одновременно: у каждого свой поток к узлу, и путать их нельзя.
s2 = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
s2.setblocking(False)
pa, pb = b"aaaa-to-A" * 10, b"bbbb-to-B" * 10
ra = echo(s, TARGET_A, 443, pa)
rb = echo(s2, TARGET_B, 443, pb)
check("два адресата не перепутались", ra == pa and rb == pb,
      "" if ra == pa and rb == pb else "A:%r B:%r" % (ra and len(ra), rb and len(rb)))

# 5. Другой порт того же адреса — тоже отдельный поток.
r = echo(s, TARGET_A, 51820, b"wireguard-keepalive")
check("другой порт: свой поток", r == b"wireguard-keepalive")

# 6. ICMP «порт недостижим» приходить НЕ ДОЛЖЕН.
unreach = 0
try:
    while True:
        data = icmp.recv(2048)
        if len(data) >= 21 and data[20] == 3:
            unreach += 1
except BlockingIOError:
    pass
check("ICMP-отказов на UDP нет", unreach == 0, "получено %d" % unreach)

print("\nпровалов: %d" % len(fails))
sys.exit(1 if fails else 0)
PY
# `|| rc=$?` вместо прежнего `|| true`, и это не косметика. Раньше следующей строкой стояло
# `rc=$?` — после `|| true` там всегда был нуль, — и ни одна строка дальше на rc не смотрела:
# приговор держался только на grep по строке отчёта. С истиной это совпадало, потому что
# отчёт печатается последним, прямо перед sys.exit. Опасна была форма: любая проверка,
# добавленная ПОСЛЕ печати отчёта, оказалась бы для стенда невидимой, а мёртвая переменная
# рядом выглядела так, будто код возврата всё-таки учитывается. Оставить `|| true` было
# нельзя и убрать тоже: при set -e ненулевой выход оборвал бы стенд ДО печати out.txt, то
# есть провал остался бы без единственной строки, объясняющей, какая проверка упала.
#
# Теперь приговор из двух половин: код возврата отвечает за «упало где угодно», grep — за
# «отчёт вообще напечатан» (питон мог умереть до него, и тогда провалов в файле нет вовсе).

sed 's/^/  /' "$WORK/out.txt"
if [ "$rc" -ne 0 ] || ! grep -q "^провалов: 0" "$WORK/out.txt"; then
    echo "  --- журнал туннеля:"
    grep -iE "warn|датаграмм|udp" "$WORK/tun.log" | tail -10 | sed 's/^/    /' || true
    echo "  --- журнал сервера:"
    tail -5 "$WORK/srv.log" | sed 's/^/    /' || true
    exit 1
fi
# Сколько потоков к узлу завёл туннель: у каждой пары адрес-порт свой, и это то самое
# свойство, из-за которого UDP здесь дороже TCP. Сервер пишет об этом, когда поток
# ЗАКРЫВАЕТСЯ, поэтому сначала останавливаем туннель, а потом считаем.
kill "$TUN_PID" 2>/dev/null || true
TUN_PID=""
sleep 1
# Не приговор, а справка: сервер печатает строку при ЗАКРЫТИИ потока, и последнюю он может
# не успеть записать до того, как мы его снимем. Число здесь нужно для другого — увидеть, что
# потоков несколько (по одному на пару адрес-порт), а не один общий на всё.
echo "  потоков UDP к узлу: $(grep -c 'UDP-поток закрыт' "$WORK/srv.log" || true) (адресов 2, портов 2 — то есть до 4)"
echo "  датаграмм принял сервер: $(sed -n 's/.*датаграмм \([0-9]*\)$/\1/p' "$WORK/srv.log" | awk '{s+=$1} END {print s+0}')"
exit 0
