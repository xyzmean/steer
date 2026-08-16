#!/bin/sh
# Пересылка запросов резолвером: живой процесс, петля, без root и без сети наружу.
#
# Зачем именно живой процесс. Наверх резолвер ходит ОДНИМ постоянным сокетом, а ответы
# всех ожиданий приходят на него вперемешку — различить их можно только по номеру
# транзакции, который движок переписывает на свой при отправке и возвращает клиентский
# на место в ответе. Ошибиться тут можно ровно двумя способами, и оба не видны в
# отдельно взятой функции: клиенту уходит чужой номер (его резолвер молча выбросит
# ответ, и имя «не разрешается» без единой строки в журнале) или ответ попадает в чужой
# слот и уезжает не тому клиенту. Поэтому здесь поднимается настоящий dnsd с поддельным
# апстримом на петле и проверяется сквозной путь.
#
# Прежняя схема — сокет на каждый запрос — такой проверки не требовала: номер не
# трогался вовсе. Стенд появился вместе с постоянным сокетом.
set -u
BIN="${STEER:-./build/steer}"
[ -x "$BIN" ] || { echo "not built: $BIN (make)"; exit 2; }
# python3 нужен для поддельного апстрима и клиента. Его отсутствие — не провал стенда:
# остальной набор офлайновый и на голой машине обязан проходить.
command -v python3 >/dev/null 2>&1 || { echo "dnsproxy: python3 нет — пропускаю"; exit 0; }

tmp="$(mktemp -d)"
trap 'kill ${DPID:-0} ${UPID:-0} 2>/dev/null; rm -rf "$tmp"' EXIT

LPORT=15300
UPORT=15353

cat > "$tmp/upstream.py" <<'PY'
import socket, sys
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
s.bind(("127.0.0.1", int(sys.argv[1]))); s.settimeout(6)
seen = []
try:
    while True:
        data, addr = s.recvfrom(2048)
        seen.append(data[:2])
        qend = 12
        while data[qend]: qend += 1 + data[qend]
        qend += 5
        hdr = data[:2] + b'\x81\x80' + data[4:6] + b'\x00\x01\x00\x00\x00\x00'
        ans = b'\xc0\x0c\x00\x01\x00\x01\x00\x00\x00\x3c\x00\x04' + bytes([93, 184, 216, 34])
        s.sendto(hdr + data[12:qend] + ans, addr)
        # Пишется ПОСЛЕ КАЖДОЙ датаграммы, а не в конце: стенд снимает апстрим сразу
        # после клиента, не дожидаясь его таймаута, и итог, записанный только на выходе,
        # не появлялся вовсе — проверка сравнивала «0 0» и всегда проваливалась.
        open(sys.argv[2], "w").write("%d %d" % (len(seen), len(set(seen))))
except socket.timeout:
    pass
PY

cat > "$tmp/client.py" <<'PY'
import socket, struct, sys
port, n = int(sys.argv[1]), int(sys.argv[2])
ok = bad_id = lost = bad_addr = 0
for i in range(1, n + 1):
    tid = 0x1000 + i
    q = (struct.pack('>HHHHHH', tid, 0x0100, 1, 0, 0, 0)
         + b'\x07example\x03com\x00' + struct.pack('>HH', 1, 1))
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM); s.settimeout(3)
    s.sendto(q, ('127.0.0.1', port))
    try:
        d, _ = s.recvfrom(2048)
    except socket.timeout:
        lost += 1; continue
    if struct.unpack('>H', d[:2])[0] != tid: bad_id += 1
    elif d[-4:] != bytes([93, 184, 216, 34]): bad_addr += 1
    else: ok += 1
print("%d %d %d %d" % (ok, bad_id, lost, bad_addr))
PY

printf 'example.com\n' > "$tmp/d.lst"
printf '{"schema":1,"from_default":["127.0.0.0/8"],'\
'"outputs":{"direct":{"kind":"direct"},"vpn":{"kind":"interface","device":"lo"}},'\
'"channels":[{"name":"c","match":{"domains_files":["%s/d.lst"],"mode":"realip"},"out":"vpn"}]}' \
    "$tmp" > "$tmp/spec.json"

python3 "$tmp/upstream.py" "$UPORT" "$tmp/up.txt" & UPID=$!
sleep 1
"$BIN" dnsd --spec "$tmp/spec.json" --state-dir "$tmp/state" \
    --listen-port "$LPORT" --upstream-port "$UPORT" > "$tmp/log" 2>&1 & DPID=$!
sleep 1

if ! kill -0 "$DPID" 2>/dev/null; then
    echo "FAIL резолвер не поднялся:"; cat "$tmp/log"; exit 1
fi

set -- $(python3 "$tmp/client.py" "$LPORT" 20)
ok=$1 bad_id=$2 lost=$3 bad_addr=$4
kill "$DPID" 2>/dev/null; wait "$DPID" 2>/dev/null
sleep 1
kill "$UPID" 2>/dev/null; wait "$UPID" 2>/dev/null

pass=0 fail=0
check() {
    if [ "$2" = "$3" ]; then pass=$((pass + 1)); else
        fail=$((fail + 1))
        printf 'FAIL %s\n  ожидалось: %s\n  получено:  %s\n' "$1" "$2" "$3"
    fi
}

check "все 20 запросов получили ответ" "20" "$ok"
check "ни одного ответа с чужим номером транзакции" "0" "$bad_id"
check "ни одного потерянного" "0" "$lost"
check "адрес в ответе не искажён" "0" "$bad_addr"

# Наверх ушло столько же запросов, сколько пришло снизу, и номера у них РАЗНЫЕ: слот
# переиспользуется, но поколение в старшем байте меняет номер, иначе запоздавший ответ
# на закрытое ожидание попал бы в чужой слот.
up="$(cat "$tmp/up.txt" 2>/dev/null || echo '0 0')"
check "наверх ушли все запросы и все с разными номерами" "20 20" "$up"

printf '\n%d проверок пройдено' "$pass"
if [ "$fail" -gt 0 ]; then printf ', %d ПРОВАЛЕНО\n' "$fail"; exit 1; fi
printf '\nвсе проверки прошли\n'
