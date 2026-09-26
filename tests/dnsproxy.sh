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
trap 'kill ${DPID:-0} ${UPID:-0} ${DPID2:-0} 2>/dev/null; exec 3>&- 2>/dev/null; rm -rf "$tmp"' EXIT

LPORT=15300
UPORT=15353

cat > "$tmp/upstream.py" <<'PY'
import socket, struct, sys, threading
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
s.bind(("127.0.0.1", int(sys.argv[1]))); s.settimeout(20)
seen = []

# TCP на том же порту: резолвер спрашивает наверх по TCP то, что к нему пришло по TCP. Ответ
# по TCP — ДРУГИМ адресом (…35 против …34 по UDP): так клиент видит, каким путём шёл вопрос.
# big.test — ответ на 300 записей (больше 4 КБ, то есть больше любого буфера датаграммы
# резолвера): по TCP он обязан пройти целиком.
def tcp_answer(q):
    qend = 12
    while q[qend]: qend += 1 + q[qend]
    qend += 5
    name = q[12:qend - 4]
    n = 300 if name == b'\x03big\x04test\x00' else 1
    hdr = q[:2] + b'\x81\x80' + q[4:6] + struct.pack('>HHH', n, 0, 0)
    ans = b''.join(b'\xc0\x0c\x00\x01\x00\x01\x00\x00\x00\x3c\x00\x04'
                   + bytes([93, 184, (216 + i // 256) % 256, (35 + i) % 256]) for i in range(n))
    return hdr + q[12:qend] + ans

def recvn(c, k):
    b = b''
    while len(b) < k:
        d = c.recv(k - len(b))
        if not d: return None
        b += d
    return b

def tcp_conn(c):
    c.settimeout(10)
    try:
        while True:
            h = recvn(c, 2)
            if not h: break
            q = recvn(c, struct.unpack('>H', h)[0])
            if not q: break
            r = tcp_answer(q)
            c.sendall(struct.pack('>H', len(r)) + r)
            with open(sys.argv[2] + '.tcp', 'a') as f: f.write('q\n')
    except Exception:
        pass
    c.close()

def tcp_srv():
    t = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    t.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    t.bind(("127.0.0.1", int(sys.argv[1]))); t.listen(64)
    while True:
        c, _ = t.accept()
        threading.Thread(target=tcp_conn, args=(c,), daemon=True).start()
threading.Thread(target=tcp_srv, daemon=True).start()
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

cat > "$tmp/tcpclient.py" <<'PY'
# Клиент по TCP: конвейер (несколько запросов одной записью, до первого ответа), ответ больше
# 4 КБ, медленный клиент (полсообщения и тишина) не мешает остальным, и простой закрывается.
import socket, struct, sys, time
port, what = int(sys.argv[1]), sys.argv[2]

def q(tid, name, qtype=1):
    b = struct.pack('>HHHHHH', tid, 0x0100, 1, 0, 0, 0)
    for l in name.split('.'): b += bytes([len(l)]) + l.encode()
    return b + b'\x00' + struct.pack('>HH', qtype, 1)

def framed(m): return struct.pack('>H', len(m)) + m

def recvn(c, k):
    b = b''
    while len(b) < k:
        d = c.recv(k - len(b))
        if not d: return None
        b += d
    return b

def reply(c):
    h = recvn(c, 2)
    if not h: return None
    return recvn(c, struct.unpack('>H', h)[0])

def conn():
    c = socket.create_connection(('127.0.0.1', port), timeout=4)
    return c

if what == 'pipeline':
    # Три запроса одной записью: два разных имени и одно повторно. Ответы могут прийти в любом
    # порядке — сопоставление по номеру.
    c = conn()
    names = {0x2001: 'example.com', 0x2002: 'other.test', 0x2003: 'www.example.com'}
    c.sendall(b''.join(framed(q(t, n)) for t, n in names.items()))
    got = {}
    for _ in names:
        r = reply(c)
        if r is None: break
        got[struct.unpack('>H', r[:2])[0]] = r
    ok = sum(1 for t in names if t in got and got[t][-4:] == bytes([93, 184, 216, 35]))
    # Затем в том же соединении — ещё пять последовательно, запрос-ответ.
    seq = 0
    for i in range(5):
        c.sendall(framed(q(0x3000 + i, 'seq%d.test' % i)))
        r = reply(c)
        if r and struct.unpack('>H', r[:2])[0] == 0x3000 + i and r[-4:] == bytes([93, 184, 216, 35]):
            seq += 1
    print(ok, seq)
elif what == 'big':
    c = conn()
    c.sendall(framed(q(0x4242, 'big.test')))
    r = reply(c)
    print(len(r) if r else 0, struct.unpack('>H', r[6:8])[0] if r else 0)
elif what == 'slow':
    # Полсообщения — и тишина. Пока это соединение висит, UDP и другое TCP-соединение
    # обязаны получать ответы: цикл резолвера не ждёт медленного клиента.
    s = conn()
    s.sendall(b'\x00')
    u = socket.socket(socket.AF_INET, socket.SOCK_DGRAM); u.settimeout(3)
    u.sendto(q(0x5151, 'example.com'), ('127.0.0.1', port))
    try:
        d, _ = u.recvfrom(2048); udp = 1 if d[:2] == b'\x51\x51' else 0
    except socket.timeout:
        udp = 0
    c = conn()
    c.sendall(framed(q(0x5252, 'other.test')))
    r = reply(c)
    tcp = 1 if r and r[:2] == b'\x52\x52' else 0
    print(udp, tcp)
elif what == 'idle':
    # Соединение без запросов закрывается резолвером по простою (10 с), а не держит место.
    c = conn(); c.settimeout(20)
    t0 = time.time()
    try:
        d = c.recv(1)
    except socket.timeout:
        d = b'x'
    el = time.time() - t0
    print('closed' if d == b'' and 8 <= el <= 14 else 'open %.1f' % el)
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

python3 "$tmp/tcpclient.py" "$LPORT" idle > "$tmp/idle.txt" 2>&1 & IDLE=$!
set -- $(python3 "$tmp/client.py" "$LPORT" 20)
ok=$1 bad_id=$2 lost=$3 bad_addr=$4
tcp_pipe="$(python3 "$tmp/tcpclient.py" "$LPORT" pipeline 2>&1)"
tcp_big="$(python3 "$tmp/tcpclient.py" "$LPORT" big 2>&1)"
tcp_slow="$(python3 "$tmp/tcpclient.py" "$LPORT" slow 2>&1)"
wait "$IDLE"
tcp_idle="$(cat "$tmp/idle.txt")"
# Тишина: ожиданий в пути нет, соединения TCP закрыты по простою — резолверу не на что
# просыпаться. Раньше он всё равно просыпался раз в секунду (epoll_wait с таймаутом 1000 мс
# ради тика), и на телефоне это было 60 пробуждений в минуту при выключенном экране.
# Меряется счётчиком добровольных переключений контекста самого процесса; одно лишнее
# допускается — последний тик, который и обнаружил, что всё затихло.
sleep 2
cs0=$(awk '/^voluntary_ctxt_switches/{print $2}' "/proc/$DPID/status")
sleep 3
cs1=$(awk '/^voluntary_ctxt_switches/{print $2}' "/proc/$DPID/status")
quiet=$(( cs1 - cs0 ))
[ "$quiet" -le 1 ] && quiet=ok
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

# Наверх по UDP ушло столько же запросов, сколько пришло снизу по UDP (20 и один из стенда
# медленного клиента), и номера у них РАЗНЫЕ: слот
# переиспользуется, но поколение в старшем байте меняет номер, иначе запоздавший ответ
# на закрытое ожидание попал бы в чужой слот.
up="$(cat "$tmp/up.txt" 2>/dev/null || echo '0 0')"
check "наверх ушли все запросы и все с разными номерами" "21 21" "$up"

# DNS по TCP (RFC 7766): тот же путь, что у датаграммы, ответ — по TCP, наверх — тоже по TCP.
check "TCP: конвейер из трёх запросов одной записью и пять подряд — все ответы по TCP сверху" \
    "3 5" "$tcp_pipe"
check "TCP: ответ больше 4 КБ (300 записей) пришёл целиком" "4826 300" "$tcp_big"
check "TCP: медленный клиент не держит цикл — UDP и другое соединение отвечают" "1 1" "$tcp_slow"
check "TCP: соединение без запросов закрыто по простою" "closed" "$tcp_idle"
check "в тишине резолвер не просыпается (добровольных переключений за 3 с не больше одного)" \
    "ok" "$quiet"
check "TCP: наверх по TCP ушли ровно вопросы клиентов TCP" "10" \
    "$(cat "$tmp/up.txt.tcp" 2>/dev/null | wc -l | tr -d ' ')"

# ---- --table-fd: таблица каналов из трубы демона, а не из спеки самим резолвером -----------
# docs/architecture.md, раздел 4а, шаг 1: dnsd принимает таблицу через дескриптор, который
# демон завёл бы для дочернего резолвера. Здесь его роль играет труба, которую заполняет
# `steer dnsd-table` (та же сборка, что напечатала бы демону), — резолвер спеку в этом режиме
# не открывает вовсе.
#
# Сигнал «канал совпал или нет» — без единой нитки к nftables (этот стенд намеренно обходится
# без root и без сети наружу, см. шапку файла): запрос AAAA на СОВПАВШЕЕ имя резолвер гасит в
# NODATA прямо из вопроса, ни разу не спросив апстрим (dns_query, proxy.c, «Подавление — свойство
# правила, а не данных из ответа») — ровно поэтому сигнал верен и без единой транзакции ядра.
# Несовпавшее имя идёт напрямую, и апстрим здесь отвечает настоящей записью AAAA — значит
# ANCOUNT (число записей в ответе, байты 6-7 заголовка) 0 значит «канал забрал домен», 1 —
# «домена в таблице нет». Разбор именно этого поля, а не адреса: NODATA не несёт вовсе
# ресурсной записи, сравнивать в ней нечего.
cat > "$tmp/upstream-aaaa.py" <<'PY'
import socket, sys
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
s.bind(("127.0.0.1", int(sys.argv[1]))); s.settimeout(20)
while True:
    data, addr = s.recvfrom(2048)
    qend = 12
    while data[qend]: qend += 1 + data[qend]
    qend += 5
    hdr = data[:2] + b'\x81\x80' + data[4:6] + b'\x00\x01\x00\x00\x00\x00'
    ans = b'\xc0\x0c\x00\x1c\x00\x01\x00\x00\x00\x3c\x00\x10' + b'\x20\x01\x0d\xb8' + b'\x00' * 12
    s.sendto(hdr + data[12:qend] + ans, addr)
PY
cat > "$tmp/qaaaa.py" <<'PY'
import socket, struct, sys
port, name = int(sys.argv[1]), sys.argv[2]
q = struct.pack('>HHHHHH', 0x7a7a, 0x0100, 1, 0, 0, 0)
for l in name.split('.'): q += bytes([len(l)]) + l.encode()
q += b'\x00' + struct.pack('>HH', 28, 1)  # qtype 28 = AAAA
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM); s.settimeout(3)
s.sendto(q, ('127.0.0.1', port))
try:
    d, _ = s.recvfrom(2048)
    print(struct.unpack('>H', d[6:8])[0])  # ANCOUNT
except socket.timeout:
    print('timeout')
PY

LPORT2=15301
UPORT2=15364
printf 'swap.test\n' > "$tmp/tab.lst"
# Таблица 1: канал с доменным правилом на swap.test. Таблица 2 — ТА ЖЕ спека, но с ПУСТЫМ
# списком каналов: не файл правил меняется (это уже умеет HUP, reload_rules — не про него
# этот стенд), а само число каналов и их состав. Это ровно то, чего построчное перечитывание
# списков никогда не делает: dch_build решает его один раз при запуске (или — здесь — один раз
# на таблицу). Совпадение исчезает и появляется вместе с таблицей — прямое доказательство, что
# резолвер живёт по НОВОЙ таблице целиком, а не донашивает старую с обновлёнными файлами.
mk_tabspec() {  # "1" — канал с swap.test в списке; "" — каналов нет вовсе
    f="$tmp/tabspec-$1.json"
    chans='[]'
    [ -n "$1" ] && chans="[{\"name\":\"c\",\"match\":{\"domains_files\":[\"$tmp/tab.lst\"]},\"out\":\"vpn\"}]"
    printf '{"schema":1,"from_default":["127.0.0.0/8"],'\
'"outputs":{"direct":{"kind":"direct"},"vpn":{"kind":"interface","device":"lo"}},'\
'"channels":%s}' "$chans" > "$f"
    printf '%s' "$f"
}
tabspec_on="$(mk_tabspec 1)"
tabspec_off="$(mk_tabspec '')"

mkfifo "$tmp/tabpipe"
# fd 3 — НАШ конец, открытый и на чтение, и на запись: писать в трубу можно, не дожидаясь
# читателя, и наш же конец не даёт нам самим поймать EOF раньше времени. Резолверу открывается
# ОТДЕЛЬНЫЙ, только читающий fd 4 (see ниже, при запуске) — если бы он вместо этого унаследовал
# fd 3 как есть, его СОБСТВЕННАЯ же копия читала-и-писала бы одну и ту же трубу, и закрытие
# нашего конца никогда не дало бы ему увидеть EOF: труба остаётся «с открытым писателем» до тех
# пор, пока хоть кто-то — не важно, мы или он сам, — держит открытым конец на запись.
exec 3<>"$tmp/tabpipe"
"$BIN" dnsd-table --spec "$tabspec_on" --state-dir "$tmp/state2" >&3

# `3<&-`: без него апстрим тоже унаследовал бы наш конец трубы и держал бы у себя открытым
# писатель, которого мы позже закрываем, — резолвер тогда не увидел бы EOF никогда, пока не
# убит и апстрим (та же причина, что у 3<&- при запуске dnsd ниже).
python3 "$tmp/upstream-aaaa.py" "$UPORT2" 3<&- & UPID2=$!
sleep 1
# `3<&-` закрывает унаследованный fd 3 ИМЕННО для этого процесса (наш собственный fd 3 в
# шелле не трогается), `4<...` открывает резолверу свежий read-only конец той же трубы — уже
# не блокируясь: наш fd 3 в этот момент открыт как писатель, поэтому open() на чтение не ждёт.
"$BIN" dnsd --table-fd 4 --state-dir "$tmp/state2" \
    --listen-port "$LPORT2" --upstream-port "$UPORT2" \
    3<&- 4<"$tmp/tabpipe" > "$tmp/log2" 2>&1 & DPID2=$!
sleep 1
if ! kill -0 "$DPID2" 2>/dev/null; then
    echo "FAIL резолвер (--table-fd) не поднялся:"; cat "$tmp/log2"; exit 1
fi

tab_on_hit="$(python3 "$tmp/qaaaa.py" "$LPORT2" swap.test)"
tab_on_miss="$(python3 "$tmp/qaaaa.py" "$LPORT2" other.test)"

# Тишина и здесь: труба таблицы в epoll — событие только на настоящей записи, не пустое
# пробуждение по таймеру. Тот же счётчик, что у первого резолвера (тот же запас в 2 с — отдать
# последнему тику время снять ожидание только что отвеченного запроса ДО начала окна).
sleep 2
cs2_0=$(awk '/^voluntary_ctxt_switches/{print $2}' "/proc/$DPID2/status")
sleep 3
cs2_1=$(awk '/^voluntary_ctxt_switches/{print $2}' "/proc/$DPID2/status")
quiet2=$(( cs2_1 - cs2_0 ))
[ "$quiet2" -le 1 ] && quiet2=ok

"$BIN" dnsd-table --spec "$tabspec_off" --state-dir "$tmp/state2" >&3
sleep 1
tab_off_hit="$(python3 "$tmp/qaaaa.py" "$LPORT2" swap.test)"
# Тот же $DPID2, тот же PID в OS: не respawn под тем же именем переменной, а kill -0 на РОВНО
# тот процесс, что подняли выше, — упал бы он и procd (здесь — никто) поднял бы замену, у
# замены был бы другой PID, а мы всё ещё спрашиваем старый.
still_up="down"; kill -0 "$DPID2" 2>/dev/null && still_up="up"

# Закрыть трубу — резолвер обязан завершиться сам, без TERM (родитель умер, docs/
# architecture.md, раздел 4а): ждать его пятью секундами таймаута, дольше make test терпеть
# зависший процесс не должен.
exec 3>&-
closed="still running"
for _ in 1 2 3 4 5 6 7 8 9 10; do
    kill -0 "$DPID2" 2>/dev/null || { closed="exited"; break; }
    sleep 0.5
done
kill "$DPID2" 2>/dev/null; wait "$DPID2" 2>/dev/null
kill "$UPID2" 2>/dev/null; wait "$UPID2" 2>/dev/null

check "table-fd: первая таблица — swap.test совпал (AAAA погашен, ANCOUNT 0)" "0" "$tab_on_hit"
check "table-fd: первая таблица — чужое имя без канала (ANCOUNT 1)" "1" "$tab_on_miss"
check "table-fd: в тишине резолвер не просыпается" "ok" "$quiet2"
check "table-fd: после второй таблицы процесс тот же, не перезапустился" "up" "$still_up"
check "table-fd: вторая таблица без каналов — swap.test больше не совпадает (ANCOUNT 1)" \
    "1" "$tab_off_hit"
check "table-fd: закрытие трубы демоном — резолвер завершается сам" "exited" "$closed"

printf '\n%d проверок пройдено' "$pass"
if [ "$fail" -gt 0 ]; then printf ', %d ПРОВАЛЕНО\n' "$fail"; exit 1; fi
printf '\nвсе проверки прошли\n'
