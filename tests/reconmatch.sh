#!/bin/sh
# Apply-сверка демона (src/daemon/recon.c, docs/ctl.md, поле changed): apply и reload трогают
# только изменившиеся части.
#
# Демон — `steer daemon --supervise` в своём сетевом пространстве с настоящим nft; помощники —
# заглушка через шов STEER_SUPERVISE_EXE (пишет «obfs выход pid»), резолвер — настоящий, на
# таблице от демона. nft и ip — обёртки в PATH, которые записывают каждый запуск.
#
# Что проверяется.
#  1. Первый apply применяет всё: набор правил и маршрутизацию обоих выходов.
#  2. apply той же спеки: nft не запускается ни разу, ip не меняет ни маршрутов, ни правил;
#     таблица в ядре та же (номер таблицы), элемент, положенный в набор со стороны (как кладёт
#     резолвер), на месте; помощники и резолвер — те же процессы, таблица резолверу не
#     отправлялась; changed — пустой. То же — reload.
#  3. Изменился только канал: набор правил новой транзакцией, маршруты, помощники и резолвер не
#     тронуты.
#  4. Изменился режим отказа одного выхода: привязан заново только он.
#  5. Изменился сервер обфускации одного выхода: перезапущен только его помощник, маршруты не
#     тронуты.
#  6. Изменился состав доменного канала: резолверу — новая таблица, процесс тот же.
#  7. Отказ ядра (адрес, который форму проходит, а ядро отвергает): прежняя спека возвращена,
#     прежняя таблица в ядре на месте; следующий apply применяет всё заново.
#  8. Пока идёт компиляция (план читает список из именованного канала, который стенд долго не
#     наполняет), status отвечает сразу: компиляция — в ребёнке, цикл демона свободен.
#
# Нужны root, unshare -n, nft, ip и python3; без них стенд пропускается.
set -u
BIN="${STEER:-./build/steer}"
BIN="$(cd "$(dirname "$BIN")" && pwd)/$(basename "$BIN")"
[ -x "$BIN" ] || { echo "not built: $BIN (make)"; exit 2; }
for t in nft ip python3; do
    command -v $t >/dev/null 2>&1 || { echo "reconmatch: $t нет — пропускаю"; exit 0; }
done
if [ "${RECON_INNER:-}" != 1 ]; then
    [ "$(id -u)" = 0 ] || { echo "reconmatch: нужен root — пропускаю"; exit 0; }
    unshare -n true 2>/dev/null || { echo "reconmatch: unshare -n недоступен — пропускаю"; exit 0; }
    RECON_INNER=1 STEER="$BIN" exec unshare -n sh "$0" "$@"
fi
ip link set lo up
real_nft="$(command -v nft)"
real_ip="$(command -v ip)"
"$real_nft" add table inet reconmatch_probe 2>/dev/null ||
    { echo "reconmatch: nf_tables недоступен — пропускаю"; exit 0; }
"$real_nft" delete table inet reconmatch_probe
for d in wga wgb; do "$real_ip" link add $d type dummy && "$real_ip" link set $d up; done

tmp="$(mktemp -d)"
mkdir -p "$tmp/st" "$tmp/st2" "$tmp/bin"
D="" D2="" W="" AP=""
trap 'kill $D $D2 $W $AP 2>/dev/null; rm -rf "$tmp"' EXIT
pass=0 fail=0
check() {
    if [ "$2" = "$3" ]; then pass=$((pass + 1)); else
        fail=$((fail + 1)); printf 'FAIL %s\n  expected: %s\n  actual:   %s\n' "$1" "$2" "$3"
    fi
}
wait_for() {
    i=0
    while [ $i -lt $(($2 * 10)) ]; do eval "$1" && return 0; sleep 0.1; i=$((i + 1)); done
    return 1
}

for t in nft ip; do
    real="$(command -v $t)"
    printf '#!/bin/sh\nprintf "%%s\\n" "$*" >> "%s/%s.log"\nexec "%s" "$@"\n' "$tmp" "$t" "$real" \
        > "$tmp/bin/$t"
    chmod +x "$tmp/bin/$t"
done
PATH="$tmp/bin:$PATH"
export PATH

cat > "$tmp/helper" <<H
#!/bin/sh
echo "\$1 \$2 \$\$" >> "$tmp/log"
trap 'exit 0' TERM
while :; do sleep 1; done
H
chmod +x "$tmp/helper"

# j ПУТЬ — поле ответа (через точку); список — через запятую.
cat > "$tmp/j.py" <<'PY'
import json, sys
d = json.loads(sys.stdin.read())
for k in sys.argv[1].split('.'):
    d = d.get(k) if isinstance(d, dict) else None
if d is None: print('-')
elif isinstance(d, bool): print('true' if d else 'false')
elif isinstance(d, list): print(','.join(d))
else: print(d)
PY
j() { python3 "$tmp/j.py" "$1"; }
ch() { printf '%s' "$1" | python3 "$tmp/j.py" changed.ruleset | tr -d '\n'; printf ' ['
       printf '%s' "$1" | python3 "$tmp/j.py" changed.routing | tr -d '\n'; printf '] ['
       printf '%s' "$1" | python3 "$tmp/j.py" changed.helpers | tr -d '\n'; printf '] '
       printf '%s' "$1" | python3 "$tmp/j.py" changed.dnsd; }
ctl() { "$BIN" ctl --socket "$tmp/s.sock" "$@"; }

printf '10.1.0.0/16\n' > "$tmp/p1.lst"
printf '10.2.0.0/16\n' > "$tmp/p2.lst"
printf 'example.com\n' > "$tmp/d1.lst"
printf 'example.org\n' > "$tmp/d2.lst"
# spec ФАЙЛ СПИСОК_P ON_FAIL_A СЕРВЕР_B ДОМЕННЫЕ_ФАЙЛЫ
spec() {
    cat > "$tmp/$1" <<EOF
{"schema":2,"from_default":["192.168.1.0/24"],"outputs":{
 "a":{"kind":"interface","device":"wga","on_fail":"$3",
      "obfs":{"mode":"wg-over-tcp","server":"10.99.0.3:4443","listen":"127.0.0.1:5101"}},
 "b":{"kind":"interface","device":"wgb",
      "obfs":{"mode":"wg-over-tcp","server":"$4","listen":"127.0.0.1:5102"}}},
 "channels":[{"name":"p","match":{"prefixes_file":"$tmp/$2"},"out":"a"},
             {"name":"d","match":{"domains_files":[$5]},"out":"b"}]}
EOF
}
D1="\"$tmp/d1.lst\"" D12="\"$tmp/d1.lst\",\"$tmp/d2.lst\""
spec S1.json p1.lst direct 10.99.0.3:4443 "$D1"
spec S2.json p2.lst direct 10.99.0.3:4443 "$D1"
spec S3.json p2.lst drop 10.99.0.3:4443 "$D1"
spec S4.json p2.lst drop 10.99.0.4:4443 "$D1"
spec S5.json p2.lst drop 10.99.0.4:4443 "$D12"
spec S6.json p3.lst drop 10.99.0.4:4443 "$D12"
cp "$tmp/S1.json" "$tmp/spec.json"

pid_of() { grep "^obfs $1 " "$tmp/log" | tail -1 | cut -d' ' -f3; }
handle() { "$real_nft" -a list table inet steer 2>/dev/null | sed -n '1s/.*# handle \([0-9]*\).*/\1/p'; }
dnsd_pid() { grep -o 'supervise: dnsd запущен (pid [0-9]*' "$tmp/d.err" | tail -1 | grep -o '[0-9]*$'; }
tabs() { grep -c "channel b_dom: .*rule(s)" "$tmp/d.err"; }
nft_runs() { [ -f "$tmp/nft.log" ] && wc -l < "$tmp/nft.log" | tr -d ' ' || echo 0; }
nft_loads() { [ -f "$tmp/nft.log" ] && grep -c '^-f ' "$tmp/nft.log" || echo 0; }
ip_changes() { [ -f "$tmp/ip.log" ] && grep -E 'route (replace|add|flush|del)|rule (add|del)' "$tmp/ip.log" |
               sed -n 's/.* table \([0-9]*\).*/\1/p' | sort -u | tr '\n' ' ' | sed 's/ $//'; }
fresh() { : > "$tmp/nft.log"; : > "$tmp/ip.log"; }

STEER_SUPERVISE_EXE="$tmp/helper" "$BIN" daemon --supervise --socket "$tmp/s.sock" \
    --spec "$tmp/spec.json" --state-dir "$tmp/st" \
    --dnsd-flag --listen-port --dnsd-flag 15411 --dnsd-flag --upstream-port --dnsd-flag 15475 \
    2>"$tmp/d.err" &
D=$!
wait_for '[ -S "$tmp/s.sock" ] && [ -n "$(pid_of a)" ] && [ -n "$(pid_of b)" ] && [ -n "$(dnsd_pid)" ]' 5
wait_for '[ "$(tabs)" -ge 1 ]' 5
TA=$(awk '$1 == "a" { print $3 }' "$tmp/st/registry")
TB=$(awk '$1 == "b" { print $3 }' "$tmp/st/registry")

# ---- 1. первый apply — всё ---------------------------------------------------------------
fresh
r="$(ctl apply < "$tmp/S1.json")"
check "первый apply: применён, набор правил и оба выхода" "0 true true [a,b] [] false" \
    "$(printf '%s' "$r" | j code | tr -d '\n') $(printf '%s' "$r" | j applied | tr -d '\n') $(ch "$r")"
check "  одна транзакция nft" "1" "$(nft_loads)"
H1="$(handle)"
check "  таблица в ядре" "yes" "$([ -n "$H1" ] && echo yes || echo no)"
SET="$("$real_nft" list table inet steer | awk '/^\tset /{s=$2} /10\.1\.0\.0\/16/{print s; exit}')"
"$real_nft" add element inet steer "$SET" "{ 10.77.0.1 }"
PA="$(pid_of a)" PB="$(pid_of b)" DN="$(dnsd_pid)" T0="$(tabs)"

# ---- 2. та же спека — ничего ---------------------------------------------------------------
fresh
r="$(ctl apply < "$tmp/S1.json")"
check "apply той же спеки: применён, changed пустой" "0 true false [] [] false" \
    "$(printf '%s' "$r" | j code | tr -d '\n') $(printf '%s' "$r" | j applied | tr -d '\n') $(ch "$r")"
check "  nft не запускался ни разу" "0" "$(nft_runs)"
check "  маршруты и правила не тронуты" "" "$(ip_changes)"
check "  таблица в ядре та же" "$H1" "$(handle)"
check "  элемент, положенный в набор со стороны, на месте" "1" \
    "$("$real_nft" list set inet steer "$SET" | grep -c '10\.77\.0\.1')"
check "  помощники и резолвер — те же процессы" "$PA $PB $DN" "$(pid_of a) $(pid_of b) $(dnsd_pid)"
check "  таблица резолверу не отправлялась" "$T0" "$(tabs)"
check "  stdout — прежняя строка итога" "steer: applied 2 channel(s), 2 output(s)" \
    "$(printf '%s' "$r" | j stdout | head -n 1)"

fresh
r="$(ctl reload)"
check "reload без изменений: changed пустой, nft не запускался" "0 false [] [] false 0" \
    "$(printf '%s' "$r" | j code | tr -d '\n') $(ch "$r") $(nft_runs)"
check "  маршруты не тронуты, таблица та же" " $H1" "$(ip_changes) $(handle)"

# ---- 3. только канал ---------------------------------------------------------------------------
fresh
r="$(ctl apply < "$tmp/S2.json")"
check "сменился только канал: набор правил, маршруты и помощники нет" "0 true [] [] false" \
    "$(printf '%s' "$r" | j code | tr -d '\n') $(ch "$r")"
check "  одна транзакция nft, таблица новая" "1 yes" \
    "$(nft_loads) $([ "$(handle)" != "$H1" ] && echo yes || echo no)"
check "  новый список в наборе" "1" "$("$real_nft" list table inet steer | grep -c '10\.2\.0\.0/16')"
check "  маршруты и правила не тронуты" "" "$(ip_changes)"
check "  помощники и резолвер — те же" "$PA $PB $DN $T0" "$(pid_of a) $(pid_of b) $(dnsd_pid) $(tabs)"

# ---- 4. режим отказа выхода a ----------------------------------------------------------------
fresh
r="$(ctl apply < "$tmp/S3.json")"
check "сменился on_fail выхода a: привязан заново только a" "[a] []" \
    "$(ch "$r" | awk '{print $2, $3}')"
check "  в ядре тронута только таблица a" "$TA" "$(ip_changes)"
check "  помощники — те же" "$PA $PB" "$(pid_of a) $(pid_of b)"

# ---- 5. сервер обфускации выхода b ----------------------------------------------------------
fresh
r="$(ctl apply < "$tmp/S4.json")"
check "сменился сервер обфускации b: перезапущен только его помощник" "[] [b]" \
    "$(ch "$r" | awk '{print $2, $3}')"
wait_for '[ "$(pid_of b)" != "$PB" ]' 5
check "  помощник b — новый процесс, a — прежний" "yes $PA" \
    "$([ "$(pid_of b)" != "$PB" ] && echo yes || echo no) $(pid_of a)"
check "  маршруты не тронуты" "" "$(ip_changes)"
PB="$(pid_of b)"

# ---- 6. состав доменного канала ----------------------------------------------------------------
fresh
r="$(ctl apply < "$tmp/S5.json")"
check "сменился состав доменного канала: резолверу новая таблица" "true" \
    "$(ch "$r" | awk '{print $4}')"
wait_for '[ "$(tabs)" -gt "$T0" ]' 5
check "  резолвер — тот же процесс, таблицу получил" "$DN yes" \
    "$(dnsd_pid) $([ "$(tabs)" -gt "$T0" ] && echo yes || echo no)"

# ---- 7. отказ ядра -------------------------------------------------------------------------------
H5="$(handle)"
printf '999.1.1.1\n' > "$tmp/p3.lst"
before="$(cksum < "$tmp/spec.json")"
fresh
r="$(ctl apply < "$tmp/S6.json")"
check "отказ ядра: не применено, прежняя спека возвращена" "false false true" \
    "$(printf '%s' "$r" | j saved | tr -d '\n') $(printf '%s' "$r" | j applied | tr -d '\n') $(printf '%s' "$r" | j rolled_back)"
check "  spec.json — прежний" "$before" "$(cksum < "$tmp/spec.json")"
check "  прежняя таблица в ядре на месте" "$H5 1" \
    "$(handle) $("$real_nft" list table inet steer | grep -c '10\.2\.0\.0/16')"
kept="$(printf '%s' "$r" | j stderr | sed -n 's/.*(kept: \(.*\))$/\1/p')"
[ -n "$kept" ] && rm -f "$kept"
fresh
r="$(ctl apply < "$tmp/S5.json")"
check "  после отказа применённое забыто: следующий apply — всё" "true [a,b]" \
    "$(ch "$r" | awk '{print $1, $2}')"

# ---- 8. status во время компиляции --------------------------------------------------------------
# Список канала — именованный канал: план открывает его и ждёт данных, пока стенд не разрешит
# писать. Второй демон — без супервизора и с выключенным движком: нужен только план.
mkfifo "$tmp/big.fifo"
python3 - "$tmp/big.lst" <<'PY'
import sys
with open(sys.argv[1], 'w') as f:
    for i in range(50000):
        f.write('11.%d.%d.%d/32\n' % (i // 65536, (i // 256) % 256, i % 256))
PY
cat > "$tmp/feed.py" <<'PY'
import os, sys, time, errno
fifo, src, go = sys.argv[1:4]
while not os.path.exists(go): time.sleep(0.05)
data = open(src, 'rb').read()
while True:
    fd = os.open(fifo, os.O_WRONLY)
    try: os.write(fd, data)
    except OSError as e:
        if e.errno != errno.EPIPE: raise
    os.close(fd)
    time.sleep(0.2)          # читатель закрывает свой конец раньше, чем откроется следующий
PY
python3 "$tmp/feed.py" "$tmp/big.fifo" "$tmp/big.lst" "$tmp/go" &
W=$!
printf '{"schema":2,"from_default":["192.168.1.0/24"],"outputs":{"a":{"kind":"interface","device":"wga"}},"channels":[{"name":"p","match":{"prefixes_file":"%s"},"out":"a"}]}\n' \
    "$tmp/big.fifo" > "$tmp/big.json"
cp "$tmp/S1.json" "$tmp/spec2.json"
STEER_CTL_ENABLED=0 "$BIN" daemon --socket "$tmp/s2.sock" --spec "$tmp/spec2.json" \
    --state-dir "$tmp/st2" 2>"$tmp/d2.err" &
D2=$!
wait_for '[ -S "$tmp/s2.sock" ]' 5
"$BIN" ctl --socket "$tmp/s2.sock" apply < "$tmp/big.json" > "$tmp/big.out" 2>&1 &
AP=$!
sleep 0.5
t="$(python3 -c '
import subprocess, sys, time
t = time.monotonic()
r = subprocess.run([sys.argv[1], "ctl", "--socket", sys.argv[2], "status"], capture_output=True)
print("%s %s" % ("fast" if time.monotonic() - t < 1.0 else "slow", r.returncode))
' "$BIN" "$tmp/s2.sock")"
check "status во время компиляции — сразу, apply ещё идёт" "fast 0 running" \
    "$t $(kill -0 $AP 2>/dev/null && [ ! -s "$tmp/big.out" ] && echo running || echo done)"
touch "$tmp/go"
wait_for '! kill -0 $AP 2>/dev/null' 30
check "  компиляция дошла до конца: спека сохранена" "0 true" \
    "$(j code < "$tmp/big.out" | tr -d '\n') $(j saved < "$tmp/big.out")"
AP=""

printf '\nreconmatch: %s passed, %s failed\n' "$pass" "$fail"
[ "$fail" -eq 0 ]
