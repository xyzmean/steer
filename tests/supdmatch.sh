#!/bin/sh
# steer daemon --supervise: помощники выходов и резолвер — дети демона (src/daemon/supd.c).
#
# Помощники не настоящие: шов STEER_SUPERVISE_EXE (тот же, что у tests/supervisematch.sh)
# подставляет скрипт, который записывает «команда выход pid», по файлу go пишет в трубу
# STEER_EVENT_FD события (up, у выхода a ещё node), по файлу crash.<выход> — down и выходит с
# кодом 3, а по SIGTERM записывает «stop выход» и гаснет через полсекунды. Резолвер настоящий:
# `steer dnsd --table-fd`, поднятый демоном, с апстримом-заглушкой на петле.
#
# Что проверяется: помощники поднимаются в порядке via (цель раньше того, кто через неё идёт);
# каждый получает свою трубу событий; up, node и down из трубы приходят подписчику как helper-up,
# node и helper-down; помощник, убитый молча после up, — тоже helper-down с причиной; упавший
# перезапускается через 5 с, а упавший снова сразу — через 10; reload со сменой параметров одного
# выхода перезапускает только его, без смены — никого; резолвер поднят на таблице от демона и
# после смены спеки (reload) ведёт себя по новой таблице тем же процессом; SIGTERM демону гасит
# помощников по одному в обратном порядке подъёма и резолвер — детей после демона не остаётся.
#
# Под root стенд уходит в своё сетевое пространство (unshare -n); без root — петля хоста и
# высокие порты. Без python3 — пропуск (заглушка апстрима и запросы DNS).
set -u
BIN="${STEER:-./build/steer}"
BIN="$(cd "$(dirname "$BIN")" && pwd)/$(basename "$BIN")"
[ -x "$BIN" ] || { echo "not built: $BIN (make test)"; exit 2; }
command -v python3 >/dev/null 2>&1 || { echo "supdmatch: python3 нет — пропускаю"; exit 0; }
if [ "${SUPD_INNER:-}" != 1 ] && [ "$(id -u)" = 0 ] && unshare -n true 2>/dev/null; then
    SUPD_INNER=1 STEER="$BIN" exec unshare -n sh "$0" "$@"
fi
[ "${SUPD_INNER:-}" = 1 ] && ip link set lo up 2>/dev/null

tmp="$(mktemp -d)"
mkdir -p "$tmp/st"
D="" SUB="" UP=""
trap 'kill $D $SUB $UP 2>/dev/null; rm -rf "$tmp"' EXIT
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

cat > "$tmp/helper" <<H
#!/bin/sh
echo "\$1 \$2 \$\$ \${STEER_EVENT_FD:--}" >> "$tmp/log"
[ -n "\${STEER_EVENT_FD:-}" ] && eval "exec 9>&\$STEER_EVENT_FD"
trap 'echo "stop \$2 \$\$" >> "$tmp/log"; sleep 0.5; exit 0' TERM
while [ ! -e "$tmp/go" ]; do sleep 0.1; done
printf '{"ev":"up"}\n' >&9
[ "\$2" = a ] && printf '{"ev":"node","n":2,"total":5}\n' >&9
while :; do
    if [ -e "$tmp/crash.\$2" ]; then
        rm -f "$tmp/crash.\$2"
        printf '{"ev":"down","why":"стенд: отказ"}\n' >&9
        exit 3
    fi
    sleep 0.1
done
H
chmod +x "$tmp/helper"

LPORT=15311 UPORT=15375
cat > "$tmp/upstream.py" <<'PY'
import socket, sys
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
s.bind(("127.0.0.1", int(sys.argv[1])))
while True:
    data, addr = s.recvfrom(2048)
    qend = 12
    while data[qend]: qend += 1 + data[qend]
    qend += 5
    hdr = data[:2] + b'\x81\x80' + data[4:6] + b'\x00\x01\x00\x00\x00\x00'
    ans = b'\xc0\x0c\x00\x1c\x00\x01\x00\x00\x00\x3c\x00\x10' + b'\x20\x01\x0d\xb8' + b'\x00' * 12
    s.sendto(hdr + data[12:qend] + ans, addr)
PY
# AAAA на имя, которое забрал доменный канал, резолвер гасит NODATA из самого вопроса (ANCOUNT 0),
# не спрашивая апстрим; чужое имя уходит наверх и получает запись (ANCOUNT 1) — см. dnsproxy.sh.
cat > "$tmp/qaaaa.py" <<'PY'
import socket, struct, sys
port, name = int(sys.argv[1]), sys.argv[2]
q = struct.pack('>HHHHHH', 0x7a7a, 0x0100, 1, 0, 0, 0)
for l in name.split('.'): q += bytes([len(l)]) + l.encode()
q += b'\x00' + struct.pack('>HH', 28, 1)
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM); s.settimeout(3)
s.sendto(q, ('127.0.0.1', port))
try:
    d, _ = s.recvfrom(2048)
    print(struct.unpack('>H', d[6:8])[0])
except socket.timeout:
    print('timeout')
PY
python3 "$tmp/upstream.py" "$UPORT" & UP=$!

printf 'swap.test\n' > "$tmp/swap.lst"
# spec [chan] — выходы с obfs: a идёт через t (via), b сам по себе; порядок в спеке — a, t, b.
# $BSRV — сервер обфускации выхода b. chan=1 — доменный канал swap.test → t.
spec() {
    chans='[]'
    [ -n "${1:-}" ] && chans="[{\"name\":\"c\",\"match\":{\"domains_files\":[\"$tmp/swap.lst\"]},\"out\":\"t\"}]"
    cat > "$tmp/spec.json" <<EOF
{"schema":2,"from_default":["127.0.0.0/8"],"outputs":{
 "a":{"kind":"interface","device":"wga","via":"t",
      "obfs":{"mode":"wg-over-tcp","server":"10.99.0.3:4443","listen":"127.0.0.1:5101"}},
 "t":{"kind":"interface","device":"wgt",
      "obfs":{"mode":"wg-over-tcp","server":"10.99.0.3:4443","listen":"127.0.0.1:5102"}},
 "b":{"kind":"interface","device":"wgb",
      "obfs":{"mode":"wg-over-tcp","server":"${BSRV:-10.99.0.3:4443}","listen":"127.0.0.1:5103"}}},
 "channels":$chans}
EOF
}
pid_of() { grep "^obfs $1 " "$tmp/log" | tail -1 | cut -d' ' -f3; }
runs() { grep -c "^obfs $1 " "$tmp/log" 2>/dev/null; }
alive() { p="$(pid_of "$1")"; [ -n "$p" ] && kill -0 "$p" 2>/dev/null && echo yes || echo no; }
ctl() { "$BIN" ctl --socket "$tmp/s.sock" "$@"; }

spec 1
STEER_SUPERVISE_EXE="$tmp/helper" "$BIN" daemon --supervise --socket "$tmp/s.sock" \
    --spec "$tmp/spec.json" --state-dir "$tmp/st" \
    --dnsd-flag --listen-port --dnsd-flag "$LPORT" --dnsd-flag --upstream-port --dnsd-flag "$UPORT" \
    2>"$tmp/d.err" &
D=$!
wait_for '[ -S "$tmp/s.sock" ] && [ "$(runs a)" = 1 ] && [ "$(runs b)" = 1 ]' 5
check "поднято по помощнику на выход" "1 1 1" "$(runs a) $(runs t) $(runs b)"
check "  в порядке via: цель t раньше a, идущего через неё (b — в порядке спеки)" "t b a" \
    "$(grep -o 'supervise: obfs [a-z]* запущен' "$tmp/d.err" | awk '{print $3}' | tr '\n' ' ' | sed 's/ $//')"
check "  каждому — своя труба событий (STEER_EVENT_FD)" "3" \
    "$(grep '^obfs ' "$tmp/log" | awk '$4 != "-"' | wc -l | tr -d ' ')"
DN="$(grep -o 'supervise: dnsd запущен (pid [0-9]*' "$tmp/d.err" | grep -o '[0-9]*$')"
check "резолвер поднят демоном — на таблице" "1" \
    "$(tr '\0' ' ' < "/proc/$DN/cmdline" 2>/dev/null | grep -c -- ' dnsd --table-fd ')"

ctl subscribe > "$tmp/sub.out" 2>&1 &
SUB=$!
wait_for 'grep -q "\"cmd\":\"subscribe\"" "$tmp/sub.out" 2>/dev/null' 5
touch "$tmp/go"
wait_for '[ "$(grep -c "\"ev\":\"helper-up\"" "$tmp/sub.out")" = 3 ] && grep -q "\"ev\":\"node\"" "$tmp/sub.out"' 5
check "up из трубы — подписчику helper-up по каждому выходу" \
'{"v":1,"ev":"helper-up","out":"a","helper":"obfs"}
{"v":1,"ev":"helper-up","out":"b","helper":"obfs"}
{"v":1,"ev":"helper-up","out":"t","helper":"obfs"}' "$(grep '"ev":"helper-up"' "$tmp/sub.out" | sort)"
check "node из трубы — подписчику node" '{"v":1,"ev":"node","out":"a","n":2,"total":5}' \
    "$(grep '"ev":"node"' "$tmp/sub.out")"

# Резолвер на таблице: канал swap.test есть — AAAA погашен; чужое имя — ответ апстрима.
wait_for '[ "$(python3 "$tmp/qaaaa.py" "$LPORT" other.test)" = 1 ]' 5
check "резолвер: канал из таблицы демона забрал swap.test, чужое имя — наверх" "0 1" \
    "$(python3 "$tmp/qaaaa.py" "$LPORT" swap.test) $(python3 "$tmp/qaaaa.py" "$LPORT" other.test)"

# reload без изменений — никого не трогать; со сменой сервера обфускации b — только b.
pa="$(pid_of a)" pt="$(pid_of t)" pb="$(pid_of b)"
r="$(ctl reload)"
check "reload с --supervise: резолверу таблица, помощников сверяет демон" "table daemon" \
    "$(printf '%s' "$r" | python3 -c 'import json,sys; d=json.load(sys.stdin)["reload"]; print(d["dnsd"], d["outputs"])')"
sleep 1
check "  без изменений спеки — никто не перезапущен" "$pa $pt $pb" "$(pid_of a) $(pid_of t) $(pid_of b)"
BSRV=10.99.0.4:4443 spec 1
ctl reload >/dev/null
wait_for '[ "$(runs b)" = 2 ] && [ "$(alive b)" = yes ]' 5
check "reload со сменой параметров b: b поднят заново" "2 yes" "$(runs b) $(alive b)"
check "  прежний b погашен" "no" "$(kill -0 "$pb" 2>/dev/null && echo yes || echo no)"
check "  a и t не тронуты" "$pa $pt" "$(pid_of a) $(pid_of t)"
check "  и о причине сказано" "1" "$(grep -c 'supervise: obfs b — параметры выхода изменились' "$tmp/d.err")"

check "  подписчику — helper-down с нашей причиной" \
    '{"v":1,"ev":"helper-down","out":"b","helper":"obfs","why":"перезапуск: параметры выхода изменились"}' \
    "$(grep '"ev":"helper-down"' "$tmp/sub.out")"

# Смена спеки меняет поведение резолвера без перезапуска: канала больше нет.
BSRV=10.99.0.4:4443 spec ""
ctl reload >/dev/null
sleep 1
check "резолвер: после reload без канала swap.test уходит наверх" "1" \
    "$(python3 "$tmp/qaaaa.py" "$LPORT" swap.test)"
check "  тем же процессом" "$DN yes" "$DN $(kill -0 "$DN" 2>/dev/null && echo yes || echo no)"
check "  и новую таблицу он принял" "1" "$(grep -c 'таблица от демона: 0 доменных' "$tmp/d.err")"

# Отказ: помощник пишет down и выходит с кодом 3 — helper-down с причиной, перезапуск через 5 с.
touch "$tmp/crash.b"
wait_for 'grep -q "стенд: отказ" "$tmp/sub.out"' 5
check "down из трубы — подписчику helper-down с причиной" \
    '{"v":1,"ev":"helper-down","out":"b","helper":"obfs","why":"стенд: отказ"}' \
    "$(grep '"ev":"helper-down"' "$tmp/sub.out" | grep 'стенд')"
check "  в журнале — выход и пауза 5 с" "1" "$(grep -c 'supervise: obfs b вышел (код 3) — перезапуск через 5 с' "$tmp/d.err")"
sleep 4
check "  за 4 с ещё не перезапущен" "2" "$(runs b)"
wait_for '[ "$(runs b)" = 3 ]' 4
check "  через 5 с перезапущен" "3" "$(runs b)"
wait_for '[ "$(grep -c "\"ev\":\"helper-up\"" "$tmp/sub.out")" -ge 5 ]' 3
touch "$tmp/crash.b"
wait_for 'grep -q "supervise: obfs b вышел (код 3) — перезапуск через 10 с" "$tmp/d.err"' 5
check "  упал снова сразу — пауза растёт до 10 с" "1" \
    "$(grep -c 'supervise: obfs b вышел (код 3) — перезапуск через 10 с' "$tmp/d.err")"

# Молча убитый после up — тоже helper-down: причина — сигнал.
kill -KILL "$(pid_of t)"
wait_for 'grep -q "\"out\":\"t\",\"helper\":\"obfs\",\"why\"" "$tmp/sub.out"' 5
check "помощник убит молча после up — helper-down с причиной" \
    '{"v":1,"ev":"helper-down","out":"t","helper":"obfs","why":"процесс убит (сигнал 9)"}' \
    "$(grep '"out":"t","helper":"obfs","why"' "$tmp/sub.out")"
wait_for '[ "$(runs t)" = 2 ] && [ "$(alive t)" = yes ]' 8
wait_for '[ "$(runs b)" -ge 4 ] && [ "$(alive b)" = yes ]' 12

# Тишина: помощники и резолвер живы и молчат — демон не просыпается.
sleep 1
cs0=$(awk '/^voluntary_ctxt_switches/{print $2}' "/proc/$D/status")
sleep 3
cs1=$(awk '/^voluntary_ctxt_switches/{print $2}' "/proc/$D/status")
q=$(( cs1 - cs0 )); [ "$q" -le 1 ] && q=ok
check "в тишине демон с детьми не просыпается" "ok" "$q"

# SIGTERM: по одному в обратном порядке подъёма (a раньше t), резолвер — тоже; детей не остаётся.
kill $SUB 2>/dev/null; wait $SUB 2>/dev/null; SUB=""
pa="$(pid_of a)" pt="$(pid_of t)" pb="$(pid_of b)"
before=$(wc -l < "$tmp/log")
kill -TERM $D
wait_for '! kill -0 $D 2>/dev/null' 15
check "SIGTERM: демон вышел" "no" "$(kill -0 $D 2>/dev/null && echo yes || echo no)"
live=""
for p in $pa $pt $pb $DN; do kill -0 "$p" 2>/dev/null && live="$live $p"; done
check "  помощники и резолвер погашены" "" "$live"
check "  помощники — по одному, в обратном порядке подъёма" "a b t" \
    "$(tail -n +$((before + 1)) "$tmp/log" | awk '$1 == "stop" {print $2}' | tr '\n' ' ' | sed 's/ $//')"
check "  журнал демона — с уровнем" "0" \
    "$(grep -v '^steer\[\(warn\|info\)\]' "$tmp/d.err" | grep -v '^steer dnsd: ' | grep -c .)"
D=""

printf '\nsupdmatch: %s passed, %s failed\n' "$pass" "$fail"
[ "$fail" -eq 0 ]
