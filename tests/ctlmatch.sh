#!/bin/sh
# steer ctl-serve: управляющий сокет — то, через что приложение splify2 на телефоне говорит с
# движком (см. шапку src/ctl.c и docs/ctl.md).
#
# Что проверяется.
#  1. Каждая команда таблицы отвечает тем же, что одноимённая подкоманда, набранная руками:
#     status (без поля времени), status fast, diag (код), explain, version; vless-nodes в
#     базовой сборке — честный отказ подкоманды, а не сервера.
#  2. Слова запроса проверяются до запуска: флаг вместо адреса, чужой знак, число вне
#     пределов, неизвестная команда, лишнее слово — отказ bad-request/unknown-command.
#  3. Пределы: строка длиннее 512 байт и тело больше 1 МиБ — too-large, причём тело не
#     читается вовсе; тело короче объявленного — bad-request; пятый одновременный клиент —
#     busy, и после ухода первых четырёх сервер снова отвечает.
#  4. Кого пускать: uid 65534 — denied (и отказ записан в журнал), uid из --allow-uid —
#     пускается.
#  5. apply: негодная спека не трогает spec.json и не оставляет временных файлов; годная при
#     выключенном движке сохраняется и не применяется; check ничего не сохраняет.
#  6. reload: супервизор помощников получает SIGHUP и поднимает выход, добавленный в спеку.
#  7. Под root в своём сетевом пространстве с настоящим nft: apply при включённом движке
#     ставит таблицу; резолвер после apply получает HUP, если состав доменных каналов тот же, и
#     TERM, если он изменился; отказ ядра (nft -f не прошёл) возвращает прежнюю спеку.
#
# Без root пункты 4 и 7 пропускаются, без python3 — весь стенд (им шлются сырые запросы).
set -u
BIN="${STEER:-./build/steer}"
BIN="$(cd "$(dirname "$BIN")" && pwd)/$(basename "$BIN")"
[ -x "$BIN" ] || { echo "not built: $BIN (make test)"; exit 2; }
command -v python3 >/dev/null 2>&1 || { echo "ctlmatch: python3 нет — пропускаю"; exit 0; }
if [ "${CTLMATCH_INNER:-}" != 1 ] && [ "$(id -u)" = 0 ] && unshare -n true 2>/dev/null; then
    CTLMATCH_INNER=1 STEER="$BIN" exec unshare -n sh "$0" "$@"
fi
ROOT=0
[ "$(id -u)" = 0 ] && ROOT=1

tmp="$(mktemp -d)"
# Обходить каталог сокета должен и чужой uid из пункта 4 — как /data/misc/steer (0711).
chmod 0711 "$tmp"
mkdir -p "$tmp/state" "$tmp/bin"
SRV="" SUP="" DNSD=""
trap 'kill $SRV $SUP $DNSD 2>/dev/null; rm -rf "$tmp"' EXIT
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

# j ПУТЬ — поле ответа со стандартного ввода; путь через точку, нет поля — «-».
cat > "$tmp/j.py" <<'PY'
import json, sys
d = json.loads(sys.stdin.read())
for k in sys.argv[1].split('.'):
    d = d.get(k) if isinstance(d, dict) else None
if d is None: print('-')
elif isinstance(d, bool): print('true' if d else 'false')
else: sys.stdout.write(d if isinstance(d, str) else str(d))
PY
j() { python3 "$tmp/j.py" "$1"; }
# raw — послать стандартный ввод как есть, закрыть запись, напечатать ответ.
cat > "$tmp/raw.py" <<'PY'
import socket, sys
s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
s.connect(sys.argv[1])
try:
    s.sendall(sys.stdin.buffer.read())
except OSError:
    pass
s.shutdown(socket.SHUT_WR)
out = b''
while True:
    try:
        b = s.recv(65536)
    except ConnectionResetError:
        # Сервер обязан дочитывать отказанный запрос (ctl_close), и сброс после ответа —
        # это нарушение, которое стенд должен видеть, а не прятать.
        out += b'<RESET>'
        break
    if not b: break
    out += b
sys.stdout.write(out.decode())
PY
raw() { python3 "$tmp/raw.py" "$tmp/s.sock"; }
# hold N — открыть N соединений и молчать, пока не появится файл hold.stop.
cat > "$tmp/hold.py" <<'PY'
import socket, sys, os, time
ss = []
for _ in range(int(sys.argv[2])):
    s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM); s.connect(sys.argv[1]); ss.append(s)
open(sys.argv[3], 'w').close()
while not os.path.exists(sys.argv[4]): time.sleep(0.05)
PY
ctl() { "$BIN" ctl --socket "$tmp/s.sock" "$@"; }

# nft: в пространстве стенда — настоящий через обёртку, которая по файлу failnft отказывает
# на `nft -f` (отказ ядра, которого dry-run не видит); без root — заглушка с отказом, как в
# statusmatch.sh: счётчики тогда не читаются, ответ от них не зависит.
real_nft="$(command -v nft 2>/dev/null || true)"
if [ "${CTLMATCH_INNER:-}" = 1 ] && [ -n "$real_nft" ]; then
    cat > "$tmp/bin/nft" <<EOF
#!/bin/sh
if [ -e "$tmp/failnft" ]; then for a in "\$@"; do [ "\$a" = -f ] && exit 1; done; fi
exec "$real_nft" "\$@"
EOF
else
    printf '#!/bin/sh\nexit 1\n' > "$tmp/bin/nft"
fi
chmod +x "$tmp/bin/nft"
PATH="$tmp/bin:$PATH"
export PATH

printf '10.1.0.0/16\n' > "$tmp/p1.lst"
printf '10.2.0.0/16\n' > "$tmp/p2.lst"
printf 'example.com\n' > "$tmp/d1.lst"
printf 'example.org\n' > "$tmp/d2.lst"
# spec ИМЯ [файл подсетей] [файлы доменов через запятую] — спека с выходом vpn на lo.
spec() {
    ch='{"name":"p","match":{"prefixes_files":["'"$2"'"]},"out":"vpn"}'
    if [ -n "${3:-}" ]; then
        dl=""; for f in $(echo "$3" | tr ',' ' '); do dl="$dl${dl:+,}\"$f\""; done
        ch="$ch"',{"name":"d","match":{"domains_files":['"$dl"'],"mode":"fakeip"},"out":"vpn"}'
    fi
    printf '{"schema":1,"from_default":["127.0.0.0/8"],"outputs":{"direct":{"kind":"direct"},'\
'"vpn":{"kind":"interface","device":"lo"}},"channels":[%s]}\n' "$ch" > "$tmp/$1"
}
spec A.json "$tmp/p1.lst"
spec B.json "$tmp/p2.lst"
printf '{"schema":1,"outputs":{"x":{"kind":"bogus"}},"channels":[]}\n' > "$tmp/bad.json"
cp "$tmp/A.json" "$tmp/spec.json"

# Без root стенд сам — чужой uid для сервера: пускаем его явно, как пустили бы отладку.
self_uid=""
[ $ROOT = 1 ] || self_uid="--allow-uid $(id -u)"
serve() {   # serve ВКЛЮЧЁН — поднять сервер заново
    [ -n "$SRV" ] && { kill "$SRV" 2>/dev/null; wait "$SRV" 2>/dev/null; }
    STEER_CTL_ENABLED="$1" "$BIN" ctl-serve --socket "$tmp/s.sock" --spec "$tmp/spec.json" \
        --state-dir "$tmp/state" --allow-uid 65533 $self_uid 2>>"$tmp/serve.err" &
    SRV=$!
    wait_for '[ -S "$tmp/s.sock" ]' 5
}
serve 0

# ---- 1. команды отвечают тем же, что подкоманды -----------------------------------------
r="$(ctl version)"
check "version: код 0" "0" "$(printf '%s' "$r" | j code)"
check "version: тот же текст, что у steer version" "$("$BIN" version)" "$(printf '%s' "$r" | j stdout)"

direct="$("$BIN" status --spec "$tmp/spec.json" --state-dir "$tmp/state" 2>/dev/null | sed 's/"at":[0-9]*,//')"
r="$(ctl status)"
check "status: код 0" "0" "$(printf '%s' "$r" | j code)"
check "status: тот же JSON, что у подкоманды (без времени)" "$direct" \
    "$(printf '%s' "$r" | j stdout | sed 's/"at":[0-9]*,//')"
r="$(ctl status fast)"
check "status fast: запомненный ответ" "1" "$(printf '%s' "$r" | j stdout | grep -c '"cached":true')"

"$BIN" diag --spec "$tmp/spec.json" --state-dir "$tmp/state" >/dev/null 2>&1; dcode=$?
r="$(ctl diag)"
check "diag: тот же код, что у подкоманды" "$dcode" "$(printf '%s' "$r" | j code)"
check "diag: stdout — JSON" "{" "$(printf '%s' "$r" | j stdout | head -c 1)"

r="$(ctl explain 10.1.2.3)"
check "explain: тот же ответ, что у подкоманды" \
    "$("$BIN" explain 10.1.2.3 --spec "$tmp/spec.json" --state-dir "$tmp/state" 2>/dev/null)" \
    "$(printf '%s' "$r" | j stdout)"

r="$(ctl vless-nodes vpn)"
check "vless-nodes в базовой сборке: отказ подкоманды (код 2), не сервера" "2 -" \
    "$(printf '%s' "$r" | j code) $(printf '%s' "$r" | j error)"

# ---- 2. слова запроса -------------------------------------------------------------------
check "explain с флагом вместо адреса — bad-request" "bad-request" "$(ctl explain --spec | j error)"
check "explain с чужим знаком — bad-request" "bad-request" "$(ctl 'explain' 'a;b' | j error)"
check "vless-probe: срок вне 1..30 — bad-request" "bad-request" "$(ctl vless-probe vpn 0 99 | j error)"
check "vless-probe: номер не число — bad-request" "bad-request" "$(ctl vless-probe vpn abc | j error)"
check "status с лишним словом — bad-request" "bad-request" "$(ctl status slow | j error)"
check "неизвестная команда — unknown-command" "unknown-command" "$(ctl conns-all | j error)"
check "два пробела подряд — bad-request" "bad-request" "$(printf 'explain  1.1.1.1\n' | raw | j error)"

# ---- 3. пределы -------------------------------------------------------------------------
check "строка длиннее 512 байт — too-large" "too-large" \
    "$(head -c 1000 /dev/zero | tr '\0' x | raw | j error)"
check "тело больше 1 МиБ — too-large до чтения тела" "too-large" \
    "$(printf 'apply 2000000\n{}' | raw | j error)"
check "тело короче объявленного — bad-request" "bad-request" \
    "$(printf 'apply 100\n{"a":1}' | raw | j error)"
check "у apply нет длины тела — bad-request" "bad-request" "$(printf 'apply\n' | raw | j error)"

rm -f "$tmp/hold.ready" "$tmp/hold.stop"
python3 "$tmp/hold.py" "$tmp/s.sock" 4 "$tmp/hold.ready" "$tmp/hold.stop" & HOLD=$!
wait_for '[ -e "$tmp/hold.ready" ]' 5
sleep 0.3
check "пятый одновременный клиент — busy" "busy" "$(ctl status | j error)"
touch "$tmp/hold.stop"; wait $HOLD 2>/dev/null
wait_for '[ "$(ctl version | j code)" = 0 ]' 3
check "после ухода четырёх сервер снова отвечает" "0" "$(ctl version | j code)"

# ---- 4. кого пускать --------------------------------------------------------------------
if [ $ROOT = 1 ] && command -v setpriv >/dev/null 2>&1; then
    r="$(setpriv --reuid 65534 --regid 65534 --clear-groups "$BIN" ctl --socket "$tmp/s.sock" status)"
    check "uid 65534 — denied" "denied" "$(printf '%s' "$r" | j error)"
    check "  и отказ записан в журнал сервера" "1" "$(grep -c 'steer\[warn\] ctl: отказ: uid 65534' "$tmp/serve.err")"
    r="$(setpriv --reuid 65533 --regid 65533 --clear-groups "$BIN" ctl --socket "$tmp/s.sock" version)"
    check "uid из --allow-uid — пускается" "0" "$(printf '%s' "$r" | j code)"
else
    echo "ctlmatch: не root или нет setpriv — проверки uid пропущены"
fi

# ---- 5. apply и check -------------------------------------------------------------------
sum() { cksum < "$tmp/spec.json"; }
before="$(sum)"
r="$(ctl check < "$tmp/bad.json")"
check "check негодной спеки: код 2 и причина" "2 1" \
    "$(printf '%s' "$r" | j code) $(printf '%s' "$r" | j stderr | grep -c 'kind')"
check "check годной спеки: код 0" "0" "$(ctl check < "$tmp/B.json" | j code)"
check "check ничего не сохраняет" "$before" "$(sum)"
r="$(ctl apply < "$tmp/bad.json")"
check "apply негодной спеки: отказ, saved=false" "2 false false" \
    "$(printf '%s' "$r" | j code) $(printf '%s' "$r" | j saved) $(printf '%s' "$r" | j applied)"
check "apply негодной спеки: spec.json не тронут" "$before" "$(sum)"
check "  и временных файлов не осталось" "0" "$(ls "$tmp" | grep -c 'ctl-')"
r="$(ctl apply < "$tmp/B.json")"
check "apply при выключенном движке: сохранена, не применена" "0 true false false" \
    "$(printf '%s' "$r" | j code) $(printf '%s' "$r" | j saved) $(printf '%s' "$r" | j applied) $(printf '%s' "$r" | j enabled)"
check "  spec.json — присланная спека" "$(cksum < "$tmp/B.json")" "$(sum)"

# ---- 6. reload: супервизору SIGHUP ------------------------------------------------------
cat > "$tmp/helper" <<H
#!/bin/sh
echo "\$1 \$2 \$\$" >> "$tmp/helper.log"
trap 'exit 0' TERM
while :; do sleep 1; done
H
chmod +x "$tmp/helper"
obfs_spec() {   # obfs_spec ВЫХОД... — спека супервизора с obfs у каждого выхода
    printf '{"schema":2,"from_default":["192.168.1.0/24"],"outputs":{' > "$tmp/sup.json"
    sep=""
    for o in "$@"; do
        printf '%s"%s":{"kind":"interface","device":"wg%s","obfs":{"mode":"wg-over-tcp","server":"10.99.0.3:4443","listen":"127.0.0.1:5%s"}}' \
            "$sep" "$o" "${#o}" "$(printf '%04d' "${#o}")" >> "$tmp/sup.json"
        sep=","
    done
    printf '},"channels":[]}\n' >> "$tmp/sup.json"
}
r="$(ctl reload)"
check "reload без резолвера и супервизора: трогать некого" "0 none none" \
    "$(printf '%s' "$r" | j code) $(printf '%s' "$r" | j reload.dnsd) $(printf '%s' "$r" | j reload.outputs)"
obfs_spec a
STEER_SUPERVISE_EXE="$tmp/helper" "$BIN" supervise --spec "$tmp/sup.json" 2>"$tmp/sup.err" &
SUP=$!
wait_for 'grep -q "^obfs a " "$tmp/helper.log" 2>/dev/null' 5
obfs_spec a bb
r="$(ctl reload)"
check "reload: супервизору послан SIGHUP" "hup" "$(printf '%s' "$r" | j reload.outputs)"
wait_for 'grep -q "^obfs bb " "$tmp/helper.log" 2>/dev/null' 5
check "  и он поднял выход, добавленный в спеку" "1" "$(grep -c '^obfs bb ' "$tmp/helper.log")"
check "  а прежний не тронул" "1" "$(grep -c '^obfs a ' "$tmp/helper.log")"
kill "$SUP"; wait "$SUP" 2>/dev/null; SUP=""

# ---- 7. настоящий apply, резолвер и откат -----------------------------------------------
if [ "${CTLMATCH_INNER:-}" = 1 ] && [ -n "$real_nft" ] && ip link set lo up 2>/dev/null &&
   "$real_nft" add table inet ctlmatch_probe 2>/dev/null; then
    "$real_nft" delete table inet ctlmatch_probe
    serve 1
    spec D.json "$tmp/p1.lst" "$tmp/d1.lst"
    r="$(ctl apply < "$tmp/D.json")"
    check "apply при включённом движке: применена" "0 true true" \
        "$(printf '%s' "$r" | j code) $(printf '%s' "$r" | j saved) $(printf '%s' "$r" | j applied)"
    check "  таблица движка в ядре" "0" "$("$real_nft" list table inet steer >/dev/null 2>&1; echo $?)"
    check "explain после apply: адрес ушёл в выход vpn" "1" \
        "$(ctl explain 10.1.2.3 | j stdout | grep -c 'output "vpn"')"

    "$BIN" dnsd --spec "$tmp/spec.json" --state-dir "$tmp/state" \
        --fakeip-state "$tmp/state/fakeip" 2>"$tmp/dnsd.err" &
    DNSD=$!
    wait_for '[ -s "$tmp/state/dnsd.sig" ]' 5
    # Обновился только СОСТАВ списка (как после ночного обновления) — подпись та же: HUP.
    # Путь файла подсетей в подписи тоже есть (список может нести и домены, и подсети), поэтому
    # меняется содержимое, а не имя.
    printf 'example.com\nexample.net\n' > "$tmp/d1.lst"
    r="$(ctl apply < "$tmp/D.json")"
    check "apply без смены доменных каналов: резолверу HUP" "0 hup" \
        "$(printf '%s' "$r" | j code) $(printf '%s' "$r" | j reload.dnsd)"
    sleep 0.5
    check "  резолвер жив и перечитал списки" "yes 2" \
        "$(kill -0 $DNSD 2>/dev/null && echo yes || echo no) $(grep -c 'channel .*rule(s)' "$tmp/dnsd.err")"
    spec D3.json "$tmp/p1.lst" "$tmp/d1.lst,$tmp/d2.lst"
    r="$(ctl apply < "$tmp/D3.json")"
    check "apply со сменой состава доменных каналов: резолверу перезапуск" "0 restart" \
        "$(printf '%s' "$r" | j code) $(printf '%s' "$r" | j reload.dnsd)"
    wait_for '! kill -0 $DNSD 2>/dev/null' 5
    check "  резолвер получил TERM и вышел (поднимет init)" "no" \
        "$(kill -0 $DNSD 2>/dev/null && echo yes || echo no)"
    DNSD=""

    touch "$tmp/failnft"
    before="$(sum)"
    r="$(ctl apply < "$tmp/B.json")"
    check "отказ ядра: apply не прошёл, прежняя спека возвращена" "false false true" \
        "$(printf '%s' "$r" | j saved) $(printf '%s' "$r" | j applied) $(printf '%s' "$r" | j rolled_back)"
    check "  код не 0" "yes" "$([ "$(printf '%s' "$r" | j code)" != 0 ] && echo yes || echo no)"
    check "  spec.json — прежняя" "$before" "$(sum)"
    check "  временных файлов не осталось" "0" "$(ls "$tmp" | grep -c 'ctl-')"
    rm -f "$tmp/failnft"
    "$BIN" down --state-dir "$tmp/state" >/dev/null 2>&1
else
    echo "ctlmatch: нет root, сетевого пространства или nf_tables — настоящий apply пропущен"
fi

kill "$SRV" 2>/dev/null; wait "$SRV" 2>/dev/null
check "SIGTERM: сервер убрал за собой сокет" "no" "$([ -e "$tmp/s.sock" ] && echo yes || echo no)"
SRV=""

printf '\nctlmatch: %s passed, %s failed\n' "$pass" "$fail"
[ "$fail" -eq 0 ]
