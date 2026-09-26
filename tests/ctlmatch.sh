#!/bin/sh
# steer ctl-serve: управляющий сокет — то, через что приложение splify2 на телефоне говорит с
# движком (см. шапку src/daemon/ctl.c и docs/ctl.md).
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
#  7. Файлы списков: put-file кладёт файл переименованием (прежний файл, на который держат
#     ссылку, не переписан на месте), тело больше 1 МиБ (предела спеки) принимается, больше
#     16 МиБ — too-large без чтения тела; имена с «..», «/», точкой или «-» в начале — отказ;
#     тело короче объявленного не оставляет ни файла, ни временного; пределы каталога (256
#     файлов) — отказ новому имени и замена старого; list-files — по имени, без скрытых;
#     rm-file — removed true/false, отказ in-use для файла из сохранённой спеки; брошенный
#     временный файл сервер убирает при старте.
#  8. Под root в своём сетевом пространстве с настоящим nft: apply при включённом движке
#     ставит таблицу; резолвер после apply получает HUP, если состав доменных каналов тот же, и
#     TERM, если он изменился; отказ ядра (nft -f не прошёл) возвращает прежнюю спеку. conns:
#     из записей conntrack с разными метками в ответе только те, у которых поле метки движка не
#     ноль, с выходом по реестру (или null), с состоянием TCP и счётчиками, если их вело ядро.
#     dns-log: имена, спрошенные у резолвера по UDP и по TCP, — с каналом, выходом и счётчиком;
#     без резолвера — "running":false; сокет журнала резолвер убирает при выходе.
#  9. Демон (steer daemon, ctl-serve — его прежнее имя): status из памяти байт в байт совпадает
#     с подкомандой и после apply отдаёт новую спеку; explain — тоже; subscribe получает applied
#     после apply и reload и spec-error, когда спека не прочиталась (а status отвечает по
#     последней годной); в тишине, с открытым подписчиком, демон не просыпается; подписчик,
#     который не читает, отключается по переполнению очереди, а демон отвечает остальным и
#     читающий подписчик остаётся.
# 10. Сторож в демоне (steer daemon --watch; root, своё сетевое пространство и свой /sys): первый
#     проход при старте; устройство упало (ip link set down) — внеочередной проход по событию
#     netlink, подписчику switched с причиной, status из памяти и таблица выхода — на новом
#     устройстве, выбор отражён в файл active прежним форматом, замеры и отметки оживлений на
#     диск не пишутся; status во время долгой пробы (адресат молчит, проба ждёт 3 с) отвечает
#     сразу — проход идёт в цикле демона, без ребёнка; оживление — revived; живых нет — failed с
#     on_fail и запрет в таблице; в тишине демон не просыпается; после перезапуска выход не
#     перепривязан; проходы по периоду — не чаще периода, и ни один проход по исправной спеке не
#     запускает процессов (счёт PID в своём пространстве PID демона).
#
# Без root пункты 4 и 8 пропускаются, без python3 — весь стенд (им шлются сырые запросы).
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
SRV="" SUP="" DNSD="" SUB1=""
trap 'kill $SRV $SUP $DNSD $SUB1 ${WD:-} ${WSUB:-} ${RPID:-} 2>/dev/null; rm -rf "$tmp"' EXIT
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
        --state-dir "$tmp/state" --lists-dir "$tmp/lists" --allow-uid 65533 $self_uid \
        2>>"$tmp/serve.err" &
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
# sub-check: разбор подписки подкомандой vless-nodes по временному файлу. В базовой сборке
# VLESS нет — честный отказ подкоманды (код 2), не сервера; временный файл убран в любом случае.
printf 'vless://11111111-2222-3333-4444-555555555555@1.2.3.4:443?security=none#n\n' > "$tmp/sub.txt"
r="$(ctl sub-check < "$tmp/sub.txt")"
if "$BIN" version | grep -q 'расширенная'; then
    check "sub-check: код 0, пригодных узлов 1" "0 1" \
        "$(printf '%s' "$r" | j code) $(printf '%s' "$r" | j stdout | j usable)"
else
    check "sub-check в базовой сборке: отказ подкоманды (код 2), не сервера" "2 -" \
        "$(printf '%s' "$r" | j code) $(printf '%s' "$r" | j error)"
fi
check "  временный файл подписки убран" "0" "$(ls /tmp | grep -c "^sub-check\.ctl-")"
check "sub-check без длины тела — bad-request" "bad-request" "$(printf 'sub-check\n' | raw | j error)"
r="$(ctl dns-log)"
check "dns-log без резолвера: код 0, running=false, имён нет" "0 false" \
    "$(printf '%s' "$r" | j code) $(printf '%s' "$r" | j stdout | j running)"

# ---- 2. слова запроса -------------------------------------------------------------------
check "explain с флагом вместо адреса — bad-request" "bad-request" "$(ctl explain --spec | j error)"
check "explain с чужим знаком — bad-request" "bad-request" "$(ctl 'explain' 'a;b' | j error)"
check "vless-probe: срок вне 1..30 — bad-request" "bad-request" "$(ctl vless-probe vpn 0 99 | j error)"
check "vless-probe: номер не число — bad-request" "bad-request" "$(ctl vless-probe vpn abc | j error)"
check "status с лишним словом — bad-request" "bad-request" "$(ctl status slow | j error)"
check "неизвестная команда — unknown-command" "unknown-command" "$(ctl conns-all | j error)"
check "conns со словом — bad-request" "bad-request" "$(ctl conns all | j error)"
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

# ---- 7. файлы списков -------------------------------------------------------------------
L="$tmp/lists"
check "list-files до первого put: пусто, каталога нет" "0 0 no" \
    "$(ctl list-files | j code) $(ctl list-files | python3 -c 'import json,sys; print(len(json.load(sys.stdin)["files"]))') \
$([ -e "$L" ] && echo yes || echo no)"
printf 'one\n' > "$tmp/f1"
r="$(ctl put-file yt.lst "$tmp/f1")"
check "put-file: код 0, имя, размер и путь" "0 yt.lst 4 $L/yt.lst" \
    "$(printf '%s' "$r" | j code) $(printf '%s' "$r" | j name) $(printf '%s' "$r" | j size) $(printf '%s' "$r" | j path)"
check "  файл на месте с присланным содержимым" "one" "$(cat "$L/yt.lst")"
check "  каталог создан с правами 0700" "700" "$(stat -c %a "$L")"
# Атомарность: замена идёт переименованием нового файла, а не записью в прежний. Жёсткая
# ссылка на прежний файл держит его inode: запись на месте переписала бы и её.
ln "$L/yt.lst" "$tmp/old-link"
printf 'two\n' | ctl put-file yt.lst - >/dev/null
check "put-file поверх: новое содержимое под именем" "two" "$(cat "$L/yt.lst")"
check "  прежний файл не переписан на месте (замена переименованием)" "one" "$(cat "$tmp/old-link")"
check "  временных файлов не осталось" "0" "$(ls -A "$L" | grep -c '^\.')"
head -c 2000000 /dev/zero | tr '\0' a > "$tmp/big"
check "put-file больше 1 МиБ (предела спеки): принят" "0 2000000" \
    "$(ctl put-file big.lst "$tmp/big" | j code) $(stat -c %s "$L/big.lst")"
check "put-file больше 16 МиБ — too-large до чтения тела" "too-large" \
    "$(printf 'put-file huge.lst 16777217\n' | raw | j error)"
check "  и файла нет" "no" "$([ -e "$L/huge.lst" ] && echo yes || echo no)"
check "put-file: тело короче объявленного — bad-request" "bad-request" \
    "$(printf 'put-file short.lst 100\nabc' | raw | j error)"
check "  ни файла, ни временного" "no 0" \
    "$([ -e "$L/short.lst" ] && echo yes || echo no) $(ls -A "$L" | grep -c '^\.')"
for bad in ../x a..b .hidden -x 'a/b' 'a;b' \
           "$(head -c 65 /dev/zero | tr '\0' n)"; do
    check "put-file с именем «$bad» — bad-request" "bad-request" \
        "$(printf 'x' | ctl put-file "$bad" - | j error)"
done
check "put-file без тела (нет длины) — bad-request" "bad-request" "$(printf 'put-file a.lst\n' | raw | j error)"
check "  плохие имена не создали ничего вне каталога" "no no" \
    "$([ -e "$tmp/x" ] && echo yes || echo no) $([ -e "$L/a" ] && echo yes || echo no)"
touch "$L/.stray"
r="$(ctl list-files)"
check "list-files: по имени, без скрытых" "big.lst:2000000 yt.lst:4" \
    "$(printf '%s' "$r" | python3 -c 'import json,sys; print(" ".join("%s:%d" % (f["name"], f["size"]) for f in json.load(sys.stdin)["files"]))')"
check "  mtime — секунды Unix, свежие" "yes" \
    "$(printf '%s' "$r" | python3 -c 'import json,sys,time; print("yes" if all(abs(f["mtime"]-time.time())<120 for f in json.load(sys.stdin)["files"]) else "no")')"
check "  dir — каталог списков" "$L" "$(printf '%s' "$r" | j dir)"
rm -f "$L/.stray"
# Пределы каталога: 256 файлов уже лежат — новому имени отказ, замене старого — нет.
i=0; while [ $i -lt 254 ]; do : > "$L/n$i"; i=$((i + 1)); done
check "257-й файл — too-large" "too-large" "$(printf 'x' | ctl put-file new.lst - | j error)"
check "замена при полном каталоге — принята" "0" "$(printf 'x' | ctl put-file n0 - | j code)"
i=0; while [ $i -lt 254 ]; do rm -f "$L/n$i"; i=$((i + 1)); done
r="$(ctl rm-file big.lst)"
check "rm-file: removed=true, файла нет" "0 true no" \
    "$(printf '%s' "$r" | j code) $(printf '%s' "$r" | j removed) $([ -e "$L/big.lst" ] && echo yes || echo no)"
r="$(ctl rm-file big.lst)"
check "rm-file повторно: код 0, removed=false" "0 false" \
    "$(printf '%s' "$r" | j code) $(printf '%s' "$r" | j removed)"
check "rm-file с именем «../spec.json» — bad-request" "bad-request" "$(ctl rm-file ../spec.json | j error)"
check "  спека на месте" "yes" "$([ -e "$tmp/spec.json" ] && echo yes || echo no)"
# Файл, на который ссылается сохранённая спека, не удаляется.
spec L.json "$L/yt.lst"
cp "$tmp/spec.json" "$tmp/spec.keep"
cp "$tmp/L.json" "$tmp/spec.json"
r="$(ctl rm-file yt.lst)"
check "rm-file файла из сохранённой спеки — in-use, файл на месте" "in-use yes" \
    "$(printf '%s' "$r" | j error) $([ -e "$L/yt.lst" ] && echo yes || echo no)"
cp "$tmp/spec.keep" "$tmp/spec.json"
check "rm-file после смены спеки — удалён" "true" "$(ctl rm-file yt.lst | j removed)"
# Временный файл, брошенный убитым обработчиком, сервер убирает при старте.
: > "$L/.put-stale1"
serve 0
check "брошенный временный файл убран при старте сервера" "no" \
    "$([ -e "$L/.put-stale1" ] && echo yes || echo no)"

# ---- 9. демон: память, подписка, тишина, медленный подписчик ---------------------------
# Ответ status из памяти — те же байты, что у подкоманды (поле времени приведено к нулю: они
# собраны в разные секунды). Сравнивается весь stdout, с концом строки, а не через $(…).
cat > "$tmp/same.py" <<'PY'
import json, re, sys
a = open(sys.argv[1], 'rb').read()
b = json.loads(open(sys.argv[2], 'rb').read())["stdout"].encode()
z = lambda x: re.sub(rb'"at":[0-9]+', b'"at":0', x)
print("same" if a and z(a) == z(b) else "differ")
PY
same_status() {
    "$BIN" status --spec "$tmp/spec.json" --state-dir "$tmp/state" > "$tmp/st.direct" 2>/dev/null
    ctl status > "$tmp/st.mem"
    python3 "$tmp/same.py" "$tmp/st.direct" "$tmp/st.mem"
}
check "status из памяти — байт в байт как у подкоманды" "same" "$(same_status)"

# Подписчик, который читает (steer ctl печатает события по мере прихода). Подписка — на
# спеке A, чтобы apply спеки B сменил отпечаток.
ctl apply < "$tmp/A.json" >/dev/null
"$BIN" ctl --socket "$tmp/s.sock" subscribe > "$tmp/sub1.out" 2>&1 &
SUB1=$!
wait_for 'grep -q "\"cmd\":\"subscribe\",\"code\":0" "$tmp/sub1.out" 2>/dev/null' 5
check "subscribe: ответ с кодом 0 и отпечатком спеки" "1" \
    "$(head -n 1 "$tmp/sub1.out" | grep -c '"code":0,"spec":"[0-9a-f]\{16\}"')"
ctl apply < "$tmp/B.json" >/dev/null
wait_for 'grep -q "\"ev\":\"applied\",\"by\":\"apply\"" "$tmp/sub1.out"' 5
check "subscribe: после apply — событие applied (движок выключен — enabled false)" "1" \
    "$(grep -c '^{"v":1,"ev":"applied","by":"apply","spec":"[0-9a-f]\{16\}","enabled":false}$' "$tmp/sub1.out")"
check "  отпечаток — уже новой спеки" "yes" \
    "$([ "$(sed -n 's/.*"by":"apply","spec":"\([0-9a-f]*\)".*/\1/p' "$tmp/sub1.out")" != \
         "$(head -n 1 "$tmp/sub1.out" | sed -n 's/.*"spec":"\([0-9a-f]*\)".*/\1/p')" ] && echo yes || echo no)"
check "status из памяти после apply — новая спека, байт в байт" "same" "$(same_status)"
check "  в ответе канал новой спеки" "1" "$(ctl status | j stdout | grep -c 'p2.lst\|"lists":1')"
check "explain из памяти — тот же ответ, что у подкоманды" \
    "$("$BIN" explain 10.2.3.4 --spec "$tmp/spec.json" --state-dir "$tmp/state" 2>/dev/null)" \
    "$(ctl explain 10.2.3.4 | j stdout)"
check "explain: не адрес и не имя — тот же отказ, что у подкоманды" \
    "2 $("$BIN" explain 1.2.3.4:5 --spec "$tmp/spec.json" --state-dir "$tmp/state" 2>&1)" \
    "$(r="$(ctl explain 1.2.3.4:5)"; printf '%s %s' "$(printf '%s' "$r" | j code)" "$(printf '%s' "$r" | j stderr)")"
ctl reload >/dev/null
wait_for 'grep -q "\"by\":\"reload\"" "$tmp/sub1.out"' 5
check "subscribe: после reload — applied от reload" "1" \
    "$(grep -c '"ev":"applied","by":"reload"' "$tmp/sub1.out")"
cp "$tmp/spec.json" "$tmp/spec.good"
printf '{"schema":1,' > "$tmp/spec.json"
r="$(ctl reload)"
wait_for 'grep -q "spec-error" "$tmp/sub1.out"' 5
check "reload негодной спеки: spec-error с причиной" "1" \
    "$(grep -c '^{"v":1,"ev":"spec-error","by":"reload","message":".\+"}$' "$tmp/sub1.out")"
check "  а status отвечает по последней годной" "0 1" \
    "$(ctl status | j code) $(ctl status | j stdout | grep -c '"lists":1')"
cp "$tmp/spec.good" "$tmp/spec.json"
ctl reload >/dev/null

# Тишина: подписчик подключён, запросов нет — демон спит без срока. Меряется счётчиком
# добровольных переключений контекста, как у резолвера в dnsproxy.sh.
sleep 1
cs0=$(awk '/^voluntary_ctxt_switches/{print $2}' "/proc/$SRV/status")
sleep 3
cs1=$(awk '/^voluntary_ctxt_switches/{print $2}' "/proc/$SRV/status")
q=$(( cs1 - cs0 )); [ "$q" -le 1 ] && q=ok
check "в тишине демон не просыпается (с открытым подписчиком)" "ok" "$q"

# Медленный подписчик: подписался и не читает. События шлёт reload; очередь подписчика
# ограничена, и переполнение его отключает — демон пишет об этом в журнал.
cat > "$tmp/slow.py" <<'PY'
import socket, sys, os, time
s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
s.connect(sys.argv[1]); s.sendall(b"subscribe\n")
open(sys.argv[2], 'w').close()
while not os.path.exists(sys.argv[3]): time.sleep(0.05)
s.settimeout(3)
try:
    while True:
        b = s.recv(65536)
        if not b: print("closed"); break
except socket.timeout:
    print("open")
except ConnectionResetError:
    print("closed")
PY
cat > "$tmp/flood.py" <<'PY'
import socket, sys
for i in range(int(sys.argv[3])):
    s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM); s.connect(sys.argv[1])
    s.sendall(b"reload\n"); s.shutdown(socket.SHUT_WR)
    while s.recv(65536): pass
    s.close()
    if i % 25 == 0 and "не забирает события" in open(sys.argv[2], errors="replace").read():
        break
print(i + 1)
PY
rm -f "$tmp/slow.ready" "$tmp/slow.stop"
python3 "$tmp/slow.py" "$tmp/s.sock" "$tmp/slow.ready" "$tmp/slow.stop" > "$tmp/slow.out" & SLOW=$!
wait_for '[ -e "$tmp/slow.ready" ]' 5
sleep 0.2
n="$(python3 "$tmp/flood.py" "$tmp/s.sock" "$tmp/serve.err" 3000)"
check "медленный подписчик отключён по переполнению очереди" "1" \
    "$(grep -c 'подписчик не забирает события' "$tmp/serve.err")"
touch "$tmp/slow.stop"; wait $SLOW 2>/dev/null
check "  и видит закрытое соединение" "closed" "$(cat "$tmp/slow.out")"
check "  демон отвечает остальным" "0" "$(ctl version | j code)"
check "  читающий подписчик остался и получил все события" "yes $n" \
    "$(kill -0 $SUB1 2>/dev/null && echo yes || echo no) $(grep -c '"ev":"applied","by":"reload"' "$tmp/sub1.out" | awk '{print $1 - 2}')"
kill $SUB1 2>/dev/null; wait $SUB1 2>/dev/null; SUB1=""

# ---- 8. настоящий apply, резолвер и откат -----------------------------------------------
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

    # conns: записи conntrack с метками — своими правилами nft в своей таблице, как в
    # tests/ctnl49.sh (метку выхода берём из реестра, раскладку поля не повторяем).
    M=$((0x$(awk '$1 == "vpn" { print $2 }' "$tmp/state/registry")))
    MASK=$(( M | (M << 1) | (M << 2) | (M << 3) | (M << 4) | (M << 5) | (M << 6) | (M << 7) ))
    M2=$(( M * 2 ))                          # другое значение поля — выхода с ним в реестре нет
    X=$(( 0x1234 ))                          # чужие биты вне поля (как у netd на телефоне)
    hex() { printf '0x%08x' "$1"; }
    "$real_nft" -f - <<N
table inet ctt {
    chain o {
        type filter hook output priority 0;
        udp dport { 41001, 41006 } ct mark set $(hex $M)
        udp dport 41002 ct mark set $(hex $((M | X)))
        udp dport 41003 ct mark set $(hex $M2)
        udp dport 41004 ct mark set $(hex $X)
        tcp dport 41010 ct mark set $(hex $M)
    }
}
N
    # 41006 — до включения счётчиков: у такой записи их нет и потом.
    echo 0 > /proc/sys/net/netfilter/nf_conntrack_acct
    python3 -c 'import socket; socket.socket(socket.AF_INET, socket.SOCK_DGRAM).sendto(b"x", ("127.0.0.1", 41006))'
    echo 1 > /proc/sys/net/netfilter/nf_conntrack_acct
    python3 - <<'PY' &
import socket, time
for p in (41001, 41002, 41003, 41004, 41005):
    socket.socket(socket.AF_INET, socket.SOCK_DGRAM).sendto(b"x", ("127.0.0.1", p))
socket.socket(socket.AF_INET6, socket.SOCK_DGRAM).sendto(b"x", ("::1", 41001))
l = socket.socket(); l.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
l.bind(("127.0.0.1", 41010)); l.listen(1)
c = socket.create_connection(("127.0.0.1", 41010)); a, _ = l.accept(); a.send(b"hello")
time.sleep(5)
PY
    CPY=$!
    sleep 0.5
    cat > "$tmp/conns.py" <<'PY'
import json, sys
r = json.loads(sys.stdin.read())
d = json.loads(r["stdout"])
for c in sorted(d["conns"], key=lambda c: (c["family"], c["proto"], c.get("dport", 0))):
    if c.get("dport", 0) < 41000 or c.get("dport", 0) > 41100: continue
    f = [c["family"], c["proto"], str(c.get("dport")), c["out"] or "null", c.get("state", "-"),
         "cnt" if "packets" in c and "reply_bytes" in c else "nocnt"]
    print(" ".join(f))
print("total=%d shown=%d truncated=%s" % (d["total"], d["shown"], d["truncated"]))
PY
    r="$(ctl conns)"
    check "conns: код 0" "0" "$(printf '%s' "$r" | j code)"
    out="$(printf '%s' "$r" | python3 "$tmp/conns.py")"
    check "conns: только записи с полем метки движка, выход по реестру" \
"ipv4 tcp 41010 vpn established cnt
ipv4 udp 41001 vpn - cnt
ipv4 udp 41002 vpn - cnt
ipv4 udp 41003 null - cnt
ipv4 udp 41006 vpn - nocnt
ipv6 udp 41001 vpn - cnt" "$(printf '%s\n' "$out" | grep -v '^total')"
    check "  без обрезки" "False" "$(printf '%s\n' "$out" | sed -n 's/.*truncated=//p')"
    check "  адреса и порты исходного направления" "127.0.0.1 41001" \
        "$(printf '%s' "$r" | j stdout | python3 -c 'import json,sys; c=[c for c in json.load(sys.stdin)["conns"] if c.get("dport")==41001 and c["family"]=="ipv4"][0]; print(c["dst"], c["dport"]) if c["src"]=="127.0.0.1" and c["sport"]>0 else print("-")')"
    kill $CPY 2>/dev/null; wait $CPY 2>/dev/null
    "$real_nft" delete table inet ctt

    "$BIN" dnsd --spec "$tmp/spec.json" --state-dir "$tmp/state" \
        --fakeip-state "$tmp/state/fakeip" 2>"$tmp/dnsd.err" &
    DNSD=$!
    wait_for '[ -s "$tmp/state/dnsd.sig" ]' 5
    # dns-log: запросы по UDP и по TCP, регистр имени не важен; имя мимо каналов — channel null.
    wait_for '[ -S "$tmp/state/dnsd.sock" ]' 5
    cat > "$tmp/q.py" <<'PY'
import socket, struct, sys, time
def q(name, tcp):
    m = struct.pack(">HHHHHH", 0x1234, 0x0100, 1, 0, 0, 0)
    m += b"".join(bytes([len(p)]) + p.encode() for p in name.split(".")) + b"\0"
    m += struct.pack(">HH", 1, 1)
    if tcp:
        s = socket.create_connection(("127.0.0.1", 5300), timeout=2)
        s.sendall(struct.pack(">H", len(m)) + m)
        time.sleep(0.3)
        s.close()
    else:
        socket.socket(socket.AF_INET, socket.SOCK_DGRAM).sendto(m, ("127.0.0.1", 5300))
for a in sys.argv[1:]:
    t, n = a.split(":")
    q(n, t == "tcp")
PY
    python3 "$tmp/q.py" udp:example.com udp:Example.COM tcp:example.com tcp:only-tcp.test udp:nomatch.test
    sleep 0.3
    r="$(ctl dns-log)"
    check "dns-log: код 0, резолвер работает" "0 true" \
        "$(printf '%s' "$r" | j code) $(printf '%s' "$r" | j stdout | j running)"
    check "  имена с каналом, выходом и счётчиком (UDP и TCP вместе)" \
"example.com d vpn 3
nomatch.test null null 1
only-tcp.test null null 1" \
        "$(printf '%s' "$r" | j stdout | python3 -c 'import json,sys; [print(n["name"], n["channel"] or "null", n["out"] or "null", n["count"]) for n in sorted(json.load(sys.stdin)["names"], key=lambda n: n["name"])]')"
    check "  last — секунды Unix, ago — возраст" "yes" \
        "$(printf '%s' "$r" | j stdout | python3 -c 'import json,sys,time; print("yes" if all(abs(n["last"]-time.time())<60 and 0<=n["ago"]<60 for n in json.load(sys.stdin)["names"]) else "no")')"
    check "  сокет журнала — только владельцу" "600" "$(stat -c %a "$tmp/state/dnsd.sock")"
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
    check "  и убрал за собой сокет журнала" "no" "$([ -e "$tmp/state/dnsd.sock" ] && echo yes || echo no)"
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

# ---- 10. сторож в демоне (--watch) ------------------------------------------------------
# Выход vpn с пулом из двух устройств — концов пар veth, вторые концы которых лежат в соседнем
# сетевом пространстве-ответчике: там на lo адреса 1.1.1.1 и 8.8.8.8 (цели пробы сторожа), и
# эхо ICMP через sw1 или sw2 ему по-настоящему отвечают. Проба — из самого демона (сырой сокет,
# привязанный к устройству, с правилом пробы), ping не подменяется и не нужен; мёртвым
# устройство делает `ip link set … down`, молчащим адресатом — снятый у ответчика адрес. Демон
# живёт в своём пространстве имён монтирования со своим /sys — иначе /sys/class/net показывал бы
# устройства хоста, а не пространства стенда (сторож судит о наличии устройства по operstate).
# ifdown/ifup подменены отказом: оживление интерфейса netifd здесь — ожидание подъёма.
RPID=""
if [ "${CTLMATCH_INNER:-}" = 1 ] && command -v nsenter >/dev/null 2>&1 &&
   unshare -m sh -c 'mount -t sysfs sysfs /sys' 2>/dev/null && { unshare -n sleep 600 & RPID=$!; } &&
   sleep 0.3 && ip link add sw1 type veth peer name sw1p 2>/dev/null &&
   ip link add sw2 type veth peer name sw2p 2>/dev/null &&
   ip link set sw1p netns "$RPID" && ip link set sw2p netns "$RPID"; then
    R() { nsenter -t "$RPID" -n "$@"; }
    R ip link set lo up
    R ip addr add 1.1.1.1/32 dev lo; R ip addr add 8.8.8.8/32 dev lo
    R ip link set sw1p up; R ip link set sw2p up
    R ip addr add 10.9.1.2/24 dev sw1p; R ip addr add 10.9.2.2/24 dev sw2p
    printf '#!/bin/sh\nexit 1\n' > "$tmp/bin/ifdown"
    printf '#!/bin/sh\nexit 1\n' > "$tmp/bin/ifup"
    chmod +x "$tmp/bin/ifdown" "$tmp/bin/ifup"
    # Без адресов IPv6 link-local: у veth их проверка дубликата (DAD) кончается через секунду-
    # другую после подъёма, и это событие адреса будило бы сторожа внеочередным проходом там,
    # где стенд считает проходы по периоду.
    ip link set sw1 addrgenmode none 2>/dev/null; ip link set sw2 addrgenmode none 2>/dev/null
    ip link set sw1 up; ip link set sw2 up
    ip addr add 10.9.1.1/24 dev sw1; ip addr add 10.9.2.1/24 dev sw2
    mkdir -p "$tmp/wstate"
    printf '{"schema":1,"outputs":{"vpn":{"kind":"interface","devices":["sw1","sw2"],"on_fail":"drop"}},'\
'"channels":[{"name":"p","match":{"prefixes_files":["%s"]},"out":"vpn"}]}\n' "$tmp/p1.lst" > "$tmp/w.json"
    WD="" WU="" WSUB=""
    # wserve ПЕРИОД [pid] — поднять демона-сторожа заново. С «pid» — ещё и в своём пространстве
    # PID: там номера процессов идут подряд, и по ним видно, запускал ли демон кого-нибудь.
    # Демон там — первый процесс пространства; WD — его номер снаружи, WU — unshare над ним.
    wserve() {
        wstop
        pidns=""; [ "${2:-}" = pid ] && pidns="-p -f"
        unshare -m $pidns sh -c "mount -t sysfs sysfs /sys && exec \"$BIN\" daemon --watch \
            --watch-period $1 --socket \"$tmp/w.sock\" --spec \"$tmp/w.json\" \
            --state-dir \"$tmp/wstate\"" >>"$tmp/w.out" 2>>"$tmp/w.err" &
        WU=$! WD=$!
        wait_for '[ -S "$tmp/w.sock" ]' 5
        if [ -n "$pidns" ]; then
            WD="$(cat "/proc/$WU/task/$WU/children" 2>/dev/null | tr -d ' ')"
            [ -n "$WD" ] || WD="$(pgrep -P "$WU" | head -n 1)"
        fi
    }
    wstop() {
        [ -n "$WD" ] && kill "$WD" 2>/dev/null
        [ -n "$WU" ] && wait "$WU" 2>/dev/null
        rm -f "$tmp/w.sock"
        WD="" WU=""
    }
    wctl() { "$BIN" ctl --socket "$tmp/w.sock" "$@"; }
    wdev() { wctl status | j stdout | j outputs.vpn.device; }
    wtbl() { ip -4 route show table "$(awk '$1 == "vpn" { print $3 }' "$tmp/wstate/registry")" | grep '^default\|^blackhole default' | grep -v 'metric 65535'; }
    # Сколько эхо-запросов ответчик получил (Icmp InEchos его пространства) — по ним видны пробы.
    echos() { R awk '/^Icmp:/ { if (!h) { for (i = 1; i <= NF; i++) if ($i == "InEchos") c = i; h = 1 } else print $c }' /proc/net/snmp; }
    # Сырых сокетов ICMP в пространстве стенда — открыты только пробой демона, пока она ждёт.
    rawsocks() { awk 'NR > 1' /proc/net/raw | grep -c .; }
    # Номер следующего процесса в пространстве PID демона (сам вызов — один процесс там).
    nspid() { nsenter -t "$WD" -p sh -c 'echo $$'; }
    wserve 60
    wait_for 'grep -q "^vpn sw1 0$" "$tmp/wstate/active" 2>/dev/null' 5
    check "сторож: первый проход при старте — выход на первом устройстве пула" "sw1" "$(wdev)"
    check "  таблица выхода привязана к нему" "default dev sw1 scope link" "$(wtbl | sed 's/ *$//')"
    check "  проба — эхо ICMP через устройство, ответчик его получил" "1" \
        "$([ "$(echos)" -ge 1 ] && echo 1 || echo 0)"
    check "  правило пробы после пробы снято" "0" "$(ip -4 rule show | grep -c 'lookup 299')"
    "$BIN" ctl --socket "$tmp/w.sock" subscribe > "$tmp/wsub.out" 2>&1 &
    WSUB=$!
    wait_for 'grep -q "\"cmd\":\"subscribe\"" "$tmp/wsub.out" 2>/dev/null' 5

    # Устройство упало — событие netlink, через пять секунд внеочередной проход.
    ip link set sw1 down
    wait_for 'grep -q "\"ev\":\"switched\"" "$tmp/wsub.out"' 12
    check "сторож: устройство упало — подписчику switched с причиной" \
        '{"v":1,"ev":"switched","out":"vpn","from":"sw1","to":"sw2","why":"down"}' \
        "$(grep '"ev":"switched"' "$tmp/wsub.out")"
    check "  status из памяти демона — новое устройство" "sw2" "$(wdev)"
    check "  таблица выхода — на новом устройстве" "default dev sw2 scope link" "$(wtbl | sed 's/ *$//')"
    check "  выбор отражён в файл active (его читают подкоманды) — прежним форматом" "vpn sw2 0" \
        "$(cat "$tmp/wstate/active")"
    check "  замеры и отметки оживлений на диск не пишутся" "" \
        "$(ls "$tmp/wstate" | grep '^latency\|^restart-')"

    # Долгая проба: первая цель молчит (адрес у ответчика снят — эхо ждёт свои три секунды),
    # а демон отвечает сразу: проба ждёт в его цикле, а не в ребёнке.
    R ip addr del 1.1.1.1/32 dev lo
    ip link add sw3 type dummy
    wait_for '[ "$(rawsocks)" -gt 0 ]' 12
    t0=$(date +%s%N); r="$(wctl status)"; t1=$(date +%s%N)
    ms=$(( (t1 - t0) / 1000000 ))
    check "сторож: status во время пробы отвечает сразу (код 0, быстрее секунды, проба ещё идёт)" \
        "0 yes yes" "$(printf '%s' "$r" | j code) $([ $ms -lt 1000 ] && echo yes || echo "no:$ms") $([ "$(rawsocks)" -gt 0 ] && echo yes || echo no)"
    check "  у демона нет детей, пока проба ждёт" "" "$(cat "/proc/$WD/task/$WD/children" 2>/dev/null | tr -d ' ')"
    wait_for '[ "$(rawsocks)" = 0 ]' 10
    check "  промолчала первая цель — ответила вторая, выход на месте" "sw2" "$(wdev)"
    R ip addr add 1.1.1.1/32 dev lo
    ip link del sw3
    sleep 0.5

    # Упало и второе: первое в пуле оживает, пока сторож его ждёт, — revived и возврат на него.
    before=$(wc -l < "$tmp/w.err")
    ip link set sw2 down
    wait_for '[ "$(tail -n +$((before + 1)) "$tmp/w.err" | grep -c "sw1: не отвечает")" -gt 0 ]' 12
    ip link set sw1 up
    wait_for 'grep -q "\"ev\":\"revived\"" "$tmp/wsub.out"' 12
    wait_for '[ "$(grep -c "\"ev\":\"switched\"" "$tmp/wsub.out")" -ge 2 ]' 5
    check "сторож: ожившее при оживлении устройство — revived" \
        '{"v":1,"ev":"revived","out":"vpn","dev":"sw1"}' "$(grep '"ev":"revived"' "$tmp/wsub.out")"
    check "  и switched назад на него" \
        '{"v":1,"ev":"switched","out":"vpn","from":"sw2","to":"sw1","why":"down"}' \
        "$(grep '"ev":"switched"' "$tmp/wsub.out" | tail -n 1)"
    check "  status — снова первое" "sw1" "$(wdev)"

    # Живых нет: sw1 недавно оживляли (отметка в памяти — не чаще раза в пять минут), sw2 ждём
    # десять секунд — и отказ с on_fail=drop.
    ip link set sw1 down
    wait_for 'grep -q "\"ev\":\"failed\"" "$tmp/wsub.out"' 25
    check "сторож: живых устройств нет — failed с применённым on_fail" \
        '{"v":1,"ev":"failed","out":"vpn","from":"sw1","on_fail":"drop","why":"down"}' \
        "$(grep '"ev":"failed"' "$tmp/wsub.out")"
    check "  в таблице запрет" "blackhole default" "$(wtbl | sed 's/ *$//')"
    check "  status: устройства нет" "vpn - 0" "$(cat "$tmp/wstate/active")"

    # Тишина при периоде 60: проход кончился, событий нет — демон спит.
    sleep 1
    cs0=$(awk '/^voluntary_ctxt_switches/{print $2}' "/proc/$WD/status")
    sleep 3
    cs1=$(awk '/^voluntary_ctxt_switches/{print $2}' "/proc/$WD/status")
    q=$(( cs1 - cs0 )); [ "$q" -le 1 ] && q=ok
    check "сторож: в тишине демон не просыпается (период 60)" "ok" "$q"
    kill $WSUB 2>/dev/null; wait $WSUB 2>/dev/null; WSUB=""

    # Перезапуск демона: выбор берётся из файла active, и выход не перепривязывается заново
    # (перепривязка снимает соединения выхода). Период 2 — проходы не чаще периода. Демон — в
    # своём пространстве PID: за несколько проходов по исправной спеке он не запускает ни одного
    # процесса (номер следующего процесса там растёт только на наши собственные вызовы nspid).
    ip link set sw1 up; ip link set sw2 up
    # Смена operstate приходит от linkwatch с задержкой до секунды — пусть придёт прежнему демону,
    # а не новому: иначе его первый период съело бы внеочередное успокоение.
    sleep 2
    printf 'vpn sw1 0\n' > "$tmp/wstate/active"
    ip route replace default dev sw1 table "$(awk '$1 == "vpn" { print $3 }' "$tmp/wstate/registry")"
    outs=$(wc -l < "$tmp/w.out")
    e0=$(echos)
    wserve 2 pid
    sleep 1
    p0=$(nspid)
    sleep 6
    p1=$(nspid)
    e1=$(echos)
    check "сторож: после перезапуска демона выход не перепривязан" "0" \
        "$(tail -n +$((outs + 1)) "$tmp/w.out" | grep -c 'выход vpn')"
    n=$((e1 - e0))
    check "  проходы — по периоду, не чаще (эхо-проб за 7 с при периоде 2)" "ok" \
        "$([ "$n" -ge 3 ] && [ "$n" -le 5 ] && echo ok || echo "n=$n")"
    check "  процессов на проход нет (новых PID в пространстве демона за 6 с, кроме своих)" "0" \
        "$(( p1 - p0 - 1 ))"
    check "  журнал сторожа — с уровнем" "0" \
        "$(grep -v '^steer\[\(warn\|info\)\]' "$tmp/w.err" | grep -c .)"
    wstop
    ip link del sw1; ip link del sw2
    kill "$RPID" 2>/dev/null; wait "$RPID" 2>/dev/null
else
    [ -n "$RPID" ] && kill "$RPID" 2>/dev/null
    echo "ctlmatch: нет root, сетевого пространства, nsenter или своего /sys — сторож в демоне пропущен"
fi

printf '\nctlmatch: %s passed, %s failed\n' "$pass" "$fail"
[ "$fail" -eq 0 ]
