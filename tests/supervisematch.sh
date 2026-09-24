#!/bin/sh
# steer supervise: помощники выходов одним процессом — запуск, перезапуск, SIGHUP, SIGTERM.
#
# Помощники здесь не настоящие: шов STEER_SUPERVISE_EXE подставляет скрипт, который
# записывает «команда выход pid» и спит. Так видно ровно то, что делает супервизор, без сети,
# туннелей и root. Выходы — с obfs: их помощник есть и в базовой сборке.
#
# Что проверяется: по помощнику на выход с процессом; убитый помощник перезапускается; SIGHUP
# после удаления выхода из спеки гасит его помощника и не трогает остальных; SIGHUP с
# новым выходом поднимает его; SIGTERM гасит всех и завершает супервизор.
set -u
BIN="${STEER:-./build/steer}"
[ -x "$BIN" ] || { echo "not built: $BIN (make test)"; exit 2; }
pass=0 fail=0
tmp="$(mktemp -d)"
check() {
    if [ "$2" = "$3" ]; then pass=$((pass + 1)); else
        fail=$((fail + 1)); printf 'FAIL %s\n  expected: %s\n  actual:   %s\n' "$1" "$2" "$3"
    fi
}
cat > "$tmp/helper" <<H
#!/bin/sh
echo "\$1 \$2 \$\$" >> "$tmp/log"
trap 'echo "stop \$2 \$\$" >> "$tmp/log"; exit 0' TERM
while :; do sleep 1; done
H
chmod +x "$tmp/helper"
spec() {   # spec ВЫХОД... — выходы с obfs
    printf '{"schema":2,"from_default":["192.168.1.0/24"],"outputs":{' > "$tmp/spec.json"
    sep=""
    for o in "$@"; do
        printf '%s"%s":{"kind":"interface","device":"wg%s","obfs":{"mode":"wg-over-tcp","server":"10.99.0.3:4443","listen":"127.0.0.1:5%s"}}' \
            "$sep" "$o" "${#o}" "$(printf '%04d' "${#o}")" >> "$tmp/spec.json"
        sep=","
    done
    printf '},"channels":[]}\n' >> "$tmp/spec.json"
}
running() { grep -c "^obfs $1 " "$tmp/log" 2>/dev/null; }
alive() {  # alive ВЫХОД — жив ли его последний помощник
    p="$(grep "^obfs $1 " "$tmp/log" | tail -1 | cut -d' ' -f3)"
    [ -n "$p" ] && kill -0 "$p" 2>/dev/null && echo yes || echo no
}

spec a bb
STEER_SUPERVISE_EXE="$tmp/helper" "$BIN" supervise --spec "$tmp/spec.json" 2>"$tmp/sup.err" &
SUP=$!
sleep 1
check "поднят помощник выхода a" "1" "$(running a)"
check "поднят помощник выхода bb" "1" "$(running bb)"

kill "$(grep '^obfs a ' "$tmp/log" | tail -1 | cut -d' ' -f3)"
sleep 6.5
check "убитый помощник перезапущен через 5 с" "2" "$(running a)"
check "  и о перезапуске сказано" "1" "$(grep -c 'supervise: obfs a вышел' "$tmp/sup.err")"

spec bb ccc
kill -HUP $SUP
sleep 1
check "SIGHUP: выход a убран из спеки — его помощник остановлен" "no" "$(alive a)"
check "SIGHUP: bb не тронут" "1" "$(running bb)"
check "SIGHUP: новый выход ccc поднят" "1" "$(running ccc)"
sleep 6
check "убранный выход не перезапускается" "2" "$(running a)"

kill -TERM $SUP
sleep 1
check "SIGTERM: супервизор вышел" "no" "$(kill -0 $SUP 2>/dev/null && echo yes || echo no)"
check "SIGTERM: помощники погашены" "no no" "$(alive bb) $(alive ccc)"

# Помощник, падающий сразу: первый перезапуск через 5 с, следующий — через 10 (пауза растёт,
# чтобы отказ не будил процессор каждые пять секунд всю ночь).
cat > "$tmp/crash" <<H
#!/bin/sh
echo "\$1 \$2 \$\$" >> "$tmp/crash.log"
exit 1
H
chmod +x "$tmp/crash"
spec d
STEER_SUPERVISE_EXE="$tmp/crash" "$BIN" supervise --spec "$tmp/spec.json" 2>"$tmp/crash.err" &
SUP=$!
sleep 12
check "падающий сразу: к 12-й секунде два запуска (0 и 5 с)" "2" "$(grep -c '^obfs d ' "$tmp/crash.log")"
sleep 5
check "  третий — через 10 с после второго" "3" "$(grep -c '^obfs d ' "$tmp/crash.log")"
check "  и пауза растёт в журнале: 5, затем 10 с" "1 1" \
    "$(grep -c 'через 5 с' "$tmp/crash.err") $(grep -c 'через 10 с' "$tmp/crash.err")"
kill -TERM $SUP; wait $SUP 2>/dev/null

rm -rf "$tmp"
printf '\nsupervisematch: %s passed, %s failed\n' "$pass" "$fail"
[ "$fail" -eq 0 ]
