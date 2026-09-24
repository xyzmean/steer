#!/bin/sh
# steer supervise: помощники выходов одним процессом — запуск, перезапуск, SIGHUP, SIGTERM.
#
# Помощники здесь не настоящие: шов STEER_SUPERVISE_EXE подставляет скрипт, который
# записывает «команда выход pid» и спит. Так видно ровно то, что делает супервизор, без сети,
# туннелей и root. Выходы — с obfs: их помощник есть и в базовой сборке.
#
# Что проверяется: по помощнику на выход с процессом; убитый помощник перезапускается; SIGHUP
# после удаления выхода из спеки гасит его помощника и не трогает остальных; SIGHUP с
# новым выходом поднимает его; SIGHUP со сменой параметров выхода (сервер обфускации)
# перезапускает его помощника сразу и не трогает соседей, а SIGHUP без изменений не трогает
# никого; SIGTERM гасит всех и завершает супервизор; смена МЕТКИ цели via (цель пересоздана с тем
# же именем) перезапускает помощника выхода через неё, а помощник получает каталог состояния
# супервизора.
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
# Гаснет не сразу — как настоящий помощник, убирающий за собой: так видно, что супервизор не
# поднимает второй экземпляр рядом с ещё живым прежним.
trap 'echo "stop \$2 \$\$" >> "$tmp/log"; sleep 2; exit 0' TERM
while :; do sleep 1; done
H
chmod +x "$tmp/helper"
spec() {   # spec ВЫХОД... — выходы с obfs; у выхода $CHG другой сервер обфускации
    printf '{"schema":2,"from_default":["192.168.1.0/24"],"outputs":{' > "$tmp/spec.json"
    sep=""
    for o in "$@"; do
        srv=10.99.0.3:4443
        [ "$o" = "${CHG:-}" ] && srv=10.99.0.4:4443
        printf '%s"%s":{"kind":"interface","device":"wg%s","obfs":{"mode":"wg-over-tcp","server":"%s","listen":"127.0.0.1:5%s"}}' \
            "$sep" "$o" "${#o}" "$srv" "$(printf '%04d' "${#o}")" >> "$tmp/spec.json"
        sep=","
    done
    printf '},"channels":[]}\n' >> "$tmp/spec.json"
}
running() { grep -c "^obfs $1 " "$tmp/log" 2>/dev/null; }
# wait_for УСЛОВИЕ СЕК — ждать, пока shell-условие не станет истинным (вместо sleep на глаз:
# под нагрузкой помощник гасится позже, чем через секунду).
wait_for() {
    i=0
    while [ $i -lt $(($2 * 10)) ]; do eval "$1" && return 0; sleep 0.1; i=$((i + 1)); done
    return 1
}
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

kill -KILL "$(grep '^obfs a ' "$tmp/log" | tail -1 | cut -d' ' -f3)"
sleep 4
check "убитый помощник: за 4 с ещё не перезапущен (пауза 5 с)" "1" "$(running a)"
wait_for '[ "$(running a)" = 2 ]' 4
check "убитый помощник перезапущен через 5 с" "2" "$(running a)"
check "  и о перезапуске сказано" "1" "$(grep -c 'supervise: obfs a вышел' "$tmp/sup.err")"

spec bb ccc
kill -HUP $SUP
wait_for '[ "$(alive a)" = no ] && [ "$(running ccc)" = 1 ]' 8
check "SIGHUP: выход a убран из спеки — его помощник остановлен" "no" "$(alive a)"
check "SIGHUP: bb не тронут — жив" "yes" "$(alive bb)"
check "SIGHUP: новый выход ccc поднят" "1" "$(running ccc)"
sleep 6
check "убранный выход не перезапускается" "2" "$(running a)"
check "bb и через 6 с — тот же процесс, не перезапущен" "1 yes" "$(running bb) $(alive bb)"

# Выход убрали и тут же вернули, пока его помощник ещё гаснет: второй экземпляр рядом с живым
# старым не поднимается — слот тот же, запуск после выхода прежнего.
spec bb
kill -HUP $SUP
sleep 0.3          # супервизор дочитал спеку; помощник ccc ещё гаснет (trap после sleep 1)
spec bb ccc
kill -HUP $SUP
sleep 0.3
live=0
for pid in $(grep '^obfs ccc ' "$tmp/log" | cut -d' ' -f3); do kill -0 "$pid" 2>/dev/null && live=$((live + 1)); done
check "возвращённый выход, пока прежний гаснет, — не второй экземпляр рядом" "1" "$live"
wait_for '[ "$(running ccc)" = 2 ] && [ "$(alive ccc)" = yes ]' 10
check "  и после выхода прежнего поднят заново" "2 yes" "$(running ccc) $(alive ccc)"

# Сменился сервер обфускации у bb: его помощник перезапускается — сразу после выхода прежнего
# (тот гаснет две секунды), а не через пятисекундную паузу упавшего; ccc не тронут.
bb_pid="$(grep '^obfs bb ' "$tmp/log" | tail -1 | cut -d' ' -f3)"
CHG=bb spec bb ccc
kill -HUP $SUP
wait_for '[ "$(running bb)" = 2 ]' 4
check "SIGHUP: параметры bb изменились — помощник поднят заново за 4 с" "2 yes" \
    "$(running bb) $(alive bb)"
check "  прежний помощник bb погашен" "no" "$(kill -0 "$bb_pid" 2>/dev/null && echo yes || echo no)"
check "  ccc не тронут" "2 yes" "$(running ccc) $(alive ccc)"
check "  и о причине сказано" "1" "$(grep -c 'supervise: obfs bb — параметры выхода изменились' "$tmp/sup.err")"
# Та же спека ещё раз: подпись та же — никого не трогать.
kill -HUP $SUP
sleep 3
check "SIGHUP без изменений: никто не перезапущен" "2 2" "$(running bb) $(running ccc)"

kill -TERM $SUP
wait_for '! kill -0 $SUP 2>/dev/null' 5
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

# Метка цели via — в подписи помощника, а не только её имя. Цель убрали из спеки и вернули под тем
# же именем — реестр выдал ей другое место, то есть другую метку; помощник, прочитавший метку при
# старте, метил бы сокет старой (теперь чужой или ничьей — то есть мимо цели) до своего
# перезапуска. Здесь «пересоздание» — правка реестра в каталоге состояния супервизора.
st="$tmp/st"
mkdir -p "$st"
cat > "$tmp/via.json" <<EOF
{"schema":2,"from_default":["192.168.1.0/24"],"outputs":{
 "t":{"kind":"interface","device":"wgt"},
 "a":{"kind":"interface","device":"wga","via":"t",
      "obfs":{"mode":"wg-over-tcp","server":"10.99.0.3:4443","listen":"127.0.0.1:5101"}}},
 "channels":[]}
EOF
: > "$tmp/log"
STEER_SUPERVISE_EXE="$tmp/helper" "$BIN" supervise --spec "$tmp/via.json" --state-dir "$st" \
    2>"$tmp/via.err" &
SUP=$!
wait_for '[ "$(running a)" = 1 ]' 5
check "via: помощник выхода a поднят" "1" "$(running a)"
check "via: метки — из реестра каталога состояния супервизора" "1" "$(grep -c '^t ' "$st/registry" 2>/dev/null)"
p="$(grep '^obfs a ' "$tmp/log" | tail -1 | cut -d' ' -f3)"
check "via: помощник получил тот же каталог состояния" "1" \
    "$(tr '\0' ' ' < "/proc/$p/cmdline" 2>/dev/null | grep -c -- "--state-dir $st")"
kill -HUP $SUP
sleep 2
check "via: SIGHUP без изменений — помощник не перезапущен" "1 yes" "$(running a) $(alive a)"
sed -i 's/^t .*/t 500000 304/' "$st/registry"
kill -HUP $SUP
wait_for '[ "$(running a)" = 2 ] && [ "$(alive a)" = yes ]' 8
check "via: у цели другая метка — помощник перезапущен" "2 yes" "$(running a) $(alive a)"
check "  и о причине сказано" "1" "$(grep -c 'supervise: obfs a — параметры выхода изменились' "$tmp/via.err")"
kill -TERM $SUP; wait $SUP 2>/dev/null

rm -rf "$tmp"
printf '\nsupervisematch: %s passed, %s failed\n' "$pass" "$fail"
[ "$fail" -eq 0 ]
