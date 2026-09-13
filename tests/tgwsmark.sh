#!/bin/sh
# Два экземпляра движка на одном роутере: полный (splify2) и мини-сборка микропакета tgws.
#
# Оба метят пакеты в prerouting на одном приоритете правилом `mark and ~МАСКА or метка`. Пока
# маска у них была общая (0x0ff00000), тот, чья цепочка шла второй, стирал метку первого, — а
# порядок цепочек одного приоритета равен порядку их загрузки и менялся при каждом apply любого
# из двух. Telegram то уходил в туннель полного движка, то в мост микропакета, в зависимости от
# того, кто применился последним. Здесь проверяется, что маски не пересекаются, что порты и
# таблицы у мини-сборки свои и что реестр с меткой из чужого диапазона ей не указ.
set -u
STEER="${STEER:-./build/steer}"
SIM="${TGWSSIM:-./build/tgwssim}"
[ -x "$STEER" ] || { echo "not built: $STEER (make)"; exit 2; }
[ -x "$SIM" ] || { echo "not built: $SIM (make build/tgwssim)"; exit 2; }
pass=0 fail=0
tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT
check() {
    if [ "$2" = "$3" ]; then
        pass=$((pass + 1))
    else
        fail=$((fail + 1))
        printf 'FAIL %s\n  expected: %s\n  actual:   %s\n' "$1" "$2" "$3"
    fi
}

printf '149.154.160.0/20\n91.108.4.0/22\n' > "$tmp/tg.lst"
# Та же спека, что пишет /usr/sbin/tgws в brb: один выход kind=tgws и адресный канал на него.
cat > "$tmp/spec.json" <<JSON
{ "schema": 1,
  "outputs": { "direct": { "kind": "direct" },
               "tg": { "kind": "tgws", "domain": "kws.example.org", "on_fail": "drop" } },
  "channels": [ { "name": "telegram", "match": { "prefixes_files": [ "$tmp/tg.lst" ] }, "out": "tg" } ] }
JSON

full="$("$STEER" apply --dry-run --spec "$tmp/spec.json" --state-dir "$tmp/st-full" 2>&1)"
check "полный движок: спека принята" "0" "$?"
mini="$(STEER_NFT_TABLE=stgws STEER_MARK_ORDER=top \
        "$SIM" apply --dry-run --spec "$tmp/spec.json" --state-dir "$tmp/st-mini" 2>&1)"
check "мини-сборка: спека принята" "0" "$?"

# Маски. Полный движок чистит и ставит восемь бит с двадцатого; мини — только бит 28.
check "полный движок метит своим диапазоном" "1" \
    "$(printf '%s\n' "$full" | grep -c 'meta mark set mark and 0xf00fffff or 0x40100000')"
check "мини-сборка метит своим битом, не трогая диапазон полного" "1" \
    "$(printf '%s\n' "$mini" | grep -c 'meta mark set mark and 0xefffffff or 0x50000000')"
check "в ruleset мини-сборки нет маски полного движка" "0" \
    "$(printf '%s\n' "$mini" | grep -c '0x0ff00000\|0xf00fffff')"
# Перенаправление — по своему биту и на свой порт: у полного движка первый выход kind=tgws
# слушает 8480, и общий ряд портов свёл бы два моста на один порт.
check "перенаправление мини — по своему биту, на свой порт" "1" \
    "$(printf '%s\n' "$mini" | grep -c 'meta mark and 0x10000000 == 0x10000000 tcp dport { 443, 80, 5222 } counter redirect to :8490')"
check "порт моста у полного движка прежний" "1" \
    "$(printf '%s\n' "$full" | grep -c 'meta mark and 0x0ff00000 == 0x00100000 tcp dport { 443, 80, 5222 } counter redirect to :8480')"
check "таблица правил у мини-сборки своя" "1" \
    "$(printf '%s\n' "$mini" | grep -c '^table inet stgws')"
# Реестр: свой бит и свой ряд таблиц (300..315 — у полного движка; уборка мёртвых правил
# делает по реестру `ip route flush table N`, и общий ряд опустошал бы чужую таблицу).
check "реестр мини-сборки: бит 28, таблица вне ряда полного движка" "tg 10000000 316" \
    "$(grep '^tg ' "$tmp/st-mini/registry" 2>/dev/null)"
check "реестр полного движка: как прежде" "tg 100000 300" \
    "$(grep '^tg ' "$tmp/st-full/registry" 2>/dev/null)"

# Реестр от прежней мини-сборки: метка 08000000 (бит 7 сверху общего диапазона) и таблица 307.
# Взять её значило бы ставить правило с битом за пределами своей маски — оно стояло бы и не
# срабатывало никогда. Метка выдаётся заново, чужая запись не переживает apply.
mkdir -p "$tmp/st-old"
printf 'tg 08000000 307\n' > "$tmp/st-old/registry"
old="$(STEER_NFT_TABLE=stgws STEER_MARK_ORDER=top \
       "$SIM" apply --dry-run --spec "$tmp/spec.json" --state-dir "$tmp/st-old" 2>&1)"
check "метка из чужого диапазона в реестре не берётся" "1" \
    "$(printf '%s\n' "$old" | grep -c 'or 0x50000000')"
check "и в реестре заменяется своей" "tg 10000000 316" "$(grep '^tg ' "$tmp/st-old/registry")"

printf '%d passed, %d failed\n' "$pass" "$fail"
[ "$fail" -eq 0 ]
