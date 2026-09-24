#!/bin/sh
# Перепривязка таблицы выхода не выпускает помеченный трафик мимо туннеля — на настоящем ядре.
#
# ЗАЧЕМ. Движок привязывал таблицу выхода парами команд: `ip rule del` → `ip rule add` и
# `ip route flush table N` → `ip route add default dev X table N`. Между командами одной пары у
# помеченного пакета нет правила или в таблице нет маршрута — и он уходит по main, то есть
# напрямую, мимо туннеля (на стенде так утекло рукопожатие WireGuard). Окно — миллисекунды, но
# открывается оно на каждом apply, на каждой смене устройства пула, на каждой починке
# разъехавшейся маршрутизации и на каждом отказе с on_fail=drop. Модульный стенд
# (tests/failovermatch.c) проверяет порядок команд; этот — что ядро действительно ни одного
# помеченного пакета в WAN не выпустило.
#
# КАК. Два сетевых пространства: здесь — «роутер» с движком, рядом — «интернет». Путей три: wan0
# (маршрут по умолчанию main) и t1, t2 — устройства выхода vpn (kind=interface, пул из двух,
# on_fail=drop; пары veth без маршрута по умолчанию, туда ведёт только таблица выхода). Всё время
# стенда tests/markflood.c шлёт UDP с меткой выхода с несоединённого сокета — маршрут ищется для
# каждой датаграммы, так что в любое мгновение перепривязки по таблице идёт пакет. Счётчик nft на
# postrouting считает пакеты с этой меткой, ушедшие в wan0. Сценарии:
#   1. apply десять раз подряд (apply_routing);
#   2. сторож переключает пул t1 → t2 → t1 (bind_device по смене устройства; t1 «умирает» —
#      соседи отвечают на пробу отказом ICMP, устройство при этом на месте);
#   3. в таблице выхода оказался запрет, устройство живо — сторож чинит (bind_device по сверке);
#   4. оба устройства умерли — сторож ставит запрет (apply_failed), ожили — возвращает;
#   5. устройство, в которое привязана таблица, ИСЧЕЗЛО (так пропадает TUN умершего помощника и
#      устройство awg при пересоздании): ядро само вычищает маршрут в него, и до прохода сторожа
#      в таблице остаётся только запасной запрет (STEER_BACKSTOP_METRIC); затем сторож уводит пул
#      на t2.
# После каждого — в wan0 с меткой выхода обязан уйти НОЛЬ пакетов, а в t1/t2 — не ноль (иначе
# стенд ничего не проверил); в первой половине пятого в туннель идти нечему.
#
# Использование (root, unshare, ip, nft, ping):
#   STEER=build/steer sh tests/rebindleak.sh
# Поток собирается из tests/markflood.c компилятором хоста (или FLOOD=<бинарник>). Годится и
# Android-сборка для хоста (-DSTEER_ANDROID с каталогами в /tmp, как в шапке local49.sh).
#
# На ядре 4.9 (стенд tools/vm49 хаба): у ip в образе нет veth — пары заводит помощник awg49-veth
# (/root/vm49/awg), компилятора нет — поток приносится готовым, собранным musl статически:
#   musl-gcc -static -O2 -o OUT/markflood tests/markflood.c
#   (сценарий-обёртка: mkdir -p /data/misc/steer/tmp; STEER=/work/steer FLOOD=/work/markflood
#    sh /work/rebindleak.sh)
#   tools/vm49/vm49.sh run ОБЁРТКА steer/tests/rebindleak.sh OUT/steer OUT/markflood \
#       /root/vm49/awg/awg49-veth
set -u
BIN="${STEER:-./build/steer}"
BIN="$(cd "$(dirname "$BIN")" && pwd)/$(basename "$BIN")"
[ -x "$BIN" ] || { echo "not built: $BIN (make)"; exit 2; }
skip() { echo "rebindleak: $1 — пропускаю"; exit 0; }
for t in ip nft unshare nsenter ping; do command -v $t >/dev/null 2>&1 || skip "нет $t"; done
if [ "${REBIND_INNER:-}" != 1 ]; then
    [ "$(id -u)" = 0 ] || skip "нужен root"
    unshare -nm true 2>/dev/null || skip "unshare -nm недоступен"
    FL="${FLOOD:-}"
    if [ -z "$FL" ]; then
        FL="$(mktemp -d)/markflood"
        ${CC:-cc} -O2 -o "$FL" "$(dirname "$0")/markflood.c" || skip "не собрать markflood"
    fi
    REBIND_INNER=1 STEER="$BIN" FLOOD="$FL" exec unshare -nm sh "$0" "$@"
fi
# Своё /sys: сторож читает operstate устройств, и без перемонтирования это были бы устройства
# машины, а не этого пространства.
mount --make-rprivate / 2>/dev/null
mount -t sysfs sysfs /sys 2>/dev/null || skip "не смонтировать sysfs в своём пространстве"
ip link set lo up

tmp="$(mktemp -d)"
peer="" fl=""
cleanup() {
    [ -n "$fl" ] && kill "$fl" 2>/dev/null
    [ -n "$peer" ] && kill "$peer" 2>/dev/null
    rm -rf "$tmp"
}
trap cleanup EXIT
pass=0 fail=0
check() {
    if [ "$2" = "$3" ]; then pass=$((pass + 1)); echo "ok   $1"; else
        fail=$((fail + 1)); printf 'FAIL %s\n  expected: %s\n  actual:   %s\n' "$1" "$2" "$3"
    fi
}

# ---- «интернет» ------------------------------------------------------------------------------
unshare -n sleep 600 &
peer=$!
sleep 0.3
P="nsenter -t $peer -n"
$P ip link set lo up
# veth — командой ip, а где её ip не умеет (образ стенда vm49), — помощником awg49-veth.
mkveth() { ip link add "$1" type veth peer name "$2" 2>/dev/null || awg49-veth "$1" "$2"; }
n=0
for d in wan0 t1 t2; do
    mkveth $d s$d
    ip link set s$d netns "$peer"
    ip addr add 10.8$n.0.2/24 dev $d; ip link set $d up
    $P ip addr add 10.8$n.0.1/24 dev s$d; $P ip link set s$d up
    n=$((n + 1))
done
ip route add default via 10.80.0.1 dev wan0
# Адреса проб сторожа и адрес, куда идёт поток, — на dummy соседа: отвечают с любого пути.
$P ip link add dum0 type dummy
for a in 1.1.1.1 8.8.8.8 203.0.113.7; do $P ip addr add $a/32 dev dum0; done
$P ip link set dum0 up
# «Смерть» устройства — отказ ICMP на пробу со стороны соседа. Устройство на месте: если бы оно
# падало, ядро само вычистило бы маршрут из таблицы, и стенд мерил бы не перепривязку.
$P nft add table inet rej
$P nft add chain inet rej in '{ type filter hook input priority 0; policy accept; }'
die_on()  { $P nft add rule inet rej in iifname "s$1" icmp type echo-request reject comment "\"$1\""; }
live_all() { $P nft flush chain inet rej in; }

printf '203.0.113.0/24\n' > "$tmp/a.lst"
cat > "$tmp/spec.json" <<EOF
{ "schema": 2, "from_default": ["192.168.1.0/24"],
  "outputs": { "vpn": { "kind": "interface", "devices": ["t1", "t2"], "on_fail": "drop" } },
  "channels": [ { "name": "a", "match": { "prefixes_file": "$tmp/a.lst" }, "out": "vpn" } ] }
EOF
S="--spec $tmp/spec.json --state-dir $tmp/state"
"$BIN" apply $S >"$tmp/apply0.log" 2>&1
check "apply проходит" "0" "$?"
mark="0x$(awk '$1=="vpn"{print $2}' "$tmp/state/registry")"
tbl="$(awk '$1=="vpn"{print $3}' "$tmp/state/registry")"
check "таблица выхода ведёт в t1" "1" "$(ip route show table "$tbl" | grep -c '^default dev t1')"

nft -f - <<NFT
table inet rbcnt {
    chain post {
        type filter hook postrouting priority 300; policy accept;
        oifname "wan0" meta mark $mark counter comment "leak"
        oifname { "t1", "t2" } meta mark $mark counter comment "tun"
    }
}
NFT
cnt() { nft list chain inet rbcnt post | sed -n "s/.*packets \([0-9]*\).*comment \"$1\".*/\1/p"; }
cnt_reset() { nft reset rules inet rbcnt post >/dev/null 2>&1; }
# phase ИМЯ [notun] — итог сценария: утечка ноль, в туннель не ноль (с notun — не проверять).
phase() {
    l=$(cnt leak); u=$(cnt tun)
    echo "    $1: в wan0 ${l:-?} пакетов с меткой выхода, в t1/t2 ${u:-?}"
    check "$1: мимо туннеля — ноль" "0" "${l:-x}"
    [ "${2:-}" = notun ] ||
        check "$1: поток шёл в туннель" "1" "$([ "${u:-0}" -gt 0 ] && echo 1 || echo 0)"
    cnt_reset
}
fo() { STEER_FAILOVER_HYST=0 "$BIN" failover $S >>"$tmp/fo.log" 2>&1; }
# Метки перезапуска свежими: иначе сторож, не найдя живых, ждал бы подъёма по десять секунд на
# устройство, а проверяется здесь не ожидание.
stamps() { for d in t1 t2; do date +%s > "$tmp/state/restart-$d"; done; }

"$FLOOD" "$mark" 203.0.113.7 9 600 >"$tmp/flood.out" 2>&1 &
fl=$!
sleep 0.5
cnt_reset

# ---- 1. apply подряд ------------------------------------------------------------------------
for _ in 1 2 3 4 5 6 7 8 9 10; do "$BIN" apply $S >>"$tmp/apply.log" 2>&1; done
phase "apply ×10"

# ---- 2. смена устройства пула ---------------------------------------------------------------
fo
for _ in 1 2 3 4; do
    die_on t1; fo
    live_all; fo
done
check "пул переключался (t2 и обратно)" "1" \
      "$([ "$(grep -c 'выход vpn -> t2' "$tmp/fo.log")" -ge 4 ] && echo 1 || echo 0)"
phase "переключение t1 ⇄ t2 ×4"

# ---- 3. починка разъехавшейся таблицы -------------------------------------------------------
for _ in 1 2 3 4; do
    ip route replace blackhole default table "$tbl"
    fo
done
check "сторож чинил таблицу" "1" \
      "$([ "$(grep -c 'маршрутизация разъехалась' "$tmp/fo.log")" -ge 4 ] && echo 1 || echo 0)"
phase "починка таблицы ×4"

# ---- 4. отказ с on_fail=drop и возврат ------------------------------------------------------
for _ in 1 2 3; do
    stamps; die_on t1; die_on t2; fo
    live_all; fo
done
check "отказ объявлялся" "1" \
      "$([ "$(grep -c 'трафик остановлен (on_fail=drop)' "$tmp/fo.log")" -ge 3 ] && echo 1 || echo 0)"
phase "отказ drop и возврат ×3"

# ---- 5. устройство исчезло ------------------------------------------------------------------
check "перед пятым таблица снова на t1" "1" "$(ip route show table "$tbl" | grep -c '^default dev t1')"
ip link del t1
sleep 2
check "маршрут в исчезнувшее устройство ядро вычистило" "0" \
      "$(ip route show table "$tbl" | grep -c 'dev t1')"
phase "устройство исчезло, до прохода сторожа" notun
fo
check "сторож увёл пул на t2" "1" "$(ip route show table "$tbl" | grep -c '^default dev t2')"
sleep 0.5
phase "устройство исчезло, после прохода сторожа"

kill "$fl" 2>/dev/null; wait "$fl" 2>/dev/null; fl=""
echo "    поток: $(cat "$tmp/flood.out")"
check "правило выхода — ровно одно" "1" "$(ip -4 rule show | grep -c "fwmark $(printf '0x%x' "$mark")/")"
"$BIN" down --state-dir "$tmp/state" >/dev/null 2>&1

echo "rebindleak: $pass passed, $fail failed"
[ "$fail" -eq 0 ]
