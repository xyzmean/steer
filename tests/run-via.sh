#!/bin/sh
# Вложенные выходы (`via`) целиком: VLESS, чей туннель идёт через выход-интерфейс.
#
# ЧТО ПРОВЕРЯЕТСЯ И ПОЧЕМУ ТОЛЬКО ТАК. `via` не добавляет ни одного правила nft и ни одного
# ip rule — он метит сокет клиента меткой выхода-цели, а дальше работает ядро: ip rule цели,
# её таблица, выбор устройства и адреса источника при connect(). Всё это видно только на
# настоящем стеке: текст generate() от via не меняется вовсе (так и задумано), и модульный стенд
# здесь ничего не докажет. Поэтому — три сетевых пространства и счётчики на выходе.
#
# Стенд:
#   via-s  — «интернет»: поддельный сервер VLESS (tests/fake-vless.py) на 10.72.0.1 и адреса
#            проб сторожа (1.1.1.1, 8.8.8.8) на dummy. Два пути к нему от роутера: «WAN»
#            (маршрут по умолчанию) и vx0 — устройство выхода kind=interface, то есть
#            подделка WireGuard: обычный veth без маршрута по умолчанию.
#   via-a  — роутер (или телефон): steer, выход vx (interface, vx0) и выход vl (vless) с
#            `via: vx`. Счётчики nft на postrouting: сколько пакетов к серверу VLESS ушло в
#            vx0 и сколько в WAN, сколько пакетов канала ушло в устройство туннеля vl.
#   via-c  — клиент раздачи (только в режиме router): его трафик канал уводит в vl.
#
# В режиме android то же самое делает приложение самого телефона: wget под UID 10050, канал
# `from: uid:10050` на хуке output, Android-сборка движка (поле метки 22-27, ip rule 9000,
# masquerade у выхода-интерфейса правилом iptables). Раскладка правил — STEER_NFT_COMPAT
# (modern или legacy-min: та, что на ядре 4.9 телефона, с битом перемаршрутизации).
#
# Затем — контроль, без которого первая часть ничего не доказывает: тот же выход без via обязан
# ходить к серверу через WAN. И отказ цели: vx0 лёг — сторож объявляет нерабочим и vl.
#
# Использование:
#   STEER=<расширенный движок> sh tests/run-via.sh router
#   STEER=<расширенный движок, собранный с -DSTEER_ANDROID> STEER_NFT_COMPAT=legacy-min \
#       sh tests/run-via.sh android
# Нужны root, ip netns, nft, python3, wget; в режиме android — iptables и setpriv.
set -eu
cd "$(dirname "$0")/.."

MODE="${1:-router}"
BIN="${STEER:-./build/steer-ext-check}"
[ -x "$BIN" ] || { echo "нет бинарника: $BIN (собери extended)"; exit 2; }
BIN="$(cd "$(dirname "$BIN")" && pwd)/$(basename "$BIN")"
MB=4
UUID=8f7d3b1a-2c4e-4f60-9a81-b5d7e6c30124
PORT=10800
NODE=10.72.0.1
TARGET=203.0.113.7
APP_UID=10050
A=via-a S=via-s C=via-c
WORK=""

pass=0 fail=0
ok()  { pass=$((pass + 1)); echo "  ok   $1"; }
bad() { fail=$((fail + 1)); echo "  FAIL $1"; }

cleanup() {
    for ns in $A $S $C; do
        ip netns pids "$ns" 2>/dev/null | xargs -r kill 2>/dev/null || true
        ip netns delete "$ns" 2>/dev/null || true
    done
    [ -n "$WORK" ] && rm -rf "$WORK"
}
cleanup 2>/dev/null || true
trap cleanup EXIT INT TERM
# Пишет сюда и приложение под чужим UID (режим android) — отсюда 1777.
WORK="$(mktemp -d)"; chmod 1777 "$WORK"

inA() { ip netns exec $A "$@"; }
inS() { ip netns exec $S "$@"; }

for ns in $A $S; do ip netns add $ns; ip netns exec $ns ip link set lo up; done
# WAN: маршрут по умолчанию роутера.
ip link add wan0 netns $A type veth peer name swan netns $S
inA ip addr add 10.70.0.2/24 dev wan0; inA ip link set wan0 up
inS ip addr add 10.70.0.1/24 dev swan; inS ip link set swan up
inA ip route add default via 10.70.0.1 dev wan0
# vx0: устройство выхода kind=interface. Маршрута по умолчанию через него нет — туда ведёт
# только таблица выхода, то есть только помеченное.
ip link add vx0 netns $A type veth peer name svx netns $S
inA ip addr add 10.71.0.2/24 dev vx0; inA ip link set vx0 up
inS ip addr add 10.71.0.1/24 dev svx; inS ip link set svx up
# Сервер VLESS и адреса проб — на dummy сервера: отвечают с любого из двух путей (ARP на
# чужой адрес ядро по умолчанию отдаёт с любого устройства).
inS ip link add node type dummy
inS ip addr add $NODE/32 dev node
inS ip addr add 1.1.1.1/32 dev node
inS ip addr add 8.8.8.8/32 dev node
inS ip link set node up

LAN_DEV=lan0
if [ "$MODE" = router ]; then
    ip netns add $C; ip netns exec $C ip link set lo up
    ip link add lan0 netns $A type veth peer name eth0 netns $C
    inA ip addr add 10.73.0.1/24 dev lan0; inA ip link set lan0 up
    ip netns exec $C ip addr add 10.73.0.2/24 dev eth0
    ip netns exec $C ip link set eth0 up
    ip netns exec $C ip route add default via 10.73.0.1
    inA sysctl -qw net.ipv4.ip_forward=1
    FROM='"10.73.0.2"'
else
    FROM="\"uid:$APP_UID\""
fi

inS python3 tests/fake-vless.py --port $PORT --uuid $UUID --mb $MB --bind $NODE \
    > "$WORK/srv.log" 2>&1 &
sleep 1

printf '%s\n' "vless://$UUID@$NODE:$PORT?security=none&type=tcp#local" > "$WORK/sub.txt"
spec() {   # $1 — строка via у выхода vl (пустая — без via)
    cat > "$WORK/spec.json" <<SPEC
{"schema":2,"lan_devices":["$LAN_DEV"],
 "outputs":{
   "vx":{"kind":"interface","device":"vx0","on_fail":"drop"},
   "vl":{"kind":"vless","sub_file":"$WORK/sub.txt","node":0$1}},
 "channels":[{"name":"all","out":"vl","scope":"device","from":[$FROM],"match":{"any":true}}]}
SPEC
}

# Счётчики — своя таблица, на postrouting после всех: видит и локальное, и транзитное.
inA nft -f - <<'NFT'
table inet viacnt {
    chain post {
        type filter hook postrouting priority 300; policy accept;
        oifname "vx0" ip daddr 10.72.0.1 tcp dport 10800 counter comment "node-vx0"
        oifname "wan0" ip daddr 10.72.0.1 counter comment "node-wan0"
        oifname "vl" ip daddr 203.0.113.7 counter comment "chan-vl"
    }
}
NFT
cnt() {   # пакеты правила с комментарием $1
    inA nft list chain inet viacnt post | sed -n "s/.*packets \([0-9]*\).*comment \"$1\".*/\1/p"
}
cnt_zero() { inA nft reset rules inet viacnt post >/dev/null 2>&1 || true; }

start_vless() {
    # Не через inA: функция в фоне — это подоболочка, и $! дал бы её, а не движок (kill
    # оставил бы прежний туннель жить, и следующая часть мерила бы его).
    ip netns exec $A "$BIN" vless vl --spec "$WORK/spec.json" --state-dir "$WORK/state" \
        > "$WORK/tun.log" 2>&1 &
    VL_PID=$!
    for _ in $(seq 50); do
        inA ip link show vl >/dev/null 2>&1 && break
        sleep 0.2
    done
    inA ip link show vl >/dev/null 2>&1
}
stop_vless() {
    kill "$VL_PID" 2>/dev/null || true
    wait "$VL_PID" 2>/dev/null || true
    for _ in $(seq 25); do inA ip link show vl >/dev/null 2>&1 || break; sleep 0.2; done
}
fetch() {
    rm -f "$WORK/dl"
    if [ "$MODE" = router ]; then
        ip netns exec $C wget -q -O "$WORK/dl" -T 30 "http://$TARGET/x" || true
    else
        inA setpriv --reuid=$APP_UID --regid=$APP_UID --clear-groups \
            wget -q -O "$WORK/dl" -T 30 "http://$TARGET/x" || true
    fi
    got=$(wc -c < "$WORK/dl" 2>/dev/null || echo 0)
    [ "$got" = $((MB * 1024 * 1024)) ]
}

echo "run-via: режим $MODE, раскладка ${STEER_NFT_COMPAT:-по пробе}"

# ---- 1. vl через vx -----------------------------------------------------------------
spec ',"via":"vx"'
if inA "$BIN" apply --spec "$WORK/spec.json" --state-dir "$WORK/state" > "$WORK/apply.log" 2>&1
then ok "apply со спекой via"; else bad "apply со спекой via"; sed 's/^/    /' "$WORK/apply.log"; fi
start_vless && ok "устройство vl поднялось через vx" || { bad "устройство vl не поднялось"; sed 's/^/    /' "$WORK/tun.log"; }
cnt_zero
if fetch; then ok "канал через vl: скачано $MB МБ"; else bad "канал через vl: скачано $got байт"; fi
n_vx=$(cnt node-vx0); n_wan=$(cnt node-wan0); n_ch=$(cnt chan-vl)
echo "    к серверу VLESS: vx0 $n_vx пакетов, wan0 $n_wan; в устройство vl: $n_ch"
[ "${n_vx:-0}" -gt 0 ] && ok "соединение с сервером VLESS ушло в vx0" || bad "в vx0 к серверу — ноль"
[ "${n_wan:-0}" -eq 0 ] && ok "мимо WAN" || bad "к серверу через WAN: $n_wan"
[ "${n_ch:-0}" -gt 0 ] && ok "трафик канала — в устройство vl" || bad "в vl — ноль"
# Адрес источника соединения с сервером — адрес vx0: его выбрал connect() по таблице цели.
src=$(inS ss -tnH state established "( sport = :$PORT )" | awk '{print $4}' | sed 's/:[0-9]*$//' | sort -u | tr '\n' ' ')
case "$src" in *10.71.0.2*) ok "сервер видит клиента с адреса vx0 ($src)" ;;
                *) bad "сервер видит клиента с $src, а не с 10.71.0.2" ;; esac
# Метка сокета туннеля — метка выхода vx из реестра (ss печатает её как fwmark).
mk_of() { awk -v n="$1" '$1==n{print $2}' "$WORK/state/registry" | sed 's/^0*//'; }
fwm=$(inA ss -tneH "( dport = :$PORT )" 2>/dev/null | grep -o 'fwmark:0x[0-9a-f]*' | sort -u | tr '\n' ' ')
case "$fwm" in *"fwmark:0x$(mk_of vx)"*) ok "сокет туннеля несёт метку vx ($fwm)" ;;
               *) bad "метка сокета туннеля $fwm, а у vx 0x$(mk_of vx)" ;; esac
if [ "$MODE" = android ]; then
    if inA iptables -w -t nat -S POSTROUTING | grep -q -- '-o vx0 .*MASQUERADE'; then
        ok "masquerade на vx0 (iptables)"; else bad "masquerade на vx0 не встал"; fi
fi

# ---- 2. отказ цели: сторож объявляет нерабочим и vl -----------------------------------
inA "$BIN" failover --spec "$WORK/spec.json" --state-dir "$WORK/state" > "$WORK/fo1.log" 2>&1 || true
if grep -q 'выход vl -> vl\|vl: vl работает' "$WORK/fo1.log" || inA ip route show table all | grep -q 'default dev vl'; then
    ok "сторож: цель жива — vl в работе"; else bad "сторож: vl не в работе"; sed 's/^/    /' "$WORK/fo1.log"; fi
inA ip link set vx0 down
inA "$BIN" failover --spec "$WORK/spec.json" --state-dir "$WORK/state" > "$WORK/fo2.log" 2>&1 || true
if grep -q 'выход vl: идёт через vx, а тот не работает' "$WORK/fo2.log"; then
    ok "сторож: vx лёг — vl объявлен нерабочим"; else bad "сторож не связал отказ vl с vx"; sed 's/^/    /' "$WORK/fo2.log"; fi
tbl=$(awk '$1=="vl"{print $3}' "$WORK/state/registry")
if inA ip route show table "$tbl" | grep -q blackhole; then
    ok "on_fail=drop у vl: blackhole в его таблице"; else bad "у vl нет blackhole"; fi
inA ip link set vx0 up
inA "$BIN" failover --spec "$WORK/spec.json" --state-dir "$WORK/state" > "$WORK/fo3.log" 2>&1 || true
if inA ip route show table "$tbl" | grep -q 'default dev vl'; then
    ok "vx ожил — vl вернулся тем же проходом"; else bad "vl не вернулся"; sed 's/^/    /' "$WORK/fo3.log"; fi
# И трафик снова идёт тем же путём: соединение туннеля с сервером переоткрывается с той же
# меткой и снова уходит в vx0 (устройство цели сторож вернул сам, без apply).
cnt_zero
if fetch; then ok "после возврата vx: скачано $MB МБ"; else bad "после возврата vx: скачано $got байт"; fi
n_vx=$(cnt node-vx0); n_wan=$(cnt node-wan0)
[ "${n_vx:-0}" -gt 0 ] && [ "${n_wan:-0}" -eq 0 ] && ok "после возврата vx: к серверу снова через vx0" \
    || bad "после возврата vx: vx0 $n_vx, wan0 $n_wan"
stop_vless

# ---- 3. контроль: без via тот же выход ходит к серверу через WAN ----------------------
spec ''
inA "$BIN" apply --spec "$WORK/spec.json" --state-dir "$WORK/state" > "$WORK/apply2.log" 2>&1 || true
start_vless || { bad "без via: устройство vl не поднялось"; sed 's/^/    /' "$WORK/tun.log"; }
cnt_zero
if fetch; then ok "без via: скачано $MB МБ"; else bad "без via: скачано $got байт"; fi
n_vx=$(cnt node-vx0); n_wan=$(cnt node-wan0)
echo "    к серверу VLESS: vx0 $n_vx пакетов, wan0 $n_wan"
[ "${n_wan:-0}" -gt 0 ] && [ "${n_vx:-0}" -eq 0 ] && ok "без via: к серверу через WAN, в vx0 ноль" \
    || bad "без via: vx0 $n_vx, wan0 $n_wan"
# Без via метка — «мимо каналов»: на роутере её нет вовсе, на телефоне — «сам движок»
# (STEER_SELF_MARK, всё поле 22-27).
fwm=$(inA ss -tneH "( dport = :$PORT )" 2>/dev/null | grep -o 'fwmark:0x[0-9a-f]*' | sort -u | tr '\n' ' ')
if [ "$MODE" = android ]; then want="fwmark:0xfc00000 "; else want=""; fi
[ "$fwm" = "$want" ] && ok "без via: метка сокета «мимо каналов» (${fwm:-нет})" \
    || bad "без via: метка сокета $fwm, ждали ${want:-никакой}"
stop_vless

echo "run-via ($MODE): $pass passed, $fail failed"
[ "$fail" -eq 0 ]
