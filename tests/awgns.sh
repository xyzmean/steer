#!/bin/sh
# Выход kind=awg с настоящим ядром: движок поднимает туннель по спеке против пира в соседнем
# сетевом пространстве, трафик с меткой выхода уходит в туннель, status и сторож видят
# рукопожатие, смена файла перенастраивает устройство без пересоздания, down его снимает.
#
# Ядро здесь — ядро машины разработки, а модуль — ОБЫЧНЫЙ WireGuard: AmneziaWG на ней нет, и
# это не недостаток стенда, а второе, что он проверяет: файл без обфускации поднимается
# запасным модулем wireguard, а файл с обфускацией получает внятный отказ («в ядре нет модуля
# AmneziaWG»), и устройство не создаётся. Модуль AmneziaWG и ядро телефона — tests/awg49e.sh на
# стенде tools/vm49.
#
# Пир настраивается инструментом `wg`, то есть независимой реализацией протокола настройки:
# стенд, где обе стороны настроил бы наш же код, проверял бы сам себя.
#
# Нужны root, unshare, nsenter, ip, nft, wg, ping с ключом -m (метка) и модуль wireguard.
# Чего-то нет — стенд пропускается вслух, с кодом 0.
#
# Android-сборку тем же сценарием: собрать хостом с -DSTEER_ANDROID и своими каталогами
# (-DSTEER_TMP_DIR=... -DSTEER_STATE_DIR=... -DSTEER_ETC_DIR=..., как в шапке local49.sh) и
# запустить с STEER=<бинарник> AWG_FWMARK=0xfc00000 — у неё метка сокета туннеля без via —
# STEER_SELF_MARK, а не 0.
set -u
BIN="${STEER:-./build/steer}"
BIN="$(cd "$(dirname "$BIN")" && pwd)/$(basename "$BIN")"
[ -x "$BIN" ] || { echo "not built: $BIN (make)"; exit 2; }
skip() { echo "awgns: $1 — пропускаю"; exit 0; }
for t in ip nft wg unshare nsenter ping; do command -v $t >/dev/null 2>&1 || skip "нет $t"; done
if [ "${AWGNS_INNER:-}" != 1 ]; then
    [ "$(id -u)" = 0 ] || skip "нужен root"
    unshare -n true 2>/dev/null || skip "unshare -n недоступен"
    unshare -nm true 2>/dev/null || skip "unshare -nm недоступен"
    AWGNS_INNER=1 STEER="$BIN" exec unshare -nm sh "$0" "$@"
fi
# Своё /sys: sysfs показывает устройства того пространства, в котором смонтирован, и без
# перемонтирования сторож читал бы operstate устройств машины, а не своих.
mount --make-rprivate / 2>/dev/null
mount -t sysfs sysfs /sys 2>/dev/null || skip "не смонтировать sysfs в своём пространстве"

ip link set lo up
# Проверка обратного пути выключена в этом пространстве: ответ из туннеля приходит с адреса за
# пиром, а маршрута к нему без метки здесь нет (по умолчанию некуда), и даже «мягкая» проверка
# (2, так настроена машина) такой пакет отбросила бы. На роутере и телефоне маршрут по
# умолчанию есть. Новые устройства берут значение из default.
sysctl -qw net.ipv4.conf.all.rp_filter=0 net.ipv4.conf.default.rp_filter=0 2>/dev/null
nft add table inet awgns_probe 2>/dev/null || skip "nf_tables недоступен"
nft delete table inet awgns_probe
ip link add awgprobe type wireguard 2>/dev/null || skip "модуля wireguard нет"
ip link del awgprobe

tmp="$(mktemp -d)"
peer=""
cleanup() { [ -n "$peer" ] && kill "$peer" 2>/dev/null; rm -rf "$tmp"; }
trap cleanup EXIT
pass=0 fail=0
check() {
    if [ "$2" = "$3" ]; then pass=$((pass + 1)); echo "ok   $1"; else
        fail=$((fail + 1))
        printf 'FAIL %s\n  expected: %s\n  actual:   %s\n' "$1" "$2" "$3"
    fi
}

# ---- пир в соседнем пространстве ----------------------------------------------------------
unshare -n sleep 600 &
peer=$!
sleep 0.3
P="nsenter -t $peer -n"
ip link add awgv0 type veth peer name awgv1
ip link set awgv1 netns "$peer"
ip addr add 192.0.2.1/24 dev awgv0
ip link set awgv0 up
$P ip link set lo up
$P ip addr add 192.0.2.2/24 dev awgv1
$P ip link set awgv1 up
# «Интернет» за пиром: адрес, который канал уводит в туннель.
$P ip link add dum0 type dummy
$P ip addr add 198.51.100.1/32 dev dum0
$P ip link set dum0 up

umask 077
wg genkey > "$tmp/our.key"; wg pubkey < "$tmp/our.key" > "$tmp/our.pub"
wg genkey > "$tmp/peer.key"; wg pubkey < "$tmp/peer.key" > "$tmp/peer.pub"
$P ip link add wgpeer type wireguard
$P wg set wgpeer listen-port 51820 private-key "$tmp/peer.key" \
    peer "$(cat "$tmp/our.pub")" allowed-ips 10.77.0.0/24
$P ip addr add 10.77.0.1/24 dev wgpeer
$P ip link set wgpeer up

mkconf() {   # $1 — дополнительные строки [Interface]
    {
        echo "[Interface]"
        echo "PrivateKey = $(cat "$tmp/our.key")"
        echo "Address = 10.77.0.2/24"
        echo "DNS = 9.9.9.9"
        [ -n "${1:-}" ] && printf '%s\n' "$1"
        echo "[Peer]"
        echo "PublicKey = $(cat "$tmp/peer.pub")"
        echo "Endpoint = 192.0.2.2:51820"
        echo "AllowedIPs = 0.0.0.0/0"
    } > "$tmp/nl.conf"
}
mkspec() {   # $1 — имя выхода
    printf '198.51.100.0/24\n' > "$tmp/a.lst"
    cat > "$tmp/spec.json" <<EOF
{ "schema": 2, "from_default": ["192.168.1.0/24"],
  "outputs": { "$1": { "kind": "awg", "conf": "$tmp/nl.conf", "on_fail": "drop" } },
  "channels": [ { "name": "a", "match": { "prefixes_file": "$tmp/a.lst" }, "out": "$1" } ] }
EOF
}
S="--spec $tmp/spec.json --state-dir $tmp/state"
st() { "$BIN" status $S 2>/dev/null; }
field() { st | grep -o "\"$1\":[^,}]*" | head -1 | cut -d: -f2- | tr -d '"'; }

# ---- 1. apply поднимает туннель ----------------------------------------------------------
mkconf ""
mkspec nl
err="$("$BIN" apply $S 2>&1 >/dev/null)"
check "apply проходит" "0" "$?"
check "устройство nl создано" "1" "$(ip link show nl 2>/dev/null | grep -c 'nl:')"
check "модуль — запасной wireguard (AmneziaWG на машине нет)" "1" \
      "$(ip -d link show nl 2>/dev/null | grep -c 'wireguard')"
check "приватный ключ на устройстве — из файла" "$(cat "$tmp/our.key")" "$(wg show nl private-key 2>/dev/null)"
check "пир и эндпоинт" "192.0.2.2:51820" "$(wg show nl endpoints 2>/dev/null | cut -f2)"
check "keepalive выключен (батарея)" "off" "$(wg show nl persistent-keepalive 2>/dev/null | cut -f2)"
check "метка сокета туннеля без via" "${AWG_FWMARK:-off}" "$(wg show nl fwmark 2>/dev/null)"
check "адрес из Address" "1" "$(ip -4 addr show dev nl | grep -c '10.77.0.2/24')"
check "MTU по умолчанию 1420" "1" "$(ip link show nl | grep -c 'mtu 1420')"
check "предупреждение про DNS из файла" "1" "$(printf '%s\n' "$err" | grep -c 'DNS из файла не применяется')"
check "таблица выхода ведёт в nl" "1" "$(ip route show table all 2>/dev/null | grep -c '^default dev nl table')"
check "в status ключа нет" "0" "$(st | grep -c "$(cat "$tmp/our.key" | cut -c1-20)")"
check "status: impl" "wireguard" "$(field impl)"
# Android-сборка: masquerade туннелю ставит сам движок правилом iptables (android_masq_sync), как
# выходу kind=interface, — сервер WireGuard примет только адрес туннеля.
if [ "${AWG_FWMARK:-off}" != off ] && command -v iptables >/dev/null 2>&1; then
    check "Android: masquerade на nl по метке выхода" "1" \
          "$(iptables -w -t nat -S POSTROUTING 2>/dev/null | grep -c -- '-o nl .*MASQUERADE')"
fi
check "status: рукопожатия ещё не было" "null" "$(field handshake_ago)"

# ---- 2. трафик канала уходит в туннель ---------------------------------------------------
mark="$(st | grep -o '"mark":"0x[0-9a-f]*"' | head -1 | cut -d'"' -f4)"
# Адрес источника — адрес туннеля: так его выбрало бы ядро для пакета, маршрутизированного в
# nl, а у ping без -I выбор источника идёт пробным connect БЕЗ метки, и в пространстве без
# маршрута по умолчанию он кончается «Network unreachable» раньше, чем метка что-то решит.
ping -q -c 3 -W 2 -m "$((mark))" -I 10.77.0.2 198.51.100.1 >"$tmp/ping.out" 2>&1
rc=$?
[ "$rc" = 0 ] || cat "$tmp/ping.out"
check "пакет с меткой выхода дошёл через туннель до адреса за пиром" "0" "$rc"
check "маршрут по метке — через nl" "1" "$(ip route get 198.51.100.1 mark "$mark" 2>/dev/null | grep -c 'dev nl')"
ago="$(field handshake_ago)"
check "status: рукопожатие было (секунд назад — число)" "1" "$(printf '%s' "$ago" | grep -cE '^[0-9]+$')"
check "status: endpoint" "192.0.2.2:51820" "$(field endpoint)"
check "status: rx растёт" "1" "$([ "$(field rx)" -gt 0 ] && echo 1)"
check "пир видит рукопожатие (сторона wg)" "1" "$($P wg show wgpeer latest-handshakes | awk '{print ($2>0)}')"

# ---- 3. сторож: здоровье по рукопожатию, без проб ---------------------------------------
"$BIN" failover $S >/dev/null 2>&1
check "сторож: выход жив, маршрут на месте" "1" "$(ip route show table all | grep -c '^default dev nl table')"
# Запасной запрет (blackhole с метрикой STEER_BACKSTOP_METRIC) лежит у выхода с drop всегда и
# запретом в таблице не считается — проверки ниже смотрят на основной, без метрики.
nobs() { grep -v ' metric 65535'; }
check "сторож: без blackhole" "0" "$(ip route show table all | nobs | grep -c 'blackhole default')"
check "запасной запрет у выхода с drop на месте" "1" \
      "$(ip route show table all | grep -c 'blackhole default.* metric 65535')"

# ---- 4. смена файла — перенастройка без пересоздания ------------------------------------
idx="$(cat /sys/class/net/nl/ifindex)"
hs_before="$(wg show nl latest-handshakes | cut -f2)"
mkconf "MTU = 1400
ListenPort = 51999
Address = 10.77.1.2/32"
"$BIN" apply $S >/dev/null 2>&1
check "повторный apply проходит" "0" "$?"
check "устройство не пересоздано (тот же ifindex)" "$idx" "$(cat /sys/class/net/nl/ifindex)"
check "ListenPort из нового файла" "51999" "$(wg show nl listen-port)"
check "MTU из нового файла" "1" "$(ip link show nl | grep -c 'mtu 1400')"
check "второй адрес добавлен, первый на месте" "2" "$(ip -4 addr show dev nl | grep -cE '10.77.(0.2/24|1.2/32)')"
check "сессия пира не порвана (рукопожатие то же)" "$hs_before" "$(wg show nl latest-handshakes | cut -f2)"
ping -q -c 1 -W 2 -m "$((mark))" -I 10.77.0.2 198.51.100.1 >/dev/null 2>&1
check "трафик после перенастройки идёт" "0" "$?"

mkconf ""
"$BIN" apply $S >/dev/null 2>&1
check "адрес, убранный из файла, снят" "0" "$(ip -4 addr show dev nl | grep -c '10.77.1.2')"

# ---- 5. обфускация без модуля AmneziaWG: отказ ------------------------------------------
mkconf "Jc = 4
Jmin = 40
Jmax = 70
S1 = 15
S2 = 18
H1 = 100
H2 = 200
H3 = 300
H4 = 400"
mkspec nl2
err="$("$BIN" apply $S 2>&1 >/dev/null)"
check "отказ назван" "1" "$(printf '%s\n' "$err" | grep -c 'нет модуля AmneziaWG')"
check "устройство nl2 не создано" "0" "$(ip link show nl2 2>/dev/null | grep -c nl2)"
check "устройство выхода, убранного из спеки, снято" "0" "$(ip link show nl 2>/dev/null | grep -c 'nl:')"
check "таблица выхода без устройства — blackhole (on_fail=drop)" "1" \
      "$(ip route show table all | nobs | grep -c 'blackhole default')"

# ---- 6. имя, выдающее туннель, заменяется ------------------------------------------------
mkconf ""
mkspec wg7
"$BIN" apply $S >/dev/null 2>&1
check "устройства «wg7» нет" "0" "$(ip link show wg7 2>/dev/null | grep -c wg7)"
dev="$(field device)"
check "устройство — нейтральное if…" "1" "$(printf '%s' "$dev" | grep -cE '^if[0-9a-f]{8}$')"
check "и оно создано" "1" "$(ip link show "$dev" 2>/dev/null | grep -c "$dev")"

# ---- 6a. via: UDP туннеля — через выход-интерфейс -----------------------------------------
# Второй путь к пиру — ux0, устройство выхода kind=interface (подделка другого туннеля: veth без
# маршрута по умолчанию). Endpoint пира — адрес на его dummy, до которого из этого пространства
# без метки нет маршрута вовсе: дойти туда UDP туннеля может только меткой выхода ux, то есть
# через его таблицу и ux0. Рукопожатие и ping через туннель это и доказывают, а счётчик на ux0 и
# адрес, с которого пир видит нас, — что путь именно тот.
ip link add ux0 type veth peer name ux1
ip link set ux1 netns "$peer"
ip addr add 10.78.0.1/24 dev ux0
ip link set ux0 up
$P ip addr add 10.78.0.2/24 dev ux1
$P ip link set ux1 up
$P ip addr add 203.0.113.9/32 dev dum0
# Адрес пробы сторожа — за ux0 тоже: иначе сторож считал бы ux мёртвым всегда, и проверка
# отказа ниже проходила бы, ничего не проверяя.
$P ip addr add 1.1.1.1/32 dev dum0
sed -i 's/^Endpoint = .*/Endpoint = 203.0.113.9:51820/' "$tmp/nl.conf"
cat > "$tmp/spec.json" <<SPEC
{ "schema": 2, "from_default": ["192.168.1.0/24"],
  "outputs": { "ux": { "kind": "interface", "device": "ux0", "on_fail": "drop" },
               "nl": { "kind": "awg", "conf": "$tmp/nl.conf", "device": "nl", "via": "ux",
                       "on_fail": "drop" } },
  "channels": [ { "name": "a", "match": { "prefixes_file": "$tmp/a.lst" }, "out": "nl" } ] }
SPEC
nft add table inet awgvia
nft add chain inet awgvia post '{ type filter hook postrouting priority 300; policy accept; }'
nft add rule inet awgvia post oifname ux0 udp dport 51820 counter
"$BIN" apply $S >/dev/null 2>&1
check "via: apply проходит" "0" "$?"
omark() { st | grep -o "\"$1\":{[^}]*" | grep -o '"mark":"0x[0-9a-f]*"' | cut -d'"' -f4; }
uxmark="$(omark ux)"; nlmark="$(omark nl)"
# У Android-сборки к метке цели добавлен бит «собственный трафик туннеля» (STEER_TUNNEL_BIT,
# 0x10000000): по нему заворот DNS приложений пропускает туннель через via.
tunbit=0; [ "${AWG_FWMARK:-off}" != off ] && tunbit=$((0x10000000))
check "via: метка сокета туннеля — метка выхода ux" "$(printf '0x%x' "$((uxmark | tunbit))")" \
      "$(wg show nl fwmark 2>/dev/null)"
check "via: status называет цель" "1" "$(st | grep -o '"nl":{[^}]*' | grep -c '"via":"ux"')"
ping -q -c 3 -W 2 -m "$((nlmark))" -I 10.77.0.2 198.51.100.1 >"$tmp/ping.out" 2>&1
rc=$?
[ "$rc" = 0 ] || cat "$tmp/ping.out"
check "via: трафик канала дошёл через awg, а awg — через ux" "0" "$rc"
n="$(nft list chain inet awgvia post | sed -n 's/.*packets \([0-9]*\).*/\1/p')"
check "via: UDP туннеля ушёл в ux0 (пакетов > 0)" "1" "$([ "${n:-0}" -gt 0 ] && echo 1)"
check "via: пир видит нас с адреса ux0" "10.78.0.1" \
      "$($P wg show wgpeer endpoints | cut -f2 | cut -d: -f1)"
# Отказ цели: ux0 лёг — сторож объявляет нерабочим и nl (его on_fail — blackhole в его таблице).
nltable="$(st | grep -o '"nl":{[^}]*' | grep -o '"table":[0-9]*' | cut -d: -f2)"
"$BIN" failover $S >"$tmp/fo.out" 2>&1
check "via: ux жив — nl в работе" "1" "$(ip route show table "$nltable" | grep -c 'default dev nl')"
ip link set ux0 down
"$BIN" failover $S >"$tmp/fo.out" 2>&1
check "via: ux лёг — nl объявлен нерабочим" "1" "$(grep -c 'выход nl: идёт через ux' "$tmp/fo.out")"
check "via: у nl blackhole" "1" "$(ip route show table "$nltable" | nobs | grep -c blackhole)"
ip link set ux0 up
"$BIN" failover $S >"$tmp/fo.out" 2>&1
check "via: ux ожил — nl вернулся" "1" "$(ip route show table "$nltable" | grep -c 'default dev nl')"
nft delete table inet awgvia
# Endpoint по IPv6 при via: таблица цели — только IPv4, и такой туннель ушёл бы мимо ux. Отказ с
# причиной и при --dry-run, и при apply; устройство не перенастраивается на адрес IPv6.
sed -i 's/^Endpoint = .*/Endpoint = [2001:db8::9]:51820/' "$tmp/nl.conf"
err="$("$BIN" apply --dry-run $S 2>&1 >/dev/null)"
check "via + Endpoint IPv6: --dry-run называет причину" "1" \
      "$(printf '%s\n' "$err" | grep -c 'адрес IPv6 (2001:db8::9), а туннель идёт через via ux')"
err="$("$BIN" apply $S 2>&1 >/dev/null)"
check "via + Endpoint IPv6: apply отказывает туннелю с причиной" "1" \
      "$(printf '%s\n' "$err" | grep -c 'туннель не поднят')"
check "via + Endpoint IPv6: адрес IPv6 на устройство не лёг" "0" \
      "$(wg show nl endpoints 2>/dev/null | grep -c '2001:db8::9')"
sed -i 's/^Endpoint = .*/Endpoint = 203.0.113.9:51820/' "$tmp/nl.conf"
"$BIN" apply $S >/dev/null 2>&1

# ---- 7. down снимает туннель -------------------------------------------------------------
"$BIN" down --state-dir "$tmp/state" >/dev/null 2>&1
check "down: устройство снято" "0" "$(ip link show "$dev" 2>/dev/null | grep -c "$dev")"
check "down: реестр устройств убран" "0" "$(ls "$tmp/state" 2>/dev/null | grep -c '^awg-devices$')"
check "пир в соседнем пространстве не тронут" "1" "$($P ip link show wgpeer | grep -c wgpeer)"

echo "awgns: $pass passed, $fail failed"
[ "$fail" -eq 0 ]
