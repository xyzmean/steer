#!/bin/sh
# Живая звезда xsteer: хаб и два пира в отдельных пространствах имён.
#
# ЗАЧЕМ ЭТОТ СТЕНД. Главное обещание звезды — «пир видит пир через хаб» — не проверяется
# ни одной чистой функцией и ни одним стендом в памяти: там нет ни TUN, ни сырых сокетов, ни
# ядра, которое эти пакеты маршрутизирует. Здесь обе стороны настоящие, бинарники те же, что
# уедут в пакет и в архив, и разница в числах относится к туннелю, а не к обстановке.
#
# Сравнивается с tests/wgbaseline.sh: тот же iperf3, тот же veth, та же машина.
#
# Требует root (пространства имён и сырые сокеты), /dev/net/tun, iperf3 и собранные
# бинарники. В make test не входит — как run-tunnel.sh, run-udp.sh и run-reality.sh.
#
#     sudo sh tests/run-xsteer.sh [секунд_на_замер]
set -eu
umask 077

SECS="${1:-6}"
HUB=${STEER_HUB_BIN:-./build/steer-hub}
EXT=${STEER_EXT_BIN:-./build/steer-ext}
NSH=xs-hub
NSA=xs-a
NSB=xs-b
WORK=

fail=0
ok()   { printf '%-58s ok\n' "$1"; }
bad()  { printf '%-58s ПРОВАЛ\n' "$1"; fail=$((fail + 1)); }
check() { if [ "$2" = "$3" ]; then ok "$1"; else bad "$1"; printf '     хочу: %s\n     есть: %s\n' "$2" "$3"; fi; }

cleanup() {
    for ns in $NSH $NSA $NSB; do
        pkill -f "netns $ns" 2>/dev/null || true
        ip netns pids $ns 2>/dev/null | xargs -r kill 2>/dev/null || true
        ip netns del $ns 2>/dev/null || true
    done
    if [ -n "$WORK" ]; then rm -rf "$WORK"; fi
    return 0
}
trap cleanup EXIT INT TERM
cleanup

[ "$(id -u)" = 0 ] || { echo "нужен root: стенд делает пространства имён и сырые сокеты"; exit 2; }
[ -c /dev/net/tun ] || { echo "нет /dev/net/tun — туннель не поднять"; exit 2; }
[ -x "$HUB" ] || { echo "нет $HUB (соберите серверную сборку)"; exit 2; }
[ -x "$EXT" ] || { echo "нет $EXT (соберите расширенную сборку)"; exit 2; }
command -v iperf3 >/dev/null || { echo "нет iperf3"; exit 2; }

WORK="$(mktemp -d)"
chmod 700 "$WORK"

# ---- сеть: хаб в центре, по veth к каждой пиру ------------------------------
for ns in $NSH $NSA $NSB; do ip netns add $ns; ip -n $ns link set lo up; done
# Пересылку в ядре ВЫКЛЮЧАЕМ явно, а не надеемся на умолчание: значение наследуется от
# хозяйской системы при создании пространства, и на машине с включённой пересылкой стенд
# проверял бы не то, что обещает. Связь пир↔пир обязана работать без неё — трафик разворачивает
# хаб в пользовательском пространстве.
for ns in $NSH $NSA $NSB; do ip netns exec $ns sysctl -qw net.ipv4.ip_forward=0; done
ip link add ha netns $NSH type veth peer name ah netns $NSA
ip link add hb netns $NSH type veth peer name bh netns $NSB
ip -n $NSH addr add 10.210.1.1/24 dev ha
ip -n $NSA addr add 10.210.1.2/24 dev ah
ip -n $NSH addr add 10.210.2.1/24 dev hb
ip -n $NSB addr add 10.210.2.2/24 dev bh
for p in "$NSH ha" "$NSA ah" "$NSH hb" "$NSB bh"; do
    set -- $p
    ip -n "$1" link set "$2" up
done

# ---- ключи и конфигурации ----------------------------------------------------
gen() { "$EXT" xsteer-key; }
gen > "$WORK/hub.keys"
gen > "$WORK/a.keys"
gen > "$WORK/b.keys"
kpriv() { awk '/PrivateKey/ {print $3}' "$1"; }
kpub()  { awk '/PublicKey/  {print $3}' "$1"; }

cat > "$WORK/hub.conf" <<EOF
[Interface]
PrivateKey = $(kpriv "$WORK/hub.keys")
Address    = 10.77.0.1/24
ListenPort = 443

[Peer]
PublicKey  = $(kpub "$WORK/a.keys")
AllowedIPs = 10.77.0.2/32

[Peer]
PublicKey  = $(kpub "$WORK/b.keys")
AllowedIPs = 10.77.0.3/32
EOF

spoke_conf() {   # $1 — файл ключей, $2 — адрес в туннеле, $3 — адрес хаба, $4 — куда писать
    cat > "$4" <<EOF
[Interface]
PrivateKey = $(kpriv "$1")
Address    = $2/24
SNI        = www.example.com

[Peer]
PublicKey  = $(kpub "$WORK/hub.keys")
AllowedIPs = 10.77.0.0/24
Endpoint   = $3:443
PersistentKeepalive = 15
EOF
}
spoke_conf "$WORK/a.keys" 10.77.0.2 10.210.1.1 "$WORK/a.conf"
spoke_conf "$WORK/b.keys" 10.77.0.3 10.210.2.1 "$WORK/b.conf"
chmod 600 "$WORK"/*.conf

# Спека нужна клиенту: он выход и его устройство берёт оттуда. Каналов в ней нет — стенд
# проверяет туннель, а не маршрутизацию по правилам.
spec() {   # $1 — имя выхода, $2 — путь к конфигурации, $3 — куда писать
    cat > "$3" <<EOF
{"schema":1,"lan_device":"lo","from_default":["10.77.0.0/24"],
 "outputs":{"$1":{"kind":"xsteer","conf":"$2"}},
 "channels":[]}
EOF
}
spec vpna "$WORK/a.conf" "$WORK/a.json"
spec vpnb "$WORK/b.conf" "$WORK/b.json"

# ---- запуск ------------------------------------------------------------------
# Перепроверка пути — раз в три секунды вместо двух минут: стенду надо УВИДЕТЬ, как пир
# замечает сузившийся путь, а с боевым интервалом проверка заняла бы четыре минуты и её
# выключили бы первой. На боевой работе переменная не ставится.
export STEER_XS_PROBE_MS=3000
# Число воркеров хаб выбирает сам (не больше числа пиров); XSW позволяет сравнить с другим
# числом на том же прогоне — без этого «многопоток помог» проверить нечем.
if [ -n "${XSW:-}" ]; then export STEER_XS_WORKERS="$XSW"; fi
mkdir -p "$WORK/state-hub" "$WORK/state-a" "$WORK/state-b"
ip netns exec $NSH "$HUB" xsteer-hub --config "$WORK/hub.conf" \
    --state-dir "$WORK/state-hub" > "$WORK/hub.log" 2>&1 &
HUBPID=$!
sleep 0.6
ip netns exec $NSA "$EXT" xsteer vpna --spec "$WORK/a.json" \
    --state-dir "$WORK/state-a" > "$WORK/a.log" 2>&1 &
APID=$!
ip netns exec $NSB "$EXT" xsteer vpnb --spec "$WORK/b.json" \
    --state-dir "$WORK/state-b" > "$WORK/b.log" 2>&1 &

# Ждём рукопожатий: их видно и в журнале хаба, и в файле состояния пира.
# grep -c печатает 0 и выходит с кодом 1, когда совпадений нет: «|| echo 0» дописывал бы
# ВТОРУЮ строку, и сравнение числа падало бы с «Illegal number» — ровно это и случилось при
# первом прогоне. Поэтому счётчик снимается одной подстановкой без запасного echo.
# Считаются РАЗНЫЕ ПИРЫ, а не строки: пир открывает по соединению на ядро, и строк
# «поднялся» у неё столько же. Проверять число строк значило бы вписать в стенд число ядер
# машины, на которой он запущен.
count_up() { grep -h 'поднялся' "$WORK/hub.log" 2>/dev/null | sed 's/.*пир \([^ ]*\) .*/\1/' \
             | sort -u | grep -c .; }
count_lines() { grep -c 'поднялся' "$WORK/hub.log" 2>/dev/null | head -1; }
for i in $(seq 1 80); do
    [ "$(count_up)" -ge 2 ] && break
    sleep 0.25
done

peers_up=$(count_up)
check "рукопожатия: оба пира опознаны хабом" "2" "$peers_up"
if [ "$peers_up" -lt 2 ]; then
    echo "--- журнал хаба ---"; cat "$WORK/hub.log"
    echo "--- журнал пира A ---"; cat "$WORK/a.log"
    exit 1
fi

# ---- связь -------------------------------------------------------------------
if ip netns exec $NSA ping -c 3 -W 2 -q 10.77.0.1 >/dev/null 2>&1; then
    ok "пир A → хаб: ping проходит"
else
    bad "пир A → хаб: ping проходит"
fi
# ГЛАВНОЕ утверждение звезды: пир видит пир, и трафик разворачивает хаб в
# пользовательском пространстве, без ip_forward.
fwd=$(ip netns exec $NSH cat /proc/sys/net/ipv4/ip_forward)
check "ip_forward на хабе выключен" "0" "$fwd"
if ip netns exec $NSA ping -c 3 -W 2 -q 10.77.0.3 >/dev/null 2>&1; then
    ok "пир A → пир B через хаб: ping проходит"
else
    bad "пир A → пир B через хаб: ping проходит"
    echo "--- журнал хаба ---"; tail -5 "$WORK/hub.log"
fi

# ---- согласование MTU --------------------------------------------------------
# MTU НЕ ЗАШИТ в стенд намеренно: его выясняет сам движок — берёт минимум из пределов сторон
# и проверяет путь пробами. Зашитое число проверяло бы, что стенд и код согласны друг с другом,
# а не что согласование работает.
mtu_of() { ip netns exec $NSA cat /sys/class/net/vpna/mtu; }
# Ждём УСТОЯВШЕГОСЯ значения, а не первого изменения. Разница принципиальна: поиск идёт
# несколькими пробами, и снятое посередине число относится к незакончившемуся поиску. Первая
# версия стенда так и попалась — прочитала безопасный низ в тот миг, когда его только
# применили, и приписала найденный дальше предел следующей проверке.
settle() {                      # окно устойчивости больше интервала пробоя
    _last=""; _same=0; _i=0
    while [ $_same -lt 8 ] && [ $_i -lt 120 ]; do
        _cur=$(mtu_of)
        if [ "$_cur" = "$_last" ]; then _same=$((_same + 1)); else _same=0; _last=$_cur; fi
        sleep 0.5; _i=$((_i + 1))
    done
    echo "$_last"
}
tmtu=$(settle)
# Канал в стенде — обычные 1500, поэтому предел равен 1500-61. Меньше означало бы, что пробой
# не дошёл до потолка; больше — что предел взят с потолка без проверки пути.
check "MTU согласован по каналу 1500" "1439" "$tmtu"
# Ровно MTU туннеля минус заголовки ICMP: должен пройти. На байт больше с запретом
# фрагментации — не должен, и это правильно: иначе он пропал бы молча уже на канале.
if ip netns exec $NSA ping -c 2 -W 2 -q -M do -s $((tmtu - 28)) 10.77.0.1 >/dev/null 2>&1; then
    ok "пакет размером в MTU туннеля проходит"
else
    bad "пакет размером в MTU туннеля проходит"
fi
if ip netns exec $NSA ping -c 1 -W 2 -q -M do -s 1500 10.77.0.1 >/dev/null 2>&1; then
    bad "пакет больше MTU не проходит (а он прошёл)"
else
    ok "пакет больше MTU не проходит"
fi

# ---- путь сузился под живой сессией ------------------------------------------
# Самый неприятный вид отказа у любого туннеля: канал «работает», рукопожатие проходит, ping
# идёт, а большие пакеты пропадают целиком и молча. Случается это не из-за настройки, а само:
# оператор переключил маршрут, дальше появился ещё один туннель, сменился канал у пира.
#
# Подделываем это правилом, отбрасывающим у хаба крупные сегменты, — именно так ведёт себя
# посредник с меньшим MTU, который не шлёт ICMP (а не шлёт его большинство). Фрагментации тут
# нет: у нас нет DF, но правило смотрит на РАЗМЕР, а не на возможность нарезать.
#
# Ожидание: пир замечает это на очередном пробое, немедленно опускается на безопасный низ и
# сходится на новом настоящем пределе. Проверка стоит именно живьём: в памяти «путь сузился»
# не выражается.
echo
narrow=1400          # столько несёт «новый» путь; предел туннеля станет 1400-61 = 1339
ip netns exec $NSH nft add table ip xstest 2>/dev/null
ip netns exec $NSH nft add chain ip xstest c '{ type filter hook input priority -300 ; }' 2>/dev/null
ip netns exec $NSH nft add rule ip xstest c ip length gt $narrow drop 2>/dev/null
new=$(settle)
if [ "$new" -lt "$tmtu" ]; then
    ok "путь сузился: пир опустил MTU ($tmtu → $new)"
else
    bad "путь сузился: пир опустил MTU"
    grep -E "MTU|путь" "$WORK/a.log" | tail -4
fi
# И новый предел обязан РАБОТАТЬ: опуститься куда угодно мало, надо опуститься туда, где ходят
# полные пакеты. Зерно поиска — 8 байт, поэтому найденное значение может быть чуть ниже
# настоящего; выше настоящего оно быть не может. Заодно это отличает «нашёл новый предел» от
# «сел на безопасный низ и там остался»: низ тоже работает, но он на 139 байт хуже.
if ip netns exec $NSA ping -c 3 -W 2 -q -M do -s $((new - 28)) 10.77.0.1 >/dev/null 2>&1; then
    ok "на новом MTU полные пакеты ходят"
else
    bad "на новом MTU полные пакеты ходят"
fi
check "новый предел не выше того, что несёт путь" "1" \
      "$([ "$new" -le $((narrow - 61)) ] && echo 1 || echo 0)"
check "новый предел не ниже настоящего на зерно поиска" "1" \
      "$([ "$new" -ge $((narrow - 61 - 8)) ] && echo 1 || echo 0)"
# Убираем правило: путь снова широкий, и пир обязан это ЗАМЕТИТЬ и подняться обратно.
# Без этой половины проверки согласование могло бы деградировать в одну сторону — то есть
# однажды севшая пир так и осталась бы на низком MTU до перезапуска.
ip netns exec $NSH nft delete table ip xstest 2>/dev/null
back=$(settle)
if [ "$back" = "$tmtu" ]; then
    ok "путь расширился: пир вернулся к прежнему MTU ($new → $back)"
else
    bad "путь расширился: пир вернулся к прежнему MTU ($tmtu)"
    printf '     есть: %s\n' "$back"
    grep -E "MTU|путь" "$WORK/a.log" | tail -4
fi

# ---- хаб перезапустили -------------------------------------------------------
# Переподключение — событие обычное: перезапуск хаба, смена ключей, тишина на пути. Проверяется
# здесь не то, что туннель поднимется (это видно и по ping), а что MTU ВЕРНЁТСЯ к измеренному.
# Именно это и было сломано: устройство оставалось на безопасном низу, подтверждённое значение
# считалось прежним, «ничего не изменилось» — и туннель молча работал на 1200 вместо 1439, не
# написав об этом ни строки. Ловится только проверкой ЧИСЛА на устройстве после переподключения.
echo
# Снимок ДО убийства: после него хаб успевает написать свои строки, и снятое позже число
# сравнивалось бы само с собой.
was_lines=$(count_lines)
kill "$HUBPID" 2>/dev/null
sleep 1
ip netns exec $NSH "$HUB" xsteer-hub --config "$WORK/hub.conf" \
    --state-dir "$WORK/state-hub" >> "$WORK/hub.log" 2>&1 &
HUBPID=$!
# Ждём БОЛЬШЕ строк «поднялся», чем было до перезапуска: сколько именно, зависит от числа
# соединений пира, а вот «стало больше» верно всегда.
i=0
while [ "$(count_lines)" -le "$was_lines" ] && [ $i -lt 120 ]; do sleep 0.5; i=$((i + 1)); done
if [ "$(count_lines)" -gt "$was_lines" ]; then
    ok "после перезапуска хаба пир поднялся заново"
else
    bad "после перезапуска хаба пир поднялся заново"
fi
after=$(settle)
check "MTU после переподключения вернулся к измеренному" "$tmtu" "$after"
if ip netns exec $NSA ping -c 2 -W 2 -q -M do -s $((after - 28)) 10.77.0.1 >/dev/null 2>&1; then
    ok "на восстановленном MTU полные пакеты ходят"
else
    bad "на восстановленном MTU полные пакеты ходят"
fi

# ---- кто упирается: хаб или пир --------------------------------------------
# Число «столько-то Гбит/с» само по себе не диагноз: непонятно, чей это потолок и что чинить.
# Поэтому за ОДИН и тот же замер снимаются процессорные тики обоих процессов. Сотая доля
# секунды — один тик, значит ядро целиком за N секунд это 100*N тиков.
ticks() { awk '{print $14 + $15}' "/proc/$1/stat" 2>/dev/null || echo 0; }
h0=$(ticks "$HUBPID"); a0=$(ticks "$APID"); t0=$(date +%s)
ip netns exec $NSH iperf3 -s -1 -D --logfile "$WORK/ipcpu.log" -B 10.77.0.1 >/dev/null 2>&1
sleep 0.5
mbit=$(ip netns exec $NSA iperf3 -c 10.77.0.1 -t 8 -O 1 -f m 2>/dev/null | awk '/receiver/{print $7}')
h1=$(ticks "$HUBPID"); a1=$(ticks "$APID"); t1=$(date +%s)
full=$(( (t1 - t0) * 100 ))
echo
printf 'на %s Мбит/с: хаб съел %s тиков, пир %s (ядро целиком за этот замер = %s)\n' \
       "${mbit:-?}" "$((h1 - h0))" "$((a1 - a0))" "$full"

# ---- скорость ----------------------------------------------------------------
echo
echo "скорость через звезду (пир A → хаб, MTU туннеля $(ip netns exec $NSA cat /sys/class/net/vpna/mtu)):"
ip netns exec $NSH iperf3 -s -1 -D --logfile "$WORK/iperf.log" -B 10.77.0.1 >/dev/null 2>&1
sleep 0.5
ip netns exec $NSA iperf3 -c 10.77.0.1 -t "$SECS" -f m 2>/dev/null \
    | awk '/receiver/ {printf "  %8.2f Гбит/с  (пир → хаб, один поток)\n", $7/1000}'
# ОБРАТНОЕ направление меряется отдельно и обязательно: путь в нём другой (хаб читает TUN и
# шифрует, пир расшифровывает и пишет TUN), и для человека это направление главное — им
# грузятся страницы. Одно число «туда» скрывало бы поломку в половине кода пути данных.
ip netns exec $NSH iperf3 -s -1 -D --logfile "$WORK/iperfR.log" -B 10.77.0.1 >/dev/null 2>&1
sleep 0.5
ip netns exec $NSA iperf3 -c 10.77.0.1 -t "$SECS" -R -f m 2>/dev/null \
    | awk '/receiver/ {printf "  %8.2f Гбит/с  (хаб → пир, один поток)\n", $7/1000}'
# Четыре потока отвечают на вопрос, во что мы упираемся. Вырос итог — упирались в задержку и
# окно одного соединения; не вырос — в процессор. Без этого числа «медленно» не диагноз.
ip netns exec $NSH iperf3 -s -1 -D --logfile "$WORK/iperf1b.log" -B 10.77.0.1 >/dev/null 2>&1
sleep 0.5
ip netns exec $NSA iperf3 -c 10.77.0.1 -t "$SECS" -P 4 -f m 2>/dev/null \
    | awk '/SUM.*receiver/ {printf "  %8.2f Гбит/с  (пир → хаб, четыре потока)\n", $6/1000}'

# ---- сколько тянет ОДНА пир несколькими соединениями -----------------------
# Двумя ОТДЕЛЬНЫМИ процессами iperf3, а не одним с флагом -P: iperf3 однопоточный, и «четыре
# потока» одного процесса упираются в его собственное ядро, а не в туннель. Первая версия
# замера этим и обманулась — показывала 0,54 Гбит/с там, где туннель ни при чём.
echo
echo "один пир, два процесса (соединений у пира: ${STEER_XS_CONNS:-по числу ядер}):"
ip netns exec $NSH iperf3 -s -1 -D -p 5321 --logfile "$WORK/ip1a.log" -B 10.77.0.1 >/dev/null 2>&1
ip netns exec $NSH iperf3 -s -1 -D -p 5322 --logfile "$WORK/ip1b.log" -B 10.77.0.1 >/dev/null 2>&1
sleep 0.5
ip netns exec $NSA iperf3 -c 10.77.0.1 -p 5321 -t "$SECS" -f m > "$WORK/oneA" 2>/dev/null &
p1=$!
ip netns exec $NSA iperf3 -c 10.77.0.1 -p 5322 -t "$SECS" -f m > "$WORK/oneB" 2>/dev/null &
p2=$!
wait $p1 $p2
o1=$(awk '/receiver/{print $7}' "$WORK/oneA"); o2=$(awk '/receiver/{print $7}' "$WORK/oneB")
awk -v a="${o1:-0}" -v b="${o2:-0}" 'BEGIN{printf "  %8.2f Гбит/с  (%.0f + %.0f Мбит/с)\n", (a+b)/1000, a, b}'

# ---- сколько тянет хаб СУММАРНО ----------------------------------------------
# Главное число для звезды и единственное, которое проверяет раскладку по воркерам: один пир
# — это одно поддельное соединение, то есть один воркер, и на ней многопоток не виден вовсе.
# Смысл он имеет ровно там, где хаб обслуживает НЕСКОЛЬКО пиров: их порты попадают в разные
# воркеры, и суммарная пропускная способность перестаёт упираться в одно ядро.
echo
echo "суммарно от двух пиров одновременно (воркеров: ${STEER_XS_WORKERS:-по числу ядер}):"
ip netns exec $NSH iperf3 -s -1 -D -p 5311 --logfile "$WORK/ipsum1.log" -B 10.77.0.1 >/dev/null 2>&1
ip netns exec $NSH iperf3 -s -1 -D -p 5312 --logfile "$WORK/ipsum2.log" -B 10.77.0.1 >/dev/null 2>&1
sleep 0.5
ip netns exec $NSA iperf3 -c 10.77.0.1 -p 5311 -t "$SECS" -f m > "$WORK/sumA" 2>/dev/null &
pa=$!
ip netns exec $NSB iperf3 -c 10.77.0.1 -p 5312 -t "$SECS" -f m > "$WORK/sumB" 2>/dev/null &
pb=$!
wait $pa $pb
sa=$(awk '/receiver/{print $7}' "$WORK/sumA"); sb=$(awk '/receiver/{print $7}' "$WORK/sumB")
awk -v a="${sa:-0}" -v b="${sb:-0}" 'BEGIN{printf "  %8.2f Гбит/с  (пир A %.0f + пир B %.0f Мбит/с)\n", (a+b)/1000, a, b}'

echo
echo "скорость пир → пир через хаб:"
ip netns exec $NSB iperf3 -s -1 -D --logfile "$WORK/iperf2.log" -B 10.77.0.3 >/dev/null 2>&1
sleep 0.5
ip netns exec $NSA iperf3 -c 10.77.0.3 -t "$SECS" -f m 2>/dev/null \
    | awk '/receiver/ {printf "  %8.2f Гбит/с  (через хаб, два прохода AEAD)\n", $7/1000}'

# ---- облик на проводе --------------------------------------------------------
# Что видит DPI. Проверяется по СЫРЫМ БАЙТАМ, а не по тому, как их назвал tcpdump: у него
# нет причин считать этот поток TLS, и полагаться на его разбор значило бы проверять его
# эвристику, а не наш формат. Заголовки IP и TCP у нас без опций — ровно по 20 байт, — поэтому
# нагрузка начинается со 80-го шестнадцатеричного символа дампа.
echo
echo "облик на проводе (первые байты нагрузки каждого сегмента):"
# Трафик создаётся ПОКА идёт съём: на покое в дампе окажутся одни подтверждения, и проверять
# будет нечего. Первая версия так и вышла — один сегмент без нагрузки.
( sleep 0.5; ip netns exec $NSA ping -c 8 -i 0.1 -s 1200 -W 1 -q 10.77.0.1 >/dev/null 2>&1 ) &
ip netns exec $NSH timeout 4 tcpdump -i ha -n -c 14 -x "tcp port 443" 2>/dev/null \
  | awk '
    /^[0-9]/ { if (hex != "") print hex; hex = ""; next }
    /0x[0-9a-f]+:/ { line = $0; sub(/^.*: /, "", line); gsub(/ /, "", line); hex = hex line }
    END { if (hex != "") print hex }' \
  | awk '
    { pay = substr($0, 81, 6)
      if (length($0) <= 80) t = "нет нагрузки (SYN, ACK)"
      else if (pay == "170303") t = "17 03 03 — application_data, как у TLS 1.3"
      else if (pay == "160301") t = "16 03 01 — ClientHello"
      else if (pay == "160303") t = "16 03 03 — ServerHello"
      else if (pay == "140303") t = "14 03 03 — ChangeCipherSpec"
      else t = "ЧУЖОЕ: " pay
      cnt[t]++ }
    END { for (k in cnt) printf "  %3d сегм.: %s\n", cnt[k], k }'

echo
echo "состояние пира A (секретов в нём нет):"
sed 's/,/,\n   /g' "$WORK/state-a/xsteer-vpna.json" 2>/dev/null | head -12 || echo "  файла нет"

echo
if [ "$fail" -gt 0 ]; then echo "ЕСТЬ ПРОВАЛЫ: $fail"; exit 1; fi
echo "все проверки прошли"
