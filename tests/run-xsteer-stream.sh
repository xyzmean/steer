#!/bin/sh
# Режим потока: НАШ клиент против хаба РЕАЛИЗАЦИИ НА GO.
#
# ЗАЧЕМ ЭТОТ СТЕНД. Обещание режима потока двойное, и ни одну половину нельзя проверить в
# памяти. Первая: записи едут по обычному соединению TCP, без сырого сокета и без правила
# против RST, — то есть туннель поднимается там, где поддельный TCP невозможен. Вторая, и
# более тонкая: ключи меняются ЭПОХАМИ каждые 64 МиБ, номер эпохи на проводе не передаётся, и
# обе стороны обязаны прийти к одним ключам, ничего друг другу не сказав. Расхождение в выводе
# ключей не видно ни на рукопожатии, ни в первую минуту: туннель исправно несёт трафик и
# умирает ровно на 64-м мегабайте. Поэтому здесь через него ГОНЯТСЯ гигабайты и проверяется,
# что пир НЕ ПЕРЕПОДКЛЮЧАЛСЯ.
#
# Именно так и была найдена настоящая ошибка переноса (перепутанные соль и ikm во втором
# HKDF-Extract): всё работало, и каждые 64 МиБ соединение поднималось заново.
#
# Хаб здесь ЧУЖОЙ нарочно — бинарник из репозитория xsteer. Стенд с нашим хабом на обеих
# сторонах доказывал бы только внутреннюю согласованность; обещание же в том, что роутер
# разговаривает с тем хабом, который стоит на VPS, а он бывает и на Go. Обратную сторону той
# же проверки (клиент на Go против нашего хаба) делает xsteer/tests/interop.sh.
#
# Требует root (пространства имён), /dev/net/tun, iperf3 и оба бинарника. В make test не
# входит — как run-xsteer.sh, run-tunnel.sh и run-reality.sh.
#
#     sudo sh tests/run-xsteer-stream.sh [секунд_на_замер]
set -eu
umask 077

SECS="${1:-12}"
EXT=${STEER_EXT_BIN:-./build/steer-ext}
GO_XS=${XSTEER_BIN:-../xsteer/build/xsteer}
PORT=${XS_STREAM_PORT:-443}
NSH=xss-hub
NSA=xss-a
WORK=

fail=0
ok()   { printf '%-58s ok\n' "$1"; }
bad()  { printf '%-58s ПРОВАЛ\n' "$1"; fail=$((fail + 1)); }
check() { if [ "$2" = "$3" ]; then ok "$1"; else bad "$1"; printf '     хочу: %s\n     есть: %s\n' "$2" "$3"; fi; }

cleanup() {
    for ns in $NSH $NSA; do
        ip netns pids $ns 2>/dev/null | xargs -r kill 2>/dev/null || true
        ip netns del $ns 2>/dev/null || true
    done
    # XSS_KEEP=1 оставляет журналы: без них разбираться в упавшем прогоне можно только по
    # тому, что успело напечататься в терминал.
    if [ -n "$WORK" ] && [ -z "${XSS_KEEP:-}" ]; then rm -rf "$WORK"
    elif [ -n "$WORK" ]; then echo "журналы оставлены в $WORK"; fi
    return 0
}
# PIPE в списке потому, что вывод стенда часто читают через `| head`: без него оболочка гибнет
# от SIGPIPE, уборка не выполняется, и в системе остаются процессы в пространствах имён,
# которые портят ЛЮБОЙ следующий прогон.
trap cleanup EXIT INT TERM PIPE HUP
cleanup

[ "$(id -u)" = 0 ] || { echo "нужен root: стенд делает пространства имён"; exit 2; }
[ -c /dev/net/tun ] || { echo "нет /dev/net/tun — туннель не поднять"; exit 2; }
[ -x "$EXT" ] || { echo "нет $EXT (соберите расширенную сборку)"; exit 2; }
[ -x "$GO_XS" ] || { echo "нет хаба на Go: $GO_XS — соберите его в ../xsteer (go build -o build/xsteer ./cmd/xsteer) или укажите XSTEER_BIN"; exit 2; }
command -v iperf3 >/dev/null || { echo "нет iperf3: без него не прогнать 64 МиБ, то есть не проверить эпохи"; exit 2; }

WORK="$(mktemp -d)"; chmod 700 "$WORK"
mkdir -p "$WORK/state-a"

# ---- сеть: хаб и пир, veth между ними ----------------------------------------
for ns in $NSH $NSA; do ip netns add $ns; ip -n $ns link set lo up; done
# Пересылку выключаем ЯВНО: значение наследуется от хозяйской системы, и на машине с
# включённой пересылкой стенд проверял бы не то, что обещает.
for ns in $NSH $NSA; do ip netns exec $ns sysctl -qw net.ipv4.ip_forward=0; done
ip link add ha netns $NSH type veth peer name ah netns $NSA
ip -n $NSH addr add 10.212.1.1/24 dev ha
ip -n $NSA addr add 10.212.1.2/24 dev ah
ip -n $NSH link set ha up
ip -n $NSA link set ah up

# ---- ключи и конфигурации ----------------------------------------------------
# Ключи делает НАШ бинарник, а читает их обе стороны: формат конфигурации общий, и это тоже
# часть обещания (файл, принятый одной реализацией, обязан приниматься другой).
"$EXT" xsteer-key > "$WORK/hub.keys"
"$EXT" xsteer-key > "$WORK/a.keys"
kpriv() { awk '/PrivateKey/ {print $3}' "$1"; }
kpub()  { awk '/PublicKey/  {print $3}' "$1"; }

cat > "$WORK/hub.conf" <<EOF
[Interface]
PrivateKey = $(kpriv "$WORK/hub.keys")
Address    = 10.79.0.1/24
ListenPort = $PORT

[Peer]
PublicKey  = $(kpub "$WORK/a.keys")
AllowedIPs = 10.79.0.2/32
EOF

cat > "$WORK/a.conf" <<EOF
[Interface]
PrivateKey = $(kpriv "$WORK/a.keys")
Address    = 10.79.0.2/24
SNI        = www.example.com

[Peer]
PublicKey  = $(kpub "$WORK/hub.keys")
AllowedIPs = 10.79.0.0/24
Endpoint   = 10.212.1.1:$PORT
PersistentKeepalive = 15
EOF
chmod 600 "$WORK"/*.conf

# Режим потока задан В СПЕКЕ, а не ключом: так проверяется и разбор поля, и путь, которым
# туннель поднимает procd на роутере. Ключ --stream проверяется отдельно, ниже.
cat > "$WORK/a.json" <<EOF
{"schema":1,"lan_device":"lo","from_default":["10.79.0.0/24"],
 "outputs":{"vpna":{"kind":"xsteer","conf":"$WORK/a.conf","stream":true}},
 "channels":[]}
EOF

# ---- запуск ------------------------------------------------------------------
# --stream-only: хаб не поднимает поддельный TCP вовсе. Так проверяется именно то, ради чего
# режим существует — что до хаба, у которого сырого сокета нет в принципе, мы доходим.
ip netns exec $NSH "$GO_XS" hub "$WORK/hub.conf" --stream-only --stream-port "$PORT" \
    > "$WORK/hub.log" 2>&1 &
sleep 1
ip netns exec $NSA "$EXT" xsteer vpna --spec "$WORK/a.json" \
    --state-dir "$WORK/state-a" > "$WORK/a.log" 2>&1 &

up_count() { grep -c 'поднялся потоком' "$WORK/hub.log" 2>/dev/null | head -1; }
for i in $(seq 1 60); do
    [ "$(up_count)" -ge 1 ] && break
    sleep 0.25
done
first_up=$(up_count)
if [ "$first_up" -lt 1 ]; then
    bad "рукопожатие потоком прошло"
    echo "--- журнал хаба ---";  cat "$WORK/hub.log"
    echo "--- журнал пира ---"; cat "$WORK/a.log"
    exit 1
fi
ok "рукопожатие потоком прошло"

# Правила против RST в режиме потока быть НЕ ДОЛЖНО: соединением владеет ядро, и просить прав
# на firewall незачем. Это не косметика — ровно этим режим и ценен там, где прав нет.
if ip netns exec $NSA nft list ruleset 2>/dev/null | grep -q 'steer'; then
    bad "правило nft не ставится (в потоке оно не нужно)"
else
    ok "правило nft не ставится (в потоке оно не нужно)"
fi

# ---- связь -------------------------------------------------------------------
if ip netns exec $NSA ping -c 3 -W 2 -q 10.79.0.1 >/dev/null 2>&1; then
    ok "пир → хаб: ping через туннель проходит"
else
    bad "пир → хаб: ping через туннель проходит"
    echo "--- журнал хаба ---"; tail -5 "$WORK/hub.log"
    echo "--- журнал пира ---"; tail -5 "$WORK/a.log"
fi

# MTU: в потоке согласование одноступенчатое — минимум пределов сторон, без проб пути
# (сегментацией распоряжается ядро). Число не зашито: его называют сами стороны.
tmtu=$(ip netns exec $NSA cat /sys/class/net/vpna/mtu)
hub_mtu=$(sed -n 's/.*MTU \([0-9]*\).*/\1/p' "$WORK/hub.log" | head -1)
check "MTU устройства равен согласованному" "$hub_mtu" "$tmtu"

# ---- облик на проводе --------------------------------------------------------
# Проверяется по СЫРЫМ БАЙТАМ, а не по тому, как их назвал tcpdump: у него нет причин считать
# этот поток TLS. Смещение нагрузки считается из заголовков — в отличие от поддельного TCP,
# здесь заголовок TCP настоящий и опции в нём есть (метки времени), поэтому постоянное
# смещение 40 байт дало бы «ЧУЖОЕ» на исправном потоке.
echo
echo "облик на проводе (первые байты нагрузки каждого сегмента):"
( sleep 0.5; ip netns exec $NSA ping -c 8 -i 0.1 -s 1200 -W 1 -q 10.79.0.1 >/dev/null 2>&1 ) &
shape=$(ip netns exec $NSH timeout 4 tcpdump -i ha -n -c 14 -x "tcp port $PORT" 2>/dev/null \
  | awk '
    /^[0-9]/ { if (hex != "") print hex; hex = ""; next }
    /0x[0-9a-f]+:/ { line = $0; sub(/^.*: /, "", line); gsub(/ /, "", line); hex = hex line }
    END { if (hex != "") print hex }' \
  | awk '
    function hx(c) { return index("0123456789abcdef", c) - 1 }
    { ihl = hx(substr($0, 2, 1)) * 4
      doff = hx(substr($0, ihl * 2 + 25, 1)) * 4
      poff = (ihl + doff) * 2 + 1
      if (length($0) < poff + 5) t = "нет нагрузки (SYN, ACK)"
      else { pay = substr($0, poff, 6)
             if (pay == "170303") t = "17 03 03 — application_data, как у TLS 1.3"
             else if (pay == "160301") t = "16 03 01 — ClientHello"
             else if (pay == "160303") t = "16 03 03 — ServerHello"
             else if (pay == "140303") t = "14 03 03 — ChangeCipherSpec"
             else t = "ЧУЖОЕ: " pay }
      cnt[t]++ }
    END { for (k in cnt) printf "  %3d сегм.: %s\n", cnt[k], k }')
echo "$shape"
if echo "$shape" | grep -q 'ЧУЖОЕ'; then
    bad "на проводе только записи TLS"
else
    ok "на проводе только записи TLS"
fi

# ---- ГЛАВНОЕ: гигабайты через границы эпох ------------------------------------
echo
echo "прогон через границы эпох (по 64 МиБ на эпоху):"
before_up=$(up_count)
ip netns exec $NSH iperf3 -s -B 10.79.0.1 -1 > "$WORK/iperf-s.log" 2>&1 &
sleep 0.5
rate=$(ip netns exec $NSA iperf3 -c 10.79.0.1 -t "$SECS" -f m 2>/dev/null \
       | awk '/sender/ {print $7" "$8}' | tail -1)
echo "      ${rate:-нет числа}  (пир → хаб, режим потока)"

# Обратное направление отдельным прогоном, а не -d: приём под насыщением — это другой путь в
# коде (разбор записей из буфера), и там своя граница на число записей за круг, без которой
# чтение TUN голодает. Проверять только отдачу значило бы проверять половину.
ip netns exec $NSH iperf3 -s -B 10.79.0.1 -1 > "$WORK/iperf-s2.log" 2>&1 &
sleep 0.5
rrate=$(ip netns exec $NSA iperf3 -c 10.79.0.1 -t "$SECS" -R -f m 2>/dev/null \
        | awk '/receiver/ {print $7" "$8}' | tail -1)
echo "      ${rrate:-нет числа}  (хаб → пир, режим потока)"
if [ -n "$rrate" ]; then ok "обратное направление тоже несёт трафик"
else bad "обратное направление тоже несёт трафик"; fi

sent=$(sed 's/.*"tx_bytes":\([0-9]*\).*/\1/' "$WORK/state-a/xsteer-vpna.json" 2>/dev/null || echo 0)
mib=$((sent / 1048576))
echo "      прогнано ${mib} МиБ, то есть эпох сменилось около $((mib / 64))"
if [ "$mib" -ge 128 ]; then
    ok "прогнано больше двух эпох (иначе проверять нечего)"
else
    bad "прогнано больше двух эпох (иначе проверять нечего)"
fi

# Если ратчет разошёлся, хаб не расшифрует первую же запись новой эпохи и закроет соединение,
# а пир поднимется заново. Число рукопожатий поэтому и есть проверка: ОНО НЕ РАСТЁТ.
after_up=$(up_count)
check "после гигабайтов ни одного нового рукопожатия" "$before_up" "$after_up"
if [ "$before_up" != "$after_up" ]; then
    echo "     похоже, эпохи разошлись: сверьте вывод ключей стендом tests/xsepochmatch.c"
    echo "--- журнал пира ---"; grep -i 'warn' "$WORK/a.log" | tail -5
fi

if grep -q 'не расшифровалась' "$WORK/a.log"; then
    bad "ни одна запись не осталась нерасшифрованной"
    grep 'не расшифровалась' "$WORK/a.log" | tail -3
else
    ok "ни одна запись не осталась нерасшифрованной"
fi

if ip netns exec $NSA ping -c 3 -W 2 -q 10.79.0.1 >/dev/null 2>&1; then
    ok "туннель жив ПОСЛЕ смены ключей"
else
    bad "туннель жив ПОСЛЕ смены ключей"
fi

# ---- ключ --stream без спеки --------------------------------------------------
# Тот же режим, но заданный руками и на готовом устройстве (режим netifd): им пользуется
# человек, когда проверяет канал, и путь этот отдельный — спека не читается вовсе.
echo
ip netns pids $NSA 2>/dev/null | xargs -r kill 2>/dev/null || true
sleep 0.5
ip netns exec $NSA ip tuntap add dev xsm mode tun 2>/dev/null || true
ip netns exec $NSA ip addr replace 10.79.0.2/24 dev xsm
ip netns exec $NSA ip link set dev xsm mtu 1439 up
ip netns exec $NSA "$EXT" xsteer --config "$WORK/a.conf" --device xsm --stream \
    --stream-port "$PORT" > "$WORK/a2.log" 2>&1 &
for i in $(seq 1 40); do
    grep -q 'рукопожатие' "$WORK/a2.log" 2>/dev/null && break
    sleep 0.25
done
if ip netns exec $NSA ping -c 3 -W 2 -q -I xsm 10.79.0.1 >/dev/null 2>&1; then
    ok "ключ --stream на готовом устройстве: туннель работает"
else
    bad "ключ --stream на готовом устройстве: туннель работает"
    tail -5 "$WORK/a2.log"
fi

echo
if [ "$fail" -gt 0 ]; then echo "ЕСТЬ ПРОВАЛЫ: $fail"; exit 1; fi
echo "все проверки прошли"
