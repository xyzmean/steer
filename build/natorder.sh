#!/bin/sh
# ГДЕ считать скачанное по каналу: prerouting или postrouting.
#
# Вопрос стоял так. Встречный счётчик канала сверяет адрес источника ответного пакета с
# набором канала. У доменного канала в наборе лежат fake-IP, значит адрес обязан быть уже
# переведён обратно в fake-IP — иначе такой канал ВСЕГДА показывает нуль скачанного, причём
# объяснить это нечем: правило на месте, трафик идёт, набор непустой.
#
# Я считал, что достаточно взять в prerouting приоритет после dstnat. Опыт показал, что это
# неверно, и цена ошибки — молчаливый нуль у всех доменных каналов:
#
#   на месте метки (prerouting, mangle+1) : 0
#   после dstnat   (prerouting, dstnat+10): 0
#   postrouting    (srcnat+10), fake-адрес: 42 пакета, 1050973 байта
#   postrouting    (srcnat+10), настоящий : 42 пакета, 1050973 байта
#
# Причина: обратный перевод адреса источника — это манипуляция ИСТОЧНИКОМ, а она делается в
# postrouting. В prerouting в saddr стоит настоящий адрес сервера при любом приоритете.
# Последние две строки объясняют, почему цепочка в итоге ОДНА: адресному каналу postrouting
# годится ровно так же, переводить там нечего.
#
# Роутер — отдельное пространство, а не хозяин: у хозяина свои правила (docker, wg0), и
# ответы гибли в них, а не в проверяемой логике. Это уже стоило одного ложного вывода.
#
# Запуск: sh build/natorder.sh   (нужны root, veth, netns, nft, python3)
set -u
CL=10.77.0.2; RC=10.77.0.1
SV=10.88.0.2; RS=10.88.0.1
FAKE=198.18.0.1
PORT=8099

cleanup() {
    for n in fkR fkA fkB; do ip netns del $n 2>/dev/null; done
    ip link del vA 2>/dev/null; ip link del vB 2>/dev/null
}
trap cleanup EXIT
cleanup

for n in fkR fkA fkB; do ip netns add $n; done
ip link add vA type veth peer name vAR
ip link add vB type veth peer name vBR
ip link set vA netns fkA;  ip link set vAR netns fkR
ip link set vB netns fkB;  ip link set vBR netns fkR

ip netns exec fkA sh -c "ip link set lo up; ip addr add $CL/24 dev vA; ip link set vA up; ip route add default via $RC"
ip netns exec fkB sh -c "ip link set lo up; ip addr add $SV/24 dev vB; ip link set vB up; ip route add default via $RS"
ip netns exec fkR sh -c "ip link set lo up;
    ip addr add $RC/24 dev vAR; ip link set vAR up;
    ip addr add $RS/24 dev vBR; ip link set vBR up;
    sysctl -qw net.ipv4.ip_forward=1"

ip netns exec fkA ping -c1 -W2 $SV >/dev/null 2>&1 || { echo "пересылка не работает — проверять нечего"; exit 2; }
echo "пересылка работает"

# Тело на мегабайт и сервер в пространстве fkB. Каталог свой: в /tmp может лежать чужой
# файл с тем же именем, и «скачался мегабайт» значило бы не то, что мы проверяем.
BODY_DIR="${TMPDIR:-/tmp}/steer-natorder"
rm -rf "$BODY_DIR"; mkdir -p "$BODY_DIR"
dd if=/dev/urandom of="$BODY_DIR/body" bs=1024 count=1024 2>/dev/null
ip netns exec fkB sh -c "cd '$BODY_DIR' && exec python3 -m http.server $PORT --bind $SV" >/dev/null 2>&1 &
srv=$!

# Ждём готовности, а не спим фиксированно: со `sleep 2` опыт то проходил, то падал на
# «НЕ скачалось», и это выглядело как отказ проверяемой логики, а не как непоспевший сервер.
ready=0
i=0
while [ $i -lt 40 ]; do
    if ip netns exec fkB wget -q -T 1 -O /dev/null "http://$SV:$PORT/body" 2>/dev/null; then
        ready=1; break
    fi
    i=$((i + 1)); sleep 0.25
done
[ $ready = 1 ] || { echo "сервер в fkB не поднялся — проверять нечего"; exit 2; }
echo "сервер отвечает у себя в пространстве"

# Четыре места сразу, чтобы сравнивать, а не гадать: там же, где steer ставит метку
# (prerouting mangle+1), после dstnat (prerouting dstnat+10) и в postrouting — по
# fake-адресу и по настоящему. Последняя пара отвечает, нужна ли отдельная цепочка для
# адресных каналов.
ip netns exec fkR nft -f - <<EOF
table ip fk {
    chain dnat_in {
        type nat hook prerouting priority dstnat; policy accept;
        ip daddr $FAKE tcp dport $PORT dnat to $SV:$PORT
    }
    chain count_mark_time {
        type filter hook prerouting priority mangle + 1; policy accept;
        ip saddr $FAKE ip daddr $CL counter comment "as-mangle"
    }
    chain count_after_nat {
        type filter hook prerouting priority dstnat + 10; policy accept;
        ip saddr $FAKE ip daddr $CL counter comment "after-dstnat"
    }
    chain count_post {
        type filter hook postrouting priority srcnat + 10; policy accept;
        ip saddr $FAKE ip daddr $CL counter comment "post-fake"
        ip saddr $SV ip daddr $CL counter comment "post-real"
    }
}
EOF

bytes_of() {   # ЦЕПОЧКА КОММЕНТАРИЙ
    ip netns exec fkR nft list chain ip fk "$1" |
        sed -n "s/.*bytes \([0-9]*\).*comment \"$2\".*/\1/p"
}

echo "-- качаем мегабайт через fake-IP $FAKE (доменный канал)"
ip netns exec fkA wget -q -T 20 -O /dev/null "http://$FAKE:$PORT/body" ||
    { echo "НЕ скачалось — вывод делать не на чем"; kill $srv 2>/dev/null; exit 2; }
echo "-- и мегабайт напрямую по $SV (адресный канал)"
ip netns exec fkA wget -q -T 20 -O /dev/null "http://$SV:$PORT/body" ||
    { echo "НЕ скачалось — вывод делать не на чем"; kill $srv 2>/dev/null; exit 2; }
kill $srv 2>/dev/null

m=$(bytes_of count_mark_time as-mangle)
d=$(bytes_of count_after_nat after-dstnat)
pf=$(bytes_of count_post post-fake)
pr=$(bytes_of count_post post-real)
echo "prerouting, на месте метки (mangle+1) : ${m:-?} Б"
echo "prerouting, после dstnat   (+10)      : ${d:-?} Б"
echo "postrouting (srcnat+10), fake-адрес   : ${pf:-?} Б"
echo "postrouting (srcnat+10), настоящий    : ${pr:-?} Б"

if [ "${pf:-0}" -gt 1000000 ] && [ "${m:-0}" -lt 10000 ] && [ "${d:-0}" -lt 10000 ]; then
    echo "ВЫВОД: fake-адрес в saddr виден ТОЛЬКО в postrouting — считать надо там."
    [ "${pr:-0}" -gt 1000000 ] &&
        echo "       Адресный канал считается там же, значит цепочка нужна одна."
elif [ "${d:-0}" -gt 1000000 ]; then
    echo "ВЫВОД: fake-адрес виден уже после dstnat — годится и prerouting"
else
    echo "ВЫВОД: опыт не удался (метка=$m dstnat=$d post=$pf)"
fi
