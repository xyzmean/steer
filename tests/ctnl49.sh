#!/bin/sh
# Снятие соединений выхода самим движком (ctnetlink) — на НАСТОЯЩЕМ ядре: при смене маршрута
# выхода снимаются записи conntrack с его меткой, и только они, в обоих семействах.
#
# Зачем стенд. На телефоне инструмента conntrack нет, и снимает записи сам движок: дамп
# ctnetlink и удаление каждой совпавшей записи по её кортежу (ctnl_evict_mark в src/dnsd/dnsd.c).
# Ошибка здесь дорогая в обе стороны — не снять значит оставить соединения приложений на
# мёртвом выходе, снять лишнее значит оборвать чужие соединения всего телефона, — а увидеть
# её можно только на ядре: у стенда make test ядра нет, и снятие там подменено моком
# (tests/failovermatch.c). Ядро 4.9 — ядро телефона; на свежем ядре сценарий тоже годится.
#
# Запускается на стенде tools/vm49 хаба splicicd:
#
#   K=/root/vm49/sysroot/kinc
#   musl-gcc -static -idirafter $K -O2 -DSTEER_ANDROID -o OUT/steer <исходники как в Makefile>
#   musl-gcc -static -idirafter $K -O2 -o OUT/ctnl49-tool tests/ctnl49-tool.c
#   tools/vm49/vm49.sh run steer/tests/ctnl49.sh OUT/steer OUT/ctnl49-tool
#
# На машине разработки (свежее ядро, современная раскладка) — в своём сетевом пространстве:
# сборка с -DSTEER_TMP_DIR/-DSTEER_STATE_DIR/-DSTEER_ETC_DIR в свой каталог (чтобы не писать
# в общие /tmp и /data), оба бинарника в PATH, WORK и CT_TMP — свои каталоги:
#
#   WORK=DIR CT_TMP=DIR PATH=OUT:$PATH unshare -n sh tests/ctnl49.sh
#
# Что проверяется.
#   1. Запасной путь (только на стенде 4.9, где модуль nf_conntrack_netlink не загружен):
#      подсистема conntrack в nfnetlink не отвечает — движок зовёт внешний conntrack с меткой
#      выхода и маской движка. Инструмент изображает запись вызова в файл.
#   2. Нативный путь: десять записей UDP — по пять в IPv4 и IPv6 — с метками: ровно метка
#      выхода; метка выхода плюс чужие биты вне поля движка (так метит netd на телефоне);
#      метка ДРУГОГО выхода (соседнее значение поля); только чужие биты; без метки. После
#      отказа выхода сторожем обязаны исчезнуть первые две в каждом семействе и только они,
#      а внешний conntrack — не зваться вовсе.
#   3. Список соединений движка (`steer conns`, команда conns управляющего сокета) по тем же
#      записям, до отказа выхода: в ответе записи с полем метки движка (метка выхода — с
#      именем выхода, другое значение поля — с "out":null), без записей только с чужими
#      битами и без метки; в сборке под Android — без собственного трафика движка (значение
#      «все биты поля», STEER_SELF_MARK). Счётчики — только у записей, заведённых при
#      включённом nf_conntrack_acct. Формат дампа у 4.9 свой (вложенные атрибуты без флага
#      NLA_F_NESTED, счётчики с выравниванием на 4 байта) — ради этого пункт и идёт на 4.9.
# Отказ выхода — настоящий: устройство выхода удаляется, и `steer failover` уводит выход в
# on_fail=direct, где и снимаются его соединения (apply_failed в src/daemon/failover.c).
set -u
pass=0 fail=0
check() {
    if [ "$2" = "$3" ]; then pass=$((pass + 1)); echo "ok   $1"; else
        fail=$((fail + 1)); printf 'FAIL %s\n  expected: %s\n  actual:   %s\n' "$1" "$2" "$3"
    fi
}
uname -r
W=${WORK:-/work}
T=${CT_TMP:-/tmp}
[ -n "${VM49:-}" ] && mkdir -p /data/misc/steer/state /data/misc/steer/tmp
mkdir -p "$T/st" "$T/fakebin"
ip link set lo up

# Изображение внешнего инструмента: записывает, с чем его позвали, и отвечает успехом (на
# --version тоже — иначе движок решил бы, что инструмента нет, и только предупредил бы).
cat > "$T/fakebin/conntrack" <<EOF
#!/bin/sh
echo "\$*" >> $T/conntrack.calls
exit 0
EOF
chmod 755 "$T/fakebin/conntrack"
PATH=$T/fakebin:$PATH
rm -f "$T/conntrack.calls"

printf '203.0.113.0/24\n' > "$W/p.lst"
cat > "$W/ct.json" <<J
{ "schema": 2, "lan_devices": ["br-lan"],
  "outputs": { "vpn": { "kind": "interface", "device": "wg9", "on_fail": "direct" } },
  "channels": [ { "name": "lan", "match": { "prefixes_files": ["$W/p.lst"] }, "out": "vpn" } ] }
J
S="--spec $W/ct.json --state-dir $T/st"

up_wg9() { ip link add wg9 type dummy 2>/dev/null; ip link set wg9 up; }
# Метка и маска выхода — из его правила маршрутизации: так сценарий не повторяет у себя
# раскладку поля метки (у Android и роутера она разная).
rule_mark() { ip rule show | sed -n 's/.*fwmark \(0x[0-9a-f]*\)\/\(0x[0-9a-f]*\).*/\1 \2/p' | head -1; }

up_wg9
check "apply" "0" "$(steer apply $S >"$T/apply.log" 2>&1; echo $?)"
set -- $(rule_mark)
M=${1:-0} MASK=${2:-0}
echo "метка выхода $M, маска $MASK"
check "правило выхода стоит" "1" "$([ "$M" != 0 ] && echo 1)"

# --- 1. запасной путь: ctnetlink не отвечает -----------------------------------------------
if [ -n "${VM49:-}" ] && ! grep -q '^nf_conntrack_netlink ' /proc/modules; then
    # Автозагрузка модуля по запросу nfnetlink выключена — так выглядит роутер без
    # kmod-nf-conntrack-netlink: сокет открывается, подсистема conntrack в нём не отвечает.
    echo /bin/false > /proc/sys/kernel/modprobe
    ip link del wg9
    steer failover $S >"$T/fo1.log" 2>&1
    check "без ctnetlink — внешний conntrack с меткой выхода" \
        "-D --mark $((M))/$((MASK))" "$(grep -- '-D' "$T/conntrack.calls" 2>/dev/null | head -1)"
    check "без ctnetlink модуль так и не загружен" "0" \
        "$(grep -c '^nf_conntrack_netlink ' /proc/modules)"
    echo /sbin/modprobe > /proc/sys/kernel/modprobe
    modprobe nf_conntrack_netlink
    rm -f "$T/conntrack.calls"
    up_wg9
    check "повторный apply" "0" "$(steer apply $S >"$T/apply2.log" 2>&1; echo $?)"
    check "правило выхода снова стоит" "$M $MASK" "$(rule_mark)"
fi

# --- 2. нативный путь ------------------------------------------------------------------------
# Записи UDP без ответа живут 30 секунд; сценарию хватило бы и этого, но запас не мешает.
echo 600 > /proc/sys/net/netfilter/nf_conntrack_udp_timeout 2>/dev/null
LOW=$((MASK & -MASK))                  # младший бит поля движка
M2=$(( (M + LOW) & MASK ))             # соседнее значение поля — метка другого выхода
[ "$M2" = "$((M))" ] && M2=$(( (M - LOW) & MASK ))
X=$(( 0x1234 & ~MASK ))                # чужие биты вне поля (netd на телефоне)
hex() { printf '0x%08x' "$1"; }
nft -f - <<N
table inet ctt {
    chain o {
        type filter hook output priority 0;
        udp dport { 41001, 42001, 41006 } ct mark set $(hex $M)
        udp dport { 41002, 42002 } ct mark set $(hex $((M | X)))
        udp dport { 41003, 42003 } ct mark set $(hex $M2)
        udp dport { 41004, 42004 } ct mark set $(hex $X)
        udp dport 41007 ct mark set $(hex $MASK)
    }
}
N
# 41006 заводится при выключенных счётчиках — у такой записи их нет и потом; остальные при
# включённых (пункт 3).
echo 0 > /proc/sys/net/netfilter/nf_conntrack_acct
ctnl49-tool udp 127.0.0.1 41006
echo 1 > /proc/sys/net/netfilter/nf_conntrack_acct
ctnl49-tool udp 127.0.0.1 41007
for p in 1 2 3 4 5; do
    ctnl49-tool udp 127.0.0.1 4100$p
    ctnl49-tool udp ::1 4200$p
done
# mark_of СЕМЕЙСТВО ПОРТ — метка записи или «нет».
mark_of() { ctnl49-tool list | sed -n "s/^$1 $2 //p" | head -1 | grep . || echo нет; }
ctnl49-tool list | grep ' 4[12]00[1-5] '
check "до: v4 метка выхода"        "$(hex $M)"          "$(mark_of v4 41001)"
check "до: v4 метка выхода + netd" "$(hex $((M | X)))" "$(mark_of v4 41002)"
check "до: v4 другой выход"        "$(hex $M2)"         "$(mark_of v4 41003)"
check "до: v4 только netd"         "$(hex $X)"          "$(mark_of v4 41004)"
check "до: v4 без метки"           "0x00000000"         "$(mark_of v4 41005)"
check "до: v6 метка выхода"        "$(hex $M)"          "$(mark_of v6 42001)"
check "до: v6 метка выхода + netd" "$(hex $((M | X)))" "$(mark_of v6 42002)"
check "до: v6 другой выход"        "$(hex $M2)"         "$(mark_of v6 42003)"
check "до: v6 только netd"         "$(hex $X)"          "$(mark_of v6 42004)"
check "до: v6 без метки"           "0x00000000"         "$(mark_of v6 42005)"

# --- 3. список соединений движка -------------------------------------------------------------
# conn_of СЕМЕЙСТВО ПОРТ — «выход счётчики» записи из ответа `steer conns` или «нет». Объекты
# в ответе плоские, поэтому разбор — по «}», без разборщика JSON (его в ВМ нет).
steer conns $S > "$T/conns.json" 2>"$T/conns.err"
check "conns: код 0" "0" "$?"
conn_of() {
    tr '}' '\n' < "$T/conns.json" | grep "\"family\":\"$1\"" | grep "\"dport\":$2," | head -1 |
        sed -n 's/.*"out":\([^,]*\).*/\1/p; ' | tr -d '"' | grep . || { echo нет; return; }
}
cnt_of() {
    tr '}' '\n' < "$T/conns.json" | grep "\"family\":\"$1\"" | grep "\"dport\":$2," | head -1 |
        grep -q '"packets":1,"bytes":[0-9]*,"reply_packets":0' && echo есть || echo нет
}
check "conns: v4 метка выхода — выход vpn"         "vpn"  "$(conn_of ipv4 41001)"
check "conns: v4 метка выхода + netd — выход vpn"  "vpn"  "$(conn_of ipv4 41002)"
check "conns: v4 другое значение поля — out null"  "null" "$(conn_of ipv4 41003)"
check "conns: v4 только чужие биты — нет"          "нет"  "$(conn_of ipv4 41004)"
check "conns: v4 без метки — нет"                  "нет"  "$(conn_of ipv4 41005)"
check "conns: v6 метка выхода — выход vpn"         "vpn"  "$(conn_of ipv6 42001)"
check "conns: v6 другое значение поля — out null"  "null" "$(conn_of ipv6 42003)"
check "conns: v6 без метки — нет"                  "нет"  "$(conn_of ipv6 42005)"
check "conns: счётчики у записи при включённом acct" "есть" "$(cnt_of ipv4 41001)"
check "conns: без acct — поля счётчиков нет"       "нет"  "$(cnt_of ipv4 41006)"
check "conns: запись без счётчиков всё же в ответе" "vpn" "$(conn_of ipv4 41006)"
if [ -n "${VM49:-}" ]; then
    check "conns: собственный трафик движка (все биты поля) — нет" "нет" "$(conn_of ipv4 41007)"
fi
check "conns: адреса исходного направления" "1" \
    "$(tr '}' '\n' < "$T/conns.json" | grep -c '"src":"127.0.0.1","sport":[0-9]*,"dst":"127.0.0.1","dport":41001,')"
check "conns: без обрезки" "1" "$(grep -c '"truncated":false' "$T/conns.json")"

ip link del wg9
steer failover $S >"$T/fo2.log" 2>&1
cat "$T/fo2.log"
check "отказ выхода — правило снято" "" "$(rule_mark)"
check "v4 метка выхода — снята"        "нет"                "$(mark_of v4 41001)"
check "v4 метка выхода + netd — снята" "нет"                "$(mark_of v4 41002)"
check "v4 другой выход — на месте"     "$(hex $M2)"         "$(mark_of v4 41003)"
check "v4 только netd — на месте"      "$(hex $X)"          "$(mark_of v4 41004)"
check "v4 без метки — на месте"        "0x00000000"         "$(mark_of v4 41005)"
check "v6 метка выхода — снята"        "нет"                "$(mark_of v6 42001)"
check "v6 метка выхода + netd — снята" "нет"                "$(mark_of v6 42002)"
check "v6 другой выход — на месте"     "$(hex $M2)"         "$(mark_of v6 42003)"
check "v6 только netd — на месте"      "$(hex $X)"          "$(mark_of v6 42004)"
check "v6 без метки — на месте"        "0x00000000"         "$(mark_of v6 42005)"
check "внешний conntrack не звался" "" "$(cat "$T/conntrack.calls" 2>/dev/null)"
check "без предупреждения «нечем»" "0" "$(grep -c 'нечем' "$T/fo2.log")"

nft delete table inet ctt
echo "ctnl49: $pass passed, $fail failed"
[ "$fail" = 0 ]
