#!/bin/sh
# Golden tests for the compiler: spec in, ruleset text out. No router, no nft, no
# network — the whole reason the engine is a compiler rather than a daemon.
set -u
BIN="${STEER:-./build/steer}"
[ -x "$BIN" ] || { echo "not built: $BIN (make)"; exit 2; }

pass=0 fail=0
tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT
S="--state-dir $tmp/state"

check() {
    if [ "$2" = "$3" ]; then pass=$((pass + 1)); else
        fail=$((fail + 1))
        printf 'FAIL %s\n  expected: %s\n  actual:   %s\n' "$1" "$2" "$3"
    fi
}

printf '203.0.113.0/24\n198.51.100.5\n' > "$tmp/a.lst"
printf '198.51.100.5\n' > "$tmp/b.lst"

spec() { sed "s|TMP|$tmp|g" > "$tmp/spec.json"; }

spec <<'EOF'
{ "schema": 1,
  "from_default": ["192.168.1.0/24"],
  "outputs": {
    "direct": { "kind": "direct" },
    "vpn":    { "kind": "interface", "device": "wg0" }
  },
  "channels": [
    { "name": "keep",    "match": { "prefixes_file": "TMP/b.lst" }, "out": "direct" },
    { "name": "blocked", "match": { "prefixes_file": "TMP/a.lst" }, "out": "vpn" }
  ] }
EOF

out="$("$BIN" apply --dry-run --spec "$tmp/spec.json" $S)"

# Метка ставится ЧТЕНИЕМ-МОДИФИКАЦИЕЙ, а не перезаписью слова. Проверяется отдельно от
# золотого текста, потому что расхождение в нём говорит «что-то изменилось», а нужно
# «сохраняются ли чужие биты»: слово метки общее с mwan3 (маска 0x3F00), pbr и sqm, и
# перезапись выключала их политику молча, а чужая перезапись — нашу (I-135).
check "метка ставится без затирания чужих бит" "1" \
    "$(printf '%s\n' "$out" | grep -c 'meta mark set mark and 0xf00fffff or 0x40100000')"
# В метке ДВА бита, и второй (0x40000000) чужой: им системный обход zapret узнаёт «этот
# трафик не мой». Стоит он у всякого выхода, кроме direct — см. отдельный раздел ниже.
# Маска при этом та же: 0xf00fffff это ~0x0ff00000, наши восемь бит и ничего больше.
check "и вместе с ней стоит бит «не для общего обхода»" "1" \
    "$(printf '%s\n' "$out" | grep -c 'or 0x40100000')"
# Метка СОЕДИНЕНИЯ рядом с меткой пакета. Без неё запись conntrack не связана с выходом
# вообще (в дампе mark=0), и сделать с уже установленным соединением нельзя ничего: ни
# понять, каким выходом оно идёт, ни снять его при смене маршрута. Замер на роутере показал,
# зачем это нужно: при включённой выгрузке потоков (flow_offloading) наша цепочка видит
# 2-7 пакетов соединения вместо одиннадцати тысяч, то есть решение о маршруте для
# установленного соединения больше не пересматривается, и запрет on_fail=drop до него не
# доходит (R-096).
check "метка соединения ставится рядом с меткой пакета" "1" \
    "$(printf '%s\n' "$out" | grep -c 'ct mark set mark')"
check "перезаписи слова метки не осталось" "0" \
    "$(printf '%s\n' "$out" | grep -cE 'meta mark set 0x')"

# The whole ruleset, once: a diff here is a behaviour change, which is exactly what
# a golden test is for.
want="$(cat <<'EOF'
table inet steer {
    set direct_ip {
        type ipv4_addr
        flags interval
        auto-merge
        elements = { 198.51.100.5 }
    }
    set vpn_ip {
        type ipv4_addr
        flags interval
        auto-merge
        elements = { 203.0.113.0/24, 198.51.100.5 }
    }
    chain prerouting_mark {
        type filter hook prerouting priority mangle + 1; policy accept;
        ip saddr { 192.168.1.0/24 } ip daddr @direct_ip counter return comment "steer:direct_ip"
        ip saddr { 192.168.1.0/24 } ip daddr @vpn_ip meta mark set mark and 0xf00fffff or 0x40100000 ct mark set mark counter return comment "steer:vpn_ip"
    }

    chain postrouting_down {
        type filter hook postrouting priority srcnat + 10; policy accept;
        ip daddr { 192.168.1.0/24 } ip saddr @direct_ip counter comment "steer-down:direct_ip"
        ip daddr { 192.168.1.0/24 } ip saddr @vpn_ip counter comment "steer-down:vpn_ip"
    }
    chain prerouting_dns {
        type nat hook prerouting priority dstnat; policy accept;
        ip saddr 192.168.1.0/24 udp dport 53 counter redirect to :5300
        meta nfproto ipv6 iifname "br-lan" udp dport 53 counter redirect to :5300
    }
}
EOF
)"
check "generates the expected ruleset" "$want" "$out"

# Встречная цепочка обязана считать в POSTROUTING, и это не косметика приоритетов.
#
# У доменного канала в наборе лежат fake-IP, а у ответного пакета адрес источника переводится
# обратно в fake-IP манипуляцией ИСТОЧНИКА — то есть в postrouting. В prerouting там стоит
# настоящий адрес сервера при любом приоритете, набор не совпадает, и доменные каналы вечно
# показывали бы нуль скачанного при работающем правиле и идущем трафике. Проверено опытом:
# build/natorder.sh, мегабайт через fake-IP дал в prerouting нуль, в postrouting 1 050 921
# байт. Перенести цепочку обратно стоит одного слова, а замечается это только по нулям в
# интерфейсе, которые легко списать на «ещё не качали».
check "встречная цепочка считает в postrouting" "1" \
    "$(printf '%s\n' "$out" | grep -c 'hook postrouting priority srcnat + 10')"
# Цепочек в prerouting теперь две, и это не ослабление проверки, а её уточнение.
#
# Первая — метка, она в filter и проходит КАЖДЫЙ пакет; ради этого проверка и стоит.
# Вторая — перенаправление DNS, и с запуска 65 она стоит всегда, а не по факту доменных
# каналов (решение владельца: резолвер держим постоянно, иначе доменность зависит от
# содержимого списков и может перевернуться ночным обновлением). Цена у неё другого
# порядка: хук nat, то есть только первый пакет соединения, и внутри сразу `udp dport 53`.
#
# Проверяется поэтому не число, а СОСТАВ: считающая цепочка ровно одна, вторая — именно
# DNS, и никакой третьей. Появится третья — стенд покраснеет так же, как раньше.
check "считающая цепочка в prerouting ровно одна" "1" \
    "$(printf '%s\n' "$out" | grep -c 'filter hook prerouting')"
check "и вторая — это перенаправление DNS" "1" \
    "$(printf '%s\n' "$out" | grep -c 'chain prerouting_dns')"
check "и больше в prerouting никого" "2" \
    "$(printf '%s\n' "$out" | grep -c 'hook prerouting')"
check "и не ставит метку" "0" \
    "$(printf '%s\n' "$out" | sed -n '/chain postrouting_down/,/^    }/p' | grep -c 'meta mark set')"
# Вердикта тоже быть не должно: цепочка только считает, решения принимает prerouting_mark.
check "и не выносит вердиктов" "0" \
    "$(printf '%s\n' "$out" | sed -n '/chain postrouting_down/,/^    }/p' | grep -cE ' (return|accept|drop)$')"

# ---- перенос счётчиков через apply -------------------------------------------
#
# apply сносит таблицу и загружает новую, а счётчики живут в правилах — значит без переноса
# каждый apply обнуляет объёмы. Само по себе незаметно, но обновление списков вызывает apply
# по расписанию, раз в сутки: объёмы в интерфейсе оказывались «с пяти утра», причём молча.
#
# Ядро в тестах недоступно, поэтому подставляем nft, который печатает готовое состояние. Так
# проверяется то, что здесь и может сломаться: разбор его вывода и подстановка значений в
# новые правила. Перенос ПО ИМЕНИ, а не по позиции: правила перетасовываются при правке
# спеки, и перенос по номеру приписал бы каналу чужой трафик.
mkdir -p "$tmp/bin"
cat > "$tmp/bin/nft" <<'NFT'
#!/bin/sh
# Порядок нарочно обратный порядку каналов в спеке: перенос обязан идти по имени.
case "$*" in
*prerouting_mark*)
    echo '  ip saddr { 192.168.1.0/24 } ip daddr @vpn_ip meta mark set meta mark & 0xf01fffff | 0x40100000 counter packets 7 bytes 700 return comment "steer:vpn_ip"'
    echo '  ip saddr { 192.168.1.0/24 } ip daddr @direct_ip counter packets 3 bytes 300 return comment "steer:direct_ip"'
    ;;
esac
case "$*" in
*postrouting_down*)
    echo '  ip daddr { 192.168.1.0/24 } ip saddr @vpn_ip counter packets 9 bytes 90000 comment "steer-down:vpn_ip"'
    ;;
esac
exit 0
NFT
chmod +x "$tmp/bin/nft"
carried="$(PATH="$tmp/bin:$PATH" $BIN apply --dry-run --spec "$tmp/spec.json" $S 2>/dev/null)"

check "перенос: наружу по direct_ip" "1" \
    "$(printf '%s\n' "$carried" | grep -c 'counter packets 3 bytes 300 return comment "steer:direct_ip"')"
check "перенос: наружу по vpn_ip" "1" \
    "$(printf '%s\n' "$carried" | grep -c 'counter packets 7 bytes 700 return comment "steer:vpn_ip"')"
check "перенос: внутрь по vpn_ip" "1" \
    "$(printf '%s\n' "$carried" | grep -c 'counter packets 9 bytes 90000 comment "steer-down:vpn_ip"')"
# Канала, которого в ядре не было, переносить нечего — и выдумывать значение нельзя.
check "чего не было, то остаётся нулём" "1" \
    "$(printf '%s\n' "$carried" | grep -c 'ip saddr @direct_ip counter comment "steer-down:direct_ip"')"
# Ноль печатается коротким `counter`: иначе вывод на чистой машине менялся бы без причины.
check "нули не пишутся числами" "0" \
    "$(printf '%s\n' "$out" | grep -c 'counter packets 0 bytes 0')"

# ---- выключенное правило ------------------------------------------------------
#
# «Выключено» обязано значить «не действует», а не «действует тише»: правило не превращается ни
# в набор, ни в правило ядра. Проверяется именно на выводе компилятора, потому что ошибка здесь
# выглядела бы безобиднее всего — интерфейс показывает выключатель, а трафик продолжает идти.
# Адрес у выключенного списка СВОЙ, которого нет во включённом: иначе «не попал в набор»
# проверялось бы адресом, который туда попадает законно, и тест прошёл бы при сломанном коде.
printf '10.77.77.0/24\n' > "$tmp/off.lst"
cat > "$tmp/off.json" <<EOF
{ "schema": 1, "from_default": ["192.168.1.0/24"],
  "outputs": { "vpn": { "kind": "interface", "device": "wg0" } },
  "channels": [
    { "name": "on",  "match": { "prefixes_file": "$tmp/a.lst" }, "out": "vpn" },
    { "name": "off", "enabled": false, "match": { "prefixes_file": "$tmp/off.lst" }, "out": "vpn" }
  ] }
EOF
offout="$("$BIN" apply --dry-run --spec "$tmp/off.json" --state-dir "$tmp/state-off")"
check "включённое рядом с выключенным работает" "1" \
    "$(printf '%s\n' "$offout" | grep -c 'comment "steer:vpn_ip"')"
# Оба правила ведут в один выход и один вид, то есть слиплись бы в одну группу. Попади
# выключенное в неё — его адрес оказался бы в наборе.
check "список выключенного в набор не попал" "0" \
    "$(printf '%s\n' "$offout" | grep -c '10.77.77.0/24')"
# И одного набора с одним правилом достаточно: выключенное не создаёт своих.
check "лишних наборов не появилось" "1" \
    "$(printf '%s\n' "$offout" | grep -c '    set ')"

# Спека без поля обязана значить то же, что значила: умолчание — включено.
check "поля нет — правило работает" "1" \
    "$(printf '%s\n' "$out" | grep -c 'comment "steer:vpn_ip"')"

# Выключенное правило не проверяется: иначе сломанное правило нельзя было бы выключить,
# только удалить.
cat > "$tmp/offbad.json" <<EOF
{ "schema": 1, "from_default": ["192.168.1.0/24"],
  "outputs": { "vpn": { "kind": "interface", "device": "wg0" } },
  "channels": [
    { "name": "bad", "enabled": false, "match": { "any": true }, "out": "vpn" }
  ] }
EOF
"$BIN" apply --dry-run --spec "$tmp/offbad.json" --state-dir "$tmp/state-ob" >/dev/null 2>&1
check "выключенное правило не мешает применить спеку" "0" "$?"

# ---- «кому» по MAC ------------------------------------------------------------
#
# Адрес у устройства меняется (DHCP выдаёт другой после перезагрузки), и правило начинает
# касаться не того. MAC живёт, пока живёт устройство. На встречном пути наш клиент —
# ПОЛУЧАТЕЛЬ, поэтому там ether daddr, а не saddr: перепутать их значит считать нуль
# скачанного при работающем правиле.
cat > "$tmp/mac.json" <<EOF
{ "schema": 1,
  "outputs": { "vpn": { "kind": "interface", "device": "wg0" } },
  "channels": [
    { "name": "tv", "from": ["a4:83:e7:2c:11:0f"],
      "match": { "prefixes_file": "$tmp/a.lst" }, "out": "vpn" }
  ] }
EOF
macout="$("$BIN" apply --dry-run --spec "$tmp/mac.json" --state-dir "$tmp/state-mac")"
check "MAC в метке: ether saddr" "1" \
    "$(printf '%s\n' "$macout" | grep -c 'ether saddr { a4:83:e7:2c:11:0f } ip daddr @vpn_ip')"
check "MAC на встречном пути: ether daddr" "1" \
    "$(printf '%s\n' "$macout" | grep -c 'ether daddr { a4:83:e7:2c:11:0f } ip saddr @vpn_ip')"
check "и никакого ip saddr с MAC-ом" "0" \
    "$(printf '%s\n' "$macout" | grep -c 'ip saddr { a4:')"

# Смешивать адреса и MAC-и в одном правиле нельзя: nft не умеет «или» внутри правила, и
# молчаливая половина означала бы, что часть устройств правило не касается.
cat > "$tmp/mix.json" <<EOF
{ "schema": 1,
  "outputs": { "vpn": { "kind": "interface", "device": "wg0" } },
  "channels": [
    { "name": "mix", "from": ["192.168.1.5", "a4:83:e7:2c:11:0f"],
      "match": { "prefixes_file": "$tmp/a.lst" }, "out": "vpn" }
  ] }
EOF
"$BIN" apply --dry-run --spec "$tmp/mix.json" --state-dir "$tmp/state-mix" >/dev/null 2>&1
# Сравниваем с фактом отказа, а не с числом: код у die свой (2), и привязка к нему сделала бы
# тест хрупким к тому, что нас здесь не касается.
check "смешанное «кому» отвергается" "отказ" "$([ $? -ne 0 ] && echo отказ || echo приняло)"

# Precedence is the spec's central promise: 198.51.100.5 is in BOTH lists, and the
# rule that claims it must be the one written first.
first="$(printf '%s\n' "$out" | grep -n 'comment "steer:' | head -1 | sed 's/.*steer://; s/".*//')"
# The order of GROUPS follows the first channel that created each, so "first match
# wins" still reads off the spec even though several channels may share one rule.
check "first channel in the spec is first in the chain" "direct_ip" "$first"

# A direct output claims the packet and marks nothing — the point of `return`.
check "direct output sets no mark" "0" \
    "$(printf '%s\n' "$out" | grep 'steer:direct_ip' | grep -c 'meta mark set')"

# ---- domain channels ---------------------------------------------------------
# A domain channel's set is filled by the resolver, but the RULE still has to test
# it. Emitting the daddr match only for prefix channels once left a domain channel
# matching everything from the LAN and marking it all into that tunnel.
printf 'example.com\n' > "$tmp/d.lst"
cat > "$tmp/dspec.json" <<EOF
{ "schema": 1, "from_default": ["192.168.1.0/24"], "lan_device": "br-lan",
  "outputs": { "geo": { "kind": "interface", "device": "tun0" } },
  "channels": [ { "name": "dom", "match": { "domains_file": "$tmp/d.lst" }, "out": "geo" } ] }
EOF
dout="$("$BIN" apply --dry-run --spec "$tmp/dspec.json" --state-dir "$tmp/state-dom")"
check "domain channel still tests its set" "1" \
    "$(printf '%s\n' "$dout" | grep 'steer:geo_dom' | grep -c 'ip daddr @geo_dom')"
check "domain set is declared empty, with timeouts" "1" \
    "$(printf '%s\n' "$dout" | grep -A3 'set geo_dom' | grep -c 'flags interval,timeout')"
check "fake-IP DNAT appears with a domain channel" "1" \
    "$(printf '%s\n' "$dout" | grep -c 'dnat ip to ip daddr map @fakeip')"
check "DNS redirect covers IPv6 too" "1" \
    "$(printf '%s\n' "$dout" | grep -c 'nfproto ipv6 iifname "br-lan" udp dport 53')"
# No domain channel means none of that plumbing should exist at all.
check "no fake-IP plumbing without domain channels" "0" \
    "$(printf '%s\n' "$out" | grep -c 'fakeip')"

# explain must consult a domain channel's set as well — those hold the fake IPs,
# which are precisely the addresses someone asks explain about.
check "explain queries domain channels too" "1" \
    "$(STEER_EXPLAIN_TRACE=1 "$BIN" explain 198.18.0.1 --spec "$tmp/dspec.json" \
        --state-dir "$tmp/state-dom" 2>&1 | grep -c 'geo_dom')"

# realip mode exists so traceroute stays legible: no DNAT means the kernel does not
# rewrite ICMP errors, so hops show real routers instead of the fake address.
cat > "$tmp/rspec.json" <<EOF
{ "schema": 1, "from_default": ["192.168.1.0/24"], "lan_device": "br-lan",
  "outputs": { "geo": { "kind": "interface", "device": "tun0" } },
  "channels": [ { "name": "dom", "match": { "domains_file": "$tmp/d.lst", "mode": "realip" }, "out": "geo" } ] }
EOF
rout="$("$BIN" apply --dry-run --spec "$tmp/rspec.json" --state-dir "$tmp/state-r")"
check "realip needs no fake-IP translation" "0" "$(printf '%s\n' "$rout" | grep -c 'fakeip')"
# Two rules, not one: IPv4 by subnet and IPv6 by device — a client that prefers the
# router's IPv6 resolver must not slip past the proxy.
check "realip still redirects DNS on both families" "2" \
    "$(printf '%s\n' "$rout" | grep -c 'udp dport 53 counter redirect')"
check "realip channel still has its set" "1" \
    "$(printf '%s\n' "$rout" | grep -c 'ip daddr @geo_dom')"

sed 's/"mode": "realip"/"mode": "nonsense"/' "$tmp/rspec.json" > "$tmp/rbad.json"
"$BIN" apply --dry-run --spec "$tmp/rbad.json" --state-dir "$tmp/state-r" >/dev/null 2>&1
check "refuses an unknown mode" "2" "$?"

# Intermediate traceroute hops: untracking ICMP time-exceeded stops the kernel from
# rewriting its source to the fake address. Only type 11 — dest-unreachable must stay
# tracked or path-MTU discovery breaks.
sed 's/"schema": 1,/"schema": 1, "traceroute_hops": true,/' "$tmp/dspec.json" > "$tmp/tspec.json"
tout="$("$BIN" apply --dry-run --spec "$tmp/tspec.json" --state-dir "$tmp/state-t")"
check "untracks time-exceeded when asked" "1" \
    "$(printf '%s\n' "$tout" | grep -c 'icmp type time-exceeded counter notrack')"
check "leaves dest-unreachable tracked" "0" \
    "$(printf '%s\n' "$tout" | grep -c 'destination-unreachable')"
check "off by default" "0" "$(printf '%s\n' "$dout" | grep -c notrack)"

# ---- several lists in one channel -------------------------------------------
# Enabling "youtube" and "google" must not force two channels: as far as routing is
# concerned they are one destination. The lists are read as several files rather than
# concatenated by the caller — duplicating list bytes to express "and" costs overlay
# space on the box that has least of it.
printf '10.1.0.0/24\n' > "$tmp/m1.lst"
printf '10.2.0.0/24\n10.1.0.0/24\n' > "$tmp/m2.lst"
cat > "$tmp/mspec.json" <<EOF
{ "schema": 1, "from_default": ["192.168.1.0/24"],
  "outputs": { "vpn": { "kind": "interface", "device": "wg0" } },
  "channels": [ { "name": "many",
                  "match": { "prefixes_files": ["$tmp/m1.lst", "$tmp/m2.lst"] },
                  "out": "vpn" } ] }
EOF
mout="$("$BIN" apply --dry-run --spec "$tmp/mspec.json" --state-dir "$tmp/state-m")"
# Two lists, one output: one set and one rule, not two of each. On the weak box that
# is the difference between walking two rules per packet and walking a dozen.
check "one set from several lists" "1" "$(printf '%s\n' "$mout" | grep -c 'set vpn_ip')"
check "and one rule" "1" "$(printf '%s\n' "$mout" | grep -c 'comment "steer:vpn_ip"')"
check "all three entries present" "1" \
    "$(printf '%s\n' "$mout" | grep -c 'elements = { 10.1.0.0/24, 10.2.0.0/24, 10.1.0.0/24 }')"
# The duplicate is not deduplicated in text on purpose: the kernel folds it via
# auto-merge, which is cheaper than us rewriting the list.
check "auto-merge lets the kernel fold the duplicate" "1" \
    "$(printf '%s\n' "$mout" | grep -A3 'set vpn_ip' | grep -c 'auto-merge')"

# ---- одно правило про СЕРВИС, а не про вид списка -----------------------------
#
# Адреса и домены в одном правиле разрешены. Раньше запрещались: набор один, а заполняются они
# по-разному — адреса из файла при компиляции, домены кладёт резолвер. Из этого следовало, что
# человек выбирает не сервис, а вид списка, и «YouTube адресами» с «YouTube доменами» жили
# двумя правилами.
#
# Ограничение оказалось нашим: набор с `flags interval,timeout` держит и постоянные элементы, и
# временные. Проверяется здесь, потому что сломать это легко и незаметно — набор без timeout
# примет адреса из файла и молча откажет резолверу, а выглядит это как «домены не работают».
cat > "$tmp/xspec.json" <<EOF
{ "schema": 1, "outputs": { "vpn": { "kind": "interface", "device": "wg0" } },
  "channels": [ { "name": "mixed",
                  "match": { "prefixes_files": ["$tmp/m1.lst"], "domains_files": ["$tmp/d.lst"] },
                  "out": "vpn" } ] }
EOF
mixout="$("$BIN" apply --dry-run --spec "$tmp/xspec.json" --state-dir "$tmp/state-m" 2>&1)"
check "адреса и домены в одном правиле принимаются" "1" \
    "$(printf '%s\n' "$mixout" | grep -c 'set vpn_dom')"
check "набор смешанного правила с timeout" "1" \
    "$(printf '%s\n' "$mixout" | grep -c 'flags interval,timeout')"
check "и адреса из файла в нём есть" "1" \
    "$(printf '%s\n' "$mixout" | grep -c 'elements = {')"
check "набора _ip при этом не появилось" "0" \
    "$(printf '%s\n' "$mixout" | grep -c 'set vpn_ip')"

# Два ОТДЕЛЬНЫХ правила одного сервиса — адресное и доменное — в один outbound и для одних
# клиентов сливаются в один набор. Это и есть «выбирать по сервису»: два способа описать одно и
# то же перестают быть двумя правилами в ядре.
cat > "$tmp/twospec.json" <<EOF
{ "schema": 1, "outputs": { "vpn": { "kind": "interface", "device": "wg0" } },
  "channels": [
    { "name": "адресами", "match": { "prefixes_files": ["$tmp/m1.lst"] }, "out": "vpn" },
    { "name": "доменами", "match": { "domains_files": ["$tmp/d.lst"] }, "out": "vpn" }
  ] }
EOF
twoout="$("$BIN" apply --dry-run --spec "$tmp/twospec.json" --state-dir "$tmp/state-two" 2>&1)"
check "два правила одного сервиса — один набор" "1" \
    "$(printf '%s\n' "$twoout" | grep -c '    set ')"
check "и одно правило в цепочке метки" "1" \
    "$(printf '%s\n' "$twoout" | grep -c 'comment \"steer:')"

# ---- вывод `steer fit` годен каналу как есть ----------------------------------
# Фиттер объединяет два соседних адреса, не складывающихся в выровненный префикс, в
# ДИАПАЗОН — «10.0.0.1-10.0.0.2». Проверка формы отвергала дефис, поэтому подогнанный
# список терял такие строки, а на списке из одной такой строки движок объявлял файл
# доменным и советовал «подключите как доменный». То есть главный путь работы с большим
# списком — ужать и подать каналу — заканчивался пустым каналом и советом не по делу.
printf '10.0.0.1\n10.0.0.2\n' > "$tmp/pair.lst"
"$BIN" fit "$tmp/pair.lst" > "$tmp/fitted.lst" 2>/dev/null
check "fit объединяет пару в диапазон" "10.0.0.1-10.0.0.2" "$(cat "$tmp/fitted.lst")"
cat > "$tmp/fitspec.json" <<EOF
{ "schema": 1, "from_default": ["192.168.1.0/24"],
  "outputs": { "vpn": { "kind": "interface", "device": "wg0" } },
  "channels": [ { "name": "ужатый", "match": { "prefixes_files": ["$tmp/fitted.lst"] }, "out": "vpn" } ] }
EOF
fitout="$("$BIN" apply --dry-run --spec "$tmp/fitspec.json" --state-dir "$tmp/state-fit" 2>&1)"
check "диапазон уезжает в набор" "1" \
    "$(printf '%s\n' "$fitout" | grep -c 'elements = { 10.0.0.1-10.0.0.2 }')"
check "и список не назван доменным" "0" \
    "$(printf '%s\n' "$fitout" | grep -c 'это доменный список')"
# Дефис не должен превратить в адрес что попало: доменное имя с дефисом обязано остаться
# доменным, иначе проверка «адресный список или доменный» перестанет различать их вовсе.
printf 'my-site.example\n' > "$tmp/dash.lst"
cat > "$tmp/dashspec.json" <<EOF
{ "schema": 1, "from_default": ["192.168.1.0/24"],
  "outputs": { "vpn": { "kind": "interface", "device": "wg0" } },
  "channels": [ { "name": "дефис", "match": { "prefixes_files": ["$tmp/dash.lst"] }, "out": "vpn" } ] }
EOF
# Сообщение сменилось вместе со смыслом: список из одних имён в адресном ключе перестал
# быть отказом (гибридные списки — резолвер берёт из того же файла доменные строки), но
# остался НЕОЖИДАННЫМ состоянием, о котором человеку говорят. Проверка по-прежнему про
# классификатор: если бы `my-site.example` сочли адресом, не было бы ни этой строки, ни
# доменного правила — имя молча уехало бы в набор nft и отвергло бы его целиком.
check "имя с дефисом адресом не считается" "1" \
    "$("$BIN" apply --dry-run --spec "$tmp/dashspec.json" --state-dir "$tmp/state-dash" 2>&1 |
       grep -c 'адресов нет вовсе, только имена')"
check "и apply на таком списке больше не падает" "0" \
    "$("$BIN" apply --dry-run --spec "$tmp/dashspec.json" --state-dir "$tmp/state-dash" \
       >/dev/null 2>&1; echo $?)"
# И имя обязано доехать до набора nft НЕ адресом: элементов в наборе ноль.
check "имя в набор адресом не уехало" "0" \
    "$("$BIN" apply --dry-run --spec "$tmp/dashspec.json" --state-dir "$tmp/state-dash" 2>/dev/null |
       grep -c 'my-site.example')"

# ---- правило на устройство старше глобального ВСЕГДА --------------------------
#
# Порядок совпадения в цепочке и есть приоритет: правило заканчивается `return`, поэтому
# побеждает первое совпавшее. Пока порядок читался только со спеки, правило «этот телефон
# не маршрутизируем» работало ровно до тех пор, пока человек держал его выше глобальных —
# стоило добавить новое глобальное и поставить первым, и исключение перестало действовать,
# молча.
#
# Поэтому глобальное правило в спеке ниже стоит ПЕРВЫМ: проверяется, что приоритет — это
# свойство правила, а не порядка в списке.
cat > "$tmp/devspec.json" <<EOF
{ "schema": 2, "from_default": ["192.168.1.0/24"],
  "outputs": { "direct": { "kind": "direct" },
               "vpn": { "kind": "interface", "device": "wg0" } },
  "channels": [
    { "name": "global", "out": "vpn", "match": { "prefixes_files": ["$tmp/p.lst"] } },
    { "name": "laptop", "out": "direct", "scope": "device",
      "from": ["192.168.1.55"], "match": { "any": true } },
    { "name": "phone", "out": "vpn", "scope": "device",
      "from": ["aa:bb:cc:dd:ee:ff"], "match": { "any": true } } ] }
EOF
devout="$("$BIN" apply --dry-run --spec "$tmp/devspec.json" --state-dir "$tmp/state-dev" 2>&1)"
check "спека с правилами на устройство применяется" "0" \
    "$("$BIN" apply --dry-run --spec "$tmp/devspec.json" --state-dir "$tmp/state-dev" \
       >/dev/null 2>&1; echo $?)"
# Порядок строк в цепочке — это и есть проверка приоритета.
devseq="$(printf '%s\n' "$devout" | sed -n '/chain prerouting_mark/,/^    }/p' |
          sed -n 's/.*comment "steer:\([a-z0-9_]*\)".*/\1/p' | tr '\n' ' ')"
check "оба устройства впереди глобального, хотя в спеке оно первое" \
    "direct_all_c1 vpn_all_c2 vpn_ip " "$devseq"
# Ноутбук «мимо туннеля»: правило заканчивается return и НИЧЕГО не метит.
check "правило «не маршрутизировать» метку не ставит" "0" \
    "$(printf '%s\n' "$devout" | grep 'steer:direct_all_c1' | grep -c 'meta mark set')"
# Телефон по MAC: ether saddr, а не ip saddr — адрес по DHCP сменится, MAC нет.
check "правило по MAC ловит по ether saddr" "1" \
    "$(printf '%s\n' "$devout" | grep -c 'ether saddr { aa:bb:cc:dd:ee:ff }')"
# И его трафик уходит в туннель с чужим битом: обход его трогать не должен.
check "весь трафик устройства уходит в туннель" "1" \
    "$(printf '%s\n' "$devout" | grep 'ether saddr' | grep -c 'or 0x40100000')"

# `any` без allow_all у правила на устройство ЗАКОНЕН: общий запрет заведён против «все
# клиенты без интернета и починка с провода», а здесь цена ошибки — один хозяин.
check "у правила на устройство any не требует allow_all" "0" \
    "$(printf '%s\n' "$devout" | grep -ci 'allow_all')"
# А у глобального по-прежнему требует.
cat > "$tmp/allspec.json" <<EOF
{ "schema": 2, "from_default": ["192.168.1.0/24"],
  "outputs": { "vpn": { "kind": "interface", "device": "wg0" } },
  "channels": [ { "name": "all", "out": "vpn", "match": { "any": true } } ] }
EOF
check "у глобального any по-прежнему требует allow_all" "1" \
    "$("$BIN" apply --dry-run --spec "$tmp/allspec.json" --state-dir "$tmp/state-dev2" 2>&1 |
       grep -c 'allow_all')"

# ПОДСЕТЬ В ПРАВИЛЕ НА УСТРОЙСТВО — ОТКАЗ. Иначе приоритет достался бы не телефону, а
# половине сети, и достался бы тихо: снаружи такое правило выглядит точно так же.
cat > "$tmp/netspec.json" <<EOF
{ "schema": 2, "from_default": ["192.168.1.0/24"],
  "outputs": { "direct": { "kind": "direct" } },
  "channels": [ { "name": "half", "out": "direct", "scope": "device",
                  "from": ["192.168.1.0/24"], "match": { "any": true } } ] }
EOF
check "подсеть в правиле на устройство отвергнута" "1" \
    "$("$BIN" apply --dry-run --spec "$tmp/netspec.json" --state-dir "$tmp/state-dev3" 2>&1 |
       grep -c 'только одиночных')"
# Пустой `from` — тоже отказ: правило «на устройство» без хозяина действует на всех, то есть
# получает приоритет устройства, будучи глобальным. Самое опасное из недоразумений.
cat > "$tmp/emptyspec.json" <<EOF
{ "schema": 2, "from_default": ["192.168.1.0/24"],
  "outputs": { "direct": { "kind": "direct" } },
  "channels": [ { "name": "nohost", "out": "direct", "scope": "device",
                  "match": { "any": true } } ] }
EOF
check "правило на устройство без хозяина отвергнуто" "1" \
    "$("$BIN" apply --dry-run --spec "$tmp/emptyspec.json" --state-dir "$tmp/state-dev4" 2>&1 |
       grep -c 'нет ни одного хозяина')"
# И ключ `scope` — поле схемы 2: в спеке schema 1 он отвергается, а не игнорируется. Иначе
# движок постарше положил бы правило в порядке спеки, и приоритет пропал бы молча.
cat > "$tmp/s1spec.json" <<EOF
{ "schema": 1, "from_default": ["192.168.1.0/24"],
  "outputs": { "direct": { "kind": "direct" } },
  "channels": [ { "name": "dev", "out": "direct", "scope": "device",
                  "from": ["192.168.1.55"], "match": { "any": true } } ] }
EOF
check "scope в спеке schema 1 отвергнут" "1" \
    "$("$BIN" apply --dry-run --spec "$tmp/s1spec.json" --state-dir "$tmp/state-dev5" 2>&1 |
       grep -c 'schema 2')"

# ---- группы с разными клиентами получают РАЗНЫЕ наборы -----------------------
# Имя набора собиралось только из выхода и вида, а группы разделяются ещё и по `from` и по
# режиму. Двум группам доставалось одно имя, ядро сливало наборы в один, и список,
# заведённый «только для телевизора», уезжал в туннель для всей сети — без отказа, без
# предупреждения, потому что nft принимает два объявления одного набора.
cat > "$tmp/twofrom.json" <<EOF
{ "schema": 1, "from_default": ["192.168.1.0/24"],
  "outputs": { "vpn": { "kind": "interface", "device": "wg0" } },
  "channels": [
    { "name": "телевизор", "from": ["192.168.1.5"], "match": { "prefixes_files": ["$tmp/m1.lst"] }, "out": "vpn" },
    { "name": "остальные", "match": { "prefixes_files": ["$tmp/m2.lst"] }, "out": "vpn" }
  ] }
EOF
tfout="$("$BIN" apply --dry-run --spec "$tmp/twofrom.json" --state-dir "$tmp/state-tf" 2>&1)"
check "разные клиенты — два РАЗНЫХ набора" "2" \
    "$(printf '%s\n' "$tfout" | grep -c '^    set ')"
check "и одноимённых наборов среди них нет" "2" \
    "$(printf '%s\n' "$tfout" | sed -n 's/^    set \([a-z0-9_]*\) .*/\1/p' | sort -u | wc -l)"
check "клиент по умолчанию сохраняет прежнее имя набора" "1" \
    "$(printf '%s\n' "$tfout" | grep -c '^    set vpn_ip {')"

# Доменные каналы: свой список клиентов и свой режим тоже обязаны давать свой набор,
# иначе резолвер кладёт fake-IP и настоящие адреса в один набор.
cat > "$tmp/threedom.json" <<EOF
{ "schema": 1, "from_default": ["192.168.1.0/24"],
  "outputs": { "vpn": { "kind": "interface", "device": "wg0" } },
  "channels": [
    { "name": "d1", "match": { "domains_files": ["$tmp/d.lst"] }, "out": "vpn" },
    { "name": "d2", "match": { "domains_files": ["$tmp/d.lst"], "mode": "realip" }, "out": "vpn" },
    { "name": "d3", "from": ["192.168.1.9"], "match": { "domains_files": ["$tmp/d.lst"] }, "out": "vpn" }
  ] }
EOF
tdout="$("$BIN" apply --dry-run --spec "$tmp/threedom.json" --state-dir "$tmp/state-td" 2>&1)"
check "fakeip, realip и свои клиенты — три разных набора" "3" \
    "$(printf '%s\n' "$tdout" | sed -n 's/^    set \([a-z0-9_]*\) .*/\1/p' | sort -u | wc -l)"

# Канал «весь трафик» рядом со списочным того же выхода: раньше они сливались в одну
# группу, правило получало имя _ip и начинало проверять набор — то есть «весь трафик этой
# сети в туннель» молча превращался в «только адреса из списка».
cat > "$tmp/anymix.json" <<EOF
{ "schema": 1, "from_default": ["192.168.1.0/24"],
  "outputs": { "vpn": { "kind": "interface", "device": "wg0" } },
  "channels": [
    { "name": "список", "match": { "prefixes_files": ["$tmp/m1.lst"] }, "out": "vpn" },
    { "name": "всё",    "match": { "any": true, "allow_all": true }, "out": "vpn" }
  ] }
EOF
amout="$("$BIN" apply --dry-run --spec "$tmp/anymix.json" --state-dir "$tmp/state-am" 2>&1)"
check "any рядом со списком остаётся отдельным правилом" "1" \
    "$(printf '%s\n' "$amout" | grep -c 'comment \"steer:vpn_all\"')"
check "и это правило безусловное — набор оно не проверяет" "0" \
    "$(printf '%s\n' "$amout" | grep 'steer:vpn_all' | grep -c 'daddr @')"

# ---- трафик в туннель общий обход не трогает ----------------------------------
#
# Бит ZAPRET_SKIP_MARK (0x40000000) — чужой: это тот бит, по которому цепочка системного
# zapret говорит «этот пакет не мой» (её условие входа — `meta mark & 0x40000000 == 0`).
# До запуска 65 мы ставили его ТОЛЬКО выходу kind=zapret, и трафик, уходящий в туннель,
# по-прежнему проходил через общий обход.
#
# Почему это вредно, а не просто бесполезно: пакет, уходящий в туннель, DPI видит снаружи
# как сам туннель — полезной нагрузки там не разобрать, — но nfqws при этом рассинхронизирует
# и режет ВНЕШНИЕ пакеты, то есть трогает транспорт туннеля, и рукопожатие может не сойтись.
#
# kind=direct — единственное исключение, и оно же смысл прямого канала: там общий обход
# обязан работать.
#
# Выходов в фикстуре ТРИ, и мост Telegram здесь не для полноты: у него причина та же, что у
# kind=zapret (его трафик разбирает наш собственный обработчик, и второй разбиратель поверх —
# это два обхода на один пакет), но вид выхода другой, и забытым `case` он оказался бы первым.
# kind=vless и kind=xsteer базовая сборка не принимает вовсе, поэтому их доля правила
# проверяется по самой функции — см. out_skips_zapret в tests/specmatch.c.
printf '203.0.113.0/24\n' > "$tmp/p.lst"
printf '104.16.0.0/12\n' > "$tmp/p2.lst"
cat > "$tmp/skipspec.json" <<EOF
{ "schema": 1, "from_default": ["192.168.1.0/24"],
  "outputs": { "direct": { "kind": "direct" },
               "vpn": { "kind": "interface", "device": "wg0" },
               "tg": { "kind": "tgws", "domain": "ex.co.uk" } },
  "channels": [ { "name": "t", "out": "vpn", "match": { "prefixes_files": ["$tmp/p.lst"] } },
                { "name": "g", "out": "tg", "match": { "prefixes_files": ["$tmp/p2.lst"] } },
                { "name": "d", "out": "direct", "match": { "prefixes_files": ["$tmp/p.lst"] } } ] }
EOF
skipout="$("$BIN" apply --dry-run --spec "$tmp/skipspec.json" --state-dir "$tmp/state-skip" 2>/dev/null)"
# 0x40100000 = метка выхода 0x00100000 плюс чужой бит 0x40000000.
check "туннельному выходу ставится бит «не мой» для zapret" "1" \
    "$(printf '%s\n' "$skipout" | grep 'steer:vpn_ip' | grep -c 'or 0x40100000')"
check "мосту telegram — тот же бит" "1" \
    "$(printf '%s\n' "$skipout" | grep 'steer:tg_ip' | grep -c 'or 0x40200000')"
# И маска остальных бит не пострадала: своё слово мы по-прежнему затираем целиком, а чужие
# (mwan3, pbr, sqm) сохраняем чтением-модификацией.
check "и маска своего слова осталась прежней" "2" \
    "$(printf '%s\n' "$skipout" | grep -c 'mark and 0xf00fffff or 0x4')"
# У прямого канала разметки нет вовсе (он заканчивается `return`), поэтому чужого бита у него
# быть не может ни в каком виде.
check "прямой канал метку не ставит" "0" \
    "$(printf '%s\n' "$skipout" | grep 'steer:direct_ip' | grep -c 'meta mark set')"
check "прямому каналу чужой бит не ставится" "0" \
    "$(printf '%s\n' "$skipout" | grep 'steer:direct_ip' | grep -c '0x40')"
# ГЛАВНАЯ ПРОВЕРКА ПРАВИЛА, и она нарочно НЕ перечисляет виды выхода: перечисли — и стенд
# знал бы про виды ровно столько же, сколько забытый `case`, из-за которого правка и
# понадобилась. Спрашивается свойство: раз метка ставится, чужой бит обязан стоять.
check "метку без чужого бита не ставит никто" "0" \
    "$(printf '%s\n' "$skipout" | grep 'meta mark set mark and' | grep -vc 'or 0x4')"

# ---- does the spec need the resolver ----------------------------------------
# The init script asks the engine this. It used to grep the spec for the literal
# `"domains_file"`, and when the plural `domains_files` arrived the match stopped
# matching: the resolver did not start while apply still installed the DNS redirect,
# so every LAN query went to a closed port. DNS died on a live router.
#
# С ЗАПУСКА 65 ОТВЕТ ВСЕГДА «ДА», и это решение владельца, а не упрощение стенда.
# Перенаправление DNS стоит постоянно, значит резолвер, к которому оно ведёт, обязан
# существовать постоянно вместе с ним — иначе воспроизводится ровно та беда, ради которой
# эта проверка и заведена: правило есть, слушать некому, запросы уходят в закрытый порт.
#
# Почему ответ перестал зависеть от спеки: доменность канала стала зависеть от СОДЕРЖИМОГО
# файлов списков (домен и подсеть лежат в одном файле), то есть могла бы перевернуться
# ночным обновлением списков, которое зовёт apply напрямую, минуя синхронизацию force_dns
# в управляющем слое. Постоянный резолвер убирает переменную, а с ней и гонку.
"$BIN" needs-dnsd --spec "$tmp/dspec.json" --state-dir "$tmp/state-n" >/dev/null 2>&1
check "needs-dnsd: yes for a domain channel" "0" "$?"
"$BIN" needs-dnsd --spec "$tmp/spec.json" --state-dir "$tmp/state-n" >/dev/null 2>&1
check "needs-dnsd: yes for address channels too" "0" "$?"
# Отказ на непонятой спеке обязан остаться: init-скрипт не должен поднимать резолвер под
# конфигурацию, которую apply отвергнет.
printf '%s' '{"schema":99,"outputs":{},"channels":[]}' > "$tmp/badschema.json"
"$BIN" needs-dnsd --spec "$tmp/badschema.json" --state-dir "$tmp/state-n" >/dev/null 2>&1
check "needs-dnsd: отказ на непонятой спеке" "2" "$?"

# And the shipped init script must ASK rather than guess, or the same trap returns
# the next time a key is renamed.
# Путь от КОРНЯ репозитория, откуда стенд и запускается (make test). Он был написан как
# `../files/...`, то есть указывал наружу репозитория, файл не находился никогда, и обе
# проверки молча не выполнялись — счётчик о них даже не знал. Поэтому существование файла
# теперь само по себе проверка: если путь снова уедет, стенд об этом скажет.
init=files/etc/init.d/steer
check "init-скрипт найден" "1" "$([ -f "$init" ] && echo 1 || echo 0)"
if [ -f "$init" ]; then
    # Считается ВЫЗОВ, а не упоминание: слово needs-dnsd встречается ещё и в комментарии
    # рядом, поэтому счёт по всему файлу давал 2 и проверка не прошла бы, даже когда всё
    # в порядке. Проверить это раньше было нельзя — путь к файлу был неверен, и стенд
    # молчал (см. выше).
    check "init script asks the engine" "1" "$(grep -c '^[^#]*steer needs-dnsd' "$init")"
    check "init script does not grep the spec for keys" "0" \
        "$(grep -c "grep -q '\"domains" "$init")"
    # Сторож устройств обязан открываться ДО вопроса про резолвер: тот выходит из
    # функции, когда доменных каналов нет, и failover оставался незапущенным на самой
    # обычной конфигурации — только адресные списки.
    check "failover открывается раньше вопроса про резолвер" "1" \
        "$([ "$(grep -n 'procd_open_instance failover' "$init" | cut -d: -f1)" \
             -lt "$(grep -n 'needs-dnsd' "$init" | tail -1 | cut -d: -f1)" ] && echo 1 || echo 0)"
fi

# ---- kind=zapret: очередь вместо маршрута ------------------------------------
#
# У этого вида выхода нет ни устройства, ни таблицы: пакет уходит обычным маршрутом, а
# выход меняет только то, что с ним по дороге сделает nfqws. Поэтому и проверяется здесь
# не маршрутизация, а ровно три вещи, каждая из которых уже была сломана в разработке:
# метка (без неё правило канала встаёт, а в очередь не попадает ни один пакет), приоритет
# цепочки (mangle идёт ДО трансляции адресов, а обходу нужен пакет в том виде, в каком он
# уйдёт с роутера) и `bypass` как выражение on_fail.
cat > "$tmp/zap.json" <<EOF
{ "schema": 1, "lan_devices": ["br-lan"],
  "outputs": { "direct": { "kind": "direct" },
               "yt":  { "kind": "zapret" },
               "dis": { "kind": "zapret", "on_fail": "direct" } },
  "channels": [ { "name": "ю", "match": { "prefixes_file": "$tmp/a.lst" }, "out": "yt" },
                { "name": "д", "match": { "prefixes_file": "$tmp/b.lst" }, "out": "dis" } ] }
EOF
zout="$("$BIN" apply --dry-run --spec "$tmp/zap.json" --state-dir "$tmp/state-z" 2>&1)"
check "zapret: спека компилируется" "0" "$?"
check "цепочка очередей появилась" "1" "$(printf '%s\n' "$zout" | grep -c 'chain zapret_queue {')"
# Приоритет — post-NAT. Сначала здесь стояло `mangle + 10`, то есть ДО трансляции адресов:
# nfqws правил бы ClientHello с адресом источника из локальной сети, а в сеть уходил бы
# другой пакет. У самого zapret цепочка стоит на srcnat + 1 ровно поэтому.
check "очередь висит после трансляции адресов" "1" \
    "$(printf '%s\n' "$zout" | grep -c 'hook postrouting priority srcnat + 2')"
# Свои пакеты обработчика в очередь не возвращаются: у них поднят 0x20000000. Без этого
# правила первое же соединение даёт круг «свой пакет снова в свою очередь».
check "первым правилом выход по своей метке" "1" \
    "$(printf '%s\n' "$zout" | grep -c 'meta mark and 0x20000000 == 0x20000000 counter return')"
# on_fail=drop (умолчание) — очередь БЕЗ bypass: нет процесса, нет трафика. on_fail=direct —
# с bypass: нет процесса, трафик идёт как обычный. Выражает это само ядро, без сторожа.
check "on_fail=drop даёт очередь без bypass" "1" \
    "$(printf '%s\n' "$zout" | grep -c 'queue num 8300 comment "steer:zapret:yt"')"
check "on_fail=direct даёт bypass" "1" \
    "$(printf '%s\n' "$zout" | grep -c 'queue num 8301 bypass comment "steer:zapret:dis"')"
# Предел пакетов: без него в userspace уезжает весь поток, а не первые пакеты соединения.
check "в очередь идут только первые пакеты" "2" \
    "$(printf '%s\n' "$zout" | grep -c 'ct original packets 1-9')"
# Метка канала несёт ЧУЖОЙ бит 0x40000000 — им системный обход узнаёт «этот трафик не мой».
check "трафик выхода помечен как чужой для общего обхода" "1" \
    "$(printf '%s\n' "$zout" | grep -c 'or 0x40100000')"
# …но перед НАШЕЙ очередью этот бит снимается: nfqws считает своим порождённым любой пакет с
# общим битом со своим fwmark (0x60000000) и не обрабатывает его. Пока бит доезжал до очереди,
# выход не трогал ни одного пакета (снято с роутера владельца: YouTube 3 из 37 → 33 из 37).
check "перед очередью чужой бит снимается" "2" \
    "$(printf '%s\n' "$zout" | grep -c 'meta mark set mark and 0xbfffffff counter queue num')"
# Ответные пакеты тоже в очередь, как у zapret: по ним nfqws узнаёт TTL для autottl.
check "ответные пакеты соединения идут в очередь по ct mark" "2" \
    "$(printf '%s\n' "$zout" | grep -c 'ct reply packets 1-3 counter queue num 830[01] bypass comment "steer:zapret-reply:')"
check "цепочка ответов висит на prerouting" "1" \
    "$(printf '%s\n' "$zout" | grep -A1 'chain zapret_queue_in' | grep -c 'hook prerouting priority mangle;')"
# Порождённые обработчиком пакеты снимаются с учёта conntrack НАШЕЙ цепочкой, а не цепочкой
# службы zapret: та исчезает вместе со службой, а выключить общий обход и оставить его одному
# выходу — ровно то, ради чего выход и заводят. Снято с роутера владельца: общий обход
# выключен, обработчик жив, очередь считает — YouTube не открывается (INVALID у fw4).
check "своя predefrag до conntrack" "1" \
    "$(printf '%s\n' "$zout" | grep -c 'chain zapret_predefrag {')"
check "висит на output до conntrack" "1" \
    "$(printf '%s\n' "$zout" | grep -c 'hook output priority -401')"
check "вход по чужому биту порождённых пакетов" "1" \
    "$(printf '%s\n' "$zout" | grep -c 'meta mark and 0x40000000 != 0x00000000 jump zapret_predefrag_nfqws')"
check "четыре правила notrack, как у zapret" "4" \
    "$(printf '%s\n' "$zout" | grep -c ' notrack comment')"
# Таблицы маршрутизации у такого выхода нет: маршрут не меняется вовсе.
check "маршрутной таблицы у выхода zapret нет" "0" \
    "$(printf '%s\n' "$zout" | grep -c 'ip route')"
# Пока в спеке нет ни одного такого выхода, цепочки быть не должно: пустая базовая цепочка
# в postrouting — это лишний проход по правилам на КАЖДОМ пакете роутера.
check "без выходов zapret цепочки нет" "0" "$(printf '%s\n' "$out" | grep -c 'zapret_queue')"
check "и predefrag без них тоже нет" "0" "$(printf '%s\n' "$out" | grep -c 'zapret_predefrag')"

# ---- перехват Telegram (kind=tgws) --------------------------------------------------------
# Правило стоит в nat prerouting, то есть ловит трафик КЛИЕНТОВ. Приоритет и хук проверяются
# здесь, а работу целиком — tests/run-tgws.sh на двух сетевых пространствах: на одном
# пространстве соединение идёт через output и правило не срабатывает вовсе.
cat > "$tmp/tgws.json" <<EOF
{ "schema": 1, "lan_devices": ["br-lan"],
  "outputs": { "direct": { "kind": "direct" }, "tg": { "kind": "tgws", "domain": "ex.co.uk" } },
  "channels": [ { "name": "тг", "match": { "prefixes_file": "$tmp/a.lst" }, "out": "tg" } ] }
EOF
tout="$("$BIN" apply --dry-run --spec "$tmp/tgws.json" --state-dir "$tmp/state-t" 2>&1)"
check "tgws: спека компилируется" "0" "$?"
check "цепочка перехвата появилась" "1" \
    "$(printf '%s\n' "$tout" | grep -c 'chain tgws_redirect')"
# dstnat + 1, а не dstnat: сначала наша же цепочка fakeip обязана вернуть настоящий адрес,
# и только потом решается, наш ли он. И не mangle: метку канала ставят раньше, на mangle + 1.
check "перехват идёт после трансляции адресов" "1" \
    "$(printf '%s\n' "$tout" | grep -c 'hook prerouting priority dstnat + 1')"
check "заворачивает по метке выхода на его порт" "1" \
    "$(printf '%s\n' "$tout" | grep -c 'meta mark and 0x0ff00000 == 0x00100000 tcp dport { 443, 80, 5222 } counter redirect to :8480')"
# Таблицы маршрутизации у такого выхода нет — маршрут не меняется, меняется адресат.
check "маршрутной таблицы у выхода tgws нет" "0" \
    "$(printf '%s\n' "$tout" | grep -c 'ip route')"
check "без выходов tgws цепочки нет" "0" "$(printf '%s\n' "$out" | grep -c 'tgws_redirect')"
# Порт печатает движок: второй расчёт того же в init-скрипте разошёлся бы молча.
ti="$("$BIN" tgws-instances --spec "$tmp/tgws.json" --state-dir "$tmp/state-t" 2>&1)"
check "tgws-instances: код 0, когда поднимать есть что" "0" "$?"
check "имя и порт по строке на выход" "tg	8480" "$ti"
"$BIN" tgws-instances --spec "$tmp/zap.json" --state-dir "$tmp/state-z" >/dev/null 2>&1
check "без таких выходов код 1" "1" "$?"
# Устройство у такого выхода — почти наверняка описка, и молча принять её значит обещать
# маршрутизацию, которой не будет.
cat > "$tmp/tgws-bad.json" <<EOF
{ "schema": 1, "outputs": { "tg": { "kind": "tgws", "domain": "ex.co.uk", "device": "eth0" } }, "channels": [] }
EOF
"$BIN" apply --dry-run --spec "$tmp/tgws-bad.json" --state-dir "$tmp/state-tb" >/dev/null 2>&1
check "устройство у tgws отвергается" "2" "$?"
# on_fail у него не выражается ничем: правило перехвата стоит в ядре всегда.
cat > "$tmp/tgws-of.json" <<EOF
{ "schema": 1, "outputs": { "tg": { "kind": "tgws", "domain": "ex.co.uk", "on_fail": "direct" } }, "channels": [] }
EOF
"$BIN" apply --dry-run --spec "$tmp/tgws-of.json" --state-dir "$tmp/state-to" >/dev/null 2>&1
check "on_fail=direct у tgws отвергается" "2" "$?"
# Домена нет — выход отвергается: прямые точки Telegram отвечают только TLS 1.2 и стоят на
# телеграмовских адресах, то есть на тех самых, которые режут. Подставить их молча значило бы
# завести выход, который выглядит настроенным и не работает никогда.
cat > "$tmp/tgws-nd.json" <<EOF
{ "schema": 1, "outputs": { "tg": { "kind": "tgws" } }, "channels": [] }
EOF
"$BIN" apply --dry-run --spec "$tmp/tgws-nd.json" --state-dir "$tmp/state-tn" >/dev/null 2>&1
check "tgws без domain отвергается" "2" "$?"
# И наоборот: domain у чужого вида выхода — поле, принятое молча там, где оно ничего не значит.
cat > "$tmp/tgws-alien.json" <<EOF
{ "schema": 1, "outputs": { "d": { "kind": "direct", "domain": "ex.co.uk" } }, "channels": [] }
EOF
"$BIN" apply --dry-run --spec "$tmp/tgws-alien.json" --state-dir "$tmp/state-ta" >/dev/null 2>&1
check "domain у чужого вида выхода отвергается" "2" "$?"

# Что поднимать — спрашивают у движка, вместе с номером очереди и файлом ключей.
zi="$("$BIN" zapret-instances --spec "$tmp/zap.json" --state-dir "$tmp/state-z" 2>&1)"
check "zapret-instances: код 0, когда поднимать есть что" "0" "$?"
check "по строке на выход" "2" "$(printf '%s\n' "$zi" | grep -c .)"
check "номер очереди печатает движок" "1" \
    "$(printf '%s\n' "$zi" | grep -c "^yt	8300	/etc/steer/zapret/yt.opts$")"
"$BIN" zapret-instances --spec "$tmp/spec.json" --state-dir "$tmp/state-z" >/dev/null 2>&1
check "zapret-instances: код 1, когда таких выходов нет" "1" "$?"

if [ -f "$init" ]; then
    # Номер очереди init-скрипт БЕРЁТ У ДВИЖКА, а не считает сам: второй источник правды о
    # том, какой процесс какой трафик разбирает, разошёлся бы молча — процесс встал бы на
    # очередь, в которую ядро ничего не отдаёт.
    check "init-скрипт спрашивает выходы zapret у движка" "1" \
        "$(grep -c '^[^#]*steer zapret-instances' "$init")"
    check "init-скрипт не считает номер очереди сам" "0" \
        "$(grep -c '^[^#]*8300' "$init")"
    # Описание экземпляра НЕЛЬЗЯ собирать в подоболочке: procd_open_instance накапливает его
    # в переменных оболочки, и из подоболочки оно не возвращается никуда — ни одного
    # поднятого обработчика при полностью исправном на вид скрипте.
    check "экземпляры не открываются в конвейере" "0" \
        "$(grep -c '|[[:space:]]*while.*read.*zname' "$init")"
    # Ключи стратегии читает ОБЁРТКА, а не init-скрипт: описание экземпляра procd
    # фиксируется в момент start_service, поэтому собранная в скрипте командная строка
    # означала бы, что смена стратегии требует перезапуска всего движка вместе с туннелями.
    check "обработчик поднимается обёрткой" "1" \
        "$(grep -c 'procd_set_param command /usr/sbin/steer-nfqws' "$init")"
    check "init-скрипт не собирает ключи сам" "0" \
        "$(grep -c 'dpi-desync-fwmark' "$init")"
    # И обратная сторона того же: должна быть команда, которая перечитывает стратегии, НЕ
    # трогая туннели. Без неё единственным способом применить другую стратегию остаётся
    # restart, а он роняет клиенты vless — то есть каждая проба стоит секунд без интернета.
    check "есть reload_zapret" "1" "$(grep -c '^reload_zapret()' "$init")"
    check "reload_zapret объявлен в EXTRA_COMMANDS" "1" \
        "$(grep -c '^EXTRA_COMMANDS=.*reload_zapret' "$init")"
    # Сигнал уходит ИМЕНОВАННЫМ экземплярам обхода, а не '*': звёздочка уже однажды убивала
    # туннели на каждое «Сохранить и применить» (см. reload_dnsd там же).
    check "reload_zapret не сигналит всем подряд" "0" \
        "$(sed -n '/^reload_zapret()/,/^}/p' "$init" | grep -c "procd_send_signal steer '\*'")"
fi

# Обёртка обработчика: она и есть то место, где файл стратегии превращается в аргументы.
wrap=files/usr/sbin/steer-nfqws
check "обёртка обработчика найдена" "1" "$([ -f "$wrap" ] && echo 1 || echo 0)"
if [ -f "$wrap" ]; then
    check "обёртка ставит метку своих пакетов" "1" \
        "$(grep -c 'dpi-desync-fwmark=0x60000000' "$wrap")"
    # Комментарии в файл ключей не едут: первая строка там — имя стратегии (так её отмечает
    # и Zapret Manager), и уехав в командную строку, она стала бы неизвестным ключом, на
    # котором nfqws отказывает целиком.
    check "обёртка пропускает строки-комментарии" "1" \
        "$(grep -cF 'case "$line" in' "$wrap")"
    check "обёртка отказывает без файла ключей" "1" \
        "$(grep -c 'файла стратегии' "$wrap")"
    # Обработчики — ДО apply: при on_fail=drop правило очереди стоит без bypass, то есть
    # пока процесса нет, помеченный трафик отбрасывается ядром.
    check "обработчики открываются раньше apply" "1" \
        "$([ "$(grep -n 'procd_open_instance "zapret_' "$init" | cut -d: -f1)" \
             -lt "$(grep -n '^[^#]*steer apply --spec' "$init" | head -1 | cut -d: -f1)" ] \
           && echo 1 || echo 0)"

    # А теперь ПОВЕДЕНИЕ, а не наличие строк: обёртка запускается с подставным nfqws (шов
    # NFQWS у неё для этого и есть) и предъявляет то, что дошло до командной строки.
    #
    # Файл без завершающего перевода строки — не выдумка стенда, а обычный след правки
    # руками: файл ключей объявлен «просто файлом», и его правят по ssh (splify2#17 — то же
    # про свои списки). `read` на последней строке без перевода возвращает ненулевой код,
    # УЖЕ ЗАПОЛНИВ переменную, поэтому цикл `while read` теряет её молча — и стратегия
    # работает без последнего ключа, а именно в нём обычно и стоит способ обхода. Этот
    # капкан в проекте уже срабатывал дважды на чтении запроса ubus (см. sub_info и
    # sub_quota в объекте rpcd splify2), поэтому проверяется, а не подразумевается.
    mkdir -p "$tmp/nfq"
    printf '#!/bin/sh\nprintf "%%s\\n" "$@" > "$OUT"\n' > "$tmp/nfq/nfqws"
    chmod +x "$tmp/nfq/nfqws"
    printf '#Стратегия\n--dpi-desync=fake\n--dpi-desync-ttl=6' > "$tmp/z.opts"
    OUT="$tmp/zargs" NFQWS="$tmp/nfq/nfqws" sh "$wrap" 8300 "$tmp/z.opts" 2>/dev/null
    check "обёртка не теряет последний ключ без перевода строки" "1" \
        "$(grep -cx -- '--dpi-desync-ttl=6' "$tmp/zargs" 2>/dev/null)"
    check "и имя стратегии в ключи не уезжает" "0" \
        "$(grep -c '^#' "$tmp/zargs" 2>/dev/null)"
    check "и номер очереди тот, что дали" "1" \
        "$(grep -cx -- '--qnum=8300' "$tmp/zargs" 2>/dev/null)"
fi

# ---- пустая спека законна ----------------------------------------------------
# Отказ на ней запирал настройку наглухо: чтобы завести канал, нужен выход, а сохранить
# выход без каналов движок не давал. Из такого тупика нельзя выйти изнутри интерфейса.
printf '{"schema":1,"outputs":{},"channels":[]}' > "$tmp/empty.json"
"$BIN" apply --dry-run --spec "$tmp/empty.json" --state-dir "$tmp/state-e" >"$tmp/eo" 2>&1
check "пустая спека компилируется" "0" "$?"
check "и даёт таблицу с пустой цепочкой" "1" "$(grep -c 'chain prerouting_mark' "$tmp/eo")"
check "без наборов" "0" "$(grep -c '    set ' "$tmp/eo")"

printf '{"schema":1,"outputs":{"vpn":{"kind":"interface","device":"wg0"}},"channels":[]}' > "$tmp/only.json"
"$BIN" apply --dry-run --spec "$tmp/only.json" --state-dir "$tmp/state-e" >/dev/null 2>&1
check "выходы без каналов — законное состояние" "0" "$?"

# ---- защита от конфигураций, отрезающих роутер -------------------------------
# Всё это компилируется и применяется без жалоб, а замечается как "роутер пропал".
# Отказать дешевле, чем объяснять, как чинить коробку, до которой не достучаться.
cat > "$tmp/all.json" <<EOF
{ "schema": 1, "outputs": { "o": { "kind": "interface", "device": "wg0" } },
  "channels": [ { "name": "все", "match": { "any": true }, "out": "o" } ] }
EOF
"$BIN" apply --dry-run --spec "$tmp/all.json" --state-dir "$tmp/state-g" >/dev/null 2>&1
check "канал any без списка отвергается" "2" "$?"

# ...но остаётся выразимым, когда это правда то, что нужно.
sed 's/"any": true/"any": true, "allow_all": true/' "$tmp/all.json" > "$tmp/allok.json"
"$BIN" apply --dry-run --spec "$tmp/allok.json" --state-dir "$tmp/state-g" >/dev/null 2>&1
check "с allow_all он проходит" "0" "$?"

sed 's/"device": "wg0"/"device": "br-lan"/' "$tmp/allok.json" > "$tmp/loop.json"
"$BIN" apply --dry-run --spec "$tmp/loop.json" --state-dir "$tmp/state-g" >/dev/null 2>&1
check "выход в локальный мост отвергается" "2" "$?"

sed 's/"device": "wg0"/"devices": ["wg0","wg0"]/' "$tmp/allok.json" > "$tmp/dup.json"
"$BIN" apply --dry-run --spec "$tmp/dup.json" --state-dir "$tmp/state-g" >/dev/null 2>&1
check "дубликат устройства отвергается" "2" "$?"

# Сообщение обязано называть виновника: "steer: " без текста — это отказ, из
# которого нельзя понять, что чинить.
msg="$("$BIN" apply --dry-run --spec "$tmp/loop.json" --state-dir "$tmp/state-g" 2>&1 | tail -1)"
check "и объясняет, что не так" "1" "$(printf '%s' "$msg" | grep -c 'br-lan')"

# ---- клиенты не только из br-lan (splify2#16) --------------------------------
# Роутер бывает выходной точкой не только для своего моста: у человека к домашним
# устройствам добавились хосты из Tailscale/ZeroTier, для которых он шлюз. Клиенты таких
# сетей выбираются ПО УСТРОЙСТВУ, а не по подсети, и это не стилистика: у tailscale0 адрес
# на роутере /32, то есть выведенная из него «подсеть» — сам роутер, и адресный способ здесь
# не работает в принципе.
# Выходов два, а не один: адресный и доменный канал в ОДИН выход для одних клиентов
# сливаются в одну группу (это отдельное свойство компилятора), и имена наборов зависели бы
# от порядка. Разными выходами группы гарантированно две — vpn_ip и geo_dom.
cat > "$tmp/lan.json" <<EOF
{ "schema": 1, "lan_devices": ["br-lan", "tailscale0", "ztrq4abcde"],
  "outputs": { "vpn": { "kind": "interface", "device": "wg0" },
               "geo": { "kind": "interface", "device": "tun0" } },
  "channels": [ { "name": "списки", "match": { "prefixes_files": ["$tmp/a.lst"] }, "out": "vpn" },
                { "name": "домены", "match": { "domains_files": ["$tmp/d.lst"] }, "out": "geo" } ] }
EOF
lout="$("$BIN" apply --dry-run --spec "$tmp/lan.json" --state-dir "$tmp/state-lan")"
check "правило канала висит на всех перечисленных устройствах" "1" \
    "$(printf '%s\n' "$lout" | grep 'steer:vpn_ip' |
       grep -c 'iifname { "br-lan", "tailscale0", "ztrq4abcde" }')"
# Встречный путь — это тот же клиент, но ПОЛУЧАТЕЛЬ: там устройство исходящее.
check "встречное правило висит на них же, но как oifname" "1" \
    "$(printf '%s\n' "$lout" | grep 'steer-down:vpn_ip' |
       grep -c 'oifname { "br-lan", "tailscale0", "ztrq4abcde" }')"
# Одно правило на оба семейства: пометки nfproto нет, потому что имя устройства одинаково
# верно и для IPv4, и для IPv6 — прежняя асимметрия (IPv4 по адресу, IPv6 по устройству)
# держалась только на том, что подсеть была единственным способом сказать «наши».
check "DNS заворачивается по устройствам одним правилом" "1" \
    "$(printf '%s\n' "$lout" |
       grep -c 'iifname { "br-lan", "tailscale0", "ztrq4abcde" } udp dport 53 counter redirect')"
check "и без пометки семейства" "0" \
    "$(printf '%s\n' "$lout" | grep 'udp dport 53' | grep -c 'nfproto')"
# Ровно одно правило на канал, а не два: «или» внутри правила nft не выражается, и добавлять
# второе значило бы менять смысл уже написанного from_default (см. отказ ниже).
check "правило у канала одно" "1" \
    "$(printf '%s\n' "$lout" | grep -c 'comment "steer:vpn_ip"')"

# Одиночная форма остаётся сокращением для списка из одного, и текст правила у неё прежний:
# без фигурных скобок, ровно так, как печатает сам nft.
cat > "$tmp/lan1.json" <<EOF
{ "schema": 1, "lan_device": "br-lan",
  "outputs": { "vpn": { "kind": "interface", "device": "wg0" } },
  "channels": [ { "name": "списки", "match": { "prefixes_files": ["$tmp/a.lst"] }, "out": "vpn" } ] }
EOF
l1="$("$BIN" apply --dry-run --spec "$tmp/lan1.json" --state-dir "$tmp/state-lan1")"
check "одно устройство печатается без скобок" "1" \
    "$(printf '%s\n' "$l1" | grep 'steer:vpn_ip' | grep -c 'iifname "br-lan" ip daddr')"

# Петля проверяется по ВСЕМУ списку: выход в tailscale0, с которого мы забираем клиентов,
# закольцуется ровно так же, как выход в br-lan, и отличать одно от другого нечем.
sed 's/"device": "wg0"/"device": "tailscale0"/' "$tmp/lan.json" > "$tmp/lanloop.json"
"$BIN" apply --dry-run --spec "$tmp/lanloop.json" --state-dir "$tmp/state-lan" >/dev/null 2>&1
check "выход в любое из локальных устройств отвергается" "2" "$?"

# Обе формы сразу — противоречие, а не обогащение: молча взять одну значило бы, что половина
# написанного человеком не действует, и понять это было бы нечем.
cat > "$tmp/lanboth.json" <<EOF
{ "schema": 1, "lan_device": "br-lan", "lan_devices": ["br-lan", "tailscale0"],
  "outputs": { "vpn": { "kind": "interface", "device": "wg0" } },
  "channels": [ { "name": "с", "match": { "prefixes_files": ["$tmp/a.lst"] }, "out": "vpn" } ] }
EOF
"$BIN" apply --dry-run --spec "$tmp/lanboth.json" --state-dir "$tmp/state-lan" >/dev/null 2>&1
check "lan_device и lan_devices вместе отвергаются" "2" "$?"

sed 's/"br-lan", "tailscale0", "ztrq4abcde"/"br-lan", "br-lan"/' "$tmp/lan.json" > "$tmp/landup.json"
"$BIN" apply --dry-run --spec "$tmp/landup.json" --state-dir "$tmp/state-lan" >/dev/null 2>&1
check "дубликат в списке устройств отвергается" "2" "$?"

sed 's/"br-lan", "tailscale0", "ztrq4abcde"/"br lan"/' "$tmp/lan.json" > "$tmp/lanbad.json"
"$BIN" apply --dry-run --spec "$tmp/lanbad.json" --state-dir "$tmp/state-lan" >/dev/null 2>&1
check "негодное имя устройства отвергается" "2" "$?"

# from_default вместе с НЕСКОЛЬКИМИ устройствами — отказ, и это главное решение всей правки.
# Взять только подсети значило бы, что человек добавил tailscale0 и ничего не изменилось.
# Взять и то, и другое — хуже: from_default пишут, чтобы клиентов ОГРАНИЧИТЬ (гостевая
# подсеть на том же мосту нарочно вне списка), и правило по iifname молча забрало бы её.
sed 's/"schema": 1,/"schema": 1, "from_default": ["192.168.1.0\/24"],/' "$tmp/lan.json" \
    > "$tmp/lanboth2.json"
"$BIN" apply --dry-run --spec "$tmp/lanboth2.json" --state-dir "$tmp/state-lan" >/dev/null 2>&1
check "from_default вместе с несколькими устройствами отвергается" "2" "$?"
msg="$("$BIN" apply --dry-run --spec "$tmp/lanboth2.json" --state-dir "$tmp/state-lan" 2>&1 | tail -1)"
check "и объясняет, что убрать" "1" "$(printf '%s' "$msg" | grep -c 'from_default')"

# ...а с ОДНИМ устройством — законно и значит ровно то, что значило: так написаны все спеки,
# сделанные до появления перечня, и ломать их нельзя.
sed 's/"schema": 1,/"schema": 1, "from_default": ["192.168.1.0\/24"],/' "$tmp/lan1.json" \
    > "$tmp/lanold.json"
lold="$("$BIN" apply --dry-run --spec "$tmp/lanold.json" --state-dir "$tmp/state-lan")"
check "старая форма (подсети плюс один мост) работает как раньше" "1" \
    "$(printf '%s\n' "$lold" | grep 'steer:vpn_ip' | grep -c 'ip saddr { 192.168.1.0/24 }')"

# ---- failover ----------------------------------------------------------------
# devices — это приоритет, и единственное число остаётся сокращением для одного,
# чтобы прежние спеки не сломались.
cat > "$tmp/fo.json" <<EOF
{ "schema": 1,
  "outputs": { "o": { "kind": "interface", "devices": ["wg0", "wg1"], "on_fail": "drop" } },
  "channels": [ { "name": "c", "match": { "domains_files": ["$tmp/d.lst"] }, "out": "o" } ] }
EOF
"$BIN" apply --dry-run --spec "$tmp/fo.json" --state-dir "$tmp/state-f" >/dev/null 2>&1
check "список устройств принимается" "0" "$?"

sed 's/"on_fail": "drop"/"on_fail": "чепуха"/' "$tmp/fo.json" > "$tmp/fobad.json"
"$BIN" apply --dry-run --spec "$tmp/fobad.json" --state-dir "$tmp/state-f" >/dev/null 2>&1
check "неизвестный on_fail отвергается" "2" "$?"

# ---- refusals ---------------------------------------------------------------
# Guessing at an unknown schema would mean compiling a config we do not understand
# into firewall rules.
#
# Число здесь ТРОЙКА, а не двойка: двойку движок теперь понимает (см. раздел про порты
# ниже). Смысл проверки от этого не изменился — стеречь она обязана не конкретное число, а
# отказ на major, которого сборка не знает.
sed 's/"schema": 1/"schema": 3/' "$tmp/spec.json" > "$tmp/s2.json"
"$BIN" apply --dry-run --spec "$tmp/s2.json" $S >/dev/null 2>&1
check "refuses an unknown schema" "2" "$?"

sed 's/"out": "vpn"/"out": "nope"/' "$tmp/spec.json" > "$tmp/s3.json"
"$BIN" apply --dry-run --spec "$tmp/s3.json" $S >/dev/null 2>&1
check "refuses a channel pointing at a missing output" "2" "$?"

sed 's/"kind": "interface", "device": "wg0"/"kind": "interface"/' "$tmp/spec.json" > "$tmp/s4.json"
"$BIN" apply --dry-run --spec "$tmp/s4.json" $S >/dev/null 2>&1
check "refuses an interface output with no device" "2" "$?"

# An address from the command line reaches an nft invocation. This used to go
# through system(), which made `explain '$(...)'` a command-injection hole.
"$BIN" explain '$(id)' --spec "$tmp/spec.json" $S >/dev/null 2>&1
check "refuses an address that is not address-shaped" "2" "$?"

# ---- registry ----------------------------------------------------------------
# An output must keep its mark across runs: a reshuffle leaves stale `ip rule`
# entries pointing at the wrong table, and traffic silently takes another path.
before="$(cat "$tmp/state/registry")"
sed 's|"vpn":    { "kind": "interface", "device": "wg0" }|"vpn": { "kind": "interface", "device": "wg0" }, "extra": { "kind": "interface", "device": "wg1" }|' \
    "$tmp/spec.json" > "$tmp/s5.json"
"$BIN" apply --dry-run --spec "$tmp/s5.json" $S >/dev/null 2>&1
check "adding an output keeps the existing marks" "$before" \
    "$(grep -v '^extra ' "$tmp/state/registry")"
check "and gives the new one its own" "1" \
    "$(grep -c '^extra ' "$tmp/state/registry")"

# ---- пропавший список канала не рушит ВЕСЬ набор правил -----------------------
# Так выглядит роутер после обновления образа: спека выжила (она в keep.d), а каталог
# списков нет — он в архив не берётся намеренно, это решение владельца (splicicd#6): десятки
# файлов и сотни килобайт, а списки восстанавливаются по расписанию. Обоснование опиралось
# на «отсутствующий список не мешает применению», и это оказалось неверно: apply умирал на
# первом же непрочитанном файле (код возврата 2), таблицы не появлялось вовсе, и весь трафик
# роутера шёл напрямую — включая каналы, чьи списки были на месте (I-136).
#
# Правильное поведение: пропавший список убирает из набора СВОИ адреса и ничего больше.
# Канал при этом обязан остаться в наборе правил ПУСТЫМ, а не исчезнуть: правило без
# `ip daddr @набор` — это «весь трафик этих клиентов в туннель», то есть пропавший список
# молча превратил бы узкий канал в полный туннель.
printf '198.51.100.5\n' > "$tmp/keep2.lst"
spec <<'EOF'
{ "schema": 1,
  "from_default": ["192.168.1.0/24"],
  "outputs": {
    "direct": { "kind": "direct" },
    "vpn":    { "kind": "interface", "device": "wg0" }
  },
  "channels": [
    { "name": "цел",    "match": { "prefixes_file": "TMP/keep2.lst" }, "out": "direct" },
    { "name": "пропал", "match": { "prefixes_file": "TMP/gone.lst" },  "out": "vpn" }
  ] }
EOF
gout="$("$BIN" apply --dry-run --spec "$tmp/spec.json" --state-dir "$tmp/state-gone" 2>"$tmp/gerr")"
check "пропавший список: apply не умирает" "0" "$?"
check "пропавший список: назван в предупреждении" "1" \
    "$(grep -c 'gone.lst' "$tmp/gerr")"
check "пропавший список: уцелевший канал на месте" "1" \
    "$(printf '%s\n' "$gout" | grep -c 'elements = { 198.51.100.5 }')"
check "пропавший список: его канал остался ПУСТЫМ, а не исчез" "1" \
    "$(printf '%s\n' "$gout" | grep -c 'ip daddr @vpn_ip')"
check "пропавший список: правило не стало безусловным" "0" \
    "$(printf '%s\n' "$gout" | grep 'steer:vpn_ip' | grep -vc 'ip daddr')"
check "пропавший список: набор объявлен" "1" \
    "$(printf '%s\n' "$gout" | grep -c 'set vpn_ip {')"

# Второй случай: у канала два списка, один пропал. Уцелевший обязан доехать — иначе правка
# лечила бы «весь роутер напрямую» ценой «канал молча стал пустым».
printf '203.0.113.0/24\n' > "$tmp/half.lst"
spec <<'EOF'
{ "schema": 1,
  "from_default": ["192.168.1.0/24"],
  "outputs": { "vpn": { "kind": "interface", "device": "wg0" } },
  "channels": [
    { "name": "две половины",
      "match": { "prefixes_files": ["TMP/half.lst", "TMP/gone.lst"] }, "out": "vpn" }
  ] }
EOF
hout="$("$BIN" apply --dry-run --spec "$tmp/spec.json" --state-dir "$tmp/state-half" 2>/dev/null)"
check "один из двух списков пропал: уцелевший доехал" "1" \
    "$(printf '%s\n' "$hout" | grep -c 'elements = { 203.0.113.0/24 }')"

# ---- schema 2: у канала появилось измерение «протокол и порты» ---------------
#
# ЗАЧЕМ ЭТО ВООБЩЕ. Списки itdoginfo/allow-domains публикуются двоичными `.srs`, и из 25
# файлов релиза 24 разбираются, а `discord.srs` отвергается с кодом 2: он описывает не
# домены, а `network: udp` плюс `ip_cidr 104.16.0.0/12` плюс `port_range 50000:65535,
# 19000:20000`. Взять его подсети и отбросить порты нельзя — 104.16.0.0/12 это Cloudflare,
# и весь TCP к нему уехал бы в туннель молча.
#
# ЗАЧЕМ ЧИСЛО СХЕМЫ, А НЕ ПРОСТО НОВЫЙ КЛЮЧ. Неизвестный КЛЮЧ старый движок пропускает
# (js_skip в spec.c), и это правильно для всего, что совпадение РАСШИРЯЕТ: не понял —
# ничего не потерял. Порты совпадение СУЖАЮТ, и пропущенный ключ означает «сузить забыли»
# — то есть ровно тот молчаливый весь-TCP-в-туннель, от которого мы отказывались в srs.c.
# Поэтому major поднят: старый движок обязан отвергнуть спеку ЦЕЛИКОМ (exit 2), а не понять
# её наполовину. Управляющий слой это переживает: spec_set проверяет спеку через
# `apply --dry-run` ДО записи на диск, видит код 2 и говорит человеку «обновите движок».

# Схема 2 сама по себе не меняет НИЧЕГО: та же спека с другим числом обязана дать
# побайтово тот же набор правил. Иначе поднятие major стало бы вторым изменением поведения,
# спрятанным за первым.
spec <<'EOF'
{ "schema": 1,
  "from_default": ["192.168.1.0/24"],
  "outputs": {
    "direct": { "kind": "direct" },
    "vpn":    { "kind": "interface", "device": "wg0" }
  },
  "channels": [
    { "name": "keep",    "match": { "prefixes_file": "TMP/b.lst" }, "out": "direct" },
    { "name": "blocked", "match": { "prefixes_file": "TMP/a.lst" }, "out": "vpn" }
  ] }
EOF
cp "$tmp/spec.json" "$tmp/v1.json"
sed 's/"schema": 1/"schema": 2/' "$tmp/v1.json" > "$tmp/v2.json"
o1="$("$BIN" apply --dry-run --spec "$tmp/v1.json" --state-dir "$tmp/st-v1" 2>/dev/null)"
o2="$("$BIN" apply --dry-run --spec "$tmp/v2.json" --state-dir "$tmp/st-v2" 2>/dev/null)"
check "схема 2 принимается" "0" \
    "$("$BIN" apply --dry-run --spec "$tmp/v2.json" --state-dir "$tmp/st-v2" >/dev/null 2>&1; echo $?)"
check "схема 2 без новых полей даёт тот же набор правил" "$o1" "$o2"

# Канал Discord: подсети плюс udp плюс два диапазона портов.
printf '104.16.0.0/12\n' > "$tmp/dc.lst"
spec <<'EOF'
{ "schema": 2,
  "from_default": ["192.168.1.0/24"],
  "outputs": { "vpn": { "kind": "interface", "device": "wg0" } },
  "channels": [
    { "name": "discord", "out": "vpn",
      "match": { "prefixes_files": ["TMP/dc.lst"],
                 "proto": "udp", "ports": ["50000-65535", "19000-20000"] } }
  ] }
EOF
dout="$("$BIN" apply --dry-run --spec "$tmp/spec.json" --state-dir "$tmp/st-dc" 2>/dev/null)"
check "канал с портами компилируется" "0" "$?"
# ОДНО правило, а не два: «tcp или udp» внутри правила nft не выражается, и если бы
# протокол печатался словом `tcp dport`/`udp dport`, смесь пришлось бы разбивать на два
# правила — с двумя счётчиками и с порядком, который спекой уже не читается. Поэтому
# `meta l4proto` плюс `th dport`: одна форма и для одного протокола, и для двух.
check "ограничение попало в правило разметки" "1" \
    "$(printf '%s\n' "$dout" | grep -c 'meta l4proto udp th dport { 50000-65535, 19000-20000 }')"
check "правило у канала по-прежнему одно" "1" \
    "$(printf '%s\n' "$dout" | grep -c 'steer:vpn_ip_c0_p1"')"
# `th dport` НИКОГДА не печатается без `meta l4proto` перед ним, и это не стиль. `th` —
# это смещение в транспортном заголовке: у протокола без портов (icmp, esp, gre) по этому
# смещению лежат чужие байты, и правило совпало бы на них. Протокол сужает раньше, чем
# читается порт.
check "порты без указания протокола не печатаются" "0" \
    "$(printf '%s\n' "$dout" | grep 'th dport' | grep -vc 'meta l4proto')"
# Встречный путь: клиент — ПОЛУЧАТЕЛЬ, значит порт сервера здесь исходящий. Без зеркала
# счётчик скачанного считал бы и тот TCP, который правило разметки не берёт, — то есть
# врал бы ровно на ту величину, ради которой заведены порты.
check "встречная цепочка зеркалит порты как sport" "1" \
    "$(printf '%s\n' "$dout" | grep -c 'meta l4proto udp th sport { 50000-65535, 19000-20000 }')"
# Набор адресов остался обычным: порты — свойство ПРАВИЛА, а не элементов набора.
check "набор канала на месте" "1" \
    "$(printf '%s\n' "$dout" | grep -c 'elements = { 104.16.0.0/12 }')"

# Протокол без портов — законное сужение («весь UDP к этим адресам»), и `th` тогда не
# печатается вовсе.
spec <<'EOF'
{ "schema": 2,
  "from_default": ["192.168.1.0/24"],
  "outputs": { "vpn": { "kind": "interface", "device": "wg0" } },
  "channels": [
    { "name": "quic", "out": "vpn",
      "match": { "prefixes_files": ["TMP/dc.lst"], "proto": "udp" } }
  ] }
EOF
pout="$("$BIN" apply --dry-run --spec "$tmp/spec.json" --state-dir "$tmp/st-p" 2>/dev/null)"
# Сужение стоит ПЕРЕД поиском по набору: сравнение одного байта протокола дешевле поиска в
# наборе, и для канала «только UDP» оно отбрасывает весь TCP роутера до поиска, а не после.
check "протокол без портов: сужение по протоколу есть" "1" \
    "$(printf '%s\n' "$pout" | grep -c 'meta l4proto udp ip daddr @vpn_ip_c0_p1 meta mark set')"
check "протокол без портов: порты не выдуманы" "0" \
    "$(printf '%s\n' "$pout" | grep -c 'th dport')"

# Порты без протокола — «и TCP, и UDP на этих портах». Одним правилом, потому что
# `meta l4proto { tcp, udp }` это множество, а не «или».
spec <<'EOF'
{ "schema": 2,
  "from_default": ["192.168.1.0/24"],
  "outputs": { "vpn": { "kind": "interface", "device": "wg0" } },
  "channels": [
    { "name": "web", "out": "vpn",
      "match": { "prefixes_files": ["TMP/dc.lst"], "ports": ["443"] } }
  ] }
EOF
wout="$("$BIN" apply --dry-run --spec "$tmp/spec.json" --state-dir "$tmp/st-w" 2>/dev/null)"
check "порты без протокола: оба протокола одним правилом" "1" \
    "$(printf '%s\n' "$wout" | grep -c 'meta l4proto { tcp, udp } th dport 443')"
# Один порт печатается без фигурных скобок — так же, как одно устройство в emit_ifs, и по
# той же причине: так это печатает сам nft.
check "один порт печатается без скобок" "0" \
    "$(printf '%s\n' "$wout" | grep -c 'th dport { 443 }')"
# Явное «both» — это ЗАПИСАННОЕ умолчание, а не третье поведение: сужения по протоколу из
# него не выходит, только носитель для портов.
sed 's/"ports": \["443"\]/"proto": "both", "ports": ["443"]/' "$tmp/spec.json" > "$tmp/both.json"
bout="$("$BIN" apply --dry-run --spec "$tmp/both.json" --state-dir "$tmp/st-b" 2>/dev/null)"
check "proto both значит то же, что отсутствие proto" "$wout" "$bout"

# ---- поля схемы 2 в спеке schema 1 — ОТКАЗ, а не молчаливый пропуск ----------
# Молчаливый пропуск здесь и есть та самая беда: человек написал порты, движок их не
# понял, канал забрал весь трафик к Cloudflare, и сказать об этом было бы нечем.
spec <<'EOF'
{ "schema": 1,
  "from_default": ["192.168.1.0/24"],
  "outputs": { "vpn": { "kind": "interface", "device": "wg0" } },
  "channels": [
    { "name": "discord", "out": "vpn",
      "match": { "prefixes_files": ["TMP/dc.lst"], "proto": "udp", "ports": ["50000-65535"] } }
  ] }
EOF
msg="$("$BIN" apply --dry-run --spec "$tmp/spec.json" --state-dir "$tmp/st-o" 2>&1 >/dev/null)"
check "поля схемы 2 при schema 1 отвергаются" "2" \
    "$("$BIN" apply --dry-run --spec "$tmp/spec.json" --state-dir "$tmp/st-o" >/dev/null 2>&1; echo $?)"
check "и сказано, что поднять" "1" "$(printf '%s' "$msg" | grep -c 'schema')"
check "и назван канал" "1" "$(printf '%s' "$msg" | grep -c 'discord')"

# ---- порты БЕЗ списка адресов — это недописанная настройка -------------------
# «Канал ловит по портам» выразить нечем и не нужно: без списка адресов правило накрыло бы
# весь трафик клиентов на этих портах. Проверка «matches nothing» обязана остаться в силе —
# новые поля источником совпадения не являются.
spec <<'EOF'
{ "schema": 2,
  "from_default": ["192.168.1.0/24"],
  "outputs": { "vpn": { "kind": "interface", "device": "wg0" } },
  "channels": [
    { "name": "только порты", "out": "vpn",
      "match": { "proto": "udp", "ports": ["50000-65535"] } }
  ] }
EOF
nmsg="$("$BIN" apply --dry-run --spec "$tmp/spec.json" --state-dir "$tmp/st-n" 2>&1 >/dev/null)"
check "порты без списка: отказ" "2" \
    "$("$BIN" apply --dry-run --spec "$tmp/spec.json" --state-dir "$tmp/st-n" >/dev/null 2>&1; echo $?)"
check "порты без списка: отказ тот же, что был" "1" \
    "$(printf '%s' "$nmsg" | grep -c 'matches nothing')"

# ---- каналы с РАЗНЫМИ портами не сливаются в одну группу ---------------------
# Слияние здесь было бы молчаливой потерей смысла в обе стороны сразу: набор один, а
# правило одно, и ограничение по портам либо распространилось бы на чужие адреса (сузили
# то, чего не просили), либо пропало бы вовсе (весь TCP к Cloudflare в туннель). Поэтому
# протокол и порты входят в ключ слияния наравне с выходом и списком клиентов.
#
# Имя набора при этом обязано РАЗОЙТИСЬ: ядро сливает одноимённые наборы молча, и без
# различителя два канала одного выхода делили бы один набор адресов (см. from_disc в
# spec.c — та же беда и то же лечение).
spec <<'EOF'
{ "schema": 2,
  "from_default": ["192.168.1.0/24"],
  "outputs": { "vpn": { "kind": "interface", "device": "wg0" } },
  "channels": [
    { "name": "youtube", "out": "vpn", "match": { "prefixes_files": ["TMP/a.lst"] } },
    { "name": "discord", "out": "vpn",
      "match": { "prefixes_files": ["TMP/dc.lst"], "proto": "udp", "ports": ["50000-65535"] } }
  ] }
EOF
sout="$("$BIN" apply --dry-run --spec "$tmp/spec.json" --state-dir "$tmp/st-s" 2>/dev/null)"
check "канал без портов сохранил прежнее имя набора" "1" \
    "$(printf '%s\n' "$sout" | grep -c 'set vpn_ip {')"
check "канал с портами получил свой набор" "1" \
    "$(printf '%s\n' "$sout" | grep -c 'set vpn_ip_c0_p1 {')"
check "правил стало два" "2" \
    "$(printf '%s\n' "$sout" | grep -c 'steer:vpn_ip')"
check "адреса не перемешались" "1" \
    "$(printf '%s\n' "$sout" | grep -c 'elements = { 104.16.0.0/12 }')"
check "ограничение стоит только у своего правила" "1" \
    "$(printf '%s\n' "$sout" | grep -c 'th dport')"

# ...а каналы с ОДИНАКОВЫМ сужением сливаются, как сливались всегда: иначе предел в 64
# канала расходовался бы на то, что для ядра одно и то же правило.
spec <<'EOF'
{ "schema": 2,
  "from_default": ["192.168.1.0/24"],
  "outputs": { "vpn": { "kind": "interface", "device": "wg0" } },
  "channels": [
    { "name": "dc1", "out": "vpn",
      "match": { "prefixes_files": ["TMP/a.lst"], "proto": "udp", "ports": ["50000-65535"] } },
    { "name": "dc2", "out": "vpn",
      "match": { "prefixes_files": ["TMP/dc.lst"], "proto": "udp", "ports": ["50000-65535"] } }
  ] }
EOF
mout="$("$BIN" apply --dry-run --spec "$tmp/spec.json" --state-dir "$tmp/st-m" 2>/dev/null)"
check "одинаковое сужение: правило одно" "1" \
    "$(printf '%s\n' "$mout" | grep -c 'steer:vpn_ip_c0_p1"')"
check "одинаковое сужение: набор один и общий" "1" \
    "$(printf '%s\n' "$mout" | grep -c 'elements = { 203.0.113.0/24, 198.51.100.5, 104.16.0.0/12 }')"

# ---- негодные записи портов отвергаются громко ------------------------------
# Не педантизм: `nft -f` отвергает НАБОР ПРАВИЛ ЦЕЛИКОМ на одном плохом элементе, и тогда
# на роутере остаются прежние правила, а человек видит, что его выбор не подействовал, без
# единого намёка на причину. Тот же довод, что у check_address_lists в steer.c.
portspec() {
    sed "s|PORTS|$1|" > "$tmp/pp.json" <<EOF
{ "schema": 2,
  "from_default": ["192.168.1.0/24"],
  "outputs": { "vpn": { "kind": "interface", "device": "wg0" } },
  "channels": [
    { "name": "p", "out": "vpn",
      "match": { "prefixes_files": ["$tmp/dc.lst"], "ports": PORTS } }
  ] }
EOF
    "$BIN" apply --dry-run --spec "$tmp/pp.json" --state-dir "$tmp/st-pp" >/dev/null 2>&1
    echo $?
}
check "порт 0 отвергается"                    "2" "$(portspec '["0"]')"
check "порт 65536 отвергается"                "2" "$(portspec '["65536"]')"
check "перевёрнутый диапазон отвергается"     "2" "$(portspec '["9-1"]')"
check "не число отвергается"                  "2" "$(portspec '["abc"]')"
check "двоеточие вместо тире отвергается"     "2" "$(portspec '["50000:65535"]')"
check "пустая строка отвергается"             "2" "$(portspec '[""]')"
check "число вместо строки отвергается"       "2" "$(portspec '[443]')"
check "висящая запятая отвергается"           "2" "$(portspec '["443",]')"
# Пересечение и повтор — тоже отказ, и по той же причине, что негодная запись: nft не
# принимает множество с накладывающимися интервалами и отвергает весь набор правил.
check "повтор диапазона отвергается"          "2" "$(portspec '["443", "443"]')"
check "пересечение диапазонов отвергается"    "2" "$(portspec '["1-100", "50-60"]')"
check "соседние диапазоны законны"            "0" "$(portspec '["1-100", "101-200"]')"
# Неизвестный протокол — отказ: угадать, что имел в виду человек, значит однажды не сузить
# там, где он считает, что сузил.
protospec() {
    sed "s|PROTO|$1|" > "$tmp/pr.json" <<EOF
{ "schema": 2,
  "from_default": ["192.168.1.0/24"],
  "outputs": { "vpn": { "kind": "interface", "device": "wg0" } },
  "channels": [
    { "name": "p", "out": "vpn",
      "match": { "prefixes_files": ["$tmp/dc.lst"], "proto": "PROTO" } }
  ] }
EOF
    "$BIN" apply --dry-run --spec "$tmp/pr.json" --state-dir "$tmp/st-pr" >/dev/null 2>&1
    echo $?
}
check "неизвестный proto отвергается" "2" "$(protospec sctp)"
check "proto tcp принимается"         "0" "$(protospec tcp)"

# ---- explain не переоценивает совпадение ------------------------------------
# Адрес лежит в наборе — но канал сужен по портам, и «идёт в туннель» верно не для всего
# его трафика. Прежний ответ был бы правдой лишь наполовину, а по нему настраивают.
spec <<'EOF'
{ "schema": 2,
  "from_default": ["192.168.1.0/24"],
  "outputs": { "vpn": { "kind": "interface", "device": "wg0" } },
  "channels": [
    { "name": "весь udp", "out": "vpn",
      "match": { "any": true, "allow_all": true, "proto": "udp", "ports": ["50000-65535"] } }
  ] }
EOF
eout="$("$BIN" explain 104.16.0.1 --spec "$tmp/spec.json" --state-dir "$tmp/st-e" 2>/dev/null)"
check "explain называет сужение канала" "1" \
    "$(printf '%s\n' "$eout" | grep -c 'udp 50000-65535')"

printf '\n%s passed, %s failed\n' "$pass" "$fail"
[ "$fail" -eq 0 ]

