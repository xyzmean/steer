#!/bin/sh
# Диагностика (`steer diag`) на фикстурах: без роутера, без nft, без сети.
#
# Почему стенд шелловый, а не на C. diag — единственная подкоманда, которая почти целиком
# состоит из обращений к системе: nft, pgrep, ip. Проверять её по функциям нечего, зато
# подменить эти три команды в PATH и посмотреть на JSON — ровно то, что делает человек,
# когда читает вывод diag на роутере. Тот же приём, что в splify2/tests/listsmatch.sh.
#
# Бинарник отдельный (build/diagsim): спека с `kind: vless` отвергается парсером базовой
# сборки, а именно VLESS-выход интересен диагностике — см. tests/vless-stub.c.
set -u
DIAG="${DIAG:-./build/diagsim}"
[ -x "$DIAG" ] || { echo "not built: $DIAG (make test)"; exit 2; }

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

# ---- окружение: nft/pgrep/ip подменены, всё остальное настоящее -------------
mkdir -p "$tmp/bin"
cat > "$tmp/bin/nft" <<'EOF'
#!/bin/sh
# Таблица на месте, встречная цепочка тоже: так проверки 1-2 дают ok и не шумят
# в выводе, а интересующие нас проверки остаются единственными находками.
echo "table inet steer {"
echo "  chain prerouting_mark { }"
echo "  chain postrouting_down { }"
echo "}"
EOF
# Резолвер не запущен и IPv6 наружу нет: обе проверки при этом молчат либо ругаются
# предсказуемо, а от них здесь ничего не зависит.
printf '#!/bin/sh\nexit 1\n' > "$tmp/bin/pgrep"
printf '#!/bin/sh\nexit 1\n' > "$tmp/bin/ip"
chmod +x "$tmp/bin/nft" "$tmp/bin/pgrep" "$tmp/bin/ip"
PATH="$tmp/bin:$PATH"
export PATH

# spec NAME KIND — конфигурация с одним адресным каналом в выход указанного вида.
spec() {
    if [ "$2" = "vless" ]; then
        out='"vpn": { "kind": "vless", "sub_file": "/etc/steer/sub.json", "on_fail": "drop" }'
    else
        out='"vpn": { "kind": "interface", "devices": ["wg0"], "on_fail": "drop" }'
    fi
    cat > "$tmp/$1.json" <<EOF
{
  "schema": 1,
  "lan_device": "br-lan",
  "from_default": ["192.168.1.0/24"],
  "outputs": { $out, "direct": { "kind": "direct" } },
  "channels": [
    { "name": "cloudflare", "match": { "prefixes_files": ["$tmp/cf.lst"] }, "out": "vpn" }
  ]
}
EOF
}
echo '104.16.0.0/13' > "$tmp/cf.lst"

# verdict ID < вывод diag — приговор проверки с данным id, пусто если проверки нет.
verdict() { sed -n "s/.*{\"id\":\"$1\",\"verdict\":\"\([a-z]*\)\".*/\1/p" | head -1; }
# count — сколько всего проверок в отчёте.
count() { tr ',' '\n' | grep -c '"id":'; }

# ---- отчёт вообще собирается ------------------------------------------------
spec iface interface
out="$($DIAG diag --spec "$tmp/iface.json" 2>/dev/null)"
check "отчёт начинается со schema" "1" "$(printf '%s' "$out" | sed -n 's/.*"schema":\([0-9]*\).*/\1/p')"
check "таблица найдена" "ok" "$(printf '%s' "$out" | verdict table)"
check "встречная цепочка найдена" "ok" "$(printf '%s' "$out" | verdict down_chain)"

# ---- UDP через VLESS (I-026) ------------------------------------------------
# Туннель VLESS несёт только TCP: UDP-пакет получает ICMP-отказ (src/ext/tun.c).
# Браузер после отказа берёт TCP, а WireGuard/WARP и игровой трафик через такой выход
# не заработают вовсе — и до этой проверки об этом не говорил никто: ни движок, ни UI.
spec vless vless
outv="$($DIAG diag --spec "$tmp/vless.json" 2>/dev/null)"
check "выход vless: сказано про UDP" "note" "$(printf '%s' "$outv" | verdict udp)"

# Приговор именно note: ограничение постоянное и верное всегда, а warn на постоянном
# условии красит исправный роутер в жёлтый навсегда — та же причина, что у doh.
check "note не идёт в счётчик warn" "0" "$(printf '%s' "$outv" | sed -n 's/.*"warn":\([0-9]*\).*/\1/p')"

# Выход-устройство несёт UDP как есть, и совет там был бы ложью.
check "выход interface: про UDP молчим" "" "$(printf '%s' "$out" | verdict udp)"

# Канал в выход vless обязателен: сам по себе неиспользуемый выход ничей трафик не
# ограничивает, и предупреждать не о чем.
sed 's/"out": "vpn"/"out": "direct"/' "$tmp/vless.json" > "$tmp/vless-unused.json"
outu="$($DIAG diag --spec "$tmp/vless-unused.json" 2>/dev/null)"
check "vless без каналов: про UDP молчим" "" "$(printf '%s' "$outu" | verdict udp)"

# ---- публичный резолвер внутри списка канала (I-030) ------------------------
# Категории издателя собираются по ASN целиком, поэтому 8.8.8.0/24 (Google Public DNS)
# лежит внутри «YouTube» и «Google», а 1.1.1.0/24 — внутри «Cloudflare». Уйдя в туннель
# VLESS, запрос к такому резолверу получает ICMP-отказ вместо ответа, и клиент, у которого
# этот резолвер прописан руками, остаётся без DNS вовсе.
echo '1.1.1.0/24' >> "$tmp/cf.lst"
outr="$($DIAG diag --spec "$tmp/vless.json" 2>/dev/null)"
check "резолвер в списке: сказано" "warn" "$(printf '%s' "$outr" | verdict resolver)"
check "назван сам адрес" "1" \
      "$(printf '%s' "$outr" | grep -c '1\.1\.1\.0/24' || true)"

# Выход-устройство несёт UDP как есть — резолвер в списке для него не проблема.
outri="$($DIAG diag --spec "$tmp/iface.json" 2>/dev/null)"
check "выход interface: про резолвер молчим" "" "$(printf '%s' "$outri" | verdict resolver)"

# Перенаправление DNS есть только при доменных правилах: тогда запросы клиентов из
# from_default до туннеля не доходят, и приговор смягчается до совета.
echo 'example.com' > "$tmp/dom.lst"
sed 's#"prefixes_files": \["'"$tmp"'/cf.lst"\]#"prefixes_files": ["'"$tmp"'/cf.lst"], "domains_files": ["'"$tmp"'/dom.lst"]#' \
    "$tmp/vless.json" > "$tmp/vless-dom.json"
outrd="$($DIAG diag --spec "$tmp/vless-dom.json" 2>/dev/null)"
check "есть редирект DNS: приговор мягче" "note" "$(printf '%s' "$outrd" | verdict resolver)"

# Список без резолверов — молчим: иначе метка станет постоянной.
grep -v '^1\.1\.1\.0/24$' "$tmp/cf.lst" > "$tmp/cf-clean.lst"
sed "s#$tmp/cf.lst#$tmp/cf-clean.lst#" "$tmp/vless.json" > "$tmp/vless-clean.json"
outrc="$($DIAG diag --spec "$tmp/vless-clean.json" 2>/dev/null)"
check "список без резолверов: молчим" "" "$(printf '%s' "$outrc" | verdict resolver)"

# ---- отчёт остаётся разбираемым --------------------------------------------
check "проверок в отчёте с vless больше, чем без него" "1" \
      "$([ "$(printf '%s' "$outv" | count)" -gt "$(printf '%s' "$out" | count)" ] && echo 1 || echo 0)"

printf '\n%d проверок пройдено' "$pass"
if [ "$fail" -gt 0 ]; then printf ', %d ПРОВАЛЕНО\n' "$fail"; exit 1; fi
printf '\nвсе проверки прошли\n'
