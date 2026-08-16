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
#
# Локальная переменная называется outdef, а НЕ out. Раньше здесь было `out`, то есть то же
# имя, в котором ниже лежит отчёт diag: вызов `spec vless vless` затирал отчёт интерфейсного
# выхода куском JSON, и две проверки после него сравнивали пустоту с пустотой, а «у vless
# проверок больше» превращалось в «4 больше 0» — истинное при любом поведении движка.
spec() {
    if [ "$2" = "vless" ]; then
        outdef='"vpn": { "kind": "vless", "sub_file": "/etc/steer/sub.json", "on_fail": "drop" }'
    else
        outdef='"vpn": { "kind": "interface", "devices": ["wg0"], "on_fail": "drop" }'
    fi
    cat > "$tmp/$1.json" <<EOF
{
  "schema": 1,
  "lan_device": "br-lan",
  "from_default": ["192.168.1.0/24"],
  "outputs": { $outdef, "direct": { "kind": "direct" } },
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

# ---- UDP через VLESS: заметки БОЛЬШЕ НЕТ (I-026 снят) ------------------------
# Прежде здесь проверялось, что движок говорит «выход VLESS несёт только TCP». Туннель
# теперь несёт UDP командой VLESS 2 (QUIC, WireGuard, игры), и заметка убрана: сообщение о
# снятом ограничении хуже молчания — по нему уходят настраивать обход, которого не нужно.
#
# Проверка осталась, но с обратным ожиданием: пусто. Так поломка «заметку вернули вместе с
# копипастой» будет видна сразу.
spec vless vless
outv="$($DIAG diag --spec "$tmp/vless.json" 2>/dev/null)"
check "выход vless: про UDP молчим (UDP поддержан)" "" "$(printf '%s' "$outv" | verdict udp)"
check "выход interface: про UDP молчим" "" "$(printf '%s' "$out" | verdict udp)"

# ---- публичный резолвер внутри списка канала (I-030) ------------------------
# Категории издателя собираются по ASN целиком, поэтому 8.8.8.0/24 (Google Public DNS)
# лежит внутри «YouTube» и «Google», а 1.1.1.0/24 — внутри «Cloudflare». Уйдя в туннель
# VLESS, запросы к такому резолверу теперь ПРОХОДЯТ — но у UDP поток к узлу свой на каждую
# пару адрес-порт, а DNS берёт новый порт на каждый запрос: имя разрешается ценой отдельного
# рукопожатия с узлом. Поэтому заметка осталась, а приговор стал мягче.
echo '1.1.1.0/24' >> "$tmp/cf.lst"
outr="$($DIAG diag --spec "$tmp/vless.json" 2>/dev/null)"
check "резолвер в списке: сказано" "note" "$(printf '%s' "$outr" | verdict resolver)"
check "назван сам адрес" "1" \
      "$(printf '%s' "$outr" | grep -c '1\.1\.1\.0/24' || true)"
# Приговор note, а не warn: имена разрешаются, поломки нет — а warn на постоянном условии
# красит исправный роутер в жёлтый навсегда (та же причина, что у doh).
check "note не идёт в счётчик warn" "0" "$(printf '%s' "$outr" | sed -n 's/.*"warn":\([0-9]*\).*/\1/p')"

# Выход-устройство несёт UDP ядром, своих потоков к узлу там нет — говорить не о чем.
outri="$($DIAG diag --spec "$tmp/iface.json" 2>/dev/null)"
check "выход interface: про резолвер молчим" "" "$(printf '%s' "$outri" | verdict resolver)"

# С доменными правилами есть перенаправление DNS, и цену платят только клиенты вне
# from_default. Приговор тот же note, но текст другой — проверяем, что он про перенаправление.
echo 'example.com' > "$tmp/dom.lst"
sed 's#"prefixes_files": \["'"$tmp"'/cf.lst"\]#"prefixes_files": ["'"$tmp"'/cf.lst"], "domains_files": ["'"$tmp"'/dom.lst"]#' \
    "$tmp/vless.json" > "$tmp/vless-dom.json"
outrd="$($DIAG diag --spec "$tmp/vless-dom.json" 2>/dev/null)"
check "есть редирект DNS: он и назван" "1" \
      "$(printf '%s' "$outrd" | grep -c 'from_default прикрывает' || true)"

# Список без резолверов — молчим: иначе метка станет постоянной.
grep -v '^1\.1\.1\.0/24$' "$tmp/cf.lst" > "$tmp/cf-clean.lst"
sed "s#$tmp/cf.lst#$tmp/cf-clean.lst#" "$tmp/vless.json" > "$tmp/vless-clean.json"
outrc="$($DIAG diag --spec "$tmp/vless-clean.json" 2>/dev/null)"
check "список без резолверов: молчим" "" "$(printf '%s' "$outrc" | verdict resolver)"

# ---- отчёт остаётся разбираемым --------------------------------------------
# Здесь стояло «проверок с vless больше, чем без него». Лишней у vless была ровно заметка
# про UDP, и когда её убрали (I-026, см. выше), утверждение стало неверным — но заметить
# это было нельзя: переменная с отчётом интерфейсного выхода затиралась вызовом spec(), и
# сравнение вырождалось в «4 больше 0», истинное всегда.
#
# Проверяется то, что осталось правдой: отчёт разбираем для обоих видов выхода, и состав
# проверок у них ОДИНАКОВ — то есть vless больше не порождает заметок про самого себя.
check "отчёт с vless разбираем" "1" \
      "$([ "$(printf '%s' "$outv" | count)" -gt 0 ] && echo 1 || echo 0)"
check "vless не добавляет своих заметок" \
      "$(printf '%s' "$out" | count)" "$(printf '%s' "$outv" | count)"

printf '\n%d проверок пройдено' "$pass"
if [ "$fail" -gt 0 ]; then printf ', %d ПРОВАЛЕНО\n' "$fail"; exit 1; fi
printf '\nвсе проверки прошли\n'
