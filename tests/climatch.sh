#!/bin/sh
# Обвязка командной строки: справка, коды возврата и отказы на кривых аргументах.
#
# Зачем стенд. Разбор аргументов — единственная часть движка, с которой человек
# сталкивается раньше всего остального, и ошибка в нём молчалива по своей природе:
# неизвестный флаг, попавший в позиционный аргумент, не ломает ничего видимого — он
# просто делает не то, о чём просили. Именно так `steer apply --dryrun` применял
# правила по-настоящему. Проверяется поэтому не текст справки (он меняется), а
# контракт: что печатается в stdout, что в stderr и с каким кодом.
#
# Спека здесь нужна не всегда: почти все проверки падают на разборе аргументов раньше,
# чем движок доберётся до файла.
set -u
BIN="${STEER:-./build/steer}"
[ -x "$BIN" ] || { echo "not built: $BIN (make)"; exit 2; }

pass=0 fail=0
tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT

check() {
    if [ "$2" = "$3" ]; then
        pass=$((pass + 1))
    else
        fail=$((fail + 1))
        printf 'FAIL %s\n  ожидалось: %s\n  получено:  %s\n' "$1" "$2" "$3"
    fi
}

# code ИМЯ ОЖИДАЕМЫЙ_КОД -- команда...
code() {
    name="$1"; want="$2"; shift 3
    "$@" >/dev/null 2>&1
    check "$name" "$want" "$?"
}

# ---- справка отвечает нулём и печатает в stdout -----------------------------
# Код 2 и вывод в stderr — это поведение ОШИБКИ. Справка, запрошенная явно, ошибкой
# не является: `steer --help | less` на прежнем движке показывал пустую страницу,
# потому что весь текст уходил в stderr.
for form in --help -h help; do
    out="$("$BIN" $form 2>/dev/null)"
    code "$form: код 0" 0 -- "$BIN" $form
    check "$form: список команд в stdout" "1" "$(printf '%s' "$out" | grep -c '^  apply ')"
done

# Справка по команде — тремя способами, и все три дают один текст.
a="$("$BIN" help explain 2>/dev/null)"
b="$("$BIN" explain --help 2>/dev/null)"
c="$("$BIN" explain -h 2>/dev/null)"
check "help КОМАНДА и КОМАНДА --help совпадают" "$a" "$b"
check "КОМАНДА -h — то же самое" "$a" "$c"
check "справка по команде показывает синопсис" "1" \
    "$(printf '%s' "$a" | grep -c 'steer explain <адрес|имя>')"

# --help перехватывается и у команд со своим разбором аргументов, иначе они успели бы
# принять его за флаг и ответить своей ошибкой.
code "fit --help: код 0" 0 -- "$BIN" fit --help
check "fit --help: свои флаги на месте" "1" \
    "$("$BIN" fit --help 2>/dev/null | grep -c '^  --budget ')"
code "dnsd --help: код 0" 0 -- "$BIN" dnsd --help
check "dnsd --help: свои флаги на месте" "1" \
    "$("$BIN" dnsd --help 2>/dev/null | grep -c '^  --listen-port ')"

# ---- версия -----------------------------------------------------------------
check "version: называет версию из файла VERSION" "1" \
    "$("$BIN" --version 2>/dev/null | grep -c "^steer $(cat VERSION) ")"
check "version: словом и флагом одинаково" \
    "$("$BIN" version 2>/dev/null)" "$("$BIN" --version 2>/dev/null)"

# ---- ошибки: всё в stderr и код 2 -------------------------------------------
code "без команды — код 2" 2 -- "$BIN"
check "без команды — ни слова в stdout" "" "$("$BIN" 2>/dev/null)"
code "неизвестная команда — код 2" 2 -- "$BIN" nosuchthing
check "опечатка получает подсказку" "1" \
    "$("$BIN" aply 2>&1 >/dev/null | grep -c 'steer apply')"
# Порог подсказки: далёкое слово не должно уверенно советовать случайную команду.
check "далёкое слово подсказки не получает" "0" \
    "$("$BIN" nosuchthing 2>&1 >/dev/null | grep -c 'имелось в виду')"

# Главное, ради чего всё затевалось: опечатка во флаге — это отказ, а не тихое
# согласие. Прежний разбор клал --dryrun в позиционный аргумент, apply его не читал, и
# правила применялись НА САМОМ ДЕЛЕ вместо обещанного показа.
code "опечатка во флаге — отказ" 2 -- "$BIN" apply --dryrun
code "чужой флаг команде — отказ" 2 -- "$BIN" status --dry-run
code "флаг без значения — отказ" 2 -- "$BIN" apply --spec
code "значение, съеденное флагом, — отказ" 2 -- "$BIN" apply --spec --dry-run
code "лишний позиционный — отказ" 2 -- "$BIN" apply лишнее
code "не-число там, где ждали число" 2 -- "$BIN" vless-probe out --node abc
code "порт за пределами диапазона" 2 -- "$BIN" obfs-server --listen 99999 --forward 127.0.0.1:51820
code "флаг вместо команды — отказ" 2 -- "$BIN" --spec /etc/steer/spec.json apply
code "обязательный аргумент пропущен" 2 -- "$BIN" explain

# ---- разобранные значения доходят до команды --------------------------------
# Спека нарочно несуществующая: если --spec дошёл, движок жалуется именно на этот путь,
# а не на /etc/steer/spec.json. Так проверяется, что значение флага не потерялось.
check "--spec доходит до команды" "1" \
    "$("$BIN" apply --spec "$tmp/нет.json" 2>&1 >/dev/null | grep -c "$tmp/нет.json")"

cat > "$tmp/spec.json" <<'EOF'
{ "schema": 1,
  "from_default": ["192.168.1.0/24"],
  "outputs": { "direct": { "kind": "direct" }, "vpn": { "kind": "interface", "device": "wg0" } },
  "channels": [ { "name": "c", "match": { "any": true, "allow_all": true }, "out": "vpn" } ] }
EOF
S="--spec $tmp/spec.json --state-dir $tmp/state"
check "outputs без отбора" "direct
vpn" "$("$BIN" outputs $S 2>/dev/null)"
check "outputs --kind отбирает" "vpn" "$("$BIN" outputs $S --kind interface 2>/dev/null)"
# --state-dir принимается всеми командами, которые читают спеку: init-скрипт и стенды
# передают его не глядя, и «не понимает флаг» тут был бы регрессией.
for cmd in status diag outputs needs-dnsd; do
    "$BIN" $cmd $S >/dev/null 2>"$tmp/err"
    check "$cmd понимает --state-dir" "0" "$(grep -c 'не понимает флаг' "$tmp/err")"
done

# ---- таблица и диспетчер не разошлись ---------------------------------------
# Команда, объявленная в таблице и забытая в диспетчере, попадает в справку и не
# работает — самый обидный вид расхождения, ради устранения которого таблица и
# заводилась. Движок отвечает на такое отдельной строкой; здесь проверяется, что её
# не печатает ни одна команда из списка. Спека нарочно несуществующая: до неё доходят
# только те команды, которые действительно подключены.
# Имена берутся из разделов справки, а не из списка в этом файле: список пришлось бы
# дописывать руками при каждой новой команде, то есть ровно тогда, когда проверка
# нужнее всего. Строка под «Использование:» и раздел про саму справку пропускаются —
# steer, help и version командами таблицы не являются.
cmd_names() {
    "$BIN" help 2>/dev/null | awk '
        /^Использование:/       { skip = 1; next }
        /^Справка и версия:/    { exit }
        /^[^ ]/                 { skip = 0; next }
        skip                    { next }
        /^  [a-z]/              { print $1 }'
}
for name in $(cmd_names); do
    code "help $name отвечает нулём" 0 -- "$BIN" help "$name"
    out="$("$BIN" "$name" x --spec "$tmp/нет.json" 2>&1)"
    check "$name подключена к диспетчеру" "0" \
        "$(printf '%s' "$out" | grep -c 'не подключена')"
done

# ---- вызовы, которыми движок зовёт splify2 ----------------------------------
# Разбор аргументов — граница между двумя репозиториями, и ужесточать её можно только
# зная, что через неё ходит. Строки ниже взяты из splify2/files/usr/libexec/rpcd/splify2
# и splify2-update-lists; проверяется не результат, а то, что ни один из них не
# отвергнут разбором. Так уже ловилось `--node -1` — часовой «первый рабочий», который
# диапазон «с нуля» отверг бы, и проверка выхода в интерфейсе молча перестала бы
# работать.
# Проверяется КОД ВОЗВРАТА, а не текст ошибки. Первая версия считала вхождения четырёх
# русских фраз в stderr — то есть любая переформулировка сообщения в cli.c делала все
# проверки границы вечнозелёными, а именно они и стерегут совместимость с splify2.
# Разбор аргументов отвечает кодом 2; всё остальное (нет спеки, нет выхода, движок без
# VLESS) — это уже работа команды, и такие коды здесь законны.
accepted() { # ИМЯ -- команда...
    name="$1"; shift 2
    "$@" >/dev/null 2>&1
    rc=$?
    check "$name" "принят" "$([ "$rc" = 2 ] && echo "ОТВЕРГНУТ разбором" || echo "принят")"
}
accepted "splify2: apply --dry-run --spec" -- "$BIN" apply --dry-run --spec "$tmp/spec.json"
accepted "splify2: outputs --kind vless --spec" -- "$BIN" outputs --kind vless --spec "$tmp/spec.json"
accepted "splify2: outputs --obfs --spec" -- "$BIN" outputs --obfs --spec "$tmp/spec.json"
accepted "splify2: status --spec" -- "$BIN" status --spec "$tmp/spec.json"
accepted "splify2: diag --spec" -- "$BIN" diag --spec "$tmp/spec.json"
accepted "splify2: explain АДРЕС --spec" -- "$BIN" explain 1.2.3.4 --spec "$tmp/spec.json"
# Команды VLESS в базовой сборке отвечают кодом 2 — «в этой сборке их нет», — и по коду
# это не отличить от отказа разбора. Поэтому здесь проверяется маркер: базовая сборка
# обязана дойти до отказа САМОЙ КОМАНДЫ и назвать нужный пакет. Заодно это единственное
# место, где закреплена строка «steer-extended».
#
# Строка — контракт, а не текст. splify2 (rpcd/splify2) отличает базовую сборку от
# расширенной так:  out="$(steer vless '' 2>&1)"; case "$out" in *steer-extended*) …
# и по этому решает, показывать ли вкладку VLESS целиком. Переформулируйте отказ в
# src/steer.c без оглядки сюда — и интерфейс объявит расширенную сборку базовой.
ext_marker() { # ИМЯ -- команда...
    name="$1"; shift 2
    out="$("$@" 2>&1 >/dev/null)"
    check "$name" "1" "$(printf '%s' "$out" | grep -c 'steer-extended')"
}
ext_marker "splify2: vless-nodes доходит до команды" -- \
    "$BIN" vless-nodes v --spec "$tmp/spec.json"
ext_marker "splify2: vless-probe --node -1 --timeout 6 доходит до команды" -- \
    "$BIN" vless-probe v --node -1 --timeout 6 --spec "$tmp/spec.json"
ext_marker "splify2: vless-probe --node 0 доходит до команды" -- \
    "$BIN" vless-probe v --node 0 --timeout 6 --spec "$tmp/spec.json"
# Пустое имя выхода: rpcd зовёт именно `steer vless ''`. Пустая строка обязана считаться
# позиционным аргументом, а не пропущенным, — иначе разбор отвергнет вызов раньше, чем
# движок успеет назвать пакет, и определение сборки сломается.
ext_marker "splify2: vless '' называет пакет (по этому splify2 узнаёт сборку)" -- \
    "$BIN" vless ''
accepted "splify2: fit --budget --report ФАЙЛ" -- \
    "$BIN" fit --budget 100 --report "$tmp/rep.json" /dev/null

printf '\n%d проверок пройдено' "$pass"
if [ "$fail" -gt 0 ]; then printf ', %d ПРОВАЛЕНО\n' "$fail"; exit 1; fi
printf '\nвсе проверки прошли\n'
