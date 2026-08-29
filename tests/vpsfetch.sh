#!/bin/sh
# Лестница источников установщика хаба на VPS (server/xs_install.sh) — без сети.
#
# ЗАЧЕМ. Прямая ссылка релиза GitHub перенаправляет на release-assets.githubusercontent.com,
# и у части аудитории провайдер закрыл этот домен целиком: raw., objects. и release-assets.
# стоят на одной сети Fastly. На роутерах это уже стоило людям установки (splify2#15), а
# здесь была ровно та же единственная ссылка. Стенд стоит на том, что ступеней теперь три,
# что вторая и третья пробуются, и что отказ называет ВСЕ источники, а не молчит.
#
# КАК. Скрипт подключается как библиотека (XS_INSTALL_LIB=1), а curl подменяется в PATH:
# фальшивый curl решает по подстроке в URL, отдать файл или отказать. Сети не нужно, root не
# нужен, интерактивная часть установщика не запускается.
set -u
SCRIPT="${XS_INSTALL:-server/xs_install.sh}"
[ -r "$SCRIPT" ] || { echo "нет файла: $SCRIPT"; exit 2; }
command -v bash >/dev/null 2>&1 || { echo "vpsfetch: нужен bash, стенд пропущен"; exit 0; }

pass=0 fail=0
tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT

check() {
    if [ "$2" = "$3" ]; then pass=$((pass + 1)); else
        fail=$((fail + 1))
        printf 'FAIL %s\n  expected: %s\n  actual:   %s\n' "$1" "$2" "$3"
    fi
}

# Фальшивый curl. XS_ALLOW — подстрока URL, который единственный отдаёт файл; пустая
# означает «не отдаёт никто». Все запрошенные URL пишутся в XS_LOG по строке, поэтому стенду
# видно и сколько ступеней пройдено, и в каком порядке.
mkdir -p "$tmp/bin"
cat > "$tmp/bin/curl" <<'EOF'
#!/bin/sh
url=""; out=""
while [ $# -gt 0 ]; do
    case "$1" in
    -o) out="$2"; shift 2 ;;
    -*) shift ;;
    *)  url="$1"; shift ;;
    esac
done
echo "$url" >> "$XS_LOG"
if [ -n "${XS_ALLOW:-}" ] && [ "${url#*$XS_ALLOW}" != "$url" ]; then
    printf 'полезная нагрузка\n' > "$out"
    exit 0
fi
exit 22
EOF
chmod +x "$tmp/bin/curl"
PATH="$tmp/bin:$PATH"
export PATH

# try ЧТО_ОТДАЁТ — прогнать fetchArtifact и вернуть его вывод; журнал запросов в $tmp/log.
try() {
    : > "$tmp/log"
    XS_LOG="$tmp/log" XS_ALLOW="$1" \
    XS_INSTALL_LIB=1 bash -c \
        'source "$0"; fetchArtifact steer-hub-x86_64.tar.gz "$1"' "$SCRIPT" "$tmp/got" 2>&1
}

# ---- первая ступень: прямая ссылка релиза ------------------------------------
# Работает у всех, у кого ничего не закрыто, и остаётся первой именно поэтому: обход не
# должен становиться обычной дорогой.
out="$(try 'releases/latest/download')"
check "релиз отдал — взято с первой ступени" "1" \
      "$(printf '%s\n' "$out" | grep -c 'взято: https://github.com/xyzmean/steer/releases')"
check "остальные источники не трогались" "1" "$(wc -l < "$tmp/log" | tr -d ' ')"
check "файл на месте" "1" "$(grep -c 'полезная нагрузка' "$tmp/got")"

# ---- вторая ступень: ветка через contents API самого GitHub -------------------
# Хосты GitHub (140.82.121.x) — другая сеть, чем githubusercontent (185.199.108-111.133), и
# при этой блокировке работают. Заголовок Accept обязателен: без него contents API отдаёт
# JSON с полем download_url, ведущим обратно на raw.githubusercontent.
out="$(try 'api.github.com')"
check "релиз закрыт — пошли в contents API" "1" \
      "$(printf '%s\n' "$out" | grep -c 'взято: https://api.github.com')"
# Цвет в строке отказа стоит между словом и двоеточием, поэтому образец берёт слово и хост
# по отдельности: точное «не отдал: https://…» не совпало бы никогда.
check "первая ступень попробована и названа" "1" \
      "$(printf '%s\n' "$out" | grep -c 'не отдал.*https://github.com/xyzmean/steer/releases')"
check "запрошена именно ветка dist-vps" "1" "$(grep -c 'ref=dist-vps' "$tmp/log")"

# ---- третья ступень: зеркало на GitLab ---------------------------------------
# На случай, когда закрыт и сам GitHub: там та же ветка.
out="$(try 'gitlab.com')"
check "GitHub закрыт целиком — взято с зеркала" "1" \
      "$(printf '%s\n' "$out" | grep -c 'взято: https://gitlab.com/xyzmean/steer')"
check "пройдены все три ступени" "3" "$(wc -l < "$tmp/log" | tr -d ' ')"

# ---- не отдал никто ----------------------------------------------------------
# Главное здесь не код возврата, а то, что отказ НАЗЫВАЕТ каждый источник. Молчаливый отказ
# — это именно то, из-за чего человек с закрытым githubusercontent не мог понять, что у него
# сломано: сообщение было неотличимо от «сервер релизов лежит».
out="$(try '')"
check "никто не отдал — код возврата ненулевой" "1" \
      "$(XS_LOG=$tmp/log XS_ALLOW= XS_INSTALL_LIB=1 bash -c \
         'source "$0"; fetchArtifact x "$1" >/dev/null 2>&1 || echo 1' "$SCRIPT" "$tmp/got")"
check "названа первая ступень" "1" "$(printf '%s\n' "$out" | grep -c 'не отдал.*https://github.com/')"
check "названа вторая" "1" "$(printf '%s\n' "$out" | grep -c 'не отдал.*https://api.github.com/')"
check "названа третья" "1" "$(printf '%s\n' "$out" | grep -c 'не отдал.*https://gitlab.com/')"

# ---- ветка выкладки существует в релизном процессе ---------------------------
# Лестница бессмысленна, если во вторую и третью ступень никто ничего не кладёт. Проверяется
# здесь, а не в buildmatch.sh, чтобы обе половины одного обещания стояли рядом.
WF=.github/workflows/release.yml
check "релиз выкладывает сборки VPS в ветку dist-vps" "1" "$(grep -c 'DIST_VPS: dist-vps' "$WF")"
check "и кладёт туда именно архивы хаба" "1" "$(grep -c 'out/steer-hub-\*\.tar\.gz /tmp/dist-vps/' "$WF")"
check "и архивы обфускатора" "1" "$(grep -c 'out/steer-obfs-\*\.tar\.gz /tmp/dist-vps/' "$WF")"
# Пакеты роутера сюда не едут и не должны: их ветка dist качается роутером ЦЕЛИКОМ, и лишние
# два мегабайта сборок для VPS платил бы каждый роутер.
check "пакеты роутера в ветку VPS не попадают" "0" \
      "$(sed -n '/Выложить сборки VPS/,/^      - name:/p' "$WF" | grep -c 'out/\*\.apk')"

printf '\n%d проверок пройдено' "$pass"
if [ "$fail" -gt 0 ]; then printf ', %d ПРОВАЛЕНО\n' "$fail"; exit 1; fi
printf '\nвсе проверки прошли\n'
