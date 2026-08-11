#!/bin/sh
# Сборочные списки против каталога с исходниками: без docker, без сети, без zig.
#
# Зачем. Релизная сборка перечисляет файлы руками в трёх местах — BASE_SRC в build.sh,
# базовый и расширенный списки в build/build-ext.sh, — а `make test` компилирует свой
# набор и про эти списки ничего не знает. Новый файл в src/ext поэтому проходит
# ext-syntax (там маска src/ext/*.c), проходит весь набор тестов и ломается только в
# `./build.sh`, на чужой машине с docker, сообщением про неопределённую ссылку. Это
# ровно продолжение I-024: локально зелено, релиз сломан. Стенд сверяет списки с
# каталогом, поэтому расхождение видно на том же `make test`.
#
# Проверять сам docker-путь нечем: образа здесь нет. Но список файлов — это текст, и
# текст сверяется текстом.
set -u
pass=0 fail=0

check() {
    if [ "$2" = "$3" ]; then
        pass=$((pass + 1))
    else
        fail=$((fail + 1))
        printf 'FAIL %s\n  ожидалось: %s\n  в скрипте: %s\n' "$1" "$2" "$3"
    fi
}

names() { sed 's|.*/||' | sort -u | tr '\n' ' '; }

# ---- что лежит на диске ----------------------------------------------------
disk_base="$(ls src/*.c | names)"
disk_ext="$(ls src/ext/*.c | names)"

# ---- что перечислено в сборочных скриптах ----------------------------------
# Пути в build-ext.sh абсолютные (внутри контейнера), в build.sh — относительные:
# см. комментарий про cd в каталог mbedtls в build/build-ext.sh.
ext_ext="$(grep -o '/src/src/ext/[a-z0-9_]*\.c' build/build-ext.sh | names)"
ext_base="$(grep -o '/src/src/[a-z0-9_]*\.c' build/build-ext.sh | names)"
sh_base="$(grep '^BASE_SRC=' build.sh | grep -o 'src/[a-z0-9_]*\.c' | names)"

check "build/build-ext.sh перечисляет весь src/ext" "$disk_ext" "$ext_ext"
check "build/build-ext.sh перечисляет весь src"     "$disk_base" "$ext_base"
check "BASE_SRC в build.sh перечисляет весь src"    "$disk_base" "$sh_base"

# ---- переменная, которую никто не читает -----------------------------------
# Присвоенная и ни разу не использованная переменная в сборочном скрипте — это список,
# который выглядит действующим и не действует. Так в build.sh жили BASE_SRC_ABS и
# EXT_SRC_ABS: build-ext.sh запускается отдельным процессом с тремя аргументами, ничего
# не экспортируется, и правка этих строк не меняла в сборке ничего (I-032).
for f in build.sh build/build-ext.sh build/bench.sh; do
    dead=""
    for v in $(grep -oE '^[A-Z_][A-Z0-9_]*=' "$f" | tr -d '='); do
        # Присвоение не считается использованием, поэтому строки `V=` отбрасываются.
        if [ "$(grep -v "^$v=" "$f" | grep -c "\\\$$v\|\${$v")" -eq 0 ]; then
            dead="$dead$v "
        fi
    done
    check "$f: нет переменных, которые никто не читает" "" "$dead"
done

printf '\n%d проверок пройдено' "$pass"
if [ "$fail" -gt 0 ]; then printf ', %d ПРОВАЛЕНО\n' "$fail"; exit 1; fi
printf '\nвсе проверки прошли\n'
