# Чтение build/sources.mk без make: для build.sh и build/build-ext.sh (в контейнере make нет).
#
#   . build/sources.sh
#   profile_src extended           # файлы профиля, пути относительно корня репозитория
#   profile_src extended /src/     # то же с приставкой (build-ext.sh видит репозиторий в /src)
#   profile_var PROFILE_DEFS_tgws  # любая переменная манифеста
#
# Разбор знает ровно то подмножество make, которое разрешено в шапке sources.mk: строки
# `ИМЯ := значение`, продолжение `\`, ссылки `$(ИМЯ)` на объявленное выше. Незнакомая
# ссылка — отказ, а не пустое место: пустой список файлов собрал бы бинарник без половины
# движка и сломался бы только на линковке, далеко от причины.

# Путь к манифесту — SOURCES_MK, по умолчанию build/sources.mk от корня репозитория (оттуда
# запускаются build.sh и стенды). Сценарии, которые живут в другом каталоге, задают его сами.
SOURCES_MK="${SOURCES_MK:-build/sources.mk}"
[ -f "$SOURCES_MK" ] || { echo "sources.sh: нет манифеста $SOURCES_MK" >&2; return 2 2>/dev/null || exit 2; }

profile_var() {
    awk -v want="$1" '
        function expand(s,    out, name, i) {
            out = ""
            while ((i = index(s, "$(")) > 0) {
                out = out substr(s, 1, i - 1)
                s = substr(s, i + 2)
                name = substr(s, 1, index(s, ")") - 1)
                s = substr(s, index(s, ")") + 1)
                if (!(name in v)) { print "sources.mk: неизвестное имя " name > "/dev/stderr"; bad = 1; exit 2 }
                out = out v[name]
            }
            return out s
        }
        /^[ \t]*#/ || /^[ \t]*$/ { if (!cont) next }
        {
            line = $0
            if (cont) { acc = acc " " line } else { acc = line }
            if (line ~ /\\$/) { sub(/\\$/, "", acc); cont = 1; next }
            cont = 0
            if (acc !~ /:=/) next
            name = acc; sub(/[ \t]*:=.*/, "", name); gsub(/^[ \t]+/, "", name)
            val = acc; sub(/^[^:]*:=[ \t]*/, "", val)
            v[name] = expand(val)
        }
        END {
            if (bad) exit 2
            if (!(want in v)) { print "sources.mk: нет переменной " want > "/dev/stderr"; exit 2 }
            n = split(v[want], w, /[ \t]+/)
            out = ""
            for (i = 1; i <= n; i++) if (w[i] != "") out = out (out == "" ? "" : " ") w[i]
            print out
        }' "$SOURCES_MK"
}

profile_src() {
    list="$(profile_var "PROFILE_$1")" || return 2
    [ -n "$list" ] || { echo "sources.mk: профиль $1 пуст" >&2; return 2; }
    out=""
    for f in $list; do out="$out${out:+ }${2:-}$f"; done
    echo "$out"
}
