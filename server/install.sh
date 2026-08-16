#!/bin/sh
# Серверная половина «WireGuard поверх TCP»: сборка, юнит, запуск.
#
# Ставится на VPS рядом с WireGuard. Собирается системным cc из тех же исходников, что и
# движок на роутере: внешних зависимостей у базовой сборки нет вовсе, поэтому скачивать
# готовый бинарник (и гадать про libc целевой системы) незачем.
#
# Идемпотентен: повторный запуск обновляет бинарник и настройки на месте.
set -e

PORT=4567
FORWARD=127.0.0.1:51820
PREFIX=/usr/local/sbin
ENVFILE=/etc/default/steer-obfs
UNIT=/etc/systemd/system/steer-obfs.service

usage() {
    cat <<EOF
использование: sh server/install.sh [--port ПОРТ] [--forward АДРЕС:ПОРТ]

  --port      порт поддельного TCP, который слушаем снаружи (сейчас $PORT)
  --forward   куда отдавать разобранные датаграммы, то есть WireGuard (сейчас $FORWARD)
EOF
    exit 2
}

while [ $# -gt 0 ]; do
    case "$1" in
        --port) PORT="$2"; shift 2 ;;
        --forward) FORWARD="$2"; shift 2 ;;
        -h|--help) usage ;;
        *) echo "неизвестный аргумент: $1"; usage ;;
    esac
done

[ "$(id -u)" = 0 ] || { echo "нужны права root"; exit 1; }

# Запускается из корня репозитория или из server/ — определяемся по своему пути, а не по
# текущему каталогу: «сработало у меня» из-за cd — не то свойство, которое нужно установщику.
here=$(cd "$(dirname "$0")" && pwd)
root=$(dirname "$here")

# Два способа получить бинарник, и оба ведут к одному и тому же файлу.
#
# Рядом со скриптом лежит готовый steer — значит это распакованный архив из релиза
# (steer-obfs-ВЕРСИЯ-АРХ.tar.gz). Он статический, собран тем же zig под musl, что и пакеты
# для роутера, и потому не зависит ни от версии libc на VPS, ни от дистрибутива вовсе.
# Компилятор в этом случае не нужен — а раньше был нужен всегда, и на голой VPS установка
# начиналась с apt install build-essential ради одного файла.
#
# Готового нет — собираем из исходников рядом, как и прежде.
if [ -x "$here/steer" ]; then
    BIN="$here/steer"
    echo "беру готовый бинарник: $BIN"
else
    [ -f "$root/Makefile" ] || {
        echo "рядом нет ни готового бинарника steer, ни исходников движка."
        echo "возьмите архив steer-obfs-*.tar.gz со страницы релизов либо клонируйте репозиторий."
        exit 1
    }
    command -v cc >/dev/null 2>&1 || { echo "нужен компилятор: apt install build-essential"; exit 1; }
    BIN="$root/build/steer"
fi

command -v nft >/dev/null 2>&1 || cat <<'EOF'
внимание: nft не найден. Процесс не сможет поставить правило против RST, и ядро будет
рвать сессии. Поставьте nftables либо добавьте правило вручную:
  iptables -I OUTPUT -p tcp --sport ПОРТ --tcp-flags RST RST -j DROP
EOF

if [ "$BIN" = "$root/build/steer" ]; then
    echo "собираю движок…"
    make -C "$root" -s all
fi

install -d "$PREFIX"
install -m 0755 "$BIN" "$PREFIX/steer"

cat > "$ENVFILE" <<EOF
# Настройки серверной половины обфускации. Меняются здесь, а не в юните:
# systemctl edit не понадобится, а обновление установщиком юнит перезапишет.
OBFS_PORT=$PORT
OBFS_FORWARD=$FORWARD
EOF

cat > "$UNIT" <<EOF
[Unit]
Description=steer obfs — WireGuard поверх поддельного TCP (серверная половина)
# После сети: сырой сокет выбирает маршрут при первом же ответе клиенту.
After=network-online.target
Wants=network-online.target

[Service]
EnvironmentFile=$ENVFILE
ExecStart=$PREFIX/steer obfs-server --listen \${OBFS_PORT} --forward \${OBFS_FORWARD}
# Сырой сокет и правило nft — это CAP_NET_RAW и CAP_NET_ADMIN. Остальные права не нужны,
# поэтому ограничиваем набор, а не запускаем «просто от root».
AmbientCapabilities=CAP_NET_RAW CAP_NET_ADMIN
CapabilityBoundingSet=CAP_NET_RAW CAP_NET_ADMIN
NoNewPrivileges=yes
ProtectSystem=strict
ProtectHome=yes
PrivateTmp=yes
# Выход процесса — всегда отказ (см. заголовок obfs.c), поэтому поднимаем заново всегда,
# но с паузой: сеть, которой ещё нет, не станет доступнее от частых попыток.
Restart=always
RestartSec=3

[Install]
WantedBy=multi-user.target
EOF

systemctl daemon-reload
systemctl enable --now steer-obfs
systemctl restart steer-obfs

cat <<EOF

готово: слушаю поддельный TCP на порту $PORT, отдаю в $FORWARD

осталось сделать руками (это чужая конфигурация, установщик её не трогает):
  1. открыть снаружи TCP $PORT;
  2. закрыть снаружи UDP-порт WireGuard — ради этого всё и затевалось;
  3. выставить MTU интерфейса wg = MTU канала − 72 (обычно 1428) на ОБЕИХ сторонах;
  4. на роутере прописать выход с obfs: server = адрес этого VPS:$PORT,
     listen = тот же адрес и порт, что в Endpoint пира.

состояние:  systemctl status steer-obfs
журнал:     journalctl -u steer-obfs -f
EOF
