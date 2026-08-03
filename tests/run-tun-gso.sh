#!/bin/sh
# Собрать и прогнать tests/tun-gso.c в своём сетевом пространстве.
#
# Пространство нужно не для чистоты, а чтобы тест не трогал сеть машины: он включает
# пересылку, выключает проверку обратного пути и поднимает два устройства с адресами.
set -eu
cd "$(dirname "$0")/.."

BIN="${TMPDIR:-/tmp}/tun-gso"
cc -O2 -Wall -Wextra -o "$BIN" tests/tun-gso.c src/ext/tun.c

NS=steer-tungso
ip netns delete "$NS" 2>/dev/null || true
ip netns add "$NS"
trap 'ip netns delete "$NS" 2>/dev/null || true' EXIT
ip netns exec "$NS" ip link set lo up

# Оба пути, а не только быстрый: без разгрузки суммы считаем мы сами, и это отдельный код,
# который остаётся единственным на ядрах без IFF_VNET_HDR.
echo "-- с разгрузкой"
ip netns exec "$NS" "$BIN"
echo "-- без разгрузки (STEER_TUN_NOGSO)"
ip netns exec "$NS" env STEER_TUN_NOGSO=1 "$BIN"
