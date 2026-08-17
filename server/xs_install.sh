#!/bin/bash
# Хаб xsteer на VPS: установка, пира, снятие. По образцу wireguard-install от angristan —
# тот же порядок вопросов, то же меню при повторном запуске, тот же способ отдать готовый
# конфиг. Человек, ставивший WireGuard этим скриптом, здесь узнаёт всё, кроме названий.
#
# ЧЕМ ЭТО ОТЛИЧАЕТСЯ ОТ server/install.sh. Тот ставит серверную половину обфускации для
# ШТАТНОГО WireGuard: свои ключи ему не нужны, пиров он не знает, конфигураций не выдаёт. Здесь
# полноценный протокол: у хаба свой статический ключ, свой список пиров с их AllowedIPs и своё
# устройство TUN. Отсюда и меню: пира приходят и уходят, а не настраиваются один раз.
#
# ПОЧЕМУ bash, А НЕ sh, КАК ОСТАЛЬНЫЕ СКРИПТЫ ПРОЕКТА. Ради `read -e -i`: значения по
# умолчанию, которые можно поправить на месте. В wg-install.sh это же и сделано, и именно оно
# превращает установку в «нажать enter шесть раз». На VPS bash есть всегда; если его нет, ставить
# хаб придётся руками по docs/xsteer.md.
#
# КОМПИЛЯТОРА ЗДЕСЬ НЕТ НАМЕРЕННО. Хабу нужна криптография, то есть mbedtls, и три варианта её
# получить взвешены в плане: системный libmbedtls даёт РАЗНЫЕ версии на Debian и Ubuntu и, что
# хуже, отменяет наш steer_mbedtls_config.h — то есть собирается тихо не та криптография.
# Поэтому берётся готовый статический бинарник из релиза, а если его для этой архитектуры нет —
# отказ с внятной причиной, а не попытка собрать.
set -u

RED='\033[0;31m'
ORANGE='\033[0;33m'
GREEN='\033[0;32m'
NC='\033[0m'

PREFIX=/usr/local/sbin
BIN="$PREFIX/steer-hub"
CONFDIR=/etc/steer/xsteer
CONF="$CONFDIR/hub.conf"
PARAMS="$CONFDIR/params"
ENVFILE=/etc/default/steer-xsteer-hub
UNIT=/etc/systemd/system/steer-xsteer-hub.service
NATUNIT=/etc/systemd/system/steer-xsteer-nat.service
RELEASES=https://github.com/xyzmean/steer/releases/latest/download

# Спросить с приглашением и значением по умолчанию.
#
# ЗАЧЕМ ОТДЕЛЬНОЙ ФУНКЦИЕЙ, а не `read` на месте: цикл вида `until <проверка>; do read ...; done`
# при КОНЦЕ ВВОДА крутится вечно и печатает приглашение в никуда. Случается это не в теории —
# так ведёт себя любой запуск не с терминала: `bash xs_install.sh < answers`, прогон из чужого
# скрипта, ssh без -t. Установщик в этом случае обязан отказать, а не висеть. Здесь конец ввода
# — отказ с внятной строкой.
function ask() { # ask ПЕРЕМЕННАЯ "приглашение" ["по умолчанию"]
	local __var="$1" __prompt="$2" __def="${3:-}" __val=""
	if ! read -rp "$__prompt" -e -i "$__def" __val; then
		echo ""
		echo -e "${RED}ввод закончился${NC} — прерываюсь. Скрипт спрашивает и его надо запускать"
		echo "с терминала: bash xs_install.sh"
		exit 1
	fi
	printf -v "$__var" '%s' "$__val"
}

function anykey() {
	if ! read -n1 -r -p "$1"; then
		echo ""
		echo -e "${RED}ввод закончился${NC} — прерываюсь."
		exit 1
	fi
	echo ""
}

function isRoot() {
	if [ "${EUID}" -ne 0 ]; then
		echo "Скрипт запускается от root"
		exit 1
	fi
}

function checkTun() {
	# /dev/net/tun нет на части LXC и почти на всех OpenVZ, и это не «настроим потом»: без
	# него хаб не может отдать трафик наружу вовсе. Проверяется ДО вопросов, иначе человек
	# ответит на десять из них и получит отказ.
	if [ ! -c /dev/net/tun ]; then
		echo -e "${RED}нет /dev/net/tun${NC}"
		echo "Хабу нужно устройство TUN: через него идёт выход пиров в интернет."
		echo "На OpenVZ его обычно нет вовсе, на LXC он включается хозяином узла."
		echo "Попробуйте: modprobe tun. Если не помогло — нужна другая VPS."
		exit 1
	fi
}

function checkSystemd() {
	if ! command -v systemctl >/dev/null 2>&1; then
		echo -e "${RED}нет systemd${NC}: этот установщик ставит юнит и без него бесполезен."
		echo "Запускайте хаб как вам удобно: $BIN xsteer-hub --config $CONF"
		exit 1
	fi
}

function checkNft() {
	if ! command -v nft >/dev/null 2>&1; then
		echo -e "${ORANGE}nft не найден.${NC}"
		echo "Без него процесс не поставит правило против RST собственного ядра, и ядро будет"
		echo "рвать сессии пиров. Поставьте nftables (apt install nftables) либо добавьте правило"
		echo "вручную:"
		echo "  iptables -I OUTPUT -p tcp --sport ПОРТ --tcp-flags RST RST -j DROP"
		echo ""
	fi
}

function initialCheck() {
	isRoot
	checkSystemd
	checkTun
	checkNft
}

# Бинарник хаба: три способа, все ведут к одному файлу. Компилятор не нужен ни в одном.
function getHubBinary() {
	local here
	here="$(cd "$(dirname "$0")" && pwd)"

	if [ -x "$here/steer-hub" ]; then
		# Рядом со скриптом — значит это распакованный архив из релиза.
		install -m 0755 "$here/steer-hub" "$BIN"
		return 0
	fi
	if [ -x "$BIN" ]; then
		echo "бинарник уже стоит: $BIN ($("$BIN" version 2>/dev/null || echo "версия не печатается"))"
		return 0
	fi

	local arch
	arch="$(uname -m)"
	case "$arch" in
	x86_64) arch=x86_64 ;;
	aarch64 | arm64) arch=aarch64 ;;
	*)
		echo -e "${RED}архитектура $arch: готового бинарника хаба для неё нет${NC}"
		echo "Соберите его в клоне репозитория (./build.sh, нужен docker) и положите файл"
		echo "steer-hub рядом с этим скриптом."
		exit 1
		;;
	esac

	echo "скачиваю steer-hub для $arch..."
	local tmp
	tmp="$(mktemp -d)"
	if ! curl -fsSL "$RELEASES/steer-hub-$arch.tar.gz" -o "$tmp/h.tar.gz"; then
		echo -e "${RED}не скачалось${NC}: $RELEASES/steer-hub-$arch.tar.gz"
		echo "Возьмите архив со страницы релизов вручную, распакуйте и запустите xs_install.sh"
		echo "из распакованного каталога."
		rm -rf "$tmp"
		exit 1
	fi
	tar -xzf "$tmp/h.tar.gz" -C "$tmp" || { echo "архив не распаковался"; exit 1; }
	local got
	got="$(find "$tmp" -name steer-hub -type f | head -1)"
	[ -n "$got" ] || { echo "в архиве нет steer-hub"; exit 1; }
	install -m 0755 "$got" "$BIN"
	rm -rf "$tmp"
}

function installQuestions() {
	echo "Хаб xsteer — установка."
	echo ""
	echo "Несколько вопросов; на всё, что устраивает, достаточно нажать enter."
	echo ""

	HUB_PUB_IP="$(ip -4 addr | sed -ne 's|^.* inet \([^/]*\)/.* scope global.*$|\1|p' | awk '{print $1}' | head -1)"
	ask HUB_PUB_IP "Публичный адрес IPv4 этого сервера: " "${HUB_PUB_IP}"

	HUB_NIC_GUESS="$(ip -4 route ls | grep default | awk '/dev/ {for (i=1; i<=NF; i++) if ($i == "dev") print $(i+1)}' | head -1)"
	until [[ ${HUB_NIC:-} =~ ^[a-zA-Z0-9_.-]+$ ]]; do
		ask HUB_NIC "Внешний интерфейс (через него уходит трафик пиров): " "${HUB_NIC_GUESS}"
	done

	# 443 по умолчанию НЕ ради красоты: на этом порту поток, похожий на TLS, не выделяется
	# среди остального. Другой порт работает так же, но заметен сам по себе.
	until [[ ${HUB_PORT:-} =~ ^[0-9]+$ ]] && [ "${HUB_PORT}" -ge 1 ] && [ "${HUB_PORT}" -le 65535 ]; do
		ask HUB_PORT "Порт хаба [1-65535]: " 443
	done
	# Порт принадлежит нам ЦЕЛИКОМ: слушающий сокет ядра на нём отвечал бы SYN-ACK нашим же
	# спицам, и рукопожатие ломалось бы через раз. Проверяем сразу, а не оставляем на diag.
	if ss -ltn 2>/dev/null | awk '{print $4}' | grep -qE "[:.]${HUB_PORT}\$"; then
		echo -e "${RED}порт ${HUB_PORT} уже слушает чей-то сокет${NC}"
		echo "Хабу порт нужен целиком: сокет ядра на нём будет отвечать нашим же спицам."
		echo "Выберите другой порт или освободите этот."
		exit 1
	fi

	until [[ ${HUB_SUBNET:-} =~ ^([0-9]{1,3}\.){3}[0-9]{1,3}/[0-9]{1,2}$ ]]; do
		ask HUB_SUBNET "Сеть туннеля (хаб займёт первый адрес): " 10.77.0.0/24
	done
	HUB_BASE="$(echo "${HUB_SUBNET%/*}" | awk -F. '{print $1"."$2"."$3}')"
	HUB_PLEN="${HUB_SUBNET#*/}"
	HUB_ADDR="${HUB_BASE}.1"

	echo ""
	echo "Пиры могут ходить через хаб в интернет — тогда нужен masquerade на внешнем"
	echo "интерфейсе. Правило ставится в ОТДЕЛЬНУЮ таблицу nft (steer_xsteer_nat), чужих"
	echo "правил установщик не трогает и не переписывает."
	ask HUB_NAT "Поставить masquerade и включить пересылку? [y/n]: " y

	echo ""
	echo "Готово, вопросов больше нет."
	anykey "Нажмите любую клавишу, чтобы продолжить..."
	echo ""
}

function writeParams() {
	# Секретов здесь НЕТ: приватный ключ живёт только в hub.conf с правами 0600. Этот файл
	# читают меню и, возможно, человек — ключу в нём делать нечего.
	cat >"$PARAMS" <<EOF
HUB_PUB_IP=${HUB_PUB_IP}
HUB_NIC=${HUB_NIC}
HUB_PORT=${HUB_PORT}
HUB_SUBNET=${HUB_SUBNET}
HUB_BASE=${HUB_BASE}
HUB_PLEN=${HUB_PLEN}
HUB_ADDR=${HUB_ADDR}
HUB_PUB_KEY=${HUB_PUB_KEY}
HUB_NAT=${HUB_NAT}
EOF
	chmod 0600 "$PARAMS"
}

function installHub() {
	installQuestions
	getHubBinary

	mkdir -p "$CONFDIR"
	chmod 0700 "$CONFDIR"

	# Ключи делает сам движок: то же место, что печатает `steer xsteer-key` на роутере, и та
	# же проверка энтропии внутри. Приватный ключ не покидает этот файл.
	local keys
	keys="$("$BIN" xsteer-key)" || { echo "ключи не сделались"; exit 1; }
	local priv pub
	priv="$(echo "$keys" | awk '/PrivateKey/ {print $3}')"
	pub="$(echo "$keys" | awk '/PublicKey/ {print $3}')"
	HUB_PUB_KEY="$pub"

	( umask 077; cat >"$CONF" <<EOF
[Interface]
PrivateKey = $priv
Address = ${HUB_ADDR}/${HUB_PLEN}
ListenPort = ${HUB_PORT}
EOF
	)
	# ПРОВЕРЯТЬ КОНФИГУРАЦИЮ ЗДЕСЬ НЕЛЬЗЯ, и это не мелочь порядка: хабу нужен хотя бы один
	# пир — без него разбор отвергает файл, и правильно отвергает (хаб без пиров не имеет
	# смысла и всё равно не запустится). Поэтому сначала заводится первый пир, и только
	# потом проверка и запуск. Первая версия скрипта падала здесь на верных данных.
	writeParams

	cat >"$ENVFILE" <<EOF
# Настройки хаба xsteer. Меняются здесь, а не в юните: обновление установщиком юнит
# перезаписывает, а этот файл — нет.
XS_CONFIG=$CONF
EOF

	cat >"$UNIT" <<EOF
[Unit]
Description=steer xsteer — хаб звезды поверх поддельного TCP
# После сети: сырой сокет выбирает маршрут при первом же ответе пиру.
After=network-online.target
Wants=network-online.target

[Service]
EnvironmentFile=$ENVFILE
ExecStart=$BIN xsteer-hub --config \${XS_CONFIG}
# Сырой сокет, правило nft и настройка TUN — это CAP_NET_RAW и CAP_NET_ADMIN. Больше ничего не
# нужно, поэтому набор ограничен, а не «просто root».
AmbientCapabilities=CAP_NET_RAW CAP_NET_ADMIN
CapabilityBoundingSet=CAP_NET_RAW CAP_NET_ADMIN
NoNewPrivileges=yes
DeviceAllow=/dev/net/tun rw
StateDirectory=steer
ProtectSystem=strict
ReadWritePaths=$CONFDIR
ProtectHome=yes
PrivateTmp=yes
# Выход процесса — всегда отказ, поэтому поднимаем заново всегда, но с паузой: сеть, которой
# ещё нет, не станет доступнее от частых попыток.
Restart=always
RestartSec=3

[Install]
WantedBy=multi-user.target
EOF

	if [[ ${HUB_NAT} =~ ^[yY]$ ]]; then
		# Пересылка — это УСЛОВИЕ РАБОТЫ того, что мы ставим, а не чужая настройка: без неё
		# пир со 0.0.0.0/0 не выйдет в интернет вовсе.
		cat >/etc/sysctl.d/99-steer-xsteer.conf <<'EOF'
# Хабу xsteer нужна пересылка: трафик пиров выходит наружу через ядро.
net.ipv4.ip_forward = 1
EOF
		sysctl -q --system

		# Своя таблица nft и свой юнит, который её ставит при загрузке. Отдельная таблица —
		# принципиально: чужие правила не переписываются, а снятие хаба уносит ровно своё.
		cat >/usr/local/sbin/steer-xsteer-nat <<EOF
#!/bin/sh
# masquerade для трафика пиров xsteer. Своя таблица: чужих правил не касаемся.
nft delete table ip steer_xsteer_nat 2>/dev/null
nft add table ip steer_xsteer_nat
nft add chain ip steer_xsteer_nat post '{ type nat hook postrouting priority srcnat; policy accept; }'
nft add rule ip steer_xsteer_nat post ip saddr ${HUB_SUBNET} oifname "${HUB_NIC}" masquerade
EOF
		chmod 0755 /usr/local/sbin/steer-xsteer-nat
		cat >"$NATUNIT" <<EOF
[Unit]
Description=steer xsteer — masquerade для трафика пиров
After=network-online.target
Wants=network-online.target

[Service]
Type=oneshot
RemainAfterExit=yes
ExecStart=/usr/local/sbin/steer-xsteer-nat
ExecStop=/usr/bin/env nft delete table ip steer_xsteer_nat

[Install]
WantedBy=multi-user.target
EOF
		systemctl daemon-reload
		systemctl enable --now steer-xsteer-nat >/dev/null 2>&1
	fi

	echo ""
	echo "Хаб настроен. Теперь первый пир — без него хаб не запустится: пиров нет."
	if ! newSpoke; then
		echo -e "${RED}пир не добавлена${NC} — хаб остался ненастроенным."
		echo "Запустите скрипт снова: настройки уже сохранены, он предложит меню."
		exit 1
	fi

	echo ""
	echo -e "${GREEN}хаб работает${NC}: поддельный TCP на ${HUB_PUB_IP}:${HUB_PORT}, сеть туннеля ${HUB_SUBNET}"
	echo ""
	echo "осталось сделать руками (это чужая конфигурация, установщик её не трогает):"
	echo "  1. открыть снаружи TCP ${HUB_PORT};"
	echo "  2. НЕ поднимать на этом порту ничего своего — он принадлежит хабу целиком."
	echo ""
	echo "состояние:  systemctl status steer-xsteer-hub"
	echo "журнал:     journalctl -u steer-xsteer-hub -f"
	echo "меню:       запустите этот скрипт снова"
}

# Применить конфигурацию: проверить, поднять юнит, убедиться, что работает. Одна функция на все
# пути — установка, добавление пира, удаление — потому что порядок «проверить ДО перезапуска»
# обязателен в каждом из них, а забыть его легче всего в том, который добавили позже.
function hubApply() {
	if ! "$BIN" xsteer-check --config "$CONF"; then
		return 1
	fi
	systemctl daemon-reload
	systemctl enable --now steer-xsteer-hub >/dev/null 2>&1
	systemctl restart steer-xsteer-hub
	sleep 1
	if ! systemctl is-active --quiet steer-xsteer-hub; then
		echo -e "${RED}хаб не запустился${NC}"
		journalctl -u steer-xsteer-hub -n 20 --no-pager 2>/dev/null
		return 1
	fi
	return 0
}

# ---- пира -------------------------------------------------------------------

function nextFreeIP() {
	local i taken
	for i in $(seq 2 254); do
		taken="$(grep -c "^AllowedIPs = ${HUB_BASE}.${i}/32" "$CONF")"
		[ "$taken" = 0 ] && { echo "$i"; return 0; }
	done
	echo ""
}

function newSpoke() {
	echo ""
	echo "Новый пир."
	echo "Имя — буквы, цифры, дефис и подчёркивание, до 15 символов."

	local exists=1
	until [[ ${SPOKE_NAME:-} =~ ^[a-zA-Z0-9_-]+$ ]] && [ "${#SPOKE_NAME}" -lt 16 ] && [ "$exists" = 0 ]; do
		ask SPOKE_NAME "Имя пира: "
		exists="$(grep -c "^### spoke ${SPOKE_NAME}\$" "$CONF")"
		if [ "$exists" != 0 ]; then
			echo -e "${ORANGE}пир с таким именем уже есть${NC}"
		fi
	done

	local dot
	dot="$(nextFreeIP)"
	[ -n "$dot" ] || { echo "свободных адресов в ${HUB_SUBNET} не осталось"; return 1; }
	local SPOKE_IP
	ask dot "Адрес пира в туннеле: ${HUB_BASE}." "$dot"
	SPOKE_IP="${HUB_BASE}.${dot}"
	if grep -q "^AllowedIPs = ${SPOKE_IP}/32" "$CONF"; then
		echo -e "${ORANGE}этот адрес уже занят${NC}"
		unset SPOKE_NAME
		return 1
	fi

	# Сеть за пиром — это то, из-за чего иначе понадобится masquerade на роутере. Перечислив
	# её здесь, хаб примет пакеты с адресами этой сети (иначе он отбросит их проверкой
	# источника) и сам поставит маршрут для ответов. Так же делают с wg, и адреса при этом
	# сохраняются — видно, кто из локальной сети ходил.
	echo ""
	echo "Сеть за этим пиром (его локальная сеть). Пусто — только адрес в туннеле;"
	echo "тогда на роутере понадобится masquerade в туннель."
	local SPOKE_LAN=""
	ask SPOKE_LAN "Сеть за пиром, например 192.168.1.0/24: "
	if [ -n "$SPOKE_LAN" ]; then
		if ! [[ ${SPOKE_LAN} =~ ^([0-9]{1,3}\.){3}[0-9]{1,3}/[0-9]{1,2}$ ]]; then
			echo -e "${RED}не похоже на префикс${NC} — пропускаю"
			SPOKE_LAN=""
		elif grep -q "^AllowedIPs = .*${SPOKE_LAN}" "$CONF"; then
			# Пересечение AllowedIPs двух пиров движок отвергает НАМЕРЕННО: на хабе
			# неоднозначность означает тихий увод трафика не туда.
			echo -e "${RED}эта сеть уже числится за другой пиром${NC} — пропускаю"
			SPOKE_LAN=""
		fi
	fi

	echo ""
	echo "Что пир отправляет в туннель:"
	echo "   1) только звезду (${HUB_SUBNET}) — интернет идёт напрямую"
	echo "   2) весь трафик (0.0.0.0/0) — интернет тоже через хаб"
	local WHAT
	until [[ ${WHAT:-} =~ ^[12]$ ]]; do
		ask WHAT "Выбор [1-2]: " 1
	done
	local SPOKE_ALLOWED="${HUB_SUBNET}"
	[ "$WHAT" = 2 ] && SPOKE_ALLOWED="0.0.0.0/0"

	# Ключи делаются ЗДЕСЬ, как в wg-install.sh, и это компромисс: приватный ключ пира
	# проходит через хаб. Аккуратнее — сделать пару на самом роутере (`steer xsteer-key`) и
	# принести сюда только публичную половину; в этом случае вставьте её вместо
	# сгенерированной. Сказано прямо, чтобы выбор был осознанным, а не незамеченным.
	local keys spriv spub
	keys="$("$BIN" xsteer-key)" || { echo "ключи не сделались"; return 1; }
	spriv="$(echo "$keys" | awk '/PrivateKey/ {print $3}')"
	spub="$(echo "$keys" | awk '/PublicKey/ {print $3}')"

	local allowed="${SPOKE_IP}/32"
	[ -n "$SPOKE_LAN" ] && allowed="${SPOKE_IP}/32, ${SPOKE_LAN}"

	# Дописываем пира и ПРОВЕРЯЕМ конфигурацию до перезапуска: испорченный файл иначе уронил
	# бы работающий хаб вместе со всеми остальными пирами.
	cp "$CONF" "$CONF.bak"
	cat >>"$CONF" <<EOF

### spoke ${SPOKE_NAME}
[Peer]
PublicKey = ${spub}
AllowedIPs = ${allowed}
EOF
	if ! hubApply; then
		echo -e "${RED}конфигурация с новой пиром не принята — возвращаю прежнюю${NC}"
		mv "$CONF.bak" "$CONF"
		hubApply >/dev/null 2>&1
		unset SPOKE_NAME
		return 1
	fi
	rm -f "$CONF.bak"

	local out="/root/xsteer-${SPOKE_NAME}.conf"
	( umask 077; cat >"$out" <<EOF
# Пир ${SPOKE_NAME} звезды xsteer. Скопировать на роутер в
# /etc/steer/xsteer/<имя выхода>.conf либо внести через интерфейс splify2.
[Interface]
PrivateKey = ${spriv}
Address = ${SPOKE_IP}/${HUB_PLEN}
# SNI: имя, которое уйдёт в ClientHello. Для наблюдателя поток выглядит обычным TLS к этому
# домену, поэтому имя стоит брать существующее и ничем не выделяющееся.
SNI = www.microsoft.com

[Peer]
PublicKey = ${HUB_PUB_KEY}
Endpoint = ${HUB_PUB_IP}:${HUB_PORT}
AllowedIPs = ${SPOKE_ALLOWED}
PersistentKeepalive = 25
EOF
	)

	echo ""
	echo -e "${GREEN}пир ${SPOKE_NAME} добавлен${NC}: ${SPOKE_IP}, конфигурация в ${out}"
	echo ""
	cat "$out"
	echo ""
	echo "На роутере с splify2 это же делается интерфейсом (протокол xsteer) или командами:"
	echo "  uci set network.${SPOKE_NAME}=interface"
	echo "  uci set network.${SPOKE_NAME}.proto='xsteer'"
	echo "  uci set network.${SPOKE_NAME}.private_key='${spriv}'"
	echo "  uci add_list network.${SPOKE_NAME}.addresses='${SPOKE_IP}/${HUB_PLEN}'"
	echo "  uci set network.${SPOKE_NAME}.sni='www.microsoft.com'"
	echo "  uci set network.xsteer_${SPOKE_NAME}=xsteer_${SPOKE_NAME}"
	echo "  uci add_list network.xsteer_${SPOKE_NAME}.allowed_ips='${SPOKE_ALLOWED}'"
	echo "  uci set network.xsteer_${SPOKE_NAME}.public_key='${HUB_PUB_KEY}'"
	echo "  uci set network.xsteer_${SPOKE_NAME}.endpoint_host='${HUB_PUB_IP}'"
	echo "  uci set network.xsteer_${SPOKE_NAME}.endpoint_port='${HUB_PORT}'"
	echo "  uci commit network && ifup ${SPOKE_NAME}"
	echo ""
	echo "MTU задавать НЕ НУЖНО: движок согласует его сам и проверит путь пробами."
	unset SPOKE_NAME
}

function listSpokes() {
	local n
	n="$(grep -c "^### spoke " "$CONF")"
	if [ "$n" = 0 ]; then
		echo "пиров пока нет"
		return 0
	fi
	echo "пиры (имя, адрес в туннеле, что заворачивает):"
	awk '
		/^### spoke /   { name = $3 }
		/^AllowedIPs = /{ if (name != "") { sub(/^AllowedIPs = /, ""); print "  " name "  " $0; name = "" } }
	' "$CONF"
}

function revokeSpoke() {
	local n
	n="$(grep -c "^### spoke " "$CONF")"
	[ "$n" = 0 ] && { echo "пиров нет"; return 0; }
	echo "какой пир убрать?"
	grep "^### spoke " "$CONF" | cut -d' ' -f3 | nl -s ') '
	local num=""
	until [[ ${num} =~ ^[0-9]+$ ]] && [ "$num" -ge 1 ] && [ "$num" -le "$n" ]; do
		ask num "Номер [1-$n]: "
	done
	local name
	name="$(grep "^### spoke " "$CONF" | cut -d' ' -f3 | sed -n "${num}p")"

	# Убираем блок пира целиком: строку-метку, [Peer] и его ключи до следующей пустой строки
	# или следующей метки. Обрезать по счёту строк нельзя — у пиров разное число полей.
	cp "$CONF" "$CONF.bak"
	awk -v target="$name" '
		/^### spoke /  { skip = ($3 == target); if (skip) next }
		skip && /^\[Peer\]|^PublicKey|^AllowedIPs|^PersistentKeepalive|^Endpoint|^[[:space:]]*$/ { next }
		skip           { skip = 0 }
		{ print }
	' "$CONF.bak" >"$CONF"

	if ! "$BIN" xsteer-check --config "$CONF"; then
		# Самый частый случай здесь — убирали последнюю пир. Хабу нужен хотя бы один пир,
		# поэтому это не поломка, а осмысленный отказ, и сказать надо именно так.
		echo -e "${ORANGE}конфигурация без этой пира не проходит проверку — возвращаю прежнюю${NC}"
		echo "Если это был последний пир: хабу нужен хотя бы один пир. Чтобы выключить хаб"
		echo "целиком, выберите в меню «Снять хаб»."
		mv "$CONF.bak" "$CONF"
		return 1
	fi
	rm -f "$CONF.bak"
	hubApply || return 1
	rm -f "/root/xsteer-${name}.conf"
	echo -e "${GREEN}пир ${name} убран${NC}"
	echo "На самом пире туннель после этого не поднимется: хаб его больше не знает."
}

function showStatus() {
	echo "юнит:"
	systemctl status steer-xsteer-hub --no-pager -n 0 | sed -n '1,4p'
	echo ""
	echo "устройство:"
	# Проверяется НЕПУСТОТА вывода, а не код возврата: за конвейером код принадлежит sed,
	# который на пустом входе успешен, и «устройства нет» превратилось бы в пустую строку.
	local dev_info
	dev_info="$(ip -o addr show dev xshub0 2>/dev/null)"
	if [ -n "$dev_info" ]; then
		echo "$dev_info" | sed 's/^/  /'
	else
		echo "  xshub0 ещё не создан — значит хаб не запускался или упал при старте"
	fi
	echo ""
	echo "пира, поднимавшиеся за сутки (по журналу):"
	local hist
	hist="$(journalctl -u steer-xsteer-hub --since -1d --no-pager 2>/dev/null |
		grep -E "поднялся|согласован MTU" | tail -10)"
	if [ -n "$hist" ]; then
		echo "$hist" | sed 's/^/  /'
	else
		echo "  ни одного рукопожатия — проверьте, что порт ${HUB_PORT} открыт снаружи"
	fi
	echo ""
	listSpokes
	echo ""
	echo "полный журнал: journalctl -u steer-xsteer-hub -f"
}

function uninstallHub() {
	echo ""
	ask yn "Точно снять хаб? Пиры останутся без связи. [y/n]: " n
	[[ ${yn} =~ ^[yY]$ ]] || return 0

	systemctl disable --now steer-xsteer-hub >/dev/null 2>&1
	systemctl disable --now steer-xsteer-nat >/dev/null 2>&1
	rm -f "$UNIT" "$NATUNIT" /usr/local/sbin/steer-xsteer-nat
	rm -f /etc/sysctl.d/99-steer-xsteer.conf
	systemctl daemon-reload
	nft delete table ip steer_xsteer_nat 2>/dev/null
	ip link del xshub0 2>/dev/null

	# Ключи и конфигурации НЕ удаляются молча: восстановить их нельзя, а пира без них надо
	# перевыпускать все до одной.
	echo ""
	echo "юнит, правило NAT и sysctl убраны."
	echo "Ключи и список пиров оставлены в $CONFDIR — удалите сами, если не нужны:"
	echo "  rm -rf $CONFDIR /root/xsteer-*.conf $BIN $ENVFILE"
}

function manageMenu() {
	echo "Хаб xsteer уже стоит."
	echo ""
	echo "Что делаем?"
	echo "   1) Добавить пир"
	echo "   2) Показать пира"
	echo "   3) Убрать пир"
	echo "   4) Состояние"
	echo "   5) Снять хаб"
	echo "   6) Выход"
	local opt=""
	until [[ ${opt} =~ ^[1-6]$ ]]; do
		ask opt "Выбор [1-6]: "
	done
	case "${opt}" in
	1) newSpoke ;;
	2) listSpokes ;;
	3) revokeSpoke ;;
	4) showStatus ;;
	5) uninstallHub ;;
	6) exit 0 ;;
	esac
}

initialCheck
if [ -e "$PARAMS" ]; then
	# shellcheck source=/dev/null
	source "$PARAMS"
	manageMenu
else
	installHub
fi
