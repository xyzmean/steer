#!/bin/sh
# Активное зондирование: что видит прибор, постучавшийся на порт хаба xsteer.
#
# ЗАЧЕМ ЭТОТ СТЕНД. Устойчивость к зондированию — не свойство кода, а свойство ОТВЕТА, и
# проверить её можно только настоящим клиентом TLS, который про наш протокол не знает ничего.
# Здесь это `openssl s_client`: он присылает подлинный ClientHello и печатает, что получил.
#
# Почему стенд шелловый и почему его не заменяет hubmatch. hubmatch проверяет ту же дорожку
# изнутри: он вызывает функции хаба и смотрит на байты, которые те возвращают. Это ловит
# арифметику и учёт, но не отвечает на вопрос, ради которого дорожка существует, — «отличим ли
# порт от сервера HTTPS». Отличим или нет, решает прибор, а не наш разбор своих же байтов.
#
# Стенд перенесён из реализации на Go (xsteer/tests/probe.sh) вместе с самой защитой: там она
# появилась раньше и там же проверялась настоящим openssl. Пока стенда здесь не было, четыре
# режима движка на C держались на hubmatch и на чтении кода — то есть проверялись не тем
# прибором, от которого защищаются (R-062, I-076).
#
# Пир здесь НЕ поднимается: что защита не мешает своим, проверяет tests/run-xsteer.sh — там
# звезда поднимается целиком и через неё идёт трафик. Дублировать это здесь значило бы держать
# два места, где ломается подъём туннеля, ради одного вопроса про зондирование.
#
#     sudo sh tests/probe.sh
set -u
umask 077

BUILD=${BUILD:-build}
# Хаб живёт в СЕРВЕРНОЙ сборке (-DSTEER_SERVER): на VPS нет ни спеки, ни выходов, а у роутерной
# сборки подкоманда xsteer-hub — штатная заглушка «ставится из архива steer-hub». Стенд поэтому
# просит именно серверный бинарник, а не расширенный: перепутать их легко, и молчаливо это
# выглядело бы как «хаб не поднялся».
BIN=${STEER_HUB_BIN:-$BUILD/steer-hub-native}
NSH=xsp-hub
NSA=xsp-probe
WORK=
fails=0
pass=0
ok()  { pass=$((pass + 1)); printf '    %-58s ok\n' "$1"; }
bad() { fails=$((fails + 1)); printf '    %-58s ПРОВАЛ\n' "$1"; }

cleanup() {
    for ns in $NSH $NSA; do
        ip netns pids $ns 2>/dev/null | xargs -r kill 2>/dev/null || true
        ip netns del $ns 2>/dev/null || true
    done
    [ -n "$WORK" ] && [ -z "${XSP_KEEP:-}" ] && rm -rf "$WORK"
    return 0
}
trap cleanup EXIT INT TERM HUP
cleanup

# ГРОМКИЙ пропуск, а не падение и не тишина: стенд требует root, сетевых пространств и openssl,
# и на машине без них он должен сказать это вслух. Молчаливый пропуск читается как «прошло» —
# ровно так стенд однажды и превратился в фикцию.
[ "$(id -u)" = 0 ] || { echo "probe: ПРОПУЩЕН — нужен root (сырые сокеты и netns)"; exit 0; }
command -v openssl >/dev/null 2>&1 || { echo "probe: ПРОПУЩЕН — нет openssl, прибором быть нечем"; exit 0; }
command -v ip >/dev/null 2>&1 || { echo "probe: ПРОПУЩЕН — нет iproute2"; exit 0; }
[ -x "$BIN" ] || {
    echo "probe: ПРОПУЩЕН — нет $BIN. Серверная сборка собирается так (mbedtls системный):"
    echo "        cc -O1 -w -Isrc -DSTEER_SERVER \\"
    echo "           \"-DMBEDTLS_PRIVATE(x)=x\" -o build/steer-hub-native \\"
    echo "           src/steer.c src/spec.c src/dnsd.c src/failover.c src/aggregate.c \\"
    echo "           src/obfs.c src/cli.c src/ext/xswire.c src/ext/xsconf.c src/ext/xsroute.c \\"
    echo "           src/ext/chello.c src/ext/xshake.c src/ext/xsconn.c src/ext/xsstream.c \\"
    echo "           src/ext/xsepoch.c src/ext/tls13.c src/ext/reality.c src/ext/tun.c \\"
    echo "           src/ext/h2.c src/ext/xsadmin.c src/ext/xshub.c \\"
    echo "           -lmbedtls -lmbedx509 -lmbedcrypto -lpthread"
    echo "        (на mbedtls 3.x флаг доступа другой: -DMBEDTLS_ALLOW_PRIVATE_ACCESS)"
    exit 0
}
ip netns add "$NSH" 2>/dev/null || { echo "probe: ПРОПУЩЕН — netns недоступны в этом окружении"; exit 0; }
ip netns del "$NSH" 2>/dev/null

WORK="$(mktemp -d)"; chmod 700 "$WORK"
for ns in $NSH $NSA; do ip netns add $ns; ip -n $ns link set lo up; done
ip link add hp netns $NSH type veth peer name ph netns $NSA
ip -n $NSH addr add 10.214.1.1/24 dev hp
ip -n $NSA addr add 10.214.1.2/24 dev ph
ip -n $NSH link set hp up; ip -n $NSA link set ph up

# ВЫКЛЮЧИТЬ РАЗГРУЗКУ КОНТРОЛЬНЫХ СУММ — без этого стенд врёт целиком, и врёт убедительно.
#
# Поддельный TCP хаба живёт в пользовательском пространстве и проверяет контрольную сумму сам
# (obfs_parse). На veth отправитель её не считает вовсе: ядро ставит CHECKSUM_PARTIAL и полагается
# на то, что сумму досчитает железо, которого здесь нет. Получатель видит в поле недосчитанное
# значение, наш разбор честно объявляет сегмент битым — и ни один SYN прибора до защиты не
# доезжает.
#
# Поймано этим же стендом с первого прогона: хаб печатал «сегментов 5, битых 5, SYN 0», прибор
# получал тишину, и выглядело это как «защита не работает». Разница между «движок сломан» и
# «стенд считает не то» здесь стоит целого вывода, поэтому без ethtool стенд не работает, а
# ГРОМКО пропускается.
command -v ethtool >/dev/null 2>&1 || {
    echo "probe: ПРОПУЩЕН — нет ethtool. На veth ядро не считает контрольные суммы (CHECKSUM_PARTIAL),"
    echo "        поддельный TCP проверяет их сам и отвергает каждый сегмент как битый:"
    echo "        без выключения разгрузки стенд показал бы «защита не работает» на исправном хабе."
    exit 0
}
ip netns exec $NSH ethtool -K hp tx off rx off >/dev/null 2>&1
ip netns exec $NSA ethtool -K ph tx off rx off >/dev/null 2>&1

# Ключи и конфигурация хаба. Пир в списке нужен даже без запуска: файл без пиров хаб отвергает,
# а проверяем мы не разбор файла.
eval "$("$BIN" xsteer-key | sed 's/PrivateKey *= */HUB_PRIV=/; s/PublicKey *= */HUB_PUB=/')"
eval "$("$BIN" xsteer-key | sed 's/PrivateKey *= */A_PRIV=/; s/PublicKey *= */A_PUB=/')"

# Сайт-прикрытие: НАСТОЯЩИЙ сервер TLS со своим сертификатом. Живёт в пространстве хаба — именно
# хаб к нему дозванивается, и прибор о его существовании знать не должен вовсе.
openssl req -x509 -newkey rsa:2048 -nodes -keyout "$WORK/k.pem" -out "$WORK/c.pem" \
    -days 2 -subj "/CN=decoy.example.net" >/dev/null 2>&1
start_decoy() {
    ip netns exec $NSH openssl s_server -accept 8443 -cert "$WORK/c.pem" -key "$WORK/k.pem" \
        -www -quiet >> "$WORK/decoy.log" 2>&1 &
    DECOY_PID=$!
    sleep 0.6
}
start_decoy

hub_conf() {  # $1 — значение Decoy, дальше необязательные строки
    mode="$1"; shift
    {
        printf '[Interface]\nPrivateKey = %s\nAddress = 10.90.0.1/24\nListenPort = 443\n' "$HUB_PRIV"
        printf 'Decoy = %s\n' "$mode"
        [ "$mode" = proxy ] && printf 'DecoyDest = 10.214.1.1:8443\n'
        for extra in "$@"; do printf '%s\n' "$extra"; done
        printf '\n[Peer]\nPublicKey = %s\nAllowedIPs = 10.90.0.2/32\n' "$A_PUB"
    } > "$WORK/hub.conf"
    chmod 600 "$WORK/hub.conf"
}

run_hub() {  # $1 — имя режима для журнала
    HUBLOG="$WORK/hub-$1.log"
    # Что защита не мешает своим — в run-xsteer.sh, там звезда поднимается целиком и через неё
    # идёт трафик. Здесь проверяется только то, что видит прибор.
    ip netns exec $NSH "$BIN" xsteer-hub --config "$WORK/hub.conf" \
        --state-dir "$WORK/state" > "$HUBLOG" 2>&1 &
    HUBPID=$!
    sleep 1.2
    kill -0 "$HUBPID" 2>/dev/null
}

stop_hub() {
    kill "$HUBPID" 2>/dev/null || true
    # Ждём НАСТОЯЩЕГО выхода: уходя, хаб снимает свою цепочку в nftables, и новый, успевший
    # добавить её раньше, получил бы её снос от старого. Тогда ядро начинает отвечать RST на
    # рукопожатия, и стенд падает в клетке, к которой это не имеет отношения.
    i=0
    while kill -0 "$HUBPID" 2>/dev/null && [ "$i" -lt 60 ]; do sleep 0.1; i=$((i + 1)); done
    ip netns pids $NSA 2>/dev/null | xargs -r kill 2>/dev/null || true
    sleep 0.2
    # Прикрытие поднимаем заново: s_server уходит после соединения не всегда, но надёжнее не
    # зависеть от этого.
    kill -0 "$DECOY_PID" 2>/dev/null || start_decoy
}

# Прибор: подлинный ClientHello и всё, что пришло в ответ. Имя спрашивает ЧУЖОЕ — так и делает
# прибор, которому интересно, что здесь за сервер.
probe() {  # $1 — файл вывода, $2 — имя в SNI
    ip netns exec $NSA timeout 8 openssl s_client -connect 10.214.1.1:443 \
        -servername "$2" -brief < /dev/null > "$1" 2>&1
    printf '%s' "$?" > "$1.rc"
}

echo "== что видит прибор на порту хаба =="

echo
echo "-- Decoy = alert (умолчание): фатальное оповещение TLS --"
hub_conf alert
if run_hub alert; then
    probe "$WORK/p-alert.txt" www.microsoft.com
    if grep -qiE 'handshake failure|alert|ssl3?_read|no protocols' "$WORK/p-alert.txt"; then
        ok "прибор получил отказ TLS"
    else bad "прибор получил отказ TLS"; fi
    # Отказ лучше молчания, но он же и есть та различимость, ради которой заведён proxy:
    # настоящего сертификата здесь нет.
    if grep -q 'decoy.example.net' "$WORK/p-alert.txt"; then
        bad "в режиме alert сертификата быть не должно"
    else ok "сертификата нет — порт отличим от сервера HTTPS, и это ожидаемо"; fi
    stop_hub
else bad "хаб поднялся (alert)"; stop_hub; fi

echo
echo "-- Decoy = silent: порт молчит (отличимо СИЛЬНЕЕ отказа) --"
hub_conf silent
if run_hub silent; then
    probe "$WORK/p-silent.txt" www.microsoft.com
    # Молчание — не «лучше отказа», а хуже: открытый порт, не ответивший на ClientHello,
    # рассказывает о себе больше, чем порт, ответивший отказом. Режим есть потому, что бывает
    # нужен, а не потому, что рекомендован; стенд это и закрепляет.
    # Проверяется ОТСУТСТВИЕ рукопожатия, а не конкретное слово в выводе openssl. Как именно
    # выглядит молчание, зависит от окружения: в netns через veth прибор получает
    # write:errno=104 (сессия поддельного TCP встала, ответа на Hello нет, дальше разрыв), на
    # настоящем канале это чаще таймаут. Отличимость от настоящего сервера даёт не слово, а
    # отсутствие ServerHello — на него и смотрим.
    if grep -qiE 'Protocol version|Ciphersuite' "$WORK/p-silent.txt"; then
        bad "рукопожатия в режиме silent быть не должно"
    else ok "рукопожатия нет"; fi
    if grep -q 'decoy.example.net' "$WORK/p-silent.txt"; then
        bad "сертификата в режиме silent быть не должно"
    else ok "сертификата нет"; fi
    stop_hub
else bad "хаб поднялся (silent)"; stop_hub; fi

echo
echo "-- Decoy = reset: разрыв --"
hub_conf reset
if run_hub reset; then
    probe "$WORK/p-reset.txt" www.microsoft.com
    # Важно не то, каким словом openssl назовёт разрыв (у него их несколько), а то, что
    # рукопожатия с сертификатом не состоялось.
    if grep -qiE 'decoy.example.net|Protocol version|Ciphersuite' "$WORK/p-reset.txt"; then
        bad "рукопожатия в режиме reset быть не должно"
    else ok "рукопожатия нет"; fi
    stop_hub
else bad "хаб поднялся (reset)"; stop_hub; fi

echo
echo "-- Decoy = proxy: прибор видит НАСТОЯЩИЙ сервер --"
hub_conf proxy
if run_hub proxy; then
    probe "$WORK/p-proxy.txt" www.microsoft.com
    # Главная проверка всего стенда: подлинный ServerHello и подлинный сертификат прикрытия.
    if grep -q 'decoy.example.net' "$WORK/p-proxy.txt"; then
        ok "пришёл подлинный сертификат прикрытия"
    else bad "пришёл подлинный сертификат прикрытия"; fi
    if grep -qiE 'Protocol version|Ciphersuite|Verification' "$WORK/p-proxy.txt"; then
        ok "рукопожатие TLS состоялось целиком"
    else bad "рукопожатие TLS состоялось целиком"; fi
    if grep -qiE 'handshake failure|no protocols available' "$WORK/p-proxy.txt"; then
        bad "отказа быть не должно"
    else ok "отказа нет"; fi
    # Ради этой строки стенд и существует: у трёх других режимов рукопожатия нет вовсе, у
    # четвёртого оно состоялось целиком и с чужим сертификатом. Это и есть «порт неотличим от
    # сервера HTTPS» — утверждение, которое нельзя проверить своим же разбором своих байтов.
    if grep -qiE 'Verification' "$WORK/p-proxy.txt"; then
        ok "прибор дошёл до проверки сертификата — как у обычного сервера"
    else bad "прибор дошёл до проверки сертификата"; fi
    stop_hub
else bad "хаб поднялся (proxy)"; stop_hub; fi

echo
echo "-- мусор вместо TLS: открытый порт не должен МОЛЧАТЬ --"
# В реализации на Go это нашлось только стендом: прибор, приславший «GET / HTTP/1.1», не
# получал ничего, и молчание на обычном запросе — признак не хуже молчания на Hello.
hub_conf proxy
if run_hub garbage; then
    # Прибором служит отдельный скрипт (tests/probe-garbage.py), а не nc: nc есть не везде, а
    # вложенный heredoc внутри стенда — место, где ошибаются молча.
    if command -v python3 >/dev/null 2>&1; then
        ip netns exec $NSA python3 "$(dirname "$0")/probe-garbage.py" 10.214.1.1 443 6 \
            > "$WORK/p-http.txt" 2>&1
        if grep -qE 'ОТВЕТ|РАЗРЫВ' "$WORK/p-http.txt"; then
            ok "на «GET /» пришёл ответ, а не тишина"
        else
            bad "на «GET /» пришёл ответ, а не тишина"
            sed 's/^/       /' "$WORK/p-http.txt" | head -2
        fi
    else
        printf '    %-58s пропуск (нет python3)\n' "на «GET /» пришёл ответ"
    fi
    stop_hub
else bad "хаб поднялся (мусор)"; stop_hub; fi

echo
echo "-- DecoySNI: прикрытие выбирает сам прибор --"
# Имя разрешается один раз при подъёме; здесь оно указано адресом через /etc/hosts netns не
# получится, поэтому проверяется другое утверждение того же ключа: незнакомое имя ведёт к
# прежнему поведению (DecoyDest), а не к отказу. Отказывай хаб по незнакомому имени, порт
# начал бы отвечать по-разному на разные имена — и сама разница рассказывала бы прибору,
# какие имена мы обслуживаем.
hub_conf proxy "DecoySNI = decoy.example.net"
if run_hub sni; then
    probe "$WORK/p-sni.txt" совсем-другое-имя.invalid
    if grep -q 'decoy.example.net' "$WORK/p-sni.txt"; then
        ok "незнакомое имя ведёт к DecoyDest, а не к отказу"
    else bad "незнакомое имя ведёт к DecoyDest, а не к отказу"; fi
    stop_hub
else bad "хаб поднялся (DecoySNI)"; stop_hub; fi

echo
echo "-- настройка защиты проверяется ДО подъёма --"
# Неверная настройка защиты, обнаруженная под зондированием, — это защита, которой нет.
{
    printf '[Interface]\nPrivateKey = %s\nAddress = 10.90.0.1/24\nListenPort = 443\nDecoy = proxy\n' "$HUB_PRIV"
    printf '\n[Peer]\nPublicKey = %s\nAllowedIPs = 10.90.0.2/32\n' "$A_PUB"
} > "$WORK/bad.conf"
chmod 600 "$WORK/bad.conf"
ip netns exec $NSH "$BIN" xsteer-hub --config "$WORK/bad.conf" --state-dir "$WORK/state" \
    > "$WORK/p-bad.txt" 2>&1
rc=$?
if [ "$rc" != 0 ]; then ok "proxy без DecoyDest отвергнут до подъёма (код $rc)"
else bad "proxy без DecoyDest отвергнут до подъёма"; fi

printf '\n%d проверок пройдено' "$pass"
if [ "$fails" -gt 0 ]; then printf ', %d ПРОВАЛЕНО\n' "$fails"; exit 1; fi
printf '\nвсе проверки прошли\n'
