/* Корни путей движка на диске — отдельным заголовком, потому что они нужны и файлам
 * src/proto (мост tgws, хаб xsteer), которые spec.h не включают: у них свои стенды, собирающие
 * их без парсера спеки. */
#ifndef STEER_PATHS_H
#define STEER_PATHS_H

/* ---- где движок живёт на диске: роутер и Android --------------------------------------
 *
 * СБОРКА ПОД ANDROID (STEER_ANDROID) — не другой движок, а тот же, у которого другие три
 * вещи: каталоги, поле метки и приоритеты ip rule (последние две — в spec.h, у STEER_MARK_BASE
 * и STEER_RULE_PREF). Режим nft для старого ядра к ней НЕ привязан: он определяется пробой ядра
 * при apply (nft_compat в spec.c), потому что телефоны на Android 17 придут с ядрами новее
 * 5.2, и навсегда запаянная старая раскладка отняла бы у них настоящие наборы со сроками.
 *
 * ПОЧЕМУ КАТАЛОГИ МАКРОСАМИ, а не ключами командной строки. Ключи есть (--spec, --state-dir),
 * но ими не покрыть всё: пути по умолчанию для файлов выходов (xsteer, zapret, tgws), место
 * временного файла набора правил и проб, подсказки в справке. На телефоне /etc и /var — часть
 * системного раздела только для чтения, а /tmp нет вовсе; писать туда значило бы, что каждый
 * apply падает на mkstemp, а резолвер не может сохранить раздачу поддельных адресов. Поэтому
 * три корня объявлены здесь, одним местом, а весь код строит пути от них.
 *
 * /data/misc/steer — каталог, который обязан создать init-скрипт сборки (rc-файл), владелец root;
 * state и tmp внутри него, а не в /data/local/tmp: тот доступен shell-пользователю, и чужой
 * процесс мог бы подложить туда файл до нашего mkstemp или прочитать ruleset.
 *
 * Каждый макрос под #ifndef: сборка может переопределить корень ключом -D, не трогая файл
 * (так стенды держат свои пути, и так же поступит сборка с другим расположением /data). */
#ifdef STEER_ANDROID
#ifndef STEER_ETC_DIR
#define STEER_ETC_DIR   "/data/misc/steer"
#endif
#ifndef STEER_STATE_DIR
#define STEER_STATE_DIR "/data/misc/steer/state"
#endif
#ifndef STEER_TMP_DIR
#define STEER_TMP_DIR   "/data/misc/steer/tmp"
#endif
#else
#ifndef STEER_ETC_DIR
#define STEER_ETC_DIR   "/etc/steer"
#endif
#ifndef STEER_STATE_DIR
#define STEER_STATE_DIR "/var/lib/steer"
#endif
#ifndef STEER_TMP_DIR
#define STEER_TMP_DIR   "/tmp"
#endif
#endif

/* Каталог файлов, которые приложение заливает командой put-file управляющего сокета (src/daemon/ctl.c):
 * списки доменов и подсетей, файл подписки — всё, на что ссылается собранная им спека.
 *
 * Внутри каталога спеки, а не в каталоге состояния: это ДАННЫЕ настройки человека, такие же,
 * как сама спека, — резервная копия и перенос на другое устройство берут их вместе, а каталог
 * состояния движок вправе вычистить (down, смена раскладки) без потери того, что выбрал
 * человек. SELinux-метку каталог получает ту же, что всё под /data/misc/steer
 * (steerd_data_file, file_contexts vendor/der), и приложению он закрыт так же, как спека.
 * Создаёт его сам сервер при первом put-file (права 0700), а не init: каталог нужен только
 * приложению, и пока оно ничего не залило, пустой каталог ничего не даёт. */
#ifndef STEER_LISTS_DIR
#define STEER_LISTS_DIR STEER_ETC_DIR "/lists"
#endif

/* ---- узел TUN ---------------------------------------------------------------------------
 *
 * На Android ueventd создаёт его как /dev/tun (system/core/rootdir/ueventd.rc: «/dev/tun 0660
 * system vpn», метка tun_device), а /dev/net/tun там нет вовсе: открытие по роутерному пути
 * кончалось ENOENT, то есть «нет модуля tun» на ядре, где он встроен. Подсказка при отказе
 * тоже своя: kmod-tun — это пакет OpenWrt, на телефоне ставить нечего, TUN даёт ядро прошивки. */
/* Путь — под #ifndef, как каталоги выше: стенду Android-сборки на обычном Linux (tests/run-via.sh,
 * хост и vm49) узел нужен по роутерному пути, а подделывать /dev/tun в чужой системе незачем. */
#ifdef STEER_ANDROID
#ifndef STEER_TUN_DEV
#define STEER_TUN_DEV  "/dev/tun"
#endif
#define STEER_TUN_HINT "в ядре прошивки нет CONFIG_TUN"
#else
#ifndef STEER_TUN_DEV
#define STEER_TUN_DEV  "/dev/net/tun"
#endif
#define STEER_TUN_HINT "не установлен kmod-tun"
#endif

#endif
