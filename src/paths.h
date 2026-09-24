/* Корни путей движка на диске — отдельным заголовком, потому что они нужны и файлам
 * src/ext (мост tgws, хаб xsteer), которые spec.h не включают: у них свои стенды, собирающие
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

/* ---- узел TUN ---------------------------------------------------------------------------
 *
 * На Android ueventd создаёт его как /dev/tun (system/core/rootdir/ueventd.rc: «/dev/tun 0660
 * system vpn», метка tun_device), а /dev/net/tun там нет вовсе: открытие по роутерному пути
 * кончалось ENOENT, то есть «нет модуля tun» на ядре, где он встроен. Подсказка при отказе
 * тоже своя: kmod-tun — это пакет OpenWrt, на телефоне ставить нечего, TUN даёт ядро прошивки. */
#ifdef STEER_ANDROID
#define STEER_TUN_DEV  "/dev/tun"
#define STEER_TUN_HINT "в ядре прошивки нет CONFIG_TUN"
#else
#define STEER_TUN_DEV  "/dev/net/tun"
#define STEER_TUN_HINT "не установлен kmod-tun"
#endif

#endif
