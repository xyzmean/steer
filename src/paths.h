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

#endif
