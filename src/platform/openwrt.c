/* Роутер OpenWrt: платформа, для которой движок писался с первого выпуска.
 *
 * ---- где движок живёт на диске ---------------------------------------------------------
 *
 * ПОЧЕМУ КОРНИ ОДНИМ МЕСТОМ, а не только ключами командной строки. Ключи есть (--spec,
 * --state-dir), но ими не покрыть всё: пути по умолчанию для файлов выходов (xsteer, zapret,
 * tgws), место временного файла набора правил и проб, подсказки в справке. Поэтому три корня
 * (etc, state, tmp) объявлены в таблице платформы, а весь код строит пути от них.
 *
 * Каждый корень можно переопределить ключом сборки -D (STEER_ETC_DIR, STEER_STATE_DIR,
 * STEER_TMP_DIR, STEER_LISTS_DIR, STEER_TUN_DEV), не трогая файл: так стенды держат свои пути
 * (tests/ctnl49.sh, awgns.sh, run-via.sh), и так же поступит сборка с другим расположением.
 * Ключ действует на обе платформы сразу — стенду нужен свой каталог, на какой бы платформе
 * бинарник ни оказался. */
#include <unistd.h>
#include "platform.h"

#ifdef STEER_ETC_DIR
#define ETC STEER_ETC_DIR
#else
#define ETC "/etc/steer"
#endif
#ifdef STEER_STATE_DIR
#define STATE STEER_STATE_DIR
#else
#define STATE "/var/lib/steer"
#endif
#ifdef STEER_TMP_DIR
#define TMP STEER_TMP_DIR
#else
#define TMP "/tmp"
#endif
/* Каталог файлов put-file (src/daemon/ctl.c) — внутри каталога спеки: это данные настройки
 * человека, как сама спека (подробно — у android.c, где его и завели). */
#ifdef STEER_LISTS_DIR
#define LISTS STEER_LISTS_DIR
#else
#define LISTS ETC "/lists"
#endif
#ifdef STEER_TUN_DEV
#define TUN STEER_TUN_DEV
#else
#define TUN "/dev/net/tun"
#endif

static int openwrt_detect(void) {
    return access("/etc/openwrt_release", F_OK) == 0;
}

const struct platform_ops plat_openwrt = {
    .name = "openwrt",
    .detect = openwrt_detect,

    .etc_dir = ETC,
    .state_dir = STATE,
    .tmp_dir = TMP,
    .lists_dir = LISTS,
    .spec_path = ETC "/spec.json",
    .ctl_sock = ETC "/steer.sock",
    /* Имена таблиц для iproute2. Каталог, а не сам rt_tables: файл принадлежит пакету
     * iproute2, и дописывать в него значило бы править чужое; rt_tables.d для этого и
     * существует. */
    .rt_tables_d = "/etc/iproute2/rt_tables.d",
    .tun_dev = TUN,
    .tun_hint = "не установлен kmod-tun",
    .ca_dirs = NULL,

    /* Поле метки — восемь бит с двадцатого (контракт, docs/contract-v1.md); почему именно
     * они и с кем поле соседствует — marks.h.
     *
     * МИНИ-СБОРКА (STEER_TGWS, микропакет tgws) живёт в своём бите 28, а не в диапазоне
     * полного движка: оба ставятся рядом и метят пакеты на одном приоритете, и при общей
     * маске тот, чья цепочка идёт второй, стирал бы метку первого (подробно — marks.h). Это
     * профиль сборки, а не платформа, и развилка по нему уйдёт вместе с профилями
     * (docs/architecture.md, правило 3); пока она здесь, в данных роутера, — мини-сборка
     * бывает только на роутере. */
#ifdef STEER_TGWS
    .mark_base = 0x10000000u,
    .mark_bits = 1,
    .mark_mask = PLAT_MARK_MASK(0x10000000u, 1),
#else
    .mark_base = 0x00100000u,
    .mark_bits = 8,
    .mark_mask = PLAT_MARK_MASK(0x00100000u, 8),
#endif
    /* Приоритет правил выходов не указывается вовсе (0 — не передавать pref): ядро ставит
     * правило сразу перед первым ненулевым, то есть выше main (32766), и так движок работает
     * с первого выпуска. */
    .rule_pref = 0,
    .probe_pref = 29999,
    /* Цепочек route на output (каналов на сам роутер) нет, собственный трафик движка не
     * метится: каналы роутера — на prerouting, трафик самого роутера они не трогают. */
    .reroute_bit = 0,
    .self_mark = 0,
    .tunnel_bit = 0,
    .app_uid_min = 0,

    .local_channels = 0,
    .zapret = 1,
    .fw4 = 1,
    .netifd = 1,
    .iptables_masq = 0,
    .lan_bridge = 1,
    .warn_iptables_nat = 1,
    .dnsd_origdst = 0,                /* наверх — dnsmasq роутера на петле */
    .ctl_allow_domain = NULL,

    .os_release = "/etc/openwrt_release",
    .os_name = "OpenWrt",
    .model_path = "/tmp/sysinfo/model",
    .model_fallback = "router",
};
