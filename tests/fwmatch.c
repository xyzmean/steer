/* Проверка зависимости выхода от firewall: что движок засчитывает как «здесь есть
 * masquerade», а что нет.
 *
 * Зачем отдельным стендом. fw_check() — единственное место, где движок судит о чужой
 * конфигурации, и судит её ТЕКСТОМ: он читает дамп `nft list ruleset` и ищет в нём
 * признаки. Признак — эвристика, а эвристика проверяется только примерами; ошибка же
 * здесь не видна как сбой: движок работает, трафик идёт, а человек читает в диагностике
 * «у warp0 нет masquerade» при включённом masq и идёт чинить то, что не сломано. Ложная
 * тревога дороже отсутствующей — по ней настраивают лишнее и перестают верить настоящим.
 *
 * Дамп берётся из живого fw4 (OpenWrt 25.12, стенд): формы строк здесь не придуманы, а
 * скопированы, включая то, что имя ЗОНЫ и имя УСТРОЙСТВА — разные вещи, совпадающие лишь
 * по привычке называть зону как интерфейс.
 *
 * Дотянуться до fw_check иначе нельзя: она статическая, а данные берёт из popen(). Поэтому
 * стенд включает исходник движка и подменяет popen/pclose на чтение из памяти (fmemopen) —
 * тот же приём, что в specmatch.c с exit: проверяется настоящая функция, а не её копия,
 * и ради теста в движок не добавляется ни строки. */
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

static const char *g_ruleset;    /* что «вернёт» nft этому вызову */

static FILE *test_popen(const char *cmd, const char *mode) {
    (void)cmd; (void)mode;
    return fmemopen((void *)g_ruleset, strlen(g_ruleset), "r");
}

#define popen(cmd, mode) test_popen(cmd, mode)
#define pclose(f) fclose(f)
#define main steer_main_unused

#include "../src/steer.c"

#undef popen
#undef pclose
#undef main

static int g_fail;

static void check(const char *what, int got, int want) {
    if (got == want) return;
    fprintf(stderr, "fwmatch: %s: получено %d, ожидалось %d\n", what, got, want);
    g_fail++;
}

static void probe(const char *what, const char *ruleset, const char *device,
                  int want_in_firewall, int want_masq) {
    char label[256];
    g_ruleset = ruleset;
    struct fwcheck r = fw_check(device);
    snprintf(label, sizeof(label), "%s — устройство в firewall", what);
    check(label, r.in_firewall, want_in_firewall);
    snprintf(label, sizeof(label), "%s — masquerade", what);
    check(label, r.masqueraded, want_masq);
}

/* Зона названа так же, как устройство (warp0). Так выглядит роутер, где зону завёл
 * splify2 или человек, повторивший имя интерфейса, — этот случай работал и до правки. */
static const char RS_ZONE_EQ_DEVICE[] =
"table inet fw4 {\n"
"	chain srcnat {\n"
"		type nat hook postrouting priority srcnat; policy accept;\n"
"		oifname \"br-lan\" jump srcnat_lan comment \"!fw4: Handle lan IPv4/IPv6 srcnat traffic\"\n"
"		oifname \"wan\" jump srcnat_wan comment \"!fw4: Handle wan IPv4/IPv6 srcnat traffic\"\n"
"		oifname \"warp0\" jump srcnat_warp0 comment \"!fw4: Handle warp0 IPv4/IPv6 srcnat traffic\"\n"
"	}\n"
"	chain srcnat_lan {\n"
"	}\n"
"	chain srcnat_wan {\n"
"		meta nfproto ipv4 masquerade comment \"!fw4: Masquerade IPv4 wan traffic\"\n"
"	}\n"
"	chain srcnat_warp0 {\n"
"		meta nfproto ipv4 masquerade comment \"!fw4: Masquerade IPv4 warp0 traffic\"\n"
"	}\n"
"}\n";

/* То же самое, но зона названа vpn, а устройство осталось warp0 — обычный случай для
 * того, кто заводил зону руками по любому руководству. Устройство не стоит рядом со
 * словом masquerade НИ В ОДНОЙ строке набора: fw4 пишет в цепочку и в комментарий имя
 * зоны, а устройство называет только на переходе. Ровно этот дамп снят со стенда. */
static const char RS_ZONE_RENAMED[] =
"table inet fw4 {\n"
"	chain srcnat {\n"
"		type nat hook postrouting priority srcnat; policy accept;\n"
"		oifname \"br-lan\" jump srcnat_lan comment \"!fw4: Handle lan IPv4/IPv6 srcnat traffic\"\n"
"		oifname \"wan\" jump srcnat_wan comment \"!fw4: Handle wan IPv4/IPv6 srcnat traffic\"\n"
"		oifname \"warp0\" jump srcnat_vpn comment \"!fw4: Handle vpn IPv4/IPv6 srcnat traffic\"\n"
"	}\n"
"	chain srcnat_lan {\n"
"	}\n"
"	chain srcnat_wan {\n"
"		meta nfproto ipv4 masquerade comment \"!fw4: Masquerade IPv4 wan traffic\"\n"
"	}\n"
"	chain srcnat_vpn {\n"
"		meta nfproto ipv4 masquerade comment \"!fw4: Masquerade IPv4 vpn traffic\"\n"
"	}\n"
"}\n";

/* Цепочка зоны есть, masquerade в ней нет (так выглядит lan). Устройство упомянуто
 * firewall'ом, но NAT ему не делают — предупреждение обязано остаться. */
static const char RS_ZONE_NO_MASQ[] =
"table inet fw4 {\n"
"	chain srcnat {\n"
"		type nat hook postrouting priority srcnat; policy accept;\n"
"		oifname \"tun0\" jump srcnat_guest comment \"!fw4: Handle guest IPv4/IPv6 srcnat traffic\"\n"
"		oifname \"wan\" jump srcnat_wan comment \"!fw4: Handle wan IPv4/IPv6 srcnat traffic\"\n"
"	}\n"
"	chain srcnat_guest {\n"
"	}\n"
"	chain srcnat_wan {\n"
"		meta nfproto ipv4 masquerade comment \"!fw4: Masquerade IPv4 wan traffic\"\n"
"	}\n"
"}\n";

/* Явный snat вместо masquerade, зона снова названа иначе. */
static const char RS_SNAT_RENAMED[] =
"table inet fw4 {\n"
"	chain srcnat {\n"
"		oifname \"proton_nl\" jump srcnat_vpn comment \"!fw4: Handle vpn IPv4/IPv6 srcnat traffic\"\n"
"	}\n"
"	chain srcnat_vpn {\n"
"		meta nfproto ipv4 snat to 10.2.0.2 comment \"!fw4: SNAT vpn traffic\"\n"
"	}\n"
"}\n";

/* Устройство называет только наша собственная таблица. Про NAT это не говорит ничего,
 * и про зону тоже: steer сам себе не firewall. */
static const char RS_ONLY_STEER[] =
"table inet fw4 {\n"
"	chain srcnat {\n"
"		oifname \"wan\" jump srcnat_wan comment \"!fw4: Handle wan IPv4/IPv6 srcnat traffic\"\n"
"	}\n"
"	chain srcnat_wan {\n"
"		meta nfproto ipv4 masquerade comment \"!fw4: Masquerade IPv4 wan traffic\"\n"
"	}\n"
"}\n"
"table inet steer {\n"
"	chain forward {\n"
"		oifname \"warp0\" counter accept\n"
"		meta l4proto tcp oifname \"warp0\" masquerade\n"
"	}\n"
"}\n";

int main(void) {
    /* 1. Зона = имя устройства: и раньше засчитывалось, и обязано засчитываться дальше. */
    probe("зона названа как устройство", RS_ZONE_EQ_DEVICE, "warp0", 1, 1);

    /* 2. Тот же роутер, зона названа vpn. До правки здесь было «нет masquerade»
     *    при работающем NAT — жалоба из splicicd#8. */
    probe("зона названа иначе, чем устройство", RS_ZONE_RENAMED, "warp0", 1, 1);

    /* 3. Соседнее устройство той же таблицы не должно получить чужой вердикт. */
    probe("устройство соседней зоны без masquerade", RS_ZONE_RENAMED, "br-lan", 1, 0);

    /* 4. Зона есть, masquerade в ней нет — предупреждение остаётся. Это направление
     *    ошибки, ради которого проверка вообще написана: ложное «всё в порядке» хуже
     *    ложной тревоги. */
    probe("зона без masquerade", RS_ZONE_NO_MASQ, "tun0", 1, 0);

    /* 5. Устройства нет в наборе вовсе. */
    probe("устройство не упомянуто", RS_ZONE_NO_MASQ, "warp0", 0, 0);

    /* 6. Явный snat засчитывается наравне с masquerade. */
    probe("snat в переименованной зоне", RS_SNAT_RENAMED, "proton_nl", 1, 1);

    /* 7. Подстрока не отвечает за целое имя: warp ≠ warp0, иначе выход на несуществующем
     *    устройстве отчитался бы чужим NAT. */
    probe("warp не отвечает за warp0", RS_ZONE_RENAMED, "warp", 0, 0);

    /* 8. Собственная таблица движка не доказывает ни зоны, ни NAT. */
    probe("только table inet steer", RS_ONLY_STEER, "warp0", 0, 0);

    if (g_fail) {
        fprintf(stderr, "fwmatch: провалено проверок: %d\n", g_fail);
        return 1;
    }
    printf("fwmatch: 16/16 проверок пройдено\n");
    return 0;
}
