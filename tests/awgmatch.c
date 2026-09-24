/* Выход kind=awg без ядра: разбор файла awg-quick, спека, сборка сообщений netlink.
 *
 * ЗАЧЕМ ОТДЕЛЬНЫМ СТЕНДОМ. Ошибка в любой из трёх частей не выглядит ошибкой снаружи:
 *   - разбор, принявший чужой файл «почти правильно» (ключ из 43 знаков, IPv6 без скобок,
 *     AllowedIPs со второй строки, потерянные при этом), даёт туннель, который поднят и молчит;
 *   - сообщение netlink с атрибутом не той ширины ядро со строгой проверкой отвергает, а
 *     старое 4.9 читает по младшим байтам — то есть на стенде работает, на телефоне нет. H1
 *     у модуля AmneziaWG трёх версий записывается тремя разными способами (u32, строка, u64),
 *     и перепутанная версия даёт устройство с другими заголовками, чем у сервера;
 *   - имя устройства, выданное не по правилу, — это «wg0» в списке интерфейсов телефона, то
 *     есть ровно тот след, которого владелец просил не оставлять.
 * Всё это проверяется в памяти, без CAP_NET_ADMIN: ядро здесь не нужно. Поведение с ядром —
 * tests/awgns.sh (свежее ядро, модуль wireguard, без AmneziaWG — там же отказ без модуля) и
 * tests/awg49e.sh (ядро 4.9 с модулем AmneziaWG).
 *
 * Стенд включает исходники spec.c и awg.c целиком: die() в spec.c зовёт exit(2), и отказ
 * спеки ловится тем же приёмом, что в specmatch.c (exit подменён longjmp). run_quiet — заглушка:
 * до команд ip стенд не доходит. */
#include <setjmp.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>

static jmp_buf g_jmp;
static int g_exit_code;
#define exit(code) (g_exit_code = (code), longjmp(g_jmp, 1))
#include "../src/spec.c"
#undef exit

int run_quiet(const char *const argv[]) { (void)argv; return 0; }

#include "../src/awg.c"

static int fails, passes;

static void check(const char *what, long want, long got) {
    if (want == got) { passes++; printf("ok   %s\n", what); return; }
    fails++;
    printf("FAIL %s\n  expected: %ld\n  actual:   %ld\n", what, want, got);
}

static void check_str(const char *what, const char *want, const char *got) {
    if (!strcmp(want, got)) { passes++; printf("ok   %s\n", what); return; }
    fails++;
    printf("FAIL %s\n  expected: \"%s\"\n  actual:   \"%s\"\n", what, want, got);
}

static void check_mem(const char *what, const void *want, const void *got, size_t n) {
    if (!memcmp(want, got, n)) { passes++; printf("ok   %s\n", what); return; }
    fails++;
    printf("FAIL %s\n  expected:", what);
    for (size_t i = 0; i < n; i++) printf(" %02x", ((const uint8_t *)want)[i]);
    printf("\n  actual:  ");
    for (size_t i = 0; i < n; i++) printf(" %02x", ((const uint8_t *)got)[i]);
    printf("\n");
}

/* Ключи — только для стенда (сгенерированы `wg genkey` и нигде больше не используются). */
#define PRIV  "YAnz5TF+lXXJte14tji3zlMNq+hd2rYUIgJBgB3fBmk="
#define PRIV_HEX "6009f3e5317e9575c9b5ed78b638b7ce530dabe85ddab614220241801ddf0669"
#define PUB1  "JrqlBksd+vEdWt5BfiwipZTlnyF1i6douaEj/lMIYy0="
#define PUB2  "cDXZqx4jwB7zS8czqE9gqbfWe/TdnHNmwHfxZL3cmHU="
#define PSK   "E8kLZsHP24ArgYb+BUoBd3QaUfKvnmMB94ZHOzHeMiE="

static void hex(const char *h, uint8_t *out, size_t n) {
    for (size_t i = 0; i < n; i++) { unsigned v; sscanf(h + 2 * i, "%2x", &v); out[i] = (uint8_t)v; }
}

static struct awg_conf C;
static struct awg_secrets S;
static char E[256];

static int parse(const char *t) {
    awg_conf_free(&C);
    return awg_conf_parse(t, strlen(t), &C, &S, E, sizeof E);
}

/* ---- мини-разбор собранного сообщения ---------------------------------------------- */
static const struct nlattr *find(const void *p, size_t len, int type) {
    const uint8_t *q = p, *end = q + len;
    while (q + NLA_HDRLEN <= end) {
        const struct nlattr *a = (const void *)q;
        if (a->nla_len < NLA_HDRLEN || q + a->nla_len > end) return NULL;
        if ((a->nla_type & NLA_TYPE_MASK) == type) return a;
        q += NLA_ALIGN(a->nla_len);
    }
    return NULL;
}
/* n-й элемент массива вложенных атрибутов (тип 0 у всех). */
static const struct nlattr *nth(const struct nlattr *arr, int n) {
    const uint8_t *q = NLA_DATA(arr), *end = q + NLA_PLEN(arr);
    for (int i = 0; q + NLA_HDRLEN <= end; i++) {
        const struct nlattr *a = (const void *)q;
        if (i == n) return a;
        q += NLA_ALIGN(a->nla_len);
    }
    return NULL;
}
#define TOP(buf) ((const uint8_t *)(buf) + NLMSG_HDRLEN + NLMSG_ALIGN(sizeof(struct genlmsghdr)))
#define TOPLEN(buf, n) ((n) - NLMSG_HDRLEN - NLMSG_ALIGN(sizeof(struct genlmsghdr)))

static uint32_t u32of(const struct nlattr *a) { uint32_t v = 0; if (a) memcpy(&v, NLA_DATA(a), 4); return v; }
static uint16_t u16of(const struct nlattr *a) { uint16_t v = 0; if (a) memcpy(&v, NLA_DATA(a), 2); return v; }
static uint64_t u64of(const struct nlattr *a) { uint64_t v = 0; if (a) memcpy(&v, NLA_DATA(a), 8); return v; }

/* ---- спека -------------------------------------------------------------------------- */
static int spec_str(const char *body) {
    char path[] = "/tmp/awgmatch-spec-XXXXXX";
    int fd = mkstemp(path);
    if (fd < 0) return -1;
    FILE *f = fdopen(fd, "w");
    fprintf(f, "{\"schema\":1,%s}", body);
    fclose(f);
    g_out_n = 0; g_ch_n = 0;
    memset(g_out, 0, sizeof g_out);
    int rc;
    if (setjmp(g_jmp) == 0) { load_spec(path); rc = 0; }
    else rc = g_exit_code;
    unlink(path);
    return rc;
}

int main(void) {
    /* ---- 1. разбор полного файла ------------------------------------------------------- */
    const char *full =
        "# файл Amnezia, как его выдаёт приложение\n"
        "[Interface]\n"
        "PrivateKey = " PRIV "\n"
        "Address = 10.8.0.2/32, fd00:8::2/128\n"
        "address = 10.8.1.2\n"                       /* второй строкой и без префикса */
        "DNS = 1.1.1.1, 8.8.8.8\n"
        "MTU = 1380\n"
        "ListenPort = 51999\n"
        "Jc = 4\nJmin = 40\nJmax = 70\nS1 = 15\nS2 = 18\nS3 = 20\nS4 = 22\n"
        "H1 = 100-200\nH2 = 300\nH3 = 400-500\nH4 = 600-700\n"
        "I1 = <b 0xc6000000010843290a47ba8ba2ed000044d0e3efd9326adb60561baa3bc4b52471b2d459ddcc9a508dffddfc4d8d2e1fdde1f4b8>< r 16>\n"
        "I3 = <b 0xabcd>\n"
        "I2 =\n"                                     /* пустое — как отсутствие */
        "ContentPaddingAddition = 8-16\n"
        "RekeyAfterTime = 300\n"
        "RandomTrailers = true\n"
        "Table = off\nPostUp = iptables -A FORWARD -j ACCEPT\nFwMark = 0x10\n"
        "\n[Peer]\n"
        "PublicKey = " PUB1 "\n"
        "PresharedKey = " PSK "\n"
        "Endpoint = [2001:db8::1]:51820\n"
        "AllowedIPs = 0.0.0.0/0, ::/0\n"
        "AllowedIPs = 192.168.5.0/24\n"             /* второй строкой — дописывается */
        "PersistentKeepalive = 25\n"
        "[peer]\n"
        "publickey = " PUB2 "\n"
        "Endpoint = vpn.example.org:443\n"
        "AllowedIPs = 10.99.0.0/16\n";
    check("полный файл разобран", 0, parse(full));
    if (E[0]) printf("  (%s)\n", E);
    uint8_t want[32];
    hex(PRIV_HEX, want, 32);
    check_mem("PrivateKey раскодирован из base64", want, S.priv, 32);
    check("адресов три (две строки Address)", 3, (long)C.addr_n);
    check("Address без префикса — /32", 32, C.addr[2].cidr);
    check("Address v6 — семейство", AF_INET6, C.addr[1].family);
    check("MTU", 1380, C.mtu);
    check("ListenPort", 51999, C.listen_port);
    check("DNS посчитан (не применяется)", 1, C.dns_n);
    check("Table, PostUp, FwMark — отмечены как неисполняемые",
          AWG_IGN_TABLE | AWG_IGN_SCRIPTS | AWG_IGN_FWMARK, C.ignored);
    check("Jc", 4, C.u16[AWG_JC]);
    check("S4", 22, C.u16[AWG_S4]);
    check("J/S заданы все семь", 0x7f, C.u16_has);
    check("H1 диапазон lo", 100, (long)(uint32_t)C.h[0]);
    check("H1 диапазон hi", 200, (long)(C.h[0] >> 32));
    check("H2 одно число: lo == hi", 1, (uint32_t)C.h[1] == (uint32_t)(C.h[1] >> 32));
    check("I1 взят целиком, с пробелами внутри", 1, C.istr[0] && strstr(C.istr[0], "< r 16>") != NULL);
    check("I2 пустой — отсутствует", 1, C.istr[1] == NULL);
    check("I3 задан", 1, C.istr[2] && !strcmp(C.istr[2], "<b 0xabcd>"));
    check("ContentPaddingAddition 8-16 упакован lo | hi<<16", 8 | (16 << 16), C.r16[AWG_CPA]);
    check("RandomTrailers", 1, C.u8v[AWG_RANDOM_TRAILERS]);
    check("пиров два (раздел [peer] в нижнем регистре)", 2, (long)C.peer_n);
    check("Endpoint [IPv6]:порт — хост без скобок", 1, !strcmp(C.peer[0].ep_host, "2001:db8::1"));
    check("Endpoint порт", 51820, C.peer[0].ep_port);
    check("Endpoint с именем сохранён как имя", 1, !strcmp(C.peer[1].ep_host, "vpn.example.org"));
    check("AllowedIPs первого пира: три (две строки)", 3, (long)C.peer[0].aip_n);
    check("AllowedIPs второго пира — свой срез", 1, (long)C.peer[1].aip_n);
    check("срез второго пира начинается после первого", 3, (long)C.peer[1].aip_first);
    check("::/0 — префикс 0", 0, C.aips[1].cidr);
    check("PSK у первого пира", 1, C.peer[0].has_psk);
    check("PSK у второго нет", 0, C.peer[1].has_psk);
    check("PersistentKeepalive 25 (lo == hi)", 25 | (25 << 16), C.peer[0].keepalive);
    check("keepalive второго по умолчанию выключен (батарея)", 0, C.peer[1].keepalive);
    check("нужен AmneziaWG", 1, awg_conf_needs_awg(&C));
    const char *why = NULL;
    check("версия интерфейса — 3 (параметры AmneziaWG 3)", 3, awg_conf_min_version(&C, &why));

    /* ---- 2. ключи base64 --------------------------------------------------------------- */
    uint8_t k[32];
    check("ключ: 44 знака — годен", 0, key_from_b64(k, PRIV));
    check("ключ: 43 знака — отказ", -1, key_from_b64(k, "YAnz5TF+lXXJte14tji3zlMNq+hd2rYUIgJBgB3fBmk"));
    check("ключ: без '=' в конце — отказ", -1, key_from_b64(k, "YAnz5TF+lXXJte14tji3zlMNq+hd2rYUIgJBgB3fBmkA"));
    check("ключ: чужой знак — отказ", -1, key_from_b64(k, "YAnz5TF+lXXJte14tji3zlMNq+hd2rYUIgJBgB3f-mk="));
    check("ключ: лишние биты в последнем знаке — отказ", -1,
          key_from_b64(k, "YAnz5TF+lXXJte14tji3zlMNq+hd2rYUIgJBgB3fBmn="));

    /* ---- 3. ошибки, и в тексте ошибки нет значений ------------------------------------ */
#define IFACE "[Interface]\nPrivateKey = " PRIV "\n"
#define PEER1 "[Peer]\nPublicKey = " PUB1 "\n"
    check("без PrivateKey — отказ", -1, parse("[Interface]\nAddress = 10.0.0.2\n" PEER1));
    check("без [Peer] — отказ", -1, parse(IFACE));
    check("неизвестный параметр — отказ", -1, parse(IFACE "Foo = 1\n" PEER1));
    check("  и ошибка называет его", 1, strstr(E, "Foo") != NULL);
    check("IPv6 в Endpoint без скобок — отказ", -1, parse(IFACE PEER1 "Endpoint = 2001:db8::1:51820\n"));
    check("порт Endpoint 0 — отказ", -1, parse(IFACE PEER1 "Endpoint = 1.2.3.4:0\n"));
    check("Endpoint без порта — отказ", -1, parse(IFACE PEER1 "Endpoint = 1.2.3.4\n"));
    check("Jmin > Jmax — отказ", -1, parse(IFACE "Jc = 3\nJmin = 90\nJmax = 10\n" PEER1));
    check("H пересекаются — отказ", -1, parse(IFACE "H1 = 100-200\nH2 = 150\n" PEER1));
    check("повтор PublicKey — отказ", -1, parse(IFACE PEER1 PEER1));
    check("AllowedIPs с негодным префиксом — отказ", -1, parse(IFACE PEER1 "AllowedIPs = 10.0.0.0/33\n"));
    check("MTU 100 — отказ", -1, parse(IFACE "MTU = 100\n" PEER1));
    check("PrivateKey негодный — отказ", -1,
          parse("[Interface]\nPrivateKey = SECRETSECRETSECRET\n" PEER1));
    check("  и значения ключа в ошибке нет", 1, strstr(E, "SECRET") == NULL);
    check("параметр вне раздела — отказ", -1, parse("PrivateKey = " PRIV "\n" PEER1));
    check("после отказа секреты затёрты", 1, !S.has_priv && S.priv[0] == 0 && S.priv[31] == 0);

    /* ---- 4. обычный WireGuard: модуль AmneziaWG не нужен ----------------------------- */
    check("файл WireGuard разобран", 0,
          parse(IFACE "Address = 10.0.0.2/24\n" PEER1 "Endpoint = 1.2.3.4:51820\nAllowedIPs = 0.0.0.0/0\n"));
    check("обычному WireGuard AmneziaWG не нужен", 0, awg_conf_needs_awg(&C));
    check("нулевые Jc/S и H1..H4 = 1..4 — всё ещё обычный WireGuard", 0,
          (parse(IFACE "Jc = 0\nS1 = 0\nH1 = 1\nH2 = 2\nH3 = 3\nH4 = 4\n" PEER1), awg_conf_needs_awg(&C)));
    check("AmneziaWG 1.0 (J, S1, S2, H числом) — версия 1", 1,
          (parse(IFACE "Jc = 4\nJmin = 8\nJmax = 80\nS1 = 10\nS2 = 20\nH1 = 11\nH2 = 22\nH3 = 33\nH4 = 44\n" PEER1),
           awg_conf_min_version(&C, NULL)));
    check("  и ему AmneziaWG нужен", 1, awg_conf_needs_awg(&C));
    check("S3 — версия 2", 2, (parse(IFACE "S3 = 5\n" PEER1), awg_conf_min_version(&C, NULL)));
    check("диапазон H — версия 2", 2, (parse(IFACE "H1 = 10-20\n" PEER1), awg_conf_min_version(&C, NULL)));
    check("диапазон keepalive — версия 3", 3,
          (parse(IFACE PEER1 "PersistentKeepalive = 20-30\n"), awg_conf_min_version(&C, NULL)));

    /* ---- 5. сборка сообщений: побайтно ------------------------------------------------ */
    {
        uint8_t b[128];
        size_t n = awg_build_getfamily(b, sizeof b, "amneziawg", 7);
        static const uint8_t g[] = {
            36, 0, 0, 0,  0x10, 0,  1, 0,  7, 0, 0, 0,  0, 0, 0, 0,       /* nlmsghdr: GENL_ID_CTRL */
            3, 1, 0, 0,                                                   /* CTRL_CMD_GETFAMILY, v1 */
            14, 0, 2, 0, 'a', 'm', 'n', 'e', 'z', 'i', 'a', 'w', 'g', 0, 0, 0, /* FAMILY_NAME */
        };
        check("CTRL_CMD_GETFAMILY: длина", sizeof g, (long)n);
        check_mem("CTRL_CMD_GETFAMILY: байты", g, b, sizeof g);

        n = awg_build_newlink(b, sizeof b, "ifab", "amneziawg", 1420, 9);
        static const uint8_t l[] = {
            72, 0, 0, 0,  16, 0,  0x05, 0x06,  9, 0, 0, 0,  0, 0, 0, 0,  /* RTM_NEWLINK, REQ|ACK|EXCL|CREATE */
            0, 0, 0, 0,  0, 0, 0, 0,  0, 0, 0, 0,  0, 0, 0, 0,           /* ifinfomsg */
            9, 0, 3, 0, 'i', 'f', 'a', 'b', 0, 0, 0, 0,                   /* IFLA_IFNAME */
            8, 0, 4, 0, 0x8c, 0x05, 0, 0,                                 /* IFLA_MTU 1420 */
            20, 0, 18, 0x80,                                              /* IFLA_LINKINFO | NESTED */
            14, 0, 1, 0, 'a', 'm', 'n', 'e', 'z', 'i', 'a', 'w', 'g', 0, 0, 0, /* IFLA_INFO_KIND */
        };
        check("RTM_NEWLINK: длина", sizeof l, (long)n);
        check_mem("RTM_NEWLINK: байты", l, b, sizeof l);
    }

    /* SET_DEVICE — ключевые атрибуты по версиям. */
    const char *setconf =
        IFACE "Jc = 4\nJmin = 8\nJmax = 80\nS1 = 10\nS2 = 20\nH1 = 11\nH2 = 22\nH3 = 33\nH4 = 44\n"
        PEER1 "PresharedKey = " PSK "\nEndpoint = 192.0.2.7:51820\n"
        "AllowedIPs = 0.0.0.0/0, fd00::/8\nPersistentKeepalive = 25\n";
    check("файл для сборки разобран", 0, parse(setconf));
    check("литерал Endpoint разрешается без сети", 0, resolve_peers(&C, "ifab", 0, 0));
    static uint8_t m[65536];
    for (int ver = 1; ver <= 3; ver++) {
        char t[96];
        size_t n = awg_build_set(m, sizeof m, 0x22, ver, 1, "ifab", &C, &S, 0x00c00000, 0, 11);
        snprintf(t, sizeof t, "SET v%d: сообщение собрано", ver);
        check(t, 1, n > 0);
        const struct nlmsghdr *nh = (const void *)m;
        const struct genlmsghdr *gh = NLMSG_DATA(nh);
        snprintf(t, sizeof t, "SET v%d: тип — номер семейства, команда SET_DEVICE", ver);
        check(t, 1, nh->nlmsg_type == 0x22 && gh->cmd == 1 && nh->nlmsg_len == n);
        const uint8_t *top = TOP(m);
        size_t tl = TOPLEN(m, n);
        const struct nlattr *a = find(top, tl, AD_IFNAME);
        snprintf(t, sizeof t, "SET v%d: IFNAME", ver);
        check(t, 1, a && !strcmp(NLA_DATA(a), "ifab"));
        a = find(top, tl, AD_PRIVATE_KEY);
        hex(PRIV_HEX, want, 32);
        snprintf(t, sizeof t, "SET v%d: PRIVATE_KEY — 32 байта ключа", ver);
        check(t, 1, a && NLA_PLEN(a) == 32 && !memcmp(NLA_DATA(a), want, 32));
        a = find(top, tl, AD_FWMARK);
        snprintf(t, sizeof t, "SET v%d: FWMARK u32", ver);
        check(t, 0x00c00000, a && NLA_PLEN(a) == 4 ? (long)u32of(a) : -1);
        a = find(top, tl, AD_JC);
        snprintf(t, sizeof t, "SET v%d: JC — u16", ver);
        check(t, 4, a && NLA_PLEN(a) == 2 ? u16of(a) : -1);
        a = find(top, tl, AD_H1);
        if (ver == 1) check("SET v1: H1 — u32", 11, a && NLA_PLEN(a) == 4 ? (long)u32of(a) : -1);
        if (ver == 2) check("SET v2: H1 — строка", 1, a && !strcmp(NLA_DATA(a), "11"));
        if (ver == 3) check("SET v3: H1 — u64 lo|hi<<32", 1, a && NLA_PLEN(a) == 8 && u64of(a) == 0x0000000b0000000bull);
        snprintf(t, sizeof t, "SET v%d: без REPLACE_PEERS флага устройства нет", ver);
        check(t, 1, find(top, tl, AD_FLAGS) == NULL);
        const struct nlattr *peers = find(top, tl, AD_PEERS);
        snprintf(t, sizeof t, "SET v%d: PEERS вложенный (NLA_F_NESTED)", ver);
        check(t, 1, peers && (peers->nla_type & NLA_F_NESTED));
        const struct nlattr *p0 = peers ? nth(peers, 0) : NULL;
        const uint8_t *pd = p0 ? NLA_DATA(p0) : NULL;
        size_t pl = p0 ? NLA_PLEN(p0) : 0;
        a = pd ? find(pd, pl, AP_PERSISTENT_KEEPALIVE_INTERVAL) : NULL;
        if (ver < 3) {
            snprintf(t, sizeof t, "SET v%d: keepalive — u16", ver);
            check(t, 25, a && NLA_PLEN(a) == 2 ? u16of(a) : -1);
        } else check("SET v3: keepalive — u32 диапазоном", 25 | (25 << 16), a && NLA_PLEN(a) == 4 ? (long)u32of(a) : -1);
        if (ver == 3) {
            a = find(pd, pl, AP_FLAGS);
            check("пир: REPLACE_ALLOWEDIPS", AWG_PEER_F_REPLACE_ALLOWEDIPS, (long)u32of(a));
            a = find(pd, pl, AP_PRESHARED_KEY);
            uint8_t psk[32];
            key_from_b64(psk, PSK);
            check("пир: PRESHARED_KEY", 1, a && NLA_PLEN(a) == 32 && !memcmp(NLA_DATA(a), psk, 32));
            a = find(pd, pl, AP_ENDPOINT);
            struct sockaddr_in ep;
            memset(&ep, 0, sizeof ep);
            if (a && NLA_PLEN(a) >= sizeof ep) memcpy(&ep, NLA_DATA(a), sizeof ep);
            check("пир: ENDPOINT — sockaddr_in, порт сетевым порядком", 1,
                  ep.sin_family == AF_INET && ntohs(ep.sin_port) == 51820 &&
                  ep.sin_addr.s_addr == htonl(0xc0000207));
            const struct nlattr *aips = find(pd, pl, AP_ALLOWEDIPS);
            const struct nlattr *e1 = aips ? nth(aips, 1) : NULL;
            const struct nlattr *fam = e1 ? find(NLA_DATA(e1), NLA_PLEN(e1), AA_FAMILY) : NULL;
            const struct nlattr *ad = e1 ? find(NLA_DATA(e1), NLA_PLEN(e1), AA_IPADDR) : NULL;
            const struct nlattr *cm = e1 ? find(NLA_DATA(e1), NLA_PLEN(e1), AA_CIDR_MASK) : NULL;
            check("AllowedIPs[1]: семейство u16 AF_INET6", AF_INET6, fam && NLA_PLEN(fam) == 2 ? u16of(fam) : -1);
            check("AllowedIPs[1]: адрес 16 байт fd00::", 1,
                  ad && NLA_PLEN(ad) == 16 && ((const uint8_t *)NLA_DATA(ad))[0] == 0xfd);
            check("AllowedIPs[1]: префикс u8 8", 8, cm && NLA_PLEN(cm) == 1 ? *(const uint8_t *)NLA_DATA(cm) : -1);
        }
    }
    {
        size_t n = awg_build_set(m, sizeof m, 0x21, 1, 0, "ifab", &C, &S, 0, 1, 12);
        const uint8_t *top = TOP(m);
        size_t tl = TOPLEN(m, n);
        check("wireguard: атрибутов AmneziaWG нет", 1,
              find(top, tl, AD_JC) == NULL && find(top, tl, AD_H1) == NULL);
        check("wireguard: REPLACE_PEERS по просьбе", AWG_DEV_F_REPLACE_PEERS, (long)u32of(find(top, tl, AD_FLAGS)));
        check("wireguard: FWMARK 0 передаётся явно (снять прежний via)", 1, find(top, tl, AD_FWMARK) != NULL);
        const struct nlattr *p0 = nth(find(top, tl, AD_PEERS), 0);
        check("wireguard: флаг пира без AdvancedSecurity", AWG_PEER_F_REPLACE_ALLOWEDIPS,
              (long)u32of(find(NLA_DATA(p0), NLA_PLEN(p0), AP_FLAGS)));
        check("не влезает — 0, а не обрезанное сообщение", 0,
              (long)awg_build_set(m, 200, 0x21, 1, 0, "ifab", &C, &S, 0, 0, 13));
    }
    {
        /* PSK убран из файла — на устройство уходит нулевой ключ, то есть «снять». */
        parse(IFACE PEER1 "AllowedIPs = 0.0.0.0/0\n");
        size_t n = awg_build_set(m, sizeof m, 0x21, 1, 0, "ifab", &C, &S, 0, 0, 14);
        const struct nlattr *p0 = nth(find(TOP(m), TOPLEN(m, n), AD_PEERS), 0);
        const struct nlattr *a = find(NLA_DATA(p0), NLA_PLEN(p0), AP_PRESHARED_KEY);
        static const uint8_t z[32];
        check("PSK нет в файле — нулевой PRESHARED_KEY", 1, a && NLA_PLEN(a) == 32 && !memcmp(NLA_DATA(a), z, 32));
        check("keepalive нет в файле — 0 (выключить)", 0,
              (long)u16of(find(NLA_DATA(p0), NLA_PLEN(p0), AP_PERSISTENT_KEEPALIVE_INTERVAL)));
    }

    /* ---- 6. подпись: что поверх не снять ---------------------------------------------- */
    {
        parse(IFACE "Jc = 4\nH1 = 11\n" PEER1);
        struct awg_sig a = conf_sig(&C);
        parse(IFACE "Jc = 5\nH1 = 11\n" PEER1);
        struct awg_sig b = conf_sig(&C);
        parse(IFACE "H1 = 11\n" PEER1);
        struct awg_sig c = conf_sig(&C);
        check("сменилось значение Jc — поверх", 0, sig_lost(&a, &b));
        check("убран Jc — пересоздать", 1, sig_lost(&a, &c));
        check("добавлен Jc — поверх", 0, sig_lost(&c, &a));
    }

    /* ---- 7. имя устройства -------------------------------------------------------------- */
    char d[32], d2[32];
    awg_default_ifname("home", d, sizeof d);
    check_str("имя выхода годно — оно и есть устройство", "home", d);
    awg_default_ifname("wg0", d, sizeof d);
    check("«wg0» выдаёт туннель — имя заменено", 1, strncmp(d, "if", 2) == 0 && strlen(d) == 10);
    awg_default_ifname("wg0", d2, sizeof d2);
    check_str("замена детерминирована", d, d2);
    awg_default_ifname("AWG-nl", d2, sizeof d2);
    check("регистр не спасает: AWG-nl заменено", 1, strncmp(d2, "if", 2) == 0);
    awg_default_ifname("a-very-long-output-name", d2, sizeof d2);
    check("длинное имя — не усечение, а хэш (≤15)", 1, strlen(d2) <= 15 && !strncmp(d2, "if", 2));
    const char *bad[] = { "tun0", "tap1", "ppp0", "vpn", "ipsec0", "utun3", "wireguard1", "awg0", "wg" };
    int allbad = 1;
    for (size_t i = 0; i < sizeof bad / sizeof bad[0]; i++) allbad &= awg_ifname_conspicuous(bad[i]);
    check("tun/tap/ppp/vpn/ipsec/utun/wireguard/awg/wg — все приметны", 1, allbad);
    check("wlan-подобное имя не считается приметным", 0, awg_ifname_conspicuous("nl1"));

    /* ---- 8. спека ------------------------------------------------------------------------- */
    check("kind awg без conf — годен", 0,
          spec_str("\"outputs\":{\"nl\":{\"kind\":\"awg\",\"on_fail\":\"drop\"}},\"channels\":[]"));
    check_str("  устройство — имя выхода", "nl", g_out[0].device);
    check_str("  conf по умолчанию из имени выхода", STEER_ETC_DIR "/awg/nl.conf", g_out[0].xs_conf);
    check("  выход с устройством и меткой", 1, out_has_device(&g_out[0]) && out_needs_mark(&g_out[0]));
    check("  устройство заводит движок", 1, out_engine_managed(&g_out[0]));
    check("  masquerade ему нужен (не self_natting)", 0, out_self_natting(&g_out[0]));
    check_str("  вид печатается как awg", "awg", out_kind_name(g_out[0].kind));
    check("kind awg c именем wg0 — годен", 0,
          spec_str("\"outputs\":{\"wg0\":{\"kind\":\"awg\",\"conf\":\"/data/misc/steer/awg/a.conf\"}},\"channels\":[]"));
    check("  устройство не «wg0»", 1, strcmp(g_out[0].device, "wg0") != 0 && !strncmp(g_out[0].device, "if", 2));
    check("device «tun1» явно — отказ", 2,
          spec_str("\"outputs\":{\"nl\":{\"kind\":\"awg\",\"device\":\"tun1\"}},\"channels\":[]"));
    check("device нейтральный явно — годен", 0,
          spec_str("\"outputs\":{\"nl\":{\"kind\":\"awg\",\"device\":\"rt5\"}},\"channels\":[]"));
    check_str("  взят как есть", "rt5", g_out[0].device);
    check("devices списком из двух — отказ", 2,
          spec_str("\"outputs\":{\"nl\":{\"kind\":\"awg\",\"devices\":[\"a1\",\"a2\"]}},\"channels\":[]"));
    check("conf относительный — отказ", 2,
          spec_str("\"outputs\":{\"nl\":{\"kind\":\"awg\",\"conf\":\"a.conf\"}},\"channels\":[]"));
    check("stream у awg — отказ", 2,
          spec_str("\"outputs\":{\"nl\":{\"kind\":\"awg\",\"stream\":true}},\"channels\":[]"));
    check("канал в выход awg — годен", 0,
          spec_str("\"outputs\":{\"nl\":{\"kind\":\"awg\"}},"
                   "\"channels\":[{\"name\":\"c\",\"out\":\"nl\",\"match\":{\"prefixes_file\":\"/tmp/x\"}}]"));

    /* ---- 9. метка сокета туннеля ----------------------------------------------------- */
    {
        spec_str("\"outputs\":{\"nl\":{\"kind\":\"awg\"},\"up\":{\"kind\":\"interface\",\"device\":\"eth9\"},"
                 "\"d\":{\"kind\":\"direct\"}},\"channels\":[]");
        g_out[1].mark = 0x00300000;
        uint32_t mk = 0xdead;
#ifdef STEER_SELF_MARK
        uint32_t self = STEER_SELF_MARK;
#else
        uint32_t self = 0;
#endif
        check("без via — метка «сам движок» (на роутере 0)", 0, awg_sock_mark(NULL, &mk));
        check("  значение", (long)self, (long)mk);
        check("via на выход с меткой — его метка", 0, awg_sock_mark("up", &mk));
        check("  значение", 0x00300000, (long)mk);
        check("via на direct — как без via", 0, (awg_sock_mark("d", &mk), (long)(mk != self)));
        check("via на несуществующий выход — отказ", -1, awg_sock_mark("nope", &mk));
    }

    /* ---- 10. туннель через via — только IPv4 -------------------------------------------
     * Таблица выхода-цели и её ip rule — только IPv4: датаграмма WireGuard к серверу по IPv6 с
     * меткой цели ушла бы мимо цели, напрямую. Литерал IPv6 при via — отказ с причиной, имя при
     * via разрешается только в IPv4; без via IPv6 законен. */
    {
        const char *v6 = "[Interface]\nPrivateKey = " PRIV "\n"
                         "[Peer]\nPublicKey = " PUB1 "\nEndpoint = [2001:db8::1]:51820\n"
                         "AllowedIPs = 0.0.0.0/0\n";
        check("файл с Endpoint IPv6 разобран", 0, parse(v6));
        char why[512] = "";
        check("Endpoint IPv6 без via — годен", 0, awg_via_check(&C, NULL, why, sizeof why));
        check("Endpoint IPv6 при via — отказ", -1, awg_via_check(&C, "up", why, sizeof why));
        check("  причина называет IPv6 и via", 1,
              strstr(why, "IPv6") && strstr(why, "via up") && strstr(why, "2001:db8::1"));
        const char *v4 = "[Interface]\nPrivateKey = " PRIV "\n"
                         "[Peer]\nPublicKey = " PUB1 "\nEndpoint = 192.0.2.2:51820\n"
                         "AllowedIPs = 0.0.0.0/0\n"
                         "[Peer]\nPublicKey = " PUB2 "\nEndpoint = ip6-localhost:51820\n"
                         "AllowedIPs = 10.0.0.0/8\n";
        check("файл с IPv4 и именем разобран", 0, parse(v4));
        check("IPv4 и имя при via — годны", 0, awg_via_check(&C, "up", why, sizeof why));
        /* Имя при via — только IPv4: ip6-localhost (у машины разработки это только ::1) при via не
         * разрешается вовсе, без via — законно в IPv6. Где имени нет в /etc/hosts, обе половины
         * сводятся к «не разрешилось», и проверка ничего не утверждает зря. */
        resolve_peers(&C, "nl", 0, 1);
        check("via: литерал IPv4 разрешён в IPv4", AF_INET,
              C.peer[0].ep_len ? ((struct sockaddr *)&C.peer[0].ep)->sa_family : -1);
        check("via: имя не разрешено в IPv6", 1,
              C.peer[1].ep_len == 0 || ((struct sockaddr *)&C.peer[1].ep)->sa_family == AF_INET);
        resolve_peers(&C, "nl", 0, 0);
        check("без via: имя разрешено как есть, в IPv6", 1,
              C.peer[1].ep_len == 0 || ((struct sockaddr *)&C.peer[1].ep)->sa_family == AF_INET6);
    }

    awg_conf_free(&C);
    printf("\nawgmatch: %d passed, %d failed\n", passes, fails);
    return fails ? 1 : 0;
}
