/* Spec parsing and the mark/table registry — see spec.h for why this is shared. */
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include "spec.h"

/* Marks and tables live well away from what splify (0x40000/0x80000, tables
 * 200/202) and mwan3 use, so both can run on one box while the migration is in
 * progress. One bit per output keeps `nft` output readable. */
#define MARK_BASE   0x00100000u
#define TABLE_BASE  300




struct output g_out[MAX_OUTPUTS];
size_t g_out_n;
struct channel g_ch[MAX_CHANNELS];
size_t g_ch_n;
char g_from_default[MAX_FROM][64];
size_t g_from_default_n;

/* Needed for the IPv6 DNS redirect: a LAN IPv6 prefix is dynamic (a ULA plus a
 * delegated global one that changes), so there is no stable `ip6 saddr` to write
 * and the rule has to match the device instead. */
char g_lan_device[32] = "br-lan";
/* Opt-in, because it cannot work without a firewall rule the engine does not own —
 * see the comment on the generated chain in steer.c. Defaulting it on would turn
 * legible-but-wrong hops into no hops at all. */
int g_traceroute_hops;
const char *g_state_dir = "/var/lib/steer";

void die(const char *fmt, const char *a) {
    fprintf(stderr, "steer: ");
    fprintf(stderr, fmt, a);
    fputc('\n', stderr);
    exit(2);
}

/* ---- a JSON reader small enough to audit ---------------------------------- */
/* Deliberately not a general parser: it walks the document the shape of the spec
 * demands and refuses anything else. A router config that compiles into firewall
 * rules should fail loudly on an unexpected shape rather than guess — which is the
 * same reason the spec is JSON and not YAML. */
struct js { const char *p; };

static void js_ws(struct js *j) {
    while (*j->p == ' ' || *j->p == '\t' || *j->p == '\n' || *j->p == '\r') j->p++;
}
static int js_lit(struct js *j, char c) {
    js_ws(j);
    if (*j->p != c) return -1;
    j->p++;
    return 0;
}
static int js_str(struct js *j, char *buf, size_t n) {
    js_ws(j);
    if (*j->p != '"') return -1;
    j->p++;
    size_t i = 0;
    while (*j->p && *j->p != '"') {
        if (*j->p == '\\' && j->p[1]) j->p++;
        if (i + 1 < n) buf[i++] = *j->p;
        j->p++;
    }
    if (*j->p != '"') return -1;
    j->p++;
    buf[i] = '\0';
    return 0;
}
static long js_num(struct js *j) {
    js_ws(j);
    char *e = NULL;
    long v = strtol(j->p, &e, 10);
    j->p = e;
    return v;
}
/* Skips one value of any type, so unknown keys are tolerated (forward compat
 * within a schema major) without being silently interpreted. */
static void js_skip(struct js *j) {
    js_ws(j);
    if (*j->p == '"') { char t[512]; js_str(j, t, sizeof(t)); return; }
    if (*j->p == '{' || *j->p == '[') {
        char open = *j->p, close = open == '{' ? '}' : ']';
        int depth = 0;
        do {
            if (*j->p == '"') { char t[512]; js_str(j, t, sizeof(t)); continue; }
            if (*j->p == open) depth++;
            else if (*j->p == close) depth--;
            j->p++;
        } while (*j->p && depth > 0);
        return;
    }
    while (*j->p && *j->p != ',' && *j->p != '}' && *j->p != ']') j->p++;
}

/* Same as str_array but for the 256-byte path arrays. Kept separate rather than
 * templated: two element widths in C means two functions, and a void*+stride version
 * would trade a compiler-checked bound for a runtime one. */
static size_t str_list(struct js *j, char dst[][256], size_t max) {
    if (js_lit(j, '[') != 0) return 0;
    size_t n = 0;
    js_ws(j);
    if (*j->p == ']') { j->p++; return 0; }
    for (;;) {
        char t[256];
        if (js_str(j, t, sizeof(t)) != 0) return n;
        if (n < max) snprintf(dst[n++], 256, "%s", t);
        js_ws(j);
        if (*j->p == ',') { j->p++; continue; }
        break;
    }
    js_lit(j, ']');
    return n;
}

static int str_array(struct js *j, char dst[][64], size_t max, size_t *n) {
    if (js_lit(j, '[') != 0) return -1;
    *n = 0;
    js_ws(j);
    if (*j->p == ']') { j->p++; return 0; }
    for (;;) {
        char t[64];
        if (js_str(j, t, sizeof(t)) != 0) return -1;
        if (*n < max) snprintf(dst[(*n)++], 64, "%s", t);
        js_ws(j);
        if (*j->p == ',') { j->p++; continue; }
        break;
    }
    return js_lit(j, ']');
}

static void parse_outputs(struct js *j) {
    if (js_lit(j, '{') != 0) die("outputs: expected an object", NULL);
    js_ws(j);
    if (*j->p == '}') { j->p++; return; }
    for (;;) {
        struct output o = {0};
        if (js_str(j, o.name, sizeof(o.name)) != 0) die("outputs: expected a name", NULL);
        if (js_lit(j, ':') != 0) die("outputs.%s: expected ':'", o.name);
        if (js_lit(j, '{') != 0) die("outputs.%s: expected an object", o.name);
        char kind[32] = "";
        js_ws(j);
        while (*j->p != '}') {
            char key[32];
            if (js_str(j, key, sizeof(key)) != 0) die("outputs.%s: bad key", o.name);
            js_lit(j, ':');
            if (!strcmp(key, "kind")) js_str(j, kind, sizeof(kind));
            else if (!strcmp(key, "device")) js_str(j, o.device, sizeof(o.device));
            else if (!strcmp(key, "devices")) {
                /* Кандидаты в порядке предпочтения. Единственное число остаётся
                 * сокращением для одного — прежние спеки не ломаются. */
                if (js_lit(j, '[') == 0) {
                    js_ws(j);
                    if (*j->p == ']') j->p++;
                    else for (;;) {
                        char t[32];
                        if (js_str(j, t, sizeof(t)) != 0) break;
                        if (o.devices_n < MAX_DEVICES)
                            snprintf(o.devices[o.devices_n++], 32, "%s", t);
                        js_ws(j);
                        if (*j->p == ',') { j->p++; continue; }
                        js_lit(j, ']');
                        break;
                    }
                }
            }
            else if (!strcmp(key, "on_fail")) {
                char m[16];
                js_str(j, m, sizeof(m));
                if (!strcmp(m, "drop")) o.on_fail = FAIL_DROP;
                else if (!strcmp(m, "direct")) o.on_fail = FAIL_DIRECT;
                else if (!strcmp(m, "zapret")) o.on_fail = FAIL_ZAPRET;
                else die("outputs.%s: unknown on_fail (want drop, direct or zapret)", o.name);
            }
            else js_skip(j);
            js_ws(j);
            if (*j->p == ',') { j->p++; js_ws(j); }
        }
        j->p++;
        if (!strcmp(kind, "direct")) o.kind = OUT_DIRECT;
        else if (!strcmp(kind, "interface")) {
            o.kind = OUT_INTERFACE;
            /* device и devices описывают одно и то же с разных сторон: device — что
             * работает сейчас, devices — из чего выбирать. Задан один, выводится
             * второй, чтобы дальше по коду не было двух путей. */
            if (!o.devices_n && o.device[0]) snprintf(o.devices[o.devices_n++], 32, "%s", o.device);
            if (!o.device[0] && o.devices_n) snprintf(o.device, sizeof(o.device), "%s", o.devices[0]);
            if (!o.device[0]) die("outputs.%s: kind interface needs a device", o.name);
        } else die("outputs.%s: unknown kind (want direct or interface)", o.name);
        if (g_out_n >= MAX_OUTPUTS) die("too many outputs", NULL);
        g_out[g_out_n++] = o;
        js_ws(j);
        if (*j->p == ',') { j->p++; continue; }
        break;
    }
    js_lit(j, '}');
}

static void parse_channels(struct js *j) {
    if (js_lit(j, '[') != 0) die("channels: expected an array", NULL);
    js_ws(j);
    if (*j->p == ']') { j->p++; return; }
    for (;;) {
        struct channel c = {0};
        if (js_lit(j, '{') != 0) die("channels: expected an object", NULL);
        js_ws(j);
        while (*j->p != '}') {
            char key[32];
            if (js_str(j, key, sizeof(key)) != 0) die("channels: bad key", NULL);
            js_lit(j, ':');
            if (!strcmp(key, "name")) js_str(j, c.name, sizeof(c.name));
            else if (!strcmp(key, "out")) js_str(j, c.out, sizeof(c.out));
            else if (!strcmp(key, "from")) str_array(j, c.from, MAX_FROM, &c.from_n);
            else if (!strcmp(key, "match")) {
                if (js_lit(j, '{') != 0) die("channels.%s: match must be an object", c.name);
                js_ws(j);
                while (*j->p != '}') {
                    char mk[32];
                    js_str(j, mk, sizeof(mk));
                    js_lit(j, ':');
                    /* Singular is shorthand for a one-element list, so a spec written
                     * before this stayed valid. */
                    if (!strcmp(mk, "prefixes_file")) {
                        if (js_str(j, c.prefixes_files[0], 256) == 0) c.prefixes_n = 1;
                    } else if (!strcmp(mk, "domains_file")) {
                        if (js_str(j, c.domains_files[0], 256) == 0) c.domains_n = 1;
                    } else if (!strcmp(mk, "prefixes_files")) {
                        c.prefixes_n = str_list(j, c.prefixes_files, MAX_FILES);
                    } else if (!strcmp(mk, "domains_files")) {
                        c.domains_n = str_list(j, c.domains_files, MAX_FILES);
                    }
                    else if (!strcmp(mk, "mode")) {
                        char m[16]; js_str(j, m, sizeof(m));
                        if (!strcmp(m, "realip")) c.realip = 1;
                        else if (strcmp(m, "fakeip") != 0) die("channels: unknown mode %s (want fakeip or realip)", m);
                    }
                    else if (!strcmp(mk, "any")) { js_ws(j); c.any = (*j->p == 't'); js_skip(j); }
                    else if (!strcmp(mk, "allow_all")) { js_ws(j); c.allow_all = (*j->p == 't'); js_skip(j); }
                    else js_skip(j);
                    js_ws(j);
                    if (*j->p == ',') { j->p++; js_ws(j); }
                }
                j->p++;
            }
            else js_skip(j);
            js_ws(j);
            if (*j->p == ',') { j->p++; js_ws(j); }
        }
        j->p++;
        if (!c.name[0]) die("a channel has no name", NULL);
        if (!c.out[0]) die("channel %s has no out", c.name);
        if (!c.prefixes_n && !c.domains_n && !c.any)
            die("channel %s matches nothing (want prefixes_files, domains_files or any)", c.name);
        /* Addresses and domains reach the set by different routes — one from a file,
         * one from the resolver — so one channel cannot hold both. */
        if (c.prefixes_n && c.domains_n)
            die("channel %s mixes addresses and domains — split it in two", c.name);
        if (g_ch_n >= MAX_CHANNELS) die("too many channels", NULL);
        g_ch[g_ch_n++] = c;
        js_ws(j);
        if (*j->p == ',') { j->p++; continue; }
        break;
    }
    js_lit(j, ']');
}

void load_spec(const char *path) {
    FILE *f = strcmp(path, "-") ? fopen(path, "r") : stdin;
    if (!f) die("%s: cannot open", path);
    static char buf[262144];
    size_t n = fread(buf, 1, sizeof(buf) - 1, f);
    buf[n] = '\0';
    if (f != stdin) fclose(f);

    struct js j = { buf };
    long schema = -1;
    if (js_lit(&j, '{') != 0) die("spec: expected an object", NULL);
    js_ws(&j);
    while (*j.p && *j.p != '}') {
        char key[64];
        if (js_str(&j, key, sizeof(key)) != 0) die("spec: bad key", NULL);
        js_lit(&j, ':');
        if (!strcmp(key, "schema")) schema = js_num(&j);
        else if (!strcmp(key, "outputs")) parse_outputs(&j);
        else if (!strcmp(key, "channels")) parse_channels(&j);
        else if (!strcmp(key, "from_default")) str_array(&j, g_from_default, MAX_FROM, &g_from_default_n);
        else if (!strcmp(key, "lan_device")) js_str(&j, g_lan_device, sizeof(g_lan_device));
        else if (!strcmp(key, "traceroute_hops")) { js_ws(&j); g_traceroute_hops = (*j.p == 't'); js_skip(&j); }
        else js_skip(&j);
        js_ws(&j);
        if (*j.p == ',') { j.p++; js_ws(&j); }
    }
    /* Refusing an unknown major is the whole point of having the field: guessing
     * would mean compiling a config we do not understand into firewall rules. */
    if (schema != 1) {
        fprintf(stderr, "steer: spec schema %ld is not supported (this build speaks 1)\n", schema);
        exit(2);
    }
    /* Auto-detect the LAN subnet when from_default is not set.
     *
     * Without this, every new install ships with no IPv4 DNS redirect: the rule is
     * generated from from_default, an empty field makes no rule, and clients querying
     * IPv4 go straight to dnsmasq — fake-IP silently does nothing. The symptom is
     * "works from the router but not from devices", with no error, because the chain
     * is syntactically fine, just missing a rule.
     *
     * The spec author should not have to know the LAN subnet: the engine has the box
     * in front of it. Reads the lan_device's address, derives the network, same as
     * OpenWrt's own uci. Overridable by setting from_default explicitly. */
    if (!g_from_default_n) {
        char cmd[128];
        snprintf(cmd, sizeof(cmd), "ip -4 -o addr show %s 2>/dev/null", g_lan_device);
        FILE *pf = popen(cmd, "r");
        if (pf) {
            char line[256];
            while (g_from_default_n < MAX_FROM && fgets(line, sizeof(line), pf)) {
                char ifname[32], addr[64];
                if (sscanf(line, "%*d: %31s inet %63s", ifname, addr) != 2) continue;
                char *slash = strchr(addr, '/');
                if (!slash) continue;
                int plen = atoi(slash + 1);
                *slash = '\0';
                unsigned a, b, c, d;
                if (sscanf(addr, "%u.%u.%u.%u", &a, &b, &c, &d) != 4) continue;
                unsigned ip = (a << 24) | (b << 16) | (c << 8) | d;
                unsigned mask = plen ? (0xFFFFFFFFu << (32 - plen)) : 0;
                ip &= mask;
                snprintf(g_from_default[g_from_default_n], 64, "%u.%u.%u.%u/%u",
                         (ip >> 24) & 255, (ip >> 16) & 255, (ip >> 8) & 255, ip & 255, plen);
                g_from_default_n++;
            }
            pclose(pf);
        }
    }
    /* Пустая спека законна, и отказ на ней запирал настройку наглухо: чтобы завести
     * канал, нужен выход, а сохранить выход без каналов движок не давал — тупик, из
     * которого нельзя выйти изнутри интерфейса.
     *
     * "Выходы есть, каналов нет" — это осмысленное состояние: steer настроен, но
     * ничего не направляет. Оно же и правильное начальное: угадывать, какие списки
     * человеку нужны, хуже, чем не направлять ничего. */
    for (size_t i = 0; i < g_ch_n; i++) {
        size_t k = 0;
        for (; k < g_out_n; k++) if (!strcmp(g_ch[i].out, g_out[k].name)) break;
        if (k == g_out_n) die("channel %s points at an output that does not exist", g_ch[i].name);
    }

    /* ---- защита от конфигураций, которые отрежут доступ к роутеру -----------
     *
     * Всё ниже — про ошибки, которые компилируются и применяются без единой
     * жалобы, а замечаются как «роутер пропал». Отказать на них дешевле, чем
     * потом объяснять, как чинить коробку, до которой уже не достучаться.
     * Каждая проверка отвечает на «что человек сделает случайно», а не на
     * «что запрещено стандартом». */
    for (size_t i = 0; i < g_out_n; i++) {
        struct output *o = &g_out[i];
        if (o->kind != OUT_INTERFACE) continue;

        /* Выход в локальный мост — это петля: помеченный пакет получает маршрут
         * обратно в ту же сеть, откуда пришёл. */
        if (!strcmp(o->device, g_lan_device)) {
            char msg[160];
            snprintf(msg, sizeof(msg),
                     "выход %s ведёт в %s — это локальная сеть, трафик закольцуется",
                     o->name, g_lan_device);
            die("%s", msg);
        }

        /* Дубликат устройства внутри одного выхода делает failover бессмысленным:
         * второй кандидат ничем не отличается от первого. */
        for (size_t a = 0; a < o->devices_n; a++)
            for (size_t b = a + 1; b < o->devices_n; b++)
                if (!strcmp(o->devices[a], o->devices[b])) {
                    char msg[160];
                    snprintf(msg, sizeof(msg), "выход %s: устройство %s указано дважды",
                             o->name, o->devices[a]);
                    die("%s", msg);
                }
    }

    for (size_t i = 0; i < g_ch_n; i++) {
        struct channel *c = &g_ch[i];
        struct output *o = out_by_name(c->out);
        if (!o || o->kind != OUT_INTERFACE) continue;

        /* Канал `any` в туннель уводит ВЕСЬ трафик клиентов, включая их доступ к
         * самому роутеру и к его DNS. Это законная конфигурация, но только
         * осознанная: без явного признака она почти всегда описка вместо списка. */
        if (c->any && !c->prefixes_n && !c->domains_n && !c->allow_all)
            die("канал %s забирает ВЕСЬ трафик в туннель. Если это правда нужно, "
                "добавьте \"allow_all\": true — иначе выберите список", c->name);
    }
}

/* ---- mark/table registry -------------------------------------------------- */
/* Persisted, because an output must keep its mark across restarts: a reboot that
 * reshuffles marks leaves stale `ip rule` entries pointing at the wrong table,
 * and the symptom is traffic silently taking someone else's path. */
void registry_assign(void) {
    char path[512];
    snprintf(path, sizeof(path), "%s/registry", g_state_dir);
    FILE *f = fopen(path, "r");
    if (f) {
        char name[32];
        unsigned mark;
        int table;
        while (fscanf(f, "%31s %x %d\n", name, &mark, &table) == 3)
            for (size_t i = 0; i < g_out_n; i++)
                if (!strcmp(g_out[i].name, name) && g_out[i].kind != OUT_DIRECT) {
                    g_out[i].mark = mark;
                    g_out[i].table = table;
                }
        fclose(f);
    }
    unsigned next_bit = 0;
    for (size_t i = 0; i < g_out_n; i++)
        if (g_out[i].mark) {
            unsigned b = 0;
            while ((MARK_BASE << b) < g_out[i].mark && b < 8) b++;
            if (b + 1 > next_bit) next_bit = b + 1;
        }
    for (size_t i = 0; i < g_out_n; i++) {
        if (g_out[i].kind == OUT_DIRECT || g_out[i].mark) continue;
        if (next_bit >= 8) die("out of mark bits for output %s", g_out[i].name);
        g_out[i].mark = MARK_BASE << next_bit;
        g_out[i].table = TABLE_BASE + (int)next_bit;
        next_bit++;
    }
    mkdir(g_state_dir, 0755);
    f = fopen(path, "w");
    if (!f) return;             /* best effort: apply still works, next boot re-assigns */
    for (size_t i = 0; i < g_out_n; i++)
        if (g_out[i].kind != OUT_DIRECT)
            fprintf(f, "%s %x %d\n", g_out[i].name, g_out[i].mark, g_out[i].table);
    fclose(f);
}

struct output *out_by_name(const char *n) {
    for (size_t i = 0; i < g_out_n; i++) if (!strcmp(g_out[i].name, n)) return &g_out[i];
    return NULL;
}

