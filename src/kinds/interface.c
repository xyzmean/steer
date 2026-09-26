/* kind=interface — устройство, которое уже есть в системе (wireguard, openvpn, pppoe…): его
 * заводит и поднимает netifd, а движок только ведёт в него трафик меткой и таблицей.
 *
 * Кандидатов несколько (`devices`), первый здоровый забирает трафик — это общий механизм сторожа,
 * а не свойство вида. Своё у вида одно — обфускация транспорта (`obfs`): WireGuard поверх
 * поддельного TCP через наш процесс-помощник (src/proto/obfs/obfs.c). С ней у выхода появляется
 * свой сокет наверх, а значит и `via` (caps_of ниже). */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "spec.h"

const struct out_obfs *iface_obfs(const struct output *o) {
    return kind_of(o) == &kind_interface && o->iface.obfs.on ? &o->iface.obfs : NULL;
}

static int iface_parse(struct output *o, const struct out_keys *k, struct err *e) {
    /* device и devices описывают одно и то же с разных сторон: device — что
     * работает сейчас, devices — из чего выбирать. Задан один, выводится
     * второй, чтобы дальше по коду не было двух путей. */
    if (!o->devices_n && o->device[0]) snprintf(o->devices[o->devices_n++], 32, "%s", o->device);
    if (!o->device[0] && o->devices_n) snprintf(o->device, sizeof(o->device), "%s", o->devices[0]);
    if (!o->device[0]) return err_set(e, "outputs.%s: kind interface needs a device", o->name);
    o->iface.obfs = k->obfs;
    return 0;
}

/* Обычный interface — без своего сокета наверх: его открывает ядро WireGuard по настройке
 * netifd, и метку ему ставить не нам. С obfs сокет к серверу обфускации открывает наш помощник,
 * и `via` у такого выхода есть (см. out_via_capable в spec.h). */
static unsigned iface_caps_of(const struct output *o) {
    return o->iface.obfs.on ? KC_OVER : 0;
}

/* Обфускация — поле, а не отдельный вид выхода, поэтому и в статусе она
 * поле. Признак живости здесь не печатается намеренно: status опрашивают
 * раз в пять секунд, а pgrep — это запуск процесса; приговор о живости
 * даёт diag, который спрашивают по нажатию. */
static void iface_status(FILE *out, const struct spec *sp, const struct output *o) {
    (void)sp;
    const struct out_obfs *ob = &o->iface.obfs;
    if (ob->on)
        fprintf(out, ",\"obfs\":{\"mode\":\"wg-over-tcp\",\"server\":\"%s:%d\""
               ",\"listen\":\"%s:%d\"}",
               ob->server, ob->server_port, ob->listen, ob->listen_port);
}

/* MTU устройства из sysfs. -1, если устройства нет. Читаем файл, а не спрашиваем ip:
 * это один открытый файл против запуска процесса, а ответ тот же. */
static int dev_mtu(const char *dev) {
    char path[128];
    snprintf(path, sizeof(path), "/sys/class/net/%.32s/mtu", dev);
    FILE *f = fopen(path, "r");
    if (!f) return -1;
    int mtu = -1;
    if (fscanf(f, "%d", &mtu) != 1) mtu = -1;
    fclose(f);
    return mtu;
}

/* Через какое устройство ядро отправит пакет к адресу и каков MTU этого устройства.
 * Возвращает MTU (или -1) и пишет имя устройства в dev.
 *
 * Адрес попадает в командную строку, поэтому обязан быть проверен ДО вызова: здесь он
 * приходит из спеки, где парсер уже отверг всё, что не является литералом IPv4
 * (inet_pton). Это то же требование, из-за которого в explain появилась проверка
 * формы: подстановка непроверенной строки в вызов однажды уже была дырой. */
static int route_egress(const char *addr, char *dev, size_t devn) {
    dev[0] = '\0';
    char cmd[160];
    snprintf(cmd, sizeof(cmd), "ip route get %.45s 2>/dev/null", addr);
    FILE *p = popen(cmd, "r");
    if (!p) return -1;
    char line[512];
    if (fgets(line, sizeof(line), p)) {
        char *d = strstr(line, " dev ");
        if (d) {
            d += 5;
            size_t k = 0;
            while (d[k] && d[k] != ' ' && d[k] != '\n' && k + 1 < devn) { dev[k] = d[k]; k++; }
            dev[k] = '\0';
        }
    }
    pclose(p);
    return dev[0] ? dev_mtu(dev) : -1;
}

/* Обфускация транспорта (WireGuard поверх поддельного TCP).
 *
 * Четыре проверки, и каждая — про отказ, который иначе виден только как «туннель
 * не поднимается»: процесса нет; правило против RST не встало (тогда сессию рвёт
 * собственное ядро); маршрут к серверу обфускации идёт через сам туннель (петля,
 * которую не разорвать изнутри); MTU туннеля больше того, что помещается в
 * поддельный TCP (тогда работает всё, кроме больших пакетов). */
static void iface_diag(kind_diag_fn *diag, const struct spec *sp, const struct output *o) {
    (void)sp;
    const struct out_obfs *ob = &o->iface.obfs;
    if (!ob->on) return;
    char what[200], why[400], cmdline[128];

    snprintf(cmdline, sizeof(cmdline), "pgrep -f 'steer obfs %.32s' >/dev/null 2>&1", o->name);
    int alive = system(cmdline) == 0;
    snprintf(what, sizeof(what), "выход %.40s: обфускатор %s", o->name, alive ? "работает" : "не запущен");
    diag("obfs", alive ? "ok" : "fail", what,
         alive ? "" : "перезапустите движок: /etc/init.d/steer restart");

    /* nft_has смотрит в таблицу steer, здесь нужна соседняя — поэтому свой вызов. */
    snprintf(cmdline, sizeof(cmdline), "nft list chain inet steer_obfs o_%.32s >/dev/null 2>&1", o->name);
    int guard = system(cmdline) == 0;
    if (!guard) {
        snprintf(what, sizeof(what), "выход %.40s: правила против RST нет", o->name);
        diag("obfs", "warn", what,
             "ядро отвечает RST на входящие сегменты обфускатора и рвёт его же сессию — "
             "проверьте, что nft доступен процессу");
    }

    char dev[64] = "";
    int link_mtu = route_egress(ob->server, dev, sizeof(dev));
    if (dev[0] && !strcmp(dev, o->device)) {
        snprintf(what, sizeof(what), "выход %.40s: маршрут к %.20s идёт через %.24s",
                 o->name, ob->server, dev);
        diag("obfs", "fail", what,
             "сервер обфускации доступен только через туннель, который сам через него и "
             "поднимается: петля. Уберите адрес сервера из списков канала или пропишите "
             "к нему отдельный маршрут");
    }

    int wg_mtu = dev_mtu(o->device);
    /* 20 внешний IP + 20 поддельный TCP + 32 сам WireGuard. Считаем от MTU того
     * устройства, которым пакет уходит наружу, а не от 1500: на PPPoE это 1492, и
     * разница ровно в те восемь байт, на которых «всё работает, кроме больших
     * страниц». */
    if (link_mtu > 0 && wg_mtu > 0 && wg_mtu > link_mtu - 72) {
        snprintf(what, sizeof(what), "выход %.40s: MTU %d великоват для обфускации", o->name, wg_mtu);
        snprintf(why, sizeof(why),
                 "поверх поддельного TCP в %d байт канала помещается %d: поставьте "
                 "интерфейсу %.24s MTU %d и тот же MTU на другой стороне туннеля, иначе "
                 "пропадать будут только большие пакеты",
                 link_mtu, link_mtu - 72, o->device, link_mtu - 72);
        diag("obfs", "warn", what, why);
    }
}

/* Помощник — обфускатор (`steer obfs <выход>`). В подпись — сервер и локальный адрес: ровно то,
 * что он читает при старте (см. sup_sig в supervise.c). */
static int iface_helper(const struct spec *sp, const struct output *o, struct kind_helper *h) {
    (void)sp;
    const struct out_obfs *ob = &o->iface.obfs;
    if (!ob->on) return -1;
    snprintf(h->cmd, sizeof(h->cmd), "obfs");
    kind_sig_mix(&h->sig, ob->server, strlen(ob->server));
    kind_sig_mix(&h->sig, &ob->server_port, sizeof(ob->server_port));
    kind_sig_mix(&h->sig, ob->listen, strlen(ob->listen));
    kind_sig_mix(&h->sig, &ob->listen_port, sizeof(ob->listen_port));
    return 0;
}

const struct kind_ops kind_interface = {
    .name = "interface",
    .caps = KC_DEVICE | KC_MARK | KC_CTMARK | KC_SKIP_ZAPRET | KC_IPV6,
    .keys = KK_OBFS,
    .caps_of = iface_caps_of,
    .novia = "interface без obfs",
    .parse = iface_parse,
    .status = iface_status,
    .diag = iface_diag,
    .helper = iface_helper,
};
