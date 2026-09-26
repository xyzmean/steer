/* kind=vless — туннель VLESS по подписке, устройство которого создаёт наш процесс
 * (`steer vless <выход>`, src/tunnel/tunnel.c).
 *
 * vless — это тоже устройство: клиент поднимает TUN, и дальше всё остальное (метки,
 * таблицы, failover, каналы) работает с ним ровно как с wireguard. Отдельный вид нужен
 * только потому, что устройство надо СОЗДАТЬ и обслуживать процессом, тогда как
 * wireguard уже есть в системе к моменту apply.
 *
 * Вид только расширенной сборки: файла нет в профиле base (build/sources.mk), и там реестр
 * отвечает на него отказом «требует пакет steer-extended» (kind.c). Отказываем СРАЗУ, а не при
 * подъёме: иначе спека применяется, правила встают, и выход молча никуда не ведёт — то есть
 * человек видит рабочую конфигурацию, в которой трафик пропадает. */
#include <stdio.h>
#include <string.h>
#include <unistd.h>

#include "spec.h"

const struct vless_cfg *out_vless(const struct output *o) {
    return kind_of(o) == &kind_vless ? &o->vless : NULL;
}

static int vless_parse(struct output *o, const struct out_keys *k, struct err *e) {
    snprintf(o->vless.sub_file, sizeof(o->vless.sub_file), "%s", k->sub_file);
    memcpy(o->vless.nodes, k->nodes, sizeof(o->vless.nodes));
    o->vless.nodes_n = k->nodes_n;
    if (!o->vless.sub_file[0])
        return err_set(e, "outputs.%s: kind vless нужен sub_file с подпиской", o->name);
    /* Имя устройства выводится из имени выхода: держать его отдельным полем
     * значило бы дать двум именам расходиться, а никакой пользы от их различия
     * нет. Ограничение в 15 символов — предел IFNAMSIZ. */
    if (!o->device[0]) snprintf(o->device, sizeof(o->device), "%.15s", o->name);
    if (!o->devices_n) snprintf(o->devices[o->devices_n++], 32, "%s", o->device);
    return 0;
}

/* Выбранные узлы подписки — рядом с devices, потому что это то же самое: список
 * кандидатов выхода, только у vless кандидаты называются номерами узлов.
 * Печатается ВСЕГДА, в том числе пустым, и это главное здесь: незнакомый ключ
 * спеки движок пропускает молча (js_skip), поэтому интерфейс, записавший `nodes`
 * в старый движок, получил бы применённую спеку и трафик через узел, которого не
 * выбирал. Наличие поля в status — единственный способ узнать движок, который
 * `nodes` понимает, до того как их писать. Тем же приёмом узнаётся движок с
 * lan_devices. */
static void vless_status(FILE *out, const struct spec *sp, const struct output *o) {
    (void)sp;
    fprintf(out, ",\"nodes\":[");
    for (size_t d = 0; d < o->vless.nodes_n; d++)
        fprintf(out, "%s%d", d ? "," : "", o->vless.nodes[d]);
    fprintf(out, "]");
}

/* Помощник — клиент туннеля. В подпись — файл подписки, его СОДЕРЖИМОЕ и выбор узлов (helper_sig,
 * daemon/helpers.c). Содержимое — потому что клиент читает узлы один раз, при старте: обновлённая
 * подписка без перезапуска не заработала бы. До демона это делал управляющий слой сигналом
 * экземпляру procd (vless_<выход>); у демона такого экземпляра нет, и сверка по подписи — apply,
 * reload, SIGHUP — перезапускает клиент ровно того выхода, чья подписка изменилась. */
static int vless_helper(const struct spec *sp, const struct output *o, struct kind_helper *h) {
    (void)sp;
    snprintf(h->cmd, sizeof(h->cmd), "vless");
    /* Счётчики туннеля — по файлу-выключателю, как у init.d/steer (procd_set_param env). */
    char st[256];
    if (access(plat_etc_path(st, sizeof(st), "stats"), F_OK) == 0)
        snprintf(h->env, sizeof(h->env), "STEER_TUN_STATS=1");
    kind_sig_mix(&h->sig, o->vless.sub_file, strlen(o->vless.sub_file));
    FILE *f = fopen(o->vless.sub_file, "r");
    if (f) {
        char buf[4096];
        size_t n;
        while ((n = fread(buf, 1, sizeof(buf), f)) > 0) kind_sig_mix(&h->sig, buf, n);
        fclose(f);
    }
    for (size_t i = 0; i < o->vless.nodes_n; i++)
        kind_sig_mix(&h->sig, &o->vless.nodes[i], sizeof(o->vless.nodes[i]));
    return 0;
}

/* Порядок перебора узлов подписки. Объяснение — у объявления в kind.h. */
size_t out_node_list(const struct output *o, size_t usable, int *dst, size_t max) {
    size_t n = 0;
    if (!o->vless.nodes_n) {
        /* Кандидатов не выбирали — кандидаты все, в порядке подписки. Это прежнее
         * поведение `node: -1` и умолчание, которое рекомендует интерфейс: номер узла
         * меняется при обновлении подписки, а проверка находит живой сама. */
        for (size_t i = 0; i < usable && n < max; i++) dst[n++] = (int)i;
        return n;
    }
    for (size_t i = 0; i < o->vless.nodes_n && n < max; i++)
        if (o->vless.nodes[i] >= 0 && (size_t)o->vless.nodes[i] < usable) dst[n++] = o->vless.nodes[i];
    return n;
}

/* Назван ли узел человеком. Объяснение — у объявления в kind.h. */
int out_node_named(const struct output *o) {
    return o->vless.nodes_n == 1;
}

const struct kind_ops kind_vless = {
    .name = "vless",
    .caps = KC_DEVICE | KC_MARK | KC_CTMARK | KC_ENGINE_OWNED | KC_SELF_NAT | KC_OVER |
            KC_SKIP_ZAPRET | KC_TCP_PROBE | KC_FLOW_UDP,
    .keys = KK_NODES,
    /* Сюда попадает выход без masquerade, которому он и не нужен, — для него это норма
     * (см. out_self_natting и проверку «output» в diag.c). */
    .selfnat_why = "masquerade не нужен: туннель завершает TCP сам, адреса клиентов "
                   "наружу не уходят",
    .parse = vless_parse,
    .status = vless_status,
    .helper = vless_helper,
};
