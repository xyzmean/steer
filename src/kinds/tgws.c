/* kind=tgws — Telegram через веб-сокет: соединения клиентов раздачи к дата-центрам Telegram
 * перехватываются в nat prerouting и уводятся в наш мост (`steer tgws <выход>`,
 * src/proto/tgws/tgws.c), который везёт MTProto через веб-точки Telegram.
 *
 * Устройства и таблицы у выхода нет — маршрут не меняется, меняется то, куда уводится
 * перехваченное соединение. Метка пакета есть (по ней стоит перехват), метки соединения нет:
 * почему — у out_needs_ctmark в spec.h.
 *
 * Вид в БАЗОВОЙ сборке: правила перехвата пишет любой движок, а мост живёт своей программой —
 * в полном пакете и в микропакете stgws. Поэтому помощник для супервизора (он поднимает мост сам
 * только на телефоне) называется лишь там, где команда моста есть в том же бинарнике, — в
 * расширенной сборке, как было до переноса вида сюда. */
#include <stdio.h>
#include <string.h>

#include "spec.h"

const struct tgws_cfg *out_tgws(const struct output *o) {
    return kind_of(o) == &kind_tgws ? &o->tg : NULL;
}

static int tgws_parse(struct output *o, const struct out_keys *k, struct err *e) {
    snprintf(o->tg.domain, sizeof(o->tg.domain), "%s", k->domain);
    /* Домен обязателен и умолчания у него нет НАРОЧНО. Сам web.telegram.org мост
     * пробует и без спеки, но только для ДЦ2 и ДЦ4 (TLS 1.2 на адрес веб-клиента,
     * см. «прямо к Telegram» в tgws.c): ДЦ1, 3, 5 и 203 там не обслуживаются. Им
     * нужен домен за Cloudflare, и подставить вместо него web.telegram.org молча
     * значило бы завести выход, у которого эти дата-центры не работают никогда. */
    if (!o->tg.domain[0])
        return err_set(e, "outputs.%s: kind tgws нужен domain — имя за Cloudflare, у которого "
            "kwsN.<domain> ведёт на веб-точку Telegram: web.telegram.org обслуживает "
            "только ДЦ2 и ДЦ4", o->name);
    /* Устройства нет по той же причине, что у zapret: маршрут не меняется, меняется
     * то, куда уводится перехваченное соединение. Названное устройство — почти
     * наверняка описка, и принять её молча значило бы обещать маршрутизацию,
     * которой не будет. */
    if (o->device[0] || o->devices_n)
        return err_set(e, "outputs.%s: у kind tgws нет устройства — соединение перехватывается",
            o->name);
    return 0;
}

/* У tgws on_fail не выражается вовсе, и молчать об этом нельзя. Перехват — это
 * правило nat, оно стоит в ядре всегда; когда моста нет, ядро отвечает отказом на
 * соединение, то есть ведёт себя как drop, и никаким полем это не переключить.
 * Обещать direct и не сделать его хуже, чем отказать сразу. */
static int tgws_check(const struct spec *sp, const struct output *o, struct err *e) {
    (void)sp;
    if (o->on_fail != FAIL_DROP)
        return err_set(e, "outputs.%s: у kind tgws on_fail только drop: перехват стоит в ядре, и без "
            "моста соединение отвергается — обойти это правилом нечем", o->name);
    return 0;
}

#ifdef STEER_EXTENDED
/* Помощник — мост. В подпись — домен точек (sup_sig в supervise.c). */
static int tgws_helper(const struct spec *sp, const struct output *o, struct kind_helper *h) {
    (void)sp;
    snprintf(h->cmd, sizeof(h->cmd), "tgws");
    kind_sig_mix(&h->sig, o->tg.domain, strlen(o->tg.domain));
    return 0;
}
#define TGWS_HELPER tgws_helper
#else
#define TGWS_HELPER NULL
#endif

/* `steer tgws-instances` — что поднимать для выходов kind=tgws: имя и порт, по строке на выход.
 * Тот же довод, что у zapret-instances (kinds/zapret.c), включая главный: порт выводит движок
 * (out_tgws_port), а не считает init-скрипт — второй расчёт того же в shell разошёлся бы при
 * первой правке, и мост слушал бы порт, на который ядро ничего не заворачивает. */
int tgws_instances(const struct spec *sp) {
    int n = 0;
    for (size_t i = 0; i < sp->out_n; i++) {
        if (kind_of(&sp->out[i]) != &kind_tgws) continue;
        printf("%s\t%d\n", sp->out[i].name, out_tgws_port(&sp->out[i]));
        n++;
    }
    return n ? 0 : 1;
}

const struct kind_ops kind_tgws = {
    .name = "tgws",
    .caps = KC_MARK | KC_SKIP_ZAPRET,
    .keys = KK_DOMAIN,
    /* Мост перехватывает соединения только в prerouting (раздача): у трафика самого телефона
     * такого заворота нет, и канал «приложение → tgws» стоял бы применённым, не делая ничего. */
    .lan_only = "у трафика самого телефона моста нет",
    .parse = tgws_parse,
    .check = tgws_check,
    .helper = TGWS_HELPER,
};
