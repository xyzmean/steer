/* kind=xsteer — свой протокол поверх поддельного TCP с конфигурацией в стиле wg (см.
 * docs/xsteer.md); устройство создаёт наш процесс (`steer xsteer <выход>`,
 * src/proto/xsteer/xsclient.c).
 *
 * Отдельный ВИД, а не свойство существующего, и здесь оба довода из struct out_obfs
 * (spec.h) переворачиваются. Первый: у obfs выход по смыслу остаётся тем же интерфейсом,
 * устройство уже есть, и старому движку достаточно не сломаться. У xsteer устройства нет —
 * его создаёт наш процесс, и спека, применённая базовой сборкой «как интерфейс», дала бы
 * правила, метки и таблицу, ведущую в устройство, которого никто не создаст: человек увидел
 * бы исправную конфигурацию, из которой не выходит ни один пакет. Отказ разбором здесь не цена
 * совместимости, а единственный честный ответ — его даёт реестр (kind.c) в сборке без этого
 * файла. Второй: obfs не меняет того, чем выход является для остальной части движка, а xsteer
 * меняет, кто отвечает за жизнь устройства (наш процесс, а не netifd), — и это ровно то
 * различие, ради которого заводился вид vless.
 *
 * Подстроку «steer-extended» в отказе читают снаружи (см. src/daemon/main.c и kind.c). */
#include <stdio.h>
#include <string.h>

#include "spec.h"

const struct xsteer_cfg *out_xsteer(const struct output *o) {
    return kind_of(o) == &kind_xsteer ? &o->xs : NULL;
}

static int xsteer_parse(struct output *o, const struct out_keys *k, struct err *e) {
    snprintf(o->xs.conf, sizeof(o->xs.conf), "%s", k->conf);
    o->xs.stream = k->stream;
    o->xs.stream_port = k->stream_port;
    /* Имя устройства и путь к конфигурации выводятся из имени выхода — тот же
     * довод, что у vless: два имени, которым позволено разойтись, пользы не
     * приносят. Имя выхода уже проверено name_ok, поэтому путь собирается
     * из проверенного. */
    if (!o->device[0]) snprintf(o->device, sizeof(o->device), "%.15s", o->name);
    if (!o->devices_n) snprintf(o->devices[o->devices_n++], 32, "%s", o->device);
    if (!o->xs.conf[0])
        snprintf(o->xs.conf, sizeof(o->xs.conf), STEER_ETC_DIR "/xsteer/%.200s.conf", o->name);
    /* Абсолютный путь: процесс запускает procd со своим рабочим каталогом, а не
     * наша оболочка, — относительный «работал бы из шелла» и не работал у
     * сервиса. Годность к JSON: путь печатается в status, diag и xsteer-peers. */
    else if (o->xs.conf[0] != '/' || !label_ok(o->xs.conf))
        return err_set(e, "outputs.%s: conf должен быть абсолютным путём без кавычек", o->name);
    if (o->xs.stream_port && (o->xs.stream_port < 1 || o->xs.stream_port > 65535))
        return err_set(e, "outputs.%s: stream_port вне 1..65535", o->name);
    /* Порт без режима — это настройка, которая ничего не делает: сказать «настроено»,
     * не настроив, хуже, чем отказать. Тот же довод, что у obfs при чужом kind. */
    if (o->xs.stream_port && !o->xs.stream)
        return err_set(e, "outputs.%s: stream_port без stream: транспорт остался бы поддельным TCP",
            o->name);
    return 0;
}

/* xsteer НЕ проверяется ни PROBE_TARGETS, ни пробой TCP, и это не недоделка.
 *
 * PROBE_TARGETS — публичные адреса, то есть проверка интернета У ХАБА. Хаб полной
 * звезды имеет право маршрутизировать только между пирами: у такого выхода
 * AllowedIPs это, скажем, 10.0.0.0/8, и пинг 1.1.1.1 через его устройство теряется на
 * полностью исправном туннеле. При on_fail=drop (умолчании) сторож поставил бы
 * blackhole работающему выходу — то есть сам сломал бы то, что охраняет. Проба TCP,
 * как у vless, проверила бы ровно то же самое и с тем же итогом.
 *
 * Правильная мера здоровья здесь — возраст последнего рукопожатия с хабом, и её
 * источник (файл состояния, который пишет сам процесс) появляется вместе с клиентом.
 * До тех пор приговор даёт наличие устройства (его сторож проверил до вопроса виду):
 * устройство создаёт наш процесс, и пропало оно — значит процесса нет. Это не полная
 * проверка, но она никогда не врёт в сторону «сломано», а именно эта сторона здесь дорого
 * стоит. */
static int xsteer_health(const struct spec *sp, const struct output *o, const char *dev) {
    (void)sp; (void)o; (void)dev;
    return 1;
}

/* Задержка не меряется НИКОГДА, и это то же решение, что у здоровья: замер соединением к
 * PROBE_TARGETS — это проверка интернета у хаба, и на исправном туннеле полной звезды он дал бы
 * -1, то есть выбросил бы выход из сравнения. Возврат -1 честнее: сторож на нём откатывается к
 * порядку. */
static int xsteer_latency(const struct spec *sp, const struct output *o, const char *dev) {
    (void)sp; (void)o; (void)dev;
    return -1;
}

/* Помощник — клиент звезды. В подпись — файл конфигурации и режим потока (sup_sig в
 * supervise.c). */
static int xsteer_helper(const struct spec *sp, const struct output *o, struct kind_helper *h) {
    (void)sp;
    snprintf(h->cmd, sizeof(h->cmd), "xsteer");
    kind_sig_mix(&h->sig, o->xs.conf, strlen(o->xs.conf));
    kind_sig_mix(&h->sig, &o->xs.stream, sizeof(o->xs.stream));
    kind_sig_mix(&h->sig, &o->xs.stream_port, sizeof(o->xs.stream_port));
    return 0;
}

const struct kind_ops kind_xsteer = {
    .name = "xsteer",
    .caps = KC_DEVICE | KC_MARK | KC_CTMARK | KC_ENGINE_OWNED | KC_SELF_NAT | KC_OVER |
            KC_SKIP_ZAPRET,
    .keys = KK_STREAM,
    /* Текст свой, а не общий с vless: формулировка vless («туннель завершает TCP сам, адреса
     * клиентов наружу не уходят») для xsteer неверна — адреса уходят, к хабу. */
    .selfnat_why = "masquerade не нужен и вреден: адреса клиентов уходят к хабу, а NAT "
                   "скрыл бы, от какой пира пришёл пакет",
    .parse = xsteer_parse,
    .health = xsteer_health,
    .latency = xsteer_latency,
    .helper = xsteer_helper,
};
