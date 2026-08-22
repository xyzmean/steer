/* xsteer: поиск пира и поиск сессии. Почему одно линейно, а другое нет — в xsroute.h. */
#include <string.h>
#include "xsroute.h"

void xs_router_build(struct xs_router *r, const struct xs_peer *peers, size_t peer_n) {
    memset(r, 0, sizeof(*r));
    for (size_t i = 0; i < peer_n && i < XS_PEERS_MAX; i++)
        for (size_t a = 0; a < peers[i].allowed_n; a++) {
            if (r->n >= XS_ROUTE_MAX) return;
            r->ent[r->n].net = peers[i].allowed[a].net;
            r->ent[r->n].mask = peers[i].allowed[a].mask;
            r->ent[r->n].plen = (uint8_t)peers[i].allowed[a].plen;
            r->ent[r->n].peer = (int16_t)i;
            r->n++;
        }
    /* Сортировка вставками по длине префикса по убыванию. Список короткий (до 512 записей,
     * на деле десятки) и строится один раз, поэтому простой алгоритм здесь дешевле
     * умного: с ним нечему пойти не так.
     *
     * Смысл сортировки в том, что после неё «самое длинное совпадение» получается ПЕРВЫМ
     * найденным — то есть без дерева, без второго прохода и без сравнения длин на горячем
     * пути. */
    for (size_t i = 1; i < r->n; i++) {
        struct xs_route_ent e = r->ent[i];
        size_t k = i;
        while (k > 0 && r->ent[k - 1].plen < e.plen) { r->ent[k] = r->ent[k - 1]; k--; }
        r->ent[k] = e;
    }
}

int xs_route(const struct xs_router *r, uint32_t dst_host, struct xs_route_cache *c) {
    if (c && c->valid && c->dst == dst_host) return c->peer;
    int found = -1;
    for (size_t i = 0; i < r->n; i++)
        if ((dst_host & r->ent[i].mask) == r->ent[i].net) { found = r->ent[i].peer; break; }
    /* Кэш личный, поэтому порядок записи здесь ни на что не влияет — но признак годности
     * всё равно ставится последним: та же строка, скопированная однажды в общий кэш, была
     * бы гонкой, и пусть она читается как гонка сразу. */
    if (c) {
        c->dst = dst_host;
        c->peer = (int16_t)found;
        c->valid = 1;
    }
    return found;
}

int xs_src_ok(const struct xs_peer *p, uint32_t src_host) {
    for (size_t a = 0; a < p->allowed_n; a++)
        if ((src_host & p->allowed[a].mask) == p->allowed[a].net) return 1;
    return 0;
}

/* Контрольная сумма заголовка IPv4 считается ЗАНОВО, а не поправляется инкрементально.
 *
 * Инкрементальная поправка (RFC 1624) сэкономила бы девять сложений на пакет — против
 * 124 микросекунд AEAD это ноль, — а стоила бы отдельного класса ошибок: заворот
 * переноса при уменьшении TTL через границу байта даёт неверную сумму на редких
 * значениях, и проявляется это как молча отброшенный пакет у той стороны. Здесь дешёвое
 * и очевидно верное лучше быстрого и хитрого; стенд сверяет результат с независимым
 * подсчётом на всех значениях TTL. */
static uint16_t ip_csum(const uint8_t *ip, size_t hl) {
    uint32_t s = 0;
    for (size_t i = 0; i < hl; i += 2) {
        if (i == 10) continue;                 /* поле самой суммы считается нулём */
        s += (uint32_t)((ip[i] << 8) | ip[i + 1]);
    }
    while (s >> 16) s = (s & 0xFFFF) + (s >> 16);
    return (uint16_t)(~s & 0xFFFF);
}

int xs_ttl_dec(uint8_t *ip, size_t n) {
    if (n < 20) return -1;
    if ((ip[0] >> 4) != 4) return -1;
    size_t hl = (size_t)(ip[0] & 0x0F) * 4;
    if (hl < 20 || hl > n) return -1;
    /* TTL 1 и 0 несём дальше нельзя: следующий узел обязан отбросить пакет, а мы бы
     * отправили его по кругу. Отбрасываем здесь и считаем — ICMP «время истекло» не
     * порождаем намеренно: хаб не является узлом маршрутизации в глазах клиента, и
     * ответ от него удивил бы больше, чем помог. */
    if (ip[8] <= 1) return -1;
    ip[8]--;
    uint16_t c = ip_csum(ip, hl);
    ip[10] = (uint8_t)(c >> 8);
    ip[11] = (uint8_t)(c & 0xFF);
    return 0;
}

/* Пересчёт суммы TCP целиком, с псевдозаголовком. Инкрементальную поправку по RFC 1624 здесь
 * не делаем НАРОЧНО: правка касается только SYN, то есть одного пакета на соединение, а не
 * горячего пути, и полный подсчёт на сорока байтах нельзя испортить незаметно — в отличие от
 * поправки, ошибка в которой даёт битую сумму лишь на некоторых значениях поля. */
static void tcp_csum_fix(uint8_t *ip, size_t hl, size_t total) {
    uint8_t *tcp = ip + hl;
    size_t tn = total - hl;
    tcp[16] = tcp[17] = 0;
    uint32_t s = 0;
    for (size_t i = 12; i < 20; i += 2)            /* адреса из псевдозаголовка */
        s += (uint32_t)((ip[i] << 8) | ip[i + 1]);
    s += 6;                                        /* протокол */
    s += (uint32_t)tn;                             /* длина TCP */
    for (size_t i = 0; i + 1 < tn; i += 2)
        s += (uint32_t)((tcp[i] << 8) | tcp[i + 1]);
    if (tn & 1) s += (uint32_t)tcp[tn - 1] << 8;
    while (s >> 16) s = (s & 0xFFFF) + (s >> 16);
    uint16_t c = (uint16_t)(~s & 0xFFFF);
    tcp[16] = (uint8_t)(c >> 8);
    tcp[17] = (uint8_t)(c & 0xFF);
}

int xs_mss_clamp(uint8_t *ip, size_t n, int mtu) {
    if (n < 40 || (ip[0] >> 4) != 4) return 0;
    size_t hl = (size_t)(ip[0] & 0x0F) * 4;
    if (hl < 20 || n < hl + 20) return 0;
    if (ip[9] != 6) return 0;                      /* только TCP */
    /* Длина берётся из заголовка, а не из принятого размера: на приёме из туннеля они
     * совпадают, но полагаться на это нельзя — пакет с завышенной total_len заставил бы
     * считать сумму по чужой памяти. */
    size_t total = ((size_t)ip[2] << 8) | ip[3];
    if (total < hl + 20 || total > n) return 0;
    /* Фрагмент, кроме первого, заголовка TCP не несёт вовсе. */
    if ((((ip[6] << 8) | ip[7]) & 0x1FFF) != 0) return 0;
    uint8_t *tcp = ip + hl;
    size_t thl = (size_t)(tcp[12] >> 4) * 4;
    if (thl < 20 || hl + thl > total) return 0;
    if (!(tcp[13] & 0x02)) return 0;               /* опция MSS бывает только в SYN */
    int limit = mtu - 20 - 20;
    if (limit < 536) limit = 536;                  /* ниже этого не опускаемся: RFC 1122 */
    if (limit > 0xFFFF) return 0;

    for (size_t i = 20; i + 1 <= thl;) {
        uint8_t kind = tcp[i];
        if (kind == 0) break;                      /* конец списка опций */
        if (kind == 1) { i++; continue; }          /* NOP */
        if (i + 1 >= thl) return 0;                /* опция без длины — битый заголовок */
        size_t ol = tcp[i + 1];
        if (ol < 2 || i + ol > thl) return 0;
        if (kind == 2 && ol == 4) {
            int cur = (tcp[i + 2] << 8) | tcp[i + 3];
            if (cur <= limit) return 0;
            tcp[i + 2] = (uint8_t)(limit >> 8);
            tcp[i + 3] = (uint8_t)(limit & 0xFF);
            tcp_csum_fix(ip, hl, total);
            return 1;
        }
        i += ol;
    }
    return 0;
}

uint32_t xs_flow_hash(const uint8_t *ip, size_t n) {
    if (n < 20 || (ip[0] >> 4) != 4) return 0;
    uint32_t h = 2166136261u;                       /* FNV-1a: коротко и без таблиц */
    for (int i = 12; i < 20; i++) { h ^= ip[i]; h *= 16777619u; }
    h ^= ip[9]; h *= 16777619u;                     /* протокол */
    size_t hl = (size_t)(ip[0] & 0x0F) * 4;
    /* Порты берём только у TCP и UDP и только если заголовок целиком на месте: у остального
     * (ICMP, фрагменты) поток определяется адресами, и это верно — фрагменты одного пакета
     * обязаны уйти по одному пути. */
    if ((ip[9] == 6 || ip[9] == 17) && hl >= 20 && n >= hl + 4 &&
        (((ip[6] << 8) | ip[7]) & 0x1FFF) == 0)
        for (size_t i = hl; i < hl + 4; i++) { h ^= ip[i]; h *= 16777619u; }
    return h;
}

/* ---- индекс сессий --------------------------------------------------------- */

void xs_sidx_reset(struct xs_sidx *x) { memset(x, 0, sizeof(*x)); }

int xs_sidx_find(const struct xs_sidx *x, uint32_t addr, uint16_t port) {
    unsigned h = xs_sess_hash(addr, port);
    for (unsigned step = 0; step < XS_SIDX_SLOTS; step++) {
        const struct xs_sidx_ent *e = &x->slot[(h + step) & (XS_SIDX_SLOTS - 1)];
        /* Пустая ячейка обрывает поиск, надгробие — нет: за ним может лежать запись,
         * положенная туда, когда удалённой ещё не было. Пропустить надгробие значило бы
         * «сессия исчезла после того, как рядом закрылась чужая» — беда, которая
         * воспроизводится только под нагрузкой. */
        if (e->state == 0) return -1;
        if (e->state == 1 && e->addr == addr && e->port == port) return e->idx;
    }
    return -1;
}

/* Пересобрать таблицу из живых записей. Надгробия накапливаются: за час работы хаба через
 * него проходят тысячи сессий, и без уборки таблица со временем перестаёт обрывать поиск
 * — то есть каждый промах начинает обходить все 1024 ячейки. Уборка редкая (когда
 * надгробий стало четверть) и стоит один проход. */
static void sidx_rehash(struct xs_sidx *x) {
    struct xs_sidx_ent live[XS_SIDX_SLOTS];
    uint16_t n = 0;
    for (unsigned i = 0; i < XS_SIDX_SLOTS; i++)
        if (x->slot[i].state == 1) live[n++] = x->slot[i];
    memset(x->slot, 0, sizeof(x->slot));
    x->used = 0;
    x->dead = 0;
    for (uint16_t i = 0; i < n; i++)
        xs_sidx_insert(x, live[i].addr, live[i].port, live[i].idx);
}

int xs_sidx_insert(struct xs_sidx *x, uint32_t addr, uint16_t port, int idx) {
    if (x->used + x->dead >= XS_SIDX_SLOTS - 1) {
        if (x->dead) sidx_rehash(x);
        if (x->used >= XS_SIDX_SLOTS - 1) return -1;
    }
    unsigned h = xs_sess_hash(addr, port);
    for (unsigned step = 0; step < XS_SIDX_SLOTS; step++) {
        struct xs_sidx_ent *e = &x->slot[(h + step) & (XS_SIDX_SLOTS - 1)];
        if (e->state == 1 && e->addr == addr && e->port == port) { e->idx = (int16_t)idx; return 0; }
        if (e->state != 1) {
            if (e->state == 2) x->dead--;
            e->addr = addr;
            e->port = port;
            e->idx = (int16_t)idx;
            e->state = 1;
            x->used++;
            return 0;
        }
    }
    return -1;
}

void xs_sidx_remove(struct xs_sidx *x, uint32_t addr, uint16_t port) {
    unsigned h = xs_sess_hash(addr, port);
    for (unsigned step = 0; step < XS_SIDX_SLOTS; step++) {
        struct xs_sidx_ent *e = &x->slot[(h + step) & (XS_SIDX_SLOTS - 1)];
        if (e->state == 0) return;
        if (e->state == 1 && e->addr == addr && e->port == port) {
            e->state = 2;
            x->used--;
            x->dead++;
            if (x->dead > XS_SIDX_SLOTS / 4) sidx_rehash(x);
            return;
        }
    }
}
