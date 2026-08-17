/* Куда отдать пакет: поиск пира по AllowedIPs, проверка источника, TTL, индекс сессий.
 *
 * Зачем отдельным стендом. Ошибка здесь — это «трафик ушёл не тому пиру», и по симптому
 * она не ищется вовсе: канал работает, счётчик растёт, пакеты приходят не туда. Три
 * утверждения, без которых звезда небезопасна или неработоспособна, проверяются именно
 * тут: побеждает самый длинный префикс; отсутствие совпадения означает ОТБРОСИТЬ, а не
 * «отдать первому»; пир не может отправлять от чужого имени.
 *
 * Ни сети, ни mbedtls. */
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#include "../src/ext/xsroute.c"

static int fails;

static void check(const char *what, long want, long got) {
    printf("%-62s %s\n", what, want == got ? "ok" : "ПРОВАЛ");
    if (want != got) {
        printf("     хочу: %ld\n     есть:  %ld\n", want, got);
        fails++;
    }
}

/* Независимый подсчёт суммы TCP: 0 означает «сошлась». */
static int tcpsum_ref(const uint8_t *ip, size_t total) {
    size_t hl = (size_t)(ip[0] & 0x0F) * 4;
    const uint8_t *tcp = ip + hl;
    size_t tn = total - hl;
    uint32_t s = 0;
    for (size_t i = 12; i < 20; i += 2) s += (uint32_t)((ip[i] << 8) | ip[i + 1]);
    s += 6 + (uint32_t)tn;
    for (size_t i = 0; i + 1 < tn; i += 2) s += (uint32_t)((tcp[i] << 8) | tcp[i + 1]);
    if (tn & 1) s += (uint32_t)tcp[tn - 1] << 8;
    while (s >> 16) s = (s & 0xFFFF) + (s >> 16);
    return (uint16_t)(~s & 0xFFFF) != 0;
}

static uint32_t ip4(int a, int b, int c, int d) {
    return ((uint32_t)a << 24) | ((uint32_t)b << 16) | ((uint32_t)c << 8) | (uint32_t)d;
}

static void add_allowed(struct xs_peer *p, uint32_t net, int plen) {
    uint32_t mask = plen ? (0xFFFFFFFFu << (32 - plen)) : 0;
    p->allowed[p->allowed_n].net = net & mask;
    p->allowed[p->allowed_n].mask = mask;
    p->allowed[p->allowed_n].plen = plen;
    p->allowed_n++;
}

/* Независимый подсчёт суммы заголовка: смысл сверки в том, что реализации две. */
static uint16_t csum_ref(const uint8_t *ip, size_t hl) {
    uint32_t s = 0;
    for (size_t i = 0; i < hl; i += 2) {
        uint32_t w = (uint32_t)((ip[i] << 8) | ip[i + 1]);
        if (i == 10) w = 0;
        s += w;
    }
    while (s >> 16) s = (s & 0xFFFF) + (s >> 16);
    return (uint16_t)(~s & 0xFFFF);
}

static uint32_t rnd_state = 0x2BADF00Du;
static uint32_t rnd(void) {
    rnd_state ^= rnd_state << 13;
    rnd_state ^= rnd_state >> 17;
    rnd_state ^= rnd_state << 5;
    return rnd_state;
}

int main(void) {
    /* ---- самое длинное совпадение ------------------------------------------ */
    {
        struct xs_peer peers[3];
        memset(peers, 0, sizeof(peers));
        add_allowed(&peers[0], ip4(10, 0, 0, 0), 8);          /* широкий */
        add_allowed(&peers[1], ip4(10, 9, 0, 0), 16);         /* уже */
        add_allowed(&peers[2], ip4(10, 9, 5, 0), 24);         /* ещё уже */
        struct xs_router r;
        xs_router_build(&r, peers, 3);
        check("маршрут: три записи", 3, (long)r.n);
        check("маршрут: разложены по длине по убыванию", 24, r.ent[0].plen);
        check("маршрут: /24 побеждает /16 и /8", 2, xs_route(&r, ip4(10, 9, 5, 7)));
        r.cache_valid = 0;
        check("маршрут: /16 побеждает /8", 1, xs_route(&r, ip4(10, 9, 6, 7)));
        r.cache_valid = 0;
        check("маршрут: /8 достаётся остальному", 0, xs_route(&r, ip4(10, 1, 1, 1)));
        r.cache_valid = 0;
        /* Отсутствие совпадения — это РЕШЕНИЕ отбросить. Отдать пакет «первому пиру»
         * означало бы утечку трафика между пирами звезды. */
        check("маршрут: нет совпадения — отбросить", -1, xs_route(&r, ip4(192, 168, 1, 1)));
    }
    {
        /* Кэш обязан давать тот же ответ, что обход: иначе первый пакет потока уходит
         * одному пиру, а остальные другому — и это тот самый неотлаживаемый случай. */
        struct xs_peer peers[2];
        memset(peers, 0, sizeof(peers));
        add_allowed(&peers[0], ip4(10, 0, 0, 0), 8);
        add_allowed(&peers[1], ip4(172, 16, 0, 0), 12);
        struct xs_router r;
        xs_router_build(&r, peers, 2);
        int bad = 0;
        for (int i = 0; i < 20000; i++) {
            uint32_t d = rnd();
            struct xs_router fresh;
            xs_router_build(&fresh, peers, 2);
            int with_cache = xs_route(&r, d);      /* r несёт кэш от прошлых вызовов */
            int no_cache = xs_route(&fresh, d);
            if (with_cache != no_cache) bad++;
            /* Тот же адрес второй раз — попадание в кэш, ответ обязан не измениться. */
            if (xs_route(&r, d) != with_cache) bad++;
        }
        check("маршрут: кэш даёт тот же ответ, что обход", 0, bad);
    }
    {
        /* Крайние длины: /0 забирает всё, /32 — ровно один адрес. */
        struct xs_peer peers[2];
        memset(peers, 0, sizeof(peers));
        add_allowed(&peers[0], 0, 0);
        add_allowed(&peers[1], ip4(1, 1, 1, 1), 32);
        struct xs_router r;
        xs_router_build(&r, peers, 2);
        check("маршрут: /32 побеждает /0", 1, xs_route(&r, ip4(1, 1, 1, 1)));
        r.cache_valid = 0;
        check("маршрут: /0 забирает остальное", 0, xs_route(&r, ip4(8, 8, 8, 8)));
        r.cache_valid = 0;
        check("маршрут: /0 забирает и нуль", 0, xs_route(&r, 0));
    }
    {
        struct xs_router r;
        struct xs_peer none;
        memset(&none, 0, sizeof(none));
        xs_router_build(&r, &none, 1);
        check("маршрут: пир без префиксов не даёт записей", 0, (long)r.n);
        check("маршрут: пустая таблица отбрасывает всё", -1, xs_route(&r, ip4(10, 0, 0, 1)));
    }

    /* ---- проверка источника ------------------------------------------------ */
    {
        struct xs_peer p;
        memset(&p, 0, sizeof(p));
        add_allowed(&p, ip4(10, 77, 0, 2), 32);
        add_allowed(&p, ip4(192, 168, 88, 0), 24);
        check("источник: свой адрес внутри туннеля — можно", 1, xs_src_ok(&p, ip4(10, 77, 0, 2)));
        check("источник: свой LAN — можно", 1, xs_src_ok(&p, ip4(192, 168, 88, 33)));
        /* Без этой проверки одна скомпрометированная пир подделывает трафик любой другой. */
        check("источник: чужой адрес — нельзя", 0, xs_src_ok(&p, ip4(10, 77, 0, 3)));
        check("источник: чужая сеть — нельзя", 0, xs_src_ok(&p, ip4(192, 168, 99, 1)));
    }

    /* ---- TTL --------------------------------------------------------------- */
    {
        uint8_t pkt[40];
        memset(pkt, 0, sizeof(pkt));
        pkt[0] = 0x45;                              /* IPv4, заголовок 20 байт */
        pkt[2] = 0; pkt[3] = 40;                    /* длина */
        pkt[9] = 6;                                 /* TCP */
        int bad_sum = 0, bad_rc = 0;
        for (int ttl = 2; ttl <= 255; ttl++) {
            pkt[8] = (uint8_t)ttl;
            uint16_t c = csum_ref(pkt, 20);
            pkt[10] = (uint8_t)(c >> 8);
            pkt[11] = (uint8_t)(c & 0xFF);
            if (xs_ttl_dec(pkt, sizeof(pkt)) != 0) bad_rc++;
            if (pkt[8] != (uint8_t)(ttl - 1)) bad_rc++;
            uint16_t want = csum_ref(pkt, 20);
            uint16_t got = (uint16_t)((pkt[10] << 8) | pkt[11]);
            if (want != got) bad_sum++;
        }
        check("TTL: уменьшается на всех значениях", 0, bad_rc);
        check("TTL: сумма сходится с независимым подсчётом", 0, bad_sum);

        pkt[8] = 1;
        check("TTL: единица — отбросить, а не завернуть в ноль", -1,
              xs_ttl_dec(pkt, sizeof(pkt)));
        pkt[8] = 0;
        check("TTL: нуль — отбросить", -1, xs_ttl_dec(pkt, sizeof(pkt)));
        pkt[8] = 64;
        check("TTL: пакет короче заголовка — отбросить", -1, xs_ttl_dec(pkt, 19));
        pkt[0] = 0x65;                              /* версия 6 в поле IPv4 */
        check("TTL: не IPv4 — отбросить", -1, xs_ttl_dec(pkt, sizeof(pkt)));
        pkt[0] = 0x4F;                              /* заголовок 60 байт, а пакет 40 */
        check("TTL: заголовок длиннее пакета — отбросить", -1, xs_ttl_dec(pkt, 40));
    }
    {
        /* Заголовок с опциями: длина берётся из ihl, а не подразумевается. */
        uint8_t pkt[64];
        memset(pkt, 0, sizeof(pkt));
        pkt[0] = 0x46;                              /* ihl=6, то есть 24 байта */
        pkt[3] = 64;
        pkt[8] = 10;
        pkt[9] = 17;
        pkt[20] = 0x94;                             /* какая-то опция */
        uint16_t c = csum_ref(pkt, 24);
        pkt[10] = (uint8_t)(c >> 8);
        pkt[11] = (uint8_t)(c & 0xFF);
        check("TTL: заголовок с опциями принят", 0, xs_ttl_dec(pkt, sizeof(pkt)));
        uint16_t want = csum_ref(pkt, 24);
        check("TTL: сумма по всему заголовку с опциями", want,
              (long)((pkt[10] << 8) | pkt[11]));
    }

    /* ---- индекс сессий ----------------------------------------------------- */
    {
        struct xs_sidx x;
        xs_sidx_reset(&x);
        check("индекс: пустой ничего не находит", -1, xs_sidx_find(&x, ip4(1, 2, 3, 4), 1234));
        check("индекс: вставка", 0, xs_sidx_insert(&x, ip4(1, 2, 3, 4), 1234, 7));
        check("индекс: находится", 7, xs_sidx_find(&x, ip4(1, 2, 3, 4), 1234));
        check("индекс: другой порт — не тот", -1, xs_sidx_find(&x, ip4(1, 2, 3, 4), 1235));
        check("индекс: другой адрес — не тот", -1, xs_sidx_find(&x, ip4(1, 2, 3, 5), 1234));
        check("индекс: повторная вставка обновляет", 0, xs_sidx_insert(&x, ip4(1, 2, 3, 4), 1234, 9));
        check("индекс: обновлённое значение", 9, xs_sidx_find(&x, ip4(1, 2, 3, 4), 1234));
        xs_sidx_remove(&x, ip4(1, 2, 3, 4), 1234);
        check("индекс: после удаления не находится", -1, xs_sidx_find(&x, ip4(1, 2, 3, 4), 1234));
    }
    {
        /* Полное соответствие с честной таблицей на длинном прогоне со вставками и
         * удалениями: именно здесь ловится и потеря записи за надгробием, и порча
         * таблицы при уборке. */
        struct xs_sidx x;
        xs_sidx_reset(&x);
        enum { N = 600 };
        static uint32_t addrs[N];
        static uint16_t ports[N];
        static int live[N];
        for (int i = 0; i < N; i++) { addrs[i] = rnd(); ports[i] = (uint16_t)(rnd() | 1); }
        int wrong = 0;
        for (int round = 0; round < 40; round++) {
            for (int i = 0; i < N; i++) {
                int op = (int)(rnd() % 3);
                if (op == 0 && !live[i]) {
                    /* Больше 128 живых сессий у хаба не бывает (32 пира × 4), но индекс
                     * обязан выдерживать и заметно больше: заполнение — это то, на чём
                     * открытая адресация ломается, если её сломать можно. */
                    if (x.used < XS_SIDX_SLOTS / 2 && xs_sidx_insert(&x, addrs[i], ports[i], i) == 0)
                        live[i] = 1;
                } else if (op == 1 && live[i]) {
                    xs_sidx_remove(&x, addrs[i], ports[i]);
                    live[i] = 0;
                }
                int got = xs_sidx_find(&x, addrs[i], ports[i]);
                if (live[i] ? got != i : got != -1) wrong++;
            }
        }
        check("индекс: 24 тысячи операций — ни одного расхождения", 0, wrong);
        check("индекс: надгробий не накопилось выше порога уборки", 1,
              x.dead <= XS_SIDX_SLOTS / 4);
    }
    {
        /* Поиск отсутствующей записи в почти полной таблице обязан завершаться, а не
         * ходить по кругу. */
        struct xs_sidx x;
        xs_sidx_reset(&x);
        for (unsigned i = 0; i < XS_SIDX_SLOTS - 2; i++)
            xs_sidx_insert(&x, ip4(10, 0, (int)(i >> 8), (int)(i & 0xFF)), 1000, (int)(i % 128));
        check("индекс: почти полон", XS_SIDX_SLOTS - 2, (long)x.used);
        check("индекс: поиск отсутствующей завершается", -1, xs_sidx_find(&x, ip4(9, 9, 9, 9), 1));
        /* Заполнение до отказа: последняя свободная ячейка занимается, следующая вставка
         * ОТКАЗЫВАЕТ, а не портит таблицу и не уходит в бесконечный обход. Проверяется
         * именно этой парой, потому что «вернуло -1» без «остальное цело» ничего не
         * говорит: испортить таблицу можно и вернув отказ. */
        check("индекс: последняя ячейка занимается", 0, xs_sidx_insert(&x, ip4(9, 9, 9, 9), 1, 5));
        check("индекс: вставка сверх ёмкости — отказ", -1, xs_sidx_insert(&x, ip4(9, 9, 9, 10), 1, 6));
        check("индекс: после отказа таблица цела", 5, xs_sidx_find(&x, ip4(9, 9, 9, 9), 1));
        check("индекс: отказавшая запись не появилась", -1, xs_sidx_find(&x, ip4(9, 9, 9, 10), 1));
    }

    /* ---- подрезка MSS ------------------------------------------------------- */
    {
        /* Независимый подсчёт суммы TCP: сравнивать правку кода с ним же самим смысла нет,
         * поэтому сумма здесь считается второй реализацией, буква в букву по RFC 793. */
        #define TCPSUM(pkt, total) tcpsum_ref(pkt, total)
        uint8_t syn[60];
        /* SYN с опциями MSS 1460, SACK_PERM и NOP — то, что действительно шлёт Linux. */
        static const uint8_t tmpl[] = {
            0x45, 0x00, 0x00, 0x34, 0x12, 0x34, 0x40, 0x00, 0x40, 0x06, 0x00, 0x00,
            10, 0, 0, 2,  1, 1, 1, 1,
            0xc0, 0x00, 0x01, 0xbb, 0x11, 0x22, 0x33, 0x44, 0x00, 0x00, 0x00, 0x00,
            0x80, 0x02, 0xff, 0xff, 0x00, 0x00, 0x00, 0x00,
            0x02, 0x04, 0x05, 0xb4,          /* MSS 1460 */
            0x01, 0x01, 0x04, 0x02,          /* NOP NOP SACK_PERM */
            0x01, 0x03, 0x03, 0x07           /* NOP, window scale */
        };
        memcpy(syn, tmpl, sizeof(tmpl));
        check("MSS: 1460 при туннеле 1387 подрезан", 1, xs_mss_clamp(syn, sizeof(tmpl), 1387));
        check("MSS: поставлено ровно mtu-40", 1347, (syn[42] << 8) | syn[43]);
        check("MSS: сумма TCP сошлась", 0, tcpsum_ref(syn, sizeof(tmpl)));
        check("MSS: остальные опции не тронуты", 0x04, syn[46]);
        check("MSS: повторный вызов уже ничего не меняет", 0, xs_mss_clamp(syn, sizeof(tmpl), 1387));

        /* Меньше предела — не трогаем: подрезка обязана только опускать. */
        memcpy(syn, tmpl, sizeof(tmpl));
        syn[42] = 0x02; syn[43] = 0x00;                 /* MSS 512 */
        check("MSS: меньше предела оставлен как есть", 0, xs_mss_clamp(syn, sizeof(tmpl), 1387));
        check("MSS: значение не изменилось", 512, (syn[42] << 8) | syn[43]);

        /* Не SYN — опции MSS в нём быть не может, а байты на её месте это данные. */
        memcpy(syn, tmpl, sizeof(tmpl));
        syn[33] = 0x10;                                 /* только ACK */
        check("MSS: не-SYN не трогаем", 0, xs_mss_clamp(syn, sizeof(tmpl), 1387));
        check("MSS: данные не-SYN целы", 0xb4, syn[43]);

        /* Не TCP, не IPv4, обрезанный пакет. */
        memcpy(syn, tmpl, sizeof(tmpl));
        syn[9] = 17;
        check("MSS: UDP не трогаем", 0, xs_mss_clamp(syn, sizeof(tmpl), 1387));
        memcpy(syn, tmpl, sizeof(tmpl));
        syn[0] = 0x65;
        check("MSS: не IPv4 не трогаем", 0, xs_mss_clamp(syn, sizeof(tmpl), 1387));
        memcpy(syn, tmpl, sizeof(tmpl));
        check("MSS: короткий пакет не трогаем", 0, xs_mss_clamp(syn, 39, 1387));

        /* Заявленная длина больше принятой: считать сумму по чужой памяти нельзя. */
        memcpy(syn, tmpl, sizeof(tmpl));
        syn[2] = 0xFF; syn[3] = 0xFF;
        check("MSS: total_len больше пакета — отказ", 0, xs_mss_clamp(syn, sizeof(tmpl), 1387));

        /* Битая опция: длина 0 закрутила бы обход навсегда, длина за границей заголовка
         * заставила бы читать чужие байты. */
        memcpy(syn, tmpl, sizeof(tmpl));
        syn[41] = 0;
        check("MSS: опция длиной 0 — отказ, а не зацикливание", 0, xs_mss_clamp(syn, sizeof(tmpl), 1387));
        memcpy(syn, tmpl, sizeof(tmpl));
        syn[41] = 40;
        check("MSS: опция за границей заголовка — отказ", 0, xs_mss_clamp(syn, sizeof(tmpl), 1387));

        /* Конец списка опций до MSS: дальше лежит набивка, а не опции. */
        memcpy(syn, tmpl, sizeof(tmpl));
        syn[40] = 0;
        check("MSS: после EOL опции не разбираем", 0, xs_mss_clamp(syn, sizeof(tmpl), 1387));

        /* Опции IP (ihl > 5) сдвигают заголовок TCP — самый частый способ ошибиться. */
        {
            uint8_t big[64];
            memcpy(big, tmpl, 20);
            big[0] = 0x46;                              /* ihl 6: четыре байта опций IP */
            big[2] = 0x00; big[3] = 0x38;
            memset(big + 20, 0x01, 4);
            memcpy(big + 24, tmpl + 20, sizeof(tmpl) - 20);
            check("MSS: с опциями IP найден и подрезан", 1, xs_mss_clamp(big, 0x38, 1387));
            check("MSS: с опциями IP значение верное", 1347, (big[46] << 8) | big[47]);
            check("MSS: с опциями IP сумма сошлась", 0, tcpsum_ref(big, 0x38));
        }

        /* Не первый фрагмент заголовка TCP не несёт. */
        memcpy(syn, tmpl, sizeof(tmpl));
        syn[6] = 0x00; syn[7] = 0x10;                   /* смещение 128 байт */
        check("MSS: не первый фрагмент не трогаем", 0, xs_mss_clamp(syn, sizeof(tmpl), 1387));

        /* Крошечный туннель: ниже 536 не опускаемся, иначе сегменты станут неразумно мелкими. */
        memcpy(syn, tmpl, sizeof(tmpl));
        check("MSS: при mtu 500 предел 536, а не меньше", 1, xs_mss_clamp(syn, sizeof(tmpl), 500));
        check("MSS: нижняя граница соблюдена", 536, (syn[42] << 8) | syn[43]);
        #undef TCPSUM
    }

    /* ---- хеш внутреннего потока --------------------------------------------- */
    {
        uint8_t pkt[40];
        static const uint8_t tmpl[] = {
            0x45, 0x00, 0x00, 0x28, 0x00, 0x01, 0x00, 0x00, 0x40, 0x06, 0x00, 0x00,
            10, 77, 0, 2,  10, 77, 0, 3,
            0x30, 0x39, 0x01, 0xbb, 0, 0, 0, 0, 0, 0, 0, 0, 0x50, 0x10, 0xff, 0xff, 0, 0, 0, 0
        };
        memcpy(pkt, tmpl, sizeof(tmpl));
        uint32_t h1 = xs_flow_hash(pkt, sizeof(tmpl));
        check("хеш потока: не ноль на обычном пакете", 1, h1 != 0);
        /* Тот же поток — тот же ответ, иначе пакеты одного соединения разъехались бы по разным
         * путям и приезжали переставленными. */
        check("хеш потока: повторный вызов даёт то же", 1, h1 == xs_flow_hash(pkt, sizeof(tmpl)));
        /* Другой порт источника — другой поток. */
        pkt[20] = 0x30; pkt[21] = 0x3A;
        check("хеш потока: другой порт — другой ответ", 1, h1 != xs_flow_hash(pkt, sizeof(tmpl)));
        /* Не первый фрагмент портов не несёт: они обязаны идти тем же путём, что первый,
         * поэтому от полей за заголовком хеш зависеть не должен. */
        memcpy(pkt, tmpl, sizeof(tmpl));
        pkt[6] = 0x00; pkt[7] = 0x10;
        uint32_t hf = xs_flow_hash(pkt, sizeof(tmpl));
        pkt[20] = 0xAA; pkt[21] = 0xBB;
        check("хеш потока: у фрагмента порты не учитываются", 1, hf == xs_flow_hash(pkt, sizeof(tmpl)));
        /* Мусор и обрезки не должны читать за буфером и обязаны давать хоть что-то. */
        memcpy(pkt, tmpl, sizeof(tmpl));
        check("хеш потока: короткий пакет — ноль", 0, (long)xs_flow_hash(pkt, 10));
        pkt[0] = 0x60;
        check("хеш потока: не IPv4 — ноль", 0, (long)xs_flow_hash(pkt, sizeof(tmpl)));
        /* Распределение: восемь соединений должны получать не один и тот же номер, иначе
         * раскладка выродится в «всё в одно». */
        {
            int hit[8];
            memset(hit, 0, sizeof(hit));
            memcpy(pkt, tmpl, sizeof(tmpl));
            for (int port = 1024; port < 1024 + 64; port++) {
                pkt[20] = (uint8_t)(port >> 8);
                pkt[21] = (uint8_t)(port & 0xFF);
                hit[xs_flow_hash(pkt, sizeof(tmpl)) & 7]++;
            }
            int used = 0;
            for (int i = 0; i < 8; i++) if (hit[i]) used++;
            check("хеш потока: 64 порта разошлись по всем восьми слотам", 8, used);
        }
    }

    printf("\n%s\n", fails ? "ЕСТЬ ПРОВАЛЫ" : "все проверки прошли");
    return fails ? 1 : 0;
}
