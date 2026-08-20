/* Арифметика провода xsteer: запись, nonce, окно приёма, пределы соединения.
 *
 * Зачем отдельным стендом. Всё, что здесь проверяется, ломается МОЛЧА. Ошибка в поле
 * длины записи — пакет отбрасывается стеком той стороны без единого сообщения; ошибка в
 * nonce — каждый пакет не расшифровывается, и это выглядит как «туннель поднялся и не
 * несёт трафик»; ошибка в окне — либо честные пакеты отвергаются как повторы, либо
 * воспроизведение проходит, и ни то ни другое из журнала не видно. Поэтому проверяются
 * границы и свойства, а не пара примеров.
 *
 * Ни сети, ни прав root, ни mbedtls: xswire.c намеренно не включает библиотеку (см. его
 * заголовок), поэтому стенд подключает исходник напрямую и входит в обычный make test —
 * так же, как submatch и visionmatch, и в отличие от остального src/ext, который доходит
 * только до ext-syntax. */
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#include "../src/ext/xswire.c"

static int fails;

/* Приёмник кадров пачки: обратный вызов, потому что разбор отдаёт кадры по одному и не
 * выделяет памяти. */
static int got_n;
static size_t got_bytes;
static void collect(void *ctx, const uint8_t *frame, size_t flen) {
    (void)ctx;
    (void)frame;
    got_n++;
    got_bytes += flen;
}

static void check(const char *what, long want, long got) {
    printf("%-62s %s\n", what, want == got ? "ok" : "ПРОВАЛ");
    if (want != got) {
        printf("     хочу: %ld\n     есть:  %ld\n", want, got);
        fails++;
    }
}

/* Независимая реализация того же вывода nonce, что в src/ext/tls13.c (aead_nonce): номер
 * записи 64-битный и накладывается на все восемь младших байт. Наша xs_nonce работает по
 * 32-битному смещению — то есть обязана давать тот же ответ на любом смещении, иначе
 * xsteer и TLS-слой, из которого взят AEAD, разойдутся в шифровании. Списывать её нельзя:
 * смысл сверки в том, что реализации две. */
static void nonce_ref(const unsigned char iv[12], uint64_t seq, unsigned char out[12]) {
    memcpy(out, iv, 12);
    for (int i = 0; i < 8; i++)
        out[11 - i] ^= (unsigned char)(seq >> (8 * i));
}

/* Простой детерминированный генератор: стенд обязан давать один и тот же прогон при
 * каждом запуске, иначе «иногда падает» превращается в неотлаживаемое. */
static uint32_t rnd_state = 0x12345678u;
static uint32_t rnd(void) {
    rnd_state ^= rnd_state << 13;
    rnd_state ^= rnd_state >> 17;
    rnd_state ^= rnd_state << 5;
    return rnd_state;
}

int main(void) {
    /* ---- размеры: числа, выведенные одно из другого ------------------------
     * Статические проверки в xswire.h уже не дали бы файлу собраться при расхождении;
     * здесь то же самое сказано ещё раз числами, чтобы при чтении стенда не приходилось
     * держать арифметику в голове. */
    check("накладные расходы 61 байт", 61, XS_OVERHEAD);
    check("место под заголовки 45 байт", 45, XS_HDR_ROOM);
    check("MTU туннеля при канале 1500", 1439, XS_MTU_DEF);
    check("строка буфера равна пакету на проводе", XS_LINK_MAX,
          XS_HDR_ROOM + XS_MTU_DEF + XS_TAG);
    check("MTU: канал 1500", 1439, xs_mtu(1500));
    check("MTU: канал 1492 (PPPoE)", 1431, xs_mtu(1492));
    check("MTU: канал 1400", 1339, xs_mtu(1400));
    /* Выигрыш против того, что в движке уже едет по поддельному TCP (20+20+32 = 72). */
    check("дешевле WireGuard поверх поддельного TCP на 11 байт", 11, 72 - XS_OVERHEAD);

    /* ---- заголовок записи -------------------------------------------------- */
    {
        uint8_t h[XS_REC_HDR];
        check("запись: сборка на 1455 байт", 0, xs_rec_build(h, 1455));
        check("запись: тип application_data", 0x17, h[0]);
        check("запись: версия 0x0303, как у настоящего TLS 1.3", 0x0303,
              ((long)h[1] << 8) | h[2]);
        check("запись: длина старшим байтом вперёд", 1455, ((long)h[3] << 8) | h[4]);
        check("запись: нагрузка короче тега — отказ", -1, xs_rec_build(h, XS_TAG - 1));
        check("запись: нагрузка больше поля длины — отказ", -1, xs_rec_build(h, 0x10000));
    }
    {
        /* Полный круг: собрали заголовок, разобрали, получили ту же нагрузку. */
        uint8_t seg[XS_REC_HDR + 100];
        xs_rec_build(seg, 100);
        for (int i = 0; i < 100; i++) seg[XS_REC_HDR + i] = (uint8_t)i;
        const uint8_t *body = NULL;
        size_t body_n = 0;
        check("разбор: принят", 0, xs_rec_parse(seg, sizeof(seg), &body, &body_n));
        check("разбор: длина нагрузки", 100, (long)body_n);
        check("разбор: нагрузка та самая", 0, memcmp(body, seg + XS_REC_HDR, 100));
    }
    {
        uint8_t seg[XS_REC_HDR + 100];
        const uint8_t *body;
        size_t body_n;
        xs_rec_build(seg, 100);

        seg[0] = 0x16;   /* handshake: форма верная, тип не наш */
        check("разбор: чужой тип записи отвергнут", -1,
              xs_rec_parse(seg, sizeof(seg), &body, &body_n));
        seg[0] = 0x17;
        seg[1] = 0x03; seg[2] = 0x04;
        check("разбор: версия 0x0304 отвергнута", -1,
              xs_rec_parse(seg, sizeof(seg), &body, &body_n));
        xs_rec_build(seg, 100);
        /* Длина, не равная остатку сегмента, — предфильтр, а не педантизм: за концом
         * записи в датаграммном протоколе прятать нечего. */
        seg[4] = 99;
        check("разбор: длина меньше остатка отвергнута", -1,
              xs_rec_parse(seg, sizeof(seg), &body, &body_n));
        seg[4] = 101;
        check("разбор: длина больше остатка отвергнута", -1,
              xs_rec_parse(seg, sizeof(seg), &body, &body_n));
        xs_rec_build(seg, 100);
        check("разбор: сегмент короче минимальной записи отвергнут", -1,
              xs_rec_parse(seg, XS_REC_MIN - 1, &body, &body_n));
    }
    {
        /* Keepalive: открытый текст пустой, нагрузка — один тег. Самая маленькая запись,
         * которая обязана проходить: на ней держится живым отображение NAT. */
        uint8_t seg[XS_REC_MIN];
        const uint8_t *body;
        size_t body_n;
        check("keepalive: заголовок собран", 0, xs_rec_build(seg, XS_TAG));
        check("keepalive: разобран", 0, xs_rec_parse(seg, sizeof(seg), &body, &body_n));
        check("keepalive: нагрузка — только тег", XS_TAG, (long)body_n);
    }

    /* ---- тип кадра по первому байту открытого текста ---------------------- */
    {
        uint8_t p[64];
        memset(p, 0, sizeof(p));
        check("кадр: пустой — keepalive", XS_KEEPALIVE, xs_frame_kind(p, 0));
        p[0] = 0x45;
        check("кадр: 0x45 — IPv4", XS_IPV4, xs_frame_kind(p, 40));
        check("кадр: IPv4 короче заголовка — брак", XS_BAD, xs_frame_kind(p, 19));
        p[0] = 0x60;
        check("кадр: 0x60 — IPv6", XS_IPV6, xs_frame_kind(p, 40));
        check("кадр: IPv6 короче заголовка — брак", XS_BAD, xs_frame_kind(p, 39));
        p[0] = XS_CTL_MTU;
        check("кадр: младшие значения — служебный", XS_CTL, xs_frame_kind(p, 8));
        p[0] = 0x50;   /* не 4 и не 6 в старшем полубайте */
        check("кадр: чужая версия IP — брак", XS_BAD, xs_frame_kind(p, 40));
    }

    /* ---- смещение: инвариантность к постоянному сдвигу --------------------
     *
     * Ради этого свойства nonce и считается от относительного смещения. Без стенда
     * утверждение «посредник, рандомизирующий начальный номер, нам не мешает» остаётся
     * словами, а проверить его на живом стенде нечем: такого посредника не воспроизвести. */
    {
        uint32_t isn = 0xDEADBEEFu;
        check("смещение: первая запись — единица", 1, xs_rel(isn + 1, isn));
        check("смещение: считается через заворот uint32", 3,
              xs_rel(0x00000002u, 0xFFFFFFFFu));
        int bad = 0;
        for (int i = 0; i < 1000; i++) {
            uint32_t base_isn = rnd();
            uint32_t off = rnd() % 100000u + 1;
            uint32_t delta = rnd();              /* сдвиг посредника */
            if (xs_rel(base_isn + off, base_isn) !=
                xs_rel(base_isn + delta + off, base_isn + delta)) bad++;
        }
        check("смещение: постоянный сдвиг номеров ничего не меняет", 0, bad);
    }

    /* ---- nonce ------------------------------------------------------------- */
    {
        uint8_t iv[12];
        for (int i = 0; i < 12; i++) iv[i] = (uint8_t)(0xA0 + i);
        int bad = 0;
        uint32_t probes[] = { 0, 1, 2, 255, 256, 65535, 65536, 0x00FFFFFFu,
                              0x01000000u, XS_REL_RETIRE, 0xFFFFFFFFu };
        for (size_t i = 0; i < sizeof(probes) / sizeof(probes[0]); i++) {
            uint8_t a[12], b[12];
            xs_nonce(iv, probes[i], a);
            nonce_ref(iv, probes[i], b);
            if (memcmp(a, b, 12) != 0) bad++;
        }
        for (int i = 0; i < 5000; i++) {
            uint32_t r = rnd();
            uint8_t a[12], b[12];
            xs_nonce(iv, r, a);
            nonce_ref(iv, r, b);
            if (memcmp(a, b, 12) != 0) bad++;
        }
        check("nonce: совпадает с выводом TLS 1.3 на всех смещениях", 0, bad);
        uint8_t z[12], out[12];
        memset(z, 0, sizeof(z));
        xs_nonce(z, 0, out);
        check("nonce: нулевое смещение не меняет iv", 0, memcmp(z, out, 12));
        xs_nonce(iv, 1, out);
        check("nonce: единица ложится в младший байт", iv[11] ^ 1, out[11]);
        check("nonce: старшие байты iv не тронуты", 0, memcmp(iv, out, 8));
    }

    /* ---- окно приёма ------------------------------------------------------- */
    {
        struct xs_win w;
        xs_win_reset(&w);
        check("окно: нулевое смещение не бывает данными", -1, xs_win_check(&w, 0));
        check("окно: первая запись принята", 0, xs_win_check(&w, 1));
        xs_win_commit(&w, 1);
        check("окно: повтор первой отвергнут", -1, xs_win_check(&w, 1));
        check("окно: следующая по порядку принята", 0, xs_win_check(&w, 1460));
        xs_win_commit(&w, 1460);
        check("окно: пропуск вперёд принят", 0, xs_win_check(&w, 5000));
        xs_win_commit(&w, 5000);
        check("окно: пришедшая позже дырка принята", 0, xs_win_check(&w, 2920));
        xs_win_commit(&w, 2920);
        check("окно: её повтор отвергнут", -1, xs_win_check(&w, 2920));
        check("окно: самое дальнее принятое не сдвинулось назад", 5000, (long)w.max);
    }
    {
        /* Подделка с далёким смещением НЕ должна двигать окно: commit зовётся только
         * после сошедшегося тега. Если бы двигала, честный поток стал бы «слишком
         * старым» — то есть один поддельный пакет глушил бы туннель. */
        struct xs_win w;
        xs_win_reset(&w);
        for (uint32_t r = 1; r <= 100; r++) { xs_win_check(&w, r); xs_win_commit(&w, r); }
        (void)xs_win_check(&w, 900000000u);          /* тег не сошёлся — commit не зовём */
        check("окно: неподтверждённое смещение не двигает max", 100, (long)w.max);
        check("окно: честный следующий пакет по-прежнему принят", 0, xs_win_check(&w, 101));
    }
    {
        /* Кольцо переполнено: всё, что старше самого старого помнимого, отвергается —
         * не потому, что это точно повтор, а потому, что проверить нечем. */
        struct xs_win w;
        xs_win_reset(&w);
        for (uint32_t r = 1; r <= XS_WIN_RING + 50; r++) {
            if (xs_win_check(&w, r) == 0) xs_win_commit(&w, r);
        }
        check("окно: за пределами памяти отвергнуто", -1, xs_win_check(&w, 3));
        check("окно: внутри памяти повтор отвергнут", -1, xs_win_check(&w, XS_WIN_RING + 10));
        check("окно: новое смещение принято", 0, xs_win_check(&w, XS_WIN_RING + 51));
    }
    {
        /* Свойство целиком: поток с переупорядочиванием, дублями и потерями. Ни одного
         * ложного отказа на честном пакете и ни одного принятого дубля. */
        struct xs_win w;
        xs_win_reset(&w);
        enum { N = 20000, JITTER = 40 };
        static uint32_t offs[N];
        uint32_t rel = 1;
        for (int i = 0; i < N; i++) {
            offs[i] = rel;
            rel += 21 + rnd() % 1440;            /* запись: 5 + нагрузка + 16 */
        }
        static char accepted[N];
        int false_reject = 0, dup_accepted = 0;
        for (int i = 0; i < N; i++) {
            /* Переупорядочивание: берём индекс из окна вокруг текущего. */
            int k = i + (int)(rnd() % (2 * JITTER + 1)) - JITTER;
            if (k < 0) k = 0;
            if (k >= N) k = N - 1;
            for (int rep = 0; rep < 2; rep++) {          /* каждый второй — дубль */
                int ok = xs_win_check(&w, offs[k]) == 0;
                if (ok) xs_win_commit(&w, offs[k]);
                if (ok && accepted[k]) dup_accepted++;
                if (!ok && !accepted[k] &&
                    (int32_t)(offs[k] - w.ring[w.head]) >= 0) false_reject++;
                if (ok) accepted[k] = 1;
                if (rnd() % 2) break;                    /* иногда дубля нет */
            }
        }
        check("окно: ни одного принятого дубля на 20 тыс. записей", 0, dup_accepted);
        check("окно: ни одного ложного отказа внутри памяти", 0, false_reject);
    }

    /* ---- пределы соединения ----------------------------------------------- */
    {
        check("ретайр: на покое не срабатывает", 0, xs_retire_due(1000, 1000));
        check("ретайр: по объёму", 1, xs_retire_due(XS_REL_RETIRE, 0));
        check("ретайр: за байт до порога ещё нет", 0, xs_retire_due(XS_REL_RETIRE - 1, 0));
        check("ретайр: по времени", 1, xs_retire_due(0, XS_AGE_RETIRE_MS));
        /* Порог успешника проверяется с двух сторон, а НЕ повторением его формулы: стенд,
         * переписавший выражение из заголовка, проверяет только собственное умение делить
         * в том же порядке (первая же версия этой строки на этом и упала — деление до
         * умножения дало другое число). Важно поведение: заметно раньше ретайра — да,
         * задолго до него — нет. */
        check("успешник: на 95% объёма поднимается", 1,
              xs_renew_due((uint32_t)((uint64_t)XS_REL_RETIRE * 95 / 100), 0));
        check("успешник: на 80% объёма ещё нет", 0,
              xs_renew_due((uint32_t)((uint64_t)XS_REL_RETIRE * 80 / 100), 0));
        check("успешник: на 95% времени поднимается", 1,
              xs_renew_due(0, (long long)XS_AGE_RETIRE_MS * 95 / 100));
        check("успешник: на 80% времени ещё нет", 0,
              xs_renew_due(0, (long long)XS_AGE_RETIRE_MS * 80 / 100));
        check("успешник: всегда раньше ретайра", 0,
              xs_retire_due((uint32_t)((uint64_t)XS_REL_RETIRE * 95 / 100), 0));
        /* Главное свойство: ретайр наступает ЗАДОЛГО до заворота uint32, поэтому
         * восстанавливать старшие разряды смещения не нужно вовсе — и кода, который это
         * делает раз в 4 ГиБ и потому не проверен ничем, в протоколе нет. */
        check("ретайр: наступает раньше заворота с большим запасом", 1,
              XS_REL_RETIRE < 0xFFFFFFFFu / 2);
        int late = 0;
        for (uint32_t r = XS_REL_RETIRE; r != 0; r += 0x01000000u)
            if (!xs_retire_due(r, 0)) late++;
        check("ретайр: срабатывает на всём остатке диапазона", 0, late);
    }

    /* ---- согласование MTU --------------------------------------------------
     *
     * Лестница и кадры проб — то, что ломается незаметно: туннель продолжает работать, просто
     * медленнее, потому что согласовался на меньшем размере или не согласовался вовсе. */
    {
        /* Поиск предела делением. Проверяется не «работает ли», а два свойства, которые
         * ломаются молча: сходимость (иначе пробы идут вечно) и то, что в обычном случае
         * полная скорость достаётся ОДНОЙ пробой. */
        check("поиск: без верхней границы пробуем потолок", 1431,
              xs_mtu_next(XS_MTU_FLOOR, 0, 1431));
        check("поиск: потолок подтвердился — больше нечего проверять", 0,
              xs_mtu_next(1431, 0, 1431));
        check("поиск: потолок зажат сверху пределом записи", XS_MTU_DEF,
              xs_mtu_next(XS_MTU_FLOOR, 0, 99999));
        check("поиск: потолок ниже низа — нечего проверять", 0,
              xs_mtu_next(XS_MTU_FLOOR, 0, XS_MTU_FLOOR));
        check("поиск: середина отрезка", 1300, xs_mtu_next(1200, 1400, 1431));
        check("поиск: сошлось при разнице меньше зерна", 0, xs_mtu_next(1380, 1387, 1431));
        check("поиск: границы вне разумного зажимаются", 1, xs_mtu_next(-100, 0, 1431) > 0);

        /* Сходимость на всех возможных настоящих пределах: поиск обязан за считанные пробы
         * прийти к значению не ниже (настоящий − зерно) и никогда выше настоящего. */
        int worst_tries = 0, too_low = 0, too_high = 0;
        for (int real = XS_MTU_FLOOR; real <= XS_MTU_DEF; real++) {
            int lo = XS_MTU_FLOOR, hi = 0, tries = 0, cur;
            while ((cur = xs_mtu_next(lo, hi, XS_MTU_DEF)) != 0) {
                if (++tries > XS_MTU_TRIES_MAX) break;
                if (cur <= real) lo = cur; else hi = cur;
            }
            if (tries > worst_tries) worst_tries = tries;
            if (lo > real) too_high++;
            if (real - lo > XS_MTU_GRAIN) too_low++;
        }
        check("поиск: ни разу не выбрал размер больше настоящего", 0, too_high);
        check("поиск: всегда сошёлся в пределах зерна", 0, too_low);
        check("поиск: уложился в предел числа проб", 1, worst_tries <= XS_MTU_TRIES_MAX);
    }
    {
        static uint8_t pt[XS_ROW];
        int size = 1387;
        check("проба: собрана заявленного размера", size,
              xs_probe_build(pt, sizeof(pt), size));
        check("проба: тип кадра — служебный", XS_CTL, xs_frame_kind(pt, (size_t)size));
        check("проба: размер читается обратно", size, xs_probe_size(pt, (size_t)size));
        /* Заявленный размер обязан совпадать с фактическим. Иначе эхо сообщило бы, что путь
         * несёт больше, чем несёт: кадр на 100 байт, заявивший 1400, «прошёл бы». */
        check("проба: заявлено больше, чем пришло — не проба", -1, xs_probe_size(pt, 100));
        check("проба: слишком маленькая — отказ", -1, xs_probe_build(pt, sizeof(pt), 3));
        check("проба: больше предела записи — отказ", -1,
              xs_probe_build(pt, sizeof(pt), XS_MTU_DEF + 1));

        check("эхо: три байта", 3, (long)xs_pack_build(pt, sizeof(pt), size));
        check("эхо: размер читается обратно", size, xs_pack_size(pt, 3));
        check("эхо: проба за эхо не выдаётся", -1, xs_probe_size(pt, 3));

        check("итог: три байта", 3, (long)xs_mtu_build(pt, sizeof(pt), 1387));
        check("итог: значение читается обратно", 1387, xs_mtu_value(pt, 3));
        check("итог: эхо за итог не выдаётся", -1, xs_mtu_value(pt, 3) == 1387 ? -1 : 0);
    }

    /* ---- ограничитель частоты сообщений ------------------------------------- */
    {
        struct xs_ratelog r;
        memset(&r, 0, sizeof(r));
        unsigned long long held = 99;
        check("ограничитель: первое сообщение печатается", 1, xs_ratelog(&r, 1000, 5000, &held));
        check("ограничитель: подавленных при первом нет", 0, (long)held);
        int printed = 0;
        for (long long t = 1001; t < 6000; t++) {
            unsigned long long h = 0;
            if (xs_ratelog(&r, t, 5000, &h)) printed++;
        }
        check("ограничитель: внутри окна не напечатал ничего", 0, printed);
        held = 0;
        check("ограничитель: за окном печатает снова", 1, xs_ratelog(&r, 6001, 5000, &held));
        /* Число подавленных обязано быть НАСТОЯЩИМ: именно оно отличает «поправьте настройку»
         * от «вас заливают», и потерять его значит соврать в журнале. */
        check("ограничитель: подавленные посчитаны все", 4999, (long)held);
        held = 0;
        check("ограничитель: сразу после печати снова молчит", 0, xs_ratelog(&r, 6002, 5000, &held));

        /* Хвост строки: при нуле подавленных — пустой, иначе с числом. */
        char buf[64];
        check("хвост: при нуле пустой", 1, xs_held_str(0, buf, sizeof(buf))[0] == 0);
        check("хвост: при ненулевом непустой", 1, xs_held_str(7, buf, sizeof(buf))[0] != 0);
        check("хвост: число в тексте есть", 1, strstr(xs_held_str(7, buf, sizeof(buf)), "7") != NULL);

        /* Нулевое время не должно означать «ещё ни разу не печатали»: иначе первый же вызов в
         * нулевую миллисекунду открывал бы поток заново на каждый пакет. */
        struct xs_ratelog z;
        memset(&z, 0, sizeof(z));
        held = 0;
        check("ограничитель: печать в нулевое время учтена", 1, xs_ratelog(&z, 0, 5000, &held));
        check("ограничитель: следующая в нулевое время подавлена", 0, xs_ratelog(&z, 0, 5000, &held));
    }


    /* ---- пачка кадров в одной записи ---------------------------------------
     *
     * Зачем она нужна и чем оплачена — в xswire.h. Здесь проверяется то, на чём эта затея
     * стоит: круг сборки и разбора, отказ от контейнера для одиночного кадра, отвержение
     * битого контейнера ЦЕЛИКОМ и — главное — что пачка дешевле тех же кадров поодиночке. */
    {
        static uint8_t f1[40], f2[1439], f3[1];
        memset(f1, 0x45, sizeof(f1));
        memset(f2, 0x46, sizeof(f2));
        f3[0] = 0x47;
        struct xs_frame fr[3] = { { f1, sizeof(f1) }, { f2, sizeof(f2) }, { f3, sizeof(f3) } };
        static uint8_t dst[XS_MAX_RECORD];
        size_t n = xs_batch_build(dst, sizeof(dst), fr, 3);
        check("пачка: собрана", 1, n > 0);
        check("пачка: контейнер опознаётся как служебный кадр", XS_CTL, xs_frame_kind(dst, n));
        got_n = 0;
        got_bytes = 0;
        check("пачка: разобрана", 0, xs_batch_iter(dst, n, collect, NULL));
        check("пачка: кадров вышло столько же", 3, got_n);
        check("пачка: байтов вышло столько же", (long)(sizeof(f1) + sizeof(f2) + sizeof(f3)),
              (long)got_bytes);

        /* Смысл всей затеи числом: три кадра одной записью обязаны стоить меньше, чем те же
         * три поодиночке. Станет наоборот — пачка потеряет смысл, и стенд скажет об этом. */
        long alone = 0;
        for (int i = 0; i < 3; i++) alone += XS_OVERHEAD + (long)fr[i].n;
        size_t segs = (n + XS_TAG + (size_t)XS_MTU_DEF - 1) / (size_t)XS_MTU_DEF;
        long batched = (long)(segs * (XS_IP_HDR + XS_TCP_HDR)) + XS_REC_HDR + XS_TAG + (long)n;
        check("пачка: дешевле одиночных записей", 1, batched < alone);

        check("пачка: один кадр в контейнер не кладётся", 0, (long)xs_batch_build(dst, sizeof(dst), fr, 1));

        /* Битый контейнер отвергается ЦЕЛИКОМ: обработчик не видит НИ ОДНОГО кадра, а не
         * «сколько успели до места порчи». Портится длина ПОСЛЕДНЕГО кадра: на первом префикса
         * не бывает по построению, поэтому порча первой длины одинаково выглядит и при разборе
         * в два прохода, и при разборе с доставкой по мере чтения — она это свойство не
         * проверяет вовсе (I-063). Проверяется здесь именно доставленное, а не только код
         * возврата. */
        static uint8_t bad[XS_MAX_RECORD];
        memcpy(bad, dst, n);
        size_t last_len_at = XS_BATCH_HDR + 2 + sizeof(f1) + 2 + sizeof(f2);
        bad[last_len_at] = 0xFF;
        got_n = 0;
        got_bytes = 0;
        check("пачка: завышенная длина ПОСЛЕДНЕГО кадра отвергнута", -1,
              xs_batch_iter(bad, n, collect, NULL));
        check("пачка: из битого контейнера не доставлено ни кадра", 0, got_n);
        check("пачка: из битого контейнера не доставлено ни байта", 0, (long)got_bytes);

        memcpy(bad, dst, n);
        bad[1] = 0xFF;                          /* та же порча, но на длине ПЕРВОГО кадра */
        got_n = 0;
        check("пачка: завышенная длина первого кадра отвергнута", -1,
              xs_batch_iter(bad, n, collect, NULL));
        check("пачка: и здесь не доставлено ни кадра", 0, got_n);

        got_n = 0;
        check("пачка: обрезок контейнера отвергнут", -1, xs_batch_iter(dst, 2, collect, NULL));
        check("пачка: из обрезка не доставлено ни кадра", 0, got_n);

        /* Предел на число кадров обязан действовать и на ПРИЁМЕ, а не только на сборке:
         * контейнер на 8191 байт из однобайтовых кадров дал бы 2730 вызовов обработчика, тогда
         * как законная пачка не бывает длиннее XS_BATCH_FRAMES_MAX кадров ни в одной из
         * реализаций. */
        struct xs_frame frm[XS_BATCH_FRAMES_MAX + 1];
        static uint8_t one[XS_BATCH_FRAMES_MAX + 1];
        for (size_t i = 0; i < XS_BATCH_FRAMES_MAX + 1; i++) {
            one[i] = (uint8_t)(0x50 + i);
            frm[i].p = &one[i];
            frm[i].n = 1;
        }
        size_t nlim = xs_batch_build(dst, sizeof(dst), frm, XS_BATCH_FRAMES_MAX);
        got_n = 0;
        check("пачка: предельное число кадров принимается", 0, xs_batch_iter(dst, nlim, collect, NULL));
        check("пачка: и доставлено ровно столько", XS_BATCH_FRAMES_MAX, got_n);
        size_t nover = xs_batch_build(dst, sizeof(dst), frm, XS_BATCH_FRAMES_MAX + 1);
        got_n = 0;
        check("пачка: кадров больше предела отвергнуто", -1, xs_batch_iter(dst, nover, collect, NULL));
        check("пачка: из переполненного контейнера не доставлено ни кадра", 0, got_n);

        /* Обратная связь по сборке. */
        uint8_t lf[8];
        check("обратная связь: три байта", 3, (long)xs_loss_build(lf, sizeof(lf), 7));
        check("обратная связь: значение читается обратно", 7, xs_loss_value(lf, 3));
        check("обратная связь: проба за неё не выдаётся", -1, xs_loss_value((const uint8_t *)"\x03\x00\x07", 3));
    }

    /* ---- сборка записи, разрезанной между сегментами ------------------------ */
    {
        static uint8_t rec[XS_REC_HDR + 3000];
        check("сборка: заголовок собран", 0, xs_rec_build(rec, 3000));
        memset(rec + XS_REC_HDR, 0xAB, 3000);
        struct xs_reasm r;
        memset(&r, 0, sizeof(r));

        const uint8_t *body = NULL, *hdr = NULL;
        size_t body_n = 0;
        uint32_t rel = 0;
        uint32_t isn = 1000, seq = isn + 1;
        size_t parts[3] = { 1400, 1400, XS_REC_HDR + 3000 - 2800 };
        size_t off = 0;
        int done = 0;
        for (int i = 0; i < 3; i++) {
            done = xs_reasm_feed(&r, seq, isn, rec + off, parts[i], &body, &body_n, &hdr, &rel);
            if (i < 2) check("сборка: раньше времени не собралась", 0, done);
            off += parts[i];
            seq += (uint32_t)parts[i];
        }
        check("сборка: собралась на последнем сегменте", 1, done);
        check("сборка: длина нагрузки та самая", 3000, (long)body_n);
        check("сборка: байты не испортились", 0, memcmp(body, rec + XS_REC_HDR, 3000));
        /* Смещение — от ПЕРВОГО сегмента: им зашифрована вся запись. Возьми вызывающий его из
         * последнего — тег не сошёлся бы при полностью верной криптографии. */
        check("сборка: смещение от первого сегмента", 1, (long)rel);
        check("сборка: заголовок отдан как AAD", 0, memcmp(hdr, rec, XS_REC_HDR));

        /* Пропавший средний сегмент: запись обязана быть выброшена и посчитана, а не склеена
         * из несмежных байтов. */
        memset(&r, 0, sizeof(r));
        xs_reasm_feed(&r, 1, 0, rec, 1400, &body, &body_n, &hdr, &rel);
        check("сборка: несмежные сегменты не склеиваются", 0,
              xs_reasm_feed(&r, 1400 + 1000, 0, rec + 2800, 205, &body, &body_n, &hdr, &rel));
        check("сборка: выброшенная посчитана", 1, (long)(r.dropped > 0));

        /* Целая запись в одном сегменте по-прежнему разбирается сразу и без копии. */
        memset(&r, 0, sizeof(r));
        static uint8_t one[XS_REC_HDR + XS_TAG + 10];
        xs_rec_build(one, XS_TAG + 10);
        check("сборка: целая запись в одном сегменте", 1,
              xs_reasm_feed(&r, 5, 0, one, sizeof(one), &body, &body_n, &hdr, &rel));
        check("сборка: она отдана без копии", 1, body == one + XS_REC_HDR);
    }

    printf("\n%s\n", fails ? "ЕСТЬ ПРОВАЛЫ" : "все проверки прошли");
    return fails ? 1 : 0;
}
