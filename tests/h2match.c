/* Управление потоком HTTP/2: проверка того, что окно отправки считается со знаком.
 *
 * Зачем отдельным тестом. Окно сервера (send_win, send_win_conn) — int32_t, и минус для
 * него законен: SETTINGS с INITIAL_WINDOW_SIZE меньше 65535 вычитает разницу из уже
 * выданного окна (RFC 7540 §6.9.2). Проверка в h2_write приводила размер к size_t, и
 * отрицательное окно превращалось в 1,8·10^19 — то есть проверка не срабатывала никогда,
 * кадр уходил за пределы окна, а сервер отвечал RST_STREAM с FLOW_CONTROL_ERROR. Снаружи
 * это выглядело как «grpc/xhttp-узел иногда рвётся», причём h2_write возвращал успех:
 * ошибка приходила позже и из другого места. Именно такие расхождения между «вернул 0» и
 * «на самом деле сломал поток» стенд и должен ловить.
 *
 * Включается ИСХОДНИК h2.c: send_win — поле состояния, которое снаружи не выставить, а
 * ради теста заводить в движке подкоманду означало бы менять движок под тест. Ввод-вывод
 * подменяется целиком через struct h2_io — он для того и абстракция, поэтому ни сети, ни
 * TLS здесь нет. Заголовки mbedtls, которые тянет tls13.h, подменены заглушками из
 * tests/stub: h2.c берёт оттуда одну константу TLS13_MAX_PLAIN и ничего не вызывает. */
#include <stdio.h>
#include <string.h>

#include "../src/ext/h2.c"

static int fails;

static void check(const char *what, int want, int got) {
    printf("%-58s %s\n", what, want == got ? "ok" : "ПРОВАЛ");
    if (want != got) fails++;
}

/* Сеть под нами: запись копится в буфер, чтение отдаёт заранее подготовленные байты.
 * Этого хватает — h2.c не знает, что под ним, кроме двух функций. */
struct fake_io {
    unsigned char sent[65536];
    size_t sent_n;
    const unsigned char *feed;
    size_t feed_n, feed_pos;
};

static int fake_write(void *ctx, const unsigned char *d, size_t n) {
    struct fake_io *io = ctx;
    if (io->sent_n + n > sizeof(io->sent)) return H2_EIO;
    memcpy(io->sent + io->sent_n, d, n);
    io->sent_n += n;
    return 0;
}

static int fake_read(void *ctx, unsigned char *d, size_t cap, size_t *got) {
    struct fake_io *io = ctx;
    size_t left = io->feed_n - io->feed_pos;
    size_t take = left < cap ? left : cap;
    memcpy(d, io->feed + io->feed_pos, take);
    io->feed_pos += take;
    *got = take;
    return 0;
}

static void h2_open(struct h2 *h, struct fake_io *io) {
    memset(io, 0, sizeof(*io));
    struct h2_io ops = { io, fake_write, fake_read };
    h2_start(h, &ops, "example.org", "/x", "application/grpc", NULL);
    io->sent_n = 0;                      /* преамбула и HEADERS дальше не интересны */
}

/* Кадр DATA на поток sid с телом из len байт. Возвращает полную длину кадра. */
static size_t put_data(unsigned char *out, uint32_t sid, size_t len) {
    out[0] = (unsigned char)(len >> 16); out[1] = (unsigned char)(len >> 8);
    out[2] = (unsigned char)len;
    out[3] = FR_DATA; out[4] = 0;
    put32(out + 5, sid);
    memset(out + 9, 'q', len);
    return 9 + len;
}

/* Сумма прибавок во всех WINDOW_UPDATE, ушедших на поток sid. Считается по тому, что
 * реально уехало в сеть: поля состояния скажут, сколько мы НАМЕРЕНЫ вернуть, а сервер
 * видит только кадры. */
static uint32_t wu_sum(const struct fake_io *io, uint32_t sid) {
    uint32_t sum = 0;
    size_t p = 0;
    while (p + 9 <= io->sent_n) {
        uint32_t len = ((uint32_t)io->sent[p] << 16) | ((uint32_t)io->sent[p + 1] << 8) |
                       io->sent[p + 2];
        unsigned char type = io->sent[p + 3];
        uint32_t fsid = get32(io->sent + p + 5) & 0x7FFFFFFF;
        if (type == FR_WINDOW_UPDATE && fsid == sid && len == 4)
            sum += get32(io->sent + p + 9) & 0x7FFFFFFF;
        p += 9 + len;
    }
    return sum;
}

/* Кадр любого типа с данным телом. Возвращает полную длину кадра. */
static size_t put_frame(unsigned char *out, unsigned char type, unsigned char flags,
                        uint32_t sid, const unsigned char *body, size_t len) {
    out[0] = (unsigned char)(len >> 16); out[1] = (unsigned char)(len >> 8);
    out[2] = (unsigned char)len;
    out[3] = type; out[4] = flags;
    put32(out + 5, sid);
    if (len) memcpy(out + 9, body, len);
    return 9 + len;
}

/* Кадр SETTINGS с одной настройкой. */
static size_t settings_frame(unsigned char *out, uint16_t id, uint32_t v) {
    out[0] = 0; out[1] = 0; out[2] = 6;
    out[3] = FR_SETTINGS; out[4] = 0;
    put32(out + 5, 0);
    out[9] = (unsigned char)(id >> 8); out[10] = (unsigned char)id;
    put32(out + 11, v);
    return 15;
}

int main(void) {
    {
        /* Окно, ушедшее в минус: сервер объявил INITIAL_WINDOW_SIZE = 1024, то есть
         * отнял 64511 байт от выданных по умолчанию 65535. */
        struct h2 h;
        struct fake_io io;
        unsigned char feed[64];
        h2_open(&h, &io);
        io.feed = feed;
        io.feed_n = settings_frame(feed, 0x0004, 1024);
        io.feed_pos = 0;

        unsigned char out[H2_MIN_READ_CAP];
        size_t got = 0;
        h2_read(&h, out, sizeof(out), &got);
        check("SETTINGS INITIAL_WINDOW_SIZE=1024: окно потока стало 1024",
              1024, h.send_win);

        h.send_win = -60000;             /* сервер урезал окно ниже уже отправленного */
        unsigned char payload[16384];
        memset(payload, 'x', sizeof(payload));
        io.sent_n = 0;
        check("окно -60000: h2_write отказывает (I-009)",
              H2_EWINDOW, h2_write(&h, payload, sizeof(payload)));
        check("окно -60000: в сеть не ушло ни байта (I-009)", 0, (int)io.sent_n);
    }
    {
        /* Граница: ровно столько, сколько разрешено, проходит; на байт больше — нет. */
        struct h2 h;
        struct fake_io io;
        h2_open(&h, &io);
        h.send_win = 16384;
        h.send_win_conn = 16384;
        unsigned char payload[16384];
        memset(payload, 'x', sizeof(payload));
        check("окно ровно по размеру данных: отправка разрешена",
              0, h2_write(&h, payload, sizeof(payload)));
        check("после отправки окно потока обнулилось", 0, h.send_win);
        check("окно 0 при следующей отправке: отказ",
              H2_EWINDOW, h2_write(&h, payload, 1));
    }
    {
        /* Окно СОЕДИНЕНИЯ проверяется отдельно от окна потока: у них разные счётчики,
         * и раньше оба сравнивались одинаково неверно. */
        struct h2 h;
        struct fake_io io;
        h2_open(&h, &io);
        h.send_win = 65535;
        h.send_win_conn = -1;
        unsigned char payload[16];
        memset(payload, 'x', sizeof(payload));
        check("окно соединения в минусе: отказ, даже если окно потока открыто",
              H2_EWINDOW, h2_write(&h, payload, sizeof(payload)));
    }
    {
        /* Тело DATA доходит до вызывающего целиком — базовая проверка, чтобы правка
         * окна не сломала само чтение (в запуске 26 «фикс» I-009 был вписан именно в
         * h2_read и снёс объявление буфера чтения). */
        struct h2 h;
        struct fake_io io;
        unsigned char feed[64];
        h2_open(&h, &io);
        feed[0] = 0; feed[1] = 0; feed[2] = 4;
        feed[3] = FR_DATA; feed[4] = 0;
        /* Номер потока берётся ИЗ СОСТОЯНИЯ, а не из константы: с появлением packet-up
         * поток перестал быть вечной единицей и растёт на два с каждым запросом. */
        put32(feed + 5, h.sid);
        memcpy(feed + 9, "abcd", 4);
        io.feed = feed;
        io.feed_n = 13;
        io.feed_pos = 0;

        unsigned char out[H2_MIN_READ_CAP];
        size_t got = 0;
        int rc = h2_read(&h, out, sizeof(out), &got);
        check("DATA-кадр: h2_read вернул успех", 0, rc);
        check("DATA-кадр: отдано 4 байта тела", 4, (int)got);
        check("DATA-кадр: тело не искажено", 0, memcmp(out, "abcd", 4));
    }

    {
        /* WINDOW_UPDATE близко к пределу: окно НЕ должно переполниться в минус.
         *
         * Прибавление без проверки — знаковое переполнение (неопределённое поведение), а
         * наблюдаемо это тем, что окно уходит в минус НАВСЕГДА: дальше h2_write вечно
         * отвечает H2_EWINDOW, и отправка по соединению встаёт насмерть. Сервер добивается
         * этого двумя кадрами, каждый из которых сам по себе законен. RFC 7540 §6.9.1
         * велит считать превышение 2^31-1 ошибкой, поэтому ждём разрыв, а не молчание. */
        struct h2 h;
        struct fake_io io;
        unsigned char feed[64];
        h2_open(&h, &io);
        feed[0] = 0; feed[1] = 0; feed[2] = 4;
        feed[3] = FR_WINDOW_UPDATE; feed[4] = 0;
        put32(feed + 5, 1);              /* наш поток */
        put32(feed + 9, 0x7FFFFFFF);
        io.feed = feed; io.feed_n = 13; io.feed_pos = 0;

        unsigned char out[H2_MIN_READ_CAP];
        size_t got = 0;
        int rc = h2_read(&h, out, sizeof(out), &got);
        check("WINDOW_UPDATE за предел 2^31-1: соединение разорвано", H2_ERESET, rc);
        check("и окно не ушло в минус", 1, h.send_win >= 0);
    }
    {
        /* Одинаковые SETTINGS дважды: окно обязано остаться прежним. Сдвиг считался от
         * 65535 всегда, поэтому вторые такие же настройки применяли разницу ещё раз, и
         * окно уезжало на величину, которой сервер не давал (RFC 7540 §6.9.2). */
        struct h2 h;
        struct fake_io io;
        unsigned char feed[64];
        h2_open(&h, &io);
        io.feed = feed; io.feed_n = settings_frame(feed, 0x0004, 1024); io.feed_pos = 0;
        unsigned char out[H2_MIN_READ_CAP];
        size_t got = 0;
        h2_read(&h, out, sizeof(out), &got);
        int after_first = h.send_win;
        io.feed_n = settings_frame(feed, 0x0004, 1024); io.feed_pos = 0;
        h2_read(&h, out, sizeof(out), &got);
        check("те же SETTINGS дважды: окно не сдвинулось повторно", after_first, h.send_win);
    }

    {
        /* ---- череда запросов на одном соединении (packet-up) ---------------------
         *
         * До packet-up поток был вечной единицей, и этого хватало: один запрос на всё
         * соединение. Теперь кусок выгрузки — отдельный запрос, и проверяется ровно то, на
         * чём такая череда ломается: номер обязан расти на два (переиспользовать номер
         * закрытого потока нельзя — сервер ответит ошибкой СОЕДИНЕНИЯ, и связь оборвётся
         * целиком), а кадры, опоздавшие от прежнего потока, обязаны отбрасываться, а не
         * попадать в тело следующего. */
        struct h2 h;
        struct fake_io io;
        h2_open(&h, &io);
        check("первый запрос: поток 1", 1, (int)h.sid);

        io.sent_n = 0;
        check("закрыть свою половину: без ошибки", 0, h2_end_stream(&h));
        /* Пустой DATA с END_STREAM на текущем потоке: 9 байт заголовка и ни байта тела. */
        check("END_STREAM: девять байт заголовка", 9, (int)io.sent_n);
        check("END_STREAM: тип кадра DATA", FR_DATA, io.sent[3]);
        check("END_STREAM: признак стоит", FLAG_END_STREAM, io.sent[4] & FLAG_END_STREAM);
        check("END_STREAM: на своём потоке", 1, (int)io.sent[8]);

        io.sent_n = 0;
        check("следующий запрос: без ошибки",
              0, h2_next(&h, "example.org", "/x/sid/1", "application/grpc", NULL, H2_POST));
        check("следующий запрос: поток стал третьим", 3, (int)h.sid);
        check("следующий запрос: это HEADERS", FR_HEADERS, io.sent[3]);
        check("следующий запрос: номер потока в кадре", 3, (int)io.sent[8]);
        check("следующий запрос: END_STREAM не ставится", 0, io.sent[4] & FLAG_END_STREAM);
        /* Состояние ПОТОКА свежее, состояние СОЕДИНЕНИЯ нетронуто — иначе мы забыли бы,
         * сколько байт нам уже разрешил сервер, и переполнили бы окно соединения. */
        check("следующий запрос: статус сброшен", 0, h.status);
        check("следующий запрос: окно соединения не тронуто", 65535, (int)h.send_win_conn);

        /* Кадр DATA от ЗАКРЫТОГО потока 1 не должен попасть в тело третьего. */
        unsigned char feed[32];
        feed[0] = 0; feed[1] = 0; feed[2] = 4;
        feed[3] = FR_DATA; feed[4] = 0;
        put32(feed + 5, 1);
        memcpy(feed + 9, "zzzz", 4);
        io.feed = feed; io.feed_n = 13; io.feed_pos = 0;
        unsigned char out[H2_MIN_READ_CAP];
        size_t got = 99;
        check("кадр прежнего потока: не ошибка", 0, h2_read(&h, out, sizeof(out), &got));
        check("кадр прежнего потока: в тело не попал", 0, (int)got);
    }

    {
        /* ---- окно ПРИЁМА: соединение считается отдельно от потока ----------------
         *
         * Окно приёма пополняется кадром WINDOW_UPDATE, и уровней у него два: поток и
         * соединение. Байты, полученные по любому потоку, тратят ОБА, поэтому вернуть их
         * серверу надо тоже на оба — иначе окно, которое мы объявили, монотонно сходится к
         * нулю, и сервер перестаёт писать. Снаружи это выглядит как «выгрузка встала на
         * большом файле», причём тем позже, чем больше окно.
         *
         * У packet-up на этом расходятся два случая, и стенд проверяет оба:
         *
         *   1) кадр DATA от УЖЕ ЗАКРЫТОГО потока прежнего куска — в тело он не идёт (это
         *      проверено выше), но окно соединения он уже потратил;
         *   2) переход к следующему куску (h2_next) — состояние ПОТОКА свежее, а долг
         *      перед окном СОЕДИНЕНИЯ переходит вместе с соединением.
         *
         * Проверяется поведение, а не поле: сумма прибавок во всех WINDOW_UPDATE, которые
         * ушли на нулевой поток, обязана сойтись с числом полученных байт DATA. */
        struct h2 h;
        struct fake_io io;
        static unsigned char feed[2 * (9 + 16384)];
        unsigned char out[H2_MIN_READ_CAP];
        size_t got = 0;

        /* --- случай 1: кадр прежнего потока тратит окно соединения --- */
        h2_open(&h, &io);
        /* 16384 байт по текущему потоку: до порога пополнения (32 КБ) не дотягивает, и
         * ни одного WINDOW_UPDATE пока не должно быть. */
        put_data(feed, h.sid, 16384);
        io.feed = feed; io.feed_n = 9 + 16384; io.feed_pos = 0;
        io.sent_n = 0;
        while (io.feed_pos < io.feed_n)
            if (h2_read(&h, out, sizeof(out), &got) != 0) break;
        check("до порога: пополнения окна нет", 0, (int)wu_sum(&io, 0));

        /* Ещё столько же, но от ЗАКРЫТОГО прежнего потока: в тело не идёт, окно тратит. */
        check("следующий кусок: без ошибки",
              0, h2_next(&h, "example.org", "/x/sid/1", "application/grpc", NULL, H2_POST));
        io.sent_n = 0;
        put_data(feed, 1, 16384);
        io.feed = feed; io.feed_n = 9 + 16384; io.feed_pos = 0;
        while (io.feed_pos < io.feed_n)
            if (h2_read(&h, out, sizeof(out), &got) != 0) break;
        check("кадр прежнего потока: окно соединения возвращено целиком",
              32768, (int)wu_sum(&io, 0));
        check("и окну потока чужие байты не приписаны", 0, (int)wu_sum(&io, h.sid));

        /* --- случай 2: h2_next не теряет долг перед окном соединения --- */
        h2_open(&h, &io);
        put_data(feed, h.sid, 16384);
        io.feed = feed; io.feed_n = 9 + 16384; io.feed_pos = 0;
        io.sent_n = 0;
        while (io.feed_pos < io.feed_n)
            if (h2_read(&h, out, sizeof(out), &got) != 0) break;
        h2_next(&h, "example.org", "/x/sid/1", "application/grpc", NULL, H2_POST);
        io.sent_n = 0;
        put_data(feed, h.sid, 16384);
        io.feed = feed; io.feed_n = 9 + 16384; io.feed_pos = 0;
        while (io.feed_pos < io.feed_n)
            if (h2_read(&h, out, sizeof(out), &got) != 0) break;
        check("после h2_next: долг перед окном соединения не потерян",
              32768, (int)wu_sum(&io, 0));
    }

    {
        /* ---- :status значением в кодировке Huffman (I-325) -----------------------
         *
         * Go-сервер (Xray) пишет статус литералом с индексом имени 8 и значением в Huffman,
         * когда так короче: «502» — два байта 0x6C 0x02 вместо трёх цифр. Такой статус
         * обязан читаться как 502, то есть кончаться H2_ESTATUS с кодом, а не молчанием. */
        static const unsigned char st502[] = { 0x48, 0x82, 0x6C, 0x02 };
        static const unsigned char st200[] = { 0x48, 0x82, 0x10, 0x01 };
        struct h2 h;
        struct fake_io io;
        unsigned char feed[64];
        unsigned char out[H2_MIN_READ_CAP];
        size_t got = 0;

        h2_open(&h, &io);
        g_last_status = 0;
        io.feed = feed; io.feed_pos = 0;
        io.feed_n = put_frame(feed, FR_HEADERS, FLAG_END_HEADERS, h.sid, st502, sizeof st502);
        check(":status 502 в Huffman: H2_ESTATUS", H2_ESTATUS, h2_read(&h, out, sizeof(out), &got));
        check(":status 502 в Huffman: код назван", 502, g_last_status);

        h2_open(&h, &io);
        io.feed = feed; io.feed_pos = 0;
        io.feed_n = put_frame(feed, FR_HEADERS, FLAG_END_HEADERS, h.sid, st200, sizeof st200);
        check(":status 200 в Huffman: не ошибка", 0, h2_read(&h, out, sizeof(out), &got));
        check(":status 200 в Huffman: статус 200", 200, h.status);
    }

    {
        /* ---- RST_STREAM закрытого потока не рвёт текущий (I-325) -------------------
         *
         * Go-сервер отвечает RST_STREAM(NO_ERROR) на поток, чей обработчик уже закончил, и у
         * packet-up такой кадр приходит по ПРЕЖНЕМУ куску, когда открыт следующий. Это конец
         * чужого потока, а не нашего: соединение обязано жить. RST по ТЕКУЩЕМУ потоку —
         * по-прежнему разрыв. */
        static const unsigned char no_error[4] = { 0, 0, 0, 0 };
        struct h2 h;
        struct fake_io io;
        unsigned char feed[64];
        unsigned char out[H2_MIN_READ_CAP];
        size_t got = 0;

        h2_open(&h, &io);
        h2_end_stream(&h);
        h2_next(&h, "example.org", "/x/sid/1", "application/grpc", NULL, H2_POST);
        io.feed = feed; io.feed_pos = 0;
        io.feed_n = put_frame(feed, FR_RST_STREAM, 0, 1, no_error, 4);
        check("RST_STREAM прежнего потока: не ошибка", 0, h2_read(&h, out, sizeof(out), &got));
        io.feed_pos = 0;
        io.feed_n = put_frame(feed, FR_RST_STREAM, 0, h.sid, no_error, 4);
        check("RST_STREAM текущего потока: разрыв", H2_ERESET, h2_read(&h, out, sizeof(out), &got));
    }

    {
        /* ---- следующий запрос влезает туда же, куда первый (I-325) -----------------
         *
         * Кусок packet-up идёт обликом браузера с Referer до 1399 байт (предел xhttp_referer_r
         * в client.c) — так же, как первый запрос. Первый собирается в буфер на 4 КБ,
         * следующие собирались в 2 КБ: при длинном пути узла (здесь 240 байт) первый кусок
         * уходил, а второй с теми же заголовками получал H2_ETOOBIG. */
        static char ref[1400], path[241];
        memset(ref, 'X', 1399); ref[1399] = '\0';
        path[0] = '/'; memset(path + 1, 'p', 239); path[240] = '\0';
        struct h2 h;
        struct fake_io io;
        memset(&io, 0, sizeof io);
        struct h2_io ops = { &io, fake_write, fake_read };
        check("первый запрос: путь 240, Referer 1399 — без ошибки",
              0, h2_start_ex(&h, &ops, "example.org", path, "application/grpc", ref,
                             H2_POST, 0, 1));
        h2_end_stream(&h);
        check("следующий запрос с теми же заголовками: без ошибки",
              0, h2_next(&h, "example.org", path, "application/grpc", ref, H2_POST));
    }

    {
        /* ---- PADDED и PRIORITY (I-325) -------------------------------------------
         *
         * DATA и HEADERS вправе нести набивку (PADDED: байт длины впереди, набивка в конце),
         * HEADERS — ещё и пять байт приоритета (PRIORITY). Ни то ни другое не данные: байт
         * длины и набивка не должны попасть в тело, а статус лежит после приоритета. Окну
         * при этом зачитывается ВЕСЬ кадр, с набивкой (RFC 7540 §6.9.1), иначе объявленное
         * серверу окно разойдётся с тем, что считает он. */
        struct h2 h;
        struct fake_io io;
        unsigned char feed[128];
        unsigned char out[H2_MIN_READ_CAP];
        size_t got = 0;

        /* HEADERS: набивка 2, приоритет, :status 404 индексом, две нулевые набивки. */
        static const unsigned char hdrs[] = { 2, 0, 0, 0, 0, 16, 0x8D, 0, 0 };
        h2_open(&h, &io);
        g_last_status = 0;
        io.feed = feed; io.feed_pos = 0;
        io.feed_n = put_frame(feed, FR_HEADERS, FLAG_END_HEADERS | 0x08 | 0x20, h.sid,
                              hdrs, sizeof hdrs);
        check("HEADERS с PADDED и PRIORITY: статус 404 прочитан",
              H2_ESTATUS, h2_read(&h, out, sizeof(out), &got));
        check("HEADERS с PADDED и PRIORITY: код назван", 404, g_last_status);

        /* HEADERS только с PRIORITY: :status 200. */
        static const unsigned char hdrs_pri[] = { 0, 0, 0, 0, 16, 0x88 };
        h2_open(&h, &io);
        io.feed = feed; io.feed_pos = 0;
        io.feed_n = put_frame(feed, FR_HEADERS, FLAG_END_HEADERS | 0x20, h.sid,
                              hdrs_pri, sizeof hdrs_pri);
        check("HEADERS с PRIORITY: не ошибка", 0, h2_read(&h, out, sizeof(out), &got));
        check("HEADERS с PRIORITY: статус 200", 200, h.status);

        /* DATA: набивка 3, тело «abcd». */
        static const unsigned char data[] = { 3, 'a', 'b', 'c', 'd', 0, 0, 0 };
        h2_open(&h, &io);
        io.feed = feed; io.feed_pos = 0;
        io.feed_n = put_frame(feed, FR_DATA, 0x08, h.sid, data, sizeof data);
        int rc = h2_read(&h, out, sizeof(out), &got);
        check("DATA с PADDED: без ошибки", 0, rc);
        check("DATA с PADDED: отдано 4 байта тела", 4, (int)got);
        check("DATA с PADDED: тело не искажено", 0, got == 4 ? memcmp(out, "abcd", 4) : 1);
        check("DATA с PADDED: окну соединения зачтён весь кадр", 8, h.recv_credit_conn);
        check("DATA с PADDED: окну потока зачтён весь кадр", 8, h.recv_credit);

        /* Тот же кадр, разорванный границами записей: заголовок и байт длины, потом два
         * байта тела, потом остаток тела с набивкой. */
        static const unsigned char data2[] = { 3, 'a', 'b', 'c', 'd', 0, 0, 0 };
        h2_open(&h, &io);
        size_t fn = put_frame(feed, FR_DATA, 0x08, h.sid, data2, sizeof data2);
        size_t cuts[] = { 10, 12, fn };
        size_t from = 0, total = 0;
        unsigned char body[16];
        for (int i = 0; i < 3; i++) {
            io.feed = feed + from; io.feed_n = cuts[i] - from; io.feed_pos = 0;
            if (h2_read(&h, out, sizeof(out), &got) != 0) { total = 99; break; }
            if (total + got <= sizeof body) memcpy(body + total, out, got);
            total += got;
            from = cuts[i];
        }
        check("DATA с PADDED по трём записям: отдано 4 байта", 4, (int)total);
        check("DATA с PADDED по трём записям: тело не искажено",
              0, total == 4 ? memcmp(body, "abcd", 4) : 1);

        /* Граница записи ВНУТРИ набивки: набивка 5, тело «abcd», первая запись кончается
         * через два байта набивки. Остаток набивки во второй записи — не данные. */
        static const unsigned char data3[] = { 5, 'a', 'b', 'c', 'd', 0, 0, 0, 0, 0 };
        h2_open(&h, &io);
        fn = put_frame(feed, FR_DATA, 0x08, h.sid, data3, sizeof data3);
        size_t cut = 9 + 1 + 4 + 2;
        total = 0;
        rc = 0;
        io.feed = feed; io.feed_n = cut; io.feed_pos = 0;
        rc = h2_read(&h, out, sizeof(out), &got);
        if (rc == 0 && got <= sizeof body) { memcpy(body, out, got); total = got; }
        io.feed = feed + cut; io.feed_n = fn - cut; io.feed_pos = 0;
        if (rc == 0) rc = h2_read(&h, out, sizeof(out), &got);
        if (rc == 0) total += got;
        check("DATA: граница внутри набивки — без ошибки", 0, rc);
        check("DATA: граница внутри набивки — отдано 4 байта", 4, (int)total);
        check("DATA: граница внутри набивки — тело не искажено",
              0, total == 4 ? memcmp(body, "abcd", 4) : 1);
        check("DATA: граница внутри набивки — окну зачтён весь кадр",
              (int)sizeof data3, h.recv_credit_conn);

        /* Набивка длиннее кадра — ошибка протокола (RFC 7540 §6.1), а не чтение за край. */
        static const unsigned char bad[] = { 9, 'a', 'b' };
        h2_open(&h, &io);
        io.feed = feed; io.feed_pos = 0;
        io.feed_n = put_frame(feed, FR_DATA, 0x08, h.sid, bad, sizeof bad);
        check("DATA с набивкой длиннее кадра: H2_EPROTO",
              H2_EPROTO, h2_read(&h, out, sizeof(out), &got));
    }

    {
        /* ---- H2_ETOOBIG не теряет хвост записи (I-325) ----------------------------
         *
         * Буфер меньше H2_MIN_READ_CAP — нарушение договора вызывающим, но последствия
         * обязаны быть честными: отказ, после которого соединение можно читать дальше.
         * Прежде отказ случался посреди кадра — прочитанная запись выбрасывалась вместе с
         * хвостом, а счётчик тела оставался, и следующий кадр читался как продолжение
         * прежнего: в тело шёл его заголовок. */
        struct h2 h;
        struct fake_io io;
        static unsigned char feed[256];
        unsigned char small[64];
        unsigned char out[H2_MIN_READ_CAP];
        size_t got = 0;

        h2_open(&h, &io);
        size_t n1 = put_data(feed, h.sid, 100);
        io.feed = feed; io.feed_n = n1; io.feed_pos = 0;
        check("буфер меньше договора: H2_ETOOBIG",
              H2_ETOOBIG, h2_read(&h, small, sizeof(small), &got));
        /* Дальше — чтение по договору: кадр «abcd» обязан прийти как есть. */
        size_t n2 = put_frame(feed + n1, FR_DATA, 0, h.sid, (const unsigned char *)"abcd", 4);
        io.feed_n = n1 + n2;
        size_t total = 0;
        int rc = 0;
        unsigned char last[4] = { 0 };
        while (io.feed_pos < io.feed_n && rc == 0) {
            rc = h2_read(&h, out, sizeof(out), &got);
            total += got;
            if (got >= 4) memcpy(last, out + got - 4, 4);
        }
        check("после отказа: следующее чтение без ошибки", 0, rc);
        check("после отказа: оба кадра дошли целиком", 104, (int)total);
        check("после отказа: тело второго кадра не искажено", 0, memcmp(last, "abcd", 4));
    }

    printf("\n%s\n", fails ? "ЕСТЬ ПРОВАЛЫ" : "все проверки прошли");

    return fails ? 1 : 0;
}
