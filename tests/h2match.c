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
        unsigned char out[64];
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

    printf("\n%s\n", fails ? "ЕСТЬ ПРОВАЛЫ" : "все проверки прошли");

    return fails ? 1 : 0;
}
