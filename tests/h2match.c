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
        put32(feed + 5, STREAM_ID);
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

    printf("\n%s\n", fails ? "ЕСТЬ ПРОВАЛЫ" : "все проверки прошли");
    return fails ? 1 : 0;
}
