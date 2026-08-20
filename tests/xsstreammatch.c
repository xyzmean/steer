/* Рамка записей по НАСТОЯЩЕМУ потоку TCP: границы, смещения, досылка хвоста.
 *
 * ЗАЧЕМ ОТДЕЛЬНЫМ СТЕНДОМ. Всё, что здесь проверяется, ломается молча и одинаково: «туннель
 * поднялся и не несёт трафик». Смещение — это nonce (xsstream.h), поэтому расхождение на ОДИН
 * байт означает, что ни одна запись больше не расшифруется; запись, разобранная не с той
 * границы, даёт то же самое; недосланный хвост записи разъезжает поток навсегда, а не теряет
 * один пакет, как в поддельном TCP. Ни одно из этих событий не видно из журнала — видно
 * только следствие.
 *
 * Обстановка — socketpair, а не сеть: буфер, границы и частичная запись воспроизводятся на
 * нём точно и повторяемо, а сеть добавила бы к проверке свою погоду. Ни прав root, ни
 * mbedtls: xsstream.c криптографии не касается вовсе (её зовёт вызывающий), поэтому стенд
 * подключает исходник напрямую и входит в обычный make test — как xswirematch.
 */
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

#include "../src/ext/xsstream.c"

static int fails;

static void check(const char *what, long want, long got) {
    printf("%-62s %s\n", what, want == got ? "ok" : "ПРОВАЛ");
    if (want != got) {
        printf("     хочу: %ld\n     есть:  %ld\n", want, got);
        fails++;
    }
}

static void ok(const char *what, int good) {
    printf("%-62s %s\n", what, good ? "ok" : "ПРОВАЛ");
    if (!good) fails++;
}

/* Пара сокетов: a — наша сторона, b — «та». Оба неблокирующие, как требует xsstream.h. */
static void pair_up(int fd[2], int sndbuf) {
    if (socketpair(AF_UNIX, SOCK_STREAM, 0, fd) != 0) { perror("socketpair"); exit(2); }
    for (int i = 0; i < 2; i++) {
        int fl = fcntl(fd[i], F_GETFL, 0);
        fcntl(fd[i], F_SETFL, fl | O_NONBLOCK);
    }
    /* Маленький буфер отправки нужен ровно одной проверке — частичной записи. Ядро удваивает
     * запрошенное и держит свой минимум, поэтому число здесь не точное, а «заведомо меньше
     * записи»; сама проверка смотрит на признак busy, а не на конкретный остаток. */
    if (sndbuf) setsockopt(fd[0], SOL_SOCKET, SO_SNDBUF, &sndbuf, sizeof(sndbuf));
}

/* Собрать запись с нагрузкой из n байт: заголовок настоящий, «шифротекст» — узнаваемая
 * набивка. Криптографии здесь нет намеренно: рамка обязана быть верной независимо от того,
 * что лежит внутри. */
static size_t rec_make(uint8_t *dst, size_t body_n, uint8_t fill) {
    dst[0] = XS_REC_TYPE; dst[1] = XS_REC_V0; dst[2] = XS_REC_V1;
    dst[3] = (uint8_t)(body_n >> 8);
    dst[4] = (uint8_t)(body_n & 0xFF);
    memset(dst + XS_REC_HDR, fill, body_n);
    return XS_REC_HDR + body_n;
}

int main(void) {
    int fd[2];
    struct xs_stream st;
    uint8_t buf[XS_STREAM_REC_MAX * 2];

    /* ---- смещения начинаются с единицы ------------------------------------------
     * Нулевое занято подтверждением рукопожатия, и это инвариант обеих реализаций: ноль,
     * потраченный дважды, означал бы повтор nonce с одним ключом. */
    pair_up(fd, 0);
    xs_stream_init(&st, fd[0]);
    check("смещение отправки начинается с единицы", 1, (long)xs_stream_tx_next(&st));
    check("смещение приёма начинается с единицы", 1, (long)st.rx_off);

    /* ---- одна запись целиком ---------------------------------------------------- */
    size_t n = rec_make(buf, 64, 0xA1);
    ok("запись отдана в сокет", write(fd[1], buf, n) == (ssize_t)n);
    const uint8_t *hdr, *body;
    size_t bn;
    uint64_t rel;
    check("запись прочитана", 1, xs_stream_recv(&st, &hdr, &body, &bn, &rel));
    check("длина нагрузки", 64, (long)bn);
    check("смещение записи — её первый байт", 1, (long)rel);
    ok("нагрузка та самая", body[0] == 0xA1 && body[63] == 0xA1);
    check("смещение приёма подвинулось на всю запись", 1 + 69, (long)st.rx_off);
    check("больше записей нет", 0, xs_stream_recv(&st, &hdr, &body, &bn, &rel));

    /* ---- ДВЕ записи в одном чтении ----------------------------------------------
     * Это и есть смысл буфера: одно чтение ядра наполняет его целиком, и следующие записи
     * разбираются из памяти без единого лишнего вызова. */
    size_t n1 = rec_make(buf, 32, 0xB2);
    size_t n2 = rec_make(buf + n1, 48, 0xC3);
    ok("две записи отданы одним куском", write(fd[1], buf, n1 + n2) == (ssize_t)(n1 + n2));
    check("первая разобрана", 1, xs_stream_recv(&st, &hdr, &body, &bn, &rel));
    check("длина первой", 32, (long)bn);
    uint64_t rel1 = rel;
    check("вторая разобрана без нового чтения", 1, xs_stream_recv(&st, &hdr, &body, &bn, &rel));
    check("длина второй", 48, (long)bn);
    check("смещение второй — сразу за первой", (long)(rel1 + XS_REC_HDR + 32), (long)rel);
    ok("нагрузка второй та самая", body[0] == 0xC3);

    /* ---- запись, приехавшая ПО ЧАСТЯМ -------------------------------------------
     * В потоке это обычное дело: ядро режет его на сегменты где ему удобно. Пока записи нет
     * целиком, разбирать нельзя — иначе тег считался бы по обрезанной нагрузке. */
    n = rec_make(buf, 300, 0xD4);
    uint64_t before = st.rx_off;
    ok("отдан только заголовок", write(fd[1], buf, XS_REC_HDR) == XS_REC_HDR);
    check("неполная запись не отдаётся", 0, xs_stream_recv(&st, &hdr, &body, &bn, &rel));
    ok("отдана половина нагрузки", write(fd[1], buf + XS_REC_HDR, 150) == 150);
    check("половины нагрузки тоже мало", 0, xs_stream_recv(&st, &hdr, &body, &bn, &rel));
    check("смещение приёма не двинулось ни на байт", (long)before, (long)st.rx_off);
    ok("отдан остаток", write(fd[1], buf + XS_REC_HDR + 150, n - XS_REC_HDR - 150) ==
                       (ssize_t)(n - XS_REC_HDR - 150));
    check("собранная запись отдана", 1, xs_stream_recv(&st, &hdr, &body, &bn, &rel));
    check("длина собранной", 300, (long)bn);
    check("смещение собранной — первый её байт", (long)before, (long)rel);
    ok("нагрузка собранной цела", body[0] == 0xD4 && body[299] == 0xD4);

    /* ---- не наша запись ---------------------------------------------------------
     * Соединение после этого продолжать нельзя, и код отличается от обрыва: границы следующей
     * записи известны только из длины, которой мы уже не верим. */
    n = rec_make(buf, 64, 0x11);
    buf[0] = 0x16;                       /* handshake вместо application_data */
    (void)!write(fd[1], buf, n);
    check("чужой тип записи — отказ, а не обрыв", -2,
          xs_stream_recv(&st, &hdr, &body, &bn, &rel));

    /* Длина меньше тега: нагрузки нет даже под пустую запись. */
    pair_up(fd, 0);
    xs_stream_init(&st, fd[0]);
    n = rec_make(buf, XS_TAG - 1, 0x22);
    (void)!write(fd[1], buf, n);
    check("длина меньше тега — отказ", -2, xs_stream_recv(&st, &hdr, &body, &bn, &rel));

    /* Длина больше предела: столько не пишет в одну запись ни настоящий xhttp, ни мы сами. */
    pair_up(fd, 0);
    xs_stream_init(&st, fd[0]);
    buf[0] = XS_REC_TYPE; buf[1] = XS_REC_V0; buf[2] = XS_REC_V1;
    buf[3] = 0xFF; buf[4] = 0xFF;        /* 65535 — заведомо больше XS_MAX_RECORD + XS_TAG */
    (void)!write(fd[1], buf, XS_REC_HDR);
    check("длина больше предела — отказ", -2, xs_stream_recv(&st, &hdr, &body, &bn, &rel));

    /* ---- пустая запись: это keepalive ------------------------------------------- */
    pair_up(fd, 0);
    xs_stream_init(&st, fd[0]);
    n = rec_make(buf, XS_TAG, 0x33);
    (void)!write(fd[1], buf, n);
    check("пустая запись (только тег) принимается", 1,
          xs_stream_recv(&st, &hdr, &body, &bn, &rel));
    check("её длина — ровно тег", XS_TAG, (long)bn);

    /* ---- сырые байты рукопожатия двигают смещение ------------------------------- */
    pair_up(fd, 0);
    xs_stream_init(&st, fd[0]);
    memset(buf, 0x44, 100);
    check("сырая отправка прошла", 0, xs_stream_write_raw(&st, buf, 100));
    check("смещение отправки выросло на длину рукопожатия", 101,
          (long)xs_stream_tx_next(&st));

    /* ---- отправка записи: смещение и байты на проводе --------------------------- */
    pair_up(fd, 0);
    xs_stream_init(&st, fd[0]);
    n = rec_make(buf, 64, 0x55);
    check("запись отправлена", 0, xs_stream_send(&st, buf, n));
    check("смещение отправки выросло на всю запись", 1 + 69, (long)xs_stream_tx_next(&st));
    ok("хвоста не осталось", !xs_stream_busy(&st));
    uint8_t got[256];
    check("та сторона получила ровно эти байты", (long)n, (long)read(fd[1], got, sizeof(got)));
    ok("байты совпали", memcmp(got, buf, n) == 0);

    /* ---- ЧАСТИЧНАЯ ЗАПИСЬ: хвост копится и досылается ---------------------------
     * Самое важное здесь — что смещение двигается на ВСЮ запись сразу. Считать по фактически
     * отправленным байтам значило бы, что смещение зависит от размера очереди сокета, и
     * стороны разъехались бы на первом же переполнении под нагрузкой. */
    pair_up(fd, 2048);
    xs_stream_init(&st, fd[0]);
    size_t big = rec_make(buf, XS_MAX_RECORD, 0x66);
    int filled = 0;
    for (int i = 0; i < 64 && !xs_stream_busy(&st); i++) {
        if (xs_stream_send(&st, buf, big) != 0) break;
        filled++;
    }
    ok("очередь сокета переполнилась и хвост остался", xs_stream_busy(&st));
    check("следующая запись отвергнута, а не порвала поток", -2,
          xs_stream_send(&st, buf, big));
    uint64_t off_after = xs_stream_tx_next(&st);
    check("смещение учло все принятые записи целиком",
          (long)(1 + (uint64_t)filled * big), (long)off_after);
    /* Опустошаем ту сторону и досылаем хвост. */
    size_t drained = 0;
    for (;;) {
        ssize_t r = read(fd[1], got, sizeof(got));
        if (r <= 0) {
            if (xs_stream_flush(&st) == 1) break;
            if (drained > (size_t)filled * big + big) { ok("хвост не досылается", 0); break; }
            continue;
        }
        drained += (size_t)r;
    }
    ok("хвост дослан, поток снова свободен", !xs_stream_busy(&st));
    check("смещение от досылки не изменилось", (long)off_after, (long)xs_stream_tx_next(&st));

    /* ---- много записей подряд: буфер сдвигается и ничего не теряет --------------
     * Сдвиг остатка к началу буфера случается раз на 64 КБ потока, и ошибка в нём проявилась
     * бы не сразу, а «иногда под нагрузкой» — то есть худшим образом. Поэтому через стенд
     * прогоняется больше буфера, и каждая запись сверяется по смещению и по нагрузке. */
    pair_up(fd, 0);
    xs_stream_init(&st, fd[0]);
    uint64_t want_off = 1;
    int seen = 0, bad = 0;
    for (int round = 0; round < 60; round++) {
        /* Пишем пачкой по 4 записи разного размера, читаем всё, что успело приехать. */
        size_t tot = 0;
        for (int k = 0; k < 4; k++) {
            size_t bodyn = (size_t)(500 + 300 * k);
            tot += rec_make(buf + tot, bodyn, (uint8_t)(0x70 + k));
        }
        size_t put = 0;
        while (put < tot) {
            ssize_t w = write(fd[1], buf + put, tot - put);
            if (w > 0) { put += (size_t)w; continue; }
            /* Та сторона переполнилась — вычитываем и продолжаем. */
            while (xs_stream_recv(&st, &hdr, &body, &bn, &rel) == 1) {
                if (rel != want_off || body[0] != (uint8_t)(0x70 + seen % 4)) bad++;
                want_off = rel + XS_REC_HDR + bn;
                seen++;
            }
        }
        while (xs_stream_recv(&st, &hdr, &body, &bn, &rel) == 1) {
            if (rel != want_off || body[0] != (uint8_t)(0x70 + seen % 4)) bad++;
            want_off = rel + XS_REC_HDR + bn;
            seen++;
        }
    }
    check("прогнано записей", 240, seen);
    check("ни одна не разобрана не с той границы", 0, bad);
    ok("суммарный поток больше буфера чтения",
       want_off - 1 > (uint64_t)XS_STREAM_RBUF);

    /* ---- обрыв ------------------------------------------------------------------ */
    pair_up(fd, 0);
    xs_stream_init(&st, fd[0]);
    close(fd[1]);
    check("закрытая сторона — обрыв, а не «пока нет данных»", -1,
          xs_stream_recv(&st, &hdr, &body, &bn, &rel));
    check("после обрыва отправка тоже отказывает", -1, xs_stream_send(&st, buf, 21));

    printf(fails ? "\nПРОВАЛОВ: %d\n" : "\nвсе проверки прошли\n", fails);
    return fails ? 1 : 0;
}
