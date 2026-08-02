/* XTLS-Vision: обёртка потока VLESS в кадры с набивкой.
 *
 * Зачем это существует. Обычный VLESS внутри TLS даёт узнаваемую картину: сразу за
 * рукопожатием идёт запись ровно в размер заголовка VLESS, потом сразу данные. Наблюдатель
 * видит характерную последовательность длин записей, по которой соединение отличимо от
 * настоящего HTTPS даже без расшифровки. Vision это ломает: каждый кадр несёт случайную
 * набивку, поэтому длины записей перестают быть предсказуемыми.
 *
 * Формат кадра (из XtlsPadding в proxy/proxy.go Xray):
 *
 *   [UUID 16 байт]  — ТОЛЬКО в самом первом кадре, дальше не повторяется
 *   команда   1 байт  0=continue, 1=end, 2=direct
 *   длина     2 байта  сколько полезных данных
 *   набивка   2 байта  сколько случайных байт после данных
 *   данные    N
 *   набивка   M случайных байт
 *
 * Команда `end` говорит серверу, что набивка на этом закончилась и дальше идёт чистый
 * поток. `direct` — переход в режим прямого копирования (мы его не используем: он ускоряет
 * ценой того, что длины записей снова становятся честными).
 *
 * Мы всегда шлём `end` на первом же кадре с данными: набивка нужна, чтобы скрыть ЗАГОЛОВОК
 * VLESS, а дальше поток и так неотличим — внутри TLS видны только зашифрованные записи.
 */
#define _GNU_SOURCE
#include <string.h>
#include <sys/random.h>
#include <errno.h>

#include "vision.h"

/* Границы длины набивки — те же, что в Xray (там они зовутся testseed). Взяты числами, а
 * не выведены: они подобраны так, чтобы распределение длин записей походило на HTTPS, и
 * менять их «на свой вкус» значит ослаблять маскировку, ради которой всё это и написано. */
#define PAD_SHORT_THRESHOLD 900
#define PAD_LONG_RANGE      500
#define PAD_LONG_BASE       900
#define PAD_SHORT_RANGE     256

static int rnd_bytes(unsigned char *b, size_t n) {
    size_t got = 0;
    while (got < n) {
        ssize_t r = getrandom(b + got, n - got, 0);
        if (r < 0) { if (errno == EINTR) continue; return -1; }
        got += (size_t)r;
    }
    return 0;
}

static unsigned rnd_below(unsigned limit) {
    if (limit == 0) return 0;
    unsigned char b[2];
    if (rnd_bytes(b, 2) != 0) return limit / 2;
    return (((unsigned)b[0] << 8) | b[1]) % limit;
}

void vision_init(struct vision *v, const unsigned char uuid[16]) {
    memset(v, 0, sizeof(*v));
    memcpy(v->uuid, uuid, 16);
    v->need_uuid = 1;
}

/* Обернуть данные в кадр. Возвращает длину кадра или 0, если не влез в буфер.
 *
 * После кадра с командой end обёртки больше НЕ БЫВАЕТ: сервер, получив end, перестаёт
 * ждать заголовки и читает поток как есть. Продолжать оборачивать — значит вписывать пять
 * байт заголовка внутрь данных, и сервер отдаст их дальше как часть запроса. На одном
 * коротком запросе это незаметно, потому что кадр всего один; ломается всё, что длиннее
 * одной посылки, и выглядит как «выгрузка портится». */
size_t vision_wrap(struct vision *v, const unsigned char *data, size_t n,
                   unsigned char *out, size_t cap) {
    if (v->sent_end) {
        if (n > cap) return 0;
        memcpy(out, data, n);
        return n;
    }
    /* Длинная набивка — пока прячем заголовок VLESS, то есть на первых кадрах и на
     * коротких данных. Дальше короткая: длинная на каждом кадре съедала бы полосу. */
    unsigned pad;
    if (n < PAD_SHORT_THRESHOLD && v->need_uuid) {
        unsigned r = rnd_below(PAD_LONG_RANGE);
        pad = r + PAD_LONG_BASE > n ? (unsigned)(r + PAD_LONG_BASE - n) : 0;
    } else {
        pad = rnd_below(PAD_SHORT_RANGE);
    }

    size_t head = (v->need_uuid ? 16u : 0u) + 5u;
    if (head + n + pad > cap) {
        /* Урезаем набивку, а не данные: потерянные данные это потеря потока, а меньшая
         * набивка — только чуть более узнаваемая длина записи. */
        if (head + n > cap) return 0;
        pad = (unsigned)(cap - head - n);
    }

    size_t i = 0;
    if (v->need_uuid) {
        memcpy(out, v->uuid, 16);
        i = 16;
        v->need_uuid = 0;
    }
    /* Команда end сразу: набивка скрыла заголовок, дальше она не нужна. */
    out[i++] = VISION_CMD_END;
    out[i++] = (unsigned char)(n >> 8);
    out[i++] = (unsigned char)n;
    out[i++] = (unsigned char)(pad >> 8);
    out[i++] = (unsigned char)pad;
    if (n) { memcpy(out + i, data, n); i += n; }
    if (pad) {
        if (rnd_bytes(out + i, pad) != 0) return 0;
        i += pad;
    }
    v->sent_frames++;
    v->sent_end = 1;
    return i;
}

/* Развернуть кадр из входящего потока.
 *
 * Сервер отвечает такими же кадрами, пока не пришлёт `end`; после него поток чистый.
 * Состояние держится в структуре, потому что кадр может прийти не целиком за одно чтение —
 * TLS-запись и кадр Vision это разные границы, и совпадать они не обязаны. */
int vision_unwrap(struct vision *v, const unsigned char *in, size_t n,
                  size_t *consumed, const unsigned char **payload, size_t *payload_n) {
    *consumed = 0;
    *payload = NULL;
    *payload_n = 0;
    if (!n) return 0;

    /* После end сервер шлёт данные без обёртки — отдаём как есть. */
    if (v->recv_done) {
        *consumed = n;
        *payload = in;
        *payload_n = n;
        return 0;
    }

    /* Первый кадр ОТ СЕРВЕРА тоже начинается с UUID — точно так же, как наш к нему.
     * Симметрия протокола: UUID здесь служит признаком начала обёрнутого потока, и
     * сервер им пользуется в обе стороны.
     *
     * Первая версия ждала сразу команду и получала первый байт UUID (0x96) как её
     * значение: команда выходила недопустимой, unwrap возвращал EPROTO, и ответ
     * терялся целиком. Проявлялось как «сервер не отвечает», хотя данные приходили. */
    if (!v->recv_uuid_seen) {
        if (n < 16 + 5) return VISION_EAGAIN;
        if (memcmp(in, v->uuid, 16) != 0) {
            /* UUID не наш — значит обёртки нет вовсе, поток идёт открытым. Это законно:
             * сервер оборачивает не всегда. */
            v->recv_done = 1;
            *consumed = n;
            *payload = in;
            *payload_n = n;
            return 0;
        }
        in += 16;
        n -= 16;
        v->recv_uuid_seen = 1;
        *consumed = 16;
    }

    /* Дальше — потоком. Кадр не обязан приехать целиком: его длина описывает данные,
     * которых может быть больше, чем несёт одна запись TLS, и это обычное дело на любой
     * передаче крупнее ответа в пару килобайт.
     *
     * Прежняя версия требовала кадр целиком и при нехватке ВЫБРАСЫВАЛА остаток. Хуже
     * того, выбрасывала не только его: потеряв начало, разбор терял и синхронизацию, и
     * дальше каждый кусок выглядел испорченным. Симптом — «скачивание отдаёт ноль байт»,
     * причём короткие ответы при этом работали, потому что укладывались в одну запись. */
    size_t i = 0;

    /* Остаток данных текущего кадра. */
    if (v->rx_data_left) {
        size_t take = v->rx_data_left < n - i ? v->rx_data_left : n - i;
        *payload = in + i;
        *payload_n = take;
        v->rx_data_left -= (uint32_t)take;
        i += take;
        *consumed += i;
        if (!v->rx_data_left && !v->rx_pad_left && v->rx_end_after) v->recv_done = 1;
        return 0;
    }

    /* Остаток набивки: молча проглатывается, полезного в ней нет. */
    if (v->rx_pad_left) {
        size_t take = v->rx_pad_left < n - i ? v->rx_pad_left : n - i;
        v->rx_pad_left -= (uint32_t)take;
        i += take;
        *consumed += i;
        if (!v->rx_pad_left && v->rx_end_after) v->recv_done = 1;
        return 0;
    }

    /* Заголовок следующего кадра — тоже по байтам: он может разорваться границей записи. */
    while (v->rx_hdr_n < 5 && i < n) v->rx_hdr[v->rx_hdr_n++] = in[i++];
    *consumed += i;
    if (v->rx_hdr_n < 5) return 0;              /* дочитаем в следующий раз */

    unsigned char cmd = v->rx_hdr[0];
    if (cmd > VISION_CMD_DIRECT) return VISION_EPROTO;
    v->rx_data_left = ((uint32_t)v->rx_hdr[1] << 8) | v->rx_hdr[2];
    v->rx_pad_left = ((uint32_t)v->rx_hdr[3] << 8) | v->rx_hdr[4];
    v->rx_end_after = (cmd == VISION_CMD_END || cmd == VISION_CMD_DIRECT);
    /* direct — не «end с другим номером». Сервер сообщает, что дальше пишет в сокет поток
     * целевого соединения БЕЗ своего TLS, и читать его надо в обход расшифровки. Считать
     * это концом набивки и продолжать разбирать записи — значит принимать чужие записи за
     * свои: длины выходят бессмысленные, AEAD не сходится, и соединение умирает посреди
     * передачи. Именно так и ломался любой https через узел с Vision, причём место обрыва
     * каждый раз было другим — оно зависит от того, когда сервер разглядел TLS внутри. */
    if (cmd == VISION_CMD_DIRECT) v->recv_direct = 1;
    v->rx_hdr_n = 0;
    /* Кадр без данных и без набивки: сервер так закрывает набивку. */
    if (!v->rx_data_left && !v->rx_pad_left && v->rx_end_after) v->recv_done = 1;
    return 0;
}

/* Функция vision_payload_total удалена: её никто не вызывал.
 *
 * Она считала, сколько полезных байт даст разбор буфера, чтобы вызывающий заранее знал
 * размер. Вызывающий вместо этого просто складывает куски в один буфер по мере разбора —
 * то же самое без второго прохода по данным. Мёртвый код в файле, отвечающем за разбор
 * недоверенного потока, хуже отсутствующего: он выглядит частью механизма и его начинают
 * поддерживать при изменениях. */
