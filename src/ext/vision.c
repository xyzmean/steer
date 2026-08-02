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

/* Обернуть данные в кадр. Возвращает длину кадра или 0, если не влез в буфер. */
size_t vision_wrap(struct vision *v, const unsigned char *data, size_t n,
                   unsigned char *out, size_t cap) {
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

    if (n < 5) return VISION_EAGAIN;
    unsigned char cmd = in[0];
    size_t len = ((size_t)in[1] << 8) | in[2];
    size_t pad = ((size_t)in[3] << 8) | in[4];
    if (cmd > VISION_CMD_DIRECT) return VISION_EPROTO;
    if (n < 5 + len + pad) return VISION_EAGAIN;

    *consumed += 5 + len + pad;
    *payload = in + 5;
    *payload_n = len;
    if (cmd == VISION_CMD_END || cmd == VISION_CMD_DIRECT) v->recv_done = 1;
    return 0;
}

/* Сколько байт полезных данных в буфере, если развернуть все кадры. Нужно вызывающему,
 * чтобы собрать их в один TCP-пакет: отдавать клиенту по пакету на кадр значит дробить
 * поток на куски по 200 байт там, где сервер прислал 1400. */
size_t vision_payload_total(struct vision *v, const unsigned char *in, size_t n) {
    struct vision probe = *v;      /* копия: подсчёт не должен менять состояние */
    size_t total = 0;
    while (n) {
        size_t used = 0;
        const unsigned char *pl = NULL;
        size_t pl_n = 0;
        if (vision_unwrap(&probe, in, n, &used, &pl, &pl_n) != 0 || !used) break;
        total += pl_n;
        in += used;
        n -= used;
    }
    return total;
}
