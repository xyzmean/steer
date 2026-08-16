/* Разбор потока Vision на фикстурах: без сети, без сервера, без root.
 *
 * Зачем отдельный стенд. vision_unwrap читает поток ОТ СЕРВЕРА, то есть недоверенные
 * байты, и делает это потоком — состояние переносится между вызовами. Всё интересное в
 * нём поэтому зависит не от содержимого, а от НАРЕЗКИ: где именно легла граница записи
 * TLS. Живой стенд (tests/run-tunnel.sh) нарезку не выбирает и такие места не достаёт —
 * он гоняет исправный путь целиком и требует root с ip netns.
 *
 * Проверяется ровно то, что ломалось: начало потока, пришедшее по кускам (раньше байты
 * до опознания UUID отбрасывались, разбор терял синхронизацию и отдавал клиенту
 * служебные байты кадров как данные), и недопустимая команда (раньше не сбрасывала
 * накопленный заголовок, из-за чего разбор навсегда потреблял ноль байт).
 *
 * Исходник включается напрямую: состояние struct vision снаружи не выставить, а именно
 * оно здесь и проверяется. Тот же приём, что в tests/h2match.c и tests/dnsmatch.c. */
#include <stdio.h>
#include <string.h>
#include "../src/ext/vision.c"

static int fails;

static void check(const char *what, long want, long got) {
    if (want == got) { printf("%-58s ok\n", what); return; }
    printf("%-58s ПРОВАЛ: ожидалось %ld, получено %ld\n", what, want, got);
    fails++;
}

static const unsigned char UUID[16] = {
    0x96, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77,
    0x88, 0x99, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF
};

/* Поток от сервера: UUID, заголовок кадра (команда, длина данных, длина набивки) и сами
 * данные. Ровно та форма, которую собирает vision_wrap на другой стороне. */
static size_t make_stream(unsigned char *out, unsigned char cmd,
                          const char *data, size_t data_n) {
    size_t i = 0;
    memcpy(out + i, UUID, 16); i += 16;
    out[i++] = cmd;
    out[i++] = (unsigned char)(data_n >> 8);
    out[i++] = (unsigned char)(data_n & 0xFF);
    out[i++] = 0;                       /* набивки нет */
    out[i++] = 0;
    memcpy(out + i, data, data_n); i += data_n;
    return i;
}

/* Прогнать весь поток через разбор кусками по step байт и собрать выданное. */
static size_t drain(struct vision *v, const unsigned char *in, size_t n, size_t step,
                    char *out, size_t out_cap, int *rc_out) {
    size_t got = 0, pos = 0;
    *rc_out = 0;
    while (pos < n) {
        size_t chunk = n - pos < step ? n - pos : step;
        size_t off = 0;
        /* Внутри куска крутимся, пока разбор потребляет или что-то отдаёт, — так же, как
         * это делает downstream_pump в туннеле. */
        for (;;) {
            size_t used = 0, pl_n = 0;
            const unsigned char *pl = NULL;
            int rc = vision_unwrap(v, in + pos + off, chunk - off, &used, &pl, &pl_n);
            if (rc != 0) { *rc_out = rc; return got; }
            if (pl_n) {
                if (got + pl_n > out_cap) return got;
                memcpy(out + got, pl, pl_n);
                got += pl_n;
            }
            off += used;
            if (!used && !pl_n) break;
            if (off >= chunk) break;
        }
        pos += chunk;
    }
    return got;
}

int main(void) {
    unsigned char stream[256];
    const char *msg = "полезная нагрузка кадра";
    size_t msg_n = strlen(msg);
    size_t n = make_stream(stream, VISION_CMD_CONTINUE, msg, msg_n);

    /* Целиком одним куском — базовый случай, он работал и раньше. */
    {
        struct vision v;
        memset(&v, 0, sizeof(v));
        memcpy(v.uuid, UUID, 16);
        char out[256];
        int rc = 0;
        size_t got = drain(&v, stream, n, n, out, sizeof(out), &rc);
        check("поток одним куском: ошибки нет", 0, rc);
        check("поток одним куском: длина нагрузки", (long)msg_n, (long)got);
        check("поток одним куском: содержимое", 0, memcmp(out, msg, msg_n));
    }

    /* Нарезка по всем размерам куска, включая 1 байт. Раньше любой кусок короче 21 байта
     * приводил к VISION_EAGAIN, вызывающий отбрасывал эти байты, и разбор дальше сползал:
     * UUID сравнивался по сдвинутому смещению и не совпадал. */
    {
        int bad_step = -1;
        for (size_t step = 1; step <= n && bad_step < 0; step++) {
            struct vision v;
            memset(&v, 0, sizeof(v));
            memcpy(v.uuid, UUID, 16);
            char out[256];
            int rc = 0;
            size_t got = drain(&v, stream, n, step, out, sizeof(out), &rc);
            if (rc != 0 || got != msg_n || memcmp(out, msg, msg_n) != 0)
                bad_step = (int)step;
        }
        check("нарезка любым куском вплоть до 1 байта даёт ту же нагрузку", -1, bad_step);
    }

    /* Чужой UUID: обёртки нет, поток идёт как есть — и накопленное начало обязано дойти
     * до клиента целиком, а не пропасть в буфере разбора. */
    {
        unsigned char plain[64];
        memset(plain, 0, sizeof(plain));
        memcpy(plain, "это не обёрнутый поток, а обычные данные подряд", 46);
        struct vision v;
        memset(&v, 0, sizeof(v));
        memcpy(v.uuid, UUID, 16);            /* в потоке этого UUID нет */
        char out[128];
        int rc = 0;
        size_t got = drain(&v, plain, 46, 7, out, sizeof(out), &rc);
        check("чужой UUID: ошибки нет", 0, rc);
        check("чужой UUID: поток дошёл целиком", 46, (long)got);
        check("чужой UUID: содержимое не искажено", 0, memcmp(out, plain, 46));
    }

    /* Недопустимая команда: разрыв, а не вечное перечитывание одного кадра. */
    {
        unsigned char bad[64];
        size_t bn = make_stream(bad, 0x7F, "xx", 2);   /* команды 0x7F не существует */
        struct vision v;
        memset(&v, 0, sizeof(v));
        memcpy(v.uuid, UUID, 16);
        char out[64];
        int rc = 0;
        drain(&v, bad, bn, bn, out, sizeof(out), &rc);
        check("недопустимая команда: разбор сообщает EPROTO", VISION_EPROTO, rc);
    }

    /* Тот же испорченный кадр, поданный повторно, обязан снова дать EPROTO, а не
     * «успешно ничего». Именно на этом строилась вечная помойка: возврат до сброса
     * заголовка означал ноль потреблённых байт при живом соединении. */
    {
        unsigned char bad[64];
        size_t bn = make_stream(bad, 0x7F, "xx", 2);
        struct vision v;
        memset(&v, 0, sizeof(v));
        memcpy(v.uuid, UUID, 16);
        size_t used = 0, pl_n = 0;
        const unsigned char *pl = NULL;
        int rc1 = vision_unwrap(&v, bad, bn, &used, &pl, &pl_n);
        check("испорченный кадр: ошибка с первого раза", VISION_EPROTO, rc1);
        int rc2 = vision_unwrap(&v, bad, bn, &used, &pl, &pl_n);
        check("испорченный кадр: и со второго тоже ошибка, а не «успешно ничего»",
              VISION_EPROTO, rc2);
    }

    printf("\n%s\n", fails ? "ЕСТЬ ПРОВАЛЫ" : "все проверки прошли");
    return fails ? 1 : 0;
}
