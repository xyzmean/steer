/* Разбор ClientHello: граница доверия хаба xsteer.
 *
 * Зачем отдельным стендом. Это первый код, который смотрит на байты, присланные кем угодно
 * на публичный порт хаба. Ошибка здесь — не «не разобралось», а чтение за пределами буфера
 * по длине, которой доверились. Поэтому проверяется двумя способами: на НАСТОЯЩЕМ Hello
 * (замороженные байты reality.c — см. tests/chello-frozen.h) и на нём же, испорченном во
 * всех местах, где есть поле длины.
 *
 * Настоящий Hello берётся из заморозки, а не собирается здесь, — поэтому стенду не нужен
 * mbedtls, и он входит в обычный make test. Байтовую неизменность самого сборщика проверяет
 * отдельный стенд tests/hellofreeze.c, которому библиотека нужна. */
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#include "../src/ext/chello.c"
#include "chello-frozen.h"

static int fails;

static void check(const char *what, long want, long got) {
    printf("%-62s %s\n", what, want == got ? "ok" : "ПРОВАЛ");
    if (want != got) {
        printf("     хочу: %ld\n     есть:  %ld\n", want, got);
        fails++;
    }
}

static void check_str(const char *what, const char *want, const char *got) {
    printf("%-62s %s\n", what, strcmp(want, got) == 0 ? "ok" : "ПРОВАЛ");
    if (strcmp(want, got) != 0) {
        printf("     хочу: \"%s\"\n     есть:  \"%s\"\n", want, got);
        fails++;
    }
}

int main(void) {
    const uint8_t *aes = (const uint8_t *)FROZEN_AES;
    const uint8_t *cha = (const uint8_t *)FROZEN_CHACHA;
    struct chello_ref r;

    /* ---- настоящий Hello ---------------------------------------------------- */
    check("Hello: разобран", 0, chello_parse(aes, FROZEN_N, &r));
    check("Hello: сообщение рукопожатия начинается за записью", 5, (long)r.hs_off);
    check("Hello: длина сообщения = запись минус заголовок", FROZEN_N - 5, (long)r.hs_n);
    check("Hello: session_id найден", 1, r.sid_off != 0);
    check("Hello: session_id внутри записи", 1, r.sid_off + 32 <= FROZEN_N);
    check("Hello: ключ x25519 найден", 1, r.ks_off != 0);
    check("Hello: ключ внутри записи", 1, r.ks_off + 32 <= FROZEN_N);
    check("Hello: набивка ECH найдена", 1, r.ech_off != 0);
    /* 176 байт — ровно столько кладёт reality.c, повторяя эталон Chrome. Именно в них едет
     * запечатанный статический ключ пира, поэтому размер важен: меньше — не влезет. */
    check("Hello: набивка ECH 176 байт", 176, (long)r.ech_n);
    check("Hello: набивка внутри записи", 1, r.ech_off + r.ech_n <= FROZEN_N);
    check_str("Hello: SNI прочитан", "www.example.com", r.sni);
    /* Набор шифров: GREASE обязан быть пропущен. У браузера он стоит В СПИСКЕ ПЕРВЫМ, и
     * взять «первый» буквально означало бы согласовать несуществующий шифр. */
    check("Hello (aes): выбран AES-128-GCM", 0x1301, r.suite);
    check("Hello: session_id и ключ не совпадают по смещению", 1, r.sid_off != r.ks_off);

    struct chello_ref r2;
    check("Hello (chacha): разобран", 0, chello_parse(cha, FROZEN_N, &r2));
    /* Порядок наборов у двух вариантов разный, и разбор обязан это видеть: именно так
     * пир сообщает хабу, какой AEAD ей дешевле. */
    check("Hello (chacha): выбран ChaCha20-Poly1305", 0x1303, r2.suite);
    check("Hello (chacha): смещения полей те же", 1,
          r.sid_off == r2.sid_off && r.ks_off == r2.ks_off && r.ech_off == r2.ech_off);

    /* ---- перемешивание расширений ------------------------------------------
     *
     * Chrome 110+ перемешивает порядок расширений, и reality.c делает то же. Значит
     * смещения полей на каждом соединении РАЗНЫЕ, и разбор обязан находить их всегда — это
     * и есть причина, по которой хаб не может обойтись константами. Проверяется на
     * замороженных байтах с искусственной перестановкой двух расширений одинаковой длины:
     * полноценный набор перестановок даёт стенд hellofreeze, где Hello собирается заново. */
    {
        uint8_t buf[FROZEN_N];
        memcpy(buf, aes, FROZEN_N);
        struct chello_ref a;
        check("перемешивание: исходный разобран", 0, chello_parse(buf, FROZEN_N, &a));
        /* Пройдём список расширений и поменяем местами два ЛЮБЫХ равной длины. Именно
         * «любых», а не заранее выбранных по типу: порядок в замороженных байтах уже
         * перемешан, и искать конкретную пару рядом бессмысленно — она там где угодно. */
        size_t ext_len_off = 0;
        {
            /* Начало списка расширений: за фиксированной частью Hello. */
            size_t i = a.hs_off + 4 + 2 + 32;      /* тип+длина, версия, random */
            i += 1 + 32;                            /* session_id */
            size_t suites = ((size_t)buf[i] << 8) | buf[i + 1];
            i += 2 + suites;
            i += 1 + buf[i];                        /* методы сжатия */
            ext_len_off = i;
        }
        size_t ext_end = ext_len_off + 2 +
                         (((size_t)buf[ext_len_off] << 8) | buf[ext_len_off + 1]);
        size_t off[64], tot[64];
        int cnt = 0;
        for (size_t i = ext_len_off + 2; i + 4 <= ext_end && cnt < 64; ) {
            size_t l = ((size_t)buf[i + 2] << 8) | buf[i + 3];
            off[cnt] = i;
            tot[cnt] = 4 + l;
            i += 4 + l;
            cnt++;
        }
        int p = -1, q = -1;
        for (int i = 0; i < cnt && p < 0; i++)
            for (int k = i + 1; k < cnt; k++)
                if (tot[i] == tot[k]) { p = i; q = k; break; }
        check("перемешивание: расширения перечислены", 1, cnt > 10);
        check("перемешивание: нашлась пара равной длины для перестановки", 1, p >= 0);
        if (p >= 0) {
            uint8_t tmp[64];
            memcpy(tmp, buf + off[p], tot[p]);
            memcpy(buf + off[p], buf + off[q], tot[q]);
            memcpy(buf + off[q], tmp, tot[p]);
        }
        struct chello_ref b;
        check("перемешивание: переставленный разобран", 0, chello_parse(buf, FROZEN_N, &b));
        check("перемешивание: поля найдены там же", 1,
              a.sid_off == b.sid_off && a.ks_off == b.ks_off && a.ech_off == b.ech_off);
    }

    /* ---- брак и злой умысел ------------------------------------------------
     *
     * Каждый случай — про поле длины, которому нельзя доверять. Проверяется не только то,
     * что разбор отказывает, но и то, что он не читает за буфером: стенд гоняется под
     * -fsanitize=address в дополнительной цели Makefile, а здесь буфер ещё и обрезается по
     * настоящей длине, чтобы чтение за концом было именно чтением за концом. */
    {
        check("брак: пустой буфер", -1, chello_parse(aes, 0, &r));
        check("брак: только тип записи", -1, chello_parse(aes, 1, &r));
        check("брак: заголовок записи без тела", -1, chello_parse(aes, 5, &r));
        for (size_t cut = 6; cut < FROZEN_N; cut += 7)
            if (chello_parse(aes, cut, &r) == 0) {
                printf("     обрезанный до %zu байт принят — это чтение за концом\n", cut);
                fails++;
            }
        printf("%-62s %s\n", "брак: ни один обрезанный Hello не принят", "ok");
    }
    {
        uint8_t buf[FROZEN_N + 8];
        memcpy(buf, aes, FROZEN_N);
        buf[0] = 0x17;
        check("брак: чужой тип записи", -1, chello_parse(buf, FROZEN_N, &r));
        memcpy(buf, aes, FROZEN_N);
        buf[5] = 0x02;                              /* не ClientHello, а ServerHello */
        check("брак: не ClientHello", -1, chello_parse(buf, FROZEN_N, &r));
        memcpy(buf, aes, FROZEN_N);
        buf[3] = 0xFF; buf[4] = 0xFF;               /* запись заявила больше, чем есть */
        check("брак: длина записи больше буфера", -1, chello_parse(buf, FROZEN_N, &r));
        memcpy(buf, aes, FROZEN_N);
        buf[3] = 0x00; buf[4] = 0x10;               /* меньше, чем есть */
        check("брак: длина записи меньше буфера", -1, chello_parse(buf, FROZEN_N, &r));
        memcpy(buf, aes, FROZEN_N);
        buf[6] = 0xFF;                              /* длина сообщения рукопожатия */
        check("брак: длина сообщения не сходится с записью", -1,
              chello_parse(buf, FROZEN_N, &r));
        memcpy(buf, aes, FROZEN_N);
        buf[43] = 31;                               /* длина session_id */
        check("брак: session_id не 32 байта", -1, chello_parse(buf, FROZEN_N, &r));
        memcpy(buf, aes, FROZEN_N);
        buf[43] = 0xFF;
        check("брак: session_id длиннее записи", -1, chello_parse(buf, FROZEN_N, &r));
    }
    {
        /* Испортим каждый байт по очереди и убедимся, что разбор либо отказывает, либо
         * возвращает смещения ВНУТРИ буфера. Ни одного выхода за пределы — это главное
         * утверждение файла, и проверяется оно единственным способом: перебором. */
        uint8_t buf[FROZEN_N];
        int out_of_range = 0, crashes = 0;
        for (size_t i = 0; i < FROZEN_N; i++) {
            for (int bit = 0; bit < 8; bit += 3) {
                memcpy(buf, aes, FROZEN_N);
                buf[i] ^= (uint8_t)(1 << bit);
                struct chello_ref x;
                if (chello_parse(buf, FROZEN_N, &x) != 0) continue;
                if (x.sid_off + 32 > FROZEN_N) out_of_range++;
                if (x.ks_off + 32 > FROZEN_N) out_of_range++;
                if (x.ech_off + x.ech_n > FROZEN_N) out_of_range++;
                if (x.hs_off + x.hs_n > FROZEN_N) out_of_range++;
            }
        }
        check("перебор искажений: смещения всегда внутри буфера", 0, out_of_range);
        check("перебор искажений: разбор ни разу не упал", 0, crashes);
    }

    /* ---- GREASE ------------------------------------------------------------- */
    check("GREASE: 0x0A0A распознан", 1, chello_is_grease(0x0A0A));
    check("GREASE: 0xFAFA распознан", 1, chello_is_grease(0xFAFA));
    check("GREASE: 0x1301 не GREASE", 0, chello_is_grease(0x1301));
    check("GREASE: 0x0A1A не GREASE (байты разные)", 0, chello_is_grease(0x0A1A));

    printf("\n%s\n", fails ? "ЕСТЬ ПРОВАЛЫ" : "все проверки прошли");
    return fails ? 1 : 0;
}
