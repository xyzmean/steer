/* Стенд хаба xsteer: размеры, из которых складывается запись, и их согласие друг с другом.
 *
 * ЗАЧЕМ ИМЕННО ТАКОЙ СТЕНД. Цикл хаба (worker_loop) целиком построен на I/O: сырой сокет,
 * очередь TUN, потоки. Проверить его целиком в памяти нельзя, не переписав. Но самая дорогая
 * ошибка в нём — не в логике ветвлений, а в АРИФМЕТИКЕ РАЗМЕРОВ: набор кадров в пачку
 * ограничен одним правилом, строка под запись объявлена другим числом, и разойтись они могут
 * молча. Ровно это и вышло (I-070): строку посчитали с местом под ОДИН заголовок вместо трёх,
 * и на предельной пачке тег AEAD ложился на четыре байта за границу поля — внутрь соседнего
 * поля той же структуры, где его не видит ни компилятор, ни AddressSanitizer (у ASan нет
 * красной зоны между полями структуры). Получатель при этом получал запись с испорченным
 * тегом и отбрасывал её целиком, то есть терял до шести пакетов разом — молча.
 *
 * Стенд включает сам xshub.c: правило набора и объявление строки живут внутри него, и смотреть
 * на них надо на настоящих, а не пересказанных числах. Ни сети, ни root, ни потоков он не
 * трогает — только считает и один раз вызывает настоящий xs_conn_split_mm.
 *
 * Отсюда же растёт стенд для самого цикла, когда до него дойдёт очередь: включение .c уже
 * даёт доступ к struct worker, g_sess и статическим функциям.
 *
 *     cc -O2 -w -Isrc -I<mbedtls>/include -o build/hubmatch tests/hubmatch.c \
 *        src/ext/xsconn.c src/ext/xswire.c src/ext/xsepoch.c src/ext/xsroute.c \
 *        src/ext/xsconf.c src/ext/xsstream.c src/ext/xshake.c src/ext/chello.c \
 *        src/ext/reality.c src/ext/tls13.c src/ext/h2.c src/ext/tun.c src/obfs.c \
 *        src/spec.c <mbedtls>/library/libmbedcrypto.a -lpthread
 */
#define _GNU_SOURCE
#include <stdio.h>
#include <string.h>

/* Хабу run_quiet нужен для `ip link` (hub_retune_mtu, cmd_xsteer_hub); в src/steer.c его
 * настоящая реализация, а стенду достаточно отказа: ничего из этого он не вызывает. */
int run_quiet(const char *const argv[]) { (void)argv; return -1; }

#include "../src/ext/xshub.c"

static int fails;

static void check(const char *what, long want, long got) {
    printf("%-64s %s\n", what, want == got ? "ok" : "ПРОВАЛ");
    if (want != got) {
        printf("     хочу: %ld\n     есть: %ld\n", want, got);
        fails++;
    }
}

int main(void) {
    printf("== хаб: арифметика записи ==\n");

    /* ПРАВИЛО НАБОРА, дословно как в worker_loop: перед чтением очередного кадра цикл требует
     * off + 2 + XS_MTU_DEF + XS_TAG <= XS_MAX_RECORD, а прочитанный кадр может быть полным.
     * Значит предельная нагрузка записи — вот эта. */
    size_t off_max = XS_MAX_RECORD - 2 - XS_MTU_DEF - XS_TAG;
    size_t pn_max = off_max + 2 + XS_MTU_DEF;
    check("предельная нагрузка записи по правилу набора",
          (long)(XS_MAX_RECORD - XS_TAG), (long)pn_max);
    check("она же равна XSH_PN_MAX, на который смотрит статическая проверка",
          (long)XSH_PN_MAX, (long)pn_max);

    /* ДОСТИЖИМОСТЬ. Проверка выше — про предел правила; эта — про то, что предел берётся
     * настоящими кадрами обычных размеров, а не только на бумаге. Набираем так же, как цикл:
     * полные кадры, пока следующий полный ещё оставляет off не выше границы правила; один
     * подогнанный, чтобы off встал ровно на границу; и ещё один полный — тот самый, который
     * правило пропускает, а строка уже не держала. */
    size_t off = XS_BATCH_HDR;
    int frames = 0;
    while (off + 2 + (size_t)XS_MTU_DEF <= off_max) { off += 2 + XS_MTU_DEF; frames++; }
    size_t pad = off_max - off - 2;
    off = off_max; frames++;
    off += 2 + XS_MTU_DEF; frames++;
    printf("     %d кадров: %d полных, один %zu байт и последний полный\n",
           frames, frames - 2, pad);
    check("подогнанный кадр — обычный пакет, а не выдумка", 1,
          pad > 20 && pad <= (size_t)XS_MTU_DEF);
    check("кадров нужно не больше, чем несёт пачка", 1, frames <= XS_BATCH_FRAMES_MAX);
    check("и набранная нагрузка равна предельной", (long)pn_max, (long)off);

    /* СТРОКА ВОРКЕРА. Нагрузка лежит по row + XS_HDR_ROOM (там же, где оказывается
     * расшифрованный пакет при пересылке пир↔пир), тег — сразу за нагрузкой. */
    size_t row = sizeof(((struct worker *)0)->row);
    check("строка воркера вмещает предельную запись с заголовками и тегом",
          1, row >= XS_HDR_ROOM + pn_max + XS_TAG);
    printf("     строка %zu, нужно %zu (заголовки %d + нагрузка %zu + тег %d)\n",
           row, XS_HDR_ROOM + pn_max + XS_TAG, XS_HDR_ROOM, pn_max, XS_TAG);

    /* ОДИНОЧНЫЙ КАДР. Он едет без контейнера, и hub_send_frames переносит его на место
     * нагрузки записи (memmove внутри строки) — предел тот же, что у сегмента. */
    check("одиночный кадр в строку влезает", 1,
          XS_HDR_ROOM + (size_t)XS_MTU_DEF + XS_TAG <= row);

    /* СЕГМЕНТОВ У ПРЕДЕЛЬНОЙ ЗАПИСИ НЕ БОЛЬШЕ, ЧЕМ ВЕКТОРОВ ПОД sendmmsg. Иначе
     * xs_conn_split_mm вернёт -1 и запись не уйдёт вовсе — то же молчаливое исчезновение
     * пакетов, только по другой причине. Проверяем настоящим split_mm на обоих концах
     * диапазона MTU: договорённом по умолчанию и наименьшем, до которого доходит пробой пути. */
    size_t cap = sizeof(((struct worker *)0)->hdrs) / 20;
    uint8_t rec[XS_REC_HDR + XSH_PN_MAX + XS_TAG];
    uint8_t hdrs[XS_BATCH_FRAMES_MAX + 8][20];
    struct iovec iov[2 * (XS_BATCH_FRAMES_MAX + 8)];
    struct mmsghdr mm[XS_BATCH_FRAMES_MAX + 8];
    memset(rec, 0x5A, sizeof(rec));
    int mtus[2] = { XS_MTU_DEF, XS_MTU_FLOOR };
    for (int i = 0; i < 2; i++) {
        struct xs_conn c;
        memset(&c, 0, sizeof(c));
        c.fd = -1;
        c.sport = 443;
        c.dport = 40000;
        size_t max_seg = (size_t)mtus[i] + XS_OVERHEAD - 40;
        int segs = xs_conn_split_mm(&c, rec, sizeof(rec), max_seg, hdrs, iov, mm, cap, 1000);
        printf("     MTU %d: сегментов %d, векторов %zu\n", mtus[i], segs, cap);
        check("предельная запись режется и влезает в векторы", 1, segs > 0);
    }

    printf(fails ? "\nПРОВАЛОВ: %d\n" : "\nвсе проверки прошли\n", fails);
    return fails ? 1 : 0;
}
