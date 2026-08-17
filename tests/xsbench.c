/* Сколько стоит один пакет xsteer: замер ПОЛНОГО пути, а не одного шифра.
 *
 * ЗАЧЕМ ИМЕННО ТАК. В этом проекте уже есть стенд, который мерил «800 Мбит/с» у кода,
 * которого не было: tests/crypto-bench.c ставит ключ ОДИН раз вне измеряемого цикла, а
 * рабочий код тогда разворачивал его на каждую запись. Поэтому здесь измеряется ровно то,
 * что делает цикл пересылки на каждый пакет, и в том же порядке:
 *
 *     1. AEAD на месте по нагрузке (единственный проход шифра — второго слоя у xsteer нет);
 *     2. заголовок записи TLS перед нагрузкой в том же буфере;
 *     3. заголовок TCP перед записью, там же;
 *     4. контрольная сумма TCP по псевдозаголовку и всей нагрузке (сырому сокету ядро её
 *        не считает — сегмент с неверной суммой уйдёт, и стек той стороны отбросит его
 *        молча).
 *
 * Ключ разворачивается один раз на сессию — так же, как в рабочем коде (tls13_keys_setup),
 * потому что иначе замер снова относился бы к другой программе.
 *
 * Отдельно печатаются слагаемые: пока не видно, что именно съедает время, «стало быстрее»
 * нельзя ни подтвердить, ни опровергнуть. На сильном железе главная статья — AEAD, и это
 * ответ на вопрос, есть ли смысл оптимизировать всё остальное.
 *
 * МАСШТАБИРОВАНИЕ ПО ЯДРАМ измеряется здесь же, и это не украшение замера. Устройство
 * xsteer обещает, что на пути данных нет общего изменяемого состояния: поддельное
 * TCP-соединение принадлежит одному потоку навсегда, вместе со своим ключом, своим
 * смещением и своим окном приёма. Обещание проверяется единственным способом — запустить N
 * потоков и посмотреть, растёт ли сумма линейно. Если не растёт, значит состояние всё-таки
 * общее, и это надо знать до того, как оно проявится под нагрузкой.
 *
 * Нужен настоящий mbedtls (здесь СЧИТАЕТСЯ шифр), поэтому в make test стенд не входит.
 * Собрать и запустить:
 *     cc -O2 -w -Isrc -I<mbedtls>/include -o build/xsbench tests/xsbench.c \
 *        src/ext/xswire.c src/ext/reality.c -lpthread <mbedtls>/library/libmbedcrypto.a
 *     ./build/xsbench [размер_нагрузки] [секунд_на_замер] [потоков]
 */
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <stdint.h>
#include <pthread.h>
#include <sched.h>
#include <unistd.h>

/* obfs.c зовёт run_quiet из failover.c — здесь она не нужна, а линковать сторож ради
 * одной заглушки незачем. */
int run_quiet(const char *const argv[]);
int run_quiet(const char *const argv[]) { (void)argv; return 0; }

#include "../src/obfs.c"
#include "../src/ext/xswire.h"
#include "../src/ext/tls13.h"

/* tls13.c тянет за собой рукопожатие и h2; нам нужны только keys_setup и aead_*, но
 * включать исходник целиком проще, чем выкраивать: линкуется он без сети. */
#include "../src/ext/tls13.c"

static double now_s(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (double)ts.tv_sec + (double)ts.tv_nsec / 1e9;
}

static void keys_init(struct tls13_keys *k, enum tls13_aead aead) {
    memset(k, 0, sizeof(*k));
    k->aead = aead;
    k->key_n = aead == TLS13_AEAD_AES256 ? 32 : (aead == TLS13_AEAD_CHACHA ? 32 : 16);
    for (size_t i = 0; i < k->key_n; i++) k->key[i] = (unsigned char)(i * 7 + 1);
    for (int i = 0; i < 12; i++) k->iv[i] = (unsigned char)(i + 0x20);
    if (tls13_keys_setup(k) != 0) { puts("не развернулся ключ"); exit(2); }
}

/* Один пакет ровно так, как его собирает цикл пересылки: шифрование на месте, заголовки
 * ПЕРЕД нагрузкой в том же буфере, сумма по готовому сегменту. */
static inline int one_packet(struct tls13_keys *k, uint8_t *row, size_t plen,
                            uint32_t rel, uint32_t saddr, uint32_t daddr) {
    uint8_t *pt = row + XS_HDR_ROOM;
    uint8_t *rec = pt - XS_REC_HDR;
    if (xs_rec_build(rec, plen + XS_TAG) != 0) return -1;
    if (tls13_aead_seal(k, rel, rec, XS_REC_HDR, pt, plen, pt + plen) != 0) return -1;
    struct tcp_hdr *t = (struct tcp_hdr *)(rec - sizeof(struct tcp_hdr));
    memset(t, 0, sizeof(*t));
    t->sport = htons(41234);
    t->dport = htons(443);
    t->seq = htonl(rel);
    t->ack = htonl(1);
    t->off = (uint8_t)((sizeof(*t) / 4) << 4);
    t->flags = TH_PSH | TH_ACK;
    t->win = htons(OBFS_WIN);
    size_t seglen = sizeof(*t) + XS_REC_HDR + plen + XS_TAG;
    t->sum = htons(obfs_tcp_csum(saddr, daddr, t, seglen));
    return 0;
}

/* ---- многопоточный прогон ---------------------------------------------------
 *
 * Каждый поток полностью автономен: своя строка буфера, свой ключ, своё смещение. Ни одной
 * общей изменяемой переменной — кроме итогов, которые складываются ПОСЛЕ join. */
struct worker {
    pthread_t th;
    size_t plen;
    double budget;
    int cpu;
    unsigned long long pkts;
    double secs;
};

static void *worker_main(void *arg) {
    struct worker *w = arg;
    /* Привязка к ядру: без неё планировщик перекидывает потоки, и на восьми ядрах замер
     * гуляет на десятки процентов от прогона к прогону. */
    cpu_set_t set;
    CPU_ZERO(&set);
    CPU_SET(w->cpu, &set);
    pthread_setaffinity_np(w->th, sizeof(set), &set);

    uint8_t *row = aligned_alloc(64, XS_ROW);
    if (!row) return NULL;
    for (size_t i = 0; i < XS_ROW; i++) row[i] = (uint8_t)i;
    struct tls13_keys k;
    keys_init(&k, TLS13_AEAD_CHACHA);

    uint32_t rel = 1;
    for (int i = 0; i < 5000; i++) one_packet(&k, row, w->plen, rel + (uint32_t)i, 1, 2);

    unsigned long long pkts = 0;
    double t0 = now_s(), t1;
    do {
        for (int i = 0; i < 1000; i++) {
            one_packet(&k, row, w->plen, rel, 1, 2);
            rel += (uint32_t)(w->plen + XS_REC_HDR + XS_TAG);
            if (rel >= XS_REL_RETIRE) rel = 1;
        }
        pkts += 1000;
        t1 = now_s();
    } while (t1 - t0 < w->budget);
    w->pkts = pkts;
    w->secs = t1 - t0;
    tls13_keys_free(&k);
    free(row);
    return NULL;
}

static double run_threads(int n, size_t plen, double budget) {
    struct worker w[64];
    memset(w, 0, sizeof(w));
    for (int i = 0; i < n; i++) {
        w[i].plen = plen;
        w[i].budget = budget;
        w[i].cpu = i % (int)sysconf(_SC_NPROCESSORS_ONLN);
        pthread_create(&w[i].th, NULL, worker_main, &w[i]);
    }
    double total = 0;
    for (int i = 0; i < n; i++) {
        pthread_join(w[i].th, NULL);
        if (w[i].secs > 0) total += (double)w[i].pkts * (double)plen / w[i].secs / 1e6;
    }
    return total;
}

static void report(const char *what, double secs, unsigned long long pkts, size_t plen) {
    double bytes = (double)pkts * (double)plen;
    printf("  %-34s %7.0f тыс. пак/с  %8.2f МБ/с  %8.2f Гбит/с  %6.0f нс/пакет\n",
           what, (double)pkts / secs / 1000.0,
           bytes / secs / 1e6, bytes * 8 / secs / 1e9,
           secs / (double)pkts * 1e9);
}

int main(int argc, char **argv) {
    size_t plen = argc > 1 ? (size_t)atoi(argv[1]) : (size_t)XS_MTU_DEF;
    double budget = argc > 2 ? atof(argv[2]) : 1.0;
    if (plen < 1 || plen > XS_MTU_DEF) { printf("нагрузка 1..%d\n", XS_MTU_DEF); return 2; }

    static uint8_t row[XS_ROW] __attribute__((aligned(8)));
    for (size_t i = 0; i < sizeof(row); i++) row[i] = (uint8_t)i;
    uint32_t saddr = 0x0100007F, daddr = 0x0A00000A;

    struct { const char *name; enum tls13_aead aead; } CIPHERS[] = {
        { "AES-128-GCM", TLS13_AEAD_AES128 },
        { "ChaCha20-Poly1305", TLS13_AEAD_CHACHA },
    };

    printf("нагрузка %zu байт, накладные %d байт (пакет на проводе %zu)\n\n",
           plen, XS_OVERHEAD, plen + XS_OVERHEAD);

    for (size_t ci = 0; ci < sizeof(CIPHERS) / sizeof(CIPHERS[0]); ci++) {
        struct tls13_keys k;
        keys_init(&k, CIPHERS[ci].aead);
        printf("%s:\n", CIPHERS[ci].name);

        /* Прогрев: первые проходы платят за промахи кэша и за то, что таблицы шифра ещё
         * не в нём. Без прогрева короткий замер мерит именно это. */
        for (int i = 0; i < 10000; i++) one_packet(&k, row, plen, (uint32_t)(i + 1), saddr, daddr);

        /* Полный путь. rel растёт, как в жизни: каждый пакет — свой nonce. */
        unsigned long long pkts = 0;
        uint32_t rel = 1;
        double t0 = now_s(), t1;
        do {
            for (int i = 0; i < 1000; i++) {
                one_packet(&k, row, plen, rel, saddr, daddr);
                rel += (uint32_t)(plen + XS_REC_HDR + XS_TAG);
                if (rel >= XS_REL_RETIRE) rel = 1;      /* как ретайр в жизни */
            }
            pkts += 1000;
            t1 = now_s();
        } while (t1 - t0 < budget);
        report("полный путь пакета", t1 - t0, pkts, plen);

        /* Только AEAD — чтобы было видно, сколько стоит всё остальное. */
        pkts = 0; rel = 1;
        t0 = now_s();
        do {
            for (int i = 0; i < 1000; i++) {
                tls13_aead_seal(&k, rel, row, XS_REC_HDR, row + XS_HDR_ROOM, plen,
                                row + XS_HDR_ROOM + plen);
                rel += (uint32_t)(plen + XS_REC_HDR + XS_TAG);
                if (rel >= XS_REL_RETIRE) rel = 1;
            }
            pkts += 1000;
            t1 = now_s();
        } while (t1 - t0 < budget);
        report("только AEAD", t1 - t0, pkts, plen);

        /* Только сумма TCP: второй проход по тем же байтам, ещё лежащим в кэше. */
        pkts = 0;
        t0 = now_s();
        do {
            for (int i = 0; i < 1000; i++) {
                volatile uint16_t s = obfs_tcp_csum(saddr, daddr, row + XS_HDR_ROOM - 20,
                                                    20 + XS_REC_HDR + plen + XS_TAG);
                (void)s;
            }
            pkts += 1000;
            t1 = now_s();
        } while (t1 - t0 < budget);
        report("только сумма TCP", t1 - t0, pkts, plen);

        /* Только расшифровка: путь вниз, он же самый частый при скачивании. */
        keys_init(&k, CIPHERS[ci].aead);
        struct tls13_keys w;
        keys_init(&w, CIPHERS[ci].aead);
        pkts = 0;
        t0 = now_s();
        do {
            for (int i = 0; i < 1000; i++) {
                uint8_t *pt = row + XS_HDR_ROOM;
                uint8_t *rec = pt - XS_REC_HDR;
                xs_rec_build(rec, plen + XS_TAG);
                tls13_aead_seal(&w, 1, rec, XS_REC_HDR, pt, plen, pt + plen);
                tls13_aead_open(&k, 1, rec, XS_REC_HDR, pt, plen + XS_TAG);
            }
            pkts += 1000;
            t1 = now_s();
        } while (t1 - t0 < budget);
        report("шифрование + расшифровка", t1 - t0, pkts, plen);
        tls13_keys_free(&k);
        tls13_keys_free(&w);
        printf("\n");
    }

    /* ---- масштабирование по ядрам ------------------------------------------
     *
     * Каждый поток — сам себе воркер: свой ключ, своё смещение, своя строка буфера. Ровно
     * так устроен путь данных, поэтому линейный рост здесь означает, что общего изменяемого
     * состояния действительно нет, а не что нам так кажется. */
    {
        int maxj = argc > 3 ? atoi(argv[3]) : (int)sysconf(_SC_NPROCESSORS_ONLN);
        if (maxj < 1) maxj = 1;
        if (maxj > 64) maxj = 64;
        printf("масштабирование по ядрам (ChaCha20-Poly1305, полный путь пакета):\n");
        double one = 0;
        for (int j = 1; j <= maxj; j *= 2) {
            double mbs = run_threads(j, plen, budget);
            if (j == 1) one = mbs;
            printf("  %2d %-31s %8.2f МБ/с  %8.2f Гбит/с  ускорение ×%.2f\n",
                   j, j == 1 ? "поток" : "потоков", mbs, mbs * 8 / 1000.0,
                   one > 0 ? mbs / one : 0.0);
        }
        if (maxj > 1 && (maxj & (maxj - 1)) != 0) {
            double mbs = run_threads(maxj, plen, budget);
            printf("  %2d %-31s %8.2f МБ/с  %8.2f Гбит/с  ускорение ×%.2f\n",
                   maxj, "потоков", mbs, mbs * 8 / 1000.0, one > 0 ? mbs / one : 0.0);
        }
    }
    return 0;
}
