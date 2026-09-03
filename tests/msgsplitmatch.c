/* Нарезка потока клиента на пакеты MTProto: один пакет — один кадр веб-сокета.
 *
 * ЗАЧЕМ ОТДЕЛЬНЫЙ СТЕНД. Точка apiws считает границу кадра границей пакета: она сделана для
 * веб-клиента, а тот посылает каждый пакет отдельным вызовом send(). Мост же берёт байты из
 * TCP-сокета, где границы чужие. Пока клиент писал по одному пакету за раз, совпадение было
 * случайно верным — и медиа грузилось прекрасно, потому что запрос куска файла это один
 * пакет. Но телефон при подключении пишет подряд подтверждения, ping и updates.getDifference,
 * TCP склеивает их в одно чтение, сервер разбирает первый пакет и молчит: «Обновление» висит,
 * сообщения не отправляются. Ошибка не видна ничем — соединение живо, точка отвечает 101,
 * байты идут, — поэтому она и держалась месяцами. Здесь она видна.
 *
 * Файл включает исходник моста: ms_feed статическая, и дотянуться до неё иначе значило бы
 * добавить в движок подкоманду ради стенда (тот же приём, что в dcmatch.c).
 *
 * Шифр в заглушках сквозной (memcpy), поэтому шифротекст равен открытому тексту: стенд
 * проверяет РАЗБОР ГРАНИЦ, а не обфускацию. Маска кадров нулевая по той же причине —
 * xc_random в заглушке отдаёт нули, и тело кадра можно сравнивать напрямую. */
#include "../src/ext/tgws.c"

int xc_random(unsigned char *out, size_t n) { memset(out, 0, n); return 0; }
int xc_x25519_keypair(unsigned char priv[32], unsigned char pub[32])
                                        { memset(priv, 0, 32); memset(pub, 0, 32); return 0; }
int reality_build_hello_carry(const struct reality_cfg *cfg, struct reality_state *st,
                              const struct reality_carrier *car,
                              unsigned char *out, size_t out_n, size_t *out_len)
                                        { (void)cfg; (void)st; (void)car; (void)out;
                                          (void)out_n; *out_len = 0; return -1; }
int tls13_handshake(struct tls13 *t, int fd, const unsigned char *ch, size_t n,
                    const unsigned char *ss)
                                        { (void)t; (void)fd; (void)ch; (void)n; (void)ss; return -1; }
int tls13_has_record(const struct tls13 *t) { (void)t; return 0; }
int tls13_write(struct tls13 *t, const unsigned char *d, size_t n)
                                        { (void)t; (void)d; (void)n; return -1; }
int tls13_read(struct tls13 *t, unsigned char *o, size_t c, size_t *g)
                                        { (void)t; (void)o; (void)c; *g = 0; return -1; }
void tls13_free(struct tls13 *t) { (void)t; }
void mbedtls_aes_init(mbedtls_aes_context *c) { (void)c; }
void mbedtls_aes_free(mbedtls_aes_context *c) { (void)c; }
int mbedtls_aes_setkey_enc(mbedtls_aes_context *c, const unsigned char *k, unsigned int b)
                                        { (void)c; (void)k; (void)b; return 0; }
int mbedtls_aes_crypt_ctr(mbedtls_aes_context *c, size_t n, size_t *off, unsigned char *nc,
                          unsigned char *sb, const unsigned char *in, unsigned char *out)
                                        { (void)c; (void)off; (void)nc; (void)sb;
                                          memcpy(out, in, n); return 0; }
void load_spec(const char *path) { (void)path; }
void registry_assign(void) { }
struct output g_out[MAX_OUTPUTS];
size_t g_out_n;

static int fails;

static void ok(const char *what) { printf("%-52s ok\n", what); }
static void bad(const char *what, const char *why, long a, long b) {
    printf("%-52s БРАК: %s (%ld против %ld)\n", what, why, a, b);
    fails++;
}

/* ---- поток к точке: собираем то, что мост записал в сокет ---- */

struct cap { unsigned char b[262144]; size_t n; int rd, wr; };

static void cap_open(struct cap *c) {
    int sp[2];
    if (socketpair(AF_UNIX, SOCK_STREAM, 0, sp) != 0) { perror("socketpair"); exit(2); }
    c->wr = sp[0];
    c->rd = sp[1];
    c->n = 0;
    fcntl(c->rd, F_SETFL, O_NONBLOCK);
}

static void cap_drain(struct cap *c) {
    for (;;) {
        ssize_t r = read(c->rd, c->b + c->n, sizeof(c->b) - c->n);
        if (r <= 0) break;
        c->n += (size_t)r;
    }
}

static void cap_close(struct cap *c) { close(c->rd); close(c->wr); }

/* Разбор записанного: длины кадров и склеенное содержимое. Возврат — число кадров или -1. */
static long frames_parse(const struct cap *c, size_t *lens, size_t lens_n,
                         unsigned char *cat, size_t *cat_n) {
    size_t off = 0, k = 0;
    *cat_n = 0;
    while (off < c->n) {
        if (c->n - off < 2) return -1;
        if (c->b[off] != 0x82) return -1;             /* FIN + двоичный кадр */
        if (!(c->b[off + 1] & 0x80)) return -1;       /* кадр клиента обязан быть замаскирован */
        size_t len = c->b[off + 1] & 0x7f, head = 2;
        if (len == 126) {
            if (c->n - off < 4) return -1;
            len = ((size_t)c->b[off + 2] << 8) | c->b[off + 3];
            head = 4;
        } else if (len == 127) {
            if (c->n - off < 10) return -1;
            len = 0;
            for (int i = 0; i < 8; i++) len = (len << 8) | c->b[off + 2 + i];
            head = 10;
        }
        head += 4;                                    /* маска */
        if (c->n - off < head + len) return -1;
        if (k < lens_n) lens[k] = len;
        memcpy(cat + *cat_n, c->b + off + head, len); /* маска нулевая — см. заглушки */
        *cat_n += len;
        off += head + len;
        k++;
    }
    return (long)k;
}

/* ---- сборка потока клиента ---- */

static size_t put_abridged(unsigned char *out, size_t body, unsigned char fill) {
    size_t k = 0;
    if (body / 4 >= 0x7f) {
        out[k++] = 0x7f;
        out[k++] = (unsigned char)((body / 4) & 0xff);
        out[k++] = (unsigned char)(((body / 4) >> 8) & 0xff);
        out[k++] = (unsigned char)(((body / 4) >> 16) & 0xff);
    } else {
        out[k++] = (unsigned char)(body / 4);
    }
    memset(out + k, fill, body);
    return k + body;
}

static size_t put_inter(unsigned char *out, size_t body, unsigned char fill) {
    out[0] = (unsigned char)(body & 0xff);
    out[1] = (unsigned char)((body >> 8) & 0xff);
    out[2] = (unsigned char)((body >> 16) & 0xff);
    out[3] = (unsigned char)((body >> 24) & 0xff);
    memset(out + 4, fill, body);
    return 4 + body;
}

/* Один прогон: поток клиента → кадры. chunk = 0 значит «отдать одним куском». */
static void run(unsigned char tag, const unsigned char *stream, size_t n, size_t chunk,
                const size_t *want, size_t want_n, const char *what) {
    struct cap c;
    cap_open(&c);
    struct upstream u;
    memset(&u, 0, sizeof(u));
    u.fd = c.wr;
    u.tls_on = 0;

    unsigned char hs[HS_LEN];
    memset(hs, 0x11, sizeof(hs));
    struct msgsplit m;
    if (ms_init(&m, hs, tag) != 0) { bad(what, "теневой шифр не поднялся", 0, 0); cap_close(&c); return; }

    size_t step = chunk ? chunk : n;
    for (size_t off = 0; off < n; off += step) {
        size_t part = n - off < step ? n - off : step;
        if (ms_feed(&m, &u, stream + off, part) < 0) {
            bad(what, "запись отказала", (long)off, (long)part);
            cap_close(&c);
            return;
        }
    }
    cap_drain(&c);

    size_t lens[64], cat_n = 0;
    static unsigned char cat[262144];
    long k = frames_parse(&c, lens, 64, cat, &cat_n);
    cap_close(&c);

    if (k < 0) { bad(what, "кадры не разбираются", (long)c.n, 0); return; }
    if ((size_t)k != want_n) { bad(what, "кадров не столько", k, (long)want_n); return; }
    for (size_t i = 0; i < want_n && i < 64; i++)
        if (lens[i] != want[i]) { bad(what, "длина кадра не та", (long)lens[i], (long)want[i]); return; }
    if (cat_n != n || memcmp(cat, stream, n) != 0) {
        bad(what, "содержимое не совпало", (long)cat_n, (long)n);
        return;
    }
    ok(what);
}

int main(void) {
    static unsigned char s[262144];
    size_t n, want[8];

    /* РОВНО ТОТ СЛУЧАЙ, ИЗ-ЗА КОТОРОГО НЕ РАБОТАЛ ТЕЛЕФОН: три пакета в одном чтении. */
    n  = put_abridged(s,     4,  0xa1);
    n += put_abridged(s + n, 8,  0xa2);
    n += put_abridged(s + n, 12, 0xa3);
    want[0] = 1 + 4; want[1] = 1 + 8; want[2] = 1 + 12;
    run(0xef, s, n, 0, want, 3, "три пакета в одном чтении — три кадра");

    /* Один пакет, разорванный на куски по три байта: кадр обязан остаться ОДИН. */
    n = put_abridged(s, 64, 0xb0);
    want[0] = 1 + 64;
    run(0xef, s, n, 3, want, 1, "пакет по кускам — всё равно один кадр");

    /* Длинная форма префикса: 0x7f и три байта длины в четвёрках. */
    n = put_abridged(s, 512, 0xc0);
    want[0] = 4 + 512;
    run(0xef, s, n, 0, want, 1, "длинная форма префикса — один кадр");

    /* Просьба о быстром подтверждении: старший бит в префиксе к длине не относится. */
    n = put_abridged(s, 4, 0xd0);
    s[0] |= 0x80;
    want[0] = 1 + 4;
    run(0xef, s, n, 0, want, 1, "старший бит префикса — не часть длины");

    /* Обычный транспорт, поток отдаётся ПО ОДНОМУ БАЙТУ. */
    n  = put_inter(s,     16, 0xe1);
    n += put_inter(s + n, 32, 0xe2);
    want[0] = 4 + 16; want[1] = 4 + 32;
    run(0xee, s, n, 1, want, 2, "обычный транспорт по байту — два кадра");

    /* Транспорт с набивкой читается той же длиной. */
    n = put_inter(s, 20, 0xe3);
    want[0] = 4 + 20;
    run(0xdd, s, n, 0, want, 1, "транспорт с набивкой — один кадр");

    /* Кадр больше 64 КБ: длина обязана уйти восьмибайтовым полем. */
    n = put_inter(s, 70000, 0xf1);
    want[0] = 4 + 70000;
    run(0xee, s, n, 8192, want, 1, "пакет больше 64 КБ — одним кадром");

    /* Много мелких пакетов подряд: накопитель записи не должен их склеивать в один кадр. */
    n = 0;
    for (int i = 0; i < 40; i++) n += put_abridged(s + n, 4, (unsigned char)(0x40 + i));
    {
        size_t w[64];
        for (int i = 0; i < 40; i++) w[i] = 1 + 4;
        run(0xef, s, n, 0, w, 40, "сорок мелких пакетов — сорок кадров");
    }

    /* НЕГОДНАЯ ДЛИНА: нарезка выключается, но байты обязаны дойти. Молча рвать соединение
     * человека из-за непонятного префикса нельзя — это хуже неоптимальных границ. */
    {
        struct cap c;
        cap_open(&c);
        struct upstream u;
        memset(&u, 0, sizeof(u));
        u.fd = c.wr;
        unsigned char hs[HS_LEN];
        memset(hs, 0x11, sizeof(hs));
        struct msgsplit m;
        ms_init(&m, hs, 0xee);
        unsigned char zero[16];
        memset(zero, 0, sizeof(zero));               /* длина 0 — так не бывает */
        int r = ms_feed(&m, &u, zero, sizeof(zero));
        cap_drain(&c);
        cap_close(&c);
        if (r < 0) bad("негодная длина — нарезка выключается", "запись отказала", r, 0);
        else if (m.on) bad("негодная длина — нарезка выключается", "нарезка осталась включённой", 1, 0);
        else if (c.n == 0) bad("негодная длина — нарезка выключается", "байты потерялись", 0, 16);
        else ok("негодная длина — нарезка выключается, байты идут");
    }

    if (fails) { printf("\nбрак: %d\n", fails); return 1; }
    printf("\nнарезка на пакеты: все проверки прошли\n");
    return 0;
}
