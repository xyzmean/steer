/* Пути отказа моста Telegram, которые прогоном настоящего бинаря не достать.
 *
 * ЗАЧЕМ ОТДЕЛЬНЫЙ СТЕНД. У всех трёх случаев одно общее: снаружи они не видны ничем.
 * Слишком длинная строка списка запасных доменов превращалась в чужое имя, и в журнале это
 * выглядело как «точка недоступна»; отказ источника случайности и отказ рукопожатия TLS
 * оставляли за собой память, а мост при этом работал дальше. `tests/run-tgws.sh` поднимает
 * настоящий бинарь, у которого случайность есть всегда, а рукопожатие либо проходит, либо
 * падает до разворота ключей, — ни одна из этих веток там не исполняется.
 *
 * ЧТО ЗДЕСЬ ПРОВЕРЯЕТСЯ.
 *   1) alt_init: строка длиннее места под имя не принимается ни целиком, ни по кускам,
 *      а соседние строки читаются как обычно (I-155);
 *   2) ws_upgrade: отказ xc_random не оставляет выделенного буфера ответа (I-196);
 *   3) tls_start: отказ рукопожатия после разворота ключа записи не оставляет развёрнутого
 *      контекста (I-197);
 *   4) pump: сессия через веб-сокет кончается, когда данные MTProto молчат в обе стороны
 *      дольше срока затишья, и ping точки этот срок не продлевает; каждый выход называет
 *      свою причину, а не «срок затишья вышел» по умолчанию. Прогон настоящего бинаря этого
 *      не достаёт: срок там пять минут, а обрыв TLS и негодный кадр стенд не изображает.
 *
 * Файл включает исходник моста: alt_init, ws_upgrade и tls_start статические (тот же приём,
 * что в dcmatch.c, msgsplitmatch.c, warmmatch.c и upmatch.c). Выделение памяти считается
 * обёртками, подставленными макросом ДО включения tgws.c: заголовки к этому моменту уже
 * прочитаны, так что обёртка касается только кода моста. */
#define _GNU_SOURCE
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <signal.h>
#include <sys/wait.h>

static long live_allocs;
static void *t_malloc(size_t n) { void *p = malloc(n); if (p) live_allocs++; return p; }
static void t_free(void *p) { if (p) live_allocs--; free(p); }
#define malloc(n) t_malloc(n)
#define free(p) t_free(p)
#include "../src/proto/tgws/tgws.c"
#undef malloc
#undef free

/* Заглушки того, что мост берёт из соседних файлов. Источник случайности отказывает по
 * просьбе стенда; рукопожатие TLS изображает ровно тот путь tls13.c, на котором ключ записи
 * уже развёрнут, а ключ чтения — нет, и возвращает отказ. */
static int rand_fail;
int xc_random(unsigned char *out, size_t n) { memset(out, 0, n); return rand_fail ? -1 : 0; }
int xc_x25519_keypair(unsigned char priv[32], unsigned char pub[32])
                                        { memset(priv, 0, 32); memset(pub, 0, 32); return 0; }
int reality_build_hello_carry(const struct reality_cfg *cfg, struct reality_state *st,
                              const struct reality_carrier *car,
                              unsigned char *out, size_t out_n, size_t *out_len)
                                        { (void)cfg; (void)st; (void)car; (void)out_n;
                                          memset(out, 0x16, 5); *out_len = 5; return 0; }
int tls13_handshake(struct tls13 *t, int fd, const unsigned char *ch, size_t n,
                    const unsigned char *ss)
                                        { (void)fd; (void)ch; (void)n; (void)ss;
                                          t->wr.ctx_ready = 1; return TLS13_ECRYPTO; }
int tls13_has_record(const struct tls13 *t) { (void)t; return 0; }
int tls13_write(struct tls13 *t, const unsigned char *d, size_t n)
                                        { (void)t; (void)d; (void)n; return -1; }
int tls13_read(struct tls13 *t, unsigned char *o, size_t c, size_t *g)
                                        { (void)t; (void)o; (void)c; *g = 0; return -1; }
void tls13_free(struct tls13 *t) { t->wr.ctx_ready = 0; t->rd.ctx_ready = 0; }
int tls12_handshake(struct tls13 *t, int fd, const char *sni)
{ (void)t; (void)fd; (void)sni; return -1; }
void mbedtls_aes_init(mbedtls_aes_context *c) { (void)c; }
void mbedtls_aes_free(mbedtls_aes_context *c) { (void)c; }
int mbedtls_aes_setkey_enc(mbedtls_aes_context *c, const unsigned char *k, unsigned int b)
                                        { (void)c; (void)k; (void)b; return 0; }
int mbedtls_aes_crypt_ctr(mbedtls_aes_context *c, size_t n, size_t *off, unsigned char *nc,
                          unsigned char *sb, const unsigned char *in, unsigned char *out)
                                        { (void)c; (void)off; (void)nc; (void)sb;
                                          memcpy(out, in, n); return 0; }
/* Мосту (cmd_tgws) эти две функции нужны на этапе разбора спеки — этот стенд его не зовёт, но
 * символы обязаны разрешиться на линковке: спека — значение, а не глобалы (правило 6,
 * docs/architecture.md, раздел 2), поэтому здесь больше нет и мока g_out/g_out_n — cmd_tgws с
 * этого шага держит свой static struct spec сам. */
int load_spec(const char *path, struct spec *s, struct err *e) { (void)path; (void)s; (void)e; return 0; }
int registry_assign(struct spec *s, struct err *e) { (void)s; (void)e; return 0; }
const struct tgws_cfg *out_tgws(const struct output *o) { (void)o; return NULL; }

static int fails;

static void eq(const char *what, long got, long want) {
    if (got == want) { printf("%-62s ok\n", what); return; }
    printf("%-62s БРАК: получили %ld, ждали %ld\n", what, got, want);
    fails++;
}

static void eqs(const char *what, const char *got, const char *want) {
    if (!strcmp(got, want)) { printf("%-62s ok\n", what); return; }
    printf("%-62s БРАК: получили «%s», ждали «%s»\n", what, got, want);
    fails++;
}

static void pump_pairs(int c[2], int sp[2]) {
    if (socketpair(AF_UNIX, SOCK_STREAM, 0, c) != 0 ||
        socketpair(AF_UNIX, SOCK_STREAM, 0, sp) != 0) { perror("socketpair"); exit(1); }
}

static void pump_close(int c[2], int sp[2]) {
    for (int i = 0; i < 2; i++) {
        if (c[i] >= 0) close(c[i]);
        if (sp[i] >= 0) close(sp[i]);
    }
}

/* Один прогон pump на голом транспорте без нарезки; возвращает длительность в мс. */
static long run_pump(int cfd, int ufd, struct pump_stat *st) {
    struct upstream u;
    struct msgsplit ms;
    memset(&u, 0, sizeof(u));
    memset(&ms, 0, sizeof(ms));
    u.fd = ufd;
    long long t0 = mono_ms();
    pump(cfd, &u, st, &ms);
    return (long)(mono_ms() - t0);
}

int main(void) {
    /* ---- 1. alt_init: длинная строка ------------------------------------------------
     *
     * Две длины, потому что до правки они ломались по-разному: 140 байт влезали в буфер
     * чтения и урезались до 127 — мост звонил в имя, которого человек не писал; 300 байт
     * не влезали и в буфер чтения, и хвост строки читался следующей «строкой» — то есть из
     * одной строки получалось два чужих имени. Правильный исход у обеих один: строки нет,
     * соседи на месте. */
    {
        char path[] = "/tmp/tgwsfailmatch-XXXXXX";
        int fd = mkstemp(path);
        FILE *f = fdopen(fd, "w");
        char l140[141], l300[301];
        memset(l140, 'a', 136); memcpy(l140 + 136, ".com", 5);
        memset(l300, 'b', 296); memcpy(l300 + 296, ".com", 5);
        fprintf(f, "first.example\n%s\n%s\nlast.example\n", l140, l300);
        fclose(f);
        setenv("STEER_TGWS_DOMAINS", path, 1);
        g_alt_n = 0;
        alt_init();
        unlink(path);
        eq("список с двумя слишком длинными: принято только два", (long)g_alt_n, 2);
        eqs("первый домен на месте", g_alt_n > 0 ? g_alt[0] : "", "first.example");
        eqs("домен после длинных строк на месте", g_alt_n > 1 ? g_alt[1] : "", "last.example");
    }

    /* ---- 2. ws_upgrade: отказ источника случайности -----------------------------------
     *
     * Буфер ответа выделяется до ключа Sec-WebSocket-Key, и отказ xc_random — первый выход
     * после выделения. Через ws_upgrade идёт каждый дозвон, включая фоновые дозвоны запаса,
     * так что при отказе случайности утечка шла бы по буферу на попытку. Смотрим баланс
     * выделений моста до и после вызова. */
    {
        struct upstream u;
        memset(&u, 0, sizeof(u));
        u.fd = -1;
        rand_fail = 1;
        long before = live_allocs;
        int rc = ws_upgrade(&u, "kws2.example");
        rand_fail = 0;
        eq("ws_upgrade без случайных байт: отказ", rc, -1);
        eq("ws_upgrade без случайных байт: буфер ответа освобождён", live_allocs - before, 0);
    }

    /* ---- 3. tls_start: отказ рукопожатия после разворота ключа записи ----------------
     *
     * tls_on выставляется только после успешного рукопожатия, поэтому вызывающие на отказе
     * ключей не освобождают. В tls13.c есть путь, где ключ записи уже развёрнут, а ключ
     * чтения отказал, — заглушка рукопожатия изображает ровно его. Hello уходит в пару
     * сокетов, чтобы up_write было куда писать. */
    {
        int sv[2];
        if (socketpair(AF_UNIX, SOCK_STREAM, 0, sv) != 0) { perror("socketpair"); return 1; }
        struct upstream u;
        memset(&u, 0, sizeof(u));
        u.fd = sv[0];
        int rc = tls_start(&u, "kws2.example");
        eq("tls_start при отказе рукопожатия: отказ", rc, -1);
        eq("и соединение не считается зашифрованным", u.tls_on, 0);
        eq("и ключ записи не остался развёрнутым", u.tls.wr.ctx_ready, 0);
        close(sv[0]);
        close(sv[1]);
    }

    /* ---- 4. pump: срок затишья и причины конца ----------------------------------------
     *
     * Обе стороны — пары сокетов: клиент на c[0] (его конец у стенда — c[1]), точка на s[0]
     * (её конец — s[1]). Транспорт голый (tls_on = 0), нарезка выключена: проверяется
     * цикл переливания, а не TLS и не разбор пакетов. Срок затишья — одна секунда. */
    signal(SIGPIPE, SIG_IGN);
    {
        int c[2], sp[2];
        struct pump_stat st;
        long ms;

        /* 4а. Полная тишина: сессия кончается сроком, а не висит. */
        pump_pairs(c, sp);
        memset(&st, 0, sizeof(st)); st.idle_s = 1;
        ms = run_pump(c[0], sp[0], &st);
        eqs("тишина в обе стороны: причина", st.why ? st.why : "(нет)", "срок затишья вышел");
        eq("тишина в обе стороны: конец за 1..2 с", ms >= 900 && ms < 2000, 1);
        pump_close(c, sp);

        /* 4б. Точка пингует каждые 250 мс, данных нет: ping — не разговор, срок идёт. */
        pump_pairs(c, sp);
        pid_t kid = fork();
        if (kid == 0) {
            static const unsigned char ping[] = { 0x89, 0x02, 'h', 'i' };
            int pongs = 0;
            for (int i = 0; i < 16; i++) {
                if (send(sp[1], ping, sizeof(ping), MSG_NOSIGNAL) != (ssize_t)sizeof(ping)) break;
                usleep(250 * 1000);
                unsigned char b[64];
                ssize_t r;
                while ((r = recv(sp[1], b, sizeof(b), MSG_DONTWAIT)) > 0)
                    for (ssize_t k = 0; k < r; k++) if (b[k] == 0x8a) pongs++;
                if (r == 0) break;
            }
            _exit(pongs > 250 ? 250 : pongs);
        }
        memset(&st, 0, sizeof(st)); st.idle_s = 1;
        ms = run_pump(c[0], sp[0], &st);
        pump_close(c, sp);
        int ws = 0;
        waitpid(kid, &ws, 0);
        eqs("только ping от точки: причина", st.why ? st.why : "(нет)", "срок затишья вышел");
        eq("только ping от точки: конец за 1..2 с, ping срок не продлил",
           ms >= 900 && ms < 2000, 1);
        eq("и на ping ушёл pong", WIFEXITED(ws) && WEXITSTATUS(ws) > 0, 1);

        /* 4в. Данные от точки каждые 300 мс в течение двух секунд: сессия живёт, пока они
         * идут, и кончается сроком после них. */
        pump_pairs(c, sp);
        kid = fork();
        if (kid == 0) {
            static const unsigned char data[] = { 0x82, 0x04, 1, 2, 3, 4 };
            for (int i = 0; i < 7; i++) {
                if (send(sp[1], data, sizeof(data), MSG_NOSIGNAL) != (ssize_t)sizeof(data)) break;
                usleep(300 * 1000);
            }
            pause();
            _exit(0);
        }
        memset(&st, 0, sizeof(st)); st.idle_s = 1;
        ms = run_pump(c[0], sp[0], &st);
        kill(kid, SIGKILL);
        waitpid(kid, NULL, 0);
        pump_close(c, sp);
        eqs("данные от точки, потом тишина: причина", st.why ? st.why : "(нет)",
            "срок затишья вышел");
        eq("данные от точки продлевают срок: сессия дольше 2 с", ms >= 2000 && ms < 4000, 1);
        eq("и все данные дошли клиенту", (long)st.down, 7 * 4);

        /* 4г. Точка закрыла соединение. */
        pump_pairs(c, sp);
        close(sp[1]); sp[1] = -1;
        memset(&st, 0, sizeof(st)); st.idle_s = 1;
        run_pump(c[0], sp[0], &st);
        eqs("точка закрыла соединение: причина", st.why ? st.why : "(нет)",
            "точка закрыла соединение");
        pump_close(c, sp);

        /* 4д. Замаскированный кадр от точки — нарушение RFC 6455, а не затишье. */
        pump_pairs(c, sp);
        {
            static const unsigned char bad[] = { 0x82, 0x81, 0, 0, 0, 0, 7 };
            send(sp[1], bad, sizeof(bad), MSG_NOSIGNAL);
        }
        memset(&st, 0, sizeof(st)); st.idle_s = 1;
        run_pump(c[0], sp[0], &st);
        eqs("негодный кадр: причина", st.why ? st.why : "(нет)", "ошибка кадра веб-сокета");
        pump_close(c, sp);

        /* 4е. Кадр close от точки. */
        pump_pairs(c, sp);
        {
            static const unsigned char cl[] = { 0x88, 0x00 };
            send(sp[1], cl, sizeof(cl), MSG_NOSIGNAL);
        }
        memset(&st, 0, sizeof(st)); st.idle_s = 1;
        run_pump(c[0], sp[0], &st);
        eqs("close от точки: причина", st.why ? st.why : "(нет)", "точка закрыла веб-сокет");
        pump_close(c, sp);

        /* 4ж. Клиент закрыл. */
        pump_pairs(c, sp);
        close(c[1]); c[1] = -1;
        memset(&st, 0, sizeof(st)); st.idle_s = 1;
        run_pump(c[0], sp[0], &st);
        eqs("клиент закрыл: причина", st.why ? st.why : "(нет)", "клиент закрыл");
        pump_close(c, sp);
    }

    printf("\n%s\n", fails ? "ЕСТЬ БРАК" : "все проверки прошли");
    return fails ? 1 : 0;
}
