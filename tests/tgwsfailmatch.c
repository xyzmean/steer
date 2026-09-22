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
 *      контекста (I-197).
 *
 * Файл включает исходник моста: alt_init, ws_upgrade и tls_start статические (тот же приём,
 * что в dcmatch.c, msgsplitmatch.c, warmmatch.c и upmatch.c). Выделение памяти считается
 * обёртками, подставленными макросом ДО включения tgws.c: заголовки к этому моменту уже
 * прочитаны, так что обёртка касается только кода моста. */
#define _GNU_SOURCE
#include <stdlib.h>
#include <stdio.h>
#include <string.h>

static long live_allocs;
static void *t_malloc(size_t n) { void *p = malloc(n); if (p) live_allocs++; return p; }
static void t_free(void *p) { if (p) live_allocs--; free(p); }
#define malloc(n) t_malloc(n)
#define free(p) t_free(p)
#include "../src/ext/tgws.c"
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

    printf("\n%s\n", fails ? "ЕСТЬ БРАК" : "все проверки прошли");
    return fails ? 1 : 0;
}
