/* Запас поднятых соединений моста Telegram: что решает один проход наполнителя.
 *
 * ЗАЧЕМ ОТДЕЛЬНЫЙ СТЕНД. Запас (`warm_*`) заведён ради одной вещи: клиент не должен платить
 * рукопожатием TLS к чужому общественному домену за каждое соединение. Ошибка здесь не видна
 * ничем — соединения устанавливаются, мессенджер работает, — но мост либо жжёт рукопожатия
 * впустую, либо отдаёт клиенту готовое соединение, которого уже нет. `tests/run-tgws.sh`
 * поднимает настоящий бинарь и наполнитель на нём РАБОТАЕТ, только ни одна проверка о нём
 * ничего не утверждала.
 *
 * ПОТОКОВ ЗДЕСЬ НЕТ НАРОЧНО. Наполнитель живёт отдельным потоком, но проверять чередования —
 * значит завести мигающий стенд, а он хуже отсутствующего. Поэтому тело прохода вынесено в
 * `warm_pass()` и зовётся отсюда из главного потока, а дозвон подставляется параметром: в
 * сеть стенд не ходит вовсе и проверяет не дозвон, а РЕШЕНИЕ прохода — дозваниваться или нет.
 *
 * Файл включает исходник моста: `warm_*` статические, и дотянуться до них иначе значило бы
 * добавить в движок подкоманду ради стенда (тот же приём, что в dcmatch.c и msgsplitmatch.c). */
#include "../src/ext/tgws.c"

/* Заглушки того, что мост берёт из соседних файлов: стенд не поднимает ни одного настоящего
 * соединения, и тянуть ради него TLS-часть значило бы собирать полдвижка с настоящим mbedtls. */
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

static void ok(const char *what) { printf("%-58s ok\n", what); }

static void eq(const char *what, long got, long want) {
    if (got == want) { ok(what); return; }
    printf("%-58s БРАК: получили %ld, ждали %ld\n", what, got, want);
    fails++;
}

/* ---- подставной дозвон ---------------------------------------------------------------- */

static int dials;                       /* сколько раз проход РЕШИЛ дозваниваться */
static int dial_ok = 1;                 /* 0 — «точка недоступна», как при 503 */

static int fake_dial(short dc, short media, struct upstream *u_out,
                     char *sni_out, size_t sni_cap, int *tries_out) {
    dials++;
    if (tries_out) *tries_out = 1;
    if (!dial_ok) return 0;
    memset(u_out, 0, sizeof(*u_out));
    /* Настоящий дескриптор, а не выдуманное число: проход закрывает соединение, которому не
     * нашлось места, и уборка тухлого зовёт close() — с выдуманным номером стенд закрывал бы
     * чужой дескриптор своего же процесса. */
    u_out->fd = open("/dev/null", O_RDONLY);
    snprintf(sni_out, sni_cap, "kws%d%s.stand", dc, media ? "-1" : "");
    return u_out->fd >= 0;
}

static void reset(void) {
    for (size_t i = 0; i < WARM_SLOTS; i++)
        if (g_warm[i].busy && g_warm[i].u.fd >= 0) close(g_warm[i].u.fd);
    memset(g_warm, 0, sizeof(g_warm));
    memset(g_want, 0, sizeof(g_want));
    dials = 0;
    dial_ok = 1;
}

static int busy_n(void) {
    int n = 0;
    for (size_t i = 0; i < WARM_SLOTS; i++) if (g_warm[i].busy) n++;
    return n;
}

static int busy_for(short dc, short media) {
    int n = 0;
    for (size_t i = 0; i < WARM_SLOTS; i++)
        if (g_warm[i].busy && g_warm[i].dc == dc && g_warm[i].media == media) n++;
    return n;
}

int main(void) {
    struct upstream u;
    char sni[160];

    /* ---- сколько держим на пару ------------------------------------------------------- */

    reset();
    warm_want_mark(2, 0);
    warm_pass(fake_dial);
    eq("за проход пара получает одно соединение, не больше", dials, 1);
    warm_pass(fake_dial);
    eq("второй проход добирает до WARM_PER_DC", busy_for(2, 0), 2);
    dials = 0;
    warm_pass(fake_dial);
    eq("на пару держим ровно WARM_PER_DC, дальше не дозваниваемся", dials, 0);

    /* ---- отдача клиенту --------------------------------------------------------------- */

    eq("готовое соединение отдаётся клиенту", warm_take(2, 0, &u, sni, sizeof(sni)), 1);
    eq("отданное из запаса убрано", busy_for(2, 0), 1);
    close(u.fd);
    eq("чужой ДЦ из запаса не берут", warm_take(3, 0, &u, sni, sizeof(sni)), 0);
    eq("медийное соединение обычному не отдают", warm_take(2, 1, &u, sni, sizeof(sni)), 0);

    /* Тухлое не отдаётся: соединение старше срока точка уже закрыла или закроет вот-вот. */
    for (size_t i = 0; i < WARM_SLOTS; i++)
        if (g_warm[i].busy) g_warm[i].born = time(NULL) - (WARM_TTL_S + 1);
    eq("тухлое соединение клиенту не отдают", warm_take(2, 0, &u, sni, sizeof(sni)), 0);

    dial_ok = 0;                        /* чтобы проход только убирал, но ничего не добирал */
    warm_pass(fake_dial);
    eq("тухлый слот убирает проход", busy_n(), 0);

    /* ---- отказ дозвона ---------------------------------------------------------------- */

    /* 503 у общественного домена — обычное дело, а не поломка: слот при этом не занимается. */
    reset();
    warm_want_mark(4, 1);
    dial_ok = 0;
    warm_pass(fake_dial);
    eq("отказавший дозвон в запас ничего не кладёт", busy_n(), 0);
    eq("но попытка была", dials, 1);

    /* ---- пар больше, чем вмещает запас ------------------------------------------------ */

    /* Ёмкость запаса — WARM_SLOTS / WARM_PER_DC = четыре пары «ДЦ + медиа», а список желаний
     * держит десять, и десять достижимы обычным клиентом: dc 1..5 при media 0/1. Пятая пара
     * места не получит никогда, и дозваниваться ради неё — значит платить полным рукопожатием
     * TLS к общественному домену каждый проход, вечно, и тут же закрывать соединение. */
    reset();
    for (short dc = 1; dc <= 5; dc++) warm_want_mark(dc, 0);
    for (int i = 0; i < 4; i++) warm_pass(fake_dial);
    eq("четыре пары занимают запас целиком", busy_n(), WARM_SLOTS);

    dials = 0;
    warm_pass(fake_dial);
    eq("при полном запасе проход не дозванивается", dials, 0);
    eq("и запас не пострадал", busy_n(), WARM_SLOTS);

    reset();
    if (fails) { printf("\nбрак: %d\n", fails); return 1; }
    printf("\nзапас соединений: все проверки прошли\n");
    return 0;
}
