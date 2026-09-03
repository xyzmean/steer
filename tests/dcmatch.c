/* Таблица дата-центров Telegram: адрес назначения → номер ДЦ.
 *
 * ЗАЧЕМ ОТДЕЛЬНЫЙ СТЕНД. Мост берёт номер ДЦ из адреса, куда шёл клиент, и пишет его в хвост
 * рукопожатия. Ошибка здесь не видна ничем: соединение устанавливается, точка отвечает, а
 * ключ клиента не подходит к чужому ДЦ — Telegram просто не работает. Именно так и вышло на
 * живом роутере: таблица знала девять адресов поимённо, клиент пошёл на 149.154.167.222, мост
 * сказал «не наш дата-центр» и пропустил соединение мимо себя.
 *
 * Файл включает исходник моста: dc_of и dc_add статические, и дотянуться до них иначе
 * значило бы добавить в движок подкоманду ради стенда (тот же приём, что в dnsmatch.c). */
#include "../src/ext/tgws.c"

/* Заглушки того, что мост берёт из соседних файлов: стенд проверяет одну таблицу, и тянуть
 * ради неё TLS-часть значило бы собирать полдвижка с настоящим mbedtls. */
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

static void eq(const char *ip, short want_dc, short want_media, const char *what) {
    struct in_addr a;
    short media = 0;
    short dc;
    inet_pton(AF_INET, ip, &a);
    dc = dc_of(a.s_addr, &media);
    if (dc == want_dc && media == want_media) {
        printf("%-46s ok\n", what);
        return;
    }
    printf("%-46s БРАК: %s → ДЦ %d%s, ждали %d%s\n", what, ip,
           dc, media ? " (медийный)" : "", want_dc, want_media ? " (медийный)" : "");
    fails++;
}

int main(void) {
    dc_table_init();

    /* Ровно тот случай, из-за которого Telegram не работал на живом роутере. */
    eq("149.154.167.41",  2, 0, "соседний адрес подсети — тот же ДЦ");
    eq("149.154.167.40",  2, 0, "и ещё один соседний");

    /* Поимённые записи обязаны перекрывать подсеть: маска длиннее. */
    eq("149.154.167.91",  4, 0, "исключение внутри подсети сильнее");
    eq("149.154.167.51",  2, 0, "адрес и подсеть говорят одно");
    eq("149.154.175.100", 3, 0, "третий ДЦ в подсети первого");
    eq("149.154.175.50",  1, 0, "первый ДЦ");

    /* МЕДИЙНЫМИ АДРЕСА НЕ ПОМЕЧАЮТСЯ — см. пояснение в таблице. Клиент не говорит, медийное
     * ли это соединение, и наша догадка по адресу ломала отправку сообщений: точка отдавала
     * клиента файловому серверу. Обычная точка обслуживает и переписку, и файлы. */
    eq("149.154.164.250", 4, 0, "адрес не помечен медийным");
    eq("149.154.167.151", 2, 0, "и этот тоже");
    eq("149.154.167.222", 2, 0, "самый нагруженный адрес — обычный ДЦ2");
    eq("149.154.165.96",  4, 0, "подсеть четвёртого ДЦ");

    /* Подсети целиком. */
    eq("91.108.56.200",   5, 0, "подсеть /22 пятого ДЦ");
    eq("91.105.192.7",    2, 0, "подсеть /23");

    /* Чужое остаётся чужим: иначе мост перехватывал бы то, что должен пропускать. */
    eq("8.8.8.8",         0, 0, "чужой адрес — не наш ДЦ");
    eq("149.155.167.51",  0, 0, "соседняя чужая сеть — не наш ДЦ");

    /* Файл дополняет встроенную таблицу и перекрывает её при равной маске. */
    dc_add("203.0.113.0/24", 3, 0);
    eq("203.0.113.9",     3, 0, "запись из файла работает");
    dc_add("203.0.113.9",  4, 1);
    eq("203.0.113.9",     4, 1, "адрес из файла точнее подсети");
    dc_add("203.0.113.0/24", 5, 0);
    eq("203.0.113.10",    5, 0, "повтор той же маски заменяет прежнюю");

    if (fails) { printf("\nбрак: %d\n", fails); return 1; }
    printf("\nтаблица дата-центров: все проверки прошли\n");
    return 0;
}
