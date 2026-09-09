/* Чем в мосту обозначено «дескриптора нет» — и что бывает, когда ядро выдаёт ноль.
 *
 * ЗАЧЕМ ОТДЕЛЬНЫЙ СТЕНД. Ноль — совершенно годный дескриптор. Он достаётся первому же
 * socket(), если стандартный ввод закрыт, а служба, поднятая через procd с
 * перенаправлением, именно такой и бывает. Пока отсутствие соединения обозначалось нулём,
 * ветка отката в `serve` (`if (u.fd > 0)`) на таком соединении не срабатывала вовсе:
 * контекст AEAD в 18 КБ не освобождался, сокет к чужому домену оставался открытым, клиент
 * уходил на relay_direct и жил дальше. Это I-204, и заметить её прогоном было нечем:
 * `tests/run-tgws.sh` поднимает настоящий бинарь, у которого стандартный ввод на месте, и
 * дескриптор ноль там не достаётся никому.
 *
 * ЧТО ЗДЕСЬ ПРОВЕРЯЕТСЯ. Не `serve` целиком — ему нужны клиент, точка и рукопожатие, — а
 * `up_drop`: то единственное место, где теперь живёт ответ на вопрос «соединение есть или
 * нет». Три случая, и третий — тот самый:
 *
 *   1) обычное соединение (дескриптор больше нуля) закрывается;
 *   2) пустая структура после memset + часового -1 не закрывает НИЧЕГО (иначе `up_drop`
 *      на недозвонившемся соединении закрывал бы чужой дескриптор);
 *   3) соединение с дескриптором НОЛЬ закрывается — до правки не закрывалось.
 *
 * Дескриптор ноль стенд получает честно: закрывает свой стандартный ввод и открывает
 * /dev/null, которому ядро обязано отдать наименьший свободный номер. Обратно он не
 * восстанавливается — стенд ничего со стандартного ввода не читает, а печатает в stdout,
 * который не трогали.
 *
 * Файл включает исходник моста: `up_drop` статическая, и дотянуться до неё иначе значило бы
 * объявить её в заголовке ради стенда (тот же приём, что в dcmatch.c, msgsplitmatch.c и
 * warmmatch.c). */
#include "../src/ext/tgws.c"

#include <dirent.h>

/* Заглушки того, что мост берёт из соседних файлов: настоящий TLS стенду не нужен —
 * освобождение ключей он наблюдает по своему счётчику, а не по внутренностям mbedtls. */
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

/* Освобождение ключей наблюдается счётчиком: настоящий tls13_free тянул бы за собой mbedtls,
 * а вопрос стенда — не как освобождают, а освобождают ли вообще. */
static int frees;
void tls13_free(struct tls13 *t) { (void)t; frees++; }

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

/* Живой ли дескриптор. Наблюдаемое напрямую и без догадок: закрытый отвечает EBADF. */
static int alive(int fd) { return fcntl(fd, F_GETFD) != -1; }

/* Сколько дескрипторов открыто у процесса — тем же способом, что в tests/vlessmatch.c. */
static int fd_count(void) {
    DIR *d = opendir("/proc/self/fd");
    if (!d) return -1;
    int n = 0;
    struct dirent *e;
    while ((e = readdir(d))) if (e->d_name[0] != '.') n++;
    closedir(d);
    return n;
}

int main(void) {
    /* ---- 1. обычное соединение ---------------------------------------------------- */
    {
        struct upstream u;
        memset(&u, 0, sizeof(u));
        u.fd = open("/dev/null", O_RDONLY);
        u.tls_on = 1;
        frees = 0;
        eq("обычное соединение: дескриптор получен", u.fd > 0, 1);
        int fd = u.fd;
        up_drop(&u);
        eq("обычное соединение: дескриптор закрыт", alive(fd), 0);
        eq("обычное соединение: ключи освобождены", frees, 1);
        eq("обычное соединение: структура снова означает «нет»", u.fd, -1);
        eq("и ключей в ней тоже больше нет", u.tls_on, 0);
    }

    /* ---- 2. соединения не было ------------------------------------------------------
     *
     * Ровно тот случай, ради которого условие вообще существует: dial_upstream вернул
     * отказ и `u` так и остался после memset. Закрывать нечего, и `up_drop` не имеет права
     * закрыть чужое — поэтому проверяется не только «ничего не сломалось», а число
     * дескрипторов процесса до и после. */
    {
        int before = fd_count();
        struct upstream u;
        memset(&u, 0, sizeof(u));
        u.fd = -1;
        frees = 0;
        up_drop(&u);
        eq("дозвона не было: ни один дескриптор не закрыт", fd_count(), before);
        eq("дозвона не было: ключи не освобождались", frees, 0);
        eq("дозвона не было: структура так и означает «нет»", u.fd, -1);

        /* И дважды подряд — тоже ничего: после up_drop структура означает «нет», значит
         * повторный вызов обязан быть безвредным (в serve он и случается, когда откат
         * прошёл, а дальше по коду встречается общий выход). */
        up_drop(&u);
        eq("повторный вызов безвреден", fd_count(), before);
    }

    /* ---- 3. дескриптор НОЛЬ — сама находка I-204 -------------------------------------
     *
     * До правки здесь стояло `if (u.fd > 0)`, и ноль означал сразу две вещи: «дескриптора
     * нет» и «дескриптор ноль». Второй смысл проигрывал молча. */
    {
        close(0);                       /* стандартный ввод стенду не нужен */
        int z = open("/dev/null", O_RDONLY);
        eq("ядро выдало дескриптор ноль", z, 0);

        struct upstream u;
        memset(&u, 0, sizeof(u));
        u.fd = z;
        u.tls_on = 1;
        frees = 0;
        up_drop(&u);
        eq("дескриптор ноль закрыт (I-204)", alive(0), 0);
        eq("ключи при этом освобождены", frees, 1);
        eq("структура означает «нет» через -1, а не через ноль", u.fd, -1);
    }

    if (fails) { printf("\nбрак: %d\n", fails); return 1; }
    printf("\nосвобождение соединения наверх: все проверки прошли\n");
    return 0;
}
