/* Ветви отказа vless_connect: дескриптор и ключи после каждого «нет».
 *
 * ЗАЧЕМ ОТДЕЛЬНЫМ СТЕНДОМ. У установления соединения с узлом VLESS не было ни одного
 * стенда, который доходит до TLS. tests/fake-vless.py говорит только security=none и до
 * рукопожатия не добирается; tests/run-reality.sh требует sing-box, root и сетевых
 * пространств, поэтому не входит ни в `make test`, ни в `make ext-test`. Всё, что охраняло
 * здесь освобождение — чтение кода глазами, тогда как у xsteer на ту же болезнь (I-067)
 * стенд стоит под AddressSanitizer с запуска 42. Разрыв назван в R-114; этот файл его
 * закрывает.
 *
 * ЧТО ИМЕННО ПРОВЕРЯЕТСЯ. У vless_connect ДЕВЯТЬ путей выхода по ошибке (client.c:717, 737,
 * 739, 769, 777, 792, 822, 825, 827) и три успешных, и каждый путь отказа сам решает, чем
 * закрыться: четыре зовут close(fd), четыре — vless_close(conn), а самый первый уходит до
 * того, как дескриптор появился. Перечисление с разбором — A-139. Выбор не косметический —
 * после развёртывания ключей трафика контексты AES/GCM живут в КУЧЕ (tls13.c:
 * mbedtls_gcm_setkey → mbedtls_cipher_setup → calloc), и дескриптор их не держит.
 * Вызывающие тоже не убирают: пул запасных сессий на отказе лишь помечает слот пустым, а
 * проверка узла возвращается сразу. Значит цена ошибки в выборе — утечка НА КАЖДУЮ попытку
 * при том, что попытки не кончаются: пул пополняется на каждый SYN, сторож перебирает узлы
 * пачками. Стенд наблюдает три вещи на каждой ветви: код возврата, дескрипторы процесса
 * (их число обязано вернуться к исходному) и кучу — через LeakSanitizer, отдельной
 * проверкой после каждого случая, а не одним отчётом на выходе.
 *
 * КАК ЭТО РАБОТАЕТ БЕЗ УЗЛА И БЕЗ СЕТИ. Установление TCP вынесено в шов g_tcp_dial
 * (src/ext/client.c) — так же, как замер задержки в failover.c. Стенд отдаёт клиенту конец
 * socketpair, а на другом конце сам говорит серверную половину TLS 1.3: разбирает
 * ClientHello, достаёт из него key_share, считает X25519, выводит расписание ключей
 * рукопожатия по RFC 8446 §7.1 и шлёт зашифрованные EncryptedExtensions, при надобности
 * Certificate, и Finished. Это ровно та половина, которой в проекте не было, и без неё до
 * серверного Finished не доходил ни один стенд.
 *
 * ПОЧЕМУ СЕРВЕРНАЯ ПОЛОВИНА ЗДЕСЬ, А НЕ НА ПИТОНЕ. Стенд живёт в `make ext-test`, и та же
 * цель запускается ВНУТРИ образа сборщика при релизе (build/ext-test-image.sh). Питона там
 * может не быть вовсе, а mbedtls есть по построению — на ней и собран сам движок. Вторая
 * причина: расписание ключей обязано совпасть с клиентским до байта, и когда обе половины
 * стоят на одной библиотеке, расхождение означает ошибку в нашем коде, а не разницу
 * реализаций.
 *
 * Нужен настоящий mbedtls (в куче лежит контекст AES — это и есть то, что может утечь),
 * поэтому в `make test` стенд не входит, как xsloop и spokematch.
 *
 * ВТОРАЯ ПОЛОВИНА: security=tls СО СВОИМИ КОРНЯМИ (R-118). Ветвей Reality мало для того,
 * чтобы охватить установление соединения целиком: у Reality доказательством служит HMAC в
 * поле подписи временного сертификата, и для ОТКАЗА проверки не нужно ни цепочки X.509, ни
 * хранилища корней — то есть все шесть случаев выше проходят мимо certverify.c, у которого
 * не было ни одного стенда. Главное же в том, что при отказе проверки соединение не
 * доходит до конца никогда, а ровно та ветвь, ради которой в клиенте появился vless_close
 * (VLESS_CONN_ENOH2, ключи уже развёрнуты и контексты AES/GCM лежат в куче), достижима
 * ТОЛЬКО через УДАВШУЮСЯ проверку сервера.
 *
 * Поэтому стенд выпускает цепочку сам: корень и лист на имя SNI, ключи ECDSA P-256, сроки
 * от текущего времени (замороженный в репозитории сертификат однажды истёк бы и покрасил
 * стенд не по своей вине). Корень уезжает файлом PEM, путь к нему отдаётся движку швом
 * g_cert_roots в client.c — вторым такой же природы, что g_tcp_dial. Серверная половина
 * подписывает CertificateVerify настоящей подписью над транскриптом по Certificate
 * включительно (RFC 8446 §4.4.3, приставка из 64 пробелов и метки), и клиент проверяет её
 * своим кодом, а не нашим: расхождение здесь означает ошибку в движке.
 *
 * Что этим накрыто: успех целиком (рукопожатие, проверка цепочки, имя против sni), ветвь
 * ENOH2 с её vless_close, имя не то, «не прислал подпись», подпись не сходится, алгоритм
 * подписи не из предложенных и лист, подписанный сам собой. Без второго стенда все семь
 * ветвей были недостижимы.
 *
 * Выпуск сертификатов требует MBEDTLS_X509_CRT_WRITE_C. Есть он не везде, и если его нет,
 * случаи security=tls ПРОПУСКАЮТСЯ ГРОМКО (проба в tests/ext-test.sh задаёт
 * STEER_HAVE_X509WRITE, стенд говорит о пропуске сам) — молчаливый пропуск читался бы как
 * «прошло», ровно как в I-232.
 */
/* До любого include: client.c просит расширения GNU, а первый подключённый заголовок
 * фиксирует набор. */
#define _GNU_SOURCE
#include <stdio.h>
#include <string.h>
#include <pthread.h>
#include <signal.h>
#include <dirent.h>
#include <stdint.h>

/* Исходник целиком, а не компоновка: шов g_tcp_dial статический, и дотянуться до него
 * иначе значило бы объявить его в client.h — то есть завести в движке публичную точку
 * подмены ради стенда. Тот же приём, что в tests/devupmatch.c и tests/failovermatch.c. */
#include "../src/ext/client.c"

#include "mbedtls/hkdf.h"
#include "mbedtls/md.h"
#include "mbedtls/gcm.h"
#include "mbedtls/sha256.h"
#include "mbedtls/version.h"
#if defined(STEER_HAVE_X509WRITE)
# include "mbedtls/x509_crt.h"
# include "mbedtls/pk.h"
# include "mbedtls/ecp.h"
# include "mbedtls/bignum.h"
#endif

/* Общий секрет с эфемерным ключом собеседника: та же функция, которой пользуется tls13.c,
 * а не копия — копия крипто-кода это два места, где может разойтись прижатие скаляра. */
int x25519_shared_ext(const unsigned char priv[32], const unsigned char peer[32],
                      unsigned char out[32]);

/* Заглушки того, что живёт в src/steer.c: ни команд, ни устройств стенду не нужно. */
int run_quiet(const char *const argv[]) { (void)argv; return 0; }
void bind_device(struct output *o, const char *dev) { (void)o; (void)dev; }

#if defined(__SANITIZE_ADDRESS__)
# include <sanitizer/lsan_interface.h>
# define LEAK_CHECK() __lsan_do_recoverable_leak_check()
#else
/* Санитайзера нет — проверки кода возврата и дескрипторов всё равно идут, а про кучу
 * стенд молчать не имеет права: молчаливый пропуск читается как «прошло». Громко
 * говорится один раз, в main. */
# define LEAK_CHECK() 0
#endif

static int fails;

static void check(const char *what, long want, long got) {
    printf("%-64s %s\n", what, want == got ? "ok" : "ПРОВАЛ");
    if (want != got) {
        printf("     хочу: %ld\n     есть:  %ld\n", want, got);
        fails++;
    }
}

static void check_str(const char *what, const char *want, const char *got) {
    int ok = got && strstr(got, want) != NULL;
    printf("%-64s %s\n", what, ok ? "ok" : "ПРОВАЛ");
    if (!ok) {
        printf("     хочу подстроку: %s\n     есть:           %s\n", want, got ? got : "(нет)");
        fails++;
    }
}

/* Сколько дескрипторов открыто у процесса. Наблюдаемое напрямую: утечку дескриптора видно
 * без всякого санитайзера, и ровно эта утечка (ветка ENOH2, узел grpc с security=reality)
 * упирала процесс в RLIMIT_NOFILE за сутки опроса. */
static int fd_count(void) {
    DIR *d = opendir("/proc/self/fd");
    if (!d) return -1;
    int n = 0;
    struct dirent *e;
    while ((e = readdir(d))) if (e->d_name[0] != '.') n++;
    closedir(d);
    return n;
}

/* ---- серверная половина TLS 1.3 ------------------------------------------------
 *
 * Ровно столько, сколько нужно, чтобы клиент дошёл до конца рукопожатия: один набор шифров
 * (0x1301, AES-128-GCM с SHA-256), одна группа (X25519), никакого возобновления. */

#define SUITE_HI 0x13
#define SUITE_LO 0x01
#define HLEN 32u                       /* SHA-256: и хеш транскрипта, и длина секретов */

struct plan {
    const char *name;
    int no_keyshare;      /* ServerHello без key_share — отказ ДО вывода ключей */
    int bad_finished;     /* испортить серверный Finished */
    int cert;             /* 0 — не присылать, 1 — мусорный Certificate, 2 — сжатый (0x19) */
    const char *alpn;     /* строка ALPN в EncryptedExtensions, или NULL */
    int hangup;           /* закрыть соединение сразу после ClientHello */
    /* Ниже — путь security=tls: настоящая цепочка, выпущенная стендом (R-118). Поле cert у
     * этих случаев не читается: чем именно отвечать, решает leaf. */
    int chain;            /* 0 — не путь tls; иначе номер листа из g_leaf[] */
    int no_cv;            /* прислать Certificate и НЕ прислать CertificateVerify */
    int cv_bad_sig;       /* испортить байт подписи */
    int cv_bad_alg;       /* подписать кодом, которого мы не предлагали (rsa_pkcs1_sha256) */
};

struct srv {
    int fd;
    const struct plan *plan;
    /* Ключи записи сервера и счётчик записей. */
    unsigned char key[16], iv[12];
    unsigned char s_hs[HLEN];
    uint64_t seq;
    mbedtls_sha256_context tr;         /* транскрипт рукопожатия */
    int rc;                            /* !=0 — половина сломалась сама, а не по замыслу */
};

static const mbedtls_md_info_t *md256(void) {
    return mbedtls_md_info_from_type(MBEDTLS_MD_SHA256);
}

/* HKDF-Expand-Label из RFC 8446 §7.1. Своя копия, а не вызов статической из tls13.c:
 * стенд обязан считать метку САМ, иначе ошибка в клиентской обёртке сошлась бы сама с
 * собой и осталась незамеченной. */
static int xlabel(const unsigned char *secret, const char *label,
                  const unsigned char *ctx, size_t ctx_n,
                  unsigned char *out, size_t out_n) {
    unsigned char info[128];
    size_t n = 0, ln = strlen(label);
    if (2 + 1 + 6 + ln + 1 + ctx_n > sizeof(info)) return -1;
    info[n++] = (unsigned char)(out_n >> 8);
    info[n++] = (unsigned char)out_n;
    info[n++] = (unsigned char)(6 + ln);
    memcpy(info + n, "tls13 ", 6); n += 6;
    memcpy(info + n, label, ln);    n += ln;
    info[n++] = (unsigned char)ctx_n;
    if (ctx_n) { memcpy(info + n, ctx, ctx_n); n += ctx_n; }
    return mbedtls_hkdf_expand(md256(), secret, HLEN, info, n, out, out_n);
}

static void tr_snapshot(const mbedtls_sha256_context *tr, unsigned char out[HLEN]) {
    mbedtls_sha256_context c;
    mbedtls_sha256_init(&c);
    mbedtls_sha256_clone(&c, tr);
    mbedtls_sha256_finish(&c, out);
    mbedtls_sha256_free(&c);
}

static int wr_all(int fd, const unsigned char *b, size_t n) {
    size_t sent = 0;
    while (sent < n) {
        ssize_t w = write(fd, b + sent, n - sent);
        if (w <= 0) return -1;
        sent += (size_t)w;
    }
    return 0;
}

static int rd_all(int fd, unsigned char *b, size_t n) {
    size_t got = 0;
    while (got < n) {
        ssize_t r = read(fd, b + got, n - got);
        if (r <= 0) return -1;
        got += (size_t)r;
    }
    return 0;
}

/* Одна запись: заголовок из пяти байт, затем тело. */
static int rd_rec(int fd, unsigned char *type, unsigned char *body, size_t cap, size_t *n) {
    unsigned char h[5];
    if (rd_all(fd, h, 5)) return -1;
    size_t len = ((size_t)h[3] << 8) | h[4];
    if (len > cap) return -1;
    if (rd_all(fd, body, len)) return -1;
    *type = h[0];
    *n = len;
    return 0;
}

/* ---- своя цепочка X.509 для security=tls (R-118) ------------------------------------
 *
 * Три листа, и каждый нужен ровно одной проверке:
 *   LEAF_OK   — на имя SNI, подписан корнем: единственный путь к УДАВШЕЙСЯ проверке, а
 *               значит и к ветви ENOH2, ради которой в клиенте появился vless_close;
 *   LEAF_NAME — тем же корнем, но на другое имя: проверка обязана отказать по имени, а не
 *               пропустить «цепочка же сошлась»;
 *   LEAF_SELF — подписан сам собой: корень не при чём, отказ по цепочке.
 *
 * Ключи ECDSA P-256, а не RSA: генерация RSA-2048 занимает секунды и делала бы стенд
 * заметно медленнее без всякой пользы для проверяемого — certverify.c принимает и то, и
 * другое, а подпись CertificateVerify проверяется одной и той же mbedtls_pk_verify.
 *
 * СРОКИ СЧИТАЮТСЯ ОТ ТЕКУЩЕГО ВРЕМЕНИ, а не зашиты строкой: замороженный сертификат
 * однажды истекает и красит стенд не по своей вине — это named risk у самого R-118, и
 * закрывается он тем, что срок выпускается заново на каждый прогон.
 */
#if defined(STEER_HAVE_X509WRITE)

#define LEAF_OK   1
#define LEAF_NAME 2
#define LEAF_SELF 3

/* Имя, на которое выпущен годный лист, и оно же уезжает в SNI узла: сертификат проверяется
 * против sni, а не против host (client.c, verify_host). */
#define TLS_SNI "tls.node.invalid"

struct leaf {
    unsigned char der[2048];
    size_t der_n;
    mbedtls_pk_context key;      /* ключ листа — им подписывается CertificateVerify */
};

static struct leaf g_leaf[4];        /* [0] не используется: номера совпадают с LEAF_* */
static char g_roots_file[64];
static int g_chain_ready;

/* RNG для mbedtls в форме обратного вызова. Своего DRBG стенд не поднимает: xc_random —
 * тот же источник, которым пользуется движок, и второй в одном процессе означал бы два
 * разных ответа на вопрос «откуда случайность». */
static int rng_cb(void *ctx, unsigned char *out, size_t n) {
    (void)ctx;
    return xc_random(out, n) == 0 ? 0 : -1;
}

static int gen_key(mbedtls_pk_context *k) {
    mbedtls_pk_init(k);
    const mbedtls_pk_info_t *info = mbedtls_pk_info_from_type(MBEDTLS_PK_ECKEY);
    if (!info || mbedtls_pk_setup(k, info) != 0) return -1;
    return mbedtls_ecp_gen_key(MBEDTLS_ECP_DP_SECP256R1, mbedtls_pk_ec(*k), rng_cb, NULL);
}

/* «YYYYMMDDHHMMSS» от текущего времени со сдвигом в сутках. */
static void when(int days, char out[16]) {
    time_t t = time(NULL) + (time_t)days * 24 * 3600;
    struct tm g;
    gmtime_r(&t, &g);
    snprintf(out, 16, "%04d%02d%02d%02d%02d%02d", g.tm_year + 1900, g.tm_mon + 1, g.tm_mday,
             g.tm_hour, g.tm_min, g.tm_sec);
}

/* Выписать сертификат. pem != NULL — вернуть заодно PEM (нужен только корню: хранилище
 * корней читается как PEM, см. roots_load в certverify.c). */
static int issue(const char *subject, mbedtls_pk_context *skey,
                 const char *issuer, mbedtls_pk_context *ikey, int is_ca,
                 unsigned char *der, size_t *der_n, char *pem, size_t pem_n) {
    mbedtls_x509write_cert c;
    mbedtls_x509write_crt_init(&c);
    mbedtls_x509write_crt_set_version(&c, MBEDTLS_X509_CRT_VERSION_3);
    mbedtls_x509write_crt_set_md_alg(&c, MBEDTLS_MD_SHA256);
    mbedtls_x509write_crt_set_subject_key(&c, skey);
    mbedtls_x509write_crt_set_issuer_key(&c, ikey);
    int rc = mbedtls_x509write_crt_set_subject_name(&c, subject);
    if (rc == 0) rc = mbedtls_x509write_crt_set_issuer_name(&c, issuer);
    if (rc == 0) rc = mbedtls_x509write_crt_set_basic_constraints(&c, is_ca, is_ca ? 1 : -1);

    /* Серийный номер. В 3.x старая форма через mbedtls_mpi объявлена устаревшей и в сборке
     * с MBEDTLS_DEPRECATED_REMOVED её нет вовсе, поэтому ветка по мажорной версии — та же
     * дисциплина, что у флага доступа к приватным полям в ext-test.sh. */
    if (rc == 0) {
#if MBEDTLS_VERSION_MAJOR >= 3
        unsigned char serial[] = { 0x01, 0x02, 0x03 };
        serial[2] = (unsigned char)is_ca + 1;
        rc = mbedtls_x509write_crt_set_serial_raw(&c, serial, sizeof(serial));
#else
        mbedtls_mpi sn;
        mbedtls_mpi_init(&sn);
        rc = mbedtls_mpi_lset(&sn, is_ca ? 1 : 2);
        if (rc == 0) rc = mbedtls_x509write_crt_set_serial(&c, &sn);
        mbedtls_mpi_free(&sn);
#endif
    }
    char nb[16], na[16];
    when(-1, nb);
    when(365 * 5, na);
    if (rc == 0) rc = mbedtls_x509write_crt_set_validity(&c, nb, na);

    if (rc == 0) {
        /* der пишется В КОНЕЦ буфера — так устроен mbedtls_x509write_crt_der, — поэтому
         * готовое сдвигается к началу: дальше оно уезжает в сообщение как есть. */
        int n = mbedtls_x509write_crt_der(&c, der, 2048, rng_cb, NULL);
        if (n < 0) rc = n;
        else {
            memmove(der, der + 2048 - n, (size_t)n);
            *der_n = (size_t)n;
        }
    }
    if (rc == 0 && pem)
        rc = mbedtls_x509write_crt_pem(&c, (unsigned char *)pem, pem_n, rng_cb, NULL);
    mbedtls_x509write_crt_free(&c);
    return rc;
}

/* Корень, три листа и файл хранилища. Один раз на процесс: certverify.c разбирает корни
 * под pthread_once, и второе хранилище в том же процессе не подействовало бы (I-217) —
 * значит все случаи обязаны проверяться ОДНИМ набором корней. */
static int chain_build(void) {
    mbedtls_pk_context root_key;
    if (gen_key(&root_key) != 0) return -1;

    static char pem[4096];
    unsigned char root_der[2048];
    size_t root_n = 0;
    if (issue("CN=steer test root", &root_key, "CN=steer test root", &root_key, 1,
              root_der, &root_n, pem, sizeof(pem)) != 0) return -1;

    struct { int idx; const char *cn; int self; } want[] = {
        { LEAF_OK,   "CN=" TLS_SNI,          0 },
        { LEAF_NAME, "CN=other.invalid",     0 },
        { LEAF_SELF, "CN=" TLS_SNI,          1 },
    };
    for (size_t i = 0; i < sizeof(want) / sizeof(*want); i++) {
        struct leaf *l = &g_leaf[want[i].idx];
        if (gen_key(&l->key) != 0) return -1;
        const char *issuer = want[i].self ? want[i].cn : "CN=steer test root";
        mbedtls_pk_context *ikey = want[i].self ? &l->key : &root_key;
        if (issue(want[i].cn, &l->key, issuer, ikey, 0, l->der, &l->der_n, NULL, 0) != 0)
            return -1;
    }

    snprintf(g_roots_file, sizeof(g_roots_file), "%s", "/tmp/vlessmatch-roots-XXXXXX");
    int fd = mkstemp(g_roots_file);
    if (fd < 0) return -1;
    size_t pn = strlen(pem);
    int ok = wr_all(fd, (const unsigned char *)pem, pn) == 0;
    close(fd);
    mbedtls_pk_free(&root_key);
    if (!ok) return -1;
    g_chain_ready = 1;
    return 0;
}

static void chain_free(void) {
    for (int i = 1; i <= LEAF_SELF; i++) mbedtls_pk_free(&g_leaf[i].key);
    if (g_roots_file[0]) unlink(g_roots_file);
}

/* Сообщение Certificate из одного листа (RFC 8446 §4.4.2): байт контекста, список из трёх
 * байт длины, в нём запись «три байта длины + DER + два байта расширений». Корень в
 * список не кладётся намеренно: он уже в хранилище, и цепочка обязана сойтись без него —
 * иначе стенд проверял бы не проверку, а щедрость сервера. */
static size_t cert_msg(const struct leaf *l, unsigned char *out, size_t cap) {
    size_t body = 1 + 3 + 3 + l->der_n + 2;
    if (4 + body > cap) return 0;
    size_t n = 0;
    out[n++] = 0x0B;
    out[n++] = (unsigned char)(body >> 16);
    out[n++] = (unsigned char)(body >> 8);
    out[n++] = (unsigned char)body;
    out[n++] = 0x00;                                     /* certificate_request_context */
    size_t list = 3 + l->der_n + 2;
    out[n++] = (unsigned char)(list >> 16);
    out[n++] = (unsigned char)(list >> 8);
    out[n++] = (unsigned char)list;
    out[n++] = (unsigned char)(l->der_n >> 16);
    out[n++] = (unsigned char)(l->der_n >> 8);
    out[n++] = (unsigned char)l->der_n;
    memcpy(out + n, l->der, l->der_n); n += l->der_n;
    out[n++] = 0x00; out[n++] = 0x00;                    /* extensions: пусто */
    return n;
}

/* CertificateVerify: подпись над 64 пробелами, меткой, нулём и хешем транскрипта по
 * Certificate включительно. Приставка собирается ЗДЕСЬ, а не берётся из certverify.c: две
 * половины обязаны прийти к одному ответу независимо, иначе ошибка в приставке сошлась бы
 * сама с собой. */
static size_t cv_msg(const struct leaf *l, const unsigned char thash[HLEN],
                     const struct plan *pl, unsigned char *out, size_t cap) {
    unsigned char content[64 + 33 + 1 + HLEN];
    size_t cn = 0;
    memset(content, 0x20, 64); cn = 64;
    memcpy(content + cn, "TLS 1.3, server CertificateVerify", 33); cn += 33;
    content[cn++] = 0x00;
    memcpy(content + cn, thash, HLEN); cn += HLEN;

    /* Без проверки кода возврата намеренно: в 2.x mbedtls_sha256 объявлена void (значение
     * возвращает mbedtls_sha256_ret), в 3.x — int, и ветка по версии здесь ничего бы не
     * дала. Так же зовёт её и расписание ключей выше. */
    unsigned char digest[HLEN];
    mbedtls_sha256(content, cn, digest, 0);

    unsigned char sig[MBEDTLS_PK_SIGNATURE_MAX_SIZE];
    size_t sig_n = 0;
#if MBEDTLS_VERSION_MAJOR >= 3
    if (mbedtls_pk_sign(&((struct leaf *)l)->key, MBEDTLS_MD_SHA256, digest, HLEN,
                        sig, sizeof(sig), &sig_n, rng_cb, NULL) != 0) return 0;
#else
    if (mbedtls_pk_sign(&((struct leaf *)l)->key, MBEDTLS_MD_SHA256, digest, HLEN,
                        sig, &sig_n, rng_cb, NULL) != 0) return 0;
#endif
    if (pl->cv_bad_sig) sig[sig_n / 2] ^= 0xFF;

    if (4 + 4 + sig_n > cap) return 0;
    size_t n = 0;
    out[n++] = 0x0F;
    out[n++] = 0; out[n++] = 0; out[n++] = (unsigned char)(4 + sig_n);
    /* 0x0403 — ecdsa_secp256r1_sha256, он в нашем signature_algorithms есть. 0x0401 —
     * rsa_pkcs1_sha256, которым в TLS 1.3 подписывать CertificateVerify запрещено, и мы
     * его не предлагаем: сервер, выбравший его, обязан получить отдельную причину, а не
     * «подпись не сошлась». */
    out[n++] = 0x04; out[n++] = pl->cv_bad_alg ? 0x01 : 0x03;
    out[n++] = (unsigned char)(sig_n >> 8);
    out[n++] = (unsigned char)sig_n;
    memcpy(out + n, sig, sig_n); n += sig_n;
    return n;
}
#endif /* STEER_HAVE_X509WRITE */

/* ClientHello: нужны серверная сторона обмена (key_share клиента) и session_id, который
 * сервер обязан вернуть как есть. Разбор по типам расширений, а не по смещениям: состав
 * Hello у reality.c меняется вместе с обликом браузера. */
static int ch_pick(const unsigned char *b, size_t n, unsigned char pub[32],
                   unsigned char *sid, size_t *sid_n) {
    if (n < 40 || b[0] != 0x01) return -1;
    size_t p = 4 + 2 + 32;
    size_t sn = b[p++];
    if (sn > 32 || p + sn > n) return -1;
    memcpy(sid, b + p, sn);
    *sid_n = sn;
    p += sn;
    if (p + 2 > n) return -1;
    size_t cs = ((size_t)b[p] << 8) | b[p + 1];
    p += 2 + cs;
    if (p >= n) return -1;
    p += 1 + b[p];                                  /* compression_methods */
    if (p + 2 > n) return -1;
    size_t exts = ((size_t)b[p] << 8) | b[p + 1];
    p += 2;
    size_t end = p + exts;
    if (end > n) return -1;
    while (p + 4 <= end) {
        unsigned etype = ((unsigned)b[p] << 8) | b[p + 1];
        size_t elen = ((size_t)b[p + 2] << 8) | b[p + 3];
        p += 4;
        if (p + elen > end) return -1;
        if (etype == 0x0033) {
            /* client_shares: длина списка(2), затем группа(2)+длина(2)+ключ. Берём именно
             * X25519 (0x001d): reality.c умеет предлагать и постквантовую группу, и она в
             * списке стоит первой. */
            size_t q = 2;
            while (q + 4 <= elen) {
                unsigned grp = ((unsigned)b[p + q] << 8) | b[p + q + 1];
                size_t kn = ((size_t)b[p + q + 2] << 8) | b[p + q + 3];
                if (q + 4 + kn > elen) break;
                if (grp == 0x001d && kn == 32) {
                    memcpy(pub, b + p + q + 4, 32);
                    return 0;
                }
                q += 4 + kn;
            }
        }
        p += elen;
    }
    return -1;
}

/* Зашифрованная запись рукопожатия: одно сообщение на запись — клиент собирает их через
 * границы записей, и так проверяется в том числе это. */
static int send_enc(struct srv *s, const unsigned char *msg, size_t n) {
    unsigned char out[4096];
    if (n + 1 + 16 + 5 > sizeof(out)) return -1;
    size_t total = n + 1 + 16;
    out[0] = 0x17; out[1] = 0x03; out[2] = 0x03;
    out[3] = (unsigned char)(total >> 8);
    out[4] = (unsigned char)total;
    memcpy(out + 5, msg, n);
    out[5 + n] = 0x16;                              /* настоящий тип записи */

    unsigned char nonce[12];
    memcpy(nonce, s->iv, 12);
    for (int i = 0; i < 8; i++) nonce[11 - i] ^= (unsigned char)(s->seq >> (8 * i));

    mbedtls_gcm_context g;
    mbedtls_gcm_init(&g);
    int rc = mbedtls_gcm_setkey(&g, MBEDTLS_CIPHER_ID_AES, s->key, 128);
    if (rc == 0)
        rc = mbedtls_gcm_crypt_and_tag(&g, MBEDTLS_GCM_ENCRYPT, n + 1, nonce, 12,
                                       out, 5, out + 5, out + 5, 16, out + 5 + n + 1);
    mbedtls_gcm_free(&g);
    if (rc) return -1;
    s->seq++;
    return wr_all(s->fd, out, 5 + total);
}

static void *server_half(void *arg) {
    struct srv *s = arg;
    const struct plan *pl = s->plan;
    unsigned char ch[4096];
    unsigned char type;
    size_t ch_n = 0;

    s->rc = -1;
    if (rd_rec(s->fd, &type, ch, sizeof(ch), &ch_n) || type != 0x16) return NULL;
    if (pl->hangup) { s->rc = 0; close(s->fd); s->fd = -1; return NULL; }

    unsigned char cpub[32], sid[32];
    size_t sid_n = 0;
    if (ch_pick(ch, ch_n, cpub, sid, &sid_n)) return NULL;

    unsigned char spriv[32], spub[32];
    if (xc_x25519_keypair(spriv, spub) != 0) return NULL;

    /* ---- ServerHello ---- */
    unsigned char sh[256];
    size_t m = 0;
    sh[m++] = 0x02; m += 3;                          /* длина впишется ниже */
    sh[m++] = 0x03; sh[m++] = 0x03;
    if (xc_random(sh + m, 32) != 0) return NULL;
    m += 32;
    sh[m++] = (unsigned char)sid_n;
    memcpy(sh + m, sid, sid_n); m += sid_n;
    sh[m++] = SUITE_HI; sh[m++] = SUITE_LO;
    sh[m++] = 0x00;                                  /* compression */
    size_t exts_at = m; m += 2;
    sh[m++] = 0x00; sh[m++] = 0x2b; sh[m++] = 0x00; sh[m++] = 0x02;
    sh[m++] = 0x03; sh[m++] = 0x04;                  /* supported_versions: TLS 1.3 */
    if (!pl->no_keyshare) {
        sh[m++] = 0x00; sh[m++] = 0x33; sh[m++] = 0x00; sh[m++] = 0x24;
        sh[m++] = 0x00; sh[m++] = 0x1d; sh[m++] = 0x00; sh[m++] = 0x20;
        memcpy(sh + m, spub, 32); m += 32;
    }
    sh[exts_at]     = (unsigned char)((m - exts_at - 2) >> 8);
    sh[exts_at + 1] = (unsigned char)(m - exts_at - 2);
    sh[1] = (unsigned char)((m - 4) >> 16);
    sh[2] = (unsigned char)((m - 4) >> 8);
    sh[3] = (unsigned char)(m - 4);

    unsigned char rec[5 + 256];
    rec[0] = 0x16; rec[1] = 0x03; rec[2] = 0x03;
    rec[3] = (unsigned char)(m >> 8); rec[4] = (unsigned char)m;
    memcpy(rec + 5, sh, m);
    if (wr_all(s->fd, rec, 5 + m)) return NULL;

    mbedtls_sha256_init(&s->tr);
    mbedtls_sha256_starts(&s->tr, 0);
    mbedtls_sha256_update(&s->tr, ch, ch_n);
    mbedtls_sha256_update(&s->tr, sh, m);

    if (pl->no_keyshare) { s->rc = 0; return NULL; }   /* дальше клиент уже не слушает */

    /* ---- расписание ключей рукопожатия, RFC 8446 §7.1 ---- */
    unsigned char zeros[HLEN] = {0}, empty[HLEN];
    unsigned char early[HLEN], derived[HLEN], hs[HLEN], ecdhe[32], th[HLEN];
    mbedtls_sha256(zeros, 0, empty, 0);
    if (mbedtls_hkdf_extract(md256(), NULL, 0, zeros, HLEN, early) != 0) return NULL;
    if (xlabel(early, "derived", empty, HLEN, derived, HLEN) != 0) return NULL;
    if (x25519_shared_ext(spriv, cpub, ecdhe) != 0) return NULL;
    if (mbedtls_hkdf_extract(md256(), derived, HLEN, ecdhe, 32, hs) != 0) return NULL;
    tr_snapshot(&s->tr, th);
    if (xlabel(hs, "s hs traffic", th, HLEN, s->s_hs, HLEN) != 0) return NULL;
    if (xlabel(s->s_hs, "key", NULL, 0, s->key, sizeof(s->key)) != 0) return NULL;
    if (xlabel(s->s_hs, "iv", NULL, 0, s->iv, sizeof(s->iv)) != 0) return NULL;

    /* ---- EncryptedExtensions ---- */
    unsigned char ee[64];
    size_t en = 0;
    ee[en++] = 0x08; en += 3;
    size_t elist_at = en; en += 2;
    if (pl->alpn) {
        size_t pn = strlen(pl->alpn);
        ee[en++] = 0x00; ee[en++] = 0x10;
        ee[en++] = 0x00; ee[en++] = (unsigned char)(3 + pn);
        ee[en++] = 0x00; ee[en++] = (unsigned char)(1 + pn);
        ee[en++] = (unsigned char)pn;
        memcpy(ee + en, pl->alpn, pn); en += pn;
    }
    ee[elist_at]     = (unsigned char)((en - elist_at - 2) >> 8);
    ee[elist_at + 1] = (unsigned char)(en - elist_at - 2);
    ee[1] = 0; ee[2] = (unsigned char)((en - 4) >> 8); ee[3] = (unsigned char)(en - 4);
    if (send_enc(s, ee, en)) return NULL;
    mbedtls_sha256_update(&s->tr, ee, en);

#if defined(STEER_HAVE_X509WRITE)
    /* ---- Certificate и CertificateVerify настоящей цепочкой (путь security=tls) ---- */
    if (pl->chain) {
        const struct leaf *l = &g_leaf[pl->chain];
        unsigned char msg[3072];
        size_t mn = cert_msg(l, msg, sizeof(msg));
        if (!mn) return NULL;
        if (send_enc(s, msg, mn)) return NULL;
        mbedtls_sha256_update(&s->tr, msg, mn);

        if (!pl->no_cv) {
            /* Хеш снимается ПОСЛЕ Certificate и ДО CertificateVerify — ровно то, что
             * подписывает сервер по RFC 8446 §4.4.3, и ровно то место, где клиент снимает
             * свой (tls13.c, разбор сообщения 0x0F). Ошибка на один шаг здесь дала бы
             * «подпись не сошлась» и выглядела бы находкой в движке. */
            unsigned char th_cv[HLEN];
            tr_snapshot(&s->tr, th_cv);
            size_t cn = cv_msg(l, th_cv, pl, msg, sizeof(msg));
            if (!cn) return NULL;
            if (send_enc(s, msg, cn)) return NULL;
            mbedtls_sha256_update(&s->tr, msg, cn);
        }
        goto finished;
    }
#endif

    /* ---- Certificate или его сжатый вид ---- */
    if (pl->cert == 2) {
        /* CompressedCertificate: клиент отвечает на него отказом сразу, не дожидаясь
         * Finished — сжатый сертификат означает, что нас передали маскировочному сайту. */
        unsigned char cc[16] = { 0x19, 0x00, 0x00, 0x08, 0x00, 0x02, 0x00, 0x00,
                                 0x04, 0x01, 0x02, 0x03 };
        s->rc = send_enc(s, cc, 12) ? -1 : 0;
        return NULL;
    }
    if (pl->cert == 1) {
        /* Тело намеренно не разбирается ни в один сертификат: проверяется не разбор X.509,
         * а то, чем закрывается отказ проверки. */
        unsigned char cr[40];
        cr[0] = 0x0B; cr[1] = 0; cr[2] = 0; cr[3] = 32;
        memset(cr + 4, 0xA5, 32);
        if (send_enc(s, cr, 36)) return NULL;
        mbedtls_sha256_update(&s->tr, cr, 36);
    }

    /* ---- Finished ---- */
#if defined(STEER_HAVE_X509WRITE)
finished:;
#endif
    unsigned char fkey[HLEN], hash[HLEN], vd[HLEN];
    tr_snapshot(&s->tr, hash);
    if (xlabel(s->s_hs, "finished", NULL, 0, fkey, HLEN) != 0) return NULL;
    if (mbedtls_md_hmac(md256(), fkey, HLEN, hash, HLEN, vd) != 0) return NULL;
    if (pl->bad_finished) vd[0] ^= 0xFF;
    unsigned char fin[4 + HLEN];
    fin[0] = 0x14; fin[1] = 0; fin[2] = 0; fin[3] = (unsigned char)HLEN;
    memcpy(fin + 4, vd, HLEN);
    if (send_enc(s, fin, sizeof(fin))) return NULL;
    mbedtls_sha256_update(&s->tr, fin, sizeof(fin));

    s->rc = 0;
    return NULL;
}

/* ---- шов установления TCP ------------------------------------------------------ */

static int g_give_fd = -1;

static int fake_dial(const char *host, uint16_t port, int timeout_s) {
    (void)host; (void)port;
    int fd = g_give_fd;
    g_give_fd = -1;
    if (fd < 0) return VLESS_CONN_ECONNECT;
    /* Ровно то, что делает tcp_connect с победившим сокетом: срок на чтение и запись.
     * Без него ошибка в серверной половине вешала бы стенд, а не роняла его. */
    sock_ready(fd, timeout_s);
    return fd;
}

/* Узел: Reality поверх tcp. Именно Reality, а не security=tls: доказательством подлинности
 * здесь служит подпись временного сертификата на authkey, и для отказа проверки не нужно
 * ни хранилища корней, ни цепочки X.509 — то есть ветвь ECERT достижима без второго
 * стенда под сертификаты. Ключ pbk произвольный: X25519 умножает любые 32 байта, а сервер
 * этой пары всё равно поддельный. */
static void node_reality(struct vless_node *n, const char *type) {
    memset(n, 0, sizeof(*n));
    snprintf(n->host, sizeof(n->host), "%s", "node.invalid");
    n->port = 443;
    snprintf(n->uuid, sizeof(n->uuid), "%s", "00000000-0000-0000-0000-000000000001");
    snprintf(n->type, sizeof(n->type), "%s", type);
    snprintf(n->security, sizeof(n->security), "%s", "reality");
    snprintf(n->sni, sizeof(n->sni), "%s", "www.example.com");
    snprintf(n->fp, sizeof(n->fp), "%s", "chrome");
    snprintf(n->pbk, sizeof(n->pbk), "%s", "AQIDBAUGBwgJCgsMDQ4PEBESExQVFhcYGRobHB0eHyA");
    snprintf(n->sid, sizeof(n->sid), "%s", "0123456789abcdef");
}

#if defined(STEER_HAVE_X509WRITE)
/* Узел security=tls: доказательство подлинности — цепочка до корня и имя, больше ничего.
 * pbk/sid не заполняются вовсе, и это не небрежность: у обычного TLS их не бывает, а
 * reality_build_hello при .plain = 1 их и не читает (client.c). Имя обязано быть — и
 * проверяется оно против sni, а не против host, поэтому sni здесь то, на которое выпущен
 * годный лист. */
static void node_tls(struct vless_node *n, const char *type) {
    memset(n, 0, sizeof(*n));
    snprintf(n->host, sizeof(n->host), "%s", "node.invalid");
    n->port = 443;
    snprintf(n->uuid, sizeof(n->uuid), "%s", "00000000-0000-0000-0000-000000000001");
    snprintf(n->type, sizeof(n->type), "%s", type);
    snprintf(n->security, sizeof(n->security), "%s", "tls");
    snprintf(n->sni, sizeof(n->sni), "%s", TLS_SNI);
    snprintf(n->fp, sizeof(n->fp), "%s", "chrome");
}
#endif

/* Один прогон: поднять пару, отдать один конец клиенту, второй — серверной половине.
 *
 * ctx_left, если он задан, получает число контекстов шифра, оставшихся РАЗВЁРНУТЫМИ в
 * соединении после возврата. Это наблюдаемая форма утверждения «освобождать было нечего»:
 * ветвь отказа рукопожатия закрывается одним close(fd), и безопасно это лишь пока tls13.c
 * разворачивает контексты трафика последним действием — уже после всех своих отказов.
 * Связь между двумя файлами, которую до этого стенда не охраняло ничто; проверка пойдёт
 * красной в тот день, когда порядок в tls13.c изменится. */
static int run_case(const struct plan *pl, struct vless_node *n, char *reason, size_t rn,
                    int *ctx_left) {
    int sv[2];
    if (socketpair(AF_UNIX, SOCK_STREAM, 0, sv) != 0) return -100;

    struct srv s;
    memset(&s, 0, sizeof(s));
    s.fd = sv[1];
    s.plan = pl;

    pthread_t th;
    if (pthread_create(&th, NULL, server_half, &s) != 0) {
        close(sv[0]); close(sv[1]);
        return -101;
    }

    g_give_fd = sv[0];
    g_tcp_dial = fake_dial;
    struct vless_conn c;
    int rc = vless_connect(n, &c, 3);
    if (rc == 0) vless_close(&c);
    g_tcp_dial = NULL;

    if (reason && rn) snprintf(reason, rn, "%s", tls13_verify_reason());
    if (ctx_left) *ctx_left = (c.tls.rd.ctx_ready ? 1 : 0) + (c.tls.wr.ctx_ready ? 1 : 0) +
                              (c.up.tls.rd.ctx_ready ? 1 : 0) + (c.up.tls.wr.ctx_ready ? 1 : 0);

    pthread_join(th, NULL);
    if (s.fd >= 0) close(s.fd);
    /* Свой конец пары закрывает сам vless_connect (или vless_close на успехе). Не закрыл —
     * это и есть находка, и её видно проверкой по числу дескрипторов у вызывающего. */
    return rc;
}

/* Работает ли сама проверка кучи.
 *
 * Зачем это отдельной проверкой. Стенд, собранный С санитайзером, но запущенный с
 * ASAN_OPTIONS=detect_leaks=0, показывал бы «в куче ничего не осталось» на КАЖДОЙ ветви —
 * зелёный стенд, который больше не проверяет то, ради чего написан. Ровно этот класс
 * молчаливого отказа уже стоил проекту двух находок (I-066, I-067 не прогонялись ни разу),
 * и урок захода 75 сформулирован там же: барьер, который можно случайно выключить, обязан
 * говорить о своём состоянии сам.
 *
 * Утечка делается НАРОЧНО и тут же убирается: указатель спрятан исключающим ИЛИ, потому что
 * LeakSanitizer просматривает и стек, и регистры — живой указатель он не счёл бы утечкой.
 * Отчёт санитайзера, который появится ниже, — часть проверки, а не поломка. */
static volatile uintptr_t g_hidden;
#define HIDE_MASK ((uintptr_t)0x5a5a5a5a5a5a5a5aULL)

static void heap_check_selftest(void) {
#if defined(__SANITIZE_ADDRESS__)
    void *p = malloc(64);
    if (!p) return;
    memset(p, 0x11, 64);
    g_hidden = (uintptr_t)p ^ HIDE_MASK;
    p = NULL;
    printf("-- ниже ОЖИДАЕМЫЙ отчёт об утечке: так стенд убеждается, что проверка кучи включена --\n");
    fflush(stdout);
    int seen = LEAK_CHECK();
    printf("-- конец ожидаемого отчёта --\n");
    check("проверка кучи включена (нарочная утечка замечена)", 1, seen);
    free((void *)(g_hidden ^ HIDE_MASK));
    g_hidden = 0;
#endif
}

int main(void) {
    /* Серверная половина пишет в сокет, который клиент уже закрыл, — на отказе проверки он
     * закрывается, не дочитав. Без этого стенд умирал бы от SIGPIPE вместо того, чтобы
     * назвать результат. */
    signal(SIGPIPE, SIG_IGN);

    heap_check_selftest();

    struct vless_node node;
    node_reality(&node, "tcp");

    /* Прогрев. Первое рукопожатие тянет за собой одноразовые выделения самой mbedtls и
     * подъём потока, и без него первая же проверка кучи показала бы их как утечку. Что
     * прогрев сработал, видно по коду возврата: он обязан быть тем же, что в первом
     * измеряемом случае ниже. */
    {
        struct plan warm = { .name = "прогрев", .cert = 0 };
        char why[256];
        int rc = run_case(&warm, &node, why, sizeof(why), NULL);
        check("прогрев: рукопожатие дошло до проверки сертификата", TLS13_ECERT, rc);
    }

    static const struct plan plans[] = {
        { .name = "сервер не прислал сертификат", .cert = 0 },
        { .name = "сертификат не сошёлся с authkey", .cert = 1 },
        { .name = "сертификат приехал сжатым", .cert = 2 },
        { .name = "ServerHello без key_share", .no_keyshare = 1 },
        { .name = "серверный Finished не совпал", .bad_finished = 1 },
        { .name = "сервер закрылся после ClientHello", .hangup = 1 },
    };
    static const int want[] = {
        TLS13_ECERT, TLS13_ECERT, TLS13_ECERT,
        TLS13_ENOKEYSHARE, TLS13_EFINISHED, TLS13_ECLOSED,
    };
    /* Причина отказа обязана дойти до вызывающего: без неё «узел не работает» и «узел не
     * тот» выглядят одинаково. Проверяется у трёх ветвей ECERT — только у них она есть. */
    static const char *why_want[] = {
        "не прислал сертификат",
        "не разобрался",
        /* Сжатый сертификат назван «не признал ключ», а не словом про сжатие, и это
         * намеренно: сервер Reality, признавший клиента, отвечает своим временным
         * сертификатом и не сжимает его — значит отвечает маскировочный сайт. Проверка
         * стоит здесь потому, что подмена этого текста на буквальный («сервер сжал
         * сертификат») увела бы человека к сжатию, к которому он не имеет отношения. */
        "не признал ключ",
        "", "", "",
    };

    for (size_t i = 0; i < sizeof(plans) / sizeof(*plans); i++) {
        /* Буфер стенда ВДВОЕ больше движкового (g_verify_reason[96]): стенд обязан
         * мерить движок, а не себя. Совпадающие размеры показали бы обрезку
         * собственным буфером как свойство движка — и наоборот. */
        char what[160], why[256] = "";
        int fd0 = fd_count(), ctx_left = -1;
        int rc = run_case(&plans[i], &node, why, sizeof(why), &ctx_left);

        snprintf(what, sizeof(what), "%s: код возврата", plans[i].name);
        check(what, want[i], rc);

        if (why_want[i][0]) {
            snprintf(what, sizeof(what), "%s: причина названа", plans[i].name);
            check_str(what, why_want[i], why);
        }

        /* Двадцать попыток подряд — то, что происходит на роутере: пул запасных сессий
         * пополняется на каждый SYN, сторож перебирает узлы пачками. Утечка на попытку
         * здесь и становится видимой, а не остаётся округлением. */
        for (int k = 0; k < 20; k++) {
            int again = run_case(&plans[i], &node, NULL, 0, NULL);
            if (again != want[i]) { rc = again; break; }
        }
        snprintf(what, sizeof(what), "%s: двадцать попыток дают тот же код", plans[i].name);
        check(what, want[i], rc);

        snprintf(what, sizeof(what), "%s: контекстов шифра не осталось развёрнутыми", plans[i].name);
        check(what, 0, ctx_left);

        snprintf(what, sizeof(what), "%s: дескрипторы вернулись к исходному числу", plans[i].name);
        check(what, fd0, fd_count());

        snprintf(what, sizeof(what), "%s: в куче ничего не осталось", plans[i].name);
        check(what, 0, LEAK_CHECK());
    }

    /* ---- security=tls со своими корнями (R-118) ---------------------------------
     *
     * Здесь и только здесь проверка сервера может ПРОЙТИ, а значит только здесь достижимы
     * успешное установление целиком и ветвь ENOH2 — та, ради которой в клиенте появился
     * vless_close вместо close(fd). Корни отдаются движку швом g_cert_roots; хранилище
     * одно на весь процесс, потому что certverify.c разбирает его под pthread_once
     * (I-217), и второе тут не подействовало бы. */
#if defined(STEER_HAVE_X509WRITE)
    if (chain_build() != 0) {
        printf("%-64s %s\n", "выпуск своей цепочки X.509", "ПРОВАЛ");
        fails++;
    } else {
        g_cert_roots = g_roots_file;

        /* Прогрев второй половины: первое рукопожатие с проверкой цепочки тянет за собой
         * разбор хранилища корней под pthread_once — 
         * он остаётся в куче навсегда по замыслу (см. roots_load), и без прогрева первая
         * же проверка кучи показала бы его утечкой. */
        {
            struct plan warm = { .name = "прогрев tls", .chain = LEAF_OK };
            struct vless_node w;
            node_tls(&w, "tcp");
            int rc = run_case(&warm, &w, NULL, 0, NULL);
            check("прогрев tls: цепочка сошлась, соединение установлено", 0, rc);
        }

        static const struct plan tls_plans[] = {
            { .name = "tls: цепочка сошлась",            .chain = LEAF_OK },
            { .name = "tls: сервер выбрал не h2",        .chain = LEAF_OK, .alpn = "http/1.1" },
            { .name = "tls: лист выдан на другое имя",   .chain = LEAF_NAME },
            { .name = "tls: лист подписан сам собой",    .chain = LEAF_SELF },
            { .name = "tls: сертификат без подписи",     .chain = LEAF_OK, .no_cv = 1 },
            { .name = "tls: подпись не сходится",        .chain = LEAF_OK, .cv_bad_sig = 1 },
            { .name = "tls: алгоритм не из предложенных",.chain = LEAF_OK, .cv_bad_alg = 1 },
        };
        /* Транспорт: у случая с ALPN он ОБЯЗАН быть не raw. Для tcp ALPN не просят вовсе
         * (client.c: cfg.alpn = NULL при VT_RAW), и проверка «сервер назвал не h2» там не
         * стоит — то есть на tcp этот случай молча прошёл бы успехом. */
        static const char *tls_type[] = { "tcp", "grpc", "tcp", "tcp", "tcp", "tcp", "tcp" };
        static const int tls_want[] = {
            0, VLESS_CONN_ENOH2, TLS13_ECERT, TLS13_ECERT,
            TLS13_ECERT, TLS13_ECERT, TLS13_ECERT,
        };
        /* ОЖИДАЕТСЯ ТО, ЧТО ДОХОДИТ СЕГОДНЯ, а не то, что написано в certverify.c, и разница
         * здесь — находка I-236, а не небрежность стенда. Два самых длинных текста причин не
         * влезают в g_verify_reason[96]: «сертификат не сошёлся с корнями или выдан не на это
         * имя» это 100 байт, «сервер подписал алгоритмом, которого мы не предлагали» — 99.
         * Обрезка у первого приходится НА СЕРЕДИНУ БУКВЫ. Поправить нельзя автономно: буфер
         * живёт в tls13.c, а это защищённый путь (п.5.0) — заведён proposal. Проверка ниже
         * («причина обрезана») меряет это числом, и когда буфер вырастет, она покраснеет —
         * это и будет напоминанием заменить ожидания здесь на полные тексты. */
        static const char *tls_why[] = {
            "", "",
            "выдан не на это",          /* CERTV_ECHAIN: имя проверяется третьим доводом verify */
            "не сошёлся с корнями",     /* тот же код, другая половина его текста */
            "не прислал подпись",       /* tls13.c различает «нет сертификата» и «нет подписи» */
            "подпись сервера неверна",  /* CERTV_ESIG */
            "которого мы не предлага",  /* CERTV_EALG — отдельная причина, а не «подпись плохая» */
        };
        /* Сколько байт причины дошло. -1 — «не проверяем»; 95 — обрезано движковым буфером. */
        static const int tls_why_len[] = { -1, -1, 95, -1, -1, -1, 95 };

        for (size_t i = 0; i < sizeof(tls_plans) / sizeof(*tls_plans); i++) {
            struct vless_node tn;
            node_tls(&tn, tls_type[i]);
            char what[160], why[256] = "";
            int fd0 = fd_count(), ctx_left = -1;
            int rc = run_case(&tls_plans[i], &tn, why, sizeof(why), &ctx_left);

            snprintf(what, sizeof(what), "%s: код возврата", tls_plans[i].name);
            check(what, tls_want[i], rc);

            if (tls_why[i][0]) {
                snprintf(what, sizeof(what), "%s: причина названа", tls_plans[i].name);
                check_str(what, tls_why[i], why);
            }
            if (tls_why_len[i] >= 0) {
                /* КРАСНОЕ ЗДЕСЬ — ХОРОШАЯ НОВОСТЬ: значит g_verify_reason вырос и текст
                 * доходит целиком (I-236). Тогда это число убирается, а ожидание причины
                 * выше заменяется полным текстом из certverify.c. */
                snprintf(what, sizeof(what), "%s: причина обрезана буфером движка (I-236)",
                         tls_plans[i].name);
                check(what, tls_why_len[i], (long)strlen(why));
            }

            for (int k = 0; k < 20; k++) {
                int again = run_case(&tls_plans[i], &tn, NULL, 0, NULL);
                if (again != tls_want[i]) { rc = again; break; }
            }
            snprintf(what, sizeof(what), "%s: двадцать попыток дают тот же код", tls_plans[i].name);
            check(what, tls_want[i], rc);

            snprintf(what, sizeof(what), "%s: контекстов шифра не осталось развёрнутыми", tls_plans[i].name);
            check(what, 0, ctx_left);

            snprintf(what, sizeof(what), "%s: дескрипторы вернулись к исходному числу", tls_plans[i].name);
            check(what, fd0, fd_count());

            snprintf(what, sizeof(what), "%s: в куче ничего не осталось", tls_plans[i].name);
            check(what, 0, LEAK_CHECK());
        }
        g_cert_roots = NULL;
        chain_free();
    }
#else
    printf("\nВНИМАНИЕ: собрано БЕЗ выпуска сертификатов (нет MBEDTLS_X509_CRT_WRITE_C) —\n");
    printf("          семь случаев security=tls ПРОПУЩЕНЫ: ни удавшаяся проверка сервера,\n");
    printf("          ни ветвь ENOH2 с её vless_close здесь не проверены (R-118).\n\n");
#endif

    /* security=none: TLS нет вовсе, и путь выхода тут единственный успешный. Нужен не ради
     * него самого, а как поверка стенда: если бы шов отдавал негодный сокет, «успех» тоже
     * стал бы отказом, и все проверки выше прошли бы по неверной причине. */
    {
        struct vless_node plain;
        memset(&plain, 0, sizeof(plain));
        snprintf(plain.host, sizeof(plain.host), "%s", "node.invalid");
        plain.port = 443;
        snprintf(plain.type, sizeof(plain.type), "%s", "tcp");
        snprintf(plain.security, sizeof(plain.security), "%s", "none");

        int sv[2];
        if (socketpair(AF_UNIX, SOCK_STREAM, 0, sv) != 0) return 2;
        g_give_fd = sv[0];
        g_tcp_dial = fake_dial;
        struct vless_conn c;
        int rc = vless_connect(&plain, &c, 3);
        g_tcp_dial = NULL;
        check("security=none поверх tcp: соединение установлено", 0, rc);
        check("security=none: TLS не разворачивался", 1, c.plain);
        if (rc == 0) vless_close(&c);
        check("security=none: дескриптор закрыт vless_close", -1, c.fd);
        close(sv[1]);
        check("security=none: в куче ничего не осталось", 0, LEAK_CHECK());
    }

#if !defined(__SANITIZE_ADDRESS__)
    printf("\nВНИМАНИЕ: собрано БЕЗ AddressSanitizer — проверки «в куче ничего не осталось»\n");
    printf("          прошли пусто. Коды возврата и дескрипторы проверены, куча — НЕТ.\n");
#endif
    printf("\n%s\n", fails ? "ЕСТЬ ПРОВАЛЫ" : "все проверки прошли");
    return fails ? 1 : 0;
}
