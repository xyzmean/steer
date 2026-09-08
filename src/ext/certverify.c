/* Проверка сертификата сервера для security=tls. Объяснение, зачем отдельный файл, — в
 * certverify.h.
 *
 * ЧТО ЗДЕСЬ ПРОВЕРЯЕТСЯ И ПОЧЕМУ ИМЕННО ЭТО. У security=tls нет ничего, кроме сертификата.
 * Reality доказывает подлинность сервера аутентификатором, который умеет посчитать только
 * владелец постоянного ключа; у обычного TLS такого ключа нет, и единственное доказательство —
 * цепочка до корня плюс подпись CertificateVerify над транскриптом. Пропустить любую из двух
 * половин значит не проверить ничего: цепочка без подписи доказывает лишь то, что кто-то
 * когда-то получил сертификат на это имя, а подпись без цепочки — что собеседник владеет
 * ключом, который мы же у него и взяли.
 *
 * ЧЕГО ЗДЕСЬ НЕТ. Ни OCSP, ни списков отзыва: на роутере их нечем и некогда качать, а
 * молчаливая имитация проверки хуже честного её отсутствия. Срок действия mbedtls проверяет
 * сам (MBEDTLS_HAVE_TIME), и это единственная временная проверка, на которую мы опираемся.
 */
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <pthread.h>

#include "mbedtls/x509_crt.h"
#include "mbedtls/pk.h"
#include "mbedtls/md.h"

#include "certverify.h"

/* ---- хранилище корней ---------------------------------------------------------------
 *
 * Разбирается ОДИН РАЗ на процесс. Файл ca-bundle — 182 КБ и полторы сотни сертификатов;
 * разбирать его на каждое соединение значило бы полсекунды и треть мегабайта на КАЖДУЮ
 * попытку узла, а сторож перебирает узлы пачками. Отсюда pthread_once: соединители работают
 * в нескольких потоках (tunnel.c), и два одновременных первых обращения иначе разобрали бы
 * хранилище дважды, причём второе легло бы поверх первого.
 *
 * Освобождения нет намеренно: хранилище живёт столько же, сколько процесс, и «освободить перед
 * выходом» здесь означало бы код, который исполняется ровно в момент, когда его результат уже
 * никому не нужен. */
static mbedtls_x509_crt g_roots;
static int g_roots_rc = CERTV_ENOROOTS;
static pthread_once_t g_roots_once = PTHREAD_ONCE_INIT;
static const char *g_roots_path;

static void roots_load(void) {
    const char *path = (g_roots_path && g_roots_path[0]) ? g_roots_path : CERTV_DEFAULT_ROOTS;
    mbedtls_x509_crt_init(&g_roots);

    FILE *f = fopen(path, "rb");
    if (!f) return;
    if (fseek(f, 0, SEEK_END) != 0) { fclose(f); return; }
    long sz = ftell(f);
    /* Верхняя граница — не паранойя: путь приходит из настройки, и указать им, скажем,
     * /dev/zero не должно означать «съесть всю память роутера». Нынешний ca-bundle весит
     * 182 КБ, восьми мегабайт хватит любому разумному хранилищу. */
    if (sz <= 0 || sz > 8 * 1024 * 1024) { fclose(f); return; }
    rewind(f);

    /* +1 байт под ноль: mbedtls_x509_crt_parse отличает PEM от DER по наличию терминатора и
     * требует, чтобы он ВХОДИЛ в переданную длину. Без него разбор молча уходит в ветку DER
     * и не находит ни одного корня — то есть хранилище выглядит пустым. */
    unsigned char *buf = malloc((size_t)sz + 1);
    if (!buf) { fclose(f); return; }
    size_t got = fread(buf, 1, (size_t)sz, f);
    fclose(f);
    buf[got] = '\0';

    /* Возврат больше нуля — «часть сертификатов не разобралась». Это НЕ отказ: в хранилище
     * встречаются записи с алгоритмами, которых нет в нашей сборке mbedtls, и требовать
     * идеального разбора значило бы остаться без корней целиком из-за одного экзотического. */
    int rc = mbedtls_x509_crt_parse(&g_roots, buf, got + 1);
    free(buf);
    if (rc < 0 || g_roots.version == 0) return;
    g_roots_rc = 0;
}

/* ---- разбор сообщения Certificate (RFC 8446 §4.4.2) ---------------------------------
 *
 * Тело: контекст запроса (1 байт длины и байты), затем список длиной в 3 байта, а в нём
 * записи «3 байта длины + DER» с двухбайтовым хвостом расширений у каждой. Расширения не
 * читаются: в них бывает разве что signed_certificate_timestamp, на решение он не влияет.
 */
static int parse_chain(const unsigned char *b, size_t n, mbedtls_x509_crt *chain) {
    if (n < 1) return CERTV_EPARSE;
    size_t p = 1 + b[0];                       /* certificate_request_context */
    if (p + 3 > n) return CERTV_EPARSE;
    size_t list = ((size_t)b[p] << 16) | ((size_t)b[p + 1] << 8) | b[p + 2];
    p += 3;
    if (p + list > n) return CERTV_EPARSE;

    size_t end = p + list, seen = 0;
    while (p + 3 <= end) {
        size_t clen = ((size_t)b[p] << 16) | ((size_t)b[p + 1] << 8) | b[p + 2];
        p += 3;
        if (clen == 0 || p + clen > end) return CERTV_EPARSE;
        /* Разбор ПРОДОЛЖАЕТСЯ при отказе на промежуточном сертификате, но не на первом:
         * листовой нужен обязательно (им проверяется подпись), а промежуточный, который мы
         * не поняли, может оказаться лишним — цепочка нередко приезжает с запасом. */
        int rc = mbedtls_x509_crt_parse_der(chain, b + p, clen);
        if (rc != 0 && seen == 0) return CERTV_EPARSE;
        if (rc == 0) seen++;
        p += clen;
        if (p + 2 > end) break;
        size_t elen = ((size_t)b[p] << 8) | b[p + 1];
        p += 2;
        if (p + elen > end) return CERTV_EPARSE;
        p += elen;
    }
    return seen ? 0 : CERTV_EPARSE;
}

/* ---- подпись CertificateVerify (RFC 8446 §4.4.3) ------------------------------------
 *
 * Подписываются не байты транскрипта, а строка с приставкой: 64 пробела, «TLS 1.3, server
 * CertificateVerify», нулевой байт и хеш транскрипта. Приставка нужна затем, чтобы подпись
 * нельзя было переставить между ролями и версиями протокола, и без неё сервер не сойдётся.
 */
static const char CV_LABEL[] = "TLS 1.3, server CertificateVerify";

/* Алгоритм подписи из двух байт кода. Поддержаны РОВНО те, что мы предлагаем в
 * signature_algorithms (см. reality.c), минус rsa_pkcs1_*: в TLS 1.3 подписывать ими
 * CertificateVerify запрещено (RFC 8446 §4.4.3), они остаются только для подписей ВНУТРИ
 * сертификатов. Сервер, выбравший что-то ещё, нарушает наш же список — это отдельная
 * причина, а не «подпись не сошлась». */
static int sig_alg(unsigned code, mbedtls_md_type_t *md, int *is_pss) {
    switch (code) {
        case 0x0403: *md = MBEDTLS_MD_SHA256; *is_pss = 0; return 0;  /* ecdsa_secp256r1 */
        case 0x0503: *md = MBEDTLS_MD_SHA384; *is_pss = 0; return 0;  /* ecdsa_secp384r1 */
        case 0x0603: *md = MBEDTLS_MD_SHA512; *is_pss = 0; return 0;  /* ecdsa_secp521r1 */
        case 0x0804: *md = MBEDTLS_MD_SHA256; *is_pss = 1; return 0;  /* rsa_pss_rsae */
        case 0x0805: *md = MBEDTLS_MD_SHA384; *is_pss = 1; return 0;
        case 0x0806: *md = MBEDTLS_MD_SHA512; *is_pss = 1; return 0;
        case 0x0809: *md = MBEDTLS_MD_SHA256; *is_pss = 1; return 0;  /* rsa_pss_pss */
        case 0x080A: *md = MBEDTLS_MD_SHA384; *is_pss = 1; return 0;
        case 0x080B: *md = MBEDTLS_MD_SHA512; *is_pss = 1; return 0;
        default: return CERTV_EALG;
    }
}

static int check_signature(mbedtls_pk_context *pk, const unsigned char *cv, size_t cv_n,
                           const unsigned char *transcript, size_t thash_n) {
    if (cv_n < 4) return CERTV_EPARSE;
    unsigned code = ((unsigned)cv[0] << 8) | cv[1];
    size_t sig_n = ((size_t)cv[2] << 8) | cv[3];
    if (4 + sig_n != cv_n) return CERTV_EPARSE;

    mbedtls_md_type_t mdt;
    int is_pss;
    int rc = sig_alg(code, &mdt, &is_pss);
    if (rc) return rc;

    const mbedtls_md_info_t *mi = mbedtls_md_info_from_type(mdt);
    if (!mi) return CERTV_EALG;
    size_t hn = mbedtls_md_get_size(mi);

    /* ДЛИНА ТРАНСКРИПТА И ДЛИНА ХЕША ПОДПИСИ — РАЗНЫЕ ВЕЛИЧИНЫ, и путать их нельзя.
     *
     * Транскрипт хешируется хешем НАБОРА ШИФРОВ (RFC 8446 §4.4.1): у TLS_AES_256_GCM_SHA384
     * это 48 байт. Подпись же считается алгоритмом из самого CertificateVerify, и сервер
     * вправе выбрать rsa_pss_rsae_sha256 — 32 байта. Первая версия требовала их совпадения и
     * отвергала такое сочетание как «сертификат не разобрался»: снято на www.microsoft.com,
     * где набор SHA-384, а подпись SHA-256, — узел выглядел неисправным, притом что сервер
     * безупречен, а yandex.ru и wikipedia.org с совпадающими длинами проходили. */
    if (thash_n == 0 || thash_n > 64) return CERTV_EPARSE;

    /* 64 + 33 + 1 + 64 = 162 — с запасом на самый длинный транскрипт. */
    unsigned char content[176];
    size_t cn = 0;
    memset(content, 0x20, 64); cn = 64;
    memcpy(content + cn, CV_LABEL, sizeof(CV_LABEL) - 1); cn += sizeof(CV_LABEL) - 1;
    content[cn++] = 0x00;
    memcpy(content + cn, transcript, thash_n); cn += thash_n;

    unsigned char digest[64];
    if (mbedtls_md(mi, content, cn, digest) != 0) return CERTV_ESIG;

    if (is_pss) {
        /* Соль ЛЮБОЙ длины. RFC 8446 требует, чтобы она равнялась длине хеша, но встречаются
         * серверы (и посредники, переподписывающие поток), у которых она другая; отвергать
         * их значило бы объявить узел неисправным там, где подпись верна. */
        mbedtls_pk_rsassa_pss_options o = {
            .mgf1_hash_id = mdt,
            .expected_salt_len = MBEDTLS_RSA_SALT_LEN_ANY,
        };
        if (mbedtls_pk_verify_ext(MBEDTLS_PK_RSASSA_PSS, &o, pk, mdt, digest, hn,
                                  cv + 4, sig_n) != 0)
            return CERTV_ESIG;
        return 0;
    }
    if (mbedtls_pk_verify(pk, mdt, digest, hn, cv + 4, sig_n) != 0) return CERTV_ESIG;
    return 0;
}

int cert_verify_server(const unsigned char *cert_body, size_t cert_n,
                       const unsigned char *cv_body, size_t cv_n,
                       const unsigned char *transcript, size_t thash_n,
                       const char *host, const char *roots) {
    if (!cert_body || !cv_body || !host || !host[0]) return CERTV_EPARSE;

    g_roots_path = roots;
    pthread_once(&g_roots_once, roots_load);
    if (g_roots_rc != 0) return CERTV_ENOROOTS;

    mbedtls_x509_crt chain;
    mbedtls_x509_crt_init(&chain);
    int rc = parse_chain(cert_body, cert_n, &chain);
    if (rc == 0) {
        /* ИМЯ ПРОВЕРЯЕТСЯ ЗДЕСЬ ЖЕ, третьим доводом verify: отдельной проверкой оно
         * оказалось бы вторым местом, где живёт разбор SAN, и разошлось бы с библиотечным.
         * Флаги важнее кода возврата: verify возвращает отказ и на «имя не то», и на
         * «корня нет», а различать их человеку нужно. */
        uint32_t flags = 0;
        int vr = mbedtls_x509_crt_verify(&chain, &g_roots, NULL, host, &flags, NULL, NULL);
        if (vr != 0 || flags != 0) rc = CERTV_ECHAIN;
    }
    if (rc == 0) rc = check_signature(&chain.pk, cv_body, cv_n, transcript, thash_n);
    mbedtls_x509_crt_free(&chain);
    return rc;
}

const char *cert_verify_strerror(int rc) {
    switch (rc) {
        case 0:              return "";
        case CERTV_EPARSE:   return "сертификат сервера не разобрался";
        case CERTV_ENOROOTS: return "нет хранилища корней (нужен пакет ca-bundle)";
        case CERTV_ECHAIN:   return "сертификат не сошёлся с корнями или выдан не на это имя";
        case CERTV_ESIG:     return "подпись сервера неверна";
        case CERTV_EALG:     return "сервер подписал алгоритмом, которого мы не предлагали";
        default:             return "проверка сертификата не удалась";
    }
}
