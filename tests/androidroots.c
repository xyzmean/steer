/* Корни сертификатов на Android: склейка каталога в файл для certverify.
 *
 * ЗАЧЕМ. На телефоне нет файла ca-bundle, который certverify.c читает на роутере: корни лежат
 * каталогом, по сертификату на файл, и каждый файл — это текст `openssl x509 -text`, за
 * которым идёт PEM. client.c под STEER_ANDROID склеивает первый найденный каталог в файл
 * состояния и отдаёт его certverify швом auth.roots (см. cert_roots в client.c). Если склейка
 * молча не работает, проверка security=tls на телефоне отвергает КАЖДЫЙ узел как «хранилище
 * корней не прочиталось», а на роутере этого не видно никогда — там путь другой.
 *
 * ЧТО ПРОВЕРЯЕТСЯ. Первый каталог списка отсутствует, второй пуст — берётся третий; в нём файлы в формате
 * Android (текст перед PEM), и из склейки mbedtls разбирает ровно столько сертификатов,
 * сколько файлов; скрытые файлы пропускаются; повторный вызов отдаёт тот же путь, не
 * пересобирая; в каталоге состояния не остаётся времянок; заданный шов стенда (g_cert_roots)
 * главнее склейки.
 *
 * Сертификаты стенд выпускает сам (mbedtls_x509write), поэтому нужен mbedtls с
 * MBEDTLS_X509_CRT_WRITE_C — как у vlessmatch; без него стенд — громкий пропуск.
 *
 * Сборка — tests/ext-test.sh. */
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <dirent.h>
#include <sys/stat.h>

#ifndef STEER_ANDROID
#define STEER_ANDROID
#endif
/* Каталог состояния и каталоги корней — свои, во временном месте: стенд не трогает ни /data,
 * ни /apex. */
#define STEER_STATE_DIR "/tmp/steer-androidroots/state"
#define STEER_ANDROID_CA_DIRS "/tmp/steer-androidroots/nope", "/tmp/steer-androidroots/empty", \
                              "/tmp/steer-androidroots/cacerts"
#include "../src/ext/client.c"

#include "mbedtls/x509_crt.h"
#include "mbedtls/pk.h"
#include "mbedtls/ecp.h"
#include "mbedtls/ctr_drbg.h"
#include "mbedtls/entropy.h"

static int g_fail, g_pass;
static void check(const char *what, long want, long got) {
    if (want == got) { g_pass++; printf("%-58s ok\n", what); }
    else { g_fail++; printf("%-58s FAIL (ожидалось %ld, получено %ld)\n", what, want, got); }
}

#ifdef STEER_HAVE_X509WRITE
#include "mbedtls/x509_csr.h"

static int rng(void *ctx, unsigned char *out, size_t n) {
    (void)ctx;
    return getrandom(out, n, 0) == (ssize_t)n ? 0 : -1;
}

/* Самоподписанный сертификат в PEM — корень, как в хранилище Android. */
static int make_root(const char *cn, char *pem, size_t cap) {
    mbedtls_pk_context key;
    mbedtls_x509write_cert crt;
    mbedtls_pk_init(&key);
    mbedtls_x509write_crt_init(&crt);
    int rc = mbedtls_pk_setup(&key, mbedtls_pk_info_from_type(MBEDTLS_PK_ECKEY));
    if (!rc) rc = mbedtls_ecp_gen_key(MBEDTLS_ECP_DP_SECP256R1, mbedtls_pk_ec(key), rng, NULL);
    char name[128];
    snprintf(name, sizeof name, "CN=%s,O=steer", cn);
    if (!rc) rc = mbedtls_x509write_crt_set_subject_name(&crt, name);
    if (!rc) rc = mbedtls_x509write_crt_set_issuer_name(&crt, name);
    mbedtls_x509write_crt_set_subject_key(&crt, &key);
    mbedtls_x509write_crt_set_issuer_key(&crt, &key);
    mbedtls_x509write_crt_set_md_alg(&crt, MBEDTLS_MD_SHA256);
    unsigned char serial[] = { 1 };
    if (!rc) rc = mbedtls_x509write_crt_set_serial_raw(&crt, serial, sizeof serial);
    if (!rc) rc = mbedtls_x509write_crt_set_validity(&crt, "20250101000000", "20450101000000");
    if (!rc) rc = mbedtls_x509write_crt_set_basic_constraints(&crt, 1, -1);
    if (!rc) rc = mbedtls_x509write_crt_pem(&crt, (unsigned char *)pem, cap, rng, NULL);
    mbedtls_x509write_crt_free(&crt);
    mbedtls_pk_free(&key);
    return rc;
}
#endif

int main(void) {
#ifndef STEER_HAVE_X509WRITE
    printf("androidroots: в этой mbedtls нет выпуска X.509 — ПРОПУСК\n");
    return 0;
#else
    (void)system("rm -rf /tmp/steer-androidroots");
    mkdir("/tmp/steer-androidroots", 0700);
    mkdir("/tmp/steer-androidroots/state", 0700);
    mkdir("/tmp/steer-androidroots/cacerts", 0700);
    mkdir("/tmp/steer-androidroots/empty", 0700);      /* есть, но пуст — пропустить */

    /* Три корня в формате Android: текст перед PEM и хвостовая строка SHA1, как в
     * system/ca-certificates/files. Плюс скрытый файл, который читать нельзя. */
    const int N = 3;
    for (int i = 0; i < N; i++) {
        char pem[4096], cn[32], path[128];
        snprintf(cn, sizeof cn, "root-%d", i);
        if (make_root(cn, pem, sizeof pem) != 0) { printf("выпуск корня не удался\n"); return 1; }
        snprintf(path, sizeof path, "/tmp/steer-androidroots/cacerts/%08x.0", 0x1000 + i);
        FILE *f = fopen(path, "w");
        fprintf(f, "Certificate:\n    Data:\n        Version: 3 (0x2)\n        Subject: O=steer, CN=%s\n"
                   "        Subject Public Key Info: ...\n%s"
                   "SHA1 Fingerprint=00:11:22:33\n", cn, pem);
        fclose(f);
    }
    FILE *h = fopen("/tmp/steer-androidroots/cacerts/.hidden", "w");
    fputs("-----BEGIN CERTIFICATE-----\nбрак\n-----END CERTIFICATE-----\n", h);
    fclose(h);

    /* Каталог состояния — как его задаёт --state-dir (g_state_dir, spec.c). */
    g_state_dir = "/tmp/steer-androidroots/state";
    const char *p = cert_roots();
    check("склейка: путь выдан", 1, p != NULL);
    check("склейка: из третьего каталога (первого нет, второй пуст), в каталоге состояния", 0,
          p ? strcmp(p, "/tmp/steer-androidroots/state/ca-roots.pem") : -1);

    mbedtls_x509_crt roots;
    mbedtls_x509_crt_init(&roots);
    int rc = p ? mbedtls_x509_crt_parse_file(&roots, p) : -1;
    int n = 0;
    for (mbedtls_x509_crt *c = &roots; c && c->version; c = c->next) n++;
    check("склейка: разбор без ошибок (текст между PEM не мешает)", 0, rc);
    check("склейка: сертификатов столько же, сколько файлов", N, n);
    mbedtls_x509_crt_free(&roots);

    check("повторный вызов: тот же путь", 1, cert_roots() == p);

    int left = 0;
    DIR *d = opendir("/tmp/steer-androidroots/state");
    for (struct dirent *e; d && (e = readdir(d));)
        if (strstr(e->d_name, ".XXXXXX") || strstr(e->d_name, "ca-roots.pem."))
            left++;
    if (d) closedir(d);
    check("времянок в каталоге состояния нет", 0, left);

    /* Шов стенда главнее: заданный g_cert_roots отдаётся как есть, склейка не зовётся. */
    g_cert_roots = "/свой/путь.pem";
    check("заданный шов отдаётся как есть", 0, strcmp(cert_roots(), "/свой/путь.pem"));
    g_cert_roots = NULL;

    (void)system("rm -rf /tmp/steer-androidroots");
    printf("\n%d проверок пройдено%s\n", g_pass, g_fail ? "" : "\nвсе проверки прошли");
    return g_fail ? 1 : 0;
#endif
}
