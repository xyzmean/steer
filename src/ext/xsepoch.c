/* Ратчет эпох: вывод следующего корня и разворот шифра на нём. Обоснование — в xsepoch.h.
 *
 * ПОРЯДОК ВЫВОДА ПОВТОРЯЕТ noise/epoch.go БУКВА В БУКВУ, потому что номер эпохи не
 * передаётся: любая разница в метке, длине или порядке шагов проявится не отказом
 * рукопожатия, а тишиной на 64-м мегабайте. Метки — те же строки:
 *
 *     следующий корень = HKDF-Extract(соль = прежний корень, ikm = "xsteer epoch advance")
 *     prk              = HKDF-Extract(соль = следующий корень, ikm = пусто)
 *     44 байта         = HKDF-Expand(prk, "xsteer epoch keys")  →  ключ(32) и iv(12)
 *
 * СОЛЬ — ЭТО КЛЮЧ HMAC, и в обоих вызовах она стоит первой. Написано это явно потому, что в
 * Go порядок аргументов ОБРАТНЫЙ (hkdf.Extract(hash, secret, salt)), и `Extract(sha256.New,
 * nil, next)` читается как «ikm пустой, соль next». Перепутанные местами, они дают тот же
 * корень и другие ключи — то есть туннель, который работает и умирает ровно на 64-м
 * мегабайте; поймал это только живой стенд, поэтому вывод и закреплён векторами
 * (tests/xsepochmatch.c).
 *
 * Пустой ikm записан строкой нулевой длины, как и в split_keys.
 */
#define _GNU_SOURCE
#include <string.h>

#include "mbedtls/hkdf.h"
#include "mbedtls/md.h"

#include "xsepoch.h"

#define EP_LABEL_ADV  "xsteer epoch advance"
#define EP_LABEL_KEYS "xsteer epoch keys"

void xs_epoch_start(struct xs_epoch *e, const uint8_t root[32]) {
    memset(e, 0, sizeof(*e));
    memcpy(e->root, root, 32);
    e->on = 1;
}

void xs_epoch_stop(struct xs_epoch *e) {
    if (e->prev_ok) {
        tls13_keys_free(&e->prev);
        e->prev_ok = 0;
    }
    /* Корень — секрет: из него выводятся все будущие ключи этого направления. Затираем через
     * volatile-указатель по той же причине, что xs_conf_wipe: memset по памяти, которая
     * больше не читается, компилятор вправе выбросить целиком. */
    volatile uint8_t *p = e->root;
    for (int i = 0; i < 32; i++) p[i] = 0;
    e->on = 0;
    e->epoch = 0;
}

/* Один шаг ратчета: вывести следующий корень из текущего и развернуть на нём шифр. Прошлый
 * корень СТИРАЕТСЯ — в этом весь смысл: назад по хешу не пройти, и вскрытая память не выдаёт
 * прошлые эпохи. */
static int ep_advance(struct xs_epoch *e, struct tls13_keys *k) {
    const mbedtls_md_info_t *md = mbedtls_md_info_from_type(MBEDTLS_MD_SHA256);
    if (!md) return TLS13_ECRYPTO;
    uint8_t next[32], prk[32], out[44];
    int rc = TLS13_ECRYPTO;
    if (mbedtls_hkdf_extract(md, e->root, 32, (const uint8_t *)EP_LABEL_ADV,
                             sizeof(EP_LABEL_ADV) - 1, next) != 0) goto done;
    /* СОЛЬ — это next, а ikm пустой, а не наоборот. Порядок аргументов здесь стоил живого
     * стенда: hkdf.Extract(hash, secret, salt) в Go принимает ikm ПЕРВЫМ, а соль второй, и
     * `Extract(sha256.New, nil, next)` означает HMAC(ключ = next, данные = пусто). Перепутав
     * их, я получил тот же корень (он выводится другим вызовом) и ДРУГИЕ ключи — то есть
     * туннель, который исправно работает и умирает ровно на 64-м мегабайте. Ровно так же
     * устроен и первый Extract в split_keys: соль это ck, ikm пустой. */
    if (mbedtls_hkdf_extract(md, next, 32, (const uint8_t *)"", 0, prk) != 0) goto done;
    if (mbedtls_hkdf_expand(md, prk, 32, (const uint8_t *)EP_LABEL_KEYS,
                            sizeof(EP_LABEL_KEYS) - 1, out, sizeof(out)) != 0) goto done;

    /* Новый контекст шифра разворачивается ДО того, как тронуто что-либо ещё: отказ разворота
     * на полпути оставил бы направление без рабочих ключей вовсе. */
    struct tls13_keys nk;
    memset(&nk, 0, sizeof(nk));
    nk.aead = k->aead;
    nk.key_n = k->key_n;
    memcpy(nk.key, out, nk.key_n);
    memcpy(nk.iv, out + 32, 12);
    if (tls13_keys_setup(&nk) != 0) goto done;

    /* ПЕРЕМЕЩЕНИЕ, А НЕ КОПИЯ, и это важно ровно настолько, насколько написано в tls13.h:
     * контекст AES внутри GCM лежит в куче, и две структуры с одним указателем освободили бы
     * одну память дважды. Здесь у контекста в каждый момент РОВНО ОДИН владелец: прежние
     * ключи переезжают в prev, а *k тут же перезаписывается новыми и старым владельцем быть
     * перестаёт. Освобождение прежнего prev — до переезда, иначе он утечёт. */
    if (e->prev_ok) tls13_keys_free(&e->prev);
    e->prev = *k;
    e->prev_ok = 1;
    *k = nk;
    memcpy(e->root, next, 32);
    e->epoch++;
    rc = 0;
done:
    {
        /* Выведенный материал больше не нужен: корень скопирован, ключ развёрнут в шифре. */
        volatile uint8_t *a = next, *b = prk, *c = out;
        for (size_t i = 0; i < sizeof(next); i++) a[i] = 0;
        for (size_t i = 0; i < sizeof(prk); i++) b[i] = 0;
        for (size_t i = 0; i < sizeof(out); i++) c[i] = 0;
    }
    return rc;
}

/* Подвести направление к нужной эпохе. Назад не ходит: эпохи только вперёд. */
static int ep_to(struct xs_epoch *e, struct tls13_keys *k, uint64_t want) {
    if (want <= e->epoch) return 0;
    if (want - e->epoch > XS_EPOCH_JUMP_MAX) return TLS13_EAUTH;
    while (e->epoch < want) {
        int rc = ep_advance(e, k);
        if (rc != 0) return rc;
    }
    return 0;
}

int xs_epoch_seal(struct xs_epoch *e, struct tls13_keys *k, uint64_t off,
                  const uint8_t *aad, size_t aad_n,
                  uint8_t *buf, size_t n, uint8_t *tag) {
    if (e->on) {
        /* Эпоха записи определяется её смещением, и получатель посчитает ту же самую: номер
         * эпохи нигде не передаётся. */
        int rc = ep_to(e, k, off / XS_EPOCH_BYTES);
        if (rc != 0) return rc;
    }
    return tls13_aead_seal(k, off, aad, aad_n, buf, n, tag);
}

int xs_epoch_open(struct xs_epoch *e, struct tls13_keys *k, uint64_t off,
                  const uint8_t *aad, size_t aad_n,
                  uint8_t *buf, size_t n) {
    if (e->on) {
        uint64_t want = off / XS_EPOCH_BYTES;
        if (want + 1 == e->epoch && e->prev_ok) {
            /* Запись прошлой эпохи: расшифровываем прошлыми ключами и состояние НЕ откатываем. */
            return tls13_aead_open(&e->prev, off, aad, aad_n, buf, n);
        }
        if (want > e->epoch) {
            int rc = ep_to(e, k, want);
            if (rc != 0) return rc;
        } else if (want < e->epoch) {
            /* Слишком старая эпоха: её ключи стёрты — в этом и смысл ратчета. Код тот же, что
             * у несошедшегося тега: снаружи это одно и то же событие — «запись не наша». */
            return TLS13_EAUTH;
        }
    }
    return tls13_aead_open(k, off, aad, aad_n, buf, n);
}
