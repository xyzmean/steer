#include "sindex.h"
#include <stdlib.h>
#include <string.h>

uint32_t sidx_hash(const char *s) {
    /* FNV-1a: три операции на байт и никаких таблиц. Имена короткие, и разница с более
     * хитрыми функциями здесь меньше, чем цена одного промаха кэша. */
    uint32_t h = 2166136261u;
    for (; *s; s++) {
        h ^= (unsigned char)*s;
        h *= 16777619u;
    }
    return h;
}

void sindex_free(struct sindex *ix) {
    free(ix->slot);
    ix->slot = NULL;
    ix->cap = 0;
    ix->n = 0;
}

static void sidx_insert_raw(struct sindex *ix, const void *owner, sidx_key_fn key,
                            const char *s, uint32_t val) {
    uint32_t m = ix->cap - 1;
    uint32_t i = sidx_hash(s) & m;
    while (ix->slot[i]) {
        uint32_t idx = (ix->slot[i] & SIDX_IDX_MASK) - 1;
        if (strcmp(key(owner, idx), s) == 0) {
            /* Тот же ключ: добавляем метку типа, а не второй слот. */
            ix->slot[i] |= val & ~SIDX_IDX_MASK;
            return;
        }
        i = (i + 1) & m;
    }
    ix->slot[i] = val;
    ix->n++;
}

/* Место под ещё одну запись; при заполнении выше половины таблица удваивается. */
static int sindex_reserve(struct sindex *ix, const void *owner, sidx_key_fn key) {
    if (ix->cap && (ix->n + 1) * 2 <= ix->cap) return 0;
    uint32_t ncap = ix->cap ? ix->cap * 2 : 256;
    uint32_t *ns = calloc(ncap, sizeof(*ns));
    if (!ns) return -1;
    uint32_t *old = ix->slot;
    uint32_t ocap = ix->cap;
    ix->slot = ns;
    ix->cap = ncap;
    ix->n = 0;
    for (uint32_t i = 0; i < ocap; i++) {
        if (!old[i]) continue;
        uint32_t idx = (old[i] & SIDX_IDX_MASK) - 1;
        sidx_insert_raw(ix, owner, key, key(owner, idx), old[i]);
    }
    free(old);
    return 0;
}

int sindex_put(struct sindex *ix, const void *owner, sidx_key_fn key,
               const char *s, uint32_t idx, unsigned tag) {
    if (sindex_reserve(ix, owner, key) != 0) return -1;
    sidx_insert_raw(ix, owner, key, s, (idx + 1) | (tag << SIDX_TAG_SHIFT));
    return 0;
}

/* Ноль, если ключа нет. Иначе номер записи в младших битах и метки в старших. */
uint32_t sindex_get(const struct sindex *ix, const void *owner, sidx_key_fn key,
                     const char *s) {
    if (!ix->cap) return 0;
    uint32_t m = ix->cap - 1;
    uint32_t i = sidx_hash(s) & m;
    while (ix->slot[i]) {
        uint32_t idx = (ix->slot[i] & SIDX_IDX_MASK) - 1;
        if (strcmp(key(owner, idx), s) == 0) return ix->slot[i];
        i = (i + 1) & m;
    }
    return 0;
}
