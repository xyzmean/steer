/* Идентификатор роутера и описание устройства. Разбор — в src/hwid.h.
 *
 * ФАЙЛ ПЕРЕЕХАЛ СЮДА ИЗ src/ext/subfetch.c БЕЗ ЕДИНОГО ИЗМЕНЕНИЯ ШАГА ВЫЧИСЛЕНИЯ, и это
 * главное его свойство: значение уже разошлось по панелям подписок, и любая правка объявила
 * бы каждый заведённый роутер новым устройством. Единственная замена — sha256: mbedtls
 * заменён своей реализацией, потому что базовая сборка с mbedtls не связывается. Совпадение
 * результата проверяет стенд, сверяя его с `sha256sum` оболочки, а не с нашим же кодом.
 */
#include <dirent.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "hwid.h"

const char *steer_env_or(const char *name, const char *dflt) {
    const char *v = getenv(name);
    return (v && *v) ? v : dflt;
}

/* ---- SHA-256 -----------------------------------------------------------------------
 *
 * Обычный SHA-256 из FIPS 180-4, без единой особенности: он обязан совпадать и с
 * `mbedtls_sha256`, которым считалось раньше, и с `sha256sum`, которым считала оболочка до
 * движка. Проверяется это не чтением, а известными ответами (стенд hwidmatch): «abc» и
 * пустая строка — те самые векторы, которые печатает сам стандарт, плюс сверка настоящего
 * идентификатора с выводом `sha256sum` в оболочке.
 *
 * Реализация ровно на один вызов: всё сообщение в памяти, потокового интерфейса нет. Нам
 * хешировать двадцать пять байт, а поток — это состояние, которое нечем проверить. */
static uint32_t ror(uint32_t x, int k) { return (x >> k) | (x << (32 - k)); }

void steer_sha256(const unsigned char *in, size_t n, unsigned char out[32]) {
    static const uint32_t K[64] = {
        0x428a2f98u, 0x71374491u, 0xb5c0fbcfu, 0xe9b5dba5u, 0x3956c25bu, 0x59f111f1u,
        0x923f82a4u, 0xab1c5ed5u, 0xd807aa98u, 0x12835b01u, 0x243185beu, 0x550c7dc3u,
        0x72be5d74u, 0x80deb1feu, 0x9bdc06a7u, 0xc19bf174u, 0xe49b69c1u, 0xefbe4786u,
        0x0fc19dc6u, 0x240ca1ccu, 0x2de92c6fu, 0x4a7484aau, 0x5cb0a9dcu, 0x76f988dau,
        0x983e5152u, 0xa831c66du, 0xb00327c8u, 0xbf597fc7u, 0xc6e00bf3u, 0xd5a79147u,
        0x06ca6351u, 0x14292967u, 0x27b70a85u, 0x2e1b2138u, 0x4d2c6dfcu, 0x53380d13u,
        0x650a7354u, 0x766a0abbu, 0x81c2c92eu, 0x92722c85u, 0xa2bfe8a1u, 0xa81a664bu,
        0xc24b8b70u, 0xc76c51a3u, 0xd192e819u, 0xd6990624u, 0xf40e3585u, 0x106aa070u,
        0x19a4c116u, 0x1e376c08u, 0x2748774cu, 0x34b0bcb5u, 0x391c0cb3u, 0x4ed8aa4au,
        0x5b9cca4fu, 0x682e6ff3u, 0x748f82eeu, 0x78a5636fu, 0x84c87814u, 0x8cc70208u,
        0x90befffau, 0xa4506cebu, 0xbef9a3f7u, 0xc67178f2u,
    };
    uint32_t h[8] = { 0x6a09e667u, 0xbb67ae85u, 0x3c6ef372u, 0xa54ff53au,
                      0x510e527fu, 0x9b05688cu, 0x1f83d9abu, 0x5be0cd19u };
    /* Дополнение считается заранее, целиком: сообщение у нас короткое, и держать его в
     * одном буфере дешевле, чем вести состояние между блоками. */
    size_t total = n + 1 + 8;
    size_t blocks = (total + 63) / 64;
    size_t padded = blocks * 64;
    unsigned char stack_buf[128];
    unsigned char *buf = stack_buf;
    unsigned char *heap = NULL;
    if (padded > sizeof stack_buf) {
        heap = (unsigned char *)calloc(1, padded);
        if (!heap) { memset(out, 0, 32); return; }
        buf = heap;
    } else {
        memset(buf, 0, sizeof stack_buf);
    }
    memcpy(buf, in, n);
    buf[n] = 0x80;
    uint64_t bits = (uint64_t)n * 8;
    for (int i = 0; i < 8; i++) buf[padded - 1 - i] = (unsigned char)(bits >> (8 * i));

    for (size_t b = 0; b < blocks; b++) {
        const unsigned char *p = buf + b * 64;
        uint32_t w[64];
        for (int i = 0; i < 16; i++)
            w[i] = ((uint32_t)p[i * 4] << 24) | ((uint32_t)p[i * 4 + 1] << 16) |
                   ((uint32_t)p[i * 4 + 2] << 8) | (uint32_t)p[i * 4 + 3];
        for (int i = 16; i < 64; i++) {
            uint32_t s0 = ror(w[i - 15], 7) ^ ror(w[i - 15], 18) ^ (w[i - 15] >> 3);
            uint32_t s1 = ror(w[i - 2], 17) ^ ror(w[i - 2], 19) ^ (w[i - 2] >> 10);
            w[i] = w[i - 16] + s0 + w[i - 7] + s1;
        }
        uint32_t a = h[0], bb = h[1], c = h[2], d = h[3];
        uint32_t e = h[4], f = h[5], g = h[6], hh = h[7];
        for (int i = 0; i < 64; i++) {
            uint32_t S1 = ror(e, 6) ^ ror(e, 11) ^ ror(e, 25);
            uint32_t ch = (e & f) ^ ((~e) & g);
            uint32_t t1 = hh + S1 + ch + K[i] + w[i];
            uint32_t S0 = ror(a, 2) ^ ror(a, 13) ^ ror(a, 22);
            uint32_t mj = (a & bb) ^ (a & c) ^ (bb & c);
            uint32_t t2 = S0 + mj;
            hh = g; g = f; f = e; e = d + t1;
            d = c; c = bb; bb = a; a = t1 + t2;
        }
        h[0] += a; h[1] += bb; h[2] += c; h[3] += d;
        h[4] += e; h[5] += f; h[6] += g; h[7] += hh;
    }
    free(heap);
    for (int i = 0; i < 8; i++) {
        out[i * 4]     = (unsigned char)(h[i] >> 24);
        out[i * 4 + 1] = (unsigned char)(h[i] >> 16);
        out[i * 4 + 2] = (unsigned char)(h[i] >> 8);
        out[i * 4 + 3] = (unsigned char)h[i];
    }
}

/* ---- HMAC-SHA256 и PBKDF2 ----------------------------------------------------------
 *
 * Ровно столько, сколько нужно одному вызову: ключ короче блока, длина вывода 16 или 32
 * байта. Потоковый интерфейс не заводится — считать надо один раз за жизнь роутера. */
static void hmac_sha256(const unsigned char *key, size_t klen,
                        const unsigned char *msg, size_t mlen, unsigned char out[32]) {
    unsigned char k[64];
    memset(k, 0, sizeof k);
    if (klen > 64) {
        unsigned char kh[32];
        steer_sha256(key, klen, kh);
        memcpy(k, kh, 32);
    } else {
        memcpy(k, key, klen);
    }
    unsigned char in[64 + 64];
    /* Внутренний проход: (ключ^0x36) ‖ сообщение. Буфер под сообщение фиксирован, потому что
     * длиннее 64 байт мы здесь не хешируем — это проверяет вызывающий, а не удача. */
    unsigned char *buf = (unsigned char *)malloc(64 + mlen);
    if (!buf) { memset(out, 0, 32); return; }
    for (int i = 0; i < 64; i++) buf[i] = (unsigned char)(k[i] ^ 0x36);
    memcpy(buf + 64, msg, mlen);
    unsigned char ih[32];
    steer_sha256(buf, 64 + mlen, ih);
    free(buf);
    for (int i = 0; i < 64; i++) in[i] = (unsigned char)(k[i] ^ 0x5c);
    memcpy(in + 64, ih, 32);
    steer_sha256(in, 96, out);
}

void steer_pbkdf2_sha256(const unsigned char *pw, size_t pwlen,
                         const unsigned char *salt, size_t saltlen,
                         unsigned iters, unsigned char *out, size_t outlen) {
    unsigned block = 1;
    size_t done = 0;
    if (iters == 0) iters = 1;
    while (done < outlen) {
        /* U1 = HMAC(пароль, соль ‖ номер блока), дальше Ui = HMAC(пароль, U(i-1)). */
        unsigned char *m = (unsigned char *)malloc(saltlen + 4);
        if (!m) { memset(out + done, 0, outlen - done); return; }
        memcpy(m, salt, saltlen);
        m[saltlen]     = (unsigned char)(block >> 24);
        m[saltlen + 1] = (unsigned char)(block >> 16);
        m[saltlen + 2] = (unsigned char)(block >> 8);
        m[saltlen + 3] = (unsigned char)block;
        unsigned char u[32], acc[32];
        hmac_sha256(pw, pwlen, m, saltlen + 4, u);
        free(m);
        memcpy(acc, u, 32);
        for (unsigned i = 1; i < iters; i++) {
            hmac_sha256(pw, pwlen, u, 32, u);
            for (int j = 0; j < 32; j++) acc[j] ^= u[j];
        }
        size_t take = outlen - done < 32 ? outlen - done : 32;
        memcpy(out + done, acc, take);
        done += take;
        block++;
    }
}

/* ---- идентификатор устройства для панели подписки (HWID) ----------------------------
 *
 * ЗАЧЕМ. Панели (Remnawave и родня) умеют привязывать подписку к устройствам и требуют,
 * чтобы клиент назвал себя заголовком `x-hwid`. Клиенту, который его не присылает, панель
 * отвечает не отказом, а ЗАГЛУШКОЙ: HTTP 200 и пара законных ссылок на `0.0.0.0:1`, где
 * сообщение человеку спрятано в ИМЯ узла («📱 Неправильный клиент», «🔌 Лимит устройств
 * достигнут»). То есть подписка скачалась, узлы есть, туннель не поднимется никогда — ровно
 * тот вид отказа, который в проекте называется тихим. Замерено на живой подписке: без
 * заголовка приезжает 556 байт заглушки, с заголовком — 15 КБ настоящих узлов.
 *
 * ИЗ ЧЕГО СЧИТАЕТСЯ. Из MAC-адреса. Это единственный признак на роутере, который переживает
 * сброс к заводским настройкам: сброс стирает overlay, то есть весь /etc, а MAC живёт в
 * самом устройстве и приезжает от ядра. Любой идентификатор, сохранённый в файл (UUID,
 * случайное число), после сброса стал бы ДРУГИМ устройством — человек, сбросивший роутер,
 * потерял бы слот в панели и не понял бы, почему.
 *
 * MAC НАРУЖУ НЕ УХОДИТ: HWID — это хеш от него. Панели нужен постоянный идентификатор, а не
 * адрес железа; отдавать адрес значило бы рассказать чужому серверу больше, чем нужно для
 * его работы. Обратной дороги от хеша к адресу нет, а постоянство сохраняется.
 *
 * ЗНАЧЕНИЕ ОБЯЗАНО СОВПАДАТЬ С ПРЕЖНИМ, посчитанным в оболочке: `sha256sum` от строки
 * «splify2:<mac>» без завершающего перевода строки, первые двадцать шестнадцатеричных
 * знаков, приставка «splify2-». Изменить здесь хоть один шаг — значит объявить каждый уже
 * заведённый роутер новым устройством и отобрать у человека его слот в панели.
 */
#define HWID_MAX_IFACES 64
#define HWID_NAME_MAX 32

static int read_line(const char *path, char *out, size_t n) {
    FILE *f = fopen(path, "r");
    if (!f) return 0;
    if (!fgets(out, (int)n, f)) { fclose(f); return 0; }
    fclose(f);
    size_t l = strlen(out);
    while (l && (out[l - 1] == '\n' || out[l - 1] == '\r' || out[l - 1] == ' ')) out[--l] = 0;
    return l > 0;
}

/* Годен ли адрес как ПОСТОЯННЫЙ идентификатор.
 *
 * Адреса «назначен локально» отбрасываются: их выдумывает ядро (так бывает у некоторых
 * wifi-чипов и USB-адаптеров), и после перезагрузки они другие. Признак — второй младший
 * бит первого октета, то есть вторая шестнадцатеричная цифра из 2,3,6,7,a,b,e,f. */
static int mac_usable(const char *m) {
    if (strlen(m) != 17) return 0;
    if (!strcmp(m, "00:00:00:00:00:00") || !strcmp(m, "ff:ff:ff:ff:ff:ff")) return 0;
    if (m[2] != ':') return 0;
    switch (m[1]) {
        case '2': case '3': case '6': case '7':
        case 'a': case 'b': case 'e': case 'f': return 0;
        default: return 1;
    }
}

/* Какой из MAC-адресов брать, если портов несколько.
 *
 * Порядок задан жёстко: сначала имена, которыми OpenWrt называет порты SoC (eth*, lan*,
 * wan*) по алфавиту, потом всё остальное физическое. Виртуальные интерфейсы исключены
 * признаком `device` — у моста, туннеля и wifi-ap ссылки на устройство нет.
 *
 * Имена СОРТИРУЮТСЯ. В оболочке это делал сам glob, а readdir отдаёт их в порядке
 * файловой системы — то есть без сортировки идентификатор менялся бы от перезагрузки к
 * перезагрузке на коробке с несколькими портами, и человек терял бы слот в панели без
 * всякого повода. */
static int hwid_mac(char *out, size_t n) {
    static const char *PFX[] = { "eth", "lan", "wan", "" };
    /* Каталог копируется в буфер известного размера: дальше из него собираются пути, и
     * компилятор обязан видеть, что они влезают. Молча обрезанный путь означал бы чтение
     * чужого файла. Настоящий путь короткий (/sys/class/net), длинным он бывает только у
     * шва стенда. */
    char sysnet[288];
    if (snprintf(sysnet, sizeof sysnet, "%s",
                 steer_env_or("STEER_SYSNET", "/sys/class/net")) >= (int)sizeof sysnet)
        return 0;
    char names[HWID_MAX_IFACES][HWID_NAME_MAX];
    size_t nn = 0;

    DIR *d = opendir(sysnet);
    if (!d) return 0;
    const struct dirent *e;
    while ((e = readdir(d)) != NULL && nn < HWID_MAX_IFACES) {
        if (e->d_name[0] == '.') continue;
        size_t nl = strlen(e->d_name);
        if (nl >= HWID_NAME_MAX) continue;
        /* Копия ДЛИНОЙ, а не через snprintf с «%s»: длина уже проверена строкой выше, но по
         * `e->d_name` компилятор этого не видит и предупреждает об усечении, которого не
         * бывает. Заглушить предупреждение прагмой значило бы спрятать проверку, которая
         * однажды пригодится; memcpy по проверенной длине её наоборот показывает. */
        memcpy(names[nn], e->d_name, nl + 1);
        nn++;
    }
    closedir(d);

    /* Сортировка вставками: имён на роутере десяток-полтора, и заводить ради них qsort с
     * функцией сравнения было бы больше кода, чем сама сортировка. */
    for (size_t i = 1; i < nn; i++)
        for (size_t j = i; j && strcmp(names[j - 1], names[j]) > 0; j--) {
            /* Обмен через memcpy, а не через snprintf: обе строки лежат в одном массиве,
             * и `snprintf` с «%s» из него же — это перекрытие источника и приёмника, о
             * котором компилятор законно предупреждает (-Wrestrict). Длина известна, обмен
             * целыми ячейками её и использует. */
            char t[HWID_NAME_MAX];
            memcpy(t, names[j - 1], HWID_NAME_MAX);
            memcpy(names[j - 1], names[j], HWID_NAME_MAX);
            memcpy(names[j], t, HWID_NAME_MAX);
        }

    for (size_t k = 0; k < sizeof PFX / sizeof PFX[0]; k++) {
        size_t pl = strlen(PFX[k]);
        for (size_t i = 0; i < nn; i++) {
            if (pl && strncmp(names[i], PFX[k], pl)) continue;
            /* Имя через свой буфер известного размера: по `names[i]` компилятор не видит,
             * где кончается строка внутри общего массива, и не может доказать, что путь
             * влезает. Доказательство здесь дешевле подавленного предупреждения. */
            char nm[HWID_NAME_MAX];
            memcpy(nm, names[i], HWID_NAME_MAX);
            nm[HWID_NAME_MAX - 1] = 0;
            char p[384];
            snprintf(p, sizeof p, "%s/%s/device", sysnet, nm);
            if (access(p, F_OK) != 0) continue;   /* виртуальный интерфейс */
            snprintf(p, sizeof p, "%s/%s/address", sysnet, nm);
            char m[64];
            if (!read_line(p, m, sizeof m)) continue;
            for (char *q = m; *q; q++) if (*q >= 'A' && *q <= 'F') *q += 'a' - 'A';
            if (!mac_usable(m)) continue;
            snprintf(out, n, "%s", m);
            return 1;
        }
    }
    return 0;
}

/* Сам идентификатор. Приставка НЕ украшение: HWID человек видит в панели и в боте, и по
 * «splify2-…» он узнаёт свой роутер среди телефонов и ноутбуков — а именно там ему и надо
 * освобождать слот, когда устройств больше, чем позволено. */
int steer_hwid(char *out, size_t n) {
    char mac[64];
    if (!hwid_mac(mac, sizeof mac)) return 0;
    char msg[96];
    int k = snprintf(msg, sizeof msg, "splify2:%s", mac);
    if (k <= 0) return 0;
    unsigned char dg[32];
    steer_sha256((const unsigned char *)msg, (size_t)k, dg);
    char hex[41];
    for (int i = 0; i < 20; i++) snprintf(hex + i * 2, 3, "%02x", dg[i]);
    hex[20] = 0;   /* ровно то, что брал `cut -c1-20` от вывода sha256sum */
    snprintf(out, n, "splify2-%s", hex);
    return 1;
}

/* ---- заголовки, которыми панель описывает устройство ------------------------------
 *
 * Значения честные: человеку в панели полезнее увидеть «OpenWrt · Xiaomi AX3000T», чем
 * выдуманный телефон, а нам незачем притворяться другим клиентом — заглушку панель отдаёт
 * не по User-Agent, а по отсутствию `x-hwid` (проверено: с User-Agent клиента Happ, но без
 * HWID приезжает та же заглушка).
 *
 * Значение чистится обязательно: перевод строки внутри заголовка — это вставка чужого
 * заголовка в запрос, а модель роутера приходит из файла, который пишет не наш код.
 * Оставляется печатаемый ASCII от пробела до тильды: он читаем в панели, а кириллица там
 * всё равно показывается байтами UTF-8, то есть мусором. */
static void hdr_clean(const char *in, char *out, size_t n) {
    size_t o = 0;
    for (const unsigned char *p = (const unsigned char *)in; *p; p++) {
        if (*p < ' ' || *p > '~') continue;
        if (o + 1 >= n || o >= 64) break;
        out[o++] = (char)*p;
    }
    out[o] = 0;
}

void steer_dev_os(char *out, size_t n) {
    char ver[80] = "";
    FILE *f = fopen(steer_env_or("STEER_OPENWRT_RELEASE", "/etc/openwrt_release"), "r");
    if (f) {
        char line[256];
        while (fgets(line, sizeof line, f)) {
            static const char KEY[] = "DISTRIB_RELEASE=";
            if (strncmp(line, KEY, sizeof KEY - 1)) continue;
            char *v = line + sizeof KEY - 1;
            /* Кавычки вокруг значения — часть формата файла, а не значение. */
            if (*v == '\'' || *v == '"') v++;
            size_t l = strlen(v);
            while (l && (v[l - 1] == '\n' || v[l - 1] == '\r' ||
                         v[l - 1] == '\'' || v[l - 1] == '"')) v[--l] = 0;
            snprintf(ver, sizeof ver, "%s", v);
            break;
        }
        fclose(f);
    }
    char raw[176];
    snprintf(raw, sizeof raw, "OpenWrt%s%s", ver[0] ? " " : "", ver);
    hdr_clean(raw, out, n);
}

void steer_dev_model(char *out, size_t n) {
    char m[160] = "";
    if (!read_line(steer_env_or("STEER_SYSINFO_MODEL", "/tmp/sysinfo/model"), m, sizeof m))
        snprintf(m, sizeof m, "router");
    hdr_clean(m, out, n);
}


/* ---- идентификатор для телеметрии --------------------------------------------------
 *
 * Разбор — в hwid.h: почему значение ОТДЕЛЬНОЕ от HWID и почему считается медленно.
 *
 * Соль публичная и общая, и в неё вписан номер: сменить схему когда-нибудь придётся, и
 * тогда старые и новые идентификаторы должны быть различимы, а не молча перемешаться. */
#define DEVID_SALT "splify2-telemetry-id/1"
/* ШЕСТЬСОТ ТЫСЯЧ, а не двести. Считается это ОДИН РАЗ за жизнь роутера — вызывающий
 * запоминает ответ, а счёт детерминирован, поэтому кэш только избавляет от повторной платы
 * и не становится вторым источником истины. Раз плата разовая, её и стоит поднять: 0,6 с на
 * x86 и десятки секунд на слабом MIPS — при первом запуске, в фоне, один раз. Для того, кто
 * захочет восстановить MAC, эта же цифра множится на 2^40 вариантов: около 1,3·10^18 сжатий
 * SHA-256, то есть годы на серьёзной установке вместо минут на одной видеокарте.
 *
 * Верхнюю границу задаёт не безопасность, а сброс к заводским настройкам: после него счёт
 * повторяется, и минута на слабом роутере — это уже заметно человеку. */
#define DEVID_ITERS 600000

int steer_dev_id(char *out, size_t n) {
    char mac[64];
    if (!hwid_mac(mac, sizeof mac)) return 0;
    /* Прообраз — НЕ тот же, что у HWID («splify2:<mac>»), и это не придирка: одинаковый
     * прообраз с разными числами проходов всё равно давал бы два значения одной длины из
     * одного места, и сверить их между собой было бы делом одного вычисления. */
    char msg[96];
    int k = snprintf(msg, sizeof msg, "splify2-telemetry:%s", mac);
    if (k <= 0) return 0;
    unsigned iters = DEVID_ITERS;
    const char *e = getenv("STEER_DEVID_ITERS");
    if (e && *e) {
        long v = strtol(e, NULL, 10);
        /* Шов только для стендов, поэтому и предел скромный: он существует затем, чтобы
         * проверка не считала секунды, а не затем, чтобы кто-то ослабил счёт на роутере. */
        if (v > 0 && v <= DEVID_ITERS) iters = (unsigned)v;
    }
    unsigned char dk[16];
    steer_pbkdf2_sha256((const unsigned char *)msg, (size_t)k,
                        (const unsigned char *)DEVID_SALT, sizeof DEVID_SALT - 1,
                        iters, dk, sizeof dk);
    char hex[33];
    for (int i = 0; i < 16; i++) snprintf(hex + i * 2, 3, "%02x", dk[i]);
    hex[32] = 0;
    snprintf(out, n, "sp-%s", hex);
    return 1;
}

/* ---- подкоманда sub-hwid ------------------------------------------------------------
 *
 * Печатает и в базовой сборке. Прежде здесь стоял отказ «нужен пакет steer-extended», и он
 * был верен ровно пока читатель был один — панель подписки. */
static void hwid_json_str(const char *s) {
    putchar('"');
    for (const unsigned char *p = (const unsigned char *)s; *p; p++) {
        if (*p == '"' || *p == '\\') { putchar('\\'); putchar(*p); }
        else if (*p < 0x20) printf("\\u%04x", *p);
        else putchar(*p);
    }
    putchar('"');
}

int cmd_sub_hwid(void) {
    char id[64] = "";
    int ok = steer_hwid(id, sizeof id);
    char os[80], model[80];
    steer_dev_os(os, sizeof os);
    steer_dev_model(model, sizeof model);
    /* Пустая строка значит «не из чего считать» — ни одного физического порта с постоянным
     * MAC. Тогда заголовок не уходит вовсе, и об этом говорит sub-fetch отдельным словом. */
    printf("{\"hwid\":");
    hwid_json_str(ok ? id : "");
    printf(",\"os\":");
    hwid_json_str(os);
    printf(",\"model\":");
    hwid_json_str(model);
    printf("}\n");
    return 0;
}

/* ---- подкоманда dev-id --------------------------------------------------------------
 *
 * ОТДЕЛЬНО ОТ sub-hwid, И ЭТО РЕШЕНИЕ ПРО ЦЕНУ, А НЕ ПРО ЧИСТОТУ. `sub-hwid` спрашивают на
 * обычном пути: управляющий слой зовёт его, чтобы отдать панели подписки заголовок, и
 * держит ответ в памяти до перезагрузки. Двести тысяч проходов PBKDF2 — это 0,2 секунды на
 * x86 и секунды на слабом MIPS; поставив их в тот же вызов, мы сделали бы медленным путь,
 * который сегодня укладывается в миллисекунды, и заплатили бы этим за поле, которое нужно
 * раз в сутки.
 *
 * Ответ обязан кэшировать вызывающий (у splify2 для этого уже есть место в настройке): счёт
 * детерминирован, поэтому кэш — это только избавление от повторной платы, а не второй
 * источник истины. */
int cmd_dev_id(void) {
    char id[64] = "";
    int ok = steer_dev_id(id, sizeof id);
    printf("{\"tid\":");
    hwid_json_str(ok ? id : "");
    printf("}\n");
    return 0;
}
