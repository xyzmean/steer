/* xsteer: две служебные подкоманды — проверка конфигурации и генерация ключей.
 *
 * ЗАЧЕМ ОТДЕЛЬНЫМ ФАЙЛОМ. Обе нужны И пиру, И хабу: конфигурацию проверяет прослойка netifd
 * на роутере, а ключи генерируют на обеих сторонах — без них звезду не настроить. Держать их
 * в цикле пира значило бы, что на VPS их нет вовсе, и оператор хаба остался бы без
 * `xsteer-key`. Ни сокетов, ни TUN здесь нет: только разбор и случайность.
 */
#define _GNU_SOURCE
#include <stdio.h>
#include <string.h>
#include <arpa/inet.h>

#include "xsconf.h"
#include "xslink.h"
#include "xswire.h"
#include "reality.h"

/* Что именно принято, человеческими словами.
 *
 * ЗАЧЕМ ПЕЧАТАТЬ, ЕСЛИ ХВАТАЕТ КОДА ВОЗВРАТА. Молчание отвечает на вопрос «файл разобран?», а
 * человек, который правит конфигурацию работающего хаба, спрашивает другое: «то, что я
 * написал, понято ТАК, как я думал?». Разница видна на самых частых ошибках — Address с
 * маской /32 вместо /24, забытый Endpoint, лишний пир, MTU, который человек считал заданным, а
 * он выводится сам. Ни одна из них не отказ разбора, и увидеть их иначе можно только по
 * поведению туннеля. То же самое и по той же причине печатает `xsteer check` реализации на Go.
 *
 * Печатается в stdout, а не в stderr: это ответ на вопрос, а не жалоба. Прослойка netifd
 * читает только stderr и код возврата (см. splify2, proto/xsteer.sh), поэтому вывод её не
 * задевает. */
static void check_report(const char *path, const char *role, const struct xs_conf *c) {
    struct in_addr in;
    in.s_addr = htonl(c->addr);
    printf("%s: %s, разбор прошёл\n", path, role);
    printf("адрес в туннеле %s/%d", inet_ntoa(in), c->addr_plen);
    if (c->mtu > 0) printf(", MTU задан %d", c->mtu);
    else printf(", MTU выведет сам (потолок %d)", XS_MTU_DEF);
    if (c->listen_port > 0) printf(", слушает %d", c->listen_port);
    printf("\n");
    if (c->sni[0]) printf("SNI %s\n", c->sni);
    /* Названо явно, потому что ключ принят, а поведения за ним нет: молчание здесь читалось
     * бы как «DNS настроен». */
    if (c->dns_n) {
        printf("DNS: ");
        for (int i = 0; i < c->dns_n; i++) printf("%s%s", i ? ", " : "", c->dns[i]);
        printf(" — приняты, но на роутере НЕ применяются\n");
    }
    if (c->device[0]) printf("устройство %s\n", c->device);
    printf("пиров %zu:\n", c->peer_n);
    for (size_t i = 0; i < c->peer_n; i++) {
        const struct xs_peer *p = &c->peer[i];
        char fp[12];
        xs_key_fp(p->pub, fp);
        printf("  %s ", fp);
        for (size_t a = 0; a < p->allowed_n; a++) {
            in.s_addr = htonl(p->allowed[a].net);
            printf("%s%s/%d", a ? ", " : "", inet_ntoa(in), p->allowed[a].plen);
        }
        if (p->endpoint_port) printf("  через %s:%d", p->endpoint, p->endpoint_port);
        if (p->keepalive_set) printf("  keepalive %d с", p->keepalive);
        printf("\n");
    }
}

/* Проверка конфигурации без подъёма. Роль выводится из самого файла: требовать её флагом
 * значило бы дать человеку возможность ошибиться там, где ошибиться нельзя, — а признак
 * однозначен (ListenPort бывает только у хаба). */
int cmd_xsteer_check(const char *conf_path) {
    if (!conf_path) {
        fprintf(stderr, "steer: нужен --config ФАЙЛ\n");
        return 2;
    }
    struct xs_conf c;
    struct xs_secrets sec;
    char err[256], err2[256];
    /* Пробуем как пир, потом как хаб. Печатаем ту ошибку, которая относится к делу: если
     * файл не годен ни в одной роли, человеку полезнее объяснение для той роли, к которой он
     * ближе, — а ближе он к пиру, пока в нём нет ListenPort. */
    /* Принимается и ссылка, и «-»: проверить присланную ссылку до того, как класть её в
     * настройки, — ровно то же действие, что проверить файл, и требовать сначала превратить её в
     * файл значило бы отправить человека делать шаг, который эта команда и должна была избавить
     * от нужды делать. */
    if (xs_conf_load_any(conf_path, XS_ROLE_SPOKE, &c, &sec, NULL, 0, NULL, err, sizeof(err)) == 0) {
        /* Секреты затираются ДО печати, а не после: так «в выводе нет приватного ключа»
         * становится свойством порядка операций, а не обещанием. Тот же приём, что в
         * cmd_xsteer_peers. */
        xs_conf_wipe(&sec);
        check_report(conf_path, "пир", &c);
        return 0;
    }
    if (xs_conf_load_any(conf_path, XS_ROLE_HUB, &c, &sec, NULL, 0, NULL, err2, sizeof(err2)) == 0) {
        xs_conf_wipe(&sec);
        check_report(conf_path, "хаб", &c);
        return 0;
    }
    fprintf(stderr, "steer: %s\n", strstr(err, "ListenPort") ? err2 : err);
    return 2;
}

/* Ссылка из конфигурации и конфигурация из ссылки.
 *
 * НАПРАВЛЕНИЕ ВЫБИРАЕТСЯ ПО ВХОДУ, а не отдельным ключом, и это не экономия на флагах: человек
 * здесь всегда хочет «дай мне другой вид того же самого», и спрашивать его, какой именно, значило
 * бы заставлять называть то, что уже видно из аргумента. Ошибиться нечем: файл и ссылка
 * различаются первыми знаками.
 *
 * Роль пробуется ТОЛЬКО пирская. Хабовая конфигурация ссылкой не выражается (у неё список пиров), и
 * попытка разобрать её как пира дала бы отказ не про то — поэтому про хаб сказано прямо, отдельной
 * строкой, тем же приёмом, что в xs_link_parse. */
int cmd_xsteer_link(const char *what, const char *name) {
    struct xs_conf c;
    struct xs_secrets sec;
    char err[384], from_link[XS_LINK_NAME_MAX] = "";
    if (!what) {
        fprintf(stderr, "steer: нужен файл, ссылка xs:// или «-» (позиционным аргументом "
                        "или --config)\n");
        return 2;
    }
    int was_link = 0;
    if (xs_conf_load_any(what, XS_ROLE_SPOKE, &c, &sec, from_link, sizeof(from_link),
                         &was_link, err, sizeof(err)) != 0) {
        /* Хабовую конфигурацию узнаём по её же отказу: ListenPort в файле есть, а пиром он не
         * бывает. Сказать «это хаб» полезнее, чем перечислить, чем файл не годится для пира. */
        if (strstr(err, "ListenPort"))
            fprintf(stderr, "steer: это конфигурация хаба — ссылка описывает доступ ОДНОГО пира, "
                            "а у хаба список пиров. Ссылку выдают из конфигурации пира.\n");
        else
            fprintf(stderr, "steer: %s\n", err);
        return 2;
    }
    char out[XS_URI_MAX];
    int rc;
    if (was_link) {
        /* Пришла ссылка — печатаем файл. Имя из фрагмента при этом ТЕРЯЕТСЯ, и это не потеря:
         * поля «имя» в конфигурации нет вовсе, а выдумывать под него ключ значило бы завести в
         * формате файла то, чего в нём нет. Кто хочет сохранить имя, держит его снаружи — так же,
         * как имя интерфейса. */
        rc = xs_conf_render(&c, &sec, out, sizeof(out), err, sizeof(err));
    } else {
        rc = xs_link_render(&c, &sec, name && *name ? name : NULL, out, sizeof(out),
                            err, sizeof(err));
    }
    /* Секреты живут ровно до печати и ни мгновением дольше — но затереть их можно только ПОСЛЕ
     * печати: приватный ключ и есть то, что печатается. Отсюда порядок: напечатали, затёрли. */
    if (rc != 0) {
        xs_conf_wipe(&sec);
        fprintf(stderr, "steer: %s\n", err);
        return 2;
    }
    printf("%s\n", out);
    memset(out, 0, sizeof(out));
    xs_conf_wipe(&sec);
    return 0;
}

int cmd_xsteer_key(void) {
    uint8_t priv[32], pub[32];
    if (xc_x25519_keypair(priv, pub) != 0) {
        /* Отказываемся, а не выдумываем ключ из времени: предсказуемый ключ хуже
         * отсутствующего, потому что отсутствующий заметен сразу, а предсказуемый — никогда. */
        fprintf(stderr, "steer: нет источника случайности — ключ не сгенерирован\n");
        return 2;
    }
    char b[XS_KEY_B64 + 1];
    xs_key_encode(priv, b);
    printf("PrivateKey = %s\n", b);
    xs_key_encode(pub, b);
    printf("PublicKey  = %s\n", b);
    volatile uint8_t *p = priv;
    for (int i = 0; i < 32; i++) p[i] = 0;
    return 0;
}
