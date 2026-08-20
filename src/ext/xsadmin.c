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
    if (c->dns_n) printf("DNS: %d адр. — приняты, но на роутере НЕ применяются\n", c->dns_n);
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
    if (xs_conf_load(conf_path, XS_ROLE_SPOKE, &c, &sec, err, sizeof(err)) == 0) {
        /* Секреты затираются ДО печати, а не после: так «в выводе нет приватного ключа»
         * становится свойством порядка операций, а не обещанием. Тот же приём, что в
         * cmd_xsteer_peers. */
        xs_conf_wipe(&sec);
        check_report(conf_path, "пир", &c);
        return 0;
    }
    if (xs_conf_load(conf_path, XS_ROLE_HUB, &c, &sec, err2, sizeof(err2)) == 0) {
        xs_conf_wipe(&sec);
        check_report(conf_path, "хаб", &c);
        return 0;
    }
    fprintf(stderr, "steer: %s\n", strstr(err, "ListenPort") ? err2 : err);
    return 2;
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
