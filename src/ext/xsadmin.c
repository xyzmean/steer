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

#include "xsconf.h"
#include "reality.h"

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
        xs_conf_wipe(&sec);
        return 0;
    }
    if (xs_conf_load(conf_path, XS_ROLE_HUB, &c, &sec, err2, sizeof(err2)) == 0) {
        xs_conf_wipe(&sec);
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
