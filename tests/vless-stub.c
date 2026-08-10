/* Заглушки команд расширенной сборки — только для стенда diagmatch.
 *
 * Спека с `kind: vless` отвергается парсером, если движок собран без STEER_EXTENDED
 * (spec.c: «kind vless требует пакет steer-extended»). Значит проверить диагностику
 * на конфигурации с VLESS-выходом базовым бинарником нельзя вовсе — а именно такая
 * конфигурация и интересна: у неё свои ограничения по протоколу.
 *
 * Собирать ради этого настоящий src/ext нельзя: он тянет mbedtls и docker (см. R-014).
 * Но steer.c обращается к расширенной части ровно через три функции — подкоманды
 * `vless`, `vless-nodes`, `vless-probe`. Ни одну из них diag не зовёт, поэтому стенду
 * достаточно их существования при компоновке. Если расширенная часть однажды
 * понадобится diag по-настоящему, стенд об этом сообщит отказом, а не тишиной. */
#include <stdio.h>

static int stub(const char *who) {
    fprintf(stderr, "diagmatch: подкоманда %s в стенде не реализована\n", who);
    return 2;
}

int cmd_vless(const char *spec_path, const char *out_name);
int cmd_vless_nodes(const char *spec_path, const char *out_name);
int cmd_vless_probe(const char *spec_path, const char *out_name, int node, int timeout_s);

int cmd_vless(const char *spec_path, const char *out_name) {
    (void)spec_path; (void)out_name;
    return stub("vless");
}
int cmd_vless_nodes(const char *spec_path, const char *out_name) {
    (void)spec_path; (void)out_name;
    return stub("vless-nodes");
}
int cmd_vless_probe(const char *spec_path, const char *out_name, int node, int timeout_s) {
    (void)spec_path; (void)out_name; (void)node; (void)timeout_s;
    return stub("vless-probe");
}
