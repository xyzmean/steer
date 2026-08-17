/* Заглушки команд расширенной сборки — только для стенда diagmatch.
 *
 * Спека с `kind: vless` отвергается парсером, если движок собран без STEER_EXTENDED
 * (spec.c: «kind vless требует пакет steer-extended»). Значит проверить диагностику
 * на конфигурации с VLESS-выходом базовым бинарником нельзя вовсе — а именно такая
 * конфигурация и интересна: у неё свои ограничения по протоколу.
 *
 * Собирать ради этого настоящий src/ext нельзя: он тянет mbedtls и docker (см. R-014).
 * Но steer.c обращается к расширенной части через несколько функций — подкоманды `vless`,
 * `vless-nodes`, `vless-probe` и, с появлением звезды, `xsteer`, `xsteer-peers`,
 * `xsteer-key`. Ни одну из них diag не зовёт, поэтому стенду достаточно их существования
 * при компоновке. Если расширенная часть однажды понадобится diag по-настоящему, стенд
 * сообщит об этом отказом, а не тишиной.
 *
 * Хаб (`xsteer-hub`) здесь НЕ нужен: он под гейтом серверной сборки, а diagsim собирается
 * без него и получает отказ прямо из steer.c. */
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

int cmd_xsteer(const char *spec_path, const char *out_name, const char *conf,
               const char *device);
int cmd_xsteer_peers(const char *spec_path, const char *out_name, const char *conf);

int cmd_xsteer(const char *spec_path, const char *out_name, const char *conf,
               const char *device) {
    (void)spec_path; (void)out_name; (void)conf; (void)device;
    return stub("xsteer");
}
int cmd_xsteer_peers(const char *spec_path, const char *out_name, const char *conf) {
    (void)spec_path; (void)out_name; (void)conf;
    return stub("xsteer-peers");
}

/* Служебные подкоманды xsteer живут в src/ext/xsadmin.c, и циклов в них нет вовсе — но
 * генерация ключа опирается на примитивы reality.c, то есть на mbedtls, которого у стенда
 * нет. Поэтому заглушки нужны и здесь. */
int cmd_xsteer_key(void);
int cmd_xsteer_check(const char *conf);

int cmd_xsteer_key(void) { return stub("xsteer-key"); }
int cmd_xsteer_check(const char *conf) { (void)conf; return stub("xsteer-check"); }
