/* Заглушки моста — только для стенда tgwsmark (build/tgwssim).
 *
 * Стенд проверяет не мост, а то, что мини-сборка (STEER_TGWS) печатает в ruleset рядом с
 * полным движком: свой бит метки, свой порт, свой ряд таблиц, отношение к чужому реестру.
 * Собирать ради этого настоящий src/ext нельзя — он тянет TLS и docker (см. R-014), — а
 * steer.c под STEER_TGWS обращается к мосту ровно через три функции, ни одну из которых
 * apply не зовёт. Стенду достаточно их существования при компоновке. */
#include <stdio.h>

int cmd_tgws(const char *spec_path, const char *out_name);
int cmd_tgws_probe(int dc, int media);
int cmd_tls_probe(const char *host, const char *addr, int port, int local_port, int quiet);

int cmd_tgws(const char *spec_path, const char *out_name) {
    (void)spec_path; (void)out_name;
    fprintf(stderr, "tgwsmark: мост в стенде не реализован\n");
    return 2;
}
int cmd_tgws_probe(int dc, int media) { (void)dc; (void)media; return 2; }
int cmd_tls_probe(const char *host, const char *addr, int port, int local_port, int quiet) {
    (void)host; (void)addr; (void)port; (void)local_port; (void)quiet;
    return 2;
}
