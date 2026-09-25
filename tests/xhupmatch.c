/* Ответ сервера на выгрузку xhttp (stream-up и packet-up): отказ обязан дойти до отправителя.
 *
 * ЗАЧЕМ ОТДЕЛЬНЫМ СТЕНДОМ. У stream-up и packet-up выгрузка идёт своей связью, и её ответы
 * читает только up_drain — попутно с отправкой. Прежде он был void и всё прочитанное
 * выбрасывал, включая отказ: сервер xhttp отвечает 400 на кусок с неверной набивкой, а
 * vless_send возвращал успех, и узел выглядел живым, хотя данные не шли (I-219). У packet-up
 * было хуже: ответ на кусок приходит, когда открыт уже следующий, и h2.c таких кадров не
 * разбирал вовсе — «не наш поток». Стенды tests/run-tunnel*.sh до этого не достают: у
 * поддельного сервера там голый tcp, без xhttp.
 *
 * КАК. Файл включает src/proto/vless/client.c целиком (up_drain и up_request статические) и берёт
 * настоящий h2.c. Связь выгрузки — голая (plain, как при security=none) на сокетной паре:
 * что клиент пишет, стенд вычитывает и выбрасывает, а «сервер» пишет на другой конец кадры
 * HTTP/2 руками. TLS и Reality стенду не нужны и подменены заглушками; заголовки mbedtls —
 * из tests/stub. Сетей и прав не нужно, поэтому стенд живёт в `make test`. */
#include "../src/proto/vless/client.c"

#include <sys/socket.h>

/* ---- заглушки TLS и Reality: связь стенда голая, до них дело не доходит ------------ */

int reality_build_hello(const struct reality_cfg *cfg, struct reality_state *st,
                        unsigned char *out, size_t out_n, size_t *out_len)
    { (void)cfg; (void)st; (void)out; (void)out_n; *out_len = 0; return -1; }
int tls13_handshake_auth(struct tls13 *t, int fd, const unsigned char *ch, size_t n,
                         const unsigned char *ss, const struct tls13_auth *auth)
    { (void)t; (void)fd; (void)ch; (void)n; (void)ss; (void)auth; return -1; }
const char *tls13_verify_reason(void) { return ""; }
int tls13_has_record(const struct tls13 *t) { (void)t; return 0; }
size_t tls13_buffered(const struct tls13 *t) { (void)t; return 0; }
size_t tls13_take_pending(struct tls13 *t, unsigned char *out, size_t cap)
    { (void)t; (void)out; (void)cap; return 0; }
int tls13_write(struct tls13 *t, const unsigned char *d, size_t n)
    { (void)t; (void)d; (void)n; return -1; }
int tls13_read(struct tls13 *t, unsigned char *o, size_t cap, size_t *got)
    { (void)t; (void)o; (void)cap; *got = 0; return -1; }
int tls13_read_ref(struct tls13 *t, const unsigned char **b, size_t *bn)
    { (void)t; *b = NULL; *bn = 0; return -1; }
void tls13_free(struct tls13 *t) { (void)t; }

/* ---- стенд ----------------------------------------------------------------------- */

static int g_fail;
static void check(int ok, const char *what) {
    printf("%-74s %s\n", what, ok ? "ok" : "ПРОВАЛ");
    if (!ok) g_fail = 1;
}

static int g_srv = -1;                /* сторона «сервера» у сокетной пары */

/* Выбросить всё, что клиент успел написать: преамбулу, HEADERS, DATA. */
static void srv_drain(void) {
    unsigned char b[8192];
    while (recv(g_srv, b, sizeof(b), MSG_DONTWAIT) > 0) {}
}

/* HEADERS от сервера на поток sid с одним байтом HPACK: статический индекс :status.
 * 0x88 — 200, 0x8C — 400 (RFC 7541, приложение A). */
static void srv_headers(uint32_t sid, unsigned char hpack, int end_stream) {
    unsigned char f[10] = { 0, 0, 1, 0x01, (unsigned char)(0x04 | (end_stream ? 0x01 : 0)),
                            (unsigned char)(sid >> 24), (unsigned char)(sid >> 16),
                            (unsigned char)(sid >> 8), (unsigned char)sid, hpack };
    if (write(g_srv, f, sizeof(f)) != (ssize_t)sizeof(f)) { perror("write"); exit(2); }
}

static void conn_init(struct vless_conn *c, enum xhttp_mode xh, int fd) {
    memset(c, 0, sizeof(*c));
    c->fd = -1;
    c->tr = VT_XHTTP;
    c->xh = xh;
    c->up.fd = fd;
    c->up.plain = 1;
    snprintf(c->authority, sizeof(c->authority), "stand.example");
    snprintf(c->up_path, sizeof(c->up_path), "/xh/0f1e2d3c");
}

static int new_pair(int *cli) {
    int sp[2];
    if (socketpair(AF_UNIX, SOCK_STREAM, 0, sp) != 0) return -1;
    if (g_srv >= 0) close(g_srv);
    g_srv = sp[1];
    *cli = sp[0];
    return 0;
}

static const unsigned char piece[] = "кусок выгрузки";

/* packet-up: ответ на кусок 0 приходит, когда открыт уже кусок 1. */
static void t_packet_up(unsigned char hpack, int want_refused, const char *what) {
    int fd;
    if (new_pair(&fd) != 0) { check(0, "сокетная пара"); return; }
    struct vless_conn c;
    conn_init(&c, XH_PACKET_UP, fd);
    int rc0 = vless_send(&c, piece, sizeof(piece));     /* кусок 0, поток 1 */
    srv_drain();
    srv_headers(1, hpack, 1);                           /* ответ на кусок 0 */
    int rc1 = vless_send(&c, piece, sizeof(piece));     /* кусок 1, поток 3 */
    srv_drain();
    if (want_refused)
        check(rc0 == 0 && rc1 == H2_ESTATUS &&
              strstr(vless_strerror(rc1), "400") != NULL, what);
    else
        check(rc0 == 0 && rc1 == 0, what);
    close(fd);
}

/* stream-up: один длинный POST, отказ приходит на него самого. */
static void t_stream_up(unsigned char hpack, int want_refused, const char *what) {
    int fd;
    if (new_pair(&fd) != 0) { check(0, "сокетная пара"); return; }
    struct vless_conn c;
    conn_init(&c, XH_STREAM_UP, fd);
    int ro = up_request(&c, -1);                        /* как up_open: POST открыт сразу */
    srv_drain();
    srv_headers(1, hpack, 0);
    int rc = vless_send(&c, piece, sizeof(piece));
    srv_drain();
    if (want_refused)
        check(ro == 0 && rc == H2_ESTATUS && strstr(vless_strerror(rc), "400") != NULL, what);
    else
        check(ro == 0 && rc == 0, what);
    close(fd);
}

int main(void) {
    t_packet_up(0x8C, 1, "I-219: packet-up — 400 на прошлый кусок возвращён отправке");
    t_packet_up(0x88, 0, "I-219: packet-up — 200 на прошлый кусок отказом не считается");
    t_stream_up(0x8C, 1, "I-219: stream-up — 400 на выгрузку возвращён отправке");
    t_stream_up(0x88, 0, "I-219: stream-up — 200 на выгрузку отказом не считается");
    printf(g_fail ? "\nxhupmatch: ПРОВАЛ\n" : "\nвсе проверки прошли\n");
    return g_fail;
}
