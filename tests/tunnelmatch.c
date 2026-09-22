/* Разбор пакетов туннеля VLESS без сети: handle_packet и его соседи на подменённом клиенте.
 *
 * ЗАЧЕМ ОТДЕЛЬНЫМ СТЕНДОМ. Стенды tests/run-tunnel*.sh гоняют туннель целиком, но до
 * некоторых дорожек не достают: закрытое окно HTTP/2 (SEND_AGAIN) бывает только у grpc и
 * xhttp, а у поддельного сервера стенда транспорт голый tcp; отказ создания установщиков
 * нельзя вызвать по заказу; номер адреса устройства зависит от записи в реестре. Здесь все
 * эти случаи задаются руками, а смотрится то, что видно снаружи: пакеты, ушедшие в
 * устройство, и то, осталось ли соединение живым.
 *
 * КАК. Стенд включает src/ext/tunnel.c целиком (всё нужное в нём статическое) и подменяет
 * клиента VLESS (client.c не входит): vless_connect, vless_send и vless_recv_zc отвечают
 * так, как велит проверка. Устройство — сокетная пара: что туннель пишет в «TUN», стенд
 * читает с другого конца и разбирает тем же ip_parse. Дескриптор «сессии» — канал с
 * непрочитанным байтом: poll на нём всегда видит готовность к чтению, а читает из него
 * только подменённый клиент, то есть никто.
 *
 * РАЗМЕР СТЕКА. Таблица соединений живёт в __thread, это около 14 МБ на поток, а glibc
 * кладёт статический TLS в стек потока: установщик со стеком 128 КБ на glibc НЕ СОЗДАЁТСЯ
 * (на musl роутера — создаётся, там TLS отдельно). Это и есть честный отказ pthread_create
 * для проверки I-322. Для остальных проверок стенд подменяет pthread_attr_setstacksize и
 * поднимает стек, когда велено (g_big_stack).
 *
 * Сетей, прав и mbedtls не нужно: заголовки берутся из tests/stub, а всё, что требует TLS,
 * подменено. Поэтому стенд живёт в `make test`.
 */
#define _GNU_SOURCE
#include <dlfcn.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <poll.h>
#include <time.h>
#include <sys/socket.h>

/* ---- стек установщиков --------------------------------------------------------- */

static int g_big_stack;

int pthread_attr_setstacksize(pthread_attr_t *a, size_t s) {
    static int (*real)(pthread_attr_t *, size_t);
    if (!real) real = (int (*)(pthread_attr_t *, size_t))dlsym(RTLD_NEXT,
                                                               "pthread_attr_setstacksize");
    if (g_big_stack && s < (64u << 20)) s = 64u << 20;
    return real(a, s);
}

/* ---- подменённое окружение движка ---------------------------------------------- */

static char g_cmd[16][256];
static int  g_cmd_n;

int run_quiet(const char *const argv[]) {
    char joined[256];
    size_t jn = 0;
    for (int i = 0; argv[i] && jn < sizeof(joined) - 2; i++)
        jn += (size_t)snprintf(joined + jn, sizeof(joined) - jn, i ? " %s" : "%s", argv[i]);
    if (g_cmd_n < 16) snprintf(g_cmd[g_cmd_n++], sizeof(g_cmd[0]), "%s", joined);
    return 0;
}

#include "../src/spec.h"
void bind_device(struct output *o, const char *dev) { (void)o; (void)dev; }

#include "../src/ext/tunnel.c"

/* ---- подменённый клиент VLESS -------------------------------------------------- */

static int g_sess_pipe[2] = { -1, -1 };
static int g_send_rc;                 /* что вернёт vless_send: 0 или H2_EWINDOW */
static int g_recv_calls;
static int g_recv_rc;                 /* что вернёт vless_recv_zc: 0 или -1 (конец потока) */
static unsigned char g_recv_buf[4096];
static size_t g_recv_n;               /* сколько отдать при g_recv_rc == 0 (разово) */

int vless_connect(const struct vless_node *node, struct vless_conn *conn, int timeout_s) {
    (void)node; (void)timeout_s;
    memset(conn, 0, sizeof(*conn));
    conn->fd = g_sess_pipe[0];
    conn->plain = 1;
    return 0;
}
int vless_send(struct vless_conn *c, const unsigned char *d, size_t n) {
    (void)c; (void)d; (void)n;
    return g_send_rc;
}
int vless_recv_zc(struct vless_conn *c, unsigned char *buf, size_t cap,
                  const unsigned char **data, size_t *got) {
    (void)c; (void)buf; (void)cap;
    g_recv_calls++;
    *got = 0;
    if (g_recv_rc) return g_recv_rc;
    *data = g_recv_buf;
    *got = g_recv_n;
    g_recv_n = 0;
    return 0;
}
int vless_has_data(const struct vless_conn *c) { (void)c; return 0; }
void vless_close(struct vless_conn *c) { c->fd = -1; }   /* канал общий — не закрываем */
const char *vless_strerror(int rc) { (void)rc; return "подмена"; }
int vless_probe(const struct vless_node *node, int timeout_s, char *why, size_t why_n) {
    (void)node; (void)timeout_s; (void)why; (void)why_n; return -1;
}
int vless_probe_timed(const struct vless_node *node, int timeout_s, char *why, size_t why_n,
                      int *handshake_ms, int *ttfb_ms) {
    (void)node; (void)timeout_s; (void)why; (void)why_n; (void)handshake_ms; (void)ttfb_ms;
    return -1;
}

/* ---- устройство и пакеты клиента ----------------------------------------------- */

static struct tun_dev g_tun;
static int g_dev_peer = -1;           /* второй конец «TUN»: сюда приходит написанное туннелем */
static struct vless_node g_node;

#define CLI_IP  0x0164330au           /* 10.51.100.1 в сетевом порядке — как читает ip_parse */
#define SRV_IP  0x0771cbcbu
#define CLI_PORT 40000
#define SRV_PORT 443

static int g_fail;
static void check(int ok, const char *what) {
    printf("%-72s %s\n", what, ok ? "ok" : "ПРОВАЛ");
    if (!ok) g_fail = 1;
}

static void cli_send(uint32_t seq, uint32_t ack, unsigned char flags, uint16_t win,
                     const unsigned char *d, size_t n) {
    unsigned char p[2048];
    size_t l = tcp_build(p, sizeof(p), CLI_IP, SRV_IP, CLI_PORT, SRV_PORT, seq, ack, flags,
                         d, n, win, 0, -1);
    handle_packet(&g_tun, &g_node, p, l);
}

/* Вычитать всё, что туннель написал в устройство. Возвращает число пакетов, в last — ключ
 * последнего (там номер подтверждения). */
static int dev_drain(struct flow_key *last) {
    unsigned char p[70000];
    int cnt = 0;
    for (;;) {
        ssize_t r = recv(g_dev_peer, p, sizeof(p), MSG_DONTWAIT);
        if (r <= 0) break;
        struct flow_key k;
        size_t off;
        if (ip_parse(p, (size_t)r, &k, &off) == 0) { if (last) *last = k; cnt++; }
    }
    return cnt;
}

static struct flow_key cli_key(void) {
    struct flow_key k;
    memset(&k, 0, sizeof(k));
    k.src = CLI_IP; k.dst = SRV_IP; k.sport = CLI_PORT; k.dport = SRV_PORT; k.proto = 6;
    return k;
}

/* То, что делает цикл по готовности заявки (worker_loop): ждать установщика до срока. */
static int wait_ready(struct conn *c, int ms) {
    for (int i = 0; i < ms; i++) {
        if (__atomic_load_n(&c->done, __ATOMIC_ACQUIRE)) {
            c->pending = 0;
            c->fd = SESS(c)->v.fd;
            if (c->early) early_flush(c, &g_node);
            return 0;
        }
        struct timespec ts = { 0, 1000000 };
        nanosleep(&ts, NULL);
    }
    return -1;
}

/* Открыть соединение до состояния «поток готов, сервер ответил заголовком и 1000 байт,
 * клиент их ещё не подтвердил». Клиентский ISN 1000. */
static struct conn *open_conn(uint16_t win) {
    struct flow_key k = cli_key();
    struct conn *c = conn_find(&k);
    if (c) conn_drop(c);
    cli_send(1000, 0, TCP_SYN, win, NULL, 0);
    c = conn_find(&k);
    if (!c || !c->pending || wait_ready(c, 2000) != 0) return NULL;
    cli_send(1001, 2, TCP_ACK, win, NULL, 0);
    g_recv_rc = 0;
    g_recv_buf[0] = 0; g_recv_buf[1] = 0;                 /* ответ VLESS: версия, длина доп. */
    memset(g_recv_buf + 2, 'r', 1000);
    g_recv_n = 1002;
    drain_conn(c, &g_node, &g_tun);
    dev_drain(NULL);
    return c;
}

/* ---- проверки ------------------------------------------------------------------ */

/* I-322: установщиков не создалось ни одного. Прежде очередь считалась запущенной, SYN
 * получал SYN-ACK, а заявка висела pending навсегда — ни RST, ни повторной попытки. */
static void t_no_connectors(void) {
    g_big_stack = 0;
    struct flow_key k = cli_key();
    cli_send(1000, 0, TCP_SYN, 65535, NULL, 0);
    struct conn *c = conn_find(&k);
    struct flow_key last;
    int synack = 0;
    int n = dev_drain(&last);
    if (n && (last.tcp_flags & TCP_SYN)) synack = 1;
    check(!c && !synack, "I-322: без установщиков SYN отклонён, SYN-ACK не ушёл");
    if (c) conn_drop(c);

    /* Стек дали — следующий SYN обязан получить установщика: отказ не залипает. */
    g_big_stack = 1;
    cli_send(1000, 0, TCP_SYN, 65535, NULL, 0);
    c = conn_find(&k);
    check(c && c->pending && wait_ready(c, 2000) == 0,
          "I-322: после отказа установщики заводятся на следующем SYN");
    if (c) conn_drop(c);
    dev_drain(NULL);
}

/* I-322: номер адреса устройства из таблицы выхода. Таблица приходит из файла реестра, и
 * отрицательное число оттуда давало адрес 198.51.100.-N. */
static void t_bring_up_table(void) {
    g_cmd_n = 0;
    int save = dup(2), nul = open("/dev/null", O_WRONLY);
    dup2(nul, 2);
    tun_bring_up("vl", -7);
    fflush(stderr);
    dup2(save, 2); close(save); close(nul);
    int host = -1;
    const char *p = g_cmd_n ? strstr(g_cmd[0], "198.51.100.") : NULL;
    if (p) host = atoi(p + 11);
    check(host >= 1 && host <= 200, "I-322: таблица -7 даёт адрес 198.51.100.1..200");
}

int main(void) {
    int sp[2];
    if (socketpair(AF_UNIX, SOCK_DGRAM, 0, sp) != 0 || pipe(g_sess_pipe) != 0) return 2;
    if (write(g_sess_pipe[1], "x", 1) != 1) return 2;
    memset(&g_tun, 0, sizeof(g_tun));
    g_tun.fd = sp[0];
    g_dev_peer = sp[1];
    snprintf(g_node.uuid, sizeof(g_node.uuid), "8f7d3b1a-2c4e-4f60-9a81-b5d7e6c30124");
    snprintf(g_node.host, sizeof(g_node.host), "stand");
    conn_table_init();
    g_spare_want = 0;
    g_now_ns = now_ns();
    g_now_s = (time_t)(g_now_ns / 1000000000ull);

    t_no_connectors();
    t_bring_up_table();
    (void)open_conn;

    printf(g_fail ? "\ntunnelmatch: ПРОВАЛ\n" : "\nвсе проверки прошли\n");
    return g_fail;
}
