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

/* ---- сон установщика ----------------------------------------------------------- */

/* connq_release ждёт доклада установщиков сном по 10 мс до 15 с. Проверке I-193 нужен не
 * срок, а то, что решается после ПОСЛЕДНЕГО сна: сны не спят, а на заданном по счёту
 * «докладывает» заявка g_sleep_c. Вне проверки — настоящий сон. */
static int g_sleep_hook;
static int g_sleep_n;
static int g_sleep_report_at;
static int *g_sleep_c;             /* поле done заявки, которая «доложит» */

int nanosleep(const struct timespec *req, struct timespec *rem) {
    static int (*real)(const struct timespec *, struct timespec *);
    if (g_sleep_hook) {
        if (++g_sleep_n == g_sleep_report_at && g_sleep_c)
            __atomic_store_n(g_sleep_c, 1, __ATOMIC_RELEASE);
        return 0;
    }
    if (!real) real = (int (*)(const struct timespec *, struct timespec *))dlsym(RTLD_NEXT,
                                                                           "nanosleep");
    return real(req, rem);
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
static int g_send_again_n;            /* столько раз подряд вернуть H2_EWINDOW, потом 0 */
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
    if (g_send_again_n > 0) { g_send_again_n--; return H2_EWINDOW; }
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
    /* Стенд сам себя проверяет: без этого «провал» мог бы означать сломанную подготовку. */
    if (!c->established || c->rtx.len != 1000 || c->srv_closed) return NULL;
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

/* I-320: окно HTTP/2 закрыто (SEND_AGAIN), и туннель читает у сервера, надеясь на
 * WINDOW_UPDATE. Читать можно только то, что клиент в силах принять: прочитанное за его
 * окно уходит в пустоту и лечится лишь повтором по таймауту. */
static void t_sendagain_window(void) {
    struct conn *c = open_conn(65535);
    if (!c) { check(0, "I-320: соединение не открылось"); return; }
    /* Клиент принял не всё и объявил окно ровно под уже отправленное: места нет. */
    const unsigned char d[] = "GET / HTTP/1.1\r\n";
    g_send_rc = H2_EWINDOW;
    g_recv_rc = 0;
    memset(g_recv_buf, 'r', 1000);
    g_recv_n = 1000;
    int calls = g_recv_calls;
    cli_send(1001, 2, TCP_ACK | TCP_PSH, 1000, d, sizeof(d) - 1);
    check(g_recv_calls == calls, "I-320: при закрытом окне клиента у сервера не читаем");
    g_send_rc = 0;
    g_recv_n = 0;
    conn_drop(c);
    dev_drain(NULL);
}

/* I-320, обратная сторона: окно клиента открыто — чтение у сервера делается (оттуда
 * приходит WINDOW_UPDATE), повторная отправка удаётся, пакет подтверждён. */
static void t_sendagain_retry(void) {
    struct conn *c = open_conn(65535);
    if (!c) { check(0, "I-320: соединение не открылось"); return; }
    const unsigned char d[] = "GET / HTTP/1.1\r\n";
    g_send_again_n = 1;
    g_recv_rc = 0;
    g_recv_n = 0;                                       /* служебный кадр: данных нет */
    int calls = g_recv_calls;
    cli_send(1001, 2, TCP_ACK | TCP_PSH, 65535, d, sizeof(d) - 1);
    check(g_recv_calls > calls && c->used && c->client_seq == 1001 + sizeof(d) - 1,
          "I-320: окно клиента открыто — читаем, повтор отправки удался");
    g_send_again_n = 0;
    conn_drop(c);
    dev_drain(NULL);
}

/* I-320: на том же чтении сервер закрыл поток. Соединение обязано дожить до подтверждения
 * уже отправленного (srv_closed, как в drain_conn), а не пропасть вместе с кольцом. */
static void t_sendagain_eof(void) {
    struct conn *c = open_conn(65535);
    if (!c) { check(0, "I-320: соединение не открылось"); return; }
    const unsigned char d[] = "GET / HTTP/1.1\r\n";
    g_send_rc = H2_EWINDOW;
    g_recv_rc = -1;
    cli_send(1001, 2, TCP_ACK | TCP_PSH, 65535, d, sizeof(d) - 1);
    struct flow_key k = cli_key();
    c = conn_find(&k);
    check(c && c->srv_closed && c->rtx.len == 1000,
          "I-320: конец потока при SEND_AGAIN — соединение живо, 1000 байт ждут подтверждения");
    g_send_rc = 0;
    g_recv_rc = 0;
    if (c) conn_drop(c);
    dev_drain(NULL);
}

/* I-321: сегмент не по порядку отбрасывается (буфера переупорядочивания нет), но ответить
 * на него обязаны подтверждением ожидаемого номера: без дубликатов ACK у клиента не
 * срабатывает быстрый повтор, и дыра закрывается только по таймауту. Тот же ответ нужен и
 * на повтор уже принятого — иначе потерянный наш ACK не восстанавливается ничем. */
static void t_out_of_order_dupack(void) {
    struct conn *c = open_conn(65535);
    if (!c) { check(0, "I-321: соединение не открылось"); return; }
    const unsigned char d[100] = { 0 };
    struct flow_key last;
    cli_send(1001 + 500, 2, TCP_ACK | TCP_PSH, 65535, d, sizeof(d));
    flush_acks(&g_tun);
    memset(&last, 0, sizeof(last));
    int n = dev_drain(&last);
    check(n == 1 && (last.tcp_flags & TCP_ACK) && last.ack == 1001 && c->client_seq == 1001,
          "I-321: сегмент за дырой — не принят, ушёл ACK ожидаемого номера");

    cli_send(1001, 2, TCP_ACK | TCP_PSH, 65535, d, sizeof(d));      /* по порядку */
    flush_acks(&g_tun);
    dev_drain(NULL);
    cli_send(1001, 2, TCP_ACK | TCP_PSH, 65535, d, sizeof(d));      /* его же повтор */
    flush_acks(&g_tun);
    memset(&last, 0, sizeof(last));
    n = dev_drain(&last);
    check(n == 1 && last.ack == 1101 && c->client_seq == 1101,
          "I-321: повтор принятого — не принят дважды, ACK с текущим номером");
    conn_drop(c);
    dev_drain(NULL);
}

/* I-193: установщик доложил за время ПОСЛЕДНЕГО сна ожидания. Прежде проверка стояла перед
 * сном, результат последнего не спрашивался, и приговор «не доложил за 15 с» ставился по
 * счётчику кругов — таблица при этом намеренно не освобождается. */
static void t_release_last_sleep(void) {
    struct conn *c = &g_conns[MAX_CONNS - 1];
    struct conn save = *c;
    c->used = 1;
    c->pending = 1;
    __atomic_store_n(&c->done, 0, __ATOMIC_RELEASE);
    g_sleep_c = (int *)&c->done;
    g_sleep_n = 0;
    g_sleep_report_at = 1500;
    g_sleep_hook = 1;
    int save_err = dup(2), nul = open("/dev/null", O_WRONLY);
    dup2(nul, 2);
    int rc = connq_release(g_conns);
    fflush(stderr);
    dup2(save_err, 2); close(save_err); close(nul);
    g_sleep_hook = 0;
    check(rc == 0, "I-193: доклад за последний сон ожидания принят, таблица освобождается");

    /* И обратное: не доложил вовсе — приговор прежний. */
    __atomic_store_n(&c->done, 0, __ATOMIC_RELEASE);
    c->pending = 1;
    g_sleep_n = 0;
    g_sleep_report_at = 0;
    g_sleep_hook = 1;
    save_err = dup(2); nul = open("/dev/null", O_WRONLY);
    dup2(nul, 2);
    rc = connq_release(g_conns);
    fflush(stderr);
    dup2(save_err, 2); close(save_err); close(nul);
    g_sleep_hook = 0;
    check(rc == -1 && g_sleep_n == 1500, "I-193: не доложивший за 15 с — отказ, снов 1500");
    g_sleep_c = NULL;
    *c = save;
}

/* Выполнить f с stderr в файл и вернуть, нашлась ли в написанном строка needle. */
static int stderr_has(void (*f)(void *), void *arg, const char *needle) {
    char path[] = "/tmp/tunnelmatch-err.XXXXXX";
    int fd = mkstemp(path);
    if (fd < 0) return 0;
    fflush(stderr);
    int save = dup(2);
    dup2(fd, 2);
    f(arg);
    fflush(stderr);
    dup2(save, 2); close(save);
    char buf[4096];
    ssize_t r = pread(fd, buf, sizeof(buf) - 1, 0);
    close(fd); unlink(path);
    buf[r > 0 ? r : 0] = 0;
    return strstr(buf, needle) != NULL;
}

static void syn_bad(void *arg) {
    struct vless_node *bad = arg;
    unsigned char p[128];
    size_t l = tcp_build(p, sizeof(p), CLI_IP, SRV_IP, CLI_PORT, SRV_PORT, 1000, 0, TCP_SYN,
                         NULL, 0, 65535, 0, -1);
    handle_packet(&g_tun, bad, p, l);
}

static int g_run_rc;
static void run_bad(void *arg) {
    struct output o;
    memset(&o, 0, sizeof(o));
    /* Имя длиннее 15 символов: tun_open откажет и сам, так что устройство не появится ни до
     * правки, ни после — различается только названа ли причина. */
    snprintf(o.device, sizeof(o.device), "tunnelmatch-no-such-dev");
    g_run_rc = tunnel_run(&o, arg);
}

/* I-097: UUID узла не разбирается. Прежде соединение закрывалось молча — ни строки, ни
 * причины, — а tunnel_run поднимал устройство, которое закрывало бы всё подряд. */
static void t_bad_uuid(void) {
    struct vless_node bad = g_node;
    /* Короче 31 знака — законный «производный» UUID (sha1 строки, как у Xray); длиннее 36
     * не разбирается никак. */
    memset(bad.uuid, 0, sizeof(bad.uuid));
    memset(bad.uuid, 'x', 40);
    snprintf(bad.name, sizeof(bad.name), "узел-стенда");
    struct flow_key k = cli_key();
    struct conn *c = conn_find(&k);
    if (c) conn_drop(c);
    g_now_s += 10;                                   /* ограничитель строки не мешает */
    int said = stderr_has(syn_bad, &bad, "не разбирается UUID");
    c = conn_find(&k);
    check(said && !c, "I-097: SYN к узлу с негодным UUID — отказ назван в журнале");
    if (c) conn_drop(c);
    dev_drain(NULL);
    said = stderr_has(run_bad, &bad, "не разбирается UUID");
    check(said && g_run_rc == 1, "I-097: tunnel_run называет негодный UUID до подъёма устройства");
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
    t_sendagain_window();
    t_sendagain_retry();
    t_sendagain_eof();
    t_out_of_order_dupack();
    t_release_last_sleep();
    t_bad_uuid();

    printf(g_fail ? "\ntunnelmatch: ПРОВАЛ\n" : "\nвсе проверки прошли\n");
    return g_fail;
}
