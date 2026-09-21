/* Стенд команды `steer tls-probe`: чем кончилась проба и что она об этом говорит.
 *
 * ЗАЧЕМ ОТДЕЛЬНЫЙ СТЕНД. У пробы ровно один наблюдаемый результат — строка «итог:». Всё
 * остальное (рукопожатие, ключи, отпечаток браузера) проверяется соседними стендами, а здесь
 * проверяется ПРИГОВОР: та единственная фраза, по которой человек решает, дошёл ли его
 * ClientHello до узла. До появления этого файла на tls-probe не было ни одной строки тестов
 * ни в одном стенде, и три её исхода назывались не своими именами (I-272).
 *
 * ОБСТАНОВКА — петлевые сокеты, а не сеть. Каждый исход воспроизводится локально и
 * детерминированно:
 *
 *   - отказ соединения      — порт, на котором никто не слушает;
 *   - истёкший срок         — слушающий сокет с ОЧЕРЕДЬЮ В ОДНО МЕСТО, уже занятым чужим
 *                             соединением: ядро на этом молча роняет SYN, и connect() висит
 *                             до срока, отдавая EINPROGRESS (проверено: см. ниже);
 *   - занятый свой порт     — свой же слушающий сокет на том порту, который проба просит
 *                             под --local-port;
 *   - ответ не рукопожатием — сервер, отдающий запись предупреждения 0x15;
 *   - молчание после приёма — сервер, закрывающий соединение сразу;
 *   - ответ по байту        — сервер, отдающий пять байт заголовка с паузами: каждая пауза
 *                             короче срока ОДНОГО вызова, а сумма их — длиннее срока пробы.
 *
 * Срок пробы стенду подменён на секунду (-DPROBE_TIMEOUT_S=1 в Makefile): с шестью
 * настоящими прогон стоял бы полминуты на ожиданиях, а проверяется здесь не длительность
 * срока, а то, чем он кончается.
 *
 * Файл включает исходник пробы — `bind_local` и `hello12_build` статические, и дотянуться до
 * них иначе значило бы объявить их в заголовке ради стенда (тот же приём, что в upmatch.c,
 * dcmatch.c и warmmatch.c). Крипто подменено заглушками: до сети доезжает любой буфер, а
 * настоящий сборщик Hello тянул бы за собой mbedtls, которого в `make test` нет по
 * построению (см. ext-syntax в Makefile). */
#include "../src/ext/tlsprobe.c"

#include <sys/wait.h>
#include <fcntl.h>
#include <signal.h>

/* ---- заглушки соседних файлов ------------------------------------------------------- */
/* Байты Hello стенду безразличны: он смотрит, что проба сделала с ответом, а не что она
 * отправила. Форму настоящего Hello сторожит tests/hellofreeze.c. */
int xc_random(unsigned char *out, size_t n) { memset(out, 0x5a, n); return 0; }
int xc_x25519_keypair(unsigned char priv[32], unsigned char pub[32])
                                        { memset(priv, 1, 32); memset(pub, 2, 32); return 0; }
int reality_build_hello_carry(const struct reality_cfg *cfg, struct reality_state *st,
                              const struct reality_carrier *car,
                              unsigned char *out, size_t out_n, size_t *out_len) {
    (void)cfg; (void)st; (void)car;
    size_t n = 300;                       /* влезает в один сегмент: send не заблокируется */
    if (out_n < n) return REALITY_ETOOBIG;
    memset(out, 0x16, n);
    *out_len = n;
    return 0;
}

static int fails;

static void eq(const char *what, long got, long want) {
    if (got == want) { printf("%-64s ok\n", what); return; }
    printf("%-64s БРАК: получили %ld, ждали %ld\n", what, got, want);
    fails++;
}

static void has(const char *what, const char *hay, const char *needle) {
    if (strstr(hay, needle)) { printf("%-64s ok\n", what); return; }
    printf("%-64s БРАК: в «%s» нет «%s»\n", what, hay, needle);
    fails++;
}

static void hasnt(const char *what, const char *hay, const char *needle) {
    if (!strstr(hay, needle)) { printf("%-64s ok\n", what); return; }
    printf("%-64s БРАК: в «%s» нашлось «%s»\n", what, hay, needle);
    fails++;
}

/* ---- запуск пробы с перехватом её единственного вывода -------------------------------- */
static char g_say[4096];

static int probe(const char *host, const char *addr, int port, int local_port) {
    FILE *cap = tmpfile();                /* именно файл, а не канал: канал на 64 КБ не
                                           * нужен, а взаимная блокировка на нём возможна */
    int saved = dup(1);
    g_say[0] = '\0';
    if (!cap || saved < 0) { printf("нет временного файла — проверка невозможна\n"); exit(2); }
    fflush(stdout);
    dup2(fileno(cap), 1);
    int rc = cmd_tls_probe(host, addr, port, local_port, 0);
    fflush(stdout);
    dup2(saved, 1);
    close(saved);
    rewind(cap);
    size_t n = fread(g_say, 1, sizeof(g_say) - 1, cap);
    g_say[n] = '\0';
    fclose(cap);
    /* Для сообщений об ошибке удобнее одна строка. */
    for (size_t i = 0; i < n; i++) if (g_say[i] == '\n') g_say[i] = ' ';
    return rc;
}

/* ---- петлевой сервер ------------------------------------------------------------------ */
static int listen_local(int backlog, int *port) {
    struct sockaddr_in sa;
    socklen_t sl = sizeof(sa);
    int fd = socket(AF_INET, SOCK_STREAM, 0);
    memset(&sa, 0, sizeof(sa));
    sa.sin_family = AF_INET;
    sa.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    if (fd < 0 || bind(fd, (struct sockaddr *)&sa, sizeof(sa)) != 0 ||
        listen(fd, backlog) != 0 || getsockname(fd, (struct sockaddr *)&sa, &sl) != 0) {
        printf("нет петлевого сокета — проверка невозможна\n");
        exit(2);
    }
    *port = ntohs(sa.sin_port);
    return fd;
}

enum { SRV_CLOSE, SRV_ALERT, SRV_HELLO, SRV_DRIBBLE };

/* Отдельный процесс, а не поток: проба — блокирующий код, и держать её в том же процессе,
 * что и сервер, значило бы городить вокруг неё неблокирующий ввод-вывод ради стенда. */
static pid_t serve(int ls, int how) {
    pid_t pid = fork();
    if (pid != 0) return pid;

    int c = accept(ls, NULL, NULL);
    if (c < 0) _exit(1);
    /* ClientHello принимается ВСЕГДА, в том числе перед закрытием: непрочитанные данные в
     * приёмном буфере превращают close() в RST, и «сервер закрыл соединение» стало бы
     * «соединение сброшено» — другой исход, чем тот, который здесь проверяется. */
    unsigned char junk[512];
    recv(c, junk, sizeof(junk), 0);

    static const unsigned char ALERT[5] = { 0x15, 0x03, 0x03, 0x00, 0x02 };
    static const unsigned char HEAD[5]  = { 0x16, 0x03, 0x03, 0x00, 0x40 };
    switch (how) {
    case SRV_CLOSE:   break;
    case SRV_ALERT:   send(c, ALERT, sizeof(ALERT), MSG_NOSIGNAL); break;
    case SRV_HELLO:   send(c, HEAD, sizeof(HEAD), MSG_NOSIGNAL); break;
    case SRV_DRIBBLE:
        /* Пауза вчетверо короче срока одного вызова — ни один recv по сроку не промахнётся.
         * Сумма пауз при этом вдвое длиннее срока всей пробы. */
        for (int i = 0; i < 5; i++) {
            struct timespec ts = { .tv_sec = 0, .tv_nsec = 400 * 1000 * 1000 };
            nanosleep(&ts, NULL);
            if (send(c, HEAD + i, 1, MSG_NOSIGNAL) <= 0) break;
        }
        break;
    }
    close(c);
    close(ls);
    _exit(0);
}

static void reap(pid_t pid) { int st; kill(pid, SIGKILL); waitpid(pid, &st, 0); }

int main(void) {
    signal(SIGPIPE, SIG_IGN);
    printf("проба браузерным рукопожатием: исходы и приговор\n\n");

    /* ---- 1. имя не разрешилось --------------------------------------------------------- */
    {
        int rc = probe("нет-такого.invalid", "нет-такого.invalid", 443, 0);
        eq("несуществующее имя: код 2", rc, 2);
        has("несуществующее имя: так и сказано", g_say, "имя не разрешилось");
    }

    /* ---- 2. отказ соединения ------------------------------------------------------------ */
    /* Порт, на котором только что слушали и перестали: ядро отвечает RST сразу, и это ЕДИНСТВЕННЫЙ
     * исход, который проба и до правки называла верно, — он здесь сторожем, чтобы правка
     * срока не съела заодно настоящую причину отказа. */
    {
        int port = 0;
        int ls = listen_local(1, &port);
        close(ls);
        int rc = probe("example.com", "127.0.0.1", port, 0);
        eq("никто не слушает: код 1", rc, 1);
        has("никто не слушает: названо соединением", g_say, "соединение не установилось");
        has("никто не слушает: причина от ядра сохранена", g_say, "Connection refused");
    }

    /* ---- 3. истёкший срок соединения (I-272, пункт 1) ------------------------------------ */
    /* Очередь в одно место, уже занятое: ядро роняет следующий SYN молча, connect висит до
     * срока SO_SNDTIMEO и отдаёт EINPROGRESS. Печатать его дословно — значит сказать
     * человеку, что операция ЕЩЁ ИДЁТ, ровно в тот момент, когда она кончилась ничем. */
    {
        int port = 0;
        int ls = listen_local(0, &port);
        int filler = socket(AF_INET, SOCK_STREAM, 0);
        struct sockaddr_in sa;
        memset(&sa, 0, sizeof(sa));
        sa.sin_family = AF_INET;
        sa.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
        sa.sin_port = htons((uint16_t)port);
        eq("очередь занята чужим соединением", connect(filler, (struct sockaddr *)&sa, sizeof(sa)), 0);

        int rc = probe("example.com", "127.0.0.1", port, 0);
        eq("SYN уронили: код 1", rc, 1);
        has("SYN уронили: назван срок", g_say, "нет ответа за");
        hasnt("SYN уронили: не сказано, что операция ещё идёт", g_say, "now in progress");
        close(filler);
        close(ls);
    }

    /* ---- 4. свой порт занят (I-272, пункт 2) --------------------------------------------- */
    /* Проба садится на свой порт, чтобы попадать в полосу, которую подбор изолирует
     * правилами. Порт занят второй пробой — соединение при этом не НАЧИНАЛОСЬ, и называть
     * это «соединение не установилось» значит послать человека искать блокировку там, где
     * её нет. */
    {
        int own = 0, dst = 0;
        int mine = listen_local(1, &own);       /* этот порт проба попросит под свой */
        int ls = listen_local(1, &dst);
        pid_t pid = serve(ls, SRV_HELLO);

        int rc = probe("example.com", "127.0.0.1", dst, own);
        eq("свой порт занят: код 1", rc, 1);
        has("свой порт занят: так и сказано", g_say, "свой порт");
        has("свой порт занят: порт назван числом", g_say, "занят");
        hasnt("свой порт занят: не выдано за отказ соединения", g_say, "соединение не установилось");
        reap(pid);
        close(ls);
        close(mine);
    }

    /* ---- 5. сервер ответил рукопожатием --------------------------------------------------- */
    {
        int port = 0;
        int ls = listen_local(1, &port);
        pid_t pid = serve(ls, SRV_HELLO);
        int rc = probe("example.com", "127.0.0.1", port, 0);
        eq("ответ рукопожатием: код 0", rc, 0);
        has("ответ рукопожатием: назван облик", g_say, "браузерным рукопожатием");
        has("ответ рукопожатием: назван узел", g_say, "example.com");
        reap(pid);
        close(ls);
    }

    /* ---- 6. сервер ответил предупреждением ------------------------------------------------ */
    {
        int port = 0;
        int ls = listen_local(1, &port);
        pid_t pid = serve(ls, SRV_ALERT);
        int rc = probe("example.com", "127.0.0.1", port, 0);
        eq("ответ предупреждением: код 1", rc, 1);
        has("ответ предупреждением: назван тип записи", g_say, "ответ не рукопожатие (0x15)");
        reap(pid);
        close(ls);
    }

    /* ---- 7. сервер принял и закрыл --------------------------------------------------------- */
    {
        int port = 0;
        int ls = listen_local(1, &port);
        pid_t pid = serve(ls, SRV_CLOSE);
        int rc = probe("example.com", "127.0.0.1", port, 0);
        eq("принял и закрыл: код 1", rc, 1);
        has("принял и закрыл: названо закрытием", g_say, "соединение закрыто");
        reap(pid);
        close(ls);
    }

    /* ---- 8. ответ по байту (I-272, пункт 3) ------------------------------------------------ */
    /* Пять пауз по 0.4 с: каждый recv укладывается в свой срок, а проба целиком — нет.
     * Пока срок считался у каждого вызова отдельно, такой узел держал пробу впятеро дольше
     * объявленного, и приговор всё равно выходил «отвечает браузерным рукопожатием». */
    {
        int port = 0;
        int ls = listen_local(1, &port);
        pid_t pid = serve(ls, SRV_DRIBBLE);
        struct timespec t0, t1;
        clock_gettime(CLOCK_MONOTONIC, &t0);
        int rc = probe("example.com", "127.0.0.1", port, 0);
        clock_gettime(CLOCK_MONOTONIC, &t1);
        long ms = (t1.tv_sec - t0.tv_sec) * 1000 + (t1.tv_nsec - t0.tv_nsec) / 1000000;
        eq("ответ по байту: код 1", rc, 1);
        has("ответ по байту: назван истёкший срок", g_say, "срок");
        hasnt("ответ по байту: не выдан за рукопожатие", g_say, "отвечает");
        eq("ответ по байту: проба уложилась в свой срок", ms < 1000 * (PROBE_TIMEOUT_S + 1), 1);
        reap(pid);
        close(ls);
    }

    /* ---- 9. старое рукопожатие TLS 1.2 ------------------------------------------------------ */
    /* Длины внутри hello12_build посчитаны руками в шести местах; разъехавшись, они дадут не
     * ошибку сборки, а запись, которую сервер отвергнет. Здесь запись разбирается обратно. */
    {
        unsigned char h[4096];
        const char *sni = "updates.discord.com";
        size_t n = hello12_build(sni, h, sizeof(h));
        eq("Hello 1.2 собрался", n > 0, 1);
        eq("запись рукопожатия", h[0], 0x16);
        eq("версия записи 1.2", (h[1] << 8) | h[2], 0x0303);
        size_t rec = ((size_t)h[3] << 8) | h[4];
        eq("длина записи сходится с длиной буфера", (long)(rec + 5), (long)n);
        eq("внутри client_hello", h[5], 0x01);
        size_t hs = ((size_t)h[6] << 16) | ((size_t)h[7] << 8) | h[8];
        eq("длина сообщения сходится с длиной записи", (long)(hs + 4), (long)rec);
        eq("версия 1.2 и в сообщении", (h[9] << 8) | h[10], 0x0303);
        eq("session_id пуст", h[43], 0x00);
        size_t cs = ((size_t)h[44] << 8) | h[45];
        eq("восемнадцать наборов шифров", (long)(cs / 2), 18);
        size_t p = 46 + cs;
        eq("сжатия нет", (long)h[p] * 256 + h[p + 1], 0x0100);
        p += 2;
        size_t ext = ((size_t)h[p] << 8) | h[p + 1];
        p += 2;
        eq("расширения занимают остаток записи", (long)(p + ext), (long)n);
        /* Пройти расширения по длинам: первое — server_name с именем внутри. */
        eq("первое расширение — server_name", (long)((h[p] << 8) | h[p + 1]), 0x0000);
        size_t sn = ((size_t)h[p + 2] << 8) | h[p + 3];
        eq("имя внутри server_name названо целиком",
           (long)sn, (long)(2 + 1 + 2 + strlen(sni)));
        eq("имя лежит там, где обещано", memcmp(h + p + 9, sni, strlen(sni)) == 0, 1);
        size_t walk = p, seen = 0;
        while (walk + 4 <= n) {
            size_t len = ((size_t)h[walk + 2] << 8) | h[walk + 3];
            walk += 4 + len;
            seen++;
        }
        eq("расширения кончаются ровно на границе записи", (long)walk, (long)n);
        /* Семь: шесть из снимка (TAIL) плюс server_name, который собирается отдельно. */
        eq("расширения все на месте", (long)seen, 7);

        /* Тесный буфер — отказ, а не запись мимо памяти. */
        eq("в тесный буфер не пишем", (long)hello12_build(sni, h, n - 1), 0);
        char longsni[260];
        memset(longsni, 'a', sizeof(longsni) - 1);
        longsni[sizeof(longsni) - 1] = '\0';
        eq("слишком длинное имя отвергнуто", (long)hello12_build(longsni, h, sizeof(h)), 0);
    }

    if (fails) { printf("\nбрак: %d\n", fails); return 1; }
    printf("\nпроба браузерным рукопожатием: все проверки прошли\n");
    return 0;
}
