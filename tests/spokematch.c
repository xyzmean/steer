/* Освобождение ключей пира при неудачном рукопожатии.
 *
 * ЗАЧЕМ. Транспортные ключи выводит xs_hs_client_finish, а флаг s->up ставится позже —
 * после того, как подтверждение уехало хабу. Между этими двумя точками есть отказы:
 * подтверждение хаба не сошлось (версии разошлись), само подтверждение не ушло (ошибка
 * записи). После них контексты шифра уже выделены, а закрытие сессии смотрело на s->up и
 * поэтому их не освобождало. Следующая попытка входит в split_keys, тот делает memset
 * ключа — указатель на прежний контекст AES теряется. Это утечка, а не отложенное
 * освобождение, и она повторяется каждые 5 секунд, пока воркер переподключается.
 *
 * Стенду не нужны ни сеть, ни хаб: проверяется ровно закрытие сессии, а не рукопожатие.
 * Целиком протокол проверяет tests/xsloop.c.
 *
 * Нужен настоящий mbedtls (контекст AES в куче — это и есть утекающее), поэтому в make test
 * стенд не входит, как и xsloop. Сборка (mbedtls 2.x требует заглушку MBEDTLS_PRIVATE,
 * в 3.x макрос свой):
 *
 *     cc -O1 -g -w -Isrc -fsanitize=address -o build/spokematch tests/spokematch.c \
 *        src/ext/xsconn.c src/ext/xswire.c src/ext/xsepoch.c src/ext/xsroute.c \
 *        src/ext/xsconf.c src/ext/xsstream.c src/ext/xshake.c src/ext/chello.c \
 *        src/ext/reality.c src/ext/tls13.c src/ext/h2.c src/ext/tun.c src/obfs.c \
 *        src/spec.c -lmbedcrypto -lpthread
 */
/* До любого include: xsclient.c просит расширения GNU (sendmmsg), а первый
 * подключённый заголовок фиксирует набор. */
#define _GNU_SOURCE
#include <stdio.h>
#include <string.h>

#include "../src/ext/xsclient.c"

/* Заглушки того, что живёт в src/steer.c: ни команд, ни устройств стенду не нужно. */
int run_quiet(const char *const argv[]) { (void)argv; return 0; }
void bind_device(struct output *o, const char *dev) { (void)o; (void)dev; }

static int fails;

static void check(const char *what, long want, long got) {
    printf("%-62s %s\n", what, want == got ? "ok" : "ПРОВАЛ");
    if (want != got) {
        printf("     хочу: %ld\n     есть:  %ld\n", want, got);
        fails++;
    }
}

/* Ключи в том виде, в каком их оставляет split_keys: AES-128, контекст развёрнут.
 * Именно AES, а не ChaCha: в куче лежит контекст только у AES внутри GCM. */
static int keys_up(struct tls13_keys *k) {
    memset(k, 0, sizeof(*k));
    k->aead = TLS13_AEAD_AES128;
    k->key_n = 16;
    return tls13_keys_setup(k);
}

int main(void) {
    /* Поддельный TCP: рукопожатие не дошло до конца, s->up остался нулём. */
    {
        static struct spoke s;
        s.conn.fd = -1;
        if (keys_up(&s.tx) != 0 || keys_up(&s.rx) != 0) return 2;
        session_down(&s);
        check("поддельный TCP: ключ к хабу освобождён при up=0", 0, s.tx.ctx_ready);
        check("поддельный TCP: ключ от хаба освобождён при up=0", 0, s.rx.ctx_ready);
    }

    /* Режим потока: та же точка отказа, другое закрытие. */
    {
        static struct spoke s;
        s.conn.fd = -1;
        if (keys_up(&s.tx) != 0 || keys_up(&s.rx) != 0) return 2;
        stream_down(&s);
        check("поток: ключ к хабу освобождён при up=0", 0, s.tx.ctx_ready);
        check("поток: ключ от хаба освобождён при up=0", 0, s.rx.ctx_ready);
    }

    /* Поднятая сессия закрывается как прежде: снятие условия не должно было ничего изменить
     * на пути, который работал. */
    {
        static struct spoke s;
        s.conn.fd = -1;
        if (keys_up(&s.tx) != 0 || keys_up(&s.rx) != 0) return 2;
        s.up = 1;
        session_down(&s);
        check("поднятая сессия: ключи освобождены", 0, s.tx.ctx_ready);
        check("поднятая сессия: флаг снят", 0, s.up);
    }

    /* Двойное закрытие не должно ни падать, ни освобождать дважды: закрытие зовётся и по
     * отказу подключения, и по выходу воркера. */
    {
        static struct spoke s;
        s.conn.fd = -1;
        if (keys_up(&s.tx) != 0 || keys_up(&s.rx) != 0) return 2;
        session_down(&s);
        session_down(&s);
        check("двойное закрытие: ключи освобождены один раз", 0, s.tx.ctx_ready);
    }

    /* САМА УТЕЧКА, а не только флаг: двадцать попыток подряд, каждая выводит ключи заново
     * ровно так же, как split_keys. Под LeakSanitizer прежний код давал 10944 байта в 38
     * объектах; починенный не даёт ничего, и это видно по коду возврата стенда. */
    {
        static struct spoke s;
        s.conn.fd = -1;
        for (int attempt = 0; attempt < 20; attempt++) {
            if (keys_up(&s.tx) != 0 || keys_up(&s.rx) != 0) return 2;
            s.up = 0;
            session_down(&s);
        }
        check("двадцать попыток: контекст не остался развёрнутым", 0, s.tx.ctx_ready);
    }

    printf("\n%s\n", fails ? "ЕСТЬ ПРОВАЛЫ" : "все проверки прошли");
    return fails ? 1 : 0;
}
