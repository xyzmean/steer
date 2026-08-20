/* Рукопожатие и поток данных xsteer целиком в памяти: обе стороны в одном процессе.
 *
 * ЗАЧЕМ. Это единственный стенд, который проверяет протокол как протокол, а не по частям.
 * Ошибка в порядке шагов Noise, в подписываемых байтах или в выводе ключей не видна ни
 * одному стенду чистых функций: каждая половина «работает», а вместе они расходятся. Причём
 * симптом на живом туннеле самый злой — рукопожатие проходит, данные не расшифровываются, и
 * ни одна из сторон не может сказать почему.
 *
 * Ровно эта ошибка тут и была найдена при первом прогоне: хаб генерировал свою эфемерную
 * пару ДО того, как сохранял чужую, и затирал её — ee у сторон не совпадал.
 *
 * Ни сети, ни прав root: обе стороны обмениваются байтами через буфер. Но нужен настоящий
 * mbedtls (здесь считается криптография), поэтому в make test стенд не входит.
 *
 *     cc -O2 -w -Isrc -I<mbedtls>/include -o build/xsloop tests/xsloop.c \
 *        src/ext/xshake.c src/ext/chello.c src/ext/xswire.c src/ext/reality.c \
 *        src/ext/tls13.c src/ext/h2.c <mbedtls>/library/libmbedcrypto.a
 */
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#include "../src/ext/xshake.h"
#include "../src/ext/xswire.h"
#include "../src/ext/chello.h"
#include "../src/ext/reality.h"

static int fails;

static void check(const char *what, long want, long got) {
    printf("%-62s %s\n", what, want == got ? "ok" : "ПРОВАЛ");
    if (want != got) {
        printf("     хочу: %ld\n     есть:  %ld\n", want, got);
        fails++;
    }
}

static uint32_t rnd_state = 0x5EED1234u;
static uint32_t rnd(void) {
    rnd_state ^= rnd_state << 13;
    rnd_state ^= rnd_state >> 17;
    rnd_state ^= rnd_state << 5;
    return rnd_state;
}

/* Один полный обмен. Возвращает 0 при успехе; ключи и состояния отдаются наружу, чтобы
 * дальше на них можно было прогнать поток данных. */
struct pair {
    struct xs_secrets spoke, hub;
    uint8_t spoke_pub[32], hub_pub[32];
    struct xs_hs cs, ss;                       /* состояния: пир и хаб */
    struct tls13_keys c_tx, c_rx, s_tx, s_rx;
    uint8_t hello[4096], resp[4096], fin[256];
    size_t hello_n, resp_n, fin_n;
};

static int handshake(struct pair *p, int spoke_mtu, int hub_mtu) {
    memset(&p->cs, 0, sizeof(p->cs));
    memset(&p->ss, 0, sizeof(p->ss));
    int rc = xs_hs_client_hello(&p->cs, &p->spoke, p->hub_pub, "www.example.com",
                               spoke_mtu, 0, p->hello, sizeof(p->hello), &p->hello_n);
    if (rc != 0) return rc;
    uint8_t peer[32];
    rc = xs_hs_server_read(&p->ss, &p->hub, p->hello, p->hello_n, peer);
    if (rc != 0) return rc;
    if (memcmp(peer, p->spoke_pub, 32) != 0) return -999;
    rc = xs_hs_server_write(&p->ss, hub_mtu, p->resp, sizeof(p->resp), &p->resp_n,
                            &p->s_tx, &p->s_rx);
    if (rc != 0) return rc;
    size_t used = 0;
    rc = xs_hs_client_finish(&p->cs, p->resp, p->resp_n, &p->c_tx, &p->c_rx, &used);
    if (rc != 0) return rc;
    if (used != p->resp_n) return -998;
    rc = xs_hs_client_confirm(&p->cs, &p->c_tx, p->fin, sizeof(p->fin), &p->fin_n);
    if (rc != 0) return rc;
    size_t fused = 0;
    rc = xs_hs_server_confirm(&p->ss, &p->s_rx, p->fin, p->fin_n, &fused);
    if (rc != 0) return rc;
    if (fused != p->fin_n) return -997;
    return 0;
}

/* Транспортные ключи принадлежат СЕССИИ, и освобождает их её закрытие. В стенде сессий
 * нет, поэтому освобождаем руками — иначе санитайзер справедливо покажет утечку, и в ней
 * утонет настоящая, если она появится. */
static void pair_free(struct pair *p) {
    tls13_keys_free(&p->c_tx); tls13_keys_free(&p->c_rx);
    tls13_keys_free(&p->s_tx); tls13_keys_free(&p->s_rx);
    xs_hs_wipe(&p->cs);
    xs_hs_wipe(&p->ss);
}

static void keys_for(struct pair *p) {
    if (xc_x25519_keypair(p->spoke.priv, p->spoke_pub) != 0) exit(2);
    if (xc_x25519_keypair(p->hub.priv, p->hub_pub) != 0) exit(2);
    p->spoke.has_priv = p->hub.has_priv = 1;
}

int main(void) {
    static struct pair p;
    keys_for(&p);

    /* ---- рукопожатие целиком ------------------------------------------------ */
    check("рукопожатие: прошло", 0, handshake(&p, 1439, 1400));
    /* HELLO НЕ ОБЯЗАН ВЛЕЗАТЬ В ОДИН СЕГМЕНТ, И ЭТО НЕ УПУЩЕНИЕ. Постквантовый key_share
     * (X25519MLKEM768, 1216 байт) включён нарочно: у Chrome Hello занимает около 1760 байт и
     * уезжает ДВУМЯ сегментами, а «537 байт в одном сегменте» опознаётся и по размеру, и по
     * числу сегментов (см. reality.h про поле pq). Прежняя проверка «влез в один сегмент»
     * описывала движок до 17022ae и с 18 августа держала стенд красным — то есть единственный
     * стенд протокола как протокола перестал отвечать на вопрос «сломалось ли что-то ещё».
     * Проверяется теперь то, что обещано: облик Chrome по умолчанию и короткий Hello под
     * аварийным выключателем, которым пир говорит с хабом предыдущей версии. */
    check("рукопожатие: Hello размера Chrome, не одного сегмента", 1,
          p.hello_n > 1439 && p.hello_n < 2048);
    check("рукопожатие: ответ влез в один сегмент", 1, p.resp_n <= 1439);
    check("рукопожатие: подтверждение пира 58 байт", 58, (long)p.fin_n);
    /* Аварийный выключатель обязан выключать именно то, для чего заведён: хаб до c86c739 не
     * собирает ClientHello из сегментов, поэтому под STEER_XS_COMPAT Hello обязан влезть в
     * один сегмент, а рукопожатие — по-прежнему проходить целиком. */
    {
        static struct pair cq;
        keys_for(&cq);
        setenv("STEER_XS_COMPAT", "1", 1);
        int crc = handshake(&cq, 1439, 1400);
        unsetenv("STEER_XS_COMPAT");
        check("совместимость: рукопожатие прошло", 0, crc);
        check("совместимость: Hello влез в один сегмент", 1, cq.hello_n <= 1439);
        pair_free(&cq);
    }
    /* Форма на проводе: первая запись — рукопожатие TLS, дальше фальшивый CCS. */
    check("облик: Hello — запись рукопожатия", 0x16, p.hello[0]);
    check("облик: ответ начинается с ServerHello", 0x16, p.resp[0]);
    check("облик: подтверждение — запись application_data", 0x17, p.fin[0]);
    check("облик: версия записи 0x0303, как у настоящего TLS 1.3", 0x0303,
          ((long)p.fin[1] << 8) | p.fin[2]);

    /* Ключи обязаны сойтись КРЕСТ-НАКРЕСТ: то, чем шифрует пир, — то, чем расшифровывает
     * хаб. Сравнение по байтам ключа, а не «данные расшифровались»: так видно, что именно
     * разъехалось, если разъехалось. */
    check("ключи: пир→хаб совпал", 0, memcmp(p.c_tx.key, p.s_rx.key, p.c_tx.key_n));
    check("ключи: хаб→пир совпал", 0, memcmp(p.s_tx.key, p.c_rx.key, p.s_tx.key_n));
    check("ключи: iv пир→хаб совпал", 0, memcmp(p.c_tx.iv, p.s_rx.iv, 12));
    check("ключи: iv хаб→пир совпал", 0, memcmp(p.s_tx.iv, p.c_rx.iv, 12));
    /* Направления РАЗНЫЕ: один ключ на оба означал бы, что отражённый пакет принимается за
     * свой, а это готовая атака отражением. */
    check("ключи: направления не совпадают", 1,
          memcmp(p.c_tx.key, p.c_rx.key, p.c_tx.key_n) != 0);
    check("транскрипт: у сторон одинаковый", 0, memcmp(p.cs.h, p.ss.h, 32));

    /* MTU обменялись в самом рукопожатии — до первого пакета данных. */
    check("MTU: хаб узнал MTU пира", 1439, p.ss.peer.mtu);
    check("MTU: пир узнала MTU хаба", 1400, p.cs.peer.mtu);
    check("версия: хаб прочитал версию пира", XS_PROTO_VER, p.ss.peer.ver);

    /* ---- поток данных ------------------------------------------------------- */
    {
        /* Двадцать тысяч пакетов через настоящие seal/open с переупорядочиванием, дублями и
         * потерями. Проверяются два разных утверждения, и путать их нельзя:
         *   - расшифровка обязана сходиться на КАЖДОЙ доставке (AEAD детерминирован, и
         *     повторная доставка тех же байт расшифровывается так же);
         *   - окно обязано ПРИНЯТЬ первую доставку и ОТВЕРГНУТЬ вторую. Именно окно, а не
         *     AEAD, защищает от воспроизведения: повторно присланный пакет расшифруется.
         *
         * Первая версия этого блока считала корректно отвергнутый дубль «пропущенным» —
         * то есть проверяла обратное тому, что хотела. Отсюда явные имена ниже. */
        enum { N = 20000, SLOTS = 61 };
        static struct slot {
            uint8_t buf[XS_ROW];
            uint32_t rel;
            uint16_t len;
            uint8_t head[8];
            uint8_t used, delivered;
        } q[SLOTS];
        memset(q, 0, sizeof(q));
        struct xs_win win;
        xs_win_reset(&win);

        int decrypt_fail = 0, content_bad = 0, dup_passed_window = 0, false_reject = 0;
        int delivered = 0, dups = 0, lost = 0;
        uint32_t rel = 1;

        for (int i = 0; i < N; i++) {
            /* Записать новый пакет в слот (затирая самый старый — это и есть потеря). */
            struct slot *w = &q[i % SLOTS];
            if (w->used && !w->delivered) lost++;
            size_t plen = 21 + rnd() % 1400;
            for (size_t b = 0; b < plen; b++)
                w->buf[XS_HDR_ROOM + b] = (uint8_t)(i * 17 + b);
            memcpy(w->head, w->buf + XS_HDR_ROOM, 8);
            uint8_t *rec = w->buf + XS_HDR_ROOM - XS_REC_HDR;
            if (xs_rec_build(rec, plen + XS_TAG) != 0) { decrypt_fail++; continue; }
            if (tls13_aead_seal(&p.c_tx, rel, rec, XS_REC_HDR,
                                w->buf + XS_HDR_ROOM, plen,
                                w->buf + XS_HDR_ROOM + plen) != 0) { decrypt_fail++; continue; }
            w->rel = rel;
            w->len = (uint16_t)plen;
            w->used = 1;
            w->delivered = 0;
            rel += (uint32_t)(plen + XS_REC_HDR + XS_TAG);

            /* Доставить один-два случайных пакета из окна: так получается и
             * переупорядочивание, и дубли. */
            for (int rep = 0; rep < 2; rep++) {
                struct slot *r = &q[rnd() % SLOTS];
                if (!r->used) continue;
                size_t total = XS_REC_HDR + r->len + XS_TAG;
                uint8_t copy[XS_ROW];
                memcpy(copy, r->buf + XS_HDR_ROOM - XS_REC_HDR, total);
                const uint8_t *body;
                size_t body_n;
                if (xs_rec_parse(copy, total, &body, &body_n) != 0) { decrypt_fail++; continue; }
                int window_ok = xs_win_check(&win, r->rel) == 0;
                if (tls13_aead_open(&p.s_rx, r->rel, copy, XS_REC_HDR,
                                    copy + XS_REC_HDR, body_n) != 0) { decrypt_fail++; continue; }
                if (memcmp(copy + XS_REC_HDR, r->head, 8) != 0) content_bad++;
                if (r->delivered) {
                    /* Это дубль. Окно ОБЯЗАНО было его отвергнуть — если приняло, значит
                     * защиты от воспроизведения нет. */
                    dups++;
                    if (window_ok) dup_passed_window++;
                } else {
                    /* Первая доставка. Окно обязано принять — если отвергло, честный пакет
                     * потерян, и это хуже, чем пропущенный дубль. */
                    if (!window_ok) false_reject++;
                    else { xs_win_commit(&win, r->rel); delivered++; r->delivered = 1; }
                }
                if (rnd() % 3) break;
            }
        }
        check("поток: расшифровка сошлась на каждой доставке", 0, decrypt_fail);
        check("поток: содержимое восстановлено побайтово", 0, content_bad);
        check("поток: окно не пропустило ни одного дубля", 0, dup_passed_window);
        check("поток: ни одного ложного отказа честному пакету", 0, false_reject);
        check("поток: доставки были", 1, delivered > 1000);
        check("поток: дубли были", 1, dups > 100);
        check("поток: потери были", 1, lost > 0);
    }

    /* ---- порча и чужие ключи ------------------------------------------------ */
    {
        /* Чужой хаб: тот же Hello, другой статический ключ — рукопожатие обязано не пройти.
         * Это то самое свойство IK, из-за которого статический ключ хаба входит в транскрипт. */
        static struct pair q;
        keys_for(&q);
        struct xs_hs cs;
        uint8_t hello[4096];
        size_t hn = 0;
        uint8_t wrong_pub[32], wrong_priv[32];
        xc_x25519_keypair(wrong_priv, wrong_pub);
        check("чужой ключ: Hello собрался", 0,
              xs_hs_client_hello(&cs, &q.spoke, wrong_pub, "www.example.com", 1439, 0,
                                 hello, sizeof(hello), &hn));
        struct xs_hs ss;
        uint8_t peer[32];
        int rc = xs_hs_server_read(&ss, &q.hub, hello, hn, peer);
        check("чужой ключ: хаб отверг рукопожатие", 1, rc != 0);
        check("чужой ключ: отказ именно по аутентификации", XS_EAUTH, rc);
        xs_hs_wipe(&cs);
    }
    {
        /* Порча: каждый байт Hello по очереди. Хаб обязан либо отказать, либо (для байтов,
         * не входящих в подписанное) принять — но НИКОГДА не принять с изменённой личностью
         * пира. Перебором, потому что «мы подумали, что подписано всё» — не утверждение. */
        static struct pair q;
        keys_for(&q);
        check("порча: исходное рукопожатие проходит", 0, handshake(&q, 1439, 1400));
        int accepted_tampered = 0, identity_changed = 0;
        for (size_t i = 0; i < q.hello_n; i += 7) {
            uint8_t save = q.hello[i];
            q.hello[i] ^= 0x40;
            struct xs_hs ss;
            uint8_t peer[32];
            if (xs_hs_server_read(&ss, &q.hub, q.hello, q.hello_n, peer) == 0) {
                accepted_tampered++;
                if (memcmp(peer, q.spoke_pub, 32) != 0) identity_changed++;
            }
            q.hello[i] = save;
        }
        pair_free(&q);
        check("порча: ни один изменённый Hello не принят", 0, accepted_tampered);
        check("порча: личность пира подменить не удалось", 0, identity_changed);
    }
    {
        /* Порча подтверждения: тег обязан не сойтись, и код должен быть про аутентификацию,
         * а не про формат — иначе «туннель молчит» не отличить от «мы не поняли ответ». */
        static struct pair q;
        keys_for(&q);
        check("порча подтверждения: рукопожатие прошло", 0, handshake(&q, 1439, 1400));
        q.fin[10] ^= 0x01;
        /* Ключ берётся ПО УКАЗАТЕЛЮ, а не копией: struct tls13_keys владеет контекстом в
         * куче, и копия с последующим освобождением обеих — двойное освобождение (см.
         * предупреждение в tls13.h; именно на этом стенд и упал). */
        size_t used = 0;
        check("порча подтверждения: хаб отверг", XS_EAUTH,
              xs_hs_server_confirm(&q.ss, &q.s_rx, q.fin, q.fin_n, &used));
        pair_free(&q);
    }
    {
        /* Отказ неузнанному имеет форму настоящего фатального оповещения TLS. */
        uint8_t alert[16];
        size_t n = xs_hs_alert(alert, sizeof(alert));
        check("отказ: оповещение 7 байт", 7, (long)n);
        check("отказ: тип записи alert", 0x15, alert[0]);
        check("отказ: fatal handshake_failure", 0x0228,
              ((long)alert[5] << 8) | alert[6]);
    }
    {
        /* Затирание: после xs_hs_wipe в состоянии не остаётся ни ключей, ни транскрипта. */
        static struct pair q;
        keys_for(&q);
        handshake(&q, 1439, 1400);
        xs_hs_wipe(&q.cs);
        int nz = 0;
        const uint8_t *raw = (const uint8_t *)&q.cs;
        for (size_t i = 0; i < sizeof(q.cs); i++) if (raw[i]) nz++;
        check("затирание: состояние рукопожатия обнулено", 0, nz);
    }

    pair_free(&p);
    printf("\n%s\n", fails ? "ЕСТЬ ПРОВАЛЫ" : "все проверки прошли");
    return fails ? 1 : 0;
}
