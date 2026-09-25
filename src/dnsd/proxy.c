#include "dnsd_int.h"
#include "sindex.h"
#include "nftnl.h"

#define MAX_PKT 4096

/* ---------------------------------------------------------------------- */
/* proxy state                                                           */
/* ---------------------------------------------------------------------- */

/* MAX_PENDING/PENDING_*, struct pending и g_pending/g_gen_next — в dnsd_int.h: их читает
 * (без static) tests/dnsmatch.c. */

struct pending g_pending[MAX_PENDING];
int g_epfd = -1;
static int g_listen_fd = -1;
/* Единственный сокет к апстриму, живёт всё время работы процесса. Апстрим — это
 * 127.0.0.1, сокет connect'нут, поэтому отказ от случайного исходящего порта здесь
 * ничего не стоит: подделать ответ может только тот, кто уже на петле, а такой и так
 * может всё. */
static int g_up_fd = -1;
/* Порт резолвера наверху — только чтобы назвать его в жалобах: человеку, читающему
 * «запрос не ушёл наверх», нужно знать, куда именно мы не достучались. */
static int g_up_port;
uint8_t g_gen_next;

/* ПЕРЕСПРАШИВАТЬ ТОГО, К КОМУ ШЁЛ ЗАПРОС: --upstream-origdst.
 *
 * На роутере наверху всегда dnsmasq на петле, и резолвер переспрашивает его. На телефоне на
 * петле никто не слушает: DNS приложений делает DnsResolver (модуль netd) — сам, к серверам
 * текущей сети, а раздачу обслуживает dnsmasq тетеринга на адресе интерфейса раздачи. Любой
 * фиксированный апстрим здесь был бы неправдой: серверы сети меняются вместе с сетью, и
 * движок о них не знает.
 *
 * Зато знает ядро. Запрос попадает к нам правилом `redirect` (nat), и в записи conntrack
 * лежит исходное назначение — тот сервер, к которому шёл запрос. По обратному кортежу
 * (наш адрес:порт -> клиент:порт, его видит recvmsg) ctnetlink отдаёт запись целиком, и
 * запрос уходит туда же, куда шёл, — от root, поэтому правило заворота (оно для всех, кроме
 * root) его не заворачивает снова.
 *
 * Сокет наверх в этом режиме не connect'нут (серверы разные), и ответ принимается только от
 * того адреса, куда ушёл запрос: иначе подделать ответ мог бы кто угодно, угадав номер
 * транзакции. Записи NAT нет (к нам обратились напрямую, мимо redirect) или назначение —
 * мы сами — запрос уходит на петлю, как в обычном режиме: так петли не бывает.
 *
 * IPv6 — ТАК ЖЕ, СВОИМ ПУЛОМ. Запрос приложения к серверу сети по IPv6 заворот на output
 * переводит на ::1 (redirect на выходе всегда даёт петлю своего семейства), запись conntrack
 * ищется в семействе AF_INET6, и переспрос уходит к тому же IPv6-серверу сокетом из пула
 * AF_INET6 (g_up_pool6). Отдельный пул, а не двойной стек на одном: у IPv4-пути остаются ровно
 * прежние сокеты и прежнее поведение, а ядро без IPv6 просто не откроет второй пул — тогда
 * IPv6-запрос уходит на петлю, как раньше.
 *
 * Сервер по адресу link-local (fe80::…, его раздаёт RDNSS в объявлении маршрутизатора) —
 * частый случай на Wi-Fi, и зоны (интерфейса) в записи conntrack нет. Переспрос уходит без
 * sin6_scope_id, и интерфейс выбирает маршрут: на Android — по метке сети (см. g_up_mark ниже),
 * которая ведёт в таблицу своей сети, где fe80::/64 указывает на её интерфейс. Без метки
 * решила бы основная таблица. */
/* Раскладка IPV6_PKTINFO и IP_PKTINFO — своя, а не из netinet/in.h: там их видно только с
 * _GNU_SOURCE, а этот файл включают и стенды со своим порядком заголовков. Поля и размеры —
 * ядра (include/uapi/linux/ipv6.h и in.h), от libc они не зависят. */
struct dnsd_in6_pktinfo { struct in6_addr addr; int ifindex; };
struct dnsd_in_pktinfo { int ifindex; struct in_addr spec_dst; struct in_addr addr; };
#ifndef IPV6_RECVPKTINFO
#define IPV6_RECVPKTINFO 49
#endif
#ifndef IPV6_PKTINFO
#define IPV6_PKTINFO 50
#endif
#ifndef IP_PKTINFO
#define IP_PKTINFO 8
#endif

int g_origdst;
int g_ct_fd = -1;
static int g_listen_port;

/* ЗАЩИТА ОТ ПОДДЕЛАННОГО ОТВЕТА В РЕЖИМЕ origdst. Пока наверху была петля, подделать ответ
 * мог только тот, кто уже на ней. Теперь наверху сервер Wi-Fi или оператора, по UDP, и
 * отравить ответ может любой в той же сети, подделав адрес сервера, — а ответ ляжет в общий
 * кэш DnsResolver на всё устройство. Проверка адреса источника от этого не спасает. Спасают
 * две вещи, те же, что у любого резолвера: случайный номер транзакции (вместо слота с
 * поколением — угадывался за десятки попыток) и случайный порт — пул сокетов на случайных
 * портах, запрос уходит случайным из них. Номер к слоту ведёт таблица g_txmap; устаревшая
 * запись безвредна — слот сверяется с номером. */
#define UP_POOL 8
static int g_up_pool[UP_POOL];
static int g_up_pool6[UP_POOL];
static int g_up_pool6_n;              /* открытые сокеты g_up_pool6 — первые g_up_pool6_n */
static int16_t g_txmap[65536];

#ifdef STEER_ANDROID
/* ПЕРЕСПРОС С МЕТКОЙ СЕТИ ИСХОДНОГО ЗАПРОСА (только Android, только origdst).
 *
 * Зачем. netd метит каждый сокет fwmark'ом (Fwmark.h: номер сети — биты 0-15, explicitly
 * selected — 16, protectedFromVpn — 17, права — 18-19, uidBillingDone — 20), и маршрут на
 * телефоне выбирает не адрес, а эта метка: лестница ip rule netd сравнивает её поля масками и
 * отправляет пакет в таблицу своей сети. Приложение, привязанное к мобильной сети при живом
 * Wi-Fi, или DnsResolver, спрашивающий «по сети N» (у каждой сети свои серверы и свой кэш),
 * шлёт запрос с номером той сети. Переспрашивай мы все запросы одной меткой движка, запрос
 * ушёл бы по сети по умолчанию — к серверу мобильной сети через Wi-Fi (где он недоступен или
 * отвечает другое), а сервер link-local — вовсе в чужой интерфейс.
 *
 * Как метка до нас доходит. SO_RCVMARK появился в 5.19, на 4.9 телефона метку датаграммы
 * принятым сокетом не узнать. Зато метку знает правило заворота: оно видит пакет с fwmark
 * приложения и пишет её в метку соединения (`ct mark set mark` в правиле steer-dns-local,
 * см. emit_local_dns в steer.c). А запись conntrack dnsd и так берёт целиком — ради
 * исходного назначения (ct_origdst), — и CTA_MARK лежит в том же ответе ядра: ни одного
 * лишнего системного вызова на запрос.
 *
 * Что уходит наверх: метка соединения без поля движка (биты 22-27) и без бита
 * перемаршрутизации (21), плюс STEER_SELF_MARK в поле движка. Всё прочее — поля netd и биты
 * vendor/ingress — копируется как есть: это их правила, и решать за них нечего. SELF в поле
 * обязателен: по нему правило заворота пропускает наш же переспрос (иначе он завернулся бы
 * к нам по кругу), и по нему же разметка каналов его не трогает. Поэтому канал движка у
 * исходного запроса (приложение «весь трафик», спрашивающее свой DNS само) на переспрос не
 * переносится — он уходит сетью netd, как и шёл бы DnsResolver.
 *
 * Метка ставится на сокет пула прямо перед sendto. Процесс однопоточный (один цикл epoll,
 * без потоков), поэтому между setsockopt и sendto на этот сокет никто не вклинится, а
 * метка у неподключённого UDP-сокета читается ядром на каждой отправке (udp_sendmsg берёт
 * sk_mark и для поиска маршрута, и для skb->mark) — кэша маршрута, который пришлось бы
 * сбрасывать, у него нет. Отдельный сокет на каждую сеть не нужен: ответ приходит на порт
 * сокета независимо от метки. Текущая метка сокета запоминается (g_up_mark), и setsockopt
 * зовётся только при смене — на телефоне с одной сетью это ноль вызовов сверх прежнего. */
static unsigned g_up_mark[UP_POOL], g_up_mark6[UP_POOL];

static unsigned up_mark_for(uint32_t ctmark, int have) {
    if (!have) return STEER_SELF_MARK;
    return (ctmark & ~(STEER_MARK_MASK | STEER_REROUTE_BIT)) | STEER_SELF_MARK;
}

static void up_mark_set(int fd, unsigned *cur, unsigned want) {
    if (*cur == want) return;
    if (setsockopt(fd, SOL_SOCKET, SO_MARK, &want, sizeof(want)) == 0) *cur = want;
}
#endif

static uint16_t rand16(void) {
    uint16_t v = 0;
    if (getrandom(&v, sizeof(v), 0) != (ssize_t)sizeof(v)) v = (uint16_t)(rand() ^ time(NULL));
    return v;
}

/* Соединение TCP, чей запрос (или ответ на чей запрос) обрабатывается прямо сейчас, — или NULL,
 * если датаграмма пришла по UDP. Обработка запроса и ответа — одна на оба протокола (см.
 * dns_query и upstream_answer), и чтобы не протаскивать «куда отвечать» через каждую её ветку,
 * место ответа выставляется вокруг вызова, а reply_client и ct_origdst его читают. Цикл
 * однопоточный, так что это не гонка, а просто контекст вызова. */
struct tcpc;
struct tcpc *g_tcp_cur;
static void tcpc_reply(struct tcpc *c, const void *b, size_t n);
static int tcpu_open(struct pending *p, const uint8_t *q, size_t n, const union dnsd_sa *up,
                     uint16_t tag, size_t qend, uint32_t ctmark, int have_mark);

/* Ответ клиенту. В режиме origdst — с того адреса, на который пришёл запрос: заворот на
 * output переводит запрос приложения на 127.0.0.1, а сокет слушает любой адрес, и без
 * явного адреса источника ядро выбрало бы адрес Wi-Fi. Ответ с чужого адреса conntrack не
 * узнаёт, обратного перевода нет, и DnsResolver (он connect'ит сокет и сверяет, откуда пришёл
 * ответ) его выбрасывает — DNS приложений не работал бы вовсе. */
static void reply_client(const void *b, size_t n, const struct sockaddr_storage *cl,
                         socklen_t cll, const struct dnsd_local *local, int have_local) {
    if (g_tcp_cur) { tcpc_reply(g_tcp_cur, b, n); return; }
    if (!g_origdst || !have_local) {
        sendto(g_listen_fd, b, n, 0, (const struct sockaddr *)cl, cll);
        return;
    }
    struct iovec iov = { (void *)b, n };
    union { struct cmsghdr h; char b[CMSG_SPACE(sizeof(struct dnsd_in6_pktinfo))]; } cb;
    memset(&cb, 0, sizeof(cb));
    struct msghdr mh;
    memset(&mh, 0, sizeof(mh));
    mh.msg_name = (void *)cl; mh.msg_namelen = cll;
    mh.msg_iov = &iov; mh.msg_iovlen = 1;
    mh.msg_control = cb.b;
    struct cmsghdr *c = (struct cmsghdr *)cb.b;
    if (cl->ss_family == AF_INET6) {
        /* Слушающий сокет двойного стека: IPv4-клиенту — v4-mapped адрес приёма, IPv6-клиенту
         * (запрос по IPv6, заворот на ::1) — сам адрес приёма. */
        struct dnsd_in6_pktinfo pi;
        memset(&pi, 0, sizeof(pi));
        if (local->af == AF_INET6) {
            pi.addr = local->v6;
        } else {
            pi.addr.s6_addr[10] = 0xff; pi.addr.s6_addr[11] = 0xff;
            memcpy(&pi.addr.s6_addr[12], &local->v4, 4);
        }
        c->cmsg_level = IPPROTO_IPV6; c->cmsg_type = IPV6_PKTINFO;
        c->cmsg_len = CMSG_LEN(sizeof(pi));
        memcpy(CMSG_DATA(c), &pi, sizeof(pi));
        mh.msg_controllen = CMSG_SPACE(sizeof(pi));
    } else {
        struct dnsd_in_pktinfo pi;
        memset(&pi, 0, sizeof(pi));
        pi.spec_dst = local->v4;
        c->cmsg_level = IPPROTO_IP; c->cmsg_type = IP_PKTINFO;
        c->cmsg_len = CMSG_LEN(sizeof(pi));
        memcpy(CMSG_DATA(c), &pi, sizeof(pi));
        mh.msg_controllen = CMSG_SPACE(sizeof(pi));
    }
    sendmsg(g_listen_fd, &mh, 0);
}

/* Куда слать запрос наверх: исходное назначение (в режиме origdst), иначе петля. *mark — метка
 * исходного соединения (см. g_up_mark), *have_mark — узнали ли её. */
static void upstream_for(const struct sockaddr_storage *cli, const struct dnsd_local *local,
                         int have_local, union dnsd_sa *up, uint32_t *mark, int *have_mark) {
    memset(up, 0, sizeof(*up));
    up->v4.sin_family = AF_INET;
    up->v4.sin_port = htons((uint16_t)g_up_port);
    up->v4.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    *have_mark = 0;
    if (!g_origdst || !have_local) return;
    union dnsd_sa o;
    if (ct_origdst(cli, local, g_listen_port, &o, mark, have_mark) != 0) { *have_mark = 0; return; }
    /* IPv6-назначение, а пула AF_INET6 нет (ядро без IPv6) — на петлю, как раньше. */
    if (o.sa.sa_family == AF_INET6 && g_up_pool6_n == 0) { *have_mark = 0; return; }
    *up = o;
}

/* Поколение для нового ожидания. Оно ОБЯЗАНО быть усечённым здесь, а не только при
 * сборке номера: на приёме сравнивается целое поле p->gen с шестью битами, вынутыми из
 * номера транзакции, и всякое значение от 64 и выше не совпадёт ни с чем. Ответ сверху
 * тогда отбрасывается молча, клиент ждёт таймаута и спрашивает заново — это три запроса
 * из четырёх после первых шестидесяти четырёх, то есть «резолвит по 5-7 секунд» на любом
 * роутере, проработавшем пару минут. Отдельной функцией — чтобы тест проверял именно то
 * выражение, которым пользуется резолвер. */
uint8_t pending_next_gen(void) {
    return (uint8_t)(g_gen_next++ & PENDING_GEN_MASK);
}

/* Номер транзакции, под которым ожидание уходит наверх. */
uint16_t pending_tag(const struct pending *p) {
    return (uint16_t)(((uint16_t)(p->gen & PENDING_GEN_MASK) << PENDING_IDX_BITS) |
                      (uint16_t)((p - g_pending) & PENDING_IDX_MASK));
}

/* Отпечаток СЕКЦИИ ВОПРОСА: имя, тип и класс, то есть всё, что делает вопрос вопросом.
 *
 * Зачем он есть. Ответ приходит на общий сокет, и единственное, чем он связан со своим
 * ожиданием, — номер транзакции. Номер составной (слот плюс поколение), и поколение
 * когда-нибудь повторится: запоздавший ответ на давно закрытый вопрос имеет шанс попасть
 * в живой слот и уехать клиенту КАК ОТВЕТ НА ДРУГОЙ ВОПРОС — то есть чужой адрес вместо
 * нужного, молча. Отпечаток это закрывает по существу: ответ обязан нести тот же вопрос,
 * что мы задали, иначе он не наш, каким бы ни был номер.
 *
 * FNV-1a по сырым байтам, без разбора имени: ответ echo'ит секцию вопроса дословно — на
 * этом уже держится быстрый путь (см. pending.hit), — и сравнивать байты и дешевле, и
 * строже, чем разбирать их второй раз. */
uint16_t question_fp(const uint8_t *pkt, size_t qend) {
    uint32_t h = 2166136261u;
    for (size_t i = 12; i < qend; i++) {
        h ^= pkt[i];
        h *= 16777619u;
    }
    return (uint16_t)((h ^ (h >> 16)) | 1u);   /* ненулевой: 0 значит «отпечатка нет» */
}

/* Сколько секунд подряд отказ ядра ещё считается окном пересборки таблицы.
 *
 * SERVFAIL вместо настоящего адреса (см. handle_upstream_response) оправдан ровно одним
 * состоянием: таблицы с картой ещё нет, и через секунду-другую она будет. Прежде так выглядел
 * каждый apply — он удалял таблицу и грузил новую двумя запусками nft; теперь замена идёт
 * одной транзакцией (см. cmd_apply в steer.c) и карта не пропадает, но окно осталось там, где
 * таблицы нет по-настоящему: резолвер поднят раньше первого apply (старт роутера, установка).
 *
 * Ещё раньше ветка срабатывала на ЛЮБОЙ отказ при открытом сокете netlink — и стойкий отказ
 * (карта не того типа, таблицу снесли и никто не применяет набор заново) превращал «сеть идёт
 * мимо туннеля» в «имена не разрешаются», вопреки fail-open из шапки файла (I-207).
 *
 * Различаются два признака. Код ошибки: в окне пересборки ядро отвечает ENOENT (нет таблицы
 * или карты), а если ответа не дождались — исход неизвестен (ETIMEDOUT), и занятое
 * загрузкой набора ядро похоже именно на это. Всё прочее (EINVAL на карту не того типа,
 * ENOMEM, EPERM) окном не бывает и сразу даёт настоящий ответ. И длительность: окно
 * пересборки — секунды даже на наборе в сотни тысяч элементов, поэтому ENOENT, длящийся
 * дольше MAP_WINDOW_SEC с первого отказа подряд, считается стойким. Серия обрывается первым
 * же принятым отображением. */
#define MAP_WINDOW_SEC 15
static time_t g_map_fail_since;

static int map_refusal_is_window(int rc, time_t now) {
    if (rc != -ENOENT && rc != -ETIMEDOUT) return 0;
    if (!g_map_fail_since) g_map_fail_since = now;
    return now - g_map_fail_since < MAP_WINDOW_SEC;
}

static volatile int g_reload_pending = 0;
static volatile int g_running = 1;

static void on_sighup(int sig) { (void)sig; g_reload_pending = 1; }
static void on_sigterm(int sig) { (void)sig; g_running = 0; }

/* Поколение правил: pending несёт результат матчинга, вычисленный на приёме
 * запроса, и ответ вправе переиспользовать его только пока правила те же.
 * SIGHUP посреди пятисекундного окна ожидания — редкость, но молча применить
 * старое решение к новым правилам — это класс ошибок, который снаружи не
 * виден вовсе. */
static unsigned g_rules_gen;

/* Перечитать списки всех каналов.
 *
 * Новый набор собирается РЯДОМ и подменяет текущий только целиком. Прежде текущий
 * освобождался первым, и HUP в тот миг, когда файла списка нет (его переписывают или
 * качают заново), оставлял канал без правил вовсе: имена канала до следующего HUP шли
 * настоящими адресами мимо туннеля — вопреки обещанию load_rules_into «missing file:
 * caller keeps what it has» (I-318). Теперь нет хотя бы одного файла канала — канал
 * остаётся с тем, что было. Исключение — пустой прежний набор (первая загрузка при
 * запуске): держаться там не за что, и канал берёт те файлы, что есть. Исчезнуть файлу
 * насовсем HUP не может: перечень файлов входит в подпись таблицы (dch_signature), и
 * его смена ведёт к перезапуску, а не к HUP. */
static void reload_rules(void) {
    g_rules_gen++;
    for (size_t i = 0; i < g_dch_n; i++) {
        struct ruleset fresh;
        memset(&fresh, 0, sizeof(fresh));
        int missing = 0;
        for (size_t k = 0; k < g_dch[i].rules_n; k++)
            if (load_rules_into(g_dch[i].rules_path[k], &fresh) != 0) {
                missing++;
                fprintf(stderr, "steer dnsd: channel %s: %s не читается\n",
                        g_dch[i].set, g_dch[i].rules_path[k]);
            }
        if (missing && g_dch[i].rules.n > 0) {
            ruleset_free(&fresh);
            fprintf(stderr, "steer dnsd: channel %s: оставлены прежние правила\n",
                    g_dch[i].set);
            continue;
        }
        ruleset_free(&g_dch[i].rules);
        g_dch[i].rules = fresh;
    }
    for (size_t i = 0; i < g_dch_n; i++)
        fprintf(stderr, "steer dnsd: channel %s: %zu rule(s)\n",
                g_dch[i].set, g_dch[i].rules.n);
}

/* Снятие протухших ожиданий. Вызывается из секундного тика цикла событий, а не
 * на каждом запросе: полный проход по таблице (256 записей по ~160 байт — это
 * ~40 КБ, весь L1 роутерного ядра) на каждый пакет вымывал из кеша и индекс
 * правил, и таблицу fake-IP. Тик же заодно закрывает случай, который прежний
 * реап «по дороге» не закрывал вовсе: на тихой сети слот запроса, чей upstream
 * так и не ответил, висел с открытым fd до следующего чужого запроса. */
static void pending_reap(time_t now) {
    for (int i = 0; i < MAX_PENDING; i++) {
        if (g_pending[i].in_use && g_pending[i].expire < now)
            g_pending[i].in_use = 0;      /* сокета за слотом больше нет — закрывать нечего */
    }
}

static struct pending *pending_alloc(void) {
    for (int i = 0; i < MAX_PENDING; i++)
        if (!g_pending[i].in_use) return &g_pending[i];
    /* Всё занято — прежде чем ронять запрос, попробовать вернуть протухшее:
     * редкий путь, но именно он сохраняет прежнюю ёмкость под всплеском. */
    pending_reap(time(NULL));
    for (int i = 0; i < MAX_PENDING; i++)
        if (!g_pending[i].in_use) return &g_pending[i];
    return NULL;
}

/* Возвращает 1, если датаграмма была и обработана, 0 — если читать нечего.
 * Слушающий сокет неблокирующий, и цикл событий дочитывает очередь до EAGAIN:
 * под всплеском (страница — это 20-40 запросов за миллисекунды) это один
 * epoll_wait на пачку вместо круга через ядро на каждую датаграмму. */
/* upstream_port больше не нужен на этом пути: сокет наверх открыт и connect'нут один раз
 * в run_proxy, порт задан там. */
static int dns_query(uint8_t *buf, ssize_t n, struct sockaddr_storage from, socklen_t fromlen,
                     struct dnsd_local local, int have_local);
static int handle_client_query(void) {
    uint8_t buf[MAX_PKT];
    /* Dual-stack listener -> the client may be IPv6 (or v4-mapped). The reply is
     * sent back to exactly these bytes, so the family never has to be inspected. */
    struct sockaddr_storage from;
    socklen_t fromlen = sizeof(from);
    ssize_t n;
    /* Адрес, на который пришла датаграмма, нужен только режиму origdst: по нему (вместе с
     * адресом клиента) ищется запись conntrack. В обычном режиме — прежний recvfrom. */
    struct dnsd_local local;
    memset(&local, 0, sizeof(local));
    int have_local = 0;
    if (g_origdst) {
        struct iovec iov = { buf, sizeof(buf) };
        union { struct cmsghdr h; char b[CMSG_SPACE(sizeof(struct dnsd_in6_pktinfo)) +
                                          CMSG_SPACE(sizeof(struct dnsd_in_pktinfo))]; } cb;
        struct msghdr mh;
        memset(&mh, 0, sizeof(mh));
        mh.msg_name = &from; mh.msg_namelen = sizeof(from);
        mh.msg_iov = &iov; mh.msg_iovlen = 1;
        mh.msg_control = cb.b; mh.msg_controllen = sizeof(cb.b);
        n = recvmsg(g_listen_fd, &mh, 0);
        if (n <= 0) return 0;
        fromlen = mh.msg_namelen;
        for (struct cmsghdr *c = CMSG_FIRSTHDR(&mh); c; c = CMSG_NXTHDR(&mh, c)) {
            if (c->cmsg_level == IPPROTO_IPV6 && c->cmsg_type == IPV6_PKTINFO) {
                struct dnsd_in6_pktinfo pi;
                memcpy(&pi, CMSG_DATA(c), sizeof(pi));
                if (IN6_IS_ADDR_V4MAPPED(&pi.addr)) {
                    local.af = AF_INET;
                    memcpy(&local.v4, &pi.addr.s6_addr[12], 4);
                } else {
                    local.af = AF_INET6;
                    local.v6 = pi.addr;
                }
                have_local = 1;
            } else if (c->cmsg_level == IPPROTO_IP && c->cmsg_type == IP_PKTINFO) {
                struct dnsd_in_pktinfo pi;
                memcpy(&pi, CMSG_DATA(c), sizeof(pi));
                local.af = AF_INET;
                local.v4 = pi.addr;
                have_local = 1;
            }
        }
    } else {
        n = recvfrom(g_listen_fd, buf, sizeof(buf), 0, (struct sockaddr *)&from, &fromlen);
        if (n <= 0) return 0;
    }
    return dns_query(buf, n, from, fromlen, local, have_local);
}

/* Запрос клиента — один путь для UDP и TCP: разбор, доменные каналы, быстрый путь, пересылка
 * наверх. Откуда пришёл запрос, решает g_tcp_cur (NULL — UDP). Аргументы по значению: так тело
 * осталось тем же, каким было внутри handle_client_query. Буфер переписывается (номер
 * транзакции наверх). Возвращает 1 — как handle_client_query, «запрос был». */
static int dns_query(uint8_t *buf, ssize_t n, struct sockaddr_storage from, socklen_t fromlen,
                     struct dnsd_local local, int have_local) {
    /* Быстрый путь: на вопрос, ответ на который НЕ ЗАВИСИТ от upstream, отвечаем
     * прямо из запроса. Это и есть задержка fake-ip глазами клиента: раньше каждый
     * запрос — включая повторный A для уже выданного fake-IP и AAAA/HTTPS/SVCB,
     * ответ на которые для совпавшего домена всегда NODATA, — ждал полного круга
     * до резолвера и обратно. Теперь круг платит только первый A нового домена:
     * лишь ему нужен настоящий адрес, без которого нечего класть в DNAT. */
    char qname[MAX_HOSTNAME];
    uint16_t qtype = 0;
    size_t qend = 0;
    int quiet = 0;
    int hit = -2; /* -2 = вопрос не разобрался; см. struct pending */
    uint64_t sets = 0;
    if (parse_query(buf, (size_t)n, qname, sizeof(qname), &qtype, &qend) == 0) {
        /* Совпавшие каналы — ВСЕ, а решает ответ первый из них: он старший по
         * порядку правил, а ответ клиенту всё равно один. */
        sets = dch_match_mask(qname);
        hit = dch_first(sets);
        /* В журнал — каждый разобранный вопрос, до быстрого пути: ответ из быстрого пути —
         * тоже запрос приложения. Сюда приходят и UDP, и TCP (tcpc_read зовёт эту же функцию). */
        dlog_note(qname, hit);
        if (hit >= 0 && !g_dch[hit].realip) {
            if (qtype == DNS_TYPE_AAAA || qtype == DNS_TYPE_HTTPS ||
                qtype == DNS_TYPE_SVCB) {
                /* Подавление — свойство правила, а не данных из ответа: NODATA
                 * можно построить из самого вопроса, наверх не ходим вовсе. */
                uint8_t out[512];
                size_t len = build_rewritten_response(buf, qend, out, sizeof(out), 0, 0);
                if (len) {
                    make_response_flags(out);
                    reply_client(out, len, &from, fromlen, &local, have_local);
                    return 1;
                }
            } else if (qtype == DNS_TYPE_A) {
                /* Ключи таблицы — всегда в нижнем регистре (ответ приводится
                 * перед вставкой), поэтому и искать нужно так же: клиент с
                 * рандомизацией регистра (DNS-0x20) обязан попадать в ту же
                 * запись, что и обычный. */
                char lname[MAX_HOSTNAME];
                snprintf(lname, sizeof(lname), "%s", qname);
                str_lower(lname);
                long at = fakeip_find(lname);
                if (at >= 0 && g_fakeip.entries[at].real_host) {
                    /* DNAT для этого fake-IP уже стоит (real_host запоминается
                     * только после успешного ack от ядра либо восстановлен
                     * rehydrate-проходом) — значит, ответ клиенту безопасен до
                     * похода наверх. */
                    uint8_t out[512];
                    size_t len = build_rewritten_response(buf, qend, out, sizeof(out),
                                                          1, g_fakeip.entries[at].addr);
                    if (len) {
                        make_response_flags(out);
                        reply_client(out, len, &from, fromlen, &local, have_local);
                        /* Маршрут переутверждается идемпотентно (fw4 reload
                         * смывает элементы наборов); дроссель внутри. */
                        fakeip_route_set(lname, dch_fakeip_only(sets));
                        /* Поход наверх — только ради свежести DNAT-карты, и
                         * чаще TTL ответа он ничего нового не узнаёт: клиент
                         * до истечения TTL и не переспросит. Без дросселя
                         * каждый повторный запрос оплачивал полный круг
                         * сокет-эполл-резолвер плюс работу dnsmasq — на том же
                         * единственном ядре. */
                        time_t now = time(NULL);
                        if (now - g_fakeip.entries[at].refreshed < FAKEIP_ANSWER_TTL)
                            return 1;
                        g_fakeip.entries[at].refreshed = now;
                        quiet = 1;
                    }
                }
            }
        }
    }

    struct pending *p = pending_alloc();
    if (!p) {
        /* Мест нет: запрос отбрасывается, клиент переспросит сам. Но сказать об этом
         * надо — это и есть «DNS тормозит», увиденное изнутри, и без строки в журнале
         * отличить его от беды у провайдера нечем. */
        static time_t said_full;
        time_t now = time(NULL);
        if (warn_due(&said_full, now))
            fprintf(stderr, "steer dnsd: таблица ожиданий полна (%d мест): запросы "
                            "отбрасываются. Резолвер наверху (127.0.0.1:%d) отвечает "
                            "слишком медленно\n", MAX_PENDING, g_up_port);
        return 1;
    }

    if (g_up_fd < 0) return 1;                 /* апстрим не открылся — отвечать нечем */

    /* Номер транзакции переписывается на наш: ответы всех ожиданий приходят теперь на
     * ОДИН сокет, и различить их можно только по нему. Исходный номер клиента ложится в
     * слот и возвращается на место в ответе. */
    p->cli_id = (uint16_t)((buf[0] << 8) | buf[1]);
    p->gen = pending_next_gen();
    uint16_t tag = pending_tag(p);
    int ufd = g_up_fd;
    union dnsd_sa up;
    uint32_t ctmark = 0;
    int have_mark = 0;
    upstream_for(&from, &local, have_local, &up, &ctmark, &have_mark);
    socklen_t uplen = up.sa.sa_family == AF_INET6 ? sizeof(up.v6) : sizeof(up.v4);
    if (g_origdst) {
        tag = rand16();
        g_txmap[tag] = (int16_t)(p - g_pending);
        p->txid = tag;
        /* Пул — по семейству сервера: IPv6-назначение upstream_for отдаёт, только если пул
         * AF_INET6 открыт (g_up_pool6_n > 0). */
        if (up.sa.sa_family == AF_INET6) {
            int i = rand16() % g_up_pool6_n;
            ufd = g_up_pool6[i];
#ifdef STEER_ANDROID
            up_mark_set(ufd, &g_up_mark6[i], up_mark_for(ctmark, have_mark));
#endif
        } else {
            int i = rand16() % UP_POOL;
            ufd = g_up_pool[i];
            if (ufd < 0) ufd = g_up_fd;
#ifdef STEER_ANDROID
            else up_mark_set(ufd, &g_up_mark[i], up_mark_for(ctmark, have_mark));
#endif
        }
    }
    (void)ctmark; (void)have_mark;
    p->up_fd = ufd;
    buf[0] = (uint8_t)(tag >> 8);
    buf[1] = (uint8_t)(tag & 0xFF);

    /* Запрос, пришедший по TCP, уходит наверх тоже по TCP (почему — у struct tcpu), к тому же
     * серверу и с той же меткой сети; тихий (клиенту уже ответили из быстрого пути, ответ нужен
     * только ради карты) — по UDP, как любой: ответ ему не нужен целиком, а круг по UDP дешевле
     * рукопожатия. */
    int tcpu = -1;
    if (g_tcp_cur && !quiet) {
        tcpu = tcpu_open(p, buf, (size_t)n, &up, tag, qend, ctmark, have_mark);
        if (tcpu < 0) return 1;                /* ответ SERVFAIL уже ушёл клиенту */
    } else if ((g_origdst ? sendto(ufd, buf, (size_t)n, 0, &up.sa, uplen)
                   : send(g_up_fd, buf, (size_t)n, 0)) < 0) {
        /* Чаще всего это ECONNREFUSED от петли: резолвер наверху не запущен или
         * перезапускается. Ядро отдаёт такую ошибку отложенно, следующим системным
         * вызовом, поэтому одна строка на десять секунд — ровно то, что нужно: увидеть
         * факт, не залив журнал. */
        static time_t said_send;
        time_t now = time(NULL);
        if (warn_due(&said_send, now))
            fprintf(stderr, "steer dnsd: запрос не ушёл наверх (127.0.0.1:%d): %s\n",
                    g_up_port, strerror(errno));
        return 1;
    }

    /* Отпечаток вопроса — ПОСЛЕ удачной отправки и до того, как слот объявлен занятым:
     * ровно те байты, что уехали наверх. Вопрос, который не разобрался (qend == 0),
     * отпечатка не получает. */
    p->qfp = (qend > 12 && qend <= (size_t)n) ? question_fp(buf, qend) : 0;
    p->qsec_end = (uint16_t)((p->qfp) ? qend : 0);

    p->in_use = 1;
    p->tcp_up = tcpu;
    p->quiet = quiet;
    p->hit = hit;
    p->sets = sets;
    p->rules_gen = g_rules_gen;
    p->client = from;
    p->client_len = fromlen;
    p->up = up;
    p->local = local;
    p->have_local = have_local;
    p->expire = time(NULL) + PENDING_TTL_SEC;
    return 1;
}

/* Ответ пришёл оттуда, куда ушёл вопрос: семейство, адрес и порт. Зона (sin6_scope_id) не
 * сравнивается: вопрос к серверу link-local уходит без неё (см. g_origdst), а ответ приходит
 * с номером интерфейса. */
static int up_same(const union dnsd_sa *a, const union dnsd_sa *b) {
    if (a->sa.sa_family != b->sa.sa_family) return 0;
    if (a->sa.sa_family == AF_INET6)
        return !memcmp(&a->v6.sin6_addr, &b->v6.sin6_addr, 16) &&
               a->v6.sin6_port == b->v6.sin6_port;
    return a->v4.sin_addr.s_addr == b->v4.sin_addr.s_addr && a->v4.sin_port == b->v4.sin_port;
}

/* Возвращает 1, если датаграмма была прочитана (есть смысл читать дальше), 0 — если
 * очередь пуста. Ответы всех ожиданий приходят на один сокет, поэтому своё ожидание
 * находится по номеру транзакции, который мы же и проставили при отправке. */
static int upstream_answer(struct pending *p, uint8_t *buf, ssize_t n);
static int handle_upstream_response(int ufd) {
    uint8_t buf[MAX_PKT];
    union dnsd_sa src;
    socklen_t srclen = sizeof(src);
    memset(&src, 0, sizeof(src));
    ssize_t n = recvfrom(ufd, buf, sizeof(buf), 0, &src.sa, &srclen);
    if (n < 0) {
        if (errno == EAGAIN || errno == EWOULDBLOCK) return 0;   /* очередь пуста */
        /* Прочая ошибка — это ОДНА отложенная ошибка сокета (обычно ECONNREFUSED с
         * петли), а не конец очереди: за ней в очереди могут лежать настоящие ответы, и
         * прежний `return 0` бросал их ждать следующего витка цикла. Читаем дальше. */
        static time_t said_recv;
        time_t now = time(NULL);
        if (warn_due(&said_recv, now))
            fprintf(stderr, "steer dnsd: ошибка чтения ответа сверху (127.0.0.1:%d): %s\n",
                    g_up_port, strerror(errno));
        return 1;
    }
    if (n < 12) return 1;                      /* короче заголовка DNS — не ответ */

    uint16_t tag = (uint16_t)((buf[0] << 8) | buf[1]);
    struct pending *p = &g_pending[tag & PENDING_IDX_MASK];
    if (g_origdst) {
        /* Случайный номер: слот — по таблице, и сверяется всё — номер, сокет, источник. */
        int slot = g_txmap[tag];
        if (slot < 0) return 1;
        p = &g_pending[slot];
        if (!p->in_use || p->txid != tag || p->up_fd != ufd) return 1;
    }
    /* Слот занят и поколение совпадает. Иначе датаграмма — запоздавший ответ на давно
     * закрытое ожидание или чужая подделка, и применять её к живому слоту нельзя. */
    if (!p->in_use ||
        (!g_origdst && p->gen != (uint8_t)((tag >> PENDING_IDX_BITS) & PENDING_GEN_MASK)))
        return 1;
    /* Режим origdst: сокет не connect'нут, и ответ обязан прийти оттуда, куда ушёл вопрос. */
    if (g_origdst && !up_same(&src, &p->up)) return 1;
    /* И ГЛАВНОЕ: ответ обязан отвечать на НАШ вопрос. Поколение когда-нибудь повторится
     * (шесть бит), и без этой проверки запоздавший ответ уехал бы клиенту как ответ на
     * другой вопрос — чужой адрес вместо нужного, молча и без единой строки в журнале. */
    if (p->qfp && ((size_t)n < p->qsec_end || question_fp(buf, p->qsec_end) != p->qfp))
        return 1;
    /* Ожидание, ушедшее наверх по TCP, ждёт ответа на своём соединении, а не здесь. */
    if (p->tcp_up >= 0) return 1;
    return upstream_answer(p, buf, n);
}

/* Ответ сверху, уже сверенный со своим ожиданием, — один путь для UDP и TCP: доменные каналы,
 * fakeip, наборы, ответ клиенту. Кому отвечать, решает g_tcp_cur (см. reply_client). */
static int upstream_answer(struct pending *p, uint8_t *buf, ssize_t n) {
    /* Номер клиента возвращается на место ДО любой отправки вниз: клиент сопоставляет
     * ответ с запросом именно по нему, а дальше буфер уходит клиенту и как есть, и
     * переписанным. */
    buf[0] = (uint8_t)(p->cli_id >> 8);
    buf[1] = (uint8_t)(p->cli_id & 0xFF);

    p->in_use = 0;
    int quiet = p->quiet;

    /* Несовпавший домен (подавляющее большинство трафика): решение уже принято
     * на приёме запроса, имя вопроса в ответе — те же байты, а правила с тех
     * пор не менялись. Разбирать пакет и матчить его второй раз — значит
     * оплачивать разбор каждой RR и проход по индексам всех каналов ради
     * вывода, который уже известен: реле как есть. */
    if (p->hit == -1 && p->rules_gen == g_rules_gen) {
        if (!quiet)
            reply_client(buf, (size_t)n, &p->client, p->client_len, &p->local, p->have_local);
        return 1;
    }

    char qname[MAX_HOSTNAME];
    uint16_t qtype = 0;
    size_t qend = 0;
    struct answer_ip ips[32];
    int nips = parse_response(buf, (size_t)n, qname, sizeof(qname), &qtype, &qend, ips, 32);
    /* В нижний регистр СРАЗУ: дальше это имя — ключ таблицы fake-IP и вход
     * матчинга. Прежде вставка шла в регистре ответа (эхо запроса клиента), и
     * клиент с DNS-0x20 плодил второй fake-IP на тот же домен, а быстрый путь,
     * ищущий строчными, не находил такую запись никогда. */
    if (nips >= 0) str_lower(qname);

    /* Unparseable (malformed, or the rare qdcount != 1) or no rule match:
     * relay the real answer unchanged, exactly as before this feature. */
    /* Имя, названное в нескольких правилах, принадлежит ВСЕМ ним, а ответ клиенту
     * строит первое — старшее по порядку правил. Кто из правил заберёт пакет, решает
     * порядок цепочки, то есть тот же порядок, который человек видит в списке правил
     * и меняет стрелками (решение владельца: «победитель выше», а не «нижнее правило
     * отбрасываем»). Прежде поддельный адрес ложился в набор ОДНОГО канала, и для
     * клиентов остальных имя переставало открываться вовсе. */
    int hit = -1;
    uint64_t sets = 0;
    if (nips >= 0) {
        if (p->hit >= 0 && p->rules_gen == g_rules_gen) {
            hit = p->hit; /* матчинг уже сделан на приёме запроса */
            sets = p->sets;
        } else {
            sets = dch_match_mask(qname);
            hit = dch_first(sets);
        }
    }
    if (nips < 0 || hit < 0) {
        if (!quiet)
            reply_client(buf, (size_t)n, &p->client, p->client_len, &p->local, p->have_local);
        return 1;
    }

    /* Matched a rule. AAAA, HTTPS (65), and SVCB (64) are suppressed outright
     * (NODATA) rather than relayed:
     * - AAAA: splify has no IPv6 routing at all (VPN_SET/DIRECT_SET are IPv4-only),
     *   so letting a real AAAA answer through would hand a dual-stack client a real
     *   unmanaged address bypassing the tunnel.
     * - HTTPS/SVCB: upstream HTTPS responses contain ipv4hint/ipv6hint (real IPs) and
     *   h3 (QUIC ALPN). Letting real IPv4/IPv6 hints through causes modern browsers to
     *   attempt direct connections to real IPs outside fake-IP DNAT/set, causing 1-3s delays. */
    if (qtype == DNS_TYPE_AAAA || qtype == DNS_TYPE_HTTPS || qtype == DNS_TYPE_SVCB) {
        if (!quiet) {
            uint8_t out[512];
            size_t len = build_rewritten_response(buf, qend, out, sizeof(out), 0, 0);
            reply_client(len ? out : buf, len ? len : (size_t)n, &p->client, p->client_len, &p->local, p->have_local);
        }
        return 1;
    }

    /* real-IP mode: the answer goes to the client untouched and every address in it
     * joins the channel's set with its own TTL. No DNAT is involved, so ICMP errors
     * are not rewritten and a traceroute shows the actual hops — which is the whole
     * reason this mode exists. The cost is precision: two domains behind one address
     * become one entry, and if they belong to different channels the first one to be
     * resolved decides for both. */
    if (g_dch[hit].realip) {
        /* Адреса кладутся в наборы ВСЕХ совпавших каналов реального адреса, а не
         * только первого: правило на устройство и правило на всю сеть спорят за одно
         * имя законно, и решать спор должен порядок цепочки. Каналы поддельного
         * адреса среди совпавших пропускаются — им поддельного адреса никто не
         * выдавал, класть в их набор нечего. */
        if (qtype == DNS_TYPE_A)
            for (size_t c = 0; c < g_dch_n; c++) {
                if (!(sets & (1ULL << c)) || !g_dch[c].realip) continue;
                for (int k = 0; k < nips; k++)
                    nft_add_element(g_dch[c].set, ntohl(ips[k].addr), set_ttl_clamp(ips[k].ttl));
            }
        if (!quiet)
            reply_client(buf, (size_t)n, &p->client, p->client_len, &p->local, p->have_local);
        return 1;
    }

    if (qtype == DNS_TYPE_A && nips > 0) {
        uint32_t fake_addr;
        if (fakeip_lookup_or_alloc(qname, &fake_addr) == 0) {
            /* Какой адрес класть в DNAT. Порядок RR в ответе — не сигнал: CDN
             * тасуют записи в каждом ответе, и «первый A сменился» означало
             * delete+add транзакцию в ядре и перезапись state-файла на каждый
             * ре-резолв — вечно, пока домен спрашивают. Если установленный
             * backend всё ещё среди ответов, он всё ещё обслуживает домен —
             * оставляем его; настоящий переезд (адреса нет в ответе) по-прежнему
             * ведёт к замене. */
            uint32_t known = fakeip_entry_get_real(qname);
            uint32_t real_host = ntohl(ips[0].addr);
            if (known)
                for (int k = 0; k < nips; k++)
                    if (ntohl(ips[k].addr) == known) { real_host = known; break; }
            if (dbg())
                fprintf(stderr, "nftlk-debug: matched qname=%s qtype=%u nips=%d fake=0x%08x real=0x%08x nlk_fd=%d\n",
                        qname, qtype, nips, fake_addr, real_host, g_nlk_fd);
            /* DNAT map FIRST, synchronously, and ONLY hand the client the fake
             * IP once the kernel has acked the fake->real mapping. This is the
             * fix for the "locks up the router" symptom: previously the fake IP
             * was returned immediately while the (fork/exec'd, OOM-prone) map
             * add raced asynchronously and usually lost, leaving clients with a
             * fake IP whose DNAT entry never landed — a SYN into the tunnel to
             * nowhere, hanging on TCP retries for minutes. Now a failed/missing
             * ack makes us relay the REAL answer instead (fail-open). */
            int maprc = nft_map_set_element(g_fakeip_map, fake_addr, real_host,
                                            known);
            if (dbg())
                fprintf(stderr, "nftlk-debug: nft_map_set_element -> %d\n", maprc);
            if (maprc == 0) {
                g_map_fail_since = 0;               /* серия отказов ядра окончена */
                /* Record the real backend so a post-restart rehydrate can rebuild
                 * the DNAT map from state without re-resolving every domain. */
                fakeip_entry_set_real(qname, real_host);

                /* Route the fake IP into its channel's set as a PERMANENT element.
                 * This replaces the old `nft_add_element(..., ips[0].ttl)`: a TTL
                 * equal to the real answer's expired mid-session and the packet
                 * then bypassed the tunnel (see fakeip_route_set). Best-effort:
                 * a missing entry means default policy, which is fine. Наборов
                 * может быть несколько — по одному на каждое правило, назвавшее это
                 * имя; какая метка победит, решает порядок цепочки, и это ровно тот
                 * порядок, в котором правила стоят у человека. */
                fakeip_route_set(qname, dch_fakeip_only(sets));

                /* Клиенту из быстрого пути уже ушёл fake-IP; этот ответ был нужен
                 * только ради строк выше — обновить карту и реальный адрес. */
                if (quiet) return 1;

                uint8_t out[512];
                size_t len = build_rewritten_response(buf, qend, out, sizeof(out), 1, fake_addr);
                if (len > 0) {
                    reply_client(out, len, &p->client, p->client_len, &p->local, p->have_local);
                    return 1;
                }
            } else if (g_nlk_fd >= 0 && map_refusal_is_window(maprc, time(NULL))) {
                /* Ядро НЕ ПРИНЯЛО подмену при живом netlink в окне пересборки таблицы — apply
                 * пересобирает таблицу, и карты ещё нет (что считается окном, решает
                 * map_refusal_is_window; стойкий отказ идёт ниже, в fail-open). Прежний ответ здесь был
                 * fail-open: клиенту уходил настоящий адрес. Для домена, который человек велел
                 * вести в туннель, это не «открыто», а «мимо»: сайт идёт напрямую (у
                 * заблокированного — не идёт вовсе), и клиент запоминает настоящий адрес на
                 * весь TTL записи — минуты, а браузер ещё держит на нём соединения. Снято с
                 * живого роутера: после «Применить» посреди YouTube ролики не открывались до
                 * перезапуска браузера уже при исправном туннеле.
                 *
                 * SERVFAIL честнее: клиент повторит запрос через секунду-две, к этому времени
                 * карта на месте, и ответом будет поддельный адрес с работающей подменой.
                 * Кэшировать SERVFAIL резолверы не имеют права дольше пары секунд. Без
                 * netlink вовсе (g_nlk_fd < 0) поведение прежнее — там подмены нет и не
                 * будет, и настоящий адрес лучше тишины. */
                if (!quiet) {
                    uint8_t out[512];
                    size_t len = build_rewritten_response(buf, qend, out, sizeof(out), 0, 0);
                    if (len) {
                        make_response_flags(out);
                        out[3] = (uint8_t)((out[3] & 0xf0) | 0x02);   /* RCODE 2 — SERVFAIL */
                        reply_client(out, len, &p->client, p->client_len, &p->local, p->have_local);
                    }
                }
                static time_t warned;
                time_t now = time(NULL);
                if (now - warned > 60) {
                    warned = now;
                    fprintf(stderr, "steer dnsd: подмена для %s не встала в ядро (rc=%d) — "
                                    "клиенту отвечено SERVFAIL, а не настоящим адресом\n",
                            qname, maprc);
                }
                return 1;
            } else if (g_nlk_fd >= 0) {
                /* Стойкий отказ — дальше fail-open настоящим ответом, как везде в файле. */
                static time_t warned_open;
                time_t now = time(NULL);
                if (now - warned_open > 60) {
                    warned_open = now;
                    fprintf(stderr, "steer dnsd: подмена для %s не встала в ядро (rc=%d) — "
                                    "клиенту отвечено настоящим адресом\n", qname, maprc);
                }
            }
        }
    }

    /* Fallback: matched but nothing to substitute (qtype outside A/AAAA/HTTPS/SVCB
     * — MX, TXT, PTR and the like — zero real A answers yet, or the fake-IP pool
     * is exhausted). Relay the real answer unchanged — fail open, never block the
     * DNS transaction. */
    if (!quiet)
        reply_client(buf, (size_t)n, &p->client, p->client_len, &p->local, p->have_local);
    return 1;
}

/* ---------------------------------------------------------------------- */
/* DNS по TCP (RFC 7766)                                                  */
/* ---------------------------------------------------------------------- */

/* ЗАЧЕМ РЕЗОЛВЕРУ TCP. По TCP спрашивают три рода клиентов: получившие по UDP усечённый ответ
 * (TC=1 — большой ответ, DNSSEC, длинные цепочки CNAME), те, кому ответ заведомо велик, и
 * приложения, которые ходят по TCP сразу. Пока резолвер слушал только UDP, такие вопросы шли
 * мимо него: доменный канал имени не видел, поддельный адрес не выдавался, набор канала не
 * наполнялся, и соединение уходило по настоящему адресу — мимо туннеля, молча.
 *
 * Слушает резолвер TCP всегда, на том же адресе и порту, что и UDP, а заворачивает к нему
 * TCP/53 только Android-сборка (steer.c: prerouting_dns, prerouting_nat, emit_local_dns).
 * Правила роутера этим изменением не тронуты: их вывод стерегут побайтно, и включать заворот
 * TCP на роутере — отдельное решение. Лишний слушающий сокет без заворота к нему ничего не
 * ломает: к порту 5300 по TCP никто, кроме заворота, не обращается.
 *
 * УСТРОЙСТВО. Цикл однопоточный, и медленный клиент TCP не должен его останавливать: все сокеты
 * неблокирующие, чтение копится в буфере соединения, недописанный ответ — в его очереди, и ни
 * одна операция не ждёт. Каждое сообщение потока (два байта длины и сам запрос) идёт тем же
 * dns_query, что и датаграмма, — с теми же доменными каналами, быстрым путём, fakeip и
 * наборами. Несколько запросов подряд в одном соединении (конвейер) обрабатываются по мере
 * прихода, и ответы уходят в порядке готовности: RFC 7766 это разрешает, клиент сопоставляет
 * ответ с вопросом по номеру транзакции.
 *
 * ЛИМИТЫ. TCP_MAX_CONN соединений клиентов; новое сверх него вытесняет самое давно молчащее из
 * тех, у кого нет запросов в пути и кто молчит хотя бы секунду. Секунда — не прихоть: на всплеске
 * соединений вытеснялись бы только что принятые, ещё не успевшие прислать вопрос, и из перегрузки
 * не выигрывал бы никто. Вытеснить некого — новое соединение не принимается вовсе, а ждёт в
 * очереди ядра (listen), пока место не освободится: слушающий сокет на это время снимается с
 * epoll (иначе уровневый epoll будил бы цикл впустую), а возвращается при закрытии соединения и
 * на секундном тике. Закрыть принятое сразу было бы хуже: клиент получил бы обрыв, а не ожидание
 * в полсекунды. Простой — TCP_IDLE_SEC,
 * и отсчитывается он от последнего ЦЕЛОГО запроса или сдвига очереди записи, а не от последнего
 * байта: иначе клиент, присылающий по байту раз в несколько секунд, держал бы место вечно.
 * Проверка простоя и сроков — на секундном тике цикла, который уже есть ради pending_reap: своих
 * таймеров у TCP нет, и будить устройство ему нечем — epoll_wait ждёт по CLOCK_MONOTONIC,
 * который во сне стоит. Если тик когда-нибудь станет «только пока есть ожидания», соединения
 * TCP тоже должны его держать — иначе простой не снимется до следующего события. */
#include <netinet/tcp.h>
#include <stddef.h>

#define TCP_MAX_CONN 32
#define TCP_MAX_UP   64
#define TCP_IDLE_SEC 10
/* Предел недописанных ответов одного соединения. Ответ — до 64 КБ; клиент, который не читает
 * и четыре таких, больше не клиент, а место в памяти. */
#define TCP_OUT_MAX  (256 * 1024)

/* Соединение клиента. Буфер чтения — на одно сообщение наибольшей длины, которую мы принимаем
 * (MAX_PKT, как у датаграммы): полный запрос в нём помещается всегда, и после его разбора
 * место под следующий есть. Запрос длиннее — не запрос, а мусор, и соединение закрывается. */
struct tcpc {
    int fd;                         /* -1 — место свободно */
    uint32_t gen;                   /* растёт на каждом открытии: так запрос наверху узнаёт,
                                     * что его соединение закрыто и место отдано другому */
    int eof;                        /* клиент закрыл свою сторону: дописать ответы и закрыть */
    int inflight;                   /* его запросов наверху (g_tcpu) */
    uint32_t ev;                    /* интерес в epoll сейчас */
    time_t last;                    /* последний целый запрос или сдвиг записи */
    struct sockaddr_storage peer;
    socklen_t peer_len;
    struct dnsd_local local;        /* куда подключился клиент — для conntrack (origdst) */
    int have_local;
    size_t in_len;
    uint8_t in[2 + MAX_PKT];
    uint8_t *out;
    size_t out_len, out_cap;
};

/* ЗАПРОС НАВЕРХ ПО TCP — для вопроса, пришедшего по TCP. Почему не по UDP с повтором по TC=1:
 * по TCP клиент спрашивает в основном потому, что уже получил по UDP усечённый ответ, и тот же
 * вопрос наверх по UDP почти наверняка вернул бы TC снова — лишний круг перед тем же TCP. Ответ
 * по TCP бывает до 64 КБ, и ему незачем проходить через буфер датаграммы. Сервер видит тот же
 * протокол, что видел бы без нас: не умеет он TCP — клиент получил бы отказ и напрямую, и наш
 * SERVFAIL передаёт ровно это. И в режиме origdst, где наверху сервер чужой сети, рукопожатие
 * TCP само закрывает подделку ответа со стороны — то, что для UDP закрывают случайные номер и
 * порт.
 *
 * Соединение наверх — одно на запрос: так спрашивает и обычный клиент (DnsResolver открывает TCP
 * на вопрос), серверы наверху в режиме origdst разные, а держать постоянные соединения ради
 * редкого TCP — сложность без выигрыша. Срок — срок ожидания (PENDING_TTL_SEC): протухшее
 * ожидание закрывает соединение, и клиенту уходит SERVFAIL, а не тишина — по TCP он ждал бы
 * своего таймаута с занятым соединением. */
struct tcpu {
    int fd;                         /* -1 — место свободно */
    int slot;                       /* ожидание в g_pending */
    int conn;                       /* соединение клиента и его поколение */
    uint32_t conn_gen;
    uint16_t tag;                   /* номер транзакции, с которым вопрос ушёл наверх */
    uint16_t cli_id;                /* номер клиента — для SERVFAIL */
    size_t qend;                    /* конец вопроса в q + 2 (0 — не разобрался) */
    int connected;
    uint8_t *q;                     /* вопрос с двумя байтами длины */
    size_t qlen, qoff;              /* сколько отправлять и сколько ушло */
    uint8_t hdr[2];                 /* длина ответа */
    uint8_t *r;                     /* ответ */
    size_t rlen, rgot;              /* rgot считает и два байта длины */
};

static int g_tcp_lfd = -1;
static int g_tcp_paused;            /* слушающий сокет снят с epoll: мест нет (см. «ЛИМИТЫ») */
static struct tcpc g_tcpc[TCP_MAX_CONN];
static struct tcpu g_tcpu[TCP_MAX_UP];
/* Куда отвечать, когда соединение клиента уже закрыто: ответ сверху всё равно доводится до
 * карты и наборов (они нужны и следующему вопросу), а tcpc_reply на закрытом месте молчит. */
static struct tcpc g_tcp_dead = { .fd = -1 };

static void tcpc_set_ev(struct tcpc *c) {
    uint32_t want = (c->eof ? 0u : (uint32_t)EPOLLIN) | (c->out_len ? (uint32_t)EPOLLOUT : 0u);
    if (want == c->ev) return;
    struct epoll_event ev = {0};
    ev.events = want;
    ev.data.ptr = c;
    epoll_ctl(g_epfd, EPOLL_CTL_MOD, c->fd, &ev);
    c->ev = want;
}

static void tcp_listen_pause(int pause) {
    if (g_tcp_lfd < 0 || g_tcp_paused == pause) return;
    struct epoll_event ev = {0};
    ev.events = pause ? 0u : (uint32_t)EPOLLIN;
    ev.data.ptr = &g_tcp_lfd;
    if (epoll_ctl(g_epfd, EPOLL_CTL_MOD, g_tcp_lfd, &ev) == 0) g_tcp_paused = pause;
}

static void tcpc_close(struct tcpc *c) {
    if (c->fd < 0) return;
    tcp_listen_pause(0);                /* место освободилось — принимать снова */
    epoll_ctl(g_epfd, EPOLL_CTL_DEL, c->fd, NULL);
    close(c->fd);
    c->fd = -1;
    free(c->out);
    c->out = NULL;
    c->out_len = c->out_cap = 0;
    c->in_len = 0;
    c->inflight = 0;
    c->eof = 0;
}

static void tcpc_maybe_close(struct tcpc *c) {
    if (c->fd >= 0 && c->eof && !c->inflight && !c->out_len) tcpc_close(c);
}

/* Положить байты в очередь записи. Сверх TCP_OUT_MAX — соединение закрывается: клиент не
 * читает, и копить для него дальше значит отдать ему память процесса. */
static int tcpc_queue(struct tcpc *c, const uint8_t *b, size_t n) {
    if (c->out_len + n > TCP_OUT_MAX) { tcpc_close(c); return -1; }
    if (c->out_len + n > c->out_cap) {
        size_t cap = c->out_cap ? c->out_cap : 1024;
        while (cap < c->out_len + n) cap *= 2;
        uint8_t *nb = realloc(c->out, cap);
        if (!nb) { tcpc_close(c); return -1; }
        c->out = nb;
        c->out_cap = cap;
    }
    memcpy(c->out + c->out_len, b, n);
    c->out_len += n;
    return 0;
}

/* Ответ клиенту TCP: два байта длины и сообщение. Сначала — сразу в сокет; что не влезло
 * (клиент читает медленно) — в очередь, и дописывается по EPOLLOUT. Вне очереди писать нельзя:
 * ответы в потоке обязаны идти целиком, один за другим. */
static void tcpc_reply(struct tcpc *c, const void *b, size_t n) {
    if (c->fd < 0 || n > 65535) return;
    uint8_t hdr[2] = { (uint8_t)(n >> 8), (uint8_t)n };
    size_t done = 0;
    if (!c->out_len) {
        struct iovec iov[2] = { { hdr, 2 }, { (void *)b, n } };
        struct msghdr mh;
        memset(&mh, 0, sizeof(mh));
        mh.msg_iov = iov;
        mh.msg_iovlen = 2;
        ssize_t w = sendmsg(c->fd, &mh, MSG_NOSIGNAL | MSG_DONTWAIT);
        if (w < 0) {
            if (errno != EAGAIN && errno != EWOULDBLOCK && errno != EINTR) { tcpc_close(c); return; }
            w = 0;
        }
        done = (size_t)w;
        if (done) c->last = time(NULL);
        if (done == n + 2) return;
    }
    if (done < 2 && tcpc_queue(c, hdr + done, 2 - done) != 0) return;
    size_t boff = done > 2 ? done - 2 : 0;
    if (tcpc_queue(c, (const uint8_t *)b + boff, n - boff) != 0) return;
    tcpc_set_ev(c);
}

static void tcpc_flush(struct tcpc *c) {
    while (c->out_len) {
        ssize_t w = send(c->fd, c->out, c->out_len, MSG_NOSIGNAL | MSG_DONTWAIT);
        if (w < 0) {
            if (errno == EAGAIN || errno == EWOULDBLOCK || errno == EINTR) break;
            tcpc_close(c);
            return;
        }
        memmove(c->out, c->out + w, c->out_len - (size_t)w);
        c->out_len -= (size_t)w;
        c->last = time(NULL);
    }
    tcpc_set_ev(c);
}

/* Дочитать, что пришло, и отдать каждый целый запрос в dns_query. Не больше нескольких чтений
 * за событие: epoll уровневый и вернётся сам, а один болтливый клиент не должен заслонять
 * остальные события витка. */
static void tcpc_read(struct tcpc *c) {
    for (int k = 0; k < 8 && c->fd >= 0 && !c->eof; k++) {
        ssize_t r = recv(c->fd, c->in + c->in_len, sizeof(c->in) - c->in_len, MSG_DONTWAIT);
        if (r < 0) {
            if (errno == EAGAIN || errno == EWOULDBLOCK || errno == EINTR) return;
            tcpc_close(c);
            return;
        }
        if (r == 0) {                   /* клиент дописал своё: ответить на начатое и закрыть */
            c->eof = 1;
            tcpc_set_ev(c);
            return;
        }
        c->in_len += (size_t)r;
        size_t off = 0;
        while (c->fd >= 0 && c->in_len - off >= 2) {
            size_t mlen = ((size_t)c->in[off] << 8) | c->in[off + 1];
            if (mlen < 12 || mlen > MAX_PKT) { tcpc_close(c); return; }
            if (c->in_len - off < 2 + mlen) break;
            uint8_t *msg = c->in + off + 2;
            off += 2 + mlen;
            c->last = time(NULL);
            /* Сообщение обрабатывается прямо в буфере: dns_query переписывает в нём только
             * номер транзакции, а байты эти уже прочитаны. Буфер статический, и закрытие
             * соединения посреди обработки (очередь записи переполнилась) его не освобождает. */
            g_tcp_cur = c;
            dns_query(msg, (ssize_t)mlen, c->peer, c->peer_len, c->local, c->have_local);
            g_tcp_cur = NULL;
        }
        if (c->fd < 0) return;
        memmove(c->in, c->in + off, c->in_len - off);
        c->in_len -= off;
    }
}

/* SERVFAIL клиенту — из заголовка и вопроса его же запроса. Вопрос не разобрался — только
 * заголовок, без секции вопроса. */
static void tcp_servfail(struct tcpc *c, const uint8_t *q, size_t qend, uint16_t cli_id) {
    if (!c || c->fd < 0) return;
    uint8_t out[512];
    size_t use = (qend >= 12 && qend <= sizeof(out)) ? qend : 12;
    size_t len = build_rewritten_response(q, use, out, sizeof(out), 0, 0);
    if (!len) return;
    if (use == 12) { out[4] = 0; out[5] = 0; }
    out[0] = (uint8_t)(cli_id >> 8);
    out[1] = (uint8_t)cli_id;
    out[3] = (uint8_t)((out[3] & 0xf0) | 0x02);     /* RCODE 2 — SERVFAIL */
    tcpc_reply(c, out, len);
}

static struct tcpc *tcpu_conn(const struct tcpu *u) {
    struct tcpc *c = &g_tcpc[u->conn];
    return (c->fd >= 0 && c->gen == u->conn_gen) ? c : &g_tcp_dead;
}

static void tcpu_close(struct tcpu *u) {
    if (u->fd < 0) return;
    epoll_ctl(g_epfd, EPOLL_CTL_DEL, u->fd, NULL);
    close(u->fd);
    u->fd = -1;
    free(u->q);
    free(u->r);
    u->q = u->r = NULL;
    struct tcpc *c = tcpu_conn(u);
    if (c->fd >= 0) {
        if (c->inflight > 0) c->inflight--;
        tcpc_maybe_close(c);
    }
}

/* Ожидание ещё наше? Протухшее (pending_reap) или отданное другому вопросу — уже нет. */
static struct pending *tcpu_pending(const struct tcpu *u) {
    struct pending *p = &g_pending[u->slot];
    return (p->in_use && p->tcp_up == (int)(u - g_tcpu)) ? p : NULL;
}

/* Наверх не вышло (не соединился, оборвал, ответил не то) — SERVFAIL клиенту и конец. */
static void tcpu_fail(struct tcpu *u) {
    struct pending *p = tcpu_pending(u);
    if (p) p->in_use = 0;
    tcp_servfail(tcpu_conn(u), u->q + 2, u->qend, u->cli_id);
    tcpu_close(u);
}

static int tcpu_open(struct pending *p, const uint8_t *q, size_t n, const union dnsd_sa *up,
                     uint16_t tag, size_t qend, uint32_t ctmark, int have_mark) {
    struct tcpc *c = g_tcp_cur;
    struct tcpu *u = NULL;
    for (int i = 0; i < TCP_MAX_UP; i++)
        if (g_tcpu[i].fd < 0) { u = &g_tcpu[i]; break; }
    int fd = -1;
    const char *why = "все соединения наверх заняты";
    if (u) {
        fd = socket(up->sa.sa_family, SOCK_STREAM | SOCK_NONBLOCK | SOCK_CLOEXEC, 0);
        why = "сокет не открылся";
    }
    uint8_t *fq = fd >= 0 ? malloc(n + 2) : NULL;
    if (fd >= 0 && !fq) why = "нет памяти";
    if (fd >= 0 && fq) {
#ifdef STEER_ANDROID
        /* Та же метка, что у переспроса по UDP (up_mark_for): поля netd исходного соединения —
         * чтобы запрос ушёл сетью, по которой спрашивал клиент, — и «сам движок» в поле
         * движка, без которого заворот TCP/53 на output вернул бы наш же запрос к нам. Ставится
         * до connect: SYN уже идёт по маршруту этой метки. */
        unsigned mk = up_mark_for(ctmark, have_mark);
        setsockopt(fd, SOL_SOCKET, SO_MARK, &mk, sizeof(mk));
#else
        (void)ctmark; (void)have_mark;
#endif
        int one = 1;
        setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, &one, sizeof(one));
        int rc = connect(fd, &up->sa, up->sa.sa_family == AF_INET6 ? sizeof(up->v6)
                                                                     : sizeof(up->v4));
        if (rc == 0 || errno == EINPROGRESS) {
            fq[0] = (uint8_t)(n >> 8);
            fq[1] = (uint8_t)n;
            memcpy(fq + 2, q, n);
            memset(u, 0, sizeof(*u));
            u->fd = fd;
            u->slot = (int)(p - g_pending);
            u->conn = (int)(c - g_tcpc);
            u->conn_gen = c->gen;
            u->tag = tag;
            u->cli_id = p->cli_id;
            u->qend = qend;
            u->connected = rc == 0;
            u->q = fq;
            u->qlen = n + 2;
            struct epoll_event ev = {0};
            ev.events = EPOLLOUT;
            ev.data.ptr = u;
            if (epoll_ctl(g_epfd, EPOLL_CTL_ADD, fd, &ev) == 0) {
                c->inflight++;
                return (int)(u - g_tcpu);
            }
            u->fd = -1;
            u->q = NULL;
        }
        why = strerror(errno);
    }
    free(fq);
    if (fd >= 0) close(fd);
    static time_t said;
    if (warn_due(&said, time(NULL)))
        fprintf(stderr, "steer dnsd: запрос по TCP не ушёл наверх: %s — клиенту SERVFAIL\n", why);
    uint16_t cli = p->cli_id;
    tcp_servfail(c, q, qend, cli);
    return -1;
}

/* Толкнуть запрос наверх дальше: соединиться, дописать вопрос, дочитать ответ. Решение — по
 * состоянию сокета, а не по маске события: событие могло остаться от прежнего сокета на этом
 * месте, а неготовый сокет просто отвечает EAGAIN. */
static void tcpu_poke(struct tcpu *u) {
    if (u->fd < 0) return;
    struct pending *p = tcpu_pending(u);
    if (!p) { tcpu_fail(u); return; }
    if (u->qoff < u->qlen) {
        if (!u->connected) {
            int err = 0;
            socklen_t el = sizeof(err);
            if (getsockopt(u->fd, SOL_SOCKET, SO_ERROR, &err, &el) != 0 || err) {
                tcpu_fail(u);
                return;
            }
        }
        ssize_t w = send(u->fd, u->q + u->qoff, u->qlen - u->qoff, MSG_NOSIGNAL | MSG_DONTWAIT);
        if (w < 0) {
            if (errno == EAGAIN || errno == EWOULDBLOCK || errno == EINTR || errno == ENOTCONN)
                return;
            tcpu_fail(u);
            return;
        }
        u->connected = 1;
        u->qoff += (size_t)w;
        if (u->qoff < u->qlen) return;
        struct epoll_event ev = {0};
        ev.events = EPOLLIN;
        ev.data.ptr = u;
        epoll_ctl(g_epfd, EPOLL_CTL_MOD, u->fd, &ev);
        return;
    }
    for (;;) {
        uint8_t *dst;
        size_t want;
        if (u->rgot < 2) { dst = u->hdr + u->rgot; want = 2 - u->rgot; }
        else { dst = u->r + (u->rgot - 2); want = u->rlen - (u->rgot - 2); }
        ssize_t r = recv(u->fd, dst, want, MSG_DONTWAIT);
        if (r < 0 && (errno == EAGAIN || errno == EWOULDBLOCK || errno == EINTR)) return;
        if (r <= 0) { tcpu_fail(u); return; }
        u->rgot += (size_t)r;
        if (u->rgot == 2) {
            u->rlen = ((size_t)u->hdr[0] << 8) | u->hdr[1];
            if (u->rlen < 12 || !(u->r = malloc(u->rlen))) { tcpu_fail(u); return; }
        }
        if (u->rgot >= 2 && u->rgot - 2 == u->rlen) break;
    }
    /* Ответ целиком. Сверка — та же, что у датаграммы: наш номер и НАШ вопрос. Соединение
     * наше собственное, так что чужой ответ здесь — это сбой сервера, а не подделка, и клиент
     * получает SERVFAIL, а не молчание. */
    if (((u->r[0] << 8) | u->r[1]) != u->tag ||
        (p->qfp && (u->rlen < p->qsec_end || question_fp(u->r, p->qsec_end) != p->qfp))) {
        tcpu_fail(u);
        return;
    }
    g_tcp_cur = tcpu_conn(u);
    upstream_answer(p, u->r, (ssize_t)u->rlen);
    g_tcp_cur = NULL;
    tcpu_close(u);
}

/* Место под новое соединение: свободное, иначе — давно молчащее без запросов в пути и без
 * начатого запроса в буфере (см. «ЛИМИТЫ» выше); NULL — вытеснить некого. Само место не
 * освобождается: вытеснять стоит, только когда соединение и правда принято. */
static struct tcpc *tcpc_pick(void) {
    struct tcpc *old = NULL;
    time_t now = time(NULL);
    for (int i = 0; i < TCP_MAX_CONN; i++) {
        struct tcpc *c = &g_tcpc[i];
        if (c->fd < 0) return c;
        if (!c->inflight && !c->in_len && now - c->last >= 1 && (!old || c->last < old->last))
            old = c;
    }
    return old;
}

static void tcp_accept(void) {
    for (int k = 0; k < TCP_MAX_CONN; k++) {
        struct tcpc *c = tcpc_pick();
        if (!c) {
            static time_t said;
            tcp_listen_pause(1);
            if (warn_due(&said, time(NULL)))
                fprintf(stderr, "steer dnsd: соединений TCP %d, и все заняты — новые ждут в "
                                "очереди\n", TCP_MAX_CONN);
            return;
        }
        struct sockaddr_storage peer;
        socklen_t pl = sizeof(peer);
        int fd = accept(g_tcp_lfd, (struct sockaddr *)&peer, &pl);
        if (fd < 0) return;
        if (c->fd >= 0) tcpc_close(c);  /* вытеснение — теперь, когда новое точно есть */
        fcntl(fd, F_SETFL, O_NONBLOCK);
        fcntl(fd, F_SETFD, FD_CLOEXEC);
        int one = 1;
        setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, &one, sizeof(one));
        uint32_t gen = c->gen + 1;
        memset(c, 0, offsetof(struct tcpc, in));
        c->fd = fd;
        c->gen = gen;
        c->peer = peer;
        c->peer_len = pl;
        c->last = time(NULL);
        /* Адрес, к которому подключился клиент: после redirect это наш адрес (петля или адрес
         * интерфейса раздачи), и по нему вместе с адресом клиента conntrack находит исходное
         * назначение — как для датаграммы по IP_PKTINFO. */
        struct sockaddr_storage ls;
        socklen_t ll = sizeof(ls);
        if (getsockname(fd, (struct sockaddr *)&ls, &ll) == 0) {
            /* Как у датаграммы (handle_client_query): IPv4 двойного стека приходит v4-mapped и
             * хранится как v4 — в conntrack это IPv4-соединение. */
            const struct sockaddr_in6 *l6 = (const struct sockaddr_in6 *)&ls;
            if (ls.ss_family == AF_INET) {
                c->local.af = AF_INET;
                c->local.v4 = ((struct sockaddr_in *)&ls)->sin_addr;
                c->have_local = 1;
            } else if (ls.ss_family == AF_INET6 && IN6_IS_ADDR_V4MAPPED(&l6->sin6_addr)) {
                c->local.af = AF_INET;
                memcpy(&c->local.v4, &l6->sin6_addr.s6_addr[12], 4);
                c->have_local = 1;
            } else if (ls.ss_family == AF_INET6) {
                c->local.af = AF_INET6;
                c->local.v6 = l6->sin6_addr;
                c->have_local = 1;
            }
        }
        struct epoll_event ev = {0};
        ev.events = EPOLLIN;
        ev.data.ptr = c;
        if (epoll_ctl(g_epfd, EPOLL_CTL_ADD, fd, &ev) != 0) { close(fd); c->fd = -1; continue; }
        c->ev = EPOLLIN;
    }
}

static void tcpc_event(struct tcpc *c, uint32_t evs) {
    if (c->fd < 0) return;
    if (evs & (EPOLLERR | EPOLLHUP)) {
        /* Ошибка или обе стороны закрыты: дописать некому. Сверка с сокетом — на случай, если
         * событие осталось от прежнего соединения на этом месте. */
        int err = 0;
        socklen_t el = sizeof(err);
        char b;
        getsockopt(c->fd, SOL_SOCKET, SO_ERROR, &err, &el);
        if (err || ((evs & EPOLLHUP) && recv(c->fd, &b, 1, MSG_PEEK | MSG_DONTWAIT) == 0)) {
            tcpc_close(c);
            return;
        }
    }
    if (c->out_len) tcpc_flush(c);
    if (c->fd >= 0 && !c->eof) tcpc_read(c);
    tcpc_maybe_close(c);
}

/* Событие epoll, если оно TCP: 1 — обработано здесь, 0 — не наше. */
static int tcp_event(void *ptr, uint32_t evs) {
    uintptr_t a = (uintptr_t)ptr;
    if (ptr == &g_tcp_lfd) { tcp_accept(); return 1; }
    if (a >= (uintptr_t)g_tcpc && a < (uintptr_t)(g_tcpc + TCP_MAX_CONN)) {
        tcpc_event((struct tcpc *)ptr, evs);
        return 1;
    }
    if (a >= (uintptr_t)g_tcpu && a < (uintptr_t)(g_tcpu + TCP_MAX_UP)) {
        tcpu_poke((struct tcpu *)ptr);
        return 1;
    }
    return 0;
}

/* Секундный тик: запросы наверх, чьё ожидание протухло, — SERVFAIL и закрыть; соединения
 * клиентов без дела дольше TCP_IDLE_SEC — закрыть. */
static void tcp_reap(time_t now) {
    /* Место могло стать вытесняемым без закрытия (соединение отмолчало секунду) — пусть
     * следующий приём проверит заново; мест нет — tcp_accept снимет сокет снова. */
    tcp_listen_pause(0);
    for (int i = 0; i < TCP_MAX_UP; i++)
        if (g_tcpu[i].fd >= 0 && !tcpu_pending(&g_tcpu[i])) tcpu_fail(&g_tcpu[i]);
    for (int i = 0; i < TCP_MAX_CONN; i++) {
        struct tcpc *c = &g_tcpc[i];
        if (c->fd >= 0 && !c->inflight && now - c->last >= TCP_IDLE_SEC) tcpc_close(c);
    }
}

/* Слушать TCP на том же порту, что и UDP, двойным стеком так же. Не вышло — не отказ: UDP
 * работает, а запросы по TCP пройдут тем путём, каким шли до этого. */
static void tcp_listen_open(int port) {
    for (int i = 0; i < TCP_MAX_CONN; i++) g_tcpc[i].fd = -1;
    for (int i = 0; i < TCP_MAX_UP; i++) g_tcpu[i].fd = -1;
    int on = 1, off = 0;
    int fd = socket(AF_INET6, SOCK_STREAM | SOCK_NONBLOCK | SOCK_CLOEXEC, 0);
    if (fd >= 0) {
        struct sockaddr_in6 a6;
        memset(&a6, 0, sizeof(a6));
        a6.sin6_family = AF_INET6;
        a6.sin6_port = htons((uint16_t)port);
        a6.sin6_addr = in6addr_any;
        setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &on, sizeof(on));
        if (setsockopt(fd, IPPROTO_IPV6, IPV6_V6ONLY, &off, sizeof(off)) != 0 ||
            bind(fd, (struct sockaddr *)&a6, sizeof(a6)) != 0) {
            close(fd);
            fd = -1;
        }
    }
    if (fd < 0) {
        fd = socket(AF_INET, SOCK_STREAM | SOCK_NONBLOCK | SOCK_CLOEXEC, 0);
        struct sockaddr_in a4;
        memset(&a4, 0, sizeof(a4));
        a4.sin_family = AF_INET;
        a4.sin_port = htons((uint16_t)port);
        a4.sin_addr.s_addr = htonl(INADDR_ANY);
        if (fd >= 0) setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &on, sizeof(on));
        if (fd >= 0 && bind(fd, (struct sockaddr *)&a4, sizeof(a4)) != 0) { close(fd); fd = -1; }
    }
    if (fd < 0 || listen(fd, TCP_MAX_CONN) != 0) {
        fprintf(stderr, "steer dnsd: TCP на :%d не слушается (%s) — запросы по TCP пройдут "
                        "мимо доменных каналов\n", port, strerror(errno));
        if (fd >= 0) close(fd);
        return;
    }
    struct epoll_event ev = {0};
    ev.events = EPOLLIN;
    ev.data.ptr = &g_tcp_lfd;
    if (epoll_ctl(g_epfd, EPOLL_CTL_ADD, fd, &ev) != 0) { close(fd); return; }
    g_tcp_lfd = fd;
}

static void tcp_close_all(void) {
    for (int i = 0; i < TCP_MAX_UP; i++) tcpu_close(&g_tcpu[i]);
    for (int i = 0; i < TCP_MAX_CONN; i++) tcpc_close(&g_tcpc[i]);
    if (g_tcp_lfd >= 0) close(g_tcp_lfd);
    g_tcp_lfd = -1;
    g_tcp_paused = 0;
}

int run_proxy(int listen_port, int upstream_port) {
    /* Dual-stack on ONE socket (AF_INET6 with IPV6_V6ONLY off), because an
     * IPv4-only listener silently loses most of the LAN's DNS.
     *
     * OpenWrt advertises the router as an IPv6 resolver by default (odhcpd RA +
     * DHCPv6), and Windows/Android/iOS then prefer the IPv6 server. Measured on a
     * real client: 15 of its DNS packets went to the router over IPv6 against 20
     * over IPv4, and `nslookup claude.ai` answered with the REAL address via
     * fdd6:...::1 while the same query forced to 192.168.1.1 answered 198.18.0.5.
     * Both stacks get asked and the first reply wins, so the unproxied one wins
     * essentially always — domain routing appeared to do nothing at all.
     *
     * MUST bind the wildcard address, not loopback: nft's `redirect` DNATs the
     * destination to the box's own address on the inbound (LAN) interface, not to
     * 127.0.0.1 — only LAN-sourced traffic ever reaches this port because
     * splify-apply scopes the redirect rule to the LAN.
     *
     * Falls back to AF_INET if the kernel has no IPv6 at all, so a build for a
     * v4-only box keeps working exactly as before. */
    int reuse = 1;
    g_listen_fd = socket(AF_INET6, SOCK_DGRAM, 0);
    if (g_listen_fd >= 0) {
        int v6only = 0;
        setsockopt(g_listen_fd, SOL_SOCKET, SO_REUSEADDR, &reuse, sizeof(reuse));
        if (setsockopt(g_listen_fd, IPPROTO_IPV6, IPV6_V6ONLY, &v6only, sizeof(v6only)) != 0) {
            /* Can't serve IPv4 through it -> a v4 client would break. Drop back. */
            close(g_listen_fd);
            g_listen_fd = -1;
        } else {
            struct sockaddr_in6 a6 = {0};
            a6.sin6_family = AF_INET6;
            a6.sin6_port = htons((uint16_t)listen_port);
            a6.sin6_addr = in6addr_any;
            if (bind(g_listen_fd, (struct sockaddr *)&a6, sizeof(a6)) != 0) {
                close(g_listen_fd);
                g_listen_fd = -1;
            }
        }
    }
    if (g_listen_fd < 0) {
        g_listen_fd = socket(AF_INET, SOCK_DGRAM, 0);
        if (g_listen_fd < 0) { perror("socket"); return 1; }
        setsockopt(g_listen_fd, SOL_SOCKET, SO_REUSEADDR, &reuse, sizeof(reuse));
        struct sockaddr_in addr = {0};
        addr.sin_family = AF_INET;
        addr.sin_port = htons((uint16_t)listen_port);
        addr.sin_addr.s_addr = htonl(INADDR_ANY);
        if (bind(g_listen_fd, (struct sockaddr *)&addr, sizeof(addr)) != 0) {
            perror("bind");
            return 1;
        }
        fprintf(stderr, "steer dnsd: no IPv6 on this kernel — listening on IPv4 only\n");
    }
    /* Неблокирующий: цикл событий дочитывает очередь датаграмм до EAGAIN, и
     * готовность от epoll перестаёт быть обещанием, что recvfrom не повиснет. */
    fcntl(g_listen_fd, F_SETFL, O_NONBLOCK);
    g_listen_port = listen_port;
    if (g_origdst) {
        /* Адрес назначения каждой датаграммы — для поиска записи conntrack. У двойного
         * стека IPv4 приходит как v4-mapped в IPV6_PKTINFO. */
        int on = 1;
        if (setsockopt(g_listen_fd, IPPROTO_IPV6, IPV6_RECVPKTINFO, &on, sizeof(on)) != 0)
            setsockopt(g_listen_fd, IPPROTO_IP, IP_PKTINFO, &on, sizeof(on));
    }

    g_epfd = epoll_create1(0);
    if (g_epfd < 0) { perror("epoll_create1"); return 1; }
    struct epoll_event ev = {0};
    ev.events = EPOLLIN;
    ev.data.ptr = NULL; /* NULL marks the listen socket */
    epoll_ctl(g_epfd, EPOLL_CTL_ADD, g_listen_fd, &ev);
    /* И TCP на том же порту — см. «DNS по TCP» выше. */
    tcp_listen_open(listen_port);
    /* Сокет журнала имён — см. «журнал имён» выше. */
    dlog_listen();

    /* Один сокет наверх на весь процесс — см. комментарий у struct pending. Открывается
     * здесь, а не при первом запросе, чтобы отказ был виден сразу, а не превращался в
     * «DNS иногда не работает». Неблокирующий, как и слушающий: готовность epoll не
     * гарантирует, что recv не заблокируется, а блокировка стоит всего цикла. */
    g_up_fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (g_up_fd < 0) { perror("upstream socket"); return 1; }
    struct sockaddr_in up = {0};
    up.sin_family = AF_INET;
    g_up_port = upstream_port;
    up.sin_port = htons((uint16_t)upstream_port);
    up.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
#ifdef STEER_ANDROID
    /* Собственный запрос наверх помечен значением «сам движок» (STEER_SELF_MARK в spec.h):
     * заворот DNS на output берёт всех, включая root, — DnsResolver шлёт запросы приложений от
     * root, — и без метки наш же запрос к серверу сети завернулся бы обратно к нам. */
    {
        unsigned mk = STEER_SELF_MARK;
        if (setsockopt(g_up_fd, SOL_SOCKET, SO_MARK, &mk, sizeof(mk)) != 0)
            fprintf(stderr, "steer[warn] dnsd: SO_MARK на сокете наверх не встал (%s) — "
                            "запросы наверх завернутся к резолверу по кругу\n", strerror(errno));
    }
#endif
    /* В режиме origdst серверы наверху разные — сокет не connect'нут (см. g_origdst). */
    if (!g_origdst && connect(g_up_fd, (struct sockaddr *)&up, sizeof(up)) != 0) {
        perror("upstream connect");
        return 1;
    }
    fcntl(g_up_fd, F_SETFL, O_NONBLOCK);
    struct epoll_event uev = {0};
    uev.events = EPOLLIN;
    uev.data.ptr = &g_up_fd;            /* не NULL — значит это ответ сверху */
    epoll_ctl(g_epfd, EPOLL_CTL_ADD, g_up_fd, &uev);
    /* Пул сокетов наверх на случайных портах — только в режиме origdst (см. g_up_pool).
     * bind на порт 0: ядро выдаёт эфемерный порт случайно. */
    for (int i = 0; i < UP_POOL; i++) g_up_pool[i] = g_up_pool6[i] = -1;
    g_up_pool6_n = 0;
    memset(g_txmap, 0xff, sizeof(g_txmap));
    if (g_origdst) {
        for (int i = 0; i < UP_POOL; i++) {
            int fd = socket(AF_INET, SOCK_DGRAM | SOCK_NONBLOCK | SOCK_CLOEXEC, 0);
            if (fd < 0) continue;
            struct sockaddr_in any = { .sin_family = AF_INET };
            if (bind(fd, (struct sockaddr *)&any, sizeof(any)) != 0) { close(fd); continue; }
#ifdef STEER_ANDROID
            unsigned mk = STEER_SELF_MARK;
            setsockopt(fd, SOL_SOCKET, SO_MARK, &mk, sizeof(mk));
            g_up_mark[i] = mk;
#endif
            g_up_pool[i] = fd;
            struct epoll_event pev = {0};
            pev.events = EPOLLIN;
            pev.data.ptr = &g_up_pool[i];
            epoll_ctl(g_epfd, EPOLL_CTL_ADD, fd, &pev);
        }
        /* Пул AF_INET6 — для запросов по IPv6 (см. g_origdst). Только IPv6 (V6ONLY): IPv4
         * ходит своим пулом. Не открылся ни один — IPv6-запросы уходят на петлю. */
        for (int i = 0; i < UP_POOL; i++) {
            int fd = socket(AF_INET6, SOCK_DGRAM | SOCK_NONBLOCK | SOCK_CLOEXEC, 0);
            if (fd < 0) break;
            int on = 1;
            setsockopt(fd, IPPROTO_IPV6, IPV6_V6ONLY, &on, sizeof(on));
            struct sockaddr_in6 any6 = { .sin6_family = AF_INET6 };
            if (bind(fd, (struct sockaddr *)&any6, sizeof(any6)) != 0) { close(fd); break; }
            int k = g_up_pool6_n++;
#ifdef STEER_ANDROID
            unsigned mk = STEER_SELF_MARK;
            setsockopt(fd, SOL_SOCKET, SO_MARK, &mk, sizeof(mk));
            g_up_mark6[k] = mk;
#endif
            g_up_pool6[k] = fd;
            struct epoll_event pev = {0};
            pev.events = EPOLLIN;
            pev.data.ptr = &g_up_pool6[k];
            epoll_ctl(g_epfd, EPOLL_CTL_ADD, fd, &pev);
        }
    }

    signal(SIGHUP, on_sighup);
    signal(SIGTERM, on_sigterm);
    signal(SIGINT, on_sigterm);
    signal(SIGPIPE, SIG_IGN);

    /* Open the long-lived nfnetlink socket BEFORE we load state, so the
     * rehydrate pass below can re-install the DNAT map synchronously. A
     * failure here is not fatal: we still proxy DNS, we just can't install
     * fake-IP mappings — every matched domain then relays its real answer
     * (fail-open), exactly as if the rules never matched. */
    int nk_open = nftlk_open();

    reload_rules();
    if (g_fakeip_state_path) fakeip_state_load(g_fakeip_state_path);

    /* Rehydrate the DNAT map AND the channel sets after a (re)start. fw4 reload /
     * a daemon restart wipes the live splify_fakeip_map contents AND the fake-IP
     * elements in each channel set (the schema is reinstalled by splify-apply,
     * but the elements are gone). For every domain we already know a real backend
     * for (from the extended 3-field state), re-insert fake->real now, so clients
     * don't have to re-resolve to un-wedge an existing fake IP.
     *
     * The channel set is re-installed for EVERY domain we have (real backend
     * known or not): the route must match for the whole lifetime of the
     * allocation, and waiting for a re-resolve after a restart would reopen the
     * same window the permanent element exists to close. The channel is
     * re-derived here by matching the stored domain against the freshly loaded
     * rules — reload_rules() above already built them. Best-effort throughout: a
     * failed insert just leaves that domain to be re-resolved on demand. */
    size_t routed = 0;
    size_t restored = fakeip_rehydrate(nk_open, &routed);
    char upd[64];
    if (g_origdst) snprintf(upd, sizeof(upd), "original destination (else 127.0.0.1:%d)",
                            upstream_port);
    else snprintf(upd, sizeof(upd), "127.0.0.1:%d", upstream_port);
    fprintf(stderr, "steer dnsd: listening on :%d -> upstream %s "
            "(netlink:%s fakeip:%zu loaded, %zu map rehydrated, %zu routes restored)\n",
            listen_port, upd, nk_open == 0 ? "ok" : "FAILED",
            g_fakeip.n, restored, routed);

    struct epoll_event events[32];
    time_t last_reap = 0;
    while (g_running) {
        if (g_reload_pending) { g_reload_pending = 0; reload_rules(); }
        time_t now = time(NULL);
        if (now != last_reap) {
            /* Секундный тик: снять протухшие ожидания (см. pending_reap). */
            pending_reap(now);
            tcp_reap(now);
            last_reap = now;
        }
        if (g_fakeip_dirty) {
            /* Перезапись — O(таблица) и с fsync, то есть настоящая запись на
             * носитель. Раз в TTL ответа достаточно: файл — best-effort
             * подсказка для rehydrate после рестарта, и потерять последние
             * секунды изменений при жёстком отключении не страшно (домен
             * просто ре-резолвится), а вот молотить носитель на каждый переезд
             * backend'а под живым трафиком — страшно вполне. */
            if (now - g_fakeip_last_rewrite >= FAKEIP_ANSWER_TTL) {
                fakeip_state_rewrite();
                g_fakeip_dirty = 0;
                g_fakeip_last_rewrite = now;
            }
        }
        int n = epoll_wait(g_epfd, events, 32, 1000);
        if (n < 0) {
            if (errno == EINTR) continue;
            break;
        }
        for (int i = 0; i < n; i++) {
            if (events[i].data.ptr == NULL) {
                /* Дочитать очередь до конца (сокет неблокирующий), но не более
                 * пачки: один разговорчивый клиент не должен заслонять ответы
                 * upstream, которые ждут в этом же массиве событий. */
                for (int k = 0; k < 64; k++)
                    if (!handle_client_query()) break;
            } else if (events[i].data.ptr == &g_dlog_fd) {
                dlog_serve();
            } else if (tcp_event(events[i].data.ptr, events[i].events)) {
                /* соединение TCP — клиента или наверх; всё сделано внутри */
            } else {
                /* Ответы всех ожиданий приходят на один сокет, поэтому очередь тоже
                 * дочитывается до конца пачкой — иначе на всплеске за один виток цикла
                 * забирался бы ровно один ответ. */
                int ufd = *(int *)events[i].data.ptr;
                for (int k = 0; k < 64; k++)
                    if (!handle_upstream_response(ufd)) break;
            }
        }
    }

    tcp_close_all();
    dlog_close();
    if (g_nlk_fd >= 0) close(g_nlk_fd);
    if (g_up_fd >= 0) close(g_up_fd);
    close(g_listen_fd);
    close(g_epfd);
    for (size_t i = 0; i < g_dch_n; i++) ruleset_free(&g_dch[i].rules);
    return 0;
}
