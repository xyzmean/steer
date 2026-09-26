/* Управляющий сокет движка: демон `steer daemon` (он же `steer ctl-serve` — прежнее имя, под
 * которым его запускает сервис телефона) и `steer ctl` (клиент для отладки).
 *
 * ЗАЧЕМ. На роутере управляющий слой splify2 зовёт движок как программу: rpcd исполняет
 * `steer status`, кладёт спеку в /etc/steer и зовёт `steer apply`. На телефоне так нельзя.
 * Приложение splify2 живёт в домене splify2_app (vendor/der/sepolicy), и политика нарочно не
 * даёт ему ни исполнить движок, ни прочитать его файлы: движок невидим для всех приложений, и
 * исключение для одного из них — это одна дверь, а не ключи от всего дома. Эта дверь —
 * unix-сокет с меткой steerd_socket, к которому SELinux пускает только splify2_app. За дверью
 * сидит этот сервер и делает от имени приложения ровно то, что перечислено в таблице команд
 * ниже, — и ничего сверх.
 *
 * ПРОТОКОЛ (версия 1; то же самое для автора моста в приложении — в docs/ctl.md).
 *
 *   Одно соединение — один запрос и один ответ, затем сервер закрывает соединение.
 *   Исключение одно — subscribe: после ответа соединение остаётся открытым, и демон пишет в
 *   него события, строка JSON на событие ({"v":1,"ev":"applied",…}). Это расширение версии 1,
 *   а не новая версия: прежние команды и их ответы не изменились ни в одном байте.
 *
 *   Запрос — строка ASCII до 512 байт с '\n' в конце: имя команды и её слова через ОДИН
 *   пробел. У команд с телом (apply, check, put-file) последнее слово — длина тела в байтах
 *   десятичным числом, и сразу за '\n' идёт ровно столько байт тела:
 *       status\n
 *       explain youtube.com\n
 *       apply 1834\n{"schema":2,...}
 *       put-file yt.lst 52311\n<байты списка>
 *   Тело спеки — не больше 1 МиБ, файла списка — 16 МиБ. На весь запрос, строку и тело, — пять
 *   секунд.
 *
 *   Ответ — один объект JSON в одну строку с '\n' в конце:
 *       {"v":1,"cmd":"status","code":0,"stdout":"...","stderr":"..."}
 *   code — код возврата одноимённой подкоманды движка (0 — успех), stdout и stderr — её вывод
 *   строками (у status и diag stdout — сам JSON, его разбирают второй раз). stdout
 *   обрезается на 1 МиБ, stderr на 64 КиБ; обрезанное помечается "truncated":true.
 *   Отказ самого сервера — без code, с полем error и человеческим message:
 *       {"v":1,"error":"denied","message":"..."}
 *   Значения error: bad-request, too-large, unknown-command, denied, busy, internal, timeout
 *   (у timeout code есть: команда шла и была убита, её вывод до этого момента приложен) и
 *   in-use (rm-file файла, на который ссылается сохранённая спека).
 *   Команды apply, reload и файлов списков добавляют свои поля — см. их обработчики и
 *   docs/ctl.md.
 *
 * ПОЧЕМУ СТРОКА И ДЛИНА, а не JSON в запросе. Запрос короткий и его слова всё равно идут в
 * argv подкоманды — разбирать ради них JSON в движке значило бы завести второй разборщик
 * рядом со спекой ради двух слов. Длина тела объявляется ЗАРАНЕЕ, а не «читать до закрытия»:
 * так слишком большое тело отвергается до того, как прочитан первый его байт, а у клиента
 * не требуется полузакрытия сокета (у LocalSocket Android оно есть, но лишнее условие
 * совместимости — лишний способ сломаться).
 *
 * ИСПОЛНЕНИЕ. Демон — один процесс с одним циклом событий (loop.h): слушающий сокет,
 * соединения, трубы детей, сигналы и таймеры — всё в одном epoll, и без событий он спит без
 * срока. Команды делятся на два рода.
 *
 *   В процессе, из памяти: version, status, explain, conns, dns-log и файлы списков. Спеку и
 *   группы демон держит в памяти (state.h) — прочитанными при старте и перечитанными после
 *   apply и reload, — поэтому status и explain не читают спеку на каждый вызов и не платят
 *   запуском движка. Ответ при этом ровно тот же, что у подкоманды: его печатает тот же код
 *   (status_answer, explain_emit, ctnl_conns_print, dlog_print) — в поток в памяти, а не в
 *   stdout, — а stderr на время команды перенаправлен в файл в памяти. Одна правда на двоих,
 *   как и прежде, только без второго процесса.
 *
 *   Через ребёнка: apply и reload (план и применение изменившихся частей — apply-сверка,
 *   recon.c; у reload ещё dnsd-sig), check, diag, vless-probe, vless-nodes, sub-check — работа
 *   ядра, компиляция или долгий срок. Ребёнок — fork+exec самого себя с подкомандой, в
 *   своей группе процессов; его stdout и stderr — неблокирующие трубы в том же epoll, выход —
 *   через signalfd, срок — таймером цикла. Пока ребёнок работает, демон отвечает остальным:
 *   долгий vless-probe больше не держит status. Сбой в ребёнке (die, зависание на nft) по-
 *   прежнему задевает только его.
 *
 *   Изменяющие команды (apply, check, reload, rm-file) идут по одной: следующая ждёт в очереди
 *   демона, пока не кончится предыдущая. Раньше это делал flock на ctl.lock между процессами-
 *   обработчиками; теперь обработчик один, и очередь — его собственная.
 *
 *   С --watch в том же цикле живёт сторож выходов (watchd.c): таймер периода, события netlink и
 *   сам проход — автоматом на этом же цикле, без ребёнка. Пока идёт изменяющая команда, проход
 *   откладывается.
 *
 *   С --supervise там же живут дети демона (supd.c): помощники выходов с трубами событий и
 *   резолвер на таблице. reload и apply тогда не ищут резолвер и супервизор по /proc и не шлют
 *   им сигналов: демон сам сверяет помощников и пишет резолверу новую таблицу, перечитав спеку.
 *
 *   SIGTERM гасит всех детей демона: помощников и резолвер (supd_stop), проход сторожа и детей
 *   команд, которые ещё идут (их группы процессов — SIGTERM, по сроку SIGKILL), — демон не
 *   оставляет после себя процессов без присмотра.
 *
 * КОГО ПУСКАТЬ. Первый замок — SELinux: connectto к steerd разрешён splify2_app, и кроме него
 * к сокету может прийти разве что root (su на userdebug) и init. Второй замок — здесь, по
 * SO_PEERCRED и SO_PEERSEC: uid 0 (root) и 1000 (system) — да; процесс в домене splify2_app
 * — да, если он у владельца устройства (пользователь 0); прочие uid — только названные
 * флагом --allow-uid (стенд, отладка). UID приложения нигде не записан и не угадывается:
 * он назначается при установке и у каждого телефона свой, а читать /data/system/packages.list
 * значило бы дать движку ещё одно право. Вместо этого спрашивается ядро — какой у собеседника
 * контекст SELinux, — и ответ «splify2_app» дан той же привязкой в seapp_contexts (имя пакета
 * плюс платформенная подпись), на которой держится весь запрет. Подменить его приложению с
 * тем же именем пакета, но чужой подписью нельзя: seinfo считается по сертификату.
 * Почему только пользователь 0: движок меняет маршрутизацию ВСЕГО устройства, а гостевой
 * пользователь или рабочий профиль — не тот, кто ею распоряжается; Android по той же логике
 * не даёт вторичным пользователям настройки сети устройства.
 *
 * ПРЕДЕЛЫ. Не больше четырёх запросов одновременно (пятому — busy сразу, не очередь: очередь
 * держала бы соединения открытыми на неопределённое время); подписчиков — не больше восьми, и
 * они в четыре запроса не входят. Строка 512 байт, тело 1 МиБ (файл списка — 16 МиБ); пять
 * секунд на запрос; у каждой команды через ребёнка свой срок, по истечении — SIGKILL всей
 * группе процессов команды (nft и ip, которых она запустила, тоже). Медленный или молчащий
 * клиент демон не держит: чтение и запись неблокирующие, со сроками, а очередь событий
 * подписчика ограничена — не успевающего читать демон отключает.
 *
 * БАТАРЕЯ. Демон спит в epoll_wait без срока: таймеры цикла взводятся только на время
 * запроса, ребёнка или отложенного закрытия и снимаются вместе с ними. Проснуться его может
 * только соединение, вывод ребёнка, сигнал или такой таймер. Стенд tests/ctlmatch.sh меряет
 * это числом добровольных переключений контекста в тишине.
 *
 * ГДЕ СОКЕТ. /data/misc/steer/steer.sock, создаёт его сам сервер. Почему не опция `socket` у
 * init (сокет в /dev/socket, как у netd): каталог /dev/socket может листать любой домен
 * (system/sepolicy, domain.te: `allow domain socket_device:dir r_dir_perms`), то есть имя
 * steerd увидело бы любое приложение простым `ls` — а требование владельца в том, чтобы
 * движка для приложений не было видно. Каталог /data/misc/steer со своим типом приложениям
 * не листается; метку steerd_socket сокету ставит type_transition по имени файла (см.
 * vendor/der/sepolicy/private/steerd.te). Цена своего сокета — убрать прежний файл при
 * старте: сервер сначала пробует к нему подключиться (живой соседний сервер — отказ стартовать),
 * и только мёртвый файл удаляет. */
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>
#include <stdint.h>
#include <errno.h>
#include <unistd.h>
#include <fcntl.h>
#include <signal.h>
#include <time.h>
#include <dirent.h>
#include <limits.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <sys/epoll.h>
#include <sys/syscall.h>
#ifdef __BIONIC__
#include <sys/system_properties.h>
#endif

#include "platform.h"
#include "spec.h"
#include "groups.h"
#include "cli.h"
#include "daemon.h"
#include "loop.h"
#include "state.h"
#include "fostate.h"
#include "watchd.h"
#include "helpers.h"
#include "recon.h"
#include "ctl.h"

/* Путь сокета по умолчанию — путь платформы (ctl_sock, src/platform/platform.h). */
/* Выключатель движка — то же свойство, за которым следит init (vendor/der/init/steerd.rc). */
#define STEER_CTL_PROP "persist.der.steer.enabled"

#define CTL_LINE_MAX    512
#define CTL_BODY_MAX    (1024 * 1024)
/* ФАЙЛЫ СПИСКОВ (put-file) — свой предел тела, в шестнадцать раз больше спеки. Спека — это
 * настройки человека, и мегабайта ей хватает с многократным запасом; списки же бывают
 * по несколько мегабайт (антизапретный список подсетей, крупные доменные списки издателя
 * в текстовом виде), и общий предел в 1 МиБ отрезал бы ровно те файлы, ради которых команда
 * заведена. Предел остаётся: тело читается в память демона целиком (так оно проверяется
 * по объявленной длине до записи на диск), и без него один запрос мог бы попросить у
 * телефона сколько угодно памяти. 16 МиБ — с запасом больше самого крупного списка каталога
 * splify2-lists и всё ещё мелочь для памяти телефона на время одного запроса.
 *
 * К пределу одного файла — пределы каталога: не больше 256 файлов и 128 МиБ всего. Каталог
 * лежит в /data, и приложение, которое заливает и забывает убирать (ошибка в его логике), не
 * должно понемногу съедать память телефона: упереться в предел и получить отказ лучше, чем
 * узнать о переполнении /data по отказу всех приложений сразу. */
#define CTL_FILE_MAX    (16 * 1024 * 1024)
#define CTL_FILES_MAX   256
#define CTL_FILES_TOTAL (128LL * 1024 * 1024)
#define CTL_FNAME_MAX   64
#define CTL_OUT_MAX     (1024 * 1024)
#define CTL_ERR_MAX     (64 * 1024)
#define CTL_CLIENTS_MAX 4
#define CTL_REQ_MS      5000
/* Сколько ждать, пока клиент заберёт ответ (раньше — SO_SNDTIMEO обработчика), и сколько
 * дочитывать непрочитанный остаток запроса после ответа (см. conn_drain). */
#define CTL_SEND_MS     5000
#define CTL_DRAIN_MS    1000
/* ПОДПИСЧИКИ. Восемь — с запасом на приложение (экран и фоновая служба) и отладку из adb;
 * больше незачем, а каждый — открытый дескриптор и очередь в памяти демона.
 *
 * Очередь событий подписчика — 32 КиБ поверх буфера сокета (его демон уменьшает до 16 КиБ,
 * чтобы очередь, которую он видит, и была той, что ограничена). Событие — сотня байт, и
 * событий в минуту единицы: подписчик, отставший на три сотни событий, не читает вовсе, и
 * держать для него память дальше значило бы дать одному зависшему клиенту расти в демоне без
 * предела. Переполнение — отключить: подписчик переподключится и спросит status заново, это
 * честнее, чем тихо выбрасывать события из середины потока. */
#define CTL_SUBS_MAX    8
#define CTL_SUBQ_MAX    (32 * 1024)
#define CTL_SUB_SNDBUF  (16 * 1024)
#define CTL_ALLOW_UIDS  8
#define CTL_AID_SYSTEM  1000
#define CTL_USER_RANGE  100000   /* AID_USER_OFFSET: uid = пользователь * 100000 + приложение */

/* daemon.h заводит LOG_W с меткой apply; у сокета своя метка. */
#undef LOG_W
#define LOG_W "steer[warn] ctl: "
#define LOG_I "steer[info] ctl: "

struct ctl_conf {
    const char *sock;
    const char *spec;
    const char *state_dir;       /* NULL — умолчание движка, флаг подкомандам не передаётся */
    const char *lists_dir;       /* куда put-file кладёт файлы (lists_dir платформы, --lists-dir) */
    const char *allow_domain;    /* NULL или "" — по домену не пускать */
    uid_t allow_uid[CTL_ALLOW_UIDS];
    int allow_uid_n;
    int watch;                   /* --watch: демон — сторож выходов (watchd.c) */
    int watch_period;            /* --watch-period, секунд */
    int supervise;               /* --supervise: помощники и резолвер — дети демона (supd.c) */
    int apply;                   /* --apply: применить спеку при старте (как reload) */
    const char *dnsd_flags[9];   /* --dnsd-flag: лишние флаги резолверу-ребёнку, NULL в конце */
    int dnsd_flag_n;
    char exe[PATH_MAX];
};

/* ---- буфер ---------------------------------------------------------------------------- */

struct cbuf {
    char *p;
    size_t n, cap;
    size_t max;      /* 0 — без предела */
    int trunc;
};

static void cb_put(struct cbuf *b, const void *s, size_t n) {
    if (b->max && b->n + n > b->max) {
        n = b->max > b->n ? b->max - b->n : 0;
        b->trunc = 1;
    }
    if (b->n + n + 1 > b->cap) {
        size_t c = b->cap ? b->cap : 1024;
        while (c < b->n + n + 1) c *= 2;
        char *q = realloc(b->p, c);
        if (!q) { b->trunc = 1; return; }
        b->p = q;
        b->cap = c;
    }
    if (n) memcpy(b->p + b->n, s, n);
    b->n += n;
    b->p[b->n] = '\0';
}

static void cb_str(struct cbuf *b, const char *s) { cb_put(b, s, strlen(s)); }

static void cb_fmt(struct cbuf *b, const char *fmt, ...) {
    char t[1024];
    va_list ap;
    va_start(ap, fmt);
    int k = vsnprintf(t, sizeof(t), fmt, ap);
    va_end(ap);
    if (k > 0) cb_put(b, t, (size_t)k < sizeof(t) ? (size_t)k : sizeof(t) - 1);
}

/* Обрезанный на пределе вывод может кончиться посреди символа UTF-8 (движок пишет
 * по-русски), и такой хвост разборщик приложения заменил бы мусором. Срезаем недописанный
 * символ целиком. */
static void cb_utf8_trim(struct cbuf *b) {
    if (!b->trunc || !b->n) return;
    size_t i = b->n, k = 0;
    while (i > 0 && k < 4 && ((unsigned char)b->p[i - 1] & 0xC0) == 0x80) { i--; k++; }
    if (i == 0) return;
    unsigned char lead = (unsigned char)b->p[i - 1];
    size_t need = lead >= 0xF0 ? 3 : lead >= 0xE0 ? 2 : lead >= 0xC0 ? 1 : 0;
    if (need != k) { b->n = lead >= 0xC0 ? i - 1 : b->n; b->p[b->n] = '\0'; }
}

/* Строка JSON. Байты от 0x80 идут как есть: вывод движка — UTF-8. */
static void cb_json(struct cbuf *b, const char *s, size_t n) {
    cb_put(b, "\"", 1);
    size_t st = 0;
    for (size_t i = 0; i < n; i++) {
        unsigned char c = (unsigned char)s[i];
        const char *e = NULL;
        char u[8];
        if (c == '"') e = "\\\"";
        else if (c == '\\') e = "\\\\";
        else if (c == '\n') e = "\\n";
        else if (c == '\t') e = "\\t";
        else if (c == '\r') e = "\\r";
        else if (c < 0x20 || c == 0x7f) { snprintf(u, sizeof(u), "\\u%04x", c); e = u; }
        if (!e) continue;
        cb_put(b, s + st, i - st);
        cb_str(b, e);
        st = i + 1;
    }
    cb_put(b, s + st, n - st);
    cb_put(b, "\"", 1);
}

static void cb_jstr(struct cbuf *b, const char *s) { cb_json(b, s, strlen(s)); }

/* ---- ввод-вывод ------------------------------------------------------------------------ */

static int ctl_write_all(int fd, const char *s, size_t n) {
    while (n) {
        ssize_t w = write(fd, s, n);
        if (w < 0 && errno == EINTR) continue;
        if (w <= 0) return -1;
        s += w;
        n -= (size_t)w;
    }
    return 0;
}

/* ---- ответы ---------------------------------------------------------------------------- */

static void resp_begin(struct cbuf *r, const char *cmd) {
    cb_str(r, "{\"v\":1");
    if (cmd) { cb_str(r, ",\"cmd\":"); cb_jstr(r, cmd); }
}

static void resp_error(struct cbuf *r, const char *err, const char *msg) {
    cb_str(r, ",\"error\":");
    cb_jstr(r, err);
    cb_str(r, ",\"message\":");
    cb_jstr(r, msg);
}

static void resp_run(struct cbuf *r, int code, struct cbuf *out, struct cbuf *err) {
    cb_utf8_trim(out);
    cb_utf8_trim(err);
    cb_fmt(r, ",\"code\":%d,\"stdout\":", code);
    cb_json(r, out->p ? out->p : "", out->n);
    cb_str(r, ",\"stderr\":");
    cb_json(r, err->p ? err->p : "", err->n);
    if (out->trunc || err->trunc) cb_str(r, ",\"truncated\":true");
}

static void resp_bool(struct cbuf *r, const char *k, int v) {
    cb_fmt(r, ",\"%s\":%s", k, v ? "true" : "false");
}

/* Закрыть соединение, не оставив в нём непрочитанного запроса.
 *
 * Unix-сокет, закрытый с непрочитанными данными, ставит собеседнику ECONNRESET (ядро,
 * unix_release_sock), и тот получает его следующим чтением — СРАЗУ ПОСЛЕ нашего ответа. Ответ
 * при этом не теряется, но клиент, читающий «до закрытия», вместо конца потока получает
 * исключение (у LocalSocket Android — IOException). Так закрывался бы каждый отказ: слишком
 * длинная строка, тело больше предела, busy — всё это отвечается, не дочитав запрос. Поэтому:
 * полузакрыть запись (клиент видит конец ответа), дочитать и выбросить то, что он успел
 * прислать, и только потом закрыть. Отвеченное соединение дочитывается в цикле событий со
 * сроком в секунду (conn_drain); отказ при приёме (denied, busy) — здесь, только то, что уже
 * пришло: ждать ради того, кого не пустили, демону незачем. Дочитывается не больше двух
 * пределов тела файла: отвергнутое как слишком большое тело put-file (больше 16 МиБ) клиент
 * шлёт целиком, прежде чем читать ответ, и сброс на середине его записи он увидел бы ошибкой
 * записи, а не нашим too-large. По локальному сокету это десятки миллисекунд; дальше —
 * секунда срока, и хватит. */
static void ctl_close_now(int c) {
    shutdown(c, SHUT_WR);
    size_t total = 0;
    char buf[16384];
    while (total < 2 * (size_t)CTL_FILE_MAX) {
        ssize_t m = recv(c, buf, sizeof(buf), MSG_DONTWAIT);
        if (m < 0 && errno == EINTR) continue;
        if (m <= 0) break;
        total += (size_t)m;
    }
    close(c);
}

/* Отказ одной строкой — для тех, кого не пустили или кому некогда: соединения у них нет,
 * отвечает сам приём. Ответ короче буфера сокета, запись не блокирует. */
static void ctl_refuse_now(int c, const char *err, const char *msg) {
    struct cbuf r = {0};
    resp_begin(&r, NULL);
    resp_error(&r, err, msg);
    cb_str(&r, "}\n");
    if (r.p) {
        ssize_t w;
        do w = send(c, r.p, r.n, MSG_NOSIGNAL | MSG_DONTWAIT); while (w < 0 && errno == EINTR);
    }
    free(r.p);
    ctl_close_now(c);
}

/* ---- выключатель движка ---------------------------------------------------------------- */

#ifdef __BIONIC__
static void ctl_prop_cb(void *cookie, const char *name, const char *value, uint32_t serial) {
    (void)name; (void)serial;
    snprintf((char *)cookie, PROP_VALUE_MAX, "%s", value);
}
#endif

/* Включён ли движок. На телефоне это свойство, которое ставит приложение и за которым
 * следит init: при выключенном движке apply через сокет только СОХРАНЯЕТ спеку — поставить
 * правила в ядро значило бы включить движок в обход выключателя, а демонов, которым их
 * обслуживать (резолвер, сторож), init при выключенном не держит. Включат — init применит
 * сохранённую спеку сам (steerd.rc).
 *
 * Вне bionic свойств нет; там это шов стенда STEER_CTL_ENABLED=0, по умолчанию «включён». */
static int ctl_enabled(void) {
#ifdef __BIONIC__
    char v[PROP_VALUE_MAX] = "";
    const prop_info *pi = __system_property_find(STEER_CTL_PROP);
    if (pi) __system_property_read_callback(pi, ctl_prop_cb, v);
    return !strcmp(v, "1");
#else
    const char *e = getenv("STEER_CTL_ENABLED");
    return !(e && !strcmp(e, "0"));
#endif
}

/* ---- таблица команд ------------------------------------------------------------------- */

enum ctl_argkind {
    CA_NONE = 0,
    CA_NAME,      /* имя выхода: [A-Za-z0-9_.-], до 31 знака, не с «-» и не с «.» */
    CA_TARGET,    /* адрес или имя для explain: ещё «:» и «/», до 253 знаков */
    CA_INT,       /* целое в [lo, hi] */
    CA_LIT,       /* ровно слово lit; уходит в argv одним флагом без значения */
    CA_FILE,      /* имя файла списка: [A-Za-z0-9_.-], до 64 знаков, не с «-»/«.», без «..» */
};

struct ctl_arg {
    enum ctl_argkind kind;
    const char *flag;    /* NULL — позиционный аргумент подкоманды */
    const char *lit;
    long lo, hi;
};

struct conn;
/* В процессе: ответ дописан в r к возврату. */
typedef void (*ctl_fn)(struct conn *c, struct cbuf *r);
/* Свой порядок шагов (обычно с детьми): ответ отдаёт conn_reply, когда шаги кончатся. */
typedef void (*ctl_start)(struct conn *c);

struct ctl_cmd {
    const char *name;
    const char *sub;          /* подкоманда движка для общего случая «через ребёнка» */
    ctl_fn fn;                /* исполняется в процессе демона */
    ctl_start start;          /* свои шаги */
    /* Предел тела в байтах; 0 — тела нет. Не 0 — после строки идёт тело, последнее слово
     * строки — его длина. Предел у каждой команды свой: спеке хватает мегабайта, файлу
     * списка — нет (см. CTL_FILE_MAX). */
    long body;
    int argmin, argmax;
    struct ctl_arg args[3];
    int timeout_s;            /* срок ребёнка (sub) */
    int spec;                 /* передать подкоманде --spec и --state-dir сервера */
    int lock;                 /* изменяющая: идёт по одной (очередь демона) */
};

struct ctl_srv;

struct ctl_req {
    const struct ctl_cmd *cmd;
    const struct ctl_conf *cf;
    const char *argv[3];
    int argc;
    const char *body;
    size_t body_n;
};

/* Ребёнок команды. Один на соединение: шаги apply идут друг за другом, не вместе. */
typedef void (*job_done_fn)(struct conn *c, int code);
struct job {
    pid_t pid;
    int po, pe;               /* трубы stdout и stderr; -1 — закрыта */
    int running, reaped, status, killed, timed_out;
    struct cbuf out, err;
    struct loop_timer *tm;
    job_done_fn done;
};

enum conn_state {
    C_REQ,        /* читаем строку и тело */
    C_WAIT,       /* изменяющая команда ждёт своей очереди */
    C_RUN,        /* исполняется (ребёнок или шаги) */
    C_SEND,       /* отдаём ответ */
    C_DRAIN,      /* ответ отдан, дочитываем остаток запроса перед закрытием */
    C_SUB,        /* подписчик: соединение открыто, пишем события */
};

struct conn {
    struct conn *next;        /* все соединения демона */
    struct conn *qnext;       /* очередь изменяющих команд */
    struct ctl_srv *srv;
    int fd;
    enum conn_state st;
    int counted;              /* входит в четыре одновременных запроса */
    int hup;                  /* собеседник ушёл, пока команда шла: ответ отдавать некому */
    int eof;                  /* подписчик закрыл свою половину — читать больше нечего */
    struct loop_timer *tm;    /* срок запроса, отдачи или дочитывания */
    char line[CTL_LINE_MAX + 1];
    size_t line_n;
    int have_line;
    struct ctl_req q;
    char *body;
    size_t body_got, body_want;
    /* Ответ, пока строится; потом — то, что уходит в сокет с позиции off. У подписчика —
     * очередь событий. */
    struct cbuf resp;
    size_t off;
    size_t drained;
    struct job job;
    /* Между шагами apply/check/reload. */
    char tmp[PATH_MAX];
    struct cbuf old;
    int had_old;
    pid_t dn[8];
    int dn_n;
    void (*after_reload)(struct conn *c);
    struct steerd_sub sub;
    /* Apply-сверка (recon.c): план новой спеки, решение, stderr плана, код и stderr reload. */
    struct recon_plan plan;
    struct recon_diff diff;
    struct cbuf perr;
    int watch;                /* сторожу внеочередной проход */
    int committed;            /* apply-commit запускался */
    int rcode;                /* код reload */
    int boot;                 /* применение при старте (--apply): соединения нет, итог — в журнал */
};

struct ctl_srv {
    struct ctl_conf cf;
    struct steerd d;
    struct loop *l;
    int lfd;
    ino_t ino;
    struct loop_timer *accept_tm;
    struct conn *conns;
    int active, subs;
    struct conn *lock_owner, *lockq;
    int hup_pending;
    struct watchd *watch;     /* сторож выходов; NULL — без --watch */
    struct recon_state rec;   /* что демон применил сам (apply-сверка, recon.c) */
    struct loop_timer *snap_tm;   /* освежение снимка status (с --watch), см. srv_snap */
};

static void mem_version(struct conn *c, struct cbuf *r);
static void mem_status(struct conn *c, struct cbuf *r);
static void mem_explain(struct conn *c, struct cbuf *r);
static void mem_conns(struct conn *c, struct cbuf *r);
static void mem_dns_log(struct conn *c, struct cbuf *r);
static void ctl_do_put_file(struct conn *c, struct cbuf *r);
static void ctl_do_list_files(struct conn *c, struct cbuf *r);
static void ctl_do_rm_file(struct conn *c, struct cbuf *r);
static void st_apply(struct conn *c);
static void st_check(struct conn *c);
static void st_reload(struct conn *c);
static void st_sub_check(struct conn *c);
static void st_subscribe(struct conn *c);

/* ТАБЛИЦА — единственное, что сервер умеет. Команда, которой здесь нет, не исполняется ни в
 * каком виде: слова запроса никогда не становятся именем подкоманды, в argv идут только
 * проверенные по виду аргументы на заранее назначенных местах.
 *
 * Новая команда поверх готовой подкоманды движка — одна строка с sub: она исполняется
 * ребёнком, и то, что приложение видит через сокет, человек получает той же подкомандой в adb
 * root shell. Команда, ответ которой демон может собрать из памяти, — строка с fn: ответ
 * собирает тот же код, что печатает подкоманда (см. «ИСПОЛНЕНИЕ» в шапке).
 *
 * Файлы списков (put-file, list-files, rm-file) — своя обработка, без подкоманды: это работа
 * с каталогом, которую делает сам демон, и подкоманда ради неё была бы вторым путём записи в
 * каталог, которым никто, кроме сервера, не пользуется.
 *
 * Сроки детей: diag — вдвое дороже status (30 с с запасом на медленное хранилище телефона);
 * vless-probe без номера узла перебирает узлы подписки по очереди, каждый со своим --timeout;
 * check и apply — свои (см. st_check, st_apply). */
static const struct ctl_cmd CTL_CMDS[] = {
    {"version",     NULL, mem_version, NULL, 0, 0, 0, {{0}}, 0, 0, 0},
    {"status",      NULL, mem_status, NULL, 0, 0, 1, {{CA_LIT, "--fast", "fast", 0, 0}}, 0, 0, 0},
    {"diag",        "diag", NULL, NULL, 0, 0, 0, {{0}}, 30, 1, 0},
    {"explain",     NULL, mem_explain, NULL, 0, 1, 1, {{CA_TARGET, NULL, NULL, 0, 0}}, 0, 0, 0},
    {"vless-nodes", "vless-nodes", NULL, NULL, 0, 1, 1, {{CA_NAME, NULL, NULL, 0, 0}}, 15, 1, 0},
    {"vless-probe", "vless-probe", NULL, NULL, 0, 1, 3,
        {{CA_NAME, NULL, NULL, 0, 0},
         {CA_INT, "--node", NULL, -1, 9999},
         {CA_INT, "--timeout", NULL, 1, 30}}, 180, 1, 0},
    {"check",       NULL, NULL, st_check,  CTL_BODY_MAX, 0, 0, {{0}}, 0, 1, 1},
    {"apply",       NULL, NULL, st_apply,  CTL_BODY_MAX, 0, 0, {{0}}, 0, 1, 1},
    {"reload",      NULL, NULL, st_reload, 0, 0, 0, {{0}}, 0, 1, 1},
    {"conns",       NULL, mem_conns, NULL, 0, 0, 0, {{0}}, 0, 0, 0},
    {"dns-log",     NULL, mem_dns_log, NULL, 0, 0, 0, {{0}}, 0, 0, 0},
    {"put-file",    NULL, ctl_do_put_file, NULL, CTL_FILE_MAX, 1, 1, {{CA_FILE, NULL, NULL, 0, 0}}, 0, 0, 0},
    {"list-files",  NULL, ctl_do_list_files, NULL, 0, 0, 0, {{0}}, 0, 0, 0},
    {"rm-file",     NULL, ctl_do_rm_file, NULL, 0, 1, 1, {{CA_FILE, NULL, NULL, 0, 0}}, 0, 0, 1},
    {"sub-check",   NULL, NULL, st_sub_check, CTL_FILE_MAX, 0, 0, {{0}}, 0, 0, 0},
    {"subscribe",   NULL, NULL, st_subscribe, 0, 0, 0, {{0}}, 0, 0, 0},
};

static const struct ctl_cmd *ctl_lookup(const char *name) {
    for (size_t i = 0; i < sizeof(CTL_CMDS) / sizeof(CTL_CMDS[0]); i++)
        if (!strcmp(CTL_CMDS[i].name, name)) return &CTL_CMDS[i];
    return NULL;
}

/* Проверка слова по виду. Слова идут в argv без shell, но слово с «-» в начале подкоманда
 * приняла бы за флаг — `explain --spec` читал бы чужой файл, — поэтому вид проверяется
 * строго, до запуска. */
static const char *ctl_arg_bad(const struct ctl_arg *a, const char *w) {
    size_t n = strlen(w);
    switch (a->kind) {
    case CA_LIT:
        return strcmp(w, a->lit) ? "здесь понимается только одно слово" : NULL;
    case CA_INT: {
        char *e = NULL;
        errno = 0;
        long v = strtol(w, &e, 10);
        if (!n || n > 6 || *e || errno) return "нужно целое число";
        if (v < a->lo || v > a->hi) return "число вне допустимого";
        return NULL;
    }
    case CA_NAME:
    case CA_TARGET: {
        size_t lim = a->kind == CA_NAME ? 31 : 253;
        if (!n || n > lim) return "слишком длинное или пустое";
        if (w[0] == '-' || w[0] == '.') return "не может начинаться с «-» или «.»";
        for (size_t i = 0; i < n; i++) {
            unsigned char c = (unsigned char)w[i];
            int ok = (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') ||
                     (c >= '0' && c <= '9') || c == '_' || c == '.' || c == '-';
            if (a->kind == CA_TARGET && (c == ':' || c == '/')) ok = 1;
            if (!ok) return "недопустимый знак";
        }
        return NULL;
    }
    case CA_FILE: {
        /* Имя файла становится путём <каталог списков>/<имя>, поэтому вид строже, чем у
         * имени выхода: ни «/», ни «..» (выход из каталога), ни точки в начале (скрытые имена
         * заняты временными файлами самого сервера, .put-XXXXXX), ни «-» в начале (имя может
         * оказаться в argv подкоманды через спеку). Знаки — те же, что у имён файлов в
         * каталоге splify2-lists. */
        if (!n || n > CTL_FNAME_MAX) return "слишком длинное или пустое имя файла";
        if (w[0] == '-' || w[0] == '.') return "имя файла не может начинаться с «-» или «.»";
        if (strstr(w, "..")) return "в имени файла не может быть «..»";
        for (size_t i = 0; i < n; i++) {
            unsigned char c = (unsigned char)w[i];
            if (!((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') ||
                  (c >= '0' && c <= '9') || c == '_' || c == '.' || c == '-'))
                return "недопустимый знак в имени файла";
        }
        return NULL;
    }
    default:
        return "лишнее слово";
    }
}

/* argv подкоманды: движок, подкоманда, аргументы по местам, затем спека и состояние. */
static size_t ctl_argv(const struct ctl_req *q, const char *sub, char **av, size_t cap) {
    size_t n = 0;
    av[n++] = (char *)q->cf->exe;
    av[n++] = (char *)sub;
    for (int i = 0; i < q->argc && n + 2 < cap; i++) {
        const struct ctl_arg *a = &q->cmd->args[i];
        if (a->flag) av[n++] = (char *)a->flag;
        if (a->kind != CA_LIT || !a->flag) av[n++] = (char *)q->argv[i];
    }
    if (q->cmd->spec && n + 5 < cap) {
        av[n++] = "--spec";
        av[n++] = (char *)q->cf->spec;
        if (q->cf->state_dir) {
            av[n++] = "--state-dir";
            av[n++] = (char *)q->cf->state_dir;
        }
    }
    av[n] = NULL;
    return n;
}

/* ---- соединения: ответ, отдача, дочитывание ---------------------------------------------- */

static void conn_free(struct conn *c);
static void conn_exec(struct conn *c);
static void conn_ev(struct loop *l, int fd, uint32_t ev, void *arg);

/* Изменяющая команда кончилась: следующая из очереди — сейчас же. SIGHUP, пришедший, пока
 * шла команда, перечитывает спеку после неё: перечитывание пишет реестр меток, как и
 * dry-run, и вперемешку с чужим apply им нельзя. */
static void srv_spec_changed(struct ctl_srv *s, const char *by, int enabled,
                             const struct recon_diff *d, int watch, struct cbuf *changed);

static void lock_release(struct ctl_srv *s) {
    s->lock_owner = NULL;
    struct conn *n = s->lockq;
    if (n) {
        s->lockq = n->qnext;
        n->qnext = NULL;
        conn_exec(n);
        return;
    }
    if (s->hup_pending) {
        s->hup_pending = 0;
        srv_spec_changed(s, "hup", ctl_enabled(), NULL, 1, NULL);
    }
}

static void conn_events(struct conn *c, uint32_t ev) {
    if (!c->hup) loop_fd_mod(c->srv->l, c->fd, ev);
}

/* Отдать, сколько сокет примет. 0 — всё отдано или ждём EPOLLOUT; -1 — соединение закрыто
 * (освобождено здесь же — трогать c после этого нельзя). */
static int conn_flush(struct conn *c) {
    int progress = 0;
    while (c->off < c->resp.n) {
        ssize_t w = send(c->fd, c->resp.p + c->off, c->resp.n - c->off, MSG_NOSIGNAL | MSG_DONTWAIT);
        if (w > 0) { c->off += (size_t)w; progress = 1; continue; }
        if (w < 0 && errno == EINTR) continue;
        if (w < 0 && (errno == EAGAIN || errno == EWOULDBLOCK)) {
            if (c->st == C_SEND && progress) loop_timer_set(c->tm, CTL_SEND_MS);
            conn_events(c, EPOLLOUT | (c->st == C_SUB && !c->eof ? EPOLLIN : 0));
            return 0;
        }
        conn_free(c);
        return -1;
    }
    if (c->st == C_SUB) {
        c->resp.n = c->off = 0;
        conn_events(c, c->eof ? 0 : EPOLLIN);
        return 0;
    }
    /* Ответ отдан целиком: полузакрыть запись (клиент видит конец ответа) и дочитать то, что
     * он ещё шлёт, — см. «Закрыть соединение, не оставив…». */
    shutdown(c->fd, SHUT_WR);
    c->st = C_DRAIN;
    c->drained = 0;
    loop_timer_set(c->tm, CTL_DRAIN_MS);
    conn_events(c, EPOLLIN);
    return 0;
}

static void conn_drain(struct conn *c) {
    char buf[16384];
    for (;;) {
        ssize_t m = recv(c->fd, buf, sizeof(buf), MSG_DONTWAIT);
        if (m < 0 && errno == EINTR) continue;
        if (m < 0 && (errno == EAGAIN || errno == EWOULDBLOCK)) return;
        if (m <= 0) { conn_free(c); return; }
        c->drained += (size_t)m;
        if (c->drained >= 2 * (size_t)CTL_FILE_MAX) { conn_free(c); return; }
    }
}

/* Ответ готов (в c->resp без закрывающей скобки) — отдать. Снимает блокировку изменяющих
 * команд, если она у этого соединения. */
static void conn_reply(struct conn *c) {
    struct ctl_srv *s = c->srv;
    if (s->lock_owner == c) lock_release(s);
    if (c->hup) { conn_free(c); return; }
    cb_str(&c->resp, "}\n");
    c->st = C_SEND;
    c->off = 0;
    loop_timer_set(c->tm, CTL_SEND_MS);
    conn_flush(c);
}

/* Отказ посреди запроса: всё, что успели дописать в ответ, выбрасывается. */
static void conn_refuse(struct conn *c, const char *cmd, const char *err, const char *msg) {
    c->resp.n = 0;
    c->resp.trunc = 0;
    resp_begin(&c->resp, cmd);
    resp_error(&c->resp, err, msg);
    conn_reply(c);
}

/* ---- ребёнок ------------------------------------------------------------------------------ */

static void job_check(struct conn *c) {
    struct job *j = &c->job;
    if (!j->running || j->po >= 0 || j->pe >= 0 || !j->reaped) return;
    j->running = 0;
    loop_timer_stop(j->tm);
    int st = j->status, code = -1;
    if (WIFEXITED(st)) code = WEXITSTATUS(st);
    else if (WIFSIGNALED(st)) code = 128 + WTERMSIG(st);
    j->done(c, code);
}

static void job_close_pipe(struct conn *c, int *fd) {
    if (*fd < 0) return;
    loop_fd_del(c->srv->l, *fd);
    close(*fd);
    *fd = -1;
}

static void job_pipe(struct loop *l, int fd, uint32_t ev, void *arg) {
    (void)l; (void)ev;
    struct conn *c = arg;
    struct job *j = &c->job;
    int *pfd = fd == j->po ? &j->po : &j->pe;
    struct cbuf *b = fd == j->po ? &j->out : &j->err;
    char buf[16384];
    for (;;) {
        ssize_t m = read(fd, buf, sizeof(buf));
        if (m > 0) { cb_put(b, buf, (size_t)m); continue; }
        if (m < 0 && errno == EINTR) continue;
        if (m < 0 && (errno == EAGAIN || errno == EWOULDBLOCK)) return;
        job_close_pipe(c, pfd);
        break;
    }
    job_check(c);
}

static void job_child(struct loop *l, pid_t pid, int status, void *arg) {
    (void)l; (void)pid;
    struct conn *c = arg;
    c->job.reaped = 1;
    c->job.status = status;
    job_check(c);
}

/* Срок. Первый раз — SIGKILL всей группе команды и ещё две секунды на то, чтобы трубы
 * закрылись; второй — трубы держит кто-то вне группы, хватит ждать: закрыть их самим. */
static void job_timer(struct loop *l, struct loop_timer *t, void *arg) {
    (void)l; (void)t;
    struct conn *c = arg;
    struct job *j = &c->job;
    if (!j->running) return;
    if (!j->killed) {
        kill(-j->pid, SIGKILL);
        if (!j->reaped) kill(j->pid, SIGKILL);
        j->killed = 1;
        j->timed_out = 1;
        loop_timer_set(j->tm, 2000);
        return;
    }
    job_close_pipe(c, &j->po);
    job_close_pipe(c, &j->pe);
    job_check(c);
}

/* Запустить движок с argv: вывод копится в job.out/job.err (с пределами outmax/errmax), по
 * выходу — done(c, код) (убитый сигналом — 128 + номер, как в shell). -1 — запустить не
 * удалось (done не будет). */
static int job_start(struct conn *c, char *const argv[], int timeout_s, size_t outmax,
                     size_t errmax, job_done_fn done) {
    struct ctl_srv *s = c->srv;
    struct job *j = &c->job;
    free(j->out.p);
    free(j->err.p);
    memset(&j->out, 0, sizeof(j->out));
    memset(&j->err, 0, sizeof(j->err));
    j->out.max = outmax;
    j->err.max = errmax;
    j->reaped = j->killed = j->timed_out = j->status = 0;
    j->po = j->pe = -1;
    j->done = done;
    if (!j->tm && !(j->tm = loop_timer_new(s->l, job_timer, c))) return -1;
    int po[2], pe[2];
    /* Ход перебора узлов vless из памяти супервизора (--supervise) — ребёнку в окружение: клиенты
     * с трубой событий файлов probe-* не пишут, а diag подкомандой спрашивает probe_read. */
    char pmem[1024];
    supd_probe_env(s->d.sup, pmem, sizeof(pmem));
    if (pipe2(po, O_CLOEXEC) != 0) return -1;
    if (pipe2(pe, O_CLOEXEC) != 0) { close(po[0]); close(po[1]); return -1; }
    pid_t pid = fork();
    if (pid < 0) {
        close(po[0]); close(po[1]); close(pe[0]); close(pe[1]);
        return -1;
    }
    if (pid == 0) {
        /* Своя группа процессов: по сроку убивается и то, что команда успела запустить
         * (nft, ip, iptables), а не только она сама. */
        setpgid(0, 0);
        int nul = open("/dev/null", O_RDONLY);
        if (nul >= 0) dup2(nul, 0);
        dup2(po[1], 1);
        dup2(pe[1], 2);
        /* Сигналы цикла заблокированы, SIGPIPE игнорируется — и то и другое наследуется
         * через exec, а подкоманды рассчитывают на обычное поведение. */
        loop_child_reset();
        if (pmem[0]) putenv(pmem);
        execv(s->cf.exe, argv);
        dprintf(2, LOG_W "не запустить %s: %s\n", s->cf.exe, strerror(errno));
        _exit(127);
    }
    close(po[1]);
    close(pe[1]);
    /* Неблокирующим — только наш конец: у ребёнка stdout обычный. */
    fcntl(po[0], F_SETFL, fcntl(po[0], F_GETFL) | O_NONBLOCK);
    fcntl(pe[0], F_SETFL, fcntl(pe[0], F_GETFL) | O_NONBLOCK);
    j->pid = pid;
    j->po = po[0];
    j->pe = pe[0];
    j->running = 1;
    if (loop_fd_add(s->l, j->po, EPOLLIN, job_pipe, c) != 0) { close(j->po); j->po = -1; }
    if (loop_fd_add(s->l, j->pe, EPOLLIN, job_pipe, c) != 0) { close(j->pe); j->pe = -1; }
    loop_child(s->l, pid, job_child, c);
    loop_timer_set(j->tm, (long)timeout_s * 1000L);
    return 0;
}

/* Общий случай: подкоманда целиком — её код и вывод. */
static void sub_done(struct conn *c, int code) {
    struct job *j = &c->job;
    if (code < 0) { resp_error(&c->resp, "internal", "не удалось дождаться движка"); conn_reply(c); return; }
    resp_run(&c->resp, code, &j->out, &j->err);
    if (j->timed_out) resp_error(&c->resp, "timeout", "команда не уложилась в свой срок и остановлена");
    conn_reply(c);
}

static void st_sub(struct conn *c) {
    char *av[16];
    ctl_argv(&c->q, c->q.cmd->sub, av, sizeof(av) / sizeof(av[0]));
    if (job_start(c, av, c->q.cmd->timeout_s, CTL_OUT_MAX, CTL_ERR_MAX, sub_done) != 0) {
        resp_error(&c->resp, "internal", "не удалось запустить движок");
        conn_reply(c);
    }
}

/* ---- в процессе: stdout в память, stderr в файл в памяти -------------------------------- *
 *
 * Ответ команды в процессе должен быть тем же, что у подкоманды, — и stdout, и stderr: у conns
 * причина отказа («нет модуля nf_conntrack_netlink») лежит именно в stderr, и приложение её
 * показывает. stdout печатается в поток open_memstream (функции ответа принимают FILE*), а
 * stderr на время команды — дескриптор 2, перенаправленный в memfd: так в ответ попадает и
 * то, что пишет глубоко вложенный код (виды выходов, nft в popen со своим stderr), без
 * протаскивания второго потока через всё дерево. Демон однопоточный, и на время команды
 * других записей в журнал у него нет. Нет memfd (ядро старше 3.17) — удалённый временный файл
 * в каталоге состояния; нет и его — stderr остаётся в журнале, а в ответе пусто. */
struct mem_run {
    FILE *f;
    char *p;
    size_t n;
    int saved, fd;
};

static int cap_fd(void) {
#ifdef SYS_memfd_create
    int fd = (int)syscall(SYS_memfd_create, "steer-ctl", 1u /* MFD_CLOEXEC */);
    if (fd >= 0) return fd;
#endif
    char t[PATH_MAX];
    snprintf(t, sizeof(t), "%s/.ctl-err-XXXXXX", steer_state_dir());
    int fd2 = mkostemp(t, O_CLOEXEC);
    if (fd2 >= 0) unlink(t);
    return fd2;
}

static FILE *mem_begin(struct mem_run *m) {
    memset(m, 0, sizeof(*m));
    m->saved = m->fd = -1;
    m->f = open_memstream(&m->p, &m->n);
    if (!m->f) return NULL;
    fflush(stderr);
    m->fd = cap_fd();
    if (m->fd >= 0) {
        m->saved = fcntl(2, F_DUPFD_CLOEXEC, 3);
        if (m->saved < 0 || dup2(m->fd, 2) < 0) {
            if (m->saved >= 0) close(m->saved);
            close(m->fd);
            m->saved = m->fd = -1;
        }
    }
    return m->f;
}

static void mem_end(struct mem_run *m, struct cbuf *r, int code) {
    struct cbuf out = { .max = CTL_OUT_MAX }, err = { .max = CTL_ERR_MAX };
    fflush(stderr);
    if (m->saved >= 0) {
        dup2(m->saved, 2);
        close(m->saved);
        char buf[16384];
        ssize_t k;
        if (lseek(m->fd, 0, SEEK_SET) == 0)
            while ((k = read(m->fd, buf, sizeof(buf))) > 0) cb_put(&err, buf, (size_t)k);
        close(m->fd);
    }
    fclose(m->f);
    if (m->p) cb_put(&out, m->p, m->n);
    free(m->p);
    resp_run(r, code, &out, &err);
    free(out.p);
    free(err.p);
}

/* Отказ разбора спеки — тем же текстом, что err_die у подкоманды. */
static int mem_no_spec(const struct steerd *d) {
    fprintf(stderr, "%s%s\n", "steer: ", d->err);
    return 2;
}

/* version — ещё и то, чью спеку демон обслуживает: spec_path и state_dir полными путями. По ним
 * клиент steer решает, отдавать ли демону `steer status --spec X` (та же спека) или движку
 * (чужая: стенд, ручной запуск). Поля добавлены к версии 1 — прежние не изменились. */
static void mem_version(struct conn *c, struct cbuf *r) {
    struct mem_run m;
    FILE *f = mem_begin(&m);
    if (!f) { resp_error(r, "internal", "нет памяти под ответ"); return; }
    cli_version(f);
    mem_end(&m, r, 0);
    /* realpath на каждый ответ, а не при старте: спеки при старте может ещё не быть (роутер без
     * настройки), а файла нет — путь как написан. */
    char rp[PATH_MAX];
    cb_str(r, ",\"spec_path\":");
    cb_jstr(r, realpath(c->srv->cf.spec, rp) ? rp : c->srv->cf.spec);
    cb_str(r, ",\"state_dir\":");
    cb_jstr(r, realpath(steer_state_dir(), rp) ? rp : steer_state_dir());
}

/* status из памяти: спека и группы — демона, а то, что меняется без спеки (устройство,
 * выбранное сторожем, /sys, счётчики nft, реестр), читается на каждый вызов, как у подкоманды.
 * fast — запомненный снимок, как `status --fast`. */
static void mem_status(struct conn *c, struct cbuf *r) {
    struct steerd *d = &c->srv->d;
    struct mem_run m;
    FILE *f = mem_begin(&m);
    if (!f) { resp_error(r, "internal", "нет памяти под ответ"); return; }
    int code = 0;
    if (c->q.argc > 0 && status_fast(f) == 0) {
        /* запомненное отдано */
    } else if (!d->have) {
        code = mem_no_spec(d);
    } else {
        memcpy(d->view, d->sp, sizeof(*d->view));
        /* Выбор устройств — из памяти сторожа, если сторож — сам демон (--watch); иначе из
         * файла, который пишет `failover --loop`. */
        outputs_adopt_active_st(d->view, d->outs ? d->outs : &fo_store_files);
        /* Дамп ruleset для fw_check — один на процесс подкоманды; у демона процесс один на
         * всё время, и дамп берётся заново на каждый ответ. */
        fwcheck_reset_cache();
        status_answer(d->view, d->gr, f);
    }
    mem_end(&m, r, code);
}

static void mem_explain(struct conn *c, struct cbuf *r) {
    struct steerd *d = &c->srv->d;
    const char *what = c->q.argv[0];
    struct mem_run m;
    FILE *f = mem_begin(&m);
    if (!f) { resp_error(r, "internal", "нет памяти под ответ"); return; }
    int code;
    /* Тот же порядок проверок, что у подкоманды (main.c): форма аргумента, затем спека. */
    if (!addr_ok(what) && !looks_like_name(what)) {
        fprintf(stderr, "%s%s%s\n", "steer: ", "это не адрес и не имя: ", what);
        code = 2;
    } else if (!d->have) {
        code = mem_no_spec(d);
    } else {
        code = explain_emit(d->sp, d->gr, what, f);
    }
    mem_end(&m, r, code);
}

static void mem_conns(struct conn *c, struct cbuf *r) {
    (void)c;
    struct mem_run m;
    FILE *f = mem_begin(&m);
    if (!f) { resp_error(r, "internal", "нет памяти под ответ"); return; }
    int code = ctnl_conns_print(f);
    mem_end(&m, r, code);
}

/* Журнал резолвера — разговор с его сокетом (dlog_print): он отвечает из памяти, за
 * миллисекунды; зависший резолвер держит демон не дольше трёх секунд срока чтения. */
static void mem_dns_log(struct conn *c, struct cbuf *r) {
    (void)c;
    struct mem_run m;
    FILE *f = mem_begin(&m);
    if (!f) { resp_error(r, "internal", "нет памяти под ответ"); return; }
    int code = dlog_print(f);
    mem_end(&m, r, code);
}

/* Снимок status (status.json, его отдаёт `status --fast`) — раз в пять минут, с --watch.
 *
 * До демона это делал отдельный экземпляр procd (`while :; do steer status; sleep 300; done` в
 * init.d): снимок обязан быть свежим к моменту, когда человек ОТКРЫВАЕТ окно splify2, а пока
 * окно закрыто, полных status никто не спрашивает. Один сервис — один процесс, и круг переехал
 * сюда. Только с --watch: это режим, в котором демон — весь движок (procd, сервис телефона);
 * стенды и ручной запуск без сторожа лишних ответов не считают. Пока идёт изменяющая команда —
 * пропуск до следующего раза: спека в памяти как раз меняется. */
#define CTL_SNAP_MS (300L * 1000L)

static void srv_snap(struct loop *l, struct loop_timer *t, void *arg) {
    (void)l;
    struct ctl_srv *s = arg;
    struct steerd *d = &s->d;
    if (d->have && !s->lock_owner) {
        FILE *f = fopen("/dev/null", "w");
        if (f) {
            memcpy(d->view, d->sp, sizeof(*d->view));
            outputs_adopt_active_st(d->view, d->outs ? d->outs : &fo_store_files);
            fwcheck_reset_cache();
            status_answer(d->view, d->gr, f);
            fclose(f);
        }
    }
    loop_timer_set(t, CTL_SNAP_MS);
}

/* ---- apply и check ---------------------------------------------------------------------- */

static const char *ctl_state_dir(const struct ctl_conf *cf) {
    return cf->state_dir ? cf->state_dir : plat()->state_dir;
}

/* Записать данные во временный файл РЯДОМ с целевым (тот же довод, что у spec_set в
 * splify2: rename атомарен только внутри одной файловой системы). 0 — готово, имя в tmp. */
static int ctl_write_tmp(const char *final, const char *data, size_t n, char *tmp, size_t tn) {
    if ((size_t)snprintf(tmp, tn, "%s.ctl-XXXXXX", final) >= tn) return -1;
    int fd = mkostemp(tmp, O_CLOEXEC);
    if (fd < 0) return -1;
    int ok = ctl_write_all(fd, data, n) == 0 && fsync(fd) == 0;
    if (close(fd) != 0) ok = 0;
    if (!ok) { unlink(tmp); return -1; }
    return 0;
}

/* Каталог после rename — чтобы новое имя пережило обрыв питания, а не только новое
 * содержимое. */
static void ctl_fsync_dir(const char *path) {
    char d[PATH_MAX];
    snprintf(d, sizeof(d), "%s", path);
    char *s = strrchr(d, '/');
    if (!s) snprintf(d, sizeof(d), ".");
    else if (s == d) d[1] = '\0';
    else *s = '\0';
    int fd = open(d, O_RDONLY | O_DIRECTORY | O_CLOEXEC);
    if (fd >= 0) { fsync(fd); close(fd); }
}

/* Прочитать файл целиком. 1 — прочитан, 0 — его нет, -1 — не прочитать. */
static int ctl_read_file(const char *path, struct cbuf *b, size_t max) {
    int fd = open(path, O_RDONLY | O_CLOEXEC);
    if (fd < 0) return errno == ENOENT ? 0 : -1;
    char buf[16384];
    ssize_t m;
    b->max = max;
    while ((m = read(fd, buf, sizeof(buf))) > 0) cb_put(b, buf, (size_t)m);
    close(fd);
    if (m < 0 || b->trunc) return -1;
    if (!b->p) cb_put(b, "", 0);
    return 1;
}

/* Поле changed ответа и события applied (docs/ctl.md): что тронула сверка. Набор правил и
 * маршрутизация — по решению apply-сверки (d; NULL — в ядро ничего не шло), помощники и таблица
 * резолвера — по сверке супервизора. */
static void changed_json(struct cbuf *b, const struct recon_diff *d, const struct supd_changes *ch) {
    cb_fmt(b, ",\"changed\":{\"ruleset\":%s,\"routing\":[", d && d->ruleset ? "true" : "false");
    for (size_t i = 0; d && i < d->route_n; i++) {
        if (i) cb_str(b, ",");
        cb_jstr(b, d->route[i]);
    }
    cb_str(b, "],\"helpers\":[");
    for (size_t i = 0; ch && i < ch->helpers_n; i++) {
        if (i) cb_str(b, ",");
        cb_jstr(b, ch->helpers[i]);
    }
    cb_fmt(b, "],\"dnsd\":%s}", ch && ch->dnsd ? "true" : "false");
}

/* Спека на диске изменилась (apply, reload, SIGHUP) — перечитать её в память и сказать
 * подписчикам. Удалось — супервизор сверяет помощников и таблицу резолвера, событие applied с
 * отпечатком и полем changed; нет — spec-error, а в памяти остаётся прежняя спека: демон
 * продолжает отвечать по последней годной. watch — сторожу внеочередной проход (изменились
 * выходы; помощники — тоже повод, их супервизор называет сам). changed (может быть NULL) — куда
 * дописать поле changed для ответа. */
static void srv_spec_changed(struct ctl_srv *s, const char *by, int enabled,
                             const struct recon_diff *d, int watch, struct cbuf *changed) {
    struct supd_changes ch;
    memset(&ch, 0, sizeof(ch));
    struct cbuf cj = {0};
    if (steerd_load(&s->d) == 0) {
        supd_spec_changed(s->d.sup, &ch);
        changed_json(&cj, d, &ch);
        struct cbuf f = {0};
        cb_fmt(&f, ",\"by\":\"%s\",\"spec\":\"%s\",\"enabled\":%s", by, s->d.fp,
               enabled ? "true" : "false");
        if (cj.p) cb_put(&f, cj.p, cj.n);
        steerd_emit(&s->d, "applied", f.p ? f.p : "");
        free(f.p);
        if (watch || ch.helpers_n) watchd_spec_changed(s->watch);
    } else {
        changed_json(&cj, d, NULL);
        fprintf(stderr, LOG_W "спека не прочитана (%s): %s\n", by, s->d.err);
        char m[2304], f[2560];
        steerd_json_str(m, sizeof(m), s->d.err);
        snprintf(f, sizeof(f), ",\"by\":\"%s\",\"message\":%s", by, m);
        steerd_emit(&s->d, "spec-error", f);
    }
    if (changed && cj.p) cb_put(changed, cj.p, cj.n);
    free(cj.p);
}

/* argv проверки кандидата: `apply --dry-run --spec ПУТЬ [--state-dir …]`. */
static void dry_argv(struct conn *c, const char *path, char **av) {
    size_t n = 0;
    av[n++] = c->srv->cf.exe;
    av[n++] = "apply";
    av[n++] = "--dry-run";
    av[n++] = "--spec";
    av[n++] = (char *)path;
    if (c->srv->cf.state_dir) { av[n++] = "--state-dir"; av[n++] = (char *)c->srv->cf.state_dir; }
    av[n] = NULL;
}

static void check_done(struct conn *c, int code) {
    struct cbuf none = {0};
    unlink(c->tmp);
    if (code < 0) { resp_error(&c->resp, "internal", "не удалось дождаться движка"); conn_reply(c); return; }
    resp_run(&c->resp, code, &none, &c->job.err);
    if (c->job.timed_out) resp_error(&c->resp, "timeout", "проверка не уложилась в свой срок и остановлена");
    conn_reply(c);
}

/* check — проверить присланную спеку и ничего не менять: для кнопки «Проверить» и для
 * предупреждений до сохранения. Кандидат — во временный файл рядом со спекой и `apply
 * --dry-run` по нему; текст набора правил (stdout) не нужен и не копится, stderr —
 * предупреждения и причина отказа — идёт в ответ.
 *
 * Идёт в очереди изменяющих, хотя спеку не трогает: dry-run не чисто читающий — он раздаёт
 * выходам метки в реестре каталога состояния (registry_assign в cmd_apply), и проверка,
 * идущая одновременно с чужим apply, писала бы реестр посреди его применения. */
static void st_check(struct conn *c) {
    if (ctl_write_tmp(c->srv->cf.spec, c->q.body, c->q.body_n, c->tmp, sizeof(c->tmp)) != 0) {
        resp_error(&c->resp, "internal", "не удалось записать временный файл спеки");
        conn_reply(c);
        return;
    }
    char *av[10];
    dry_argv(c, c->tmp, av);
    if (job_start(c, av, 120, 1, CTL_ERR_MAX, check_done) != 0) {
        unlink(c->tmp);
        resp_error(&c->resp, "internal", "не удалось запустить движок");
        conn_reply(c);
    }
}

static void reload_begin(struct conn *c);

/* ---- apply-сверка: план и применение ----------------------------------------------------------
 *
 * Устройство и доводы — в шапке recon.c. Здесь — шаги на цикле демона: ребёнок `apply-plan`
 * (проверки dry-run и отпечатки частей), решение recon_decide, ребёнок `apply-commit` только с
 * изменившимися частями — или никакого, если меняться нечему. */

/* Ребёнок-план по спеке path; раскладку набора правил, узнанную у прежнего плана, — готовой. */
static int plan_start(struct conn *c, const char *path, job_done_fn done) {
    struct ctl_srv *s = c->srv;
    char *av[12], nb[16];
    size_t n = 0;
    av[n++] = s->cf.exe;
    av[n++] = "apply-plan";
    av[n++] = "--spec";
    av[n++] = (char *)path;
    if (s->cf.state_dir) { av[n++] = "--state-dir"; av[n++] = (char *)s->cf.state_dir; }
    if (s->rec.nftc >= 0) {
        snprintf(nb, sizeof(nb), "%d", s->rec.nftc);
        av[n++] = "--nftc";
        av[n++] = nb;
    }
    av[n] = NULL;
    return job_start(c, av, 120, CTL_OUT_MAX, CTL_ERR_MAX, done);
}

/* План пришёл: разобрать и запомнить его stderr (предупреждения проверки). 0 — годный. */
static int plan_take(struct conn *c) {
    struct job *j = &c->job;
    if (recon_plan_parse(j->out.p ? j->out.p : "", j->out.n, &c->plan) != 0) return -1;
    free(c->perr.p);
    c->perr = j->err;
    memset(&j->err, 0, sizeof(j->err));
    c->srv->rec.nftc = c->plan.nftc;
    c->watch = recon_watch_changed(&c->srv->rec, &c->plan);
    return 0;
}

/* Решить, что применять, и применить: ребёнок apply-commit или сразу done(c, 0), если в ядро
 * идти незачем. */
static void commit_start(struct conn *c, job_done_fn done) {
    struct ctl_srv *s = c->srv;
    recon_decide(&s->rec, &c->plan, &c->diff);
    c->committed = 0;
    if (!recon_diff_any(&c->diff)) { done(c, 0); return; }
    char buf[1024], *av[24];
    recon_commit_argv(&c->diff, s->cf.exe, s->cf.spec, s->cf.state_dir, s->rec.nftc, buf,
                      sizeof(buf), av);
    c->committed = 1;
    if (job_start(c, av, 300, CTL_OUT_MAX, CTL_ERR_MAX, done) != 0) {
        c->committed = 0;
        done(c, -1);
    }
}

/* stdout и stderr применения для ответа: у apply-commit — его; набор правил он собирал сам (и
 * предупреждения проверки повторил), иначе впереди — предупреждения плана. Без apply-commit —
 * строка итога, как у подкоманды. */
static void commit_output(struct conn *c, struct cbuf *out, struct cbuf *err) {
    struct job *j = &c->job;
    memset(out, 0, sizeof(*out));
    memset(err, 0, sizeof(*err));
    out->max = CTL_OUT_MAX;
    err->max = CTL_ERR_MAX;
    if (c->committed && j->out.p) cb_put(out, j->out.p, j->out.n);
    if (!c->committed)
        cb_fmt(out, "steer: applied %zu channel(s), %zu output(s)\n", c->plan.ch_n, c->plan.out_n);
    if (!(c->committed && c->diff.ruleset) && c->perr.p) cb_put(err, c->perr.p, c->perr.n);
    if (c->committed && j->err.p) cb_put(err, j->err.p, j->err.n);
}

static void apply_finish(struct conn *c) {
    srv_spec_changed(c->srv, "apply", 1, &c->diff, c->watch, &c->resp);
    conn_reply(c);
}

static void apply_committed(struct conn *c, int code);

/* Шаг 2 apply: план прошёл (проверки те же, что у dry-run). */
static void apply_planned(struct conn *c, int code) {
    struct ctl_srv *s = c->srv;
    struct job *j = &c->job;
    struct cbuf none = {0};
    const char *spec = s->cf.spec;
    if (code != 0 || j->timed_out) {
        unlink(c->tmp);
        if (code < 0) { resp_error(&c->resp, "internal", "не удалось дождаться движка"); conn_reply(c); return; }
        resp_run(&c->resp, code, &none, &j->err);
        resp_bool(&c->resp, "saved", 0);
        resp_bool(&c->resp, "applied", 0);
        if (j->timed_out) resp_error(&c->resp, "timeout", "проверка не уложилась в свой срок и остановлена");
        conn_reply(c);
        return;
    }
    if (plan_take(c) != 0) {
        unlink(c->tmp);
        resp_error(&c->resp, "internal", "план применения не разобран");
        conn_reply(c);
        return;
    }
    free(c->old.p);
    memset(&c->old, 0, sizeof(c->old));
    c->had_old = ctl_read_file(spec, &c->old, 4 * CTL_BODY_MAX);
    if (rename(c->tmp, spec) != 0) {
        unlink(c->tmp);
        resp_error(&c->resp, "internal", "не удалось заменить спеку");
        conn_reply(c);
        return;
    }
    ctl_fsync_dir(spec);

    if (!ctl_enabled()) {
        /* Правила снимет и поставит init, когда движок выключат и включат: что будет в ядре
         * потом, демон не знает. */
        recon_forget(&s->rec);
        memset(&c->diff, 0, sizeof(c->diff));
        resp_run(&c->resp, 0, &none, &c->perr);
        resp_bool(&c->resp, "saved", 1);
        resp_bool(&c->resp, "applied", 0);
        resp_bool(&c->resp, "enabled", 0);
        srv_spec_changed(s, "apply", 0, &c->diff, c->watch, &c->resp);
        conn_reply(c);
        return;
    }
    commit_start(c, apply_committed);
}

/* Шаг 3 apply: ядро приняло изменившиеся части — или нет, и тогда прежняя спека возвращается на
 * место. */
static void apply_committed(struct conn *c, int code) {
    struct ctl_srv *s = c->srv;
    struct job *j = &c->job;
    const char *spec = s->cf.spec;
    struct cbuf out, err;
    commit_output(c, &out, &err);
    if (code != 0 || (c->committed && j->timed_out)) {
        /* Что успело встать до отказа, не знаем (ядро отвергло набор — ничего, срок вышел посреди
         * маршрутизации — часть): следующий apply применит всё. */
        recon_forget(&s->rec);
        int rolled = 0;
        if (c->had_old == 1) {
            char t2[PATH_MAX];
            if (ctl_write_tmp(spec, c->old.p, c->old.n, t2, sizeof(t2)) == 0) {
                if (rename(t2, spec) == 0) rolled = 1;
                else unlink(t2);
            }
        } else if (c->had_old == 0) {
            rolled = unlink(spec) == 0;
        }
        if (rolled) ctl_fsync_dir(spec);
        else cb_str(&err, LOG_W "прежнюю спеку вернуть не удалось — на диске новая\n");
        fprintf(stderr, LOG_W "apply отвергнут (код %d)%s\n", code,
                rolled ? " — прежняя спека возвращена" : "");
        resp_run(&c->resp, code < 0 ? 127 : code, &out, &err);
        resp_bool(&c->resp, "saved", !rolled);
        resp_bool(&c->resp, "applied", 0);
        resp_bool(&c->resp, "enabled", 1);
        resp_bool(&c->resp, "rolled_back", rolled);
        if (c->committed && j->timed_out)
            resp_error(&c->resp, "timeout", "применение не уложилось в свой срок и остановлено");
        /* Вернуть не удалось — на диске новая спека, и память идёт за диском (молча: в ядре
         * она не стоит, события applied нет). */
        if (!rolled) steerd_load(&s->d);
        free(out.p);
        free(err.p);
        conn_reply(c);
        return;
    }
    recon_applied(&s->rec, &c->plan, &c->diff);
    fprintf(stderr, LOG_I "спека применена%s\n", c->committed ? "" : " (в ядре менять нечего)");
    resp_run(&c->resp, 0, &out, &err);
    free(out.p);
    free(err.p);
    resp_bool(&c->resp, "saved", 1);
    resp_bool(&c->resp, "applied", 1);
    resp_bool(&c->resp, "enabled", 1);
    c->after_reload = apply_finish;
    reload_begin(c);
}

/* apply — приложение присылает спеку ЦЕЛИКОМ; демон проверяет её, атомарно кладёт на место и
 * применяет то, что в ней изменилось. Порядок и доводы:
 *
 *   1. Очередь изменяющих команд (см. «ИСПОЛНЕНИЕ» в шапке).
 *   2. Кандидат — во временный файл рядом со спекой и `apply-plan` по нему: те же проверки, что
 *      у `apply --dry-run`, и отпечатки частей (набор правил, маршрутизация выходов). Отказ —
 *      временный файл удаляется, spec.json не тронут; в ответе код и stderr проверки,
 *      "saved":false.
 *   3. Прежняя спека читается в память — на случай отката в п. 5 — и кандидат становится
 *      spec.json переименованием: снаружи виден либо прежний файл, либо новый целиком.
 *   4. Движок выключен — на этом всё: "saved":true, "applied":false, "enabled":false.
 *      Правила поставит init, когда движок включат (см. ctl_enabled).
 *   5. Сверка с применённым (recon.c): изменившиеся части — `apply-commit` (набор правил одной
 *      транзакцией, привязка изменившихся выходов, снятие правил убранных); не изменилось ничего
 *      — в ядро демон не идёт вовсе. Отказ (ядро не приняло набор — план ядро не спрашивает) —
 *      прежняя спека возвращается на место, и в ядре, и на диске остаётся то, что было: иначе
 *      init повторял бы отвергнутую спеку на каждой загрузке и перезапуске netd.
 *      "saved":false, "rolled_back":true.
 *   6. Успех — перечитать спеку резолвером и супервизором (как reload), "reload" в ответе.
 *
 * После п. 4 и п. 6 демон перечитывает спеку в память и шлёт подписчикам applied; в ответе и в
 * событии — поле changed. */
static void st_apply(struct conn *c) {
    if (ctl_write_tmp(c->srv->cf.spec, c->q.body, c->q.body_n, c->tmp, sizeof(c->tmp)) != 0) {
        resp_error(&c->resp, "internal", "не удалось записать временный файл спеки");
        conn_reply(c);
        return;
    }
    if (plan_start(c, c->tmp, apply_planned) != 0) {
        unlink(c->tmp);
        resp_error(&c->resp, "internal", "не удалось запустить движок");
        conn_reply(c);
    }
}

/* ---- reload ------------------------------------------------------------------------------ */

/* Процессы этого же движка с подкомандой sub: /proc/<pid>/exe совпадает с нашим, а второе
 * слово командной строки — sub. Искать по исполняемому файлу, а не по имени процесса:
 * имя подделать может любой, а на телефоне к тому же SELinux пускает steerd читать /proc
 * только своего домена (r_dir_file(domain, self)) — чужие процессы здесь не видны вовсе.
 * pid-файлов резолвер и супервизор не пишут, а заводить их ради этого — ещё одна вещь,
 * способная устареть (процесс умер, файл остался, сигнал ушёл чужому pid). */
static int ctl_find(const char *exe, const char *sub, pid_t *out, int max) {
    DIR *d = opendir("/proc");
    if (!d) return 0;
    int n = 0;
    pid_t me = getpid();
    struct dirent *e;
    while ((e = readdir(d)) && n < max) {
        char *end = NULL;
        long p = strtol(e->d_name, &end, 10);
        if (!end || *end || p <= 0 || p == me) continue;
        char path[64], link[PATH_MAX];
        snprintf(path, sizeof(path), "/proc/%ld/exe", p);
        ssize_t l = readlink(path, link, sizeof(link) - 1);
        if (l <= 0) continue;
        link[l] = '\0';
        if (strcmp(link, exe) != 0) continue;
        snprintf(path, sizeof(path), "/proc/%ld/cmdline", p);
        int fd = open(path, O_RDONLY | O_CLOEXEC);
        if (fd < 0) continue;
        char cl[256];
        ssize_t m = read(fd, cl, sizeof(cl) - 1);
        close(fd);
        if (m <= 0) continue;
        cl[m] = '\0';
        size_t a0 = strlen(cl);
        if ((ssize_t)a0 + 1 >= m) continue;
        if (strcmp(cl + a0 + 1, sub) != 0) continue;
        out[n++] = (pid_t)p;
    }
    closedir(d);
    return n;
}

static void ctl_rstrip(struct cbuf *b) {
    while (b->n && (b->p[b->n - 1] == '\n' || b->p[b->n - 1] == '\r')) b->p[--b->n] = '\0';
}

/* Перечитать спеку резолвером и супервизором помощников — поле "reload" ответа.
 *
 * РЕЗОЛВЕР — тем же решением, что init-скрипт роутера (files/etc/init.d/steer, reload_dnsd):
 * подпись таблицы каналов по новой спеке (`steer dnsd-sig`, ребёнком) сравнивается с той, что
 * резолвер положил в dnsd.sig при запуске. Совпали — SIGHUP: списки перечитываются без потери
 * запросов. Разошлись или подписи нет — SIGTERM: состав каналов HUP не пересобирает, а init
 * поднимает вышедший сервис заново (он не oneshot). "hup" | "restart" | "none" (не запущен).
 *
 * СУПЕРВИЗОР — SIGHUP: сверить состав помощников со спекой; помощник выхода, у которого
 * изменились параметры, перезапускается им же (см. cmd_supervise). "hup" | "none".
 *
 * Кончив, зовёт c->after_reload. */
static void reload_finish(struct conn *c, const char *dn) {
    pid_t pids[8];
    const char *sv = "none";
    int k = ctl_find(c->srv->cf.exe, "supervise", pids, 8);
    for (int i = 0; i < k; i++) kill(pids[i], SIGHUP);
    if (k > 0) sv = "hup";
    cb_fmt(&c->resp, ",\"reload\":{\"dnsd\":\"%s\",\"outputs\":\"%s\"}", dn, sv);
    c->after_reload(c);
}

static void reload_sig(struct conn *c, int code) {
    struct job *j = &c->job;
    struct cbuf run = {0};
    char sp[PATH_MAX];
    snprintf(sp, sizeof(sp), "%s/dnsd.sig", ctl_state_dir(&c->srv->cf));
    int have = ctl_read_file(sp, &run, CTL_OUT_MAX) == 1;
    ctl_rstrip(&j->out);
    ctl_rstrip(&run);
    int same = code == 0 && !j->timed_out && have && run.n && j->out.n == run.n &&
               !memcmp(j->out.p, run.p, run.n);
    for (int i = 0; i < c->dn_n; i++) kill(c->dn[i], same ? SIGHUP : SIGTERM);
    free(run.p);
    reload_finish(c, same ? "hup" : "restart");
}

static void reload_begin(struct conn *c) {
    struct ctl_srv *s = c->srv;
    /* --supervise: резолвер и помощники — дети демона, и искать их по /proc незачем (а сигнал
     * резолверу на таблице был бы ошибкой: dnsd.sig он не пишет, и сверка подписей всегда
     * давала бы TERM). Новую таблицу и сверку помощников делает supd_spec_changed, когда демон
     * перечитает спеку (after_reload → srv_spec_changed). */
    if (s->d.sup) {
        cb_str(&c->resp, ",\"reload\":{\"dnsd\":\"table\",\"outputs\":\"daemon\"}");
        c->after_reload(c);
        return;
    }
    c->dn_n = ctl_find(s->cf.exe, "dnsd", c->dn, 8);
    if (c->dn_n <= 0) { reload_finish(c, "none"); return; }
    char *av[8];
    size_t n = 0;
    av[n++] = s->cf.exe;
    av[n++] = "dnsd-sig";
    av[n++] = "--spec";
    av[n++] = (char *)s->cf.spec;
    if (s->cf.state_dir) { av[n++] = "--state-dir"; av[n++] = (char *)s->cf.state_dir; }
    av[n] = NULL;
    if (job_start(c, av, 30, CTL_OUT_MAX, CTL_ERR_MAX, reload_sig) != 0) {
        memset(&c->job.out, 0, sizeof(c->job.out));
        reload_sig(c, -1);
    }
}

static void reload_done(struct conn *c) {
    srv_spec_changed(c->srv, "reload", ctl_enabled(), &c->diff, c->watch, &c->resp);
    conn_reply(c);
}

/* Голова ответа reload: код (не 0 — ядро не приняло набор или план не прошёл, причина в
 * stderr), выключатель. Дальше — прежние шаги reload. */
static void reload_head(struct conn *c, int enabled, struct cbuf *err) {
    if (c->boot) {
        if (c->rcode != 0)
            fprintf(stderr, LOG_W "применение при старте не прошло (код %d)%s%.*s", c->rcode,
                    err && err->n ? ":\n" : "\n", err ? (int)err->n : 0,
                    err && err->p ? err->p : "");
        else if (enabled)
            fprintf(stderr, LOG_I "спека применена при старте\n");
    }
    cb_fmt(&c->resp, ",\"code\":%d", c->rcode);
    if (c->rcode != 0) {
        cb_utf8_trim(err);
        cb_str(&c->resp, ",\"stderr\":");
        cb_json(&c->resp, err->p ? err->p : "", err->n);
    }
    resp_bool(&c->resp, "enabled", enabled);
    c->after_reload = reload_done;
    reload_begin(c);
}

static void reload_committed(struct conn *c, int code) {
    struct cbuf out, err;
    commit_output(c, &out, &err);
    if (code != 0 || (c->committed && c->job.timed_out)) {
        /* Спеки на откат у reload нет: на диске она та же. Ядро отвергло набор — прежний стоит;
         * что успело встать до срока — не знаем. Остальное reload делает, как прежде. */
        recon_forget(&c->srv->rec);
        c->rcode = code < 0 ? 127 : code;
        memset(&c->diff, 0, sizeof(c->diff));
        fprintf(stderr, LOG_W "reload: применение не прошло (код %d)\n", code);
    } else {
        recon_applied(&c->srv->rec, &c->plan, &c->diff);
    }
    free(out.p);
    reload_head(c, 1, &err);
    free(err.p);
}

static void reload_planned(struct conn *c, int code) {
    struct job *j = &c->job;
    if (code != 0 || j->timed_out || plan_take(c) != 0) {
        /* Спека не проходит проверку (или план не разобран): в ядро не идём, остальное — как
         * прежде (перечитывание само скажет spec-error, если спека не читается). */
        c->rcode = code > 0 ? code : 127;
        c->watch = 1;
        memset(&c->diff, 0, sizeof(c->diff));
        reload_head(c, 1, &j->err);
        return;
    }
    commit_start(c, reload_committed);
}

/* reload — то же, что apply, без новой спеки: сверка той, что на диске, с применённой (набор
 * правил, маршрутизация, помощники, таблица резолвера — только изменившееся), и перечитывание.
 * Движок выключен — в ядро не идём. */
static void st_reload(struct conn *c) {
    c->rcode = 0;
    if (!ctl_enabled()) {
        recon_forget(&c->srv->rec);
        c->watch = 1;
        memset(&c->diff, 0, sizeof(c->diff));
        reload_head(c, 0, NULL);
        return;
    }
    if (plan_start(c, c->srv->cf.spec, reload_planned) != 0) {
        struct cbuf e = {0};
        cb_str(&e, LOG_W "не удалось запустить движок\n");
        c->rcode = 127;
        c->watch = 1;
        memset(&c->diff, 0, sizeof(c->diff));
        reload_head(c, 1, &e);
        free(e.p);
    }
}

/* ---- файлы списков: put-file, list-files, rm-file --------------------------------------------
 *
 * ЗАЧЕМ. Спека ссылается на файлы — списки доменов и подсетей (domains_files, prefixes_files),
 * файл подписки выхода VLESS, — и движок читает их сам, по путям из спеки. На роутере их
 * кладёт в /etc/steer управляющий слой splify2 (rpcd), на телефоне так нельзя: приложение
 * splify2 в каталог движка писать не может (SELinux: steerd_data_file ему закрыт целиком, см.
 * neverallow в vendor/der/sepolicy/private/steerd.te), и открывать его значило бы открыть и
 * спеку, и состояние. Поэтому файлы идут через ту же дверь, что спека: приложение скачивает
 * список, присылает его телом put-file, сервер кладёт его в lists_dir платформы, а в спеку
 * приложение пишет путь, который вернул ответ.
 *
 * Разбор спеки этим не ограничен: спека с путями ВНЕ каталога списков по-прежнему законна
 * (adb root shell, стенд, файлы, положенные руками). Каталог — место, куда может писать
 * приложение, а не единственное место, откуда может читать движок.
 *
 * АТОМАРНОСТЬ. Файл пишется во временный рядом (.put-XXXXXX в том же каталоге: rename атомарен
 * только внутри одной файловой системы), с fsync, и становится <имя> переименованием. Резолвер
 * перечитывает списки по SIGHUP в любой момент, apply читает их при применении, — и оба видят
 * либо прежний файл целиком, либо новый целиком, но не обрубок на середине записи. Имя
 * временного файла начинается с точки, а имя от приложения точкой начинаться не может
 * (CA_FILE): совпасть им негде, и list-files точечные имена не показывает. Временный файл,
 * оставшийся от демона, убитого посреди записи, убирает он же при старте (ctl_lists_sweep) —
 * в это время ни одной записи ещё не идёт, и убрать чужой живой файл нельзя.
 *
 * Очередь изменяющих команд put-file не ждёт: замена файла атомарна, и apply, идущий рядом,
 * прочтёт прежний или новый — то же, что при записи до или после него. rm-file идёт в ней:
 * он сверяется с сохранённой спекой, и сверка имеет смысл, только пока спеку никто не
 * меняет (см. ctl_do_rm_file). */

/* Сколько файлов и байт в каталоге списков, не считая временных и файла skip (его put-file
 * сейчас заменит, и его прежний размер в итог не входит). */
static void ctl_lists_usage(const char *dir, const char *skip, int *files, long long *bytes) {
    *files = 0;
    *bytes = 0;
    DIR *d = opendir(dir);
    if (!d) return;
    struct dirent *e;
    while ((e = readdir(d))) {
        if (e->d_name[0] == '.' || (skip && !strcmp(e->d_name, skip))) continue;
        struct stat sb;
        if (fstatat(dirfd(d), e->d_name, &sb, AT_SYMLINK_NOFOLLOW) != 0 || !S_ISREG(sb.st_mode))
            continue;
        (*files)++;
        *bytes += (long long)sb.st_size;
    }
    closedir(d);
}

/* Убрать временные файлы put-file, брошенные убитым обработчиком. Только при старте сервера. */
static void ctl_lists_sweep(const char *dir) {
    DIR *d = opendir(dir);
    if (!d) return;
    struct dirent *e;
    while ((e = readdir(d)))
        if (!strncmp(e->d_name, ".put-", 5)) unlinkat(dirfd(d), e->d_name, 0);
    closedir(d);
}

/* put-file <имя> <длина> + тело — положить файл в каталог списков.
 * Ответ: "code":0, "name", "size" (байт) и "path" — полный путь, который пишется в спеку. */
static void ctl_do_put_file(struct conn *c, struct cbuf *r) {
    const struct ctl_req *q = &c->q;
    const char *dir = q->cf->lists_dir, *name = q->argv[0];
    /* Каталог — при первом put, 0700: владелец движок, остальным (и shell) в нём делать нечего,
     * как в state и tmp. Родитель (каталог спеки) создан init-ом. */
    if (mkdir(dir, 0700) != 0 && errno != EEXIST) {
        resp_error(r, "internal", "не удалось создать каталог списков");
        return;
    }
    struct stat sb;
    if (stat(dir, &sb) != 0 || !S_ISDIR(sb.st_mode)) {
        resp_error(r, "internal", "каталог списков — не каталог");
        return;
    }
    int files;
    long long bytes;
    ctl_lists_usage(dir, name, &files, &bytes);
    if (files >= CTL_FILES_MAX) {
        resp_error(r, "too-large", "в каталоге списков уже 256 файлов — уберите ненужные (rm-file)");
        return;
    }
    if (bytes + (long long)q->body_n > CTL_FILES_TOTAL) {
        resp_error(r, "too-large", "файлы списков заняли бы больше 128 МиБ — уберите ненужные (rm-file)");
        return;
    }
    char path[PATH_MAX], tmp[PATH_MAX];
    if ((size_t)snprintf(path, sizeof(path), "%s/%s", dir, name) >= sizeof(path) ||
        (size_t)snprintf(tmp, sizeof(tmp), "%s/.put-XXXXXX", dir) >= sizeof(tmp)) {
        resp_error(r, "internal", "слишком длинный путь каталога списков");
        return;
    }
    int fd = mkostemp(tmp, O_CLOEXEC);          /* создаётся с правами 0600 */
    if (fd < 0) {
        resp_error(r, "internal", "не удалось создать временный файл в каталоге списков");
        return;
    }
    int ok = ctl_write_all(fd, q->body, q->body_n) == 0 && fsync(fd) == 0;
    if (close(fd) != 0) ok = 0;
    if (!ok || rename(tmp, path) != 0) {
        unlink(tmp);
        resp_error(r, "internal", "не удалось записать файл (нет места?)");
        return;
    }
    ctl_fsync_dir(path);
    fprintf(stderr, LOG_I "положен файл %s (%zu байт)\n", name, q->body_n);
    cb_fmt(r, ",\"code\":0,\"name\":");
    cb_jstr(r, name);
    cb_fmt(r, ",\"size\":%zu,\"path\":", q->body_n);
    cb_jstr(r, path);
}

static int ctl_name_cmp(const void *a, const void *b) {
    return strcmp(*(char *const *)a, *(char *const *)b);
}

/* list-files — что лежит в каталоге списков: "files":[{"name","size","mtime"}], по имени.
 * mtime — секунды Unix (время последнего put-file этого имени). Каталога ещё нет — пустой
 * список: для приложения это то же самое, что «ничего не залито». */
static void ctl_do_list_files(struct conn *c, struct cbuf *r) {
    const struct ctl_req *q = &c->q;
    const char *dir = q->cf->lists_dir;
    cb_str(r, ",\"code\":0,\"dir\":");
    cb_jstr(r, dir);
    cb_str(r, ",\"files\":[");
    DIR *d = opendir(dir);
    char *names[CTL_FILES_MAX * 2];
    size_t n = 0;
    if (d) {
        struct dirent *e;
        while ((e = readdir(d)) && n < sizeof(names) / sizeof(names[0])) {
            if (e->d_name[0] == '.') continue;
            names[n] = strdup(e->d_name);
            if (names[n]) n++;
        }
    }
    qsort(names, n, sizeof(names[0]), ctl_name_cmp);
    int first = 1;
    for (size_t i = 0; i < n; i++) {
        struct stat sb;
        if (fstatat(dirfd(d), names[i], &sb, AT_SYMLINK_NOFOLLOW) == 0 && S_ISREG(sb.st_mode)) {
            cb_str(r, first ? "{\"name\":" : ",{\"name\":");
            cb_jstr(r, names[i]);
            cb_fmt(r, ",\"size\":%lld,\"mtime\":%lld}", (long long)sb.st_size,
                   (long long)sb.st_mtime);
            first = 0;
        }
        free(names[i]);
    }
    if (d) closedir(d);
    cb_str(r, "]");
}

/* Упомянут ли путь в тексте спеки — строкой JSON, как его пишет приложение ("…/lists/имя"),
 * или с экранированными косыми ("…\/lists\/имя": так пишут некоторые сериализаторы JSON). */
static int ctl_spec_mentions(const struct cbuf *spec, const char *path) {
    char want[PATH_MAX + 2], esc[2 * PATH_MAX + 2];
    snprintf(want, sizeof(want), "\"%s\"", path);
    size_t k = 0;
    esc[k++] = '"';
    for (const char *p = path; *p && k + 3 < sizeof(esc); p++) {
        if (*p == '/') esc[k++] = '\\';
        esc[k++] = *p;
    }
    esc[k++] = '"';
    esc[k] = '\0';
    return spec->p && (strstr(spec->p, want) || strstr(spec->p, esc));
}

/* rm-file <имя> — убрать файл из каталога списков. Ответ: "code":0, "name", "removed" (false —
 * такого файла и не было: повторное удаление не ошибка, приложению незачем помнить, что оно
 * уже убрало).
 *
 * ФАЙЛ, НА КОТОРЫЙ ССЫЛАЕТСЯ СОХРАНЁННАЯ СПЕКА, НЕ УДАЛЯЕТСЯ — отказ "in-use". Цена ошибки
 * порядка («сначала убрать файл, потом применить спеку без него» вместо обратного, или apply,
 * который не прошёл и вернул прежнюю спеку) — движок, который перестаёт подниматься: init
 * применяет сохранённую спеку на каждой загрузке и после каждого перезапуска netd, а спека с
 * пропавшим файлом списка к применению уже не годится, и резолвер перестаёт узнавать имена
 * канала. Команда идёт в очереди изменяющих: пока она исполняется, apply ждёт, и «не упомянут»
 * остаётся правдой до самого unlink. */
static void ctl_do_rm_file(struct conn *c, struct cbuf *r) {
    const struct ctl_req *q = &c->q;
    const char *name = q->argv[0];
    char path[PATH_MAX];
    if ((size_t)snprintf(path, sizeof(path), "%s/%s", q->cf->lists_dir, name) >= sizeof(path)) {
        resp_error(r, "internal", "слишком длинный путь каталога списков");
        return;
    }
    struct cbuf spec = {0};
    int have = ctl_read_file(q->cf->spec, &spec, 4 * CTL_BODY_MAX);
    if (have < 0) {
        resp_error(r, "internal", "не удалось прочитать сохранённую спеку");
    } else if (have == 1 && ctl_spec_mentions(&spec, path)) {
        resp_error(r, "in-use", "файл упомянут в сохранённой спеке — сначала примените спеку без него");
    } else {
        int removed = unlink(path) == 0;
        if (!removed && errno != ENOENT) {
            resp_error(r, "internal", "не удалось удалить файл");
        } else {
            if (removed) {
                ctl_fsync_dir(path);
                fprintf(stderr, LOG_I "убран файл %s\n", name);
            }
            cb_str(r, ",\"code\":0,\"name\":");
            cb_jstr(r, name);
            resp_bool(r, "removed", removed);
        }
    }
    free(spec.p);
}

static void sub_check_done(struct conn *c, int code) {
    unlink(c->tmp);
    if (code < 0) { resp_error(&c->resp, "internal", "не удалось дождаться движка"); conn_reply(c); return; }
    resp_run(&c->resp, code, &c->job.out, &c->job.err);
    if (c->job.timed_out) resp_error(&c->resp, "timeout", "разбор подписки не уложился в свой срок и остановлен");
    conn_reply(c);
}

/* sub-check <длина> + тело — разобрать присланный файл подписки, ничего не сохраняя: сколько
 * узлов пригодно, сколько пропущено и почему. Нужно приложению ДО того, как подписка станет
 * файлом выхода: скачав её, логика показывает человеку «пригодно 12, пропущено 3 — ws не
 * поддерживается» и решает, заливать ли (put-file).
 *
 * Разбирает не демон, а `steer vless-nodes <файл>` ребёнком — та же подкоманда, тем же
 * разбором (vless_parse_sub), что и подъём выхода: второй разбор «для проверки» разошёлся бы с
 * тем, которым узлы потом поднимаются. Тело кладётся во временный файл каталога времянок
 * движка (путь абсолютный — по нему vless-nodes отличает файл от имени выхода) и удаляется
 * сразу после разбора. В ответе — код и вывод подкоманды как есть; поле sub_file в её JSON —
 * имя этого временного файла, для приложения оно ничего не значит. В базовой сборке (без
 * VLESS) подкоманда честно отказывает кодом 2, как vless-nodes. */
static void st_sub_check(struct conn *c) {
    char stem[PATH_MAX];
    snprintf(stem, sizeof stem, "%s/sub-check", plat()->tmp_dir);
    if (ctl_write_tmp(stem, c->q.body, c->q.body_n, c->tmp, sizeof(c->tmp)) != 0) {
        resp_error(&c->resp, "internal", "не удалось записать временный файл подписки");
        conn_reply(c);
        return;
    }
    char *av[4] = { c->srv->cf.exe, "vless-nodes", c->tmp, NULL };
    if (job_start(c, av, 15, CTL_OUT_MAX, CTL_ERR_MAX, sub_check_done) != 0) {
        unlink(c->tmp);
        resp_error(&c->resp, "internal", "не удалось запустить движок");
        conn_reply(c);
    }
}

/* ---- subscribe ------------------------------------------------------------------------------
 *
 * Подписчик — соединение, которое после ответа не закрывается: демон дописывает в него
 * события (steerd_emit, state.h), строка JSON на событие. Ответ на сам subscribe — обычная
 * строка {"v":1,"cmd":"subscribe","code":0,"spec":"<отпечаток>"}: с чем подписчик начинает.
 *
 * Очередь событий — тот же буфер, что у ответа, с пределом CTL_SUBQ_MAX: запись неблокирующая,
 * что сокет не принял, ждёт EPOLLOUT; событие, которое не влезло бы, отключает подписчика
 * (см. CTL_SUBQ_MAX). Что подписчик пишет после subscribe, демон читает и выбрасывает; конец
 * его записи (shutdown) — не уход: `steer ctl subscribe` полузакрывает запись сразу после
 * запроса и ждёт событий. Уход — это EPOLLHUP или ошибка записи. */
static void sub_push(struct steerd_sub *sb, const char *line, size_t n) {
    struct conn *c = sb->arg;
    size_t pending = c->resp.n - c->off;
    if (pending + n > CTL_SUBQ_MAX) {
        fprintf(stderr, LOG_W "подписчик не забирает события (в очереди %zu байт) — отключён\n",
                pending);
        conn_free(c);
        return;
    }
    if (c->off) {
        memmove(c->resp.p, c->resp.p + c->off, pending);
        c->resp.n = pending;
        c->off = 0;
    }
    cb_put(&c->resp, line, n);
    conn_flush(c);
}

static void st_subscribe(struct conn *c) {
    struct ctl_srv *s = c->srv;
    if (s->subs >= CTL_SUBS_MAX) {
        resp_error(&c->resp, "busy", "подписчиков уже восемь — повторите позже");
        conn_reply(c);
        return;
    }
    if (c->counted) { c->counted = 0; s->active--; }
    s->subs++;
    c->st = C_SUB;
    loop_timer_stop(c->tm);
    int sb = CTL_SUB_SNDBUF;
    setsockopt(c->fd, SOL_SOCKET, SO_SNDBUF, &sb, sizeof(sb));
    cb_str(&c->resp, ",\"code\":0");
    if (s->d.have) cb_fmt(&c->resp, ",\"spec\":\"%s\"", s->d.fp);
    cb_str(&c->resp, "}\n");
    c->off = 0;
    c->sub.push = sub_push;
    c->sub.arg = c;
    steerd_sub_add(&s->d, &c->sub);
    conn_flush(c);
}

/* ---- запрос ------------------------------------------------------------------------------------ */

/* Строка запроса пришла целиком: разобрать слова, проверить их по таблице, завести тело.
 * 0 — можно читать тело или исполнять; -1 — отказ уже отдан. */
static int conn_parse(struct conn *c) {
    char *tok[6];
    int nt = 0;
    for (char *s = c->line; nt < 6; ) {
        char *sp = strchr(s, ' ');
        if (sp) *sp = '\0';
        tok[nt++] = s;
        if (!sp) break;
        s = sp + 1;
        if (nt == 6) { conn_refuse(c, NULL, "bad-request", "слишком много слов в запросе"); return -1; }
    }
    for (int i = 0; i < nt; i++)
        if (!tok[i][0]) { conn_refuse(c, NULL, "bad-request", "пустое слово: слова разделяются одним пробелом"); return -1; }
    const struct ctl_cmd *cmd = ctl_lookup(tok[0]);
    if (!cmd) { conn_refuse(c, NULL, "unknown-command", "такой команды нет"); return -1; }

    memset(&c->q, 0, sizeof(c->q));
    c->q.cmd = cmd;
    c->q.cf = &c->srv->cf;
    int na = nt - 1;
    size_t blen = 0;
    if (cmd->body) {
        if (na < 1) { conn_refuse(c, cmd->name, "bad-request", "нужна длина тела последним словом"); return -1; }
        const char *w = tok[nt - 1];
        size_t wl = strlen(w);
        if (wl > 10 || strspn(w, "0123456789") != wl) {
            conn_refuse(c, cmd->name, "bad-request", "длина тела — десятичное число байт");
            return -1;
        }
        unsigned long long v = strtoull(w, NULL, 10);
        if (v > (unsigned long long)cmd->body) {
            char m[64];
            snprintf(m, sizeof(m), "тело больше %ld МиБ", cmd->body / (1024 * 1024));
            conn_refuse(c, cmd->name, "too-large", m);
            return -1;
        }
        blen = (size_t)v;
        na--;
    }
    if (na < cmd->argmin || na > cmd->argmax) {
        conn_refuse(c, cmd->name, "bad-request", "не то число слов у команды");
        return -1;
    }
    for (int i = 0; i < na; i++) {
        const char *why = ctl_arg_bad(&cmd->args[i], tok[i + 1]);
        if (why) { conn_refuse(c, cmd->name, "bad-request", why); return -1; }
        c->q.argv[i] = tok[i + 1];     /* указывают в c->line — живёт до конца соединения */
    }
    c->q.argc = na;
    if (cmd->body) {
        c->body = malloc(blen + 1);
        if (!c->body) { conn_refuse(c, cmd->name, "internal", "нет памяти под тело"); return -1; }
        c->body_want = blen;
        c->body_got = 0;
    }
    return 0;
}

/* Запрос прочитан: исполнить сейчас или встать в очередь изменяющих. */
static void conn_dispatch(struct conn *c) {
    struct ctl_srv *s = c->srv;
    loop_timer_stop(c->tm);
    /* Пока команда идёт, из сокета не читаем: всё, что клиент пришлёт сверх запроса, дочитает
     * conn_drain после ответа. Уход клиента (EPOLLHUP) epoll сообщает и так. */
    conn_events(c, 0);
    if (c->body) {
        c->body[c->body_got] = '\0';
        c->q.body = c->body;
        c->q.body_n = c->body_got;
    }
    resp_begin(&c->resp, c->q.cmd->name);
    if (c->q.cmd->lock && s->lock_owner) {
        c->st = C_WAIT;
        struct conn **pp = &s->lockq;
        while (*pp) pp = &(*pp)->qnext;
        *pp = c;
        return;
    }
    conn_exec(c);
}

static void conn_exec(struct conn *c) {
    const struct ctl_cmd *k = c->q.cmd;
    if (k->lock) c->srv->lock_owner = c;
    c->st = C_RUN;
    if (k->fn) { k->fn(c, &c->resp); conn_reply(c); }
    else if (k->start) k->start(c);
    else st_sub(c);
}

/* Читать запрос, сколько пришло. Строка — кусками, и то, что пришло за '\n', — начало тела:
 * обработчик больше не читает по байту (там это было ради того, чтобы не захватить тело), —
 * лишнее просто переносится в тело. */
static void conn_read_req(struct conn *c) {
    char buf[4096];
    for (;;) {
        if (c->have_line) {
            size_t want = c->body_want - c->body_got;
            if (!want) { conn_dispatch(c); return; }
            ssize_t m = recv(c->fd, c->body + c->body_got, want, MSG_DONTWAIT);
            if (m < 0 && errno == EINTR) continue;
            if (m < 0 && (errno == EAGAIN || errno == EWOULDBLOCK)) return;
            if (m < 0) { conn_free(c); return; }
            if (m == 0) {
                conn_refuse(c, c->q.cmd->name, "bad-request", "тело не пришло целиком за 5 секунд");
                return;
            }
            c->body_got += (size_t)m;
            continue;
        }
        ssize_t m = recv(c->fd, buf, sizeof(buf), MSG_DONTWAIT);
        if (m < 0 && errno == EINTR) continue;
        if (m < 0 && (errno == EAGAIN || errno == EWOULDBLOCK)) return;
        if (m < 0) { conn_free(c); return; }
        if (m == 0) { conn_refuse(c, NULL, "bad-request", "запрос не пришёл целиком за 5 секунд"); return; }
        char *nl = memchr(buf, '\n', (size_t)m);
        size_t take = nl ? (size_t)(nl - buf) : (size_t)m;
        if (c->line_n + take > CTL_LINE_MAX) {
            conn_refuse(c, NULL, "too-large", "строка запроса длиннее 512 байт");
            return;
        }
        memcpy(c->line + c->line_n, buf, take);
        c->line_n += take;
        if (!nl) continue;
        if (c->line_n && c->line[c->line_n - 1] == '\r') c->line_n--;
        c->line[c->line_n] = '\0';
        c->have_line = 1;
        if (conn_parse(c) != 0) return;
        if (!c->q.cmd->body) { conn_dispatch(c); return; }
        size_t rest = (size_t)m - take - 1;
        if (rest > c->body_want) rest = c->body_want;
        memcpy(c->body, nl + 1, rest);
        c->body_got = rest;
    }
}

static void conn_timer(struct loop *l, struct loop_timer *t, void *arg) {
    (void)l; (void)t;
    struct conn *c = arg;
    switch (c->st) {
    case C_REQ:
        if (c->have_line)
            conn_refuse(c, c->q.cmd->name, "bad-request", "тело не пришло целиком за 5 секунд");
        else
            conn_refuse(c, NULL, "bad-request", "запрос не пришёл целиком за 5 секунд");
        break;
    case C_SEND:
    case C_DRAIN:
        conn_free(c);
        break;
    default:
        break;
    }
}

static void conn_ev(struct loop *l, int fd, uint32_t ev, void *arg) {
    (void)fd;
    struct conn *c = arg;
    int gone = (ev & (EPOLLHUP | EPOLLERR)) != 0;
    switch (c->st) {
    case C_REQ:
        conn_read_req(c);
        break;
    case C_WAIT:
    case C_RUN:
        /* Клиент ушёл, пока команда шла или ждала очереди. Ждущему — выйти из очереди сразу;
         * идущую — довести (apply посреди шагов не бросают), а ответ не отдавать. Дескриптор
         * снимается с epoll: иначе HUP будил бы демон на каждом обороте до конца команды. */
        if (!gone) break;
        if (c->st == C_WAIT) { conn_free(c); break; }
        loop_fd_del(l, c->fd);
        c->hup = 1;
        break;
    case C_SEND:
        if (ev & EPOLLOUT) conn_flush(c);
        else if (gone) conn_free(c);
        break;
    case C_DRAIN:
        conn_drain(c);
        break;
    case C_SUB:
        if (ev & EPOLLOUT) { if (conn_flush(c) != 0) break; }
        if (ev & EPOLLIN) {
            char buf[512];
            for (;;) {
                ssize_t m = recv(c->fd, buf, sizeof(buf), MSG_DONTWAIT);
                if (m > 0) continue;
                if (m < 0 && errno == EINTR) continue;
                if (m == 0) {
                    c->eof = 1;
                    conn_events(c, c->off < c->resp.n ? EPOLLOUT : 0);
                }
                break;
            }
        }
        if (gone) conn_free(c);
        break;
    }
}

static void conn_free(struct conn *c) {
    struct ctl_srv *s = c->srv;
    if (c->st == C_SUB) { steerd_sub_del(&s->d, &c->sub); s->subs--; }
    if (c->counted) s->active--;
    for (struct conn **pp = &s->lockq; *pp; pp = &(*pp)->qnext)
        if (*pp == c) { *pp = c->qnext; break; }
    for (struct conn **pp = &s->conns; *pp; pp = &(*pp)->next)
        if (*pp == c) { *pp = c->next; break; }
    if (s->lock_owner == c) lock_release(s);
    if (!c->hup) loop_fd_del(s->l, c->fd);
    if (c->fd >= 0) close(c->fd);
    loop_timer_free(c->tm);
    loop_timer_free(c->job.tm);
    free(c->job.out.p);
    free(c->job.err.p);
    free(c->resp.p);
    free(c->old.p);
    free(c->perr.p);
    free(c->body);
    free(c);
}

/* ---- кого пускать ---------------------------------------------------------------------------- */

/* Домен из контекста SELinux «u:r:ДОМЕН:s0:c...» — третье поле. */
static int ctl_ctx_domain_is(const char *ctx, const char *dom) {
    const char *a = strchr(ctx, ':');
    if (!a) return 0;
    const char *b = strchr(a + 1, ':');
    if (!b) return 0;
    const char *e = strchr(b + 1, ':');
    size_t n = e ? (size_t)(e - (b + 1)) : strlen(b + 1);
    return n == strlen(dom) && !strncmp(b + 1, dom, n);
}

/* 1 — пустить. who — для журнала при отказе. */
static int ctl_peer_ok(int c, const struct ctl_conf *cf, char *who, size_t wn) {
    struct ucred uc;
    socklen_t l = sizeof(uc);
    if (getsockopt(c, SOL_SOCKET, SO_PEERCRED, &uc, &l) != 0) {
        snprintf(who, wn, "неизвестный собеседник (%s)", strerror(errno));
        return 0;
    }
    snprintf(who, wn, "uid %u pid %d", (unsigned)uc.uid, (int)uc.pid);
    if (uc.uid == 0 || uc.uid == CTL_AID_SYSTEM) return 1;
    for (int i = 0; i < cf->allow_uid_n; i++)
        if (cf->allow_uid[i] == uc.uid) return 1;
    if (cf->allow_domain && cf->allow_domain[0] && uc.uid < CTL_USER_RANGE) {
        char ctx[256];
        socklen_t cl = sizeof(ctx) - 1;
        if (getsockopt(c, SOL_SOCKET, SO_PEERSEC, ctx, &cl) == 0) {
            ctx[cl < sizeof(ctx) ? cl : sizeof(ctx) - 1] = '\0';
            if (ctl_ctx_domain_is(ctx, cf->allow_domain)) return 1;
            size_t wl = strlen(who);
            snprintf(who + wl, wn - wl, " %s", ctx);
        }
    }
    return 0;
}

/* ---- сервер ------------------------------------------------------------------------------------ */

static void srv_accept_resume(struct loop *l, struct loop_timer *t, void *arg) {
    (void)t;
    struct ctl_srv *s = arg;
    loop_fd_mod(l, s->lfd, EPOLLIN);
}

static void srv_accept(struct loop *l, int fd, uint32_t ev, void *arg) {
    (void)ev;
    struct ctl_srv *s = arg;
    for (;;) {
        int c = accept4(fd, NULL, NULL, SOCK_CLOEXEC | SOCK_NONBLOCK);
        if (c < 0) {
            if (errno == EINTR || errno == ECONNABORTED) continue;
            /* Нехватка дескрипторов или памяти не проходит сама за микросекунду, а соединение
             * так и ждёт в очереди — epoll будил бы демон сразу же, и он крутился бы вхолостую.
             * Приём снимается на 200 мс; в обычной работе сюда не попасть. */
            if (errno != EAGAIN && errno != EWOULDBLOCK) {
                loop_fd_mod(l, fd, 0);
                loop_timer_set(s->accept_tm, 200);
            }
            return;
        }
        char who[320];
        if (!ctl_peer_ok(c, &s->cf, who, sizeof(who))) {
            fprintf(stderr, LOG_W "отказ: %s\n", who);
            ctl_refuse_now(c, "denied", "этому процессу управлять движком нельзя");
            continue;
        }
        if (s->active >= CTL_CLIENTS_MAX) {
            ctl_refuse_now(c, "busy", "сервер занят другими запросами — повторите позже");
            continue;
        }
        struct conn *n = calloc(1, sizeof(*n));
        if (n) {
            n->srv = s;
            n->fd = c;
            n->job.po = n->job.pe = -1;
            n->tm = loop_timer_new(l, conn_timer, n);
        }
        if (!n || !n->tm || loop_fd_add(l, c, EPOLLIN, conn_ev, n) != 0) {
            if (n) loop_timer_free(n->tm);
            free(n);
            ctl_refuse_now(c, "internal", "не удалось начать обработку запроса");
            continue;
        }
        n->st = C_REQ;
        n->counted = 1;
        s->active++;
        n->next = s->conns;
        s->conns = n;
        loop_timer_set(n->tm, CTL_REQ_MS);
    }
}

/* Идёт изменяющая команда — сторож откладывает проход (watchd.h). */
static int srv_busy(void *arg) {
    return ((struct ctl_srv *)arg)->lock_owner != NULL;
}

/* Дети команд, которые ещё идут (apply, diag, vless-probe…): их группам процессов — SIGTERM,
 * через две секунды — SIGKILL. Раньше демон выходил, оставляя их доживать сиротами: `apply`
 * посреди nft или vless-probe на три минуты перебора. Ждёт сам — цикл уже не крутится. */
static void srv_jobs_stop(struct ctl_srv *s) {
    int any = 0;
    for (struct conn *c = s->conns; c; c = c->next)
        if (c->job.running) { kill(-c->job.pid, SIGTERM); any = 1; }
    long dl = loop_now_ms() + 2000;
    while (any) {
        any = 0;
        for (struct conn *c = s->conns; c; c = c->next) {
            struct job *j = &c->job;
            if (!j->running || j->reaped) continue;
            pid_t w = waitpid(j->pid, NULL, WNOHANG);
            if (w == j->pid || (w < 0 && errno == ECHILD)) { j->reaped = 1; continue; }
            if (loop_now_ms() < dl) { any = 1; continue; }
            kill(-j->pid, SIGKILL);
            kill(j->pid, SIGKILL);
            while (waitpid(j->pid, NULL, 0) < 0 && errno == EINTR) {}
            j->reaped = 1;
        }
        if (any) {
            struct timespec ts = { 0, 50000000L };
            nanosleep(&ts, NULL);
        }
    }
    /* Внуки, пережившие лидера группы (nft, запущенный командой), — туда же. */
    for (struct conn *c = s->conns; c; c = c->next)
        if (c->job.running) kill(-c->job.pid, SIGKILL);
}

static void srv_term(struct loop *l, int signo, void *arg) {
    (void)signo;
    struct ctl_srv *s = arg;
    struct stat sb;
    if (s->ino && stat(s->cf.sock, &sb) == 0 && sb.st_ino == s->ino) unlink(s->cf.sock);
    watchd_stop(s->watch);
    /* Детям команд — SIGTERM сразу: гаснут, пока демон по одному гасит помощников. */
    for (struct conn *c = s->conns; c; c = c->next)
        if (c->job.running) kill(-c->job.pid, SIGTERM);
    supd_stop(s->d.sup);
    srv_jobs_stop(s);
    loop_stop(l, 0);
}

/* SIGHUP — перечитать спеку в память, как после reload (без сигналов резолверу и супервизору:
 * им говорит reload). Идёт ли изменяющая команда — после неё (lock_release). */
static void srv_hup(struct loop *l, int signo, void *arg) {
    (void)l; (void)signo;
    struct ctl_srv *s = arg;
    if (s->lock_owner) s->hup_pending = 1;
    else srv_spec_changed(s, "hup", ctl_enabled(), NULL, 1, NULL);
}

/* --apply: применить спеку при старте демона — тем же reload, что по сокету, только без
 * соединения (итог — строкой в журнал, см. reload_head). Нужен одному сервису: procd на роутере
 * и init на телефоне держат один steerd, и отдельного `steer apply` перед ним больше нет. Через
 * сверку, а не подкомандой apply: демон тогда помнит применённое, и первое же «Применить» из
 * интерфейса трогает только изменившееся, а не ставит всё заново (наборы, которые наполнил
 * резолвер, при этом не опустошаются). Идёт в очереди изменяющих команд — apply, пришедший по
 * сокету сразу после старта, подождёт его. */
static void boot_apply(struct ctl_srv *s) {
    struct conn *c = calloc(1, sizeof(*c));
    if (!c) return;
    c->srv = s;
    c->fd = -1;
    c->hup = 1;          /* ответ отдавать некому: conn_reply освобождает соединение */
    c->boot = 1;
    c->st = C_RUN;
    c->q.cmd = ctl_lookup("reload");
    c->q.cf = &s->cf;
    c->next = s->conns;
    s->conns = c;
    resp_begin(&c->resp, "reload");
    conn_exec(c);
}

static void ctl_bad_flag(const char *cmd, const char *msg, const char *arg) {
    fprintf(stderr, "steer: %s: %s%s%s\n", cmd, msg, arg ? ": " : "", arg ? arg : "");
    exit(2);
}

void ctl_usage_flags(FILE *out) {
    const struct platform_ops *p = plat();
    fprintf(out,
          "  --socket ФАЙЛ       управляющий сокет (по умолчанию %s)\n"
          "  --spec ФАЙЛ         daemon: спека, которую читают и заменяют команды\n"
          "                      (по умолчанию %s)\n"
          "  --state-dir КАТАЛОГ daemon: каталог состояния (по умолчанию %s)\n"
          "  --allow-uid N       daemon: пускать и этот uid (до восьми раз); root и system\n"
          "                      пускаются всегда\n"
          "  --allow-domain ИМЯ  daemon: пускать процессы этого домена SELinux у владельца\n"
          "                      устройства (по умолчанию splify2_app на платформе Android;\n"
          "                      пустое значение — не пускать по домену)\n"
          "  --lists-dir КАТАЛОГ daemon: куда put-file кладёт файлы списков\n"
          "                      (по умолчанию %s)\n"
          "  --watch             daemon: сторожить выходы самому (вместо failover --loop;\n"
          "                      оба сразу не запускать)\n"
          "  --watch-period СЕК  daemon: период прохода сторожа в тишине (по умолчанию 60)\n"
          "  --supervise         daemon: держать помощников выходов и резолвер самому (вместо\n"
          "                      procd или steer supervise; оба сразу не запускать)\n"
          "  --dnsd-flag ФЛАГ    daemon: передать резолверу ещё и этот флаг (до восьми раз)\n"
          "  --apply             daemon: применить спеку при старте (сверкой, как reload)\n",
          p->ctl_sock, p->spec_path, p->state_dir, p->lists_dir);
}

static int ctl_listen(const struct ctl_conf *cf, ino_t *ino) {
    struct sockaddr_un a;
    memset(&a, 0, sizeof(a));
    a.sun_family = AF_UNIX;
    if (strlen(cf->sock) >= sizeof(a.sun_path)) ctl_bad_flag("daemon", "слишком длинный путь сокета", cf->sock);
    snprintf(a.sun_path, sizeof(a.sun_path), "%s", cf->sock);

    /* Прежний файл: живой сервер за ним — отказ стартовать (второй сервер отнял бы сокет у
     * первого молча); мёртвый — удалить, это след упавшего или убитого. */
    int t = socket(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0);
    if (t >= 0) {
        if (connect(t, (struct sockaddr *)&a, sizeof(a)) == 0) {
            close(t);
            fprintf(stderr, LOG_W "на %s уже отвечает другой сервер — второй не нужен\n", cf->sock);
            exit(1);
        }
        close(t);
    }
    unlink(cf->sock);

    int s = socket(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC | SOCK_NONBLOCK, 0);
    if (s < 0) { fprintf(stderr, LOG_W "socket: %s\n", strerror(errno)); exit(1); }
    /* Права 0666 — с рождения, через umask, а не chmod после bind: так нет мгновения, когда
     * файл уже есть, а права у него чужие. Открыто по правам файла нарочно: у приложения свой
     * uid и своя группа, которых заранее не знать, а пускает его не DAC, а SELinux (connectto
     * и метка steerd_socket) и проверка собеседника в ctl_peer_ok. */
    mode_t old = umask(0111);
    int rc = bind(s, (struct sockaddr *)&a, sizeof(a));
    umask(old);
    if (rc != 0) {
        fprintf(stderr, LOG_W "не занять %s: %s\n", cf->sock, strerror(errno));
        exit(1);
    }
    if (listen(s, 16) != 0) {
        fprintf(stderr, LOG_W "listen: %s\n", strerror(errno));
        exit(1);
    }
    struct stat sb;
    *ino = stat(cf->sock, &sb) == 0 ? sb.st_ino : 0;
    return s;
}

int ctl_serve_main(int argc, char **argv) {
    static struct ctl_srv S;
    struct ctl_conf *cf = &S.cf;
    cf->sock = plat()->ctl_sock;
    cf->spec = plat()->spec_path;
    cf->lists_dir = plat()->lists_dir;
    cf->allow_domain = plat()->ctl_allow_domain;
    for (int i = 0; i < argc; i++) {
        const char *f = argv[i];
        const char *v = i + 1 < argc ? argv[i + 1] : NULL;
        if (!strcmp(f, "--socket") || !strcmp(f, "--spec") || !strcmp(f, "--state-dir") ||
            !strcmp(f, "--allow-uid") || !strcmp(f, "--allow-domain") ||
            !strcmp(f, "--lists-dir")) {
            if (!v) ctl_bad_flag("daemon", "у флага нет значения", f);
            i++;
            if (!strcmp(f, "--socket")) cf->sock = v;
            else if (!strcmp(f, "--spec")) cf->spec = v;
            else if (!strcmp(f, "--state-dir")) cf->state_dir = v;
            else if (!strcmp(f, "--allow-domain")) cf->allow_domain = v;
            else if (!strcmp(f, "--lists-dir")) cf->lists_dir = v;
            else {
                char *e = NULL;
                unsigned long u = strtoul(v, &e, 10);
                if (!*v || *e || u > 0xfffffffful) ctl_bad_flag("daemon", "--allow-uid: нужно число", v);
                if (cf->allow_uid_n >= CTL_ALLOW_UIDS) ctl_bad_flag("daemon", "--allow-uid больше восьми раз", NULL);
                cf->allow_uid[cf->allow_uid_n++] = (uid_t)u;
            }
            continue;
        }
        if (!strcmp(f, "--watch")) { cf->watch = 1; continue; }
        if (!strcmp(f, "--supervise")) { cf->supervise = 1; continue; }
        if (!strcmp(f, "--apply")) { cf->apply = 1; continue; }
        if (!strcmp(f, "--dnsd-flag")) {
            if (!v) ctl_bad_flag("daemon", "у флага нет значения", f);
            i++;
            if (cf->dnsd_flag_n >= 8) ctl_bad_flag("daemon", "--dnsd-flag больше восьми раз", NULL);
            cf->dnsd_flags[cf->dnsd_flag_n++] = v;
            continue;
        }
        if (!strcmp(f, "--watch-period")) {
            if (!v) ctl_bad_flag("daemon", "у флага нет значения", f);
            i++;
            char *e = NULL;
            long p = strtol(v, &e, 10);
            if (!*v || *e || p < 1 || p > 86400) ctl_bad_flag("daemon", "--watch-period: нужно число 1..86400", v);
            cf->watch_period = (int)p;
            continue;
        }
        ctl_bad_flag("daemon", "неизвестный флаг", f);
    }
    ssize_t el = readlink("/proc/self/exe", cf->exe, sizeof(cf->exe) - 1);
    if (el <= 0) { fprintf(stderr, LOG_W "не найти свой исполняемый файл\n"); return 1; }
    cf->exe[el] = '\0';
    /* Команды в процессе (status, conns, dns-log) читают каталог состояния сами — тот же,
     * что подкомандам передаётся флагом. */
    if (cf->state_dir) steer_set_state_dir(cf->state_dir);

    /* Запись в ушедший сокет — ошибка send (MSG_NOSIGNAL), а не смерть демона; SIGPIPE
     * игнорируется ещё и ради записи, которую делает код в процессе. Детям он возвращается
     * (loop_child_reset). */
    signal(SIGPIPE, SIG_IGN);
    S.l = loop_new();
    if (!S.l) { fprintf(stderr, LOG_W "цикл событий: %s\n", strerror(errno)); return 1; }
    S.lfd = ctl_listen(cf, &S.ino);
    /* После ctl_listen: живой соседний сервер там уже дал бы отказ стартовать, и временные
     * файлы его обработчиков не тронуты. */
    ctl_lists_sweep(cf->lists_dir);
    recon_init(&S.rec);
    if (steerd_init(&S.d, S.l, cf->spec, cf->state_dir) != 0) {
        fprintf(stderr, LOG_W "нет памяти под спеку\n");
        return 1;
    }
    /* Спека не прочиталась — демон всё равно работает: apply через сокет её и исправляет, а
     * status до тех пор отвечает тем же отказом, что подкоманда. */
    if (steerd_load(&S.d) != 0) fprintf(stderr, LOG_W "спека не прочитана: %s\n", S.d.err);
    S.accept_tm = loop_timer_new(S.l, srv_accept_resume, &S);
    if (!S.accept_tm || loop_fd_add(S.l, S.lfd, EPOLLIN, srv_accept, &S) != 0) {
        fprintf(stderr, LOG_W "цикл событий: %s\n", strerror(errno));
        return 1;
    }
    loop_signal(S.l, SIGTERM, srv_term, &S);
    loop_signal(S.l, SIGINT, srv_term, &S);
    loop_signal(S.l, SIGHUP, srv_hup, &S);
    if (cf->watch) {
        struct watchd_conf wc = { cf->watch_period ? cf->watch_period : 60, ctl_enabled,
                                  srv_busy, &S };
        S.watch = watchd_start(&S.d, &wc);
        if (!S.watch) { fprintf(stderr, LOG_W "сторож: нет памяти\n"); return 1; }
        if ((S.snap_tm = loop_timer_new(S.l, srv_snap, &S))) loop_timer_set(S.snap_tm, CTL_SNAP_MS);
    }
    if (cf->supervise) {
        struct supd_conf sc = { ctl_enabled, cf->dnsd_flags };
        if (!supd_start(&S.d, &sc)) { fprintf(stderr, LOG_W "супервизор: нет памяти\n"); return 1; }
    }
    fprintf(stderr, LOG_I "слушаю %s%s%s\n", cf->sock, cf->watch ? ", сторожу выходы" : "",
            cf->supervise ? ", держу помощников" : "");
    if (cf->apply) {
        if (S.d.have) boot_apply(&S);
        else fprintf(stderr, LOG_W "спеки нет — применять при старте нечего\n");
    }
    return loop_run(S.l);
}

/* ---- клиент ------------------------------------------------------------------------------------ */

/* `steer ctl [--socket ФАЙЛ] КОМАНДА [СЛОВО...]` — тот же запрос, что пошлёт приложение, для
 * adb root shell и стенда. Тело команд apply, check и sub-check — со стандартного ввода, у
 * put-file — из файла, названного последним словом (`steer ctl put-file ИМЯ ФАЙЛ`; «-» —
 * стандартный ввод): имя в каталоге списков и путь на машине, откуда файл берётся, — разные
 * вещи, и имя из пути не выводится, чтобы залить /sdcard/x.txt под именем yt.lst. Печатает
 * ответ сервера как есть (строка JSON); у subscribe — строки событий по мере прихода, пока
 * демон не закроет соединение. Код: 0 — ответ с "code":0 и без "error"; 1 — иной
 * ответ; 2 — ошибка вызова или нет соединения. */
int ctl_client_main(int argc, char **argv) {
    const char *sock = plat()->ctl_sock;
    int i = 0;
    for (; i < argc; i++) {
        if (!strcmp(argv[i], "--socket")) {
            if (i + 1 >= argc) ctl_bad_flag("ctl", "у флага нет значения", argv[i]);
            sock = argv[++i];
        } else break;
    }
    if (i >= argc) ctl_bad_flag("ctl", "нужна команда", NULL);
    struct cbuf req = {0}, body = {0};
    const struct ctl_cmd *cmd = ctl_lookup(argv[i]);
    int words = argc, from_fd = 0;
    if (cmd && cmd->body && !strcmp(cmd->name, "put-file")) {
        if (argc - i != 3) ctl_bad_flag("ctl", "put-file: нужны имя и файл (или «-»)", NULL);
        const char *src = argv[argc - 1];
        words = argc - 1;
        if (strcmp(src, "-") != 0) {
            from_fd = open(src, O_RDONLY | O_CLOEXEC);
            if (from_fd < 0) ctl_bad_flag("ctl", "не открыть файл", src);
        }
    }
    for (int k = i; k < words; k++) {
        if (k > i) cb_put(&req, " ", 1);
        cb_str(&req, argv[k]);
    }
    if (cmd && cmd->body) {
        char buf[65536];
        ssize_t m;
        /* Предел клиента — с запасом выше предела сервера: слишком большое тело должен
         * отвергнуть сервер (too-large), а клиент — только не съесть всю память. */
        body.max = 4 * (size_t)CTL_FILE_MAX;
        while ((m = read(from_fd, buf, sizeof(buf))) > 0) cb_put(&body, buf, (size_t)m);
        if (from_fd > 0) close(from_fd);
        if (body.trunc) ctl_bad_flag("ctl", "тело больше 64 МиБ — такое сервер не примет", NULL);
        cb_fmt(&req, " %zu", body.n);
    }
    cb_put(&req, "\n", 1);

    struct sockaddr_un a;
    memset(&a, 0, sizeof(a));
    a.sun_family = AF_UNIX;
    snprintf(a.sun_path, sizeof(a.sun_path), "%s", sock);
    int s = socket(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0);
    if (s < 0 || connect(s, (struct sockaddr *)&a, sizeof(a)) != 0) {
        fprintf(stderr, "steer: ctl: нет соединения с %s: %s\n", sock, strerror(errno));
        return 2;
    }
    signal(SIGPIPE, SIG_IGN);
    /* Ошибка записи не повод молчать: сервер мог отказать (слишком большое тело) и закрыть
     * соединение, не читая, — его ответ всё равно лежит в сокете. */
    if (ctl_write_all(s, req.p, req.n) == 0 && body.n) ctl_write_all(s, body.p, body.n);
    shutdown(s, SHUT_WR);
    struct cbuf resp = {0};
    char buf[16384];
    ssize_t m;
    /* ECONNRESET после ответа — не ошибка: сервер отказал, не дочитав запрос (см. ctl_close),
     * а ответ уже прочитан. */
    /* subscribe — поток событий до закрытия: печатать по мере прихода, а не в конце. В
     * памяти копится только первая строка (ответ на сам subscribe) — по ней код выхода. */
    int stream = cmd && cmd->start == st_subscribe;
    while ((m = read(s, buf, sizeof(buf))) > 0 || (m < 0 && errno == EINTR)) {
        if (m <= 0) continue;
        if (!stream) { cb_put(&resp, buf, (size_t)m); continue; }
        fwrite(buf, 1, (size_t)m, stdout);
        fflush(stdout);
        if (!memchr(resp.p ? resp.p : "", '\n', resp.n)) cb_put(&resp, buf, (size_t)m);
    }
    close(s);
    if (!resp.n) { fprintf(stderr, "steer: ctl: сервер закрыл соединение без ответа\n"); return 2; }
    if (!stream) fwrite(resp.p, 1, resp.n, stdout);
    int ok = strstr(resp.p, ",\"code\":0,") && !strstr(resp.p, "\"error\":");
    free(req.p);
    free(body.p);
    free(resp.p);
    return ok ? 0 : 1;
}

