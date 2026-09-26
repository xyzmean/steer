/* Цикл событий демона: один epoll на всё — сокеты, трубы детей, сигналы, таймеры.
 *
 * ЗАЧЕМ СВОЙ, а не libev/libuv. Нужно пять вещей — дескриптор с обратным вызовом, таймер,
 * сигнал, выход ребёнка и сон без срока, — и всё это в Linux уже есть готовыми дескрипторами
 * (epoll, signalfd, timerfd). Библиотека поверх них — сотни килобайт в статическом бинарнике
 * роутера за то, что укладывается в один файл.
 *
 * СОН БЕЗ СРОКА. epoll_wait ждёт с таймаутом -1: демон просыпается только тогда, когда что-то
 * случилось, — соединение, вывод ребёнка, сигнал или СРАБОТАВШИЙ таймер. Таймеры не тикают:
 * timerfd взводится на самый ранний срок среди заведённых, а если заведённых нет, снят вовсе.
 * Тот же довод, что у dnsd после b8ca529: на телефоне с погасшим экраном каждое лишнее
 * пробуждение — это батарея, и «раз в секунду на всякий случай» — 60 пробуждений в минуту.
 *
 * СИГНАЛЫ — через signalfd, а не обработчиками. SIGCHLD, SIGHUP, SIGTERM и SIGINT заблокированы
 * с loop_new() и приходят событием на дескриптор: никакой работы в обработчике сигнала, никаких
 * гонок «флаг поставлен между проверкой и сном». Ребёнок, запущенный демоном, обязан снять
 * блокировку до exec — loop_child_reset() делает это вместе с SIGPIPE.
 *
 * ДЕТИ. Выход ребёнка приходит SIGCHLD, но waitpid(-1) здесь не зовётся: чужого ребёнка
 * (run() и popen() из кода, исполняемого в процессе, ждут своих сами) пожинать нельзя.
 * Кто запустил ребёнка, тот и называет его pid циклу — loop_child(), и цикл пожинает ровно
 * названных. Этим же будут пользоваться супервизор помощников и dnsd (шаг 4).
 *
 * Однопоточный: все обратные вызовы — из loop_run(), по одному. Обратный вызов может снимать
 * и заводить что угодно, в том числе дескриптор, событие которого ещё не разобрано в этой же
 * пачке: снятые записи освобождаются после пачки, и их события молча пропускаются. */
#ifndef STEER_LOOP_H
#define STEER_LOOP_H

#include <sys/types.h>
#include <stdint.h>

struct loop;
struct loop_timer;

/* events — биты EPOLLIN/EPOLLOUT/EPOLLERR/EPOLLHUP/EPOLLRDHUP как их отдал epoll. */
typedef void (*loop_fd_cb)(struct loop *l, int fd, uint32_t events, void *arg);
typedef void (*loop_timer_cb)(struct loop *l, struct loop_timer *t, void *arg);
typedef void (*loop_sig_cb)(struct loop *l, int signo, void *arg);
/* status — как из waitpid (WIFEXITED/WEXITSTATUS/WIFSIGNALED…). */
typedef void (*loop_child_cb)(struct loop *l, pid_t pid, int status, void *arg);

/* Создать цикл: epoll, signalfd на SIGCHLD/SIGHUP/SIGTERM/SIGINT (эти сигналы блокируются
 * в процессе), timerfd на CLOCK_MONOTONIC. NULL — не вышло (errno). */
struct loop *loop_new(void);
void loop_free(struct loop *l);

/* Крутить до loop_stop(). Возвращает код, переданный loop_stop. */
int loop_run(struct loop *l);
void loop_stop(struct loop *l, int code);

/* Дескрипторы. Цикл дескриптор не закрывает: снять — loop_fd_del, закрыть — сам владелец. */
int loop_fd_add(struct loop *l, int fd, uint32_t events, loop_fd_cb cb, void *arg);
int loop_fd_mod(struct loop *l, int fd, uint32_t events);
void loop_fd_del(struct loop *l, int fd);

/* Таймеры. Заведённый таймер срабатывает один раз; переставить — loop_timer_set ещё раз
 * (в том числе из его же обратного вызова: так делается период). ms <= 0 — сработать при
 * ближайшем обороте цикла. loop_timer_free снимает и освобождает; вызывать можно откуда
 * угодно, включая обратный вызов этого же таймера. */
struct loop_timer *loop_timer_new(struct loop *l, loop_timer_cb cb, void *arg);
void loop_timer_set(struct loop_timer *t, long ms);
void loop_timer_stop(struct loop_timer *t);
int loop_timer_armed(const struct loop_timer *t);
void loop_timer_free(struct loop_timer *t);

/* Сигнал SIGHUP, SIGTERM или SIGINT — обратный вызов (один на сигнал; NULL — снять). SIGCHLD
 * цикл разбирает сам (loop_child). -1 — сигнал не из этих. */
int loop_signal(struct loop *l, int signo, loop_sig_cb cb, void *arg);

/* Следить за выходом ребёнка pid: обратный вызов — когда он пожат, один раз. */
int loop_child(struct loop *l, pid_t pid, loop_child_cb cb, void *arg);

/* В ребёнке после fork, до exec: снять блокировку сигналов цикла и вернуть SIGPIPE по
 * умолчанию — иначе запущенная программа унаследовала бы их через exec. */
void loop_child_reset(void);

/* Монотонное время в миллисекундах (CLOCK_MONOTONIC: не прыгает при переводе часов). */
long loop_now_ms(void);

#endif
