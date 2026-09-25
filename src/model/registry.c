#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include "spec.h"
#include "registry.h"

/* Marks and tables live well away from what splify (0x40000/0x80000, tables
 * 200/202) and mwan3 use, so both can run on one box while the migration is in
 * progress. One bit per output keeps `nft` output readable. */
/* База метки и число бит — в spec.h: их знает не только распорядитель, но и тот, кто
 * ставит правило и генерирует ruleset, а маска выводится из них же. */
#define MARK_BASE   STEER_MARK_BASE
/* У мини-сборки (STEER_TGWS) свой ряд номеров таблиц. Выходу kind=tgws таблица не нужна, но
 * номер ему выдаётся вместе с меткой и живёт в реестре, а уборка мёртвых правил (steer.c,
 * cleanup_stale_routing) делает по реестру `ip route flush table N`. С общей базой N совпадал
 * бы с таблицей выхода полного движка — и удаление или переименование выхода микропакета
 * молча опустошало бы чужую таблицу маршрутизации. Полный движок берёт 300..315 (MAX_OUTPUTS). */
#ifdef STEER_TGWS
#define TABLE_BASE  316
#else
#define TABLE_BASE  300
#endif

/* ---- mark/table registry -------------------------------------------------- */
/* Persisted, because an output must keep its mark across restarts: a reboot that
 * reshuffles marks leaves stale `ip rule` entries pointing at the wrong table,
 * and the symptom is traffic silently taking someone else's path. */
static void rt_tables_write(const struct spec *s);

int registry_assign(struct spec *s, struct err *e) {
    char path[512];
    snprintf(path, sizeof(path), "%s/registry", g_state_dir);
    FILE *f = fopen(path, "r");
    if (f) {
        char name[32];
        unsigned mark;
        int table;
        while (fscanf(f, "%31s %x %d\n", name, &mark, &table) == 3) {
            /* Метка вне НАШЕЙ маски — не наша: реестр остался от сборки с другим диапазоном
             * (мини-сборка до своего бита писала 08000000). Взять её значило бы ставить
             * `and ~маска or метка` с битом за пределами маски, который сравнение
             * `mark and маска == метка` не увидит никогда, — то есть правило стоит, а не
             * срабатывает. Такой выход получает метку заново, как новый. */
            if (!mark || (mark & ~STEER_MARK_MASK)) continue;
            for (size_t i = 0; i < s->out_n; i++)
                if (!strcmp(s->out[i].name, name) && out_needs_mark(&s->out[i])) {
                    s->out[i].mark = mark;
                    s->out[i].table = table;
                }
        }
        fclose(f);
    }
    int from_top = getenv("STEER_MARK_ORDER") &&
                   !strcmp(getenv("STEER_MARK_ORDER"), "top");

    /* ЗАНЯТЫЕ МЕСТА. Место — это пара «метка, таблица»: метка `база * (место + 1)` и
     * таблица `TABLE_BASE + место`. Занятость считается по ОБОИМ полям, и вот почему.
     *
     * До перехода на значения выход получал бит, то есть метку `база << номер`. У
     * старших битов это база, умноженная на 16, 32, 64 и 128, — такого значения новая
     * раздача не выдаст никому (место не больше MAX_OUTPUTS), поэтому по метке эти
     * выходы не опознать. Зато их ТАБЛИЦА всегда лежала в 300..307, то есть в пределах
     * ряда, — по ней место и занимается. Так реестр, доживший с прежней сборки,
     * переживает обновление без единой перетасовки: метка остаётся та, что уже стоит в
     * пакетах и правилах, а новые выходы просто садятся на свободные места. */
    unsigned char taken[STEER_MARK_SLOTS];
    memset(taken, 0, sizeof(taken));
    for (size_t i = 0; i < s->out_n; i++) {
        if (!s->out[i].mark) continue;
        unsigned m = s->out[i].mark / MARK_BASE;
        if (m && s->out[i].mark % MARK_BASE == 0 && m - 1 < STEER_MARK_SLOTS)
            taken[m - 1] = 1;
        int t = s->out[i].table - TABLE_BASE;
        if (t >= 0 && (unsigned)t < STEER_MARK_SLOTS) taken[t] = 1;
    }

    for (size_t i = 0; i < s->out_n; i++) {
        /* Место в реестре (метку и таблицу) получает выход со своей меткой — все виды, кроме
         * direct (out_needs_mark). */
        if (!out_needs_mark(&s->out[i]) || s->out[i].mark) continue;
        /* СВЕРХУ ИЛИ СНИЗУ. Обычно места раздаются снизу: первый выход получает нулевое,
         * второй первое и так далее. Но на роутере движок бывает не один — рядом с полным
         * ставится микропакет tgws со своей спекой и своим состоянием, — и оба, начав с
         * нуля, выдали бы своим выходам ОДНУ И ТУ ЖЕ метку. Метка живёт в пакете, а не в
         * таблице: правило маршрутизации одного экземпляра увело бы трафик другого в свою
         * таблицу, и раздельными таблицами правил это не лечится.
         *
         * Поэтому второй экземпляр запускается с STEER_MARK_ORDER=top и раздаёт места
         * сверху вниз. Из места выводятся и метка, и номер таблицы маршрутизации, и порт
         * моста, и очередь обхода, — значит одной этой переменной хватает, чтобы развести
         * экземпляры целиком. */
        unsigned slot = 0;
        int found = 0;
        if (from_top) {
            for (unsigned k = STEER_MARK_SLOTS; k-- > 0;)
                if (!taken[k]) { slot = k; found = 1; break; }
        } else {
            for (unsigned k = 0; k < STEER_MARK_SLOTS; k++)
                if (!taken[k]) { slot = k; found = 1; break; }
        }
        if (!found)
            return err_set(e, "out of mark slots for output %s", s->out[i].name);
        taken[slot] = 1;
        s->out[i].mark = MARK_BASE * (slot + 1);
        s->out[i].table = TABLE_BASE + (int)slot;
    }
    /* Прежде чем писать — сравнить с тем, что уже на диске. registry_assign
     * зовут все подкоманды, включая status, который интерфейс опрашивает каждые
     * пять секунд: безусловная перезапись — это ~17 тысяч записей файла в сутки
     * с неизменным содержимым. Сравнивается будущий текст целиком, а не «были ли
     * новые назначения»: перезапись заодно вычищает строки исчезнувших выходов,
     * и пропускать её можно только когда файл уже дословно совпадает. */
    char want[1024]; /* 16 выходов по ≤53 байта строки — влезает с запасом */
    size_t wn = 0;
    for (size_t i = 0; i < s->out_n && wn < sizeof(want); i++)
        if (out_needs_mark(&s->out[i])) {
            int w = snprintf(want + wn, sizeof(want) - wn, "%s %x %d\n",
                             s->out[i].name, s->out[i].mark, s->out[i].table);
            if (w < 0 || (size_t)w >= sizeof(want) - wn) break; /* не бывает, но не рвём буфер */
            wn += (size_t)w;
        }
    f = fopen(path, "r");
    if (f) {
        char have[sizeof(want) + 1];
        size_t hn = fread(have, 1, sizeof(have), f);
        fclose(f);
        if (hn == wn && memcmp(have, want, wn) == 0) return 0;
    }
    mkdir(g_state_dir, 0755);
    f = fopen(path, "w");
    if (!f) return 0;           /* best effort: apply still works, next boot re-assigns */
    fwrite(want, 1, wn, f);
    fclose(f);
    rt_tables_write(s);
    return 0;
}

/* Объявить имена таблиц маршрутизации системе.
 *
 * ЗАЧЕМ. Номера таблиц (300, 301, ...) не говорят ничего: `ip route show table 300` требует
 * помнить, какой выход это был, а `ip rule show` печатает номер. iproute2 умеет имена —
 * для этого и существует /etc/iproute2/rt_tables.d, — и тогда диагностика становится
 * обычной: `ip route show table steer_vpn`. Проверено на живом роутере (10.8.1.87,
 * OpenWrt 25.12 с ip-full): имя из rt_tables.d принимается и в add, и в show.
 *
 * ПОЧЕМУ КАТАЛОГ, А НЕ САМ rt_tables. Файл rt_tables принадлежит пакету iproute2;
 * дописывать в чужой файл значило бы драться с его обновлением. Каталог .d для этого и
 * заведён.
 *
 * ПОЧЕМУ СРАВНЕНИЕ ПЕРЕД ЗАПИСЬЮ. registry_assign зовут все подкоманды, включая status,
 * который интерфейс опрашивает каждые пять секунд, — это та же причина, по которой не
 * перезаписывается сам реестр (см. выше): безусловная запись означала бы ~17 тысяч записей
 * файла в сутки с неизменным содержимым.
 *
 * Отказ здесь ничего не ломает: имена — удобство диагностики, номера работают и без них.
 * Поэтому молча, без предупреждений: на busybox-ip имён нет вовсе, и жаловаться было бы не
 * на что. */
static void rt_tables_write(const struct spec *s) {
#ifdef STEER_ANDROID
    /* На телефоне каталога iproute2 в /etc нет и быть не может: /etc там — ссылка в системный
     * раздел только для чтения. Имена таблиц — удобство диагностики (см. выше), и отказ записи
     * был бы тихим и так; но и mkdir в чужой системный каталог при каждом status пробовать
     * незачем. */
    return;
#endif
    char path[512];
    /* Файл — свой у каждой сборки: мини-сборка с тем же именем перезаписывала бы имена таблиц
     * полного движка своими. */
#ifdef STEER_TGWS
    snprintf(path, sizeof(path), "%s/stgws.conf", g_rt_tables_d);
#else
    snprintf(path, sizeof(path), "%s/steer.conf", g_rt_tables_d);
#endif

    char want[1024];
    size_t wn = 0;
    for (size_t i = 0; i < s->out_n && wn < sizeof(want); i++) {
        if (!out_needs_mark(&s->out[i]) || !s->out[i].table) continue;
        /* Имя с приставкой: таблица принадлежит выходу, но пространство имён общее для всей
         * коробки, и «vpn» там заняли бы и mwan3, и человек руками. */
        int w = snprintf(want + wn, sizeof(want) - wn, "%d steer_%s\n",
                         s->out[i].table, s->out[i].name);
        if (w < 0 || (size_t)w >= sizeof(want) - wn) break;
        wn += (size_t)w;
    }

    FILE *f = fopen(path, "r");
    if (f) {
        char have[sizeof(want) + 1];
        size_t hn = fread(have, 1, sizeof(have), f);
        fclose(f);
        if (hn == wn && memcmp(have, want, wn) == 0) return;
    }
    /* Каталога может не быть: iproute2 создаёт его не всегда, а на busybox-сборке его нет
     * вовсе. mkdir по одному уровню — родителя (/etc/iproute2) тоже может не быть. */
    char parent[512];
    snprintf(parent, sizeof(parent), "%s", g_rt_tables_d);
    char *slash = strrchr(parent, '/');
    if (slash && slash != parent) { *slash = '\0'; mkdir(parent, 0755); }
    mkdir(g_rt_tables_d, 0755);
    f = fopen(path, "w");
    if (!f) return;
    fwrite(want, 1, wn, f);
    fclose(f);
}
