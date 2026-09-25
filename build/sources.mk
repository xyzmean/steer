# Сборочные списки исходников — ЕДИНСТВЕННЫЕ.
#
# Раньше один и тот же список ядра был переписан руками у пяти целей Makefile, в build.sh,
# в build/build-ext.sh и в Android.bp, и расходились они молча: новый файл проходил make test
# и ломался только в релизной сборке, на чужой машине, неопределённой ссылкой (I-024, I-032).
# Теперь списки живут здесь, а остальные их читают:
#
#   Makefile             include build/sources.mk
#   build.sh, build-ext.sh   . build/sources.sh; profile_src <профиль>
#   Android.bp           сверяется с профилем android стендом tests/buildmatch.sh (Soong не
#                        умеет читать чужие файлы, поэтому список там остаётся, но проверяемым)
#
# Формат нарочно простой, чтобы его читал и make, и build/sources.sh без make: строки
# `ИМЯ := значение`, продолжение строки обратной косой чертой, ссылки `$(ИМЯ)` на имена,
# объявленные ВЫШЕ. Ничего другого из make здесь не использовать.
#
# Профиль — это набор файлов одной сборки. Макросы STEER_EXTENDED/STEER_SERVER/STEER_TGWS
# пока остаются рядом (PROFILE_DEFS_*); по плану пересборки (docs/architecture.md) они
# уходят, и профиль будет решать всё составом файлов.

# Каталоги слоёв (docs/architecture.md). Заголовки подключаются по имени (`#include "spec.h"`)
# из любого слоя, поэтому каждая сборка получает -I на все каталоги сразу; имена заголовков
# в дереве уникальны, и стенд tests/buildmatch.sh за этим следит.
CORE_DIRS := src/lib src/model src/compile src/daemon src/kinds src/cli src/dnsd src/tools src/proto/obfs
EXT_DIRS  := src/tunnel src/proto/tls src/proto/vless src/proto/xsteer src/proto/tgws
INC_DIRS  := $(CORE_DIRS) $(EXT_DIRS)

# Модель спеки — то, во что нарезан прежний src/model/spec.c (docs/architecture.md, «Слои и
# каталоги»): JSON-ридер, сам разбор спеки, реестр меток/таблиц, ход перебора узлов подписки и
# раскладка правил старого ядра. Порядок — тот, в котором они шли в неразрезанном файле.
MODEL_SRC := src/lib/jsonr.c src/lib/tmpfile.c src/model/parse.c src/model/registry.c \
             src/model/probe.c src/compile/nftcompat.c

# Резолвер: src/dnsd/dnsd.c был один файл, теперь — DNSD_SRC. lib/sindex.c, lib/nftnl.c,
# lib/ctnl.c родились из того же файла (хеш-индекс строк, транзакции nf_tables по netlink,
# разговор с conntrack) и собираются только вместе с резолвером — CORE_SRC берёт весь список.
DNSD_SRC := src/lib/sindex.c src/lib/nftnl.c src/lib/ctnl.c \
            src/dnsd/rules.c src/dnsd/wire.c src/dnsd/fakeip.c src/dnsd/table.c src/dnsd/dlog.c \
            src/dnsd/proxy.c src/dnsd/main.c

# src/daemon/steer.c нарезан на модули (docs/architecture.md, раздел 2, «Слои и каталоги»):
# компиляция спеки в правила — в src/compile, остальное ядро — в src/daemon, порядок ниже
# такой же, как был в steer.c (lib/run.c раньше всех — на него ссылаются и compile, и daemon).
CORE_SRC := src/lib/run.c src/compile/groups.c src/compile/generate.c src/daemon/fwcheck.c \
            src/daemon/apply.c src/daemon/status.c src/daemon/nftquery.c src/daemon/diag.c \
            src/daemon/explain.c src/daemon/supervise.c src/daemon/watch.c src/daemon/main.c \
            $(MODEL_SRC) $(DNSD_SRC) src/daemon/failover.c src/tools/aggregate.c src/proto/obfs/obfs.c \
            src/cli/cli.c src/tools/srs.c src/tools/puff.c src/tools/hwid.c src/daemon/ctl.c src/kinds/awg.c

# Общее для обеих ролей: формат кадра, конфигурация, маршрутизация, рукопожатие, соединение
# и то, на чём они стоят (TLS-записи, примитивы Reality, TUN). Расходиться на проводе этим
# половинам негде — кода формата ровно один экземпляр, и это ровно та гарантия, которая
# заменила прежнюю «один бинарник на две стороны» (см. server/README.md).
# xsstream.c и xsepoch.c лежат в ОБЩЕЙ половине, а не в клиентской: рамка записей по
# настоящему TCP и ратчет эпох нужны обеим сторонам звезды, и держать их у одной значило бы,
# что вторую придётся писать заново — то есть двумя способами ошибиться в формате, который
# обязан совпадать до байта.
# certverify.c лежит в ОБЩЕЙ половине, хотя проверка цепочки нужна только клиенту: её зовёт
# tls13.c, и зовёт безусловно, а не под #ifdef. Значит файл обязан быть везде, где
# компилируется tls13.c, — то есть во всех трёх ролях. Внесённый только в EXT_ROUTER_SRC, он
# оставил роли server и tgws с неопределёнными ссылками на cert_verify_server: сборка
# роутерного пакета при этом шла как обычно, и заметить это было нечем, кроме релиза.
XS_COMMON_SRC := src/proto/xsteer/xswire.c src/proto/xsteer/xsconf.c src/proto/xsteer/xslink.c src/proto/xsteer/xsroute.c \
                 src/proto/tls/chello.c src/proto/xsteer/xshake.c src/proto/xsteer/xsconn.c \
                 src/proto/xsteer/xsstream.c src/proto/xsteer/xsepoch.c \
                 src/proto/tls/tls13.c src/proto/tls/certverify.c \
                 src/proto/tls/reality.c src/tunnel/tun.c src/proto/tls/h2.c \
                 src/proto/xsteer/xsadmin.c
EXT_ROUTER_SRC := src/proto/vless/sub.c src/proto/vless/vless_proto.c src/proto/vless/vision.c \
                  src/proto/vless/client.c src/tunnel/tunnel.c src/tunnel/rtx.c \
                  src/proto/xsteer/xsclient.c src/proto/vless/subfetch.c src/proto/tgws/tgws.c src/proto/tls/tlsprobe.c
EXT_SERVER_SRC := src/proto/xsteer/xshub.c
EXT_TGWS_SRC := src/proto/tls/tls13.c src/proto/tls/certverify.c src/proto/tls/reality.c \
                src/proto/tls/chello.c src/proto/tgws/tgws.c src/proto/tls/tlsprobe.c

PROFILE_base     := $(CORE_SRC)
PROFILE_extended := $(CORE_SRC) $(XS_COMMON_SRC) $(EXT_ROUTER_SRC)
PROFILE_server   := $(CORE_SRC) $(XS_COMMON_SRC) $(EXT_SERVER_SRC)
PROFILE_tgws     := $(CORE_SRC) $(EXT_TGWS_SRC)
# Телефон: тот же состав, что расширенный роутерный (Android.bp, цель steer).
PROFILE_android  := $(PROFILE_extended)

PROFILE_DEFS_base     :=
PROFILE_DEFS_extended := -DSTEER_EXTENDED
PROFILE_DEFS_server   := -DSTEER_SERVER
PROFILE_DEFS_tgws     := -DSTEER_TGWS
PROFILE_DEFS_android  := -DSTEER_ANDROID -DSTEER_EXTENDED
