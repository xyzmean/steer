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

CORE_SRC := src/steer.c src/spec.c src/dnsd.c src/failover.c src/aggregate.c src/obfs.c \
            src/cli.c src/srs.c src/puff.c src/hwid.c src/ctl.c src/awg.c

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
XS_COMMON_SRC := src/ext/xswire.c src/ext/xsconf.c src/ext/xslink.c src/ext/xsroute.c \
                 src/ext/chello.c src/ext/xshake.c src/ext/xsconn.c \
                 src/ext/xsstream.c src/ext/xsepoch.c \
                 src/ext/tls13.c src/ext/certverify.c \
                 src/ext/reality.c src/ext/tun.c src/ext/h2.c \
                 src/ext/xsadmin.c
EXT_ROUTER_SRC := src/ext/sub.c src/ext/vless_proto.c src/ext/vision.c \
                  src/ext/client.c src/ext/tunnel.c src/ext/rtx.c \
                  src/ext/xsclient.c src/ext/subfetch.c src/ext/tgws.c src/ext/tlsprobe.c
EXT_SERVER_SRC := src/ext/xshub.c
EXT_TGWS_SRC := src/ext/tls13.c src/ext/certverify.c src/ext/reality.c \
                src/ext/chello.c src/ext/tgws.c src/ext/tlsprobe.c

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
