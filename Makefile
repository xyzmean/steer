# Native build for development and tests. Router builds are static musl via the
# same zig cross-toolchain splify already uses for its 29 architectures — added
# when there is something to ship, not before.
CFLAGS ?= -O2 -Wall -Wextra
BUILD  := build

# Версия — из того же файла, что читает build.sh: `steer --version` на собранном руками
# движке должен называть то же число, что окажется в имени пакета.
VERSION := $(shell cat VERSION 2>/dev/null || echo dev)
# Ревизия: чем эта сборка отличается от релиза с тем же номером версии. Версия между
# релизами не меняется, поэтому движок из релиза и движок из main через два коммита после
# него назывались одним числом — на стенде два разных бинарника отчитывались как
# «0.9.6-r1» (R-045/I-054). `--dirty` здесь, а не в build.sh: локальная сборка идёт по
# рабочему дереву с правками, релизная — по коммиту (см. комментарий там).
# Пустое значение, когда git недоступен: тогда define не даётся вовсе и работает честное
# умолчание из src/cli.c, а не подставленное число.
REV     := $(shell git describe --tags --always --dirty 2>/dev/null)
DEFS    := -DSTEER_VERSION='"$(VERSION)"' $(if $(REV),-DSTEER_REV='"$(REV)"',)

.PHONY: all test clean ext-syntax ext-test
all: $(BUILD)/steer

$(BUILD)/steer: src/steer.c src/spec.c src/dnsd.c src/failover.c src/aggregate.c \
                src/obfs.c src/cli.c src/spec.h src/obfs.h src/cli.h VERSION
	@mkdir -p $(BUILD)
	$(CC) $(CFLAGS) $(DEFS) -o $@ src/steer.c src/spec.c src/dnsd.c src/failover.c \
	      src/aggregate.c src/obfs.c src/cli.c

test: all ext-syntax $(BUILD)/dnsmatch $(BUILD)/specmatch $(BUILD)/specmatch-ext $(BUILD)/xswirematch $(BUILD)/xsconnmatch $(BUILD)/xsstreammatch $(BUILD)/tungromatch $(BUILD)/tunnamematch $(BUILD)/xsconfmatch $(BUILD)/xslinkmatch $(BUILD)/xsroutematch $(BUILD)/chellomatch $(BUILD)/failovermatch $(BUILD)/dcmatch $(BUILD)/h2match $(BUILD)/submatch $(BUILD)/subfetchmatch $(BUILD)/fwmatch $(BUILD)/obfsmatch $(BUILD)/visionmatch $(BUILD)/diagsim
	@sh tests/run.sh
	@sh tests/gen.sh
	@sh tests/climatch.sh
	@sh tests/dnsproxy.sh
	@sh tests/diagmatch.sh
	@sh tests/statusmatch.sh
	@sh tests/buildmatch.sh
	@sh tests/vpsfetch.sh
	@$(BUILD)/dnsmatch
	@$(BUILD)/specmatch
	@$(BUILD)/specmatch-ext
	@$(BUILD)/failovermatch
	@$(BUILD)/dcmatch
	@$(BUILD)/h2match
	@$(BUILD)/submatch
	@$(BUILD)/subfetchmatch
	@$(BUILD)/fwmatch
	@$(BUILD)/obfsmatch
	@$(BUILD)/visionmatch
	@$(BUILD)/xswirematch
	@$(BUILD)/xsconnmatch
	@$(BUILD)/xsstreammatch
	@$(BUILD)/tungromatch
	@$(BUILD)/tunnamematch
	@$(BUILD)/xsconfmatch
	@$(BUILD)/xslinkmatch
	@$(BUILD)/xsroutematch
	@$(BUILD)/chellomatch

# Движок, собранный как расширенный, но без самой расширенной части: нужен стенду
# diagmatch, потому что спеку с `kind: vless` базовая сборка отвергает парсером, а
# проверять диагностику интереснее всего именно на VLESS-выходе. Три подкоманды
# расширенной сборки заменены заглушками — см. tests/vless-stub.c.
$(BUILD)/diagsim: src/steer.c src/spec.c src/dnsd.c src/failover.c src/aggregate.c \
                  src/obfs.c src/cli.c src/spec.h src/cli.h tests/vless-stub.c
	@mkdir -p $(BUILD)
	$(CC) $(CFLAGS) $(DEFS) -DSTEER_EXTENDED -o $@ src/steer.c src/spec.c src/dnsd.c \
	      src/failover.c src/aggregate.c src/obfs.c src/cli.c tests/vless-stub.c

# Синтаксическая проверка расширенного движка (R-014/I-024). Полная сборка src/ext идёт
# только в build.sh через docker с mbedtls, поэтому локальный make test оставался зелёным,
# даже когда ext не компилировался вовсе — так в main пролез 654e4e6. -fsyntax-only ловит
# ровно тот класс ошибок (несуществующее имя, снесённое объявление), заглушки mbedtls уже
# лежат в tests/stub — их завёл стенд h2match. Компоновку по-прежнему проверяет build.sh.
ext-syntax:
	@for f in src/ext/*.c; do \
		$(CC) $(CFLAGS) -fsyntax-only -Itests/stub -Isrc $$f || exit 1; \
	done
	@echo "ext-syntax: src/ext компилируется"

# Стенды src/ext, которым нужен НАСТОЯЩИЙ mbedtls: xsloop (рукопожатие целиком), spokematch
# (освобождение ключей под ASan) и hubmatch (арифметика записи в хабе, I-070). В `make test`
# они не входят — там mbedtls нет по построению (R-014, см. ext-syntax), а роутерная сборка ext
# идёт только docker'ом (build.sh), поэтому первые два до запуска 42 не прогонялись ни разу и
# дали I-066/I-067 первым же прогоном. Цель закрывает
# разрыв (R-058): библиотека ищется через STEER_MBEDTLS, pkg-config или системные пути; не
# нашлась — ГРОМКИЙ пропуск, а не падение; версия печатается (docker собирает 3.x, зелёное на
# 2.28 не равно зелёному в релизе). Вся логика — в tests/ext-test.sh, как у прочих *.sh-стендов.
ext-test:
	@BUILD=$(BUILD) CC="$(CC)" sh tests/ext-test.sh

# Подбор доменного правила проверяется отдельной программой, а не через движок: сам подбор
# статический внутри dnsd.c, и дотянуться до него иначе значило бы добавить в движок
# подкоманду ради теста. Файл включает исходник резолвера — см. tests/dnsmatch.c.
$(BUILD)/dnsmatch: tests/dnsmatch.c src/dnsd.c src/spec.c src/spec.h
	@mkdir -p $(BUILD)
	$(CC) $(CFLAGS) -o $@ tests/dnsmatch.c src/spec.c

# Парсер конфигурации проверяется отдельной программой по той же причине: load_spec
# читает файл и зовёт die()/exit(2) на неверной спеке — перехватить это через подкоманду
# движка нельзя. Файл включает исходник парсера и перехватывает exit через setjmp —
# см. tests/specmatch.c.
# Таблица дата-центров Telegram — см. пояснение в самом стенде. Собирается с заглушками
# mbedtls (-Itests/stub) по той же причине, что и ext-syntax: настоящей библиотеки в `make
# test` нет по построению.
$(BUILD)/dcmatch: tests/dcmatch.c src/ext/tgws.c
	@mkdir -p $(BUILD)
	$(CC) $(CFLAGS) -Itests/stub -Isrc -o $@ tests/dcmatch.c

$(BUILD)/specmatch: tests/specmatch.c src/spec.c src/spec.h
	@mkdir -p $(BUILD)
	$(CC) $(CFLAGS) -o $@ tests/specmatch.c

# Тот же исходник, собранный КАК РАСШИРЕННЫЙ. Нужен потому, что виды выходов vless и
# xsteer в базовой сборке отвергаются парсером (и обязаны отвергаться — см. spec.c), а
# значит их положительные случаи в build/specmatch недостижимы: до появления этого
# бинарника kind=vless не проверялся здесь ни одной строкой, только комментарием.
# Прецедент тот же, что у build/diagsim: один исходник, два бинарника, ветки внутри под
# #ifdef — так «базовая отказывает» и «расширенная разбирает» проверяются одним файлом.
$(BUILD)/specmatch-ext: tests/specmatch.c src/spec.c src/spec.h
	@mkdir -p $(BUILD)
	$(CC) $(CFLAGS) -DSTEER_EXTENDED -o $@ tests/specmatch.c

# Поддельный TCP проверяется в памяти: сборка и разбор сегмента, контрольные суммы и
# арифметика номеров — чистые функции без сокетов, поэтому стенд не требует ни сети, ни
# прав root. Циклы клиента и сервера сюда не входят намеренно — см. заголовок файла.
$(BUILD)/obfsmatch: tests/obfsmatch.c src/obfs.c src/obfs.h src/spec.c src/spec.h
	@mkdir -p $(BUILD)
	$(CC) $(CFLAGS) -o $@ tests/obfsmatch.c src/spec.c

$(BUILD)/failovermatch: tests/failovermatch.c src/failover.c
	@mkdir -p $(BUILD)
	$(CC) $(CFLAGS) -o $@ tests/failovermatch.c

# Зависимость выхода от чужого firewall: fw_check судит о конфигурации по тексту дампа
# nft, и проверить эвристику можно только примерами. Стенд включает исходник движка и
# подменяет popen на чтение из памяти — см. tests/fwmatch.c.
$(BUILD)/fwmatch: tests/fwmatch.c src/steer.c src/spec.c src/dnsd.c src/failover.c \
                  src/aggregate.c src/obfs.c src/cli.c src/spec.h src/cli.h
	@mkdir -p $(BUILD)
	$(CC) $(CFLAGS) -o $@ tests/fwmatch.c src/spec.c src/dnsd.c src/failover.c \
	      src/aggregate.c src/obfs.c src/cli.c

# Управление потоком HTTP/2 проверяется в памяти: h2.c общается с сетью только через
# struct h2_io, поэтому стенд подменяет его целиком. -Itests/stub нужен, чтобы не тянуть
# mbedtls ради типов, которые тест не трогает — см. tests/stub/mbedtls/sha256.h.
$(BUILD)/h2match: tests/h2match.c src/ext/h2.c src/ext/h2.h src/ext/tls13.h
	@mkdir -p $(BUILD)
	$(CC) $(CFLAGS) -Itests/stub -o $@ tests/h2match.c

# Разбор подписки — единственное место, куда в движок попадает чужой текст из интернета.
# Ни сети, ни mbedtls он не требует, поэтому стенд включает исходник напрямую и входит
# в обычный make test, в отличие от остального src/ext (см. ext-syntax).
# Разбор потока Vision — вторая точка, куда в движок попадают недоверенные байты от
# сервера. Ни сети, ни mbedtls он не требует, поэтому входит в обычный make test, как и
# разбор подписки; остальной src/ext доходит только до ext-syntax.
$(BUILD)/visionmatch: tests/visionmatch.c src/ext/vision.c src/ext/vision.h
	@mkdir -p $(BUILD)
	$(CC) $(CFLAGS) -o $@ tests/visionmatch.c

# vless_proto.c — в предпосылках и в стенде: разбор подписки решает, ПРИГОДЕН ли
# идентификатор, а превращает его в 16 байт vless_proto.c, и правило у них одно (правило
# Xray по длине строки). Без этой строки правка вывода UUID не пересобирала стенд, то есть
# зелёный прогон ничего не значил бы. Библиотек файл не тянет — mbedtls здесь нет
# по построению (см. ext-syntax).
$(BUILD)/submatch: tests/submatch.c src/ext/sub.c src/ext/vless.h \
                  src/ext/vless_proto.c src/ext/vless_proto.h
	@mkdir -p $(BUILD)
	$(CC) $(CFLAGS) -o $@ tests/submatch.c

# Скачивание и обработка подписки. Стенд включает исходник и подставляет три вещи: свой
# SHA-256 (проверяется РЕЦЕПТУРА идентификатора устройства, а не значение хеша — библиотека
# считает его сама), свой run_quiet и поддельный curl в PATH. Поэтому ни сети, ни mbedtls, ни
# docker он не требует и входит в обычный make test — при том что до переноса вся эта работа
# жила в оболочке объекта rpcd и не проверялась ничем.
$(BUILD)/subfetchmatch: tests/subfetchmatch.c src/ext/subfetch.c src/ext/subfetch.h \
                  src/ext/sub.c src/ext/vless.h src/ext/vless_proto.c src/ext/vless_proto.h
	@mkdir -p $(BUILD)
	$(CC) $(CFLAGS) -Itests/stub -o $@ tests/subfetchmatch.c

# Арифметика провода xsteer: заголовок записи, вывод nonce, окно приёма, пределы
# соединения. Всё, что она считает, ломается МОЛЧА — пакет отбрасывается стеком той
# стороны, или не расшифровывается, или отвергается как повтор, и ни одного сообщения об
# этом нет. Ни сети, ни mbedtls стенд не требует (xswire.c намеренно без библиотеки),
# поэтому он входит в обычный make test, как submatch и visionmatch.
$(BUILD)/xswirematch: tests/xswirematch.c src/ext/xswire.c src/ext/xswire.h
	@mkdir -p $(BUILD)
	$(CC) $(CFLAGS) -o $@ tests/xswirematch.c

# Стенд поддельного соединения: порог мёртвого пути и учёт своей незанятости. Входит в обычный
# make test по той же причине, что xswirematch: ни сети, ни mbedtls — время приходит аргументом,
# а сокета у соединения в стенде нет вовсе.
$(BUILD)/xsconnmatch: tests/xsconnmatch.c src/ext/xsconn.c src/ext/xsconn.h src/obfs.c src/obfs.h
	@mkdir -p $(BUILD)
	$(CC) $(CFLAGS) -o $@ tests/xsconnmatch.c src/obfs.c src/spec.c

# Рамка записей по настоящему потоку TCP: границы записей, смещения (они же nonce) и досылка
# недописанного хвоста. Стенд входит в обычный make test по той же причине, что xswirematch:
# xsstream.c не требует ни mbedtls, ни сети — обстановка делается из socketpair. Проверять это
# на живом туннеле пришлось бы гигабайтом трафика, а ломается всё здесь молча.
$(BUILD)/xsstreammatch: tests/xsstreammatch.c src/ext/xsstream.c src/ext/xsstream.h src/ext/xswire.h
	@mkdir -p $(BUILD)
	$(CC) $(CFLAGS) -Isrc -o $@ tests/xsstreammatch.c

# Склейка соседних сегментов в одну запись в устройство: что склеивается, что нет и какими
# байтами уезжает. В make test входит потому, что tun.c не требует ни mbedtls, ни сети, а
# обстановка делается из socketpair датаграммами — по одной на writev, поэтому видно и число
# записей, и их содержимое. Ошибка здесь либо портит поток клиента (склеили лишнее), либо тихо
# отключает выигрыш (не склеили ничего) — второе тут и случилось на живом прогоне.
$(BUILD)/tungromatch: tests/tungromatch.c src/ext/tun.c src/ext/tun.h
	@mkdir -p $(BUILD)
	$(CC) $(CFLAGS) -Isrc -o $@ tests/tungromatch.c

# Имя устройства: движок работает ровно с тем именем, о котором просил, — иначе отказ. Ядро
# усекает имя длиннее 15 символов молча, и разошедшееся имя не видно ниоткуда: очереди
# открыты, туннель жив, а адрес и зона firewall уезжают на несуществующее устройство (I-107).
# Здесь нужно НАСТОЯЩЕЕ устройство (TUNSETIFF — единственный источник выбранного имени),
# поэтому стенд требует CAP_NET_ADMIN и без него пропускается вслух с кодом 0. В make test он
# всё равно входит: стенд, который надо позвать руками, не запускается никогда.
$(BUILD)/tunnamematch: tests/tunnamematch.c src/ext/tun.c src/ext/tun.h
	@mkdir -p $(BUILD)
	$(CC) $(CFLAGS) -Isrc -o $@ tests/tunnamematch.c

# Разбор конфигурации xsteer — единственное место, куда в движок попадает текст, который
# человек написал руками, поэтому разбор строгий, а стенд перечисляет каждый отказ.
# Отдельно проверяется, что приватный ключ не попадает в вывод: обещание держится на том,
# что печатающая функция не имеет к нему доступа по построению. Без mbedtls — это же
# требуется для build/diagsim, который линкует этот файл ради проверок diag.
$(BUILD)/xsconfmatch: tests/xsconfmatch.c src/ext/xsconf.c src/ext/xsconf.h src/ext/xswire.h
	@mkdir -p $(BUILD)
	$(CC) $(CFLAGS) -o $@ tests/xsconfmatch.c

# Ссылка xs:// — второе представление той же настройки, и оно ПЕРЕДАЁТСЯ между людьми и между
# половинами звезды. Расхождение здесь не падает: ссылка «принялась», а туннель молчит, потому что
# маска оказалась другой или keepalive включился сам. Поэтому стенд держит те же векторы, что
# xsteer/conf/link_cross_test.go на стороне Go, и сверяет печать ПОБАЙТОВО.
$(BUILD)/xslinkmatch: tests/xslinkmatch.c src/ext/xslink.c src/ext/xslink.h \
                  src/ext/xsconf.c src/ext/xsconf.h src/ext/xswire.h
	@mkdir -p $(BUILD)
	$(CC) $(CFLAGS) -o $@ tests/xslinkmatch.c

# Куда отдать пакет. Ошибка здесь не видна снаружи: канал работает, счётчик растёт, а
# пакеты приходят не тому пиру. Три утверждения, без которых звезда небезопасна, стоят
# именно тут — самое длинное совпадение, «нет пира — отбросить» (а не «отдать первому»,
# что было бы утечкой между спицами) и запрет отправлять от чужого имени.
$(BUILD)/xsroutematch: tests/xsroutematch.c src/ext/xsroute.c src/ext/xsroute.h src/ext/xsconf.h
	@mkdir -p $(BUILD)
	$(CC) $(CFLAGS) -o $@ tests/xsroutematch.c

# Разбор ClientHello — граница доверия хаба: это первый код, который смотрит на байты от
# кого угодно из интернета, и ошибка здесь означает чтение за буфером по длине, которой
# доверились. Разбирается НАСТОЯЩИЙ Hello из заморозки (tests/chello-frozen.h), поэтому
# mbedtls не нужен. Байтовую неизменность самого сборщика проверяет tests/hellofreeze.c,
# которому библиотека нужна и который поэтому в make test не входит.
$(BUILD)/chellomatch: tests/chellomatch.c tests/chello-frozen.h src/ext/chello.c src/ext/chello.h
	@mkdir -p $(BUILD)
	$(CC) $(CFLAGS) -o $@ tests/chellomatch.c

# НЕ rm -rf $(BUILD): в build/ живут отслеживаемые Dockerfile, build-ext.sh и
# лабораторные исходники, без которых ./build.sh из свежего клона не работает —
# .gitignore об этом прямо предупреждает, а clean их сносил (I-023). Удаляются
# только артефакты: то, что здесь же и собирается, плюс упаковка из build.sh.
clean:
	rm -rf $(BUILD)/steer $(BUILD)/steer-* $(BUILD)/dnsmatch $(BUILD)/specmatch $(BUILD)/specmatch-ext \
	       $(BUILD)/failovermatch $(BUILD)/dcmatch $(BUILD)/h2match $(BUILD)/submatch $(BUILD)/subfetchmatch $(BUILD)/fwmatch $(BUILD)/obfsmatch \
	       $(BUILD)/visionmatch $(BUILD)/xswirematch $(BUILD)/xsconnmatch $(BUILD)/xsstreammatch $(BUILD)/xsepochmatch $(BUILD)/tungromatch $(BUILD)/tunnamematch $(BUILD)/xsconfmatch $(BUILD)/xslinkmatch $(BUILD)/xsroutematch $(BUILD)/chellomatch $(BUILD)/hellofreeze $(BUILD)/xsloop $(BUILD)/xsbench \
	       $(BUILD)/steer-hub $(BUILD)/steer-ext \
	       $(BUILD)/diagsim $(BUILD)/libmbed-*.a \
	       $(BUILD)/*.err $(BUILD)/pkg $(BUILD)/scripts out
