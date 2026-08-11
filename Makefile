# Native build for development and tests. Router builds are static musl via the
# same zig cross-toolchain splify already uses for its 29 architectures — added
# when there is something to ship, not before.
CFLAGS ?= -O2 -Wall -Wextra
BUILD  := build

.PHONY: all test clean ext-syntax
all: $(BUILD)/steer

$(BUILD)/steer: src/steer.c src/spec.c src/dnsd.c src/failover.c src/aggregate.c src/spec.h
	@mkdir -p $(BUILD)
	$(CC) $(CFLAGS) -o $@ src/steer.c src/spec.c src/dnsd.c src/failover.c src/aggregate.c

test: all ext-syntax $(BUILD)/dnsmatch $(BUILD)/specmatch $(BUILD)/failovermatch $(BUILD)/h2match $(BUILD)/submatch $(BUILD)/diagsim
	@sh tests/run.sh
	@sh tests/gen.sh
	@sh tests/diagmatch.sh
	@sh tests/buildmatch.sh
	@$(BUILD)/dnsmatch
	@$(BUILD)/specmatch
	@$(BUILD)/failovermatch
	@$(BUILD)/h2match
	@$(BUILD)/submatch

# Движок, собранный как расширенный, но без самой расширенной части: нужен стенду
# diagmatch, потому что спеку с `kind: vless` базовая сборка отвергает парсером, а
# проверять диагностику интереснее всего именно на VLESS-выходе. Три подкоманды
# расширенной сборки заменены заглушками — см. tests/vless-stub.c.
$(BUILD)/diagsim: src/steer.c src/spec.c src/dnsd.c src/failover.c src/aggregate.c \
                  src/spec.h tests/vless-stub.c
	@mkdir -p $(BUILD)
	$(CC) $(CFLAGS) -DSTEER_EXTENDED -o $@ src/steer.c src/spec.c src/dnsd.c \
	      src/failover.c src/aggregate.c tests/vless-stub.c

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
$(BUILD)/specmatch: tests/specmatch.c src/spec.c src/spec.h
	@mkdir -p $(BUILD)
	$(CC) $(CFLAGS) -o $@ tests/specmatch.c

$(BUILD)/failovermatch: tests/failovermatch.c src/failover.c
	@mkdir -p $(BUILD)
	$(CC) $(CFLAGS) -o $@ tests/failovermatch.c

# Управление потоком HTTP/2 проверяется в памяти: h2.c общается с сетью только через
# struct h2_io, поэтому стенд подменяет его целиком. -Itests/stub нужен, чтобы не тянуть
# mbedtls ради типов, которые тест не трогает — см. tests/stub/mbedtls/sha256.h.
$(BUILD)/h2match: tests/h2match.c src/ext/h2.c src/ext/h2.h src/ext/tls13.h
	@mkdir -p $(BUILD)
	$(CC) $(CFLAGS) -Itests/stub -o $@ tests/h2match.c

# Разбор подписки — единственное место, куда в движок попадает чужой текст из интернета.
# Ни сети, ни mbedtls он не требует, поэтому стенд включает исходник напрямую и входит
# в обычный make test, в отличие от остального src/ext (см. ext-syntax).
$(BUILD)/submatch: tests/submatch.c src/ext/sub.c src/ext/vless.h
	@mkdir -p $(BUILD)
	$(CC) $(CFLAGS) -o $@ tests/submatch.c

# НЕ rm -rf $(BUILD): в build/ живут отслеживаемые Dockerfile, build-ext.sh и
# лабораторные исходники, без которых ./build.sh из свежего клона не работает —
# .gitignore об этом прямо предупреждает, а clean их сносил (I-023). Удаляются
# только артефакты: то, что здесь же и собирается, плюс упаковка из build.sh.
clean:
	rm -rf $(BUILD)/steer $(BUILD)/steer-* $(BUILD)/dnsmatch $(BUILD)/specmatch \
	       $(BUILD)/failovermatch $(BUILD)/h2match $(BUILD)/submatch $(BUILD)/diagsim $(BUILD)/libmbed-*.a \
	       $(BUILD)/*.err $(BUILD)/pkg $(BUILD)/scripts out
