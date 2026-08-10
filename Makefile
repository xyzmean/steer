# Native build for development and tests. Router builds are static musl via the
# same zig cross-toolchain splify already uses for its 29 architectures — added
# when there is something to ship, not before.
CFLAGS ?= -O2 -Wall -Wextra
BUILD  := build

.PHONY: all test clean
all: $(BUILD)/steer

$(BUILD)/steer: src/steer.c src/spec.c src/dnsd.c src/failover.c src/aggregate.c src/spec.h
	@mkdir -p $(BUILD)
	$(CC) $(CFLAGS) -o $@ src/steer.c src/spec.c src/dnsd.c src/failover.c src/aggregate.c

test: all $(BUILD)/dnsmatch $(BUILD)/specmatch $(BUILD)/failovermatch $(BUILD)/h2match
	@sh tests/run.sh
	@sh tests/gen.sh
	@$(BUILD)/dnsmatch
	@$(BUILD)/specmatch
	@$(BUILD)/failovermatch
	@$(BUILD)/h2match

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

clean:
	rm -rf $(BUILD)
