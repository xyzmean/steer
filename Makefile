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

test: all $(BUILD)/dnsmatch $(BUILD)/specmatch $(BUILD)/failovermatch
	@sh tests/run.sh
	@sh tests/gen.sh
	@$(BUILD)/dnsmatch
	@$(BUILD)/specmatch
	@$(BUILD)/failovermatch

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

clean:
	rm -rf $(BUILD)
