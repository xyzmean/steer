# Native build for development and tests. Router builds are static musl via the
# same zig cross-toolchain splify already uses for its 29 architectures — added
# when there is something to ship, not before.
CFLAGS ?= -O2 -Wall -Wextra
BUILD  := build

.PHONY: all test clean
all: $(BUILD)/steer-aggregate $(BUILD)/steer

$(BUILD)/steer-aggregate: src/aggregate.c
	@mkdir -p $(BUILD)
	$(CC) $(CFLAGS) -o $@ $<

$(BUILD)/steer: src/steer.c src/spec.c src/dnsd.c src/spec.h
	@mkdir -p $(BUILD)
	$(CC) $(CFLAGS) -o $@ src/steer.c src/spec.c src/dnsd.c

test: all
	@sh tests/run.sh
	@sh tests/gen.sh

clean:
	rm -rf $(BUILD)
