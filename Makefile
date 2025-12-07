CC = gcc
CFLAGS = -Wall -Isrc/q1/header -Isrc/q2/header -Isrc/common
BUILD_DIR = build

all: $(BUILD_DIR)/q1 $(BUILD_DIR)/q2

$(BUILD_DIR)/q1: src/q1/implementation/main.c src/q1/implementation/memory_analyzer.c src/q1/implementation/proc_parser.c src/q1/implementation/leak_detector.c
	@mkdir -p $(BUILD_DIR)
	$(CC) $(CFLAGS) -o $@ $^

$(BUILD_DIR)/q2: src/q2/implementation/main.c src/q2/implementation/security_checker.c src/q2/implementation/recommender.c src/q2/implementation/code_parser.c
	@mkdir -p $(BUILD_DIR)
	$(CC) $(CFLAGS) -o $@ $^

clean:
	rm -rf $(BUILD_DIR)
