.PHONY: all build test clean install help

BUILD_DIR := build
CMAKE := cmake
MAKE := make

all: build

help:
	@echo "CrossGuard C++ - Makefile targets:"
	@echo "  make build      - Build the project"
	@echo "  make test       - Build and run tests"
	@echo "  make clean      - Remove build directory"
	@echo "  make install    - Install binaries"
	@echo "  make help       - Show this message"

build:
	@mkdir -p $(BUILD_DIR)
	@cd $(BUILD_DIR) && $(CMAKE) .. && $(MAKE)
	@echo "Build complete. Binary: ./$(BUILD_DIR)/crossguard-cli"

test: build
	@cd $(BUILD_DIR) && $(MAKE) test
	@echo "Tests complete."

clean:
	@rm -rf $(BUILD_DIR)
	@echo "Clean complete."

install: build
	@cd $(BUILD_DIR) && $(MAKE) install
	@echo "Installation complete."

run-demo: build
	@./$(BUILD_DIR)/crossguard-cli --help

format-check:
	@echo "Formatting check not implemented"

.PHONY: all build test clean install help run-demo format-check
