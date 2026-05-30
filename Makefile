.PHONY: all build test clean install

BUILD := build

all: build

build:
	mkdir -p $(BUILD)
	cd $(BUILD) && cmake .. && make

test: build
	cd $(BUILD) && ctest --output-on-failure

clean:
	rm -rf $(BUILD)

install: build
	cd $(BUILD) && make install
