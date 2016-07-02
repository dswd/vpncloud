.PHONY: default
default: test build

.PHONY: build
build:
	git submodule update --init
	cargo build --release

.PHONY: test
test:
	git submodule update --init
	cargo test

.PHONY: bench
bench:
	git submodule update --init
	cargo bench --features bench

.PHONY: clean
clean:
	rm -rf target
