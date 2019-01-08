.PHONY: default
default: test build

.PHONY: build
build:
	cargo build --release

.PHONY: test
test:
	cargo test

.PHONY: bench
bench:
	cargo bench --features bench

.PHONY: deb
deb:
	make -C deb

.PHONY: clean
clean:
	rm -rf target
