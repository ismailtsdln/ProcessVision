.PHONY: build test check fmt release

build:
	cargo build

test:
	cargo test

check:
	cargo check

fmt:
	cargo fmt --all

release:
	cargo build --release

clean:
	cargo clean
