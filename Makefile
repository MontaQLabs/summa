.PHONY: all build link clean test

all: build link

build:
	cargo build --release -p confidential-asset

link:
	polkatool link --run-only-if-newer -s target/riscv64emac-unknown-none-polkavm/release/confidential_asset -o confidential-asset.polkavm

test:
	cargo test -p summa --target aarch64-apple-darwin

clean:
	cargo clean
	rm -f *.polkavm
