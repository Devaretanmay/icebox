.PHONY: all build build-daemon build-sandbox-worker

all: build

build: build-daemon build-sandbox-worker

build-daemon:
	cargo build --release

build-sandbox-worker:
	cargo xtask build-sandbox-worker
