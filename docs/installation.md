# Installation

ICEBOX ships with a unified Python SDK that includes an interactive setup wizard. This is the recommended path for both Python and non-Python users.

> **Status of the one-liners:** `pip install icebox-sdk` and `cargo install
> icebox-gov` are the flagship install paths and are documented here as the goal.
> Until the published packages / releases exist, **build from source** (section 4)
> as the working fallback. The Docker image is available from GHCR for demos.

## 1. Unified Python SDK (Recommended)

```sh
pip install icebox-sdk
```

After installing the SDK, launch the interactive setup wizard:

```sh
icebox
```

The wizard will check your environment for Docker and the Rust toolchain. If the core Rust daemon is missing, it will seamlessly compile and install it for you.

## 2. Cargo (Alternative)

If you prefer to install the underlying Rust daemon directly without the Python wizard:

```sh
cargo install icebox-gov
```

> **macOS note:** If Gatekeeper blocks the daemon on first run, clear the quarantine attribute:
> `xattr -dr com.apple.quarantine "$(command -v icebox-daemon)"`

## 3. Docker (GHCR — no Docker Hub)

```sh
docker pull ghcr.io/devaretanmay/icebox:latest
docker run --rm -p 8443:8443 ghcr.io/devaretanmay/icebox
```

## 4. Build from source (fallback)

Works today, no published package required.

```sh
git clone https://github.com/Devaretanmay/icebox.git
cd icebox
cargo build --release                 # produces ./target/release/icebox-daemon
cargo xtask build-sandbox-worker      # required for mandatory sandboxing (needs Docker)
cd python && pip install -e .         # Python SDK (PyO3 extension)
```

Run the daemon / REPL:

```sh
./target/release/icebox-daemon --api   # REST API only
./target/release/icebox-daemon         # interactive REPL + REST API
```

## Verify

```sh
# Verify the daemon
./target/release/icebox-daemon --version

# Verify the SDK (source build)
python -c "from icebox import Governance; print('ok')"
```
