# Installation

ICEBOX ships with a unified Python SDK that includes an interactive setup wizard. This is the recommended path for both Python and non-Python users.

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

## Verify

```sh
# Verify the daemon proxy works
icebox --version

# Verify the SDK
python -c "from icebox import Workspace; print('ok')"
```
