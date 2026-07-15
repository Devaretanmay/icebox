# Installation

ICEBOX ships as a single static binary plus a Python SDK. Pick the channel
you prefer — they all install the same `icebox` binary.

## One-liner (curl | sh)

```sh
curl -sSfL https://raw.githubusercontent.com/Devaretanmay/icebox/main/dist/install.sh | sh
```

macOS users: the binary is not Apple-signed, so Gatekeeper may block the
first run. Clear the quarantine bit with:

```sh
xattr -dr com.apple.quarantine "$(command -v icebox)"
```

## Homebrew (planned)

Homebrew is not wired up yet. Until then, use the one-liner, `cargo install`,
or Docker.

## Cargo

```sh
cargo install icebox
```

## Docker (GHCR — no Docker Hub)

```sh
docker pull ghcr.io/devaretanmay/icebox:latest
docker run --rm -p 8443:8443 ghcr.io/devaretanmay/icebox
```

## Python SDK

```sh
pip install icebox-sdk
```

The Python SDK wraps the compiled `libicebox` C ABI via `ctypes`. If you
install `icebox-sdk` without building the native lib, obtain `libicebox`
from any of the channels above (the SDK auto-discovers it next to the
package, or set `ICEBOX_CAPI` to its path).

## Verify

```sh
icebox --version
python -c "from icebox import Governance; print('ok')"
```
