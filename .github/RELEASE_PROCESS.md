# Release Process

This document describes how ICEBOX is published. Distribution is intentionally
split: CI builds and attaches binaries, while registry/Docker publishing is run
manually from a trusted machine with the real tokens.

## Channels

| Channel | What | How |
| --- | --- | --- |
| GitHub Releases | Prebuilt `icebox-daemon` binaries for Linux/macOS/Windows | `.github/workflows/release.yml` (triggered on `v*` tags) |
| crates.io | `cargo install icebox-gov` | **Manual** (your machine) |
| PyPI | `pip install icebox-sdk` | **Manual** (your machine) |
| GHCR | `ghcr.io/devaretanmay/icebox` Docker image | **Manual** (your machine) |
| GitHub Pages | mdBook docs | `.github/workflows/docs.yml` (on `main`) |

## Cutting a release

1. Bump `version` in `Cargo.toml` and `python/pyproject.toml` (keep
   them in sync).
2. Commit and tag: `git tag vX.Y.Z && git push origin vX.Y.Z`.
3. The `release.yml` workflow verifies the build, compiles `icebox-daemon`
   for all targets, and creates the GitHub Release with the binaries attached.
4. Publish to registries manually (below).

## Manual publish (run from your machine)

```sh
# crates.io
cargo publish -p icebox-macro
cargo publish -p icebox-gov

# PyPI
pip install maturin twine
maturin build --release --out dist_release
twine upload --username __token__ --password "$PYPI_API_TOKEN" dist_release/*

# Docker (GHCR)
docker build -t ghcr.io/devaretanmay/icebox:vX.Y.Z -t ghcr.io/devaretanmay/icebox:latest .
docker push ghcr.io/devaretanmay/icebox:vX.Y.Z
docker push ghcr.io/devaretanmay/icebox:latest
```

## Required tokens (local only, never committed)

| Token | Used for | Value |
| --- | --- | --- |
| `CARGO_REGISTRY_TOKEN` | `cargo publish` | A crates.io API token (`cargo login`). |
| `PYPI_API_TOKEN` | `twine upload` | A PyPI API token (username is `__token__`). |
| GHCR push | `docker push` | Your GitHub PAT with `write:packages`, or `docker login ghcr.io`. |

> **Security note:** the `CARGO_REGISTRY_TOKEN` and `PYPI_API_TOKEN` values
> were shared in chat during planning. Treat them as exposed and **rotate them**
> (crates.io → Account → Settings → API tokens; PyPI → Account settings → API
> tokens) before any real publish.

## Why `icebox-macro` is a separate published crate

The published `icebox-gov` crate is one package: a Rust **lib** (SDK), and a
**bin** (CLI/Daemon). The `#[module(...)]` proc macro must live in its own crate (proc macros require a separate compilation unit), so it ships as `icebox-macro` on crates.io and is published before `icebox-gov`. This mirrors the `serde` / `serde_derive` split.
