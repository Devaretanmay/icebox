# Release Process

This document describes how ICEBOX is published. It is intentionally
small: distribution should be something anyone can run.

## Channels

| Channel | What | Workflow |
| --- | --- | --- |
| GitHub Releases | Prebuilt `icebox-daemon` binaries for Linux/macOS/Windows | `.github/workflows/release.yml` (trigered on `v*` tags) |
| crates.io | `cargo install icebox-gov` | same `release.yml` (`crates` job) |
| PyPI | `pip install icebox-sdk` | same `release.yml` (`pypi` job) |
| GHCR | `ghcr.io/devaretanmay/icebox` Docker image | same `release.yml` (`docker` job) |
| GitHub Pages | mdBook docs | `.github/workflows/docs.yml` (on `main`) |

## Cutting a release

1. Bump `version` in `Cargo.toml` and `python/pyproject.toml` (keep
   them in sync).
 2. Commit and tag: `git tag v0.2.7 && git push origin v0.2.7`.
3. The `release.yml` workflow builds binaries, the Docker image, and
   publishes to crates.io + PyPI, then creates the GitHub Release with
   all assets.

## Required repository secrets

Set these under **Settings → Secrets and variables → Actions**. They are
never committed to the repo.

| Secret | Used by | Value |
| --- | --- | --- |
| `CARGO_REGISTRY_TOKEN` | `crates` job | A crates.io API token (`cargo login`). |
| `PYPI_API_TOKEN` | `pypi` job | A PyPI API token (username is `__token__`). |
| `GITHUB_TOKEN` | `docker` + `release` jobs | Provided automatically by GitHub; no action needed. Permissions are set in the workflow. |

> **Security note:** the `CARGO_REGISTRY_TOKEN` and `PYPI_API_TOKEN`
> values were shared in chat during planning. Treat them as exposed and
> **rotate them** (crates.io → Account → Settings → API tokens; PyPI →
> Account settings → API tokens) before the first real release.

## Why `icebox-macro` is a separate published crate

The published `icebox-gov` crate is one package: a Rust **lib** (SDK), and a
**bin** (CLI/Daemon). The `#[module(...)]` proc macro must live in its own crate (proc macros require a separate compilation unit), so it ships as `icebox-macro` on crates.io and is published before `icebox-gov`. This mirrors the `serde` / `serde_derive` split.

