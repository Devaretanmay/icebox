# Account-free usage

ICEBOX is designed to be useful **without creating an account or logging
in**. There is no phone-home, no telemetry, and no hosted dependency
in the default path.

## What runs locally

- The CLI and REST API bind to `127.0.0.1:8443` by default.
- The charter, scope, policy, approval queue, and audit trail all live
  in your local workspace (`workspace.json`), which you can `save` and
  `load`.
- The policy engine, approval gates, and audit engine are in-process.
  Nothing leaves your machine unless a module you run explicitly talks to
  a target you authorized.

## Optional, opt-in surfaces

These are conveniences, not requirements:

- **GitHub Releases / Homebrew / crates.io / PyPI** — channels to fetch
  the binary or SDK. You can also just `cargo install` or build from
  source.
- **GHCR** — a prebuilt Docker image for self-hosted deployments.
- **Documentation site** — copy-paste examples; no login needed to read.

## Bringing your own modules

The `#[module(...)]` macro and `MODULE_REGISTRY` mean contributor
modules are appended at runtime — you extend the seam without asking
anyone for permission.

## Enterprise (later)

Account-free stays the default. Hosted, multi-tenant, and managed
offerings are a later layer on top of the open-source kernel, not a
prerequisite for using it.
