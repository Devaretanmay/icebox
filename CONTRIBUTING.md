# Contributing to ICEBOX

Thank you for considering contributing. ICEBOX is a small, focused product:
it sits between autonomous security agents and dangerous actions, and answers
one question per action — is this allowed?

## Kernel freeze

The governance core (`src/core/`: policy engine, audit hash-chain, sandbox,
executor, SDK primitives) is **feature-complete and frozen**. Treat it like the
Linux kernel: stable, trusted, changed only for bug/security fixes or to
strengthen a core guarantee (stronger isolation, stronger audit integrity).

Contributions that are welcome:

- SDK ergonomics — the `govern()` API and the Python/Rust wrappers.
- CLI polish (`icebox init`, `icebox doctor`), docs, examples.
- Framework recipes under `examples/`.
- Distribution (packaging, install flow).

Contributions that are **out of scope** (do not build): marketplace, policy
packs, an integrations package, K8s, enterprise features, AI-orchestration
layers. The product has two concepts — protect something, govern dangerous
actions — and we keep it that way.

## How to contribute

- **Bugs:** open an issue with a clear title, reproduction steps, and expected
  vs actual behavior.
- **Features:** open an issue describing the problem and a sketch of the
  solution. Most feature ideas should be rejected in favor of SDK/UX simplicity.
- **Docs/examples:** the highest-leverage contributions right now.

## Development setup

Prerequisites: Rust (stable) and Python 3.10+.

```bash
# Build the daemon + SDK
cargo build --bin icebox-daemon
pip install -e python/

# Run the daemon (local, no auth)
./target/debug/icebox-daemon --api --no-auth

# In another shell
icebox init          # set up a profile
python -c "from icebox import govern; print(govern('List users', target='x'))"
icebox doctor        # confirm you're protected

# Tests
cargo test --lib
cargo clippy --bin icebox-daemon
cargo fmt --check
```

## Coding standards

- **Rust:** `cargo fmt --check` and `cargo clippy` (no warnings) must pass.
- **Python:** PEP 8, type hints on public functions.
- **Comments:** minimal — code should be self-documenting.
- **YAGNI:** no speculative features, no wrappers that only delegate, no
  abstractions with a single implementation.

## Tests

- Unit tests live in `#[cfg(test)] mod tests` at the bottom of source files.
- Integration tests live in `tests/`.
- All tests must pass before a PR is merged.

## Pull request process

1. Fork and branch from `main`.
2. Make changes following the standards above.
3. Run `cargo test --lib && cargo clippy --bin icebox-daemon && cargo fmt --check`.
4. Open a PR with a conventional-commit title and a short description.
5. A maintainer merges once CI passes and review is approved.

## Questions?

Open an issue or a discussion. We're happy to help you find a good first
contribution.
