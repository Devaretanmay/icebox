# Contributing to ICEBOX

First off, thank you for considering contributing to ICEBOX. The project is in
its early stages, and every contribution — whether code, documentation, bug
reports, or design feedback — helps shape what it becomes.

> ## ❄️ Kernel Freeze (effective `v0.2.5-kernel-complete`)
>
> The ICEBOX **kernel** — the Governed Execution Environment (GEE) and its
> supporting engines in `src/core/` — is **feature-complete and frozen**. This
> is the single seam every human operator, REST client, and LLM agent must pass
> through before anything touches a target.
>
> **What is frozen (Layer 1 — do not change behavior):**
> - `src/core/gee.rs` — GEE lifecycle and stage machine
> - `src/core/safety.rs` — policy engine, `PolicyDecision`, capability rules
> - `src/core/audit.rs` — SHA-256 audit hash-chain
> - `src/core/sandbox.rs` — isolation (Docker/tier-driven)
> - `src/core/executor.rs` — `ModuleExecutor`, `execute()`, `transition_to()`
> - `src/core/sdk.rs`, `src/core/validation.rs` — validation + SDK primitives
> - Approval / validation semantics and CLI governance semantics
>
> **What belongs outside the kernel (Layers 2 & 3 — welcome contributions):**
> - Security modules, policy packs, agent integrations (`src/modules/`, etc.)
> - SDK ergonomics (the `govern()` API, Python/Rust wrappers)
> - REST/CLI surface polish, docs, examples, distribution, dashboard
>
> **Rule:** No new runtime feature is accepted into the kernel unless it
> *materially strengthens a GEE guarantee* (e.g. stronger isolation, stronger
> audit integrity). Bug fixes and security fixes are always welcome. See
> [`docs/GEE_INVARIANTS.md`](docs/GEE_INVARIANTS.md) for the non-negotiable
> guarantees the frozen kernel provides.

## Table of Contents

- [Code of Conduct](#code-of-conduct)
- [Kernel Freeze](#-kernel-freeze-effective-v025-kernel-complete)
- [How to Contribute](#how-to-contribute)
- [Development Setup](#development-setup)
- [Project Structure](#project-structure)
- [Coding Standards](#coding-standards)
- [Testing](#testing)
- [Pull Request Process](#pull-request-process)
- [Feature Requests & Design Feedback](#feature-requests--design-feedback)

## Code of Conduct

This project adheres to a [Code of Conduct](CODE_OF_CONDUCT.md). By
participating, you are expected to uphold it. Please report unacceptable
behavior to the project maintainers.

## How to Contribute

### Report Bugs

Open an issue with:

- A clear, descriptive title
- Steps to reproduce (including code snippets)
- Expected vs actual behavior
- Rust version (`rustc --version`), OS, and any relevant configuration

### Suggest Features

Open an issue with:

- What problem you're trying to solve
- How ICEBOX fits (or doesn't) into your workflow
- A sketch of the solution (pseudocode, API surface, etc.)

### Improve Documentation

Documentation is the highest-leverage contribution right now. This includes:

- README improvements
- Doc comments on public APIs
- Examples in `/python/examples/`
- Architecture diagrams
- Tutorials

### Write Tests

Tests are our safety net. Good contributions include:

- Unit tests for new functionality
- Integration tests that exercise the governance seam
- Dogfooding tests that run real modules against real APIs

### Submit Code

See [Pull Request Process](#pull-request-process) below.

## Development Setup

### Prerequisites

- **Rust** (stable) — [rustup.rs](https://rustup.rs/)
- **Python 3.10+** — for Python SDK examples
- **Ollama** (optional) — for autonomous agent features (`ollama pull llama3.2`)

### Build & Test

```bash
# Clone the repository
git clone https://github.com/Devaretanmay/icebox.git
cd icebox

# Build the workspace
cargo build --all

# Run the full test suite
cargo test --all

# Run clippy
cargo clippy --all

# Check formatting
cargo fmt --check
```

### Python SDK Setup

```bash
# Build the C ABI shared library
cargo build

# Run the governed agent example
cd python
pip install requests       # only if using the example's HTTP client
python examples/governed_agent.py
```

## Project Structure

```
icebox/
├── Cargo.toml              # Single package: lib (SDK) + cdylib (libicebox) + bin (CLI)
├── src/
│   ├── lib.rs              # Module declarations + MODULE_REGISTRY
│   ├── main.rs             # CLI / REST API binary
│   ├── capi.rs             # C ABI surface over the runtime
│   ├── core/               # Governance seam — the core product
│   ├── modules/            # Example modules (demos, not the product)
│   ├── ai/                 # Autonomous agent + orchestrator
│   └── interfaces/         # REST API
├── crates/
│   └── icebox-macro/       # Proc macro for module registration
└── python/
    ├── icebox/             # Python SDK
    └── examples/
```

**Important:** `src/modules` contains **demos**. The product is the
governance layer in `src/core`. When contributing, prefer improving the
governance seam, SDK, or documentation over adding offensive capabilities.

## Coding Standards

### Rust

- **Format:** All code must pass `cargo fmt --check`
- **Lint:** All code must pass `cargo clippy --all` with no warnings
- **Naming:** Follow standard Rust conventions (`snake_case` for functions/variables,
  `CamelCase` for types, `SCREAMING_CASE` for constants)
- **Errors:** Use `thiserror` for library error types, `anyhow` for application code
- **Async:** Use `tokio` throughout; prefer `async fn` over manual futures
- **Safety:** `unsafe` is acceptable in `src/capi.rs` for FFI; avoid it elsewhere
- **Documentation:** Public APIs must have doc comments. Use `///` with markdown
  and code examples where helpful

### Python

- **Format:** Follow PEP 8
- **Typing:** Use type hints for all function signatures
- **Documentation:** Docstrings in Google or NumPy format

### Commit Messages

Follow [Conventional Commits](https://www.conventionalcommits.org/):

```
feat: add DenyIfCvssAbove policy rule
fix: correct scope matching for CIDR ranges
docs: add Python SDK quickstart example
test: add E2E governed vuln scan test
refactor: extract policy evaluation into separate module
```

## Testing

**All tests must pass before a PR is merged.** The CI pipeline runs:

1. `cargo build --all`
2. `cargo test --all`
3. `cargo clippy --all` (no warnings)
4. `cargo fmt --check`

### Writing Tests

- **Unit tests:** Co-located at the bottom of the source file in a `#[cfg(test)] mod tests`
- **Integration tests:** In the `tests/` directory at the repository root
- **Dogfooding tests:** In `tests/dogfooding.rs` — these test
  real modules against real APIs through the governed seam
- **Network-dependent tests:** Use `#[ignore]` for tests that require external
  services if they're too flaky for CI

### Coverage Goals

- New policy rules: must have unit tests + integration tests
- New modules: must have at least one dogfooding test
- Bug fixes: must include a regression test

## Pull Request Process

1. **Fork the repository** and create a feature branch from `main`
2. **Make your changes** following the coding standards above
3. **Run the full test suite** locally:
   ```bash
   cargo test --all && cargo clippy --all && cargo fmt --check
   ```
4. **Open a pull request** with:
   - A clear title (preferably conventional commit format)
   - A description of what the change does and why
   - Links to any related issues
5. **Respond to review feedback** — we may ask for changes
6. **A maintainer will merge** once the CI passes and at least one review is approved

### Before Your First PR

If you're new to the project, consider starting with:

- A documentation improvement
- A test enhancement
- A bug fix with a clear reproduction

## Feature Requests & Design Feedback

ICEBOX is in a validation phase. We're particularly interested in:

- **Use cases:** How would you use ICEBOX? What workflow would it fit into?
- **Pain points:** What's hardest about governing autonomous security tools today?
- **Integration needs:** What language, platform, or tool would you need to integrate with?
- **Policy requirements:** What policy rules would you need to feel safe running
  autonomous agents in production?

Open an issue with the `design-feedback` or `feature-request` label.

## Questions?

Open a [Discussion](https://github.com/Devaretanmay/icebox/discussions) or reach out to
the maintainers directly. We're happy to help you find a good first contribution.
