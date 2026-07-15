<picture>
  <source
    srcset="https://img.shields.io/badge/version-0.1.0-blue?style=for-the-badge"
    media="(prefers-color-scheme: light)"
  />
  <img
    alt="ICEBOX"
    src="https://img.shields.io/badge/version-0.1.0-blue?style=for-the-badge"
  />
</picture>

# ICEBOX

> Runtime governance for autonomous offensive security.

[![Build](https://img.shields.io/github/actions/workflow/status/Devaretanmay/icebox/ci.yml?branch=main&style=flat-square)](https://github.com/Devaretanmay/icebox/actions)
[![Rust](https://img.shields.io/badge/rust-stable-orange?style=flat-square)](https://www.rust-lang.org/)
[![License](https://img.shields.io/badge/license-MIT-blue?style=flat-square)](LICENSE)
[![Tests](https://img.shields.io/badge/tests-passing-brightgreen?style=flat-square)](#self-governance)
[![Crate](https://img.shields.io/badge/rust-single%20crate-blue?style=flat-square)](#repository-layout)
[![Python SDK](https://img.shields.io/badge/python-sdk%20ready-yellow?style=flat-square)](/python/icebox)

ICEBOX is a runtime governance framework for autonomous offensive security
tooling. It provides a single, auditable control point — the governance seam —
through which every human operator, REST client, and autonomous agent must pass
before any action is taken against an authorized target.

```text
Human / CLI / REST Client / LLM Agent / Multi-Agent
                       │
                ┌────────▼────────┐
                │  ModuleExecutor  │   ← THE SEAM
                │  ::execute()     │
                └────────┬────────┘
                       │
                ┌────────▼────────┐
                │   Policy Engine  │   6 rule types, CVSS/EPSS/KEV-aware
                └────────┬────────┘
                       │
                ┌────────▼────────┐
                │  Approval Engine │   queue + gates
                └────────┬────────┘
                       │
                ┌────────▼────────┐
                │   Audit Engine   │   JSON + CSV
                └────────┬────────┘
```

By centralizing policy enforcement, approval workflow, and audit capture in one
place, ICEBOX makes it possible to prove what an agent was permitted to do, why,
and whether the controls held. The included offensive modules are reference
implementations that exercise the seam; the framework is designed to govern
arbitrary tools and agents.

## Features

- **Policy engine** — six rule types (`DenyCapability`, `AllowCapability`,
  `MaxRisk`, `RequireApproval`, `DenyIfCvssAbove`, `RequireApprovalIf`),
  CVSS 4.0 / EPSS / CISA KEV aware.
- **Approval workflow** — charter acceptance, scope allowlist, max-risk ceiling,
  and explicit approval for destructive actions.
- **Role-based access control** — `viewer`, `operator`, and `admin` with
  least-privilege enforcement.
- **Audit trail** — every decision recorded with rationale, exportable as JSON
  or CSV.
- **Reasoning traces** — per-phase explainability for autonomous agents.
- **Evidence intelligence** — module output normalized, confidence-scored, and
  provenance-tagged.
- **Continuous validation** — monotonic policy versioning, drift detection, and
  diff reporting.
- **Multi-agent orchestration** — concurrent agents sharing one governed audit
  trail.
- **Interfaces** — interactive CLI (REPL) and a REST API with identical
  governance semantics.
- **SDKs** — Rust, a C ABI (`libicebox`), and a Python `Governance` class.

## Installation

ICEBOX is distributed as a single static binary and a Python SDK.

### Binary

```sh
# One-liner (curl | sh)
curl -sSfL https://raw.githubusercontent.com/Devaretanmay/icebox/main/dist/install.sh | sh

# From source
cargo install icebox

# Docker (GHCR)
docker pull ghcr.io/devaretanmay/icebox:latest
docker run --rm -p 8443:8443 ghcr.io/devaretanmay/icebox
```

> macOS: the release binary is not Apple-signed. On first-run Gatekeeper
> blocks, clear the quarantine attribute with
> `xattr -dr com.apple.quarantine "$(command -v icebox)"`.

Homebrew packaging is planned.

### Python SDK

```sh
pip install icebox-sdk
```

The Python SDK wraps the compiled `libicebox` C ABI via `ctypes`. If the native
library is not present, build it with `cargo build` or set `ICEBOX_CAPI` to its
path.

## Quickstart

### Build from source

```bash
git clone https://github.com/Devaretanmay/icebox.git
cd icebox
cargo build --release
```

### Run the CLI and REST API

```bash
cargo run            # interactive REPL with REST API on :8443
cargo run -- --api  # REST API only
```

```text
icebox> charter accept "pentest-2026-07"
icebox> scope add 10.0.0.0/8
icebox> list
icebox> use vuln_scanner
icebox> set project_dir /path/to/your/project
icebox> run --approve /path/to/your/project
```

The REST API is served at `http://127.0.0.1:8443/api/v1`:

```bash
curl -X POST http://127.0.0.1:8443/api/v1/modules/vuln_scanner/run \
  -H 'Content-Type: application/json' \
  -d '{"target": "/path/to/project", "approved": true}'
```

### Govern an agent with the Python SDK

```python
from icebox import Governance

gov = Governance({
    "charter": {"accepted": True, "engagement": "demo", "rules_of_engagement": []},
    "scope": {"allow": ["10.0.0.0/8"]},
    "max_risk": "critical",
    "role": "admin",
})

verdict = gov.run({
    "name": "scan",
    "target": "10.0.0.5",
    "capabilities": ["network_scan"],
    "impact": "low",
    "destructive": False,
})
print(verdict)
```

### Configure CVSS-aware policy

```bash
icebox> policy rule add deny-cvss 7.0
icebox> policy rule add require-approval-if --cvss 5.0 --epss 0.1 --kev
```

## SDK and language support

| SDK | Status | Usage |
| --- | --- | --- |
| Rust (native) | Available | `icebox` crate |
| C ABI | Available | `libicebox` (`icebox_govern`, `icebox_check`, ...) |
| Python | Available | `icebox.Governance` via ctypes |
| TypeScript / Java / Go | Planned | Community contributions welcome |

## Architecture

ICEBOX enforces governance at exactly one point: `ModuleExecutor::execute()`.
Every operator action, REST call, and agent step passes through it, which is what
makes the system auditable.

- **Interfaces** — REPL CLI and Axum REST API on `127.0.0.1:8443/api/v1`, both
  calling the same executor.
- **Module executor** — resolves a module, runs the policy preflight, executes,
  and records the outcome.
- **Policy engine** — six rule types, CVSS 4.0 / EPSS / KEV aware.
- **Approval engine** — a queue plus four safety gates (charter, scope,
  max-risk, approval).
- **Audit engine** — every decision normalized, scored, and provenance-tagged
  as JSON and CSV.

Modules register through the `#[module(...)]` proc macro (in `icebox-macro`)
and are collected at compile time via `linkme` into `MODULE_REGISTRY`. The same
registry feeds the CLI, the REST API, and the C ABI, so every surface governs
identically.

## Repository layout

```
icebox/
├── Cargo.toml              # Single package: lib (SDK) + cdylib (libicebox) + bin (CLI)
├── src/
│   ├── lib.rs              # Module declarations + MODULE_REGISTRY
│   ├── main.rs             # CLI / REST API binary
│   ├── capi.rs             # C ABI surface over the runtime
│   ├── core/               # The seam: executor, policy, audit, evidence
│   ├── modules/            # Example modules: vuln_scanner, recon, network
│   ├── ai/                 # Autonomous agent + multi-agent orchestrator
│   └── interfaces/         # REST API (Axum)
├── crates/
│   └── icebox-macro/       # #[module(...)] attribute macro
├── python/
│   ├── icebox/             # Python SDK (ctypes)
│   └── examples/
│       └── governed_agent.py
├── dist/install.sh         # curl | sh installer
├── Dockerfile              # GHCR image
└── docs/                   # mdBook site
```

## Policy rule reference

| Rule | CLI command | Effect |
| --- | --- | --- |
| `DenyCapability` | `policy rule add deny network_scan` | Blocks specific capability |
| `AllowCapability` | `policy rule add allow network_scan` | Pre-approves capability |
| `MaxRisk` | `policy rule add maxrisk high` | Caps risk ceiling |
| `RequireApproval` | *(via SDK builder)* | Gates capability + target pattern |
| `DenyIfCvssAbove` | `policy rule add deny-cvss 7.0` | Blocks if CVSS > threshold |
| `RequireApprovalIf` | `policy rule add require-approval-if --cvss 5.0 --epss 0.1 --kev` | Gates on CVSS/EPSS/KEV conditions |

## Self-governance

ICEBOX governs itself. The `governed_vuln_scan_blocks_high_cvss_exploit` test
runs the `vuln_scanner` module against ICEBOX's own source tree through the
governance seam, resolves real CVSS scores from OSV.dev, and verifies that
`DenyIfCvssAbove(7.0)` blocks hypothetical exploitation of high-CVSS findings.

## Documentation

Full documentation, including SDK references and deployment guidance, is
published at [https://devaretanmay.github.io/icebox/](https://devaretanmay.github.io/icebox/).

## Security

Please report vulnerabilities privately. See
[SECURITY.md](SECURITY.md) for the disclosure process.

## Contributing

Contributions are welcome. See [CONTRIBUTING.md](CONTRIBUTING.md) for
guidelines.

## License

ICEBOX is released under the [MIT License](LICENSE).
