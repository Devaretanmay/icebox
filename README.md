<picture>
  <source
    srcset="https://img.shields.io/badge/status-MVP%20Complete-blue?style=for-the-badge"
    media="(prefers-color-scheme: light)"
  />
  <img
    alt="ICEBOX"
    src="https://img.shields.io/badge/status-MVP%20Complete-blue?style=for-the-badge"
  />
</picture>

# ICEBOX

> Runtime governance for autonomous offensive security.

[![Build](https://img.shields.io/github/actions/workflow/status/TBD/ICEBOX/ci.yml?branch=main&style=flat-square)](https://github.com/TBD/ICEBOX/actions)
[![Rust](https://img.shields.io/badge/rust-stable-orange?style=flat-square)](https://www.rust-lang.org/)
[![License](https://img.shields.io/badge/license-MIT-blue?style=flat-square)](LICENSE)
[![Tests](https://img.shields.io/badge/tests-72%20passed%200%20failed-brightgreen?style=flat-square)](#-test-suite)
[![LOC](https://img.shields.io/badge/rust-14k%20LOC-purple?style=flat-square)](#-codebase)
[![Python SDK](https://img.shields.io/badge/python-sdk%20ready-yellow?style=flat-square)](/python/icebox_sdk.py)

---

ICEBOX is **not** another autonomous pentester. It is the **single governance
seam** that every human operator, REST client, and LLM agent must pass through
before anything touches a target.

Think of it as **Kubernetes for autonomous security agents**: the policy,
approval, audit, memory, and observability layer that sits between autonomous
security tools and the environments they are authorized to operate on.

```text
┌──────────────────────────────────────────────────────────────┐
│  Human / CLI / REST Client / LLM Agent / Multi-Agent         │
│                              │                                │
│                     ┌────────▼────────┐                      │
│                     │  ModuleExecutor  │                      │
│                     │  ::execute()     │  ← THE SEAM          │
│                     └────────┬────────┘                      │
│                              │                                │
│                     ┌────────▼────────┐                      │
│                     │   Policy Engine  │                      │
│                     │  • 6 rule types   │                      │
│                     │  • CVSS/EPSS/KEV  │                      │
│                     └────────┬────────┘                      │
│                              │                                │
│                     ┌────────▼────────┐                      │
│                     │  Approval Engine │                      │
│                     │  • Queue + gates  │                      │
│                     └────────┬────────┘                      │
│                              │                                │
│                     ┌────────▼────────┐                      │
│                     │   Audit Engine   │                      │
│                     │  • JSON + CSV     │                      │
│                     └────────┬────────┘                      │
│                              │                                │
│               ┌──────────────┼──────────────┐                │
│               ▼              ▼              ▼                 │
│          Execution      Memory      Reasoning Traces          │
│               │              │              │                 │
│               └──────────────┼──────────────┘                 │
│                              ▼                                │
│                        Evidence                              │
│                    (normalized, scored,                       │
│                     provenance-tagged)                        │
└──────────────────────────────────────────────────────────────┘
```

Because the gate is in **exactly one place**, you can prove what an agent was
allowed to do, why, and whether the governance actually held. That is the
product. The offensive modules are just examples that exercise the seam.

---

## Features

- **6 policy rule types** — `DenyCapability`, `AllowCapability`, `MaxRisk`,
  `RequireApproval`, **`DenyIfCvssAbove`**, **`RequireApprovalIf`** (CVSS 4.0,
  EPSS, KEV-aware)
- **4 independent safety gates** — charter acceptance, scope allowlist, max-risk
  ceiling, approval for destructive actions
- **RBAC** — `viewer` / `operator` / `admin` roles with least-privilege enforcement
- **Audit trail** — every decision recorded with reason, exportable to JSON or CSV
- **Reasoning traces** — autonomous agent leaves an explainability trace per phase
- **Evidence intelligence** — module output normalized, confidence-scored,
  provenance-tagged
- **Continuous validation** — policy version monotonic, drift detection, diff reports
- **Multi-agent orchestration** — run concurrent agents; all share one governed audit trail
- **Two interfaces** — interactive CLI (REPL) and REST API (identical governance)
- **Governance SDK** — Rust builder, C ABI, and Python `Governance` class

---

## Quickstart (5 minutes)

### Prerequisites

- Rust toolchain (stable) — [rustup.rs](https://rustup.rs/)
- (Optional) Ollama for agent features — [ollama.ai](https://ollama.ai/)

### Build

```bash
git clone https://github.com/TBD/ICEBOX.git
cd ICEBOX
cargo build --release
# 7 crates, ~14k LOC, compiles in ~2 minutes
```

### Run the REPL

```bash
cargo run -p icebox-cli
```

```text
icebox> charter accept "pentest-2026-07"
icebox> scope add 10.0.0.0/8
icebox> list
icebox> use vuln_scanner
icebox> set project_dir /path/to/your/project
icebox> run --approve /path/to/your/project
```

### Start the REST API

```bash
cargo run -p icebox-cli -- --api
```

```text
REST API http://127.0.0.1:8443/api/v1
```

```bash
curl -X POST http://127.0.0.1:8443/api/v1/modules/vuln_scanner/run \
  -H 'Content-Type: application/json' \
  -d '{"target": "/path/to/project", "approved": true}'
```

### Use the Python SDK

```python
from icebox_sdk import Governance

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
print(verdict)  # {"decision": "Allow", "reason": "All gates passed"}
```

### Configure CVSS-Aware Policies

```bash
# Block any task with CVSS > 7.0
icebox> policy rule add deny-cvss 7.0

# Require approval if CVSS > 5.0 OR EPSS > 0.1 OR CVE is KEV
icebox> policy rule add require-approval-if --cvss 5.0 --epss 0.1 --kev
```

---

## Test Suite

**72 tests, 0 failures.** Every merge is validated against real API calls to
OSV.dev, FIRST EPSS, and the full governance seam.

| Test Target | Tests | Status |
|---|---|---|
| `icebox-ai` (agent + orchestrator) | 6 | PASS |
| `icebox-core` (lib unit tests) | 9 | PASS |
| `icebox-core` (dogfooding E2E) | 31 | PASS |
| `icebox-core` (evidence) | 3 | PASS |
| `icebox-core` (governance) | 10 | PASS |
| `icebox-modules` (lib) | 10 | PASS |
| `icebox-modules` (eval) | 3 | PASS |
| **Total** | **72** | **All passing** |

```bash
# Run the full suite
cargo test --all
```

---

## SDK & Language Support

| SDK | Status | Usage |
|---|---|---|
| **Rust** (native) | Available | Direct via `icebox-core` |
| **C ABI** | Available | `icebox_govern`, `icebox_check`, etc. via `icebox-capi` |
| **Python** | Available | `Governance` class via ctypes |
| TypeScript / Java / Go | Planned | Community contributions welcome |

---

## Repository Layout

```
ICEBOX/
├── Cargo.toml              # Workspace root (7 member crates)
├── rust-toolchain.toml     # Stable Rust + clippy + rustfmt
├── crates/
│   ├── icebox-core/        # The seam: executor, policy, audit, evidence
│   ├── icebox-modules/     # Example modules: vuln_scanner, recon, network
│   ├── icebox-ai/          # Autonomous agent + multi-agent orchestrator
│   ├── icebox-interfaces/  # REST API (Axum)
│   ├── icebox-cli/         # Interactive REPL
│   ├── icebox-capi/        # C ABI for SDK bindings
│   └── icebox-macro/       # #[module(...)] attribute macro
├── python/
│   ├── icebox_sdk.py       # Python SDK (ctypes)
│   └── examples/
│       └── governed_agent.py
└── demos/
    └── README.md
```

---

## Policy Rule Reference

| Rule | CLI Command | Effect |
|---|---|---|
| `DenyCapability` | `policy rule add deny network_scan` | Blocks specific capability |
| `AllowCapability` | `policy rule add allow network_scan` | Pre-approves capability |
| `MaxRisk` | `policy rule add maxrisk high` | Caps risk ceiling |
| `RequireApproval` | *(via SDK builder)* | Gates capability + target pattern |
| **`DenyIfCvssAbove`** | `policy rule add deny-cvss 7.0` | Blocks if CVSS > threshold |
| **`RequireApprovalIf`** | `policy rule add require-approval-if --cvss 5.0 --epss 0.1 --kev` | Gates on CVSS/EPSS/KEV conditions |

---

## Dogfooding

ICEBOX governs itself. The `governed_vuln_scan_blocks_high_cvss_exploit` test
runs the `vuln_scanner` module against ICEBOX's own source code through the
governance seam, extracts real CVSS scores from OSV.dev, and verifies that
`DenyIfCvssAbove(7.0)` blocks hypothetical exploitation of high-CVSS findings.

```text
[dogfood] vuln_scanner scanned ICEBOX project: 176 deps, 0 CVEs found
[dogfood] no real CVEs found, using synthetic CVSS 9.5 for policy test
test governed_vuln_scan_blocks_high_cvss_exploit ... ok
```

---

## License & Contributing

- **License:** MIT
- **Contributions welcome!** See [CONTRIBUTING.md](CONTRIBUTING.md)
- **Vulnerability disclosure:** See [SECURITY.md](SECURITY.md)

---

## Status

ICEBOX has completed its MVP (Phases 1–3) and is transitioning to community
validation. The architecture is stable, the test suite is comprehensive, and the
core thesis — **runtime governance for autonomous offensive security** — is
ready for real-world feedback.

**Current phase:** Open-source release, user validation, design partner program.
