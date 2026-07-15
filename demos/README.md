# ICEBOX Demo Suite

5 scripted demos for video recording — each one exercises the ICEBOX
governance seam through the interactive CLI.

## Prerequisites

- Rust toolchain (stable) — [rustup.rs](https://rustup.rs/)
- (Optional) Ollama + `llama3.2` for multi-agent and validation demos

## Quick Start

```bash
# Build the CLI first
cd ICEBOX
cargo build -p icebox-cli

# Run all demos (interactive — you press ENTER between steps)
./demos/run_all.sh

# Or run all demos non-interactively (auto-advances)
./demos/run_all.sh --non-interactive
```

## Demo Scenarios

| # | Demo | Duration | Requires Ollama | Key Message |
|---|---|---|---|---|
| 1 | [Vulnerability Scanner](01_vuln_scanner.sh) | 2 min | No | Every module execution passes through charter + scope + policy + audit |
| 2 | [Multi-Agent Campaign](02_multi_agent_campaign.sh) | 2 min | Yes* | Concurrent agents share one governed audit trail |
| 3 | [Policy Blocking](03_policy_blocking.sh) | 2 min | No | Policy engine blocks dangerous actions; Deny always wins |
| 4 | [Continuous Validation](04_continuous_validation.sh) | 2 min | Yes* | Policy version tracking, workspace snapshots, drift detection |
| 5 | [Approval Workflow](05_approval_workflow.sh) | 2.5 min | No | Request → list → approve/deny → execute with full audit |

\* Demos 2 and 4 gracefully fall back to simulated output when Ollama is not available.

## Video Recording Guide

Each demo script includes narrator comments. When recording:

1. **Clean terminal** — use a 100×40 terminal with dark background
2. **Pre-build** — run `cargo build -p icebox-cli` before recording
3. **Pacing** — each `read -r` is a natural pause point
4. **Flow** — start with Demo 1 (vuln scanner) to establish the seam concept

### Suggested Recording Order

| Segment | Demo | Time | Narrator Focus |
|---|---|---|---|
| Hook | — | 30s | "Autonomous agents need governance." |
| Seam | Demo 1 | 2m | "Charter → scope → policy → audit." |
| Policy | Demo 3 | 2m | "Deny always wins. CVSS-aware rules." |
| Approval | Demo 5 | 2m | "Human-in-the-loop with full audit trail." |
| Validation | Demo 4 | 1.5m | "Policy drift detection for continuous compliance." |
| Orchestration | Demo 2 | 1.5m | "Multi-agent, one seam." |
| Close | — | 30s | "ICEBOX is open source. Try it." |
| **Total** | | **~10 min** | |

## Artifacts

Each demo produces artifacts in `/tmp/`:

| File | Source |
|---|---|
| `/tmp/icebox_audit.csv` | Demo 1 — CSV audit export |
| `/tmp/icebox_audit.json` | Demo 1 — JSON audit export |
| `/tmp/icebox_baseline.json` | Demo 4 — workspace snapshot |
| `/tmp/icebox_modified.json` | Demo 4 — modified workspace snapshot |
| `/tmp/icebox_campaign_audit.csv` | Demo 2 — campaign audit |
| `/tmp/icebox_campaign_audit.json` | Demo 2 — campaign audit |
| `/tmp/icebox_approval_audit.csv` | Demo 5 — approval audit |
| `/tmp/icebox_approval_audit.json` | Demo 5 — approval audit |
| `/tmp/icebox_report_a.json` | Demo 4 — validation report (with Ollama) |
| `/tmp/icebox_report_b.json` | Demo 4 — modified validation report (with Ollama) |
