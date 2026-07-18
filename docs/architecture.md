# Architecture

ICEBOX has exactly one governance seam: `ModuleExecutor::execute()`. Every
operator action, REST call, and agent step must pass through it. That single
chokepoint is what makes the system auditable.

## Three layers (what's frozen vs. what's open)

ICEBOX is split into three layers. Only **Layer 1** is frozen; Layers 2 and 3 are
where contributions and product work happen.

- **Layer 1 — ICEBOX Kernel (FROZEN).** The Governed Execution Environment and its
  engines in `src/core/`: executor / stage machine, policy engine, audit hash-chain,
  sandbox isolation, approval workflow, validation. No new runtime features are
  accepted here unless they *strengthen* a GEE guarantee. See
  [GEE_INVARIANTS.md](GEE_INVARIANTS.md).
- **Layer 2 — Security Distribution.** Security modules, policy packs, agent
  integrations, payload generators, and reference examples. Lives in `src/modules/`
  and friends. This is where the offensive value is packaged.
- **Layer 3 — Ecosystem.** The Rust + Python SDKs, the REST API, the CLI, docs,
  distribution (crates.io / PyPI / Docker / Homebrew), and the operator dashboard.
  This is the developer-facing surface.

## Layers (top → bottom)

1. **Interfaces** — the REPL CLI and the Axum REST API on
   `127.0.0.1:8443/api/v1`. Both call the same executor.
2. **Module Executor** — the seam. Resolves a module, runs the policy
   preflight, executes, and records the outcome.
3. **Policy Engine** — 6 rule types
   (`DenyCapability`, `AllowCapability`, `MaxRisk`, `RequireApproval`,
   `DenyIfCvssAbove`, `RequireApprovalIf`) aware of CVSS 4.0, EPSS,
   and KEV.
4. **Approval Engine** — a queue plus four safety gates
   (charter, scope, max-risk, approval).
5. **Audit Engine** — every decision is normalized, scored, and
   provenance-tagged as JSON and CSV.

## State

- **Execution** — jobs and their results.
- **Memory** — what the agent learned.
- **Reasoning Traces** — why each step was taken.
- **Evidence** — normalized, scored, provenance-tagged artifacts.

## Modules

Modules register through the `#[module(...)]` proc macro (in
`icebox-macro`) and are collected at compile time via `linkme` into
`MODULE_REGISTRY`. The same registry feeds the CLI, the REST API, and
the daemon, so every surface governs identically.

## Why a single crate

The published `icebox-gov` crate is one package with a Rust **lib** (the SDK),
and a **bin** (the CLI/Daemon). The
`#[module(...)]` macro must stay in its own internal crate, but the
public surface is a single `icebox-gov` crate.
