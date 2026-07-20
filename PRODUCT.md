# ICEBOX — Product Identity

## What ICEBOX is
The thing that sits **between autonomous security agents and dangerous actions.**
A safety wrapper that governs an agent's actions via `govern()`:

```
Agent → govern() → ICEBOX (Policy · Sandbox · Approval · Audit) → Real World
```

Two ideas:
1. **Protect something** (`icebox init`).
2. **Govern dangerous actions** (`govern()` → allowed? do it).

## Status: v1.0.0-beta
The product is coherent and discoverable in under five minutes. Kernel is frozen
like Linux; all work happens in the SDK, CLI, examples, and docs.

- Governance core validated: fail-closed, durable audit, approval gating.
- SDK is the hero surface: `from icebox import govern`, `if govern(...):`.
- `icebox init` (what do you want to protect?) and `icebox doctor` ship.
- Framework recipes in `examples/` (Claude Code, OpenAI Agents, CrewAI, AutoGen).

## Decisions (founder, 2026-07)
- **Freeze the feature set.** No new kernel/governance primitives. The one job:
  "I have an autonomous security agent. I don't trust it. I want guardrails."
- **Do NOT build:** marketplace, ecosystem, policy packs, "AI OS", 50 integrations,
  enterprise features, K8s. Stop calling it an "AI security OS" / "K8s for agents".
- **SDK/UX is the leverage, not the kernel.** Next value comes from delight and
  adoption (onboarding, examples, distribution) — not more governance primitives.
- **Examples, not integrations.** Framework wrappers live in `examples/` as
  recipes; we do not track upstream APIs or ship an integrations package.
- **Two concepts only.** Protect something. Govern dangerous actions. No new
  terminology.

## Pre-publish mechanical (deferred)
- Tag `v1.0.0-beta` at current HEAD.
- Rotate crates.io / PyPI tokens (exposed at 0.2.6 publish).
- Manual publish: `cargo build --release` for the daemon, build + upload the
  Python wheel from `python/` (PyPI deferred pending token rotation).
