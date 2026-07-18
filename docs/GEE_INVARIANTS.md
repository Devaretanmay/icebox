# GEE Invariants

This document records the **non-negotiable guarantees** of the ICEBOX Governed
Execution Environment (GEE). The kernel that provides these guarantees is
**frozen** as of `v0.2.5-kernel-complete`. Any change to `src/core/**` that
weakens or removes an invariant below is a regression and must be rejected.

The GEE is the single seam every human operator, REST client, and LLM agent
must pass through before anything touches a target. Nothing executes outside
it.

---

## 1. Stage machine is forward-only and complete

The GEE traverses a fixed, ordered set of stages for every action:

```
Request → Authorization → PolicyEvaluation → CapabilityCheck →
ApprovalCheck → SandboxProvisioning → Execution → Validation →
Audit → Destroy
```

- **Forward-only.** `transition_to()` rejects any transition that skips a stage
  or moves backward. You cannot jump to `Execution` without passing
  `Authorization`, `PolicyEvaluation`, `CapabilityCheck`, and `ApprovalCheck`.
- **Complete.** `execute()` asserts it starts at `Request` and walks all ten
  stages; it cannot return having skipped one.
- **Reset.** On every exit path (success, denial, or error) the stage machine
  resets to `Request`, so no action inherits another action's state.

## 2. Policy is enforced at the correct boundary

- A policy `Deny` is enforced at `PolicyEvaluation` — before capability checks
  or approval.
- `RequireApproval` is enforced at `ApprovalCheck` — after policy evaluation.
- Redundant re-checks were removed; the single authoritative enforcement point
  for each decision is the stage named above.

## 3. Capability precedence is fixed

For a given capability:

1. `DenyCapability` is **absolute** — it wins over everything.
2. `AllowCapability` overrides an explicit `RequireApproval` rule.
3. `AllowCapability` overrides a `RequireApprovalIf` (e.g. CVSS-gate) rule.
4. Otherwise `RequireApproval` / `RequireApprovalIf` apply normally.

This precedence is tested and must not be reordered.

## 4. Isolation is tier-driven, never caller-controlled

- The caller **cannot** request a weaker sandbox. `RunPayload.sandbox` and the
  Python SDK `sandbox=` parameter were removed.
- `ModuleExecutor::new()` defaults to `Tier::Fridge` in tests, but every
  production path (`main.rs`, `icebox-py`) sets `Tier::Freezer` explicitly.
- `Freezer` / `DeepFreeze` tiers **require** a sandbox; `Fridge` is the only
  non-isolated tier and is used only where isolation is intentionally off.

## 5. Audit chain is tamper-evident

- The audit trail is a **SHA-256** hash chain (migrated from SHA-1). Each record
  hashes the previous record's hash plus its own payload.
- The **genesis** record is 64 hex zeros — there is no trusted "first" hash to
  forge.
- The chain is persisted via `HashChain::save(path)` / `load(path)` (JSON). A
  missing file loads as an empty chain; a tampered file fails integrity.
- At `Validate`, the chain is **verified**: SHA-256 integrity, monotonic
  evidence timestamps, and non-empty decision records. If verification fails,
  the action does not complete cleanly.

## 6. Evidence survives destruction

- At `Destroy`, the sandbox is torn down, but logs are **preserved as evidence**
  via `teardown_sandbox()`. Tearing down isolation must not discard the audit
  trail.

## 7. Every action is recorded with its decision

- `record_action()` accepts the `PolicyDecision` that was made. There is no path
  to execute an action without recording why it was allowed, denied, or
  approved.

---

## What the GEE does NOT guarantee

To keep expectations honest (see the "guarantees and limitations" docs):

- It governs what passes through the seam. It does **not** police code that
  bypasses `ModuleExecutor` entirely — that is why the kernel must remain the
  only execution path.
- It does **not** make an unsafe *policy* safe. If an operator allows a
  capability, the GEE executes it governed, not sanitized.
- Sandbox strength depends on correct Docker/tier configuration; the GEE
  enforces the *requirement* that a sandbox exist for `Freezer`/`DeepFreeze`,
  not the perfection of the sandbox image.
- Audit integrity depends on the chain file not being silently swapped; the
  SHA-256 chain detects tampering but cannot recover a lost chain.

---

## Changing the kernel

A kernel change is acceptable **only** if it:

1. fixes a bug that violates one of the invariants above, or
2. fixes a security issue, or
3. materially **strengthens** a GEE guarantee (e.g. stronger isolation, stronger
   audit integrity).

Any new runtime feature that does not fall into one of these categories belongs
in Layer 2 (security distribution) or Layer 3 (ecosystem), not in `src/core/`.
