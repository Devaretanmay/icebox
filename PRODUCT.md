# ICEBOX — Product Identity

## What ICEBOX is, in one sentence

> ICEBOX is a fail-closed governance kernel that deterministically decides whether
> autonomous agents are permitted to perform dangerous actions and durably
> records those decisions.

That sentence is fully supported by the codebase. Everything else is in service
of one job.

## The irreducible primitive

At the code level, ICEBOX owns exactly one thing: **the decision of whether an
autonomous action should be allowed to happen.** It does not execute the action,
run the agent, or manage the target. The agent executes; ICEBOX decides.

```
                    AI AGENT
                       |
                  govern(action)
                       |
                       v
                SHOULD THIS HAPPEN?
                       |
         -----------------------------------
         |                |               |
       ALLOW       REQUIRE APPROVAL       DENY
         |                |               |
         v                v               X
    Agent executes     Human decides
         |
         v
     Real World
```

Every module in the governance core exists only to make that decision
deterministic, auditable, and enforceable.

## Architecture

```
THE PRODUCT

- govern()
- icebox init
- icebox doctor
- examples/

        ↓

THE GOVERNANCE CORE

- executor.rs   enforces the mandatory execution seam
- safety.rs     evaluates policy, scope, capabilities, risk
- sandbox.rs    provides isolation when required
- audit.rs      makes every decision durable and tamper-evident
- sdk.rs        defines governance decision types
- src/interfaces/rest.rs  exposes the same governance semantics externally

        ↓

THE AGENT'S WORLD (governed, not owned by ICEBOX)

- AWS
- GitHub
- Filesystems
- Infrastructure
- Pentesting tooling
- Cloud APIs
```

## What ICEBOX is NOT

These abstractions do not exist in the source code. They are intellectual
inflation and have been deliberately excluded:

- Trust engine
- Decision engine
- Approval engine
- Agent runtime
- Execution layer
- Governance runtime
- AI operating system

ICEBOX is not an "OS kernel" or "agent kernel" in the operating-system sense.
Linux owns process execution, memory, scheduling, filesystems, and syscalls;
ICEBOX owns none of those. The term "governance kernel" is used only because
ICEBOX owns the invariants around governance decisions — nothing more.

## Status: v1.0.0-beta

The governance core is frozen and trusted. All current work is on SDK ergonomics,
onboarding, docs, and examples.

## The boring-infrastructure principle

The better ICEBOX becomes, the more boring it should feel.

Bad infrastructure products get more exciting over time:

```
AI OS → Agent Runtime → Governance Platform → Marketplace → Enterprise Dashboard
```

Good infrastructure products get more invisible over time:

```
pip install icebox-sdk
  ↓
icebox init
  ↓
if govern(...):
    do_the_thing()
  ↓
Never think about ICEBOX again.
```

If six months from now users are spending time thinking about ICEBOX, that is
probably failure. If they forget it exists because they trust the
allow/approval/deny decisions and keep building agents safely, that is success.
The strongest version of ICEBOX is also the most boring: a small, deterministic
piece of infrastructure that quietly prevents autonomous agents from doing
dangerous things unless they are allowed to.

## Decisions (founder, 2026-07)

- **Freeze the feature set.** No new kernel/governance primitives. The one job:
  "I have an autonomous security agent. I don't trust it. I want guardrails."
- **Do NOT build:** marketplace, ecosystem, policy packs, "AI OS", agent runtime,
  50 integrations, enterprise features, K8s. Anything beyond the primitive above
  is currently unsupported by the implementation and risks turning a coherent
  governance product into an unnecessarily grand narrative.
- **SDK/UX is the leverage, not the core.** Next value comes from delight and
  adoption (onboarding, examples, distribution) — not more governance machinery.
- **Examples, not integrations.** Framework wrappers live in `examples/` as
  recipes; we do not track upstream APIs or ship an integrations package.
- **Two concepts only.** Protect something. Govern dangerous actions.

## Pre-publish mechanical (deferred)

- Tag `v1.0.0-beta` at current HEAD.
- Rotate crates.io / PyPI tokens (exposed at 0.2.6 publish).
- Manual publish: `cargo build --release` for the daemon, build + upload the
  Python wheel from `python/` (PyPI deferred pending token rotation).
