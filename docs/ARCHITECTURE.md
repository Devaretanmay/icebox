# Architecture

ICEBOX reduces to one irreducible primitive:

> **Should this action happen?**

The codebase owns exactly one thing — the decision of whether an autonomous
action is allowed — and nothing else. It does not execute the action, run the
agent, or manage the target. The agent executes; ICEBOX decides.

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

## Layers

```
THE PRODUCT

- govern()          one call: is this allowed?
- icebox init       what do you want to protect?
- icebox doctor     are you protected?
- examples/         recipes: claude_code, openai_agents, crewai, autogen

        ↓

THE GOVERNANCE CORE  (frozen; the "governance kernel")

- executor.rs   enforces the mandatory execution seam (fail-closed)
- safety.rs     evaluates policy, scope, capabilities, risk
- sandbox.rs    provides isolation when required
- audit.rs      makes every decision durable and tamper-evident (SHA-256 chain)
- sdk.rs        defines governance decision types
- (src/interfaces/rest.rs) exposes the same governance semantics over REST

        ↓

THE AGENT'S WORLD  (governed, not owned by ICEBOX)

- AWS
- GitHub
- Filesystems
- Infrastructure
- Pentesting tooling
- Cloud APIs
```

### Supporting scaffolding (not part of the decision primitive)

The following modules exist in `src/core/` but are machinery that *serves* the
decision, not separate "engines." They hold the state and types the agent
interaction model needs; they do not decide anything on their own.

- `module.rs` — capability / intent / module-kind types
- `governance.rs` — roles, policy-pack, and approval-status types
- `job.rs` / `session.rs` — job and session state records
- `workspace.rs` — durable workspace snapshots (state persistence)
- `framework.rs` — shared framework container wiring the executor together
- `gee.rs` — the internal staged execution lifecycle the executor enforces
- `proxy/` — egress isolation (network-namespace / TCP proxy) for contained runs

None of these are "trust", "decision", "approval", or "runtime" engines. They are
data structures and plumbing around the single question: should this happen?


## What is deliberately absent

These do not exist in the source and are not planned. They are intellectual
inflation:

- Trust engine
- Decision engine
- Approval engine
- Agent runtime
- Execution layer
- Governance runtime
- AI operating system

ICEBOX is not an "OS kernel" in the operating-system sense: it owns no process
execution, memory, scheduling, filesystems, or syscalls. "Governance kernel" is
used only because ICEBOX owns the invariants around governance decisions.

## The one invariant

Fail closed. Every action an agent wants to take is policy-checked,
scope-enforced, approval-gated when required, and audited. If the core cannot
reach a confident allow decision, the answer is deny.
