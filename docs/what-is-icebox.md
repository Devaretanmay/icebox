# What is ICEBOX?

ICEBOX is the **runtime governance layer for autonomous and human-driven offensive
security**. It is the single, mandatory boundary — the **Governance Seam** — that
every action must pass through before anything touches an authorized target.

Instead of letting an agent call `nmap` or an exploit script directly, you force all
execution through ICEBOX. Before a single packet hits the wire, ICEBOX intercepts the
request, evaluates the risk, checks the operational scope, verifies the legal
charter, and makes a hard decision: `Allow`, `Block`, or `NeedsApproval`.

## Why ICEBOX exists

Giving autonomous agents the ability to run offensive security tools is a terrifying
prospect. One minute an agent is scanning a staging environment; the next it's
hallucinating an SQL injection against production because a prompt confused it. The
offensive security space needs automation, but it cannot afford *reckless*
automation.

ICEBOX exists to make reckless automation impossible. By explicitly defining your
Rules of Engagement, Max Risk Tolerance, and Scope Allow-lists, you strip the
life-or-death decisions away from the LLM. If the agent hallucinates an out-of-scope,
high-risk action, ICEBOX simply blocks it, records the failure in a tamper-evident
audit log, and lets the agent try again. You get the speed of AI-driven security with
the ironclad guarantees of deterministic policy enforcement.

## Who is ICEBOX for?

- **Red teams and security engineers** who want to run autonomous or semi-autonomous
  tooling without surrendering control or accountability.
- **Platform teams** building multi-agent security orchestration where many agents
  share one governed, auditable trail.
- **Compliance-minded orgs** that need to *prove* what an agent was permitted to do,
  why, and whether the controls held — after the fact, from an immutable log.

ICEBOX is **not** a scanner, an exploit framework, or a dashboard. It is the seam
those tools run through. The bundled offensive modules are reference implementations
that exercise the seam; the framework governs *arbitrary* tools and agents.

## The one call: `govern()`

Across every surface, governing an action looks the same:

- **Rust:** `govern(config)` → `GovernanceRuntime` with `.run()` / `.execute()`.
- **Python:** `with govern(config) as g:` context manager (or `Governance(...).run()`).
- **REST:** `POST /govern` with a task payload.

One model, three surfaces. See the [Quickstart](quickstart.md) and SDK docs.

## Guarantees and limitations (read this)

ICEBOX's kernel is **frozen** and its guarantees are written down in
[GEE_INVARIANTS.md](GEE_INVARIANTS.md). In brief:

**It guarantees:**
- Every action passes through a fixed, forward-only 10-stage lifecycle
  (Request → Authorization → PolicyEvaluation → CapabilityCheck → ApprovalCheck →
  SandboxProvisioning → Execution → Validation → Audit → Destroy).
- Policy is enforced at the correct boundary; capability precedence is fixed
  (`DenyCapability` absolute, `AllowCapability` overrides explicit approval gates).
- Isolation is tier-driven and caller-controlled weakening is impossible.
- The audit trail is a SHA-256 hash chain with a zero-hash genesis — tampering is
  detectable.
- Evidence is preserved even as the sandbox is destroyed.

**It does NOT guarantee:**
- That an *allowed* action is safe. If you permit a capability, ICEBOX executes it
  **governed, not sanitized**. Governance is about control and accountability, not
  magic safety.
- Protection for code that bypasses `ModuleExecutor`. That is why the kernel must
  remain the *only* execution path.
- Recovery of a lost or silently swapped audit-chain file. The chain detects
  tampering; it cannot restore what's gone.
- Perfection of the sandbox image. ICEBOX enforces that a sandbox *exists* for
  `Freezer`/`DeepFreeze`; the strength of that sandbox depends on your Docker/tier
  configuration.

Treat ICEBOX as a seatbelt, not an airbag: it keeps you accountable and contained, it
does not make a bad policy harmless.
