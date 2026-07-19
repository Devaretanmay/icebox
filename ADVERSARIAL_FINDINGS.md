# ICEBOX Adversarial / Robustness Assessment — v0.2.7 (pre-release)

**Author:** red-team pass (no new features; attempt to break the guarantees)
**Scope:** Categories 1 (malicious agent), 2 (policy engine), 4 (audit trail), 5 (SDK/interface parity), 7 (persistence/recovery). Categories 3 (sandbox), 6 (multi-agent), 8 (enterprise), 9 (perf), 10 (5-model red-team) were not yet executed — see "Remaining Work".
**Method:** drove the **real debug daemon** over REST + Python SDK + CLI. Findings are reproduced, not theoretical. Every claim cites `file:line`.

---

## TL;DR

The **enforcement seam is fundamentally sound**: a malicious agent cannot smuggle capabilities, cannot bypass approval with `approved:true`, cannot TOCTOU-swap capability between preflight and execution, and the sandbox fails closed. **But the product's headline guarantee — a durable, tamper-evident audit trail — is currently not met at all.** The audit chain is in-memory only and is lost on every restart, is not included in workspace snapshots, and is written non-atomically when explicitly saved. Additionally, a very common policy pattern (`target_pattern: ".*"`) silently never matches, which neutralizes "approve/deny everything" rules. Both are release-blocking for a governance product.

Severity tally:
- CRITICAL: C1 (audit not persisted), C2 (`target_matches` ignores `.*`)
- HIGH: H1 (corrupt policy fails open), H2 (persistence manual/opt-in), H3 (non-atomic save)

## Remediation status (updated)

| ID | Finding | Status | Commit / evidence |
|----|---------|--------|------------------|
| C1 | Audit not persisted | **FIXED** | `audit.rs` `HashChain::with_path` (fsync per append, replay on load); `build_framework` attaches `~/.icebox/audit.jsonl`; `WorkspaceSnapshot` carries `audit_entries`. Verified: 3 decisions survive restart. |
| C2 | `target_matches` ignores `.*` | **FIXED** | `safety.rs:536` now treats `*`/`/.*` as match-all. Verified: `RequireApproval{Persistence,".*"}` blocks `reverse_shell_generator` even with `approved:true`. |
| H1 | Corrupt policy fails open | **FIXED** | `main.rs` `build_framework`: load failure → `executor.safe_mode` set; `ConfigPolicy::evaluate` denies everything (`SAFE MODE`). Verified: corrupt `policy.yaml` → all governs DENY with safe-mode reason. |
| H3 | Non-atomic save | **FIXED** (audit + workspace) | `audit.rs` `save` and `workspace.rs` `save_to_file` use temp-file + rename. |
| H2 | Persistence manual/opt-in | PARTIAL | Audit now auto-persists (C1). Charter/scope/policy still require explicit `save`/`load`. |

### Deep Category-4 re-test (durable ledger) — all pass
- Delete audit file → daemon starts, empty trail, no panic.
- Corrupt MIDDLE line (valid structure, hash tampered) → integrity verify fails → file **quarantined** to `audit.jsonl.corrupt`, fresh ledger starts (0 entries), loud ERROR. No silent loss.
- Truncated (partial) last line (simulated crash mid-write) → prefix recovered (3 of 4), truncated tail dropped, chain continues on new appends (→5).
- `verify()` still detects in-memory tampering (unit tests).

### Still open
- H2 (charter/scope/policy auto-persist) — audit is now durable; the rest remains manual.
- Categories 3 (sandbox), 6 (multi-agent), 8 (enterprise), 9 (perf), 10 (5-model red-team) not yet executed.

- PASSED: 8 core guarantees held under adversarial input

---

## 1. What works (verified under attack)

| # | Guarantee tested | Result | Evidence |
|---|---|---|---|
| G1 | Capability swap between approval & execution (TOCTOU) | **HOLDS** | `execute()` rebuilds `Preflight` from the *loaded module's* real capabilities (`executor.rs:286,311`) and re-runs `policy.evaluate` (`executor.rs:315`) before any execution. REST `run_module` has no `capability` field (`rest.rs:54-62`); capability comes only from `crate::modules::load`. |
| G2 | `approved:true` cannot bypass `RequireApproval` | **HOLDS** | `Preflight::check` maps `RequireApproval`→`Err` regardless of flag (`safety.rs:499`). Empirically: `run_module reverse_shell_generator approved:true` was blocked once pattern matched. |
| G3 | Sandbox is mandatory, fails closed | **HOLDS** | Missing sandbox worker → `"Isolation is mandatory"` refusal (`rest.rs` execute path). No silent unsandboxed run. |
| G4 | In-memory audit tamper-evidence | **HOLDS (moot until C1)** | `HashChain::verify()` detects altered `hash`/`prev_hash` (`audit.rs:107-120`). Unit tests confirm tampered chain fails verify (`audit.rs:201`). |
| G5 | Malformed capability input | **HOLDS** | empty capability → deny (`executor.rs:149`); object capability → HTTP 422 (serde `capability: expected a string`); unknown capability → deny (`executor.rs:148`). |
| G6 | Lie about risk level | **HOLDS** | `destructive:true` triggers `RequireApproval` even when `impact:"low"` (`safety.rs:450`). Verified: destructive+low → require_approval. |
| G7 | Load + Deny same capability | **HOLDS (deny wins)** | `PolicySet::denied` checked first (`safety.rs:638`). Deny overrides Allow/RequireApproval. |
| G8 | Volume / concurrency | **HOLDS** | 1000 repeated governs + 50 concurrent governs: no crash, no decision flip, no errors. |
| G9 | Prompt injection via action/notes fields | **HOLDS** | `action` is opaque string; `govern_action` only reads `capability`/`target`/`impact`/`destructive` (`executor.rs:145-197`). Injection string treated as module name only. |
| G10 | SDK `govern()` evaluates daemon policy | **HOLDS** | `govern_handler`→`govern_action` runs `policy.evaluate` on the payload capability (`executor.rs:184`, `rest.rs:1186`). Verdict reflects live policy. |

---

## 2. CRITICAL findings

### C1 — Audit trail is not persisted; lost on every restart
- **What:** `HashChain` exists only in `executor.audit` (memory). `save()` is called only in unit tests (`audit.rs:236`). The live daemon never writes the chain to disk.
- **`WorkspaceSnapshot` omits the audit chain entirely** (`workspace.rs:11-20` lists charter/scope/policy/memories/jobs/sessions — no `audit`). So even an explicit `save`→`load` cycle drops all history.
- **Reproduced:** made 2 decisions via REST; restarted daemon on same `--workspace`; `GET /api/v1/audit?n=100` returned **0**; workspace dir was empty (no audit file written).
- **Impact:** The product's core promise ("tamper-evident audit trail you can trust after a crash") is **not delivered**. An autonomous agent deployed with ICEBOX leaves no durable record of what it did. This is the #1 release blocker.
- **Fix direction:** append-only on-disk ledger (one line per decision, fsync), auto-flushed in `record_decision`/`govern_action`; load on startup; include in `WorkspaceSnapshot`; `verify()` on load.

### C2 — `target_matches` ignores `.*`; every "all targets" rule is a silent no-op
- **What:** `target_matches` (`safety.rs:536-543`) supports only a trailing-`*` prefix match or exact equality. `".*"` is treated as a literal string and matches nothing.
- **Reproduced:** Added `RequireApproval{Persistence, ".*"}`; `run_module reverse_shell_generator approved:true` **ran past the gate** (reached sandbox-provisioning stage). Switching pattern to `"*"` correctly blocked it.
- **Blast radius:** `examples/agent_exercise.py:31` ships `"target_pattern": ".*"` — its approval gate is dead against real targets (it only *appeared* to work because the daemon was allow-all and the `destructive` flag independently triggered approval). Any user writing the intuitive catch-all rule is silently unguarded.
- **Impact:** A primary safety control (gate everything, require approval for everything) does not function. Release blocker.
- **Fix direction:** support `*` (any) and/or real regex; at minimum treat `.*` as catch-all. Audit all `.*` usages in examples/SDK.

---

## 3. HIGH-severity findings

### H1 — Corrupt policy file fails OPEN, not closed
- **What:** `main.rs:167-174`: if `~/.icebox/policy.yaml` fails to parse, daemon logs a warning and **continues with default empty policy** (no deny rules, no approval rules).
- **Impact:** A tampered/corrupt policy silently drops all guardrails; the agent can run low/medium actions freely. For a governance tool, corrupt policy should fail closed (refuse to govern until resolved).
- **Fix direction:** on parse failure, start in a deny-all "safe mode" or refuse to serve `govern` until policy is valid.

### H2 — Persistence is manual and opt-in
- **What:** charter/scope/policy survive only via explicit `save`/`load` commands (`main.rs:475-513`). No auto-persist per decision or on shutdown. On restart, daemon starts fresh (proved: scope `[]`, charter reset, audit gone).
- **Impact:** A deployed agent has no memory of prior approvals or policy between restarts; combined with C1, zero continuity.
- **Fix direction:** auto-save policy/charter/scope (atomic) on change; load on startup.

### H3 — `save` writes non-atomically
- **What:** `WorkspaceSnapshot::save_to_file` uses `std::fs::write` (`workspace.rs:84`) — truncates then writes; a crash mid-write corrupts the file. `load_from_file` then returns parse error → operator starts fresh (data loss).
- **Fix direction:** write to temp file + `rename` (atomic). Same for the audit ledger.

---

## 4. Category 2 — Policy engine edge cases (verified)

Precedence in `PolicySet::evaluate` (`safety.rs:637-713`):
1. **DenyCapability** wins first (`safety.rs:638`). → Allow+Deny same cap = DENY. ✅ correct.
2. If not `pre_approved` (no `AllowCapability` for any req cap): explicit `RequireApproval{cap,pattern}` fires if cap present AND `target_matches` (broken per C2). ✅ logic correct, blocked by C2.
3. `MaxRisk(m)` = min over all `MaxRisk` rules (`safety.rs:579-584`) → most restrictive. ✅
4. Default policy: charter → scope → max_risk → destructive/high-risk→RequireApproval → Allow (`safety.rs:433-456`). ✅
5. **Subtle:** if `pre_approved` (some cap is `AllowCapability`), a `RequireApproval` from the *default* policy is downgraded to Allow (`safety.rs:709-710`). But an *explicit* `RequireApproval{cap}` rule still fires regardless of `pre_approved` (`safety.rs:644-662`). Net: `AllowCapability` + `RequireApproval{same cap}` → the explicit RequireApproval wins. Verified expectation: approval should win over allow — correct.
6. **Policy update during execution:** rules are behind `fw.lock()`; `govern_action`/`execute` hold the lock for the eval. A concurrent `add_policy_rule` waits. No TOCTOU within a single decision. ✅ (concurrent *across* decisions: last-writer-wins, by design.)

Unverified in this pass: `DenyIfCvssAbove` / `RequireApprovalIf` (need CVSS path), policy rollback, invalid/empty policy packs, version mismatch.

---

## 5. Category 5 — Interface parity (verified + gap)

- **REST `govern`** and **Rust executor** share `govern_action`/`policy.evaluate` — same verdict semantics. ✅
- **Python SDK `GovernClient.govern`** calls REST `govern` → same engine. ✅
- **Python native `Governance.check`** (PyO3 `_icebox.preflight_action`) runs the **Rust engine directly** (`_sdk.py:328-339`). Same `PolicyDecision` vocabulary (`Allowed`/`Blocked`/`NeedsApproval`). ✅ parity holds *if* the native ext is built.
- **Gap:** when PyO3 ext is absent, `Governance.check` falls back to `run_module` over REST (`_sdk.py:341-346`) — a *different* code path (runs a real module, not a virtual preflight). Behavior diverges (executes vs evaluates). Low risk but a parity inconsistency to document.
- **CLI `icebox govern`** → `run_govern` → `govern_action` (`main.rs:29-50`). ✅ same engine.

---

## 6. Reproduced attack transcript (excerpt)

```
# C2 proof: RequireApproval{Persistence,".*"} does NOT block
POST /modules/reverse_shell_generator/run {"target":"10.0.0.5","approved":true,...}
 -> passed=True, reached "sandbox error: ... Isolation is mandatory"
# Fix: switch pattern to "*"
POST /policy/rules {"require_approval":{"capability":"Persistence","target_pattern":"*"}}
POST /modules/reverse_shell_generator/run {"target":"10.0.0.5","approved":true,...}
 -> passed=False, reason="destructive / high-risk action requires explicit approval"

# C1 proof: audit lost on restart
GET /audit?n=100  -> 2 entries
(pkill + restart daemon, same --workspace)
GET /audit?n=100  -> 0 entries; workspace dir empty
```

---

## 7. Recommended fix priority (matches founder's list)

1. **C1** — durable append-only audit ledger on disk (auto-flush + load + verify).
2. **C2** — real wildcard/regex in `target_matches`; fix `.*` usages in examples/SDK.
3. **H1** — fail closed on corrupt policy.
4. **H2 + H3** — atomic auto-persist of policy/charter/scope; include audit in snapshot.
5. Return to Categories 3, 6, 8, 9, 10 once trail is durable.

---

## 8. Remaining work (not yet executed)

- **Category 3 (Sandbox):** Docker-unavailable/crash/timeout/OOM/leak/100-containers — sandbox worker not built in this env, so not exercised.
- **Category 4 deep:** delete/corrupt/modify audit file, invalid SHA, out-of-order, replay, partial write, concurrent write, millions of records — blocked by C1 (no file yet). Re-test after C1 fix.
- **Category 6 (Multi-agent):** 100 agents / 1000 actions / shared trail stress — do after durable trail exists.
- **Category 8 (Enterprise scenarios):** AWS/IAM/pentest/SOC/bug-bounty simulations.
- **Category 9 (Perf):** latency/throughput/memory under load.
- **Category 10 (5-model red-team):** hand ICEBOX + "break it" prompt to Claude/GPT/Gemini/DeepSeek/Qwen.

---

## 9. Verdict

**Do not ship 0.2.7 yet.** The enforcement model is genuinely good — a hostile agent cannot subvert capability gating, approval, or sandboxing through the documented interfaces. But two release-blocking defects (C1 audit durability, C2 wildcard matching) directly contradict the product's central claims, and three high-severity gaps (H1–H3) weaken recovery and persistence guarantees. Fix C1 + C2 first; they are small, well-scoped changes. Re-run this adversarial pass (especially Category 4 deep + 6) after the trail is durable.
