# Core Features & Functionalities

ICEBOX provides an extensive suite of features designed to securely govern, audit, and normalize offensive security tasks. Here is a breakdown of what the platform brings to the table and how to use it.

### 1. The Governance Seam (Central Choke Point)
Every action taken against a target passes through the `ModuleExecutor::execute()` seam. This guarantees that no offensive tool can bypass your security policy. 

**The Problem it Solves:** An autonomous agent hallucinates a payload against a production server instead of a staging server.
**How to use it:** You don't need to do anything. The Governance Seam is active by default. All requests, whether via the CLI, REST API, or Python SDK, are automatically intercepted and evaluated.

### 2. Multi-Context Execution Interfaces
ICEBOX meets you where you operate. It ships with four native contexts: a CLI REPL, a REST API (`icebox --api`), a Rust SDK (`icebox-gov`), and a Python SDK (`icebox-sdk`).

**The Problem it Solves:** Orchestration tools are built in different languages. You shouldn't have to rewrite your architecture to add security boundaries.
**How to use it:** 
- CLI: Run `icebox`
- REST: Run `icebox --api`
- Python: `pip install icebox-sdk`

### 3. Dynamic Scope Enforcement
Operators explicitly define what network boundaries, domains, or directories the framework is allowed to touch.

**The Problem it Solves:** Preventing tools from scanning unauthorized networks (e.g., scanning `10.0.0.5` when only `127.0.0.1` is authorized).
**How to use it:** 
- CLI: `scope add 127.0.0.1`
- REST: `POST /api/v1/scope/add {"target": "127.0.0.1"}`

### 4. Charters and Rules of Engagement
Every engagement requires an explicit "Charter" to be accepted before any tool can fire, which can enforce specific Rules of Engagement.

**The Problem it Solves:** Ensuring legal compliance and operational boundaries before executing tasks.
**How to use it:** 
- CLI: `charter accept --engagement local-audit`

### 5. Risk-Based Execution Policies
ICEBOX dynamically evaluates the risk level of the capabilities a module wants to use against your configured maximum risk tolerance.

**The Problem it Solves:** An agent tries to run a highly destructive memory exploit during a low-risk reconnaissance operation.
**How to use it:** 
- Set your max risk in the engine initialization (`"max_risk": "low"`). Any action exceeding this risk is blocked.

### 6. Human-in-the-Loop Approvals Workflow
When a module requests a high-risk action, ICEBOX transitions it into a `NeedsApproval` state.

**The Problem it Solves:** Autonomous agents shouldn't be completely blocked if they genuinely need to run a high-risk task; they just need human permission.
**How to use it:** 
- CLI: `approve list` followed by `approve approve <id>`

### 7. Modular Plugin Architecture
Developers can wrap standard Rust functions with the `#[module]` procedural macro to instantly register them with the governance engine.

**The Problem it Solves:** Writing boilerplate code to integrate new offensive tools into your governance framework is tedious.
**How to use it:** 
```rust
#[module(name = "my_tool", capabilities = ["network_scan"])]
pub struct MyTool { /* ... */ }
```

### 8. Immutable Audit Engine
ICEBOX maintains a continuous, immutable audit trail of every single decision it makes.

**The Problem it Solves:** Trying to figure out exactly what an agent did and why it did it during a compliance review.
**How to use it:** 
- Python: `audit_log = gov.audit_json()`
- CLI: `audit json`

### 9. Evidence Intelligence & Normalization
ICEBOX standardizes the chaotic output of offensive tools into structured `Evidence` JSON schemas.

**The Problem it Solves:** Downstream orchestration tools struggle to parse messy, unstructured command-line text from security scanners.
**How to use it:** 
Run any module (like `whois_lookup` or `vuln_scanner`). The returned `data` array will be normalized JSON.

### 10. Role-Based Access Control (RBAC)
The framework differentiates between `operators` and `admins`.

**The Problem it Solves:** A compromised agent shouldn't be able to expand its own authorized scope or approve its own destructive actions.
**How to use it:** 
- REST: `POST /api/v1/role {"role":"operator"}`

### 11. Pre-built Policy Packs
ICEBOX supports shareable, pre-built JSON Policy Packs for best-practice governance.

**The Problem it Solves:** Writing policies from scratch for every engagement causes configuration fatigue.
**How to use it:** 
- CLI: `pack apply production` or `pack apply bug_bounty`

### 12. Autonomous AI Campaign Mode
ICEBOX features dedicated REPL commands designed specifically for LLM orchestrations when connected to a local Ollama instance.

**The Problem it Solves:** Setting up multi-agent security campaigns is typically complex and un-governed.
**How to use it:** 
- CLI: Use the `agent`, `campaign`, and `validate` commands inside the REPL.
