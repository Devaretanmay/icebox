# Quickstart Guide

ICEBOX is designed to be dead simple to install and integrate, regardless of your tech stack. Whether you are a Rust developer, a Python data scientist, or just an operator looking for a CLI, you can get ICEBOX running in under two minutes.

## Installation

### The CLI & REST Server
To install the ICEBOX binary, which provides the interactive REPL and the standalone REST API server, use `cargo`:

```bash
cargo install icebox-gov
```

This will place the `icebox` binary in your path.

### The Python SDK
For Python developers and AI orchestrators, ICEBOX ships a native C-ABI bound package directly to PyPI. You do not need the Rust toolchain to use the Python SDK.

```bash
pip install icebox-sdk
```

---

## 1. Using the CLI (REPL)

The ICEBOX CLI drops you into an interactive session where you can manually configure the governance engine, load policies, and run security modules.

```bash
$ icebox
REST API listening on 127.0.0.1:8443
icebox> charter accept --engagement local-audit
accepted: --engagement local-audit
icebox> scope add 127.0.0.1
added: 127.0.0.1
icebox> pack apply production
pack applied: production (policy now v1)
icebox> use recon
loaded recon (in-scope: n/a (set a target with `run <target>`))
icebox> run 127.0.0.1
preflight passed
job 1 completed
icebox> exit
```

## 2. Using the REST API

When you run `icebox`, it automatically spawns a REST API in the background on `127.0.0.1:8443`. If you want to run the REST API headless without the REPL, use:

```bash
$ icebox --api
REST API listening on 127.0.0.1:8443
```

You can interact with the engine using standard HTTP requests:

```bash
# Accept a charter
curl -X POST http://127.0.0.1:8443/api/v1/charter \
  -H "Content-Type: application/json" \
  -d '{"engagement":"rest-audit","rules_of_engagement":[]}'

# Set the scope
curl -X POST http://127.0.0.1:8443/api/v1/scope \
  -H "Content-Type: application/json" \
  -d '{"target":"127.0.0.1"}'

# Execute a module
curl -X POST http://127.0.0.1:8443/api/v1/modules/recon/run \
  -H "Content-Type: application/json" \
  -d '{"target":"127.0.0.1","approved":true}'
```

## 3. Using the Python SDK

The Python SDK is the recommended path for integrating ICEBOX into autonomous agent frameworks (like LangChain, AutoGen, or custom loops). Isolation is **tier-driven**, not caller-controlled — pick `Fridge` (no sandbox), `Freezer`, or `DeepFreeze` (both require a sandbox); you cannot weaken a stronger tier from code.

```python
from icebox import Governance

gov = Governance({
    "charter": {"accepted": True, "engagement": "demo", "rules_of_engagement": []},
    "scope": {"allow": ["127.0.0.1"]},
    "max_risk": "critical",
    "role": "admin",
    # "tier": "freezer"  # optional; defaults to a safe tier in production paths
})

verdict = gov.run({
    "name": "recon",
    "target": "127.0.0.1",
    "capabilities": ["network_scan"],
    "impact": "low",
    "destructive": False,
})
print(verdict)
```

> The flagship `govern()` context manager and the REST `POST /govern` endpoint
> mirror this exact shape. See `docs/sdk-python.md`.

## 4. Using the Rust SDK

If you are building high-performance tooling natively in Rust, import `icebox` and
build a runtime with `GovernanceBuilder`, then drive actions through `govern()`.

```rust
use icebox::core::sdk::{GovernanceBuilder, TaskSpec, GovernedOutcome};
use icebox::core::safety::{Capability, Charter, RiskLevel, Role};
use serde_json::json;

#[tokio::main]
async fn main() {
    let rt = GovernanceBuilder::new()
        .charter(Charter::accept("rust-audit", vec![]))
        .scope(vec!["127.0.0.1".into()])
        .max_risk(RiskLevel::Critical)
        .role(Role::Admin)
        .build();

    let task = TaskSpec {
        name: "recon".into(),
        target: "127.0.0.1".into(),
        capabilities: vec![Capability::NetworkScan],
        impact: RiskLevel::Low,
        ..Default::default()
    };

    // `.run` auto-grants approval; `.execute` requires it.
    match rt.run(task, || async { Ok(json!({"open_ports": [22, 80]})) }).await {
        GovernedOutcome::Allowed { result, .. } => println!("Success: {result}"),
        GovernedOutcome::Blocked { reason, .. } => println!("Blocked: {reason}"),
        GovernedOutcome::NeedsApproval { approval_id, .. } => println!("Needs approval #{approval_id}"),
    }
}
```
