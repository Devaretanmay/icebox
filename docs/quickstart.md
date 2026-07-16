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
curl -X POST http://127.0.0.1:8443/api/v1/charter/accept \
  -H "Content-Type: application/json" \
  -d '{"engagement":"rest-audit","rules_of_engagement":[]}'

# Set the scope
curl -X POST http://127.0.0.1:8443/api/v1/scope/add \
  -H "Content-Type: application/json" \
  -d '{"target":"127.0.0.1"}'

# Execute a module
curl -X POST http://127.0.0.1:8443/api/v1/modules/recon/run \
  -H "Content-Type: application/json" \
  -d '{"target":"127.0.0.1","approved":true}'
```

## 3. Using the Python SDK

The Python SDK is the recommended path for integrating ICEBOX into autonomous agent frameworks (like LangChain, AutoGen, or custom loops).

```python
from icebox import Governance

# Initialize the Governance Seam
gov = Governance({
    "charter": {"accepted": True, "engagement": "agent-audit", "rules_of_engagement": []},
    "scope": {"allow": ["127.0.0.1"]},
    "max_risk": "low",
    "role": "operator"
})

# Attempt to execute an offensive module
result = gov.run({
    "name": "recon",
    "target": "127.0.0.1",
    "capabilities": ["network_scan"],
    "impact": "low",
    "destructive": False
})

if "Blocked" in result:
    print(f"Execution blocked by ICEBOX: {result['Blocked']}")
elif "NeedsApproval" in result:
    print(f"Execution halted, requires human approval: {result['NeedsApproval']}")
else:
    print("Execution allowed. Evidence gathered.")
```

## 4. Using the Rust SDK

If you are building high-performance tooling natively in Rust, you can import the `icebox-gov` crate and interact directly with the `ModuleExecutor`.

```rust
use icebox_gov::core::governance::{Framework, PolicyContext};
use icebox_gov::core::module::load;

#[tokio::main]
async fn main() {
    let mut fw = Framework::new();
    
    // Accept charter and set scope
    fw.executor.charter.accept("rust-audit".into(), vec![]);
    fw.executor.scope.add_allow("127.0.0.1");

    // Load a module dynamically
    let module = load("recon").expect("Module not found");

    // Execute through the seam
    let result = fw.executor.execute(
        &module,
        "127.0.0.1",
        None,
        false, // not pre-approved
        PolicyContext::Cli,
        None
    ).await;

    match result {
        Ok(res) => println!("Success: {:?}", res),
        Err(e) => println!("Governance Blocked: {}", e),
    }
}
```
