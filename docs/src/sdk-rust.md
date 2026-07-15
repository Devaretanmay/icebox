# SDK: Rust

The `icebox` crate is the primary integration surface — you do not have to
use the CLI or the modules to govern your own agents.

```toml
[dependencies]
icebox = "0.1"
tokio = { version = "1", features = ["full"] }
serde_json = "1"
```

## Govern a task

```rust
use icebox::core::{GovernanceRuntime, GovernedOutcome, TaskSpec};
use serde_json::json;

#[tokio::main]
async fn main() {
    let rt = GovernanceRuntime::new(serde_json::from_value(json!({
        "charter": "authorized engagement",
        "scope": ["10.0.0.0/24"],
        "max_risk": "high",
    })).expect("config");

    let task = TaskSpec {
        module: "tcp_port_scanner".into(),
        target: "10.0.0.5".into(),
        options: json!({ "host": "10.0.0.5", "ports": "1-1024" }),
        ..Default::default()
    };

    // Supervised: approval-gated tasks return `NeedsApproval`.
    let outcome: GovernedOutcome = rt.check(task.clone()).await;
    // Unsupervised: approval-gated tasks are auto-granted.
    let outcome: GovernedOutcome = rt.run(task, || async { Ok(json!(null)) }).await;

    println!("{:?}", outcome.decision);
    println!("{}", rt.audit_json().await);
}
```

`GovernanceRuntime` is the in-process equivalent of the CLI seam. Use it
to wrap any tool — Rust or otherwise — behind the same policy, approval,
and audit gates.
