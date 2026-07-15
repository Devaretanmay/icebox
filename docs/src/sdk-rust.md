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
use icebox::core::sdk::{GovernanceRuntime, GovernedOutcome, TaskSpec};
use icebox::core::{Charter, RiskLevel, Capability};

#[tokio::main]
async fn main() {
    let rt = GovernanceRuntime::builder()
        .charter(Charter::accept("demo", vec![]))
        .scope(vec!["10.0.0.0/24".into()])
        .max_risk(RiskLevel::Critical)
        .build();

    let task = TaskSpec {
        name: "scan".into(),
        target: "10.0.0.5".into(),
        capabilities: vec![Capability::NetworkScan],
        impact: RiskLevel::Low,
        destructive: false,
        options: [
            ("host".into(), "10.0.0.5".into()),
            ("ports".into(), "1-1024".into()),
        ].into(),
        ..Default::default()
    };

    // `run` auto-grants approval-gated tasks; `execute` queues them.
    let outcome: GovernedOutcome = rt.run(task, || async { Ok(serde_json::json!(null)) }).await;
    println!("{:?}", outcome);
    println!("{:?}", rt.audit().await);
}
```

`GovernanceRuntime` is the in-process equivalent of the CLI seam. Use it
to wrap any tool — Rust or otherwise — behind the same policy, approval,
and audit gates.
