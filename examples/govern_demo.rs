//! Standalone Rust SDK example: govern tasks through the in-process seam,
//! including a CVSS-gated exploit that gets blocked.
//!
//! Run with: `cargo run --example govern_demo`

use icebox::core::safety::CvssScore;
use icebox::core::sdk::{GovernanceRuntime, GovernedOutcome, TaskSpec};
use icebox::core::{Capability, Charter, RiskLevel};
use serde_json::json;

#[tokio::main]
async fn main() {
    let rt = GovernanceRuntime::builder()
        .charter(Charter::accept("demo", vec!["authorized".into()]))
        .scope(vec!["10.0.0.0/8".into()])
        .max_risk(RiskLevel::Critical)
        .deny_if_cvss_above(7.0)
        .build();

    let safe = TaskSpec {
        name: "scan".into(),
        target: "10.0.0.5".into(),
        capabilities: vec![Capability::NetworkScan],
        impact: RiskLevel::Low,
        destructive: false,
        ..Default::default()
    };

    let exploit = TaskSpec {
        name: "exploit".into(),
        target: "10.0.0.5".into(),
        capabilities: vec![Capability::PrivilegeEscalation],
        impact: RiskLevel::High,
        destructive: false,
        cvss: Some(CvssScore::from_score(9.5)),
        ..Default::default()
    };

    let safe_out: GovernedOutcome = rt.run(safe, || async { Ok(json!(null)) }).await;
    let exploit_out: GovernedOutcome = rt.run(exploit, || async { Ok(json!(null)) }).await;

    println!("safe   -> {safe_out:?}");
    println!("exploit-> {exploit_out:?}");
    println!("audit  -> {:?}", rt.audit().await);
}
