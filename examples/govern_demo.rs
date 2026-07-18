//! Example: govern a task via `govern(config)` — `cargo run --example govern_demo`.
//! Mirrors the Python `with govern()` and REST `POST /govern` (one model, three surfaces).

use icebox::core::safety::{Charter, RiskLevel, ScopeManager};
use icebox::core::sdk::{govern, GovernanceConfig, GovernedOutcome, TaskSpec};
use icebox::core::{Capability, CvssScore, Role};
use serde_json::json;

#[tokio::main]
async fn main() {
    let rt = govern(GovernanceConfig {
        charter: Charter::accept("govern-demo", vec!["no destruction".into()]),
        scope: ScopeManager::new(vec!["10.0.0.0/24".into()]),
        max_risk: RiskLevel::Critical,
        role: Role::Admin,
        ..Default::default()
    });

    let task = TaskSpec {
        name: "scan".into(),
        target: "10.0.0.5".into(),
        capabilities: vec![Capability::NetworkScan],
        impact: RiskLevel::Low,
        destructive: false,
        options: [
            ("host".into(), "10.0.0.5".into()),
            ("ports".into(), "1-1024".into()),
        ]
        .into(),
        cvss: Some(CvssScore {
            cvss_v31: Some(9.5),
            cvss_v40: None,
            epss: Some(0.9),
            kev: true,
        }),
        ..Default::default()
    };

    let outcome: GovernedOutcome = rt
        .run(task, || async { Ok(json!({"open_ports": [22, 80, 443]})) })
        .await;

    match outcome {
        GovernedOutcome::Allowed {
            result,
            decision_id,
            ..
        } => {
            println!("Allowed (decision {decision_id}): {result}");
        }
        GovernedOutcome::Blocked {
            reason,
            decision_id,
        } => {
            println!("Blocked (decision {decision_id}): {reason}");
        }
        GovernedOutcome::NeedsApproval {
            reason,
            decision_id,
            approval_id,
        } => {
            println!("Needs approval {approval_id} (decision {decision_id}): {reason}");
        }
    }

    println!("Audit trail: {} records", rt.audit().await.len());
}
