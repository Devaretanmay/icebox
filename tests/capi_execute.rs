use icebox::core::module::Capability;
use icebox::core::safety::{Charter, RiskLevel};
use icebox::core::sdk::{govern, GovernanceConfig, TaskSpec};
use serde_json::json;

#[tokio::test]
async fn test_governed_execution_through_capi_path() {
    let config = GovernanceConfig {
        charter: Charter::accept("test", vec!["auth".into()]),
        scope: icebox::core::safety::ScopeManager::new(vec!["127.0.0.1".into()]),
        max_risk: RiskLevel::Critical,
        ..Default::default()
    };
    let rt = govern(config);

    let task = TaskSpec {
        name: "tcp_port_scanner".into(),
        target: "127.0.0.1".into(),
        capabilities: vec![Capability::NetworkScan],
        impact: RiskLevel::Low,
        options: [("host".into(), "127.0.0.1".into()), ("ports".into(), "1".into())].into(),
        ..Default::default()
    };

    let outcome = rt.execute(task, || async {
        Ok(json!({"success": true, "open_ports": []}))
    }).await;

    match outcome {
        icebox::core::sdk::GovernedOutcome::Allowed { result, .. } => {
            assert!(result.get("success").is_some());
        }
        other => panic!("expected Allowed, got {other:?}"),
    }
}
