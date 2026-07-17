use std::collections::HashMap;

use icebox::core::safety::{Charter, RiskLevel};
use icebox::core::sdk::GovernanceRuntime;
use serde_json::Value;

#[tokio::test]
async fn test_cabi_executes() {
    let rt = GovernanceRuntime::builder()
        .charter(Charter::accept("test", vec!["auth".into()]))
        .scope(vec!["127.0.0.1".into()])
        .max_risk(RiskLevel::Critical)
        .build();

    let mut opts = HashMap::new();
    opts.insert("host".to_string(), "127.0.0.1".to_string());
    opts.insert("ports".to_string(), "1".to_string());

    let out = rt
        .execute_module("tcp_port_scanner", "127.0.0.1", &opts)
        .await;
    assert!(out.is_ok(), "capi must execute the module, got: {out:?}");

    let json: Value = serde_json::from_str(&out.unwrap()).expect("valid ModuleResult json");
    assert!(
        json.get("success").is_some(),
        "result must be a real ModuleResult, not a no-op null"
    );
}
