use icebox::core::executor::ModuleExecutor;
use icebox::core::module::Capability;
use icebox::core::safety::{Charter, PolicyContext, PolicyRule, RiskLevel, ScopeManager};

#[tokio::test]
async fn test_sandbox_bypass_and_mock_execution() {
    let mut exec = ModuleExecutor::new(
        Charter::accept("test", vec!["auth".into()]),
        ScopeManager::new(vec!["127.0.0.1".into()]),
        RiskLevel::Low,
    );
    exec.policy_set
        .rules
        .push(PolicyRule::DenyCapability(Capability::NetworkScan));

    let loaded = icebox::modules::load("arp_scanner").expect("module");

    let res_no_sandbox = exec
        .execute(
            &loaded,
            "127.0.0.1",
            None,
            false,
            PolicyContext::Cli,
            None,
            false,
            None,
        )
        .await;
    assert!(res_no_sandbox.is_err());

    let res_sandbox = exec
        .execute(
            &loaded,
            "127.0.0.1",
            None,
            false,
            PolicyContext::Cli,
            None,
            true,
            None,
        )
        .await
        .unwrap();

    assert!(res_sandbox.success);
    assert_eq!(res_sandbox.finding.unwrap(), "Found 2 live hosts");
    assert!(res_sandbox
        .evidence
        .iter()
        .any(|line| line.contains("[SANDBOX] Scanning simulated subnet...")));
}
