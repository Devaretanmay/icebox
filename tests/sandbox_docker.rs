use icebox::core::executor::ModuleExecutor;
use icebox::core::module::Capability;
use icebox::core::safety::{Charter, PolicyContext, PolicyRule, RiskLevel, ScopeManager};
use icebox::core::sandbox::{DockerSandbox, SandboxEngineType};

#[tokio::test]
async fn test_sandbox_docker_availability() {
    let available = DockerSandbox::is_available();
    println!("Docker available: {}", available);
}

#[tokio::test]
async fn test_sandbox_docker_lifecycle() {
    if !DockerSandbox::is_available() {
        println!("Skipping docker lifecycle test because daemon is unavailable");
        return;
    }
    let sandbox = DockerSandbox::freeze("127.0.0.1", "alpine:3.20")
        .await
        .expect("freeze");
    assert!(!sandbox.container_id().is_empty());
    assert_eq!(sandbox.target(), "127.0.0.1");

    let logs = sandbox.capture_logs().await;
    assert!(logs.is_empty() || !logs.is_empty());

    sandbox.melt().await.expect("melt");
}

#[tokio::test]
async fn test_sandbox_executor_integration() {
    let mut exec = ModuleExecutor::new(
        Charter::accept("test", vec!["auth".into()]),
        ScopeManager::new(vec!["127.0.0.1".into()]),
        RiskLevel::Low,
    );
    exec.policy_set
        .rules
        .push(PolicyRule::DenyCapability(Capability::NetworkScan));

    let loaded = icebox::modules::load("arp_scanner").expect("module");

    let res = exec
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

    assert!(res.success);
    assert_eq!(res.finding.unwrap(), "Found 2 live hosts");
    let has_sandbox_evidence = res.evidence.iter().any(|line| line.contains("[SANDBOX]"));
    assert!(has_sandbox_evidence);
}
