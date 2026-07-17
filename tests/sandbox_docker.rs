use icebox::core::executor::ModuleExecutor;
use icebox::core::module::Capability;
use icebox::core::safety::{Charter, PolicyContext, PolicyRule, RiskLevel, ScopeManager};
use icebox::core::sandbox::DockerSandbox;

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
    assert!(logs.is_empty(), "sleep container should produce no logs");

    sandbox.melt().await.expect("melt");
}

#[tokio::test]
async fn test_sandbox_policy_enforcement() {
    let mut exec = ModuleExecutor::new(
        Charter::accept("test", vec!["auth".into()]),
        ScopeManager::new(vec!["127.0.0.1".into()]),
        RiskLevel::Low,
    );
    exec.policy_set
        .rules
        .push(PolicyRule::DenyCapability(Capability::NetworkScan));

    let mut loaded = icebox::modules::load("tcp_port_scanner").expect("module");

    let sandboxed = exec
        .execute(
            &mut loaded,
            "127.0.0.1",
            None,
            false,
            PolicyContext::Cli,
            None,
            true,
            None,
        )
        .await;
    assert!(
        sandboxed.is_err(),
        "policy must block even when sandbox execution is requested"
    );

    let native = exec
        .execute(
            &mut loaded,
            "127.0.0.1",
            None,
            false,
            PolicyContext::Cli,
            None,
            false,
            None,
        )
        .await;
    assert!(native.is_err(), "policy must block without sandbox");
}


