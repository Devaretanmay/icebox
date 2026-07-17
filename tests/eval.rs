//! End-to-end assertions for the safety kernel and policy engine.

use icebox::core::executor::ModuleExecutor;
use icebox::core::module::{Capability, Intent, LoadedModule};
use icebox::core::safety::{
    Charter, PolicyContext, PolicyDecision, PolicyEngine, PolicyRule, RiskLevel, ScopeManager,
};

fn executor(max_risk: RiskLevel, scope: &[&str]) -> ModuleExecutor {
    ModuleExecutor::new(
        Charter::accept("eval", vec!["authorized".into()]),
        ScopeManager::new(scope.iter().map(|s| s.to_string()).collect()),
        max_risk,
    )
}

async fn decide(
    exec: &ModuleExecutor,
    loaded: &LoadedModule,
    target: &str,
    approved: bool,
) -> PolicyDecision {
    let pf = exec.preflight(loaded, target, None, approved, PolicyContext::Cli).await;
    exec.policy(PolicyContext::Cli).evaluate(&pf.to_request())
}

#[test]
fn capability_and_intent_model() {
    let loaded = icebox::modules::load("ssh_bruteforce").expect("module present");
    assert!(loaded
        .info
        .capabilities
        .contains(&Capability::CredentialAccess));
    assert_eq!(loaded.info.effective_impact(), RiskLevel::Critical);
    assert_eq!(loaded.info.effective_intents(), vec![Intent::Dump]);

    // undeclared scanner falls back to capability-derived impact
    let scan = icebox::modules::load("tcp_port_scanner").expect("module present");
    assert_eq!(scan.info.effective_impact(), RiskLevel::Low);
}

#[tokio::test]
async fn safety_gates_block_before_run() {
    let loaded = icebox::modules::load("reverse_shell_generator").expect("module present");
    let exec = executor(RiskLevel::Critical, &["10.0.0.5"]);

    assert!(
        matches!(
            decide(&exec, &loaded, "8.8.8.8", true).await,
            PolicyDecision::Deny(_)
        ),
        "out-of-scope target must be denied"
    );
    assert!(
        matches!(
            decide(&exec, &loaded, "10.0.0.5", false).await,
            PolicyDecision::RequireApproval(_)
        ),
        "high-risk payload needs approval"
    );
    assert!(
        matches!(
            decide(&exec, &loaded, "10.0.0.5", true).await,
            PolicyDecision::Allow
        ),
        "approved high-risk payload runs"
    );
}

#[tokio::test]
async fn operator_rules_override() {
    let loaded = icebox::modules::load("ssh_bruteforce").expect("module present");

    let mut exec = executor(RiskLevel::Critical, &["10.0.0.5"]);
    exec.policy_set
        .add_rule(PolicyRule::DenyCapability(Capability::CredentialAccess));
    assert!(
        matches!(
            decide(&exec, &loaded, "10.0.0.5", true).await,
            PolicyDecision::Deny(_)
        ),
        "deny rule wins over approval"
    );

    let mut exec2 = executor(RiskLevel::Critical, &["10.0.0.5"]);
    exec2
        .policy_set
        .add_rule(PolicyRule::MaxRisk(RiskLevel::Low));
    assert!(
        matches!(
            decide(&exec2, &loaded, "10.0.0.5", true).await,
            PolicyDecision::Deny(_)
        ),
        "max-risk cap below module impact denies"
    );

    let mut exec3 = executor(RiskLevel::Critical, &["10.0.0.5"]);
    exec3
        .policy_set
        .add_rule(PolicyRule::AllowCapability(Capability::CredentialAccess));
    assert!(
        matches!(
            decide(&exec3, &loaded, "10.0.0.5", false).await,
            PolicyDecision::Allow
        ),
        "allow rule waives the approval gate"
    );
}
