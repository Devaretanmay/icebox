//! Demonstrates the preflight gates (charter, scope, risk, destructive) before any module runs.

use icebox::core::executor::ModuleExecutor;
use icebox::core::safety::{make_config_policy, Charter, PolicyContext, RiskLevel, ScopeManager};

#[tokio::main]
async fn main() {
    let loaded = icebox::modules::load("reverse_shell_payload").expect("module present");
    println!(
        "module: {} [{}]  (baseline risk = high for payloads)\n",
        loaded.info.name,
        loaded.info.kind.as_str()
    );

    let in_scope = "10.0.0.5";

    let mut exec = ModuleExecutor::new(
        Charter::accept("demo-engagement", vec!["authorized only".into()]),
        ScopeManager::new(vec![in_scope.into()]),
        RiskLevel::Critical,
    );
    let pf = exec.preflight(&loaded, "8.8.8.8", None, true, PolicyContext::Cli);
    println!(
        "[1] out-of-scope target  -> check: {:?}",
        pf.check(&make_config_policy(
            RiskLevel::Critical,
            PolicyContext::Cli,
            &exec.policy_set
        ))
    );

    let exec_no_charter = ModuleExecutor::new(
        Charter::default(),
        ScopeManager::new(vec![in_scope.into()]),
        RiskLevel::Critical,
    );
    let pf = exec_no_charter.preflight(&loaded, in_scope, None, true, PolicyContext::Cli);
    println!(
        "[2] charter not accepted -> check: {:?}",
        pf.check(&make_config_policy(
            RiskLevel::Critical,
            PolicyContext::Cli,
            &exec_no_charter.policy_set
        ))
    );

    let pf = exec.preflight(&loaded, in_scope, None, false, PolicyContext::Cli);
    println!(
        "[3] high-risk, no approval -> check: {:?}",
        pf.check(&make_config_policy(
            RiskLevel::Critical,
            PolicyContext::Cli,
            &exec.policy_set
        ))
    );

    match exec
        .execute(&loaded, in_scope, None, true, PolicyContext::Cli, None)
        .await
    {
        Ok(r) => println!("[4] approved run -> success={}", r.success),
        Err(e) => println!("[4] approved run -> error: {}", e),
    }

    let pf = exec.preflight(&loaded, in_scope, Some(true), false, PolicyContext::Cli);
    println!(
        "[5] destructive, no approval -> check: {:?}",
        pf.check(&make_config_policy(
            RiskLevel::Critical,
            PolicyContext::Cli,
            &exec.policy_set
        ))
    );
    match exec
        .execute(
            &loaded,
            in_scope,
            Some(true),
            true,
            PolicyContext::Cli,
            None,
        )
        .await
    {
        Ok(r) => println!("[6] destructive, approved -> success={}", r.success),
        Err(e) => println!("[6] destructive, approved -> error: {}", e),
    }
}
